#pragma once

/**
 * dex_macos_perf.hpp — pure math + macOS perf readers for the DEX perf primitives:
 * the "machine-health tier" per docs/dex-signal-catalog.md (Guardian DEX perf.* breach
 * trio, TAR device/app perf — consumed starting C2/C4).
 *
 * The macOS analogue of dex_linux_proc.hpp: every derivation (busy%, await-ms,
 * pressure%, used-bytes) is PURE — no syscalls, no platform guards — so it is
 * unit-tested on every host exactly like the Linux /proc arithmetic. Only the FOUR
 * `read_*` functions (read_cpu_ticks, read_vm_snapshot, read_disk_totals,
 * read_memorystatus_level) touch the kernel (host_statistics/host_statistics64, IOKit's
 * IOBlockStorageDriver "Statistics" dictionaries, sysctlbyname) and are
 * `#if defined(__APPLE__)`, with an all-invalid stub on every other platform — the
 * net_quality_sampler.cpp / dex_linux_proc.cpp shape. (The IOKit walk itself,
 * `sum_block_storage_stats`/`read_driver_stats`, is file-private to dex_macos_perf.cpp —
 * `read_disk_totals` is its only production caller.)
 *
 * THREADING CONTRACT: every `read_*` function does blocking OS work (a syscall, an
 * IOKit/CoreFoundation registry walk) and must be called from a POLL thread — never
 * inlined on the heartbeat thread (starves the heartbeat interval) or from inside a
 * Spark mechanism's `watch()`/`unwatch()` (spark_mechanism.hpp's contract: bound OS work
 * only, never call emit()/fault() synchronously — a blocking read there self-deadlocks,
 * #4181).
 *
 * Nothing in this file is wired into any collector yet (C0 goal: primitives
 * only). C2 (TAR device perf) and C4 (Guardian perf.* breach trio) are the
 * first consumers.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstdint>
#include <optional>

namespace yuzu::agent::macos {

/// Cumulative CPU tick counters since boot, from host_statistics(HOST_CPU_LOAD_INFO).
/// Mirrors yuzu::agent::lnx::CpuJiffies (dex_linux_proc.hpp), but keeps user/system/
/// nice separate — host_cpu_load_info reports each as its own CPU_STATE_* bucket
/// rather than one pre-summed "user" field the way /proc/stat's layout already is.
struct CpuTicks {
    bool valid{false};
    std::uint64_t user{0};
    std::uint64_t system{0};
    std::uint64_t nice{0};
    std::uint64_t idle{0};
};

/// PURE, saturating: convert `t` mach-absolute-time ticks to 100ns units, given the
/// host's mach_timebase_info (numer/denom — ticks-to-nanoseconds is `t*numer/denom`;
/// this then divides by 100 for the wire's 100ns unit, matching ProcCounter::cpu_100ns
/// in tar_proc_perf.hpp, C3's consumer). Saturates at UINT64_MAX rather than wrapping
/// on overflow — a malformed/extreme input must not silently underreport. `denom==0`
/// (a corrupt timebase) returns 0, never divides by zero.
YUZU_EXPORT std::uint64_t mach_abs_to_100ns(std::uint64_t t, std::uint32_t numer,
                                            std::uint32_t denom) noexcept;

/// PURE: busy% over the interval between two CpuTicks readings. nullopt when either
/// reading is invalid, any individual field regressed, or no time elapsed. Clamped to
/// [0,100]. Mirrors yuzu::agent::lnx::cpu_busy_pct, but each field is checked for
/// regression independently here — unlike yuzu::agent::lnx::CpuJiffies's single derived
/// total. A regression is ordinarily reboot/reset, but host_cpu_load_info's cpu_ticks
/// are 32-bit `natural_t`, so a field can also wrap on its own after ~497 days of
/// continuous per-mode accumulation at a 100Hz tick rate — re-baselining on that wrap is
/// the correct, safe behaviour, not a bug in this check.
YUZU_EXPORT std::optional<double> cpu_busy_pct(const CpuTicks& prev, const CpuTicks& cur);

/// Aggregate IOBlockStorageDriver "Statistics" counters, summed over every driver
/// instance in the IOKit registry — the macOS analogue of yuzu::agent::lnx::DiskIoTotals.
/// Time fields are nanoseconds from kIOBlockStorageDriverStatisticsTotal{Read,Write}
/// TimeKey ("Total Time (Read/Write)") — the driver's SERVICE time (svctm: time actually
/// spent executing the I/O), deliberately NOT
/// kIOBlockStorageDriverStatisticsLatent{Read,Write}TimeKey ("Latency Time"), which is
/// queue/wait time and is never read here — disk_await_ms() below is therefore an await
/// figure built from a service-time source, matching the iostat svctm shape, not the
/// fuller await = svctm + queue-wait iostat normally reports.
struct DiskTotals {
    bool valid{false};
    std::uint64_t read_bytes{0};
    std::uint64_t write_bytes{0};
    std::uint64_t reads{0};
    std::uint64_t writes{0};
    std::uint64_t read_time_ns{0};
    std::uint64_t write_time_ns{0};
};

/// PURE: average service time (ms per completed I/O) over the interval between two
/// DiskTotals readings — the iostat `await` shape, mirroring
/// yuzu::agent::lnx::disk_await_ms. nullopt when either reading is invalid or a
/// counter regressed. Zero completed ops this interval derives 0.0 (idle, not slow).
YUZU_EXPORT std::optional<double> disk_await_ms(const DiskTotals& prev, const DiskTotals& cur);

/// PURE: memory pressure % from a raw kern.memorystatus_level reading (0 = critical
/// pressure, 100 = plenty of headroom — the scale memory_pressure(1) itself reads).
/// Pressure is the complement, clamped [0,100] so an out-of-range level (a future
/// kernel revision, or a bad read) never produces a nonsensical negative/>100 value.
///
/// BASIS, not just polarity: this is an AVAILABILITY-basis pressure reading (derived
/// from free/reclaimable memory headroom), the inverse shape of the existing
/// `memory_pressure_observation` wording ("commit charge avg X% of limit" — a
/// COMMIT-basis reading, Windows/Linux). The two are not interchangeable inputs to the
/// same formula — C4 (Guardian perf.* breach trio) adds a `MemoryBasis` parameter to
/// `memory_pressure_observation` specifically so macOS's availability-basis number
/// renders with availability wording, never silently relabelled as a commit-basis one.
YUZU_EXPORT double memory_pressure_pct(int level) noexcept;

/// One host_statistics64(HOST_VM_INFO64) + hw.memsize snapshot, already reduced to
/// bytes (never raw page counts — the caller never needs the page size).
struct VmSnapshot {
    bool valid{false};
    std::uint64_t total_bytes{0};
    std::uint64_t used_bytes{0};
};

/// PURE, saturating: reduce a vm_statistics64 snapshot to a single "used" byte count,
/// mirroring Activity Monitor's memory accounting: wired + (internal-app pages, minus
/// the purgeable/reclaimable-on-demand pages already folded into `internal`) +
/// compressor pages, all times the page size. Saturates rather than wraps on overflow;
/// `purgeable > internal` floors the app term at 0 rather than underflowing.
YUZU_EXPORT std::uint64_t vm_used_bytes(std::uint64_t wire, std::uint64_t internal,
                                        std::uint64_t purgeable, std::uint64_t compressor,
                                        std::uint64_t page) noexcept;

/// Darwin: one host_statistics(HOST_CPU_LOAD_INFO) read. All-invalid (`CpuTicks{}`) on
/// failure or on every other platform — never a half-filled struct.
YUZU_EXPORT CpuTicks read_cpu_ticks();

/// Darwin: one host_statistics64(HOST_VM_INFO64) + hw.memsize + host_page_size read,
/// reduced via vm_used_bytes(). All-invalid on failure (any of the three underlying
/// calls) or on every other platform.
YUZU_EXPORT VmSnapshot read_vm_snapshot();

/// Darwin: sums the "Statistics" dictionary of every IOBlockStorageDriver in the IOKit
/// registry (IOServiceGetMatchingServices(kIOBlockStorageDriverClass)). A driver with no
/// Statistics dict, or missing one of the 6 keys read, is SKIPPED (does not invalidate
/// the sample — an idle/uninitialized driver legitimately has none yet); a NEGATIVE
/// value on any key present invalidates the WHOLE sample immediately (kernel-counter
/// corruption, not a benign gap). All-invalid on lookup failure or on every other
/// platform. The walk itself (`sum_block_storage_stats`/`read_driver_stats`) is
/// file-private to dex_macos_perf.cpp — this is its only caller.
YUZU_EXPORT DiskTotals read_disk_totals();

#if defined(__APPLE__)
/// TEST-ONLY seam pinning the file-private sum_block_storage_stats()'s
/// genuinely-empty-iterator arm (zero drivers matched -> valid stays false)
/// deterministically, via an IOKit service class guaranteed to match nothing —
/// independent of the live driver population, which read_disk_totals()'s own caller
/// (this box has real drivers) cannot control. Never used outside tests.
YUZU_EXPORT DiskTotals sum_block_storage_stats_empty_iterator_for_test();
#endif

/// Darwin: one sysctlbyname("kern.memorystatus_level") read. nullopt on failure or on
/// every other platform — the raw kernel scale (0..100), NOT yet reduced by
/// memory_pressure_pct (the caller composes the two).
YUZU_EXPORT std::optional<int> read_memorystatus_level();

} // namespace yuzu::agent::macos
