#pragma once

/**
 * dex_macos_perf.hpp — pure math + macOS perf readers for the DEX perf primitives
 * (Guardian DEX perf.* breach trio, TAR device/app perf — consumed starting C2/C4).
 *
 * The macOS analogue of dex_linux_proc.hpp: every derivation (busy%, await-ms,
 * pressure%, used-bytes) is PURE — no syscalls, no platform guards — so it is
 * unit-tested on every host exactly like the Linux /proc arithmetic. Only the
 * six `read_*` functions touch the kernel (host_statistics/host_statistics64,
 * IOKit's IOBlockStorageDriver "Statistics" dictionaries, sysctlbyname) and are
 * `#if defined(__APPLE__)`, with an all-invalid stub on every other platform —
 * the net_quality_sampler.cpp / dex_linux_proc.cpp shape.
 *
 * Nothing in this file is wired into any collector yet (C0 goal: primitives
 * only). C2 (TAR device perf) and C4 (Guardian perf.* breach trio) are the
 * first consumers.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <cstdint>
#include <optional>

#if defined(__APPLE__)
#include <IOKit/IOKitLib.h>
#endif

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
/// reading is invalid, any individual field regressed (reboot/reset — each field is an
/// independently monotonic counter here, unlike /proc/stat's single derived total), or
/// no time elapsed. Clamped to [0,100]. Mirrors yuzu::agent::lnx::cpu_busy_pct.
YUZU_EXPORT std::optional<double> cpu_busy_pct(const CpuTicks& prev, const CpuTicks& cur);

/// Aggregate IOBlockStorageDriver "Statistics" counters, summed over every driver
/// instance in the IOKit registry — the macOS analogue of yuzu::agent::lnx::DiskIoTotals.
/// Time fields are nanoseconds (kIOBlockStorageDriverStatisticsTotal{Read,Write}TimeKey).
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

#if defined(__APPLE__)
/// Darwin only (the type itself, io_iterator_t, does not exist off Apple platforms):
/// sum the "Statistics" dictionary of every IOBlockStorageDriver reachable from `it`.
/// A driver with no Statistics dict, or missing one of the 6 keys read, is SKIPPED
/// (does not invalidate the sample — an idle/uninitialized driver legitimately has
/// none yet); a NEGATIVE value on any key present invalidates the WHOLE sample
/// immediately (kernel-counter corruption, not a benign gap). valid=true only if at
/// least one driver fully contributed and no negative value was ever seen.
YUZU_EXPORT DiskTotals sum_block_storage_stats(io_iterator_t it);
#endif

/// Darwin: IOServiceGetMatchingServices(kIOBlockStorageDriverClass) walked via
/// sum_block_storage_stats(). All-invalid on failure (including the service lookup
/// itself) or on every other platform.
YUZU_EXPORT DiskTotals read_disk_totals();

/// Darwin: one sysctlbyname("kern.memorystatus_level") read. nullopt on failure or on
/// every other platform — the raw kernel scale (0..100), NOT yet reduced by
/// memory_pressure_pct (the caller composes the two).
YUZU_EXPORT std::optional<int> read_memorystatus_level();

} // namespace yuzu::agent::macos
