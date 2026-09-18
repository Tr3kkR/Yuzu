#include "dex_macos_perf.hpp"

#include <algorithm>
#include <limits>

#if defined(__APPLE__)
#include <yuzu/agent/scoped_cfref.hpp>
#include <yuzu/agent/scoped_ioobject.hpp>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/storage/IOBlockStorageDriver.h>
#include <mach/mach_host.h>
#include <mach/mach_init.h>
#include <mach/machine.h>
#include <sys/sysctl.h>
#endif

namespace yuzu::agent::macos {

namespace {

double clamp_pct(double v) { return std::clamp(v, 0.0, 100.0); }

// Saturating uint64 add: never wraps past UINT64_MAX.
std::uint64_t sat_add(std::uint64_t a, std::uint64_t b) {
    const std::uint64_t sum = a + b;
    return sum < a ? std::numeric_limits<std::uint64_t>::max() : sum;
}

// Saturating uint64 multiply: never wraps past UINT64_MAX.
std::uint64_t sat_mul(std::uint64_t a, std::uint64_t b) {
    if (a == 0 || b == 0)
        return 0;
    if (a > std::numeric_limits<std::uint64_t>::max() / b)
        return std::numeric_limits<std::uint64_t>::max();
    return a * b;
}

} // namespace

std::uint64_t mach_abs_to_100ns(std::uint64_t t, std::uint32_t numer, std::uint32_t denom) noexcept {
    if (denom == 0)
        return 0; // corrupt timebase — never divide by zero
    // t*numer saturates first (it can overflow 64 bits well before the final /100);
    // the two divides then reduce ticks -> ns -> 100ns, matching ProcCounter::cpu_100ns's unit.
    const std::uint64_t ns = sat_mul(t, static_cast<std::uint64_t>(numer)) / denom;
    return ns / 100;
}

std::optional<double> cpu_busy_pct(const CpuTicks& prev, const CpuTicks& cur) {
    if (!prev.valid || !cur.valid)
        return std::nullopt;
    if (cur.user < prev.user || cur.system < prev.system || cur.nice < prev.nice ||
        cur.idle < prev.idle)
        return std::nullopt; // per-field regression (reboot/reset) — re-baseline next tick
    const std::uint64_t prev_total = prev.user + prev.system + prev.nice + prev.idle;
    const std::uint64_t cur_total = cur.user + cur.system + cur.nice + cur.idle;
    const std::uint64_t dt = cur_total - prev_total;
    if (dt == 0)
        return std::nullopt; // no elapsed time
    const std::uint64_t di = std::min(cur.idle - prev.idle, dt); // idle cannot exceed total
    return clamp_pct(100.0 * static_cast<double>(dt - di) / static_cast<double>(dt));
}

std::optional<double> disk_await_ms(const DiskTotals& prev, const DiskTotals& cur) {
    if (!prev.valid || !cur.valid)
        return std::nullopt;
    if (cur.reads < prev.reads || cur.writes < prev.writes ||
        cur.read_time_ns < prev.read_time_ns || cur.write_time_ns < prev.write_time_ns)
        return std::nullopt; // counter regression (reboot/hotplug) — re-baseline
    const std::uint64_t dops = (cur.reads + cur.writes) - (prev.reads + prev.writes);
    if (dops == 0)
        return 0.0; // no I/O this interval — an idle disk is healthy, not slow
    const std::uint64_t dtime_ns =
        (cur.read_time_ns + cur.write_time_ns) - (prev.read_time_ns + prev.write_time_ns);
    return (static_cast<double>(dtime_ns) / 1e6) / static_cast<double>(dops);
}

double memory_pressure_pct(int level) noexcept {
    return std::clamp(100.0 - static_cast<double>(level), 0.0, 100.0);
}

std::uint64_t vm_used_bytes(std::uint64_t wire, std::uint64_t internal, std::uint64_t purgeable,
                             std::uint64_t compressor, std::uint64_t page) noexcept {
    // purgeable pages are reclaimable-on-demand and already folded into `internal`, so
    // they must not inflate "used" — floor at 0 rather than underflow.
    const std::uint64_t app = internal >= purgeable ? internal - purgeable : 0;
    const std::uint64_t used_pages = sat_add(sat_add(wire, app), compressor);
    return sat_mul(used_pages, page);
}

#if defined(__APPLE__)

namespace {
// mach_host_self() hands back a fixed send right naming "the host on which this task is
// running" — it never changes for the life of the process, so every reader in this file
// shares one cached port rather than each re-fetching it per call.
const mach_port_t kHostSelf = mach_host_self();
} // namespace

CpuTicks read_cpu_ticks() {
    host_cpu_load_info_data_t info{};
    mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
    if (host_statistics(kHostSelf, HOST_CPU_LOAD_INFO, reinterpret_cast<host_info_t>(&info),
                        &count) != KERN_SUCCESS)
        return {}; // invalid — never a half-filled struct
    CpuTicks out;
    out.valid = true;
    out.user = info.cpu_ticks[CPU_STATE_USER];
    out.system = info.cpu_ticks[CPU_STATE_SYSTEM];
    out.idle = info.cpu_ticks[CPU_STATE_IDLE];
    out.nice = info.cpu_ticks[CPU_STATE_NICE];
    return out;
}

#else

CpuTicks read_cpu_ticks() { return {}; }

#endif // __APPLE__

#if defined(__APPLE__)

namespace {

// Bounded sysctlbyname read into a fixed-size scalar. Same shape as
// hardware_plugin.cpp's sysctl_value — kept as a private local copy here rather than a
// shared header: hardware_plugin.cpp has its own single call site, and THIS file has two
// (hw.memsize below, kern.memorystatus_level in read_memorystatus_level) — duplicating
// this ~8-line helper is still cheaper than adding a new shared header for it.
template <typename T> std::optional<T> sysctl_value(const char* name) {
    T value{};
    std::size_t len = sizeof(value);
    if (::sysctlbyname(name, &value, &len, nullptr, 0) != 0)
        return std::nullopt;
    return value;
}

} // namespace

VmSnapshot read_vm_snapshot() {
    vm_statistics64_data_t vm{};
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    if (host_statistics64(kHostSelf, HOST_VM_INFO64, reinterpret_cast<host_info64_t>(&vm),
                          &count) != KERN_SUCCESS)
        return {};
    vm_size_t page_size = 0;
    if (host_page_size(kHostSelf, &page_size) != KERN_SUCCESS)
        return {};
    const auto total = sysctl_value<std::uint64_t>("hw.memsize");
    if (!total)
        return {}; // any of the three underlying reads failing invalidates the snapshot
    VmSnapshot out;
    out.valid = true;
    out.total_bytes = *total;
    out.used_bytes = vm_used_bytes(vm.wire_count, vm.internal_page_count, vm.purgeable_count,
                                   vm.compressor_page_count, static_cast<std::uint64_t>(page_size));
    return out;
}

#else

VmSnapshot read_vm_snapshot() { return {}; }

#endif // __APPLE__

#if defined(__APPLE__)

namespace {

// One "Statistics" dict key: present, a CFNumber, and readable as SInt64. false on any
// miss (absent key, wrong type, or a conversion CFNumberGetValue itself rejects).
bool read_stat_key(CFDictionaryRef dict, CFStringRef key, std::int64_t& out) {
    auto num = static_cast<CFNumberRef>(CFDictionaryGetValue(dict, key));
    return num && CFGetTypeID(num) == CFNumberGetTypeID() &&
           CFNumberGetValue(num, kCFNumberSInt64Type, &out);
}

// Per-driver outcome of reading one "Statistics" dict: kSkip (missing/malformed key —
// not fatal, an idle/uninitialized driver legitimately has none yet), kCorrupt (a
// negative counter — kernel-counter corruption, invalidates the WHOLE sample), or
// kAccumulated (added into `out`). `out` is left untouched on kSkip/kCorrupt.
enum class DriverStatOutcome { kSkip, kCorrupt, kAccumulated };

DriverStatOutcome read_driver_stats(CFDictionaryRef dict, DiskTotals& out) {
    std::int64_t rb = 0, wb = 0, rd = 0, wr = 0, rt = 0, wt = 0;
    const bool complete =
        read_stat_key(dict, CFSTR(kIOBlockStorageDriverStatisticsBytesReadKey), rb) &&
        read_stat_key(dict, CFSTR(kIOBlockStorageDriverStatisticsBytesWrittenKey), wb) &&
        read_stat_key(dict, CFSTR(kIOBlockStorageDriverStatisticsReadsKey), rd) &&
        read_stat_key(dict, CFSTR(kIOBlockStorageDriverStatisticsWritesKey), wr) &&
        read_stat_key(dict, CFSTR(kIOBlockStorageDriverStatisticsTotalReadTimeKey), rt) &&
        read_stat_key(dict, CFSTR(kIOBlockStorageDriverStatisticsTotalWriteTimeKey), wt);
    if (!complete)
        return DriverStatOutcome::kSkip;
    if (rb < 0 || wb < 0 || rd < 0 || wr < 0 || rt < 0 || wt < 0)
        return DriverStatOutcome::kCorrupt;
    out.read_bytes = sat_add(out.read_bytes, static_cast<std::uint64_t>(rb));
    out.write_bytes = sat_add(out.write_bytes, static_cast<std::uint64_t>(wb));
    out.reads = sat_add(out.reads, static_cast<std::uint64_t>(rd));
    out.writes = sat_add(out.writes, static_cast<std::uint64_t>(wr));
    out.read_time_ns = sat_add(out.read_time_ns, static_cast<std::uint64_t>(rt));
    out.write_time_ns = sat_add(out.write_time_ns, static_cast<std::uint64_t>(wt));
    return DriverStatOutcome::kAccumulated;
}

// File-private: read_disk_totals() below is the only caller. Sums every
// IOBlockStorageDriver's "Statistics" dict reachable from `it` via read_driver_stats().
DiskTotals sum_block_storage_stats(io_iterator_t it) {
    DiskTotals out;
    bool any = false;
    for (io_object_t raw_obj; (raw_obj = IOIteratorNext(it));) {
        ScopedIOObject obj{raw_obj};
        ScopedCFRef<CFTypeRef> stats{IORegistryEntryCreateCFProperty(
            obj.get(), CFSTR(kIOBlockStorageDriverStatisticsKey), kCFAllocatorDefault, 0)};
        if (!stats || CFGetTypeID(stats.get()) != CFDictionaryGetTypeID())
            continue; // no Statistics dict yet — skip this driver, not fatal
        const auto outcome = read_driver_stats(static_cast<CFDictionaryRef>(stats.get()), out);
        if (outcome == DriverStatOutcome::kCorrupt)
            return DiskTotals{}; // kernel-counter corruption — invalidate the whole sample
        any = any || (outcome == DriverStatOutcome::kAccumulated);
    }
    out.valid = any;
    return out;
}

} // namespace

DiskTotals read_disk_totals() {
    io_iterator_t raw_it{};
    if (IOServiceGetMatchingServices(kIOMainPortDefault,
                                     IOServiceMatching(kIOBlockStorageDriverClass),
                                     &raw_it) != KERN_SUCCESS)
        return {};
    ScopedIOObject it{raw_it};
    return sum_block_storage_stats(it.get());
}

std::optional<DiskTotals> sum_block_storage_stats_empty_iterator_for_test() {
    // "YuzuNonexistentDriverClassForTest" matches no IOKit service by construction —
    // IOServiceGetMatchingServices still succeeds, handing back a real iterator that
    // IOIteratorNext immediately hands back IO_OBJECT_NULL (not an "exhausted" iterator
    // to release — nothing was ever produced), so sum_block_storage_stats()'s "zero
    // drivers -> valid stays false" arm is pinned deterministically (this box has real
    // IOBlockStorageDriver rows, so that arm is otherwise unreachable from a test here).
    io_iterator_t raw_it{};
    if (IOServiceGetMatchingServices(kIOMainPortDefault,
                                     IOServiceMatching("YuzuNonexistentDriverClassForTest"),
                                     &raw_it) != KERN_SUCCESS)
        return std::nullopt; // lookup itself failed — inconclusive, distinct from a pin
    ScopedIOObject it{raw_it};
    return sum_block_storage_stats(it.get());
}

std::optional<int> read_memorystatus_level() {
    // Reuses the sysctl_value<T> helper declared above (read_vm_snapshot's block) —
    // one copy per TU, not one per call site.
    const auto v = sysctl_value<std::int32_t>("kern.memorystatus_level");
    if (!v)
        return std::nullopt;
    return static_cast<int>(*v);
}

#else

DiskTotals read_disk_totals() { return {}; }

std::optional<int> read_memorystatus_level() { return std::nullopt; }

#endif // __APPLE__

} // namespace yuzu::agent::macos
