#include "dex_macos_perf.hpp"

#include <algorithm>
#include <limits>

namespace yuzu::agent::macos {

namespace {

double clamp_pct(double v) { return std::clamp(v, 0.0, 100.0); }

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

} // namespace yuzu::agent::macos
