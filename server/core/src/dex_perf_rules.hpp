#pragma once

/// @file dex_perf_rules.hpp
/// Single source of truth for how agent-supplied perf heartbeat tags are
/// validated and how fleet percentiles are ranked. Shared by the Prometheus
/// rollup (`AgentHealthStore::recompute_metrics`, A4) and the F2a in-product
/// read model (`dex_perf_model.cpp`) so the /metrics gauges and the /dex
/// Performance tab can never disagree about the same heartbeat sample.
///
/// Forged-value posture (A4 + grill round, 2026-06-12): values are
/// agent-supplied strings. `std::stod` does NOT throw on "inf"/"nan" — it
/// returns the non-finite value, which one rogue agent could use to poison a
/// fleet-wide stat for every operator. Accept only finite, non-negative
/// values. Percentages have a semantic bound, so a >100% claim CLAMPS (it is
/// a lie, not an outlier); latency has no bound, so an absurd-but-finite
/// claim (1e308 ms/IO) is REJECTED above a sanity ceiling — clamping would
/// still poison the average with the ceiling value.

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::detail {

/// Heartbeat status-tag keys carrying the A4 device perf sample. The agent
/// emits these (agents/core heartbeat, dex_disable-gated); the server side
/// must never spell them inline.
inline constexpr const char* kPerfTagCpuPct = "yuzu.perf_cpu_pct";
inline constexpr const char* kPerfTagCommitPct = "yuzu.perf_commit_pct";
inline constexpr const char* kPerfTagDiskLatMs = "yuzu.perf_disk_lat_ms";

/// Beyond-absurd per-IO latency ceiling: 1000 s per IO.
inline constexpr double kPerfMaxSaneLatMs = 1.0e6;

/// Parse one agent-supplied numeric tag value. `clamp_hi > 0` clamps the
/// accepted value (percentages); `reject_above` drops absurd-but-finite
/// claims (latency). Returns nullopt on empty/garbage/non-finite/negative/
/// rejected input — the caller must treat that as "did not report", never 0.
inline std::optional<double> parse_perf_tag(const std::string& s, double clamp_hi,
                                            double reject_above) {
    if (s.empty() || s.size() > 32)
        return std::nullopt;
    try {
        const double v = std::stod(s);
        if (std::isfinite(v) && v >= 0.0 && v <= reject_above)
            return clamp_hi > 0.0 ? (std::min)(v, clamp_hi) : v;
    } catch (...) {}
    return std::nullopt;
}

inline std::optional<double> parse_perf_cpu_pct(const std::string& s) {
    return parse_perf_tag(s, 100.0, 1.0e6);
}
inline std::optional<double> parse_perf_commit_pct(const std::string& s) {
    return parse_perf_tag(s, 100.0, 1.0e6);
}
inline std::optional<double> parse_perf_disk_lat_ms(const std::string& s) {
    return parse_perf_tag(s, 0.0, kPerfMaxSaneLatMs);
}

/// True nearest-rank percentile: index ceil(p·n)−1 into a SORTED, non-empty
/// vector. floor((n−1)·p) looks similar but under-reports high percentiles in
/// small fleets (n=2 → p90 = the MIN) — the A4 grill fix, pinned by tests.
inline double nearest_rank(const std::vector<double>& sorted_vals, double p) {
    const auto n = sorted_vals.size();
    const auto idx = static_cast<std::size_t>(std::ceil(p * static_cast<double>(n)));
    return sorted_vals[(std::min)(idx == 0 ? 0 : idx - 1, n - 1)];
}

} // namespace yuzu::server::detail
