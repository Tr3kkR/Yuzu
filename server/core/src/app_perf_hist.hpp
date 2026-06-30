#pragma once

/// @file app_perf_hist.hpp
/// THE single source of truth for the DEX app-perf-over-time histogram scheme —
/// the frozen, half-open `[lo, hi)` bucket boundaries and the scheme version
/// stamped into every B2 (`AppPerfFleetStore`) row.
///
/// Deliberately a tiny, dependency-free header so BOTH sides share ONE
/// definition and can never drift:
///   - the WRITER `AppPerfRollup` builds the `COUNT(*) FILTER (…)` histogram SQL
///     from these boundaries (and keeps a thin public forwarder for its tests);
///   - the READER `dex_app_perf_model` interprets stored counts back into
///     percentiles against the SAME boundaries.
/// It carries ONLY the constants — no percentile / UI / read-model helpers — so
/// the writer never pulls a reader dependency (the reason this is its own header
/// rather than living in `dex_app_perf_model.hpp`).
///
/// ── Immutability contract (read before touching a boundary) ──
/// B2 is a 180-day store. A boundary is IMMUTABLE for the life of a stored row:
/// changing one mid-retention would silently mix two incompatible schemes under
/// the same counts. A boundary change is therefore a `kAppPerfHistVersion` bump,
/// after which readers MUST filter/branch on a row's stored `hist_version`
/// (`AppPerfFleetRow::hist_version`) rather than reinterpret old counts under the
/// new scheme. N boundaries → N+1 half-open buckets:
///   bucket 0     = `[0, b[0])`        (the metric floor — CPU% and WS bytes are ≥0)
///   bucket k     = `[b[k-1], b[k])`   for 1 ≤ k < N
///   bucket N     = `[b[N-1], +∞)`     (the OPEN top bucket — a percentile here is
///                                       a floor, never an exact value)

#include <cstdint>
#include <vector>

namespace yuzu::server {

/// CPU buckets — share-of-total-capacity percent, low-end weighted (most apps
/// idle). 11 boundaries → 12 buckets.
inline const std::vector<double>& app_perf_cpu_buckets() {
    static const std::vector<double> kCpu = {0.5, 1, 2, 3, 5, 8, 12, 20, 30, 50, 75};
    return kCpu;
}

/// Working-set buckets — bytes, log-scale 32 MiB … 8 GiB. 9 boundaries → 10 buckets.
inline const std::vector<std::int64_t>& app_perf_ws_buckets() {
    static const std::vector<std::int64_t> kWs = {
        33554432,   67108864,   134217728,  268435456, 536870912,
        1073741824, 2147483648, 4294967296, 8589934592};
    return kWs;
}

/// The scheme version stamped into every B2 row. Bump ON any boundary change.
inline constexpr int kAppPerfHistVersion = 1;

} // namespace yuzu::server
