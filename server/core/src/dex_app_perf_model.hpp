#pragma once

/// @file dex_app_perf_model.hpp
/// Slice-2 READ model for DEX app-perf-over-time — the ONE pure transform that
/// turns stored B2 (`AppPerfFleetStore`) rows into the fleet-trend shape the
/// REST endpoint, the MCP tool, and (later) the dashboard all render. Putting
/// the mean + percentile derivation here, not in each handler, is what keeps the
/// three surfaces from disagreeing (the same reason `dex_perf_model.hpp` exists
/// for the heartbeat-now surface).
///
/// This realises the "F2b retained series" the heartbeat-now model deferred
/// until the Postgres store landed (see `dex_perf_model.hpp` header) — it reads
/// the retained B1/B2 substrate rather than render-time heartbeat state.
///
/// Honesty rules carried from the rest of DEX:
///   - a percentile that falls in the OPEN top histogram bucket is a FLOOR, not
///     an exact value (`HistPctile::lower_bound`) — render "≥ value", never the
///     boundary as if exact;
///   - a row stamped under a different histogram scheme than the running
///     `kAppPerfHistVersion` has its percentiles WITHHELD (`hist_stale`), never
///     reinterpreted under the current buckets;
///   - the exact fleet mean (`cpu_sum/device_count`) and exact maxima are always
///     carried alongside the bucket-resolution percentiles for callers that need
///     a precise number.

#include "app_perf_fleet_store.hpp" // AppPerfFleetRow, AppPerfAppSummary
#include "app_perf_hist.hpp"        // bucket scheme + kAppPerfHistVersion

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

/// A percentile read off a fixed-bucket histogram. `value` is the LOWER EDGE of
/// the bucket the percentile falls in (bucket-resolution approximation, not an
/// exact quantile). `lower_bound` is true iff that bucket is the OPEN top bucket
/// (`[last_boundary, +∞)`) — then `value` is a floor and must render "≥ value".
struct HistPctile {
    double value{0.0};
    bool lower_bound{false};
};

/// PURE: the p-th percentile (p in [0,1]) of a fixed-bucket histogram, by the
/// same nearest-rank DIRECTION as `detail::nearest_rank` (the quantile reading,
/// p → value) so the two perf surfaces share one convention. `boundaries` are
/// the N half-open `[lo, hi)` cut points (→ N+1 buckets); `hist` is the per-bucket
/// counts and MUST have `boundaries.size() + 1` entries. Returns `std::nullopt`
/// when the population is empty OR `hist`/`boundaries` sizes disagree (a corrupt
/// or wrong-scheme row — defence-in-depth beneath the caller's `hist_version`
/// check). WS callers pass their byte boundaries widened to double (≤ 8 GiB is
/// exact in double).
[[nodiscard]] std::optional<HistPctile>
percentile_from_hist(const std::vector<std::int64_t>& hist, const std::vector<double>& boundaries,
                     double p);

/// One point of a fleet app-perf trend: a single `(version, day)` B2 row reduced
/// to exact means/maxima + bucket-resolution p50/p95. `hist_stale` flags a row
/// whose stored `hist_version` != `kAppPerfHistVersion` — its percentiles are
/// withheld (all four `std::nullopt`), the exact mean/max still stand.
struct AppPerfTrendPoint {
    std::string version;
    std::int64_t day{0};
    std::int64_t device_count{0};
    double cpu_mean{0.0}; ///< exact fleet mean of per-device daily CPU% averages
    double cpu_max{0.0};  ///< exact fleet max of per-device daily CPU% averages
    std::optional<HistPctile> cpu_p50;
    std::optional<HistPctile> cpu_p95;
    std::int64_t ws_mean{0}; ///< exact fleet mean of per-device daily working-set bytes
    std::int64_t ws_max{0};
    std::optional<HistPctile> ws_p50;
    std::optional<HistPctile> ws_p95;
    bool hist_stale{false};
};

/// PURE: reduce retained B2 rows (as returned by `get_app_fleet_perf`, ordered
/// `(version, day)`) to trend points, one per row. The single place the fleet
/// mean + percentile + `hist_version` gate is applied, so REST/MCP/UI cannot
/// drift. Rows with `device_count <= 0` yield zero means (never a divide).
[[nodiscard]] std::vector<AppPerfTrendPoint>
app_perf_fleet_trend(const std::vector<AppPerfFleetRow>& rows);

// ── Provider seams (wired in server.cpp over the B1/B2 stores) ────────────────
//
// One bundle threaded once through the REST + MCP registrars covers the whole
// app-perf read family. The fleet + picker seams ship in this slice; the
// per-device drill (audited) and the management-group roll-up (an ADR-0012
// cross-store query owner) land in later sub-slices and get their own seams
// here, so the bundle param never has to change again.

/// B2 fleet trend for one app (`version` empty = all versions). Mirrors
/// `AppPerfFleetStore::get_app_fleet_perf`: nullopt = degrade, empty = no rows.
using AppPerfFleetFn = std::function<std::optional<std::vector<AppPerfFleetRow>>(
    std::string_view app_name, std::string_view version)>;

/// B2 distinct-app picker. Mirrors `AppPerfFleetStore::list_apps`: nullopt =
/// degrade; `truncated` (out-param) set when the cap clipped the list.
using AppPerfAppListFn =
    std::function<std::optional<std::vector<AppPerfAppSummary>>(bool& truncated)>;

struct AppPerfProviders {
    AppPerfFleetFn fleet;
    AppPerfAppListFn apps;
};

} // namespace yuzu::server
