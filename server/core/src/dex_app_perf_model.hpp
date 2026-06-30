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

#include "app_perf_compare.hpp"     // AppPerfCohortRow (the VERIFY compare input shape)
#include "app_perf_daily_store.hpp" // AppPerfDailyRow (per-device drill)
#include "app_perf_fleet_store.hpp" // AppPerfFleetRow, AppPerfAppSummary
#include "app_perf_hist.hpp"        // bucket scheme + kAppPerfHistVersion

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

/// Max length of an operator-supplied app/version/group identifier across every
/// app-perf surface (REST, MCP, dashboard) — one cap so the surfaces agree.
inline constexpr std::size_t kAppPerfParamCap = 512;

/// PURE: validate an operator-supplied app/version/group identifier before it
/// reaches a store binding. Rejects oversize (> `kAppPerfParamCap`) or any C0
/// control byte INCLUDING NUL — a NUL truncates a libpq text parameter, so the
/// store would silently query a DIFFERENT key than supplied (a cross-surface
/// semantic divergence, not injection — everything is bound). Does NOT reject
/// empty: `version=""` is the all-versions sentinel; callers reject an empty
/// `app`/`group_id` themselves. The ONE validator the three surfaces share so they
/// cannot drift on the accepted charset/cap.
[[nodiscard]] bool app_perf_param_valid(std::string_view s);

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
    /// Set by BOTH the fleet and group paths: this (version, day) point covered
    /// fewer than the statistical floor (`kDexCohortFloor`) of devices, so its stats
    /// are suppressed (means/percentiles cleared) and only `device_count` is honest.
    /// A sub-floor aggregate singles out one operator's behaviour even without an
    /// agent_id (works-council / GDPR singling-out), whether it is fleet-wide or a
    /// named-group slice — so the fleet path floors too, not just the group path.
    bool suppressed{false};
};

/// PURE: reduce retained B2 rows (as returned by `get_app_fleet_perf`, ordered
/// `(version, day)`) to trend points, one per row. The single place the fleet
/// mean + percentile + `hist_version` gate AND the `kDexCohortFloor` suppression
/// are applied, so REST/MCP/UI cannot drift. Rows with `device_count <= 0` yield
/// zero means (never a divide); rows with `device_count < kDexCohortFloor` are
/// suppressed (count only) — a sub-floor fleet aggregate singles out an operator.
[[nodiscard]] std::vector<AppPerfTrendPoint>
app_perf_fleet_trend(const std::vector<AppPerfFleetRow>& rows);

/// One application VERSION reduced across the window — the row the dashboard
/// per-version table renders. Built by `app_perf_version_summaries` from the
/// `(version, day)` trend points: the HEADLINE stats are the LATEST day present
/// (current state), and `cpu_series` is the chronological daily mean over the
/// window (the "over time" sparkline). Keeping the reduction pure + here (not in
/// the route) means the dashboard and any future summary surface agree.
struct AppPerfVersionSummary {
    std::string version;
    std::int64_t latest_day{0};   ///< most recent day present for this version
    std::int64_t device_count{0}; ///< latest day's distinct-device count (honest even when suppressed)
    std::int64_t day_count{0};    ///< days this version appears in the window
    bool suppressed{false};       ///< latest day sub-floor (group path) → stats withheld
    bool hist_stale{false};       ///< latest day stamped under a different histogram scheme
    double cpu_mean{0.0};         ///< latest day exact fleet/group mean CPU%
    double cpu_max{0.0};
    std::optional<HistPctile> cpu_p95;
    std::int64_t ws_mean{0};
    /// Chronological daily cpu_mean over NON-suppressed days — the sparkline.
    /// A cleared (suppressed) day is skipped, never plotted as a real 0.
    std::vector<double> cpu_series;
};

/// PURE: reduce `(version, day)` trend points (the output of
/// `app_perf_fleet_trend`/`app_perf_group_trend`, ordered `(version, day)`) to one
/// summary per version. The headline is the latest day; the sparkline series skips
/// suppressed days (a cleared mean is not a real 0). Versions are returned in
/// first-seen order. Robust to unsorted input: it groups by version key, the
/// headline picks the max day, and the sparkline series is sorted chronologically.
[[nodiscard]] std::vector<AppPerfVersionSummary>
app_perf_version_summaries(const std::vector<AppPerfTrendPoint>& points);

/// PURE: the GROUP variant — the same build + percentile + `hist_version` gate as
/// the fleet path, with the statistical-floor suppression applied at the caller's
/// `floor` (the dashboard/REST/MCP pass `kDexCohortFloor`). A management group is a
/// set of SPECIFIC devices, so a small-N group aggregate is de-facto individual
/// behaviour (works-council); any point with `device_count < floor` is marked
/// `suppressed` with its means/percentiles cleared (only the honest `device_count`
/// survives). Shares the build + floor helpers with `app_perf_fleet_trend`, so the
/// group and fleet percentile + suppression conventions are IDENTICAL.
[[nodiscard]] std::vector<AppPerfTrendPoint>
app_perf_group_trend(const std::vector<AppPerfFleetRow>& rows, std::int64_t floor);

// ── Per-device drill (B1, audited PII) ────────────────────────────────────────
//
// The single-device companion to the fleet/group trend. Reads the SAME B1 daily
// rows (`AppPerfDailyStore::get_agent_app_perf`) the audited per-device REST drill
// serializes raw, but reduces them for the dashboard table. Two deliberate
// differences from the fleet/group reductions: a single device has NO histogram
// (its daily averages ARE the series, so no bucket-resolution percentiles) and NO
// cohort floor (the per-device read is behind the `dex.device.app_perf.view` audit
// gate — there is no aggregate that could single an operator out). REST serves the
// raw rows; this reduction backs the dashboard "Application performance over time"
// panel. There is no MCP twin (the per-device drill's fail-closed audit contract
// cannot be expressed on MCP's set-and-proceed posture). It lives here, pure +
// testable, so a future aggregated device surface reuses it rather than re-deriving
// the numbers.

/// One application VERSION on a single device, reduced across the retained window.
/// The window aggregates are sample-weighted (so days with more 30 s samples weigh
/// more); the maxima are plain maxima; `cpu_series` is the chronological daily
/// `cpu_avg` — the "over time" sparkline.
struct AppPerfDeviceVersion {
    std::string version;            ///< canon version ("" = unknown)
    std::int64_t latest_day{0};     ///< most recent day present for this version
    std::int64_t day_count{0};      ///< distinct days this version appears in the window
    std::int64_t instances_max{0};  ///< peak concurrent process count over the window
    double cpu_avg{0.0};            ///< sample-weighted mean of daily cpu_avg over the window
    double cpu_max{0.0};            ///< max daily cpu_max over the window
    std::int64_t ws_avg{0};         ///< sample-weighted mean of daily ws_avg over the window
    std::int64_t ws_max{0};         ///< max daily ws_max over the window
    std::vector<double> cpu_series; ///< chronological daily cpu_avg — the sparkline
};

/// One application on a single device, grouping its versions. `peak_cpu_avg` is the
/// max window `cpu_avg` across the app's versions — it ranks the app in the table
/// (resource-significant first). `latest_day` is the most recent day across versions.
struct AppPerfDeviceApp {
    std::string app_name;
    std::int64_t latest_day{0};
    double peak_cpu_avg{0.0};
    std::vector<AppPerfDeviceVersion> versions; ///< newest-day first
};

/// PURE: reduce ONE device's retained B1 daily rows (as returned by
/// `AppPerfDailyStore::get_agent_app_perf`, ordered `(app_name, version, day)`) into
/// per-app/per-version window summaries for the device drill. Window means are
/// sample-weighted (`cpu_avg`/`ws_avg` weighted by `samples`); a window whose total
/// sample count is zero falls back to an unweighted mean so a malformed-but-present
/// row still shows an honest number rather than 0. Apps are ordered by peak window
/// `cpu_avg` desc (tiebreak `app_name` asc); versions within an app are newest-day
/// first. Robust to unsorted input (groups by key, sorts the series chronologically).
///
/// Precondition: `rows` are canon-merged as `AppPerfDailyStore::get_agent_app_perf`
/// returns them — every numeric finite, non-negative, and bounded (`samples` ≤
/// `kMaxSamples`, so the `int64` sample-weight sum cannot overflow), and unique on
/// `(app_name, version, day)`. Finiteness is load-bearing: the resource-ranking sort
/// compares `double cpu_avg`, which is a valid strict-weak order only for finite
/// values (a NaN would be `std::sort` UB); key-uniqueness keeps `day_count` an honest
/// distinct-day count. The store is the sole writer and enforces all of this on the
/// apply path; this pure fn does not re-validate.
[[nodiscard]] std::vector<AppPerfDeviceApp>
app_perf_device_summaries(const std::vector<AppPerfDailyRow>& rows);

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

/// B1 per-device drill: one device's retained daily rows across all its
/// resource-significant app-versions. Mirrors `AppPerfDailyStore::get_agent_app_perf`:
/// nullopt = degrade, empty = no rows. This carries PER-DEVICE behavioural PII —
/// its read surface is audited fail-closed, unlike the fleet/picker seams above.
using AppPerfDeviceFn =
    std::function<std::optional<std::vector<AppPerfDailyRow>>(std::string_view agent_id)>;

/// Management-group trend: the on-the-fly B1 aggregate (same `AppPerfFleetRow`
/// shape as B2, computed over the group's members for one app) for `group_id`.
/// `version` empty = all versions. nullopt = degrade (member resolution OR the
/// aggregate read failed); empty = the group has no members / no rows. The
/// provider resolves members then aggregates B1 — two bounded single-store reads
/// composed, never a held cross-store lease.
using AppPerfGroupFn = std::function<std::optional<std::vector<AppPerfFleetRow>>(
    std::string_view group_id, std::string_view app_name, std::string_view version)>;

/// What the `/auto` VERIFY cohort provider returns: the group's resolved member
/// count (so the surface reports cohort_size vs paired vs no-data) PLUS the raw B1
/// rows (`agent_id` preserved) for those members × app × the two compared
/// versions — the input the pure `build_comparison` engine pairs. A non-empty
/// `member_count` with empty `rows` = the cohort has members but no app-perf data
/// for those versions (→ the compare reads "insufficient", not a degrade).
struct CohortRead {
    std::int64_t member_count{0};
    std::vector<AppPerfCohortRow> rows;
    /// The B1 read hit the hard row cap — `rows` is incomplete AND may mis-pair a
    /// boundary machine (gov UP-1). The surface must present the comparison as
    /// unreliable when this is set, never as a silent undercount.
    bool truncated{false};
};

/// VERIFY: resolve `group_id`'s members, then read their raw B1 rows for
/// `app_name` restricted to the two versions. Composes `ManagementGroupStore::
/// get_members` and `AppPerfCohortReader` as two bounded single-store leases,
/// never one held across the other (ADR-0012 §1). The provider canonicalizes the
/// versions (so the SQL filter and the engine pairing share one key). nullopt =
/// degrade (member resolution OR the row read failed); empty member list →
/// member_count 0 + empty rows (a precondition value, not a degrade).
using AppPerfCohortFn = std::function<std::optional<CohortRead>(
    std::string_view group_id, std::string_view app_name, std::string_view baseline_version,
    std::string_view candidate_version)>;

struct AppPerfProviders {
    AppPerfFleetFn fleet;
    AppPerfAppListFn apps;
    AppPerfDeviceFn device;
    AppPerfGroupFn group;
    AppPerfCohortFn cohort; ///< VERIFY before/after compare (cohort-paired)
};

} // namespace yuzu::server
