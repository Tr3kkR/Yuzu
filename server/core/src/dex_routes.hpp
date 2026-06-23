#pragma once

/// @file dex_routes.hpp
/// DEX (Digital Employee Experience) dashboard — the RELIABILITY lens over the
/// 103-signal catalogue (crashes, hangs, service failures, device stability,
/// boot/resume performance, network/identity/security/update/print signals;
/// docs/dex-signal-catalog.md).
/// A capability-limited READ MODEL over the one Guardian event store
/// (guardian_observations projection): it reinterprets ruleless observations as
/// fleet reliability. Separate from /guardian (which authors + enforces); this
/// surface is read-only. The headline rate stays the industry-standard
/// crash-free-devices number; other signals get their own panels.
///
/// Product UI: HTMX, server-rendered, dark-theme only. Reuses the shared
/// full-page shell (guardian_page_ui.cpp kGuardianDetailPageHtml) + its `.gp-*`
/// component CSS — same chrome as the Guardian detail pages.
///
/// NO MOCK DATA (Dave, 2026-06-09): every panel renders real aggregations from
/// GuaranteedStateStore or an explicit "no data" placeholder — never fabricated
/// or sample values. The crash-free-% / per-1k-device-days RATES (which need the
/// cross-store fleet-size denominator from the agent registry) are a follow-up
/// increment; this overview ships the absolute, store-backed facts.

#include <yuzu/server/auth.hpp>

#include "dex_perf_model.hpp"

#include <httplib.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

class GuaranteedStateStore;
class HttpRouteSink;

/// Fleet-size denominator for the DEX rates — sourced cross-store from the agent
/// registry (NOT the crash store). `windows_online` is the coverage-honest
/// denominator (only the OS with a crash collector today); `total_online` is
/// context. A struct (not a registry dep) keeps render pure + testable.
struct DexFleet {
    int64_t windows_online{0};
    int64_t total_online{0};
    /// Distinct OS tokens (lowercased: "windows"/"linux"/"darwin") of the agents
    /// CONNECTED right now — the coverage scope for the Catalogue's "All connected"
    /// lens. Empty when nothing is connected.
    std::vector<std::string> connected_os;
    /// CONNECTED agents as (agent_id, normalized-os: "windows"/"linux"/"macos").
    /// The Overview computes a per-device DEX score for each (window-respecting) to
    /// build the experience distribution AND groups by os for the segment breakdown.
    /// Kept here (not pre-scored) so only the Overview pays the per-device cost.
    std::vector<std::pair<std::string, std::string>> connected_agents;
};

/// One display family of the server-side signal catalogue. PUBLIC since F1:
/// the Settings → DEX alerts panel renders the routable-type list from this
/// same single source of truth (the /dex Catalogue's grouping).
struct DexSignalGroup {
    const char* name;
    std::vector<const char*> types;
};

/// The catalogued signal types, grouped for display — the server-side mirror
/// of the agent catalogue (keep in sync; the paired drift-net tests bite).
const std::vector<DexSignalGroup>& dex_signal_groups();

/// Total catalogued display types (sum over the groups).
std::size_t dex_catalogued_type_count();

/// Friendly display label for an obs_type; unknown types fall back to the
/// HTML-escaped raw obs_type (forward-compatible, render-safe).
std::string dex_signal_label(const std::string& obs_type);

/// Shared window-selector resolvers — the single source of truth for how both the
/// dashboard fragments and the `/api/v1/dex/*` REST surface interpret the window
/// token. `dex_window_to_days` maps "24h"/"7d"/"30d"/"all" (anything else → 7d) to
/// a day count (0 = "all"); `dex_iso_since` turns that day count into an ISO-8601
/// UTC cutoff ("" when days<=0 = "all"). Thin wrappers over the dashboard's
/// internal helpers so REST and HTMX can never drift on the window vocabulary.
int dex_window_to_days(const std::string& window);
std::string dex_iso_since(int days);

/// Render the DEX overview fragment (the content hx-get'd into the page shell):
/// headline rate + coverage + crash facts + top apps / modules / devices + per-OS
/// + trend, all from the crash projection. `since` is an ISO-8601 cutoff
/// ('' = all retained); `window_days` is the window length used for the
/// per-1k-device-days denominator (0 = "all", which suppresses that rate as
/// ill-defined). `fleet` supplies the cross-store denominator. `store` may be null
/// (renders the no-data placeholder). Pure + free so it is unit-testable directly.
std::string render_dex_overview_fragment(const GuaranteedStateStore* store,
                                         const std::string& since, int window_days, DexFleet fleet,
                                         const std::set<std::string>* visible = nullptr);

/// Per-obs_type platform coverage: which OSes collect this signal type today
/// (windows = the whole catalogue; linux/macos = the collector subsets). The thin
/// explicit map the Catalogue's coverage view reads; keep in sync with the agent
/// collectors (a schema↔catalogue cross-check test guards drift — H2/G9 style).
std::vector<std::string> dex_obs_platforms(const std::string& obs_type);

/// Per-device DEX experience score (0–100) — the per-device projection of the
/// canonical severity-weighted composite (100 − Σ family deductions over the
/// device's OWN observations; benign families don't deduct, events gently scaled).
/// Cheap server-side read (dex_device_signal_summary); returns -1 when `store` is
/// null. The fleet-scale path (heartbeat rollup) is a follow-up.
int dex_device_score(const GuaranteedStateStore* store, const std::string& agent_id,
                     const std::string& since);

/// Catalogue View 1 — the 13 family cards (mockup dex-catalogue-coverage.html).
/// COVERAGE-first: a family lights when a CONNECTED platform (scoped by `os_filter`:
/// "all"|"windows"|"linux"|"macos") collects one of its types — not merely when a
/// signal fired. Each card carries a roll-up health score (100 − the family's
/// dex_compute_health deduction). `fleet.connected_os` is the "all" scope. Pure + free.
std::string render_dex_catalogue_fragment(const GuaranteedStateStore* store,
                                          const std::string& since, int window_days,
                                          const DexFleet& fleet, const std::string& os_filter);

/// Catalogue View 2 — one family's signals. COVERAGE-first, like the grid: every
/// catalogued type is shown, marked MONITORED (a connected platform in scope
/// collects it — lit even at zero events) or NOT COLLECTED (no platform in view
/// emits it — dimmed, never read as "healthy"). `group_name` is allowlisted
/// against dex_signal_groups(); `fleet.connected_os` is the "all" coverage scope;
/// `os_filter` ("all"|"windows"|"linux"|"macos") is the OS lens — shown as in-view
/// chips so it both persists across the drill AND is changeable in place.
std::string render_dex_catalogue_group_fragment(const GuaranteedStateStore* store,
                                                const std::string& since, int window_days,
                                                const std::string& group_name,
                                                const DexFleet& fleet,
                                                const std::string& os_filter = "all");

/// Catalogue View 3 — one signal type's drill-down (subjects, OS split, devices,
/// trend), over the generic per-obs_type read-model. `obs_type` is SQL-bound +
/// HTML-escaped; cross-OS captions are derived live (no stale coverage counts).
/// `os_filter` is carried only to restore the family grid's OS lens on the back-link.
std::string render_dex_catalogue_signal_fragment(const GuaranteedStateStore* store,
                                                 const std::string& since, int window_days,
                                                 const std::string& obs_type,
                                                 const std::string& os_filter = "all",
                                                 const std::set<std::string>* visible = nullptr);

/// Health score — the derived/SECONDARY composite (score = 100 − Σ weighted
/// per-family deductions; every deduction traces to a measured rate). `weighting`
/// is one of the allowlisted presets (default/stability/productivity/security);
/// `fleet` supplies the reporting-agent denominator (score suppressed when 0).
std::string render_dex_health_fragment(const GuaranteedStateStore* store, const std::string& since,
                                       int window_days, DexFleet fleet,
                                       const std::string& weighting);

/// Trends — cross-OS comparison (scope derived live from dex_os_signal_scope) +
/// per-family small-multiples + a family×day activity heatmap (within-row scaled).
std::string render_dex_trends_fragment(const GuaranteedStateStore* store, const std::string& since,
                                       int window_days, DexFleet fleet);

/// Per-app drill-down fragment for `process_name` — crash + hang blast radius
/// (devices) + faulting modules + exception codes + affected devices. `window`
/// is the selector TOKEN ("24h"/"7d"/"30d"/"all"; default-resolved like the
/// overview) so the drill-down is scoped to the SAME window as the row that
/// linked here — counts match (governance C-S1/UP-11). Pure + free so it is
/// unit-testable directly against a seeded store.
std::string render_dex_app_fragment(const GuaranteedStateStore* store,
                                    const std::string& process_name, const std::string& window,
                                    const std::set<std::string>* visible = nullptr);

/// Per-device drill-down fragment for `agent_id` — the unified multi-signal
/// history (closes the deferred UP-4: friendly labelled rows, not raw
/// __observation__ events). This is behavioral PII (which apps a person runs);
/// the route gates it on Read and audit-logs each open. `window` is the selector
/// TOKEN (window-scoped to match the linking overview row). Pure + free so it is
/// unit-testable directly. `perf_snap` (PR2, may be null) feeds the vs-fleet/
/// cohort percentile strips; null omits the strips section (feature unwired).
std::string render_dex_device_fragment(const GuaranteedStateStore* store,
                                       const std::string& agent_id, const std::string& window,
                                       const DexPerfSnapshot* perf_snap = nullptr);

// ── A4: device perf sparklines (federated TAR query) ────────────────────────

/// One agent's stored response to a dispatched command — the narrow seam the
/// device perf panel needs from the ResponseStore (a struct, not a store dep,
/// keeps DexRoutes decoupled and the routes testable with a fake).
struct DexAgentResponse {
    std::string agent_id;
    int status{0}; ///< CommandResponse::Status enum value (0=RUNNING, 1=SUCCESS, 2=FAILURE, …)
    std::string output;
    std::string error_detail;
};

/// One parsed hourly perf point out of the device's TAR edge warehouse
/// (`$Perf_Hourly` — see agents/plugins/tar perf tier, BRD A1).
struct DexPerfPoint {
    std::int64_t hour_ts{0};
    double cpu_avg{0.0};      ///< % busy, clamped 0..100
    double mem_avg{0.0};      ///< % physical used, clamped 0..100
    double disk_lat_ms{0.0};  ///< worse of read/write avg per-IO service time
};

/// PURE: parse the `tar.sql` pipe-delimited output (`__schema__|col|…` header +
/// data rows) into perf points, chronologically sorted. Defensive against
/// agent-controlled bytes: columns are located by NAME from the schema line,
/// non-finite/negative numbers are rejected per-field, malformed rows are
/// skipped, and at most 200 rows are read. Returns empty on an `error|…`
/// payload or a missing schema line.
std::vector<DexPerfPoint> parse_dex_perf_output(const std::string& output);

/// PURE: render the device-performance panel (per-metric sparkline SVG +
/// now/min/max facts) from parsed points. Empty input renders the honest
/// "no history" note. Server-rendered SVG — no JS, CSP-safe.
std::string render_dex_perf_panel(const std::vector<DexPerfPoint>& points);

// ── F2a PR2: device drill perf extensions ────────────────────────────────────

/// One per-application row out of the device's `$ProcPerf_Hourly` edge tier
/// (A2 — names only, NEVER command lines; opt-in `procperf_enabled`).
struct DexProcPerfRow {
    std::string name; ///< image name — agent bytes, HTML-escape at render
    std::int64_t samples{0};
    std::int64_t instances_max{0};
    double cpu_avg{0.0}; ///< % share of total capacity, clamped 0..100
    double cpu_max{0.0};
    double ws_avg_bytes{0.0};
    double ws_max_bytes{0.0};
    std::int64_t hours{0}; ///< distinct hourly rollups the app appeared in
};

/// PURE: parse the canned per-app `tar.sql` output (same defensive contract as
/// parse_dex_perf_output: columns by NAME from the `__schema__|…` line,
/// non-finite/negative rejected per-field, malformed rows skipped, ≤100 rows,
/// empty on `error|…`). cpu percentages clamp to 0..100 (a lie, not an
/// outlier); working-set bytes above 1 PiB are rejected as forged.
std::vector<DexProcPerfRow> parse_dex_procperf_output(const std::string& output);

/// PURE: render the per-application panel from parsed rows. App names link to
/// the existing app reliability drill (per-app perf ↔ per-app crashes cross-
/// link). Empty input renders the SOFT truthful empty state: the device's
/// read-only query surface deliberately hides plugin config, so the server
/// cannot distinguish "procperf disabled (the default)" from "enabled, no
/// rollup yet" — the message says both honestly (the crisp distinction needs
/// the tar-plugin source_state meta table, a filed follow-up).
std::string render_dex_procperf_panel(const std::vector<DexProcPerfRow>& rows,
                                      const std::string& window);

/// PURE: render the "this device vs fleet & cohort" percentile strips —
/// current heartbeat values against the CURRENT registry distributions
/// (now-vs-now; no retained history). Cohort comparison is withheld below the
/// kDexCohortFloor with an honest caption; a non-reporting device renders an
/// honest note, never empty bars.
std::string render_dex_device_perf_context(const DexPerfDeviceContext& ctx,
                                           const std::string& cohort_key,
                                           const std::string& window);

// ── F2a: fleet Performance tab (now-view over registry heartbeat state) ─────

/// PURE: the /fragments/dex/perf content — fleet-now cards (same stats as the
/// yuzu_fleet_perf_* gauges, via the shared dex_perf_rules) + the cohort
/// benchmarking tables for `snap.cohort_key`. Every aggregate is a drill: the
/// metric cards open the worst-devices list, the Reporting card opens the
/// not-reporting list, cohort rows open their device list. NO window chips —
/// the page is a now-view (trend charts are F2b, Postgres-gated).
std::string render_dex_perf_fragment(const DexPerfSnapshot& snap, int window_days);

/// F2c: the A-vs-B cohort comparison result (the table the two cohort pickers
/// on the Performance tab load into). Renders each metric's p50 for both
/// cohorts + the delta (A relative to B, B the baseline), honouring
/// found/suppressed; pure render over dex_perf_cohort_diff.
std::string render_dex_perf_cohort_diff_fragment(const DexPerfSnapshot& snap,
                                                 const std::string& cohort_a,
                                                 const std::string& cohort_b, int window_days);

/// PURE: the /fragments/dex/perf/devices drill — the ONE device list serving
/// every Performance-page drill (worst-by-metric / not-reporting / cohort
/// membership). Rows link to the per-device drill-down.
std::string render_dex_perf_devices_fragment(const DexPerfSnapshot& snap, DexPerfMetric metric,
                                             bool not_reporting,
                                             const std::optional<std::string>& cohort_filter,
                                             int limit, int window_days,
                                             const std::set<std::string>* visible = nullptr);

/// DEX routes — /dex (page shell) + /fragments/dex/overview (HTMX fragment).
class DexRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;

    /// Per-device tier + management-group scope gate (wraps
    /// require_scoped_permission). Gates every PER-DEVICE drill (`/fragments/dex/device`
    /// + `/perf` + `/procperf`) so an operator can only open a device inside their
    /// management scope — the same gate the `/device` routes use. May be empty → the
    /// per-device routes fall back to the global `perm_fn` gate (legacy posture).
    using ScopedPermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation,
                           const std::string& agent_id)>;

    /// Resolve the set of agent_ids VISIBLE to `username`, following the SAME policy
    /// as `/api/agents` (`get_visible_agents_json`): returns `std::nullopt` when the
    /// caller sees the whole fleet (global Infrastructure:Read OR RBAC disabled), else
    /// the set of agent_ids in the caller's management groups. Used to filter the
    /// device-id-rendering lists so an out-of-scope operator can't enumerate other
    /// teams' device ids. MUST replicate the global-read branch — a bare
    /// `get_visible_agents` would blank an admin who is in no management group. May be
    /// empty → no list filtering (legacy posture).
    using VisibleSetFn =
        std::function<std::optional<std::set<std::string>>(const std::string& username)>;

    /// Supplies the cross-store fleet denominator (avoids an AgentRegistry
    /// incomplete-type dep — same callback trick GuardianRoutes uses for agents
    /// JSON). May be empty → rates degrade to the "no data" state.
    using FleetFn = std::function<DexFleet()>;

    /// Audit hook — used to log per-device drill-down opens (behavioral PII).
    /// May be empty (audit then degrades to a no-op). **Bool-returning** (was
    /// void pre-#1549 review): returns true iff the event was persisted (or the
    /// deployment runs audit-off — both look the same to a caller), false on a
    /// silent persistence failure. PII-emitting drill-downs capture this and
    /// surface the gap to the operator (Sec-Audit-Failed header) so a dropped
    /// works-council/SOC 2 evidence row is visible. The dashboard is an HTML/HTMX
    /// surface served to a browser, so on a failure it STILL renders the fragment
    /// (a transient audit hiccup must not blank the dashboard) but flags the gap —
    /// unlike the strict-fail-closed REST per-device endpoints.
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    /// A4: dispatch a plugin command to specific agents (same 5-param shape as
    /// DashboardRoutes' DispatchFn). Used ONLY for the canned `tar.sql` device
    /// perf query. May be empty → the perf panel renders "unavailable".
    using DispatchFn = std::function<std::pair<std::string, int>(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters)>;

    /// A4: read the stored responses for a command_id (narrow ResponseStore
    /// seam). May be empty → the perf panel renders "unavailable".
    using ResponsesFn =
        std::function<std::vector<DexAgentResponse>(const std::string& command_id)>;

    /// F2a: resolve the fleet perf snapshot for a cohort tag key (assembled in
    /// server.cpp from AgentHealthStore + AgentRegistry + TagStore). May be
    /// empty → the Performance tab renders an honest "unavailable" placeholder.
    using PerfFn = DexPerfFn;

    /// Register the DEX routes. The page shell is auth-only static chrome; the
    /// data-bearing fragments gate on GuaranteedState:Read (same securable as the
    /// Guardian read surface — a dedicated DEX:Read perm is deferred). `store` may
    /// be null (fragments render the no-data placeholder); `fleet_fn`/`audit_fn`/
    /// `dispatch_fn`/`responses_fn` may be empty (the device perf panel then
    /// degrades to an honest "unavailable" note).
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                         GuaranteedStateStore* store, FleetFn fleet_fn, AuditFn audit_fn,
                         DispatchFn dispatch_fn = {}, ResponsesFn responses_fn = {},
                         PerfFn perf_fn = {}, ScopedPermFn scoped_perm_fn = {},
                         VisibleSetFn visible_set_fn = {});

    /// HttpRouteSink overload — same registration against the polymorphic seam so
    /// the handlers are unit-testable in-process via TestRouteSink (no httplib
    /// acceptor; the #438 TSan trap). The httplib::Server& overload wraps + delegates.
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                         GuaranteedStateStore* store, FleetFn fleet_fn, AuditFn audit_fn,
                         DispatchFn dispatch_fn = {}, ResponsesFn responses_fn = {},
                         PerfFn perf_fn = {}, ScopedPermFn scoped_perm_fn = {},
                         VisibleSetFn visible_set_fn = {});

private:
    AuthFn auth_fn_;
    PermFn perm_fn_;
    ScopedPermFn scoped_perm_fn_;
    VisibleSetFn visible_set_fn_;
    GuaranteedStateStore* store_{};
    FleetFn fleet_fn_;
    AuditFn audit_fn_;
    DispatchFn dispatch_fn_;
    ResponsesFn responses_fn_;
    PerfFn perf_fn_;
};

} // namespace yuzu::server
