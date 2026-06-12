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

#include <httplib.h>

#include <cstdint>
#include <functional>
#include <optional>
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
};

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
                                         const std::string& since, int window_days,
                                         DexFleet fleet);

/// Catalogue View 1 — the 13 family cards (mockup dex-catalogue.html), each a drill
/// into its family. Reuses dex_signal_summary + dex_signal_groups. Pure + free.
std::string render_dex_catalogue_fragment(const GuaranteedStateStore* store,
                                          const std::string& since, int window_days);

/// Catalogue View 2 — one family's signals (visibility contract: every catalogued
/// type, quiet ones muted). `group_name` is allowlisted against dex_signal_groups().
std::string render_dex_catalogue_group_fragment(const GuaranteedStateStore* store,
                                                const std::string& since, int window_days,
                                                const std::string& group_name);

/// Catalogue View 3 — one signal type's drill-down (subjects, OS split, devices,
/// trend), over the generic per-obs_type read-model. `obs_type` is SQL-bound +
/// HTML-escaped; cross-OS captions are derived live (no stale coverage counts).
std::string render_dex_catalogue_signal_fragment(const GuaranteedStateStore* store,
                                                 const std::string& since, int window_days,
                                                 const std::string& obs_type);

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
                                    const std::string& process_name, const std::string& window);

/// Per-device drill-down fragment for `agent_id` — the unified multi-signal
/// history (closes the deferred UP-4: friendly labelled rows, not raw
/// __observation__ events). This is behavioral PII (which apps a person runs);
/// the route gates it on Read and audit-logs each open. `window` is the selector
/// TOKEN (window-scoped to match the linking overview row). Pure + free so it is
/// unit-testable directly.
std::string render_dex_device_fragment(const GuaranteedStateStore* store,
                                       const std::string& agent_id, const std::string& window);

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

/// DEX routes — /dex (page shell) + /fragments/dex/overview (HTMX fragment).
class DexRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;

    /// Supplies the cross-store fleet denominator (avoids an AgentRegistry
    /// incomplete-type dep — same callback trick GuardianRoutes uses for agents
    /// JSON). May be empty → rates degrade to the "no data" state.
    using FleetFn = std::function<DexFleet()>;

    /// Audit hook — used to log per-device drill-down opens (behavioral PII).
    /// May be empty (audit then degrades to a no-op).
    using AuditFn = std::function<void(const httplib::Request&, const std::string& action,
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

    /// Register the DEX routes. The page shell is auth-only static chrome; the
    /// data-bearing fragments gate on GuaranteedState:Read (same securable as the
    /// Guardian read surface — a dedicated DEX:Read perm is deferred). `store` may
    /// be null (fragments render the no-data placeholder); `fleet_fn`/`audit_fn`/
    /// `dispatch_fn`/`responses_fn` may be empty (the device perf panel then
    /// degrades to an honest "unavailable" note).
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                         GuaranteedStateStore* store, FleetFn fleet_fn, AuditFn audit_fn,
                         DispatchFn dispatch_fn = {}, ResponsesFn responses_fn = {});

    /// HttpRouteSink overload — same registration against the polymorphic seam so
    /// the handlers are unit-testable in-process via TestRouteSink (no httplib
    /// acceptor; the #438 TSan trap). The httplib::Server& overload wraps + delegates.
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                         GuaranteedStateStore* store, FleetFn fleet_fn, AuditFn audit_fn,
                         DispatchFn dispatch_fn = {}, ResponsesFn responses_fn = {});

private:
    AuthFn auth_fn_;
    PermFn perm_fn_;
    GuaranteedStateStore* store_{};
    FleetFn fleet_fn_;
    AuditFn audit_fn_;
    DispatchFn dispatch_fn_;
    ResponsesFn responses_fn_;
};

} // namespace yuzu::server
