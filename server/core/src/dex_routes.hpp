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

#include <functional>
#include <optional>
#include <string>

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

    /// Register the DEX routes. The page shell is auth-only static chrome; the
    /// data-bearing fragments gate on GuaranteedState:Read (same securable as the
    /// Guardian read surface — a dedicated DEX:Read perm is deferred). `store` may
    /// be null (fragments render the no-data placeholder); `fleet_fn`/`audit_fn`
    /// may be empty.
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                         GuaranteedStateStore* store, FleetFn fleet_fn, AuditFn audit_fn);

    /// HttpRouteSink overload — same registration against the polymorphic seam so
    /// the handlers are unit-testable in-process via TestRouteSink (no httplib
    /// acceptor; the #438 TSan trap). The httplib::Server& overload wraps + delegates.
    void register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                         GuaranteedStateStore* store, FleetFn fleet_fn, AuditFn audit_fn);

private:
    AuthFn auth_fn_;
    PermFn perm_fn_;
    GuaranteedStateStore* store_{};
    FleetFn fleet_fn_;
    AuditFn audit_fn_;
};

} // namespace yuzu::server
