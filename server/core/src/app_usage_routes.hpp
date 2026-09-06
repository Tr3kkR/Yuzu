#pragma once

/// @file app_usage_routes.hpp
/// `/api/v1/forensics/agents/{id}/app-usage` — the read surface for the
/// wave-7 PR7.2 `app_usage` daily-sync projection (AppUsageStore). Mirrors
/// SleRoutes (sle_routes.hpp) exactly: provider closures are injected
/// (store-decoupled) so the handler is unit-testable in-process via
/// TestRouteSink without a live Postgres — the InventoryRoutes / DexRoutes /
/// SleRoutes precedent (the #438 TSan trap). server.cpp binds the closure to
/// `AppUsageStore::get_agent_last_used`.
///
/// AUTH: single-agent read, gated on the Forensics securable (Forensics:Read)
/// via the SAME fail-closed scoped-gate shape SleRoutes takes (503 when the
/// gate is unwired — never a silent global read). Per-executable last-used
/// data is behavioural (what ran, when, how often) but carries no user
/// name/pid (the store has none), so it takes the app-perf-drill posture:
/// audited per access, same as the DEX per-device behavioural surfaces.
///
/// DEGRADE != EMPTY: the provider returns `std::nullopt` on a store/pool/query
/// degrade -> the route answers 503 (A4 envelope, retryable), NEVER a silent
/// empty 200. An empty vector is a genuine "no rows for this agent".

#include "app_usage_store.hpp" // AgentLastUsedRow

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

class HttpRouteSink;

/// `/api/v1/forensics/agents/{id}/app-usage` in-server read route. Providers
/// are injected closures; see the file header for the auth posture.
class AppUsageRoutes {
public:
    /// Per-device tier + management-group scope gate (ancestor-aware; writes
    /// 401/403/503). Wraps `require_scoped_permission`; wired fail-closed,
    /// the SleRoutes ScopedPermFn shape.
    using ScopedPermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation,
                           const std::string& agent_id)>;

    /// One agent's per-executable last-used rows (the `app-usage` projection —
    /// `AppUsageStore::get_agent_last_used`). `std::nullopt` on a degrade
    /// (-> 503). An empty value = the agent genuinely has no rows.
    using AgentLastUsedFn =
        std::function<std::optional<std::vector<AgentLastUsedRow>>(const std::string& agent_id)>;

    /// who/when/what audit sink (bool = persisted; false = a persist failure OR a
    /// throwing sink, routed through the #1647 throw-safe kernel). Reused signature.
    using AuditFn = std::function<bool(const httplib::Request& req, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;

    void register_routes(httplib::Server& svr, ScopedPermFn scoped_perm_fn,
                         AgentLastUsedFn agent_last_used_fn, AuditFn audit_fn = {});

    /// HttpRouteSink overload — testable in-process via TestRouteSink (no httplib
    /// acceptor; the #438 TSan trap). The httplib::Server& overload wraps + delegates.
    void register_routes(HttpRouteSink& sink, ScopedPermFn scoped_perm_fn,
                         AgentLastUsedFn agent_last_used_fn, AuditFn audit_fn = {});

private:
    ScopedPermFn scoped_perm_fn_;
    AgentLastUsedFn agent_last_used_fn_;
    AuditFn audit_fn_;
};

} // namespace yuzu::server
