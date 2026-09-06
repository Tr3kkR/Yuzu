#pragma once

/// @file dashboard_api_routes.hpp
/// Extracted from server.cpp's inline registrations onto the HttpRouteSink
/// seam (#2542 follow-up) — 7 dashboard/API routes scattered across
/// server.cpp with no single owning store of their own, grouped into one
/// module because each handler is small and mostly independent rather than
/// because they share state. Every handler body is copied verbatim from
/// server.cpp; the changes are the receiver (`web_server_->` -> `sink.`),
/// the gate closures (`require_auth`/`require_permission` ->
/// `deps.auth_fn`/`deps.perm_fn`), member accesses (`rbac_store_.` ->
/// `deps.rbac_store->`, `audit_store_.` -> `deps.audit_store->`,
/// `analytics_store_.` -> `deps.analytics_store->`), and one deliberate
/// non-verbatim addition: `/api/agents` gains a leading
/// `!deps.visible_agents_json_fn` 503 check that has no counterpart in the
/// original code (`get_visible_agents_json` there was always a callable
/// ServerImpl member, never an unset std::function) — required because
/// `Deps::visible_agents_json_fn` can be default-constructed empty, and
/// calling an empty std::function is a bad_function_call crash rather than a
/// graceful 503.
///
/// `/api/agents` deliberately does NOT own `get_visible_agents_json` —
/// that method has a second live caller in server.cpp (DEX device-list,
/// ~line 19349) and stays exactly where it is. `visible_agents_json_fn` is a
/// thin closure server.cpp binds `[this]` around a call to that method.
///
/// Routes (7) — gate in parens:
///   GET  /api/me                     (auth_fn)
///   GET  /api/agents                 (perm_fn Infrastructure:Read, THEN auth_fn — order is
///                                      load-bearing, preserved verbatim from server.cpp; see
///                                      the route's own comment in the .cpp)
///   GET  /api/audit                  (perm_fn AuditLog:Read)
///   POST /api/export/json-to-csv     (perm_fn Response:Read)
///   POST /api/scope/validate         (auth_fn)
///   GET  /api/analytics/status       (perm_fn Infrastructure:Read)
///   GET  /api/analytics/recent       (perm_fn Infrastructure:Read)

#include <yuzu/server/auth.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

class HttpRouteSink;
class RbacStore;
class AuditStore;
class AnalyticsEventStore;

namespace dashboard_api {

/// Construction deps for `register_dashboard_api_routes`. Every
/// closure/pointer is bound once at start_web_server() time in server.cpp
/// and never reseated.
struct Deps {
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn = std::function<bool(const httplib::Request&, httplib::Response&,
                                       const std::string&, const std::string&)>;
    /// `ServerImpl::get_visible_agents_json` (server.cpp:11291), bound
    /// `[this]` in server.cpp's registration block. Empty function ->
    /// `/api/agents` fails closed (503) rather than a bad std::function
    /// call.
    using VisibleAgentsJsonFn = std::function<nlohmann::json(const std::string&)>;

    AuthFn auth_fn;
    PermFn perm_fn;
    VisibleAgentsJsonFn visible_agents_json_fn;
    RbacStore* rbac_store{nullptr};
    AuditStore* audit_store{nullptr};
    AnalyticsEventStore* analytics_store{nullptr};
};

/// Register all 7 dashboard/API routes against `sink`.
void register_dashboard_api_routes(HttpRouteSink& sink, Deps deps);

} // namespace dashboard_api
} // namespace yuzu::server
