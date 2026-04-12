#pragma once

#include <yuzu/server/auth.hpp>

#include "analytics_event.hpp"
#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "rbac_store.hpp"
#include "tag_store.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>

namespace yuzu::server {

struct Config;

/// Extracted auth helpers and route handlers (Phase 2 of god-object decomposition).
///
/// AuthRoutes owns the core authentication/authorization/audit primitives that
/// are used throughout the server: require_auth, require_admin, require_permission,
/// require_scoped_permission, audit_log, emit_event, etc.
///
/// ServerImpl creates an AuthRoutes instance early, then builds lightweight lambda
/// callbacks from its public methods to inject into RestApiV1, McpServer,
/// SettingsRoutes, and its own remaining route handlers.
class AuthRoutes {
public:
    AuthRoutes(Config& cfg,
               auth::AuthManager& auth_mgr,
               RbacStore* rbac_store,
               ApiTokenStore* api_token_store,
               AuditStore* audit_store,
               ManagementGroupStore* mgmt_group_store,
               TagStore* tag_store,
               AnalyticsEventStore* analytics_store,
               std::shared_mutex& oidc_mu,
               std::unique_ptr<oidc::OidcProvider>& oidc_provider);

    // -- Auth helpers (called by server.cpp to create callbacks for other modules) --

    /// Validate session cookie, Bearer token, or X-Yuzu-Token header.
    /// Returns a Session on success, or sets 401 and returns nullopt.
    std::optional<auth::Session> require_auth(const httplib::Request& req,
                                              httplib::Response& res);

    /// Resolve the authenticated session from a request without writing a response.
    /// Tries cookie, then `Authorization: Bearer`, then `X-Yuzu-Token`. Returns
    /// nullopt if none match. Use this when you need the principal name for
    /// provenance (e.g. `created_by`, audit event annotation) on a code path
    /// that has already cleared its authorization gate via require_auth or
    /// require_permission and just needs to know who's calling.
    std::optional<auth::Session> resolve_session(const httplib::Request& req);

    /// Calls require_auth, then checks session.role == admin.
    /// Returns true if admin; sets 403 and returns false otherwise.
    bool require_admin(const httplib::Request& req, httplib::Response& res);

    /// RBAC-aware permission check. Falls back to legacy admin/user check if RBAC is disabled.
    bool require_permission(const httplib::Request& req, httplib::Response& res,
                            const std::string& securable_type, const std::string& operation);

    /// Scoped RBAC-aware permission check for device-specific operations.
    bool require_scoped_permission(const httplib::Request& req, httplib::Response& res,
                                   const std::string& securable_type,
                                   const std::string& operation,
                                   const std::string& agent_id);

    /// Build a synthetic session from a validated API token.
    auth::Session synthesize_token_session(const ApiToken& api_token);

    /// Cookie attribute string: "; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800" + optional "; Secure".
    std::string session_cookie_attrs() const;

    /// Construct an AuditEvent from HTTP request context.
    AuditEvent make_audit_event(const httplib::Request& req, const std::string& action,
                                const std::string& result);

    /// Write an audit event to the audit store.
    void audit_log(const httplib::Request& req, const std::string& action,
                   const std::string& result, const std::string& target_type = {},
                   const std::string& target_id = {}, const std::string& detail = {});

    /// Emit an analytics event with HTTP request context.
    void emit_event(const std::string& event_type, const httplib::Request& req,
                    const nlohmann::json& attrs = {}, const nlohmann::json& payload_data = {},
                    Severity sev = Severity::kInfo);

    // -- Route registration ---------------------------------------------------

    /// Register auth-related routes: GET/POST /login, POST /logout,
    /// GET /auth/oidc/start, GET /auth/callback.
    void register_routes(httplib::Server& svr);

    // -- Static utilities (also used by server.cpp pre-routing handler) --------

    /// Extract the yuzu_session cookie value from a request.
    static std::string extract_session_cookie(const httplib::Request& req);

    /// URL-decode a percent-encoded string.
    static std::string url_decode(const std::string& s);

    /// Extract a form-urlencoded value by key from a POST body.
    static std::string extract_form_value(const std::string& body, const std::string& key);

private:
    Config& cfg_;
    auth::AuthManager& auth_mgr_;
    RbacStore* rbac_store_;
    ApiTokenStore* api_token_store_;
    AuditStore* audit_store_;
    ManagementGroupStore* mgmt_group_store_;
    TagStore* tag_store_;
    AnalyticsEventStore* analytics_store_;
    std::shared_mutex& oidc_mu_;
    std::unique_ptr<oidc::OidcProvider>& oidc_provider_;
};

} // namespace yuzu::server
