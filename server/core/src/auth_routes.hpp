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

#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>

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
    AuthRoutes(Config& cfg, auth::AuthManager& auth_mgr, RbacStore* rbac_store,
               ApiTokenStore* api_token_store, AuditStore* audit_store,
               ManagementGroupStore* mgmt_group_store, TagStore* tag_store,
               AnalyticsEventStore* analytics_store, std::shared_mutex& oidc_mu,
               std::unique_ptr<oidc::OidcProvider>& oidc_provider);

    // -- Auth helpers (called by server.cpp to create callbacks for other modules) --

    /// Validate session cookie, Bearer token, or X-Yuzu-Token header.
    /// Returns a Session on success, or sets 401 and returns nullopt.
    std::optional<auth::Session> require_auth(const httplib::Request& req, httplib::Response& res);

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
                                   const std::string& securable_type, const std::string& operation,
                                   const std::string& agent_id);

    /// Build a synthetic session from a validated API token.
    auth::Session synthesize_token_session(const ApiToken& api_token);

    /// Cookie attribute string: "; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800" + optional ";
    /// Secure".
    std::string session_cookie_attrs() const;

    /// Construct an AuditEvent from HTTP request context.
    AuditEvent make_audit_event(const httplib::Request& req, const std::string& action,
                                const std::string& result);

    /// Write an audit event to the audit store. Returns true iff the row
    /// was persisted; returns true (no-op success) when no AuditStore is
    /// configured (operator-chosen audit-off mode). Returns false on a
    /// silent persist failure (audit DB locked / disk full / corruption).
    /// SOC 2 CC6.6 evidence-emitting handlers MUST capture the return so
    /// they can surface partial-success on the response (HIGH-2 on PR #883,
    /// UP-H1 on PR W1.1). The bool is [[nodiscard]] on the AuditStore
    /// primitive but not on this wrapper — most call sites legitimately
    /// fire-and-forget.
    bool audit_log(const httplib::Request& req, const std::string& action,
                   const std::string& result, const std::string& target_type = {},
                   const std::string& target_id = {}, const std::string& detail = {});

    /// Variant that stamps `principal` + `principal_role` explicitly
    /// rather than resolving from `resolve_session(req)`. Used at the
    /// three "mint a fresh session" sites (`POST /login` no-MFA,
    /// `POST /login/mfa` TOTP/recovery success, OIDC `/auth/callback`)
    /// where the request itself carries no session cookie yet but the
    /// authenticating principal IS known to the handler. Without this,
    /// `make_audit_event` writes an empty `principal` and the SOC 2
    /// CC6.6 query "every privileged session-creation row names the
    /// principal" returns false negatives (Gate 4 consistency B3).
    bool audit_log_for_principal(const httplib::Request& req, const std::string& action,
                                 const std::string& result, const std::string& principal,
                                 const std::string& principal_role,
                                 const std::string& target_type = {},
                                 const std::string& target_id = {},
                                 const std::string& detail = {});

    /// Emit an analytics event with HTTP request context.
    void emit_event(const std::string& event_type, const httplib::Request& req,
                    const nlohmann::json& attrs = {}, const nlohmann::json& payload_data = {},
                    Severity sev = Severity::kInfo);

    // -- Route registration ---------------------------------------------------

    /// Register auth-related routes: GET/POST /login, POST /login/mfa,
    /// POST /logout, GET /auth/oidc/start, GET /auth/callback.
    ///
    /// Production callers use this overload; it constructs an
    /// `HttplibRouteSink` over `svr` and delegates to the sink-based
    /// overload below. Same handlers, same lambdas, same behaviour.
    void register_routes(httplib::Server& svr);

    /// Sink-based overload — used by tests to register routes against an
    /// in-process `TestRouteSink` and dispatch synthesized requests
    /// directly, avoiding `httplib::Server`'s TSan-hostile acceptor
    /// thread (#438). Matches the pattern already in use by
    /// `SettingsRoutes::register_routes`.
    void register_routes(class HttpRouteSink& sink);

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

    /// Pending MFA challenge issued after a successful password verify on
    /// /login when the user has TOTP enrolled. Keyed by an opaque random
    /// `mfa_pending_token` returned to the browser; resolved by the
    /// matching POST /login/mfa request. Expires after
    /// `cfg.mfa_login_pending_secs`; entries are reaped lazily on every
    /// access. SOC 2 CC6.6 — see docs/auth-mfa-design.md.
    ///
    /// `attempts` caps online TOTP guessing per challenge to
    /// `kMfaMaxAttemptsPerPending` (default 5). Once exceeded the entry
    /// is erased and the operator must restart with a fresh password
    /// submission. Closes Gate 2 H1 + unhappy-path UP-11 (rate-limit
    /// gap → CPU DoS via PBKDF2 amplification).
    /// Discriminates the two pending-token flavours that share the
    /// `mfa_pending_` map (PR3). An enum rather than a bool so a third kind
    /// (e.g. a future password-reset or WebAuthn challenge) is an additive
    /// variant rather than a second bool — and so the cross-endpoint guards
    /// read as `kind != PendingKind::enrollment` (self-documenting).
    enum class PendingKind {
        /// Login challenge for an already-enrolled user, resolved by
        /// POST /login/mfa (verify a TOTP/recovery code vs the live secret).
        login_challenge,
        /// Enrollment challenge issued when `mfa_enforcement` blocks an
        /// un-enrolled login, resolved by POST /login/mfa/enroll (confirm the
        /// provisional secret's first code, then mint the session).
        enrollment,
    };

    struct MfaPending {
        std::string username;
        auth::Role role{auth::Role::user};
        std::chrono::steady_clock::time_point expires_at{};
        int attempts{0};
        /// Default is a login challenge. Each endpoint rejects the other's
        /// kind, so an enrollment token can't be replayed at the
        /// login-challenge endpoint or vice versa.
        PendingKind kind{PendingKind::login_challenge};
    };
    static constexpr int kMfaMaxAttemptsPerPending = 5;
    mutable std::mutex mfa_pending_mu_;
    std::unordered_map<std::string, MfaPending> mfa_pending_;

    /// Drop every pending row whose deadline has passed. Called under
    /// `mfa_pending_mu_` from each insert/lookup; constant-time on an
    /// empty map and bounded by the configured rate limit.
    void reap_mfa_pending_locked();
};

} // namespace yuzu::server
