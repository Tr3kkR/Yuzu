#pragma once

#include <yuzu/server/auth.hpp>

#include "analytics_event.hpp"
#include "analytics_event_store.hpp"
#include "api_token_store.hpp"
#include "audit_store.hpp"
#include "management_group_store.hpp"
#include "oidc_provider.hpp"
#include "saml_provider.hpp"
#include "rbac_store.hpp"
#include "tag_store.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace yuzu::server {

namespace detail {

/// Sanitises an externally-controlled string (the motivating case is an
/// OIDC `display`/`email`/`sub` claim — a hostile or misconfigured IdP, or a
/// user-set display name, is not trusted input) before it is concatenated
/// into an audit `detail` string or an emit_event JSON attribute. `detail`
/// is a flat "k=v;k=v" string parsed by SIEM tooling and rendered on the
/// dashboard audit log; an unsanitised value could inject `;`/`=` to forge
/// additional fields, or `\r`/`\n`/other control bytes to inject fake log
/// lines or corrupt terminal/log-viewer rendering. Replaces `;`, `=`, `\r`,
/// `\n`, and any control byte (incl. DEL) with `_`, then truncates to 128
/// bytes — backing up to a UTF-8 code-point boundary so a multi-byte value
/// never ends mid-sequence. Dependency-free by design. Exposed in
/// `yuzu::server::detail` (mirrors the rest_a4_envelope.hpp pattern) so unit
/// tests can call it directly.
///
/// This is audit-detail-field-injection defense ONLY — it does NOT strip
/// HTML markup, so it is not by itself a stored-XSS defense. An IdP-supplied
/// value with no control bytes (e.g. `<script>...</script>` as a display
/// name) passes through unchanged; the audit-log dashboard render layer's
/// HTML-escaping (`html_escape`) is what neutralises markup when this value
/// is later rendered. Never rely on this function alone to make a value
/// HTML-safe.
std::string sanitize_detail_value(std::string_view v);

} // namespace detail

struct Config;
class EnginePrincipalStore;

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
               std::unique_ptr<oidc::OidcProvider>& oidc_provider,
               saml::SamlProvider* saml_provider = nullptr);

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

    /// Re-validate the credential on a HELD-OPEN stream (MCP `GET /mcp/v1/`),
    /// against the principal that stream is bound to. Called once per heartbeat
    /// tick from the SSE pump, so a revoked credential cuts a LIVE stream — not
    /// merely future attaches (ADR-1005 Decision 15(c)).
    ///
    /// Tri-state on purpose (Decision 15(i) / chaos CH-4): an unreachable auth
    /// backend is NOT a revocation, and must not cut every stream on the fleet at
    /// the same instant — it yields kIndeterminate, which the pump rides out for a
    /// bounded grace window. Anything definitive (no credential, unknown/expired
    /// cookie, revoked/expired token, credential now bound to a DIFFERENT
    /// principal) is kRevoked and kills the stream on the spot.
    ///
    /// Credential precedence mirrors `resolve_session` (cookie → Bearer →
    /// X-Yuzu-Token) but deliberately skips its lazy elevation-reap side effect —
    /// re-validation is a read, not a request.
    ///
    /// NOTE (accepted, documented for security review): a cookie-authenticated
    /// stream slides the session's INACTIVITY window on every tick, so a live
    /// stream keeps its cookie session alive. The absolute session lifetime still
    /// terminates it. MCP clients authenticate with API tokens in practice; if the
    /// inactivity semantics matter for a future browser-side MCP client, the fix is
    /// a non-touching `peek_session` on AuthManager.
    auth::CredentialCheck revalidate_stream(const httplib::Request& req,
                                            const std::string& expected_principal);

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

    /// Build a synthetic session from a validated API token. Two-branch on the
    /// token's persisted `principal_kind` (design doc §6):
    ///  - "human" (or any legacy/unset value): exactly the pre-#2021 behavior
    ///    — attribute to the creating user, re-resolve their current role.
    ///    Always returns a session.
    ///  - "engine": the session IS the engine principal (`auth_source =
    ///    "engine_token"`); role/authority resolve from RBAC assignments, never
    ///    `get_user_role`. Consults `engine_principal_store_` — a missing/
    ///    revoked or unreachable-store outcome returns `nullopt` (fail-closed;
    ///    no session), as does a null `engine_principal_store_` (not yet wired).
    std::optional<auth::Session> synthesize_token_session(const ApiToken& api_token);

    /// Inject the engine-principal auth-lookup store (nullable — a null
    /// pointer makes every engine-kind token fail closed with no session,
    /// which is the correct posture before this is wired). Setter rather than
    /// a ctor param to keep the stacked-PR wiring in server.cpp low-risk.
    void set_engine_principal_store(EnginePrincipalStore* store) {
        engine_principal_store_ = store;
    }

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
    ///
    /// `principal_class_override`: `make_audit_event` re-stamps the class from the
    /// resolved session's `principal_kind`, so an engine principal audits as "engine"
    /// rather than the "agent" its bearer-token presentation implies. A caller that
    /// already knows the class (because it captured it while the session was live) must
    /// pass it, or its rows will disagree with the request-time rows for the same actor.
    /// Empty keeps the credential-presentation default, which is right for the
    /// pre-session login/MFA/OIDC sites.
    bool audit_log_for_principal(const httplib::Request& req, const std::string& action,
                                 const std::string& result, const std::string& principal,
                                 const std::string& principal_role,
                                 const std::string& target_type = {},
                                 const std::string& target_id = {},
                                 const std::string& detail = {},
                                 const std::string& principal_class_override = {});

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
    /// The gates `synthesize_token_session` applies AFTER the api_tokens row itself
    /// validates: the `principal_kind` allowlist, and — for an engine token — that the
    /// backing engine principal is still Active. `revalidate_stream` must apply them
    /// too, or a deleted/revoked engine principal keeps its live stream while every
    /// fresh request it makes is refused. Returns kIndeterminate (never kRevoked) when
    /// the engine store cannot answer, so a store blip defers rather than mass-kills.
    ///
    /// PRIVATE ON PURPOSE (#2367). This is the ONLY site that reads the engine
    /// principal through `EnginePrincipalStore::get_for_auth_revalidate`, i.e. the
    /// 60 s cached path. That is sound here and only here, because the stream
    /// revalidation this serves already tolerates staleness of the same order by
    /// design (on StoreUnreachable the pump rides out a ~60 s grace window,
    /// Decision 15(i)/CH-4). A FRESH authorization decision tolerates none, so
    /// widening access to this method would silently hand a caller a cached
    /// answer to a question that must be asked of Postgres every time. If you
    /// need the engine-principal gate somewhere new, call
    /// `EnginePrincipalStore::get_for_auth` directly — do not make this public.
    [[nodiscard]] auth::CredentialCheck engine_credential_state(const ApiToken& token) const;

    Config& cfg_;
    auth::AuthManager& auth_mgr_;
    RbacStore* rbac_store_;
    ApiTokenStore* api_token_store_;
    // Nullable — see set_engine_principal_store(). Non-owning; lifetime is
    // guaranteed by ServerImpl (T8 wiring), which outlives AuthRoutes.
    EnginePrincipalStore* engine_principal_store_{nullptr};
    AuditStore* audit_store_;
    ManagementGroupStore* mgmt_group_store_;
    TagStore* tag_store_;
    AnalyticsEventStore* analytics_store_;
    std::shared_mutex& oidc_mu_;
    std::unique_ptr<oidc::OidcProvider>& oidc_provider_;
    // Non-owning pointer — lifetime is guaranteed by ServerImpl which holds the
    // unique_ptr<SamlProvider> and outlives AuthRoutes. No mutex needed: the
    // provider is constructed once at startup (xmlsec global init is not thread-safe;
    // the startup phase is single-threaded) and never mutated afterward.
    saml::SamlProvider* saml_provider_{nullptr};

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
    /// Hard cap on the in-memory pending-token map. `reap_mfa_pending_locked`
    /// is an O(n) scan held under `mfa_pending_mu_`, so an unbounded map
    /// turns a distributed /login flood (many IPs, each bypassing the per-IP
    /// login rate-limiter) into an O(n²) lock-contention / CPU DoS that
    /// serialises all logins (Hermes adversarial H-2). At the cap, new
    /// challenges are load-shed with a 503 rather than growing the map.
    /// 50k entries × ~120 s TTL tolerates a very large legitimate burst.
    static constexpr std::size_t kMaxPendingTokens = 50'000;

public:
    /// Lower the pending-token cap for tests (the production default 50k is
    /// impractical to fill in a unit test). Test-only seam — governance
    /// qe-B: the load-shed branch must be exercised.
    void set_mfa_pending_cap_for_test(std::size_t cap) { mfa_pending_cap_ = cap; }

private:
    std::size_t mfa_pending_cap_{kMaxPendingTokens};
    mutable std::mutex mfa_pending_mu_;
    std::unordered_map<std::string, MfaPending> mfa_pending_;

    /// Drop every pending row whose deadline has passed. Called under
    /// `mfa_pending_mu_` from each insert/lookup; constant-time on an
    /// empty map and bounded by the configured rate limit.
    void reap_mfa_pending_locked();

    // ── Per-username login serialization (account-lockout race close) ──────
    //
    // Closes the check-then-act lockout race (adversarial C1): without it a
    // synchronized burst of requests for ONE username could all pass the
    // stale `lockout_status` pre-check and all reach `verify_password` before
    // any failure was recorded, so the effective guess budget was the in-flight
    // concurrency rather than `auth_lockout_threshold`. Holding the per-username
    // lock across the pre-check → verify_password → record/clear sequence
    // serializes attempts for that username, so at most `threshold` reach
    // password verification before the lock arms.
    //
    // Striped (fixed array; `hash(username) % N` picks the lock) so there is no
    // per-username allocation or cleanup and memory is bounded. Distinct
    // usernames that collide on a stripe serialize harmlessly and rarely
    // (N=256). Other usernames (different stripes) log in fully in parallel —
    // only an attacker bursting one account is serialized, which is the intended
    // throttle. Scope is single-process; the HA-replica-correct form is a
    // DB-atomic attempt reservation, landing with the auth store's Postgres
    // migration (see docs/security-reviews/account-lockout-2026-06-12.md).
    static constexpr std::size_t kLoginLockStripes = 256;
    std::array<std::mutex, kLoginLockStripes> login_locks_;
    std::mutex& login_lock_for(const std::string& username);
};

} // namespace yuzu::server
