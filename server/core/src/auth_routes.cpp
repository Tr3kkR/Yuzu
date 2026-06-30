#include "auth_routes.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/server.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <shared_mutex>

#include "http_route_sink.hpp"
#include "mcp_policy.hpp"
#include "mfa_qr.hpp"
#include "mfa_step_up.hpp"
#include "rest_a4_envelope.hpp"

#include <ctime>

#include <nlohmann/json.hpp>

// Login page HTML (defined in login_ui.cpp)
extern const char* const kLoginHtml;

namespace yuzu::server {

namespace {

// Max stored length of a JIT-elevation justification (anti audit-row bloat). The
// operator-supplied reason is sanitised (control bytes → space) and truncated to
// this before it reaches the audit detail.
constexpr std::size_t kMaxJustificationLength = 1024;

// A4 denial envelope for the scoped-permission gate (#1549 review MEDIUM). The
// shared require_scoped_permission gate is the denial chokepoint for the agentic
// per-device routes, so its 401/403 bodies must carry the A4 fields — a
// `correlation_id` and, for permission denials, a structured
// `securable_type:operation` permission — not the bare {"error":{"code","message"}}
// shape the rest of the per-device surface's error branches already use. Reuses
// the X-Correlation-Id the handler already set (so header and body agree),
// minting one otherwise. Deliberately scoped to this gate + the require_auth 401
// it calls; the require_admin / require_permission denials and the
// standalone-route 401s are the tracked systemic follow-up (the whole-helper
// A4 reshaping), not this PR.
std::string a4_denial(httplib::Response& res, int code, const std::string& message,
                      const std::string& permission = {}) {
    std::string cid = res.get_header_value("X-Correlation-Id");
    if (cid.empty()) {
        cid = detail::make_correlation_id();
        res.set_header("X-Correlation-Id", cid);
    }
    nlohmann::json err = {{"code", code}, {"message", message}, {"correlation_id", cid}};
    if (!permission.empty())
        err["permission"] = permission;
    return nlohmann::json{{"error", std::move(err)}, {"meta", {{"api_version", "v1"}}}}.dump();
}

} // namespace

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

AuthRoutes::AuthRoutes(Config& cfg, auth::AuthManager& auth_mgr, RbacStore* rbac_store,
                       ApiTokenStore* api_token_store, AuditStore* audit_store,
                       ManagementGroupStore* mgmt_group_store, TagStore* tag_store,
                       AnalyticsEventStore* analytics_store, std::shared_mutex& oidc_mu,
                       std::unique_ptr<oidc::OidcProvider>& oidc_provider)
    : cfg_(cfg), auth_mgr_(auth_mgr), rbac_store_(rbac_store), api_token_store_(api_token_store),
      audit_store_(audit_store), mgmt_group_store_(mgmt_group_store), tag_store_(tag_store),
      analytics_store_(analytics_store), oidc_mu_(oidc_mu), oidc_provider_(oidc_provider) {}

// ---------------------------------------------------------------------------
// Static utilities
// ---------------------------------------------------------------------------

std::string AuthRoutes::extract_session_cookie(const httplib::Request& req) {
    auto cookie = req.get_header_value("Cookie");
    const std::string prefix = "yuzu_session=";
    auto pos = cookie.find(prefix);
    if (pos == std::string::npos)
        return {};
    pos += prefix.size();
    auto end = cookie.find(';', pos);
    return cookie.substr(pos, end == std::string::npos ? end : end - pos);
}

std::string AuthRoutes::url_decode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            auto hex = s.substr(i + 1, 2);
            out += static_cast<char>(std::stoul(hex, nullptr, 16));
            i += 2;
        } else if (s[i] == '+') {
            out += ' ';
        } else {
            out += s[i];
        }
    }
    return out;
}

std::string AuthRoutes::extract_form_value(const std::string& body, const std::string& key) {
    auto needle = key + "=";
    auto pos = body.find(needle);
    if (pos == std::string::npos)
        return {};
    pos += needle.size();
    auto end = body.find('&', pos);
    auto raw = body.substr(pos, end == std::string::npos ? end : end - pos);
    return url_decode(raw);
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

auth::Session AuthRoutes::synthesize_token_session(const ApiToken& api_token) {
    auth::Session synth;
    synth.username = api_token.principal_id;
    synth.auth_source = api_token.mcp_tier.empty() ? "api_token" : "mcp_token";
    synth.token_scope_service = api_token.scope_service;
    synth.mcp_tier = api_token.mcp_tier;

    // Resolve the creator's actual legacy role fresh (not unconditional admin).
    // get_user_role() queries the current role on every call, so a creator who's
    // been demoted since the token was issued will produce a user-role session.
    auto legacy_role = auth_mgr_.get_user_role(api_token.principal_id);
    synth.role = legacy_role.value_or(auth::Role::user);

    return synth;
}

std::optional<auth::Session> AuthRoutes::resolve_session(const httplib::Request& req) {
    // 1. Try session cookie (existing browser auth)
    auto token = extract_session_cookie(req);
    // Guard against oversized cookie values before passing to validate_session (#630).
    if (token.size() > auth::kMaxSessionTokenLength)
        return std::nullopt;
    auto session = auth_mgr_.validate_session(token);
    if (session)
        return session;

    // 2. Try Authorization: Bearer <token> (API token auth)
    auto auth_header = req.get_header_value("Authorization");
    if (auth_header.size() > 7 && auth_header.substr(0, 7) == "Bearer ") {
        auto raw = auth_header.substr(7);
        // Reject overly-long API tokens early to prevent DoS via expensive hash
        // operations in ApiTokenStore::validate_token() (#630).
        if (raw.size() <= auth::kMaxApiTokenLength) {
            if (api_token_store_) {
                auto api_token = api_token_store_->validate_token(raw);
                if (api_token)
                    return synthesize_token_session(*api_token);
            }
        }
    }

    // 3. Try X-Yuzu-Token header (alternative API token header)
    auto custom_header = req.get_header_value("X-Yuzu-Token");
    if (!custom_header.empty() && custom_header.size() <= auth::kMaxApiTokenLength &&
        api_token_store_) {
        auto api_token = api_token_store_->validate_token(custom_header);
        if (api_token)
            return synthesize_token_session(*api_token);
    }

    return std::nullopt;
}

std::optional<auth::Session> AuthRoutes::require_auth(const httplib::Request& req,
                                                      httplib::Response& res) {
    if (auto session = resolve_session(req))
        return session;

    res.status = 401;
    res.set_content(a4_denial(res, 401, "unauthorized"), "application/json");
    return std::nullopt;
}

bool AuthRoutes::require_admin(const httplib::Request& req, httplib::Response& res) {
    auto session = require_auth(req, res);
    if (!session)
        return false;

    // Service-scoped tokens are limited to ITServiceOwner permissions for one named
    // service; they must never reach admin routes regardless of the creator's role.
    // MCP tokens are for fleet management (queries, instruction execution) and must
    // not be used to administer the server itself (settings, users, TLS, OIDC).
    // See docs/mcp-server.md and docs/auth-architecture.md (#520).
    if (!session->token_scope_service.empty()) {
        audit_log(req, "auth.admin_required", "denied", "", "",
                  "service-scoped token blocked from admin route");
        res.status = 403;
        res.set_content(
            R"({"error":{"code":403,"message":"service-scoped tokens cannot perform admin operations"},"meta":{"api_version":"v1"}})",
            "application/json");
        return false;
    }
    if (!session->mcp_tier.empty()) {
        audit_log(req, "auth.admin_required", "denied", "", "",
                  "MCP token blocked from admin route");
        res.status = 403;
        res.set_content(
            R"({"error":{"code":403,"message":"MCP tokens cannot perform admin operations"},"meta":{"api_version":"v1"}})",
            "application/json");
        return false;
    }

    // effective_role(), not the raw role, so an active JIT admin elevation
    // (POST /api/v1/elevate) is treated as admin for its window and auto-reverts.
    // Only interactive cookie sessions can be elevated — the MCP/service-token
    // guards above already rejected those credentials, and elevate_session never
    // runs for them.
    if (auth::effective_role(*session) != auth::Role::admin) {
        // SOC 2 CC7.2: every privileged-endpoint denial must surface in
        // the audit chain, not just the request log. Emitting here closes
        // the gap for every caller in one place rather than threading an
        // audit_fn through dozens of route registrations (governance PR4).
        audit_log(req, "auth.admin_required", "denied", "endpoint", req.path);
        res.status = 403;
        res.set_content(
            R"({"error":{"code":403,"message":"admin role required"},"meta":{"api_version":"v1"}})",
            "application/json");
        return false;
    }
    return true;
}

bool AuthRoutes::require_permission(const httplib::Request& req, httplib::Response& res,
                                    const std::string& securable_type,
                                    const std::string& operation) {
    auto session = require_auth(req, res);
    if (!session)
        return false;

    // JIT admin elevation: an active elevation grants full admin for its window,
    // so it satisfies any securable:operation (mirrors require_admin gating on
    // effective_role). Only interactive cookie sessions can be elevated —
    // elevate_session never runs for MCP/service-scoped tokens (which are
    // synthesized per-request and carry no elevated_until), so this short-circuit
    // cannot be reached by them. Auditing is on the elevation lifecycle
    // (role.elevation.granted/expired), not per privileged action.
    if (auth::is_elevated(*session))
        return true;

    // MCP-tier tokens: enforce the tier policy (readonly/operator/supervised) then
    // fall through to the standard RBAC/role check using the creator's actual role.
    // The tier is the primary MCP access control boundary; RBAC is a secondary layer.
    // Tier enforcement applies on all transports (MCP JSON-RPC and REST API) so
    // a token cannot bypass the tier by switching endpoints.
    if (!session->mcp_tier.empty()) {
        if (!mcp::tier_allows(session->mcp_tier, securable_type, operation)) {
            audit_log(req, "auth.permission_required", "denied", "", "",
                      "MCP token tier '" + session->mcp_tier + "' does not allow " +
                          securable_type + ":" + operation);
            res.status = 403;
            res.set_content(nlohmann::json({{"error",
                                             {{"code", 403},
                                              {"message", "MCP token tier does not allow " +
                                                              securable_type + ":" + operation}}},
                                            {"meta", {{"api_version", "v1"}}}})
                                .dump(),
                            "application/json");
            return false;
        }
        // Approval-gated operations (supervised tier on destructive ops) cannot
        // proceed because the approval workflow re-dispatch path is Phase 2 work.
        // mcp_server.cpp denies the same case with kTierDenied (it deliberately
        // does NOT return kApprovalRequired — A4 reserves that for a pollable
        // approval it cannot produce yet); mirror that denial here so the REST
        // transport cannot bypass it (#520).
        if (mcp::requires_approval(session->mcp_tier, securable_type, operation)) {
            audit_log(req, "auth.approval_required", "denied", "", "",
                      "MCP token tier '" + session->mcp_tier + "' requires approval for " +
                          securable_type + ":" + operation + " (Phase 2 not implemented)");
            res.status = 403;
            res.set_content(
                nlohmann::json(
                    {{"error",
                      {{"code", 403},
                       {"message", "operation requires approval; "
                                   "approval-gated MCP execution is not yet implemented"}}},
                     {"meta", {{"api_version", "v1"}}}})
                    .dump(),
                "application/json");
            return false;
        }
    }

    // Service-scoped tokens: check if the ITServiceOwner role grants this permission.
    // Scoped tokens cannot be used when RBAC is disabled.
    if (!session->token_scope_service.empty()) {
        if (!rbac_store_ || !rbac_store_->is_rbac_enabled()) {
            audit_log(req, "auth.permission_required", "denied", "", "",
                      "service-scoped token blocked: RBAC not enabled");
            res.status = 403;
            res.set_content(
                R"({"error":{"code":403,"message":"service-scoped tokens require RBAC to be enabled"},"meta":{"api_version":"v1"}})",
                "application/json");
            return false;
        }
        if (!rbac_store_->check_role_has_permission("ITServiceOwner", securable_type, operation)) {
            audit_log(req, "auth.permission_required", "denied", "", "",
                      "service-scoped token blocked: lacks ITServiceOwner permission");
            res.status = 403;
            std::string msg = "service-scoped token does not grant " + securable_type + ":" +
                              operation + " (ITServiceOwner permission required)";
            res.set_content(nlohmann::json({{"error", {{"code", 403}, {"message", msg}}},
                                            {"meta", {{"api_version", "v1"}}}})
                                .dump(),
                            "application/json");
            return false;
        }
        return true;
    }

    if (rbac_store_ && rbac_store_->is_rbac_enabled()) {
        if (!rbac_store_->check_permission(session->username, securable_type, operation)) {
            audit_log(req, "auth.permission_required", "denied", "", "",
                      "RBAC denied " + securable_type + ":" + operation);
            res.status = 403;
            res.set_content(nlohmann::json({{"error",
                                             {{"code", 403},
                                              {"message", "permission denied: " + securable_type +
                                                              ":" + operation}}},
                                            {"meta", {{"api_version", "v1"}}}})
                                .dump(),
                            "application/json");
            return false;
        }
        return true;
    }

    // Legacy fallback: write/delete/execute/approve require admin (effective_role
    // so an elevation still satisfies it as defense-in-depth, though the
    // is_elevated short-circuit above already returned for elevated sessions).
    if (operation != "Read" && auth::effective_role(*session) != auth::Role::admin) {
        audit_log(req, "auth.permission_required", "denied", "", "",
                  "non-admin role denied " + securable_type + ":" + operation +
                      (session->mcp_tier.empty() ? "" : " (mcp_tier=" + session->mcp_tier + ")"));
        res.status = 403;
        res.set_content(
            R"({"error":{"code":403,"message":"admin role required"},"meta":{"api_version":"v1"}})",
            "application/json");
        return false;
    }
    return true;
}

bool AuthRoutes::require_scoped_permission(const httplib::Request& req, httplib::Response& res,
                                           const std::string& securable_type,
                                           const std::string& operation,
                                           const std::string& agent_id) {
    auto session = require_auth(req, res);
    if (!session)
        return false;

    // JIT admin elevation grants full admin (across all management groups) for
    // its window — cookie-session-only, so unreachable by MCP/service tokens.
    if (auth::is_elevated(*session))
        return true;

    // MCP-tier tokens: enforce the tier policy then fall through to the standard
    // RBAC/role check using the creator's actual role. Approval-gated operations
    // (supervised tier on destructive ops) are blocked here because Phase 2
    // re-dispatch is not built — same contract as mcp_server.cpp (#520).
    if (!session->mcp_tier.empty()) {
        if (!mcp::tier_allows(session->mcp_tier, securable_type, operation)) {
            audit_log(req, "auth.scoped_permission_required", "denied", "", "",
                      "MCP token tier '" + session->mcp_tier + "' does not allow " +
                          securable_type + ":" + operation);
            res.status = 403;
            res.set_content(a4_denial(res, 403,
                                      "MCP token tier does not allow " + securable_type + ":" +
                                          operation,
                                      securable_type + ":" + operation),
                            "application/json");
            return false;
        }
        if (mcp::requires_approval(session->mcp_tier, securable_type, operation)) {
            audit_log(req, "auth.approval_required", "denied", "", "",
                      "MCP token tier '" + session->mcp_tier + "' requires approval for " +
                          securable_type + ":" + operation + " (Phase 2 not implemented)");
            res.status = 403;
            res.set_content(a4_denial(res, 403,
                                      "operation requires approval; approval-gated MCP "
                                      "execution is not yet implemented",
                                      securable_type + ":" + operation),
                            "application/json");
            return false;
        }
    }

    // Service-scoped tokens: verify the target agent belongs to the token's service,
    // and that the ITServiceOwner role grants the required permission.
    if (!session->token_scope_service.empty()) {
        if (!rbac_store_ || !rbac_store_->is_rbac_enabled()) {
            audit_log(req, "auth.scoped_permission_required", "denied", "", "",
                      "service-scoped token blocked: RBAC not enabled");
            res.status = 403;
            res.set_content(
                R"({"error":{"code":403,"message":"service-scoped tokens require RBAC to be enabled"},"meta":{"api_version":"v1"}})",
                "application/json");
            return false;
        }
        // Check that the ITServiceOwner role grants this permission type
        if (!rbac_store_->check_role_has_permission("ITServiceOwner", securable_type, operation)) {
            audit_log(req, "auth.scoped_permission_required", "denied", "", "",
                      "service-scoped token blocked: lacks ITServiceOwner permission");
            res.status = 403;
            std::string msg = "service-scoped token does not grant " + securable_type + ":" +
                              operation + " (ITServiceOwner permission required)";
            res.set_content(nlohmann::json({{"error", {{"code", 403}, {"message", msg}}},
                                            {"meta", {{"api_version", "v1"}}}})
                                .dump(),
                            "application/json");
            return false;
        }
        // Verify the target agent's service tag matches the token's scope
        if (!tag_store_) {
            audit_log(req, "auth.scoped_permission_required", "denied", "", "",
                      "service-scoped token blocked: tag store unavailable");
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"tag store unavailable, cannot verify scope"},"meta":{"api_version":"v1"}})",
                "application/json");
            return false;
        }
        if (!agent_id.empty()) {
            auto agent_service = tag_store_->get_tag(agent_id, "service");
            if (agent_service != session->token_scope_service) {
                audit_log(req, "auth.scoped_permission_required", "denied", agent_id,
                          "agent service '" + agent_service + "' does not match token scope '" +
                              session->token_scope_service + "'");
                res.status = 403;
                res.set_content(nlohmann::json({{"error", "forbidden"},
                                                {"detail", "agent is not in service '" +
                                                               session->token_scope_service + "'"}})
                                    .dump(),
                                "application/json");
                return false;
            }
        }
        return true;
    }

    if (rbac_store_ && rbac_store_->is_rbac_enabled()) {
        if (!rbac_store_->check_scoped_permission(session->username, securable_type, operation,
                                                  agent_id, mgmt_group_store_)) {
            audit_log(req, "auth.scoped_permission_required", "denied", agent_id,
                      "RBAC denied " + securable_type + ":" + operation);
            res.status = 403;
            res.set_content(a4_denial(res, 403,
                                      "permission denied: " + securable_type + ":" + operation,
                                      securable_type + ":" + operation),
                            "application/json");
            return false;
        }
        return true;
    }

    // Legacy fallback: write/delete/execute/approve require admin (effective_role
    // — defense-in-depth; the is_elevated short-circuit above already returned for
    // elevated sessions).
    if (operation != "Read" && auth::effective_role(*session) != auth::Role::admin) {
        audit_log(req, "auth.scoped_permission_required", "denied", agent_id,
                  "non-admin role denied " + securable_type + ":" + operation +
                      (session->mcp_tier.empty() ? "" : " (mcp_tier=" + session->mcp_tier + ")"));
        res.status = 403;
        res.set_content(a4_denial(res, 403, "admin role required", securable_type + ":" + operation),
                        "application/json");
        return false;
    }
    return true;
}

std::string AuthRoutes::session_cookie_attrs() const {
    std::string attrs = "; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800";
    if (cfg_.https_enabled) {
        attrs += "; Secure";
    }
    return attrs;
}

AuditEvent AuthRoutes::make_audit_event(const httplib::Request& req, const std::string& action,
                                        const std::string& result) {
    AuditEvent event;
    event.action = action;
    event.result = result;
    event.source_ip = req.remote_addr;
    event.user_agent = req.get_header_value("User-Agent");

    // Resolve principal via cookie / Bearer token / X-Yuzu-Token (same as require_auth).
    // Without this, audit rows for API-token-authenticated requests (REST API automation
    // and every MCP tool call) would have an empty `principal`, breaking the audit trail.
    if (auto session = resolve_session(req)) {
        event.principal = session->username;
        event.principal_role = auth::role_to_string(session->role);
        event.session_id = extract_session_cookie(req);
    }
    return event;
}

void AuthRoutes::reap_mfa_pending_locked() {
    auto now = std::chrono::steady_clock::now();
    std::erase_if(mfa_pending_, [&](const auto& p) { return now > p.second.expires_at; });
}

bool AuthRoutes::audit_log(const httplib::Request& req, const std::string& action,
                           const std::string& result, const std::string& target_type,
                           const std::string& target_id, const std::string& detail) {
    if (!audit_store_)
        return true; // audit-off deployment — not a failure relative to config
    auto event = make_audit_event(req, action, result);
    event.target_type = target_type;
    event.target_id = target_id;
    event.detail = detail;
    auto ok = audit_store_->log(event);
    if (!ok) {
        // SOC 2 CC7.2 — surface audit-write failures via spdlog so on-call
        // has a signal short of the row-count metric. The wrapper still
        // returns false so the caller can decide whether to abort the
        // surrounding operation; most call sites legitimately fire-and-
        // forget the return value (matches the historical contract).
        spdlog::warn("audit_log: AuditStore::log failed for action='{}' target_type='{}' "
                     "target_id='{}'",
                     action, target_type, target_id);
    }
    return ok;
}

bool AuthRoutes::audit_log_for_principal(const httplib::Request& req, const std::string& action,
                                         const std::string& result, const std::string& principal,
                                         const std::string& principal_role,
                                         const std::string& target_type,
                                         const std::string& target_id,
                                         const std::string& detail) {
    if (!audit_store_)
        return true;
    AuditEvent event;
    event.action = action;
    event.result = result;
    event.source_ip = req.remote_addr;
    event.user_agent = req.get_header_value("User-Agent");
    event.principal = principal;
    event.principal_role = principal_role;
    event.target_type = target_type;
    event.target_id = target_id;
    event.detail = detail;
    auto ok = audit_store_->log(event);
    if (!ok) {
        spdlog::warn("audit_log_for_principal: AuditStore::log failed for action='{}' "
                     "principal='{}' target_id='{}'",
                     action, principal, target_id);
    }
    return ok;
}

void AuthRoutes::emit_event(const std::string& event_type, const httplib::Request& req,
                            const nlohmann::json& attrs, const nlohmann::json& payload_data,
                            Severity sev) {
    if (!analytics_store_)
        return;
    AnalyticsEvent ae;
    ae.event_type = event_type;
    ae.severity = sev;
    ae.attributes = attrs;
    ae.payload = payload_data;

    if (auto session = resolve_session(req)) {
        ae.principal = session->username;
        ae.principal_role = auth::role_to_string(session->role);
        ae.session_id = extract_session_cookie(req);
    }
    analytics_store_->emit(std::move(ae));
}

// Pick the striped login mutex for a username (account-lockout race close).
// Any hash is fine — same-stripe collisions across distinct usernames just
// serialize harmlessly. See the header for the full rationale.
std::mutex& AuthRoutes::login_lock_for(const std::string& username) {
    return login_locks_[std::hash<std::string>{}(username) % login_locks_.size()];
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

void AuthRoutes::register_routes(httplib::Server& svr) {
    // Production shim — wrap the real server in an HttplibRouteSink and
    // delegate to the sink-based overload. Same handlers, same lambdas,
    // same observable behaviour. Test code calls the sink overload
    // directly with a TestRouteSink.
    HttplibRouteSink sink(svr);
    register_routes(sink);
}

void AuthRoutes::register_routes(HttpRouteSink& sink) {
    // -- Login page -----------------------------------------------------------
    sink.Get("/login", [this](const httplib::Request& req, httplib::Response& res) {
        std::string html(kLoginHtml);
        // Inject OIDC enablement flag into the page
        std::shared_lock oidc_lock(oidc_mu_);
        if (oidc_provider_ && oidc_provider_->is_enabled()) {
            auto pos = html.find("/*OIDC_CONFIG*/");
            if (pos != std::string::npos)
                html.replace(pos, 15, "window.OIDC_ENABLED=true;");
        }
        res.set_content(html, "text/html; charset=utf-8");
    });

    sink.Post("/login", [this](const httplib::Request& req, httplib::Response& res) {
        auto username = extract_form_value(req.body, "username");
        auto password = extract_form_value(req.body, "password");

        // Serialize concurrent attempts for THIS username across the whole
        // lockout-critical section below (pre-check → verify_password →
        // record/clear), so a synchronized burst cannot all pass the stale
        // pre-check and verify more than `threshold` passwords before the lock
        // arms (adversarial C1). Held only when lockout is enabled; released
        // explicitly before the MFA branching, which does not touch lockout
        // state. Striped per-username (login_lock_for) so unrelated usernames
        // log in fully in parallel — only a burst against one account is
        // serialized, which is the intended throttle.
        std::unique_lock<std::mutex> login_lk;
        if (cfg_.auth_lockout_threshold > 0) {
            login_lk = std::unique_lock<std::mutex>(login_lock_for(username));
        }

        // ── Account-lockout pre-check (SOC 2 CC6.3) ──────────────────────
        // Brute-force / credential-stuffing guard. When the account is
        // currently locked we reject with the SAME generic 401 as a bad
        // password (no Retry-After, no "locked" wording) so the response is
        // not a username-enumeration / lock-state oracle, and we skip
        // verify_password entirely — the ~100 ms PBKDF2 is never burned on a
        // locked account (a free anti-DoS win). The lock is observable only
        // server-side via the audit row + metric below. Fail-open on a read
        // error: lockout protects against *wrong* passwords, so a transient
        // auth.db read failure must not wedge logins — verify_password is
        // still the real credential gate. prior_failed_count is captured so
        // the success path knows whether to emit a "cleared" audit.
        int prior_failed_count = 0;
        // Set when the lockout pre-check read itself fails (fail-open path): we
        // then cannot know the user's prior failure count, so on a subsequent
        // successful login we clear defensively rather than leave a stale
        // counter that could lock a legitimate user on their very next slip
        // (Hermes cyber-review F4).
        bool lockout_read_failed = false;
        if (cfg_.auth_lockout_threshold > 0) {
            if (auto* db = auth_mgr_.auth_db_ptr()) {
                if (auto st = db->lockout_status(username)) {
                    prior_failed_count = st->failed_count;
                    if (st->locked) {
                        res.status = 401;
                        res.set_content(
                            R"({"error":{"code":401,"message":"Invalid username or password"},"meta":{"api_version":"v1"}})",
                            "application/json");
                        // Metric + a rate-limited log line ONLY — deliberately
                        // no audit row AND no analytics event per blocked
                        // attempt. Under a sustained brute-force against a
                        // locked account, an `emit_event` per attempt would
                        // amplify the analytics/SSE pipeline exactly the way a
                        // per-attempt audit row would amplify the audit log
                        // (governance UP-15). The aggregate signal is the
                        // counter; the once-per-lock `auth.lockout.applied`
                        // audit row is the durable evidence; the source IP for
                        // forensics is in the spdlog line below (bounded by the
                        // 10/s/IP login rate-limiter).
                        if (auto* m = auth_mgr_.metrics_registry()) {
                            m->counter("yuzu_auth_lockout_blocked_total").increment();
                        }
                        spdlog::warn("Login blocked: account '{}' is locked (source {})", username,
                                     req.remote_addr);
                        return;
                    }
                } else {
                    // Fail-open: lockout protects against *wrong* passwords, so
                    // a transient auth.db read error must not wedge logins —
                    // verify_password remains the real credential gate. Make the
                    // degradation observable (was silent) and remember it so the
                    // success path below clears the counter defensively.
                    lockout_read_failed = true;
                    spdlog::warn("lockout_status read failed for '{}' (error={}) — pre-check "
                                 "fail-open; brute-force throttle degraded for this attempt",
                                 username, static_cast<int>(st.error()));
                }
            }
        }

        auto role_opt = auth_mgr_.verify_password(username, password);
        if (!role_opt) {
            res.status = 401;
            res.set_content(
                R"({"error":{"code":401,"message":"Invalid username or password"},"meta":{"api_version":"v1"}})",
                "application/json");
            audit_log(req, "auth.login_failed", "error", "User", username);
            emit_event("auth.login_failed", req,
                       {{"source_ip", req.remote_addr}, {"username", username}}, {},
                       Severity::kWarn);
            // Record the failed attempt for lockout accounting. Only the
            // threshold-crossing failure emits an audit row — subsequent
            // blocked attempts are counted via the metric above, NOT audited.
            // record_failed_login is a no-op for unknown / malformed
            // usernames, so it never creates a row for a non-existent account
            // (anti-enumeration + no storage growth).
            if (cfg_.auth_lockout_threshold > 0) {
                if (auto* db = auth_mgr_.auth_db_ptr()) {
                    auto rec = db->record_failed_login(username, cfg_.auth_lockout_threshold,
                                                       cfg_.auth_lockout_window_secs);
                    if (rec && rec->just_locked) {
                        // result uses the canonical ok|denied|error envelope
                        // vocabulary (the lock was applied successfully); the
                        // warning *severity* is carried by the emit_event +
                        // metric, not the audit result token. The applied row
                        // is the primary CC6.3 lock evidence, so a lost write
                        // is surfaced (governance UP-14 / compliance SHOULD-1).
                        if (!audit_log_for_principal(
                                req, "auth.lockout.applied", "ok", username, "", "User", username,
                                "threshold=" + std::to_string(cfg_.auth_lockout_threshold) +
                                    " window_secs=" +
                                    std::to_string(cfg_.auth_lockout_window_secs))) {
                            spdlog::error("audit emission FAILED for auth.lockout.applied user='{}' "
                                          "— CC6.3 lock-event evidence lost",
                                          username);
                        }
                        emit_event("auth.lockout.applied", req,
                                   {{"source_ip", req.remote_addr}, {"username", username}}, {},
                                   Severity::kWarn);
                        if (auto* m = auth_mgr_.metrics_registry()) {
                            m->counter("yuzu_auth_lockout_applied_total").increment();
                        }
                        spdlog::warn("Account '{}' locked after {} failed login attempts", username,
                                     cfg_.auth_lockout_threshold);
                    } else if (!rec) {
                        spdlog::warn("record_failed_login failed for '{}': error={}", username,
                                     static_cast<int>(rec.error()));
                    }
                }
            }
            return;
        }

        // Password verified — reset the lockout counter (the brute-force
        // window is per-consecutive-failure, so any success clears it). Done
        // here, before the MFA branching below, so it covers all three
        // success exits (no-MFA mint, MFA challenge, enforced enrollment).
        // Clear when there was a known non-zero counter, OR when the pre-check
        // read failed and the count is unknown (F4 — never leave a stale
        // counter behind a successful login). Only routine logins with a known
        // zero counter skip the write, so they don't spam the audit log.
        if (cfg_.auth_lockout_threshold > 0 && (prior_failed_count > 0 || lockout_read_failed)) {
            if (auto* db = auth_mgr_.auth_db_ptr()) {
                if (auto cl = db->clear_failed_logins(username); !cl) {
                    spdlog::warn("clear_failed_logins failed for '{}': error={}", username,
                                 static_cast<int>(cl.error()));
                } else {
                    if (!audit_log_for_principal(req, "auth.lockout.cleared", "ok", username,
                                                 auth::role_to_string(*role_opt), "User", username,
                                                 "reset_on_successful_login")) {
                        spdlog::warn("audit emission failed for auth.lockout.cleared user='{}'",
                                     username);
                    }
                    emit_event("auth.lockout.cleared", req,
                               {{"source_ip", req.remote_addr}, {"username", username}});
                }
            }
        }

        // Lockout-critical section complete (password verified, counter
        // cleared). Release the per-username lock BEFORE the MFA branching so a
        // TOTP challenge for this user doesn't hold the stripe across the rest
        // of the flow — MFA state has its own (`mfa_pending_mu_`) guard.
        if (login_lk.owns_lock())
            login_lk.unlock();

        // Decide whether this user must complete a TOTP challenge before
        // we mint a real session. The AuthDB lookup is fail-open relative
        // to MFA: if AuthDB is not configured (legacy config-file-only
        // deployments) or the row read fails, we treat the user as
        // not-enrolled. Enforcement modes (`admin-only`, `required`)
        // tighten this in a follow-up PR.
        bool mfa_enrolled = false;
        if (auto* db = auth_mgr_.auth_db_ptr()) {
            auto status = db->mfa_status(username);
            if (status && status->enrolled) {
                mfa_enrolled = true;
            }
        }

        // PR3 enforcement (SOC 2 CC6.6). Under `required` (every role) or
        // `admin-only` (admins only), a user without MFA must enrol before
        // a session is minted. Reuse PR1's pending-token machinery: issue
        // a provisional TOTP secret + an enrollment-pending token and let
        // POST /login/mfa/enroll confirm the first code and complete the
        // login. No new session concept; an un-enrolled enforced user
        // never holds a cookie until they finish enrolling.
        const bool mfa_enforced = mfa_enforcement_protects(cfg_.mfa_enforcement, *role_opt);
        if (!mfa_enrolled && mfa_enforced) {
            auto* db = auth_mgr_.auth_db_ptr();
            if (!db) {
                // Enforcement is configured but the store that holds TOTP
                // secrets is unavailable, so MFA can be neither enrolled
                // nor verified. Fail CLOSED — minting an unprotected
                // session here would silently defeat the control the
                // operator explicitly enabled.
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"MFA enrollment is required but the authentication store is unavailable"},"meta":{"api_version":"v1"}})",
                    "application/json");
                audit_log_for_principal(req, "mfa.enroll.required", "error", username,
                                        auth::role_to_string(*role_opt), "User", username,
                                        "auth_db unavailable (fail-closed)");
                spdlog::error(
                    "MFA enforcement={} but auth_db unavailable — refusing login for '{}'",
                    cfg_.mfa_enforcement, username);
                return;
            }
            auto init = db->mfa_init_enrollment(username, "Yuzu");
            if (!init) {
                res.status = 500;
                res.set_content(
                    R"({"error":{"code":500,"message":"Could not initiate MFA enrollment"},"meta":{"api_version":"v1"}})",
                    "application/json");
                audit_log_for_principal(req, "mfa.enroll.required", "error", username,
                                        auth::role_to_string(*role_opt), "User", username,
                                        "mfa_init_enrollment failed");
                return;
            }
            auto pending_token =
                auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(32));
            bool at_capacity = false;
            {
                std::lock_guard lock(mfa_pending_mu_);
                reap_mfa_pending_locked();
                if (mfa_pending_.size() >= mfa_pending_cap_) {
                    at_capacity = true; // load-shed (Hermes H-2)
                } else {
                    MfaPending entry;
                    entry.username = username;
                    entry.role = *role_opt;
                    entry.kind = PendingKind::enrollment;
                    entry.expires_at = std::chrono::steady_clock::now() +
                                       std::chrono::seconds(cfg_.mfa_login_pending_secs);
                    mfa_pending_[pending_token] = std::move(entry);
                }
            }
            if (at_capacity) {
                res.status = 503;
                res.set_content(
                    R"({"error":{"code":503,"message":"too many pending authentications, retry shortly"},"meta":{"api_version":"v1"}})",
                    "application/json");
                // Observable load-shed (governance sec-MED / UP-D3): a
                // counter for alerting + a (per-event, not audit) warn.
                // Deliberately NOT an audit row — a flood would amplify
                // audit writes; the counter is the aggregated signal.
                if (auto* m = auth_mgr_.metrics_registry()) {
                    m->counter("yuzu_auth_mfa_pending_load_shed_total", {{"kind", "enrollment"}})
                        .increment();
                }
                spdlog::warn("MFA pending-token map at capacity ({}) — shedding enrollment "
                             "challenge for source {}",
                             mfa_pending_cap_, req.remote_addr);
                return;
            }
            res.status = 202;
            // The provisional secret is revealed exactly once here — the
            // caller already proved the password, the same trust level as
            // the Settings-page enrollment reveal. POST /login/mfa/enroll
            // never re-reveals it on a failed confirm.
            nlohmann::json body = {{"status", "mfa_enrollment_required"},
                                   {"mfa_pending_token", pending_token},
                                   {"otpauth_uri", init->otpauth_uri},
                                   {"secret_base32", init->secret_base32},
                                   // Server-rendered inline SVG QR (#1232). May be
                                   // "" on encode failure → the form falls back to
                                   // the textual secret.
                                   {"qr_svg", otpauth_qr_svg(init->otpauth_uri)},
                                   {"expires_in", cfg_.mfa_login_pending_secs}};
            res.set_content(body.dump(), "application/json");
            audit_log_for_principal(req, "mfa.enroll.required", "ok", username,
                                    auth::role_to_string(*role_opt), "User", username,
                                    "enforcement=" + cfg_.mfa_enforcement);
            emit_event("mfa.enroll.required", req,
                       {{"source_ip", req.remote_addr}, {"username", username}});
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_mfa_challenges_issued_total").increment();
                std::lock_guard lock(mfa_pending_mu_);
                m->gauge("yuzu_auth_mfa_pending_tokens")
                    .set(static_cast<double>(mfa_pending_.size()));
            }
            return;
        }

        if (!mfa_enrolled) {
            auto token = auth_mgr_.create_local_session(username, *role_opt, false);
            res.set_header("Set-Cookie", "yuzu_session=" + token + session_cookie_attrs());
            res.set_content(R"({"status":"ok"})", "application/json");
            // Mint-time audit row uses the explicit-principal helper —
            // request has no session cookie yet so the default
            // resolve_session-based path would leave `principal` empty
            // (consistency B3). target_type follows the
            // observability-conventions.md PascalCase convention; result
            // uses the spec's "ok"/"error" vocabulary.
            audit_log_for_principal(req, "auth.login", "ok", username,
                                    auth::role_to_string(*role_opt), "User", username);
            emit_event("auth.login", req,
                       {{"source_ip", req.remote_addr},
                        {"username", username},
                        {"auth_method", "password"},
                        {"user_agent", req.get_header_value("User-Agent")}});
            return;
        }

        // User has TOTP enrolled — issue an opaque short-lived pending
        // token and require POST /login/mfa to complete.
        auto pending_token =
            auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(32));
        bool challenge_at_capacity = false;
        {
            std::lock_guard lock(mfa_pending_mu_);
            reap_mfa_pending_locked();
            if (mfa_pending_.size() >= mfa_pending_cap_) {
                challenge_at_capacity = true; // load-shed (Hermes H-2)
            } else {
                MfaPending entry;
                entry.username = username;
                entry.role = *role_opt;
                entry.expires_at = std::chrono::steady_clock::now() +
                                   std::chrono::seconds(cfg_.mfa_login_pending_secs);
                mfa_pending_[pending_token] = std::move(entry);
            }
        }
        if (challenge_at_capacity) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"too many pending authentications, retry shortly"},"meta":{"api_version":"v1"}})",
                "application/json");
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_mfa_pending_load_shed_total", {{"kind", "challenge"}})
                    .increment();
            }
            spdlog::warn("MFA pending-token map at capacity ({}) — shedding login challenge for "
                         "source {}",
                         mfa_pending_cap_, req.remote_addr);
            return;
        }
        res.status = 202;
        nlohmann::json body = {{"status", "mfa_required"},
                               {"mfa_pending_token", pending_token},
                               {"expires_in", cfg_.mfa_login_pending_secs}};
        res.set_content(body.dump(), "application/json");
        audit_log_for_principal(req, "mfa.login.required", "ok", username,
                                auth::role_to_string(*role_opt), "User", username);
        emit_event("mfa.login.required", req,
                   {{"source_ip", req.remote_addr}, {"username", username}});
        if (auto* m = auth_mgr_.metrics_registry()) {
            m->counter("yuzu_auth_mfa_challenges_issued_total").increment();
            std::lock_guard lock(mfa_pending_mu_);
            m->gauge("yuzu_auth_mfa_pending_tokens")
                .set(static_cast<double>(mfa_pending_.size()));
        }
    });

    sink.Post("/login/mfa", [this](const httplib::Request& req, httplib::Response& res) {
        // Single error message regardless of failure mode (token-invalid
        // vs code-rejected vs attempts-exhausted) — distinguishing them
        // on the wire gives an attacker a token-validity oracle. The
        // discriminator lives in the audit `detail` column only
        // (Gate 4 consistency N1 + security oracle).
        static constexpr const char* kFailureBody =
            R"({"error":{"code":401,"message":"Invalid verification code"},"meta":{"api_version":"v1"}})";

        auto pending = extract_form_value(req.body, "mfa_pending_token");
        auto code = extract_form_value(req.body, "code");

        // Look up + atomically take ownership of the entry under the
        // lock — without the move, two concurrent submits with the same
        // pending token + same valid code would both succeed and mint
        // two sessions (Gate 4 happy-path B2). We extract the entry
        // here, work without the lock, and on terminal failure we
        // re-insert with the attempts counter bumped.
        MfaPending entry;
        bool found = false;
        {
            std::lock_guard lock(mfa_pending_mu_);
            reap_mfa_pending_locked();
            auto it = mfa_pending_.find(pending);
            if (it != mfa_pending_.end()) {
                entry = std::move(it->second);
                mfa_pending_.erase(it);
                found = true;
            }
        }
        if (!found) {
            res.status = 401;
            res.set_content(kFailureBody, "application/json");
            audit_log(req, "mfa.login.failed", "error", "User", "",
                      "pending token invalid or expired");
            emit_event("mfa.login.failed", req,
                       {{"source_ip", req.remote_addr}, {"reason", "pending_invalid"}}, {},
                       Severity::kWarn);
            return;
        }

        // Reject an enrollment-bootstrap token replayed here. The user is
        // still provisional so mfa_verify_login_code would fail regardless,
        // but an explicit guard keeps the failure audit unambiguous and
        // closes the wrong-endpoint path deterministically. The entry was
        // already consumed at lookup time, so this is terminal.
        if (entry.kind == PendingKind::enrollment) {
            res.status = 401;
            res.set_content(kFailureBody, "application/json");
            audit_log_for_principal(req, "mfa.login.failed", "error", entry.username,
                                    auth::role_to_string(entry.role), "User", entry.username,
                                    "enrollment token used at login-challenge endpoint");
            return;
        }

        auto* db = auth_mgr_.auth_db_ptr();
        if (!db) {
            res.status = 401;
            res.set_content(kFailureBody, "application/json");
            audit_log_for_principal(req, "mfa.login.failed", "error", entry.username,
                                    auth::role_to_string(entry.role), "User", entry.username,
                                    "auth_db unavailable");
            return;
        }

        bool matched = false;
        bool used_recovery = false;
        // Strict shape gate (Gate 4 consistency N2 + unhappy UP-14/UP-20):
        //   - TOTP: exactly 6 ASCII digits
        //   - Recovery: any other shape goes through normalisation +
        //     base32 alphabet check at the store layer
        // Pre-PR1's heuristic admitted 7-digit numeric noise into the
        // recovery PBKDF2 scan (~10 ms CPU each) which compounded UP-11
        // into a sustained DoS vector.
        bool is_totp = code.size() == 6;
        if (is_totp) {
            for (char c : code) {
                if (c < '0' || c > '9') {
                    is_totp = false;
                    break;
                }
            }
        }
        if (is_totp) {
            auto r = db->mfa_verify_login_code(entry.username, code);
            if (r && *r) {
                matched = true;
            }
        } else {
            auto r = db->mfa_consume_recovery_code(entry.username, code);
            if (r && *r) {
                matched = true;
                used_recovery = true;
            }
        }

        if (!matched) {
            // Bump attempts counter and re-insert if still under the cap.
            // Once exhausted the entry stays erased and the operator must
            // start over from /login (rate-limit gap closure for H1+UP-11).
            // Capture identity BEFORE the move-back — reading entry.username
            // after `std::move(entry)` would emit a CC6.6 audit row with an
            // empty principal (governance safety-B1).
            const std::string uname = entry.username;
            const auto urole = entry.role;
            entry.attempts += 1;
            bool exhausted = entry.attempts >= kMfaMaxAttemptsPerPending;
            // Only re-insert if the entry is under the cap AND still within
            // its TTL — re-inserting an already-expired entry would
            // resurrect a token past its deadline for one more attempt
            // window until the next reap (governance UP-13).
            const bool reinsert =
                !exhausted && std::chrono::steady_clock::now() < entry.expires_at;
            std::size_t pending_size = 0;
            {
                std::lock_guard lock(mfa_pending_mu_);
                if (reinsert) {
                    mfa_pending_[pending] = std::move(entry);
                }
                pending_size = mfa_pending_.size();
            }
            res.status = 401;
            res.set_content(kFailureBody, "application/json");
            audit_log_for_principal(req, "mfa.login.failed", "error", uname,
                                    auth::role_to_string(urole), "User", uname,
                                    exhausted ? "attempts exhausted"
                                              : (is_totp ? "totp code rejected"
                                                         : "recovery code rejected"));
            emit_event("mfa.login.failed", req,
                       {{"source_ip", req.remote_addr},
                        {"username", uname},
                        {"method", is_totp ? "totp" : "recovery"},
                        {"attempts_exhausted", exhausted}},
                       {}, Severity::kWarn);
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_mfa_logins_total",
                           {{"method", is_totp ? "totp" : "recovery"},
                            {"result", exhausted ? "exhausted" : "failure"}})
                    .increment();
                m->gauge("yuzu_auth_mfa_pending_tokens")
                    .set(static_cast<double>(pending_size));
            }
            return;
        }

        // Terminal success — entry was already erased atomically at
        // lookup time. Mint the real session marked as MFA-verified.
        auto token = auth_mgr_.create_local_session(entry.username, entry.role, true);
        res.set_header("Set-Cookie", "yuzu_session=" + token + session_cookie_attrs());
        res.set_content(R"({"status":"ok"})", "application/json");
        // Audit chain — emit BOTH the method-specific verb AND the
        // canonical auth.login row so SIEM queries that key on
        // `auth.login` for session-creation parity across password,
        // OIDC, and MFA paths stay correct (Gate 4 architect S2 +
        // happy-path S1 + S2).
        if (used_recovery) {
            audit_log_for_principal(req, "mfa.recovery_code.used", "ok", entry.username,
                                    auth::role_to_string(entry.role), "User", entry.username,
                                    "method=recovery");
        } else {
            audit_log_for_principal(req, "mfa.login.verified", "ok", entry.username,
                                    auth::role_to_string(entry.role), "User", entry.username);
        }
        audit_log_for_principal(req, "auth.login", "ok", entry.username,
                                auth::role_to_string(entry.role), "User", entry.username,
                                used_recovery ? "method=password+recovery"
                                              : "method=password+totp");
        emit_event(used_recovery ? "mfa.recovery_code.used" : "mfa.login.verified", req,
                   {{"source_ip", req.remote_addr},
                    {"username", entry.username},
                    {"auth_method", used_recovery ? "password+recovery" : "password+totp"}});
        if (auto* m = auth_mgr_.metrics_registry()) {
            m->counter("yuzu_auth_mfa_logins_total",
                       {{"method", used_recovery ? "recovery" : "totp"},
                        {"result", "success"}})
                .increment();
            std::lock_guard lock(mfa_pending_mu_);
            m->gauge("yuzu_auth_mfa_pending_tokens")
                .set(static_cast<double>(mfa_pending_.size()));
        }
    });

    // -- MFA enrollment bootstrap (PR3) ---------------------------------------
    //
    // POST /login/mfa/enroll — completes a login that /login blocked
    // because `mfa_enforcement` required MFA and the user had none. /login
    // issued a provisional TOTP secret + an enrollment-pending token; this
    // endpoint confirms the first code against that provisional secret,
    // promotes it to enrolled, mints the (MFA-verified) session, and
    // returns the one-time recovery codes for the browser to display.
    //
    // Only a 6-digit TOTP code is accepted — recovery codes don't exist
    // until enrollment completes, and the strict shape gate keeps the
    // PBKDF2 DoS surface closed (same posture as /login/mfa). Shares the
    // `is_login` rate-limit predicate so the provisional secret can't be
    // brute-forced. Uniform 401 body on every failure mode.
    sink.Post("/login/mfa/enroll", [this](const httplib::Request& req, httplib::Response& res) {
        static constexpr const char* kFailureBody =
            R"({"error":{"code":401,"message":"Invalid verification code"},"meta":{"api_version":"v1"}})";

        auto pending = extract_form_value(req.body, "mfa_pending_token");
        auto code = extract_form_value(req.body, "code");

        // Atomically take ownership of the entry (see /login/mfa rationale —
        // without the move two concurrent confirms could both mint).
        MfaPending entry;
        bool found = false;
        {
            std::lock_guard lock(mfa_pending_mu_);
            reap_mfa_pending_locked();
            auto it = mfa_pending_.find(pending);
            if (it != mfa_pending_.end()) {
                entry = std::move(it->second);
                mfa_pending_.erase(it);
                found = true;
            }
        }
        if (!found) {
            res.status = 401;
            res.set_content(kFailureBody, "application/json");
            audit_log(req, "mfa.enroll.failed", "error", "User", "",
                      "pending token invalid or expired");
            return;
        }

        // Reject a login-challenge token replayed at the enrollment
        // endpoint — the inverse of the guard in /login/mfa.
        if (entry.kind != PendingKind::enrollment) {
            res.status = 401;
            res.set_content(kFailureBody, "application/json");
            audit_log_for_principal(req, "mfa.enroll.failed", "error", entry.username,
                                    auth::role_to_string(entry.role), "User", entry.username,
                                    "login-challenge token used at enrollment endpoint");
            return;
        }

        auto* db = auth_mgr_.auth_db_ptr();
        if (!db) {
            // Uniform 401 (NOT 503) on db-null: matches the /login/mfa
            // sibling and avoids leaking "this pending token is valid" via
            // a distinct status during a store outage (Hermes L-1). The
            // real reason is in the audit detail only.
            res.status = 401;
            res.set_content(kFailureBody, "application/json");
            audit_log_for_principal(req, "mfa.enroll.failed", "error", entry.username,
                                    auth::role_to_string(entry.role), "User", entry.username,
                                    "auth_db unavailable");
            return;
        }

        // Strict shape gate: exactly 6 ASCII digits.
        bool is_totp = code.size() == 6;
        if (is_totp) {
            for (char c : code) {
                if (c < '0' || c > '9') {
                    is_totp = false;
                    break;
                }
            }
        }

        std::vector<std::string> recovery_codes;
        bool verified = false;
        if (is_totp) {
            auto r = db->mfa_verify_enrollment(entry.username, code);
            if (r) {
                recovery_codes = std::move(*r);
                verified = true;
            }
        }

        if (!verified) {
            // Bump attempts; re-insert if still under the cap. The
            // provisional secret persists in the DB across retries (it is
            // NOT re-revealed) so the operator keeps the QR they already
            // scanned; only the next 30s code is needed.
            //
            // Capture identity BEFORE the move-back — reading entry.username
            // after `std::move(entry)` would emit a CC6.6 audit row with an
            // empty principal (governance safety-B1). Snapshot the pending
            // count under the same lock and publish metrics OUTSIDE it, so
            // mfa_pending_mu_ is never held across the metrics-registry lock
            // (lock-discipline parity with /login/mfa; cpp-safety SHOULD).
            const std::string uname = entry.username;
            const auto urole = entry.role;
            entry.attempts += 1;
            bool exhausted = entry.attempts >= kMfaMaxAttemptsPerPending;
            // Re-insert only if under the cap AND still within TTL (UP-13).
            const bool reinsert =
                !exhausted && std::chrono::steady_clock::now() < entry.expires_at;
            std::size_t pending_size = 0;
            {
                std::lock_guard lock(mfa_pending_mu_);
                if (reinsert) {
                    mfa_pending_[pending] = std::move(entry);
                }
                pending_size = mfa_pending_.size();
            }
            res.status = 401;
            res.set_content(kFailureBody, "application/json");
            audit_log_for_principal(
                req, "mfa.enroll.failed", "error", uname, auth::role_to_string(urole), "User",
                uname,
                exhausted ? "attempts exhausted"
                          : (is_totp ? "totp code rejected" : "malformed code"));
            emit_event("mfa.enroll.failed", req,
                       {{"source_ip", req.remote_addr},
                        {"username", uname},
                        {"method", "enroll"},
                        {"attempts_exhausted", exhausted}},
                       {}, Severity::kWarn);
            if (auto* m = auth_mgr_.metrics_registry()) {
                // Failure-counter parity with /login/mfa so enrollment
                // brute-force / storm is alertable (cons-S2 / sre).
                m->counter("yuzu_auth_mfa_logins_total",
                           {{"method", "enroll"},
                            {"result", exhausted ? "exhausted" : "failure"}})
                    .increment();
                m->gauge("yuzu_auth_mfa_pending_tokens")
                    .set(static_cast<double>(pending_size));
            }
            return;
        }

        // Enrollment confirmed — mint the MFA-verified session and return
        // the recovery codes for the one-time reveal. Emit the enrollment
        // verb, the canonical recovery-codes-generated verb, and the
        // canonical auth.login row (session-creation parity with the
        // password / OIDC / login-challenge paths).
        auto token = auth_mgr_.create_local_session(entry.username, entry.role, true);
        res.set_header("Set-Cookie", "yuzu_session=" + token + session_cookie_attrs());
        nlohmann::json body = {{"status", "ok"}, {"recovery_codes", recovery_codes}};
        res.set_content(body.dump(), "application/json");
        audit_log_for_principal(req, "mfa.enroll.verified", "ok", entry.username,
                                auth::role_to_string(entry.role), "User", entry.username,
                                "enforcement bootstrap");
        audit_log_for_principal(req, "mfa.recovery_codes.generated", "ok", entry.username,
                                auth::role_to_string(entry.role), "User", entry.username);
        audit_log_for_principal(req, "auth.login", "ok", entry.username,
                                auth::role_to_string(entry.role), "User", entry.username,
                                "method=password+totp-enroll");
        emit_event("mfa.enroll.verified", req,
                   {{"source_ip", req.remote_addr}, {"username", entry.username}});
        if (auto* m = auth_mgr_.metrics_registry()) {
            m->counter("yuzu_auth_mfa_logins_total", {{"method", "enroll"}, {"result", "success"}})
                .increment();
            std::lock_guard lock(mfa_pending_mu_);
            m->gauge("yuzu_auth_mfa_pending_tokens")
                .set(static_cast<double>(mfa_pending_.size()));
        }
    });

    // -- MFA step-up (PR2) ----------------------------------------------------
    //
    // POST /login/mfa/stepup — re-prove MFA for an existing session so the
    // session's mfa_verified_at refreshes and the high-risk REST/Settings
    // gate at `mfa_step_up.hpp` lets the next mutation through. The endpoint
    // is rate-limited at the server pre-routing layer (`is_login`
    // predicate widened to include this path) so a malicious operator with
    // a valid session cannot pound the TOTP space to brute-force the secret.
    //
    // Failure-mode taxonomy mirrors POST /login/mfa: uniform 401 body
    // regardless of whether the session was missing/stale, the code shape
    // was wrong, or the code mismatched. Discriminator lives in the audit
    // detail only (token-validity oracle defence). API-token principals
    // hit this endpoint with auth_source != "local"/"oidc" — they get a
    // 400 (session step-up is the wrong tool for token rotation).
    sink.Post("/login/mfa/stepup", [this](const httplib::Request& req, httplib::Response& res) {
        static constexpr const char* kFailureBody =
            R"({"error":{"code":401,"message":"MFA step-up failed"},"meta":{"api_version":"v1"}})";

        auto session = require_auth(req, res);
        if (!session)
            return;

        // Only LOCAL sessions can step up here: this endpoint verifies a
        // TOTP / recovery code against a local `users` row. Two other
        // principal kinds reach this code and must be rejected with a
        // precise remediation rather than a misleading 401:
        //   - bearer (api_token/mcp_token): no session to step up; re-issue
        //     the token.
        //   - OIDC: no local secret exists (create_oidc_session never
        //     writes a users row), so mfa_verify_login_code would always
        //     fail. The step-up gate already routes OIDC callers to
        //     /auth/oidc/start; this 400 keeps the endpoint contract honest
        //     instead of silently dead-ending them on a 401 (governance
        //     cons-B1). Audit + correlation_id keep both branches traceable.
        if (session->auth_source != "local") {
            const bool is_oidc = session->auth_source == "oidc";
            const auto cid = detail::make_correlation_id();
            res.status = 400;
            nlohmann::json envelope = {
                {"error",
                 {{"code", 400},
                  {"message",
                   is_oidc ? "OIDC sessions re-prove MFA by re-authenticating with the "
                             "identity provider — start a new SSO sign-in at /auth/oidc/start, "
                             "not local step-up"
                           : "step-up is for session-cookie callers only — re-issue the API "
                             "token to refresh MFA proof"},
                  {"correlation_id", cid}}},
                {"meta", {{"api_version", "v1"}}}};
            res.set_content(envelope.dump(), "application/json");
            audit_log_for_principal(req, "mfa.step_up.failed", "error", session->username,
                                    auth::role_to_string(session->role), "User",
                                    session->username,
                                    (is_oidc ? "oidc session cannot local step up (re-SSO)"
                                             : "bearer credential cannot step up") +
                                        std::string(" (auth_source=") + session->auth_source +
                                        ")");
            return;
        }

        auto* db = auth_mgr_.auth_db_ptr();
        if (!db) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"auth_db unavailable"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }

        auto code = extract_form_value(req.body, "code");
        if (code.empty()) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"missing code"},"meta":{"api_version":"v1"}})",
                "application/json");
            audit_log_for_principal(req, "mfa.step_up.failed", "error", session->username,
                                    auth::role_to_string(session->role), "User",
                                    session->username, "missing code");
            return;
        }

        // Strict shape gate (same as /login/mfa): 6 ASCII digits → TOTP,
        // anything else → recovery code path. Defeats the CPU-DoS shape
        // oracle that a 7-digit numeric noise would otherwise trip.
        bool is_totp = code.size() == 6;
        if (is_totp) {
            for (char c : code) {
                if (c < '0' || c > '9') {
                    is_totp = false;
                    break;
                }
            }
        }
        bool matched = false;
        bool used_recovery = false;
        if (is_totp) {
            auto r = db->mfa_verify_login_code(session->username, code);
            if (r && *r)
                matched = true;
        } else {
            auto r = db->mfa_consume_recovery_code(session->username, code);
            if (r && *r) {
                matched = true;
                used_recovery = true;
            }
        }

        if (!matched) {
            res.status = 401;
            res.set_content(kFailureBody, "application/json");
            audit_log_for_principal(req, "mfa.step_up.failed", "error", session->username,
                                    auth::role_to_string(session->role), "User",
                                    session->username,
                                    is_totp ? "totp code rejected" : "recovery code rejected");
            emit_event("mfa.step_up.failed", req,
                       {{"source_ip", req.remote_addr},
                        {"username", session->username},
                        {"method", is_totp ? "totp" : "recovery"}},
                       {}, Severity::kWarn);
            if (auto* m = auth_mgr_.metrics_registry()) {
                m->counter("yuzu_auth_mfa_step_up_total",
                           {{"method", is_totp ? "totp" : "recovery"}, {"result", "failure"}})
                    .increment();
            }
            return;
        }

        // Success — stamp `mfa_verified_at = steady_clock::now()` on the
        // existing session row. The cookie itself does NOT rotate — the
        // step-up refreshes a session attribute, it does not mint a new
        // session (which would break in-flight HTMX requests from the
        // same browser tab).
        auto token = extract_session_cookie(req);
        if (!auth_mgr_.mark_session_mfa_verified(token)) {
            // Defensive — require_auth succeeded so the token resolves to
            // a session; if mark_session_mfa_verified can't find it, the
            // session was concurrently invalidated. Fail closed.
            res.status = 401;
            res.set_content(kFailureBody, "application/json");
            audit_log_for_principal(req, "mfa.step_up.failed", "error", session->username,
                                    auth::role_to_string(session->role), "User",
                                    session->username, "session vanished during step-up");
            return;
        }
        res.set_content(R"({"status":"ok"})", "application/json");
        audit_log_for_principal(req, "mfa.step_up.passed", "ok", session->username,
                                auth::role_to_string(session->role), "User", session->username,
                                used_recovery ? "method=recovery" : "method=totp");
        emit_event("mfa.step_up.passed", req,
                   {{"source_ip", req.remote_addr},
                    {"username", session->username},
                    {"method", used_recovery ? "recovery" : "totp"}});
        if (auto* m = auth_mgr_.metrics_registry()) {
            m->counter("yuzu_auth_mfa_step_up_total",
                       {{"method", used_recovery ? "recovery" : "totp"}, {"result", "success"}})
                .increment();
        }
    });

    // -- Logout ---------------------------------------------------------------
    sink.Post("/logout", [this](const httplib::Request& req, httplib::Response& res) {
        audit_log(req, "auth.logout", "success");
        emit_event("auth.logout", req);
        auto token = extract_session_cookie(req);
        if (!token.empty()) {
            auth_mgr_.invalidate_session(token);
        }
        res.set_header("Set-Cookie", "yuzu_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
        // HTMX clients get a redirect header; non-HTMX get JSON
        if (!req.get_header_value("HX-Request").empty()) {
            res.set_header("HX-Redirect", "/login");
            res.set_content("", "text/plain");
        } else {
            res.set_content(R"({"status":"ok"})", "application/json");
        }
    });

    // -- OIDC SSO endpoints ---------------------------------------------------
    sink.Get("/auth/oidc/start", [this](const httplib::Request& req, httplib::Response& res) {
        std::shared_lock oidc_lock(oidc_mu_);
        if (!oidc_provider_ || !oidc_provider_->is_enabled()) {
            res.status = 404;
            res.set_content(
                R"({"error":{"code":404,"message":"OIDC not configured"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        // Use the configured redirect URI only — never derive from the
        // Host header, which can be manipulated for phishing attacks (M3).
        if (cfg_.oidc_redirect_uri.empty()) {
            res.status = 500;
            res.set_content(
                R"({"error":{"code":500,"message":"OIDC redirect_uri not configured — set --oidc-redirect-uri or YUZU_OIDC_REDIRECT_URI"},"meta":{"api_version":"v1"}})",
                "application/json");
            spdlog::error("OIDC auth flow blocked: redirect_uri not configured");
            return;
        }
        auto auth_url = oidc_provider_->start_auth_flow(cfg_.oidc_redirect_uri);
        res.set_redirect(auth_url);
    });

    sink.Get("/auth/callback", [this](const httplib::Request& req, httplib::Response& res) {
        std::shared_lock oidc_lock(oidc_mu_);
        if (!oidc_provider_) {
            res.status = 404;
            res.set_content("OIDC not configured", "text/plain");
            return;
        }

        // Check for error response from IdP
        auto error = req.get_param_value("error");
        if (!error.empty()) {
            auto desc = req.get_param_value("error_description");
            spdlog::warn("OIDC error from IdP: {} - {}", error, desc);
            res.set_redirect("/login?error=sso_denied");
            return;
        }

        auto code = req.get_param_value("code");
        auto state = req.get_param_value("state");

        if (code.empty() || state.empty()) {
            res.set_redirect("/login?error=sso_invalid");
            return;
        }

        auto result = oidc_provider_->handle_callback(code, state);
        if (!result) {
            spdlog::warn("OIDC callback failed: {}", result.error());
            audit_log(req, "auth.oidc_login_failed", "failure");
            emit_event("auth.oidc_login_failed", req,
                       {{"source_ip", req.remote_addr}, {"error", result.error()}}, {},
                       Severity::kWarn);
            res.set_redirect("/login?error=sso_failed");
            return;
        }

        auto& claims = result.value();
        auto email = claims.email.empty() ? claims.preferred_username : claims.email;
        auto display = claims.name.empty() ? email : claims.name;
        auto admin_gid = oidc_provider_ ? cfg_.oidc_admin_group : std::string{};

        // PR3 / SOC 2 CC6.6 — seed the session's MFA-verified timestamp
        // when the IdP `amr` claim attests a multi-factor login. The
        // step-up gate (mfa_step_up.cpp) consumes this so an MFA'd SSO
        // session clears high-risk endpoints without a redundant local
        // prompt, while a single-factor SSO login is gated. Anchor the
        // steady-clock timestamp to the IdP-asserted `iat` so a stale
        // assertion still re-prompts: a token issued `age` ago is treated
        // as proven `age` ago. `iat` is wall-clock; convert the age into
        // the steady-clock domain (never store `iat` directly — an NTP
        // step must not be able to extend the step-up window, hard
        // invariant #5). Negative ages (IdP clock ahead of ours) clamp to
        // "just now".
        const bool amr_mfa_asserted = amr_asserts_mfa(claims.amr);
        std::chrono::steady_clock::time_point mfa_at{};
        if (amr_mfa_asserted && claims.iat > 0) {
            // Anchor the steady-clock proof to the IdP-asserted `iat` so a
            // stale assertion still re-prompts: a token issued `age` ago is
            // treated as proven `age` ago. Clamp the system-clock domain
            // BEFORE the cast to steady_clock::duration (a future editor
            // casting first then clamping against steady_clock::zero risks
            // truncation skew; cpp-expert SHOULD). Negative age (IdP clock
            // ahead of ours) clamps to "just now"; it can only ever shorten
            // the window, never extend it. `iat<=0` (missing/0) is NOT
            // seeded — fabricating a fresh window from a timestampless
            // assertion would let a replayed amr-without-iat token look
            // fresh (governance UP-9). An un-seeded OIDC session simply
            // passes the step-up gate like any non-MFA SSO identity.
            auto asserted =
                std::chrono::system_clock::from_time_t(static_cast<std::time_t>(claims.iat));
            auto age = std::chrono::system_clock::now() - asserted;
            if (age < std::chrono::system_clock::duration::zero()) {
                age = std::chrono::system_clock::duration::zero();
            }
            mfa_at = std::chrono::steady_clock::now() -
                     std::chrono::duration_cast<std::chrono::steady_clock::duration>(age);
        }

        auto session_token = auth_mgr_.create_oidc_session(display, email, claims.sub,
                                                           claims.groups, admin_gid, mfa_at);

        // Sync Entra groups into the RBAC store so that group-scoped role
        // assignments (e.g. ApiTokenManager on an Entra group) take effect.
        if (rbac_store_ && !claims.groups.empty()) {
            auto username = display.empty() ? email : display;
            for (const auto& gid : claims.groups) {
                (void)rbac_store_->create_group({.name = gid,
                                                 .description = "Entra ID group (auto-synced)",
                                                 .source = "entra",
                                                 .external_id = gid});
                (void)rbac_store_->add_group_member(gid, username);
            }
        }

        res.set_header("Set-Cookie", "yuzu_session=" + session_token + session_cookie_attrs());

        // Explicit-principal audit row — request lands at /auth/callback
        // with no session cookie yet, so the default resolve_session
        // path would leave principal empty (Gate 4 consistency B3). Use
        // the validated `display` from the IdP as the canonical
        // principal name. Role is resolved from the freshly-minted
        // session — for the audit row we re-validate to capture the
        // role the user actually holds (group-mapping may have made
        // them admin).
        auto effective_role = auth_mgr_.validate_session(session_token)
                                  .transform([](const auth::Session& s) {
                                      return auth::role_to_string(s.role);
                                  })
                                  .value_or(std::string{"user"});
        // Record whether the IdP attested MFA (the `amr` decision) in the
        // audit detail so the CC6.6 "was this privileged SSO login MFA-
        // verified" question is answerable from Yuzu's own chain without
        // cross-referencing IdP logs (governance compliance-S2).
        audit_log_for_principal(req, "auth.oidc_login", "ok", display, effective_role, "User",
                                display,
                                std::string("amr_mfa_asserted=") +
                                    (amr_mfa_asserted ? "true" : "false"));
        emit_event("auth.oidc_login", req,
                   {{"source_ip", req.remote_addr},
                    {"username", display},
                    {"auth_method", "oidc"},
                    {"amr_mfa_asserted", amr_mfa_asserted},
                    {"oidc_sub", claims.sub},
                    {"email", email},
                    {"name", claims.name}});

        res.set_redirect("/");
    });

    // ── JIT admin elevation (SOC 2 CC6.3/CC6.6) — /auth-and-authz P1 #9 ───────
    // A pre-authorized (users.elevation_eligible) operator activates a
    // time-boxed, justified, MFA-gated admin elevation on their COOKIE session;
    // effective_role() then treats the session as admin for the window and it
    // auto-reverts. See docs/auth-architecture.md "JIT admin elevation".

    // Shared step-up gate: elevating to admin and granting eligibility are both
    // high-risk and require a fresh MFA proof (reuses require_mfa_step_up).
    auto elevation_step_up = [this](const httplib::Request& req, httplib::Response& res,
                                    const auth::Session& session,
                                    const std::string& label) -> bool {
        auto* db = auth_mgr_.auth_db_ptr();
        if (!db)
            return true; // legacy config-file-only: step-up needs auth.db (fail-open, as elsewhere)
        return require_mfa_step_up(
            req, res, session, *db, cfg_.mfa_step_up_window_secs,
            [this](const httplib::Request& r, const std::string& a, const std::string& rs,
                   const std::string& tt, const std::string& ti, const std::string& d) {
                return audit_log(r, a, rs, tt, ti, d);
            },
            label, cfg_.mfa_enforcement);
    };

    // POST /api/v1/users/<name>/elevation-eligibility — admin grants/revokes who
    // may elevate. Body: {"eligible": <bool>}. Admin + step-up gated.
    sink.Post(R"(/api/v1/users/([^/]+)/elevation-eligibility)",
              [this, elevation_step_up](const httplib::Request& req, httplib::Response& res) {
                  const auto cid = detail::make_correlation_id();
                  res.set_header("X-Correlation-Id", cid);
                  if (!require_admin(req, res))
                      return; // sets 401/403 + audits
                  auto session = resolve_session(req);
                  if (!session) {
                      res.status = 401;
                      res.set_content(a4_denial(res, 401, "unauthorized"), "application/json");
                      return;
                  }
                  if (!elevation_step_up(req, res, *session,
                                         "POST /api/v1/users/{name}/elevation-eligibility"))
                      return;
                  auto* db = auth_mgr_.auth_db_ptr();
                  if (!db) {
                      res.status = 503;
                      res.set_content(detail::error_json_a4(503, "JIT elevation requires the "
                                                                 "persistent auth store",
                                                            cid, "start the server with --data-dir"),
                                      "application/json");
                      return;
                  }
                  const auto target = req.matches[1].str();
                  if (target.empty() || !is_valid_username(target)) {
                      res.status = 400;
                      res.set_content(detail::error_json_a4(400, "invalid username format", cid,
                                                            "username must match the allowed format"),
                                      "application/json");
                      return;
                  }
                  auto body = nlohmann::json::parse(req.body, nullptr, false);
                  if (!body.is_object() || !body.contains("eligible") ||
                      !body["eligible"].is_boolean()) {
                      res.status = 400;
                      res.set_content(detail::error_json_a4(400, "body must be {\"eligible\": bool}",
                                                            cid),
                                      "application/json");
                      return;
                  }
                  const bool eligible = body["eligible"].get<bool>();
                  if (auto r = db->set_elevation_eligible(target, eligible); !r) {
                      const auto err = r.error();
                      const int code = err == AuthDBError::UserNotFound ? 404 : 500;
                      audit_log(req, "user.elevation_eligibility.set", "error", "User", target,
                                "store error");
                      res.status = code;
                      res.set_content(detail::error_json_a4(code,
                                                            code == 404 ? "user not found"
                                                                        : "failed to update",
                                                            cid),
                                      "application/json");
                      return;
                  }
                  audit_log(req, "user.elevation_eligibility.set", "ok", "User", target,
                            eligible ? "eligible=true" : "eligible=false");
                  res.set_content(R"({"status":"ok"})", "application/json");
              });

    // POST /api/v1/elevate — activate a time-boxed admin elevation on THIS cookie
    // session. Body: {"justification": <str, required>, "duration_secs": <int>}.
    sink.Post("/api/v1/elevate", [this, elevation_step_up](const httplib::Request& req,
                                                           httplib::Response& res) {
        const auto cid = detail::make_correlation_id();
        res.set_header("X-Correlation-Id", cid);
        // Elevation is COOKIE-session only — an API/MCP token cannot elevate
        // (it carries no cookie, and elevate_session keys on the cookie token).
        auto token = extract_session_cookie(req);
        if (token.empty()) {
            res.status = 401;
            res.set_content(detail::error_json_a4(401, "elevation requires an interactive session",
                                                  cid, "sign in to the dashboard, then elevate"),
                            "application/json");
            return;
        }
        auto session = auth_mgr_.validate_session(token);
        if (!session) {
            res.status = 401;
            res.set_content(a4_denial(res, 401, "unauthorized"), "application/json");
            return;
        }
        auto* db = auth_mgr_.auth_db_ptr();
        if (!db) {
            res.status = 503;
            res.set_content(detail::error_json_a4(503, "JIT elevation requires the persistent auth "
                                                       "store",
                                                  cid, "start the server with --data-dir"),
                            "application/json");
            return;
        }
        // Eligibility (fail-closed): a store read error denies.
        auto elig = db->is_elevation_eligible(session->username);
        if (!elig || !*elig) {
            audit_log_for_principal(req, "role.elevation.denied", "denied", session->username,
                                    auth::role_to_string(session->role), "User", session->username,
                                    elig ? "not eligible" : "eligibility read failed");
            res.status = 403;
            res.set_content(detail::error_json_a4(403, "not authorized to elevate", cid,
                                                  "ask an administrator to grant you elevation "
                                                  "eligibility"),
                            "application/json");
            return;
        }
        // High-risk: require a fresh MFA proof before granting admin.
        if (!elevation_step_up(req, res, *session, "POST /api/v1/elevate"))
            return;
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string justification =
            body.is_object() ? body.value("justification", std::string{}) : std::string{};
        // Justification is mandatory (the auditable reason). Sanitise control
        // bytes (anti log-injection) and cap length (anti audit-row bloat).
        for (char& c : justification)
            if (static_cast<unsigned char>(c) < 0x20)
                c = ' ';
        // trim surrounding whitespace for the empty-check
        auto first = justification.find_first_not_of(' ');
        if (first == std::string::npos) {
            res.status = 400;
            res.set_content(detail::error_json_a4(400, "justification is required", cid,
                                                  "include a non-empty \"justification\""),
                            "application/json");
            return;
        }
        if (justification.size() > kMaxJustificationLength)
            justification.resize(kMaxJustificationLength);
        int duration = body.is_object() ? body.value("duration_secs", 0) : 0;
        if (duration <= 0)
            duration = cfg_.jit_max_elevation_secs; // unspecified → the full cap
        if (duration > cfg_.jit_max_elevation_secs)
            duration = cfg_.jit_max_elevation_secs; // clamp
        auto until = auth_mgr_.elevate_session(token, std::chrono::seconds(duration));
        if (!until) {
            res.status = 401; // session vanished between validate and elevate
            res.set_content(a4_denial(res, 401, "unauthorized"), "application/json");
            return;
        }
        audit_log_for_principal(req, "role.elevation.granted", "ok", session->username, "admin",
                                "User", session->username,
                                "duration_secs=" + std::to_string(duration) +
                                    " justification=" + justification);
        emit_event("role.elevation.granted", req,
                   {{"username", session->username}, {"duration_secs", std::to_string(duration)}}, {},
                   Severity::kWarn);
        nlohmann::json out = {{"status", "ok"}, {"expires_in", duration}};
        res.set_content(out.dump(), "application/json");
    });

    // POST /api/v1/elevate/revoke — manual step-down (clear an active elevation).
    sink.Post("/api/v1/elevate/revoke",
              [this](const httplib::Request& req, httplib::Response& res) {
                  auto token = extract_session_cookie(req);
                  if (token.empty()) {
                      res.status = 401;
                      res.set_content(a4_denial(res, 401, "unauthorized"), "application/json");
                      return;
                  }
                  auto session = auth_mgr_.validate_session(token);
                  if (!session) {
                      res.status = 401;
                      res.set_content(a4_denial(res, 401, "unauthorized"), "application/json");
                      return;
                  }
                  const bool was_elevated = auth_mgr_.revoke_elevation(token);
                  audit_log_for_principal(req, "role.elevation.revoked", "ok", session->username,
                                          auth::role_to_string(session->role), "User",
                                          session->username,
                                          was_elevated ? "was_elevated=true" : "was_elevated=false");
                  res.set_content(R"({"status":"ok"})", "application/json");
              });
}

} // namespace yuzu::server
