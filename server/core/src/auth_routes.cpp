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
#include "rest_a4_envelope.hpp"

#include <nlohmann/json.hpp>

// Login page HTML (defined in login_ui.cpp)
extern const char* const kLoginHtml;

namespace yuzu::server {

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
    res.set_content(
        R"({"error":{"code":401,"message":"unauthorized"},"meta":{"api_version":"v1"}})",
        "application/json");
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

    if (session->role != auth::Role::admin) {
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
        // mcp_server.cpp returns kApprovalRequired for the same reason; mirror
        // that behavior here so the REST transport cannot bypass it (#520).
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

    // Legacy fallback: write/delete/execute/approve require admin
    if (operation != "Read" && session->role != auth::Role::admin) {
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
            res.set_content(nlohmann::json({{"error",
                                             {{"code", 403},
                                              {"message", "MCP token tier does not allow " +
                                                              securable_type + ":" + operation}}},
                                            {"meta", {{"api_version", "v1"}}}})
                                .dump(),
                            "application/json");
            return false;
        }
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

    // Legacy fallback: write/delete/execute/approve require admin
    if (operation != "Read" && session->role != auth::Role::admin) {
        audit_log(req, "auth.scoped_permission_required", "denied", agent_id,
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
            return;
        }

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
        {
            std::lock_guard lock(mfa_pending_mu_);
            reap_mfa_pending_locked();
            MfaPending entry;
            entry.username = username;
            entry.role = *role_opt;
            entry.expires_at = std::chrono::steady_clock::now() +
                               std::chrono::seconds(cfg_.mfa_login_pending_secs);
            mfa_pending_[pending_token] = std::move(entry);
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
            entry.attempts += 1;
            bool exhausted = entry.attempts >= kMfaMaxAttemptsPerPending;
            std::size_t pending_size = 0;
            if (!exhausted) {
                std::lock_guard lock(mfa_pending_mu_);
                mfa_pending_[pending] = std::move(entry);
                pending_size = mfa_pending_.size();
            } else {
                std::lock_guard lock(mfa_pending_mu_);
                pending_size = mfa_pending_.size();
            }
            res.status = 401;
            res.set_content(kFailureBody, "application/json");
            audit_log_for_principal(req, "mfa.login.failed", "error", entry.username,
                                    auth::role_to_string(entry.role), "User", entry.username,
                                    exhausted ? "attempts exhausted"
                                              : (is_totp ? "totp code rejected"
                                                         : "recovery code rejected"));
            emit_event("mfa.login.failed", req,
                       {{"source_ip", req.remote_addr},
                        {"username", entry.username},
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

        // Bearer-credential callers cannot step up a session (they don't
        // have one). Surface this as 400 with a precise remediation hint
        // so an agentic worker that hit this endpoint by mistake knows
        // to re-issue the token instead. Audit emission + per-request
        // correlation_id keep this branch traceable (governance Gate 2
        // sec-M4 + happy-N1).
        if (session->auth_source != "local" && session->auth_source != "oidc") {
            const auto cid = detail::make_correlation_id();
            res.status = 400;
            nlohmann::json envelope = {
                {"error",
                 {{"code", 400},
                  {"message",
                   "step-up is for session-cookie callers only — re-issue the API "
                   "token to refresh MFA proof"},
                  {"correlation_id", cid}}},
                {"meta", {{"api_version", "v1"}}}};
            res.set_content(envelope.dump(), "application/json");
            audit_log_for_principal(req, "mfa.step_up.failed", "error", session->username,
                                    auth::role_to_string(session->role), "User",
                                    session->username,
                                    "bearer credential cannot step up (auth_source=" +
                                        session->auth_source + ")");
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
        auto session_token =
            auth_mgr_.create_oidc_session(display, email, claims.sub, claims.groups, admin_gid);

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
        audit_log_for_principal(req, "auth.oidc_login", "ok", display, effective_role, "User",
                                display);
        emit_event("auth.oidc_login", req,
                   {{"source_ip", req.remote_addr},
                    {"username", display},
                    {"auth_method", "oidc"},
                    {"oidc_sub", claims.sub},
                    {"email", email},
                    {"name", claims.name}});

        res.set_redirect("/");
    });
}

} // namespace yuzu::server
