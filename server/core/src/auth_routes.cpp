#include "auth_routes.hpp"

#include <yuzu/server/server.hpp>

#include <spdlog/spdlog.h>

#include <shared_mutex>

// Login page HTML (defined in login_ui.cpp)
extern const char* const kLoginHtml;

namespace yuzu::server {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

AuthRoutes::AuthRoutes(Config& cfg,
                       auth::AuthManager& auth_mgr,
                       RbacStore* rbac_store,
                       ApiTokenStore* api_token_store,
                       AuditStore* audit_store,
                       ManagementGroupStore* mgmt_group_store,
                       TagStore* tag_store,
                       AnalyticsEventStore* analytics_store,
                       std::shared_mutex& oidc_mu,
                       std::unique_ptr<oidc::OidcProvider>& oidc_provider)
    : cfg_(cfg)
    , auth_mgr_(auth_mgr)
    , rbac_store_(rbac_store)
    , api_token_store_(api_token_store)
    , audit_store_(audit_store)
    , mgmt_group_store_(mgmt_group_store)
    , tag_store_(tag_store)
    , analytics_store_(analytics_store)
    , oidc_mu_(oidc_mu)
    , oidc_provider_(oidc_provider) {}

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
    if (!custom_header.empty() && custom_header.size() <= auth::kMaxApiTokenLength && api_token_store_) {
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

    // Scoped tokens (service-scoped or MCP-tier) carry the creator's legacy role but are
    // explicitly limited to ITServiceOwner-level permissions and must never reach admin
    // routes regardless of the creator's role (#520).
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
        audit_log(req, "auth.admin_required", "denied", "", "",
                  "non-admin user blocked from admin route");
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

    // MCP-tier tokens are explicitly limited to ITServiceOwner-level permissions
    // and must never reach write/execute/delete/approve routes when RBAC is
    // disabled, regardless of the creator's legacy role (#520).
    if (!session->mcp_tier.empty()) {
        if (!rbac_store_ || !rbac_store_->is_rbac_enabled()) {
            audit_log(req, "auth.permission_required", "denied", "", "",
                      "MCP token blocked: RBAC not enabled");
            res.status = 403;
            res.set_content(
                R"({"error":{"code":403,"message":"MCP tokens require RBAC to be enabled"},"meta":{"api_version":"v1"}})",
                "application/json");
            return false;
        }
        if (!rbac_store_->check_role_has_permission("ITServiceOwner", securable_type, operation)) {
            audit_log(req, "auth.permission_required", "denied", "", "",
                      "MCP token blocked: lacks ITServiceOwner permission");
            res.status = 403;
            res.set_content(
                nlohmann::json({{"error", "forbidden"},
                                {"detail", "MCP token does not grant " +
                                               securable_type + ":" + operation}})
                    .dump(),
                "application/json");
            return false;
        }
        return true;
    }

    // Service-scoped tokens: check if the ITServiceOwner role grants this permission.
    // Scoped tokens cannot be used when RBAC is disabled.
    if (!session->token_scope_service.empty()) {
        if (!rbac_store_ || !rbac_store_->is_rbac_enabled()) {
            res.status = 403;
            res.set_content(
                R"({"error":{"code":403,"message":"service-scoped tokens require RBAC to be enabled"},"meta":{"api_version":"v1"}})",
                "application/json");
            return false;
        }
        if (!rbac_store_->check_role_has_permission("ITServiceOwner", securable_type, operation)) {
            res.status = 403;
            res.set_content(
                nlohmann::json({{"error", "forbidden"},
                                {"detail", "service-scoped token does not grant " +
                                               securable_type + ":" + operation}})
                    .dump(),
                "application/json");
            return false;
        }
        return true;
    }

    if (rbac_store_ && rbac_store_->is_rbac_enabled()) {
        if (!rbac_store_->check_permission(session->username, securable_type, operation)) {
            res.status = 403;
            res.set_content(
                nlohmann::json({{"error", "forbidden"},
                                {"required_permission", securable_type + ":" + operation}})
                    .dump(),
                "application/json");
            return false;
        }
        return true;
    }

    // Legacy fallback: write/delete/execute/approve require admin
    if (operation != "Read" && session->role != auth::Role::admin) {
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

    // MCP-tier tokens: same as require_permission() — limited to ITServiceOwner
    // permissions under RBAC, blocked entirely when RBAC is disabled (#520).
    if (!session->mcp_tier.empty()) {
        if (!rbac_store_ || !rbac_store_->is_rbac_enabled()) {
            audit_log(req, "auth.scoped_permission_required", "denied", "", "",
                      "MCP token blocked: RBAC not enabled");
            res.status = 403;
            res.set_content(
                R"({"error":{"code":403,"message":"MCP tokens require RBAC to be enabled"},"meta":{"api_version":"v1"}})",
                "application/json");
            return false;
        }
        // Check that the ITServiceOwner role grants this permission type
        if (!rbac_store_->check_role_has_permission("ITServiceOwner", securable_type, operation)) {
            audit_log(req, "auth.scoped_permission_required", "denied", "", "",
                      "MCP token blocked: lacks ITServiceOwner permission");
            res.status = 403;
            res.set_content(
                nlohmann::json({{"error", "forbidden"},
                                {"detail", "MCP token does not grant " +
                                               securable_type + ":" + operation}})
                    .dump(),
                "application/json");
            return false;
        }
        // MCP tokens are scoped by tier; verify the target agent belongs to an
        // allowed service for this tier. Use the same tag-store check as
        // service-scoped tokens.
        if (!tag_store_) {
            audit_log(req, "auth.scoped_permission_required", "denied", "", "",
                      "MCP token blocked: tag store unavailable");
            res.status = 503;
            res.set_content(R"({"error":{"code":503,"message":"tag store unavailable, cannot verify scope"},"meta":{"api_version":"v1"}})",
                            "application/json");
            return false;
        }
        if (!agent_id.empty()) {
            // MCP tokens are scoped by tier, not by named service. However, we
            // still enforce that the target agent must have a valid service tag.
            auto agent_service = tag_store_->get_tag(agent_id, "service");
            if (agent_service.empty()) {
                audit_log(req, "auth.scoped_permission_required", "denied", agent_id,
                          "agent has no service tag");
                res.status = 403;
                res.set_content(
                    nlohmann::json({{"error", "forbidden"},
                                    {"detail", "agent has no service tag"}})
                        .dump(),
                    "application/json");
                return false;
            }
        }
        return true;
    }

    // Service-scoped tokens: verify the target agent belongs to the token's service,
    // and that the ITServiceOwner role grants the required permission.
    if (!session->token_scope_service.empty()) {
        if (!rbac_store_ || !rbac_store_->is_rbac_enabled()) {
            res.status = 403;
            res.set_content(
                R"({"error":{"code":403,"message":"service-scoped tokens require RBAC to be enabled"},"meta":{"api_version":"v1"}})",
                "application/json");
            return false;
        }
        // Check that the ITServiceOwner role grants this permission type
        if (!rbac_store_->check_role_has_permission("ITServiceOwner", securable_type, operation)) {
            res.status = 403;
            res.set_content(
                nlohmann::json({{"error", "forbidden"},
                                {"detail", "service-scoped token does not grant " +
                                               securable_type + ":" + operation}})
                    .dump(),
                "application/json");
            return false;
        }
        // Verify the target agent's service tag matches the token's scope
        if (!tag_store_) {
            // Cannot verify scope without TagStore — deny rather than silently grant (UH-6)
            res.status = 503;
            res.set_content(R"({"error":{"code":503,"message":"tag store unavailable, cannot verify scope"},"meta":{"api_version":"v1"}})",
                            "application/json");
            return false;
        }
        if (!agent_id.empty()) {
            auto agent_service = tag_store_->get_tag(agent_id, "service");
            if (agent_service != session->token_scope_service) {
                res.status = 403;
                res.set_content(
                    nlohmann::json(
                        {{"error", "forbidden"},
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
            res.status = 403;
            res.set_content(
                nlohmann::json({{"error", "forbidden"},
                                {"required_permission", securable_type + ":" + operation}})
                    .dump(),
                "application/json");
            return false;
        }
        return true;
    }

    // Legacy fallback: write/delete/execute/approve require admin
    if (operation != "Read" && session->role != auth::Role::admin) {
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

void AuthRoutes::audit_log(const httplib::Request& req, const std::string& action,
                           const std::string& result, const std::string& target_type,
                           const std::string& target_id, const std::string& detail) {
    if (!audit_store_)
        return;
    auto event = make_audit_event(req, action, result);
    event.target_type = target_type;
    event.target_id = target_id;
    event.detail = detail;
    audit_store_->log(event);
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
    // -- Login page -----------------------------------------------------------
    svr.Get("/login", [this](const httplib::Request& req, httplib::Response& res) {
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

    svr.Post("/login", [this](const httplib::Request& req, httplib::Response& res) {
        auto username = extract_form_value(req.body, "username");
        auto password = extract_form_value(req.body, "password");

        auto token = auth_mgr_.authenticate(username, password);
        if (!token) {
            res.status = 401;
            res.set_content(
                R"({"error":{"code":401,"message":"Invalid username or password"},"meta":{"api_version":"v1"}})",
                "application/json");
            audit_log(req, "auth.login_failed", "failure", "user", username);
            emit_event("auth.login_failed", req,
                       {{"source_ip", req.remote_addr}, {"username", username}}, {},
                       Severity::kWarn);
            return;
        }

        res.set_header("Set-Cookie", "yuzu_session=" + *token + session_cookie_attrs());
        res.set_content(R"({"status":"ok"})", "application/json");
        audit_log(req, "auth.login", "success", "user", username);
        emit_event("auth.login", req,
                   {{"source_ip", req.remote_addr},
                    {"user_agent", req.get_header_value("User-Agent")}});
    });

    // -- Logout ---------------------------------------------------------------
    svr.Post("/logout", [this](const httplib::Request& req, httplib::Response& res) {
        audit_log(req, "auth.logout", "success");
        emit_event("auth.logout", req);
        auto token = extract_session_cookie(req);
        if (!token.empty()) {
            auth_mgr_.invalidate_session(token);
        }
        res.set_header("Set-Cookie",
                       "yuzu_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
        // HTMX clients get a redirect header; non-HTMX get JSON
        if (!req.get_header_value("HX-Request").empty()) {
            res.set_header("HX-Redirect", "/login");
            res.set_content("", "text/plain");
        } else {
            res.set_content(R"({"status":"ok"})", "application/json");
        }
    });

    // -- OIDC SSO endpoints ---------------------------------------------------
    svr.Get("/auth/oidc/start", [this](const httplib::Request& req, httplib::Response& res) {
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

    svr.Get("/auth/callback", [this](const httplib::Request& req, httplib::Response& res) {
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

        audit_log(req, "auth.oidc_login", "success", "user", display);
        emit_event("auth.oidc_login", req,
                   {{"source_ip", req.remote_addr},
                    {"oidc_sub", claims.sub},
                    {"email", email},
                    {"name", claims.name}});

        res.set_redirect("/");
    });
}

} // namespace yuzu::server
