#include "rest_api_v1.hpp"
#include "rest_api_v1_helpers.hpp"

#include "api_token_store.hpp"
#include "management_group_store.hpp"
#include "quarantine_store.hpp"
#include "rbac_store.hpp"
#include "tag_store.hpp"

namespace yuzu::server {

void register_security_routes(httplib::Server& svr, RestApiV1::AuthFn auth_fn,
                              RestApiV1::PermFn perm_fn, RestApiV1::AuditFn audit_fn,
                              ApiTokenStore* token_store, QuarantineStore* quarantine_store,
                              RbacStore* rbac_store, ManagementGroupStore* mgmt_store,
                              TagStore* tag_store) {

    // ── API Tokens (/api/v1/tokens) ──────────────────────────────────────

    svr.Get("/api/v1/tokens",
            [auth_fn, perm_fn, token_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "ApiToken", "Read"))
                    return;
                if (!token_store) {
                    res.status = 503;
                    return;
                }

                auto session = auth_fn(req, res);
                if (!session)
                    return;

                auto tokens = token_store->list_tokens(session->username);
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& t : tokens) {
                    nlohmann::json j = {{"token_id", t.token_id},
                                        {"name", t.name},
                                        {"principal_id", t.principal_id},
                                        {"created_at", t.created_at},
                                        {"expires_at", t.expires_at},
                                        {"last_used_at", t.last_used_at},
                                        {"revoked", t.revoked}};
                    if (!t.scope_service.empty())
                        j["scope_service"] = t.scope_service;
                    arr.push_back(std::move(j));
                }
                res.set_content(list_response(arr, static_cast<int64_t>(tokens.size())).dump(),
                                "application/json");
            });

    svr.Post("/api/v1/tokens", [auth_fn, perm_fn, audit_fn, token_store, rbac_store, mgmt_store,
                                tag_store](const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "ApiToken", "Write"))
            return;
        if (!token_store) {
            res.status = 503;
            return;
        }

        auto session = auth_fn(req, res);
        if (!session)
            return;

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto name = body.value("name", "");
        auto expires_at = body.value("expires_at", int64_t{0});
        auto scope_service = body.value("scope_service", "");

        // Authorization for service-scoped tokens
        if (!scope_service.empty()) {
            if (!rbac_store || !rbac_store->is_rbac_enabled()) {
                res.status = 400;
                res.set_content(
                    error_response("service-scoped tokens require RBAC to be enabled").dump(),
                    "application/json");
                return;
            }
            bool authorized =
                rbac_store->check_permission(session->username, "ManagementGroup", "Write");
            if (!authorized && mgmt_store) {
                auto svc_group = mgmt_store->find_group_by_name("Service: " + scope_service);
                if (svc_group) {
                    auto group_roles = mgmt_store->get_group_roles(svc_group->id);
                    for (const auto& gr : group_roles) {
                        if (gr.principal_type == "user" && gr.principal_id == session->username &&
                            gr.role_name == "ITServiceOwner") {
                            authorized = true;
                            break;
                        }
                    }
                }
            }
            if (!authorized) {
                res.status = 403;
                res.set_content(
                    error_response("ITServiceOwner authority required for service '" +
                                   scope_service + "'")
                        .dump(),
                    "application/json");
                return;
            }
        }

        auto result =
            token_store->create_token(name, session->username, expires_at, scope_service);
        if (!result) {
            res.status = 400;
            res.set_content(error_response(result.error()).dump(), "application/json");
            return;
        }
        auto detail = scope_service.empty() ? "" : "scope_service=" + scope_service;
        audit_fn(req, "api_token.create", "success", "ApiToken", name, detail);
        res.status = 201;
        nlohmann::json resp = {{"token", *result}, {"name", name}};
        if (!scope_service.empty())
            resp["scope_service"] = scope_service;
        res.set_content(ok_response(resp).dump(), "application/json");
    });

    svr.Delete(R"(/api/v1/tokens/(.+))", [perm_fn, audit_fn, token_store](
                                             const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "ApiToken", "Delete"))
            return;
        if (!token_store) {
            res.status = 503;
            return;
        }

        auto token_id = req.matches[1].str();
        bool revoked = token_store->revoke_token(token_id);
        if (!revoked) {
            res.status = 404;
            res.set_content(error_response("token not found").dump(), "application/json");
            return;
        }
        audit_fn(req, "api_token.revoke", "success", "ApiToken", token_id, "");
        res.set_content(ok_response({{"revoked", true}}).dump(), "application/json");
    });

    // ── Quarantine (/api/v1/quarantine) ──────────────────────────────────

    svr.Get("/api/v1/quarantine",
            [perm_fn, quarantine_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Security", "Read"))
                    return;
                if (!quarantine_store) {
                    res.status = 503;
                    return;
                }

                auto records = quarantine_store->list_quarantined();
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& r : records) {
                    arr.push_back({{"agent_id", r.agent_id},
                                   {"status", r.status},
                                   {"quarantined_by", r.quarantined_by},
                                   {"quarantined_at", r.quarantined_at},
                                   {"whitelist", r.whitelist},
                                   {"reason", r.reason}});
                }
                res.set_content(list_response(arr, static_cast<int64_t>(records.size())).dump(),
                                "application/json");
            });

    svr.Post("/api/v1/quarantine", [auth_fn, perm_fn, audit_fn, quarantine_store](
                                       const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "Security", "Execute"))
            return;
        if (!quarantine_store) {
            res.status = 503;
            return;
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto agent_id = body.value("agent_id", "");
        auto reason = body.value("reason", "");
        auto whitelist = body.value("whitelist", "");

        auto session = auth_fn(req, res);
        std::string by = session ? session->username : "system";

        auto result = quarantine_store->quarantine_device(agent_id, by, reason, whitelist);
        if (!result) {
            res.status = 400;
            res.set_content(error_response(result.error()).dump(), "application/json");
            return;
        }
        audit_fn(req, "quarantine.enable", "success", "Security", agent_id, reason);
        res.status = 201;
        res.set_content(ok_response({{"quarantined", true}}).dump(), "application/json");
    });

    svr.Delete(
        R"(/api/v1/quarantine/(.+))",
        [perm_fn, audit_fn, quarantine_store](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "Security", "Execute"))
                return;
            if (!quarantine_store) {
                res.status = 503;
                return;
            }

            auto agent_id = req.matches[1].str();
            auto result = quarantine_store->release_device(agent_id);
            if (!result) {
                res.status = 400;
                res.set_content(error_response(result.error()).dump(), "application/json");
                return;
            }
            audit_fn(req, "quarantine.disable", "success", "Security", agent_id, "");
            res.set_content(ok_response({{"released", true}}).dump(), "application/json");
        });

    // ── RBAC (/api/v1/rbac) ──────────────────────────────────────────────

    svr.Get("/api/v1/rbac/roles",
            [perm_fn, rbac_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "UserManagement", "Read"))
                    return;
                if (!rbac_store) {
                    res.status = 503;
                    return;
                }

                auto roles = rbac_store->list_roles();
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& r : roles) {
                    arr.push_back({{"name", r.name},
                                   {"description", r.description},
                                   {"is_system", r.is_system},
                                   {"created_at", r.created_at}});
                }
                res.set_content(list_response(arr, static_cast<int64_t>(roles.size())).dump(),
                                "application/json");
            });

    svr.Get(R"(/api/v1/rbac/roles/(.+)/permissions)",
            [perm_fn, rbac_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "UserManagement", "Read"))
                    return;
                if (!rbac_store) {
                    res.status = 503;
                    return;
                }

                auto role_name = req.matches[1].str();
                auto perms = rbac_store->get_role_permissions(role_name);
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& p : perms) {
                    arr.push_back({{"securable_type", p.securable_type},
                                   {"operation", p.operation},
                                   {"effect", p.effect}});
                }
                res.set_content(ok_response(arr).dump(), "application/json");
            });

    svr.Post("/api/v1/rbac/check", [auth_fn, rbac_store](const httplib::Request& req,
                                                         httplib::Response& res) {
        auto session = auth_fn(req, res);
        if (!session)
            return;
        if (!rbac_store) {
            res.status = 503;
            return;
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto securable_type = body.value("securable_type", "");
        auto operation = body.value("operation", "");
        bool allowed = rbac_store->check_permission(session->username, securable_type, operation);
        res.set_content(ok_response({{"allowed", allowed}}).dump(), "application/json");
    });
}

} // namespace yuzu::server
