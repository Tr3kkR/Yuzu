#include "rest_api_v1.hpp"

#include <spdlog/spdlog.h>

namespace yuzu::server {

// ── JSON envelope helpers ────────────────────────────────────────────────────

nlohmann::json RestApiV1::ok_response(const nlohmann::json& data) {
    return {{"data", data}, {"meta", {{"api_version", "v1"}}}};
}

nlohmann::json RestApiV1::error_response(const std::string& message, int code) {
    nlohmann::json j = {{"error", message}, {"meta", {{"api_version", "v1"}}}};
    if (code != 0)
        j["code"] = code;
    return j;
}

nlohmann::json RestApiV1::list_response(const nlohmann::json& data, int64_t total, int64_t start,
                                        int64_t page_size) {
    return {{"data", data},
            {"pagination", {{"total", total}, {"start", start}, {"page_size", page_size}}},
            {"meta", {{"api_version", "v1"}}}};
}

// ── Route registration ───────────────────────────────────────────────────────

void RestApiV1::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                AuditFn audit_fn, RbacStore* rbac_store,
                                ManagementGroupStore* mgmt_store, ApiTokenStore* token_store,
                                QuarantineStore* quarantine_store, ResponseStore* response_store,
                                InstructionStore* instruction_store,
                                ExecutionTracker* execution_tracker,
                                ScheduleEngine* schedule_engine, ApprovalManager* approval_manager,
                                TagStore* tag_store, AuditStore* audit_store,
                                ServiceGroupFn service_group_fn, TagPushFn tag_push_fn) {

    spdlog::info("REST API v1: registering routes");

    // ── /api/v1/me ───────────────────────────────────────────────────────

    svr.Get("/api/v1/me", [auth_fn, rbac_store](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn(req, res);
        if (!session)
            return;
        auto data = nlohmann::json({{"username", session->username},
                                     {"role", auth::role_to_string(session->role)}});
        // Add RBAC role if enabled
        if (rbac_store && rbac_store->is_rbac_enabled()) {
            data["rbac_enabled"] = true;
            auto roles = rbac_store->get_principal_roles("user", session->username);
            if (!roles.empty()) {
                data["rbac_role"] = roles[0].role_name;
            } else {
                data["rbac_role"] = session->role == auth::Role::admin ? "Administrator" : "Viewer";
            }
        } else {
            data["rbac_enabled"] = false;
            data["rbac_role"] = session->role == auth::Role::admin ? "Administrator" : "Viewer";
        }
        res.set_content(ok_response(data).dump(), "application/json");
    });

    // ── Management Groups (/api/v1/management-groups) ────────────────────

    svr.Get("/api/v1/management-groups",
            [auth_fn, perm_fn, mgmt_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "ManagementGroup", "Read"))
                    return;
                if (!mgmt_store) {
                    res.status = 503;
                    return;
                }

                auto groups = mgmt_store->list_groups();
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& g : groups) {
                    arr.push_back({{"id", g.id},
                                   {"name", g.name},
                                   {"description", g.description},
                                   {"parent_id", g.parent_id},
                                   {"membership_type", g.membership_type},
                                   {"scope_expression", g.scope_expression},
                                   {"created_by", g.created_by},
                                   {"created_at", g.created_at},
                                   {"updated_at", g.updated_at}});
                }
                res.set_content(list_response(arr, static_cast<int64_t>(groups.size())).dump(),
                                "application/json");
            });

    svr.Post("/api/v1/management-groups", [auth_fn, perm_fn, audit_fn, mgmt_store](
                                              const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "ManagementGroup", "Write"))
            return;
        if (!mgmt_store) {
            res.status = 503;
            return;
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content(error_response("invalid JSON").dump(), "application/json");
            return;
        }

        ManagementGroup g;
        g.name = body.value("name", "");
        g.description = body.value("description", "");
        g.parent_id = body.value("parent_id", "");
        g.membership_type = body.value("membership_type", "static");
        g.scope_expression = body.value("scope_expression", "");

        auto session = auth_fn(req, res);
        if (session)
            g.created_by = session->username;

        auto result = mgmt_store->create_group(g);
        if (!result) {
            res.status = 400;
            res.set_content(error_response(result.error()).dump(), "application/json");
            return;
        }
        audit_fn(req, "management_group.create", "success", "ManagementGroup", *result, g.name);
        res.status = 201;
        res.set_content(ok_response({{"id", *result}}).dump(), "application/json");
    });

    svr.Get(R"(/api/v1/management-groups/([a-f0-9]+))",
            [auth_fn, perm_fn, mgmt_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "ManagementGroup", "Read"))
                    return;
                if (!mgmt_store) {
                    res.status = 503;
                    return;
                }

                auto id = req.matches[1].str();
                auto g = mgmt_store->get_group(id);
                if (!g) {
                    res.status = 404;
                    res.set_content(error_response("group not found").dump(), "application/json");
                    return;
                }
                auto members = mgmt_store->get_members(id);
                nlohmann::json member_arr = nlohmann::json::array();
                for (const auto& m : members)
                    member_arr.push_back(
                        {{"agent_id", m.agent_id}, {"source", m.source}, {"added_at", m.added_at}});

                res.set_content(ok_response({{"id", g->id},
                                             {"name", g->name},
                                             {"description", g->description},
                                             {"parent_id", g->parent_id},
                                             {"membership_type", g->membership_type},
                                             {"scope_expression", g->scope_expression},
                                             {"created_by", g->created_by},
                                             {"created_at", g->created_at},
                                             {"updated_at", g->updated_at},
                                             {"members", member_arr}})
                                    .dump(),
                                "application/json");
            });

    // Update group (rename, re-parent, change description/membership)
    svr.Put(R"(/api/v1/management-groups/([a-f0-9]+))",
            [auth_fn, perm_fn, audit_fn, mgmt_store](const httplib::Request& req,
                                                      httplib::Response& res) {
                if (!perm_fn(req, res, "ManagementGroup", "Write"))
                    return;
                if (!mgmt_store) {
                    res.status = 503;
                    return;
                }

                auto id = req.matches[1].str();
                auto existing = mgmt_store->get_group(id);
                if (!existing) {
                    res.status = 404;
                    res.set_content(error_response("group not found").dump(), "application/json");
                    return;
                }

                auto body = nlohmann::json::parse(req.body, nullptr, false);
                if (body.is_discarded()) {
                    res.status = 400;
                    res.set_content(error_response("invalid JSON").dump(), "application/json");
                    return;
                }

                // Merge provided fields over existing values
                auto updated = *existing;
                if (body.contains("name"))
                    updated.name = body["name"].get<std::string>();
                if (body.contains("description"))
                    updated.description = body["description"].get<std::string>();
                if (body.contains("parent_id"))
                    updated.parent_id = body["parent_id"].get<std::string>();
                if (body.contains("membership_type"))
                    updated.membership_type = body["membership_type"].get<std::string>();
                if (body.contains("scope_expression"))
                    updated.scope_expression = body["scope_expression"].get<std::string>();

                // Prevent re-parenting the root group
                if (id == ManagementGroupStore::kRootGroupId && !updated.parent_id.empty()) {
                    res.status = 400;
                    res.set_content(error_response("cannot re-parent root group").dump(),
                                    "application/json");
                    return;
                }

                // Cycle detection: new parent must not be a descendant of this group
                if (!updated.parent_id.empty() && updated.parent_id != existing->parent_id) {
                    auto descendants = mgmt_store->get_descendant_ids(id);
                    if (std::find(descendants.begin(), descendants.end(), updated.parent_id) !=
                        descendants.end()) {
                        res.status = 400;
                        res.set_content(
                            error_response("re-parenting would create a cycle").dump(),
                            "application/json");
                        return;
                    }
                    // Depth check
                    auto ancestors = mgmt_store->get_ancestor_ids(updated.parent_id);
                    if (ancestors.size() >= 4) { // +1 for self = 5
                        res.status = 400;
                        res.set_content(
                            error_response("maximum hierarchy depth (5) exceeded").dump(),
                            "application/json");
                        return;
                    }
                }

                auto result = mgmt_store->update_group(updated);
                if (!result) {
                    res.status = 400;
                    res.set_content(error_response(result.error()).dump(), "application/json");
                    return;
                }
                audit_fn(req, "management_group.update", "success", "ManagementGroup", id,
                         updated.name);
                res.set_content(ok_response({{"updated", true}}).dump(), "application/json");
            });

    svr.Delete(
        R"(/api/v1/management-groups/([a-f0-9]+))",
        [perm_fn, audit_fn, mgmt_store](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "ManagementGroup", "Delete"))
                return;
            if (!mgmt_store) {
                res.status = 503;
                return;
            }

            auto id = req.matches[1].str();
            auto result = mgmt_store->delete_group(id);
            if (!result) {
                res.status = (result.error() == "cannot delete root group") ? 403 : 404;
                res.set_content(error_response(result.error()).dump(), "application/json");
                return;
            }
            audit_fn(req, "management_group.delete", "success", "ManagementGroup", id, "");
            res.set_content(ok_response({{"deleted", true}}).dump(), "application/json");
        });

    // Members
    svr.Post(R"(/api/v1/management-groups/([a-f0-9]+)/members)",
             [perm_fn, audit_fn, mgmt_store](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn(req, res, "ManagementGroup", "Write"))
                     return;
                 if (!mgmt_store) {
                     res.status = 503;
                     return;
                 }

                 auto group_id = req.matches[1].str();
                 auto body = nlohmann::json::parse(req.body, nullptr, false);
                 auto agent_id = body.value("agent_id", "");
                 if (agent_id.empty()) {
                     res.status = 400;
                     res.set_content(error_response("agent_id required").dump(),
                                     "application/json");
                     return;
                 }
                 mgmt_store->add_member(group_id, agent_id);
                 audit_fn(req, "management_group.add_member", "success", "ManagementGroup",
                          group_id, agent_id);
                 res.status = 201;
                 res.set_content(ok_response({{"added", true}}).dump(), "application/json");
             });

    svr.Delete(
        R"(/api/v1/management-groups/([a-f0-9]+)/members/(.+))",
        [perm_fn, audit_fn, mgmt_store](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "ManagementGroup", "Write"))
                return;
            if (!mgmt_store) {
                res.status = 503;
                return;
            }

            auto group_id = req.matches[1].str();
            auto agent_id = req.matches[2].str();
            mgmt_store->remove_member(group_id, agent_id);
            audit_fn(req, "management_group.remove_member", "success", "ManagementGroup", group_id,
                     agent_id);
            res.set_content(ok_response({{"removed", true}}).dump(), "application/json");
        });

    // ── Management Group Roles (/api/v1/management-groups/:id/roles) ────

    svr.Get(R"(/api/v1/management-groups/([a-f0-9]+)/roles)",
            [perm_fn, mgmt_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "ManagementGroup", "Read"))
                    return;
                if (!mgmt_store) {
                    res.status = 503;
                    return;
                }

                auto group_id = req.matches[1].str();
                auto roles = mgmt_store->get_group_roles(group_id);
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& r : roles) {
                    arr.push_back({{"group_id", r.group_id},
                                   {"principal_type", r.principal_type},
                                   {"principal_id", r.principal_id},
                                   {"role_name", r.role_name}});
                }
                res.set_content(ok_response(arr).dump(), "application/json");
            });

    svr.Post(
        R"(/api/v1/management-groups/([a-f0-9]+)/roles)",
        [auth_fn, perm_fn, audit_fn, mgmt_store, rbac_store](const httplib::Request& req,
                                                              httplib::Response& res) {
            auto session = auth_fn(req, res);
            if (!session)
                return;
            if (!mgmt_store || !rbac_store) {
                res.status = 503;
                return;
            }

            auto group_id = req.matches[1].str();
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if (body.is_discarded()) {
                res.status = 400;
                res.set_content(error_response("invalid JSON").dump(), "application/json");
                return;
            }

            auto principal_type = body.value("principal_type", "user");
            auto principal_id = body.value("principal_id", "");
            auto role_name = body.value("role_name", "");

            if (principal_id.empty() || role_name.empty()) {
                res.status = 400;
                res.set_content(error_response("principal_id and role_name required").dump(),
                                "application/json");
                return;
            }

            // Delegation guard: only Operator and Viewer can be delegated
            if (role_name != "Operator" && role_name != "Viewer") {
                res.status = 403;
                res.set_content(
                    error_response("only Operator and Viewer roles can be delegated").dump(),
                    "application/json");
                return;
            }

            // Caller must be global Administrator or have ITServiceOwner on this group
            bool authorized = rbac_store->check_permission(session->username, "ManagementGroup",
                                                           "Write");
            if (!authorized) {
                // Check if caller has ITServiceOwner on this group
                auto group_roles = mgmt_store->get_group_roles(group_id);
                for (const auto& gr : group_roles) {
                    if (gr.principal_type == "user" && gr.principal_id == session->username &&
                        gr.role_name == "ITServiceOwner") {
                        authorized = true;
                        break;
                    }
                }
            }
            if (!authorized) {
                res.status = 403;
                res.set_content(error_response("forbidden").dump(), "application/json");
                return;
            }

            GroupRoleAssignment assignment;
            assignment.group_id = group_id;
            assignment.principal_type = principal_type;
            assignment.principal_id = principal_id;
            assignment.role_name = role_name;

            auto result = mgmt_store->assign_role(assignment);
            if (!result) {
                res.status = 400;
                res.set_content(error_response(result.error()).dump(), "application/json");
                return;
            }
            audit_fn(req, "management_group.assign_role", "success", "ManagementGroup", group_id,
                     principal_id + ":" + role_name);
            res.status = 201;
            res.set_content(ok_response({{"assigned", true}}).dump(), "application/json");
        });

    svr.Delete(
        R"(/api/v1/management-groups/([a-f0-9]+)/roles)",
        [auth_fn, perm_fn, audit_fn, mgmt_store, rbac_store](const httplib::Request& req,
                                                              httplib::Response& res) {
            auto session = auth_fn(req, res);
            if (!session)
                return;
            if (!mgmt_store || !rbac_store) {
                res.status = 503;
                return;
            }

            auto group_id = req.matches[1].str();
            auto body = nlohmann::json::parse(req.body, nullptr, false);
            if (body.is_discarded()) {
                res.status = 400;
                res.set_content(error_response("invalid JSON").dump(), "application/json");
                return;
            }

            auto principal_type = body.value("principal_type", "user");
            auto principal_id = body.value("principal_id", "");
            auto role_name = body.value("role_name", "");

            // Caller must be global Administrator or have ITServiceOwner on this group
            bool authorized = rbac_store->check_permission(session->username, "ManagementGroup",
                                                           "Write");
            if (!authorized) {
                auto group_roles = mgmt_store->get_group_roles(group_id);
                for (const auto& gr : group_roles) {
                    if (gr.principal_type == "user" && gr.principal_id == session->username &&
                        gr.role_name == "ITServiceOwner") {
                        authorized = true;
                        break;
                    }
                }
            }
            if (!authorized) {
                res.status = 403;
                res.set_content(error_response("forbidden").dump(), "application/json");
                return;
            }

            mgmt_store->unassign_role(group_id, principal_type, principal_id, role_name);
            audit_fn(req, "management_group.unassign_role", "success", "ManagementGroup", group_id,
                     principal_id + ":" + role_name);
            res.set_content(ok_response({{"unassigned", true}}).dump(), "application/json");
        });

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

        // Authorization for service-scoped tokens: caller must have ITServiceOwner
        // authority over the specified service (global admin or scoped role).
        if (!scope_service.empty()) {
            if (!rbac_store || !rbac_store->is_rbac_enabled()) {
                res.status = 400;
                res.set_content(
                    error_response("service-scoped tokens require RBAC to be enabled").dump(),
                    "application/json");
                return;
            }
            // Check global admin privilege
            bool authorized =
                rbac_store->check_permission(session->username, "ManagementGroup", "Write");
            if (!authorized && mgmt_store) {
                // Check if caller has ITServiceOwner on the service's management group
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

    // ── Tag Categories (/api/v1/tag-categories) ────────────────────────

    svr.Get("/api/v1/tag-categories",
            [perm_fn](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Tag", "Read"))
                    return;

                const auto& categories = get_tag_categories();
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& cat : categories) {
                    nlohmann::json c = {{"key", cat.key}, {"display_name", cat.display_name}};
                    nlohmann::json vals = nlohmann::json::array();
                    for (auto v : cat.allowed_values)
                        vals.push_back(std::string(v));
                    c["allowed_values"] = vals;
                    arr.push_back(std::move(c));
                }
                res.set_content(ok_response(arr).dump(), "application/json");
            });

    // ── Tag Compliance (/api/v1/tag-compliance) ──────────────────────────

    svr.Get("/api/v1/tag-compliance",
            [perm_fn, tag_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Tag", "Read"))
                    return;
                if (!tag_store) {
                    res.status = 503;
                    return;
                }

                auto gaps = tag_store->get_compliance_gaps();
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& [agent_id, missing] : gaps) {
                    nlohmann::json m = nlohmann::json::array();
                    for (const auto& k : missing)
                        m.push_back(k);
                    arr.push_back({{"agent_id", agent_id}, {"missing_tags", m}});
                }
                res.set_content(ok_response(arr).dump(), "application/json");
            });

    // ── Tags (/api/v1/tags) ──────────────────────────────────────────────

    svr.Get("/api/v1/tags",
            [perm_fn, tag_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Tag", "Read"))
                    return;
                if (!tag_store) {
                    res.status = 503;
                    return;
                }

                auto agent_id = req.get_param_value("agent_id");
                if (agent_id.empty()) {
                    res.status = 400;
                    res.set_content(error_response("agent_id parameter required").dump(),
                                    "application/json");
                    return;
                }
                auto tags = tag_store->get_all_tags(agent_id);
                nlohmann::json obj = nlohmann::json::object();
                for (size_t i = 0; i < tags.size(); ++i)
                    obj[tags[i].key] = tags[i].value;
                res.set_content(ok_response(obj).dump(), "application/json");
            });

    svr.Put("/api/v1/tags",
            [perm_fn, audit_fn, tag_store, service_group_fn,
             tag_push_fn](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Tag", "Write"))
                    return;
                if (!tag_store) {
                    res.status = 503;
                    return;
                }

                auto body = nlohmann::json::parse(req.body, nullptr, false);
                if (body.is_discarded()) {
                    res.status = 400;
                    res.set_content(error_response("invalid JSON").dump(), "application/json");
                    return;
                }
                auto agent_id = body.value("agent_id", "");
                auto key = body.value("key", "");
                auto value = body.value("value", "");

                if (agent_id.empty() || key.empty()) {
                    res.status = 400;
                    res.set_content(error_response("agent_id and key required").dump(),
                                    "application/json");
                    return;
                }

                auto result = tag_store->set_tag_checked(agent_id, key, value, "api");
                if (!result) {
                    res.status = 400;
                    res.set_content(error_response(result.error()).dump(), "application/json");
                    return;
                }
                if (key == "service" && service_group_fn)
                    service_group_fn(value);
                if (tag_push_fn)
                    tag_push_fn(agent_id, key);
                audit_fn(req, "tag.set", "success", "Tag", agent_id + ":" + key, value);
                res.set_content(ok_response({{"set", true}}).dump(), "application/json");
            });

    svr.Delete(
        R"(/api/v1/tags/([^/]+)/([^/]+))",
        [perm_fn, audit_fn, tag_store](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn(req, res, "Tag", "Delete"))
                return;
            if (!tag_store) {
                res.status = 503;
                return;
            }

            auto agent_id = req.matches[1].str();
            auto key = req.matches[2].str();
            bool deleted = tag_store->delete_tag(agent_id, key);
            if (!deleted) {
                res.status = 404;
                res.set_content(error_response("tag not found").dump(), "application/json");
                return;
            }
            audit_fn(req, "tag.delete", "success", "Tag", agent_id + ":" + key, "");
            res.set_content(ok_response({{"deleted", true}}).dump(), "application/json");
        });

    // ── Instructions (/api/v1/definitions) ───────────────────────────────

    svr.Get("/api/v1/definitions",
            [perm_fn, instruction_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "InstructionDefinition", "Read"))
                    return;
                if (!instruction_store) {
                    res.status = 503;
                    return;
                }

                auto defs = instruction_store->query_definitions();
                nlohmann::json arr = nlohmann::json::array();
                for (size_t i = 0; i < defs.size(); ++i) {
                    const auto& d = defs[i];
                    arr.push_back({{"id", d.id},
                                   {"name", d.name},
                                   {"description", d.description},
                                   {"plugin", d.plugin},
                                   {"action", d.action},
                                   {"version", d.version},
                                   {"created_at", d.created_at}});
                }
                res.set_content(list_response(arr, static_cast<int64_t>(defs.size())).dump(),
                                "application/json");
            });

    // ── Audit (/api/v1/audit) ────────────────────────────────────────────

    svr.Get("/api/v1/audit",
            [perm_fn, audit_store](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "AuditLog", "Read"))
                    return;
                if (!audit_store) {
                    res.status = 503;
                    return;
                }

                AuditQuery q;
                auto limit_str = req.get_param_value("limit");
                if (!limit_str.empty()) {
                    try {
                        q.limit = std::stoi(limit_str);
                    } catch (...) {}
                }
                if (q.limit > 1000)
                    q.limit = 1000;
                q.principal = req.get_param_value("principal");
                q.action = req.get_param_value("action");

                auto events = audit_store->query(q);
                nlohmann::json arr = nlohmann::json::array();
                for (size_t i = 0; i < events.size(); ++i) {
                    const auto& e = events[i];
                    arr.push_back({{"timestamp", e.timestamp},
                                   {"principal", e.principal},
                                   {"action", e.action},
                                   {"result", e.result},
                                   {"target_type", e.target_type},
                                   {"target_id", e.target_id},
                                   {"detail", e.detail}});
                }
                res.set_content(list_response(arr, static_cast<int64_t>(events.size())).dump(),
                                "application/json");
            });

    spdlog::info("REST API v1: registered all routes at /api/v1/*");
}

} // namespace yuzu::server
