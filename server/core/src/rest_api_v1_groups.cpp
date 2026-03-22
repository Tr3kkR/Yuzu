#include "rest_api_v1.hpp"
#include "rest_api_v1_helpers.hpp"

#include "management_group_store.hpp"
#include "rbac_store.hpp"

namespace yuzu::server {

void register_group_routes(httplib::Server& svr, RestApiV1::AuthFn auth_fn,
                           RestApiV1::PermFn perm_fn, RestApiV1::AuditFn audit_fn,
                           ManagementGroupStore* mgmt_store, RbacStore* rbac_store) {

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
        g.created_by = session ? session->username : "system";

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
}

} // namespace yuzu::server
