#include "rest_api_v1.hpp"
#include "rest_api_v1_helpers.hpp"

#include "audit_store.hpp"
#include "instruction_store.hpp"
#include "inventory_store.hpp"
#include "tag_store.hpp"

namespace yuzu::server {

void register_data_routes(httplib::Server& svr, RestApiV1::AuthFn auth_fn,
                          RestApiV1::PermFn perm_fn, RestApiV1::AuditFn audit_fn,
                          TagStore* tag_store, InstructionStore* instruction_store,
                          AuditStore* audit_store, InventoryStore* inventory_store,
                          RestApiV1::ServiceGroupFn service_group_fn,
                          RestApiV1::TagPushFn tag_push_fn) {

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

    // ── Inventory (/api/v1/inventory) ──────────────────────────────────

    // GET /api/v1/inventory/tables — list available inventory data types
    svr.Get("/api/v1/inventory/tables",
            [perm_fn, inventory_store](const httplib::Request& req, httplib::Response& res) {
                add_cors_headers(res, req);
                if (!perm_fn(req, res, "Inventory", "Read"))
                    return;
                if (!inventory_store || !inventory_store->is_open()) {
                    res.status = 503;
                    res.set_content(error_response("inventory store not available").dump(),
                                    "application/json");
                    return;
                }

                auto tables = inventory_store->list_tables();
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& t : tables) {
                    arr.push_back({{"plugin", t.plugin},
                                   {"agent_count", t.agent_count},
                                   {"last_collected", t.last_collected}});
                }
                res.set_content(list_response(arr, static_cast<int64_t>(tables.size())).dump(),
                                "application/json");
            });

    // GET /api/v1/inventory/:agent_id/:plugin — get inventory for agent+plugin
    svr.Get(R"(/api/v1/inventory/([^/]+)/([^/]+))",
            [perm_fn, inventory_store](const httplib::Request& req, httplib::Response& res) {
                add_cors_headers(res, req);
                if (!perm_fn(req, res, "Inventory", "Read"))
                    return;
                if (!inventory_store || !inventory_store->is_open()) {
                    res.status = 503;
                    res.set_content(error_response("inventory store not available").dump(),
                                    "application/json");
                    return;
                }

                auto agent_id = req.matches[1].str();
                auto plugin = req.matches[2].str();

                auto record = inventory_store->get(agent_id, plugin);
                if (!record) {
                    res.status = 404;
                    res.set_content(error_response("no inventory data found").dump(),
                                    "application/json");
                    return;
                }

                // Parse data_json to embed as structured JSON, not escaped string
                nlohmann::json data_obj;
                try {
                    data_obj = nlohmann::json::parse(record->data_json);
                } catch (...) {
                    data_obj = record->data_json; // Fallback to raw string
                }

                res.set_content(
                    ok_response({{"agent_id", record->agent_id},
                                 {"plugin", record->plugin},
                                 {"data", data_obj},
                                 {"collected_at", record->collected_at}})
                        .dump(),
                    "application/json");
            });

    // POST /api/v1/inventory/query — query inventory across agents
    svr.Post("/api/v1/inventory/query",
             [perm_fn, inventory_store](const httplib::Request& req, httplib::Response& res) {
                 add_cors_headers(res, req);
                 if (!perm_fn(req, res, "Inventory", "Read"))
                     return;
                 if (!inventory_store || !inventory_store->is_open()) {
                     res.status = 503;
                     res.set_content(error_response("inventory store not available").dump(),
                                     "application/json");
                     return;
                 }

                 auto body = nlohmann::json::parse(req.body, nullptr, false);
                 if (body.is_discarded()) {
                     res.status = 400;
                     res.set_content(error_response("invalid JSON").dump(), "application/json");
                     return;
                 }

                 InventoryQuery q;
                 q.agent_id = body.value("agent_id", "");
                 q.plugin = body.value("plugin", "");
                 q.since = body.value("since", int64_t{0});
                 q.until = body.value("until", int64_t{0});
                 q.limit = body.value("limit", 100);
                 if (q.limit > 1000)
                     q.limit = 1000;

                 auto records = inventory_store->query(q);
                 nlohmann::json arr = nlohmann::json::array();
                 for (const auto& r : records) {
                     nlohmann::json data_obj;
                     try {
                         data_obj = nlohmann::json::parse(r.data_json);
                     } catch (...) {
                         data_obj = r.data_json;
                     }

                     arr.push_back({{"agent_id", r.agent_id},
                                    {"plugin", r.plugin},
                                    {"data", data_obj},
                                    {"collected_at", r.collected_at}});
                 }
                 res.set_content(
                     list_response(arr, static_cast<int64_t>(records.size())).dump(),
                     "application/json");
             });
}

} // namespace yuzu::server
