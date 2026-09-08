#include "data_inventory_routes.hpp"

#include "http_route_sink.hpp"
#include "inventory_store.hpp"

#include <nlohmann/json.hpp>

namespace yuzu::server::data_inventory {

void register_data_inventory_routes(HttpRouteSink& sink, Deps deps) {
    // -- Inventory REST endpoints (Issue 7.17) --------------------------------

    // GET /api/inventory/tables — list available inventory data types
    sink.Get("/api/inventory/tables", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Inventory", "Read"))
            return;
        if (!deps.store || !deps.store->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"inventory store not available"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        auto tables = deps.store->list_tables();
        if (!tables) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"inventory store degraded"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& t : *tables) {
            arr.push_back({{"plugin", t.plugin},
                           {"agent_count", t.agent_count},
                           {"last_collected", t.last_collected}});
        }
        res.set_content(nlohmann::json({{"tables", arr}, {"count", arr.size()}}).dump(),
                        "application/json");
    });

    // GET /api/inventory/:agent_id/:plugin — get inventory for agent+plugin
    sink.Get(R"(/api/inventory/([^/]+)/([^/]+))",
            [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Inventory", "Read"))
            return;
        if (!deps.store || !deps.store->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"inventory store not available"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        auto agent_id = req.matches[1].str();
        auto plugin = req.matches[2].str();
        auto record = deps.store->get(agent_id, plugin);
        if (!record.has_value()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"inventory store degraded"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        if (!record->has_value()) {
            res.status = 404;
            res.set_content(
                R"({"error":{"code":404,"message":"no inventory data found"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        const InventoryRecord& rec = **record;
        nlohmann::json data_obj;
        try {
            data_obj = nlohmann::json::parse(rec.data_json);
        } catch (...) {
            data_obj = rec.data_json;
        }
        res.set_content(nlohmann::json({{"agent_id", rec.agent_id},
                                        {"plugin", rec.plugin},
                                        {"data", data_obj},
                                        {"collected_at", rec.collected_at}})
                            .dump(),
                        "application/json");
    });

    // POST /api/inventory/query — query inventory across agents
    sink.Post("/api/inventory/query", [deps](const httplib::Request& req, httplib::Response& res) {
        if (!deps.perm_fn(req, res, "Inventory", "Read"))
            return;
        if (!deps.store || !deps.store->is_open()) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"inventory store not available"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content(
                R"({"error":{"code":400,"message":"invalid JSON"},"meta":{"api_version":"v1"}})",
                "application/json");
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

        bool inventory_truncated = false;
        auto records = deps.store->query(q, &inventory_truncated);
        if (!records) {
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"inventory store degraded"},"meta":{"api_version":"v1"}})",
                "application/json");
            return;
        }
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& r : *records) {
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
        res.set_content(nlohmann::json({{"results", arr},
                                        {"count", arr.size()},
                                        {"result_truncated_by_cap", inventory_truncated}})
                            .dump(),
                        "application/json");
    });
}

} // namespace yuzu::server::data_inventory
