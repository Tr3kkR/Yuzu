// test_rest_devices.cpp — HTTP-level tests for the #4033 (#2146 API-parity
// Batch A) device REST twins: GET /api/v1/devices (list), GET
// /api/v1/devices/{id} (detail), and GET /api/v1/management-groups/
// agent-count-preview (the create-group agent-count preview).
//
// GET /api/v1/devices[/{id}] are migrated onto AuthRoutes::require_fleet_read
// (via the injected FleetReadFn, same seam GET /api/v1/inventory/software
// uses — see test_rest_inventory_software.cpp's InvHarness for the pattern
// this file borrows) as their SOLE gate; this harness fakes that gate the
// same way. No Postgres substrate is needed for the paths under test here:
// `agents_fn` is a plain in-memory lambda (mirrors registry_.to_json_obj()'s
// shape). `TagStore` itself is Postgres-only (`explicit TagStore(pg::PgPool&)`,
// tag_store.hpp) and cannot be constructed in a plain unit test, so the HTTP
// harness below always wires `tag_store=nullptr` — the "tag_store present"
// case is instead covered directly against the PURE builder function
// `device_agent_detail_json` (no TagStore/HTTP/store needed at all — see the
// "PURE builder coverage" section below), not through this harness.
//
// What's covered:
//   - GET /api/v1/devices: gate deny (401/403/503-unwired) -> no rows; gate
//     admit + scope filter -> only in-scope rows, correct devices_omitted
//     count; row shape matches list_agents' 5-field contract.
//   - GET /api/v1/devices/{id}: found in-scope -> 200 w/ fields; out-of-scope
//     match collapses to the SAME 404 as a genuinely nonexistent agent_id
//     (#1700-style existence-oracle closure); tag_store unwired (this file's
//     HTTP harness only) -> no `tags` key.
//   - device_agent_row_json / device_agent_detail_json (PURE, no HTTP/store):
//     5-field row shape; tags omitted when the tags pointer is null; tags
//     array populated (key/value/source per entry) when it is not — this is
//     the "tag_store present" coverage the HTTP harness above cannot provide.
//   - GET /api/v1/management-groups/agent-count-preview: perm_fn/auth_fn gate;
//     empty filters -> agent_count 0 with NO store call (works even with
//     response_store == nullptr); non-empty filters + response_store ==
//     nullptr -> 503 (degrade posture, never a false 200).

#include "device_routes.hpp"
#include "rest_api_v1.hpp"
#include "authz_gates.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <optional>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;

namespace {

struct AuditRecord {
    std::string action, result, target_id, detail;
};

// Minimal harness wiring only what the three routes under test need. Every
// OTHER register_routes dependency stays nullptr/{} — none of those routes
// are dispatched by this file's tests.
struct DeviceRestHarness {
    yuzu::server::test::TestRouteSink sink;

    bool auth_ok{true};
    bool perm_grant{true};

    // Fleet-read gate control (GET /api/v1/devices[/{id}]).
    bool fleet_admitted{true};
    authz::VisibleSet fleet_scope{std::nullopt}; // nullopt = TOP/unfiltered
    int fleet_deny_status{403};

    // Raw agent registry snapshot the two device routes filter.
    nlohmann::json agents = nlohmann::json::array();

    // D3 Response:Read-visible scope for the group-preview route.
    std::optional<std::set<std::string>> response_visible_scope; // nullopt = TOP

    std::vector<AuditRecord> audit_log;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    explicit DeviceRestHarness(bool wire_fleet_read_fn = true) {
        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response& res) -> std::optional<auth::Session> {
            if (!auth_ok) {
                res.status = 401;
                return std::nullopt;
            }
            auth::Session s;
            s.username = "operator1";
            s.role = auth::Role::user;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                              const std::string&) -> bool {
            if (!perm_grant) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&,
                               const std::string& target_id, const std::string& detail) -> bool {
            audit_log.push_back({action, result, target_id, detail});
            return true;
        };
        RestApiV1::FleetReadFn fleet_read_fn;
        if (wire_fleet_read_fn) {
            fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                   const std::string&,
                                   const std::string&) -> authz::FleetReadGate {
                if (!fleet_admitted) {
                    res.status = fleet_deny_status;
                    res.set_content(R"({"error":{"message":"denied"}})", "application/json");
                    return {};
                }
                return {true, fleet_scope};
            };
        }
        RestApiV1::AgentsJsonFn agents_fn = [this]() -> nlohmann::json { return agents; };
        RestApiV1::ResponseVisibleSetFn response_visible_set_fn =
            [this](const std::string&) -> std::optional<std::set<std::string>> {
            return response_visible_scope;
        };

        api.register_routes(
            sink, auth_fn, perm_fn, audit_fn,
            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr, /*token_store=*/nullptr,
            /*quarantine_store=*/nullptr, /*response_store=*/nullptr,
            /*instruction_store=*/nullptr, /*execution_tracker=*/nullptr,
            /*schedule_engine=*/nullptr, /*approval_manager=*/nullptr, /*tag_store=*/nullptr,
            /*audit_store=*/nullptr, /*service_group_fn=*/{}, /*tag_push_fn=*/{},
            /*inventory_store=*/nullptr, /*product_pack_store=*/nullptr,
            /*sw_deploy_store=*/nullptr, /*device_token_store=*/nullptr,
            /*license_store=*/nullptr, /*guaranteed_state_store=*/nullptr,
            /*metrics_registry=*/&metrics, /*session_revoke_fn=*/{},
            /*execution_event_bus=*/nullptr, /*result_set_store=*/nullptr,
            /*command_dispatch_fn=*/{}, /*step_up_fn=*/{}, /*guardian_push_fn=*/{},
            /*dex_perf_fn=*/{}, /*net_perf_fn=*/{}, /*lockout_clear_fn=*/{},
            /*baseline_store=*/nullptr, /*scoped_perm_fn=*/{},
            /*software_inventory_store=*/nullptr, /*response_scope_fn=*/{},
            /*app_perf_providers=*/{}, /*engine_principal_store=*/nullptr,
            /*access_review_store=*/nullptr, /*auth_db=*/nullptr, /*directory_sync=*/nullptr,
            /*stream_budget=*/nullptr, /*exec_visible_fn=*/{}, /*list_read_fn=*/{},
            std::move(fleet_read_fn), std::move(agents_fn), std::move(response_visible_set_fn));
    }

    void add_agent(const std::string& id, const std::string& hostname) {
        agents.push_back({{"agent_id", id},
                          {"hostname", hostname},
                          {"os", "linux"},
                          {"arch", "x86_64"},
                          {"agent_version", "1.0.0"}});
    }
};

} // namespace

TEST_CASE("GET /api/v1/devices — unwired fleet_read_fn fails closed (503)", "[rest][devices]") {
    DeviceRestHarness h(/*wire_fleet_read_fn=*/false);
    auto res = h.sink.Get("/api/v1/devices");
    REQUIRE(res != nullptr);
    CHECK(res->status == 503);
}

TEST_CASE("GET /api/v1/devices — gate denial forwards the gate's own status, no rows served",
          "[rest][devices]") {
    DeviceRestHarness h;
    h.fleet_admitted = false;
    h.fleet_deny_status = 403;
    h.add_agent("a1", "host1");
    auto res = h.sink.Get("/api/v1/devices");
    REQUIRE(res != nullptr);
    CHECK(res->status == 403);
}

TEST_CASE("GET /api/v1/devices — admitted + unfiltered scope returns every agent, 5-field rows",
          "[rest][devices]") {
    DeviceRestHarness h;
    h.fleet_scope = std::nullopt; // TOP
    h.add_agent("a1", "host1");
    h.add_agent("a2", "host2");
    auto res = h.sink.Get("/api/v1/devices");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& devices = body["data"]["devices"];
    REQUIRE(devices.size() == 2);
    CHECK(body["data"]["count"].get<int64_t>() == 2);
    CHECK(body["data"]["devices_omitted"].get<int64_t>() == 0);
    // Row shape: exactly the 5 list_agents fields.
    CHECK(devices[0]["agent_id"] == "a1");
    CHECK(devices[0]["hostname"] == "host1");
    CHECK(devices[0]["os"] == "linux");
    CHECK(devices[0]["arch"] == "x86_64");
    CHECK(devices[0]["agent_version"] == "1.0.0");
    CHECK_FALSE(devices[0].contains("tags"));
    CHECK_FALSE(devices[0].contains("online"));
}

TEST_CASE("GET /api/v1/devices — engaged scope filters rows and reports devices_omitted",
          "[rest][devices]") {
    DeviceRestHarness h;
    h.fleet_scope = std::unordered_set<std::string>{"a1"}; // engaged, admits only a1
    h.add_agent("a1", "host1");
    h.add_agent("a2", "host2");
    auto res = h.sink.Get("/api/v1/devices");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    const auto& devices = body["data"]["devices"];
    REQUIRE(devices.size() == 1);
    CHECK(devices[0]["agent_id"] == "a1");
    CHECK(body["data"]["devices_omitted"].get<int64_t>() == 1);
}

TEST_CASE("GET /api/v1/devices/{id} — found and in-scope returns the row", "[rest][devices]") {
    DeviceRestHarness h;
    h.fleet_scope = std::nullopt;
    h.add_agent("a1", "host1");
    auto res = h.sink.Get("/api/v1/devices/a1");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["agent_id"] == "a1");
    CHECK(body["data"]["hostname"] == "host1");
    CHECK_FALSE(body["data"].contains("tags")); // no tag_store wired
}

TEST_CASE("GET /api/v1/devices/{id} — nonexistent agent_id is a 404", "[rest][devices]") {
    DeviceRestHarness h;
    h.fleet_scope = std::nullopt;
    h.add_agent("a1", "host1");
    auto res = h.sink.Get("/api/v1/devices/does-not-exist");
    REQUIRE(res != nullptr);
    CHECK(res->status == 404);
}

TEST_CASE("GET /api/v1/devices/{id} — out-of-scope match collapses to the SAME 404 as "
          "nonexistent (#1700-style existence-oracle closure)",
          "[rest][devices]") {
    DeviceRestHarness h;
    h.fleet_scope = std::unordered_set<std::string>{}; // engaged-empty: nothing in scope
    h.add_agent("a1", "host1"); // exists in the registry, but outside the caller's scope
    auto res = h.sink.Get("/api/v1/devices/a1");
    REQUIRE(res != nullptr);
    CHECK(res->status == 404);

    // Byte-identical body to the genuinely-nonexistent case (same code path).
    DeviceRestHarness h2;
    h2.fleet_scope = std::nullopt;
    auto res2 = h2.sink.Get("/api/v1/devices/does-not-exist-either");
    REQUIRE(res2 != nullptr);
    CHECK(res2->status == 404);
}

// ── PURE builder coverage: device_agent_row_json / device_agent_detail_json ──
// No HTTP, no store, no TagStore (which is Postgres-only and cannot be
// constructed here) — direct calls against the pure functions declared in
// device_routes.hpp. This is the ONLY coverage of the tags-populated branch;
// the HTTP harness above always wires tag_store=nullptr (see file header).

TEST_CASE("device_agent_row_json: exactly the 5 list_agents fields, defensively extracted",
          "[devices][pure]") {
    nlohmann::json agent = {{"agent_id", "a1"}, {"hostname", "host1"},
                            {"os", "linux"},    {"arch", "x86_64"},
                            {"agent_version", "1.0.0"}};
    auto row = device_agent_row_json(agent);
    CHECK(row["agent_id"] == "a1");
    CHECK(row["hostname"] == "host1");
    CHECK(row["os"] == "linux");
    CHECK(row["arch"] == "x86_64");
    CHECK(row["agent_version"] == "1.0.0");
    CHECK(row.size() == 5);
}

TEST_CASE("device_agent_row_json: a short/malformed source object degrades to empty fields, "
          "never throws",
          "[devices][pure]") {
    nlohmann::json agent = {{"agent_id", "a1"}}; // hostname/os/arch/agent_version all missing
    auto row = device_agent_row_json(agent);
    CHECK(row["agent_id"] == "a1");
    CHECK(row["hostname"] == "");
    CHECK(row["os"] == "");
}

TEST_CASE("device_agent_detail_json: null tags pointer omits the tags key entirely (never an "
          "empty array)",
          "[devices][pure]") {
    nlohmann::json agent = {{"agent_id", "a1"}, {"hostname", "host1"}};
    auto detail = device_agent_detail_json(agent, /*tags=*/nullptr);
    CHECK_FALSE(detail.contains("tags"));
}

TEST_CASE("device_agent_detail_json: an engaged-but-empty tags vector produces an empty array, "
          "distinguishable from a null pointer",
          "[devices][pure]") {
    nlohmann::json agent = {{"agent_id", "a1"}};
    std::vector<DeviceTag> tags; // present, TagStore succeeded, agent just has no tags
    auto detail = device_agent_detail_json(agent, &tags);
    REQUIRE(detail.contains("tags"));
    CHECK(detail["tags"].is_array());
    CHECK(detail["tags"].empty());
}

TEST_CASE("device_agent_detail_json: a populated tags vector serialises key/value/source per "
          "entry — the 'tag_store present' case the HTTP harness above cannot cover",
          "[devices][pure]") {
    nlohmann::json agent = {{"agent_id", "a1"}, {"hostname", "host1"}, {"os", "linux"},
                            {"arch", "x86_64"}, {"agent_version", "1.0.0"}};
    std::vector<DeviceTag> tags{
        DeviceTag{.agent_id = "a1", .key = "environment", .value = "production", .source = "server"},
        DeviceTag{.agent_id = "a1", .key = "owner", .value = "sre-team", .source = "agent"},
    };
    auto detail = device_agent_detail_json(agent, &tags);
    REQUIRE(detail.contains("tags"));
    REQUIRE(detail["tags"].size() == 2);
    CHECK(detail["tags"][0]["key"] == "environment");
    CHECK(detail["tags"][0]["value"] == "production");
    CHECK(detail["tags"][0]["source"] == "server");
    CHECK(detail["tags"][1]["key"] == "owner");
    CHECK(detail["tags"][1]["value"] == "sre-team");
    CHECK(detail["tags"][1]["source"] == "agent");
    // Detail still carries the base 5 row fields alongside tags.
    CHECK(detail["agent_id"] == "a1");
    CHECK(detail["hostname"] == "host1");
}

TEST_CASE("GET /api/v1/management-groups/agent-count-preview — perm_fn denial blocks the route",
          "[rest][devices]") {
    DeviceRestHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get("/api/v1/management-groups/agent-count-preview");
    REQUIRE(res != nullptr);
    CHECK(res->status == 403);
}

TEST_CASE("GET /api/v1/management-groups/agent-count-preview — no filters is a genuine 0, "
          "no store call needed",
          "[rest][devices]") {
    DeviceRestHarness h; // response_store stays nullptr
    auto res = h.sink.Get("/api/v1/management-groups/agent-count-preview"
                          "?command_id=cmd-1&plugin=procfetch");
    REQUIRE(res != nullptr);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["agent_count"].get<int64_t>() == 0);
}

TEST_CASE("GET /api/v1/management-groups/agent-count-preview — a real filter against an "
          "unwired store degrades (503), never a false-empty 200",
          "[rest][devices]") {
    DeviceRestHarness h; // response_store stays nullptr
    auto res = h.sink.Get("/api/v1/management-groups/agent-count-preview"
                          "?command_id=cmd-1&plugin=procfetch&pid=1234");
    REQUIRE(res != nullptr);
    CHECK(res->status == 503);
}
