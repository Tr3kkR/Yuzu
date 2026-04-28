/**
 * test_rest_visualization.cpp — HTTP-level coverage for the
 * /api/v1/executions/{id}/visualization endpoint added in issue #253.
 *
 * Pattern matches test_rest_guaranteed_state.cpp: register RestApiV1 routes
 * against an in-process TestRouteSink and dispatch synthesised requests
 * directly into the captured handlers. No real socket → no #438 TSan trap.
 *
 * Coverage focuses on the wire-contract surface the dashboard depends on:
 *   - 400 when definition_id query parameter is missing
 *   - 404 when the InstructionDefinition does not exist
 *   - 404 when the definition exists but has no spec.visualization
 *   - 200 with a chart payload when responses are present
 *   - 200 with an empty bucket list when responses are absent
 */

#include "instruction_store.hpp"
#include "rest_api_v1.hpp"
#include "response_store.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <filesystem>
#include <memory>
#include <string>

namespace fs = std::filesystem;
using namespace yuzu::server;

namespace {

fs::path uniq(const std::string& prefix) {
    return yuzu::test::unique_temp_path(prefix + "-");
}

struct AuditRecord {
    std::string action;
    std::string result;
    std::string target_type;
    std::string target_id;
    std::string detail;
};

struct VizHarness {
    yuzu::server::test::TestRouteSink sink;

    fs::path inst_db, resp_db;
    std::unique_ptr<InstructionStore> instruction_store;
    std::unique_ptr<ResponseStore> response_store;

    bool perm_grant{true};
    std::vector<AuditRecord> audit_log;

    RestApiV1 api;

    VizHarness() : inst_db(uniq("rest-viz-inst")), resp_db(uniq("rest-viz-resp")) {
        fs::remove(inst_db);
        fs::remove(resp_db);
        instruction_store = std::make_unique<InstructionStore>(inst_db);
        REQUIRE(instruction_store->is_open());
        response_store = std::make_unique<ResponseStore>(resp_db, /*retention=*/0,
                                                          /*cleanup_interval=*/60);
        REQUIRE(response_store->is_open());

        auto auth_fn = [](const httplib::Request&, httplib::Response&)
            -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "tester";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [this](const httplib::Request&, httplib::Response& res,
                              const std::string&, const std::string&) -> bool {
            if (!perm_grant) {
                res.status = 403;
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& a,
                               const std::string& r, const std::string& tt,
                               const std::string& ti, const std::string& d) {
            audit_log.push_back({a, r, tt, ti, d});
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr,
                            response_store.get(),
                            instruction_store.get(),
                            /*execution_tracker=*/nullptr,
                            /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr,
                            /*audit_store=*/nullptr,
                            /*service_group_fn=*/{},
                            /*tag_push_fn=*/{},
                            /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr,
                            /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr,
                            /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr);
    }

    ~VizHarness() {
        response_store.reset();
        instruction_store.reset();
        for (auto& p : {inst_db, resp_db}) {
            fs::remove(p);
            fs::remove(p.string() + "-wal");
            fs::remove(p.string() + "-shm");
        }
    }

    /// Insert a definition with the given visualization spec and return its id.
    std::string make_def(const std::string& visualization_spec,
                         const std::string& plugin = "procfetch") {
        InstructionDefinition d;
        d.id = "def-" + std::to_string(std::hash<std::string>{}(visualization_spec) % 0xFFFFFF);
        d.name = "viz-test-" + d.id;
        d.type = "question";
        d.plugin = plugin;
        d.action = "list";
        d.visualization_spec = visualization_spec;
        auto created = instruction_store->create_definition(d);
        if (!created.has_value()) {
            INFO("create_definition failed: " << created.error());
            REQUIRE(created.has_value());
        }
        return *created;
    }

    /// Push a response into the store keyed by `instruction_id` (a.k.a.
    /// command_id, a.k.a. the {id} path parameter on the visualization route).
    void push_response(const std::string& instruction_id, const std::string& agent,
                       const std::string& output) {
        StoredResponse r;
        r.instruction_id = instruction_id;
        r.agent_id = agent;
        r.output = output;
        r.status = 0;
        r.timestamp = 1000;
        response_store->store(r);
    }
};

} // namespace

TEST_CASE("REST visualization: missing definition_id → 400",
          "[rest][visualization][validation]") {
    VizHarness h;
    auto res = h.sink.Get("/api/v1/executions/cmd-001/visualization");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->body.find("definition_id") != std::string::npos);
    // Closes governance sec-F2: error paths emit failure audit so SIEM
    // can detect enumeration probes against the visualization endpoint.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "execution.visualization.fetch");
    CHECK(h.audit_log[0].result == "failure");
    CHECK(h.audit_log[0].detail.find("missing_definition_id") != std::string::npos);
}

TEST_CASE("REST visualization: malformed definition_id → 400",
          "[rest][visualization][validation]") {
    // Closes governance sec-F3 / C-15: REST regex bound matches the
    // dashboard fragment; an unbounded value no longer flows into SQL
    // bind / audit / log without validation.
    VizHarness h;
    auto res = h.sink.Get(
        "/api/v1/executions/cmd-001/visualization?definition_id=evil%22%3E%3Cscript%3E");
    REQUIRE(res);
    CHECK(res->status == 400);
    CHECK(res->body.find("[A-Za-z0-9._-]") != std::string::npos);
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].detail.find("malformed_definition_id") != std::string::npos);
}

TEST_CASE("REST visualization: perm_fn denies → 403, no audit emission",
          "[rest][visualization][rbac]") {
    // Closes governance qe-1: 403 path was untested. A future change that
    // accidentally inverts the permission check would silently expose an
    // operator-only endpoint to lower-privileged sessions.
    VizHarness h;
    h.perm_grant = false;
    auto res = h.sink.Get(
        "/api/v1/executions/cmd-001/visualization?definition_id=does-not-exist");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK(h.audit_log.empty());
}

TEST_CASE("REST visualization: null stores → 503",
          "[rest][visualization][unavailable]") {
    // Closes governance qe-3: 503 path was untested. Mounts the route with
    // null stores so the guard at the top of the handler fires.
    yuzu::server::test::TestRouteSink sink;
    auto auth_fn = [](const httplib::Request&, httplib::Response&)
        -> std::optional<auth::Session> {
        auth::Session s;
        s.username = "x";
        s.role = auth::Role::admin;
        return s;
    };
    auto perm_fn = [](const httplib::Request&, httplib::Response&,
                      const std::string&, const std::string&) -> bool { return true; };
    auto audit_fn = [](const httplib::Request&, const std::string&,
                       const std::string&, const std::string&,
                       const std::string&, const std::string&) {};
    RestApiV1 api;
    api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                        nullptr, nullptr, nullptr, nullptr,
                        /*response_store=*/nullptr,
                        /*instruction_store=*/nullptr,
                        nullptr, nullptr, nullptr, nullptr, nullptr,
                        {}, {}, nullptr, nullptr, nullptr, nullptr, nullptr,
                        nullptr);

    auto res = sink.Get(
        "/api/v1/executions/cmd-001/visualization?definition_id=foo");
    REQUIRE(res);
    CHECK(res->status == 503);
    CHECK(res->body.find("service unavailable") != std::string::npos);
}

TEST_CASE("REST visualization: unknown definition_id → 404",
          "[rest][visualization][not_found]") {
    VizHarness h;
    auto res = h.sink.Get(
        "/api/v1/executions/cmd-001/visualization?definition_id=does-not-exist");
    REQUIRE(res);
    CHECK(res->status == 404);
    CHECK(res->body.find("not found") != std::string::npos);
}

TEST_CASE("REST visualization: definition without spec.visualization → 404",
          "[rest][visualization][not_found]") {
    VizHarness h;
    auto def_id = h.make_def(""); // no visualization configured
    auto res = h.sink.Get(
        "/api/v1/executions/cmd-001/visualization?definition_id=" + def_id);
    REQUIRE(res);
    CHECK(res->status == 404);
    CHECK(res->body.find("no visualization configured") != std::string::npos);
}

TEST_CASE("REST visualization: pie chart over procfetch responses → 200 with buckets",
          "[rest][visualization][round_trip]") {
    VizHarness h;
    auto spec = R"({"type":"pie","processor":"single_series","labelField":1,
                    "title":"Top procs"})";
    auto def_id = h.make_def(spec, "procfetch");

    h.push_response("cmd-A1", "agent-1",
        "1|chrome|/usr/bin/chrome|d\n2|chrome|/usr/bin/chrome|d\n3|firefox|/usr/bin/ff|c");
    h.push_response("cmd-A1", "agent-2",
        "1|chrome|/usr/bin/chrome|d\n2|sshd|/usr/sbin/sshd|s");

    auto res = h.sink.Get(
        "/api/v1/executions/cmd-A1/visualization?definition_id=" + def_id);
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("data"));
    auto& d = body["data"];
    CHECK(d["chart_type"] == "pie");
    CHECK(d["title"] == "Top procs");

    // Aggregate labels → counts for an order-independent assertion
    std::map<std::string, double> got;
    REQUIRE(d["labels"].size() >= 3);
    for (size_t i = 0; i < d["labels"].size(); ++i)
        got[d["labels"][i].get<std::string>()] = d["series"][0]["data"][i].get<double>();
    CHECK(got["chrome"] == 3);
    CHECK(got["firefox"] == 1);
    CHECK(got["sshd"] == 1);
    CHECK(d["meta"]["responses_total"] == 2);

    // Closes governance qe-2: audit emission was untested.
    REQUIRE(h.audit_log.size() == 1);
    CHECK(h.audit_log[0].action == "execution.visualization.fetch");
    CHECK(h.audit_log[0].result == "success");
    CHECK(h.audit_log[0].target_type == "execution");
    CHECK(h.audit_log[0].target_id == "cmd-A1");
    // Detail format: "<def_id> index=<N>" — issue #587 added the index
    // suffix so multi-chart fetches are distinguishable in the audit log.
    CHECK(h.audit_log[0].detail == def_id + " index=0");
}

TEST_CASE("REST visualization: multi-chart definition (#587)",
          "[rest][visualization][multi_chart]") {
    VizHarness h;
    // Two charts on a single definition, supplied via the canonical
    // `visualizations` array shape that import normalises into the
    // visualization_spec column.
    nlohmann::json import_body;
    import_body["id"] = "def-multi";
    import_body["name"] = "multi-chart";
    import_body["type"] = "question";
    import_body["plugin"] = "procfetch";
    import_body["visualizations"] = nlohmann::json::array({
        nlohmann::json::object({
            {"type", "pie"},
            {"processor", "single_series"},
            {"title", "By name"},
            {"labelField", 1},
        }),
        nlohmann::json::object({
            {"type", "bar"},
            {"processor", "single_series"},
            {"title", "By path"},
            {"labelField", 2},
        }),
    });
    REQUIRE(h.instruction_store->import_definition_json(import_body.dump()).has_value());

    h.push_response("cmd-multi", "agent-1",
        "1|chrome|/usr/bin/chrome|d\n2|chrome|/usr/bin/chrome|d\n3|firefox|/usr/bin/ff|c");

    // index=0 returns the pie
    auto res0 = h.sink.Get(
        "/api/v1/executions/cmd-multi/visualization?definition_id=def-multi");
    REQUIRE(res0);
    CHECK(res0->status == 200);
    auto body0 = nlohmann::json::parse(res0->body);
    CHECK(body0["data"]["chart_type"] == "pie");
    CHECK(body0["data"]["title"] == "By name");
    CHECK(body0["data"]["chart_index"] == 0);
    CHECK(body0["data"]["chart_count"] == 2);

    // index=1 returns the bar
    auto res1 = h.sink.Get(
        "/api/v1/executions/cmd-multi/visualization?definition_id=def-multi&index=1");
    REQUIRE(res1);
    CHECK(res1->status == 200);
    auto body1 = nlohmann::json::parse(res1->body);
    CHECK(body1["data"]["chart_type"] == "bar");
    CHECK(body1["data"]["title"] == "By path");
    CHECK(body1["data"]["chart_index"] == 1);
    CHECK(body1["data"]["chart_count"] == 2);

    // index=2 → 404 (out of range)
    auto res2 = h.sink.Get(
        "/api/v1/executions/cmd-multi/visualization?definition_id=def-multi&index=2");
    REQUIRE(res2);
    CHECK(res2->status == 404);
    CHECK(res2->body.find("out of range") != std::string::npos);

    // negative index → 400
    auto res_neg = h.sink.Get(
        "/api/v1/executions/cmd-multi/visualization?definition_id=def-multi&index=-1");
    REQUIRE(res_neg);
    CHECK(res_neg->status == 400);

    // garbage index → 400
    auto res_bad = h.sink.Get(
        "/api/v1/executions/cmd-multi/visualization?definition_id=def-multi&index=abc");
    REQUIRE(res_bad);
    CHECK(res_bad->status == 400);
}

TEST_CASE("REST visualization: legacy single-object spec is still index-0 reachable",
          "[rest][visualization][multi_chart][backward_compat]") {
    // Operators authoring a single chart can still use the singular
    // `visualization` block; the engine + store treat it equivalently
    // to a 1-element array (the import path normalises, the engine
    // count() / chart_at() tolerate both shapes for any rows that
    // bypass normalisation — e.g. tests calling create_definition
    // directly).
    VizHarness h;
    auto spec = R"({"type":"pie","processor":"single_series","labelField":1})";
    auto def_id = h.make_def(spec, "procfetch");

    h.push_response("cmd-legacy-single", "a1", "1|chrome|/u/b/c|d");

    auto res = h.sink.Get(
        "/api/v1/executions/cmd-legacy-single/visualization?definition_id=" + def_id);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK(body["data"]["chart_index"] == 0);
    CHECK(body["data"]["chart_count"] == 1);
}

TEST_CASE("REST visualization: snake_case keys still accepted as legacy alias",
          "[rest][visualization][backward_compat]") {
    // The DSL surface migrated to camelCase (governance dsl-B2). The engine
    // accepts the old snake_case names as deprecated aliases so any
    // pre-rename YAML out in the wild keeps working through one transition
    // window.
    VizHarness h;
    auto spec = R"({"type":"bar","processor":"single_series","label_field":1})";
    auto def_id = h.make_def(spec, "procfetch");
    h.push_response("cmd-legacy", "a1", "1|chrome|/u/b/c|d\n2|chrome|/u/b/c|d");
    auto res = h.sink.Get(
        "/api/v1/executions/cmd-legacy/visualization?definition_id=" + def_id);
    REQUIRE(res);
    CHECK(res->status == 200);
}

TEST_CASE("REST visualization: empty response set → 200 with empty payload",
          "[rest][visualization][edge]") {
    VizHarness h;
    auto spec = R"({"type":"bar","processor":"single_series","label_field":1})";
    auto def_id = h.make_def(spec, "procfetch");

    auto res = h.sink.Get(
        "/api/v1/executions/never-dispatched/visualization?definition_id=" + def_id);
    REQUIRE(res);
    CHECK(res->status == 200);

    auto body = nlohmann::json::parse(res->body);
    auto& d = body["data"];
    CHECK(d["chart_type"] == "bar");
    CHECK(d["labels"].size() == 0);
    CHECK(d["meta"]["responses_total"] == 0);
}

TEST_CASE("InstructionStore: visualization_spec round-trips through create / get / update",
          "[instruction_store][visualization]") {
    auto db_path = uniq("inst-viz");
    fs::remove(db_path);
    {
        InstructionStore store(db_path);
        REQUIRE(store.is_open());

        InstructionDefinition d;
        d.id = "def-viz-rt";
        d.name = "rt";
        d.type = "question";
        d.plugin = "procfetch";
        d.visualization_spec = R"({"type":"pie","processor":"single_series","label_field":1})";
        auto created = store.create_definition(d);
        REQUIRE(created.has_value());

        auto got = store.get_definition("def-viz-rt");
        REQUIRE(got.has_value());
        CHECK(got->visualization_spec.find("\"type\":\"pie\"") != std::string::npos);

        // Update the spec to a different chart type and confirm it persists
        got->visualization_spec = R"({"type":"line","processor":"datetime_series"})";
        REQUIRE(store.update_definition(*got));
        auto got2 = store.get_definition("def-viz-rt");
        REQUIRE(got2.has_value());
        CHECK(got2->visualization_spec.find("\"type\":\"line\"") != std::string::npos);
    }
    fs::remove(db_path);
    fs::remove(db_path.string() + "-wal");
    fs::remove(db_path.string() + "-shm");
}

TEST_CASE("InstructionStore: import_definition_json accepts visualization_spec as object or string",
          "[instruction_store][visualization][import]") {
    auto db_path = uniq("inst-viz-imp");
    fs::remove(db_path);
    {
        InstructionStore store(db_path);
        REQUIRE(store.is_open());

        // Object form (CLI converts YAML→JSON in one shot)
        nlohmann::json j;
        j["id"] = "def-imp-obj";
        j["name"] = "imp-obj";
        j["type"] = "question";
        j["plugin"] = "procfetch";
        j["visualization_spec"] = nlohmann::json::object({
            {"type", "pie"}, {"processor", "single_series"}, {"label_field", 1},
        });
        REQUIRE(store.import_definition_json(j.dump()).has_value());
        auto got = store.get_definition("def-imp-obj");
        REQUIRE(got.has_value());
        CHECK(got->visualization_spec.find("\"type\":\"pie\"") != std::string::npos);

        // Pre-serialized string form
        nlohmann::json j2;
        j2["id"] = "def-imp-str";
        j2["name"] = "imp-str";
        j2["type"] = "question";
        j2["plugin"] = "procfetch";
        j2["visualization_spec"] = R"({"type":"bar","processor":"single_series"})";
        REQUIRE(store.import_definition_json(j2.dump()).has_value());
        auto got2 = store.get_definition("def-imp-str");
        REQUIRE(got2.has_value());
        CHECK(got2->visualization_spec.find("\"type\":\"bar\"") != std::string::npos);
    }
    fs::remove(db_path);
    fs::remove(db_path.string() + "-wal");
    fs::remove(db_path.string() + "-shm");
}
