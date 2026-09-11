/**
 * test_rest_executions_v1_twins.cpp — HTTP-level coverage for #4030's
 * executions REST v1 surface: the new confined list route
 * (GET /api/v1/executions), the widened detail route's per-agent expansion
 * (GET /api/v1/executions/{id}?include=agents), and the new execution-scoped
 * responses route (GET /api/v1/executions/{id}/responses).
 *
 * Pattern matches test_rest_visualization.cpp: register RestApiV1 routes
 * against an in-process TestRouteSink and dispatch synthesised requests
 * directly into the captured handlers. No real socket → no #438 TSan trap.
 */

#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "pg/pg_pool.hpp"
#include "rest_api_v1.hpp"
#include "response_store.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../test_helpers.hpp"

#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_set>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

// Shares the "responsestore" template key with test_response_store.cpp /
// test_rest_visualization.cpp (identical setup) — ResponseStore is the base
// PgTestTemplate; ExecutionTracker/InstructionStore self-migrate their own
// schemas idempotently when constructed against the same database (matches
// test_workflow_routes.cpp's ExecHarness pattern).
yuzu::test::PgTestTemplate execv1_responsestore_tpl{
    "responsestore", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        ResponseStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("execv1 responsestore template: store failed to migrate");
    }};

struct AuditRecord {
    std::string action, result, target_type, target_id, detail;
};

struct ExecV1Harness {
    yuzu::server::test::TestRouteSink sink;

    std::unique_ptr<ExecutionTracker> execution_tracker;
    std::unique_ptr<InstructionStore> instruction_store;
    std::unique_ptr<ResponseStore> response_store;

    bool perm_grant{true};
    authz::VisibleSet fleet_read_scope{std::nullopt};
    std::string session_username{"tester"};
    std::vector<AuditRecord> audit_log;

    RestApiV1 api;

    explicit ExecV1Harness(pg::PgPool& pool) {
        execution_tracker = std::make_unique<ExecutionTracker>(pool);
        REQUIRE(execution_tracker->is_open());
        instruction_store = std::make_unique<InstructionStore>(pool);
        REQUIRE(instruction_store->is_open());
        instruction_store->set_require_signed_definitions(false);
        response_store = std::make_unique<ResponseStore>(pool, /*retention_days=*/0);
        REQUIRE(response_store->is_open());

        auto auth_fn = [this](const httplib::Request&,
                              httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = session_username;
            s.role = auth::Role::admin;
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
        auto fleet_read_fn = [this](const httplib::Request&, httplib::Response& res,
                                    const std::string&,
                                    const std::string&) -> authz::FleetReadGate {
            if (!perm_grant) {
                res.status = 403;
                res.set_content(R"({"error":"forbidden"})", "application/json");
                return {false, authz::deny_all()};
            }
            return {true, fleet_read_scope};
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& a, const std::string& r,
                               const std::string& tt, const std::string& ti,
                               const std::string& d) -> bool {
            audit_log.push_back({a, r, tt, ti, d});
            return true;
        };

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr,
                            /*mgmt_store=*/nullptr,
                            /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr, response_store.get(),
                            instruction_store.get(), execution_tracker.get(),
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
                            /*guaranteed_state_store=*/nullptr,
                            /*metrics_registry=*/nullptr,
                            /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr,
                            /*result_set_store=*/nullptr,
                            /*command_dispatch_fn=*/{},
                            /*step_up_fn=*/{},
                            /*guardian_push_fn=*/{},
                            /*dex_perf_fn=*/{},
                            /*network_api=*/{},
                            /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr,
                            /*scoped_perm_fn=*/{},
                            /*software_inventory_store=*/nullptr,
                            /*response_scope_fn=*/{},
                            /*app_perf_providers=*/{},
                            /*engine_principal_store=*/nullptr,
                            /*access_review_store=*/nullptr,
                            /*auth_db=*/nullptr,
                            /*directory_sync=*/nullptr,
                            /*stream_budget=*/nullptr,
                            /*exec_visible_fn=*/{},
                            /*list_read_fn=*/{},
                            /*fleet_read_fn=*/std::move(fleet_read_fn));
    }

    ~ExecV1Harness() {
        response_store.reset();
        instruction_store.reset();
        execution_tracker.reset();
    }

    /// Creates an execution row with two agent-status rows (one success, one
    /// failure) and returns the execution id.
    std::string make_exec_with_agents(const std::string& definition_id = "def-1") {
        Execution e;
        e.definition_id = definition_id;
        e.dispatched_by = "tester";
        e.status = "completed";
        e.dispatched_at = 1735689600;
        auto id = execution_tracker->create_execution(e);
        REQUIRE(id.has_value());
        AgentExecStatus a1;
        a1.agent_id = "agent-A";
        a1.status = "success";
        a1.dispatched_at = 1735689600;
        a1.completed_at = 1735689610;
        execution_tracker->update_agent_status(*id, a1);
        AgentExecStatus a2;
        a2.agent_id = "agent-B";
        a2.status = "failure";
        a2.dispatched_at = 1735689600;
        a2.completed_at = 1735689620;
        a2.error_detail = "boom";
        execution_tracker->update_agent_status(*id, a2);
        return *id;
    }
};

} // namespace

TEST_CASE("GET /api/v1/executions: lists via the shared builder", "[pg][rest][executions][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto exec_id = h.make_exec_with_agents("def-list-1");

    auto res = h.sink.Get("/api/v1/executions");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body.contains("data"));
    bool found = false;
    for (const auto& row : body["data"]) {
        if (row["id"] == exec_id) {
            found = true;
            CHECK(row["agents_success"] == 1);
            CHECK(row["agents_failure"] == 1);
            CHECK(row.contains("definition_name"));
            CHECK(row.contains("error_preview"));
        }
    }
    CHECK(found);
    CHECK(body["pagination"]["total"] >= 1);
}

TEST_CASE("GET /api/v1/executions: fleet_read_fn denial → 403",
          "[pg][rest][executions][v1][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    h.perm_grant = false;

    auto res = h.sink.Get("/api/v1/executions");
    REQUIRE(res);
    CHECK(res->status == 403);
}

TEST_CASE("GET /api/v1/executions/:id: bare request has no agents/kpi and is unaudited",
          "[pg][rest][executions][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto exec_id = h.make_exec_with_agents("def-bare-1");

    auto res = h.sink.Get("/api/v1/executions/" + exec_id);
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    CHECK_FALSE(body["data"].contains("agents"));
    CHECK_FALSE(body["data"].contains("kpi"));
    for (const auto& c : h.audit_log)
        CHECK(c.target_id != exec_id);
}

TEST_CASE("GET /api/v1/executions/:id?include=agents: adds per-agent array + kpi, audited",
          "[pg][rest][executions][v1]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto exec_id = h.make_exec_with_agents("def-inc-1");

    auto res = h.sink.Get("/api/v1/executions/" + exec_id + "?include=agents");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"].contains("agents"));
    REQUIRE(body["data"]["agents"].is_array());
    CHECK(body["data"]["agents"].size() == 2);
    REQUIRE(body["data"].contains("kpi"));
    CHECK(body["data"]["kpi"]["total"] == 2);
    CHECK(body["data"]["kpi"]["succeeded"] == 1);
    CHECK(body["data"]["kpi"]["failed"] == 1);

    bool audited = false;
    for (const auto& c : h.audit_log) {
        if (c.action == "execution.detail.fetch" && c.target_id == exec_id)
            audited = true;
    }
    CHECK(audited);
}

TEST_CASE("GET /api/v1/executions/:id?include=agents: confines the per-agent array to the "
          "caller's fleet-read scope",
          "[pg][rest][executions][v1][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto exec_id = h.make_exec_with_agents("def-conf-1");
    h.fleet_read_scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-A"}};

    auto res = h.sink.Get("/api/v1/executions/" + exec_id + "?include=agents");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"]["agents"].is_array());
    CHECK(body["data"]["agents"].size() == 1);
    CHECK(body["data"]["agents"][0]["agent_id"] == "agent-A");
    CHECK(body["data"]["agents_targeted"] == 1);
}

TEST_CASE("GET /api/v1/executions/:id/responses: mirrors query_responses' execution_id filter",
          "[pg][rest][executions][v1][responses]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto exec_id = h.make_exec_with_agents("def-resp-1");

    StoredResponse r;
    r.instruction_id = "def-resp-1";
    r.agent_id = "agent-A";
    r.timestamp = 1735689610;
    r.status = 0;
    r.output = "hello";
    r.execution_id = exec_id;
    h.response_store->store(r);

    auto res = h.sink.Get("/api/v1/executions/" + exec_id + "/responses");
    REQUIRE(res);
    CHECK(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"].is_array());
    REQUIRE(body["data"].size() == 1);
    CHECK(body["data"][0]["agent_id"] == "agent-A");
    CHECK(body["data"][0]["execution_id"] == exec_id);
    CHECK(body["data"][0]["output"] == "hello");

    bool audited = false;
    for (const auto& c : h.audit_log) {
        if (c.action == "execution.detail.fetch" && c.target_id == exec_id)
            audited = true;
    }
    CHECK(audited);
}

// #4030 Gate 8 fix (happy-path, Gate 4, HIGH/I3): `offset` over this
// route's non-unique, actively-growing `timestamp DESC` order silently
// skips/duplicates rows while an execution is non-terminal -- the same
// hazard its declared MCP twin query_responses deliberately avoids by
// never accepting the parameter. Reject rather than silently ignore.
TEST_CASE("GET /api/v1/executions/:id/responses: offset is rejected with 400, "
          "not silently ignored (#4030 Gate 8 fix)",
          "[pg][rest][executions][v1][responses]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    auto exec_id = h.make_exec_with_agents("def-resp-offset");

    auto res = h.sink.Get("/api/v1/executions/" + exec_id + "/responses?offset=1");
    REQUIRE(res);
    CHECK(res->status == 400);
}

TEST_CASE("GET /api/v1/executions/:id/responses: fleet_read_fn gates on Response:Read, "
          "independent of Execution:Read",
          "[pg][rest][executions][v1][responses][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, execv1_responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ExecV1Harness h(pool);
    h.perm_grant = false;

    auto res = h.sink.Get("/api/v1/executions/anything/responses");
    REQUIRE(res);
    CHECK(res->status == 403);
}
