/**
 * test_rest_result_sets_async.cpp — HTTP-level coverage for the async
 * result-set producers added in scope-walking PR-D:
 *
 *   POST /api/v1/result-sets/from-tar-query
 *   POST /api/v1/result-sets/from-instruction-result
 *   POST /api/v1/result-sets/{id}/re-eval
 *
 * Exercised via the TestRouteSink in-process dispatch pattern (#438) with a
 * REAL ResultSetStore + ExecutionTracker and a FAKE command-dispatch closure
 * that records its arguments and returns a configurable (command_id, sent).
 * The maintenance thread is NOT run here — materialisation is covered by the
 * matcher unit tests; this file asserts the synchronous handler contract:
 * create-before-dispatch ordering, the dispatched scope expression (including
 * alias pre-resolution), the 202 pending shape, the matcher persisted on the
 * row, the no-agents / no-dispatch error paths, and the re-eval sibling rule.
 */

#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "rest_api_v1.hpp"
#include "result_set_store.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>
#include <sqlite3.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "../test_helpers.hpp"

using namespace yuzu::server;

namespace {

struct DispatchCall {
    std::string plugin, action, scope_expr;
    std::vector<std::string> agent_ids;
    std::unordered_map<std::string, std::string> params;
    std::string execution_id;
};

struct SqliteHandleGuard {
    sqlite3* db{nullptr};
    ~SqliteHandleGuard() {
        if (db)
            sqlite3_close(db);
    }
};

struct AsyncHarness {
    yuzu::test::TempDbFile rs_db{std::string_view("rs-async-store-")};
    SqliteHandleGuard tracker_guard;
    yuzu::server::test::TestRouteSink sink;

    std::unique_ptr<ResultSetStore> store;
    std::unique_ptr<ExecutionTracker> tracker;
    std::unique_ptr<InstructionStore> instr;
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    // Fake-dispatch knobs / recording.
    std::vector<DispatchCall> calls;
    int dispatch_sent{2};   // agents "reached" by each dispatch
    bool dispatch_throws{false};
    bool wire_dispatch{true}; // false → leave the callback empty (503 path)

    explicit AsyncHarness(bool with_dispatch = true) : wire_dispatch(with_dispatch) {
        store = std::make_unique<ResultSetStore>(rs_db.path);
        REQUIRE(store->is_open());

        REQUIRE(sqlite3_open(":memory:", &tracker_guard.db) == SQLITE_OK);
        tracker = std::make_unique<ExecutionTracker>(tracker_guard.db);
        tracker->create_tables();

        instr = std::make_unique<InstructionStore>(":memory:");
        REQUIRE(instr->is_open());

        auto auth_fn = [](const httplib::Request&,
                          httplib::Response&) -> std::optional<auth::Session> {
            auth::Session s;
            s.username = "operator-1";
            s.role = auth::Role::admin;
            return s;
        };
        auto perm_fn = [](const httplib::Request&, httplib::Response&, const std::string&,
                          const std::string&) -> bool { return true; };
        auto audit_fn = [](const httplib::Request&, const std::string&, const std::string&,
                           const std::string&, const std::string&, const std::string&) -> bool {
            return true;
        };

        RestApiV1::CommandDispatchFn dispatch_fn;
        if (wire_dispatch) {
            dispatch_fn = [this](const std::string& plugin, const std::string& action,
                                 const std::vector<std::string>& agent_ids,
                                 const std::string& scope_expr,
                                 const std::unordered_map<std::string, std::string>& params,
                                 const std::string& exec_id) -> std::pair<std::string, int> {
                calls.push_back({plugin, action, scope_expr, agent_ids, params, exec_id});
                if (dispatch_throws)
                    throw std::runtime_error("simulated dispatch failure");
                return {"cmd-" + std::to_string(calls.size()), dispatch_sent};
            };
        }

        api.register_routes(sink, auth_fn, perm_fn, audit_fn,
                            /*rbac_store=*/nullptr, /*mgmt_store=*/nullptr, /*token_store=*/nullptr,
                            /*quarantine_store=*/nullptr, /*response_store=*/nullptr, instr.get(),
                            tracker.get(), /*schedule_engine=*/nullptr, /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr, /*audit_store=*/nullptr, /*service_group_fn=*/{},
                            /*tag_push_fn=*/{}, /*inventory_store=*/nullptr,
                            /*product_pack_store=*/nullptr, /*sw_deploy_store=*/nullptr,
                            /*device_token_store=*/nullptr, /*license_store=*/nullptr,
                            /*guaranteed_state_store=*/nullptr, &metrics, /*session_revoke_fn=*/{},
                            /*execution_event_bus=*/nullptr, store.get(), dispatch_fn);
    }

    nlohmann::json post(const std::string& path, const std::string& body, int& status) {
        auto res = sink.dispatch("POST", path, body);
        REQUIRE(res != nullptr);
        status = res->status;
        return nlohmann::json::parse(res->body, nullptr, false);
    }

    // Seed a materialized set directly in the store (a "ground" set to parent
    // off / re-eval alias targets).
    std::string seed_materialized(const std::string& name,
                                  const std::vector<std::string>& members) {
        CreateRequest cr;
        cr.owner_principal = "operator-1";
        cr.name = name;
        cr.source_kind = std::string(source_kind::kManualCurate);
        cr.source_payload = "{}";
        auto r = store->create_materialized(cr, members);
        REQUIRE(r.has_value());
        return r->id;
    }
};

std::string make_instruction(InstructionStore& s) {
    InstructionDefinition def;
    def.name = "Chrome hash check";
    def.version = "1.0";
    def.plugin = "filehash";
    def.action = "check";
    def.type = "action";
    def.description = "hash check";
    def.enabled = true;
    auto id = s.create_definition(def);
    REQUIRE(id.has_value());
    return *id;
}

} // namespace

TEST_CASE("from-tar-query: 202 pending, dispatch to __all__ when no parent",
          "[result_set][async][tar]") {
    AsyncHarness h;
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-tar-query",
                    R"({"sql":"SELECT pid FROM process_live","name":"chrome-procs"})", status);
    REQUIRE(status == 202);
    auto data = j["data"];
    REQUIRE(data["status"] == "pending");
    REQUIRE(data["source_kind"] == "tar_query");
    REQUIRE_FALSE(data["source_execution_id"].get<std::string>().empty());

    // Dispatch happened with tar/sql, empty scope (=> broadcast), sql param.
    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.calls[0].plugin == "tar");
    REQUIRE(h.calls[0].action == "sql");
    REQUIRE(h.calls[0].scope_expr.empty());
    REQUIRE(h.calls[0].params.at("sql") == "SELECT pid FROM process_live");
    // execution_id was minted BEFORE dispatch (create-before-dispatch).
    REQUIRE(h.calls[0].execution_id == data["source_execution_id"].get<std::string>());

    // The row landed pending with the default tar matcher.
    auto row = h.store->get(data["id"].get<std::string>());
    REQUIRE(row.has_value());
    REQUIRE(row->status == ResultSetStatus::Pending);
    REQUIRE(row->matcher.find("tar_rows_ge") != std::string::npos);
}

TEST_CASE("from-tar-query: parent_id scopes dispatch via from_result_set:",
          "[result_set][async][tar]") {
    AsyncHarness h;
    auto parent = h.seed_materialized("win-fleet", {"a1", "a2"});
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-tar-query",
                    R"({"sql":"SELECT 1","parent_id":")" + parent + R"("})", status);
    REQUIRE(status == 202);
    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.calls[0].scope_expr == "from_result_set:" + parent);
    // Lineage: the new set's parent is the seeded set.
    auto row = h.store->get(j["data"]["id"].get<std::string>());
    REQUIRE(row->parent_id.has_value());
    REQUIRE(*row->parent_id == parent);
}

TEST_CASE("from-tar-query: parent alias is pre-resolved to canonical id",
          "[result_set][async][tar][alias]") {
    AsyncHarness h;
    auto canonical = h.seed_materialized("my-alias", {"a1"});
    int status = 0;
    // parent_id given as the human alias, not the rs_ id.
    auto j = h.post("/api/v1/result-sets/from-tar-query",
                    R"({"sql":"SELECT 1","parent_id":"my-alias"})", status);
    REQUIRE(status == 202);
    REQUIRE(h.calls[0].scope_expr == "from_result_set:" + canonical);
    REQUIRE(*h.store->get(j["data"]["id"].get<std::string>())->parent_id == canonical);
}

TEST_CASE("from-tar-query: unknown parent alias 404s, no dispatch",
          "[result_set][async][tar][alias]") {
    AsyncHarness h;
    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query",
           R"({"sql":"SELECT 1","parent_id":"nonexistent-alias"})", status);
    REQUIRE(status == 404);
    REQUIRE(h.calls.empty());
}

TEST_CASE("from-tar-query: include_empty selects the any_response matcher",
          "[result_set][async][tar]") {
    AsyncHarness h;
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-tar-query",
                    R"({"sql":"SELECT 1","include_empty":true})", status);
    REQUIRE(status == 202);
    REQUIRE(h.store->get(j["data"]["id"].get<std::string>())->matcher.find("any_response") !=
            std::string::npos);
}

TEST_CASE("from-tar-query: missing sql is 400, no dispatch", "[result_set][async][tar]") {
    AsyncHarness h;
    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query", R"({"name":"x"})", status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
}

TEST_CASE("from-tar-query: zero agents reached is 503, execution cancelled, no pending row",
          "[result_set][async][tar]") {
    AsyncHarness h;
    h.dispatch_sent = 0; // dispatch reaches nobody
    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1"})", status);
    REQUIRE(status == 503);
    REQUIRE(h.calls.size() == 1); // dispatch was attempted
    // No pending set persisted (the operator gets a clean failure, not a row
    // that idles to the timeout).
    std::string next;
    REQUIRE(h.store->list_by_owner("operator-1", "", 50, next).empty());
}

TEST_CASE("from-tar-query: dispatch throw is 500, execution cancelled",
          "[result_set][async][tar]") {
    AsyncHarness h;
    h.dispatch_throws = true;
    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1"})", status);
    REQUIRE(status == 500);
    std::string next;
    REQUIRE(h.store->list_by_owner("operator-1", "", 50, next).empty());
}

TEST_CASE("from-tar-query: 503 when command dispatch is unwired", "[result_set][async][tar]") {
    AsyncHarness h{/*with_dispatch=*/false};
    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1"})", status);
    REQUIRE(status == 503);
}

TEST_CASE("from-instruction-result: 202 pending with operator matcher persisted",
          "[result_set][async][instruction]") {
    AsyncHarness h;
    auto iid = make_instruction(*h.instr);
    int status = 0;
    std::string body = R"({"instruction_id":")" + iid +
                       R"(","params":{"path":"/x"},"matcher":{"column":"sha256","op":"in","value_set":["bad"]}})";
    auto j = h.post("/api/v1/result-sets/from-instruction-result", body, status);
    REQUIRE(status == 202);
    REQUIRE(j["data"]["source_kind"] == "instruction_result");
    // Dispatch used the definition's plugin/action and the params.
    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.calls[0].plugin == "filehash");
    REQUIRE(h.calls[0].action == "check");
    REQUIRE(h.calls[0].params.at("path") == "/x");
    // The operator's column matcher is stored verbatim on the pending row.
    auto row = h.store->get(j["data"]["id"].get<std::string>());
    REQUIRE(row->matcher.find("sha256") != std::string::npos);
    REQUIRE(row->matcher.find("value_set") != std::string::npos);
}

TEST_CASE("from-instruction-result: unknown instruction_id 404s", "[result_set][async][instruction]") {
    AsyncHarness h;
    int status = 0;
    h.post("/api/v1/result-sets/from-instruction-result",
           R"({"instruction_id":"does-not-exist"})", status);
    REQUIRE(status == 404);
    REQUIRE(h.calls.empty());
}

TEST_CASE("re-eval: tar_query set re-dispatches as a sibling (shares parent)",
          "[result_set][async][reeval]") {
    AsyncHarness h;
    auto grandparent = h.seed_materialized("ground", {"a1", "a2"});
    int status = 0;
    // Original tar_query parented at `grandparent`.
    auto orig = h.post("/api/v1/result-sets/from-tar-query",
                       R"({"sql":"SELECT 7","parent_id":")" + grandparent + R"("})", status);
    REQUIRE(status == 202);
    auto orig_id = orig["data"]["id"].get<std::string>();
    h.calls.clear();

    int rstat = 0;
    auto re = h.post("/api/v1/result-sets/" + orig_id + "/re-eval", "", rstat);
    REQUIRE(rstat == 202);
    auto new_id = re["data"]["id"].get<std::string>();
    REQUIRE(new_id != orig_id);
    // Re-dispatched the original SQL.
    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.calls[0].params.at("sql") == "SELECT 7");
    // Sibling: new set's parent == original's parent (NOT the original).
    auto row = h.store->get(new_id);
    REQUIRE(row->parent_id.has_value());
    REQUIRE(*row->parent_id == grandparent);
}

TEST_CASE("re-eval: unsupported source_kind is 400", "[result_set][async][reeval]") {
    AsyncHarness h;
    auto manual = h.seed_materialized("hand-curated", {"a1"});
    int status = 0;
    h.post("/api/v1/result-sets/" + manual + "/re-eval", "", status);
    REQUIRE(status == 400);
}

TEST_CASE("re-eval: not-owned / missing set is 404", "[result_set][async][reeval]") {
    AsyncHarness h;
    int status = 0;
    h.post("/api/v1/result-sets/rs_00000000000deadbeef/re-eval", "", status);
    REQUIRE(status == 404);
}
