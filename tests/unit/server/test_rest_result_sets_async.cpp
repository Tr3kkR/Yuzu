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
#include "inventory_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "rest_api_v1.hpp"
#include "result_set_store.hpp"
#include "test_route_sink.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <nlohmann/json.hpp>
#include <sqlite3.h>

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "../test_helpers.hpp"

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

// ResultSetStore is now a migrated Postgres store (ADR-0036) — shares the
// "resultset" template key with test_result_set_store.cpp (identical setup).
yuzu::test::PgTestTemplate result_set_tpl{
    "resultset", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        ResultSetStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("resultset template: store failed to migrate");
    }};

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
    SqliteHandleGuard tracker_guard;
    yuzu::server::test::TestRouteSink sink;

    std::unique_ptr<ResultSetStore> store;
    std::unique_ptr<ExecutionTracker> tracker;
    std::unique_ptr<InstructionStore> instr;
    /// #2500: from-inventory-query is the FOURTH instance of the targeting
    /// widening and has its own code path. Its handler 503s before any input
    /// validation when the store is unwired (dependency-before-validation is
    /// the convention on these routes), so reaching its parent_id guard at all
    /// requires a real store. Post-ADR-0037 that store is Postgres-backed, so
    /// the one section that needs it injects a borrowed pointer. The caller
    /// owns the store and must keep it alive longer than this harness.
    InventoryStore* inventory{nullptr};
    yuzu::MetricsRegistry metrics;
    RestApiV1 api;

    // Fake-dispatch knobs / recording.
    std::vector<DispatchCall> calls;
    int dispatch_sent{2}; // agents "reached" by each dispatch
    bool dispatch_throws{false};
    bool wire_dispatch{true}; // false → leave the callback empty (503 path)

    explicit AsyncHarness(pg::PgPool& pool, bool with_dispatch = true,
                          InventoryStore* inv = nullptr)
        : inventory(inv), wire_dispatch(with_dispatch) {
        store = std::make_unique<ResultSetStore>(pool);
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
                          const std::string&) -> bool {
            return true;
        };
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
                            tracker.get(), /*schedule_engine=*/nullptr,
                            /*approval_manager=*/nullptr,
                            /*tag_store=*/nullptr, /*audit_store=*/nullptr, /*service_group_fn=*/{},
                            /*tag_push_fn=*/{}, inventory,
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

// Unwrap ResultSetStore::get's std::expected<optional<...>,...> (ADR-0036) —
// every call below hits a live, healthy Postgres, so a DbError here is a
// genuine test-infrastructure failure; REQUIRE it away and hand back the
// plain optional these tests were written against.
std::optional<ResultSet> get_ok(ResultSetStore& s, const std::string& id) {
    auto r = s.get(id);
    REQUIRE(r.has_value());
    return *r;
}

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
          "[pg][result_set][async][tar]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-tar-query",
                    R"({"sql":"SELECT pid FROM process_live","name":"chrome-procs"})", status);
    REQUIRE(status == 202);
    auto data = j["data"];
    REQUIRE(data["status"] == "pending");
    REQUIRE(data["source_kind"] == "tar_query");
    REQUIRE_FALSE(data["source_execution_id"].get<std::string>().empty());

    // Dispatch happened with tar/sql, an EXPLICIT `__all__` scope, sql param.
    // This case's name always said `__all__`; the assertion used to be
    // `scope_expr.empty()`, because empty was the proxy for broadcast at the
    // dispatch sink. #2500 inverted that default — empty now reaches nobody —
    // so the producer names the broadcast and the assertion finally matches
    // the name it has had all along.
    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.calls[0].plugin == "tar");
    REQUIRE(h.calls[0].action == "sql");
    REQUIRE(h.calls[0].scope_expr == "__all__");
    REQUIRE(h.calls[0].params.at("sql") == "SELECT pid FROM process_live");
    // execution_id was minted BEFORE dispatch (create-before-dispatch).
    REQUIRE(h.calls[0].execution_id == data["source_execution_id"].get<std::string>());

    // The row landed pending with the default tar matcher.
    auto row = get_ok(*h.store, data["id"].get<std::string>());
    REQUIRE(row.has_value());
    REQUIRE(row->status == ResultSetStatus::Pending);
    REQUIRE(row->matcher.find("tar_rows_ge") != std::string::npos);
}

TEST_CASE("from-tar-query: parent_id scopes dispatch via from_result_set:",
          "[pg][result_set][async][tar]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto parent = h.seed_materialized("win-fleet", {"a1", "a2"});
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-tar-query",
                    R"({"sql":"SELECT 1","parent_id":")" + parent + R"("})", status);
    REQUIRE(status == 202);
    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.calls[0].scope_expr == "from_result_set:" + parent);
    // Lineage: the new set's parent is the seeded set.
    auto row = get_ok(*h.store, j["data"]["id"].get<std::string>());
    REQUIRE(row->parent_id.has_value());
    REQUIRE(*row->parent_id == parent);
}

TEST_CASE("from-tar-query: parent alias is pre-resolved to canonical id",
          "[pg][result_set][async][tar][alias]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto canonical = h.seed_materialized("my-alias", {"a1"});
    int status = 0;
    // parent_id given as the human alias, not the rs_ id.
    auto j = h.post("/api/v1/result-sets/from-tar-query",
                    R"({"sql":"SELECT 1","parent_id":"my-alias"})", status);
    REQUIRE(status == 202);
    REQUIRE(h.calls[0].scope_expr == "from_result_set:" + canonical);
    REQUIRE(*get_ok(*h.store, j["data"]["id"].get<std::string>())->parent_id == canonical);
}

TEST_CASE("from-tar-query: unknown parent alias 404s, no dispatch",
          "[pg][result_set][async][tar][alias]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query",
           R"({"sql":"SELECT 1","parent_id":"nonexistent-alias"})", status);
    REQUIRE(status == 404);
    REQUIRE(h.calls.empty());
}

TEST_CASE("from-tar-query: include_empty selects the any_response matcher",
          "[pg][result_set][async][tar]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-tar-query",
                    R"({"sql":"SELECT 1","include_empty":true})", status);
    REQUIRE(status == 202);
    REQUIRE(get_ok(*h.store, j["data"]["id"].get<std::string>())->matcher.find("any_response") !=
            std::string::npos);
}

TEST_CASE("from-tar-query: missing sql is 400, no dispatch", "[pg][result_set][async][tar]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query", R"({"name":"x"})", status);
    REQUIRE(status == 400);
    REQUIRE(h.calls.empty());
}

TEST_CASE("#2500 — a supplied parent_id that names no parent is refused, not widened",
          "[pg][result_set][async][tar][targeting][security]") {
    // PG-port note (merge of #2500's dev-side case into the ADR-0036 branch):
    // the harness is now Postgres-backed, so the fixture preamble matches the
    // sibling cases and the case carries [pg] (shard-partition invariant —
    // it SKIPs without a DSN via YUZU_REQUIRE_PG_DB_TPL).
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    // parent_id IS the targeting argument on this route: present and non-empty
    // scopes the dispatch to that set's members via `from_result_set:`, absent
    // broadcasts to every connected agent. The guard used to be
    // `contains && is_string && !empty`, so a SUPPLIED parent_id that was
    // numeric or empty fell through to the untargeted arm — a caller who
    // believed it was narrowing to one result set dispatched to the whole
    // fleet instead. Same shape as the agent_ids defect on the two routes
    // #2500 names; found while auditing this call site for that fix.
    //
    // `h.calls.empty()` is the assertion that matters: a 400 that still
    // dispatched would leave the widening intact behind a better status code.
    SECTION("numeric parent_id") {
        AsyncHarness h(pool);
        int status = 0;
        h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1","parent_id":123})",
               status);
        REQUIRE(status == 400);
        REQUIRE(h.calls.empty());
    }
    SECTION("empty-string parent_id") {
        AsyncHarness h(pool);
        int status = 0;
        h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1","parent_id":""})",
               status);
        REQUIRE(status == 400);
        REQUIRE(h.calls.empty());
    }
    SECTION("explicit null parent_id") {
        // Rejected rather than read as "absent". A client that serialises an
        // unset field as null and one whose parent lookup returned nothing are
        // indistinguishable here, and only one of them wants the entire fleet.
        AsyncHarness h(pool);
        int status = 0;
        h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1","parent_id":null})",
               status);
        REQUIRE(status == 400);
        REQUIRE(h.calls.empty());
    }
    SECTION("the refusal is counted and audited, not just returned") {
        // Governance found the first version of this guard emitted neither, so
        // the third and fourth instances of the defect class were invisible to
        // the alert the change ships. The reason label names the field that was
        // actually wrong: an earlier version reused `scope_empty`, which put a
        // field the caller never sent into the audit trail.
        AsyncHarness h(pool);
        int status = 0;
        h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1","parent_id":123})",
               status);
        REQUIRE(status == 400);
        CHECK(h.metrics
                  .counter("yuzu_server_dispatch_target_rejected_total",
                           {{"route", "result_set_parent"}, {"reason", "parent_id_type"}})
                  .value() == 1.0);
    }
    SECTION("from-inventory-query — the fourth instance, its own code path") {
        // Not covered by the run_async guard: this producer has its own
        // parent_id block and was missed by the first round of the fix. It is
        // synchronous, so the consequence was a READ across every device rather
        // than a dispatch — narrower blast radius, same defect. Construct the
        // inventory dependency only in this section; the invalid parent is
        // rejected before the handler performs an inventory query.
        InventoryStore inventory{pool};
        REQUIRE(inventory.is_open());
        AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);
        int status = 0;
        h.post("/api/v1/result-sets/from-inventory-query", R"({"query":"os=linux","parent_id":""})",
               status);
        REQUIRE(status == 400);
        CHECK(h.metrics
                  .counter("yuzu_server_dispatch_target_rejected_total",
                           {{"route", "result_set_parent"}, {"reason", "parent_id_empty"}})
                  .value() == 1.0);
    }
    SECTION("from-inventory-query refuses a byte-capped read without creating a set") {
        InventoryStore inventory{pool};
        REQUIRE(inventory.is_open());
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto seeded = yuzu::server::pg::exec_params(
            lease.get(),
            "INSERT INTO inventory_store.inventory_data "
            "(agent_id, plugin, data_json, collected_at) "
            "VALUES ('byte-agent', 'custom_large', repeat('x', 8388609), 1)",
            std::vector<std::string>{});
        REQUIRE(seeded.status() == PGRES_COMMAND_OK);
        lease.reset();

        AsyncHarness h(pool, /*with_dispatch=*/true, &inventory);
        int status = 0;
        auto query = h.post("/api/v1/inventory/query", R"({"limit":10})", status);
        REQUIRE(status == 200);
        CHECK(query["result_truncated_by_cap"] == true);
        REQUIRE(query["data"].is_array());
        CHECK(query["data"].empty());

        h.post("/api/v1/result-sets/from-inventory-query", R"({"name":"must-not-exist"})",
               status);
        REQUIRE(status == 503);
        std::string next;
        CHECK(h.store->list_by_owner("operator-1", "", 50, next).empty());
    }
    SECTION("a non-object body is refused, not read as an absent parent_id") {
        AsyncHarness h(pool);
        int status = 0;
        h.post("/api/v1/result-sets/from-tar-query", R"(["sql"])", status);
        REQUIRE(status == 400);
        CHECK(h.calls.empty());
    }
    SECTION("omitting parent_id still broadcasts — the over-broadness guard") {
        AsyncHarness h(pool);
        int status = 0;
        h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1"})", status);
        REQUIRE(status == 202);
        REQUIRE(h.calls.size() == 1);
        REQUIRE(h.calls[0].scope_expr == "__all__");
    }
}

TEST_CASE("from-tar-query: zero agents reached is 503, execution cancelled, no pending row",
          "[pg][result_set][async][tar]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
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
          "[pg][result_set][async][tar]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    h.dispatch_throws = true;
    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1"})", status);
    REQUIRE(status == 500);
    std::string next;
    REQUIRE(h.store->list_by_owner("operator-1", "", 50, next).empty());
}

TEST_CASE("from-tar-query: 503 when command dispatch is unwired", "[pg][result_set][async][tar]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool, /*with_dispatch=*/false);
    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1"})", status);
    REQUIRE(status == 503);
}

TEST_CASE("from-instruction-result: 202 pending with operator matcher persisted",
          "[pg][result_set][async][instruction]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto iid = make_instruction(*h.instr);
    int status = 0;
    std::string body =
        R"({"instruction_id":")" + iid +
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
    auto row = get_ok(*h.store, j["data"]["id"].get<std::string>());
    REQUIRE(row->matcher.find("sha256") != std::string::npos);
    REQUIRE(row->matcher.find("value_set") != std::string::npos);
}

TEST_CASE("from-instruction-result: unknown instruction_id 404s",
          "[pg][result_set][async][instruction]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    h.post("/api/v1/result-sets/from-instruction-result", R"({"instruction_id":"does-not-exist"})",
           status);
    REQUIRE(status == 404);
    REQUIRE(h.calls.empty());
}

TEST_CASE("re-eval: tar_query set re-dispatches as a sibling (shares parent)",
          "[pg][result_set][async][reeval]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
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
    auto row = get_ok(*h.store, new_id);
    REQUIRE(row->parent_id.has_value());
    REQUIRE(*row->parent_id == grandparent);
}

TEST_CASE("re-eval: unsupported source_kind is 400", "[pg][result_set][async][reeval]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto manual = h.seed_materialized("hand-curated", {"a1"});
    int status = 0;
    h.post("/api/v1/result-sets/" + manual + "/re-eval", "", status);
    REQUIRE(status == 400);
}

TEST_CASE("re-eval: not-owned / missing set is 404", "[pg][result_set][async][reeval]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    int status = 0;
    h.post("/api/v1/result-sets/rs_00000000000deadbeef/re-eval", "", status);
    REQUIRE(status == 404);
}
