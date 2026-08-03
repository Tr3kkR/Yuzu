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

#include <algorithm>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_set>
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
    /// #1788: the confinement set the handler derived and handed to dispatch.
    ///
    /// Its ABSENCE from this struct is why the fleet-wide escape on these three
    /// routes survived eleven review rounds and an eight-gate governance pass.
    /// The recorder captured plugin/action/scope/ids and nothing about WHO the
    /// caller was allowed to reach, so every assertion in this file stayed
    /// green while the routes dispatched through the system closure with
    /// exec_visible hardcoded to nullopt (unfiltered). A test that cannot
    /// observe the confinement decision cannot fail when it is absent.
    yuzu::server::authz::VisibleSet exec_visible;
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

    /// Recorded audit events (verb, result, detail) — the unwired-gate refusal
    /// must leave durable evidence, not just a status code.
    struct AuditCall {
        std::string action, result, detail;
    };
    std::vector<AuditCall> audits;
    /// AuditFn return value. false models a lost evidence row, which must
    /// surface as `Sec-Audit-Failed: true` on the response rather than being
    /// swallowed — a refusal nobody can prove happened is not fail-closed.
    bool audit_ok{true};

    // Fake-dispatch knobs / recording.
    std::vector<DispatchCall> calls;
    int dispatch_sent{2}; // agents "reached" by each dispatch
    bool dispatch_throws{false};
    bool wire_dispatch{true}; // false → leave the callback empty (503 path)
    /// CWE-862: these producers DISPATCH, so they must gate on
    /// Execution:Execute. Set false to model an authenticated caller who
    /// holds no such grant — the case that previously reached the fleet.
    static inline bool permit_exec{true};

    /// #1788: the VisibleSet the wired `exec_visible_fn` returns.
    ///
    /// Default nullopt = genuinely unfiltered authority (a global admin), which
    /// is what the pre-existing cases in this file model. Set to a present set
    /// to model a confined caller — e.g. a service-scoped token.
    yuzu::server::authz::VisibleSet exec_visible_override{};
    /// Leave `exec_visible_fn` EMPTY at registration, modelling a server whose
    /// visibility derivation was never wired. That is NOT a synonym for the
    /// nullopt default above: unwired is a misconfiguration and must be refused
    /// (audited 500), whereas a callback returning nullopt is a real answer
    /// meaning "this caller sees the whole fleet".
    bool wire_exec_visible{true};

    explicit AsyncHarness(pg::PgPool& pool, bool with_dispatch = true,
                          InventoryStore* inv = nullptr, bool with_exec_visible = true)
        : inventory(inv), wire_dispatch(with_dispatch), wire_exec_visible(with_exec_visible) {
        permit_exec = true; // each harness starts permissive

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
        auto perm_fn = [](const httplib::Request&, httplib::Response& r, const std::string&,
                          const std::string&) -> bool {
            if (!permit_exec) {
                r.status = 403;
                return false;
            }
            return true;
        };
        auto audit_fn = [this](const httplib::Request&, const std::string& action,
                               const std::string& result, const std::string&, const std::string&,
                               const std::string& detail) -> bool {
            audits.push_back({action, result, detail});
            return audit_ok;
        };

        RestApiV1::CommandDispatchFn dispatch_fn;
        if (wire_dispatch) {
            dispatch_fn = [this](const std::string& plugin, const std::string& action,
                                 const std::vector<std::string>& agent_ids,
                                 const std::string& scope_expr,
                                 const std::unordered_map<std::string, std::string>& params,
                                 const std::string& exec_id,
                                 const yuzu::server::authz::VisibleSet& exec_visible)
                -> std::pair<std::string, int> {
                calls.push_back(
                    {plugin, action, scope_expr, agent_ids, params, exec_id, exec_visible});
                if (dispatch_throws)
                    throw std::runtime_error("simulated dispatch failure");
                return {"cmd-" + std::to_string(calls.size()), dispatch_sent};
            };
        }

        RestApiV1::ExecVisibleFn exec_visible_fn;
        if (wire_exec_visible) {
            exec_visible_fn = [this](const auth::Session&) -> yuzu::server::authz::VisibleSet {
                return exec_visible_override;
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
                            /*execution_event_bus=*/nullptr, store.get(), dispatch_fn,
                            /*step_up_fn=*/{}, /*guardian_push_fn=*/{}, /*dex_perf_fn=*/{},
                            /*net_perf_fn=*/{}, /*lockout_clear_fn=*/{},
                            /*baseline_store=*/nullptr, /*scoped_perm_fn=*/{},
                            /*software_inventory_store=*/nullptr, /*inventory_scope_fn=*/{},
                            /*response_scope_fn=*/{}, /*app_perf_providers=*/{},
                            /*engine_principal_store=*/nullptr, /*access_review_store=*/nullptr,
                            /*auth_db=*/nullptr, /*directory_sync=*/nullptr,
                            /*stream_budget=*/nullptr, exec_visible_fn);
    }

    /// Header value from the most recent `post`, "" if absent. Kept so a test
    /// can assert `Sec-Audit-Failed` without every call site switching to the
    /// raw response.
    std::string last_sec_audit_failed;

    nlohmann::json post(const std::string& path, const std::string& body, int& status) {
        auto res = sink.dispatch("POST", path, body);
        REQUIRE(res != nullptr);
        status = res->status;
        last_sec_audit_failed = res->get_header_value("Sec-Audit-Failed");
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

// ═══════════════════════════════════════════════════════════════════════════
// CWE-862 — the three async producers DISPATCH, so they must gate on
// Execution:Execute.
//
// They authenticated the caller and then performed no authorization check at
// all: `perm_fn` was not even in the lambda capture list, so ANY authenticated
// session — including one holding no Execution grant — reached
// `command_dispatch_fn` with scope `__all__` and ran operator SQL across the
// whole fleet. Ungated since e7b47ca3 (2026-05-31) and shipped in v0.13.0.
//
// These assert the SECURITY OUTCOME — that nothing was dispatched — not merely
// that a status code changed. A test asserting only `status == 403` would still
// pass if the gate ran after the dispatch.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("from-tar-query: an authenticated caller WITHOUT Execution:Execute dispatches nothing",
          "[pg][result_set][async][tar][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    AsyncHarness::permit_exec = false; // authenticated, but no Execution grant

    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query",
           R"({"sql":"SELECT pid FROM process_live","name":"probe"})", status);

    CHECK(status == 403);
    CHECK(h.calls.empty()); // THE assertion: the fleet was never reached
}

TEST_CASE("from-instruction-result: an authenticated caller WITHOUT Execution:Execute dispatches "
          "nothing",
          "[pg][result_set][async][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto def_id = make_instruction(*h.instr);
    AsyncHarness::permit_exec = false;

    int status = 0;
    h.post("/api/v1/result-sets/from-instruction-result",
           R"({"instruction_id":")" + def_id + R"(","name":"probe"})", status);

    CHECK(status == 403);
    CHECK(h.calls.empty());
}

TEST_CASE("re-eval: an authenticated caller WITHOUT Execution:Execute dispatches nothing",
          "[pg][result_set][async][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);

    // Create a set legitimately first (gate permitted), then re-eval it without
    // the grant — proving the gate is on the re-eval route itself, not merely
    // inherited from whoever created the original.
    int status = 0;
    auto created = h.post("/api/v1/result-sets/from-tar-query",
                          R"({"sql":"SELECT pid FROM process_live","name":"orig"})", status);
    REQUIRE(status == 202);
    const auto rs_id = created["data"]["id"].get<std::string>();
    const auto calls_before = h.calls.size();

    AsyncHarness::permit_exec = false;
    h.post("/api/v1/result-sets/" + rs_id + "/re-eval", "{}", status);

    CHECK(status == 403);
    CHECK(h.calls.size() == calls_before); // no NEW dispatch
}

// ═══════════════════════════════════════════════════════════════════════════
// #1788 — per-device dispatch confinement on the three async producers.
//
// The CWE-862 cases above cover the NO-GRANT-AT-ALL caller. They do not cover
// the caller who legitimately holds `Execution:Execute` but may only reach SOME
// devices — a service-scoped token being the live example — and that gap is
// exactly what shipped: these routes admit on a bare GLOBAL perm_fn and then
// dispatched through the SYSTEM closure, whose exec_visible is hardcoded
// nullopt. A service-A token therefore reached every connected agent. Neither
// the eleven adversarial rounds nor the eight-gate governance pass could catch
// it, because `DispatchCall` had no field in which the confinement decision
// could be observed at all.
//
// WHAT THESE ASSERT, precisely: the HANDOFF — that the route derived a present
// (confined) VisibleSet and passed it to dispatch. They are NOT the proof that
// confinement is enforced; enforcement is the intersection, which lives in
// `dispatch_confined_arms` and is bound with exact-send-set assertions against
// a real AgentRegistry in test_dispatch_confined_arms.cpp. Both layers are
// required and neither substitutes for the other — a route mock that only
// observes the set stays green while the intersection is deleted (CDX-R8-02),
// which is why this comment says so rather than letting the next reader assume
// otherwise. Shape follows the established precedent at
// test_mcp_server.cpp's execute_instruction confinement cases.
// ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("from-tar-query: a confined caller's VisibleSet is derived and threaded into dispatch",
          "[pg][result_set][async][tar][security][1788]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    // A service-scoped token: holds Execution:Execute (perm_fn admits), but may
    // reach only its own service's agents.
    h.exec_visible_override = std::unordered_set<std::string>{"agent-A"};

    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1","name":"svc"})", status);
    REQUIRE(status == 202);

    REQUIRE(h.calls.size() == 1);
    // The broadcast arm is still SELECTED (`__all__` is a targeting mechanism,
    // never an authz exemption) — and it is narrowed at the seam by this set.
    CHECK(h.calls[0].scope_expr == "__all__");
    REQUIRE(h.calls[0].exec_visible.has_value()); // CONFINED, not unfiltered
    CHECK(h.calls[0].exec_visible->count("agent-A") == 1);
    CHECK(h.calls[0].exec_visible->count("agent-B") == 0);
}

TEST_CASE("from-instruction-result: a confined caller's VisibleSet reaches dispatch",
          "[pg][result_set][async][instruction][security][1788]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);
    auto iid = make_instruction(*h.instr);
    h.exec_visible_override = std::unordered_set<std::string>{"agent-A"};

    int status = 0;
    h.post("/api/v1/result-sets/from-instruction-result",
           R"({"instruction_id":")" + iid + R"("})", status);
    REQUIRE(status == 202);

    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.calls[0].exec_visible.has_value());
    CHECK(h.calls[0].exec_visible->count("agent-A") == 1);
    CHECK(h.calls[0].exec_visible->count("agent-B") == 0);
}

TEST_CASE("re-eval: a confined caller's VisibleSet reaches the re-dispatch",
          "[pg][result_set][async][reeval][security][1788]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool);

    int status = 0;
    auto created =
        h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 7","name":"o"})", status);
    REQUIRE(status == 202);
    const auto rs_id = created["data"]["id"].get<std::string>();
    h.calls.clear();

    // Confinement applies to the RE-EVAL as its own dispatch, not inherited
    // from whatever authority created the original set.
    h.exec_visible_override = std::unordered_set<std::string>{"agent-A"};
    h.post("/api/v1/result-sets/" + rs_id + "/re-eval", "", status);
    REQUIRE(status == 202);

    REQUIRE(h.calls.size() == 1);
    REQUIRE(h.calls[0].exec_visible.has_value());
    CHECK(h.calls[0].exec_visible->count("agent-A") == 1);
    CHECK(h.calls[0].exec_visible->count("agent-B") == 0);
}

TEST_CASE("async producers: an UNWIRED exec-visible derivation is an audited 500, never a dispatch",
          "[pg][result_set][async][security][1788][fail-closed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    // Genuinely unwired — NOT the harness's nullopt default. On these routes
    // the derivation is the ONLY per-device authorization, so a missing one is
    // a server misconfiguration: refuse loudly rather than substitute
    // present-empty and report the operator "no agents reached", which reads as
    // an empty fleet and hides the broken gate.
    AsyncHarness h(pool, /*with_dispatch=*/true, /*inv=*/nullptr, /*with_exec_visible=*/false);
    auto iid = make_instruction(*h.instr);

    int status = 0;
    auto j = h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1"})", status);
    CHECK(status == 500);
    CHECK(j.dump().find("RESULT_SET_GATE_UNCONFIGURED") != std::string::npos);
    CHECK(h.calls.empty()); // THE assertion: nothing was dispatched

    h.post("/api/v1/result-sets/from-instruction-result",
           R"({"instruction_id":")" + iid + R"("})", status);
    CHECK(status == 500);
    CHECK(h.calls.empty());

    // The refusal is durable evidence, not just a status code.
    const bool audited =
        std::any_of(h.audits.begin(), h.audits.end(), [](const AsyncHarness::AuditCall& a) {
            return a.action == "result_set.create" && a.result == "denied" &&
                   a.detail.find("exec_visible_unwired") != std::string::npos;
        });
    CHECK(audited);
}

TEST_CASE("async producers: a LOST evidence row on the unwired-gate refusal is surfaced, not "
          "swallowed",
          "[pg][result_set][async][security][1788][fail-closed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool, /*with_dispatch=*/true, /*inv=*/nullptr, /*with_exec_visible=*/false);
    // A refusal nobody can prove happened is not fail-closed: if the denial
    // audit cannot be persisted, the response must say so.
    h.audit_ok = false;

    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1"})", status);
    CHECK(status == 500);
    CHECK(h.last_sec_audit_failed == "true");
    CHECK(h.calls.empty()); // still no dispatch
}

TEST_CASE("async producers: an unfiltered (nullopt) VisibleSet still dispatches — non-regression",
          "[pg][result_set][async][security][1788]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    AsyncHarness h(pool); // exec_visible_override defaults to nullopt
    int status = 0;
    h.post("/api/v1/result-sets/from-tar-query", R"({"sql":"SELECT 1"})", status);
    REQUIRE(status == 202);
    REQUIRE(h.calls.size() == 1);
    // A genuine global administrator keeps full-fleet reach — that is their
    // actual authority, not a bypass. Distinct from the unwired case above:
    // wiring a callback that RETURNS nullopt is an answer; leaving the callback
    // empty is a missing gate.
    CHECK_FALSE(h.calls[0].exec_visible.has_value());
}
