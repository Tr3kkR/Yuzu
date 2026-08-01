/**
 * test_response_store.cpp — Unit tests for ResponseStore
 *
 * Covers: CRUD, query filters, TTL, count, multi-agent, ordering, facets,
 * #1634 aggregate scope, and the ADR-0039 retention reap (`reap_expired()`).
 * Migrated Postgres store (ADR-0006/0008/0039, schema `response_store`).
 * PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails when it is set
 * but broken.
 */

#include "response_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every test
// below constructs its own ResponseStore against a clone of this schema.
yuzu::test::PgTestTemplate responsestore_tpl{"responsestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResponseStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("responsestore template: store failed to migrate");
}};

// Run a raw SQL statement against the test database on a second connection —
// lets a test simulate TTL expiry / poison gc_meta directly.
void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

// Scalar SELECT on a second connection — column 0, row 0, as text; "" when
// the result set is genuinely empty.
std::string query_scalar(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
    if (PQntuples(r.get()) == 0)
        return "";
    return PQgetvalue(r.get(), 0, 0);
}

} // namespace

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("ResponseStore: open against a fresh template clone", "[pg][response_store][db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
}

TEST_CASE("ResponseStore: bad-path constructor (unroutable DSN) is closed",
          "[response_store]") {
    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ResponseStore store(bad_pool);
    REQUIRE_FALSE(store.is_open());
    // Reads degrade to nullopt; ingest/reap are silent no-ops.
    CHECK_FALSE(store.query("cmd-x").has_value());
    CHECK(store.total_count() == 0);
    store.store(StoredResponse{}); // must not throw/crash
    store.reap_expired();          // must not throw/crash
}

TEST_CASE("ResponseStore: store and retrieve", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());

    StoredResponse resp;
    resp.instruction_id = "cmd-abc123";
    resp.agent_id = "agent-1";
    resp.status = 1; // SUCCESS
    resp.output = "hostname|WORKSTATION-01";
    store.store(resp);

    auto results = store.get_by_instruction("cmd-abc123");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].instruction_id == "cmd-abc123");
    CHECK((*results)[0].agent_id == "agent-1");
    CHECK((*results)[0].status == 1);
    CHECK((*results)[0].output == "hostname|WORKSTATION-01");
}

TEST_CASE("ResponseStore: multiple responses same instruction", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    for (int i = 0; i < 5; ++i) {
        StoredResponse resp;
        resp.instruction_id = "cmd-multi";
        resp.agent_id = "agent-" + std::to_string(i);
        resp.status = 1;
        resp.output = "data-" + std::to_string(i);
        store.store(resp);
    }

    auto results = store.get_by_instruction("cmd-multi");
    REQUIRE(results.has_value());
    CHECK(results->size() == 5);
}

TEST_CASE("ResponseStore: query with agent_id filter", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    for (const auto& aid : {"agent-a", "agent-b", "agent-a"}) {
        StoredResponse resp;
        resp.instruction_id = "cmd-filter";
        resp.agent_id = aid;
        resp.status = 1;
        resp.output = "ok";
        store.store(resp);
    }

    ResponseQuery q;
    q.agent_id = "agent-a";
    auto results = store.query("cmd-filter", q);
    REQUIRE(results.has_value());
    CHECK(results->size() == 2);
}

TEST_CASE("ResponseStore: query with status filter", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    StoredResponse r1;
    r1.instruction_id = "cmd-status";
    r1.agent_id = "agent-1";
    r1.status = 1; // SUCCESS
    r1.output = "ok";
    store.store(r1);

    StoredResponse r2;
    r2.instruction_id = "cmd-status";
    r2.agent_id = "agent-1";
    r2.status = 2; // FAILURE
    r2.output = "fail";
    store.store(r2);

    ResponseQuery q;
    q.status = 2;
    auto results = store.query("cmd-status", q);
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].output == "fail");
}

TEST_CASE("ResponseStore: query with limit and offset", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    for (int i = 0; i < 10; ++i) {
        StoredResponse resp;
        resp.instruction_id = "cmd-page";
        resp.agent_id = "agent-1";
        resp.status = 1;
        resp.output = "row-" + std::to_string(i);
        store.store(resp);
    }

    ResponseQuery q;
    q.limit = 3;
    q.offset = 0;
    auto page1 = store.query("cmd-page", q);
    REQUIRE(page1.has_value());
    CHECK(page1->size() == 3);

    q.offset = 3;
    auto page2 = store.query("cmd-page", q);
    REQUIRE(page2.has_value());
    CHECK(page2->size() == 3);
}

TEST_CASE("ResponseStore: empty query returns an engaged-empty vector, not a degrade",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    auto results = store.get_by_instruction("nonexistent");
    REQUIRE(results.has_value());
    CHECK(results->empty());
}

TEST_CASE("ResponseStore: total_count", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.total_count() == 0);

    StoredResponse resp;
    resp.instruction_id = "cmd-count";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.output = "ok";
    store.store(resp);

    REQUIRE(store.total_count() == 1);
}

TEST_CASE("ResponseStore: error_detail stored", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    StoredResponse resp;
    resp.instruction_id = "cmd-err";
    resp.agent_id = "agent-1";
    resp.status = 2;
    resp.output = "";
    resp.error_detail = "plugin not found";
    store.store(resp);

    auto results = store.get_by_instruction("cmd-err");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].error_detail == "plugin not found");
}

TEST_CASE("ResponseStore: large output stored", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    StoredResponse resp;
    resp.instruction_id = "cmd-large";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.output = std::string(100000, 'X');
    store.store(resp);

    auto results = store.get_by_instruction("cmd-large");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].output.size() == 100000);
}

// ADR-0039 addendum: `output`/`error_detail` are untrusted agent-supplied
// bytes; Postgres TEXT requires valid server-encoding (unlike SQLite's
// permissive TEXT affinity), so store() sanitizes to U+FFFD before the
// insert (sanitize_utf8_strict, utf8_sanitize.hpp) — the row still LANDS
// (never a fail-soft drop from a self-inflicted encoding rejection),
// preserving the #1593 guarantee (test_rest_bundle.cpp's REST-level pin).
TEST_CASE("ResponseStore: invalid-UTF-8 output is sanitized to U+FFFD, not dropped",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    StoredResponse resp;
    resp.instruction_id = "cmd-badutf8";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.output = std::string(1, '\xff') + "binary";
    resp.error_detail = std::string(1, '\xfe') + "err";
    store.store(resp);

    auto results = store.get_by_instruction("cmd-badutf8");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1); // present, not silently dropped
    CHECK((*results)[0].output == "\xEF\xBF\xBD" "binary");
    CHECK((*results)[0].error_detail == "\xEF\xBF\xBD" "err");
}

// Facets are derived from `sanitized_output` (response_store.cpp:324), NOT the
// raw bytes — so an invalid-UTF-8 facet value must land as its U+FFFD-defanged
// form, never a raw byte the facet INSERT would reject (SQLSTATE 22021) and
// silently ROLLBACK-TO-SAVEPOINT away. The plain-output UTF-8 test above leaves
// `plugin` empty and so skips the whole facet block; this one exercises the
// post-sanitize-derivation invariant with a real schema.
TEST_CASE("ResponseStore: facets are derived post-sanitize (invalid-UTF-8 value defanged)",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    // vuln_scan schema: severity|category|title|detail. Put an invalid byte in
    // the category field (col_idx 1) — the facet value must come back defanged.
    StoredResponse resp;
    resp.instruction_id = "cmd-facet-badutf8";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.plugin = "vuln_scan";
    resp.output = std::string("high|") + '\xff' + "category|title|detail";
    store.store(resp);

    auto facets = store.facet_values("cmd-facet-badutf8", /*col_idx=*/1);
    REQUIRE(facets.has_value());
    REQUIRE(facets->size() == 1); // derived, not dropped
    CHECK((*facets)[0].value == "\xEF\xBF\xBD" "category");
    // No raw invalid byte survived into the persisted facet value.
    CHECK((*facets)[0].value.find('\xff') == std::string::npos);
}

// finalize_terminal_status binds the agent-supplied error message; like store()
// it must U+FFFD-defang it (Gate 2 security MEDIUM). An unsanitized non-UTF-8
// byte would fail the UPDATE (SQLSTATE 22021), leaving the RUNNING row never
// finalized and no fallback frame — the #1593 "real result must surface" gap
// reopened on the finalize path.
TEST_CASE("ResponseStore: finalize_terminal_status sanitizes error_detail (invalid UTF-8)",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    // A RUNNING row (status 0) awaiting its terminal frame.
    StoredResponse running;
    running.instruction_id = "cmd-finalize-badutf8";
    running.agent_id = "agent-1";
    running.execution_id = "exec-1";
    running.status = 0;
    running.output = "partial output";
    store.store(running);

    // Terminal frame carries a non-UTF-8 error message.
    const std::string bad_err = std::string(1, '\xff') + "boom";
    auto fr = store.finalize_terminal_status("cmd-finalize-badutf8", "agent-1", /*status=*/2,
                                             bad_err, "exec-1");
    CHECK(fr == ResponseStore::FinalizeResult::Updated); // row finalized, not lost to 22021

    auto results = store.get_by_instruction("cmd-finalize-badutf8");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].status == 2);
    CHECK((*results)[0].error_detail == "\xEF\xBF\xBD" "boom");
    CHECK((*results)[0].error_detail.find('\xff') == std::string::npos);
}

TEST_CASE("ResponseStore: timestamp ordering", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    for (int64_t ts : {100, 300, 200}) {
        StoredResponse resp;
        resp.instruction_id = "cmd-order";
        resp.agent_id = "agent-1";
        resp.timestamp = ts;
        resp.status = 1;
        resp.output = std::to_string(ts);
        store.store(resp);
    }

    auto results = store.get_by_instruction("cmd-order");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 3);
    // DESC ordering
    CHECK((*results)[0].timestamp >= (*results)[1].timestamp);
    CHECK((*results)[1].timestamp >= (*results)[2].timestamp);
}

TEST_CASE("ResponseStore: query with time range", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    for (int64_t ts : {100, 200, 300, 400, 500}) {
        StoredResponse resp;
        resp.instruction_id = "cmd-range";
        resp.agent_id = "agent-1";
        resp.timestamp = ts;
        resp.status = 1;
        resp.output = "t" + std::to_string(ts);
        store.store(resp);
    }

    ResponseQuery q;
    q.since = 200;
    q.until = 400;
    auto results = store.query("cmd-range", q);
    REQUIRE(results.has_value());
    CHECK(results->size() == 3);
}

TEST_CASE("ResponseStore: multiple instructions", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    for (const auto& id : {"cmd-1", "cmd-2", "cmd-3"}) {
        StoredResponse resp;
        resp.instruction_id = id;
        resp.agent_id = "agent-1";
        resp.status = 1;
        resp.output = "ok";
        store.store(resp);
    }

    CHECK(store.get_by_instruction("cmd-1")->size() == 1);
    CHECK(store.get_by_instruction("cmd-2")->size() == 1);
    CHECK(store.get_by_instruction("cmd-99")->size() == 0);
    CHECK(store.total_count() == 3);
}

TEST_CASE("ResponseStore: ttl_expires_at set from retention", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/30);

    StoredResponse resp;
    resp.instruction_id = "cmd-ttl";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.output = "ok";
    store.store(resp);

    auto results = store.get_by_instruction("cmd-ttl");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].ttl_expires_at > 0);
}

TEST_CASE("ResponseStore: custom ttl_expires_at preserved", "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);

    StoredResponse resp;
    resp.instruction_id = "cmd-custom-ttl";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.output = "ok";
    resp.ttl_expires_at = 999999;
    store.store(resp);

    auto results = store.get_by_instruction("cmd-custom-ttl");
    REQUIRE(results.has_value());
    REQUIRE(results->size() == 1);
    CHECK((*results)[0].ttl_expires_at == 999999);
}

// ============================================================================
// PR 2 — execution_id column + query_by_execution exact correlation.
// ============================================================================

TEST_CASE("ResponseStore PR2: execution_id default empty for legacy writers",
          "[pg][response_store][execution_id]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    StoredResponse r;
    r.instruction_id = "cmd-legacy-1";
    r.agent_id = "agent-1";
    r.status = 1;
    r.output = "ok";
    // Caller did NOT set execution_id — legacy / out-of-band path.
    store.store(r);

    auto rows = store.get_by_instruction("cmd-legacy-1");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].execution_id.empty());
}

TEST_CASE("ResponseStore PR2: execution_id round-trip when stamped at write",
          "[pg][response_store][execution_id]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    StoredResponse r;
    r.instruction_id = "cmd-pr2-1";
    r.agent_id = "agent-1";
    r.status = 1;
    r.output = "ok";
    r.execution_id = "exec-aaaa-bbbb-cccc-dddd-eeee";
    store.store(r);

    auto rows = store.get_by_instruction("cmd-pr2-1");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].execution_id == "exec-aaaa-bbbb-cccc-dddd-eeee");
}

TEST_CASE("ResponseStore PR2: query_by_execution returns only matching exec",
          "[pg][response_store][execution_id]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    // Two executions of the same definition (same command_id namespace).
    StoredResponse a;
    a.instruction_id = "cmd-shared";
    a.agent_id = "agent-1";
    a.status = 1;
    a.output = "from-exec-A";
    a.execution_id = "exec-A";
    store.store(a);

    StoredResponse b;
    b.instruction_id = "cmd-shared";
    b.agent_id = "agent-1";
    b.status = 1;
    b.output = "from-exec-B";
    b.execution_id = "exec-B";
    store.store(b);

    auto from_a = store.query_by_execution("exec-A");
    REQUIRE(from_a.has_value());
    REQUIRE(from_a->size() == 1);
    CHECK((*from_a)[0].output == "from-exec-A");

    auto from_b = store.query_by_execution("exec-B");
    REQUIRE(from_b.has_value());
    REQUIRE(from_b->size() == 1);
    CHECK((*from_b)[0].output == "from-exec-B");
}

TEST_CASE("ResponseStore PR2: query_by_execution rejects empty sentinel (engaged-empty, not "
          "a degrade)",
          "[pg][response_store][execution_id]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    StoredResponse r;
    r.instruction_id = "cmd-leg";
    r.agent_id = "agent-1";
    r.status = 1;
    r.output = "legacy";
    // execution_id stays empty.
    store.store(r);

    auto rows = store.query_by_execution("");
    REQUIRE(rows.has_value());
    CHECK(rows->empty());
}

TEST_CASE("ResponseStore PR2: query_by_execution honours agent_id + since/until + status "
          "filters",
          "[pg][response_store][execution_id]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    auto seed = [&](const std::string& exec, const std::string& agent, int64_t ts, int status,
                    const std::string& out) {
        StoredResponse r;
        r.instruction_id = "cmd-x";
        r.agent_id = agent;
        r.status = status;
        r.output = out;
        r.timestamp = ts;
        r.execution_id = exec;
        store.store(r);
    };
    seed("exec-1", "agent-A", 100, 1, "A-100");
    seed("exec-1", "agent-A", 200, 1, "A-200");
    seed("exec-1", "agent-B", 150, 2, "B-150-fail");
    seed("exec-2", "agent-A", 175, 1, "exec2-A-175");

    SECTION("agent_id filter") {
        ResponseQuery q;
        q.agent_id = "agent-B";
        auto rows = store.query_by_execution("exec-1", q);
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() == 1);
        CHECK((*rows)[0].output == "B-150-fail");
    }
    SECTION("since/until window") {
        ResponseQuery q;
        q.since = 110;
        q.until = 180;
        auto rows = store.query_by_execution("exec-1", q);
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() == 1);
        CHECK((*rows)[0].output == "B-150-fail");
    }
    SECTION("status filter") {
        ResponseQuery q;
        q.status = 2;
        auto rows = store.query_by_execution("exec-1", q);
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() == 1);
        CHECK((*rows)[0].status == 2);
    }
    SECTION("scope of exec-2 doesn't bleed into exec-1") {
        auto rows = store.query_by_execution("exec-1");
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() == 3);
        for (const auto& r : *rows)
            CHECK(r.output != "exec2-A-175");
    }
}

// ── #1634 management-group scope on aggregate (filter-BEFORE-aggregate) ───────

namespace {
StoredResponse mk_agg_resp(const std::string& instr, const std::string& agent, int status) {
    StoredResponse r;
    r.instruction_id = instr;
    r.agent_id = agent;
    r.status = status;
    r.output = "out";
    return r;
}
} // namespace

TEST_CASE("ResponseStore: distinct_agent_ids returns sorted distinct agents",
          "[pg][response_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    store.store(mk_agg_resp("instr-1", "agent-c", 0));
    store.store(mk_agg_resp("instr-1", "agent-a", 0));
    store.store(mk_agg_resp("instr-1", "agent-a", 1)); // duplicate agent
    store.store(mk_agg_resp("instr-1", "agent-b", 0));
    store.store(mk_agg_resp("instr-2", "agent-z", 0)); // other instruction

    auto ids = store.distinct_agent_ids("instr-1");
    REQUIRE(ids.has_value());
    REQUIRE(ids->size() == 3);
    CHECK((*ids)[0] == "agent-a");
    CHECK((*ids)[1] == "agent-b");
    CHECK((*ids)[2] == "agent-c");
    // Genuinely-empty (instruction has no rows) is an ENGAGED empty vector, NOT
    // nullopt — nullopt is reserved for a store-read error so the caller can fail
    // closed on error without conflating it with "no agents" (#1634 UP-2).
    auto none = store.distinct_agent_ids("nope");
    REQUIRE(none.has_value());
    CHECK(none->empty());
}

TEST_CASE("ResponseStore: aggregate scope excludes out-of-scope rows from totals (#1634)",
          "[pg][response_store][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    // Two agents reported SUCCESS (status 0), one reported FAILURE (status 1).
    store.store(mk_agg_resp("instr-1", "agent-1", 0)); // in scope
    store.store(mk_agg_resp("instr-1", "agent-2", 0)); // OUT of scope
    store.store(mk_agg_resp("instr-1", "agent-3", 1)); // OUT of scope

    AggregationQuery aq;
    aq.group_by = "status";
    aq.op = AggregateOp::Count;

    auto count_for = [](const std::vector<AggregationResult>& rs, const std::string& status) {
        for (const auto& r : rs)
            if (r.group_value == status)
                return r.count;
        return std::int64_t{0};
    };

    SECTION("nullopt scope = legacy-open: all rows counted") {
        auto rs = store.aggregate("instr-1", aq, {}, std::nullopt);
        REQUIRE(rs.has_value());
        CHECK(count_for(*rs, "0") == 2);
        CHECK(count_for(*rs, "1") == 1);
    }

    SECTION("subset scope: only in-scope agents fold into the totals") {
        auto rs = store.aggregate("instr-1", aq, {}, AggregateScope{{"agent-1"}});
        REQUIRE(rs.has_value());
        // agent-1 is the only in-scope agent → status 0 count is 1, not 2.
        CHECK(count_for(*rs, "0") == 1);
        // agent-3's FAILURE belongs to an out-of-scope agent → excluded entirely.
        CHECK(count_for(*rs, "1") == 0);
    }

    SECTION("empty scope set = visible to no one: zero rows, never silently unfiltered") {
        auto rs = store.aggregate("instr-1", aq, {}, AggregateScope{std::vector<std::string>{}});
        REQUIRE(rs.has_value());
        CHECK(rs->empty());
    }
}

TEST_CASE("ResponseStore: aggregate scope applies to SUM, not just COUNT (#1634)",
          "[pg][response_store][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    store.store(mk_agg_resp("instr-1", "agent-1", 2)); // in scope, status=2
    store.store(mk_agg_resp("instr-1", "agent-2", 3)); // OUT of scope, status=3

    AggregationQuery aq;
    aq.group_by = "agent_id";
    aq.op = AggregateOp::Sum;
    aq.op_column = "status";

    auto rs = store.aggregate("instr-1", aq, {}, AggregateScope{{"agent-1"}});
    REQUIRE(rs.has_value());
    REQUIRE(rs->size() == 1);
    CHECK((*rs)[0].group_value == "agent-1");
    CHECK((*rs)[0].aggregate_value == 2.0);
}

TEST_CASE("ResponseStore: aggregate scope AND filter.agent_id compose — out-of-scope explicit "
          "agent yields zero (#1634)",
          "[pg][response_store][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    store.store(mk_agg_resp("instr-1", "agent-1", 0)); // in scope
    store.store(mk_agg_resp("instr-1", "agent-2", 0)); // OUT of scope

    AggregationQuery aq;
    aq.group_by = "status";
    aq.op = AggregateOp::Count;

    ResponseQuery filter;
    filter.agent_id = "agent-2";
    auto rs = store.aggregate("instr-1", aq, filter, AggregateScope{{"agent-1"}});
    REQUIRE(rs.has_value());
    CHECK(rs->empty());

    ResponseQuery filter_ok;
    filter_ok.agent_id = "agent-1";
    auto rs_ok = store.aggregate("instr-1", aq, filter_ok, AggregateScope{{"agent-1"}});
    REQUIRE(rs_ok.has_value());
    int64_t total = 0;
    for (const auto& r : *rs_ok)
        total += r.count;
    CHECK(total == 1);
}

TEST_CASE("ResponseStore: distinct_agent_ids / aggregate return nullopt on a closed store "
          "(#1634 UP-2)",
          "[response_store][scope]") {
    // Unroutable DSN → is_open() false. distinct_agent_ids MUST return nullopt
    // (store-read error), NOT an engaged-empty vector — so the aggregate caller
    // fails CLOSED instead of reading "couldn't read" as "no agents to drop" →
    // unrestricted (the UP-2 fail-open this contract closes).
    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ResponseStore store(bad_pool);
    REQUIRE_FALSE(store.is_open());
    auto ids = store.distinct_agent_ids("instr-1");
    CHECK_FALSE(ids.has_value());
    AggregationQuery aq;
    aq.group_by = "status";
    aq.op = AggregateOp::Count;
    CHECK_FALSE(store.aggregate("instr-1", aq).has_value());
}

// ── Facets ─────────────────────────────────────────────────────────────────

TEST_CASE("ResponseStore: facet cascade — deleting the parent response removes its facets",
          "[pg][response_store][facets]") {
    // response_facets.response_id REFERENCES responses(id) ON DELETE CASCADE
    // (ADR-0039: replaces the SQLite cleanup thread's manual orphan sweep) —
    // pinned here directly against the schema, independent of store()'s
    // ability to populate facets from a real plugin schema.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());

    StoredResponse r;
    r.instruction_id = "cmd-facet";
    r.agent_id = "agent-1";
    r.status = 1;
    r.output = "ok";
    store.store(r);
    auto rows = store.get_by_instruction("cmd-facet");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    const int64_t response_id = (*rows)[0].id;

    exec_sql(db.dsn(), "INSERT INTO response_store.response_facets (response_id, "
                       "instruction_id, agent_id, col_idx, value, line_count) VALUES (" +
                           std::to_string(response_id) + ", 'cmd-facet', 'agent-1', 0, 'v', 1)");
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.response_facets WHERE "
                                 "response_id = " +
                                     std::to_string(response_id)) == "1");

    exec_sql(db.dsn(),
            "DELETE FROM response_store.responses WHERE id = " + std::to_string(response_id));
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.response_facets WHERE "
                                 "response_id = " +
                                     std::to_string(response_id)) == "0");
}

// ── Retention reap (`reap_expired()`, #2496 gc_sweep shape, ADR-0039) ────────

TEST_CASE("ResponseStore: retention_days=0 disables TTL", "[pg][response_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/0);
    for (int i = 0; i < 5; ++i)
        store.store(mk_agg_resp("cmd-noreap", "agent-" + std::to_string(i), 1));
    store.reap_expired();
    CHECK(store.total_count() == 5);
    CHECK(store.responses_reaped_total() == 0);
}

TEST_CASE("ResponseStore: reap_expired deletes rows past ttl_expires_at, keeps fresh ones",
          "[pg][response_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/30);

    for (int i = 0; i < 3; ++i)
        store.store(mk_agg_resp("fresh-" + std::to_string(i), "agent-a", 1));
    for (int i = 0; i < 3; ++i)
        store.store(mk_agg_resp("stale-" + std::to_string(i), "agent-a", 1));
    CHECK(store.total_count() == 6);

    exec_sql(db.dsn(), "UPDATE response_store.responses SET ttl_expires_at = 1 WHERE "
                       "instruction_id LIKE 'stale-%'");

    // expiring(3) < datable(6): not would_wipe — a clean pass drains immediately.
    store.reap_expired();
    CHECK(store.responses_reaped_total() == 3);
    CHECK(store.total_count() == 3);
    for (int i = 0; i < 3; ++i) {
        auto out = store.get_by_instruction("fresh-" + std::to_string(i));
        REQUIRE(out.has_value());
        CHECK(out->size() == 1);
    }
    for (int i = 0; i < 3; ++i) {
        auto out = store.get_by_instruction("stale-" + std::to_string(i));
        REQUIRE(out.has_value());
        CHECK(out->empty());
    }
}

// reap_expired would_wipe decline-once (mirrors GuaranteedStateStore/ResultSetStore's
// gc_sweep test of the same name): when EVERY datable row is expired, part 1's
// would_wipe classifier trips — the pass reports the anomaly, records it in
// gc_meta, and declines to delete anything. An identical next pass (same fact
// set) is a suppressed repeat: the report is skipped, but the (capped) drain
// proceeds.
TEST_CASE("ResponseStore: reap_expired declines once on an all-expired (would_wipe) table, "
          "then drains",
          "[pg][response_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());

    for (int i = 0; i < 3; ++i)
        store.store(mk_agg_resp("wipe-" + std::to_string(i), "agent-a", 1));

    exec_sql(db.dsn(), "UPDATE response_store.responses SET ttl_expires_at = 1");

    auto gc_meta_anomaly_count = [&]() -> std::string {
        return query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.gc_meta WHERE key = "
                                      "'last_anomaly_facts'");
    };

    // First pass: declines (would_wipe) — nothing reaped, the anomaly recorded.
    store.reap_expired();
    CHECK(store.responses_reaped_total() == 0);
    CHECK(store.total_count() == 3); // still present — the decline held
    CHECK(gc_meta_anomaly_count() == "1");

    // Second pass: suppressed repeat (same fact set) — drains, capped.
    store.reap_expired();
    CHECK(store.responses_reaped_total() == 3);
    CHECK(store.total_count() == 0);
    CHECK(gc_meta_anomaly_count() == "1"); // not cleared by a suppressed-repeat drain

    store.store(mk_agg_resp("fresh", "agent-a", 1));
    store.reap_expired(); // clean pass: nothing expired
    CHECK(store.responses_reaped_total() == 3); // unchanged — nothing new reaped
    CHECK(gc_meta_anomaly_count() == "0");      // consumed/cleared
}

TEST_CASE("ResponseStore: reap_expired is a no-op on a closed store",
          "[response_store][retention]") {
    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ResponseStore bad(bad_pool);
    REQUIRE_FALSE(bad.is_open());
    bad.reap_expired();
    SUCCEED();
}

// gc_sweep cap: bulk-insert kReapCapPerPass(10000)+1 expired, DISTINCT-ttl
// responses directly via SQL — looping store() 10001 times would make this
// test the slow part of the whole suite. A `cap-live` (unexpired) row seeded
// alongside keeps datable strictly greater than expiring so part 1's
// would_wipe classifier does NOT trip.
TEST_CASE("ResponseStore: reap_expired caps a large expired batch at kReapCapPerPass",
          "[pg][response_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());

    exec_sql(db.dsn(),
            "INSERT INTO response_store.responses (instruction_id, agent_id, timestamp, "
            "status, output, ttl_expires_at) SELECT 'cap-cmd-' || g, 'agent-a', 1700000000, 1, "
            "'', g FROM generate_series(1, 10001) AS g");
    store.store(mk_agg_resp("cap-live", "agent-a", 1)); // 30d-ahead ttl, avoids would_wipe

    store.reap_expired();
    CHECK(store.responses_reaped_total() == 10000); // capped exactly at kReapCapPerPass

    store.reap_expired();
    CHECK(store.responses_reaped_total() == 10001); // second pass drains the remainder

    CHECK(store.total_count() == 1); // only "cap-live" survives
}

// gc_sweep advisory-lock skip: a sibling replica already sweeping holds the
// fleet-wide try-advisory-xact-lock, so this pass must skip quietly and never
// even reach the gc_meta read/stamp, never mind the delete.
TEST_CASE("ResponseStore: reap_expired skips quietly when a sibling holds the advisory lock",
          "[pg][response_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());

    store.store(mk_agg_resp("locked-cmd", "agent-a", 1));
    exec_sql(db.dsn(), "UPDATE response_store.responses SET ttl_expires_at = 1 WHERE "
                       "instruction_id = 'locked-cmd'");
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.gc_meta WHERE key = "
                                 "'last_pass_now'") == "0");

    PgConn locker{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(locker.get()) == CONNECTION_OK);
    {
        PgResult begin{PQexec(locker.get(), "BEGIN")};
        REQUIRE(begin.status() == PGRES_COMMAND_OK);
        PgResult lock{PQexec(
            locker.get(), "SELECT pg_advisory_xact_lock(hashtextextended('response_store:reap', "
                          "0))")};
        REQUIRE(lock.status() == PGRES_TUPLES_OK);
    }

    store.reap_expired();
    CHECK(store.responses_reaped_total() == 0);
    CHECK(store.total_count() == 1); // nothing deleted — the sibling held the lock
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.gc_meta WHERE key = "
                                 "'last_pass_now'") == "0"); // never reached the stamp

    PgResult rollback{PQexec(locker.get(), "ROLLBACK")};
    REQUIRE(rollback.status() == PGRES_COMMAND_OK);
}

// gc_sweep clock anomaly / prev_unusable: reap_expired() stamps a FRESH,
// honest last_pass_now on EVERY pass (including a declining one) BEFORE it
// evaluates the anomaly — so a poisoned reading self-heals on the very next
// pass.
TEST_CASE("ResponseStore: reap_expired declines once on a clock reading ahead of now",
          "[pg][response_store][retention]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool, /*retention_days=*/30);
    REQUIRE(store.is_open());

    store.store(mk_agg_resp("clock-a", "agent-a", 1));
    store.store(mk_agg_resp("clock-b", "agent-a", 1));
    store.store(mk_agg_resp("clock-live", "agent-a", 1)); // avoids would_wipe
    exec_sql(db.dsn(), "UPDATE response_store.responses SET ttl_expires_at = 1 WHERE "
                       "instruction_id IN ('clock-a', 'clock-b')");
    exec_sql(db.dsn(),
            "INSERT INTO response_store.gc_meta (key, value) VALUES ('last_pass_now', "
            "(EXTRACT(EPOCH FROM clock_timestamp())::bigint + 999999)::text) ON CONFLICT (key) "
            "DO UPDATE SET value = EXCLUDED.value");

    store.reap_expired();
    CHECK(store.responses_reaped_total() == 0); // declined: prev_unusable (BadState)
    CHECK(store.total_count() == 3);
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.gc_meta WHERE key = "
                                 "'last_anomaly_facts'") == "1");

    // Self-healed: the stamp reap_expired() just wrote is an honest reading.
    store.reap_expired();
    CHECK(store.responses_reaped_total() == 2);
    CHECK(store.total_count() == 1);
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM response_store.gc_meta WHERE key = "
                                 "'last_anomaly_facts'") == "0"); // consumed/cleared
}
