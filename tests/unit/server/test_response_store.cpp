/**
 * test_response_store.cpp — Unit tests for ResponseStore
 *
 * Covers: CRUD, query filters, TTL, count, multi-agent, ordering.
 */

#include "response_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"

#include <filesystem>
#include <string>
#include <thread>

using namespace yuzu::server;

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("ResponseStore: open in-memory", "[response_store][db]") {
    ResponseStore store(":memory:");
    REQUIRE(store.is_open());
}

TEST_CASE("ResponseStore: store and retrieve", "[response_store]") {
    ResponseStore store(":memory:");
    REQUIRE(store.is_open());

    StoredResponse resp;
    resp.instruction_id = "cmd-abc123";
    resp.agent_id = "agent-1";
    resp.status = 1; // SUCCESS
    resp.output = "hostname|WORKSTATION-01";
    store.store(resp);

    auto results = store.get_by_instruction("cmd-abc123");
    REQUIRE(results.size() == 1);
    CHECK(results[0].instruction_id == "cmd-abc123");
    CHECK(results[0].agent_id == "agent-1");
    CHECK(results[0].status == 1);
    CHECK(results[0].output == "hostname|WORKSTATION-01");
}

TEST_CASE("ResponseStore: multiple responses same instruction", "[response_store]") {
    ResponseStore store(":memory:");

    for (int i = 0; i < 5; ++i) {
        StoredResponse resp;
        resp.instruction_id = "cmd-multi";
        resp.agent_id = "agent-" + std::to_string(i);
        resp.status = 1;
        resp.output = "data-" + std::to_string(i);
        store.store(resp);
    }

    auto results = store.get_by_instruction("cmd-multi");
    REQUIRE(results.size() == 5);
}

TEST_CASE("ResponseStore: query with agent_id filter", "[response_store]") {
    ResponseStore store(":memory:");

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
    REQUIRE(results.size() == 2);
}

TEST_CASE("ResponseStore: query with status filter", "[response_store]") {
    ResponseStore store(":memory:");

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
    REQUIRE(results.size() == 1);
    CHECK(results[0].output == "fail");
}

TEST_CASE("ResponseStore: query with limit and offset", "[response_store]") {
    ResponseStore store(":memory:");

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
    REQUIRE(page1.size() == 3);

    q.offset = 3;
    auto page2 = store.query("cmd-page", q);
    REQUIRE(page2.size() == 3);
}

TEST_CASE("ResponseStore: empty query returns empty", "[response_store]") {
    ResponseStore store(":memory:");
    auto results = store.get_by_instruction("nonexistent");
    REQUIRE(results.empty());
}

TEST_CASE("ResponseStore: total_count", "[response_store]") {
    ResponseStore store(":memory:");
    REQUIRE(store.total_count() == 0);

    StoredResponse resp;
    resp.instruction_id = "cmd-count";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.output = "ok";
    store.store(resp);

    REQUIRE(store.total_count() == 1);
}

TEST_CASE("ResponseStore: error_detail stored", "[response_store]") {
    ResponseStore store(":memory:");

    StoredResponse resp;
    resp.instruction_id = "cmd-err";
    resp.agent_id = "agent-1";
    resp.status = 2;
    resp.output = "";
    resp.error_detail = "plugin not found";
    store.store(resp);

    auto results = store.get_by_instruction("cmd-err");
    REQUIRE(results.size() == 1);
    CHECK(results[0].error_detail == "plugin not found");
}

TEST_CASE("ResponseStore: large output stored", "[response_store]") {
    ResponseStore store(":memory:");

    StoredResponse resp;
    resp.instruction_id = "cmd-large";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.output = std::string(100000, 'X');
    store.store(resp);

    auto results = store.get_by_instruction("cmd-large");
    REQUIRE(results.size() == 1);
    CHECK(results[0].output.size() == 100000);
}

TEST_CASE("ResponseStore: timestamp ordering", "[response_store]") {
    ResponseStore store(":memory:");

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
    REQUIRE(results.size() == 3);
    // DESC ordering
    CHECK(results[0].timestamp >= results[1].timestamp);
    CHECK(results[1].timestamp >= results[2].timestamp);
}

TEST_CASE("ResponseStore: query with time range", "[response_store]") {
    ResponseStore store(":memory:");

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
    REQUIRE(results.size() == 3);
}

TEST_CASE("ResponseStore: db_size_bytes for in-memory", "[response_store]") {
    ResponseStore store(":memory:");
    CHECK(store.db_size_bytes() == 0);
}

TEST_CASE("ResponseStore: multiple instructions", "[response_store]") {
    ResponseStore store(":memory:");

    for (const auto& id : {"cmd-1", "cmd-2", "cmd-3"}) {
        StoredResponse resp;
        resp.instruction_id = id;
        resp.agent_id = "agent-1";
        resp.status = 1;
        resp.output = "ok";
        store.store(resp);
    }

    CHECK(store.get_by_instruction("cmd-1").size() == 1);
    CHECK(store.get_by_instruction("cmd-2").size() == 1);
    CHECK(store.get_by_instruction("cmd-99").size() == 0);
    CHECK(store.total_count() == 3);
}

TEST_CASE("ResponseStore: ttl_expires_at set from retention", "[response_store]") {
    ResponseStore store(":memory:", 30); // 30 days retention

    StoredResponse resp;
    resp.instruction_id = "cmd-ttl";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.output = "ok";
    store.store(resp);

    auto results = store.get_by_instruction("cmd-ttl");
    REQUIRE(results.size() == 1);
    CHECK(results[0].ttl_expires_at > 0);
}

TEST_CASE("ResponseStore: custom ttl_expires_at preserved", "[response_store]") {
    ResponseStore store(":memory:");

    StoredResponse resp;
    resp.instruction_id = "cmd-custom-ttl";
    resp.agent_id = "agent-1";
    resp.status = 1;
    resp.output = "ok";
    resp.ttl_expires_at = 999999;
    store.store(resp);

    auto results = store.get_by_instruction("cmd-custom-ttl");
    REQUIRE(results.size() == 1);
    CHECK(results[0].ttl_expires_at == 999999);
}


// ============================================================================
// PR 2 — execution_id column + query_by_execution exact correlation.
// The new column has empty default (legacy sentinel); StoredResponse stamps
// it at write time when the dispatch path registered a mapping. The detail
// handler in workflow_routes prefers query_by_execution and falls back to
// the timestamp-window join for pre-PR-2 (empty-execution_id) rows.
// ============================================================================

TEST_CASE("ResponseStore PR2: execution_id default empty for legacy writers",
          "[response_store][execution_id]") {
    ResponseStore store(":memory:");
    StoredResponse r;
    r.instruction_id = "cmd-legacy-1";
    r.agent_id = "agent-1";
    r.status = 1;
    r.output = "ok";
    // Caller did NOT set execution_id — legacy / out-of-band path.
    store.store(r);

    auto rows = store.get_by_instruction("cmd-legacy-1");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].execution_id.empty());
}

TEST_CASE("ResponseStore PR2: execution_id round-trip when stamped at write",
          "[response_store][execution_id]") {
    ResponseStore store(":memory:");
    StoredResponse r;
    r.instruction_id = "cmd-pr2-1";
    r.agent_id = "agent-1";
    r.status = 1;
    r.output = "ok";
    r.execution_id = "exec-aaaa-bbbb-cccc-dddd-eeee";
    store.store(r);

    auto rows = store.get_by_instruction("cmd-pr2-1");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].execution_id == "exec-aaaa-bbbb-cccc-dddd-eeee");
}

TEST_CASE("ResponseStore PR2: query_by_execution returns only matching exec",
          "[response_store][execution_id]") {
    ResponseStore store(":memory:");
    // Two executions of the same definition (same command_id namespace).
    // Pre-PR-2 the timestamp-window join would conflate them; query_by_execution
    // must NOT.
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
    REQUIRE(from_a.size() == 1);
    CHECK(from_a[0].output == "from-exec-A");

    auto from_b = store.query_by_execution("exec-B");
    REQUIRE(from_b.size() == 1);
    CHECK(from_b[0].output == "from-exec-B");
}

TEST_CASE("ResponseStore PR2: query_by_execution rejects empty sentinel",
          "[response_store][execution_id]") {
    ResponseStore store(":memory:");
    StoredResponse r;
    r.instruction_id = "cmd-leg";
    r.agent_id = "agent-1";
    r.status = 1;
    r.output = "legacy";
    // execution_id stays empty.
    store.store(r);

    // Empty execution_id is the legacy sentinel — query_by_execution must
    // refuse it (returns no rows) so callers can detect "no PR-2 data" and
    // fall back to query() with the timestamp-window join.
    auto rows = store.query_by_execution("");
    CHECK(rows.empty());
}

TEST_CASE("ResponseStore PR2: query_by_execution honours agent_id + since/until "
          "+ status filters",
          "[response_store][execution_id]") {
    ResponseStore store(":memory:");
    auto seed = [&](const std::string& exec, const std::string& agent,
                    int64_t ts, int status, const std::string& out) {
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
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].output == "B-150-fail");
    }
    SECTION("since/until window") {
        ResponseQuery q;
        q.since = 110;
        q.until = 180;
        auto rows = store.query_by_execution("exec-1", q);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].output == "B-150-fail");
    }
    SECTION("status filter") {
        ResponseQuery q;
        q.status = 2;
        auto rows = store.query_by_execution("exec-1", q);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].status == 2);
    }
    SECTION("scope of exec-2 doesn't bleed into exec-1") {
        auto rows = store.query_by_execution("exec-1");
        REQUIRE(rows.size() == 3);
        for (const auto& r : rows) CHECK(r.output != "exec2-A-175");
    }
}

TEST_CASE("ResponseStore PR2: migration v2 idempotency — re-open the same DB",
          "[response_store][execution_id][migration]") {
    auto path = yuzu::test::unique_temp_path("resp-store-mig-");
    {
        ResponseStore store(path, /*retention_days=*/0,
                             /*cleanup_interval_min=*/60);
        REQUIRE(store.is_open());
        StoredResponse r;
        r.instruction_id = "cmd-pre";
        r.agent_id = "agent-1";
        r.status = 1;
        r.output = "first";
        r.execution_id = "exec-AAAA";
        store.store(r);
    }
    // Re-open: the migration must not re-run the ALTER (would fail on
    // duplicate column without the pre-stamp probe). Existing rows must
    // round-trip with execution_id intact.
    {
        ResponseStore store(path, /*retention_days=*/0,
                             /*cleanup_interval_min=*/60);
        REQUIRE(store.is_open());
        auto rows = store.query_by_execution("exec-AAAA");
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].output == "first");
    }
    std::filesystem::remove(path);
    std::filesystem::remove(path.string() + "-wal");
    std::filesystem::remove(path.string() + "-shm");
}
