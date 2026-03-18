/**
 * test_execution_tracker.cpp — Unit tests for ExecutionTracker
 *
 * Covers: create, get, agent status transitions, summary, completion,
 *         cancellation, parent-child hierarchy, rerun, query filters.
 */

#include "execution_tracker.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <string>
#include <vector>

using namespace yuzu::server;

// ── RAII wrapper for sqlite3* ──────────────────────────────────────────────

struct TestDb {
    sqlite3* db = nullptr;
    TestDb() { sqlite3_open(":memory:", &db); }
    ~TestDb() { if (db) sqlite3_close(db); }
};

// ── Helpers ─────────────────────────────────────────────────────────────────

static ExecutionRecord make_execution(
    const std::string& definition_id = "def-001",
    const std::string& scope = "ostype = 'windows'",
    const std::string& dispatched_by = "admin")
{
    ExecutionRecord rec;
    rec.definition_id = definition_id;
    rec.scope_expression = scope;
    rec.dispatched_by = dispatched_by;
    rec.status = "running";
    return rec;
}

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: create_tables succeeds", "[execution_tracker][db]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();  // should not crash
    REQUIRE(true);
}

// ── Create Execution ───────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: create execution", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto result = tracker.create_execution(make_execution());
    REQUIRE(result.has_value());
    CHECK(!result->empty());
}

// ── Get Execution ──────────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: get execution", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto result = tracker.create_execution(make_execution("def-hostname", "ostype = 'windows'", "operator1"));
    REQUIRE(result.has_value());

    auto exec = tracker.get_execution(*result);
    REQUIRE(exec.has_value());
    CHECK(exec->definition_id == "def-hostname");
    CHECK(exec->scope_expression == "ostype = 'windows'");
    CHECK(exec->dispatched_by == "operator1");
    CHECK(exec->status == "running");
}

TEST_CASE("ExecutionTracker: get nonexistent returns empty", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto result = tracker.get_execution("nonexistent-id");
    CHECK(!result.has_value());
}

// ── Register Agents ────────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: register agents", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    tracker.register_agents(*id_result, {"agent-1", "agent-2", "agent-3"});

    auto summary = tracker.get_summary(*id_result);
    CHECK(summary.agents_targeted == 3);
    CHECK(summary.agents_responded == 0);
}

// ── Agent Status Transitions ───────────────────────────────────────────────

TEST_CASE("ExecutionTracker: agent status dispatched -> running -> success", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());
    tracker.register_agents(*id_result, {"agent-1"});

    // running (first response)
    tracker.update_agent_status(*id_result, "agent-1", "running");

    // success (terminal)
    tracker.update_agent_status(*id_result, "agent-1", "success");

    auto summary = tracker.get_summary(*id_result);
    CHECK(summary.agents_success == 1);
    CHECK(summary.agents_failure == 0);
    CHECK(summary.agents_responded == 1);
}

TEST_CASE("ExecutionTracker: agent status failure", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());
    tracker.register_agents(*id_result, {"agent-1"});

    tracker.update_agent_status(*id_result, "agent-1", "running");
    tracker.update_agent_status(*id_result, "agent-1", "failure", 1, "plugin timeout");

    auto summary = tracker.get_summary(*id_result);
    CHECK(summary.agents_failure == 1);
    CHECK(summary.agents_success == 0);
}

// ── Summary Calculation ────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: summary with mixed statuses", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());
    tracker.register_agents(*id_result, {"a1", "a2", "a3", "a4"});

    tracker.update_agent_status(*id_result, "a1", "success");
    tracker.update_agent_status(*id_result, "a2", "success");
    tracker.update_agent_status(*id_result, "a3", "failure", 1, "error");
    // a4 remains dispatched

    auto summary = tracker.get_summary(*id_result);
    CHECK(summary.agents_targeted == 4);
    CHECK(summary.agents_responded == 3);
    CHECK(summary.agents_success == 2);
    CHECK(summary.agents_failure == 1);
    CHECK(summary.progress_pct >= 74.0);
    CHECK(summary.progress_pct <= 76.0);
}

TEST_CASE("ExecutionTracker: summary progress 100%", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());
    tracker.register_agents(*id_result, {"a1", "a2"});
    tracker.update_agent_status(*id_result, "a1", "success");
    tracker.update_agent_status(*id_result, "a2", "success");

    auto summary = tracker.get_summary(*id_result);
    CHECK(summary.progress_pct == 100.0);
}

// ── Mark Completed / Cancelled ─────────────────────────────────────────────

TEST_CASE("ExecutionTracker: mark completed", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    tracker.mark_completed(*id_result);

    auto exec = tracker.get_execution(*id_result);
    REQUIRE(exec.has_value());
    CHECK(exec->status == "completed");
    CHECK(exec->completed_at > 0);
}

TEST_CASE("ExecutionTracker: mark cancelled", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    tracker.mark_cancelled(*id_result, "admin");

    auto exec = tracker.get_execution(*id_result);
    REQUIRE(exec.has_value());
    CHECK(exec->status == "cancelled");
    CHECK(exec->cancelled_by == "admin");
}

// ── Parent-Child Hierarchy ─────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: parent-child relationship", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto parent_result = tracker.create_execution(make_execution());
    REQUIRE(parent_result.has_value());

    ExecutionRecord child = make_execution();
    child.parent_id = *parent_result;
    auto child_result = tracker.create_execution(child);
    REQUIRE(child_result.has_value());

    auto children = tracker.get_children(*parent_result);
    REQUIRE(children.size() == 1);
    CHECK(children[0].parent_id == *parent_result);
}

TEST_CASE("ExecutionTracker: multiple children", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto parent_result = tracker.create_execution(make_execution());
    REQUIRE(parent_result.has_value());

    for (int i = 0; i < 3; ++i) {
        ExecutionRecord child = make_execution();
        child.parent_id = *parent_result;
        tracker.create_execution(child);
    }

    auto children = tracker.get_children(*parent_result);
    REQUIRE(children.size() == 3);
}

// ── Rerun ──────────────────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: rerun all agents", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());
    tracker.register_agents(*id_result, {"a1", "a2"});
    tracker.update_agent_status(*id_result, "a1", "success");
    tracker.update_agent_status(*id_result, "a2", "failure", 1);
    tracker.mark_completed(*id_result);

    auto rerun_result = tracker.create_rerun(*id_result, "admin", false);
    REQUIRE(rerun_result.has_value());

    auto rerun = tracker.get_execution(*rerun_result);
    REQUIRE(rerun.has_value());
    CHECK(rerun->rerun_of == *id_result);
}

TEST_CASE("ExecutionTracker: rerun failed_only", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());
    tracker.register_agents(*id_result, {"a1", "a2", "a3"});
    tracker.update_agent_status(*id_result, "a1", "success");
    tracker.update_agent_status(*id_result, "a2", "failure", 1);
    tracker.update_agent_status(*id_result, "a3", "timeout");
    tracker.mark_completed(*id_result);

    auto rerun_result = tracker.create_rerun(*id_result, "admin", true);
    REQUIRE(rerun_result.has_value());

    auto rerun = tracker.get_execution(*rerun_result);
    REQUIRE(rerun.has_value());
    CHECK(rerun->agents_targeted == 2);  // only the two failed/timeout agents
}

// ── Query with Filters ─────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: query all executions", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    tracker.create_execution(make_execution("def-1"));
    tracker.create_execution(make_execution("def-2"));
    tracker.create_execution(make_execution("def-3"));

    auto results = tracker.query_executions();
    REQUIRE(results.size() == 3);
}

TEST_CASE("ExecutionTracker: query by definition_id", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    tracker.create_execution(make_execution("def-alpha"));
    tracker.create_execution(make_execution("def-beta"));
    tracker.create_execution(make_execution("def-alpha"));

    ExecutionQuery q;
    q.definition_id = "def-alpha";
    auto results = tracker.query_executions(q);
    REQUIRE(results.size() == 2);
}

TEST_CASE("ExecutionTracker: query by status", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto id1_result = tracker.create_execution(make_execution());
    auto id2_result = tracker.create_execution(make_execution());
    REQUIRE(id1_result.has_value());
    tracker.mark_completed(*id1_result);

    ExecutionQuery q;
    q.status = "completed";
    auto results = tracker.query_executions(q);
    REQUIRE(results.size() == 1);
    CHECK(results[0].id == *id1_result);
}

TEST_CASE("ExecutionTracker: get_agent_statuses", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());
    tracker.register_agents(*id_result, {"a1", "a2"});
    tracker.update_agent_status(*id_result, "a1", "success");

    auto statuses = tracker.get_agent_statuses(*id_result);
    REQUIRE(statuses.size() == 2);
}
