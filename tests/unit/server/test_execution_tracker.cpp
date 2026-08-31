/**
 * test_execution_tracker.cpp — Unit tests for ExecutionTracker
 *
 * Covers: create, get, query filters, agent status transitions, summary,
 *         refresh_counts, parent-child hierarchy, rerun, mark cancelled.
 */

#include "execution_tracker.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "test_execution_tracker_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;

// ── Helpers ─────────────────────────────────────────────────────────────────

static Execution make_execution(const std::string& definition_id = "def-001",
                                const std::string& scope = "ostype = 'windows'",
                                const std::string& dispatched_by = "admin") {
    Execution exec;
    exec.definition_id = definition_id;
    exec.scope_expression = scope;
    exec.dispatched_by = dispatched_by;
    exec.status = "running";
    return exec;
}

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: construction migrates and opens the store",
          "[pg][execution_tracker][db]") {
    // The fixture's own constructor already REQUIREs is_open() — this test
    // exists so a construction failure surfaces here by name rather than as
    // an opaque fixture assertion inside the first unrelated test that
    // happens to run.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    REQUIRE(tracker_bundle->is_open());
}

// ── Create Execution ───────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: create execution", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto result = tracker.create_execution(make_execution());
    REQUIRE(result.has_value());
    CHECK(!result->empty());
}

TEST_CASE("ExecutionTracker: create execution with parameter_values", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto exec = make_execution();
    exec.parameter_values = R"({"timeout": 30, "force": true})";
    auto result = tracker.create_execution(exec);
    REQUIRE(result.has_value());

    auto fetched = tracker.get_execution(*result);
    REQUIRE(fetched.has_value());
    CHECK(fetched->parameter_values == exec.parameter_values);
}

// ── Get Execution ──────────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: get execution", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto result =
        tracker.create_execution(make_execution("def-hostname", "ostype = 'windows'", "operator1"));
    REQUIRE(result.has_value());

    auto exec = tracker.get_execution(*result);
    REQUIRE(exec.has_value());
    CHECK(exec->definition_id == "def-hostname");
    CHECK(exec->scope_expression == "ostype = 'windows'");
    CHECK(exec->dispatched_by == "operator1");
    CHECK(exec->status == "running");
}

TEST_CASE("ExecutionTracker: get nonexistent returns empty", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto result = tracker.get_execution("nonexistent-id");
    CHECK(!result.has_value());
}

// ── Query with Filters ─────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: query all executions", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    tracker.create_execution(make_execution("def-1"));
    tracker.create_execution(make_execution("def-2"));
    tracker.create_execution(make_execution("def-3"));

    auto results = tracker.query_executions();
    REQUIRE(results.size() == 3);
}

TEST_CASE("ExecutionTracker: query by definition_id", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    tracker.create_execution(make_execution("def-alpha"));
    tracker.create_execution(make_execution("def-beta"));
    tracker.create_execution(make_execution("def-alpha"));

    ExecutionQuery q;
    q.definition_id = "def-alpha";
    auto results = tracker.query_executions(q);
    REQUIRE(results.size() == 2);
}

TEST_CASE("ExecutionTracker: query by status", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id1_result = tracker.create_execution(make_execution());
    auto id2_result = tracker.create_execution(make_execution());
    REQUIRE(id1_result.has_value());
    REQUIRE(id2_result.has_value());
    tracker.mark_cancelled(*id1_result, "admin");

    ExecutionQuery q;
    q.status = "cancelled";
    auto results = tracker.query_executions(q);
    REQUIRE(results.size() == 1);
    CHECK(results[0].id == *id1_result);
}

TEST_CASE("ExecutionTracker: query with limit", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    for (int i = 0; i < 10; ++i) {
        tracker.create_execution(make_execution("def-" + std::to_string(i)));
    }

    ExecutionQuery q;
    q.limit = 5;
    auto results = tracker.query_executions(q);
    REQUIRE(results.size() == 5);
}

// ── Update Agent Status ────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: update_agent_status dispatched -> running -> success",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    // dispatched
    AgentExecStatus as;
    as.agent_id = "agent-1";
    as.status = "dispatched";
    as.dispatched_at = 1000;
    tracker.update_agent_status(*id_result, as);

    // running (first response)
    as.status = "running";
    as.first_response_at = 1001;
    tracker.update_agent_status(*id_result, as);

    // success (terminal)
    as.status = "success";
    as.completed_at = 1002;
    as.exit_code = 0;
    tracker.update_agent_status(*id_result, as);

    auto statuses = tracker.get_agent_statuses(*id_result);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].agent_id == "agent-1");
    CHECK(statuses[0].status == "success");
    CHECK(statuses[0].exit_code == 0);
}

TEST_CASE("ExecutionTracker: update_agent_status failure with error_detail",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    AgentExecStatus as;
    as.agent_id = "agent-1";
    as.status = "failure";
    as.dispatched_at = 1000;
    as.completed_at = 1005;
    as.exit_code = 1;
    as.error_detail = "plugin timeout";
    tracker.update_agent_status(*id_result, as);

    auto statuses = tracker.get_agent_statuses(*id_result);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].status == "failure");
    CHECK(statuses[0].exit_code == 1);
    CHECK(statuses[0].error_detail == "plugin timeout");
}

TEST_CASE("ExecutionTracker: get_agent_statuses multiple agents", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    for (int i = 0; i < 4; ++i) {
        AgentExecStatus as;
        as.agent_id = "agent-" + std::to_string(i);
        as.status = (i < 3) ? "success" : "failure";
        as.dispatched_at = 1000;
        as.completed_at = 1005;
        as.exit_code = (i < 3) ? 0 : 1;
        tracker.update_agent_status(*id_result, as);
    }

    auto statuses = tracker.get_agent_statuses(*id_result);
    REQUIRE(statuses.size() == 4);
}

TEST_CASE("ExecutionTracker: update_agent_status on unknown execution_id is a no-op",
          "[pg][execution_tracker][issue872]") {
    // Out-of-band dispatches that bypass the workflow-routes create path
    // (CLI / direct gRPC / re-mapped command_id) can reach
    // update_agent_status with an execution_id that has no row in the
    // `executions` table. The mutator must tolerate this — no crash, no
    // SQL constraint violation. The chained refresh_counts must likewise
    // return cleanly when there is nothing to aggregate.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    AgentExecStatus as;
    as.agent_id = "agent-ghost";
    as.status = "success";
    as.dispatched_at = 1000;
    as.completed_at = 1005;
    as.exit_code = 0;
    // Must not throw, must not abort the test process.
    tracker.update_agent_status("exec-does-not-exist", as);

    // No parent execution row was created; querying it returns empty.
    auto fetched = tracker.get_execution("exec-does-not-exist");
    CHECK_FALSE(fetched.has_value());

    // The agent_exec_status schema has NO foreign-key constraint on
    // execution_id (no `FOREIGN KEY(execution_id) REFERENCES executions(id)`
    // at execution_tracker.cpp lines 105-115), so the orphan row IS written.
    // Pin this as the canonical behaviour — if a future migration adds FK
    // enforcement (so the upsert silently no-ops or sqlite3_step returns
    // SQLITE_CONSTRAINT), this test will flip to size==0 and force a
    // conscious decision about the new contract. Without an explicit size
    // assertion the test would silently pass on either path, masking the
    // schema regression.
    auto statuses = tracker.get_agent_statuses("exec-does-not-exist");
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].agent_id == "agent-ghost");
    CHECK(statuses[0].status == "success");
}

TEST_CASE("ExecutionTracker: update_agent_status alone advances parent aggregates "
          "(chain invariant)",
          "[pg][execution_tracker][issue872]") {
    // UAT 2026-05-06 fix 18e8766 chained refresh_counts inside
    // update_agent_status so callers no longer need an explicit refresh.
    // The `test_rest_api_t2.cpp` cleanup in PR #1068 dropped 7 redundant
    // explicit calls based on this chain. If a future refactor breaks the
    // chain (e.g. moves refresh behind a flag or an async queue),
    // test_rest_api_t2.cpp's lower-bound assertions (>= 2) would still
    // pass with stale aggregates — only the workflow_routes terminal-
    // threshold test would bite. This case pins the chain at the mutator
    // itself so any chain-break fails ONE focused test with a clear name.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto exec = make_execution();
    exec.agents_targeted = 1;
    auto id_result = tracker.create_execution(exec);
    REQUIRE(id_result.has_value());

    AgentExecStatus as;
    as.agent_id = "agent-1";
    as.status = "success";
    as.dispatched_at = 1000;
    as.completed_at = 1005;
    as.exit_code = 0;
    // Single call, no explicit refresh_counts. The chain inside
    // update_agent_status MUST recompute aggregates and advance status.
    tracker.update_agent_status(*id_result, as);

    auto summary = tracker.get_summary(*id_result);
    CHECK(summary.agents_responded == 1);
    CHECK(summary.agents_success == 1);
    CHECK(summary.agents_failure == 0);
}

// ── Summary ────────────────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: get_summary", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto exec = make_execution();
    exec.agents_targeted = 4;
    auto id_result = tracker.create_execution(exec);
    REQUIRE(id_result.has_value());

    auto summary = tracker.get_summary(*id_result);
    CHECK(summary.id == *id_result);
    CHECK(summary.agents_targeted == 4);
}

TEST_CASE("ExecutionTracker: summary after refresh_counts", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto exec = make_execution();
    exec.agents_targeted = 3;
    auto id_result = tracker.create_execution(exec);
    REQUIRE(id_result.has_value());

    // Add agent statuses
    AgentExecStatus s1;
    s1.agent_id = "a1";
    s1.status = "success";
    tracker.update_agent_status(*id_result, s1);

    AgentExecStatus s2;
    s2.agent_id = "a2";
    s2.status = "success";
    tracker.update_agent_status(*id_result, s2);

    AgentExecStatus s3;
    s3.agent_id = "a3";
    s3.status = "failure";
    s3.exit_code = 1;
    tracker.update_agent_status(*id_result, s3);

    // Refresh aggregate counts from agent_exec_status rows
    tracker.refresh_counts(*id_result);

    auto summary = tracker.get_summary(*id_result);
    CHECK(summary.agents_responded == 3);
    CHECK(summary.agents_success == 2);
    CHECK(summary.agents_failure == 1);
    CHECK(summary.progress_pct > 0);
}

TEST_CASE("ExecutionTracker: refresh_counts retries and recovers from transient row-lock "
          "contention instead of wedging the execution (governance adversarial review "
          "2026-08-31, CHAOS-01)",
          "[pg][execution_tracker][chaos]") {
    // Reproduces UP-1: the pre-migration SQLite recursive_mutex blocked
    // UNBOUNDEDLY on contention (never dropped an update, only queued); the
    // Postgres port's bounded lock_timeout can cancel a queued
    // refresh_counts call instead, and pre-fix that failure was silent and
    // final — the execution stayed "running" forever. This test proves the
    // fix's single retry recovers once the contending transaction releases,
    // which it reliably does well inside a real lock_timeout window.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::execution_tracker_pg_template);

    // A short lock_timeout makes the injected contention resolve in
    // milliseconds instead of the production 10s default (PgPool::Options).
    yuzu::server::pg::PgPool store_pool{
        {.conninfo = db.dsn(), .size = 4, .lock_timeout_ms = 100}};
    REQUIRE(store_pool.valid());
    ExecutionTracker tracker{store_pool};
    REQUIRE(tracker.is_open());

    auto exec = make_execution();
    exec.agents_targeted = 1;
    auto id_result = tracker.create_execution(exec);
    REQUIRE(id_result.has_value());
    const std::string execution_id = *id_result;

    // A second, independent connection holds an exclusive row lock on the
    // execution for longer than store_pool's 100ms lock_timeout, so the
    // FIRST refresh_counts attempt (chained inside update_agent_status)
    // is guaranteed to be cancelled and abandoned.
    yuzu::server::pg::PgPool locker_pool{{.conninfo = db.dsn(), .size = 1}};
    REQUIRE(locker_pool.valid());
    auto locker_lease = locker_pool.try_acquire_for(std::chrono::milliseconds{2000});
    REQUIRE(locker_lease);
    auto begin = pg::exec_params(locker_lease.get(), "BEGIN", std::vector<std::string>{});
    REQUIRE(begin.status() == PGRES_COMMAND_OK);
    auto lock = pg::exec_params(
        locker_lease.get(), "SELECT 1 FROM execution_tracker.executions WHERE id=$1 FOR UPDATE",
        std::vector<std::string>{execution_id});
    REQUIRE(lock.status() == PGRES_TUPLES_OK);

    // Releases the lock partway through the store's retry window — well
    // after the 100ms lock_timeout has already cancelled attempt 1, well
    // before a human would notice anything.
    std::thread releaser([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds{150});
        auto rollback =
            pg::exec_params(locker_lease.get(), "ROLLBACK", std::vector<std::string>{});
        CHECK(rollback.status() == PGRES_COMMAND_OK);
    });

    AgentExecStatus as;
    as.agent_id = "agent-1";
    as.status = "success";
    as.dispatched_at = 1000;
    as.completed_at = 1005;
    as.exit_code = 0;
    tracker.update_agent_status(execution_id, as);

    releaser.join();

    // Pre-fix: this would be stuck at "running" with stale (zero) aggregate
    // counts — attempt 1 was cancelled and nothing ever retried it.
    auto summary = tracker.get_summary(execution_id);
    CHECK(summary.agents_responded == 1);
    CHECK(summary.agents_success == 1);
    auto row = tracker.get_execution(execution_id);
    REQUIRE(row.has_value());
    CHECK(row->status == "succeeded");
}

// ── Parent-Child Hierarchy ─────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: parent-child relationship", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto parent_result = tracker.create_execution(make_execution());
    REQUIRE(parent_result.has_value());

    Execution child = make_execution();
    child.parent_id = *parent_result;
    auto child_result = tracker.create_execution(child);
    REQUIRE(child_result.has_value());

    auto children = tracker.get_children(*parent_result);
    REQUIRE(children.size() == 1);
    CHECK(children[0].parent_id == *parent_result);
}

TEST_CASE("ExecutionTracker: multiple children", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto parent_result = tracker.create_execution(make_execution());
    REQUIRE(parent_result.has_value());

    for (int i = 0; i < 3; ++i) {
        Execution child = make_execution();
        child.parent_id = *parent_result;
        tracker.create_execution(child);
    }

    auto children = tracker.get_children(*parent_result);
    REQUIRE(children.size() == 3);
}

TEST_CASE("ExecutionTracker: get_children empty for execution without children",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    auto children = tracker.get_children(*id_result);
    CHECK(children.empty());
}

// ── Rerun ──────────────────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: create_rerun all agents", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    // Simulate agent statuses
    AgentExecStatus s1;
    s1.agent_id = "a1";
    s1.status = "success";
    tracker.update_agent_status(*id_result, s1);

    AgentExecStatus s2;
    s2.agent_id = "a2";
    s2.status = "failure";
    s2.exit_code = 1;
    tracker.update_agent_status(*id_result, s2);

    auto rerun_result = tracker.create_rerun(*id_result, "admin", false);
    REQUIRE(rerun_result.has_value());

    auto rerun = tracker.get_execution(*rerun_result);
    REQUIRE(rerun.has_value());
    CHECK(rerun->rerun_of == *id_result);
    CHECK(rerun->definition_id == "def-001");
}

TEST_CASE("ExecutionTracker: create_rerun failed_only", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    AgentExecStatus s1;
    s1.agent_id = "a1";
    s1.status = "success";
    tracker.update_agent_status(*id_result, s1);

    AgentExecStatus s2;
    s2.agent_id = "a2";
    s2.status = "failure";
    s2.exit_code = 1;
    tracker.update_agent_status(*id_result, s2);

    AgentExecStatus s3;
    s3.agent_id = "a3";
    s3.status = "failure";
    s3.exit_code = 2;
    tracker.update_agent_status(*id_result, s3);

    auto rerun_result = tracker.create_rerun(*id_result, "admin", true);
    REQUIRE(rerun_result.has_value());

    auto rerun = tracker.get_execution(*rerun_result);
    REQUIRE(rerun.has_value());
    CHECK(rerun->rerun_of == *id_result);
}

TEST_CASE("ExecutionTracker: create_rerun nonexistent fails", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto rerun_result = tracker.create_rerun("nonexistent-id", "admin", false);
    CHECK(!rerun_result.has_value());
}

// ── Mark Cancelled ─────────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: mark_cancelled", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    tracker.mark_cancelled(*id_result, "admin");

    auto exec = tracker.get_execution(*id_result);
    REQUIRE(exec.has_value());
    CHECK(exec->status == "cancelled");
    CHECK(exec->completed_at > 0);
}

TEST_CASE("ExecutionTracker: mark_cancelled sets completed_at", "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    auto before = tracker.get_execution(*id_result);
    REQUIRE(before.has_value());
    CHECK(before->completed_at == 0);

    tracker.mark_cancelled(*id_result, "operator1");

    auto after = tracker.get_execution(*id_result);
    REQUIRE(after.has_value());
    CHECK(after->completed_at > 0);
}

// ── CC-07 typed plugin result status (PR1.1 finding F11) ───────────────────
//
// update_agent_status binds plugin_result_status into agent_exec_status and
// get_agent_statuses reads it back, but no test set it to anything but the
// 0/UNDECLARED default — so binding a literal 0, or dropping the column from
// the ON CONFLICT update list, would have left the suite green while the
// executions drawer silently lost every plugin-reported status. Values mirror
// YuzuResultStatus in sdk/include/yuzu/plugin.h (4 = CONSTRAINED, 2 =
// UNAVAILABLE), chosen distinct from exit_code so a crossed bind is caught.

TEST_CASE("ExecutionTracker: plugin_result_status round-trips through update/get (CC-07)",
          "[pg][execution_tracker][cc07]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    AgentExecStatus s;
    s.agent_id = "agent-1";
    s.status = "success";
    s.exit_code = 0;
    s.plugin_result_status = 4; // CONSTRAINED
    tracker.update_agent_status(*id_result, s);

    // An agent whose plugin reported nothing stays honestly undeclared.
    AgentExecStatus silent;
    silent.agent_id = "agent-2";
    silent.status = "success";
    tracker.update_agent_status(*id_result, silent);

    auto statuses = tracker.get_agent_statuses(*id_result);
    REQUIRE(statuses.size() == 2);
    int seen = 0;
    for (const auto& st : statuses) {
        if (st.agent_id == "agent-1") {
            CHECK(st.plugin_result_status == 4);
            ++seen;
        } else if (st.agent_id == "agent-2") {
            CHECK(st.plugin_result_status == 0);
            ++seen;
        }
    }
    CHECK(seen == 2);
}

TEST_CASE("ExecutionTracker: a later frame overwrites the typed status via ON CONFLICT (CC-07)",
          "[pg][execution_tracker][cc07]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    AgentExecStatus running;
    running.agent_id = "agent-1";
    running.status = "running";
    running.plugin_result_status = 0; // nothing reported yet
    tracker.update_agent_status(*id_result, running);

    AgentExecStatus terminal;
    terminal.agent_id = "agent-1";
    terminal.status = "failure";
    terminal.exit_code = 1;
    terminal.plugin_result_status = 2; // UNAVAILABLE
    tracker.update_agent_status(*id_result, terminal);

    auto statuses = tracker.get_agent_statuses(*id_result);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].status == "failure");
    CHECK(statuses[0].plugin_result_status == 2);
}

TEST_CASE("ExecutionTracker: a store bound to an unreachable pool degrades every method, "
          "never crashes",
          "[execution_tracker]") {
    // A store that never opened, ported to Postgres (ADR-0065): an unreachable
    // port fails construction's own connect attempt deterministically
    // (test_engine_principal_store.cpp's #2456 precedent) — no live database
    // needed, so this test carries no [pg] tag. Mirrors
    // test_approval_manager.cpp's equivalent closed-store coverage.
    pg::PgPool unreachable{{.conninfo = "host=127.0.0.1 port=1 dbname=yuzu connect_timeout=1",
                            .size = 1,
                            .connect_timeout_s = 1}};
    REQUIRE(unreachable.valid()); // conninfo parses; the host is just unreachable
    ExecutionTracker closed(unreachable);
    REQUIRE(!closed.is_open());

    CHECK(closed.query_executions(ExecutionQuery{}).empty());
    CHECK_FALSE(closed.get_execution("exec-1").has_value());
    CHECK(closed.get_summary("exec-1").id == "exec-1"); // id echoed, everything else defaulted
    CHECK(closed.get_agent_statuses("exec-1").empty());

    auto created = closed.create_execution(make_execution());
    REQUIRE_FALSE(created.has_value());
    CHECK(created.error() == "database not open");

    // Mutations on a closed store are silent no-ops, not crashes.
    AgentExecStatus status;
    status.agent_id = "agent-1";
    status.status = "running";
    closed.update_agent_status("exec-1", status);
    closed.refresh_counts("exec-1");
    closed.mark_cancelled("exec-1", "tester");
}

// "v2 probe stamps straight through..."/"v2 probe does not silently skip
// v1's CREATE INDEX..."/"v2 probe refuses to stamp when only SOME of v1's
// indexes are present" (UP-12/A-5/D4(a)/CDX-P1-04) are DELETED, not ported
// (ADR-0065) — they pinned SQLite-era migration-probe logic (a hand-rolled
// pre-migration check reconciling a partially-hand-surgeried schema against
// schema_meta before running MigrationRunner) that has no equivalent once
// the v1+v2 ladder folds into one PG v1 DDL created fresh on an empty
// schema: there is no "column pre-exists but the index doesn't" state a
// fresh Postgres schema can ever be in. See test_approval_manager.cpp's
// equivalent deletions for the same reasoning applied to that store's own
// SQLite migration-ladder-specific tests.
