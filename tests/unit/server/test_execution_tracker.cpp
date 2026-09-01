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
    REQUIRE(tracker.mark_cancelled(*id1_result, "admin"));

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

// ── #3789: query_executions_checked / SQL scope pushdown ──────────────────

TEST_CASE("ExecutionTracker: query_executions_checked with no scope matches query_executions",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    REQUIRE(tracker.create_execution(make_execution("def-a")).has_value());
    REQUIRE(tracker.create_execution(make_execution("def-b")).has_value());

    auto checked = tracker.query_executions_checked(ExecutionQuery{}, std::nullopt);
    REQUIRE(checked.has_value());
    CHECK(checked->size() == 2);
}

TEST_CASE("ExecutionTracker: query_executions_checked scope admits the owner's own "
          "dispatch before any agent has responded",
          "[pg][execution_tracker]") {
    // #3789 finding: agent_exec_status is response-arrival seeded, so a
    // just-dispatched execution has zero status rows. Without the owner
    // disjunct, this execution would be invisible to its own dispatcher
    // under an engaged scope.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id = tracker.create_execution(make_execution("def-owner", "scope", "bob"));
    REQUIRE(id.has_value());

    ExecutionListScope scope;
    scope.owner = "bob";
    // visible_agents deliberately empty — no agent has reported yet.
    auto checked = tracker.query_executions_checked(ExecutionQuery{}, scope);
    REQUIRE(checked.has_value());
    REQUIRE(checked->size() == 1);
    CHECK((*checked)[0].id == *id);
}

TEST_CASE("ExecutionTracker: query_executions_checked scope admits via a visible "
          "agent's status row even when the caller is not the dispatcher",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id = tracker.create_execution(make_execution("def-teammate", "scope", "alice"));
    REQUIRE(id.has_value());
    AgentExecStatus as;
    as.agent_id = "bob-agent";
    as.status = "success";
    tracker.update_agent_status(*id, as);

    ExecutionListScope scope;
    scope.owner = "bob"; // not the dispatcher
    scope.visible_agents = {"bob-agent"};
    auto checked = tracker.query_executions_checked(ExecutionQuery{}, scope);
    REQUIRE(checked.has_value());
    REQUIRE(checked->size() == 1);
    CHECK((*checked)[0].id == *id);
}

TEST_CASE("ExecutionTracker: query_executions_checked scope excludes an execution "
          "neither dispatched by the owner nor reported by a visible agent",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id = tracker.create_execution(make_execution("def-hidden", "scope", "alice"));
    REQUIRE(id.has_value());
    AgentExecStatus as;
    as.agent_id = "alice-agent";
    as.status = "success";
    tracker.update_agent_status(*id, as);

    ExecutionListScope scope;
    scope.owner = "bob";
    scope.visible_agents = {"bob-agent"}; // does not include alice-agent
    auto checked = tracker.query_executions_checked(ExecutionQuery{}, scope);
    REQUIRE(checked.has_value());
    CHECK(checked->empty());
}

TEST_CASE("ExecutionTracker: query_executions_checked engaged-empty scope (no owner, "
          "no visible agents) excludes every row",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;
    REQUIRE(tracker.create_execution(make_execution()).has_value());

    ExecutionListScope scope; // owner empty, visible_agents empty
    auto checked = tracker.query_executions_checked(ExecutionQuery{}, scope);
    REQUIRE(checked.has_value());
    CHECK(checked->empty());
}

TEST_CASE("ExecutionTracker: query_executions_checked scope pushdown respects "
          "LIMIT ordering (INV-3) — a hidden newer execution must not consume the "
          "page while an older visible one exists",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    // Older, visible (dispatched by bob).
    Execution visible_exec = make_execution("def-visible", "scope", "bob");
    visible_exec.dispatched_at = 1000;
    REQUIRE(tracker.create_execution(visible_exec).has_value());
    // Newer, hidden (dispatched by someone else, no visible-agent row).
    Execution hidden_exec = make_execution("def-hidden", "scope", "alice");
    hidden_exec.dispatched_at = 2000;
    REQUIRE(tracker.create_execution(hidden_exec).has_value());

    ExecutionListScope scope;
    scope.owner = "bob";
    ExecutionQuery q;
    q.limit = 1; // if the scope were applied AFTER LIMIT, the hidden newer
                 // row would consume the only slot and the visible one
                 // would never be returned.
    auto checked = tracker.query_executions_checked(q, scope);
    REQUIRE(checked.has_value());
    REQUIRE(checked->size() == 1);
    CHECK((*checked)[0].definition_id == "def-visible");
}

TEST_CASE("ExecutionTracker: get_execution_checked distinguishes absent from present",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto absent = tracker.get_execution_checked("no-such-execution");
    REQUIRE(absent.has_value()); // not degraded
    CHECK_FALSE(absent->has_value()); // genuinely absent

    auto id = tracker.create_execution(make_execution());
    REQUIRE(id.has_value());
    auto present = tracker.get_execution_checked(*id);
    REQUIRE(present.has_value());
    REQUIRE(present->has_value());
    CHECK((*present)->id == *id);
}

TEST_CASE("ExecutionTracker: get_agent_statuses_for_executions_checked groups by "
          "execution id and short-circuits on empty input without degrading",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id_a = tracker.create_execution(make_execution("def-a"));
    auto id_b = tracker.create_execution(make_execution("def-b"));
    REQUIRE(id_a.has_value());
    REQUIRE(id_b.has_value());
    AgentExecStatus a1;
    a1.agent_id = "agent-1";
    a1.status = "success";
    tracker.update_agent_status(*id_a, a1);

    auto checked = tracker.get_agent_statuses_for_executions_checked({*id_a, *id_b});
    REQUIRE(checked.has_value());
    CHECK(checked->at(*id_a).size() == 1);
    CHECK(checked->find(*id_b) == checked->end()); // no rows -> no key, not degrade

    auto empty_result = tracker.get_agent_statuses_for_executions_checked({});
    REQUIRE(empty_result.has_value());
    CHECK(empty_result->empty());
}

TEST_CASE("ExecutionTracker: get_children_checked distinguishes genuinely-no-children "
          "from a degraded read",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    ExecutionTracker& tracker = *tracker_bundle;

    auto id = tracker.create_execution(make_execution());
    REQUIRE(id.has_value());
    auto checked = tracker.get_children_checked(*id);
    REQUIRE(checked.has_value()); // not degraded
    CHECK(checked->empty());      // genuinely no children
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

    // lock_timeout wide enough to be robust to CI scheduling jitter
    // (governance PR review, 2026-08-31, Doomgoose: the original 100ms/150ms
    // pair left only a ~50ms margin on each side, and a mutant that broke the
    // retry was observed to false-green under a loaded run). Attempt 2 gets
    // its OWN fresh lock_timeout window starting when attempt 1 fails
    // (~kLockTimeout after t=0), so the safe range for the release delay is
    // strictly between kLockTimeout and 2*kLockTimeout — kReleaseDelay sits
    // centered in that range with a wide (150ms) margin on both sides.
    constexpr auto kLockTimeout = std::chrono::milliseconds{300};
    constexpr auto kReleaseDelay = std::chrono::milliseconds{450};
    yuzu::server::pg::PgPool store_pool{
        {.conninfo = db.dsn(), .size = 4, .lock_timeout_ms = static_cast<int>(kLockTimeout.count())}};
    REQUIRE(store_pool.valid());
    ExecutionTracker tracker{store_pool};
    REQUIRE(tracker.is_open());

    auto exec = make_execution();
    exec.agents_targeted = 1;
    auto id_result = tracker.create_execution(exec);
    REQUIRE(id_result.has_value());
    const std::string execution_id = *id_result;

    // A second, independent connection holds an exclusive row lock on the
    // execution for longer than store_pool's lock_timeout, so the FIRST
    // refresh_counts attempt (chained inside update_agent_status) is
    // guaranteed to be cancelled and abandoned.
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
    // after kLockTimeout has already cancelled attempt 1, well before a
    // human would notice anything.
    std::thread releaser([&] {
        std::this_thread::sleep_for(kReleaseDelay);
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
    auto before = std::chrono::steady_clock::now();
    tracker.update_agent_status(execution_id, as);
    auto elapsed = std::chrono::steady_clock::now() - before;

    releaser.join();

    // Proves attempt 1 actually got cancelled rather than the test passing
    // by luck (e.g. the lock happening to already be free) — the call must
    // have blocked for at least one full lock_timeout window before the
    // retry could succeed. No log-capture seam exists in this file, so a
    // coarse wall-clock floor is the cheapest reliable proof (governance PR
    // review, 2026-08-31, Doomgoose: "never asserts attempt 1 was
    // cancelled").
    CHECK(elapsed >= kLockTimeout);

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

    CHECK(tracker.mark_cancelled(*id_result, "admin"));

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

    CHECK(tracker.mark_cancelled(*id_result, "operator1"));

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

    // #3789: the checked twins must fail closed (nullopt/unexpected), not
    // collapse to the plain methods' empty-on-degrade shape — a caller that
    // drops rows or writes `denied` audit rows off these results must be
    // able to tell "degraded" from "genuinely nothing here".
    CHECK_FALSE(closed.query_executions_checked(ExecutionQuery{}).has_value());
    auto exec_checked = closed.get_execution_checked("exec-1");
    REQUIRE_FALSE(exec_checked.has_value());
    CHECK(exec_checked.error() == "execution tracker not open");
    CHECK_FALSE(closed.get_children_checked("exec-1").has_value());
    CHECK_FALSE(
        closed.get_agent_statuses_for_executions_checked({"exec-1"}).has_value());
    // Engaged-empty still short-circuits on a closed store — zero requested
    // ids is a success-empty outcome, not a degrade, regardless of whether
    // the store could otherwise serve the request.
    auto empty_ids_result = closed.get_agent_statuses_for_executions_checked({});
    REQUIRE(empty_ids_result.has_value());
    CHECK(empty_ids_result->empty());

    auto created = closed.create_execution(make_execution());
    REQUIRE_FALSE(created.has_value());
    CHECK(created.error() == "database not open");

    // Mutations on a closed store are no-ops, not crashes — and the two
    // that report success/failure (governance PR review, 2026-08-31) must
    // honestly report failure rather than silently claiming success.
    AgentExecStatus status;
    status.agent_id = "agent-1";
    status.status = "running";
    closed.update_agent_status("exec-1", status);
    closed.refresh_counts("exec-1");
    CHECK_FALSE(closed.mark_cancelled("exec-1", "tester"));
    CHECK_FALSE(closed.set_agents_targeted("exec-1", 1));
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

// ── Command <-> execution correlation (HA WS-1(1b), ADR-2002 section 5) ────
//
// WS-9 failover scenario: proves the cross-instance property this migration
// exists to deliver — a mapping written through one ExecutionTracker
// instance (dispatch, "replica A") is resolvable through a SEPARATE
// ExecutionTracker instance pointed at the same database ("replica B").
// The former in-process map could never pass this: it was populated only
// in the writer's own process memory.

TEST_CASE("ExecutionTracker: record/lookup command_execution round-trips",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;

    CHECK_FALSE(tracker_bundle->lookup_execution_id("cmd-unknown").has_value());

    REQUIRE(tracker_bundle->record_command_execution("cmd-1", "exec-1"));
    auto looked_up = tracker_bundle->lookup_execution_id("cmd-1");
    REQUIRE(looked_up.has_value());
    CHECK(*looked_up == "exec-1");

    // Last-write-wins on a repeated command_id (mirrors the former map's
    // operator[]= semantics).
    REQUIRE(tracker_bundle->record_command_execution("cmd-1", "exec-2"));
    looked_up = tracker_bundle->lookup_execution_id("cmd-1");
    REQUIRE(looked_up.has_value());
    CHECK(*looked_up == "exec-2");

    // Empty execution_id deletes the mapping (the former map's explicit-
    // clear branch).
    REQUIRE(tracker_bundle->record_command_execution("cmd-1", ""));
    CHECK_FALSE(tracker_bundle->lookup_execution_id("cmd-1").has_value());
}

TEST_CASE("ExecutionTracker: lookup is non-destructive across a multi-agent "
          "fan-out (HF-1)",
          "[pg][execution_tracker]") {
    // One command_id dispatched to N agents; each sends its own terminal
    // response against the SAME command_id. A lookup must never consume the
    // mapping, or agents 2..N would find nothing to stamp.
    yuzu::test::ExecutionTrackerPg tracker_bundle;
    REQUIRE(tracker_bundle->record_command_execution("cmd-fanout", "exec-fanout"));

    for (int i = 0; i < 5; ++i) {
        auto looked_up = tracker_bundle->lookup_execution_id("cmd-fanout");
        REQUIRE(looked_up.has_value());
        CHECK(*looked_up == "exec-fanout");
    }
}

TEST_CASE("ExecutionTracker: a command_execution mapping written on one "
          "instance resolves on a SEPARATE instance against the same "
          "database (WS-9 failover scenario)",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle; // "replica A" — dispatches

    REQUIRE(tracker_bundle->record_command_execution("cmd-cross-replica", "exec-cross-replica"));

    // "replica B" — a second pool AND a second ExecutionTracker instance
    // against the SAME database, sharing no process memory with A. The
    // in-process map this migration replaces could never resolve this: it
    // was populated only in A's own memory.
    pg::PgPool pool_b{{.conninfo = tracker_bundle.dsn(), .size = 2}};
    ExecutionTracker tracker_b{pool_b};
    REQUIRE(tracker_b.is_open());

    auto looked_up = tracker_b.lookup_execution_id("cmd-cross-replica");
    REQUIRE(looked_up.has_value());
    CHECK(*looked_up == "exec-cross-replica");
}

TEST_CASE("ExecutionTracker: a store bound to an unreachable pool degrades "
          "command_execution methods without crashing",
          "[execution_tracker]") {
    pg::PgPool unreachable{{.conninfo = "host=127.0.0.1 port=1 dbname=yuzu connect_timeout=1",
                            .size = 1,
                            .connect_timeout_s = 1}};
    ExecutionTracker closed(unreachable);
    REQUIRE(!closed.is_open());

    CHECK_FALSE(closed.record_command_execution("cmd-1", "exec-1")); // no-op, not a crash
    CHECK_FALSE(closed.lookup_execution_id("cmd-1").has_value());
    auto reaped = closed.reap_command_execution_mappings();
    REQUIRE_FALSE(reaped.has_value());
    CHECK(reaped.error() == "execution tracker not open");
}

TEST_CASE("ExecutionTracker: reap_command_execution_mappings deletes only "
          "aged-out rows, is capped, and is clock-guarded",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;

    REQUIRE(tracker_bundle->record_command_execution("cmd-fresh", "exec-fresh"));
    REQUIRE(tracker_bundle->lookup_execution_id("cmd-fresh").has_value());

    // First pass: no anchor yet, nothing aged out (the fresh row's
    // created_at is "now", far inside the 24h retention window) — proceeds
    // (missing-anchor PROCEED decision) but deletes 0 rows.
    auto first = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(first.has_value());
    CHECK(first->deleted == 0);
    CHECK_FALSE(first->clock_anomaly);
    CHECK(tracker_bundle->lookup_execution_id("cmd-fresh").has_value());

    // Directly age the row past the retention window by rewriting
    // created_at through a second connection on the same pool (the public
    // API has no "backdate" hook by design — this is the test-only path,
    // mirroring how test_session_store.cpp pokes session_meta directly).
    {
        pg::PgPool& pool = tracker_bundle.pool();
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(
            lease.get(),
            "UPDATE execution_tracker.command_execution SET created_at = created_at - 90000 "
            "WHERE command_id = 'cmd-fresh'",
            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    } // lease released here, before the reap below acquires its own

    auto second = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(second.has_value());
    CHECK(second->deleted == 1);
    CHECK_FALSE(second->clock_anomaly);
    CHECK_FALSE(tracker_bundle->lookup_execution_id("cmd-fresh").has_value());
}

TEST_CASE("ExecutionTracker: reap declines on an implausibly-forward "
          "anchor gap (forward-skew decline)",
          "[pg][execution_tracker]") {
    // Governance Gate 4/5/6 finding (consistency-auditor + chaos-injector
    // CH-4): the forward/backward anomaly-decline branches were previously
    // untested for this reap, unlike SessionStore's equivalent guard.
    yuzu::test::ExecutionTrackerPg tracker_bundle;

    // Establish a real anchor via one ordinary pass.
    auto first = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(first.has_value());
    CHECK_FALSE(first->clock_anomaly);

    // Rewrite the persisted anchor to look implausibly far in the PAST
    // relative to the real DB clock — from the next pass's point of view,
    // now_s reads as far ahead of the anchor, exactly the forward-skew
    // shape a poisoned or stale anchor produces.
    {
        pg::PgPool& pool = tracker_bundle.pool();
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(
            lease.get(),
            "UPDATE execution_tracker.reap_meta SET value = "
            "(value::bigint - 200000)::text WHERE key = 'cmd_exec_reap_anchor'",
            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    auto second = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(second.has_value());
    CHECK(second->deleted == 0);
    CHECK(second->clock_anomaly);
}

TEST_CASE("ExecutionTracker: reap declines on a backward-stepped clock "
          "(backward-anomaly decline)",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;

    auto first = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(first.has_value());
    CHECK_FALSE(first->clock_anomaly);

    // Rewrite the persisted anchor to look far in the FUTURE relative to
    // the real DB clock — the next pass's now_s reads as BEHIND the
    // anchor, the backward-clock-movement shape (a rewound host clock, or
    // an earlier forward-skewed pass that poisoned the anchor).
    {
        pg::PgPool& pool = tracker_bundle.pool();
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(
            lease.get(),
            "UPDATE execution_tracker.reap_meta SET value = "
            "(value::bigint + 200000)::text WHERE key = 'cmd_exec_reap_anchor'",
            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    auto second = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(second.has_value());
    CHECK(second->deleted == 0);
    CHECK(second->clock_anomaly);
}

TEST_CASE("ExecutionTracker: reap declines on an unparseable persisted "
          "anchor (adversarial review Blocker, PR #3780)",
          "[pg][execution_tracker]") {
    // CLAUDE.md's clock-guarded-retention part 3: "SANITISE that reading
    // (ahead-of-now / negative / unparseable = anomaly, never a quiet
    // reset)". A bad migration, a manual reap_meta repair, or storage
    // corruption can write anything into this plain key/value table — the
    // parse must REJECT junk, never silently truncate/coerce it via an
    // unchecked strtoll (the finding this test locks: `to_i64`'s prior
    // zero-validation parse would have accepted "123junk" as 123, with no
    // rejection and no counted anomaly).
    yuzu::test::ExecutionTrackerPg tracker_bundle;

    auto first = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(first.has_value());
    CHECK_FALSE(first->clock_anomaly);

    {
        pg::PgPool& pool = tracker_bundle.pool();
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(
            lease.get(),
            "UPDATE execution_tracker.reap_meta SET value = '123junk' "
            "WHERE key = 'cmd_exec_reap_anchor'",
            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    auto second = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(second.has_value());
    CHECK(second->deleted == 0);
    CHECK(second->clock_anomaly);
}

TEST_CASE("ExecutionTracker: reap declines on a negative persisted anchor "
          "(adversarial review Blocker, PR #3780)",
          "[pg][execution_tracker]") {
    yuzu::test::ExecutionTrackerPg tracker_bundle;

    auto first = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(first.has_value());
    CHECK_FALSE(first->clock_anomaly);

    {
        pg::PgPool& pool = tracker_bundle.pool();
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(lease.get(),
                                   "UPDATE execution_tracker.reap_meta SET value = '-1' "
                                   "WHERE key = 'cmd_exec_reap_anchor'",
                                   std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    auto second = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(second.has_value());
    CHECK(second->deleted == 0);
    CHECK(second->clock_anomaly);
}

TEST_CASE("ExecutionTracker: reap declines on an overflowed persisted "
          "anchor (adversarial review Blocker, PR #3780)",
          "[pg][execution_tracker]") {
    // A value strtoll cannot represent (beyond int64_t range) must be
    // rejected via the errno==ERANGE check, not wrapped/clamped by
    // static_cast<int64_t> on an already-saturated `long long`.
    yuzu::test::ExecutionTrackerPg tracker_bundle;

    auto first = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(first.has_value());
    CHECK_FALSE(first->clock_anomaly);

    {
        pg::PgPool& pool = tracker_bundle.pool();
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(
            lease.get(),
            "UPDATE execution_tracker.reap_meta SET value = "
            "'99999999999999999999999999' WHERE key = 'cmd_exec_reap_anchor'",
            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    auto second = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(second.has_value());
    CHECK(second->deleted == 0);
    CHECK(second->clock_anomaly);
}

TEST_CASE("ExecutionTracker: reap does not overflow on a legitimately-parsed "
          "INT64_MAX anchor (adversarial review Blocker round 2, PR #3780)",
          "[pg][execution_tracker]") {
    // Distinct from the "overflowed" test above: that one exercises a
    // string strtoll cannot even PARSE (rejected by parse_reap_i64 itself,
    // via errno==ERANGE). THIS value parses cleanly and is >= 0, so it
    // passes parse_reap_i64 -- the residual defect was in the CONSUMING
    // arithmetic (`anchor + kMaxPlausibleSkewSecs`), not the parse. Under
    // UBSan this specific value reproduces "signed integer overflow:
    // 9223372036854775807 + 86400 cannot be represented in type 'long
    // int'" against the pre-fix comparison. The fixed comparison
    // (`now_s - anchor > kMaxPlausibleSkewSecs`, both operands already
    // non-negative) must decline this as a forward-skew anomaly without
    // invoking UB.
    yuzu::test::ExecutionTrackerPg tracker_bundle;

    auto first = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(first.has_value());
    CHECK_FALSE(first->clock_anomaly);

    {
        pg::PgPool& pool = tracker_bundle.pool();
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(
            lease.get(),
            "UPDATE execution_tracker.reap_meta SET value = "
            "'9223372036854775807' WHERE key = 'cmd_exec_reap_anchor'",
            std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    auto second = tracker_bundle->reap_command_execution_mappings();
    REQUIRE(second.has_value());
    CHECK(second->deleted == 0);
    CHECK(second->clock_anomaly);
}

TEST_CASE("ExecutionTracker: the four non-tracked correlation-id VALUES "
          "round-trip opaquely through the PG-backed store",
          "[pg][execution_tracker]") {
    // Governance Gate 4 consistency-auditor finding / chaos-injector CH-5,
    // corrected per Gate 8 quality-engineer re-review: polchk-/bundle-/
    // preflight-/deployment- are minted as the execution_id VALUE (by
    // PolicyEvaluator/BundleOrchestrator/PreflightRunner/the deployment
    // engine), never as the command_id KEY — the ORIGINAL version of this
    // test looked up an unwritten prefixed STRING AS A KEY, which is
    // vacuously nullopt for any string and proved nothing (a false-green
    // policy-floor finding, caught before merge). The real property: the
    // store must treat these values as opaque data, storing and returning
    // them byte-for-byte under an ordinary command_id key — the
    // PREFIX-SKIP decision itself lives in AgentServiceImpl::
    // notify_exec_tracker (see the companion test in
    // test_agent_service_impl.cpp), not in the store.
    yuzu::test::ExecutionTrackerPg tracker_bundle;

    for (const std::string execution_id :
         {"polchk-abc123", "bundle-def456", "preflight-run1-check2", "deployment-xyz-stage"}) {
        CAPTURE(execution_id);
        const std::string command_id = "plugin-cmd-" + execution_id;
        REQUIRE(tracker_bundle->record_command_execution(command_id, execution_id));
        auto looked_up = tracker_bundle->lookup_execution_id(command_id);
        REQUIRE(looked_up.has_value());
        CHECK(*looked_up == execution_id);
    }
}
