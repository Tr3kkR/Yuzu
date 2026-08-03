/**
 * test_execution_tracker.cpp — Unit tests for ExecutionTracker
 *
 * Covers: create, get, query filters, agent status transitions, summary,
 *         refresh_counts, parent-child hierarchy, rerun, mark cancelled.
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
    ~TestDb() {
        if (db)
            sqlite3_close(db);
    }
};

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

TEST_CASE("ExecutionTracker: create_tables succeeds", "[execution_tracker][db]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables(); // should not crash
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

TEST_CASE("ExecutionTracker: create execution with parameter_values", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto exec = make_execution();
    exec.parameter_values = R"({"timeout": 30, "force": true})";
    auto result = tracker.create_execution(exec);
    REQUIRE(result.has_value());

    auto fetched = tracker.get_execution(*result);
    REQUIRE(fetched.has_value());
    CHECK(fetched->parameter_values == exec.parameter_values);
}

// ── Get Execution ──────────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: get execution", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

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

TEST_CASE("ExecutionTracker: get nonexistent returns empty", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto result = tracker.get_execution("nonexistent-id");
    CHECK(!result.has_value());
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
    REQUIRE(id2_result.has_value());
    tracker.mark_cancelled(*id1_result, "admin");

    ExecutionQuery q;
    q.status = "cancelled";
    auto results = tracker.query_executions(q);
    REQUIRE(results.size() == 1);
    CHECK(results[0].id == *id1_result);
}

TEST_CASE("ExecutionTracker: query with limit", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

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
          "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

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
          "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

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

TEST_CASE("ExecutionTracker: get_agent_statuses multiple agents", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

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
          "[execution_tracker][issue872]") {
    // Out-of-band dispatches that bypass the workflow-routes create path
    // (CLI / direct gRPC / re-mapped command_id) can reach
    // update_agent_status with an execution_id that has no row in the
    // `executions` table. The mutator must tolerate this — no crash, no
    // SQL constraint violation. The chained refresh_counts must likewise
    // return cleanly when there is nothing to aggregate.
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

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
          "[execution_tracker][issue872]") {
    // UAT 2026-05-06 fix 18e8766 chained refresh_counts inside
    // update_agent_status so callers no longer need an explicit refresh.
    // The `test_rest_api_t2.cpp` cleanup in PR #1068 dropped 7 redundant
    // explicit calls based on this chain. If a future refactor breaks the
    // chain (e.g. moves refresh behind a flag or an async queue),
    // test_rest_api_t2.cpp's lower-bound assertions (>= 2) would still
    // pass with stale aggregates — only the workflow_routes terminal-
    // threshold test would bite. This case pins the chain at the mutator
    // itself so any chain-break fails ONE focused test with a clear name.
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

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

TEST_CASE("ExecutionTracker: get_summary", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto exec = make_execution();
    exec.agents_targeted = 4;
    auto id_result = tracker.create_execution(exec);
    REQUIRE(id_result.has_value());

    auto summary = tracker.get_summary(*id_result);
    CHECK(summary.id == *id_result);
    CHECK(summary.agents_targeted == 4);
}

TEST_CASE("ExecutionTracker: summary after refresh_counts", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

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

// ── Parent-Child Hierarchy ─────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: parent-child relationship", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

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

TEST_CASE("ExecutionTracker: multiple children", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

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
          "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    auto children = tracker.get_children(*id_result);
    CHECK(children.empty());
}

// ── Rerun ──────────────────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: create_rerun all agents", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

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

TEST_CASE("ExecutionTracker: create_rerun failed_only", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

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

TEST_CASE("ExecutionTracker: create_rerun nonexistent fails", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto rerun_result = tracker.create_rerun("nonexistent-id", "admin", false);
    CHECK(!rerun_result.has_value());
}

// ── Mark Cancelled ─────────────────────────────────────────────────────────

TEST_CASE("ExecutionTracker: mark_cancelled", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());

    tracker.mark_cancelled(*id_result, "admin");

    auto exec = tracker.get_execution(*id_result);
    REQUIRE(exec.has_value());
    CHECK(exec->status == "cancelled");
    CHECK(exec->completed_at > 0);
}

TEST_CASE("ExecutionTracker: mark_cancelled sets completed_at", "[execution_tracker]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

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
          "[execution_tracker][cc07]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

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
          "[execution_tracker][cc07]") {
    TestDb tdb;
    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

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

// ── UP-12 / A-5 / D4(a): v2 pre-migration predecessor guard ─────────────────
//
// The v2 probe pre-stamps schema_meta to 2 when it finds plugin_result_status
// already present on a schema_meta=0 dev DB (an iterated build that manually
// added the column ahead of time), so MigrationRunner's ALTER doesn't hit
// "duplicate column name". Because v1 creates the tables AND their indexes
// in one migration, the guard must also confirm v1's index actually exists
// before stamping — otherwise it silently skips v1's CREATE INDEX forever.

namespace {
// CDX-P1-04: `omit_index` lets a test build a schema where SOME but not ALL of
// v1's four indexes exist — the exact partial-repair state the single-index
// guard (checking only idx_agent_exec_agent) could not distinguish from a
// fully-applied v1.
void create_v1_schema_by_hand(sqlite3* db, bool with_index, const char* omit_index = nullptr) {
    std::string sql = R"(
        CREATE TABLE executions (
            id TEXT PRIMARY KEY,
            definition_id TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            scope_expression TEXT NOT NULL DEFAULT '',
            parameter_values TEXT NOT NULL DEFAULT '',
            dispatched_by TEXT NOT NULL DEFAULT '',
            dispatched_at INTEGER NOT NULL DEFAULT 0,
            agents_targeted INTEGER NOT NULL DEFAULT 0,
            agents_responded INTEGER NOT NULL DEFAULT 0,
            agents_success INTEGER NOT NULL DEFAULT 0,
            agents_failure INTEGER NOT NULL DEFAULT 0,
            completed_at INTEGER NOT NULL DEFAULT 0,
            parent_id TEXT NOT NULL DEFAULT '',
            rerun_of TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE agent_exec_status (
            execution_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            dispatched_at INTEGER NOT NULL DEFAULT 0,
            first_response_at INTEGER NOT NULL DEFAULT 0,
            completed_at INTEGER NOT NULL DEFAULT 0,
            exit_code INTEGER NOT NULL DEFAULT 0,
            error_detail TEXT NOT NULL DEFAULT '',
            plugin_result_status INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (execution_id, agent_id)
        );
    )";
    if (with_index) {
        for (const auto& [name, stmt] :
             {std::pair{"idx_executions_status",
                        "CREATE INDEX idx_executions_status ON executions(status);"},
              std::pair{"idx_agent_exec_agent",
                        "CREATE INDEX idx_agent_exec_agent ON agent_exec_status(agent_id);"},
              std::pair{"idx_executions_dispatched",
                        "CREATE INDEX idx_executions_dispatched ON executions(dispatched_at);"},
              std::pair{"idx_executions_definition",
                        "CREATE INDEX idx_executions_definition ON executions(definition_id);"}}) {
            if (omit_index && std::string(name) == omit_index)
                continue;
            sql += stmt;
        }
    }
    REQUIRE(sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
}

bool index_exists(sqlite3* db, const char* name) {
    sqlite3_stmt* stmt = nullptr;
    bool exists = false;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?", -1,
                          &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
        exists = (sqlite3_step(stmt) == SQLITE_ROW);
    }
    sqlite3_finalize(stmt);
    return exists;
}
} // namespace

TEST_CASE("ExecutionTracker: v2 probe stamps straight through when v1's index is "
          "also already present",
          "[execution_tracker][migration]") {
    TestDb tdb;
    // The realistic "iterated build" case: v1 fully happened by hand (table +
    // index), and the column was pre-added too, but schema_meta reads as
    // untracked (0) — e.g. the meta table was reset independently of the
    // data. The guard should stamp straight to v2 without re-running v1 or
    // hitting the v2 ALTER's duplicate-column error.
    create_v1_schema_by_hand(tdb.db, /*with_index=*/true);

    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    CHECK(tracker.schema_ok());
    CHECK(index_exists(tdb.db, "idx_agent_exec_agent"));

    // And the store is actually usable afterward.
    auto id_result = tracker.create_execution(make_execution());
    REQUIRE(id_result.has_value());
    AgentExecStatus s;
    s.agent_id = "agent-1";
    s.status = "success";
    s.plugin_result_status = 4;
    tracker.update_agent_status(*id_result, s);
    auto statuses = tracker.get_agent_statuses(*id_result);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].plugin_result_status == 4);
}

TEST_CASE("ExecutionTracker: v2 probe does not silently skip v1's CREATE INDEX "
          "when only the column pre-exists",
          "[execution_tracker][migration]") {
    TestDb tdb;
    // The inconsistent state the missing guard let through: the v2 column is
    // present but v1's index never was (hand-rolled schema surgery), and
    // schema_meta reads as untracked (0). Without the predecessor guard, the
    // probe stamps schema_meta straight to 2, MigrationRunner::run() then has
    // nothing left with version > 2 to apply, and idx_agent_exec_agent is
    // never created — silently, with no error. The guard must refuse to
    // stamp in this case instead.
    create_v1_schema_by_hand(tdb.db, /*with_index=*/false);
    REQUIRE(index_exists(tdb.db, "idx_agent_exec_agent") == false);

    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    // v1 (idempotent CREATE TABLE/INDEX) now runs and creates the index —
    // the guard no longer lets it be skipped silently.
    CHECK(index_exists(tdb.db, "idx_agent_exec_agent"));
    // v2's ALTER then genuinely collides with the pre-added column: the
    // failure surfaces loudly via schema_ok(), which is the documented
    // contract (see ExecutionTracker::schema_ok()) for a migration that
    // didn't fully apply — not a silent, permanently-missing index.
    CHECK_FALSE(tracker.schema_ok());
}

TEST_CASE("ExecutionTracker: v2 probe refuses to stamp when only SOME of v1's "
          "indexes are present (CDX-P1-04)",
          "[execution_tracker][migration]") {
    TestDb tdb;
    // idx_agent_exec_agent (the ONE index the pre-fix guard checked) is
    // present, but idx_executions_status — one of v1's other three — is
    // missing (e.g. hand-rolled schema surgery that only rebuilt one index).
    // A guard that checks only idx_agent_exec_agent cannot see this and would
    // stamp straight to v2, permanently skipping v1's CREATE INDEX for the
    // missing one. Requiring ALL FOUR must refuse to stamp here too.
    create_v1_schema_by_hand(tdb.db, /*with_index=*/true,
                             /*omit_index=*/"idx_executions_status");
    REQUIRE(index_exists(tdb.db, "idx_agent_exec_agent"));
    REQUIRE(index_exists(tdb.db, "idx_executions_status") == false);

    ExecutionTracker tracker(tdb.db);
    tracker.create_tables();

    // v1 (idempotent CREATE TABLE/INDEX) now re-runs and creates the missing
    // index — under the pre-fix single-index guard this assertion fails,
    // because that guard stamped schema_meta straight to 2 and v1 never ran.
    CHECK(index_exists(tdb.db, "idx_executions_status"));
    // v2's ALTER then genuinely collides with the pre-added column, exactly
    // as the all-indexes-missing case above — the documented loud-failure
    // contract, not a silent gap.
    CHECK_FALSE(tracker.schema_ok());
}
