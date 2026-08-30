/**
 * test_workflow_engine.cpp — Unit tests for WorkflowEngine (Postgres-backed, ADR-0006/0009/0064
 * migration, schema `workflow_engine`).
 *
 * The pre-migration store had ZERO tests of its own (test_workflow_routes.cpp only exercised the
 * `/fragments/executions` dashboard surface via an opt-in ExecHarness-constructed WorkflowEngine).
 * This file is the first direct coverage of the store's own methods.
 *
 * Covers: create/list/get workflow, create-workflow validation, soft-delete semantics (ADR-0064:
 * first delete succeeds, second delete/unknown id is not_found, history survives delete, a
 * concurrent delete during a running execution does not destroy that execution), execute() with a
 * stub StepDispatchFn (happy path, retry, on_failure=abort skip-remaining), cancel_execution,
 * list_executions, the degrade path (migration failure → is_open()==false → every method reports
 * a typed kDbErrorPrefix failure), and the schema-level FK invariant (workflow_executions →
 * workflows has no cascade — a direct hard DELETE while history exists is rejected).
 */

#include "workflow_engine.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "store_errors.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <stdexcept>
#include <string>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Pre-migrated template (docs/postgres-store-playbook.md step 7). Every store-behaviour case
// clones this instead of re-migrating per test.
yuzu::test::PgTestTemplate workflow_engine_tpl{
    "wfengine", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        WorkflowEngine engine{pool};
        if (!engine.is_open())
            throw std::runtime_error("workflow_engine template: store failed to migrate");
    }};

const std::string kOneStepYaml = "kind: Workflow\n"
                                 "metadata:\n"
                                 "  displayName: one-step\n"
                                 "spec:\n"
                                 "  steps:\n"
                                 "    - instruction: inst-1\n"
                                 "      label: step one\n";

const std::string kTwoStepYaml = "kind: Workflow\n"
                                 "metadata:\n"
                                 "  displayName: two-step\n"
                                 "spec:\n"
                                 "  steps:\n"
                                 "    - instruction: inst-1\n"
                                 "      label: step one\n"
                                 "    - instruction: inst-2\n"
                                 "      label: step two\n";

/// Always-succeed dispatch stub.
StepDispatchFn ok_dispatch_fn() {
    return [](const std::string&, const std::string&,
              const std::string&) -> std::expected<std::string, std::string> {
        return std::string(R"({"status":"ok"})");
    };
}

} // namespace

// Fixture: a fresh cloned PG database, a pool, and an open WorkflowEngine. The db/pool must
// outlive `engine_var` — declaring all three here keeps that order.
#define WORKFLOW_ENGINE(engine_var)                                                               \
    YUZU_REQUIRE_PG_DB_TPL(wf_db_fx_, workflow_engine_tpl);                                       \
    PgPool wf_pool_fx_{{.conninfo = wf_db_fx_.dsn(), .size = 4}};                                 \
    REQUIRE(wf_pool_fx_.valid());                                                                  \
    WorkflowEngine engine_var{wf_pool_fx_};                                                        \
    REQUIRE(engine_var.is_open())

// ── Create / list / get ──────────────────────────────────────────────────────

TEST_CASE("WorkflowEngine: create, get, list round trip", "[workflow_engine][pg][crud]") {
    WORKFLOW_ENGINE(engine);

    auto id_result = engine.create_workflow(kTwoStepYaml);
    REQUIRE(id_result.has_value());
    const auto id = *id_result;
    CHECK_FALSE(id.empty());

    auto got = engine.get_workflow(id);
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->id == id);
    CHECK((*got)->name == "two-step");
    REQUIRE((*got)->steps.size() == 2);
    CHECK((*got)->steps[0].instruction_id == "inst-1");
    CHECK((*got)->steps[1].instruction_id == "inst-2");

    auto listed = engine.list_workflows();
    REQUIRE(listed.has_value());
    REQUIRE(listed->size() == 1);
    CHECK((*listed)[0].id == id);
    CHECK((*listed)[0].steps.size() == 2); // list_workflows loads steps too
}

TEST_CASE("WorkflowEngine: get_workflow on unknown id is a successful not-found",
          "[workflow_engine][pg][crud]") {
    WORKFLOW_ENGINE(engine);
    auto got = engine.get_workflow("does-not-exist");
    REQUIRE(got.has_value());        // no DB error
    CHECK_FALSE(got->has_value());   // just absent
}

TEST_CASE("WorkflowEngine: list_workflows filters by name and respects limit",
          "[workflow_engine][pg][crud]") {
    WORKFLOW_ENGINE(engine);
    REQUIRE(engine.create_workflow(kOneStepYaml).has_value());  // "one-step"
    REQUIRE(engine.create_workflow(kTwoStepYaml).has_value());  // "two-step"

    WorkflowQuery q;
    q.name_filter = "one";
    auto filtered = engine.list_workflows(q);
    REQUIRE(filtered.has_value());
    REQUIRE(filtered->size() == 1);
    CHECK((*filtered)[0].name == "one-step");

    // Case-insensitive (SQLite-era LIKE semantics preserved as ILIKE).
    WorkflowQuery q_upper;
    q_upper.name_filter = "ONE-STEP";
    auto filtered_upper = engine.list_workflows(q_upper);
    REQUIRE(filtered_upper.has_value());
    CHECK(filtered_upper->size() == 1);
}

TEST_CASE("WorkflowEngine: create_workflow validates kind/name/steps",
          "[workflow_engine][pg][validation]") {
    WORKFLOW_ENGINE(engine);

    // #3503 review finding: create_workflow()'s wrong-kind path routes through the shared
    // kind_mismatch_error() helper (test_store_errors.cpp pins the helper's own raw two-argument
    // level; this pins it through the real call site, matching PolicyStore's equivalent case).
    auto wrong_kind = engine.create_workflow("kind: Policy\nmetadata:\n  displayName: oops\n");
    REQUIRE_FALSE(wrong_kind.has_value());
    CHECK(wrong_kind.error() ==
          "kind must be 'Workflow', got 'Policy'. yaml_source must be a "
          "complete YAML document including 'apiVersion: yuzu.io/v1alpha1' "
          "and 'kind: Workflow'.");

    auto no_name = engine.create_workflow("kind: Workflow\nspec:\n  steps:\n"
                                          "    - instruction: inst-1\n");
    REQUIRE_FALSE(no_name.has_value());
    CHECK(no_name.error().find("name is required") != std::string::npos);

    auto no_steps = engine.create_workflow("kind: Workflow\nmetadata:\n  name: empty\n");
    REQUIRE_FALSE(no_steps.has_value());
    CHECK(no_steps.error().find("at least one step") != std::string::npos);

    auto missing_instruction = engine.create_workflow(
        "kind: Workflow\nmetadata:\n  name: bad\nspec:\n  steps:\n    - label: no instruction\n");
    REQUIRE_FALSE(missing_instruction.has_value());
}

// ── Soft-delete (ADR-0064) ───────────────────────────────────────────────────

TEST_CASE("WorkflowEngine: delete_workflow soft-deletes — first succeeds, second is not_found",
          "[workflow_engine][pg][delete]") {
    WORKFLOW_ENGINE(engine);
    auto id = *engine.create_workflow(kOneStepYaml);

    auto first = engine.delete_workflow(id);
    REQUIRE(first.has_value());

    auto second = engine.delete_workflow(id);
    REQUIRE_FALSE(second.has_value());
    CHECK(second.error().starts_with("not_found:"));

    // Soft-deleted — absent from ordinary reads.
    auto got = engine.get_workflow(id);
    REQUIRE(got.has_value());
    CHECK_FALSE(got->has_value());
    auto listed = engine.list_workflows();
    REQUIRE(listed.has_value());
    CHECK(listed->empty());
}

TEST_CASE("WorkflowEngine: delete_workflow on an unknown id is not_found",
          "[workflow_engine][pg][delete]") {
    WORKFLOW_ENGINE(engine);
    auto del = engine.delete_workflow("never-existed");
    REQUIRE_FALSE(del.has_value());
    CHECK(del.error().starts_with("not_found:"));
}

TEST_CASE("WorkflowEngine: delete-after-execution — history survives (ADR-0064 point 3)",
          "[workflow_engine][pg][delete][execute]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kOneStepYaml);

    auto exec_result = engine.execute(wf_id, {"agent-1"}, ok_dispatch_fn());
    REQUIRE(exec_result.has_value());
    const auto exec_id = *exec_result;

    auto del = engine.delete_workflow(wf_id);
    REQUIRE(del.has_value());

    // Execution history is untouched by the soft-delete — still fully queryable.
    auto exec = engine.get_execution(exec_id);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->id == exec_id);
    CHECK((*exec)->status == "completed");
    REQUIRE((*exec)->step_results.size() == 1);
    CHECK((*exec)->step_results[0].status == "success");

    auto execs = engine.list_executions(wf_id);
    REQUIRE(execs.has_value());
    REQUIRE(execs->size() == 1);
}

TEST_CASE("WorkflowEngine: execute() admission race — a workflow deleted before execute() fails "
          "the same way as one that never existed",
          "[workflow_engine][pg][delete][execute]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kOneStepYaml);
    REQUIRE(engine.delete_workflow(wf_id).has_value());

    auto exec_result = engine.execute(wf_id, {"agent-1"}, ok_dispatch_fn());
    REQUIRE_FALSE(exec_result.has_value());
    CHECK(exec_result.error().find("workflow not found") != std::string::npos);
}

TEST_CASE("WorkflowEngine: delete-during-running — a concurrent delete does not destroy an "
          "in-flight execution's history",
          "[workflow_engine][pg][delete][execute]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kOneStepYaml);

    // Dispatch stub deletes the workflow mid-execution (after admission, before the step
    // finishes) — proves execute() finishes cleanly and the execution stays queryable, matching
    // ADR-0064 point 3 ("an execution admitted before deletion may finish and remain queryable").
    StepDispatchFn delete_mid_dispatch =
        [&engine, &wf_id](const std::string&, const std::string&,
                          const std::string&) -> std::expected<std::string, std::string> {
        auto del = engine.delete_workflow(wf_id);
        REQUIRE(del.has_value());
        return std::string(R"({"status":"ok"})");
    };

    auto exec_result = engine.execute(wf_id, {"agent-1"}, delete_mid_dispatch);
    REQUIRE(exec_result.has_value()); // admitted before the mid-dispatch delete — completes
    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "completed");

    // Workflow itself is now soft-deleted.
    CHECK_FALSE(engine.get_workflow(wf_id)->has_value());
}

// ── Execute ───────────────────────────────────────────────────────────────

TEST_CASE("WorkflowEngine: execute happy path records step results",
          "[workflow_engine][pg][execute]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kTwoStepYaml);

    auto exec_result = engine.execute(wf_id, {"agent-1", "agent-2"}, ok_dispatch_fn());
    REQUIRE(exec_result.has_value());

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "completed");
    CHECK((*exec)->workflow_id == wf_id);
    REQUIRE((*exec)->step_results.size() == 2);
    CHECK((*exec)->step_results[0].status == "success");
    CHECK((*exec)->step_results[1].status == "success");
}

TEST_CASE("WorkflowEngine: execute requires a dispatch function", "[workflow_engine][pg][execute]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kOneStepYaml);
    auto exec_result = engine.execute(wf_id, {"agent-1"}, nullptr);
    REQUIRE_FALSE(exec_result.has_value());
}

TEST_CASE("WorkflowEngine: execute against an unknown workflow id fails",
          "[workflow_engine][pg][execute]") {
    WORKFLOW_ENGINE(engine);
    auto exec_result = engine.execute("nope", {"agent-1"}, ok_dispatch_fn());
    REQUIRE_FALSE(exec_result.has_value());
    CHECK(exec_result.error().find("workflow not found") != std::string::npos);
}

TEST_CASE("WorkflowEngine: execute retries a failing step then succeeds",
          "[workflow_engine][pg][execute][retry]") {
    WORKFLOW_ENGINE(engine);
    const std::string yaml = "kind: Workflow\nmetadata:\n  name: retry-wf\nspec:\n  steps:\n"
                             "    - instruction: inst-1\n"
                             "      retryCount: 2\n"
                             "      retryDelay: 0\n";
    auto wf_id = *engine.create_workflow(yaml);

    int attempts = 0;
    StepDispatchFn flaky = [&attempts](const std::string&, const std::string&,
                                       const std::string&) -> std::expected<std::string, std::string> {
        ++attempts;
        if (attempts < 2)
            return std::unexpected("transient failure");
        return std::string(R"({"status":"ok"})");
    };

    auto exec_result = engine.execute(wf_id, {"agent-1"}, flaky);
    REQUIRE(exec_result.has_value());
    CHECK(attempts == 2);

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "completed");
    REQUIRE((*exec)->step_results.size() == 1);
    CHECK((*exec)->step_results[0].status == "success");
    // Pre-existing semantics, preserved by the port: the attempt column is written only on a
    // FAILED attempt (inside the retry branch); a successful attempt breaks the loop before that
    // write, so the stored value is the last FAILED attempt number (1), not the successful one (2).
    CHECK((*exec)->step_results[0].attempt == 1);
}

TEST_CASE("WorkflowEngine: execute on_failure=abort (default) skips remaining steps",
          "[workflow_engine][pg][execute]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kTwoStepYaml);

    StepDispatchFn fail_first =
        [](const std::string& instruction_id, const std::string&,
           const std::string&) -> std::expected<std::string, std::string> {
        if (instruction_id == "inst-1")
            return std::unexpected("boom");
        return std::string(R"({"status":"ok"})");
    };

    auto exec_result = engine.execute(wf_id, {"agent-1"}, fail_first);
    REQUIRE(exec_result.has_value());

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "failed");
    REQUIRE((*exec)->step_results.size() == 2);
    CHECK((*exec)->step_results[0].status == "failed");
    CHECK((*exec)->step_results[1].status == "skipped");
}

TEST_CASE("WorkflowEngine: execute on_failure=continue proceeds past a failed step",
          "[workflow_engine][pg][execute]") {
    WORKFLOW_ENGINE(engine);
    const std::string yaml = "kind: Workflow\nmetadata:\n  name: continue-wf\nspec:\n  steps:\n"
                             "    - instruction: inst-1\n"
                             "      onFailure: continue\n"
                             "    - instruction: inst-2\n";

    auto wf_id = *engine.create_workflow(yaml);

    StepDispatchFn fail_first =
        [](const std::string& instruction_id, const std::string&,
           const std::string&) -> std::expected<std::string, std::string> {
        if (instruction_id == "inst-1")
            return std::unexpected("boom");
        return std::string(R"({"status":"ok"})");
    };

    auto exec_result = engine.execute(wf_id, {"agent-1"}, fail_first);
    REQUIRE(exec_result.has_value());

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    // The second step still ran (not skipped) despite the first failing, so the overall
    // execution completes rather than failing.
    CHECK((*exec)->status == "completed");
    REQUIRE((*exec)->step_results.size() == 2);
    CHECK((*exec)->step_results[0].status == "failed");
    CHECK((*exec)->step_results[1].status == "success");
}

TEST_CASE("WorkflowEngine: execute retries exhaust and the step is recorded failed",
          "[workflow_engine][pg][execute][retry]") {
    WORKFLOW_ENGINE(engine);
    const std::string yaml = "kind: Workflow\nmetadata:\n  name: retry-exhaust-wf\nspec:\n  steps:\n"
                             "    - instruction: inst-1\n"
                             "      retryCount: 2\n"
                             "      retryDelay: 0\n";
    auto wf_id = *engine.create_workflow(yaml);

    int attempts = 0;
    StepDispatchFn always_fail =
        [&attempts](const std::string&, const std::string&,
                   const std::string&) -> std::expected<std::string, std::string> {
        ++attempts;
        return std::unexpected("boom");
    };

    auto exec_result = engine.execute(wf_id, {"agent-1"}, always_fail);
    REQUIRE(exec_result.has_value());
    CHECK(attempts == 3); // 1 initial + 2 retries, all exhausted

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "failed");
    REQUIRE((*exec)->step_results.size() == 1);
    CHECK((*exec)->step_results[0].status == "failed");
    CHECK((*exec)->step_results[0].attempt == 3); // the last (also failed) attempt number
}

TEST_CASE("WorkflowEngine: execute skips a step whose condition evaluates false",
          "[workflow_engine][pg][execute]") {
    WORKFLOW_ENGINE(engine);
    const std::string yaml = "kind: Workflow\nmetadata:\n  name: cond-wf\nspec:\n  steps:\n"
                             "    - instruction: inst-1\n"
                             "    - instruction: inst-2\n"
                             "      condition: skip-me\n";
    auto wf_id = *engine.create_workflow(yaml);

    bool condition_called = false;
    ConditionEvalFn deny_all = [&condition_called](const std::string& expr,
                                                   const std::map<std::string, std::string>&) {
        condition_called = true;
        CHECK(expr == "skip-me");
        return false;
    };

    auto exec_result = engine.execute(wf_id, {"agent-1"}, ok_dispatch_fn(), deny_all);
    REQUIRE(exec_result.has_value());
    CHECK(condition_called);

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "completed");
    REQUIRE((*exec)->step_results.size() == 2);
    CHECK((*exec)->step_results[0].status == "success");
    CHECK((*exec)->step_results[1].status == "skipped");
}

TEST_CASE("WorkflowEngine: execute expands a foreach step and aggregates per-item results",
          "[workflow_engine][pg][execute]") {
    WORKFLOW_ENGINE(engine);
    const std::string yaml = "kind: Workflow\nmetadata:\n  name: foreach-wf\nspec:\n  steps:\n"
                             "    - instruction: inst-1\n"
                             "    - instruction: inst-2\n"
                             "      foreach: items\n";
    auto wf_id = *engine.create_workflow(yaml);

    std::vector<std::string> foreach_params_seen;
    StepDispatchFn dispatch = [&foreach_params_seen](
                                  const std::string& instruction_id, const std::string&,
                                  const std::string& params) -> std::expected<std::string, std::string> {
        if (instruction_id == "inst-1")
            return std::string(R"({"items":["a","b"]})");
        foreach_params_seen.push_back(params);
        return std::string(R"({"status":"ok"})");
    };

    auto exec_result = engine.execute(wf_id, {"agent-1"}, dispatch);
    REQUIRE(exec_result.has_value());
    // The "items" array from step 1's result drove two separate dispatch calls for step 2.
    REQUIRE(foreach_params_seen.size() == 2);
    CHECK(foreach_params_seen[0] == "\"a\"");
    CHECK(foreach_params_seen[1] == "\"b\"");

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "completed");
    REQUIRE((*exec)->step_results.size() == 2);
    CHECK((*exec)->step_results[1].status == "success");
}

// ── Cancel ────────────────────────────────────────────────────────────────

TEST_CASE("WorkflowEngine: cancel_execution rejects an unknown id",
          "[workflow_engine][pg][cancel]") {
    WORKFLOW_ENGINE(engine);
    auto cancel = engine.cancel_execution("nope");
    REQUIRE_FALSE(cancel.has_value());
    CHECK(cancel.error() == "execution not found");
}

TEST_CASE("WorkflowEngine: cancel_execution rejects a terminal execution",
          "[workflow_engine][pg][cancel]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kOneStepYaml);
    auto exec_id = *engine.execute(wf_id, {"agent-1"}, ok_dispatch_fn());

    auto cancel = engine.cancel_execution(exec_id);
    REQUIRE_FALSE(cancel.has_value()); // already "completed"
    CHECK(cancel.error().find("already") != std::string::npos);
}

TEST_CASE("WorkflowEngine: cancel_execution mid-run stops subsequent steps",
          "[workflow_engine][pg][cancel]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kTwoStepYaml);

    // execute() creates the execution row (status=running) before the first dispatch call, so
    // the stub can look it up via list_executions() and cancel it from inside step 0's dispatch —
    // proving the cancellation check at the top of step 1's loop iteration takes effect.
    auto exec_result = engine.execute(
        wf_id, {"agent-1"},
        [&engine, &wf_id](const std::string&, const std::string&,
                          const std::string&) -> std::expected<std::string, std::string> {
            auto execs = engine.list_executions(wf_id, 1);
            REQUIRE(execs.has_value());
            REQUIRE_FALSE(execs->empty());
            REQUIRE(engine.cancel_execution((*execs)[0].id).has_value());
            return std::string(R"({"status":"ok"})");
        });
    REQUIRE(exec_result.has_value());

    auto exec = engine.get_execution(*exec_result);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    // Governance finding (cpp-expert): the finalize UPDATE is now guarded (`WHERE status =
    // 'running'`), so it no longer clobbers the "cancelled" status cancel_execution() already
    // committed — status stays "cancelled", not overwritten to "failed".
    CHECK((*exec)->status == "cancelled");
}

// ── Degrade path ──────────────────────────────────────────────────────────

TEST_CASE("WorkflowEngine reports !is_open on a migration failure and every method degrades",
          "[workflow_engine][pg]") {
    YUZU_REQUIRE_PG_DB(db);

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA workflow_engine")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE workflow_engine.bogus (x int)")};
        REQUIRE(t.ok());
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    WorkflowEngine engine{pool};
    CHECK_FALSE(engine.is_open()); // → server.cpp sets startup_failed_ = true

    auto create_result = engine.create_workflow(kOneStepYaml);
    REQUIRE_FALSE(create_result.has_value());
    CHECK(create_result.error().starts_with(kDbErrorPrefix));

    auto list_result = engine.list_workflows();
    REQUIRE_FALSE(list_result.has_value());
    CHECK(list_result.error().starts_with(kDbErrorPrefix));

    auto get_result = engine.get_workflow("anything");
    REQUIRE_FALSE(get_result.has_value());
    CHECK(get_result.error().starts_with(kDbErrorPrefix));

    auto del_result = engine.delete_workflow("anything");
    REQUIRE_FALSE(del_result.has_value());
    CHECK(del_result.error().starts_with(kDbErrorPrefix));

    auto exec_result = engine.execute("anything", {"agent-1"}, ok_dispatch_fn());
    REQUIRE_FALSE(exec_result.has_value());
    CHECK(exec_result.error().starts_with(kDbErrorPrefix));

    auto get_exec_result = engine.get_execution("anything");
    REQUIRE_FALSE(get_exec_result.has_value());
    CHECK(get_exec_result.error().starts_with(kDbErrorPrefix));

    auto list_exec_result = engine.list_executions();
    REQUIRE_FALSE(list_exec_result.has_value());
    CHECK(list_exec_result.error().starts_with(kDbErrorPrefix));

    auto cancel_result = engine.cancel_execution("anything");
    REQUIRE_FALSE(cancel_result.has_value());
    CHECK(cancel_result.error().starts_with(kDbErrorPrefix));
}

// ── Schema invariant ──────────────────────────────────────────────────────

TEST_CASE("WorkflowEngine schema: workflow_executions -> workflows has no cascade (ADR-0064)",
          "[workflow_engine][pg][schema]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kOneStepYaml);
    REQUIRE(engine.execute(wf_id, {"agent-1"}, ok_dispatch_fn()).has_value());

    // A direct hard DELETE (bypassing delete_workflow()'s soft-delete) must be rejected by the
    // FK while execution history exists — proves the schema itself enforces "history survives,
    // never silently cascades" independent of the store's own application-level logic.
    PgConn conn{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult del = yuzu::server::pg::exec_params(
        conn.get(), "DELETE FROM workflow_engine.workflows WHERE id = $1",
        std::vector<std::string>{wf_id});
    CHECK(del.status() == PGRES_FATAL_ERROR); // FK violation — RESTRICT/NO ACTION, not CASCADE
}

// ── Child-read failure propagation (adversarial-review CDX-P1-001/WF-3) ──────
//
// A genuine child-table query failure must surface as a typed kDbErrorPrefix failure, never as
// a successful parent row with silently-empty children — the bug this closes: the parent read
// was widened to std::expected, but wf_load_steps()/get_execution()'s step-results load kept
// the SQLite-era fail-soft shape underneath it. Each case drops the child table via a second raw
// connection to force a real query failure (not a mock), then asserts the typed-failure contract.

TEST_CASE("WorkflowEngine: get_workflow surfaces a genuine workflow_steps query failure as "
          "kDbErrorPrefix, not an empty steps list",
          "[workflow_engine][pg][crud][degrade]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kOneStepYaml);

    PgConn conn{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult drop = yuzu::server::pg::exec_params(
        conn.get(), "DROP TABLE workflow_engine.workflow_steps", std::vector<std::string>{});
    REQUIRE(drop.status() == PGRES_COMMAND_OK);

    auto got = engine.get_workflow(wf_id);
    REQUIRE_FALSE(got.has_value());
    CHECK(got.error().starts_with(kDbErrorPrefix));

    auto listed = engine.list_workflows();
    REQUIRE_FALSE(listed.has_value());
    CHECK(listed.error().starts_with(kDbErrorPrefix));
}

TEST_CASE("WorkflowEngine: get_execution surfaces a genuine workflow_step_results query "
          "failure as kDbErrorPrefix, not an execution with empty step_results",
          "[workflow_engine][pg][execute][degrade]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kOneStepYaml);
    auto exec_id = *engine.execute(wf_id, {"agent-1"}, ok_dispatch_fn());

    PgConn conn{PQconnectdb(wf_db_fx_.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult drop = yuzu::server::pg::exec_params(
        conn.get(), "DROP TABLE workflow_engine.workflow_step_results",
        std::vector<std::string>{});
    REQUIRE(drop.status() == PGRES_COMMAND_OK);

    auto exec = engine.get_execution(exec_id);
    REQUIRE_FALSE(exec.has_value());
    CHECK(exec.error().starts_with(kDbErrorPrefix));
}

// ── cancel_execution atomicity (adversarial-review CDX-P1-003/WF-2/WF-5) ─────
//
// Governance finding (quality-engineer, Gate 3): a genuine concurrent race between
// cancel_execution()'s SELECT-then-UPDATE and a racing execute() finalize cannot be reproduced
// deterministically at the API level — no thread interleaves inside one SQL statement, and a
// probabilistic thread/sleep-based stress test would violate this repo's test-determinism
// convention. The single-statement `UPDATE ... WHERE status IN ('pending','running') RETURNING
// id` shape (workflow_engine.cpp) is the actual closure evidence for the race — it is atomic by
// construction and reviewable directly in the diff, not something this test proves. What the
// case below DOES prove, and is exactly what it is named for: cancelling an execution that is
// ALREADY terminal (the common non-concurrent case, and the only shape reachable at the API
// today) reports the already-terminal message and never overwrites the row — a real, useful
// assertion, but not a race/atomicity proof. Do not re-add an "atomicity" framing here without a
// genuine concurrent reproduction.

TEST_CASE("WorkflowEngine: cancel_execution on an already-terminal execution reports "
          "already-terminal and never overwrites its status",
          "[workflow_engine][pg][cancel]") {
    WORKFLOW_ENGINE(engine);
    auto wf_id = *engine.create_workflow(kOneStepYaml);
    auto exec_id = *engine.execute(wf_id, {"agent-1"}, ok_dispatch_fn());

    // Already terminal ("completed") — the guarded UPDATE...WHERE status IN (...) matches zero
    // rows, so cancel must report the already-terminal message, never silently overwrite it.
    auto cancel = engine.cancel_execution(exec_id);
    REQUIRE_FALSE(cancel.has_value());
    CHECK(cancel.error() == "execution is already completed");

    auto exec = engine.get_execution(exec_id);
    REQUIRE(exec.has_value());
    REQUIRE(exec->has_value());
    CHECK((*exec)->status == "completed"); // never overwritten to "cancelled"
}
