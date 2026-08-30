/**
 * test_schedule_runner.cpp — Unit tests for the recurring-schedule poller
 * (ScheduleRunner, #1191).
 *
 * Strategy: real ScheduleEngine (Postgres, ADR-0065 migration-programme PR 5
 * commit 1/3) + real ExecutionTracker/ApprovalManager on one shared :memory:
 * SQLite handle (still the production shape for those two — they share
 * instructions.db until PR 5's later commits move them too), a real
 * InstructionStore on a temp DB, and a FAKE dispatch_fn that records calls
 * and returns a configurable reach count.
 * Due-ness is driven by creating schedules with next_execution_at in the
 * past (create_schedule honors an explicit value), so no clock injection is
 * needed.
 */

#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "schedule_engine.hpp"
#include "schedule_params_parsers.hpp"
#include "schedule_runner.hpp"

#include "../test_helpers.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <sqlite3.h>

#include <chrono>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;

namespace {

struct TestDb {
    sqlite3* db = nullptr;
    TestDb() { sqlite3_open(":memory:", &db); }
    ~TestDb() {
        if (db)
            sqlite3_close(db);
    }
};

struct DispatchCall {
    std::string plugin;
    std::string action;
    std::string scope;
    std::string execution_id;
    DispatchCaller caller;
    std::unordered_map<std::string, std::string> params;
};

// InstructionStore is now a migrated Postgres store (ADR-0058). ADR-0065
// migration-programme PR 5 commit 1/3 added ScheduleEngine and commit 2/3
// adds ApprovalManager to this same template/database (ADR-0008
// schema-per-store-on-one-connection) — this key has exactly one caller in
// the whole test tree (this file), so growing its setup function across PR
// 5's three commits is safe under the PgTestTemplate replay-fingerprint rule
// (no other TU shares this key, so there's no divergent setup to conflict
// with). Commit 3/3 will extend this further to also cover ExecutionTracker.
yuzu::test::PgTestTemplate schedrunner_instr_tpl{
    "schedrunnerinstr", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        InstructionStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("schedrunner instruction template: store failed to migrate");
        ScheduleEngine engine{pool};
        if (!engine.is_open())
            throw std::runtime_error("schedrunner schedule engine template: store failed to migrate");
        ApprovalManager approvals{pool};
        if (!approvals.is_open())
            throw std::runtime_error("schedrunner approval manager template: store failed to migrate");
    }};

// A trivial first-declared Harness member whose sole purpose is running the
// YUZU_REQUIRE_PG_DB_TPL skip-check BEFORE the non-movable PostgresTestDb/
// PgPool members below it construct (both delete their move ctor, so they
// cannot be built elsewhere and relocated in). SKIP() works correctly here
// because we're still within the dynamic extent of the TEST_CASE that
// constructs Harness — Catch2's macros don't care about call depth, only
// about running inside a live test case (Harness's own constructor body
// already relies on this same fact for its REQUIRE calls, below). Keeping
// every one of the 19 existing `Harness h;` / `Harness h(...)` call sites
// unchanged is the whole point of gating this way instead of threading a
// pg::PgPool& through the constructor.
struct PgSkipGate {
    PgSkipGate() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr)
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    }
};

struct Harness {
    PgSkipGate pg_gate_; // MUST stay the first declared member — see its own doc comment.
    yuzu::test::PostgresTestDb instr_db{schedrunner_instr_tpl};
    yuzu::server::pg::PgPool instr_pool{{.conninfo = instr_db.dsn(), .size = 2}};

    TestDb db; // shared by tracker (production shape; SQLite until PR 5
               // commit 3/3 moves it too)

    // ADR-0065 (migration-programme PR 5, 1-2/3): ScheduleEngine and
    // ApprovalManager now built on instr_pool (same ephemeral Postgres
    // database as InstructionStore below, schema-per-store) instead of the
    // shared SQLite `db` handle.
    ScheduleEngine engine{instr_pool};
    ExecutionTracker tracker{db.db};
    ApprovalManager approvals{instr_pool};
    InstructionStore is{instr_pool};

    std::vector<DispatchCall> calls;
    int reach{1};        // agents "reached" by the fake dispatch
    bool throw_on_dispatch{false};

    ScheduleRunner runner;

    // D7 (PLAN-003): default arming_check allows every fire, matching every
    // pre-D7 test's assumption that the schedule fires whenever nothing else
    // blocks it. D7-specific test cases pass `false` or an explicitly empty
    // ScheduleRunner::ArmingCheckFn{} to prove the deny/unset paths.
    explicit Harness(ScheduleRunner::ArmingCheckFn arming =
                          [](const std::string&, const std::string&, const std::string&) {
                              return true;
                          },
                      AuditStore* audit = nullptr, yuzu::MetricsRegistry* metrics_reg = nullptr,
                      InstructionStore* instruction_store_override = nullptr)
        : runner(ScheduleRunner::Deps{
              .schedule_engine = &engine,
              .instruction_store = instruction_store_override ? instruction_store_override : &is,
              .execution_tracker = &tracker,
              .approval_manager = &approvals,
              .audit_store = audit,
              .metrics = metrics_reg,
              .dispatch_fn =
                  [this](const std::string& plugin, const std::string& action,
                         const std::vector<std::string>&, const std::string& scope,
                         const std::unordered_map<std::string, std::string>& params,
                         const std::string& execution_id,
                         const DispatchCaller& caller) -> std::pair<std::string, int> {
                      if (throw_on_dispatch)
                          throw std::runtime_error("dispatch boom");
                      calls.push_back({plugin, action, scope, execution_id, caller, params});
                      return {"cmd-" + std::to_string(calls.size()), reach};
                  },
              // #3133 review fix: resolve_caller re-resolves a real,
              // non-system caller from the schedule's creator at fire time —
              // this fake mirrors that shape rather than a stale/system
              // caller, so a regression back to system=true is observable
              // via the DispatchCall.caller field above.
              .resolve_caller =
                  [](const std::string& username) {
                  return DispatchCaller{.principal = username, .system = false};
              },
              .arming_check = std::move(arming),
          }) {
        INFO("[schedrunner instr] fixture status (blank == database came up OK): "
             << instr_db.error());
        REQUIRE(instr_db.available());
        tracker.create_tables();
        approvals.create_tables();

        InstructionDefinition d;
        d.id = "test.def";
        d.name = "test.def";
        d.version = "1.0.0";
        d.type = "question";
        d.plugin = "procs";
        d.action = "list";
        d.enabled = true;
        REQUIRE(is.create_definition(d).has_value());

        InstructionDefinition gated = d;
        gated.id = "test.gated";
        gated.name = "test.gated";
        gated.approval_mode = "always";
        REQUIRE(is.create_definition(gated).has_value());
    }

    // A schedule that is due NOW (next_execution_at forced into the past).
    std::string make_due(const std::string& def_id, const std::string& freq,
                         bool requires_approval = false,
                         const std::string& parameters_json = "") {
        InstructionSchedule s;
        s.name = "sched-" + def_id + "-" + freq;
        s.definition_id = def_id;
        s.frequency_type = freq;
        s.interval_minutes = 60;
        s.scope_expression = "";
        s.requires_approval = requires_approval;
        s.enabled = true;
        s.created_by = "admin";
        s.next_execution_at = 1; // long past — due immediately
        s.parameter_values = parameters_json;
        auto id = engine.create_schedule(s);
        REQUIRE(id.has_value());
        return *id;
    }

    InstructionSchedule get(const std::string& id) {
        for (const auto& s : engine.query_schedules())
            if (s.id == id)
                return s;
        FAIL("schedule not found: " + id);
        return {};
    }

    // Force an already-advanced schedule due again (a "next occurrence").
    // ScheduleEngine now lives in Postgres (instr_pool) — poke it via a
    // second raw connection, same as the interval-floor test below.
    void force_due(const std::string& id) {
        yuzu::server::pg::PgConn conn{PQconnectdb(instr_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto sql =
            "UPDATE schedule_engine.schedules SET next_execution_at = 1 WHERE id = '" + id + "'";
        yuzu::server::pg::PgResult res{PQexec(conn.get(), sql.c_str())};
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }
};

} // namespace

TEST_CASE("ScheduleRunner: due interval schedule fires once and advances", "[schedule][runner][pg]") {
    Harness h;
    auto id = h.make_due("test.def", "interval");

    h.runner.tick();

    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].plugin == "procs");
    CHECK(h.calls[0].action == "list");
    REQUIRE_FALSE(h.calls[0].execution_id.empty());
    // #2500: a schedule carries no agent_ids, so an empty scope_expression is
    // how this path has always meant "the whole fleet" — by falling into the
    // dispatch sink's empty-means-everybody default, which that issue INVERTED
    // to reach nobody. The runner now names the broadcast explicitly. Without
    // this assertion the inversion would silently turn every scope-less
    // schedule into a no-op that still advances and still logs a fire, which is
    // the worst shape a regression here could take: unattended and quiet.
    CHECK(h.calls[0].scope == "__all__");
    // #3133 review fix: the dispatched caller must be the schedule's creator,
    // re-resolved via resolve_caller — NEVER system=true. Without this
    // assertion a regression back to a hardcoded system caller (the exact
    // bug the review found) would pass every other check in this file
    // silently, since none of them inspect the caller at all.
    CHECK_FALSE(h.calls[0].caller.system);
    CHECK(h.calls[0].caller.principal == "admin");

    // Tracked execution row, targeted count recorded.
    auto exec = h.tracker.get_execution(h.calls[0].execution_id);
    REQUIRE(exec.has_value());
    CHECK(exec->definition_id == "test.def");
    CHECK(exec->dispatched_by == "admin");
    CHECK(exec->agents_targeted == 1);
    CHECK(exec->status == "running");

    // Advanced: next in the future, occurrence counted.
    auto s = h.get(id);
    CHECK(s.execution_count == 1);
    CHECK(s.next_execution_at > 1);

    // Not due any more — nothing else fires.
    h.runner.tick();
    CHECK(h.calls.size() == 1);
}

TEST_CASE("ScheduleRunner: 'once' schedule fires exactly once then disables",
          "[schedule][runner][pg]") {
    Harness h;
    auto id = h.make_due("test.def", "once");

    h.runner.tick();
    h.runner.tick();

    CHECK(h.calls.size() == 1);
    CHECK(h.get(id).next_execution_at == 0); // disabled-after-fire sentinel
}

TEST_CASE("ScheduleRunner: unknown definition skips the occurrence but advances",
          "[schedule][runner][pg]") {
    Harness h;
    auto id = h.make_due("no.such.def", "interval");

    h.runner.tick();

    CHECK(h.calls.empty());
    auto s = h.get(id);
    CHECK(s.next_execution_at > 1); // advanced — must not re-fire every tick
}

TEST_CASE("ScheduleRunner: InstructionStore DB error skips the occurrence WITHOUT advancing "
          "(retries next tick)",
          "[schedule][runner][pg]") {
    // Regression pin (gov Gate 3/6 sibling finding): a genuine InstructionStore DB error used
    // to advance_schedule() unconditionally, permanently consuming that occurrence on a
    // transient Postgres blip — the same class of bug PolicyEvaluator::dispatch_due's
    // throttle-restore fix closed, not originally applied here.
    yuzu::server::pg::PgPool broken_pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 1}};
    REQUIRE_FALSE(broken_pool.valid());
    InstructionStore broken_is{broken_pool};
    REQUIRE_FALSE(broken_is.is_open());

    Harness h(
        [](const std::string&, const std::string&, const std::string&) { return true; }, nullptr,
        nullptr, &broken_is);
    auto id = h.make_due("test.def", "interval");

    h.runner.tick();

    CHECK(h.calls.empty());
    // NOT advanced — still due, so the next tick retries rather than losing the occurrence.
    CHECK(h.get(id).next_execution_at == 1);
}

TEST_CASE("ScheduleRunner: disabled definition skips the occurrence but advances",
          "[schedule][runner][pg]") {
    Harness h;
    InstructionDefinition d;
    d.id = "test.off";
    d.name = "test.off";
    d.version = "1.0.0";
    d.type = "question";
    d.plugin = "p";
    d.action = "a";
    d.enabled = false;
    REQUIRE(h.is.create_definition(d).has_value());
    auto id = h.make_due("test.off", "interval");

    h.runner.tick();

    CHECK(h.calls.empty());
    CHECK(h.get(id).next_execution_at > 1);
}

TEST_CASE("ScheduleRunner: zero agents reached cancels the execution and advances",
          "[schedule][runner][pg]") {
    Harness h;
    h.reach = 0;
    auto id = h.make_due("test.def", "interval");

    h.runner.tick();

    REQUIRE(h.calls.size() == 1);
    auto exec = h.tracker.get_execution(h.calls[0].execution_id);
    REQUIRE(exec.has_value());
    CHECK(exec->status == "cancelled");
    CHECK(h.get(id).next_execution_at > 1);
}

TEST_CASE("ScheduleRunner: dispatch throw cancels the execution and advances",
          "[schedule][runner][pg]") {
    Harness h;
    h.throw_on_dispatch = true;
    auto id = h.make_due("test.def", "interval");

    h.runner.tick();

    CHECK(h.calls.empty());
    // The pre-created execution row must not idle at 'running' forever.
    auto execs = h.tracker.query_executions();
    REQUIRE(execs.size() == 1);
    CHECK(execs[0].status == "cancelled");
    CHECK(h.get(id).next_execution_at > 1);
}

TEST_CASE("ScheduleRunner: requires_approval submits one ticket and holds the occurrence",
          "[schedule][runner][approval][pg]") {
    Harness h;
    auto id = h.make_due("test.def", "interval", /*requires_approval=*/true);

    h.runner.tick();
    h.runner.tick(); // second tick must NOT stack a duplicate ask

    CHECK(h.calls.empty());
    auto pending = h.approvals.query({.status = "pending"});
    REQUIRE(pending.size() == 1);
    CHECK(pending[0].definition_id == "test.def");
    CHECK(pending[0].submitted_by == "admin");

    // Occurrence held: not advanced, still due.
    auto s = h.get(id);
    CHECK(s.execution_count == 0);
    CHECK(s.next_execution_at == 1);
}

TEST_CASE("ScheduleRunner: approving the ticket fires the held occurrence exactly once",
          "[schedule][runner][approval][pg]") {
    Harness h;
    auto id = h.make_due("test.def", "interval", /*requires_approval=*/true);

    h.runner.tick(); // submits
    auto pending = h.approvals.query({.status = "pending"});
    REQUIRE(pending.size() == 1);
    REQUIRE(h.approvals.approve(pending[0].id, "boss", "ok").has_value());

    h.runner.tick(); // fires

    REQUIRE(h.calls.size() == 1);
    CHECK(h.get(id).execution_count == 1);

    // One-approval == one-run: force the next occurrence due — the spent
    // (still 'approved') ticket must be stale under the occurrence anchor,
    // so the runner submits a FRESH ask instead of re-firing.
    h.force_due(id);
    h.runner.tick();

    CHECK(h.calls.size() == 1); // no second fire
    CHECK(h.approvals.query({.status = "pending"}).size() == 1);
}

TEST_CASE("ScheduleRunner: rejecting the ticket skips the occurrence and re-asks next time",
          "[schedule][runner][approval][pg]") {
    Harness h;
    auto id = h.make_due("test.def", "interval", /*requires_approval=*/true);

    h.runner.tick(); // submits
    auto pending = h.approvals.query({.status = "pending"});
    REQUIRE(pending.size() == 1);
    REQUIRE(h.approvals.reject(pending[0].id, "boss", "no").has_value());

    h.runner.tick(); // occurrence skipped + advanced

    CHECK(h.calls.empty());
    CHECK(h.get(id).next_execution_at > 1);

    // Next occurrence: the rejected ticket is stale — a fresh ask goes out.
    h.force_due(id);
    h.runner.tick();
    CHECK(h.calls.empty());
    CHECK(h.approvals.query({.status = "pending"}).size() == 1);
}

TEST_CASE("ScheduleRunner: definition approval_mode gates even without the schedule flag",
          "[schedule][runner][approval][pg]") {
    Harness h;
    h.make_due("test.gated", "interval", /*requires_approval=*/false);

    h.runner.tick();

    // approval_mode="always" must not be bypassed by a scheduled fire.
    CHECK(h.calls.empty());
    CHECK(h.approvals.query({.status = "pending"}).size() == 1);
}

TEST_CASE("ScheduleRunner: two schedules sharing (creator,definition,scope) get independent "
          "approval tickets — one approval fires only its own schedule (M-02, #1806)",
          "[schedule][runner][approval][m02][pg]") {
    Harness h;
    // Both due, both reference the same gated definition, both default to
    // the same scope_expression ("") and created_by ("admin") — exactly the
    // (submitted_by, definition_id, scope_expression) tuple M-02 found was
    // used to match an approval BEFORE schedule_id existed.
    auto id_a = h.make_due("test.gated", "interval");
    auto id_b = h.make_due("test.gated", "interval");

    h.runner.tick(); // both hold; each submits its OWN ticket, no dedup collapse

    CHECK(h.calls.empty());
    auto pending = h.approvals.query({.status = "pending"});
    REQUIRE(pending.size() == 2); // two tickets, not one shared ticket

    std::string pending_a_id, pending_b_id;
    for (const auto& a : pending) {
        if (a.schedule_id == id_a)
            pending_a_id = a.id;
        else if (a.schedule_id == id_b)
            pending_b_id = a.id;
    }
    REQUIRE_FALSE(pending_a_id.empty());
    REQUIRE_FALSE(pending_b_id.empty());

    // Approve ONLY schedule A's ticket.
    REQUIRE(h.approvals.approve(pending_a_id, "boss", "ok").has_value());

    h.runner.tick();

    // Exactly one fire, and it is A's — B must not be swept along just
    // because it shares (creator, definition, scope) with A.
    REQUIRE(h.calls.size() == 1);
    CHECK(h.get(id_a).execution_count == 1);
    CHECK(h.get(id_b).execution_count == 0);

    // B still holds its OWN untouched pending ticket — proves no cross-talk
    // (not merely "no double-fire"): B was never suppressed by A's ticket
    // and never had its own ticket consumed by A's approval.
    auto still_pending = h.approvals.query({.status = "pending"});
    REQUIRE(still_pending.size() == 1);
    CHECK(still_pending[0].id == pending_b_id);
    CHECK(still_pending[0].schedule_id == id_b);
}

TEST_CASE("ScheduleEngine: interval floor rejected at create, clamped on legacy advance",
          "[schedule][runner][pg]") {
    Harness h;

    // Create-time floor.
    InstructionSchedule bad;
    bad.name = "bad";
    bad.definition_id = "test.def";
    bad.frequency_type = "interval";
    bad.interval_minutes = 0;
    auto rejected = h.engine.create_schedule(bad);
    REQUIRE_FALSE(rejected.has_value());

    // Legacy row (predates the floor): clamp on advance so it cannot land
    // next_execution_at <= now and re-fire every tick. ScheduleEngine now
    // lives in Postgres (instr_pool) — poke it via a second raw connection.
    auto id = h.make_due("test.def", "interval");
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.instr_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto sql = "UPDATE schedule_engine.schedules SET interval_minutes = 0 WHERE id = '" +
                  id + "'";
        yuzu::server::pg::PgResult res{PQexec(conn.get(), sql.c_str())};
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    h.runner.tick();

    REQUIRE(h.calls.size() == 1);
    auto s = h.get(id);
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    CHECK(s.next_execution_at > now); // clamped forward, not re-armed at now
}

// ── PR1.5a: typed schedule parameters ───────────────────────────────────────

TEST_CASE("ScheduleRunner: a schedule's parameters round-trip to the dispatch fn and "
          "exec.parameter_values",
          "[schedule][runner][params][pg]") {
    Harness h;
    auto id = h.make_due("test.def", "interval", /*requires_approval=*/false,
                         R"({"target":"prod","retries":3})");

    h.runner.tick();

    REQUIRE(h.calls.size() == 1);
    // Canonical (sorted-key) form reaches the dispatch fn's parameter map —
    // never empty, never the raw caller order.
    CHECK(h.calls[0].params.at("target") == "prod");
    CHECK(h.calls[0].params.at("retries") == "3");

    auto exec = h.tracker.get_execution(h.calls[0].execution_id);
    REQUIRE(exec.has_value());
    // exec.parameter_values equals the stored canonical JSON — never the
    // literal "{}" that dispatch_tracked hardcoded before this package.
    CHECK(exec->parameter_values == h.get(id).parameter_values);
    CHECK(exec->parameter_values != "{}");
}

TEST_CASE("ScheduleRunner: a schedule created with no parameters defaults to the canonical "
          "empty object and dispatches an empty parameter map",
          "[schedule][runner][params][pg]") {
    Harness h;
    auto id = h.make_due("test.def", "interval");

    CHECK(h.get(id).parameter_values == "{}");

    h.runner.tick();

    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].params.empty());
}

// ── D7 (PLAN-003): arming re-check on EVERY fire path ───────────────────────

TEST_CASE("ScheduleRunner: D7 a false arming_check blocks the auto (no-approval) fire path",
          "[schedule][runner][d7][pg]") {
    Harness h([](const std::string&, const std::string&, const std::string&) { return false; });
    auto id = h.make_due("test.def", "interval");

    h.runner.tick();

    CHECK(h.calls.empty()); // dispatch_fn never reached
    CHECK(h.get(id).next_execution_at > 1); // advanced — must not spin
}

TEST_CASE("ScheduleRunner: D7 a false arming_check blocks the approval-gated fire path",
          "[schedule][runner][d7][approval][pg]") {
    Harness h([](const std::string&, const std::string&, const std::string&) { return false; });
    auto id = h.make_due("test.def", "interval", /*requires_approval=*/true);

    h.runner.tick();

    // Denied BEFORE the approval branch — no ticket is even submitted, so
    // this proves arming_check gates IN FRONT OF fire_with_approval rather
    // than duplicating one of its checks.
    CHECK(h.calls.empty());
    CHECK(h.approvals.query({.status = "pending"}).empty());
    CHECK(h.get(id).next_execution_at > 1);
}

TEST_CASE("ScheduleRunner: D7 an UNSET arming_check denies both the auto and approval-gated "
          "paths",
          "[schedule][runner][d7][pg]") {
    Harness h(ScheduleRunner::ArmingCheckFn{}); // deliberately empty — p14 not wired
    auto auto_id = h.make_due("test.def", "interval");
    auto gated_id = h.make_due("test.def", "interval", /*requires_approval=*/true);

    h.runner.tick();

    CHECK(h.calls.empty());
    CHECK(h.approvals.query({.status = "pending"}).empty());
    CHECK(h.get(auto_id).next_execution_at > 1);
    CHECK(h.get(gated_id).next_execution_at > 1);
}

TEST_CASE("ScheduleRunner: D7 true arming_check still lets the auto and approved-ticket paths "
          "fire (existing approval behaviour unchanged)",
          "[schedule][runner][d7][approval][pg]") {
    Harness h([](const std::string&, const std::string&, const std::string&) { return true; });

    auto auto_id = h.make_due("test.def", "interval");
    h.runner.tick();
    REQUIRE(h.calls.size() == 1);
    CHECK(h.get(auto_id).execution_count == 1);

    auto gated_id = h.make_due("test.def", "interval", /*requires_approval=*/true);
    h.runner.tick(); // submits
    auto pending = h.approvals.query({.status = "pending"});
    REQUIRE(pending.size() == 1);
    REQUIRE(h.approvals.approve(pending[0].id, "boss", "ok").has_value());
    h.runner.tick(); // fires

    REQUIRE(h.calls.size() == 2);
    CHECK(h.get(gated_id).execution_count == 1);
}

namespace {
// AuditStore is Postgres-backed now — pre-migrated template for the single
// audit-consuming case below (everything else in this file stays hermetic
// SQLite via the runner's own stores).
yuzu::test::PgTestTemplate schedrunner_audit_tpl{"schedrunneraudit", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    AuditStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("schedrunner audit template: store failed to migrate");
}};
} // namespace

TEST_CASE("ScheduleRunner: D7 a denied arming check audits the principal + target and counts "
          "the deny",
          "[schedule][runner][d7][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, schedrunner_audit_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AuditStore audit{pool};
    REQUIRE(audit.is_open());
    yuzu::MetricsRegistry metrics;
    Harness h([](const std::string&, const std::string&, const std::string&) { return false; },
             &audit, &metrics);
    h.make_due("test.def", "interval");

    h.runner.tick();

    CHECK(metrics.counter("yuzu_schedule_arming_denied_total").value() == 1.0);

    auto rows = audit.query({.action = "instruction.schedule_fired"});
    REQUIRE(rows.has_value()); // PG store: query reports availability, not just rows
    bool found = false;
    for (const auto& e : *rows) {
        if (e.result == "denied" && e.principal == "admin" &&
            e.detail.find("plugin=procs") != std::string::npos &&
            e.detail.find("action=list") != std::string::npos) {
            found = true;
        }
    }
    CHECK(found);
}
