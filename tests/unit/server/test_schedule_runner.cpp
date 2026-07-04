/**
 * test_schedule_runner.cpp — Unit tests for the recurring-schedule poller
 * (ScheduleRunner, #1191).
 *
 * Strategy: real ScheduleEngine / ExecutionTracker / ApprovalManager on one
 * shared :memory: SQLite handle (the production shape — they share
 * instructions.db), a real InstructionStore on a temp DB, and a FAKE
 * dispatch_fn that records calls and returns a configurable reach count.
 * Due-ness is driven by creating schedules with next_execution_at in the
 * past (create_schedule honors an explicit value), so no clock injection is
 * needed.
 */

#include "approval_manager.hpp"
#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "schedule_engine.hpp"
#include "schedule_runner.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <chrono>
#include <stdexcept>
#include <string>
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
};

struct Harness {
    TestDb db; // shared by engine + tracker + approvals (production shape)
    yuzu::test::TempDbFile insdb{std::string_view("schedrun-ins-")};

    ScheduleEngine engine{db.db};
    ExecutionTracker tracker{db.db};
    ApprovalManager approvals{db.db};
    InstructionStore is{insdb.path};

    std::vector<DispatchCall> calls;
    int reach{1};        // agents "reached" by the fake dispatch
    bool throw_on_dispatch{false};

    ScheduleRunner runner;

    Harness()
        : runner(ScheduleRunner::Deps{
              .schedule_engine = &engine,
              .instruction_store = &is,
              .execution_tracker = &tracker,
              .approval_manager = &approvals,
              .audit_store = nullptr,
              .metrics = nullptr,
              .dispatch_fn =
                  [this](const std::string& plugin, const std::string& action,
                         const std::vector<std::string>&, const std::string& scope,
                         const std::unordered_map<std::string, std::string>&,
                         const std::string& execution_id) -> std::pair<std::string, int> {
                      if (throw_on_dispatch)
                          throw std::runtime_error("dispatch boom");
                      calls.push_back({plugin, action, scope, execution_id});
                      return {"cmd-" + std::to_string(calls.size()), reach};
                  },
          }) {
        engine.create_tables();
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
                         bool requires_approval = false) {
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
    void force_due(const std::string& id) {
        char* err = nullptr;
        auto sql = "UPDATE schedules SET next_execution_at = 1 WHERE id = '" + id + "'";
        REQUIRE(sqlite3_exec(db.db, sql.c_str(), nullptr, nullptr, &err) == SQLITE_OK);
    }
};

} // namespace

TEST_CASE("ScheduleRunner: due interval schedule fires once and advances", "[schedule][runner]") {
    Harness h;
    auto id = h.make_due("test.def", "interval");

    h.runner.tick();

    REQUIRE(h.calls.size() == 1);
    CHECK(h.calls[0].plugin == "procs");
    CHECK(h.calls[0].action == "list");
    REQUIRE_FALSE(h.calls[0].execution_id.empty());

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
          "[schedule][runner]") {
    Harness h;
    auto id = h.make_due("test.def", "once");

    h.runner.tick();
    h.runner.tick();

    CHECK(h.calls.size() == 1);
    CHECK(h.get(id).next_execution_at == 0); // disabled-after-fire sentinel
}

TEST_CASE("ScheduleRunner: unknown definition skips the occurrence but advances",
          "[schedule][runner]") {
    Harness h;
    auto id = h.make_due("no.such.def", "interval");

    h.runner.tick();

    CHECK(h.calls.empty());
    auto s = h.get(id);
    CHECK(s.next_execution_at > 1); // advanced — must not re-fire every tick
}

TEST_CASE("ScheduleRunner: disabled definition skips the occurrence but advances",
          "[schedule][runner]") {
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
          "[schedule][runner]") {
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
          "[schedule][runner]") {
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
          "[schedule][runner][approval]") {
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
          "[schedule][runner][approval]") {
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
          "[schedule][runner][approval]") {
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
          "[schedule][runner][approval]") {
    Harness h;
    h.make_due("test.gated", "interval", /*requires_approval=*/false);

    h.runner.tick();

    // approval_mode="always" must not be bypassed by a scheduled fire.
    CHECK(h.calls.empty());
    CHECK(h.approvals.query({.status = "pending"}).size() == 1);
}

TEST_CASE("ScheduleRunner: two schedules sharing (creator,definition,scope) get independent "
          "approval tickets — one approval fires only its own schedule (M-02, #1806)",
          "[schedule][runner][approval][m02]") {
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
          "[schedule][runner]") {
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
    // next_execution_at <= now and re-fire every tick.
    auto id = h.make_due("test.def", "interval");
    char* err = nullptr;
    auto sql = "UPDATE schedules SET interval_minutes = 0 WHERE id = '" + id + "'";
    REQUIRE(sqlite3_exec(h.db.db, sql.c_str(), nullptr, nullptr, &err) == SQLITE_OK);

    h.runner.tick();

    REQUIRE(h.calls.size() == 1);
    auto s = h.get(id);
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    CHECK(s.next_execution_at > now); // clamped forward, not re-armed at now
}
