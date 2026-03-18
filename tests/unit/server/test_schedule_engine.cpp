/**
 * test_schedule_engine.cpp — Unit tests for ScheduleEngine
 *
 * Covers: create, query with filters, delete, enable/disable, evaluate_due,
 *         advance_schedule, validation.
 */

#include "schedule_engine.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <chrono>
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

static int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static InstructionSchedule make_schedule(const std::string& definition_id,
                                         const std::string& frequency_type,
                                         const std::string& name = "test-schedule") {
    InstructionSchedule sched;
    sched.name = name;
    sched.definition_id = definition_id;
    sched.frequency_type = frequency_type;
    sched.scope_expression = "ostype = 'windows'";
    sched.enabled = true;
    sched.created_by = "admin";
    return sched;
}

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("ScheduleEngine: create_tables succeeds", "[schedule_engine][db]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();
    REQUIRE(true);
}

// ── Create Schedule ────────────────────────────────────────────────────────

TEST_CASE("ScheduleEngine: create schedule", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto sched = make_schedule("def-001", "interval", "Hourly Scan");
    sched.interval_minutes = 60;
    auto result = engine.create_schedule(sched);
    REQUIRE(result.has_value());
    CHECK(!result->empty());
}

TEST_CASE("ScheduleEngine: create with bad frequency_type fails", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto sched = make_schedule("def-001", "every_full_moon", "Bad Schedule");
    auto result = engine.create_schedule(sched);
    CHECK(!result.has_value());
}

TEST_CASE("ScheduleEngine: create schedule with all fields", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    InstructionSchedule sched;
    sched.name = "Weekly Audit";
    sched.definition_id = "def-audit";
    sched.frequency_type = "weekly";
    sched.interval_minutes = 0;
    sched.time_of_day = "09:00";
    sched.day_of_week = 1; // Monday
    sched.scope_expression = "tag = 'production'";
    sched.requires_approval = true;
    sched.enabled = true;
    sched.created_by = "admin";
    auto result = engine.create_schedule(sched);
    REQUIRE(result.has_value());
}

// ── Query Schedules ────────────────────────────────────────────────────────

TEST_CASE("ScheduleEngine: query all schedules", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    engine.create_schedule(make_schedule("def-1", "interval", "One"));
    engine.create_schedule(make_schedule("def-2", "daily", "Two"));
    engine.create_schedule(make_schedule("def-3", "weekly", "Three"));

    auto results = engine.query_schedules();
    REQUIRE(results.size() == 3);
}

TEST_CASE("ScheduleEngine: query by definition_id", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    engine.create_schedule(make_schedule("def-alpha", "daily", "A"));
    engine.create_schedule(make_schedule("def-beta", "daily", "B"));
    engine.create_schedule(make_schedule("def-alpha", "weekly", "C"));

    ScheduleQuery q;
    q.definition_id = "def-alpha";
    auto results = engine.query_schedules(q);
    REQUIRE(results.size() == 2);
}

TEST_CASE("ScheduleEngine: query enabled_only", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto r1 = engine.create_schedule(make_schedule("def-1", "daily", "Enabled"));
    auto r2 = engine.create_schedule(make_schedule("def-2", "daily", "Disabled"));
    REQUIRE(r2.has_value());
    engine.set_enabled(*r2, false);

    ScheduleQuery q;
    q.enabled_only = true;
    auto results = engine.query_schedules(q);
    REQUIRE(results.size() == 1);
    CHECK(results[0].name == "Enabled");
}

TEST_CASE("ScheduleEngine: query empty store returns empty", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto results = engine.query_schedules();
    CHECK(results.empty());
}

// ── Delete Schedule ────────────────────────────────────────────────────────

TEST_CASE("ScheduleEngine: delete schedule", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto result = engine.create_schedule(make_schedule("def-1", "interval"));
    REQUIRE(result.has_value());

    bool deleted = engine.delete_schedule(*result);
    REQUIRE(deleted);

    auto results = engine.query_schedules();
    CHECK(results.empty());
}

TEST_CASE("ScheduleEngine: delete nonexistent returns false", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    bool deleted = engine.delete_schedule("nonexistent-id");
    CHECK(!deleted);
}

// ── Enable / Disable ───────────────────────────────────────────────────────

TEST_CASE("ScheduleEngine: set_enabled disables schedule", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto result = engine.create_schedule(make_schedule("def-1", "interval"));
    REQUIRE(result.has_value());

    engine.set_enabled(*result, false);

    ScheduleQuery q;
    q.enabled_only = true;
    auto enabled = engine.query_schedules(q);
    CHECK(enabled.empty());
}

TEST_CASE("ScheduleEngine: set_enabled re-enables schedule", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto result = engine.create_schedule(make_schedule("def-1", "interval"));
    REQUIRE(result.has_value());

    engine.set_enabled(*result, false);
    engine.set_enabled(*result, true);

    ScheduleQuery q;
    q.enabled_only = true;
    auto enabled = engine.query_schedules(q);
    REQUIRE(enabled.size() == 1);
}

// ── evaluate_due ───────────────────────────────────────────────────────────

TEST_CASE("ScheduleEngine: evaluate_due returns overdue schedule", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto sched = make_schedule("def-due", "interval", "Overdue");
    sched.interval_minutes = 1;
    auto result = engine.create_schedule(sched);
    REQUIRE(result.has_value());

    // Manually set next_execution_at to past via raw SQL
    auto now = now_epoch();
    const char* sql = "UPDATE schedules SET next_execution_at = ? WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(tdb.db, sql, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, now - 60);
    sqlite3_bind_text(stmt, 2, result->c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    auto due = engine.evaluate_due();
    REQUIRE(due.size() >= 1);

    bool found = false;
    for (const auto& s : due) {
        if (s.id == *result)
            found = true;
    }
    CHECK(found);
}

TEST_CASE("ScheduleEngine: evaluate_due does not return disabled schedule", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto sched = make_schedule("def-disabled", "interval", "Disabled");
    sched.interval_minutes = 1;
    auto result = engine.create_schedule(sched);
    REQUIRE(result.has_value());
    engine.set_enabled(*result, false);

    // Set next_execution_at to past
    auto now = now_epoch();
    const char* sql = "UPDATE schedules SET next_execution_at = ? WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(tdb.db, sql, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, now - 60);
    sqlite3_bind_text(stmt, 2, result->c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    auto due = engine.evaluate_due();
    for (const auto& s : due) {
        CHECK(s.id != *result);
    }
}

TEST_CASE("ScheduleEngine: evaluate_due does not return future schedule", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto sched = make_schedule("def-future", "interval", "Future");
    sched.interval_minutes = 60;
    auto result = engine.create_schedule(sched);
    REQUIRE(result.has_value());

    // Set next_execution_at to far future
    auto future = now_epoch() + 7200;
    const char* sql = "UPDATE schedules SET next_execution_at = ? WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(tdb.db, sql, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, future);
    sqlite3_bind_text(stmt, 2, result->c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    auto due = engine.evaluate_due();
    for (const auto& s : due) {
        CHECK(s.id != *result);
    }
}

// ── advance_schedule ───────────────────────────────────────────────────────

TEST_CASE("ScheduleEngine: advance_schedule updates next_execution_at", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto sched = make_schedule("def-adv", "interval", "Advancing");
    sched.interval_minutes = 30;
    auto result = engine.create_schedule(sched);
    REQUIRE(result.has_value());

    // Set a known next_execution_at
    auto now = now_epoch();
    const char* sql = "UPDATE schedules SET next_execution_at = ? WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(tdb.db, sql, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, now - 60);
    sqlite3_bind_text(stmt, 2, result->c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    engine.advance_schedule(*result);

    // Query to check updated fields
    auto all = engine.query_schedules();
    REQUIRE(!all.empty());

    bool found = false;
    for (const auto& s : all) {
        if (s.id == *result) {
            found = true;
            // next_execution_at should have been advanced past now
            CHECK(s.next_execution_at > now - 60);
            // execution_count should be incremented
            CHECK(s.execution_count == 1);
            // last_executed_at should be set
            CHECK(s.last_executed_at > 0);
        }
    }
    REQUIRE(found);
}

TEST_CASE("ScheduleEngine: advance_schedule increments execution_count", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto sched = make_schedule("def-count", "interval", "Counter");
    sched.interval_minutes = 10;
    auto result = engine.create_schedule(sched);
    REQUIRE(result.has_value());

    engine.advance_schedule(*result);
    engine.advance_schedule(*result);
    engine.advance_schedule(*result);

    auto all = engine.query_schedules();
    for (const auto& s : all) {
        if (s.id == *result) {
            CHECK(s.execution_count == 3);
        }
    }
}

TEST_CASE("ScheduleEngine: advance_schedule sets last_executed_at", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto sched = make_schedule("def-last", "daily", "LastExec");
    sched.time_of_day = "14:00";
    auto result = engine.create_schedule(sched);
    REQUIRE(result.has_value());

    auto before = now_epoch();
    engine.advance_schedule(*result);

    auto all = engine.query_schedules();
    for (const auto& s : all) {
        if (s.id == *result) {
            CHECK(s.last_executed_at >= before);
        }
    }
}

// ── Stop ───────────────────────────────────────────────────────────────────

TEST_CASE("ScheduleEngine: stop is safe to call", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    engine.stop(); // should not crash
    REQUIRE(true);
}
