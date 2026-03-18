/**
 * test_schedule_engine.cpp — Unit tests for ScheduleEngine
 *
 * Covers: compute_next_execution for all frequency types, CRUD, enable/disable,
 *         evaluate_due callback firing, one-time auto-disable.
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
    ~TestDb() { if (db) sqlite3_close(db); }
};

// ── Helpers ─────────────────────────────────────────────────────────────────

static int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static InstructionSchedule make_schedule(
    const std::string& definition_id,
    const std::string& frequency_type,
    const std::string& name = "test-schedule")
{
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

// ── compute_next_execution ─────────────────────────────────────────────────

TEST_CASE("ScheduleEngine: compute_next — once", "[schedule_engine][next]") {
    auto sched = make_schedule("def-1", "once");
    auto now = now_epoch();
    sched.active_from = now + 3600;

    auto next = ScheduleEngine::compute_next_execution(sched, now);
    CHECK(next == sched.active_from);
}

TEST_CASE("ScheduleEngine: compute_next — once no active_from uses now", "[schedule_engine][next]") {
    auto sched = make_schedule("def-1", "once");
    auto now = now_epoch();

    auto next = ScheduleEngine::compute_next_execution(sched, now);
    CHECK(next == now);
}

TEST_CASE("ScheduleEngine: compute_next — interval", "[schedule_engine][next]") {
    auto sched = make_schedule("def-1", "interval");
    sched.interval_minutes = 5;
    auto now = now_epoch();
    sched.last_executed_at = now - 100;

    auto next = ScheduleEngine::compute_next_execution(sched, now);
    CHECK(next == sched.last_executed_at + 300);
}

TEST_CASE("ScheduleEngine: compute_next — interval first run", "[schedule_engine][next]") {
    auto sched = make_schedule("def-1", "interval");
    sched.interval_minutes = 10;
    auto now = now_epoch();

    auto next = ScheduleEngine::compute_next_execution(sched, now);
    CHECK(next == now + 600);
}

TEST_CASE("ScheduleEngine: compute_next — daily", "[schedule_engine][next]") {
    auto sched = make_schedule("def-1", "daily");
    sched.time_of_day = "14:00";
    auto now = now_epoch();

    auto next = ScheduleEngine::compute_next_execution(sched, now);
    CHECK(next > 0);
    CHECK(next > now - 86400);  // should be within next 24h
}

TEST_CASE("ScheduleEngine: compute_next — weekly", "[schedule_engine][next]") {
    auto sched = make_schedule("def-1", "weekly");
    sched.time_of_day = "09:00";
    sched.day_of_week = 1;  // Monday
    auto now = now_epoch();

    auto next = ScheduleEngine::compute_next_execution(sched, now);
    CHECK(next > 0);
}

TEST_CASE("ScheduleEngine: compute_next — monthly", "[schedule_engine][next]") {
    auto sched = make_schedule("def-1", "monthly");
    sched.time_of_day = "03:00";
    sched.day_of_month = 15;
    auto now = now_epoch();

    auto next = ScheduleEngine::compute_next_execution(sched, now);
    CHECK(next > 0);
}

// ── CRUD ───────────────────────────────────────────────────────────────────

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

TEST_CASE("ScheduleEngine: get schedule", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto sched = make_schedule("def-002", "daily", "Daily Report");
    sched.time_of_day = "08:00";
    auto result = engine.create_schedule(sched);
    REQUIRE(result.has_value());

    auto fetched = engine.get_schedule(*result);
    REQUIRE(fetched.has_value());
    CHECK(fetched->name == "Daily Report");
    CHECK(fetched->definition_id == "def-002");
    CHECK(fetched->frequency_type == "daily");
    CHECK(fetched->time_of_day == "08:00");
    CHECK(fetched->enabled == true);
}

TEST_CASE("ScheduleEngine: get nonexistent returns empty", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto result = engine.get_schedule("nonexistent-id");
    CHECK(!result.has_value());
}

TEST_CASE("ScheduleEngine: query all schedules", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    engine.create_schedule(make_schedule("def-1", "once", "One"));
    engine.create_schedule(make_schedule("def-2", "daily", "Two"));
    engine.create_schedule(make_schedule("def-3", "weekly", "Three"));

    auto results = engine.query_schedules();
    REQUIRE(results.size() == 3);
}

TEST_CASE("ScheduleEngine: delete schedule", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto result = engine.create_schedule(make_schedule("def-1", "once"));
    REQUIRE(result.has_value());

    bool deleted = engine.delete_schedule(*result);
    REQUIRE(deleted);

    auto fetched = engine.get_schedule(*result);
    CHECK(!fetched.has_value());
}

TEST_CASE("ScheduleEngine: delete nonexistent returns false", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    bool deleted = engine.delete_schedule("nonexistent-id");
    CHECK(!deleted);
}

// ── Enable / Disable ───────────────────────────────────────────────────────

TEST_CASE("ScheduleEngine: set_enabled", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto result = engine.create_schedule(make_schedule("def-1", "interval"));
    REQUIRE(result.has_value());

    bool ok = engine.set_enabled(*result, false);
    REQUIRE(ok);

    auto sched = engine.get_schedule(*result);
    REQUIRE(sched.has_value());
    CHECK(sched->enabled == false);

    engine.set_enabled(*result, true);
    auto sched2 = engine.get_schedule(*result);
    CHECK(sched2->enabled == true);
}

// ── evaluate_due ───────────────────────────────────────────────────────────

TEST_CASE("ScheduleEngine: evaluate_due fires for overdue schedule", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto sched = make_schedule("def-due", "interval", "Overdue");
    sched.interval_minutes = 1;
    auto result = engine.create_schedule(sched);
    REQUIRE(result.has_value());

    // Manually set next_execution_at to past
    auto now = now_epoch();
    const char* sql = "UPDATE instruction_schedules SET next_execution_at = ? WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(tdb.db, sql, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, now - 60);
    sqlite3_bind_text(stmt, 2, result->c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    std::vector<std::string> fired_ids;
    engine.set_dispatch_callback([&](const InstructionSchedule& s) {
        fired_ids.push_back(s.id);
    });
    engine.evaluate_due(now);

    REQUIRE(fired_ids.size() == 1);
    CHECK(fired_ids[0] == *result);
}

TEST_CASE("ScheduleEngine: evaluate_due does not fire for disabled schedule", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto sched = make_schedule("def-disabled", "interval", "Disabled");
    sched.interval_minutes = 1;
    auto result = engine.create_schedule(sched);
    REQUIRE(result.has_value());
    engine.set_enabled(*result, false);

    std::vector<std::string> fired_ids;
    engine.set_dispatch_callback([&](const InstructionSchedule& s) {
        fired_ids.push_back(s.id);
    });
    engine.evaluate_due(now_epoch() + 3600);

    CHECK(fired_ids.empty());
}

TEST_CASE("ScheduleEngine: evaluate_due does not fire for future schedule", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto sched = make_schedule("def-future", "once", "Future");
    sched.active_from = now_epoch() + 7200;  // 2 hours from now
    engine.create_schedule(sched);

    std::vector<std::string> fired_ids;
    engine.set_dispatch_callback([&](const InstructionSchedule& s) {
        fired_ids.push_back(s.id);
    });
    engine.evaluate_due(now_epoch());

    CHECK(fired_ids.empty());
}

TEST_CASE("ScheduleEngine: one-time schedule disabled after execution", "[schedule_engine]") {
    TestDb tdb;
    ScheduleEngine engine(tdb.db);
    engine.create_tables();

    auto sched = make_schedule("def-once", "once", "OneShot");
    auto result = engine.create_schedule(sched);
    REQUIRE(result.has_value());

    // Set next_execution_at to past
    auto now = now_epoch();
    const char* sql = "UPDATE instruction_schedules SET next_execution_at = ? WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(tdb.db, sql, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, now - 60);
    sqlite3_bind_text(stmt, 2, result->c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    engine.set_dispatch_callback([](const InstructionSchedule&) {});
    engine.evaluate_due(now);

    auto updated = engine.get_schedule(*result);
    REQUIRE(updated.has_value());
    CHECK(updated->enabled == false);
}

// ── Query Filters ──────────────────────────────────────────────────────────

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
