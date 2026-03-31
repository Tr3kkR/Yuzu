/**
 * test_tar_store.cpp -- Unit tests for TarDatabase (SQLite-backed TAR storage)
 *
 * Covers: open/create, warehouse tables, typed inserts, SQL queries,
 * stats, config get/set, state get/set.
 */

#include "tar_db.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::tar;

// Helper: create a TarDatabase in a unique temp file, clean up on destruction.
struct TestTarDb {
    TarDatabase db;
    fs::path path;

    ~TestTarDb() {
        { TarDatabase discard = std::move(db); }
        std::error_code ec;
        fs::remove(path, ec);
        fs::remove(fs::path{path.string() + "-wal"}, ec);
        fs::remove(fs::path{path.string() + "-shm"}, ec);
    }
};

static TestTarDb make_test_db() {
    auto tmp = fs::temp_directory_path() / "yuzu_test_tar" /
               ("tar_" +
                std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id())) +
                "_" +
                std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
                ".db");
    auto result = TarDatabase::open(tmp);
    REQUIRE(result.has_value());
    return TestTarDb{std::move(*result), tmp};
}

// =============================================================================
// Database lifecycle
// =============================================================================

TEST_CASE("TarDatabase: open creates database file", "[tar][store][lifecycle]") {
    auto t = make_test_db();
    CHECK(fs::exists(t.path));
}

TEST_CASE("TarDatabase: warehouse tables created on open", "[tar][store][lifecycle]") {
    auto t = make_test_db();
    // Verify by inserting a process event -- would fail if table doesn't exist
    ProcessEvent ev;
    ev.ts = 1000;
    ev.snapshot_id = 1;
    ev.action = "started";
    ev.pid = 42;
    ev.name = "test.exe";

    CHECK(t.db.insert_process_events({ev}));
}

// =============================================================================
// Typed inserts and SQL queries
// =============================================================================

TEST_CASE("TarDatabase: insert and query process events", "[tar][store][crud]") {
    auto t = make_test_db();

    std::vector<ProcessEvent> events;
    for (int i = 0; i < 5; ++i) {
        ProcessEvent ev;
        ev.ts = 1000 + i;
        ev.snapshot_id = 1;
        ev.action = (i % 2 == 0) ? "started" : "stopped";
        ev.pid = static_cast<uint32_t>(i + 1);
        ev.name = "proc" + std::to_string(i);
        events.push_back(std::move(ev));
    }

    REQUIRE(t.db.insert_process_events(events));

    auto results = t.db.execute_query("SELECT ts, action, pid, name FROM process_live ORDER BY ts");
    REQUIRE(results.has_value());
    REQUIRE(results->rows.size() == 5);
    CHECK(results->rows[0][0] == "1000");
    CHECK(results->rows[4][0] == "1004");
    CHECK(results->rows[0][1] == "started");
}

TEST_CASE("TarDatabase: insert and query network events", "[tar][store][crud]") {
    auto t = make_test_db();

    NetworkEvent ev;
    ev.ts = 2000;
    ev.snapshot_id = 1;
    ev.action = "connected";
    ev.proto = "tcp";
    ev.local_addr = "127.0.0.1";
    ev.local_port = 8080;
    ev.remote_addr = "10.0.0.1";
    ev.remote_port = 443;
    ev.pid = 100;
    ev.process_name = "curl";

    REQUIRE(t.db.insert_network_events({ev}));

    auto results = t.db.execute_query("SELECT proto, local_port, remote_addr FROM tcp_live");
    REQUIRE(results.has_value());
    REQUIRE(results->rows.size() == 1);
    CHECK(results->rows[0][0] == "tcp");
    CHECK(results->rows[0][1] == "8080");
    CHECK(results->rows[0][2] == "10.0.0.1");
}

TEST_CASE("TarDatabase: query with time range filter", "[tar][store][query]") {
    auto t = make_test_db();

    std::vector<ProcessEvent> events;
    for (int i = 0; i < 10; ++i) {
        ProcessEvent ev;
        ev.ts = 1000 + i;
        ev.snapshot_id = 1;
        ev.action = "started";
        ev.pid = static_cast<uint32_t>(i);
        ev.name = "proc";
        events.push_back(std::move(ev));
    }
    REQUIRE(t.db.insert_process_events(events));

    auto results = t.db.execute_query(
        "SELECT ts FROM process_live WHERE ts >= 1003 AND ts <= 1006 ORDER BY ts");
    REQUIRE(results.has_value());
    REQUIRE(results->rows.size() == 4);
    CHECK(results->rows[0][0] == "1003");
    CHECK(results->rows[3][0] == "1006");
}

TEST_CASE("TarDatabase: query with LIMIT", "[tar][store][query]") {
    auto t = make_test_db();

    std::vector<ProcessEvent> events;
    for (int i = 0; i < 20; ++i) {
        ProcessEvent ev;
        ev.ts = 1000 + i;
        ev.snapshot_id = 1;
        ev.action = "started";
        ev.pid = static_cast<uint32_t>(i);
        ev.name = "proc";
        events.push_back(std::move(ev));
    }
    REQUIRE(t.db.insert_process_events(events));

    auto results = t.db.execute_query("SELECT ts FROM process_live LIMIT 5");
    REQUIRE(results.has_value());
    CHECK(results->rows.size() == 5);
}

// =============================================================================
// Retention (purge via SQL)
// =============================================================================

TEST_CASE("TarDatabase: purge old records via execute_sql_range", "[tar][store][purge]") {
    auto t = make_test_db();

    std::vector<ProcessEvent> events;
    for (int i = 0; i < 10; ++i) {
        ProcessEvent ev;
        ev.ts = 1000 + i;
        ev.snapshot_id = 1;
        ev.action = "started";
        ev.pid = static_cast<uint32_t>(i);
        ev.name = "proc";
        events.push_back(std::move(ev));
    }
    REQUIRE(t.db.insert_process_events(events));

    // Delete records with ts < 1005
    REQUIRE(t.db.execute_sql("DELETE FROM process_live WHERE ts < 1005"));

    auto remaining = t.db.execute_query("SELECT ts FROM process_live ORDER BY ts");
    REQUIRE(remaining.has_value());
    CHECK(remaining->rows.size() == 5);
    CHECK(remaining->rows[0][0] == "1005");
}

// =============================================================================
// Stats
// =============================================================================

TEST_CASE("TarDatabase: stats returns correct values", "[tar][store][stats]") {
    auto t = make_test_db();

    std::vector<ProcessEvent> events;
    for (int i = 0; i < 5; ++i) {
        ProcessEvent ev;
        ev.ts = 2000 + i;
        ev.snapshot_id = 1;
        ev.action = "started";
        ev.pid = static_cast<uint32_t>(i);
        ev.name = "proc";
        events.push_back(std::move(ev));
    }
    REQUIRE(t.db.insert_process_events(events));

    auto s = t.db.stats();
    CHECK(s.record_count == 5);
    CHECK(s.oldest_timestamp == 2000);
    CHECK(s.newest_timestamp == 2004);
    CHECK(s.db_size_bytes > 0);
    CHECK(s.retention_days == 7); // default
}

// =============================================================================
// Config get/set
// =============================================================================

TEST_CASE("TarDatabase: config get returns default", "[tar][store][config]") {
    auto t = make_test_db();

    auto val = t.db.get_config("nonexistent", "fallback");
    CHECK(val == "fallback");
}

TEST_CASE("TarDatabase: config set and get", "[tar][store][config]") {
    auto t = make_test_db();

    t.db.set_config("test_key", "test_value");
    auto val = t.db.get_config("test_key");
    CHECK(val == "test_value");

    // Update
    t.db.set_config("test_key", "updated_value");
    val = t.db.get_config("test_key");
    CHECK(val == "updated_value");
}

TEST_CASE("TarDatabase: default retention_days is 7", "[tar][store][config]") {
    auto t = make_test_db();

    auto val = t.db.get_config("retention_days");
    CHECK(val == "7");
}

// =============================================================================
// State get/set
// =============================================================================

TEST_CASE("TarDatabase: state get returns empty for unknown collector", "[tar][store][state]") {
    auto t = make_test_db();

    auto val = t.db.get_state("unknown_collector");
    CHECK(val.empty());
}

TEST_CASE("TarDatabase: state set and get", "[tar][store][state]") {
    auto t = make_test_db();

    std::string json = R"([{"pid":1,"name":"init"},{"pid":42,"name":"firefox"}])";
    t.db.set_state("process", json);

    auto val = t.db.get_state("process");
    CHECK(val == json);

    // Update
    std::string updated = R"([{"pid":1,"name":"init"}])";
    t.db.set_state("process", updated);
    val = t.db.get_state("process");
    CHECK(val == updated);
}

TEST_CASE("TarDatabase: multiple collectors have independent state", "[tar][store][state]") {
    auto t = make_test_db();

    t.db.set_state("process", "process_state");
    t.db.set_state("network", "network_state");

    CHECK(t.db.get_state("process") == "process_state");
    CHECK(t.db.get_state("network") == "network_state");
}
