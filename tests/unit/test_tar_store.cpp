/**
 * test_tar_store.cpp -- Unit tests for TarDatabase (SQLite-backed TAR storage)
 *
 * Covers: open/create, table existence, event insert/query, type filtering,
 * limit, purge, stats, config get/set, state get/set.
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

TEST_CASE("TarDatabase: tables exist after open", "[tar][store][lifecycle]") {
    auto t = make_test_db();
    // Verify by inserting an event -- would fail if table doesn't exist
    TarEvent ev;
    ev.timestamp = 1000;
    ev.event_type = "process";
    ev.event_action = "started";
    ev.detail_json = R"({"pid":42})";
    ev.snapshot_id = 1;

    CHECK(t.db.insert_events({ev}));
}

// =============================================================================
// Event insert and query
// =============================================================================

TEST_CASE("TarDatabase: insert and query events", "[tar][store][crud]") {
    auto t = make_test_db();

    std::vector<TarEvent> events;
    for (int i = 0; i < 5; ++i) {
        TarEvent ev;
        ev.timestamp = 1000 + i;
        ev.event_type = "process";
        ev.event_action = (i % 2 == 0) ? "started" : "stopped";
        ev.detail_json = R"({"pid":)" + std::to_string(i + 1) + "}";
        ev.snapshot_id = 1;
        events.push_back(std::move(ev));
    }

    REQUIRE(t.db.insert_events(events));

    auto results = t.db.query(1000, 1010);
    REQUIRE(results.size() == 5);
    CHECK(results[0].timestamp == 1000);
    CHECK(results[4].timestamp == 1004);
    CHECK(results[0].event_type == "process");
}

TEST_CASE("TarDatabase: query with time range filter", "[tar][store][query]") {
    auto t = make_test_db();

    std::vector<TarEvent> events;
    for (int i = 0; i < 10; ++i) {
        TarEvent ev;
        ev.timestamp = 1000 + i;
        ev.event_type = "process";
        ev.event_action = "started";
        ev.detail_json = "{}";
        ev.snapshot_id = 1;
        events.push_back(std::move(ev));
    }
    t.db.insert_events(events);

    auto results = t.db.query(1003, 1006);
    REQUIRE(results.size() == 4);
    CHECK(results[0].timestamp == 1003);
    CHECK(results[3].timestamp == 1006);
}

TEST_CASE("TarDatabase: query with type filter", "[tar][store][query]") {
    auto t = make_test_db();

    TarEvent proc_ev;
    proc_ev.timestamp = 1000;
    proc_ev.event_type = "process";
    proc_ev.event_action = "started";
    proc_ev.detail_json = "{}";
    proc_ev.snapshot_id = 1;

    TarEvent net_ev;
    net_ev.timestamp = 1001;
    net_ev.event_type = "network";
    net_ev.event_action = "connected";
    net_ev.detail_json = "{}";
    net_ev.snapshot_id = 1;

    TarEvent svc_ev;
    svc_ev.timestamp = 1002;
    svc_ev.event_type = "service";
    svc_ev.event_action = "started";
    svc_ev.detail_json = "{}";
    svc_ev.snapshot_id = 1;

    t.db.insert_events({proc_ev, net_ev, svc_ev});

    auto proc_results = t.db.query(0, 2000, "process");
    REQUIRE(proc_results.size() == 1);
    CHECK(proc_results[0].event_type == "process");

    auto net_results = t.db.query(0, 2000, "network");
    REQUIRE(net_results.size() == 1);
    CHECK(net_results[0].event_type == "network");
}

TEST_CASE("TarDatabase: query with limit", "[tar][store][query]") {
    auto t = make_test_db();

    std::vector<TarEvent> events;
    for (int i = 0; i < 20; ++i) {
        TarEvent ev;
        ev.timestamp = 1000 + i;
        ev.event_type = "process";
        ev.event_action = "started";
        ev.detail_json = "{}";
        ev.snapshot_id = 1;
        events.push_back(std::move(ev));
    }
    t.db.insert_events(events);

    auto results = t.db.query(0, 2000, "", 5);
    CHECK(results.size() == 5);
}

// =============================================================================
// Purge
// =============================================================================

TEST_CASE("TarDatabase: purge removes old records", "[tar][store][purge]") {
    auto t = make_test_db();

    std::vector<TarEvent> events;
    for (int i = 0; i < 10; ++i) {
        TarEvent ev;
        ev.timestamp = 1000 + i;
        ev.event_type = "process";
        ev.event_action = "started";
        ev.detail_json = "{}";
        ev.snapshot_id = 1;
        events.push_back(std::move(ev));
    }
    t.db.insert_events(events);

    int purged = t.db.purge(1005);
    CHECK(purged == 5);

    auto remaining = t.db.query(0, 2000);
    CHECK(remaining.size() == 5);
    CHECK(remaining[0].timestamp == 1005);
}

// =============================================================================
// Stats
// =============================================================================

TEST_CASE("TarDatabase: stats returns correct values", "[tar][store][stats]") {
    auto t = make_test_db();

    std::vector<TarEvent> events;
    for (int i = 0; i < 5; ++i) {
        TarEvent ev;
        ev.timestamp = 2000 + i;
        ev.event_type = "process";
        ev.event_action = "started";
        ev.detail_json = "{}";
        ev.snapshot_id = 1;
        events.push_back(std::move(ev));
    }
    t.db.insert_events(events);

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
