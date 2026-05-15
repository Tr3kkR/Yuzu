/**
 * test_tar_store.cpp -- Unit tests for TarDatabase (SQLite-backed TAR storage)
 *
 * Covers: open/create, warehouse tables, typed inserts, SQL queries,
 * stats, config get/set, state get/set.
 */

#include "tar_db.hpp"
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::tar;

// Helper: create a TarDatabase in a unique temp file, clean up on destruction.
// Uniqueness comes from yuzu::test::unique_temp_path -- never salt with
// std::hash<thread::id> / steady_clock, which collide under Defender-induced
// I/O serialisation on the Windows runner (CLAUDE.md test conventions, #473).
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
    auto tmp = yuzu::test::unique_temp_path("tar_");
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

// ── query_recent_tcp_connections — last-N-seconds window for the viz ─────────
//
// Tracer bullet: TAR keeps every observed TCP connection in tcp_live with
// its observation timestamp. The viz wants to render any connection that
// existed within the last hour as a tube, not just the currently-ESTABLISHED
// ones from /proc/net/tcp. So `tar.fleet_snapshot` needs a way to ask the
// warehouse for the rolling window of connections seen recently.
//
// Behaviour: returns one row per unique (proto, local_addr, local_port,
// remote_addr, remote_port, pid) 5-tuple, with `ts` set to the most recent
// observation timestamp. Rows older than `since_ts` are dropped. State
// values other than ESTABLISHED are filtered out (LISTEN, TIME_WAIT, etc.
// — those aren't "this box talks to that box" edges).
TEST_CASE("TarDatabase: query_recent_tcp_connections returns rows newer than the window",
          "[tar][store][recent-tcp]") {
    auto t = make_test_db();

    NetworkEvent in_window;
    in_window.ts = 5000;
    in_window.action = "connected";
    in_window.proto = "tcp";
    in_window.local_addr = "10.0.0.10";
    in_window.local_port = 50001;
    in_window.remote_addr = "10.0.0.20";
    in_window.remote_port = 5432;
    in_window.state = "ESTABLISHED";
    in_window.pid = 100;
    in_window.process_name = "node";

    NetworkEvent out_of_window;
    out_of_window.ts = 1000; // 4000 seconds before in_window
    out_of_window.action = "connected";
    out_of_window.proto = "tcp";
    out_of_window.local_addr = "10.0.0.10";
    out_of_window.local_port = 49999;
    out_of_window.remote_addr = "10.0.0.30";
    out_of_window.remote_port = 6379;
    out_of_window.state = "ESTABLISHED";
    out_of_window.pid = 100;
    out_of_window.process_name = "node";

    REQUIRE(t.db.insert_network_events({in_window, out_of_window}));

    // Window: [5000 - 3600, 5000] = [1400, 5000]. The t=1000 row is outside.
    auto recent = t.db.query_recent_tcp_connections(/*since_ts=*/1400);
    REQUIRE(recent.has_value());
    REQUIRE(recent->size() == 1);
    CHECK(recent->at(0).proto == "tcp");
    CHECK(recent->at(0).local_addr == "10.0.0.10");
    CHECK(recent->at(0).local_port == 50001);
    CHECK(recent->at(0).remote_addr == "10.0.0.20");
    CHECK(recent->at(0).remote_port == 5432);
    CHECK(recent->at(0).pid == 100u);
    CHECK(recent->at(0).ts == 5000);
}

TEST_CASE("TarDatabase: query_recent_tcp_connections dedups by 5-tuple, keeps latest ts",
          "[tar][store][recent-tcp]") {
    auto t = make_test_db();

    // Same 5-tuple+pid observed three times. The result MUST be a single
    // row with ts set to the most recent observation (3000).
    NetworkEvent base;
    base.action = "connected";
    base.proto = "tcp";
    base.local_addr = "10.0.0.10";
    base.local_port = 60001;
    base.remote_addr = "10.0.0.20";
    base.remote_port = 5432;
    base.state = "ESTABLISHED";
    base.pid = 200;
    base.process_name = "node";

    base.ts = 1500;
    NetworkEvent first = base;
    base.ts = 2500;
    NetworkEvent middle = base;
    base.ts = 3000;
    NetworkEvent latest = base;

    REQUIRE(t.db.insert_network_events({first, middle, latest}));

    auto recent = t.db.query_recent_tcp_connections(/*since_ts=*/1000);
    REQUIRE(recent.has_value());
    REQUIRE(recent->size() == 1);
    CHECK(recent->at(0).ts == 3000);
    CHECK(recent->at(0).local_port == 60001);
}

TEST_CASE("TarDatabase: query_recent_tcp_connections filters out LISTEN and TIME_WAIT",
          "[tar][store][recent-tcp]") {
    auto t = make_test_db();

    NetworkEvent established;
    established.ts = 4000;
    established.action = "connected";
    established.proto = "tcp";
    established.local_addr = "10.0.0.10";
    established.local_port = 50100;
    established.remote_addr = "10.0.0.20";
    established.remote_port = 5432;
    established.state = "ESTABLISHED";
    established.pid = 300;
    established.process_name = "node";

    NetworkEvent listen;
    listen.ts = 4001;
    listen.action = "connected";
    listen.proto = "tcp";
    listen.local_addr = "0.0.0.0";
    listen.local_port = 3000;
    listen.remote_addr = "0.0.0.0";
    listen.remote_port = 0;
    listen.state = "LISTEN";
    listen.pid = 300;
    listen.process_name = "node";

    NetworkEvent time_wait;
    time_wait.ts = 4002;
    time_wait.action = "connected";
    time_wait.proto = "tcp";
    time_wait.local_addr = "10.0.0.10";
    time_wait.local_port = 50101;
    time_wait.remote_addr = "10.0.0.20";
    time_wait.remote_port = 5432;
    time_wait.state = "TIME_WAIT";
    time_wait.pid = 300;
    time_wait.process_name = "node";

    REQUIRE(t.db.insert_network_events({established, listen, time_wait}));

    auto recent = t.db.query_recent_tcp_connections(/*since_ts=*/0);
    REQUIRE(recent.has_value());
    REQUIRE(recent->size() == 1);
    CHECK(recent->at(0).state == "ESTABLISHED");
    CHECK(recent->at(0).local_port == 50100);
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
