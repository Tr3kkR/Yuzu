/**
 * test_tar_store.cpp -- Unit tests for TarDatabase (SQLite-backed TAR storage)
 *
 * Covers: open/create, warehouse tables, typed inserts, SQL queries,
 * stats, config get/set, state get/set.
 */

#include "tar_db.hpp"
#include "tar_netqual.hpp"
#include "tar_sql_executor.hpp"
#include "test_helpers.hpp"

#include <sqlite3.h> // raw handle for the reopen-after-DROP upgrade simulation

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#ifndef _WIN32
#include <unistd.h> // geteuid — the unmovable-quarantine test is POSIX-only
#endif

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

// =============================================================================
// Untrusted operator SQL sandbox — read-only handle + authorizer (#760), and
// the validate/execute divergence fix (#631). execute_user_query is called
// directly here so the engine-level controls are exercised independently of the
// validate_and_translate_sql text filter.
// =============================================================================

TEST_CASE("execute_user_query: SELECT on an allowlisted table succeeds",
          "[tar][store][sandbox][security]") {
    auto t = make_test_db();
    ProcessEvent ev;
    ev.ts = 1000;
    ev.snapshot_id = 1;
    ev.action = "started";
    ev.pid = 7;
    ev.name = "p";
    REQUIRE(t.db.insert_process_events({ev}));

    auto r = t.db.execute_user_query("SELECT COUNT(*) FROM process_live");
    REQUIRE(r.has_value());
    REQUIRE(r->rows.size() == 1);
    CHECK(r->rows[0][0] == "1");
}

TEST_CASE("execute_user_query: the DEX per-app canned aggregate shape stays authorizer-compatible",
          "[tar][store][sandbox][procperf][pin]") {
    // The server's /dex per-app panel dispatches this exact SQL shape
    // (dex_routes.cpp dex_procperf_sql(), with $ProcPerf_Hourly translated to
    // procperf_hourly). No other test runs aggregates through the REAL
    // authorizer on this table — an authorizer tightening that drops
    // SUM/MAX/CAST/COUNT/GROUP BY/ORDER BY-alias/LIMIT would otherwise break
    // the panel with no CI signal (governance G3 quality-engineer).
    auto t = make_test_db();
    REQUIRE(t.db.execute_sql(
        "INSERT INTO procperf_hourly (hour_ts, name, samples, instances_max, "
        "cpu_avg, cpu_max, ws_avg_bytes, ws_max_bytes) VALUES "
        "(3600, 'Teams.exe', 120, 6, 8.4, 41.2, 2040109465, 3328599654), "
        "(7200, 'Teams.exe', 120, 5, 4.0, 20.0, 1000000000, 2000000000)"));
    auto r = t.db.execute_user_query(
        "SELECT name, SUM(samples) AS samples, MAX(instances_max) AS instances_max, "
        "SUM(cpu_avg*samples)/SUM(samples) AS cpu_avg, MAX(cpu_max) AS cpu_max, "
        "CAST(SUM(ws_avg_bytes*samples)/SUM(samples) AS INTEGER) AS ws_avg, "
        "MAX(ws_max_bytes) AS ws_max, COUNT(*) AS hours "
        "FROM procperf_hourly WHERE hour_ts >= 0 "
        "GROUP BY name ORDER BY cpu_avg DESC LIMIT 25");
    REQUIRE(r.has_value());
    REQUIRE(r->rows.size() == 1);
    CHECK(r->rows[0][0] == "Teams.exe");
    CHECK(r->rows[0][1] == "240");  // SUM(samples)
    CHECK(r->rows[0][7] == "2");    // COUNT(*) hours
    // Column names ride the schema line the server parser locates fields by.
    REQUIRE(r->columns.size() == 8);
    CHECK(r->columns[0] == "name");
    CHECK(r->columns[3] == "cpu_avg");
    CHECK(r->columns[5] == "ws_avg");
}

TEST_CASE("execute_user_query: UNION across two allowlisted tables is permitted",
          "[tar][store][sandbox][security]") {
    auto t = make_test_db();
    // Both tar_config and tar_state are base tables on the allowlist; Option A
    // preserves the existing read scope rather than restricting to one table.
    auto r =
        t.db.execute_user_query("SELECT key FROM tar_config UNION SELECT collector FROM tar_state");
    CHECK(r.has_value());
}

TEST_CASE("execute_user_query: write statements are denied by the read-only sandbox",
          "[tar][store][sandbox][security]") {
    auto t = make_test_db();
    // These bypass validate_and_translate_sql entirely — the read-only handle and
    // authorizer are the layer under test.
    CHECK_FALSE(t.db.execute_user_query("INSERT INTO tar_config VALUES('k','v')").has_value());
    CHECK_FALSE(t.db.execute_user_query("UPDATE tar_config SET value='x'").has_value());
    CHECK_FALSE(t.db.execute_user_query("DELETE FROM tar_config").has_value());
    CHECK_FALSE(t.db.execute_user_query("DROP TABLE tar_config").has_value());
    // The store is untouched.
    CHECK(t.db.get_config("retention_days") == "7");
}

TEST_CASE("execute_user_query: ATTACH / PRAGMA / schema table are denied",
          "[tar][store][sandbox][security]") {
    auto t = make_test_db();
    CHECK_FALSE(t.db.execute_user_query("ATTACH DATABASE 'evil.db' AS e").has_value());
    CHECK_FALSE(t.db.execute_user_query("PRAGMA table_info(tar_config)").has_value());
    CHECK_FALSE(t.db.execute_user_query("SELECT name FROM sqlite_master").has_value());
}

TEST_CASE("execute_user_query: a non-allowlisted table is denied even via UNION",
          "[tar][store][sandbox][security]") {
    auto t = make_test_db();
    CHECK_FALSE(
        t.db.execute_user_query("SELECT key FROM tar_config UNION SELECT name FROM sqlite_master")
            .has_value());
}

TEST_CASE("execute_user_query: trailing statement is rejected at prepare",
          "[tar][store][sandbox][security]") {
    auto t = make_test_db();
    CHECK_FALSE(t.db.execute_user_query("SELECT 1; SELECT 2").has_value());
}

// ── validate_and_translate_sql — divergence fix (#631) + existing guards ──────

TEST_CASE("validate_and_translate_sql: $name in code is translated", "[tar][sql][validate]") {
    auto r = validate_and_translate_sql("SELECT * FROM $Process_Live");
    REQUIRE(r.has_value());
    CHECK(r->find("process_live") != std::string::npos);
    CHECK(r->find("$Process_Live") == std::string::npos);
}

TEST_CASE("validate_and_translate_sql: $name inside a string literal is NOT translated (#631)",
          "[tar][sql][validate][security]") {
    // The placeholder is data, not a table reference: it must survive verbatim so
    // the executed query equals the one that was validated.
    auto r = validate_and_translate_sql("SELECT '$Process_Live' AS label");
    REQUIRE(r.has_value());
    CHECK(r->find("$Process_Live") != std::string::npos);
    CHECK(r->find("process_live") == std::string::npos);
}

TEST_CASE("validate_and_translate_sql: unknown $name is rejected", "[tar][sql][validate]") {
    CHECK_FALSE(validate_and_translate_sql("SELECT * FROM $Made_Up").has_value());
}

TEST_CASE("validate_and_translate_sql: non-SELECT, multi-statement, oversize rejected",
          "[tar][sql][validate][security]") {
    CHECK_FALSE(validate_and_translate_sql("DELETE FROM $Process_Live").has_value());
    CHECK_FALSE(validate_and_translate_sql("SELECT * FROM $Process_Live; DROP TABLE tar_config")
                    .has_value());
    CHECK_FALSE(validate_and_translate_sql(std::string(5000, 'A')).has_value());
}

// ── #631 divergence — comment + escaped-quote coverage (governance Gate 3) ──

TEST_CASE("validate_and_translate_sql: $name in a line comment is not translated",
          "[tar][sql][validate][security]") {
    auto r = validate_and_translate_sql("SELECT 1 -- $Process_Live");
    REQUIRE(r.has_value());
    CHECK(r->find("$Process_Live") != std::string::npos);
    CHECK(r->find("process_live") == std::string::npos);
}

TEST_CASE("validate_and_translate_sql: $name in a block comment is not translated",
          "[tar][sql][validate][security]") {
    auto r = validate_and_translate_sql("SELECT /* $Process_Live */ 1");
    REQUIRE(r.has_value());
    CHECK(r->find("$Process_Live") != std::string::npos);
    CHECK(r->find("process_live") == std::string::npos);
}

TEST_CASE("validate_and_translate_sql: $name beside an escaped quote is not translated",
          "[tar][sql][validate][security]") {
    // '' is an escaped single quote inside the literal; the whole token is a
    // string, so $Process_Live within it must survive verbatim.
    auto r = validate_and_translate_sql("SELECT '$Process_Live''s data' AS x");
    REQUIRE(r.has_value());
    CHECK(r->find("$Process_Live") != std::string::npos);
    CHECK(r->find("process_live") == std::string::npos);
}

TEST_CASE("execute_user_query: pragma_table_info table-valued function is denied",
          "[tar][store][sandbox][security]") {
    auto t = make_test_db();
    // The pragma-as-TVF form reaches the authorizer as SQLITE_READ on a
    // non-allowlisted table name, so it is denied like any other.
    CHECK_FALSE(
        t.db.execute_user_query("SELECT * FROM pragma_table_info('tar_config')").has_value());
}

// =============================================================================
// A2: per-app perf rows + the every-open table-ensure regression
// =============================================================================

TEST_CASE("TarDatabase: insert_proc_perf_samples batch round-trips", "[tar][store][procperf]") {
    auto t = make_test_db();
    std::vector<ProcPerfRow> rows;
    for (int i = 0; i < 3; ++i) {
        ProcPerfRow r;
        r.ts = 2000 + i;
        r.snapshot_id = 7;
        r.name = "app" + std::to_string(i) + ".exe";
        r.instances = i + 1;
        r.cpu_pct = 10.0 * (i + 1);
        r.ws_bytes = (100 << 20) * (i + 1);
        rows.push_back(std::move(r));
    }
    REQUIRE(t.db.insert_proc_perf_samples(rows));
    REQUIRE(t.db.insert_proc_perf_samples({})); // empty batch is a no-op success

    auto q = t.db.execute_query("SELECT name, instances, cpu_pct, ws_bytes FROM procperf_live "
                                "ORDER BY name");
    REQUIRE(q.has_value());
    REQUIRE(q->rows.size() == 3);
    CHECK(q->rows[0][0] == "app0.exe");
    CHECK(q->rows[2][1] == "3");
}

TEST_CASE("TarDatabase: insert_netqual_samples batch round-trips", "[tar][store][netqual]") {
    auto t = make_test_db();
    std::vector<NetQualRow> rows;
    for (int i = 0; i < 3; ++i) {
        NetQualRow r;
        r.ts = 3000 + i;
        r.snapshot_id = 9;
        r.proto = "tcp";
        r.remote_bucket = (i == 0) ? "private" : "public"; // real remote_bucket() classes
        r.process_name = "app" + std::to_string(i);
        r.rtt_us = 1000 * (i + 1);
        r.rtt_var_us = 100 * (i + 1);
        r.lost = i; // row 0 = no current loss, rows 1/2 = current loss
        r.retrans = 5 * i;
        r.segs_out = 1000 * (i + 1);
        r.ca_state = (i == 2) ? 4 : 0; // app2 in TCP_CA_Loss
        rows.push_back(std::move(r));
    }
    REQUIRE(t.db.insert_netqual_samples(rows));
    REQUIRE(t.db.insert_netqual_samples({})); // empty batch is a no-op success

    auto q = t.db.execute_query(
        "SELECT proto, remote_bucket, process_name, rtt_us, lost, segs_out, ca_state "
        "FROM netqual_live ORDER BY process_name");
    REQUIRE(q.has_value());
    REQUIRE(q->rows.size() == 3);
    CHECK(q->rows[0][1] == "private");  // app0 destination class
    CHECK(q->rows[0][4] == "0");        // app0 current loss
    CHECK(q->rows[0][6] == "0");        // app0 ca_state = Open
    CHECK(q->rows[2][1] == "public");   // app2 destination class
    CHECK(q->rows[2][4] == "2");        // app2 current loss
    CHECK(q->rows[2][6] == "4");        // app2 ca_state = Loss

    // The degraded-as-query shape (a later server slice): fraction of a
    // snapshot's connections with CURRENT loss. Pin it here so the column
    // semantics stay query-able from the live tier.
    auto frac = t.db.execute_query(
        "SELECT SUM(CASE WHEN lost > 0 THEN 1 ELSE 0 END), COUNT(*) "
        "FROM netqual_live WHERE snapshot_id = 9");
    REQUIRE(frac.has_value());
    REQUIRE(frac->rows.size() == 1);
    CHECK(frac->rows[0][0] == "2"); // 2 of 3 connections currently losing
    CHECK(frac->rows[0][1] == "3");
}

TEST_CASE("netqual: remote_bucket classifies destinations into privacy-safe classes",
          "[tar][netqual][privacy]") {
    using yuzu::tar::remote_bucket;
    // Loopback.
    CHECK(remote_bucket("127.0.0.1") == "loopback");
    CHECK(remote_bucket("127.5.6.7") == "loopback");
    CHECK(remote_bucket("::1") == "loopback");
    // RFC1918 + link-local => private.
    CHECK(remote_bucket("10.0.0.5") == "private");
    CHECK(remote_bucket("192.168.1.20") == "private");
    CHECK(remote_bucket("169.254.10.10") == "private");
    CHECK(remote_bucket("172.16.0.1") == "private");
    CHECK(remote_bucket("172.31.255.254") == "private");
    CHECK(remote_bucket("fe80::1") == "private"); // link-local v6
    CHECK(remote_bucket("fd00::abcd") == "private"); // unique-local v6
    // 172.32 is OUT of the private /12 — public.
    CHECK(remote_bucket("172.32.0.1") == "public");
    CHECK(remote_bucket("172.15.0.1") == "public");
    CHECK(remote_bucket("8.8.8.8") == "public");
    CHECK(remote_bucket("2001:4860:4860::8888") == "public");
    // CGNAT 100.64.0.0/10 (RFC6598 shared space) => private; just-outside => public.
    CHECK(remote_bucket("100.64.0.1") == "private");
    CHECK(remote_bucket("100.127.255.254") == "private");
    CHECK(remote_bucket("100.63.255.1") == "public");
    CHECK(remote_bucket("100.128.0.1") == "public");
    // IPv4-mapped IPv6 (::ffff:a.b.c.d) classified by the embedded v4.
    CHECK(remote_bucket("::ffff:10.0.0.5") == "private");
    CHECK(remote_bucket("::ffff:127.0.0.1") == "loopback");
    CHECK(remote_bucket("::ffff:8.8.8.8") == "public");
    // Unknown / wildcard.
    CHECK(remote_bucket("") == "unknown");
    CHECK(remote_bucket("*") == "unknown");
}

TEST_CASE("netqual: select_netqual_rows drops the raw address and keeps degraded-first under cap",
          "[tar][netqual][privacy]") {
    using yuzu::tar::NetQualRow;
    using yuzu::tar::select_netqual_rows;
    using yuzu::tar::TcpQualitySample;

    std::vector<TcpQualitySample> samples;
    // Idle, very active, public destination — would dominate a by-activity cap.
    samples.push_back({"tcp", "8.8.8.8", "chrome", 5000, 100, 0, 0, 100000});
    // Losing connection, low activity, private destination — must be KEPT.
    samples.push_back({"tcp", "10.0.0.9", "vpnclient", 20000, 500, 7, 30, 200});
    // Idle, low activity — the one that should be dropped under cap=2.
    samples.push_back({"tcp", "192.168.1.5", "ssh", 8000, 200, 0, 0, 50});

    auto rows = select_netqual_rows(samples, /*ts=*/111, /*snapshot_id=*/222, /*cap=*/2);
    REQUIRE(rows.size() == 2);

    // Degraded-first: the losing connection ranks ahead of the idle high-activity one.
    CHECK(rows[0].process_name == "vpnclient");
    CHECK(rows[0].lost == 7);
    CHECK(rows[0].remote_bucket == "private");
    CHECK(rows[1].process_name == "chrome");
    CHECK(rows[1].lost == 0);
    CHECK(rows[1].remote_bucket == "public");

    // Privacy: NO row carries a raw address — only the coarse bucket. NetQualRow
    // has no remote_addr field at all, so this is structural; assert the bucket
    // is one of the known classes and never an IP literal.
    for (const auto& r : rows) {
        CHECK((r.remote_bucket == "loopback" || r.remote_bucket == "private" ||
               r.remote_bucket == "public" || r.remote_bucket == "unknown"));
        CHECK(r.remote_bucket.find('.') == std::string::npos);
        CHECK(r.ts == 111);
        CHECK(r.snapshot_id == 222);
    }
}

TEST_CASE("netqual: select_netqual_rows with cap=0 keeps everything", "[tar][netqual]") {
    using yuzu::tar::select_netqual_rows;
    using yuzu::tar::TcpQualitySample;
    std::vector<TcpQualitySample> samples(5);
    for (auto& s : samples) {
        s.proto = "tcp";
        s.remote_addr = "8.8.8.8";
    }
    auto rows = select_netqual_rows(samples, 1, 1, /*cap=*/0);
    CHECK(rows.size() == 5);
}

TEST_CASE("TarDatabase: insert_netqual_samples returns false (no crash) when the table is gone",
          "[tar][store][netqual]") {
    // Mirrors the procperf prepare-fail ROLLBACK path: drop netqual_live out
    // from under an open TarDatabase, then insert — prepare fails, the function
    // must ROLLBACK and return false without wedging the connection.
    auto t = make_test_db();
    REQUIRE(t.db.execute_query("DROP TABLE netqual_live").has_value());
    NetQualRow r;
    r.ts = 1;
    r.snapshot_id = 1;
    r.proto = "tcp";
    r.process_name = "x";
    CHECK_FALSE(t.db.insert_netqual_samples({r}));
    REQUIRE(t.db.execute_query("SELECT 1").has_value());
}

TEST_CASE("TarDatabase: insert_proc_perf_samples returns false (no crash) when the table is gone",
          "[tar][store][procperf]") {
    // The prepare-fail ROLLBACK path (gov QE S1): drop procperf_live out from
    // under an open TarDatabase via the trusted exec path, then insert —
    // sqlite3_prepare_v2 fails, the function must ROLLBACK and return false
    // without throwing or wedging the connection.
    auto t = make_test_db();
    REQUIRE(t.db.execute_query("DROP TABLE procperf_live").has_value());
    ProcPerfRow r;
    r.ts = 1;
    r.snapshot_id = 1;
    r.name = "x.exe";
    r.instances = 1;
    CHECK_FALSE(t.db.insert_proc_perf_samples({r}));
    // The connection is still usable afterwards (no wedged transaction).
    REQUIRE(t.db.execute_query("SELECT 1").has_value());
}

TEST_CASE("TarDatabase: missing warehouse tables are re-created on reopen (upgrade path)",
          "[tar][store][lifecycle]") {
    // The A1 regression this pins: create_warehouse_tables used to run only at
    // schema_version<2, so a table added by a NEWER release (perf tier,
    // procperf tier) never materialised on an upgraded fleet's existing
    // tar.db — inserts then failed every 30 s. The fix runs the idempotent
    // IF-NOT-EXISTS DDL on EVERY open. Simulate the upgrade by dropping a
    // "new" table from a closed v3 DB, then reopening.
    auto tmp = yuzu::test::unique_temp_path("tar_upg_");
    {
        auto db = TarDatabase::open(tmp);
        REQUIRE(db.has_value());
    } // closed

    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(tmp.string().c_str(), &raw) == SQLITE_OK);
        REQUIRE(sqlite3_exec(raw, "DROP TABLE procperf_live", nullptr, nullptr, nullptr) ==
                SQLITE_OK);
        sqlite3_close(raw);
    }

    {
        auto db = TarDatabase::open(tmp); // must re-create the dropped table
        REQUIRE(db.has_value());
        ProcPerfRow r;
        r.ts = 1;
        r.snapshot_id = 1;
        r.name = "x.exe";
        r.instances = 1;
        REQUIRE(db->insert_proc_perf_samples({r}));
    }

    std::error_code ec;
    fs::remove(tmp, ec);
    fs::remove(fs::path{tmp.string() + "-wal"}, ec);
    fs::remove(fs::path{tmp.string() + "-shm"}, ec);
}

// ── #559: corrupt-DB quarantine on open ────────────────────────────────────

TEST_CASE("TarDatabase: a corrupt tar.db is quarantined and re-initialised fresh (#559)",
          "[tar][store][lifecycle][corruption]") {
    auto tmp = yuzu::test::unique_temp_path("tar_corrupt_");

    // 1. Create a real DB and persist a deliberately-paused source. This is the
    //    forensic-preservation state a corrupt read must NOT silently undo.
    {
        auto opened = TarDatabase::open(tmp);
        REQUIRE(opened.has_value());
        TarDatabase db = std::move(*opened);
        REQUIRE(db.create_warehouse_tables());
        db.set_config("process_enabled", "false");
        CHECK(db.get_config("process_enabled", "true") == "false");
    } // connection closed; WAL checkpointed into the main file on close

    // 2. Corrupt it: drop any WAL/SHM sidecars and clobber the whole file with
    //    non-SQLite bytes so PRAGMA integrity_check fails deterministically.
    for (const char* suffix : {"-wal", "-shm"}) {
        std::error_code ec;
        fs::remove(fs::path{tmp.string() + suffix}, ec);
    }
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        REQUIRE(f.is_open());
        f << "this is not a valid sqlite database -- corrupt tar.db for #559";
    }

    // 3. Re-open: must succeed with a FRESH database (not refuse, not trust the
    //    garbage), and quarantine the corrupt file aside for forensic review.
    auto reopened = TarDatabase::open(tmp);
    REQUIRE(reopened.has_value());
    TarDatabase db2 = std::move(*reopened);
    REQUIRE(db2.create_warehouse_tables());

    // Fresh DB → the paused config is gone; the default "true" comes from a
    // CLEAN database, not a silent read-failure default over corrupt bytes.
    CHECK(db2.get_config("process_enabled", "true") == "true");

    // A timestamped quarantine sidecar exists next to the original path.
    bool found_quarantine = false;
    const std::string prefix = tmp.filename().string() + ".corrupt-";
    for (const auto& entry : fs::directory_iterator(tmp.parent_path())) {
        if (entry.path().filename().string().rfind(prefix, 0) == 0) {
            found_quarantine = true;
            std::error_code ec;
            fs::remove(entry.path(), ec); // tidy up the quarantine artifact
        }
    }
    CHECK(found_quarantine);
}

TEST_CASE("TarDatabase: a valid DB opens cleanly with no quarantine and preserves data (#559)",
          "[tar][store][lifecycle][corruption]") {
    // The happy path: integrity_ok returns true, so a previously-written DB is
    // re-opened in place with its data intact and NO `.corrupt-*` sidecar minted
    // (guards against an integrity_ok that wrongly fails every open).
    auto tmp = yuzu::test::unique_temp_path("tar_valid_");
    {
        auto opened = TarDatabase::open(tmp);
        REQUIRE(opened.has_value());
        TarDatabase db = std::move(*opened);
        db.set_config("process_enabled", "false");
    }
    auto reopened = TarDatabase::open(tmp);
    REQUIRE(reopened.has_value());
    TarDatabase db = std::move(*reopened);
    // Data survived — NOT reset to the default.
    CHECK(db.get_config("process_enabled", "true") == "false");
    // No quarantine sidecar was created for a healthy DB.
    const std::string prefix = tmp.filename().string() + ".corrupt-";
    for (const auto& entry : fs::directory_iterator(tmp.parent_path()))
        CHECK(entry.path().filename().string().rfind(prefix, 0) != 0);
    std::error_code ec;
    fs::remove(tmp, ec);
    fs::remove(fs::path{tmp.string() + "-wal"}, ec);
    fs::remove(fs::path{tmp.string() + "-shm"}, ec);
}

#ifndef _WIN32
TEST_CASE("TarDatabase: a corrupt-and-unmovable tar.db fails closed (#559 primary)",
          "[tar][store][lifecycle][corruption]") {
    // The PRIMARY #559 safety property: when a corrupt tar.db CANNOT be moved
    // aside (read-only mount, locked file, permissions), open() must REFUSE
    // (std::unexpected) rather than re-open-and-trust the still-corrupt file —
    // doing so would serve the "true" get_config default for every
    // <source>_enabled key and silently re-enable an operator-paused source.
    // POSIX-only: modelled with a read-only parent dir so the quarantine rename
    // fails. (Windows reparse/rename behaviour is a separate, static-reviewed
    // path with no CI here.)
    if (::geteuid() == 0) {
        SKIP("root bypasses directory permissions; cannot make the rename fail");
    }

    auto dir = yuzu::test::unique_temp_path("tar_unmovable_");
    REQUIRE(fs::create_directory(dir));
    // RAII: re-add write perms and remove the dir even if an assertion throws,
    // so a read-only temp dir never leaks onto a CI box that reuses workspaces.
    struct DirGuard {
        fs::path dir;
        ~DirGuard() {
            std::error_code ec;
            fs::permissions(dir, fs::perms::owner_all, fs::perm_options::add, ec);
            fs::remove_all(dir, ec);
        }
    } dir_guard{dir};
    const auto db_path = dir / "tar.db";

    // 1. Create a valid DB with a deliberately-paused source, then corrupt it.
    {
        auto opened = TarDatabase::open(db_path);
        REQUIRE(opened.has_value());
        TarDatabase db = std::move(*opened);
        REQUIRE(db.create_warehouse_tables());
        db.set_config("process_enabled", "false");
    }
    for (const char* suffix : {"-wal", "-shm"}) {
        std::error_code ec;
        fs::remove(fs::path{db_path.string() + suffix}, ec);
    }
    {
        std::ofstream f(db_path, std::ios::binary | std::ios::trunc);
        REQUIRE(f.is_open());
        f << "not a valid sqlite database -- corrupt + unmovable (#559)";
    }

    // 2. Strip write permission from the parent dir so the .corrupt-<epoch>
    //    rename inside it fails → quarantine returns nullopt → fail closed.
    std::error_code perm_ec;
    fs::permissions(dir,
                    fs::perms::owner_write | fs::perms::group_write | fs::perms::others_write,
                    fs::perm_options::remove, perm_ec);
    REQUIRE_FALSE(perm_ec);

    // 3. open() must REFUSE — not silently re-init a fresh DB over the corruption.
    auto reopened = TarDatabase::open(db_path);
    CHECK_FALSE(reopened.has_value());
    if (!reopened.has_value())
        CHECK(reopened.error().find("corrupt and unmovable") != std::string::npos);
    // dir_guard restores perms + removes the dir.
}
#endif // _WIN32
