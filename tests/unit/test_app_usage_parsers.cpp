/**
 * test_app_usage_parsers.cpp — pure app_usage sqlite seam
 * (app_usage_parsers.hpp).
 *
 * Every SQL/format function under test takes an already-open `sqlite3*` —
 * no OS dependency, so these run identically on every host. The
 * `:memory:` fixture db is built with real-looking user names and pids
 * deliberately, and a negative assertion proves none of that leaks into
 * any formatted output line — that is the whole point of the
 * `usage_daily_user`/`usage_live` count-only reads this header performs.
 */

#include "app_usage_parsers.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>

using namespace yuzu::app_usage;

namespace {

void exec_or_fail(sqlite3* db, const char* sql) {
    char* err = nullptr;
    const int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        const std::string msg = err ? err : "unknown";
        sqlite3_free(err);
        FAIL("sqlite3_exec failed: " << msg << " -- sql: " << sql);
    }
}

/// Builds the fixture schema/rows shared by every run_summary/run_last_used
/// /read_meta test below: usage_daily (2 exes, spread over two days inside
/// the default 30-day window), usage_daily_user (containing REAL-LOOKING
/// user names — never expected to appear in any formatted output),
/// usage_live (containing REAL pids — likewise never expected to leak),
/// and tar_config (every key this plugin is allowed to read, all non-zero).
class Fixture {
public:
    Fixture() {
        REQUIRE(sqlite3_open(":memory:", &db_) == SQLITE_OK);
        exec_or_fail(db_, "CREATE TABLE usage_daily (day_ts INTEGER, exe_key TEXT, "
                          "run_count INTEGER, total_seconds INTEGER, first_seen INTEGER, "
                          "last_seen INTEGER, superseded_runs INTEGER, expired_runs INTEGER)");
        exec_or_fail(db_, "CREATE TABLE usage_daily_user (day_ts INTEGER, exe_key TEXT, "
                          "user TEXT)");
        exec_or_fail(db_, "CREATE TABLE usage_live (pid INTEGER, exe_key TEXT, user TEXT, "
                          "start_ts INTEGER)");
        exec_or_fail(db_, "CREATE TABLE tar_config (key TEXT PRIMARY KEY, value TEXT)");

        // day_ts 100000 (older) and 186400 (one day later) — both inside a
        // 30-day window anchored at/after 186400.
        exec_or_fail(db_, "INSERT INTO usage_daily VALUES "
                          "(100000, 'chrome.exe', 4, 4000, 100000, 103000, 1, 0), "
                          "(186400, 'chrome.exe', 6, 6000, 186400, 190000, 0, 2), "
                          "(186400, 'notepad.exe', 2, 200, 186400, 186600, 0, 0)");
        exec_or_fail(db_, "INSERT INTO usage_daily_user VALUES "
                          "(186400, 'chrome.exe', 'alice.jones'), "
                          "(186400, 'chrome.exe', 'bob.smith'), "
                          "(186400, 'notepad.exe', 'alice.jones')");
        exec_or_fail(db_, "INSERT INTO usage_live VALUES "
                          "(4242, 'chrome.exe', 'alice.jones', 190500), "
                          "(9911, 'notepad.exe', 'bob.smith', 190600)");
        exec_or_fail(db_, "INSERT INTO tar_config VALUES "
                          "('usage_enabled', 'true'), "
                          "('process_enabled', 'true'), "
                          "('usage_feeder_enabled', 'true'), "
                          "('usage_coverage_since', '90000'), "
                          "('usage_unmatched_stops', '3'), "
                          "('usage_clock_anomalies', '1'), "
                          "('usage_gap_count', '2'), "
                          "('usage_gap_lost_events', '17'), "
                          "('usage_gap_last_ts', '150000'), "
                          "('usage_lag_events', '5'), "
                          "('usage_last_fold_ts', '190700')");
    }
    ~Fixture() {
        if (db_)
            sqlite3_close(db_);
    }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;

    sqlite3* db() const { return db_; }

private:
    sqlite3* db_{nullptr};
};

} // namespace

// ─────────────────────────────────────────────────── parse_window_params ──

TEST_CASE("parse_window_params: defaults with empty inputs", "[app_usage][params]") {
    const auto w = parse_window_params("", "", "");
    CHECK(w.days == 30);
    CHECK(w.top == 25);
    CHECK(w.by == WindowParams::By::run_time);
}

TEST_CASE("parse_window_params: days clamped to [1, 365]", "[app_usage][params]") {
    CHECK(parse_window_params("0", "10", "").days == 1);
    CHECK(parse_window_params("-5", "10", "").days == 1);
    CHECK(parse_window_params("400", "10", "").days == 365);
    CHECK(parse_window_params("90", "10", "").days == 90);
    CHECK(parse_window_params("not_a_number", "10", "").days == 30); // unparsable -> default
}

TEST_CASE("parse_window_params: top clamped to [1, 500]", "[app_usage][params]") {
    CHECK(parse_window_params("10", "0", "").top == 1);
    CHECK(parse_window_params("10", "9999", "").top == 500);
    CHECK(parse_window_params("10", "100", "").top == 100);
}

TEST_CASE("parse_window_params: by run_count/run_time recognised; anything else -> unmodelled",
          "[app_usage][params]") {
    CHECK(parse_window_params("10", "10", "run_time").by == WindowParams::By::run_time);
    CHECK(parse_window_params("10", "10", "run_count").by == WindowParams::By::run_count);
    CHECK(parse_window_params("10", "10", "bogus").by == WindowParams::By::unmodelled);
    CHECK(parse_window_params("10", "10", "RUN_TIME").by == WindowParams::By::unmodelled);
}

// ────────────────────────────────────────────────── normalise_exe_key() ───

TEST_CASE("normalise_exe_key: 10-input parity with tar_usage.hpp's rule "
          "(lowercase, basename, trim, empty -> (unknown))",
          "[app_usage][exe_key]") {
    CHECK(normalise_exe_key("Chrome.EXE") == "chrome.exe");
    CHECK(normalise_exe_key("C:\\Program Files\\Google\\Chrome.exe") == "chrome.exe");
    CHECK(normalise_exe_key("/usr/bin/bash") == "bash");
    CHECK(normalise_exe_key("  notepad.exe  ") == "notepad.exe");
    CHECK(normalise_exe_key("") == "(unknown)");
    CHECK(normalise_exe_key("   ") == "(unknown)");
    CHECK(normalise_exe_key("firefox") == "firefox");
    CHECK(normalise_exe_key("/opt/app/Weird.Name.BIN") == "weird.name.bin");
    CHECK(normalise_exe_key("C:/mixed/slashes\\App.exe") == "app.exe");
    CHECK(normalise_exe_key("systemd-journald") == "systemd-journald"); // 15-char comm, untouched
}

// ─────────────────────────────────────────────────────────── SQL pinning ──

TEST_CASE("summary SQL text is pinned", "[app_usage][sql]") {
    CHECK(kSummarySqlByRunTime ==
         "SELECT exe_key, SUM(run_count), SUM(total_seconds), MIN(first_seen), MAX(last_seen), "
         "SUM(superseded_runs), SUM(expired_runs) FROM usage_daily WHERE day_ts >= ? "
         "GROUP BY exe_key ORDER BY SUM(total_seconds) DESC LIMIT ?");
    CHECK(kSummarySqlByRunCount ==
         "SELECT exe_key, SUM(run_count), SUM(total_seconds), MIN(first_seen), MAX(last_seen), "
         "SUM(superseded_runs), SUM(expired_runs) FROM usage_daily WHERE day_ts >= ? "
         "GROUP BY exe_key ORDER BY SUM(run_count) DESC LIMIT ?");
}

// ────────────────────────────────────────────────────────────── read_meta ─

TEST_CASE("read_meta: every fixture counter is NON-ZERO and correctly read", "[app_usage][meta]") {
    Fixture fx;
    const auto meta = read_meta(fx.db(), /*since_day_ts=*/150000);
    REQUIRE(meta.has_value());
    CHECK(meta->coverage_since == "90000");
    CHECK(meta->days_present == 1); // only day_ts=186400 is >= 150000
    CHECK(meta->open_runs == 2);    // usage_live has 2 rows
    CHECK(meta->unmatched_stops == 3);
    CHECK(meta->clock_anomalies == 1);
    CHECK(meta->gap_count == 2);
    CHECK(meta->gap_lost_events == 17);
    CHECK(meta->gap_last_ts == "150000");
    CHECK(meta->lag_events == 5);
    CHECK(meta->feeder_enabled);
    CHECK(meta->last_fold_ts == "190700");
}

TEST_CASE("read_meta: missing tar_config keys fall back to honest defaults",
          "[app_usage][meta]") {
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open(":memory:", &db) == SQLITE_OK);
    exec_or_fail(db, "CREATE TABLE usage_daily (day_ts INTEGER, exe_key TEXT, run_count INTEGER, "
                     "total_seconds INTEGER, first_seen INTEGER, last_seen INTEGER, "
                     "superseded_runs INTEGER, expired_runs INTEGER)");
    exec_or_fail(db, "CREATE TABLE usage_live (pid INTEGER)");
    exec_or_fail(db, "CREATE TABLE tar_config (key TEXT PRIMARY KEY, value TEXT)");

    const auto meta = read_meta(db);
    REQUIRE(meta.has_value());
    CHECK(meta->coverage_since == "-");
    CHECK(meta->open_runs == 0);
    CHECK(meta->unmatched_stops == 0);
    CHECK(meta->feeder_enabled); // default true when the key is absent
    sqlite3_close(db);
}

// ────────────────────────────────────────────────────────── run_summary ───

TEST_CASE("run_summary: rows correct, ordered by total_seconds by default, "
          "and NO fixture user/pid token leaks into any formatted line",
          "[app_usage][summary]") {
    Fixture fx;
    WindowParams w;
    w.days = 30;
    w.top = 25;
    w.by = WindowParams::By::run_time;

    const auto result = run_summary(fx.db(), w, /*since_day_ts=*/0);
    REQUIRE(result.has_value());
    REQUIRE(result->rows.size() == 2);

    // chrome.exe aggregates both day_ts rows; ordered first (higher total_seconds).
    const auto& chrome = result->rows[0];
    CHECK(chrome.exe_key == "chrome.exe");
    CHECK(chrome.run_count == 10);
    CHECK(chrome.total_seconds == 10000);
    CHECK(chrome.first_seen == 100000);
    CHECK(chrome.last_seen == 190000);
    CHECK(chrome.distinct_users == 2); // alice + bob, count only
    CHECK(chrome.superseded_runs == 1);
    CHECK(chrome.expired_runs == 2);

    const auto& notepad = result->rows[1];
    CHECK(notepad.exe_key == "notepad.exe");
    CHECK(notepad.run_count == 2);
    CHECK(notepad.distinct_users == 1);

    std::string meta_line = format_meta_line(w, *read_meta(fx.db(), 0));
    std::string rows_text;
    for (const auto& r : result->rows)
        rows_text += format_usage_row(r) + "\n";

    for (const char* forbidden : {"alice", "jones", "bob", "smith", "4242", "9911"}) {
        INFO("forbidden token: " << forbidden);
        CHECK(meta_line.find(forbidden) == std::string::npos);
        CHECK(rows_text.find(forbidden) == std::string::npos);
    }
}

TEST_CASE("run_summary: ordered by run_count when by=run_count", "[app_usage][summary]") {
    Fixture fx;
    WindowParams w;
    w.days = 30;
    w.top = 25;
    w.by = WindowParams::By::run_count;

    const auto result = run_summary(fx.db(), w, 0);
    REQUIRE(result.has_value());
    REQUIRE(result->rows.size() == 2);
    CHECK(result->rows[0].exe_key == "chrome.exe"); // run_count 10 > 2
}

TEST_CASE("run_summary: since_day_ts window excludes the older day", "[app_usage][summary]") {
    Fixture fx;
    WindowParams w;
    w.days = 1;
    w.top = 25;
    w.by = WindowParams::By::run_time;

    const auto result = run_summary(fx.db(), w, /*since_day_ts=*/150000);
    REQUIRE(result.has_value());
    REQUIRE(result->rows.size() == 2);
    for (const auto& row : result->rows)
        CHECK(row.first_seen >= 150000); // only the 186400 day_ts rows qualify
}

TEST_CASE("run_summary: top limit is respected", "[app_usage][summary]") {
    Fixture fx;
    WindowParams w;
    w.days = 30;
    w.top = 1;
    w.by = WindowParams::By::run_time;

    const auto result = run_summary(fx.db(), w, 0);
    REQUIRE(result.has_value());
    REQUIRE(result->rows.size() == 1);
    CHECK(result->rows[0].exe_key == "chrome.exe");
}

// ─────────────────────────────────────────────────────────── run_last_used ─

TEST_CASE("run_last_used: no exe filter returns every exe_key, all-time + 30d window",
          "[app_usage][last_used]") {
    Fixture fx;
    const auto rows = run_last_used(fx.db(), std::nullopt, /*since_30d_ts=*/0);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 2);

    const auto it = std::find_if(rows->begin(), rows->end(),
                                 [](const auto& r) { return r.exe_key == "chrome.exe"; });
    REQUIRE(it != rows->end());
    CHECK(it->last_seen == 190000);  // all-time MAX
    CHECK(it->first_seen == 100000); // all-time MIN
    CHECK(it->run_count_30d == 10);  // since_30d_ts=0 includes both day_ts rows
    CHECK(it->total_seconds_30d == 10000);
}

TEST_CASE("run_last_used: exe filter is normalised the same way as stored exe_key",
          "[app_usage][last_used]") {
    Fixture fx;
    // Mixed case / path-qualified — must normalise to "chrome.exe" to match.
    const auto rows = run_last_used(fx.db(), std::string_view{"C:\\apps\\Chrome.EXE"}, 0);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK(rows->front().exe_key == "chrome.exe");
}

TEST_CASE("run_last_used: unknown exe filter returns zero rows, not an error",
          "[app_usage][last_used]") {
    Fixture fx;
    const auto rows = run_last_used(fx.db(), std::string_view{"never_seen.exe"}, 0);
    REQUIRE(rows.has_value());
    CHECK(rows->empty());
}

// ───────────────────────────────────────────────────────── schema check ───

TEST_CASE("usage_daily_table_exists: true with the table, false without", "[app_usage][schema]") {
    Fixture fx;
    CHECK(usage_daily_table_exists(fx.db()));

    sqlite3* empty_db = nullptr;
    REQUIRE(sqlite3_open(":memory:", &empty_db) == SQLITE_OK);
    CHECK_FALSE(usage_daily_table_exists(empty_db));
    sqlite3_close(empty_db);
}

// ──────────────────────────────────────────── RO+WAL open, on-disk temp db ─

TEST_CASE("plugin's exact open flags (RO|NOMUTEX) succeed against a WAL-mode on-disk db",
          "[app_usage][sqlite][wal]") {
    yuzu::test::TempDbFile fixture_db{"yuzu_test_app_usage-"};

    sqlite3* writer = nullptr;
    REQUIRE(sqlite3_open(fixture_db.path.string().c_str(), &writer) == SQLITE_OK);
    exec_or_fail(writer, "PRAGMA journal_mode=WAL");
    exec_or_fail(writer, "CREATE TABLE usage_daily (day_ts INTEGER, exe_key TEXT, "
                         "run_count INTEGER, total_seconds INTEGER, first_seen INTEGER, "
                         "last_seen INTEGER, superseded_runs INTEGER, expired_runs INTEGER)");
    exec_or_fail(writer, "INSERT INTO usage_daily VALUES (100, 'x.exe', 1, 1, 100, 100, 0, 0)");

    sqlite3* reader = nullptr;
    const int rc = sqlite3_open_v2(fixture_db.path.string().c_str(), &reader,
                                   SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nullptr);
    REQUIRE(rc == SQLITE_OK);
    REQUIRE(reader != nullptr);
    sqlite3_busy_timeout(reader, 2000);
    REQUIRE(sqlite3_exec(reader, "PRAGMA query_only=1", nullptr, nullptr, nullptr) == SQLITE_OK);

    CHECK(usage_daily_table_exists(reader));
    const auto rows = run_last_used(reader, std::nullopt, 0);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK(rows->front().exe_key == "x.exe");

    sqlite3_close(reader);
    sqlite3_close(writer);
}

// ─────────────────────────────────────────────────────────── formatting ───

TEST_CASE("format_meta_line / format_usage_row / format_last_used_row shapes",
          "[app_usage][format]") {
    WindowParams w;
    w.days = 7;
    MetaInfo m;
    m.coverage_since = "1000";
    m.days_present = 3;
    m.open_runs = 2;
    m.feeder_enabled = false;
    const auto meta_line = format_meta_line(w, m);
    CHECK(meta_line.rfind("meta|window_days|7|", 0) == 0);
    CHECK(meta_line.find("|feeder_enabled|0|") != std::string::npos);

    UsageRow row;
    row.exe_key = "app.exe";
    row.run_count = 3;
    const auto usage_line = format_usage_row(row);
    CHECK(usage_line.rfind("usage|app.exe|3|", 0) == 0);

    LastUsedRow lu;
    lu.exe_key = "app.exe";
    lu.last_seen = 42;
    const auto lu_line = format_last_used_row(lu);
    CHECK(lu_line == "last_used|app.exe|42|0|0|0");
}
