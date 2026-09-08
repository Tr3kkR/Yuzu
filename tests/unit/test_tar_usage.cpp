/**
 * test_tar_usage.cpp -- Unit tests for the TAR `usage` derived fold
 * (tar_usage.hpp pure pairing logic + tar_usage.cpp's TarDatabase-backed
 * run_usage_fold / usage_rebaseline).
 *
 * Two halves:
 *  - Pure pairing tests exercise apply_event / expire_open_runs /
 *    cap_open_runs / fold_daily directly, with NO database. The
 *    normal-pairing and orphan-stop shapes are driven from A2's REAL
 *    CAPTURE fixtures (process_events_{linux,macos}.txt) -- located via
 *    YUZU_TEST_FIXTURE_DIR and REQUIRE(exists), never SKIPPED (a missing
 *    fixture is a build-wiring defect, not a green test). The remaining
 *    fold-logic edge cases (pid reuse, clock step, expiry, cap, midnight
 *    attribution) cannot occur in a captured trace by construction (you
 *    cannot capture "20001 processes open at once" or "the clock stepped
 *    backwards") and are therefore synthetic ProcessEvent/ClosedRun inputs.
 *  - DB tests drive run_usage_fold()/usage_rebaseline() against a real
 *    on-disk TarDatabase (yuzu::test::unique_temp_path, mirroring
 *    test_tar_cursor.cpp / test_tar_store.cpp). Because the `usage`
 *    CaptureSourceDef row is integrator-owned (IT-TAR-SOURCE) and lands in
 *    a separate package, ensure_usage_schema() below creates usage_live /
 *    usage_daily / usage_daily_user + both unique indexes directly with
 *    CREATE TABLE/INDEX IF NOT EXISTS -- byte-identical to what the
 *    registry row and this file's own v6 migration declare -- so these
 *    tests are self-sufficient whether or not the registry row has landed
 *    in the build they run against.
 */

#include "tar_db.hpp"
#include "tar_usage.hpp"
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <sqlite3.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::tar;
using namespace yuzu::tar::usage;

namespace {

// ── Fixture loading (pure half) ─────────────────────────────────────────────

fs::path fixture_path(const char* name) {
    return fs::path(YUZU_TEST_FIXTURE_DIR) / "wave7" / "app_usage" / name;
}

// Parses this fixture set's own convention: ts_unix|action|pid|ppid|image_name|user
// (see process_events_linux.txt.provenance.txt). ppid is unused by the fold.
std::vector<ProcessEvent> load_fixture(const fs::path& p) {
    std::vector<ProcessEvent> events;
    std::ifstream in(p);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty())
            continue;
        std::istringstream ls(line);
        std::string ts_s, action, pid_s, ppid_s, name, user;
        std::getline(ls, ts_s, '|');
        std::getline(ls, action, '|');
        std::getline(ls, pid_s, '|');
        std::getline(ls, ppid_s, '|');
        std::getline(ls, name, '|');
        std::getline(ls, user, '|');
        ProcessEvent pe;
        pe.ts = std::stoll(ts_s);
        pe.action = action;
        pe.pid = static_cast<uint32_t>(std::stoul(pid_s));
        pe.name = name;
        pe.user = user;
        events.push_back(std::move(pe));
    }
    return events;
}

// ── DB harness (mirrors test_tar_cursor.cpp / test_tar_store.cpp) ──────────

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

// Byte-identical to the schema this file's v6 migration (tar_db.cpp) and the
// integrator's "usage" CaptureSourceDef row both declare -- see the file
// banner. Idempotent (IF NOT EXISTS), so it is harmless whichever lands
// first in a given build.
void ensure_usage_schema(TarDatabase& db) {
    REQUIRE(db.execute_sql(
        "CREATE TABLE IF NOT EXISTS usage_live (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "ts INTEGER, snapshot_id INTEGER, action TEXT, pid INTEGER, exe_key TEXT, "
        "user TEXT, start_ts INTEGER)"));
    REQUIRE(db.execute_sql(
        "CREATE TABLE IF NOT EXISTS usage_daily (day_ts INTEGER, exe_key TEXT, "
        "run_count INTEGER, total_seconds INTEGER, first_seen INTEGER, last_seen INTEGER, "
        "distinct_users INTEGER, superseded_runs INTEGER, expired_runs INTEGER)"));
    REQUIRE(db.execute_sql(
        "CREATE TABLE IF NOT EXISTS usage_daily_user (day_ts INTEGER NOT NULL, "
        "exe_key TEXT NOT NULL, user TEXT NOT NULL, PRIMARY KEY(day_ts, exe_key, user))"));
    REQUIRE(db.execute_sql(
        "CREATE UNIQUE INDEX IF NOT EXISTS usage_daily_day_exe_uq ON usage_daily(day_ts, exe_key)"));
    REQUIRE(db.execute_sql(
        "CREATE UNIQUE INDEX IF NOT EXISTS usage_live_pid_exe_uq ON usage_live(pid, exe_key)"));
}

TestTarDb make_test_db() {
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_tar_usage_");
    auto result = TarDatabase::open(tmp);
    REQUIRE(result.has_value());
    // Mutate through the std::expected's value BEFORE moving it into the
    // returned prvalue -- TestTarDb has no move constructor (its
    // user-provided destructor suppresses the implicit one), so this must
    // stay a single `return TestTarDb{...};` construction (guaranteed
    // copy elision) rather than building a named local and returning it,
    // which would need a move/copy TestTarDb cannot provide (TarDatabase's
    // copy constructor is deleted).
    ensure_usage_schema(*result);
    result->set_config("process_enabled", "true");
    result->set_config("usage_enabled", "true");
    return TestTarDb{std::move(*result), tmp};
}

ProcessEvent mk(int64_t ts, const char* action, uint32_t pid, const char* name,
                const char* user = "alice") {
    ProcessEvent pe;
    pe.ts = ts;
    pe.action = action;
    pe.pid = pid;
    pe.name = name;
    pe.user = user;
    return pe;
}

} // namespace

// ─────────────────────────────────────────────── pure pairing: fixtures ────

TEST_CASE("tar_usage: real-capture linux fixture pairs normally and surfaces the orphan stop",
         "[tar_usage]") {
    const auto p = fixture_path("process_events_linux.txt");
    REQUIRE(std::filesystem::exists(p)); // never SKIP a missing fixture
    auto events = load_fixture(p);
    REQUIRE(!events.empty());

    FoldState state;
    std::vector<ClosedRun> closed;
    for (const auto& ev : events) {
        if (auto c = apply_event(state, ev))
            closed.push_back(std::move(*c));
    }

    // The capture methodology (see .provenance.txt) guarantees at least one
    // pre-existing pid whose "stopped" has no matching "started" in-window --
    // an orphan stop -- alongside plenty of ordinary open/close pairs.
    CHECK(state.unmatched_stops > 0);
    const auto normal_count =
        std::count_if(closed.begin(), closed.end(),
                      [](const ClosedRun& c) { return c.kind == ClosedRun::Kind::normal; });
    CHECK(normal_count > 0);
    for (const auto& c : closed) {
        CHECK(c.end_ts >= c.start_ts); // duration never negative
        CHECK(!c.exe_key.empty());
    }
}

TEST_CASE("tar_usage: real-capture macos fixture pairs normally and surfaces the orphan stop",
         "[tar_usage]") {
    const auto p = fixture_path("process_events_macos.txt");
    REQUIRE(std::filesystem::exists(p)); // never SKIP a missing fixture
    auto events = load_fixture(p);
    REQUIRE(!events.empty());

    FoldState state;
    std::vector<ClosedRun> closed;
    for (const auto& ev : events) {
        if (auto c = apply_event(state, ev))
            closed.push_back(std::move(*c));
    }

    CHECK(state.unmatched_stops > 0);
    const auto normal_count =
        std::count_if(closed.begin(), closed.end(),
                      [](const ClosedRun& c) { return c.kind == ClosedRun::Kind::normal; });
    CHECK(normal_count > 0);

    // exe_key normalisation: macOS names carry full paths ("/bin/sleep") and
    // bare comm names ("sleep") for the SAME logical process across its
    // started/stopped pair in this trace -- normalise_exe_key must fold both
    // to the same key ("sleep") or every /bin/sleep start would orphan its
    // bare-name stop.
    bool saw_sleep_key = false;
    for (const auto& c : closed) {
        if (c.exe_key == "sleep")
            saw_sleep_key = true;
    }
    CHECK(saw_sleep_key);
}

// ───────────────────────────────────────── pure pairing: synthetic edges ───

TEST_CASE("tar_usage: normalise_exe_key rules", "[tar_usage]") {
    CHECK(normalise_exe_key("/usr/bin/Sleep") == "sleep");
    CHECK(normalise_exe_key("C:\\Windows\\System32\\Notepad.EXE") == "notepad.exe");
    CHECK(normalise_exe_key("  chrome  ") == "chrome");
    CHECK(normalise_exe_key("") == "(unknown)");
    CHECK(normalise_exe_key("   ") == "(unknown)");
}

TEST_CASE("tar_usage: pid reuse closes the old run as superseded", "[tar_usage]") {
    FoldState state;
    auto first_close = apply_event(state, mk(100, "started", 42, "app"));
    CHECK(!first_close.has_value()); // nothing to close yet
    auto second_close = apply_event(state, mk(200, "started", 42, "app"));
    REQUIRE(second_close.has_value());
    CHECK(second_close->kind == ClosedRun::Kind::superseded);
    CHECK(second_close->start_ts == 100);
    CHECK(second_close->end_ts == 200);
    REQUIRE(state.open.size() == 1);
    CHECK(state.open.begin()->second.start_ts == 200); // the NEW run is open
    CHECK(state.unmatched_stops == 0);
}

TEST_CASE("tar_usage: orphan stop is unmatched and closes nothing", "[tar_usage]") {
    FoldState state;
    auto closed = apply_event(state, mk(100, "stopped", 7, "ghost"));
    CHECK(!closed.has_value());
    CHECK(state.unmatched_stops == 1);
    CHECK(state.open.empty());
}

TEST_CASE("tar_usage: a clock step backwards clamps duration to 0 and counts an anomaly",
         "[tar_usage]") {
    FoldState state;
    REQUIRE(!apply_event(state, mk(1000, "started", 9, "app")).has_value());
    auto closed = apply_event(state, mk(500, "stopped", 9, "app")); // ts < start_ts
    REQUIRE(closed.has_value());
    CHECK(closed->kind == ClosedRun::Kind::normal);
    CHECK(closed->start_ts == 1000);
    CHECK(closed->end_ts == 1000); // clamped, never negative or fabricated
    CHECK(state.clock_anomalies == 1);
}

TEST_CASE("tar_usage: a run older than max_age expires at 0 duration", "[tar_usage]") {
    FoldState state;
    REQUIRE(!apply_event(state, mk(0, "started", 1, "app")).has_value());

    // Exactly at the boundary: not yet expired (> , not >=).
    auto at_boundary = expire_open_runs(state, /*now=*/kDefaultMaxAgeSeconds, kDefaultMaxAgeSeconds);
    CHECK(at_boundary.empty());
    CHECK(state.open.size() == 1);

    auto past_boundary =
        expire_open_runs(state, /*now=*/kDefaultMaxAgeSeconds + 1, kDefaultMaxAgeSeconds);
    REQUIRE(past_boundary.size() == 1);
    CHECK(past_boundary[0].kind == ClosedRun::Kind::expired);
    CHECK(past_boundary[0].end_ts == past_boundary[0].start_ts); // never fabricated
    CHECK(state.open.empty());
}

TEST_CASE("tar_usage: cap_open_runs bounds the open set by evicting the oldest",
         "[tar_usage]") {
    FoldState state;
    for (uint32_t pid = 0; pid < kMaxOpenRuns + 1; ++pid) {
        // start_ts == pid, so pid 0 is the oldest and must be the one capped.
        REQUIRE(!apply_event(state, mk(static_cast<int64_t>(pid), "started", pid, "app"))
                     .has_value());
    }
    REQUIRE(state.open.size() == kMaxOpenRuns + 1);

    auto capped = cap_open_runs(state);
    REQUIRE(capped.size() == 1);
    CHECK(capped[0].kind == ClosedRun::Kind::capped);
    CHECK(capped[0].pid == 0); // oldest by start_ts
    CHECK(capped[0].end_ts == capped[0].start_ts);
    CHECK(state.open.size() == kMaxOpenRuns);
    for (const auto& [key, run] : state.open)
        CHECK(run.pid != 0);
}

TEST_CASE("tar_usage: fold_daily attributes a run to the UTC day of its START",
         "[tar_usage]") {
    constexpr int64_t kDay = 86400;
    ClosedRun spans_midnight;
    spans_midnight.pid = 1;
    spans_midnight.exe_key = "app";
    spans_midnight.user = "alice";
    spans_midnight.start_ts = kDay - 10; // 10s before midnight
    spans_midnight.end_ts = kDay + 3600; // an hour after midnight
    spans_midnight.kind = ClosedRun::Kind::normal;

    ClosedRun after_midnight = spans_midnight;
    after_midnight.pid = 2;
    after_midnight.start_ts = kDay + 100;
    after_midnight.end_ts = kDay + 200;

    auto deltas = fold_daily({spans_midnight, after_midnight});
    REQUIRE(deltas.size() == 2); // attributed to DIFFERENT days despite the overlap
    for (const auto& d : deltas) {
        if (d.day_ts == 0) {
            CHECK(d.run_count == 1);
            CHECK(d.total_seconds == spans_midnight.end_ts - spans_midnight.start_ts);
        } else {
            CHECK(d.day_ts == kDay);
            CHECK(d.run_count == 1);
        }
    }
}

TEST_CASE("tar_usage: fold_daily counts expired and capped runs as expired_runs",
         "[tar_usage]") {
    ClosedRun normal;
    normal.exe_key = "app";
    normal.start_ts = 0;
    normal.end_ts = 10;
    normal.kind = ClosedRun::Kind::normal;

    ClosedRun superseded = normal;
    superseded.kind = ClosedRun::Kind::superseded;

    ClosedRun expired = normal;
    expired.kind = ClosedRun::Kind::expired;
    expired.end_ts = expired.start_ts;

    ClosedRun capped = normal;
    capped.kind = ClosedRun::Kind::capped;
    capped.end_ts = capped.start_ts;

    auto deltas = fold_daily({normal, superseded, expired, capped});
    REQUIRE(deltas.size() == 1);
    CHECK(deltas[0].run_count == 4);
    CHECK(deltas[0].superseded_runs == 1);
    CHECK(deltas[0].expired_runs == 2); // expired + capped
}

// ──────────────────────────────────────────────────────── DB-level tests ───

TEST_CASE("tar_usage: run_usage_fold advances hwm and populates usage_daily", "[tar_usage]") {
    auto t = make_test_db();
    std::vector<ProcessEvent> seed = {mk(1000, "started", 1, "app", "alice"),
                                      mk(1010, "stopped", 1, "app", "alice")};
    REQUIRE(t.db.insert_process_events(seed));

    auto result = run_usage_fold(t.db, /*now=*/2000);
    CHECK(result.ok);
    CHECK(result.events_seen == 2);
    CHECK(result.runs_closed == 1);
    CHECK(!result.gap_detected);
    CHECK(result.hwm_id == 2); // 2 rows inserted, ids 1 and 2

    auto rows = t.db.execute_query("SELECT day_ts, exe_key, run_count, total_seconds, "
                                   "distinct_users FROM usage_daily");
    REQUIRE(rows.has_value());
    REQUIRE(rows->rows.size() == 1);
    CHECK(rows->rows[0][1] == "app");
    CHECK(rows->rows[0][2] == "1");
    CHECK(rows->rows[0][3] == "10");
    CHECK(rows->rows[0][4] == "1");

    CHECK(t.db.get_config("usage_hwm_id", "") == "2");
}

TEST_CASE("tar_usage: a forced failure rolls back -- hwm and usage_daily are untouched",
         "[tar_usage]") {
    // Deliberately NOT a dropped-table/missing-column fault: TarDatabase::
    // execute_atomic_batch classifies a plain SQLITE_ERROR/SQLITE_CONSTRAINT
    // as a PER-TABLE fault when the transaction is otherwise intact and
    // COMMITS everything else (see its own doc comment) -- correct for
    // run_retention's many-independent-tables sweep, but it means a dropped
    // usage_daily table would NOT exercise run_usage_fold's all-or-nothing
    // contract: hwm's own statement would still commit. The class that DOES
    // abort the whole pass unconditionally is a failed BEGIN IMMEDIATE
    // itself (out.began stays false) -- forced here by a second connection
    // holding the write lock (BEGIN EXCLUSIVE).
    //
    // TarDatabase::open() sets a 5s busy_timeout on its own connection, so
    // without intervention run_usage_fold's BEGIN IMMEDIATE would retry via
    // SQLite's busy handler for the full 5s before failing -- a real sleep,
    // not a CV/future wait, and exactly the "no timing assumptions" pattern
    // the unit-test conventions forbid. Drive t.db's OWN busy_timeout to 0
    // first so its busy handler fires immediately (SQLITE_BUSY on the very
    // first BEGIN IMMEDIATE attempt) instead of actually sleeping out the
    // window -- this observes the identical rollback/early-return behavior
    // without waiting on a real timeout.
    //
    // MUTATION-VERIFY: this test's value is that run_usage_fold's
    // `if (!batch.committed) return result;` early-return, not just SQLite's
    // own rollback, is what the assertions below depend on. Manually
    // confirmed by temporarily changing that branch to fall through to the
    // success path regardless of `batch.committed` -- CHECK(!result.ok)
    // failed as expected (result.ok read back true), proving this test does
    // exercise the guard. Reverted before writing the patch.
    auto t = make_test_db();
    REQUIRE(t.db.insert_process_events({mk(1000, "started", 1, "app", "alice")}));
    REQUIRE(t.db.execute_sql("PRAGMA busy_timeout = 0"));

    sqlite3* raw = nullptr;
    REQUIRE(sqlite3_open(t.path.string().c_str(), &raw) == SQLITE_OK);
    char* err = nullptr;
    REQUIRE(sqlite3_exec(raw, "BEGIN EXCLUSIVE", nullptr, nullptr, &err) == SQLITE_OK);

    auto result = run_usage_fold(t.db, /*now=*/2000);

    sqlite3_exec(raw, "ROLLBACK", nullptr, nullptr, nullptr);
    sqlite3_close(raw);

    CHECK(!result.ok);
    CHECK(!result.error.empty());
    CHECK(result.hwm_id == 0); // unchanged from before the attempt
    CHECK(t.db.get_config("usage_hwm_id", "0") == "0");

    auto rows = t.db.execute_query("SELECT COUNT(*) FROM usage_daily");
    REQUIRE(rows.has_value());
    CHECK(rows->rows[0][0] == "0");
}

TEST_CASE("tar_usage: a destroyed id range above the hwm is reported as a gap, never resumed "
         "silently",
         "[tar_usage]") {
    auto t = make_test_db();
    std::vector<ProcessEvent> seed;
    for (int i = 0; i < 5; ++i)
        seed.push_back(mk(1000 + i, "started", static_cast<uint32_t>(100 + i), "app", "alice"));
    REQUIRE(t.db.insert_process_events(seed));

    auto first = run_usage_fold(t.db, /*now=*/2000);
    REQUIRE(first.ok);
    REQUIRE(first.hwm_id == 5);
    CHECK(!first.gap_detected);

    // Insert 3 more (ids 6,7,8), then destroy the LOWEST 7 ids the way
    // process_live's row-cap prune would -- rows 1-5 the fold already read
    // AND rows 6-7 it never got to, leaving only row 8. That is what makes
    // MIN(id) jump past hwm+1: a prune agnostic of the fold's progress, not
    // a hand-picked hole in the middle of an otherwise-intact table.
    REQUIRE(t.db.insert_process_events(
        {mk(2000, "started", 200, "app", "alice"), mk(2001, "started", 201, "app", "alice"),
         mk(2002, "started", 202, "app", "alice")}));
    REQUIRE(t.db.execute_sql("DELETE FROM process_live WHERE id <= 7"));

    auto second = run_usage_fold(t.db, /*now=*/3000);
    REQUIRE(second.ok);
    CHECK(second.gap_detected);
    CHECK(t.db.get_config("usage_gap_count", "0") == "1");
    CHECK(t.db.get_config("usage_gap_lost_events", "0") == "2"); // ids 6,7
    // Re-baselined to min_id - 1 = 7, then advanced past row 8.
    CHECK(second.hwm_id == 8);
}

TEST_CASE("tar_usage: orphan stops and clock steps surface as non-zero tar_config counters",
         "[tar_usage]") {
    auto t = make_test_db();
    REQUIRE(t.db.insert_process_events(
        {mk(1000, "stopped", 1, "ghost", "alice"),      // orphan
         mk(2000, "started", 2, "app", "alice"),
         mk(1500, "stopped", 2, "app", "alice")}));      // ts < start_ts on the SAME key

    auto result = run_usage_fold(t.db, /*now=*/5000);
    REQUIRE(result.ok);
    CHECK(t.db.get_config("usage_unmatched_stops", "0") == "1");
    CHECK(t.db.get_config("usage_clock_anomalies", "0") == "1");
}

TEST_CASE("tar_usage: an open run survives a simulated agent restart and closes later",
         "[tar_usage]") {
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_tar_usage_");
    {
        auto opened = TarDatabase::open(tmp);
        REQUIRE(opened.has_value());
        TarDatabase db = std::move(*opened);
        ensure_usage_schema(db);
        db.set_config("process_enabled", "true");
        db.set_config("usage_enabled", "true");
        REQUIRE(db.insert_process_events({mk(1000, "started", 1, "app", "alice")}));
        auto result = run_usage_fold(db, /*now=*/1001);
        REQUIRE(result.ok);
        REQUIRE(result.runs_closed == 0); // still open
        auto open_rows = db.execute_query("SELECT COUNT(*) FROM usage_live");
        REQUIRE(open_rows.has_value());
        CHECK(open_rows->rows[0][0] == "1");
    } // TarDatabase destroyed -- simulates the agent process exiting

    auto reopened = TarDatabase::open(tmp);
    REQUIRE(reopened.has_value());
    TarDatabase db2 = std::move(*reopened);
    ensure_usage_schema(db2);
    REQUIRE(db2.insert_process_events({mk(1010, "stopped", 1, "app", "alice")}));
    auto result2 = run_usage_fold(db2, /*now=*/1020);
    REQUIRE(result2.ok);
    CHECK(result2.runs_closed == 1); // the run opened before "restart" now closes

    auto rows = db2.execute_query("SELECT run_count, total_seconds FROM usage_daily");
    REQUIRE(rows.has_value());
    REQUIRE(rows->rows.size() == 1);
    CHECK(rows->rows[0][0] == "1");
    CHECK(rows->rows[0][1] == "10");

    std::error_code ec;
    fs::remove(tmp, ec);
    fs::remove(fs::path{tmp.string() + "-wal"}, ec);
    fs::remove(fs::path{tmp.string() + "-shm"}, ec);
}

TEST_CASE("tar_usage: usage_rebaseline clears open runs and stamps coverage_since",
         "[tar_usage]") {
    auto t = make_test_db();
    REQUIRE(t.db.insert_process_events({mk(1000, "started", 1, "app", "alice")}));
    REQUIRE(run_usage_fold(t.db, 1001).ok);
    auto before = t.db.execute_query("SELECT COUNT(*) FROM usage_live");
    REQUIRE(before.has_value());
    CHECK(before->rows[0][0] == "1"); // one open run persisted

    usage_rebaseline(t.db, /*now=*/5000);

    auto after = t.db.execute_query("SELECT COUNT(*) FROM usage_live");
    REQUIRE(after.has_value());
    CHECK(after->rows[0][0] == "0"); // cleared
    CHECK(t.db.get_config("usage_coverage_since", "") == "5000");
    CHECK(t.db.get_config("usage_hwm_id", "") == "1"); // MAX(id) over process_live
}

TEST_CASE("tar_usage: a disabled process feeder skips the fold and reports usage_feeder_enabled",
         "[tar_usage]") {
    auto t = make_test_db();
    t.db.set_config("process_enabled", "false");
    REQUIRE(t.db.insert_process_events({mk(1000, "started", 1, "app", "alice")}));

    auto result = run_usage_fold(t.db, /*now=*/2000);
    CHECK(result.ok); // not running is not a failure
    CHECK(result.events_seen == 0);
    CHECK(t.db.get_config("usage_feeder_enabled", "") == "false");
    CHECK(t.db.get_config("usage_hwm_id", "0") == "0"); // never advanced

    auto rows = t.db.execute_query("SELECT COUNT(*) FROM usage_daily");
    REQUIRE(rows.has_value());
    CHECK(rows->rows[0][0] == "0");
}

TEST_CASE("tar_usage: usage_daily never carries pid, cmdline, or user columns",
         "[tar_usage]") {
    auto t = make_test_db();
    auto cols = t.db.execute_query("PRAGMA table_info(usage_daily)");
    REQUIRE(cols.has_value());
    for (const auto& row : cols->rows) {
        const std::string& name = row[1]; // PRAGMA table_info column 1 = name
        CHECK(name != "pid");
        CHECK(name != "cmdline");
        CHECK(name != "user");
    }
}
