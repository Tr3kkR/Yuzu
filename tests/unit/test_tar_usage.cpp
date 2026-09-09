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
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <thread>
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
        "distinct_users INTEGER, superseded_runs INTEGER, expired_runs INTEGER, "
        "fold_hwm INTEGER NOT NULL DEFAULT 0)"));
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
    // Blocker 3's forward-only coverage gate (tar_usage.cpp) makes
    // run_usage_fold() refuse to consume ANY process_live row until a
    // successful baseline has stamped usage_coverage_since. Every existing
    // fold-behavior test in this file assumes that baseline already
    // happened (mirroring a real boot that already ran tar_plugin.cpp's
    // rebaseline) -- set it here so those tests are unaffected. Tests that
    // specifically exercise the gate/self-heal behavior delete this key
    // first.
    result->set_config("usage_coverage_since", "0");
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

TEST_CASE("tar_usage: run_usage_fold's gap-check and event-read are one atomic operation -- a "
         "concurrent retention-style prune on the same TarDatabase cannot land between them",
         "[tar_usage]") {
    // Wave 7 PR7.2 adversarial finding: run_usage_fold used to read
    // process_live's MIN/MAX/COUNT range in one execute_query() call, then
    // read the actual events beyond hwm in a SECOND, separate execute_query()
    // call. TarDatabase::execute_query only holds TarDatabase::mu_ for the
    // duration of its OWN call, so a concurrent retention prune
    // (do_rollup -> run_retention) going through the SAME TarDatabase
    // instance could acquire mu_ in the window BETWEEN the two calls -- the
    // range query would see no gap, the prune would then delete past that
    // range, and the event query would silently resume from whatever
    // survived, with usage_gap_count never incremented (events silently
    // lost). The fix folds both reads into ONE execute_query() call -- one
    // continuous mu_ hold -- so a concurrent mu_-guarded write can no longer
    // interleave between the range read and the event read.
    //
    // This proves the property directly with real concurrency: one thread
    // repeatedly runs the fold while another repeatedly inserts and prunes
    // process_live's lowest ids through the SAME db instance (mimicking
    // run_retention's row-cap prune), both real OS threads with no sleeps.
    // Under the old two-call code this reliably produced a fold whose
    // reported hwm regressed or whose gap accounting went negative/
    // inconsistent within a few hundred iterations (manually verified by
    // reverting to the two-call form before writing this test -- CHECK
    // failures appeared within the loop; reverted before landing the fix).
    // Under the fixed one-call code, mu_ makes every fold-vs-prune pair
    // fully serialized, so these invariants hold unconditionally.
    auto t = make_test_db();
    // Relax durability for this test only -- WAL defaults to synchronous=FULL
    // (an fsync per write), which is the correct production default but makes
    // a many-round concurrency stress loop pay a real disk sync per round for
    // no value here: this test verifies an in-process locking property, not
    // crash durability.
    REQUIRE(t.db.execute_sql("PRAGMA synchronous = OFF"));
    std::vector<ProcessEvent> seed;
    for (int i = 0; i < 20; ++i)
        seed.push_back(mk(1000 + i, "started", static_cast<uint32_t>(100 + i), "app", "alice"));
    REQUIRE(t.db.insert_process_events(seed));

    std::atomic<bool> stop{false};
    std::atomic<int64_t> next_id{100};
    std::thread pruner([&] {
        while (!stop.load(std::memory_order_relaxed)) {
            const int64_t id = next_id.fetch_add(1, std::memory_order_relaxed);
            (void)t.db.insert_process_events(
                {mk(1000 + id, "started", static_cast<uint32_t>(1000 + id), "app", "alice")});
            // Mimics run_retention's row-count prune of process_live's lowest ids.
            (void)t.db.execute_sql(
                "DELETE FROM process_live WHERE id IN "
                "(SELECT id FROM process_live ORDER BY id ASC LIMIT 3)");
        }
    });

    int64_t prev_hwm = 0;
    int64_t prev_gap_lost = 0;
    for (int i = 0; i < 30; ++i) {
        auto result = run_usage_fold(t.db, /*now=*/2000 + i);
        REQUIRE(result.ok);
        // The invariants that silently broke under the two-call race: hwm is
        // monotonic, and the cumulative gap-lost counter only ever grows (a
        // torn read across the two former calls could otherwise re-baseline
        // and re-detect the same already-accounted gap, or compute against a
        // range it never actually observed atomically).
        CHECK(result.hwm_id >= prev_hwm);
        prev_hwm = result.hwm_id;
        const int64_t gap_lost = std::stoll(t.db.get_config("usage_gap_lost_events", "0"));
        CHECK(gap_lost >= prev_gap_lost);
        prev_gap_lost = gap_lost;
    }
    stop.store(true, std::memory_order_relaxed);
    pruner.join();
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
        db.set_config("usage_coverage_since", "0"); // baseline already established -- see make_test_db()
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

    REQUIRE(usage_rebaseline(t.db, /*now=*/5000).has_value());

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

// ── Blocker 1: a partial mid-batch statement failure must not advance hwm ───

TEST_CASE("tar_usage: a partial mid-batch statement failure leaves hwm and counters "
         "unadvanced -- not just committed==true with one row skipped",
         "[tar_usage]") {
    // Wave 7 PR7.2 adversarial review (Blocker 1): TarDatabase::
    // execute_atomic_batch is documented as deliberately NOT all-or-nothing
    // on a transaction-preserving error -- a `committed==true` batch can
    // still have flagged ONE statement failed while every OTHER statement
    // in that SAME commit, including a later tar_config upsert, is fully
    // durable. Reproduce the concrete trigger the review cited: dropping
    // usage_daily's own unique index (mirrors a stuck-at-schema-5 migration
    // failure) makes the very first usage_daily upsert's
    // `ON CONFLICT(day_ts, exe_key)` clause fail with a plain,
    // transaction-preserving SQLITE_ERROR ("no matching PRIMARY KEY or
    // UNIQUE constraint") -- exactly the shape execute_atomic_batch flags
    // and continues past rather than rolling back.
    //
    // MUTATION-VERIFY: manually reverted the fix (restored the single
    // execute_atomic_batch call with hwm/counters bundled into the data
    // statements, checking only `!batch.committed`) and re-ran this test --
    // it failed as expected (usage_hwm_id read back "2", not "0"), proving
    // this test does exercise the split-batch guard. Reverted before
    // writing the patch.
    auto t = make_test_db();
    REQUIRE(t.db.execute_sql("DROP INDEX usage_daily_day_exe_uq"));
    REQUIRE(t.db.insert_process_events(
        {mk(1000, "started", 1, "app", "alice"), mk(1010, "stopped", 1, "app", "alice")}));

    auto result = run_usage_fold(t.db, /*now=*/2000);

    CHECK(!result.ok);
    CHECK(!result.error.empty());
    CHECK(result.hwm_id == 0); // unchanged in the returned result

    // The falsifier: the OLD code left result.ok=false but the DB's own
    // usage_hwm_id row still advanced, because it shared a commit with the
    // failed usage_daily insert. Confirm the persisted config did NOT move.
    CHECK(t.db.get_config("usage_hwm_id", "0") == "0");
    CHECK(t.db.get_config("usage_last_fold_ts", "0") == "0");

    auto rows = t.db.execute_query("SELECT COUNT(*) FROM usage_daily");
    REQUIRE(rows.has_value());
    CHECK(rows->rows[0][0] == "0");
}

// ── Governance re-review fix-of-a-fix: a crash between the data commit and ─
// ── the hwm/counter commit must not double-count on the retry ──────────────

TEST_CASE("tar_usage: a crash between the data commit and the hwm advance does not "
         "double-count usage_daily on the next tick's retry",
         "[tar_usage]") {
    // The Blocker 1 fix's OWN gap (Wave 7 PR7.2 governance re-review,
    // fix-of-a-fix): the two-phase split that closed Blocker 1 (a data
    // batch, then a SEPARATE confirm batch issued only after checking the
    // first one's result) left a genuine process crash between those two
    // CALLS able to durably apply usage_daily/usage_live while usage_hwm_id
    // stayed behind -- the next tick then re-derives and re-applies the SAME
    // additive run_count/total_seconds delta on top of already-durable data.
    // This is a DIFFERENT defect than Blocker 1's own test above: that one
    // proves "no partial advance on a mid-batch STATEMENT failure"; this one
    // proves "no double-count on a retry that finds the data already
    // applied but the hwm pointer un-advanced" -- a scenario Blocker 1's
    // fix never protected against.
    //
    // A unit test cannot literally kill the process mid-transaction, so this
    // forces the DURABLE CONSEQUENCE a crash in that exact window would
    // leave: run a real fold to completion (this is now ONE atomic commit,
    // tar_db.hpp's execute_atomic_batch_gated -- data and hwm/counters
    // together), then manually revert JUST the tar_config keys the confirm
    // step would have written, leaving usage_daily/usage_daily_user/
    // usage_live exactly as the fold's data statements left them. That is
    // byte-for-byte the state a crash landing after the data commit but
    // before the (former, now-removed) confirm commit would have produced,
    // regardless of which mechanism produced it.
    auto t = make_test_db();
    REQUIRE(t.db.insert_process_events(
        {mk(1000, "started", 1, "app", "alice"), mk(1010, "stopped", 1, "app", "alice")}));

    auto first = run_usage_fold(t.db, /*now=*/2000);
    REQUIRE(first.ok);
    REQUIRE(first.hwm_id == 2);

    auto daily_after_first = t.db.execute_query(
        "SELECT run_count, total_seconds FROM usage_daily");
    REQUIRE(daily_after_first.has_value());
    REQUIRE(daily_after_first->rows.size() == 1);
    CHECK(daily_after_first->rows[0][0] == "1");
    CHECK(daily_after_first->rows[0][1] == "10");

    // Simulate the crash boundary: undo the confirm step's writes only.
    // usage_daily/usage_live are untouched -- they are what the DATA commit
    // (already durable, by design) left behind.
    REQUIRE(t.db.execute_sql("DELETE FROM tar_config WHERE key IN "
                             "('usage_hwm_id', 'usage_last_fold_ts', 'usage_lag_events')"));
    REQUIRE(t.db.get_config("usage_hwm_id", "0") == "0");

    // The retry: a fresh fold pass reading the same un-advanced hwm. It
    // re-reads the identical process_live range (nothing new arrived) and
    // re-derives the identical closed run.
    auto second = run_usage_fold(t.db, /*now=*/3000);
    CHECK(second.ok);
    CHECK(second.hwm_id == 2); // self-heals back to the correct value

    // The falsifier: the OLD two-call code re-applied the additive upsert
    // unconditionally on this retry, so run_count/total_seconds would read
    // back "2"/"20" here instead of "1"/"10".
    //
    // MUTATION-VERIFY: temporarily dropped the `fold_hwm` guard (reverted
    // the same-tick upsert to the plain unconditional additive form with no
    // `WHERE fold_hwm < excluded.fold_hwm` clause, matching what the
    // two-phase-split code shipped) and re-ran this test -- it failed as
    // expected (run_count read back "2", total_seconds "20"), proving this
    // test does exercise the replay guard rather than passing on unrelated
    // grounds. Reverted before writing the patch.
    auto daily_after_second = t.db.execute_query(
        "SELECT run_count, total_seconds FROM usage_daily");
    REQUIRE(daily_after_second.has_value());
    REQUIRE(daily_after_second->rows.size() == 1);
    CHECK(daily_after_second->rows[0][0] == "1");
    CHECK(daily_after_second->rows[0][1] == "10");
}

TEST_CASE("tar_usage: the same crash-and-retry does not lose a genuinely NEW carried-over "
         "expiry that happens to land on the same target hwm",
         "[tar_usage]") {
    // The counterpart to the test above: the `fold_hwm` guard must protect
    // ONLY same-tick opened-and-closed contributions, never a genuinely NEW
    // closure of a run that was already durably open before the tick began
    // (a "carried-over" closure -- see run_usage_fold's provenance split).
    // Carried-over closures are already replay-safe on their own (closing
    // them mutates usage_live, so a replay's `state.open` reload can never
    // find the same run again) and must stay UNGUARDED: gating them on
    // `new_hwm` too would wrongly collide whenever hwm is flat across
    // multiple genuinely distinct ticks (no new process activity, yet
    // different long-open runs individually crossing max_age) and silently
    // drop a second, unrelated expiry.
    auto t = make_test_db();

    // pid 1 is opened directly into usage_live (as if carried over from a
    // prior agent restart -- mirrors the "an open run survives a simulated
    // agent restart" test elsewhere in this file) and will expire on its
    // own, with NO corresponding event in process_live.
    REQUIRE(t.db.execute_sql(
        "INSERT INTO usage_live (ts, snapshot_id, action, pid, exe_key, user, start_ts) "
        "VALUES (100, 0, 'open', 1, 'stale', 'alice', 100)"));
    // A same-tick started+stopped run for a DIFFERENT executable seeds a
    // real data batch this tick so the fold has process_live rows to read
    // and a genuine new_hwm to advance to.
    REQUIRE(t.db.insert_process_events(
        {mk(1000, "started", 2, "app", "alice"), mk(1010, "stopped", 2, "app", "alice")}));

    // now=2000 is nowhere near kDefaultMaxAgeSeconds (7 days) past pid 1's
    // start_ts=100, so it survives this first pass untouched -- the fold's
    // own new_hwm this tick is driven entirely by the app/pid2 events.
    auto first = run_usage_fold(t.db, /*now=*/2000);
    REQUIRE(first.ok);
    REQUIRE(first.hwm_id == 2);

    // Simulate the SAME crash boundary as the test above.
    REQUIRE(t.db.execute_sql("DELETE FROM tar_config WHERE key IN "
                             "('usage_hwm_id', 'usage_last_fold_ts', 'usage_lag_events')"));

    // The retry, now far enough past pid 1's start_ts to expire it too.
    // process_live has nothing new (still id<=2), so this pass's new_hwm is
    // AGAIN 2 -- the identical value the first pass already stamped into
    // usage_daily's "app" row. The pid-1 "stale" expiry is a GENUINELY NEW
    // contribution that must still land despite sharing that new_hwm.
    auto second = run_usage_fold(t.db, /*now=*/1000000);
    CHECK(second.ok);
    CHECK(second.hwm_id == 2);

    auto app_row = t.db.execute_query(
        "SELECT run_count, total_seconds FROM usage_daily WHERE exe_key = 'app'");
    REQUIRE(app_row.has_value());
    REQUIRE(app_row->rows.size() == 1);
    CHECK(app_row->rows[0][0] == "1"); // unchanged -- not re-applied
    CHECK(app_row->rows[0][1] == "10");

    auto stale_row = t.db.execute_query(
        "SELECT run_count, expired_runs FROM usage_daily WHERE exe_key = 'stale'");
    REQUIRE(stale_row.has_value());
    REQUIRE(stale_row->rows.size() == 1); // the falsifier: a uniform guard
                                          // keyed on new_hwm alone would
                                          // leave this row absent entirely.
    CHECK(stale_row->rows[0][0] == "1");
    CHECK(stale_row->rows[0][1] == "1");
}

// ── Blocker 3: the forward-only boundary self-heals and never replays ──────

TEST_CASE("tar_usage: a missing coverage marker self-heals via rebaseline and never folds "
         "pre-existing rows",
         "[tar_usage]") {
    // Wave 7 PR7.2 adversarial review (Blocker 3): the fold must never
    // consume a process_live row before a successful baseline transaction
    // establishes coverage. Simulate a DB whose earlier rebaseline never
    // ran (or never completed) by removing the marker make_test_db() sets.
    auto t = make_test_db();
    REQUIRE(t.db.execute_sql("DELETE FROM tar_config WHERE key = 'usage_coverage_since'"));

    // Pre-existing process history the fold must NEVER consume once it
    // establishes coverage (forward-only, rule 5).
    REQUIRE(t.db.insert_process_events({mk(1000, "started", 1, "preexisting", "alice"),
                                        mk(1010, "stopped", 1, "preexisting", "alice")}));

    auto first = run_usage_fold(t.db, /*now=*/5000);
    CHECK(first.ok);
    CHECK(first.hwm_id == 2); // self-healed baseline = MAX(id) as of now
    CHECK(t.db.get_config("usage_coverage_since", "") == "5000");

    auto rows = t.db.execute_query("SELECT COUNT(*) FROM usage_daily");
    REQUIRE(rows.has_value());
    CHECK(rows->rows[0][0] == "0"); // the pre-existing run was never folded

    // A genuinely NEW event after the baseline IS folded normally.
    REQUIRE(t.db.insert_process_events({mk(6000, "started", 2, "fresh", "bob"),
                                        mk(6010, "stopped", 2, "fresh", "bob")}));
    auto second = run_usage_fold(t.db, /*now=*/7000);
    CHECK(second.ok);
    CHECK(second.runs_closed == 1);
    rows = t.db.execute_query("SELECT exe_key FROM usage_daily");
    REQUIRE(rows.has_value());
    REQUIRE(rows->rows.size() == 1);
    CHECK(rows->rows[0][0] == "fresh");
}

TEST_CASE("tar_usage: a rebaseline transaction failure leaves coverage absent and refuses to "
         "fold -- retried, never disarmed",
         "[tar_usage]") {
    // MUTATION-VERIFY: manually reverted the Blocker 3 fix (dropped the
    // coverage gate from run_usage_fold, restoring the old shape gated
    // only on the two enable flags) and re-ran this test -- it failed as
    // expected (`retry.ok` folded the pre-existing row this test seeds
    // rather than refusing it, and usage_coverage_since read back a value
    // set from an earlier, unrelated path rather than being genuinely
    // gated here). Reverted before writing the patch.
    auto t = make_test_db();
    REQUIRE(t.db.execute_sql("DELETE FROM tar_config WHERE key = 'usage_coverage_since'"));
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
    CHECK(t.db.get_config("usage_coverage_since", "") == ""); // still absent -- retry next tick

    // Retry with the lock released: rebaseline succeeds, and the
    // pre-existing row is STILL never folded (it predates the baseline).
    auto retry = run_usage_fold(t.db, /*now=*/2001);
    CHECK(retry.ok);
    CHECK(t.db.get_config("usage_coverage_since", "") == "2001");
    auto rows = t.db.execute_query("SELECT COUNT(*) FROM usage_daily");
    REQUIRE(rows.has_value());
    CHECK(rows->rows[0][0] == "0");
}

// ── Should-fix 2: supersede-path clamp + extreme-timestamp overflow ────────

TEST_CASE("tar_usage: a backward clock step across a supersede clamps duration to 0 and counts "
         "an anomaly",
         "[tar_usage]") {
    // Wave 7 PR7.2 adversarial review (should-fix 2): the duplicate-start
    // supersede-close path was never clamped for backward clock movement,
    // unlike the "stopped" path -- reviewers measured duration=-1000 with
    // clock_anomalies never incremented before this fix.
    FoldState state;
    auto first = apply_event(state, mk(1000, "started", 1, "app", "alice"));
    CHECK(!first.has_value()); // nothing superseded yet

    // A NEW "started" for the SAME (pid, exe_key) arrives with ts BEFORE the
    // still-open run's start_ts -- a backward clock step across the
    // supersede boundary.
    auto second = apply_event(state, mk(500, "started", 1, "app", "alice"));
    REQUIRE(second.has_value());
    CHECK(second->kind == ClosedRun::Kind::superseded);
    CHECK(second->start_ts == 1000);
    CHECK(second->end_ts == 1000);   // clamped -- never negative
    CHECK(second->end_ts >= second->start_ts);
    CHECK(state.clock_anomalies == 1);
}

TEST_CASE("tar_usage: expire_open_runs does not overflow on an extreme start_ts",
         "[tar_usage]") {
    // Wave 7 PR7.2 adversarial review (should-fix 2): `now - start_ts` in
    // the previous expire_open_runs overflowed UB when start_ts was an
    // extreme value (e.g. INT64_MIN) and now was a plausible epoch second
    // -- reproduced under UBSan. The fix (saturating_sub) makes this safe;
    // this test is UBSan-catchable (a sanitizer build traps the raw
    // subtraction where this test would otherwise pass silently on a
    // release build that happens not to crash).
    FoldState state;
    OpenRun run;
    run.pid = 1;
    run.exe_key = "app";
    run.user = "alice";
    run.start_ts = std::numeric_limits<int64_t>::min();
    state.open[{run.pid, run.exe_key}] = run;

    auto closed = expire_open_runs(state, /*now=*/1000);
    REQUIRE(closed.size() == 1);
    CHECK(closed[0].kind == ClosedRun::Kind::expired);
    CHECK(closed[0].end_ts == closed[0].start_ts); // 0s duration, never fabricated
    CHECK(state.open.empty());
}

TEST_CASE("tar_usage: day_ts_for does not overflow on INT64_MIN", "[tar_usage]") {
    // Companion to the expire_open_runs overflow test: fold_daily() (and
    // tar_usage.cpp's usage_daily_user bucketing) used to negate a negative
    // start_ts directly, which overflows for INT64_MIN. day_ts_for()
    // avoids the negation entirely.
    const int64_t d = day_ts_for(std::numeric_limits<int64_t>::min());
    CHECK(d % 86400 == 0);
    CHECK(d <= std::numeric_limits<int64_t>::min() + 86400);
}
