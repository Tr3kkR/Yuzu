/**
 * test_audit_store.cpp — Unit tests for AuditStore
 *
 * Covers: logging, querying, filtering, count, multiple principals, and the
 * retention clock guard (#2360) -- decline/latch/drain, the persisted and
 * sanitised clock reading, the per-pass cap, and the fail-closed paths.
 */

#include "audit_store.hpp"
#include "audit_retention_rules.hpp"
#include "sqlite_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <sqlite3.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <string>
#include <thread>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>

#include <limits>
#include <memory>
#include <sstream>
#include <vector>

using namespace yuzu::server;

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("AuditStore: open in-memory", "[audit_store][db]") {
    AuditStore store(":memory:");
    REQUIRE(store.is_open());
}

TEST_CASE("AuditStore: log and retrieve", "[audit_store]") {
    AuditStore store(":memory:");

    AuditEvent event;
    event.principal = "admin";
    event.principal_role = "admin";
    event.action = "auth.login";
    event.result = "success";
    event.source_ip = "192.168.1.1";
    CHECK(store.log(event));

    auto results = store.query();
    REQUIRE(results.size() == 1);
    CHECK(results[0].principal == "admin");
    CHECK(results[0].action == "auth.login");
    CHECK(results[0].result == "success");
    CHECK(results[0].source_ip == "192.168.1.1");
}

TEST_CASE("AuditStore: filter by principal", "[audit_store]") {
    AuditStore store(":memory:");

    for (const auto& user : {"admin", "admin", "viewer"}) {
        AuditEvent event;
        event.principal = user;
        event.principal_role = "admin";
        event.action = "auth.login";
        event.result = "success";
        CHECK(store.log(event));
    }

    AuditQuery q;
    q.principal = "admin";
    auto results = store.query(q);
    REQUIRE(results.size() == 2);
}

TEST_CASE("AuditStore: filter by action", "[audit_store]") {
    AuditStore store(":memory:");

    AuditEvent e1;
    e1.principal = "admin";
    e1.principal_role = "admin";
    e1.action = "auth.login";
    e1.result = "success";
    CHECK(store.log(e1));

    AuditEvent e2;
    e2.principal = "admin";
    e2.principal_role = "admin";
    e2.action = "command.dispatch";
    e2.result = "success";
    CHECK(store.log(e2));

    AuditQuery q;
    q.action = "command.dispatch";
    auto results = store.query(q);
    REQUIRE(results.size() == 1);
    CHECK(results[0].action == "command.dispatch");
}

TEST_CASE("AuditStore: filter by target", "[audit_store]") {
    AuditStore store(":memory:");

    AuditEvent e1;
    e1.principal = "admin";
    e1.principal_role = "admin";
    e1.action = "agent.approve";
    e1.result = "success";
    e1.target_type = "agent";
    e1.target_id = "agent-001";
    CHECK(store.log(e1));

    AuditEvent e2;
    e2.principal = "admin";
    e2.principal_role = "admin";
    e2.action = "agent.approve";
    e2.result = "success";
    e2.target_type = "agent";
    e2.target_id = "agent-002";
    CHECK(store.log(e2));

    AuditQuery q;
    q.target_type = "agent";
    q.target_id = "agent-001";
    auto results = store.query(q);
    REQUIRE(results.size() == 1);
}

TEST_CASE("AuditStore: timestamp ordering", "[audit_store]") {
    AuditStore store(":memory:");

    for (int64_t ts : {100, 300, 200}) {
        AuditEvent event;
        event.timestamp = ts;
        event.principal = "admin";
        event.principal_role = "admin";
        event.action = "test";
        event.result = "success";
        CHECK(store.log(event));
    }

    auto results = store.query();
    REQUIRE(results.size() == 3);
    CHECK(results[0].timestamp >= results[1].timestamp);
}

TEST_CASE("AuditStore: limit and offset", "[audit_store]") {
    AuditStore store(":memory:");

    for (int i = 0; i < 10; ++i) {
        AuditEvent event;
        event.principal = "admin";
        event.principal_role = "admin";
        event.action = "test";
        event.result = "success";
        event.detail = "item-" + std::to_string(i);
        CHECK(store.log(event));
    }

    AuditQuery q;
    q.limit = 3;
    auto page1 = store.query(q);
    REQUIRE(page1.size() == 3);

    q.offset = 3;
    auto page2 = store.query(q);
    REQUIRE(page2.size() == 3);
}

TEST_CASE("AuditStore: total_count", "[audit_store]") {
    AuditStore store(":memory:");
    REQUIRE(store.total_count() == 0);

    AuditEvent event;
    event.principal = "admin";
    event.principal_role = "admin";
    event.action = "test";
    event.result = "success";
    CHECK(store.log(event));

    REQUIRE(store.total_count() == 1);
}

TEST_CASE("AuditStore: all fields stored", "[audit_store]") {
    AuditStore store(":memory:");

    AuditEvent event;
    event.principal = "admin";
    event.principal_role = "admin";
    event.action = "setting.update";
    event.target_type = "setting";
    event.target_id = "tls_enabled";
    event.detail = "changed to true";
    event.source_ip = "10.0.0.1";
    event.user_agent = "Mozilla/5.0";
    event.session_id = "sess-abc";
    event.result = "success";
    event.principal_class = "human";
    CHECK(store.log(event));

    auto results = store.query();
    REQUIRE(results.size() == 1);
    CHECK(results[0].target_type == "setting");
    CHECK(results[0].target_id == "tls_enabled");
    CHECK(results[0].detail == "changed to true");
    CHECK(results[0].user_agent == "Mozilla/5.0");
    CHECK(results[0].session_id == "sess-abc");
    CHECK(results[0].principal_class == "human");
}

TEST_CASE("AuditStore: principal_class defaults to honest-empty when unset (#1634-adjacent "
          "ADR-1005 Phase 3a)",
          "[audit_store]") {
    // Rows this program cannot attribute to an HTTP session/token principal
    // (gRPC agent-daemon calls, gateway proxying, server-internal writers) never
    // set principal_class — the column must default to "" (honest-empty), never
    // a synthesised guess.
    AuditStore store(":memory:");
    AuditEvent event;
    event.principal = "system";
    event.principal_role = "system";
    event.action = "cert.reload";
    event.result = "success";
    CHECK(store.log(event));

    auto results = store.query();
    REQUIRE(results.size() == 1);
    CHECK(results[0].principal_class.empty());
}

TEST_CASE("AuditStore: time range filter", "[audit_store]") {
    AuditStore store(":memory:");

    for (int64_t ts : {100, 200, 300, 400, 500}) {
        AuditEvent event;
        event.timestamp = ts;
        event.principal = "admin";
        event.principal_role = "admin";
        event.action = "test";
        event.result = "success";
        CHECK(store.log(event));
    }

    AuditQuery q;
    q.since = 200;
    q.until = 400;
    auto results = store.query(q);
    REQUIRE(results.size() == 3);
}

TEST_CASE("AuditStore: empty query returns empty", "[audit_store]") {
    AuditStore store(":memory:");
    auto results = store.query();
    REQUIRE(results.empty());
}

TEST_CASE("AuditStore: failed login audit", "[audit_store]") {
    AuditStore store(":memory:");

    AuditEvent event;
    event.principal = "unknown_user";
    event.principal_role = "";
    event.action = "auth.login_failed";
    event.result = "failure";
    event.source_ip = "10.0.0.99";
    CHECK(store.log(event));

    AuditQuery q;
    q.action = "auth.login_failed";
    auto results = store.query(q);
    REQUIRE(results.size() == 1);
    CHECK(results[0].result == "failure");
}

// ── #4: action-prefix scoping + random-sample (auth-log evidence export) ─────

TEST_CASE("AuditStore: action_prefixes scopes to the auth surface", "[audit_store][auth-sample]") {
    AuditStore store(":memory:");
    auto log = [&](const std::string& action) {
        AuditEvent e;
        e.principal = "admin";
        e.action = action;
        e.result = "success";
        CHECK(store.log(e));
    };
    // Auth-surface events (should match) + noise (should not).
    log("auth.login");
    log("auth.login_failed");
    log("mfa.step_up.passed");
    log("session.revoke_all");
    log("instruction.execute");  // noise
    log("ca.cert.issued");       // noise
    log("tag.create");           // noise

    AuditQuery q;
    q.action_prefixes = {"auth.", "mfa.", "session."};
    auto results = store.query(q);
    REQUIRE(results.size() == 4);
    for (const auto& e : results) {
        const bool scoped = e.action.rfind("auth.", 0) == 0 || e.action.rfind("mfa.", 0) == 0 ||
                            e.action.rfind("session.", 0) == 0;
        CHECK(scoped);
    }
}

TEST_CASE("AuditStore: a wildcard-bearing prefix is dropped, fails closed (M-2)",
          "[audit_store][auth-sample]") {
    AuditStore store(":memory:");
    auto log = [&](const std::string& action) {
        AuditEvent e;
        e.principal = "admin";
        e.action = action;
        e.result = "success";
        CHECK(store.log(e));
    };
    log("auth.login");
    log("instruction.execute");

    // A smuggled LIKE wildcard ("%") must NOT widen to all actions — the prefix
    // is dropped, and with no valid prefixes left the filter fails closed.
    AuditQuery q;
    q.action_prefixes = {"%"};
    CHECK(store.query(q).empty());

    // A valid prefix alongside a wildcard one: only the valid prefix applies.
    AuditQuery q2;
    q2.action_prefixes = {"auth.", "ins%"};
    auto r2 = store.query(q2);
    REQUIRE(r2.size() == 1);
    CHECK(r2[0].action == "auth.login"); // instruction.execute NOT matched by "ins%"

    // All three LIKE metacharacters the guard rejects (%, _, \) are dropped.
    for (const auto& bad : {std::string{"auth_"}, std::string{"auth\\."}, std::string{"%"}}) {
        AuditQuery q3;
        q3.action_prefixes = {bad};
        CHECK(store.query(q3).empty()); // dropped → all-empty → fail closed
    }
}

TEST_CASE("AuditStore: random_sample over the scan cap is recency-capped + bounded by limit",
          "[audit_store][auth-sample][slow]") {
    AuditStore store(":memory:");
    // Insert more than the candidate cap, all in-window auth events.
    const std::size_t n = kAuditSampleScanCap + 250;
    for (std::size_t i = 0; i < n; ++i) {
        AuditEvent e;
        e.principal = "admin";
        e.action = "auth.login";
        e.result = "success";
        e.timestamp = static_cast<int64_t>(1'000 + i);
        CHECK(store.log(e));
    }
    AuditQuery q;
    q.action_prefixes = {"auth."};
    q.random_sample = true;
    q.limit = 25;
    std::size_t pool = 0;
    auto results = store.query(q, &pool);
    REQUIRE(results.size() == 25);              // bounded by limit
    CHECK(pool == kAuditSampleScanCap);          // pool hit the cap (recency-biased)
    // Every returned row is from the most-recent cap window (recency bias).
    for (const auto& e : results)
        CHECK(e.timestamp >= static_cast<int64_t>(1'000 + n - kAuditSampleScanCap));
}

TEST_CASE("AuditStore: an all-empty prefix filter matches nothing (no silent widening)",
          "[audit_store][auth-sample]") {
    AuditStore store(":memory:");
    AuditEvent e;
    e.principal = "admin";
    e.action = "auth.login";
    e.result = "success";
    CHECK(store.log(e));

    AuditQuery q;
    q.action_prefixes = {"", ""}; // degenerate — must not widen to "all actions"
    CHECK(store.query(q).empty());
}

TEST_CASE("AuditStore: random_sample stays within the window + prefix scope, bounded by limit",
          "[audit_store][auth-sample]") {
    AuditStore store(":memory:");
    for (int i = 0; i < 50; ++i) {
        AuditEvent e;
        e.principal = "admin";
        e.action = (i % 2 == 0) ? "auth.login" : "mfa.login.verified";
        e.result = "success";
        e.timestamp = 1'000 + i; // inside the window below
        CHECK(store.log(e));
    }
    // An out-of-window auth event that must never appear in the sample.
    {
        AuditEvent e;
        e.principal = "admin";
        e.action = "auth.login";
        e.result = "success";
        e.timestamp = 999'999;
        CHECK(store.log(e));
    }

    AuditQuery q;
    q.action_prefixes = {"auth.", "mfa.", "session."};
    q.random_sample = true;
    q.since = 1'000;
    q.until = 1'049;
    q.limit = 10;
    auto results = store.query(q);
    REQUIRE(results.size() == 10); // bounded by limit
    for (const auto& e : results) {
        CHECK(e.timestamp >= 1'000);
        CHECK(e.timestamp <= 1'049); // never the 999'999 outlier
        const bool scoped = e.action.rfind("auth.", 0) == 0 || e.action.rfind("mfa.", 0) == 0;
        CHECK(scoped);
    }
}


// ── #2360: retention clock guard ───────────────────────────────────────────
//
// The cleanup pass used to be a blind `DELETE ... WHERE ttl_expires_at < now`
// bound to the local wall clock. One forward clock step (restored VM snapshot,
// NTP correction after a dead CMOS battery, a hand-set date) therefore emptied
// the SOC 2 evidence table in a single statement, with no counter and no log
// line an operator could act on. These tests drive `cleanup_once(now)` at an
// explicit `now` so nothing here depends on the real clock or on sleeping the
// hourly cleanup interval.

namespace {

// A TTL is written by log() as `local_clock_now + retention_days*86400`, which
// gives a test no way to place a row at a chosen distance from the `now` it
// passes to cleanup_once(). Seeding through a second connection to the same
// database lets each test state the TTL it means. Uses the production schema
// (AuditStore's migrations have already run by the time the fixture seeds).
// RAII for the raw second connection the helpers below open. A `REQUIRE` that
// fails mid-helper throws Catch2's exception, which would skip a bare
// `sqlite3_close(raw)` and leave a second writable connection open against the
// same file the AuditStore under test holds -- a plausible amplifier for a
// follow-on "database is locked" flake. `sqlite3_open` allocates the handle even
// when it fails, so the owner takes it from the first call.
struct RawConn {
    // The handle is owned from the FIRST call, not after the check: `sqlite3_open`
    // allocates even when it fails, and the `REQUIRE` below throws, so a bare
    // pointer member would leak on constructor unwind -- the same bug class this
    // helper exists to fix, one level up.
    SqliteDb owner;
    explicit RawConn(const std::filesystem::path& path) {
        const int rc = sqlite3_open(path.string().c_str(), owner.addr());
        REQUIRE(rc == SQLITE_OK);
        sqlite3_exec(owner.get(), "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    }
    // A METHOD, not a cached member. A stored `sqlite3*` alias would be the one
    // live instance of the `addr()` footgun in the tree: any later `owner.addr()`
    // finalizes/closes what the alias points at, and the recycled handle can land
    // at the SAME address, so a stale alias silently refers to a different object
    // rather than crashing.
    [[nodiscard]] sqlite3* db() const { return owner.get(); }
    // No user-declared destructor: `owner` closes, via close_v2, which is what
    // makes an outstanding statement from a throwing REQUIRE safe.
    RawConn(const RawConn&) = delete;
    RawConn& operator=(const RawConn&) = delete;
};

void seed_rows_with_ttl(const std::filesystem::path& path, std::int64_t ttl, int count) {
    RawConn c{path};
    REQUIRE(sqlite3_exec(c.db(), "BEGIN", nullptr, nullptr, nullptr) == SQLITE_OK);
    // Guard declared BEFORE the statement so the statement finalizes first --
    // SQLite wants live statements gone before ROLLBACK. Without both owners a
    // throwing REQUIRE below leaves an open transaction AND a live statement, and
    // close_v2 then defers the connection close forever (zombie), so the second
    // writable connection against the file under test never goes away.
    SqliteTxn txn{c.db()};
    SqliteStmt stmt;
    REQUIRE(sqlite3_prepare_v2(c.db(),
                               "INSERT INTO audit_events (timestamp, principal, principal_role, "
                               "action, result, ttl_expires_at) VALUES (?,?,?,?,?,?)",
                               -1, stmt.addr(), nullptr) == SQLITE_OK);
    for (int i = 0; i < count; ++i) {
        sqlite3_reset(stmt.get());
        sqlite3_bind_int64(stmt.get(), 1, ttl);
        sqlite3_bind_text(stmt.get(), 2, "admin", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 3, "admin", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 4, "auth.login", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 5, "success", -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt.get(), 6, ttl);
        REQUIRE(sqlite3_step(stmt.get()) == SQLITE_DONE);
    }
    stmt.reset(); // finalize before COMMIT
    REQUIRE(txn.commit() == SQLITE_OK);
}

// Run arbitrary SQL through a second connection (used to remove a survivor row
// or to break the table for the fail-closed test).
void exec_raw(const std::filesystem::path& path, const char* sql) {
    RawConn c{path};
    REQUIRE(sqlite3_exec(c.db(), sql, nullptr, nullptr, nullptr) == SQLITE_OK);
}

// Retention window used by every guard test below: 1 day. `cleanup_interval_min
// = 0` keeps start_cleanup() a no-op, so no background thread ever races the
// explicit cleanup_once() calls.
constexpr int kGuardRetentionDays = 1;
constexpr std::int64_t kWindow = static_cast<std::int64_t>(kGuardRetentionDays) * 86400;
// An arbitrary fixed "now", far from both the epoch and the real clock.
constexpr std::int64_t kNow = 1'700'000'000;

/// Anchor a directly-constructed store, as `GuardFixture::anchor` does for the
/// fixture-based tests. Same mechanism and same reason (#2579): a pass over an
/// empty table records the reading without classifying anything, so the test
/// that follows exercises its own trigger rather than the bootstrap.
void anchor_pass(AuditStore& s, std::int64_t at = kNow - 3600) {
    REQUIRE(s.cleanup_once(at) == 0);
    REQUIRE(s.clock_anomaly_skips_count() == 0);
    REQUIRE(s.bootstrap_declines_count() == 0);
}

struct GuardFixture {
    yuzu::test::TempDbFile tmp{std::string_view{"audit-clockguard-"}};
    AuditStore store;
    GuardFixture() : store(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0) {
        REQUIRE(store.is_open());
    }
    void seed(std::int64_t ttl, int count) { seed_rows_with_ttl(tmp.path, ttl, count); }

    /// Put this store in the state of one that has already completed a pass, so
    /// the bootstrap trigger (#2579) does not fire.
    ///
    /// Needed because #2579 made "no stored reading, and rows already expired" a
    /// decline in its own right. Almost every guard test here is about something
    /// else -- the cap, the dedup rule, one specific trigger -- and each would
    /// otherwise spend its first pass absorbing a bootstrap decline it never
    /// meant to exercise. This states the precondition those tests always
    /// assumed implicitly. The ones that ARE about the bootstrap do not call it.
    ///
    /// A pass over an EMPTY table is the whole mechanism, and it is exact rather
    /// than approximate: `cleanup_once` anchors the reading before it probes
    /// anything, and with nothing expired the rule short-circuits to `None`, so
    /// no counter moves, nothing is deleted and no anomaly is recorded. Call it
    /// BEFORE seeding. The default is an hour back, comfortably inside the
    /// 7-day step threshold, so it cannot itself provoke a `Step`.
    void anchor(std::int64_t last_pass_now = kNow - 3600) {
        REQUIRE(store.cleanup_once(last_pass_now) == 0);
        REQUIRE(store.clock_anomaly_skips_count() == 0);
        REQUIRE(store.bootstrap_declines_count() == 0);
    }
};


// ── Log capture, for the decline-attribution tests ────────────────────────────
//
// The four decline triggers (first pass / wipe / step / implausible stored
// reading) all produce ONE observable through the counters:
// `clock_anomaly_skips_count()` goes up by one. Which trigger fired is carried
// only by the warning text, and that text is what a SOC 2 reader acts on -- a
// pass that declined on a would-wipe must not claim a clock step or an outage
// that did not happen. Without a sink, a mutation that always emitted
// `DeclineWipe`, or that swapped the big_step/prev_implausible precedence, went
// green.
//
// Swaps a capturing sink onto the default logger for the duration of one test
// and restores it in the destructor, including on a throwing REQUIRE. Catch2
// runs cases serially in one process, so no other test is logging concurrently.
class LogCapture {
public:
    LogCapture() : saved_(spdlog::default_logger()) {
        sink_ = std::make_shared<spdlog::sinks::ostream_sink_mt>(stream_);
        auto logger = std::make_shared<spdlog::logger>("capture", sink_);
        logger->set_level(spdlog::level::trace);
        logger->set_pattern("%v");
        spdlog::set_default_logger(logger);
    }
    ~LogCapture() { spdlog::set_default_logger(saved_); }

    LogCapture(const LogCapture&) = delete;
    LogCapture& operator=(const LogCapture&) = delete;

    [[nodiscard]] std::string text() const { return stream_.str(); }
    [[nodiscard]] bool says(std::string_view needle) const {
        return stream_.str().find(needle) != std::string::npos;
    }
    void clear() { stream_.str(std::string{}); }

private:
    std::ostringstream stream_;
    std::shared_ptr<spdlog::sinks::ostream_sink_mt> sink_;
    std::shared_ptr<spdlog::logger> saved_;
};

} // namespace

TEST_CASE("AuditStore #2360: a first pass that would expire every datable row declines once",
          "[audit_store][retention][clock-guard]") {
    GuardFixture f;
    f.seed(kNow - 100, 10); // every row already past its TTL

    CHECK(f.store.cleanup_once(kNow) == 0);
    CHECK(f.store.total_count() == 10); // nothing deleted
    CHECK(f.store.clock_anomaly_skips_count() == 1);
    CHECK(f.store.cleanup_failed_count() == 0);
}

TEST_CASE("AuditStore #2360: the decline is latched, so the backlog still drains",
          "[audit_store][retention][clock-guard]") {
    // Declining EVERY pass would mean a genuinely all-expired store never ages
    // out anything at all - the guard would become a permanent retention leak.
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, 10);

    REQUIRE(f.store.cleanup_once(kNow) == 0);
    REQUIRE(f.store.clock_anomaly_skips_count() == 1);

    CHECK(f.store.cleanup_once(kNow + 1) == 10); // latched: accepted this time
    CHECK(f.store.total_count() == 0);
    CHECK(f.store.clock_anomaly_skips_count() == 1); // and NOT counted twice
}

TEST_CASE("AuditStore #2360: the latch clears once the backlog is gone, re-arming the guard",
          "[audit_store][retention][clock-guard]") {
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, 10);

    REQUIRE(f.store.cleanup_once(kNow) == 0);      // decline #1
    REQUIRE(f.store.cleanup_once(kNow + 1) == 10); // drain
    REQUIRE(f.store.cleanup_once(kNow + 2) == 0);  // nothing expired -> latch clears

    f.seed(kNow - 100, 4); // a fresh anomaly arrives
    CHECK(f.store.cleanup_once(kNow + 3) == 0);
    CHECK(f.store.total_count() == 4);
    CHECK(f.store.clock_anomaly_skips_count() == 2);
}

TEST_CASE("AuditStore #2360: a datable survivor means no wipe, so the pass deletes immediately",
          "[audit_store][retention][clock-guard]") {
    // The healthy steady state: some rows have aged out, others have not. The
    // guard must be completely invisible here.
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, 10);       // expired
    f.seed(kNow + kWindow, 1);    // a normal, unexpired row

    CHECK(f.store.cleanup_once(kNow) == 10);
    CHECK(f.store.total_count() == 1);
    CHECK(f.store.clock_anomaly_skips_count() == 0);
}

TEST_CASE("AuditStore #2579: no stored reading + rows already expired declines, once",
          "[audit_store][retention][clock-guard]") {
    // The disclosed shape, end to end. A host whose clock was ALREADY skewed
    // forward before its first guarded pass: rows written before the skew look
    // expired, rows written after it are still inside the window, so the
    // would-expire-everything test does not fire and -- before this trigger --
    // nothing else did either. The pass deleted, with no decline, no counter and
    // no warning.
    //
    // Deliberately NOT anchored: the absence of a stored reading IS the input.
    GuardFixture f;
    f.seed(kNow - 100, 10);    // expired: written before the skew
    f.seed(kNow + kWindow, 2); // datable survivors: written after it

    REQUIRE(f.store.cleanup_once(kNow) == 0); // was 10 before #2579
    CHECK(f.store.total_count() == 12);
    CHECK(f.store.bootstrap_declines_count() == 1);
    // The signal separation is the contract, not an implementation detail: this
    // decline must not fire the alert that means "the clock moved".
    CHECK(f.store.clock_anomaly_skips_count() == 0);

    // Once, not forever. The declining pass anchored the reading, so the next
    // pass has a comparison point and proceeds -- paced by the cap as always.
    CHECK(f.store.cleanup_once(kNow + 1) == 10);
    CHECK(f.store.total_count() == 2);
    CHECK(f.store.bootstrap_declines_count() == 1); // and NOT counted twice
}

TEST_CASE("AuditStore #2579: a probe-failed pass does not spend the bootstrap trigger",
          "[audit_store][retention][clock-guard]") {
    // BLOCKING, found by unhappy-path at Gate 4.
    //
    // `cleanup_once` re-anchors BEFORE it probes (the durable write and the
    // in-memory stamp both happen at the top of the locked section), so a pass
    // whose probes then fail has consumed the anchor without ever reaching a
    // verdict. Deriving `no_anchor` from the anchor therefore let ONE transient
    // probe failure disarm the trigger permanently: pass 2 sees a reading, calls
    // itself anchored, and deletes with every detector false -- the exact defect
    // #2579 closes, reinstated.
    //
    // It is not a remote shape. The first post-upgrade pass is the one with the
    // largest backlog and possibly no retention index yet (the index build is
    // deliberately best-effort), so it is the slowest and the likeliest to meet
    // SQLITE_BUSY. The population at risk and the population that trips this are
    // the same population.
    //
    // The fix mirrors what `loaded_meta_unusable_` already does on this path, for
    // the reason that branch states in place: the flag is not consumed by a pass
    // that did not act on it.
    GuardFixture f;
    f.seed(kNow - 100, 10);    // expired: written before the skew
    f.seed(kNow + kWindow, 2); // datable survivors: written after it

    // Pass 1 cannot probe -- and DOES re-anchor on its way past.
    exec_raw(f.tmp.path, "ALTER TABLE audit_events RENAME TO audit_events_hidden");
    CHECK(f.store.cleanup_once(kNow) == 0);
    CHECK(f.store.cleanup_failed_count() == 1);
    CHECK(f.store.bootstrap_declines_count() == 0); // no verdict was reached
    exec_raw(f.tmp.path, "ALTER TABLE audit_events_hidden RENAME TO audit_events");

    // Pass 2 must STILL decline. Before the fix it deleted all 10.
    CHECK(f.store.cleanup_once(kNow + 1) == 0);
    CHECK(f.store.bootstrap_declines_count() == 1);
    CHECK(f.store.total_count() == 12);

    // ...and having now reached a verdict, it is spent: pass 3 drains.
    CHECK(f.store.cleanup_once(kNow + 2) == 10);
    CHECK(f.store.bootstrap_declines_count() == 1);
}

TEST_CASE("AuditStore #2579: consecutive probe failures do not erode the trigger",
          "[audit_store][retention][clock-guard]") {
    // quality-engineer's Gate 8 coverage gap: the single-failure case is pinned
    // above, but nothing showed the flag surviving a RUN of them. It has to,
    // because the condition that makes a probe fail (a busy or wedged database
    // on the first post-upgrade pass) is exactly the kind that repeats.
    GuardFixture f;
    f.seed(kNow - 100, 10);
    f.seed(kNow + kWindow, 2);

    exec_raw(f.tmp.path, "ALTER TABLE audit_events RENAME TO audit_events_hidden");
    for (int i = 0; i < 3; ++i)
        CHECK(f.store.cleanup_once(kNow + i) == 0);
    CHECK(f.store.cleanup_failed_count() == 3);
    CHECK(f.store.bootstrap_declines_count() == 0); // no verdict on any of them
    exec_raw(f.tmp.path, "ALTER TABLE audit_events_hidden RENAME TO audit_events");

    // Still armed after three failures.
    CHECK(f.store.cleanup_once(kNow + 10) == 0);
    CHECK(f.store.bootstrap_declines_count() == 1);
    CHECK(f.store.total_count() == 12);
}

TEST_CASE("AuditStore #2579: nothing expired means no bootstrap decline",
          "[audit_store][retention][clock-guard]") {
    // The cost control. A fresh install has no stored reading either, and if the
    // trigger fired on that it would declare an anomaly on every server's first
    // boot -- which is why `no_anchor` is tested AFTER `has_expired`.
    GuardFixture f;
    f.seed(kNow + kWindow, 3); // nothing expired

    CHECK(f.store.cleanup_once(kNow) == 0);
    CHECK(f.store.bootstrap_declines_count() == 0);
    CHECK(f.store.clock_anomaly_skips_count() == 0);
    CHECK(f.store.total_count() == 3);
}

TEST_CASE("AuditStore #2360: one forward-skew far-future row cannot disarm the guard",
          "[audit_store][retention][clock-guard]") {
    // The predicate that makes the guard survive contact with a bad clock: a row
    // whose TTL is implausibly far ahead (written while the clock was skewed
    // forward, or carried in by a restored snapshot) can NEVER itself expire. If
    // it counted as an ordinary survivor, that single row would answer "no, this
    // pass would not wipe everything" for the life of the store - disarming the
    // guard exactly when it is needed. It is excluded from the question instead.
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, 10);
    f.seed(kNow + kWindow + kAuditTtlFutureSlackSec + 1'000, 1); // implausible future

    CHECK(f.store.cleanup_once(kNow) == 0); // still declines
    CHECK(f.store.total_count() == 11);
    CHECK(f.store.clock_anomaly_skips_count() == 1);
}

TEST_CASE("AuditStore #2360: a sub-window forward jump is caught by the step check",
          "[audit_store][retention][clock-guard]") {
    // The outcome test alone only fires when a jump exceeds the WHOLE retention
    // window. A jump of just over one window expires a large slice while leaving
    // survivors behind, which the per-pass cap would bound but nothing would
    // report. The step check is what turns that into an operator signal.
    GuardFixture f;
    f.anchor();
    // Past the FLOOR (kAuditMinBigStepSec), not merely past the 1-day retention
    // window: elapsed time cannot tell a jump from an outage, so the check only
    // fires past a duration where an outage is itself remarkable.
    const std::int64_t later = kNow + kAuditMinBigStepSec + 1;

    // A survivor must sit INSIDE the datable horizon of the reading it is meant
    // to survive -- a row beyond `now + window + slack` is treated as
    // forward-skewed and excluded, which would make the pass decline for the
    // wrong reason. So each reading gets its own.
    f.seed(kNow - 100, 5);   // expired at both readings
    f.seed(kNow + kWindow, 1); // survivor for pass 1
    REQUIRE(f.store.cleanup_once(kNow) == 5);
    REQUIRE(f.store.clock_anomaly_skips_count() == 0);

    f.seed(kNow - 50, 5);       // more expired rows for the jumped pass to find
    f.seed(later + kWindow, 1); // survivor for pass 2, so only the STEP can fire
    CHECK(f.store.cleanup_once(later) == 0);
    CHECK(f.store.clock_anomaly_skips_count() == 1);
    CHECK(f.store.total_count() == 7); // nothing deleted on the declining pass
}

TEST_CASE("AuditStore #2360: an ordinary over-cap backlog does NOT arm the latch",
          "[audit_store][retention][clock-guard]") {
    // The adjudicated latch rule. Arming on any capped pass would mean a store
    // that routinely expires more than one pass can delete sits permanently
    // latched - and a real clock anomaly arriving next would then wipe without a
    // decline, a warn line, or a counter increment. The latch tracks the WIPE
    // condition, not the backlog.
    //
    // kSurplus is deliberately independent of the cap: the assertions below stay
    // meaningful (and the cap test stays honest) if the cap is ever retuned.
    constexpr std::size_t kSurplus = 7;
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, static_cast<int>(kMaxAuditDeletesPerPass + kSurplus));
    f.seed(kNow + kWindow, 1); // a survivor: this is a backlog, not an anomaly

    // Pass 1 deletes exactly one cap's worth and leaves the rest.
    CHECK(f.store.cleanup_once(kNow) == kMaxAuditDeletesPerPass);
    CHECK(f.store.total_count() == kSurplus + 1);
    CHECK(f.store.clock_anomaly_skips_count() == 0);

    // Pass 2 finishes the backlog. The latch must still be clear.
    CHECK(f.store.cleanup_once(kNow + 1) == kSurplus);
    CHECK(f.store.total_count() == 1);
    CHECK(f.store.clock_anomaly_skips_count() == 0);

    // Now a real anomaly: drop the survivor, re-seed all-expired rows. An armed
    // latch would let this delete silently.
    exec_raw(f.tmp.path, "DELETE FROM audit_events");
    f.seed(kNow - 100, 3);
    CHECK(f.store.cleanup_once(kNow + 2) == 0);
    CHECK(f.store.clock_anomaly_skips_count() == 1);
}

TEST_CASE("AuditStore #2360: a failing pass fails closed and counts separately from a decline",
          "[audit_store][retention][clock-guard]") {
    // Both a declined pass and a broken pass leave rows undeleted. Only a
    // separate counter tells an operator watching an audit table that never
    // shrinks which of the two is happening.
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, 5);
    f.seed(kNow + kWindow, 1);
    REQUIRE(f.store.cleanup_once(kNow) == 5);
    REQUIRE(f.store.cleanup_failed_count() == 0);

    exec_raw(f.tmp.path, "DROP TABLE audit_events");

    CHECK(f.store.cleanup_once(kNow + 1) == 0);
    CHECK(f.store.cleanup_failed_count() == 1);
    CHECK(f.store.clock_anomaly_skips_count() == 0); // not misreported as a clock anomaly
}

TEST_CASE("AuditStore #2360: a delete that fails mid-statement deletes nothing and leaves the "
          "latch alone",
          "[audit_store][retention][clock-guard]") {
    // The other half of fail-closed: the probes succeed (so the guard accepts
    // the pass) but the DELETE itself errors. A rejecting BEFORE DELETE trigger
    // is the cheapest way to force that. The pass must report zero deleted --
    // SQLite unwinds the statement, so any RETURNING rows already seen are back
    // -- count as a failure rather than a clock anomaly, and not touch the latch.
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, 5);
    f.seed(kNow + kWindow, 1);
    exec_raw(f.tmp.path, "CREATE TRIGGER block_delete BEFORE DELETE ON audit_events "
                         "BEGIN SELECT RAISE(ABORT, 'blocked'); END;");

    CHECK(f.store.cleanup_once(kNow) == 0);
    CHECK(f.store.total_count() == 6); // nothing actually removed
    CHECK(f.store.cleanup_failed_count() == 1);
    CHECK(f.store.clock_anomaly_skips_count() == 0);

    // The guard still fires on a genuine anomaly afterwards.
    exec_raw(f.tmp.path, "DROP TRIGGER block_delete");
    exec_raw(f.tmp.path, "DELETE FROM audit_events WHERE ttl_expires_at > 0 "
                         "AND ttl_expires_at >= 1700000000");
    CHECK(f.store.cleanup_once(kNow + 1) == 0);
    CHECK(f.store.clock_anomaly_skips_count() == 1);
}

TEST_CASE("AuditStore #2360: a failed DELETE re-arms the guard instead of spending the latch",
          "[audit_store][retention][clock-guard]") {
    // A pass that failed learned nothing about the clock, so it must not carry a
    // SET latch forward. Carrying it would let the next pass -- which may be the
    // first sight of a genuine anomaly -- delete with no decline, no warn line
    // and no counter increment: the guard spent on a failure.
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, 10); // every datable row expired

    REQUIRE(f.store.cleanup_once(kNow) == 0); // decline #1, latch set
    REQUIRE(f.store.clock_anomaly_skips_count() == 1);

    exec_raw(f.tmp.path, "CREATE TRIGGER block_delete BEFORE DELETE ON audit_events "
                         "BEGIN SELECT RAISE(ABORT, 'blocked'); END;");
    REQUIRE(f.store.cleanup_once(kNow + 1) == 0); // latched pass, delete fails
    REQUIRE(f.store.cleanup_failed_count() == 1);

    exec_raw(f.tmp.path, "DROP TRIGGER block_delete");
    // Same wipe condition, still unresolved: the guard must decline again rather
    // than delete on the strength of a latch spent by the failure.
    CHECK(f.store.cleanup_once(kNow + 2) == 0);
    CHECK(f.store.total_count() == 10);
    CHECK(f.store.clock_anomaly_skips_count() == 2);
}

TEST_CASE("AuditStore #2360: a failed probe re-arms the guard instead of spending the latch",
          "[audit_store][retention][clock-guard]") {
    // Same contract on the other failure path. Renaming the table away and back
    // makes the EXISTS probes fail for exactly one pass.
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, 10);

    REQUIRE(f.store.cleanup_once(kNow) == 0); // decline #1, latch set
    REQUIRE(f.store.clock_anomaly_skips_count() == 1);

    exec_raw(f.tmp.path, "ALTER TABLE audit_events RENAME TO audit_events_hidden");
    REQUIRE(f.store.cleanup_once(kNow + 1) == 0);
    REQUIRE(f.store.cleanup_failed_count() == 1);
    exec_raw(f.tmp.path, "ALTER TABLE audit_events_hidden RENAME TO audit_events");

    CHECK(f.store.cleanup_once(kNow + 2) == 0);
    CHECK(f.store.total_count() == 10);
    CHECK(f.store.clock_anomaly_skips_count() == 2);
}

TEST_CASE("AuditStore #2360: retention disabled never declines on an elapsed-time step",
          "[audit_store][retention][clock-guard]") {
    // retention_days <= 0 means "never expire": log() stamps ttl 0, so the store
    // has no expiry policy of its own to report a step against. The step check is
    // gated on `window > 0` for that reason.
    //
    // What the gate is NOT is a guard against over-firing on short gaps -- the
    // threshold is the absolute kAuditMinBigStepSec (7 days), so the 2-hour gap
    // below would not fire either way. Removing the gate changes exactly one
    // case: a retention-off store holding legacy TTLs that goes more than 7 days
    // between passes would then take a step decline it has no policy to justify.
    // `would_wipe` and the per-pass cap both still apply with the gate in place,
    // so nothing about the damage bound depends on it.
    //
    // Such a store can still hold rows carrying a non-zero TTL stamped while
    // retention was switched on; those are what the passes below age out.
    yuzu::test::TempDbFile tmp{std::string_view{"audit-clockguard-off-"}};
    AuditStore store(tmp.path, /*retention_days=*/0, /*cleanup_interval_min=*/0);
    REQUIRE(store.is_open());
    anchor_pass(store);

    seed_rows_with_ttl(tmp.path, kNow - 100, 5); // expired
    seed_rows_with_ttl(tmp.path, kNow + 3'600, 1); // survivor at this reading
    REQUIRE(store.cleanup_once(kNow) == 5);
    REQUIRE(store.clock_anomaly_skips_count() == 0);

    // Two hours later. Well under the 7-day threshold, so this pass must delete.
    const std::int64_t later = kNow + 7'200;
    seed_rows_with_ttl(tmp.path, kNow - 50, 5);
    seed_rows_with_ttl(tmp.path, later + 3'600, 1); // keeps `would_wipe` false
    CHECK(store.cleanup_once(later) == 6);          // 5 new + the first survivor
    CHECK(store.clock_anomaly_skips_count() == 0);
}

// ── Claims that prose kept getting wrong ─────────────────────────────────────
//
// Each of the three cases below pins a statement that a documentation
// paraphrase of this rule asserted INCORRECTLY at least once across five
// correction rounds. They exist so the next such claim is settled by a red test
// rather than by a reviewer reading English, which is the only thing that has
// reliably caught this class. See the "Where the rule lives" note in
// docs/user-manual/audit-log.md.

TEST_CASE("AuditStore #2360: a young store IS protected against a large forward jump",
          "[audit_store][retention][clock-guard]") {
    // The false claim: "on a store younger than its retention window, a forward
    // jump of ANY size classifies None and is never counted." It is false
    // because `has_expired` is probed against the JUMPED reading, not against
    // real elapsed time -- a jump big enough to carry `now` past the rows' TTLs
    // expires them, however young the store is. The jump SIZE decides this, not
    // the store's age.
    GuardFixture f;
    f.anchor();
    LogCapture log;
    f.seed(kNow + kWindow, 5); // written "now", nothing expired yet: a young store
    REQUIRE(f.store.cleanup_once(kNow) == 0);
    REQUIRE(f.store.clock_anomaly_skips_count() == 0);

    // A jump far past the rows' TTLs, so `has_expired` becomes true on a store
    // that had nothing expired a moment ago. That is the whole point: the probe
    // runs against the JUMPED reading.
    //
    // 30 days also clears the 7-day floor, so `classify` returns Step (which
    // outranks the wipe) -- pinned below, because without it a broken
    // `would_wipe` would hide behind `big_step` here and this test would not
    // notice. The wipe path on a young store is a separate scenario.
    const std::int64_t jumped = kNow + 30 * 86400;
    CHECK(f.store.cleanup_once(jumped) == 0);
    CHECK(f.store.clock_anomaly_skips_count() == 1);
    CHECK(f.store.total_count() == 5); // refused, not deleted
    CHECK(log.says("elapsed since the last retention pass")); // the Step branch, not Wipe
}

TEST_CASE("AuditStore #2360: retention disabled: a forward ratchet declines ONCE as a Wipe",
          "[audit_store][retention][clock-guard]") {
    // Two claims settled here. First, a forward ratchet on a retention-disabled
    // store does NOT starve the drain -- `Step` is unreachable with `window == 0`
    // (the gate itself is pinned by the 8-day-gap case below, which is the only
    // test in this file whose elapsed gap clears the floor with retention off).
    // Second, and the part a code comment and a doc paragraph both got wrong:
    // it is not silent.
    // Once the ratchet carries `now` past the last legacy TTL the survivor probe
    // finds nothing, which is `Wipe`. `Wipe` is a CONDITION, so it declines once
    // and the following pass drains.
    yuzu::test::TempDbFile tmp{std::string_view{"audit-clockguard-ratchet-"}};
    AuditStore store(tmp.path, /*retention_days=*/0, /*cleanup_interval_min=*/0);
    REQUIRE(store.is_open());
    anchor_pass(store);

    // Legacy rows, stamped while retention was switched ON, all already expired
    // and with no survivor behind them.
    seed_rows_with_ttl(tmp.path, kNow - 100, 5);

    CHECK(store.cleanup_once(kNow) == 0);              // declines: would wipe
    CHECK(store.clock_anomaly_skips_count() == 1);
    CHECK(store.cleanup_once(kNow + 1) == 5);          // same facts -> dedup -> drains
    CHECK(store.clock_anomaly_skips_count() == 1);     // and NOT counted twice
}

TEST_CASE("AuditStore #2360: retention disabled: an 8-day gap is still not a step",
          "[audit_store][retention][clock-guard]") {
    // Pins the `window > 0` conjunct in `big_step`, which had NO red/green
    // coverage before this case: every other retention-disabled test in this
    // file uses an elapsed gap far under kAuditMinBigStepSec, so deleting the
    // conjunct left the whole [clock-guard] suite green. The gate is what stops
    // a retention-off store from taking a step decline it has no expiry policy
    // to justify.
    //
    // A survivor is kept at BOTH readings so `would_wipe` stays false and a STEP
    // is the only thing that could decline these passes.
    yuzu::test::TempDbFile tmp{std::string_view{"audit-clockguard-off-gap-"}};
    AuditStore store(tmp.path, /*retention_days=*/0, /*cleanup_interval_min=*/0);
    REQUIRE(store.is_open());
    anchor_pass(store);

    seed_rows_with_ttl(tmp.path, kNow - 100, 5);
    seed_rows_with_ttl(tmp.path, kNow + 3'600, 1); // inside the 2-day future slack
    REQUIRE(store.cleanup_once(kNow) == 5);
    REQUIRE(store.clock_anomaly_skips_count() == 0);

    // Eight days on: comfortably past the 7-day floor. With the gate removed
    // this classifies Step and declines instead of draining.
    const std::int64_t later = kNow + 8 * 86400;
    seed_rows_with_ttl(tmp.path, kNow - 50, 5);
    seed_rows_with_ttl(tmp.path, later + 3'600, 1);
    CHECK(store.cleanup_once(later) == 6); // 5 new + the first survivor, now expired
    CHECK(store.clock_anomaly_skips_count() == 0);
}

TEST_CASE("AuditStore #2360: a forward movement of EXACTLY the floor is not a step",
          "[audit_store][retention][clock-guard]") {
    // The floor is asymmetric and the docs stated it both ways at different
    // times. `moved_at_least` is inclusive (`>=`), but `big_step` is STRICT
    // (`>`), so a forward movement of exactly kAuditMinBigStepSec does not
    // report and the pass deletes. One second more does report -- that case is
    // the sub-window-forward-jump test above, which uses `+ 1`.
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, 5);
    f.seed(kNow + kWindow, 1); // survivor for pass 1
    REQUIRE(f.store.cleanup_once(kNow) == 5);
    REQUIRE(f.store.clock_anomaly_skips_count() == 0);

    const std::int64_t exactly = kNow + kAuditMinBigStepSec; // NOT + 1
    f.seed(kNow - 50, 5);
    f.seed(exactly + kWindow, 1); // survivor, so only a STEP could decline this
    // 6, not 5: pass 1's survivor carried a TTL of kNow + kWindow, and `exactly`
    // is seven days past kNow, so that row has expired too by this pass.
    CHECK(f.store.cleanup_once(exactly) == 6);
    // The assertion that matters: exactly-at-floor did not report, so the pass
    // was allowed to delete at all.
    CHECK(f.store.clock_anomaly_skips_count() == 0);
}

TEST_CASE("AuditStore #2360: cleanup passes race-free against concurrent writers",
          "[audit_store][retention][clock-guard]") {
    // Two claims are under test. First, the production concurrency: the hourly
    // cleanup thread runs while REST, gRPC and background writers call log().
    // Second, the header's claim that cleanup_once() is safe to call
    // concurrently with a running cleanup thread -- which is only true because
    // the exclusive mtx_ covers the WHOLE pass, including the guard latch and
    // the last-pass reading. Those two are plain non-atomic members precisely
    // because of that lock, so this is the TSan target for it: take the lock out
    // of cleanup_once and TSan reports on last_reported_ /
    // last_pass_now_. (Concurrent cleanup callers are why the second claim needs
    // its own coverage -- writers alone cannot exercise the latch, since only a
    // cleanup pass ever touches it.)
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, 400);
    f.seed(kNow + kWindow, 1); // a survivor, so passes accept and do real work

    std::atomic<bool> stop{false};
    std::vector<std::thread> threads;
    for (int t = 0; t < 3; ++t) {
        threads.emplace_back([&] {
            while (!stop.load(std::memory_order_relaxed)) {
                AuditEvent e;
                e.principal = "admin";
                e.principal_role = "admin";
                e.action = "auth.login";
                e.result = "success";
                (void)f.store.log(e);
            }
        });
    }
    std::vector<std::thread> cleaners;
    for (int t = 0; t < 2; ++t) {
        cleaners.emplace_back([&, t] {
            for (int i = 0; i < 40; ++i)
                (void)f.store.cleanup_once(kNow + t * 100 + i);
        });
    }
    for (auto& c : cleaners)
        c.join();
    stop.store(true, std::memory_order_relaxed);
    for (auto& w : threads)
        w.join();

    // Interleaving-independent: the concurrently-written rows are stamped from
    // the real clock, so they are far beyond every `now` the cleaners used and
    // survive; no pass errored.
    // The REAL assertion. `total_count() > 0` was near-vacuous: three writer
    // threads flood in rows for the whole test, so it holds even if retention
    // deleted nothing, or double-deleted. `mtx_` makes the OUTCOME deterministic
    // regardless of interleaving, so the 400 seeded-expired rows must be deleted
    // exactly once between the two racing cleaners -- never twice, never lost.
    // This one fails on a broken lock without needing TSan, so the Tier 1/2 CI
    // legs get signal from it too, not just the nightly sanitizer leg.
    CHECK(f.store.rows_deleted_count() == 400);
    CHECK(f.store.total_count() > 0);
    CHECK(f.store.cleanup_failed_count() == 0);
}

TEST_CASE("AuditStore #2360: the clock-step check survives a restart",
          "[audit_store][retention][clock-guard]") {
    // The governance finding this pins. The outcome test is defeated by ANY
    // write landing after the clock moves -- a fresh row is a datable survivor,
    // so `would_wipe` goes false -- which on a serving server is the common case.
    // That leaves the elapsed-time check as the only detector, and held in
    // memory alone it compares against zero on the first pass of a process, so a
    // server that BOOTS with an already-wrong clock never sees a step at all.
    // That is the dead-CMOS / restored-snapshot case the guard exists for.
    //
    // Persisting the reading closes it: a fresh AuditStore over the same file
    // still knows when the last pass ran.
    yuzu::test::TempDbFile tmp{std::string_view{"audit-clockguard-restart-"}};

    {
        AuditStore first(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
        REQUIRE(first.is_open());
        anchor_pass(first);
        seed_rows_with_ttl(tmp.path, kNow - 100, 5);
        seed_rows_with_ttl(tmp.path, kNow + kWindow, 1); // survivor: no `would_wipe`
        REQUIRE(first.cleanup_once(kNow) == 5);
        REQUIRE(first.clock_anomaly_skips_count() == 0);
    }

    // Process restarts. The clock is now more than a whole retention window
    // ahead, and a write has already landed at the new time -- so the outcome
    // test cannot see anything wrong.
    AuditStore second(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
    REQUIRE(second.is_open());
    const std::int64_t jumped = kNow + kAuditMinBigStepSec + 1;
    seed_rows_with_ttl(tmp.path, kNow + 10, 5);       // expired at the new reading
    seed_rows_with_ttl(tmp.path, jumped + 3'600, 1);  // survivor at the new reading

    CHECK(second.cleanup_once(jumped) == 0);
    CHECK(second.clock_anomaly_skips_count() == 1);
    CHECK(second.total_count() == 7); // nothing deleted on the declining pass
}

TEST_CASE("AuditStore #2360: a closed store counts a failed pass, not silence",
          "[audit_store][retention][clock-guard]") {
    // A store that never opened, or whose migration failed and closed it, has
    // stopped retaining permanently. If that returned 0 without counting, both
    // counters would sit at zero forever and an ever-growing audit.db would read
    // as a healthy guard -- the exact confusion the second counter exists to
    // prevent.
    yuzu::test::TempDbFile dir{std::string_view{"audit-clockguard-closed-"}};
    std::filesystem::create_directories(dir.path); // a directory is not openable
    AuditStore store(dir.path / "nested" / "audit.db", kGuardRetentionDays,
                     /*cleanup_interval_min=*/0);
    REQUIRE_FALSE(store.is_open());

    CHECK(store.cleanup_once(kNow) == 0);
    CHECK(store.cleanup_failed_count() == 1);
    CHECK(store.clock_anomaly_skips_count() == 0);
}

TEST_CASE("AuditStore #2360: a cap-bound pass is counted, not just logged",
          "[audit_store][retention][clock-guard]") {
    // The cap converts an allowed wipe into a paced drain, but it introduces its
    // own failure: if it binds on every pass, expiry outruns the drain and
    // audit.db grows without bound. Neither the skip counter nor the failure
    // counter moves in that state.
    constexpr std::size_t kSurplus = 7;
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, static_cast<int>(kMaxAuditDeletesPerPass + kSurplus));
    f.seed(kNow + kWindow, 1);

    CHECK(f.store.cleanup_once(kNow) == kMaxAuditDeletesPerPass);
    CHECK(f.store.cap_reached_count() == 1);
    CHECK(f.store.rows_deleted_count() == kMaxAuditDeletesPerPass);

    // The pass that clears the backlog does NOT count as cap-reached.
    CHECK(f.store.cleanup_once(kNow + 1) == kSurplus);
    CHECK(f.store.cap_reached_count() == 1);
    CHECK(f.store.rows_deleted_count() == kMaxAuditDeletesPerPass + kSurplus);
}

TEST_CASE("AuditStore #2360: an ordinary outage below the floor is not a clock anomaly",
          "[audit_store][retention][clock-guard]") {
    // Governance UP-2. Elapsed time cannot distinguish a forward clock jump from
    // the server simply not having run. With a short retention setting, an
    // unfloored check reports every maintenance window as a clock anomaly, which
    // destroys the signal. The gap here is far past the 1-day retention window
    // but below the floor, so it must stay silent.
    GuardFixture f;
    f.anchor();
    // A literal 5 days, deliberately NOT derived from kAuditMinBigStepSec: this
    // pins the floor's VALUE, so shrinking it back toward the retention window
    // reddens here instead of passing silently.
    const std::int64_t later = kNow + 5 * 86400;

    f.seed(kNow - 100, 5);
    f.seed(kNow + kWindow, 1);
    REQUIRE(f.store.cleanup_once(kNow) == 5);

    f.seed(kNow - 50, 5);
    f.seed(later + kWindow, 1);
    // 6, not 5: pass 1's survivor is itself expired by `later`, so it joins the
    // backlog. The point is that the pass DELETED rather than declined.
    CHECK(f.store.cleanup_once(later) == 6);
    CHECK(f.store.clock_anomaly_skips_count() == 0);
}

TEST_CASE("AuditStore #2360: a stored reading ahead of the clock is an anomaly, and self-heals",
          "[audit_store][retention][clock-guard]") {
    // Governance UP-1. The reading is durable state in the same database as the
    // evidence, so it can come back corrupt, hand-edited, or stamped by an
    // earlier pass that ran while the clock was skewed forward. Unsanitised,
    // `now - prev` stays negative until real time catches up -- potentially years
    // -- silently killing the only detector that survives a restart.
    //
    // INT64_MAX is the SILENT-DISABLE case, not a UB case: `now - INT64_MAX`
    // stays in range for a normal positive epoch. The overflow case is INT64_MIN,
    // covered by its own test below.
    yuzu::test::TempDbFile tmp{std::string_view{"audit-clockguard-poison-"}};
    {
        // Create the schema first; the raw seeding connection needs the table.
        AuditStore warm(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
        REQUIRE(warm.is_open());
    }
    seed_rows_with_ttl(tmp.path, kNow - 100, 5);
    seed_rows_with_ttl(tmp.path, kNow + kWindow, 1); // survivor: only the reading is wrong
    exec_raw(tmp.path, "INSERT INTO audit_retention_meta (key, value) VALUES "
                       "('last_pass_now', 9223372036854775807) "
                       "ON CONFLICT(key) DO UPDATE SET value = excluded.value");

    AuditStore store(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
    REQUIRE(store.is_open());
    CHECK(store.cleanup_once(kNow) == 0);              // declines rather than trusting it
    CHECK(store.clock_anomaly_skips_count() == 1);

    // Re-anchored on the current reading, so the next pass proceeds normally.
    CHECK(store.cleanup_once(kNow + 1) == 5);
    CHECK(store.clock_anomaly_skips_count() == 1);
}

TEST_CASE("AuditStore #2360 CH-1: hostile guard state cannot wipe, cannot disable, self-heals",
          "[audit_store][retention][clock-guard][chaos]") {
    // Gate 5 CH-1, the one chaos scenario scoped to block this change. It
    // compounds the round-2 sanitiser fix (UP-1) with the per-pass cap and the
    // re-arm-on-failure rule, driving four different hostile values through the
    // durable guard state in sequence.
    //
    // Run this under UBSan: the pre-fix code computed `now - prev` on whatever
    // the row held. INT64_MIN is the signed-overflow case; INT64_MAX is the
    // silent-DISABLE case (`now - INT64_MAX` stays in range for a normal epoch,
    // it just goes hugely negative and suppresses the step check forever).
    constexpr std::size_t kSurplus = 7;
    yuzu::test::TempDbFile tmp{std::string_view{"audit-clockguard-ch1-"}};
    {
        AuditStore warm(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
        REQUIRE(warm.is_open());
        anchor_pass(warm);
    }
    seed_rows_with_ttl(tmp.path, kNow - 100, static_cast<int>(kMaxAuditDeletesPerPass + kSurplus));
    seed_rows_with_ttl(tmp.path, kNow + kWindow, 1); // a survivor throughout

    auto poison = [&](const char* value) {
        exec_raw(tmp.path, (std::string("INSERT INTO audit_retention_meta (key, value) VALUES "
                                        "('last_pass_now', ") +
                            value +
                            ") ON CONFLICT(key) DO UPDATE SET value = excluded.value")
                               .c_str());
    };
    auto stored_reading = [&]() -> std::int64_t {
        RawConn c{tmp.path};
        SqliteStmt st;
        REQUIRE(sqlite3_prepare_v2(c.db(),
                                   "SELECT value FROM audit_retention_meta WHERE key='last_pass_now'",
                                   -1, st.addr(), nullptr) == SQLITE_OK);
        std::int64_t v = -1;
        if (sqlite3_step(st.get()) == SQLITE_ROW)
            v = sqlite3_column_int64(st.get(), 0);
        return v;
    };

    std::size_t before = 0;
    {
        AuditStore probe(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
        before = probe.total_count();
    }
    std::size_t pass = 0;
    std::uint64_t skips = 0, failures = 0;
    std::size_t remaining = before;
    // INT64_MAX, -1 and a far-future value are all implausible readings, so each
    // declines. (-1 used to be a quiet reset; it is now an anomaly. Note this is
    // NOT because the value is impossible for this code to have written -- a
    // dead-CMOS machine persists a negative reading legitimately -- but because
    // the guard cannot reason about it either way.) The final pass runs
    // with the row deleted entirely -- a fresh-install shape, which is NOT an
    // anomaly.
    for (const char* value : std::array<const char*, 4>{"9223372036854775807", "-1",
                                                        "1799999999", nullptr}) {
        if (value)
            poison(value);
        else
            exec_raw(tmp.path, "DELETE FROM audit_retention_meta");
        const std::int64_t now = kNow + static_cast<std::int64_t>(pass);
        INFO("pass " << pass << " value=" << (value ? value : "<row deleted>"));
        // A FRESH store per poisoning, deliberately: the reading is loaded once
        // at construction and held in memory, so tampering with the row while the
        // server runs is inert. The realistic threat is a row edited (or left
        // skewed by an earlier pass) while the process is DOWN, which is what a
        // restart models.
        AuditStore store(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
        REQUIRE(store.is_open());
        const std::size_t deleted = store.cleanup_once(now);
        // No pass may ever exceed the cap, whatever the guard state said.
        CHECK(deleted <= kMaxAuditDeletesPerPass);
        // Every pass re-anchors the durable reading on its own clock, so a
        // poisoned value can never persist beyond the pass that saw it.
        CHECK(stored_reading() == now);
        // Either decline counter answers the question this case asks -- was the
        // hostile state REPORTED, or silently accepted. #2579 split the signal in
        // two (a bootstrap decline makes no claim about the clock), so summing
        // them keeps the assertion measuring what it always measured.
        skips += store.clock_anomaly_skips_count() + store.bootstrap_declines_count();
        failures += store.cleanup_failed_count();
        remaining = store.total_count();
        ++pass;
    }

    // A PRE-1970 clock against a far-future stored reading -- a dead CMOS, the
    // motivating case for the whole guard.
    //
    // A note on the signed-overflow concern this case was written for, because
    // it did NOT hold up: `now - INT64_MAX` stays in range for any positive
    // `now` (it lands around -9.22e18, just inside INT64_MIN), so an underflow
    // needs `now <= -2`; and reaching that subtraction at all requires an
    // EXPIRED row relative to `now`, which for a negative `now` means a negative
    // `ttl_expires_at` that log() never writes. Verified empirically: with the
    // sanitiser removed, UBSan reports nothing here. The sanitiser earns its
    // place by preventing the guard from being silently DISABLED (which the
    // passes above do catch), not by preventing UB.
    {
        poison("9223372036854775807");
        AuditStore store(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
        REQUIRE(store.is_open());
        CHECK(store.cleanup_once(-86'400) == 0); // nothing is expired against a 1969 clock
        CHECK(store.cleanup_failed_count() == 0);
    }

    // The survivor is untouched and the store was never emptied: the hostile
    // state could not cause a wipe, only pace or decline. Since #2579 every one
    // of these passes declines, so nothing is removed at all -- a strictly
    // stronger statement than the old "it deleted, but only a capped amount".
    CHECK(remaining > 0);
    CHECK(remaining == before);

    // ...and the guard is NOT DISABLED by any of it -- the other half of this
    // case's title, and the half the old `remaining < before` used to carry.
    //
    // It takes two passes, and the reason is worth stating: the 1969 pass above
    // re-anchored the durable reading to a NEGATIVE value, so the next pass
    // reads it, refuses to trust it (`BadState`) and re-anchors on a sane clock.
    // Only then is there a usable comparison point. That is the self-heal, and
    // asserting a real delete at the end of it is what proves the hostile state
    // could pace the drain but never stop it.
    {
        AuditStore healed(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
        REQUIRE(healed.is_open());

        CHECK(healed.cleanup_once(kNow + 10) == 0);        // declines the negative reading
        CHECK(healed.clock_anomaly_skips_count() == 1);
        CHECK(healed.bootstrap_declines_count() == 0);     // NOT the bootstrap trigger

        // Anchored and sane: the backlog drains, paced by the cap.
        CHECK(healed.cleanup_once(kNow + 11) == kMaxAuditDeletesPerPass);
        CHECK(healed.total_count() < before);
        CHECK(healed.clock_anomaly_skips_count() == 1);    // no new anomaly
        CHECK(healed.bootstrap_declines_count() == 0);
    }
    // The two readings ahead of `now` were each reported as a decline (of one
    // kind or the other), and none of this was misreported as a cleanup failure.
    CHECK(skips >= 2);
    CHECK(failures == 0);
}

TEST_CASE("AuditStore #2360: a clean drain clears the latch in the SAME pass",
          "[audit_store][retention][clock-guard]") {
    // Sol / Gate 8. The latch used to be assigned from the PRE-delete
    // `would_wipe`, so a pass that drained the entire backlog still latched. If a
    // real anomaly arrived before the next pass could clear it, that anomaly
    // deleted with no decline, no warn and no counter -- the guard spent on an
    // anomaly that was already over. The latch now comes from a post-delete fact.
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, 10); // all expired, well under the cap

    REQUIRE(f.store.cleanup_once(kNow) == 0);      // decline, latch armed
    REQUIRE(f.store.clock_anomaly_skips_count() == 1);
    REQUIRE(f.store.cleanup_once(kNow + 1) == 10); // drains the whole backlog
    REQUIRE(f.store.total_count() == 0);

    // A fresh anomaly arrives BEFORE any intervening empty pass. The old rule
    // left the latch armed here and deleted silently.
    f.seed(kNow - 100, 6);
    CHECK(f.store.cleanup_once(kNow + 2) == 0);
    CHECK(f.store.total_count() == 6);
    CHECK(f.store.clock_anomaly_skips_count() == 2);
}

TEST_CASE("AuditStore #2360: an exact-cap drain that empties the backlog is not cap-bound",
          "[audit_store][retention][clock-guard]") {
    // The cap counter is documented as proving a backlog remains. Deriving it
    // from `deleted >= cap` alone made an exact-cap drain that emptied the table
    // report a backlog that was not there.
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, static_cast<int>(kMaxAuditDeletesPerPass));
    f.seed(kNow + kWindow, 1); // survivor, so the pass is accepted, not declined

    CHECK(f.store.cleanup_once(kNow) == kMaxAuditDeletesPerPass);
    CHECK(f.store.cap_reached_count() == 0); // nothing left behind
    CHECK(f.store.total_count() == 1);
}

TEST_CASE("AuditStore #2360: a negative stored reading is an anomaly, not a quiet reset",
          "[audit_store][retention][clock-guard]") {
    // A negative value is not something the guard can compare against. It is NOT
    // proof of tampering -- this very code persists one on a dead-CMOS machine,
    // since the caller-clock guard is upper-bound only -- but accepting it
    // quietly disabled the step check for that pass with nothing to report.
    yuzu::test::TempDbFile tmp{std::string_view{"audit-clockguard-neg-"}};
    {
        AuditStore warm(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
        REQUIRE(warm.is_open());
    }
    seed_rows_with_ttl(tmp.path, kNow - 100, 5);
    seed_rows_with_ttl(tmp.path, kNow + kWindow, 1); // survivor: only the state is wrong
    exec_raw(tmp.path, "INSERT INTO audit_retention_meta (key, value) VALUES "
                       "('last_pass_now', -1) "
                       "ON CONFLICT(key) DO UPDATE SET value = excluded.value");

    AuditStore store(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
    REQUIRE(store.is_open());
    CHECK(store.cleanup_once(kNow) == 0);
    CHECK(store.clock_anomaly_skips_count() == 1);
}

TEST_CASE("AuditStore #2360: INT64_MIN in the stored reading is rejected before any arithmetic",
          "[audit_store][retention][clock-guard][chaos]") {
    // The overflow case that actually exists. `now - INT64_MAX` stays in range
    // for a normal positive epoch (that one silently DISABLES the check, covered
    // above), but `now - INT64_MIN` exceeds INT64_MAX -- by `now + 1`, so it is
    // signed-overflow UB rather than a wrong answer -- and IS reachable with an
    // ordinary expired backlog. Run under UBSan.
    yuzu::test::TempDbFile tmp{std::string_view{"audit-clockguard-min-"}};
    {
        AuditStore warm(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
        REQUIRE(warm.is_open());
    }
    seed_rows_with_ttl(tmp.path, kNow - 100, 5);      // an ordinary expired backlog
    seed_rows_with_ttl(tmp.path, kNow + kWindow, 1);  // and a survivor
    exec_raw(tmp.path, "INSERT INTO audit_retention_meta (key, value) VALUES "
                       "('last_pass_now', -9223372036854775808) "
                       "ON CONFLICT(key) DO UPDATE SET value = excluded.value");

    AuditStore store(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
    REQUIRE(store.is_open());
    CHECK(store.cleanup_once(kNow) == 0); // declines; no subtraction is performed
    CHECK(store.clock_anomaly_skips_count() == 1);
}

TEST_CASE("AuditStore #2360: the latch is HELD through a capped drain, then released",
          "[audit_store][retention][clock-guard]") {
    // Gate 8 coverage gap: every prior over-cap test used a survivor, so
    // `would_wipe` was false and the latch was trivially clear. This is the
    // transition the latch rewrite governs -- an all-expired backlog larger than
    // one pass can delete.
    constexpr std::size_t kSurplus = 4;
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, static_cast<int>(kMaxAuditDeletesPerPass + kSurplus));

    REQUIRE(f.store.cleanup_once(kNow) == 0); // decline #1
    REQUIRE(f.store.clock_anomaly_skips_count() == 1);

    // Accepted, capped: a backlog remains, so the latch must STAY armed --
    // otherwise the next pass declines a second time for the same anomaly.
    CHECK(f.store.cleanup_once(kNow + 1) == kMaxAuditDeletesPerPass);
    CHECK(f.store.cap_reached_count() == 1);
    CHECK(f.store.clock_anomaly_skips_count() == 1);

    // Final pass clears it; the latch releases in that same pass.
    CHECK(f.store.cleanup_once(kNow + 2) == kSurplus);
    CHECK(f.store.total_count() == 0);
    CHECK(f.store.clock_anomaly_skips_count() == 1);

    // Proof the latch actually released: a fresh anomaly declines again.
    f.seed(kNow - 100, 3);
    CHECK(f.store.cleanup_once(kNow + 3) == 0);
    CHECK(f.store.clock_anomaly_skips_count() == 2);
}

TEST_CASE("AuditStore #2360: the latch does NOT survive a restart",
          "[audit_store][retention][clock-guard]") {
    // Gate 8 coverage gap. The clock reading is persisted; the latch deliberately
    // is not, so a restart re-declines. Nothing pinned that, so persisting the
    // latch by mistake would have left the suite green.
    yuzu::test::TempDbFile tmp{std::string_view{"audit-clockguard-latchrestart-"}};
    {
        AuditStore first(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
        REQUIRE(first.is_open());
        seed_rows_with_ttl(tmp.path, kNow - 100, 10);
        REQUIRE(first.cleanup_once(kNow) == 0); // decline, latch armed
        REQUIRE(first.clock_anomaly_skips_count() == 1);
    }

    AuditStore second(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
    REQUIRE(second.is_open());
    CHECK(second.cleanup_once(kNow + 1) == 0); // declines again, does not delete
    CHECK(second.total_count() == 10);
    CHECK(second.clock_anomaly_skips_count() == 1);
}

TEST_CASE("AuditStore #2360: a month-long jump fires on a DEFAULT-retention server",
          "[audit_store][retention][clock-guard]") {
    // Gate 6 / PR-body audit. The threshold used to be max(window, floor), on the
    // theory that "more than a retention window elapsed" proxied a clock jump. At
    // the 365-day default that made it a YEAR, so the check never fired on a stock
    // server -- and the outcome test is separately defeated by any row written
    // after the jump, so BOTH detectors were inert for anything short of a
    // year-long gap. A 30-day jump silently deleted a month of extra evidence.
    //
    // Deliberately uses a LONG retention: the pre-existing step tests all use a
    // 1-day fixture where the floor dominated, which is why none of them caught
    // this.
    constexpr int kLongRetentionDays = 365;
    constexpr std::int64_t kLongWindow = static_cast<std::int64_t>(kLongRetentionDays) * 86400;
    yuzu::test::TempDbFile tmp{std::string_view{"audit-clockguard-default-"}};
    {
        AuditStore warm(tmp.path, kLongRetentionDays, /*cleanup_interval_min=*/0);
        REQUIRE(warm.is_open());
        anchor_pass(warm);
    }
    seed_rows_with_ttl(tmp.path, kNow - 100, 5);        // expired at both readings
    seed_rows_with_ttl(tmp.path, kNow + kLongWindow, 1); // survivor at pass 1

    AuditStore store(tmp.path, kLongRetentionDays, /*cleanup_interval_min=*/0);
    REQUIRE(store.is_open());
    REQUIRE(store.cleanup_once(kNow) == 5);
    REQUIRE(store.clock_anomaly_skips_count() == 0);

    // 30 days later: far short of the 365-day window, far past the 7-day floor.
    const std::int64_t jumped = kNow + 30 * 86400;
    seed_rows_with_ttl(tmp.path, kNow - 50, 5);              // more expired rows
    seed_rows_with_ttl(tmp.path, jumped + kLongWindow, 1);   // survivor at pass 2,
                                                             // so only the STEP can fire
    CHECK(store.cleanup_once(jumped) == 0);
    CHECK(store.clock_anomaly_skips_count() == 1);
    // 1 survivor from pass 1 + the 6 rows seeded before pass 2: nothing was
    // deleted on the declining pass.
    CHECK(store.total_count() == 7);
}

TEST_CASE("AuditStore #2360: a pass that cannot persist its clock reading counts the failure",
          "[audit_store][retention][clock-guard]") {
    // `persist_failed_` is the only evidence that the restart-surviving half of
    // the guard is degrading, and it has a Prometheus alert pointed at it. Drop
    // the meta table out from under a live store to force the write to fail: the
    // pass must still do its job (the reading is a supplement, not a
    // precondition) AND count the failure rather than swallowing it.
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, 5);
    f.seed(kNow + kWindow, 1); // a survivor, so nothing declines on `would_wipe`

    REQUIRE(f.store.persist_failed_count() == 0);
    REQUIRE(f.store.cleanup_once(kNow) == 5); // healthy pass, reading persisted

    exec_raw(f.tmp.path, "DROP TABLE audit_retention_meta");

    f.seed(kNow - 100, 3);
    // The delete still happens: a store that stopped deleting because it could
    // not write a diagnostic row would be a far worse failure than the one being
    // reported.
    CHECK(f.store.cleanup_once(kNow + 1) == 3);
    CHECK(f.store.persist_failed_count() == 1);
    // NOT a failed pass: the pass succeeded, one bookkeeping write did not.
    CHECK(f.store.cleanup_failed_count() == 0);
    CHECK(f.store.clock_anomaly_skips_count() == 0);
}

TEST_CASE("AuditStore #2360: a store whose retention index cannot be built stays fully usable",
          "[audit_store][retention][clock-guard]") {
    // The index is a PERFORMANCE artifact, built best-effort outside the
    // migration runner so a failure degrades retention to full scans rather than
    // taking the audit trail offline. Occupying the index's name with a table
    // makes `CREATE INDEX IF NOT EXISTS` fail for real rather than by injection.
    //
    // There is deliberately NO health gauge for this state (#2526): three
    // implementations of one each shipped a defect. The guarantee tested here is
    // the one that matters -- the store opens, writes, and retains correctly
    // without the index.
    yuzu::test::TempDbFile tmp{std::string_view{"audit-clockguard-noidx-"}};
    exec_raw(tmp.path, "CREATE TABLE idx_audit_ttl_id (x INTEGER)");

    // Assert the PREMISE, not just the consequence. With the gauge gone, the
    // error log is the only evidence the build actually failed -- without this
    // the test passes identically if CREATE INDEX succeeds, and the fixture's
    // whole point (squatting the index name) goes unverified.
    LogCapture log;
    AuditStore store(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
    REQUIRE(store.is_open());
    anchor_pass(store);
    REQUIRE(log.says("could not create idx_audit_ttl_id"));

    seed_rows_with_ttl(tmp.path, kNow - 100, 5);
    seed_rows_with_ttl(tmp.path, kNow + kWindow, 1);
    CHECK(store.cleanup_once(kNow) == 5);
    CHECK(store.cleanup_failed_count() == 0);

    AuditEvent e;
    e.principal = "admin";
    e.principal_role = "admin";
    e.action = "auth.login";
    e.result = "success";
    CHECK(store.log(e));
}

TEST_CASE("AuditStore #2360: a second pass at the same `now` is a clean no-op",
          "[audit_store][retention][clock-guard]") {
    // The contract a caller can rely on: passes are not destructive to repeat.
    // Every other test advances `now` between calls, so nothing pinned this --
    // an accidental re-delete or a double-count would have gone unnoticed.
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, 6);
    f.seed(kNow + kWindow, 1); // survivor, so the first pass accepts

    REQUIRE(f.store.cleanup_once(kNow) == 6);
    const auto passes = f.store.retention_passes_count();
    const auto deleted = f.store.rows_deleted_count();

    CHECK(f.store.cleanup_once(kNow) == 0); // nothing left below the cutoff
    CHECK(f.store.rows_deleted_count() == deleted); // not double-counted
    CHECK(f.store.total_count() == 1);             // the survivor is untouched
    CHECK(f.store.clock_anomaly_skips_count() == 0);
    CHECK(f.store.cleanup_failed_count() == 0);
    // The pass still RAN, which is exactly what the liveness counters must show
    // even when there was nothing to do.
    CHECK(f.store.retention_passes_count() == passes + 1);
    CHECK(f.store.last_pass_unixtime() == kNow);
}

TEST_CASE("AuditStore #2360: liveness counters move on declined and failed passes too",
          "[audit_store][retention][clock-guard]") {
    // The whole point of these two is to distinguish "the reaper ran and had
    // nothing to do" from "the reaper is not running". If they only moved on
    // successful deletes they would be silent in exactly the states the other
    // counters already cover, and still silent in the one they do not.
    GuardFixture f;
    CHECK(f.store.retention_passes_count() == 0);
    CHECK(f.store.last_pass_unixtime() == 0);

    f.seed(kNow - 100, 5); // all expired -> the first pass DECLINES
    REQUIRE(f.store.cleanup_once(kNow) == 0);
    REQUIRE(f.store.clock_anomaly_skips_count() == 1);
    CHECK(f.store.retention_passes_count() == 1);
    CHECK(f.store.last_pass_unixtime() == kNow);

    // A failed pass: break the table so the probes error.
    exec_raw(f.tmp.path, "ALTER TABLE audit_events RENAME TO audit_events_hidden");
    CHECK(f.store.cleanup_once(kNow + 1) == 0);
    CHECK(f.store.cleanup_failed_count() == 1);
    CHECK(f.store.retention_passes_count() == 2);
    CHECK(f.store.last_pass_unixtime() == kNow + 1);
}

TEST_CASE("AuditStore #2360: an implausible caller clock is refused before any arithmetic",
          "[audit_store][retention][clock-guard]") {
    // `cleanup_once` is public, and `now + window + slack` is signed-overflow UB
    // for a `now` near INT64_MAX. Without this case the guard is mutation-inert
    // and UBSan never reaches the overflow. Run under UBSan.
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, 5);
    f.seed(kNow + kWindow, 1);

    CHECK(f.store.cleanup_once(std::numeric_limits<std::int64_t>::max()) == 0);
    CHECK(f.store.total_count() == 6);          // nothing deleted
    CHECK(f.store.cleanup_failed_count() == 1); // counted, not silent
    // Refusing is still a pass that RAN, so liveness must move -- the contract is
    // "attempted", and a refusal that looked like a dead reaper would be worse.
    // Two, not one: `anchor()` above is itself a pass that ran (#2579).
    CHECK(f.store.retention_passes_count() == 2);

    // And a NEGATIVE now is admitted: that is the dead-CMOS-1969 case the whole
    // guard exists for, and it cannot underflow anything.
    CHECK(f.store.cleanup_once(-86'400) == 0);
    CHECK(f.store.cleanup_failed_count() == 1); // unchanged -- not a refusal
    CHECK(f.store.retention_passes_count() == 3);
}

TEST_CASE("AuditStore #2360: each decline names the trigger that actually fired",
          "[audit_store][retention][clock-guard]") {
    // The counters cannot distinguish these four; the warning text is the only
    // carrier, and it is a SOC 2-relevant line. Attributing an elapsed-time step
    // to a pass that declined purely on the outcome test would tell an operator
    // their clock moved when it did not.
    SECTION("first pass, no stored reading: says so, and claims nothing about the clock") {
        GuardFixture f;
        f.seed(kNow - 100, 5); // everything expired, no previous pass
        LogCapture log;
        REQUIRE(f.store.cleanup_once(kNow) == 0);
        CHECK(log.says("first retention pass against this database"));
        CHECK(log.says("nothing can be said about the clock yet"));
        CHECK_FALSE(log.says("elapsed since the last retention pass"));
    }

    SECTION("would-wipe with a sane recent reading: no elapsed-time claim") {
        GuardFixture f;
        f.anchor();
        f.seed(kNow - 100, 5);
        f.seed(kNow + kWindow, 1);
        REQUIRE(f.store.cleanup_once(kNow) == 5); // establishes a reading, drains
        exec_raw(f.tmp.path, "DELETE FROM audit_events"); // remove the survivor
        f.seed(kNow - 100, 5);                            // all-expired again
        LogCapture log;
        REQUIRE(f.store.cleanup_once(kNow + 60) == 0);
        CHECK(log.says("would expire EVERY datable audit row"));
        CHECK(log.says("No unusual gap since the last pass"));
        CHECK_FALSE(log.says("elapsed since the last retention pass"));
    }

    SECTION("a real step: reports the gap and names BOTH possible causes") {
        GuardFixture f;
        f.anchor();
        f.seed(kNow - 100, 5);
        f.seed(kNow + kWindow, 1);
        REQUIRE(f.store.cleanup_once(kNow) == 5);
        const std::int64_t jumped = kNow + 8 * 86'400; // over the 7-day threshold
        seed_rows_with_ttl(f.tmp.path, kNow + 10, 5);
        seed_rows_with_ttl(f.tmp.path, jumped + 3'600, 1); // survivor: not a wipe
        LogCapture log;
        REQUIRE(f.store.cleanup_once(jumped) == 0);
        CHECK(log.says("elapsed since the last retention pass"));
        // Elapsed time cannot separate these, and the line must not pretend it can.
        CHECK(log.says("forward clock jump OR an outage"));
        // Not a wipe, so it must NOT claim every row would have gone.
        CHECK(log.says("an unexpectedly large slice"));
        CHECK_FALSE(log.says("EVERY datable audit row"));
    }

    SECTION("a poisoned stored reading is reported as corrupted state, not as a step") {
        GuardFixture f;
        f.anchor();
        f.seed(kNow - 100, 5);
        f.seed(kNow + kWindow, 1);
        REQUIRE(f.store.cleanup_once(kNow) == 5);
        // A reading AHEAD of now cannot be compared against (an ordinary backward NTP correction produces one).
        exec_raw(f.tmp.path, "UPDATE audit_retention_meta SET value = 9000000000 "
                             "WHERE key = 'last_pass_now'");
        f.seed(kNow - 50, 5);
        AuditStore reopened(f.tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
        REQUIRE(reopened.is_open());
        LogCapture log;
        REQUIRE(reopened.cleanup_once(kNow + 120) == 0);
        CHECK(log.says("not usable"));
        CHECK(log.says("ahead of the current clock")); // the shape THIS case exercises
        CHECK(log.says("declining once and re-anchoring"));
        // Distinguish DeclineImplausible from CorruptStateReported TEXTUALLY.
        // `says("re-anchoring")` alone separated them only because "re-anchoring"
        // is not a substring of "re-anchored" -- a suffix accident, not an
        // assertion. This keys on the other message's unique tail instead.
        CHECK_FALSE(log.says("there was nothing expired to delete"));
        CHECK_FALSE(log.says("elapsed since the last retention pass"));
    }
}

TEST_CASE("AuditStore #2360: a capped pass only claims a remainder when one exists",
          "[audit_store][retention][clock-guard]") {
    // The log line and the cap counter both read one post-delete fact. This is
    // the assertion the earlier round could not make: reverting `emit_capped` to
    // `deleted >= cap` made an exact-cap clean drain announce a remainder that
    // was not there, and nothing caught it.
    // The discriminating fixture is an EXACT-cap drain that leaves NOTHING behind:
    // `deleted == cap` while `backlog_remains == false`. A fixture with a surplus
    // cannot tell the two implementations apart -- pass 1 is capped either way and
    // pass 2 is under the cap either way, so both agree and the test is toothless.
    // Seed exactly one cap's worth.
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, static_cast<int>(kMaxAuditDeletesPerPass));
    f.seed(kNow + kWindow, 1); // survivor, so the pass accepts rather than declines

    LogCapture log;
    REQUIRE(f.store.cleanup_once(kNow) == kMaxAuditDeletesPerPass);
    CHECK_FALSE(log.says("per-pass cap reached")); // nothing was left behind
    CHECK(log.says("expired 25000 rows"));
    CHECK(f.store.cap_reached_count() == 0);
    CHECK(f.store.total_count() == 1); // only the survivor

    // And the genuinely-capped case still announces the remainder.
    log.clear();
    f.seed(kNow - 100, static_cast<int>(kMaxAuditDeletesPerPass) + 40);
    REQUIRE(f.store.cleanup_once(kNow + 1) == kMaxAuditDeletesPerPass);
    CHECK(log.says("per-pass cap reached"));
    CHECK(f.store.cap_reached_count() == 1);
}

TEST_CASE("AuditStore #2360: a non-integer stored reading is rejected, not coerced",
          "[audit_store][retention][clock-guard]") {
    // `audit_retention_meta` is not a STRICT table, so `value INTEGER NOT NULL` is
    // an affinity PREFERENCE: SQLite accepts a TEXT value into it, and
    // `sqlite3_column_int64` then coerces `'not-a-number'` to 0 -- which is a
    // LEGITIMATE reading (a dead CMOS at the Unix epoch). Without an explicit
    // type check the "unparseable durable state is an anomaly" property the guard
    // advertises simply does not exist, and corrupted state is indistinguishable
    // from a real reading.
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, 5);
    f.seed(kNow + kWindow, 1); // survivor, so nothing declines on would_wipe
    REQUIRE(f.store.cleanup_once(kNow) == 5); // establishes a real reading

    exec_raw(f.tmp.path, "UPDATE audit_retention_meta SET value = 'not-a-number' "
                         "WHERE key = 'last_pass_now'");
    // The row really is TEXT, i.e. the fixture reproduces the hazard rather than
    // being silently normalised by SQLite on the way in.
    {
        RawConn c{f.tmp.path};
        SqliteStmt st;
        REQUIRE(sqlite3_prepare_v2(c.db(),
                                   "SELECT typeof(value) FROM audit_retention_meta "
                                   "WHERE key='last_pass_now'",
                                   -1, st.addr(), nullptr) == SQLITE_OK);
        REQUIRE(sqlite3_step(st.get()) == SQLITE_ROW);
        CHECK(std::string{reinterpret_cast<const char*>(sqlite3_column_text(st.get(), 0))} ==
              "text");
    }

    f.seed(kNow - 50, 5);
    AuditStore reopened(f.tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
    REQUIRE(reopened.is_open());

    // ATTRIBUTION is the discriminator, not the decline. Coercing the TEXT to 0
    // ALSO produces a decline -- `now - 0` is decades, so the elapsed-time check
    // fires -- which is why asserting only "declined once" passes against the
    // broken implementation. The pass must say the STATE was bad, not that the
    // CLOCK stepped.
    LogCapture log;
    CHECK(reopened.cleanup_once(kNow + 120) == 0);
    CHECK(reopened.clock_anomaly_skips_count() == 1);
    // Assert the SHAPE is named, not just the generic phrase. A bare
    // `says("not usable")` passed for a whole round while the message's cause
    // list still said only "negative, or ahead of the current clock" -- an
    // operator paged for a corrupted row would not have recognised their case.
    CHECK(log.says("not usable"));
    CHECK(log.says("not an integer"));
    CHECK_FALSE(log.says("elapsed since the last retention pass"));
    // And it self-heals: the pass re-anchored a real integer over the bad value.
    {
        RawConn c{f.tmp.path};
        SqliteStmt st;
        REQUIRE(sqlite3_prepare_v2(c.db(),
                                   "SELECT typeof(value) FROM audit_retention_meta "
                                   "WHERE key='last_pass_now'",
                                   -1, st.addr(), nullptr) == SQLITE_OK);
        REQUIRE(sqlite3_step(st.get()) == SQLITE_ROW);
        CHECK(std::string{reinterpret_cast<const char*>(sqlite3_column_text(st.get(), 0))} ==
              "integer");
    }
}

TEST_CASE("AuditStore #2360: durable state that cannot be READ is an anomaly, not a clean slate",
          "[audit_store][retention][clock-guard]") {
    // The third MetaReadError arm. A read failure -- corruption, SQLITE_BUSY, an
    // I/O error, or (as induced here) the table being gone -- must NOT present as
    // the fresh-install shape: doing so silently disarms the persisted step check
    // for the whole process lifetime, on exactly the boot where it matters. Only
    // ABSENT is benign.
    yuzu::test::TempDbFile tmp{std::string_view{"audit-clockguard-unread-"}};
    {
        AuditStore seed(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
        REQUIRE(seed.is_open());
        anchor_pass(seed);
        seed_rows_with_ttl(tmp.path, kNow - 100, 5);
        seed_rows_with_ttl(tmp.path, kNow + kWindow, 1);
        REQUIRE(seed.cleanup_once(kNow) == 5); // establishes a real durable reading
    }
    // Make the read FAIL rather than come back empty.
    exec_raw(tmp.path, "DROP TABLE audit_retention_meta");

    seed_rows_with_ttl(tmp.path, kNow - 50, 5);
    AuditStore store(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
    REQUIRE(store.is_open());

    LogCapture log;
    CHECK(store.cleanup_once(kNow + 120) == 0);   // declined, not treated as fresh
    CHECK(store.clock_anomaly_skips_count() == 1);
    CHECK(log.says("not usable"));
    CHECK(log.says("unreadable")); // the shape THIS case exercises, named explicitly
    CHECK_FALSE(log.says("elapsed since the last retention pass"));

    // The flag is consumed, not sticky. The next pass DRAINS -- decline once,
    // then delete, which is the whole point of the latch -- so the assertion is
    // that it does not REPORT again, not that it does nothing.
    log.clear();
    CHECK(store.cleanup_once(kNow + 240) == 5); // the backlog ages out normally
    CHECK(store.clock_anomaly_skips_count() == 1);
    CHECK_FALSE(log.says("not usable"));
}

TEST_CASE("AuditStore #2360: corrupt durable state is reported on a retention-DISABLED store",
          "[audit_store][retention][clock-guard]") {
    // The branch that exists BECAUSE of this case, previously untested. With
    // `retention_days <= 0` nothing is ever a deletion candidate, so
    // `has_expired` is false forever and the nothing-expired branch is the ONLY
    // one that ever runs. If the corruption is not reported there it is never
    // reported at all -- which is exactly the hole the earlier "clear only where
    // consumed" fix left open.
    yuzu::test::TempDbFile tmp{std::string_view{"audit-clockguard-corruptoff-"}};
    {
        AuditStore seed(tmp.path, /*retention_days=*/0, /*cleanup_interval_min=*/0);
        REQUIRE(seed.is_open());
    }
    exec_raw(tmp.path, "INSERT INTO audit_retention_meta (key, value) VALUES "
                       "('last_pass_now', 'not-a-number')");

    AuditStore store(tmp.path, /*retention_days=*/0, /*cleanup_interval_min=*/0);
    REQUIRE(store.is_open());

    LogCapture log;
    CHECK(store.cleanup_once(kNow) == 0);
    CHECK(store.clock_anomaly_skips_count() == 1); // REPORTED, not swallowed
    CHECK(store.cleanup_failed_count() == 0);      // not a failed pass
    CHECK(log.says("re-anchored"));
    // It must not claim a backlog was held back: nothing was pending here.
    CHECK_FALSE(log.says("declining once and re-anchoring"));

    // Second pass on the same store: consumed, so silent and not double-counted.
    log.clear();
    CHECK(store.cleanup_once(kNow + 1) == 0);
    CHECK(store.clock_anomaly_skips_count() == 1);
    CHECK_FALSE(log.says("re-anchored"));
}

TEST_CASE("AuditStore #2360: an out-of-range durable VALUE is reported even with no backlog",
          "[audit_store][retention][clock-guard]") {
    // The sibling carrier. `prev_implausible` derived from a value that PARSED
    // but is out of range (here: ahead of `now`) was silently dropped on the
    // nothing-expired branch -- the row is re-anchored before the probes, so the
    // anomaly vanished with no counter and no warn. A backward NTP correction on
    // a store with no expired backlog went unreported.
    GuardFixture f;
    f.anchor();
    f.seed(kNow + kWindow, 1); // a survivor only -- nothing is expired
    REQUIRE(f.store.cleanup_once(kNow) == 0);
    REQUIRE(f.store.clock_anomaly_skips_count() == 0); // healthy baseline

    exec_raw(f.tmp.path, "UPDATE audit_retention_meta SET value = 9000000000 "
                         "WHERE key = 'last_pass_now'");
    AuditStore reopened(f.tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
    REQUIRE(reopened.is_open());

    LogCapture log;
    CHECK(reopened.cleanup_once(kNow + 60) == 0);
    CHECK(reopened.clock_anomaly_skips_count() == 1); // reported, not dropped
    CHECK(log.says("re-anchored"));

    // Quiet on the second pass -- but assert the MECHANISM, not just the
    // outcome. This previously passed because the durable row had been
    // re-anchored to a good value, so there was no anomaly left to report at
    // all; deleting the suppression rule entirely left it green. Re-poison the
    // row so the condition is genuinely still live, and THEN require silence.
    exec_raw(f.tmp.path, "UPDATE audit_retention_meta SET value = 9000000000 "
                         "WHERE key = 'last_pass_now'");
    log.clear();
    CHECK(reopened.cleanup_once(kNow + 120) == 0);
    CHECK(reopened.clock_anomaly_skips_count() == 1); // same condition, not re-reported
    CHECK_FALSE(log.says("re-anchored"));
}


TEST_CASE("AuditStore #2360: a PERSISTENTLY implausible reading reports once, not every pass",
          "[audit_store][retention][clock-guard]") {
    // The unbounded-emission case. A retention-disabled store on a pre-epoch
    // clock re-anchors a NEGATIVE reading every pass, so `prev_unusable` is
    // true forever and the nothing-expired branch is the only one ever taken.
    // An earlier version cleared the latch unconditionally at the top of that
    // branch, which made its own `!last_reported_` guard dead code: the
    // counter moved and a warn was emitted on EVERY pass, indefinitely, and the
    // clock-anomaly alert would have latched on permanently.
    //
    // The contract is report-once-and-latch, with the latch RELEASED when the
    // condition clears -- not suppressed forever, and not repeated forever.
    yuzu::test::TempDbFile tmp{std::string_view{"audit-clockguard-persist-"}};
    {
        AuditStore seed(tmp.path, /*retention_days=*/0, /*cleanup_interval_min=*/0);
        REQUIRE(seed.is_open());
    }
    // A negative stored reading: exactly what a pre-epoch pass persists.
    exec_raw(tmp.path, "INSERT INTO audit_retention_meta (key, value) VALUES "
                       "('last_pass_now', -86400)");

    AuditStore store(tmp.path, /*retention_days=*/0, /*cleanup_interval_min=*/0);
    REQUIRE(store.is_open());

    LogCapture log;
    // Six consecutive passes, each re-anchoring another negative reading.
    for (int i = 0; i < 6; ++i)
        CHECK(store.cleanup_once(-86'400 + i) == 0);

    // Reported ONCE across all six, not once per pass.
    CHECK(store.clock_anomaly_skips_count() == 1);
    CHECK(store.retention_passes_count() == 6); // the reaper did run every time
    CHECK(store.cleanup_failed_count() == 0);

    // The clock RECOVERS, and that recovery is itself an EVENT: the reading
    // moves ~54 years in one pass. It must be reported.
    //
    // This assertion used to demand silence here, which encoded the defect. The
    // same shape with expired rows present is the dead-CMOS-then-NTP sequence
    // that deleted an entire audit trail in one pass with no warning and no
    // counter: `prev` is still negative, so the pass classifies `BadState`
    // exactly as the previous six did, matches, and is suppressed. A guard whose
    // whole job is to notice the clock moving cannot stay quiet through the
    // largest movement it will ever see.
    CHECK(store.cleanup_once(kNow) == 0); // plausible now; nothing expired
    CHECK(store.clock_anomaly_skips_count() == 2);

    // But it must not SPAM. The reading is re-anchored every pass, so once the
    // clock is sane the next pass sees an interval-sized delta, is not an event,
    // and stands down. Without that, reporting a movement would starve the drain
    // forever -- which is exactly how the no-magnitude-floor version failed.
    CHECK(store.cleanup_once(kNow + 1) == 0);
    CHECK(store.clock_anomaly_skips_count() == 2);
    log.clear();
    exec_raw(tmp.path, "UPDATE audit_retention_meta SET value = -1 WHERE key = 'last_pass_now'");
    AuditStore reopened(tmp.path, /*retention_days=*/0, /*cleanup_interval_min=*/0);
    REQUIRE(reopened.is_open());
    CHECK(reopened.cleanup_once(kNow + 1) == 0);
    CHECK(reopened.clock_anomaly_skips_count() == 1); // a fresh store reports its own
}

TEST_CASE("AuditStore #2360: a DIFFERENT anomaly arriving while latched is still reported",
          "[audit_store][retention][clock-guard]") {
    // Written BEFORE the state-model rethink, and expected to FAIL against the
    // single-bool latch.
    //
    // The latch exists so one PERSISTENT condition reports once instead of every
    // pass. It should not suppress a DIFFERENT condition. With a single bool
    // there is no way to tell "still the same anomaly" from "a new one", so a
    // pass latched on a would-wipe silently swallows a subsequent clock step --
    // the operator sees one warn for the first cause and nothing at all for the
    // second, in a SOC 2 signal whose whole job is to say what happened.
    GuardFixture f;
    f.anchor();

    // 1. All rows expired, no survivor -> would-wipe. Declines and latches.
    f.seed(kNow - 100, 5);
    REQUIRE(f.store.cleanup_once(kNow) == 0);
    REQUIRE(f.store.clock_anomaly_skips_count() == 1);

    // 2. A survivor appears, so would-wipe is genuinely gone -- and the clock
    //    jumps well past the 7-day threshold. A different anomaly.
    //
    //    The survivor must sit inside the datable horizon OF THE PASS THAT READS
    //    IT (`now + window + slack`). An earlier version of this test put it 40
    //    days out, where it was excluded as forward-skewed: `would_wipe` never
    //    cleared, and the Wipe -> Step transition was carried entirely by
    //    `classify`'s precedence rather than by the mechanism the comment
    //    described. The test passed for a reason its own comment denied.
    const std::int64_t jumped = kNow + 30 * 86'400;
    f.seed(jumped + kWindow, 1); // in range for the jumped pass
    CHECK(f.store.cleanup_once(jumped) == 0);          // the step declines too
    CHECK(f.store.clock_anomaly_skips_count() == 2);   // and is REPORTED
}

TEST_CASE("AuditStore #2360: a quiet pass re-arms even when nothing was deleted",
          "[audit_store][retention][clock-guard]") {
    // Isolates the stand-down-when-quiet half of the rule from the
    // stand-down-after-a-drain half. In most sequences the drain re-arms, so
    // removing the quiet-pass re-arm is invisible; it only matters when the
    // backlog goes away WITHOUT this store deleting it -- an operator pruning
    // rows by hand, a restore, another process -- and the SAME anomaly kind then
    // recurs. Without the re-arm the recurrence equals `last_reported_` and is
    // silently swallowed.
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, 5); // all expired, no survivor -> would-wipe

    REQUIRE(f.store.cleanup_once(kNow) == 0);
    REQUIRE(f.store.clock_anomaly_skips_count() == 1);

    // The backlog vanishes without this store touching it, so the accepting
    // path -- and its stand-down -- never runs.
    exec_raw(f.tmp.path, "DELETE FROM audit_events");
    REQUIRE(f.store.cleanup_once(kNow + 1) == 0); // nothing expired: quiet pass
    CHECK(f.store.clock_anomaly_skips_count() == 1);

    // The same anomaly KIND recurs. It must be reported again.
    f.seed(kNow - 100, 4);
    CHECK(f.store.cleanup_once(kNow + 2) == 0);
    CHECK(f.store.total_count() == 4); // declined, not deleted
    CHECK(f.store.clock_anomaly_skips_count() == 2);
}

TEST_CASE("AuditStore #2360: a SECOND clock step is a second event, not a continuing condition",
          "[audit_store][retention][clock-guard]") {
    // Written before the fix, expected to FAIL.
    //
    // `Wipe` and `BadState` are CONDITIONS: they persist until something changes,
    // so suppressing a repeat is right. `Step` is an EVENT -- it is recomputed
    // each pass against a reading that was just re-anchored, so a step can only
    // fire when a genuinely NEW jump happened since the previous pass. Two
    // consecutive steps mean two real jumps, and suppressing the second by
    // equality with the first reports one and silently deletes for the other.
    //
    // Step cannot spam by construction: after any pass the stored reading is
    // `now`, so the next pass sees an interval-sized delta unless the clock
    // moved again.
    // A survivor must be inside the datable horizon (`now + window + slack`) for
    // the pass that reads it, or it is excluded as forward-skewed and `Wipe`
    // fires instead of `Step` -- so each pass gets its own.
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, 5);
    f.seed(kNow + kWindow, 1);
    REQUIRE(f.store.cleanup_once(kNow) == 5); // healthy baseline, establishes a reading

    // First jump, well past the 7-day threshold.
    const std::int64_t j1 = kNow + 30 * 86'400;
    seed_rows_with_ttl(f.tmp.path, j1 - 100, 20);
    seed_rows_with_ttl(f.tmp.path, j1 + kWindow, 1);
    REQUIRE(f.store.cleanup_once(j1) == 0);
    REQUIRE(f.store.clock_anomaly_skips_count() == 1);

    // A SECOND, independent jump on the very next pass. A distinct event.
    const std::int64_t j2 = j1 + 30 * 86'400;
    seed_rows_with_ttl(f.tmp.path, j2 - 100, 20);
    seed_rows_with_ttl(f.tmp.path, j2 + kWindow, 1);
    CHECK(f.store.cleanup_once(j2) == 0);              // must decline again
    CHECK(f.store.clock_anomaly_skips_count() == 2);   // and be reported
}

TEST_CASE("AuditStore #2360: classify pins the anomaly precedence with no database",
          "[audit_store][retention][clock-guard]") {
    // `classify` is static and pure -- four bools in, one enum out -- so the
    // whole precedence contract fits in a table with no fixture, no SQLite and
    // no clock. This would have killed the precedence mutations (M27/M28) in
    // microseconds; the integration tests that caught them each need a seeded
    // database and several passes.
    using A = yuzu::server::audit_retention::Anomaly;
    struct Case {
        bool has_expired, would_wipe, big_step, prev_unusable;
        A expected;
        const char* why;
    };
    const Case cases[] = {
        // prev_unusable wins outright, even with nothing pending to protect.
        {false, false, false, true, A::BadState, "unusable reading beats an empty table"},
        {true, true, true, true, A::BadState, "unusable reading beats step AND wipe"},
        // Nothing expired short-circuits -- even when the other inputs are set,
        // because there is nothing for the guard to hold back.
        {false, true, true, false, A::None, "nothing expired short-circuits step and wipe"},
        // A step outranks a wipe either way: an elapsed-time jump explains a
        // wipe better than the wipe explains itself.
        {true, true, true, false, A::Step, "step beats wipe when both hold"},
        {true, false, true, false, A::Step, "step alone"},
        {true, true, false, false, A::Wipe, "wipe alone"},
        {true, false, false, false, A::None, "expired rows, nothing wrong"},
    };
    for (const auto& c : cases) {
        INFO(c.why);
        CHECK(audit_retention::classify({.has_expired = c.has_expired,
                                         .would_wipe = c.would_wipe,
                                         .big_step = c.big_step,
                                         .prev_unusable = c.prev_unusable}) == c.expected);
    }
}

TEST_CASE("AuditStore #2360: a SECOND backward jump is a second event, not a continuing condition",
          "[audit_store][retention][clock-guard]") {
    // Written before the fix, expected to FAIL. The sibling of the forward-step
    // case, found independently by two reviewers.
    //
    // `BadState` has THREE carriers with different natures, and treating them as
    // one is what leaves this hole:
    //   - the load-time flag  -- one-shot
    //   - `*prev < 0`         -- a CONDITION, persists while the clock is negative
    //   - `*prev > now`       -- an EVENT: the reading is re-anchored every pass,
    //                            so it can only be true if the clock moved BACKWARD
    //                            since the previous pass
    // The third is structurally identical to `big_step`, just the other
    // direction, but `is_event = (a == Step)` excludes it -- so a second
    // independent backward jump is equality-suppressed and DELETES silently.
    //
    // The direction is safe (an earlier cutoff deletes strictly fewer rows), so
    // this is lost signal rather than data loss -- but it is a delete on a pass
    // whose own classifier just said the clock state was unusable.
    GuardFixture f;
    f.anchor();
    f.seed(kNow - 100, 9);
    f.seed(kNow + kWindow, 1);
    REQUIRE(f.store.cleanup_once(kNow) == 9); // healthy: establishes a reading

    // First backward jump: the stored reading is now AHEAD of `now`.
    const std::int64_t b1 = kNow - 10 * 86'400;
    seed_rows_with_ttl(f.tmp.path, b1 - 100, 9);
    seed_rows_with_ttl(f.tmp.path, b1 + kWindow, 1);
    REQUIRE(f.store.cleanup_once(b1) == 0);
    REQUIRE(f.store.clock_anomaly_skips_count() == 1);

    // A SECOND, independent backward jump on the very next pass.
    const std::int64_t b2 = b1 - 10 * 86'400;
    seed_rows_with_ttl(f.tmp.path, b2 - 100, 9);
    seed_rows_with_ttl(f.tmp.path, b2 + kWindow, 1);
    CHECK(f.store.cleanup_once(b2) == 0);            // must decline again
    CHECK(f.store.clock_anomaly_skips_count() == 2); // and be reported
}

TEST_CASE("AuditStore #2360: one CONDITION replacing another is reported",
          "[audit_store][retention][clock-guard]") {
    // Pins the inequality half of the rule, which nothing else does any more.
    // The `DIFFERENT anomaly` test transitions Wipe -> Step, and since `Step` is
    // now unconditionally reported it stays green even if difference-sensitivity
    // is destroyed entirely (replace `a != last_reported_` with
    // `last_reported_ == None`). This transitions between two CONDITIONS, where
    // only the inequality can carry the report.
    GuardFixture f;
    f.anchor();

    // 1. Everything expired, no survivor -> Wipe. Reported.
    f.seed(kNow - 100, 6);
    REQUIRE(f.store.cleanup_once(kNow) == 0);
    REQUIRE(f.store.clock_anomaly_skips_count() == 1);

    // 2. Corrupt the durable reading and reopen, so the NEXT pass classifies as
    //    BadState -- a different condition, with a backlog still pending so the
    //    would-wipe is still true underneath it.
    exec_raw(f.tmp.path, "UPDATE audit_retention_meta SET value = 'not-a-number' "
                         "WHERE key = 'last_pass_now'");
    AuditStore reopened(f.tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0);
    REQUIRE(reopened.is_open());

    LogCapture log;
    CHECK(reopened.cleanup_once(kNow + 1) == 0);
    CHECK(reopened.clock_anomaly_skips_count() == 1); // fresh store, its own count
    CHECK(log.says("not usable"));                    // BadState, not Wipe
    CHECK_FALSE(log.says("EVERY datable audit row"));
}

// ---------------------------------------------------------------------------
// Scoped-governance round: two BLOCKING defects in the events/conditions rule.
// Both written BEFORE the fix and confirmed RED against 4e346794.
// ---------------------------------------------------------------------------

TEST_CASE("AuditStore #2360: an arriving would-wipe is not swallowed by a standing bad state",
          "[audit_store][retention][clock-guard]") {
    // BLOCKING, found by cpp-safety and proven with a 5/5 deterministic probe.
    //
    // `classify` collapses FIVE independent facts onto ONE enum, so the
    // `a != last_reported_` half cannot see a NEW condition arriving underneath
    // an already-reported one. The dead-CMOS-then-NTP sequence -- the guard's own
    // motivating case -- walks straight through it:
    //
    //   pass 1  clock in 1969, nothing expired            -> None
    //   pass 2  still 1969, prev < 0                      -> BadState, REPORTED
    //   ...rows are written while the clock is wrong...
    //   pass 3  NTP corrects. would_wipe is now TRUE, but prev is still
    //           negative, so classify returns BadState AGAIN, which EQUALS
    //           last_reported_ -> suppressed -> the pass DELETES.
    //
    // For any store under the 25,000-row cap that is the entire SOC 2 trail, in
    // one statement, with no warning and no counter. Exactly what #2360 exists
    // to prevent.
    // NOT anchored, deliberately: the sequence below IS the fixture. Pass 1 has
    // no reading and nothing expired, which is the one shape #2579's trigger
    // stays silent on, so it is quiet for the reason the narrative needs. An
    // anchoring pass would make pass 1 a huge BACKWARD move instead and report
    // there, shifting the whole story by one.
    GuardFixture f;

    REQUIRE(f.store.cleanup_once(-100) == 0); // 1969, quiet
    REQUIRE(f.store.cleanup_once(-50) == 0);  // prev < 0 -> BadState reported
    REQUIRE(f.store.clock_anomaly_skips_count() == 1);

    // Rows written under the wrong clock. Every one is expired once the clock is
    // corrected, and there is no survivor -> would_wipe.
    f.seed(86'350, 5);

    const std::int64_t corrected = 1'700'000'000;
    CHECK(f.store.cleanup_once(corrected) == 0);     // must NOT delete
    CHECK(f.store.rows_deleted_count() == 0);
    CHECK(f.store.clock_anomaly_skips_count() == 2); // the wipe must be REPORTED
}

TEST_CASE("AuditStore #2360: a would-wipe arriving after an implausible-reading decline",
          "[audit_store][retention][clock-guard]") {
    // The sibling test above pins the dead-CMOS-then-NTP ordering. This pins the
    // BACKWARD-then-FORWARD ordering: a different route to the same swallowed
    // wipe, and the one that survives a latch-based guard which short-circuits
    // on `!has_expired` (such a guard never latches on an empty store, so it
    // passes the sibling and fails here).
    //
    // MEASURED against the implementation that shipped before this hardening:
    // pass 2 returned 6 deleted with the skip counter still at 1, emitting only
    // the routine "expired N rows" info line -- no decline, no warning, no
    // counter for an anomaly the guard exists to report.
    //
    // Scope it honestly. The table emptied because the fixture holds six rows; a
    // real pass is bounded by the 25,000-row cap, and this guard is
    // decline-once-then-drain by design, so a CORRECT latch deletes the same
    // rows one interval later anyway. What the defect destroys is the guard's
    // value for THAT anomaly: the warning, the counter, and the one interval in
    // which an operator could correct the clock -- after which expiry
    // re-evaluates against the corrected reading and nothing is deleted at all.
    GuardFixture f;
    f.anchor();
    REQUIRE(f.store.cleanup_once(kNow) == 0); // anchor the reading at kNow

    // Pass 1: the clock reads BEFORE the anchor, so the stored reading is ahead
    // of now. Expired rows plus a datable survivor, so the decline is
    // attributable to the unusable reading rather than to a wipe.
    const std::int64_t backward = kNow - 10 * 86400;
    f.seed(backward - 100, 5);
    f.seed(backward + 3600, 1);
    REQUIRE(f.store.cleanup_once(backward) == 0);
    REQUIRE(f.store.clock_anomaly_skips_count() == 1);

    // Pass 2: a forward jump far past the window. Every row is expired and no
    // survivor remains, so a NEW would-wipe arrives underneath the
    // already-reported condition. It must be reported, not swallowed.
    const std::int64_t forward = kNow + 30 * 86400;
    CHECK(f.store.cleanup_once(forward) == 0);
    CHECK(f.store.total_count() == 6); // nothing deleted
    CHECK(f.store.clock_anomaly_skips_count() == 2);
}

TEST_CASE("AuditStore #2360: a sub-threshold backward drift must not halt retention forever",
          "[audit_store][retention][clock-guard]") {
    // BLOCKING, found by unhappy-path. A REGRESSION introduced by 0407082b.
    //
    // `backward_step` fires on ONE SECOND, while its forward twin `big_step`
    // requires SEVEN DAYS. `is_event` is OR'd into the REPORT branch, and the
    // report branch is the NON-DELETING branch. So a clock that regresses a
    // second per pass -- two disagreeing time sources, a hypervisor sync racing
    // NTP -- reports every pass forever and NEVER drains. `audit.db` then grows
    // without bound while every counter looks busy: skips climbing, passes
    // climbing, rows_deleted flat. CapReached cannot fire (nothing is deleted);
    // Stalled cannot fire (passes are running).
    //
    // Before 0407082b this reported once and drained.
    GuardFixture f;
    f.anchor();

    // Establish a previous reading FIRST. Without this the opening pass has no
    // `prev`, so it cannot see a backward step and simply drains the backlog --
    // which is how the first version of this test passed against the defect it
    // was written to expose.
    REQUIRE(f.store.cleanup_once(kNow) == 0);

    f.seed(kNow - 100, 5);      // expired backlog
    f.seed(kNow + kWindow, 1);  // a survivor, so this is NOT a would-wipe

    std::int64_t t = kNow;
    for (int i = 0; i < 20; ++i) {
        t -= 1; // one second backwards, every pass
        f.store.cleanup_once(t);
    }

    // Sub-threshold jitter is a CONDITION, not twenty separate incidents: report
    // it, then get on with draining.
    CHECK(f.store.rows_deleted_count() > 0);
}

TEST_CASE("AuditStore #2360: a condition recurring after a step is reported again",
          "[audit_store][retention][clock-guard]") {
    // Closes the coverage hole cpp-safety found by mutation: changing
    // `last_reported_ = a` to `if (a != Anomaly::Step) last_reported_ = a;`
    // SURVIVED the entire committed suite. The write is not decoration -- it
    // re-arms the equality test, so a condition recurring after a step is
    // reported rather than swallowed.
    //
    // It also refutes the comment that called the Step assignment "provably
    // unobservable". It cannot cause SUPPRESSION, which is what that proof
    // actually showed; it can and does cause a report that would otherwise not
    // happen.
    GuardFixture f;
    f.anchor();

    f.seed(kNow - 100, 5); // all expired, no survivor -> Wipe
    REQUIRE(f.store.cleanup_once(kNow) == 0);
    REQUIRE(f.store.clock_anomaly_skips_count() == 1);

    const std::int64_t jumped = kNow + 30 * 86'400;
    f.seed(jumped + kWindow, 1); // survivor clears would_wipe; the clock steps
    REQUIRE(f.store.cleanup_once(jumped) == 0);
    REQUIRE(f.store.clock_anomaly_skips_count() == 2); // Step reported

    // The survivor expires, so would_wipe returns. Wipe != Step, so it must be
    // reported -- and must not delete.
    const std::int64_t later = jumped + 2 * kWindow;
    CHECK(f.store.cleanup_once(later) == 0);
    CHECK(f.store.rows_deleted_count() == 0);
    CHECK(f.store.clock_anomaly_skips_count() == 3);
}

TEST_CASE("AuditStore #2360: a wipe arriving under a standing bad state is reported even with no "
          "material clock movement",
          "[audit_store][retention][clock-guard]") {
    // Proves the deduplication key must be the FACT SET, not the classified
    // enum. Without this case, reverting to `classify(prev_facts) != a` passes
    // the entire suite -- the enum-collapse defect is otherwise masked by the
    // event path, because the sequence that first exposed it (dead CMOS, then
    // NTP) is a movement large enough to report on its own.
    //
    // Strip the movement away and the collapse is naked. `BadState` is the only
    // anomaly that can persist across two passes while the OTHER facts change:
    // `Wipe` and `None` fully determine all four facts, and `Step` is always an
    // event. So the shape is a clock stuck just below the epoch, stepping
    // forward by less than the 7-day threshold -- a broken RTC near 1970, not a
    // contrivance -- while rows become expired underneath it.
    //
    //   pass 1  now = -2   prev absent          -> None
    //   pass 2  now = -1   prev < 0             -> BadState, reported
    //   ...rows with a small positive TTL are written...
    //   pass 3  now = 100  prev < 0, moved 101s -> BadState AGAIN
    //
    // Pass 3 is not an event (101s is far under the floor) and classifies
    // identically to pass 2, so an enum comparison matches and DELETES. The fact
    // set does not match -- `has_expired` and `would_wipe` both flipped -- so it
    // is reported and nothing is deleted.
    // NOT anchored: pass 1 must have no previous reading for the sequence above
    // to be the one that runs. An anchoring pass leaves a reading AHEAD of a 1969
    // `now`, so pass 1 would report BadState and the whole narrative shifts by
    // one -- and it buys nothing here, since pass 1 has nothing expired and the
    // #2579 trigger is silent on exactly that shape.
    GuardFixture f;

    REQUIRE(f.store.cleanup_once(-2) == 0); // quiet: no previous reading yet
    REQUIRE(f.store.cleanup_once(-1) == 0); // prev < 0 -> BadState, reported
    REQUIRE(f.store.clock_anomaly_skips_count() == 1);

    // Rows that are expired under a small POSITIVE clock, with no survivor.
    f.seed(50, 5);

    CHECK(f.store.cleanup_once(100) == 0); // must decline, not delete
    CHECK(f.store.rows_deleted_count() == 0);
    CHECK(f.store.clock_anomaly_skips_count() == 2);
}
