/**
 * test_audit_store.cpp — Unit tests for AuditStore
 *
 * Covers: logging, querying, filtering, count, multiple principals, and the
 * #2360 retention clock guard.
 */

#include "audit_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <sqlite3.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <string>
#include <thread>
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
void seed_rows_with_ttl(const std::filesystem::path& path, std::int64_t ttl, int count) {
    sqlite3* raw = nullptr;
    REQUIRE(sqlite3_open(path.string().c_str(), &raw) == SQLITE_OK);
    sqlite3_exec(raw, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    REQUIRE(sqlite3_exec(raw, "BEGIN", nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_stmt* stmt = nullptr;
    REQUIRE(sqlite3_prepare_v2(raw,
                               "INSERT INTO audit_events (timestamp, principal, principal_role, "
                               "action, result, ttl_expires_at) VALUES (?,?,?,?,?,?)",
                               -1, &stmt, nullptr) == SQLITE_OK);
    for (int i = 0; i < count; ++i) {
        sqlite3_reset(stmt);
        sqlite3_bind_int64(stmt, 1, ttl);
        sqlite3_bind_text(stmt, 2, "admin", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, "admin", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, "auth.login", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, "success", -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 6, ttl);
        REQUIRE(sqlite3_step(stmt) == SQLITE_DONE);
    }
    sqlite3_finalize(stmt);
    REQUIRE(sqlite3_exec(raw, "COMMIT", nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_close(raw);
}

// Run arbitrary SQL through a second connection (used to remove a survivor row
// or to break the table for the fail-closed test).
void exec_raw(const std::filesystem::path& path, const char* sql) {
    sqlite3* raw = nullptr;
    REQUIRE(sqlite3_open(path.string().c_str(), &raw) == SQLITE_OK);
    sqlite3_exec(raw, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    REQUIRE(sqlite3_exec(raw, sql, nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_close(raw);
}

// Retention window used by every guard test below: 1 day. `cleanup_interval_min
// = 0` keeps start_cleanup() a no-op, so no background thread ever races the
// explicit cleanup_once() calls.
constexpr int kGuardRetentionDays = 1;
constexpr std::int64_t kWindow = static_cast<std::int64_t>(kGuardRetentionDays) * 86400;
// An arbitrary fixed "now", far from both the epoch and the real clock.
constexpr std::int64_t kNow = 1'700'000'000;

struct GuardFixture {
    yuzu::test::TempDbFile tmp{std::string_view{"audit-clockguard-"}};
    AuditStore store;
    GuardFixture() : store(tmp.path, kGuardRetentionDays, /*cleanup_interval_min=*/0) {
        REQUIRE(store.is_open());
    }
    void seed(std::int64_t ttl, int count) { seed_rows_with_ttl(tmp.path, ttl, count); }
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
    f.seed(kNow - 100, 10);       // expired
    f.seed(kNow + kWindow, 1);    // a normal, unexpired row

    CHECK(f.store.cleanup_once(kNow) == 10);
    CHECK(f.store.total_count() == 1);
    CHECK(f.store.clock_anomaly_skips_count() == 0);
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
    const std::int64_t later = kNow + kWindow + 1;

    f.seed(kNow - 100, 5);   // expired at both readings
    f.seed(later + 10, 1);   // a survivor at BOTH readings, so `would_wipe` stays false
    REQUIRE(f.store.cleanup_once(kNow) == 5);
    REQUIRE(f.store.clock_anomaly_skips_count() == 0);

    f.seed(kNow - 50, 5); // more expired rows for the jumped pass to find
    CHECK(f.store.cleanup_once(later) == 0);
    CHECK(f.store.clock_anomaly_skips_count() == 1);
    CHECK(f.store.total_count() == 6); // nothing deleted on the declining pass
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
    // retention_days <= 0 means "never expire", so the retention window is zero
    // and `now - last_pass > window` would be true for ANY forward movement of
    // the clock at all - every single pass would report a clock anomaly. The step
    // check is gated on a positive window for exactly that reason.
    //
    // Such a store can still hold rows carrying a non-zero TTL stamped while
    // retention was switched on; those are what the passes below age out.
    yuzu::test::TempDbFile tmp{std::string_view{"audit-clockguard-off-"}};
    AuditStore store(tmp.path, /*retention_days=*/0, /*cleanup_interval_min=*/0);
    REQUIRE(store.is_open());

    seed_rows_with_ttl(tmp.path, kNow - 100, 5); // expired
    seed_rows_with_ttl(tmp.path, kNow + 3'600, 1); // survivor at this reading
    REQUIRE(store.cleanup_once(kNow) == 5);
    REQUIRE(store.clock_anomaly_skips_count() == 0);

    // Two hours later. With window == 0 an ungated step check fires on this.
    const std::int64_t later = kNow + 7'200;
    seed_rows_with_ttl(tmp.path, kNow - 50, 5);
    seed_rows_with_ttl(tmp.path, later + 3'600, 1); // keeps `would_wipe` false
    CHECK(store.cleanup_once(later) == 6);          // 5 new + the first survivor
    CHECK(store.clock_anomaly_skips_count() == 0);
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
    // of cleanup_once and TSan reports on clock_anomaly_latched_ /
    // last_pass_now_. (Concurrent cleanup callers are why the second claim needs
    // its own coverage -- writers alone cannot exercise the latch, since only a
    // cleanup pass ever touches it.)
    GuardFixture f;
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
    CHECK(f.store.total_count() > 0);
    CHECK(f.store.cleanup_failed_count() == 0);
}
