/**
 * test_audit_store.cpp — Unit tests for AuditStore
 *
 * Covers: logging, querying, filtering, count, multiple principals.
 */

#include "audit_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

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
    CHECK(store.log(event));

    auto results = store.query();
    REQUIRE(results.size() == 1);
    CHECK(results[0].target_type == "setting");
    CHECK(results[0].target_id == "tls_enabled");
    CHECK(results[0].detail == "changed to true");
    CHECK(results[0].user_agent == "Mozilla/5.0");
    CHECK(results[0].session_id == "sess-abc");
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
