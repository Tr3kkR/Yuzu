/**
 * test_approval_manager.cpp — Unit tests for ApprovalManager
 *
 * Covers: submit, approve, reject, self-approval prevention, cancel,
 *         pending_count, needs_approval policy, expire_stale, query.
 */

#include "approval_manager.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <chrono>
#include <string>
#include <vector>

using namespace yuzu::server;

// ── RAII wrapper for sqlite3* ──────────────────────────────────────────────

struct TestDb {
    sqlite3* db = nullptr;
    TestDb() { sqlite3_open(":memory:", &db); }
    ~TestDb() {
        if (db)
            sqlite3_close(db);
    }
};

// ── Helpers ─────────────────────────────────────────────────────────────────

static int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static ApprovalRequest make_request(const std::string& definition_id = "def-001",
                                    const std::string& submitted_by = "operator1",
                                    const std::string& scope = "ostype = 'windows'") {
    ApprovalRequest req;
    req.definition_id = definition_id;
    req.submitted_by = submitted_by;
    req.scope_expression = scope;
    return req;
}

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: create_tables succeeds", "[approval_manager][db]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();
    REQUIRE(true);
}

// ── Submit Request ─────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: submit request", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit(make_request());
    REQUIRE(result.has_value());
    CHECK(!result->empty());
}

TEST_CASE("ApprovalManager: submitted request is pending", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit(make_request());
    REQUIRE(result.has_value());

    auto fetched = mgr.get(*result);
    REQUIRE(fetched.has_value());
    CHECK(fetched->status == "pending");
    CHECK(fetched->submitted_by == "operator1");
    CHECK(fetched->reviewed_by.empty());
}

// ── Approve ────────────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: approve sets status and reviewer", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit(make_request());
    REQUIRE(result.has_value());

    auto approve_result = mgr.approve(*result, "admin_user");
    REQUIRE(approve_result.has_value());

    auto fetched = mgr.get(*result);
    REQUIRE(fetched.has_value());
    CHECK(fetched->status == "approved");
    CHECK(fetched->reviewed_by == "admin_user");
    CHECK(fetched->reviewed_at > 0);
}

TEST_CASE("ApprovalManager: approve triggers callback", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    std::string callback_id;
    mgr.set_dispatch_callback([&](const ApprovalRequest& req) { callback_id = req.id; });

    auto result = mgr.submit(make_request());
    REQUIRE(result.has_value());
    mgr.approve(*result, "admin_user");

    CHECK(callback_id == *result);
}

// ── Reject ─────────────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: reject sets status and reviewer", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit(make_request());
    REQUIRE(result.has_value());

    auto reject_result = mgr.reject(*result, "admin_user", "Too risky");
    REQUIRE(reject_result.has_value());

    auto fetched = mgr.get(*result);
    REQUIRE(fetched.has_value());
    CHECK(fetched->status == "rejected");
    CHECK(fetched->reviewed_by == "admin_user");
    CHECK(fetched->review_comment == "Too risky");
}

// ── Self-Approval Prevention ───────────────────────────────────────────────

TEST_CASE("ApprovalManager: self-approval prevented", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit(make_request("def-1", "operator1"));
    REQUIRE(result.has_value());

    // Same user cannot approve their own request
    auto approve_result = mgr.approve(*result, "operator1");
    CHECK(!approve_result.has_value());

    // Request should still be pending
    auto fetched = mgr.get(*result);
    REQUIRE(fetched.has_value());
    CHECK(fetched->status == "pending");
}

// ── Cannot Approve/Reject Non-Pending ──────────────────────────────────────

TEST_CASE("ApprovalManager: cannot approve already approved", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit(make_request());
    REQUIRE(result.has_value());
    mgr.approve(*result, "admin1");

    auto approve2 = mgr.approve(*result, "admin2");
    CHECK(!approve2.has_value());
}

TEST_CASE("ApprovalManager: cannot reject already approved", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit(make_request());
    REQUIRE(result.has_value());
    mgr.approve(*result, "admin1");

    auto reject_result = mgr.reject(*result, "admin2", "too late");
    CHECK(!reject_result.has_value());
}

TEST_CASE("ApprovalManager: cannot approve already rejected", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit(make_request());
    REQUIRE(result.has_value());
    mgr.reject(*result, "admin1", "denied");

    auto approve_result = mgr.approve(*result, "admin2");
    CHECK(!approve_result.has_value());
}

// ── Cancel ─────────────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: cancel pending request", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit(make_request());
    REQUIRE(result.has_value());

    bool ok = mgr.cancel(*result);
    REQUIRE(ok);

    auto fetched = mgr.get(*result);
    REQUIRE(fetched.has_value());
    CHECK(fetched->status == "cancelled");
}

TEST_CASE("ApprovalManager: cannot cancel already approved", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit(make_request());
    REQUIRE(result.has_value());
    mgr.approve(*result, "admin1");

    bool ok = mgr.cancel(*result);
    CHECK(!ok);
}

// ── Pending Count ──────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: pending_count", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    CHECK(mgr.pending_count() == 0);

    mgr.submit(make_request("def-1"));
    mgr.submit(make_request("def-2"));
    mgr.submit(make_request("def-3"));
    CHECK(mgr.pending_count() == 3);

    // Approve one
    ApprovalQuery q;
    q.status = "pending";
    auto pending = mgr.query(q);
    REQUIRE(!pending.empty());
    mgr.approve(pending[0].id, "admin1");
    CHECK(mgr.pending_count() == 2);
}

// ── needs_approval Policy ──────────────────────────────────────────────────

TEST_CASE("ApprovalManager: questions auto-approved", "[approval_manager][policy]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    bool needs = mgr.needs_approval("question", "user");
    CHECK(!needs);
}

TEST_CASE("ApprovalManager: actions need approval for users", "[approval_manager][policy]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    bool needs = mgr.needs_approval("action", "user");
    CHECK(needs);
}

TEST_CASE("ApprovalManager: admin exempt from approval", "[approval_manager][policy]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    bool needs = mgr.needs_approval("action", "admin");
    CHECK(!needs);
}

// ── Expire Stale ───────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: expire_stale transitions pending to expired", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    ApprovalRequest req = make_request();
    req.expires_at = now_epoch() - 60; // expired 1 minute ago
    auto result = mgr.submit(req);
    REQUIRE(result.has_value());

    mgr.expire_stale(now_epoch());

    auto fetched = mgr.get(*result);
    REQUIRE(fetched.has_value());
    CHECK(fetched->status == "expired");
}

TEST_CASE("ApprovalManager: expire_stale does not affect approved", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    ApprovalRequest req = make_request();
    req.expires_at = now_epoch() - 60;
    auto result = mgr.submit(req);
    REQUIRE(result.has_value());
    mgr.approve(*result, "admin1");

    mgr.expire_stale(now_epoch());

    auto fetched = mgr.get(*result);
    CHECK(fetched->status == "approved");
}

TEST_CASE("ApprovalManager: expire_stale respects expiry time", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    ApprovalRequest req = make_request();
    req.expires_at = now_epoch() + 3600; // expires in 1 hour
    mgr.submit(req);

    mgr.expire_stale(now_epoch());

    // Should still be pending since not expired yet
    CHECK(mgr.pending_count() == 1);
}

// ── Query by Status ────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: query by status — pending", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    mgr.submit(make_request("def-1"));
    mgr.submit(make_request("def-2"));
    auto r3 = mgr.submit(make_request("def-3"));
    REQUIRE(r3.has_value());
    mgr.approve(*r3, "admin1");

    ApprovalQuery q;
    q.status = "pending";
    auto pending = mgr.query(q);
    REQUIRE(pending.size() == 2);
}

TEST_CASE("ApprovalManager: query empty returns empty", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    ApprovalQuery q;
    q.status = "pending";
    auto results = mgr.query(q);
    CHECK(results.empty());
}
