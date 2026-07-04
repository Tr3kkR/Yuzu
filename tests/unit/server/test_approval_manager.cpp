/**
 * test_approval_manager.cpp — Unit tests for ApprovalManager
 *
 * Covers: submit, query by status/submitted_by, pending_count, approve,
 *         reject, self-approval prevention, double-review prevention,
 *         approve nonexistent.
 */

#include "approval_manager.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

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

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: create_tables succeeds", "[approval_manager][db]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();
    REQUIRE(true);
}

// ── Submit ─────────────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: submit creates pending approval", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit("def-001", "operator1", "ostype = 'windows'");
    REQUIRE(result.has_value());
    CHECK(!result->empty());
}

TEST_CASE("ApprovalManager: submitted approval has pending status", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit("def-001", "operator1", "ostype = 'windows'");
    REQUIRE(result.has_value());

    // Verify via query
    ApprovalQuery q;
    q.status = "pending";
    auto pending = mgr.query(q);
    REQUIRE(pending.size() == 1);
    CHECK(pending[0].id == *result);
    CHECK(pending[0].definition_id == "def-001");
    CHECK(pending[0].submitted_by == "operator1");
    CHECK(pending[0].status == "pending");
    CHECK(pending[0].scope_expression == "ostype = 'windows'");
    CHECK(pending[0].reviewed_by.empty());
}

TEST_CASE("ApprovalManager: submit multiple approvals", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    mgr.submit("def-001", "operator1", "scope-1");
    mgr.submit("def-002", "operator2", "scope-2");
    mgr.submit("def-003", "operator1", "scope-3");

    auto all = mgr.query();
    REQUIRE(all.size() == 3);
}

// ── Query by Status ────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: query by status — pending", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    mgr.submit("def-1", "operator1", "scope-1");
    mgr.submit("def-2", "operator1", "scope-2");
    auto r3 = mgr.submit("def-3", "operator1", "scope-3");
    REQUIRE(r3.has_value());
    mgr.approve(*r3, "admin1", "approved");

    ApprovalQuery q;
    q.status = "pending";
    auto pending = mgr.query(q);
    REQUIRE(pending.size() == 2);
}

TEST_CASE("ApprovalManager: query by status — approved", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto r1 = mgr.submit("def-1", "operator1", "scope-1");
    mgr.submit("def-2", "operator1", "scope-2");
    REQUIRE(r1.has_value());
    mgr.approve(*r1, "admin1", "looks good");

    ApprovalQuery q;
    q.status = "approved";
    auto approved = mgr.query(q);
    REQUIRE(approved.size() == 1);
    CHECK(approved[0].definition_id == "def-1");
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

// ── Query by submitted_by ──────────────────────────────────────────────────

TEST_CASE("ApprovalManager: query by submitted_by", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    mgr.submit("def-1", "operator1", "scope-1");
    mgr.submit("def-2", "operator2", "scope-2");
    mgr.submit("def-3", "operator1", "scope-3");

    ApprovalQuery q;
    q.submitted_by = "operator1";
    auto results = mgr.query(q);
    REQUIRE(results.size() == 2);
}

// ── Pending Count ──────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: pending_count starts at zero", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    CHECK(mgr.pending_count() == 0);
}

TEST_CASE("ApprovalManager: pending_count increments and decrements", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    mgr.submit("def-1", "operator1", "scope-1");
    mgr.submit("def-2", "operator1", "scope-2");
    mgr.submit("def-3", "operator1", "scope-3");
    CHECK(mgr.pending_count() == 3);

    // Approve one
    ApprovalQuery q;
    q.status = "pending";
    auto pending = mgr.query(q);
    REQUIRE(!pending.empty());
    mgr.approve(pending[0].id, "admin1", "ok");
    CHECK(mgr.pending_count() == 2);
}

// ── Approve ────────────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: approve sets status, reviewer, timestamp", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit("def-001", "operator1", "scope");
    REQUIRE(result.has_value());

    auto approve_result = mgr.approve(*result, "admin_user", "Approved for deployment");
    REQUIRE(approve_result.has_value());

    ApprovalQuery q;
    q.status = "approved";
    auto approved = mgr.query(q);
    REQUIRE(approved.size() == 1);
    CHECK(approved[0].status == "approved");
    CHECK(approved[0].reviewed_by == "admin_user");
    CHECK(approved[0].reviewed_at > 0);
    CHECK(approved[0].review_comment == "Approved for deployment");
}

TEST_CASE("ApprovalManager: approve with empty comment", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit("def-001", "operator1", "scope");
    REQUIRE(result.has_value());

    auto approve_result = mgr.approve(*result, "admin_user", "");
    REQUIRE(approve_result.has_value());
}

// ── Reject ─────────────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: reject sets status, reviewer, comment", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit("def-001", "operator1", "scope");
    REQUIRE(result.has_value());

    auto reject_result = mgr.reject(*result, "admin_user", "Too risky");
    REQUIRE(reject_result.has_value());

    ApprovalQuery q;
    q.status = "rejected";
    auto rejected = mgr.query(q);
    REQUIRE(rejected.size() == 1);
    CHECK(rejected[0].status == "rejected");
    CHECK(rejected[0].reviewed_by == "admin_user");
    CHECK(rejected[0].review_comment == "Too risky");
    CHECK(rejected[0].reviewed_at > 0);
}

// ── Self-Approval Prevention ───────────────────────────────────────────────

TEST_CASE("ApprovalManager: self-approval prevented", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit("def-1", "operator1", "scope");
    REQUIRE(result.has_value());

    // Same user cannot approve their own request
    auto approve_result = mgr.approve(*result, "operator1", "self-approve");
    CHECK(!approve_result.has_value());

    // Verify request is still pending
    CHECK(mgr.pending_count() == 1);
}

// ── Cannot Approve/Reject Already-Reviewed ─────────────────────────────────

TEST_CASE("ApprovalManager: cannot approve already approved", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit("def-001", "operator1", "scope");
    REQUIRE(result.has_value());
    mgr.approve(*result, "admin1", "ok");

    auto approve2 = mgr.approve(*result, "admin2", "also ok");
    CHECK(!approve2.has_value());
}

TEST_CASE("ApprovalManager: cannot reject already approved", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit("def-001", "operator1", "scope");
    REQUIRE(result.has_value());
    mgr.approve(*result, "admin1", "ok");

    auto reject_result = mgr.reject(*result, "admin2", "too late");
    CHECK(!reject_result.has_value());
}

TEST_CASE("ApprovalManager: cannot approve already rejected", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit("def-001", "operator1", "scope");
    REQUIRE(result.has_value());
    mgr.reject(*result, "admin1", "denied");

    auto approve_result = mgr.approve(*result, "admin2", "wait, let me reconsider");
    CHECK(!approve_result.has_value());
}

TEST_CASE("ApprovalManager: cannot reject already rejected", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit("def-001", "operator1", "scope");
    REQUIRE(result.has_value());
    mgr.reject(*result, "admin1", "denied");

    auto reject2 = mgr.reject(*result, "admin2", "also denied");
    CHECK(!reject2.has_value());
}

// ── Approve/Reject Nonexistent ─────────────────────────────────────────────

TEST_CASE("ApprovalManager: approve nonexistent ID fails", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.approve("nonexistent-id", "admin1", "approving nothing");
    CHECK(!result.has_value());
}

TEST_CASE("ApprovalManager: reject nonexistent ID fails", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.reject("nonexistent-id", "admin1", "rejecting nothing");
    CHECK(!result.has_value());
}

// ── Consumption traceability (PR #1796 H3/N2, SOC-2 CC7.2) ─────────────────

TEST_CASE("ApprovalManager: consume_ticket stamps consumed_by with the recalling principal",
          "[approval_manager][approval]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{\"agent_id\":\"a1\"}");
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "ok").has_value());

    auto consumed = mgr.consume_ticket(*id, "operator1");
    REQUIRE(consumed.has_value());

    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->consumed_at > 0);
    CHECK(row->consumed_by == "operator1"); // who and when agree (same CAS UPDATE)
}

TEST_CASE("ApprovalManager: consume_ticket without a principal fails closed",
          "[approval_manager][approval]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}");
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    // An unattributable consumption would be a CC7.2 evidence hole.
    auto consumed = mgr.consume_ticket(*id, "");
    CHECK(!consumed.has_value());
    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->consumed_at == 0); // ticket untouched — still consumable
}

TEST_CASE("ApprovalManager: consume_ticket replay is rejected and keeps the original consumer",
          "[approval_manager][approval]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto id = mgr.submit("mcp.quarantine_device", "operator1", "{}");
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());
    REQUIRE(mgr.consume_ticket(*id, "operator1").has_value());

    auto replay = mgr.consume_ticket(*id, "operator2");
    CHECK(!replay.has_value());
    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->consumed_by == "operator1"); // the losing recall never overwrites
}

// ── Expiry sweep (PR #1796 N3 + L2) ────────────────────────────────────────
// The sweep runs lazily inside submit(). One shared 7-day window: pending
// tickets age out from submitted_at; approved-but-unconsumed tickets (leaked
// one-time capabilities) age out from reviewed_at. Counts come from stepping
// RETURNING rows, never sqlite3_changes() after step (#1033).

namespace {
/// Backdate a timestamp column directly — the sweep triggers on the NEXT
/// submit(), exactly like production (no test-only sweep entry point).
void backdate(sqlite3* db, const std::string& id, const char* column, int64_t seconds_ago) {
    auto sql = std::string("UPDATE approvals SET ") + column + " = " + column + " - " +
               std::to_string(seconds_ago) + " WHERE id = '" + id + "'";
    REQUIRE(sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
}
constexpr int64_t k8Days = 8 * 24 * 3600;
} // namespace

TEST_CASE("ApprovalManager: stale pending approvals expire on the next submit",
          "[approval_manager][approval]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto stale = mgr.submit("def-old", "operator1", "scope");
    REQUIRE(stale.has_value());
    backdate(tdb.db, *stale, "submitted_at", k8Days);

    REQUIRE(mgr.submit("def-new", "operator1", "scope").has_value()); // triggers the sweep

    auto row = mgr.get(*stale);
    REQUIRE(row.has_value());
    CHECK(row->status == "expired");
}

TEST_CASE("ApprovalManager: approved-but-unconsumed tickets expire 7 days after review",
          "[approval_manager][approval]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto id = mgr.submit("mcp.quarantine_device", "operator1", "{}");
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "ok").has_value());
    backdate(tdb.db, *id, "reviewed_at", k8Days);

    REQUIRE(mgr.submit("def-new", "operator1", "scope").has_value()); // triggers the sweep

    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->status == "expired"); // the leaked capability token is dead

    // An expired ticket is no longer consumable.
    auto consumed = mgr.consume_ticket(*id, "operator1");
    CHECK(!consumed.has_value());
}

TEST_CASE("ApprovalManager: consumed tickets are history, never expired",
          "[approval_manager][approval]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}");
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());
    REQUIRE(mgr.consume_ticket(*id, "operator1").has_value());
    backdate(tdb.db, *id, "reviewed_at", k8Days);

    REQUIRE(mgr.submit("def-new", "operator1", "scope").has_value()); // triggers the sweep

    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->status == "approved");        // untouched — it is evidence, not a capability
    CHECK(row->consumed_by == "operator1");  // trail intact
}
