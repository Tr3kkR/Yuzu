/**
 * test_approval_manager.cpp — Unit tests for ApprovalManager
 *
 * Covers: submit, query by status/submitted_by, pending_count, approve,
 *         reject, self-approval prevention, double-review prevention,
 *         approve nonexistent.
 */

#include "approval_manager.hpp"
#include "migration_runner.hpp"
#include "sqlite_raii.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <chrono>
#include <expected>
#include <future>
#include <stdexcept>
#include <thread>
#include <string>
#include <string_view>
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

    auto result = mgr.submit("def-001", "operator1", "ostype = 'windows'", "", ApprovalOrigin::kUnspecified);
    REQUIRE(result.has_value());
    CHECK(!result->empty());
}

TEST_CASE("ApprovalManager: submitted approval has pending status", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit("def-001", "operator1", "ostype = 'windows'", "", ApprovalOrigin::kUnspecified);
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

    mgr.submit("def-001", "operator1", "scope-1", "", ApprovalOrigin::kUnspecified);
    mgr.submit("def-002", "operator2", "scope-2", "", ApprovalOrigin::kUnspecified);
    mgr.submit("def-003", "operator1", "scope-3", "", ApprovalOrigin::kUnspecified);

    auto all = mgr.query();
    REQUIRE(all.size() == 3);
}

// ── Query by Status ────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: query by status — pending", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    mgr.submit("def-1", "operator1", "scope-1", "", ApprovalOrigin::kUnspecified);
    mgr.submit("def-2", "operator1", "scope-2", "", ApprovalOrigin::kUnspecified);
    auto r3 = mgr.submit("def-3", "operator1", "scope-3", "", ApprovalOrigin::kUnspecified);
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

    auto r1 = mgr.submit("def-1", "operator1", "scope-1", "", ApprovalOrigin::kUnspecified);
    mgr.submit("def-2", "operator1", "scope-2", "", ApprovalOrigin::kUnspecified);
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

    mgr.submit("def-1", "operator1", "scope-1", "", ApprovalOrigin::kUnspecified);
    mgr.submit("def-2", "operator2", "scope-2", "", ApprovalOrigin::kUnspecified);
    mgr.submit("def-3", "operator1", "scope-3", "", ApprovalOrigin::kUnspecified);

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

    mgr.submit("def-1", "operator1", "scope-1", "", ApprovalOrigin::kUnspecified);
    mgr.submit("def-2", "operator1", "scope-2", "", ApprovalOrigin::kUnspecified);
    mgr.submit("def-3", "operator1", "scope-3", "", ApprovalOrigin::kUnspecified);
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

    auto result = mgr.submit("def-001", "operator1", "scope", "", ApprovalOrigin::kUnspecified);
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

    auto result = mgr.submit("def-001", "operator1", "scope", "", ApprovalOrigin::kUnspecified);
    REQUIRE(result.has_value());

    auto approve_result = mgr.approve(*result, "admin_user", "");
    REQUIRE(approve_result.has_value());
}

// ── Reject ─────────────────────────────────────────────────────────────────

TEST_CASE("ApprovalManager: reject sets status, reviewer, comment", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit("def-001", "operator1", "scope", "", ApprovalOrigin::kUnspecified);
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

    auto result = mgr.submit("def-1", "operator1", "scope", "", ApprovalOrigin::kUnspecified);
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

    auto result = mgr.submit("def-001", "operator1", "scope", "", ApprovalOrigin::kUnspecified);
    REQUIRE(result.has_value());
    mgr.approve(*result, "admin1", "ok");

    auto approve2 = mgr.approve(*result, "admin2", "also ok");
    CHECK(!approve2.has_value());
}

TEST_CASE("ApprovalManager: cannot reject already approved", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit("def-001", "operator1", "scope", "", ApprovalOrigin::kUnspecified);
    REQUIRE(result.has_value());
    mgr.approve(*result, "admin1", "ok");

    auto reject_result = mgr.reject(*result, "admin2", "too late");
    CHECK(!reject_result.has_value());
}

TEST_CASE("ApprovalManager: cannot approve already rejected", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit("def-001", "operator1", "scope", "", ApprovalOrigin::kUnspecified);
    REQUIRE(result.has_value());
    mgr.reject(*result, "admin1", "denied");

    auto approve_result = mgr.approve(*result, "admin2", "wait, let me reconsider");
    CHECK(!approve_result.has_value());
}

TEST_CASE("ApprovalManager: cannot reject already rejected", "[approval_manager]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto result = mgr.submit("def-001", "operator1", "scope", "", ApprovalOrigin::kUnspecified);
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

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{\"agent_id\":\"a1\"}", "", ApprovalOrigin::kUnspecified);
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

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kUnspecified);
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

    auto id = mgr.submit("mcp.quarantine_device", "operator1", "{}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());
    REQUIRE(mgr.consume_ticket(*id, "operator1").has_value());

    auto replay = mgr.consume_ticket(*id, "operator2");
    CHECK(!replay.has_value());
    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->consumed_by == "operator1"); // the losing recall never overwrites
}

// ── Mint-surface origin + the redemption guard (#2442) ─────────────────────
// The MCP recall matches a ticket on (definition_id, scope_expression) and
// does not bind the submitter, so a ticket minted elsewhere under an `mcp.`
// definition id is a ticket the MCP gate would otherwise accept. The refusal
// lives at REDEMPTION, keyed on the recorded origin — minting is a legitimate
// act, redeeming on a foreign surface is not. These cases are the tether on
// that: they are what stops the guard being dropped or narrowed unnoticed.

TEST_CASE("ApprovalManager: a ticket minted by a declared non-MCP surface cannot be redeemed",
          "[approval_manager][approval][security]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    // The REST instruction gate: definition id caller-influenced, scope
    // expression caller-supplied verbatim. The mint SUCCEEDS — refusing it here
    // is what stranded pre-existing operator content, and is deliberately gone.
    auto forged = mgr.submit("mcp.quarantine_device", "attacker", "{\"agent_id\":\"a1\"}", "",
                             ApprovalOrigin::kInstruction);
    REQUIRE(forged.has_value());
    REQUIRE(mgr.approve(*forged, "admin1", "").has_value());

    // The redemption is where it dies. This is the MCP recall's call shape.
    auto redeemed = mgr.consume_ticket(*forged, "attacker");
    REQUIRE(!redeemed.has_value());

    // And the ticket is UNTOUCHED — a refused forgery must not burn it.
    auto row = mgr.get(*forged);
    REQUIRE(row.has_value());
    CHECK(row->consumed_at == 0);
    CHECK(row->consumed_by.empty());
    CHECK(row->status == "approved");

    // Same for the scheduler surface.
    auto sched = mgr.submit("mcp.delete_tag", "attacker", "{}", "sched-1",
                            ApprovalOrigin::kSchedule);
    REQUIRE(sched.has_value());
    REQUIRE(mgr.approve(*sched, "admin1", "").has_value());
    CHECK(!mgr.consume_ticket(*sched, "attacker").has_value());
    CHECK(mgr.get(*sched)->consumed_at == 0);
}

TEST_CASE("ApprovalManager: the redemption refusal is a distinct kind but not a distinct message",
          "[approval_manager][approval][security]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto forged = mgr.submit("mcp.quarantine_device", "attacker", "{}", "",
                             ApprovalOrigin::kInstruction);
    REQUIRE(forged.has_value());
    REQUIRE(mgr.approve(*forged, "admin1", "").has_value());

    auto denied = mgr.consume_ticket(*forged, "attacker", {});
    REQUIRE(!denied.has_value());
    // The KIND separates a forgery attempt from a replay, so the log and any
    // future audit row can tell them apart.
    CHECK(denied.error().kind == ConsumeFailure::kForeignOrigin);

    // The MESSAGE deliberately does not. A spent ordinary ticket and a refused
    // forgery must read identically to a remote caller, or the recall becomes an
    // oracle for which definition ids exist and which surface minted them.
    auto spent = mgr.submit("inventory.audit", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(spent.has_value());
    REQUIRE(mgr.approve(*spent, "admin1", "").has_value());
    REQUIRE(mgr.consume_ticket(*spent, "operator1").has_value()); // first use succeeds
    auto replay = mgr.consume_ticket(*spent, "operator1", {});    // second does not
    REQUIRE(!replay.has_value());
    CHECK(replay.error().kind == ConsumeFailure::kNotConsumable);
    CHECK(denied.error().message == replay.error().message);
}

TEST_CASE("ApprovalManager: an MCP-minted ticket under the reserved prefix still redeems",
          "[approval_manager][approval][security]") {
    // The positive control. Without it, a guard that refused EVERYTHING would
    // pass every assertion above.
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto declared = mgr.submit("mcp.quarantine_device", "operator1", "{\"agent_id\":\"a1\"}", "",
                               ApprovalOrigin::kMcp);
    REQUIRE(declared.has_value());
    REQUIRE(mgr.approve(*declared, "admin1", "").has_value());
    CHECK(mgr.consume_ticket(*declared, "operator1").has_value());
    CHECK(mgr.get(*declared)->consumed_at != 0);

    // And the undeclared mint — which is what the frozen MCP gate actually does
    // today — must also still redeem, or the guard breaks the live MCP flow.
    auto undeclared = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(undeclared.has_value());
    REQUIRE(mgr.approve(*undeclared, "admin1", "").has_value());
    CHECK(mgr.consume_ticket(*undeclared, "operator1").has_value());
}

TEST_CASE("ApprovalManager: an ordinary non-MCP ticket is refused at redemption too",
          "[approval_manager][approval][security]") {
    // The guard is keyed on ORIGIN, not on the `mcp.` id prefix — so a REST-
    // minted ticket for an ordinary definition is equally unredeemable through
    // the recall. This is the property that survives the MCP mint changing how
    // it builds its ids, which the prefix rule did not. It costs nothing: no
    // legitimate flow redeems a REST-minted ticket here (the REST gate matches
    // its own approvals by field comparison, it does not call consume_ticket).
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto rest = mgr.submit("inventory.audit", "operator1", "{}", "", ApprovalOrigin::kInstruction);
    REQUIRE(rest.has_value());
    REQUIRE(mgr.approve(*rest, "admin1", "").has_value());
    auto denied = mgr.consume_ticket(*rest, "operator1", {});
    REQUIRE(!denied.has_value());
    CHECK(denied.error().kind == ConsumeFailure::kForeignOrigin);
    CHECK(mgr.get(*rest)->consumed_at == 0);
}

TEST_CASE("ApprovalManager: a declared origin is recorded on the ticket",
          "[approval_manager][approval]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto instr = mgr.submit("inventory.audit", "operator1", "{}", "", ApprovalOrigin::kInstruction);
    REQUIRE(instr.has_value());
    auto sched = mgr.submit("inventory.audit", "operator2", "{}", "sched-1",
                            ApprovalOrigin::kSchedule);
    REQUIRE(sched.has_value());
    auto mcp = mgr.submit("mcp.delete_tag", "operator3", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(mcp.has_value());

    CHECK(mgr.get(*instr)->origin == ApprovalOrigin::kInstruction);
    CHECK(mgr.get(*sched)->origin == ApprovalOrigin::kSchedule);
    CHECK(mgr.get(*mcp)->origin == ApprovalOrigin::kMcp);
    CHECK(mgr.query({.submitted_by = "operator1"}).at(0).origin == ApprovalOrigin::kInstruction);
}

TEST_CASE("ApprovalManager: an undeclared mint records no origin and keeps the mcp. prefix",
          "[approval_manager][approval]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    // The MCP gate still mints without declaring (mcp_server.cpp is frozen for
    // a parallel rebase). It must keep working, and must NOT be recorded as a
    // surface it did not come from.
    //
    // This case is also the TETHER on the exemption, which is the weakest part
    // of the design and is meant to be temporary: an undeclared mint is the
    // one remaining way to reach the reserved namespace, so a future caller
    // that forgot to declare an origin would reach it too. Nothing relies on
    // that today — the MCP gate is the only undeclared caller in the tree.
    // When the MCP mint declares kMcp, the exemption should go and THIS TEST
    // should fail; that failure is the prompt to delete it deliberately, not a
    // regression to paper over.
    auto id = mgr.submit("mcp.delete_tag", "operator1", "{\"agent_id\":\"a1\"}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(id.has_value());
    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->origin == ApprovalOrigin::kUnspecified);
}

TEST_CASE("ApprovalManager: origin round-trips through its column text",
          "[approval_manager][approval]") {
    CHECK(std::string_view(to_string(ApprovalOrigin::kInstruction)) == "instruction");
    CHECK(std::string_view(to_string(ApprovalOrigin::kSchedule)) == "schedule");
    CHECK(std::string_view(to_string(ApprovalOrigin::kMcp)) == "mcp");
    CHECK(std::string_view(to_string(ApprovalOrigin::kUnspecified)).empty());

    CHECK(approval_origin_from_string("instruction") == ApprovalOrigin::kInstruction);
    CHECK(approval_origin_from_string("schedule") == ApprovalOrigin::kSchedule);
    CHECK(approval_origin_from_string("mcp") == ApprovalOrigin::kMcp);
    CHECK(std::string_view(to_string(ApprovalOrigin::kUnrecognised)) == "unrecognised");

    CHECK(approval_origin_from_string("") == ApprovalOrigin::kUnspecified);
    // CHANGED by #2442, deliberately. These two used to decode to kUnspecified
    // on the reasoning that an unknown string "must never be promoted into a
    // surface". That reasoning inverted the moment kUnspecified became the value
    // the redemption guard EXEMPTS: folding unknown into it made the composite
    // parse-then-decide fail OPEN while the predicate itself failed closed.
    // kUnrecognised is refused by declares_non_mcp_surface.
    CHECK(approval_origin_from_string("MCP") == ApprovalOrigin::kUnrecognised); // case-sensitive
    CHECK(approval_origin_from_string("nonsense") == ApprovalOrigin::kUnrecognised);
    CHECK(declares_non_mcp_surface(ApprovalOrigin::kUnrecognised));
    CHECK(!declares_non_mcp_surface(ApprovalOrigin::kUnspecified));
}

TEST_CASE("ApprovalManager: migration v5 leaves pre-existing rows with no declared origin",
          "[approval_manager][db]") {
    TestDb tdb;
    // A v4-shaped store with a row already in it, schema_meta pinned at 4 so
    // create_tables() runs migration 5 alone (the shape test_nvd.cpp uses).
    REQUIRE(sqlite3_exec(tdb.db,
                         "CREATE TABLE schema_meta (store TEXT PRIMARY KEY,"
                         " version INTEGER NOT NULL, upgraded_at INTEGER NOT NULL DEFAULT 0);"
                         "INSERT INTO schema_meta (store, version, upgraded_at)"
                         " VALUES ('approval_manager', 4, 0);"
                         "CREATE TABLE approvals ("
                         "id TEXT PRIMARY KEY, definition_id TEXT NOT NULL,"
                         "status TEXT NOT NULL DEFAULT 'pending',"
                         "submitted_by TEXT NOT NULL DEFAULT '',"
                         "submitted_at INTEGER NOT NULL DEFAULT 0,"
                         "reviewed_by TEXT NOT NULL DEFAULT '',"
                         "reviewed_at INTEGER NOT NULL DEFAULT 0,"
                         "review_comment TEXT NOT NULL DEFAULT '',"
                         "scope_expression TEXT NOT NULL DEFAULT '',"
                         "consumed_at INTEGER NOT NULL DEFAULT 0,"
                         "consumed_by TEXT NOT NULL DEFAULT '',"
                         "schedule_id TEXT NOT NULL DEFAULT '');"
                         "INSERT INTO approvals (id, definition_id, status, submitted_by)"
                         " VALUES ('legacy-1', 'inventory.audit', 'pending', 'operator1');",
                         nullptr, nullptr, nullptr) == SQLITE_OK);

    ApprovalManager mgr(tdb.db);
    mgr.create_tables(); // migrates v1..v5 over the existing table
    REQUIRE(mgr.is_open());

    auto row = mgr.get("legacy-1");
    REQUIRE(row.has_value());
    CHECK(row->definition_id == "inventory.audit");
    // NOT back-filled to 'instruction': the row is evidence, and its surface is
    // genuinely unknown.
    CHECK(row->origin == ApprovalOrigin::kUnspecified);
}

// ── Pre-consume recheck (#2443) ────────────────────────────────────────────
// A ticket can sit approved-but-unconsumed for up to the 7-day TTL, so the
// state its effect assumes may drift. The recheck runs between the match and
// the CAS: a denial must leave the ticket RECALLABLE, because burning a
// human-approved capability on a no-op is the defect being fixed.

TEST_CASE("ApprovalManager: a failing pre-consume recheck denies WITHOUT consuming",
          "[approval_manager][approval]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto id = mgr.submit("mcp.confirm_engine_rotation", "operator1", "{\"token_id\":\"t1\"}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "ok").has_value());

    auto consumed = mgr.consume_ticket(*id, "operator1", [](const Approval&) {
        return std::expected<void, std::string>(
            std::unexpected("rotation t1 already resolved; mint a fresh ticket"));
    });
    REQUIRE(!consumed.has_value());
    CHECK(consumed.error().kind == ConsumeFailure::kPrecondition);
    CHECK(consumed.error().message == "rotation t1 already resolved; mint a fresh ticket");

    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->status == "approved");
    CHECK(row->consumed_at == 0); // the CAS never ran
    CHECK(row->consumed_by.empty());
}

TEST_CASE("ApprovalManager: a ticket denied by the recheck is still consumable afterwards",
          "[approval_manager][approval]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto id = mgr.submit("mcp.confirm_engine_rotation", "operator1", "{}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    bool drifted = true;
    ConsumePrecondition recheck = [&drifted](const Approval&) -> std::expected<void, std::string> {
        if (drifted)
            return std::unexpected("state drifted");
        return {};
    };

    REQUIRE(!mgr.consume_ticket(*id, "operator1", recheck).has_value());
    drifted = false; // operator resolved the drift — the SAME ticket still works
    REQUIRE(mgr.consume_ticket(*id, "operator1", recheck).has_value());

    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->consumed_at > 0);
    CHECK(row->consumed_by == "operator1");
}

TEST_CASE("ApprovalManager: the pre-consume recheck sees the matched ticket's own row",
          "[approval_manager][approval]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{\"agent_id\":\"a1\"}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "ok").has_value());

    Approval seen;
    auto consumed = mgr.consume_ticket(*id, "operator1",
                                       [&seen](const Approval& a) -> std::expected<void, std::string> {
                                           seen = a;
                                           return {};
                                       });
    REQUIRE(consumed.has_value());
    CHECK(seen.id == *id);
    CHECK(seen.definition_id == "mcp.delete_tag");
    CHECK(seen.scope_expression == "{\"agent_id\":\"a1\"}");
    CHECK(seen.submitted_by == "operator1");
    CHECK(seen.status == "approved"); // pre-CAS snapshot, so not yet consumed
    CHECK(seen.consumed_at == 0);
}

TEST_CASE("ApprovalManager: a non-consumable ticket is declined without running the recheck",
          "[approval_manager][approval]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());
    REQUIRE(mgr.consume_ticket(*id, "operator1").has_value());

    bool ran = false;
    auto replay = mgr.consume_ticket(*id, "operator2",
                                     [&ran](const Approval&) -> std::expected<void, std::string> {
                                         ran = true;
                                         return {};
                                     });
    REQUIRE(!replay.has_value());
    CHECK(replay.error().kind == ConsumeFailure::kNotConsumable);
    CHECK(!ran); // the recheck may be costly or emit audit — spent tickets skip it

    // Same for a pending (never-approved) ticket and for an absent id.
    auto pending = mgr.submit("mcp.delete_tag", "operator1", "{\"n\":1}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(pending.has_value());
    ran = false; // reset per sub-case so a regression names WHICH one regressed
    auto on_pending = mgr.consume_ticket(*pending, "operator1",
                                         [&ran](const Approval&) -> std::expected<void, std::string> {
                                             ran = true;
                                             return {};
                                         });
    REQUIRE(!on_pending.has_value());
    CHECK(on_pending.error().kind == ConsumeFailure::kNotConsumable);

    ran = false;
    auto absent = mgr.consume_ticket("does-not-exist", "operator1",
                                     [&ran](const Approval&) -> std::expected<void, std::string> {
                                         ran = true;
                                         return {};
                                     });
    REQUIRE(!absent.has_value());
    CHECK(absent.error().kind == ConsumeFailure::kNotConsumable);
    CHECK(!ran);
}

TEST_CASE("ApprovalManager: an empty precondition consumes exactly like the two-argument overload",
          "[approval_manager][approval]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    REQUIRE(mgr.consume_ticket(*id, "operator1", {}).has_value());
    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->consumed_by == "operator1");
}

TEST_CASE("ApprovalManager: a missing principal fails closed on the recheck overload too",
          "[approval_manager][approval]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    bool ran = false;
    auto consumed = mgr.consume_ticket(*id, "",
                                       [&ran](const Approval&) -> std::expected<void, std::string> {
                                           ran = true;
                                           return {};
                                       });
    REQUIRE(!consumed.has_value());
    CHECK(consumed.error().kind == ConsumeFailure::kStoreError);
    CHECK(!ran); // argument validation precedes any callback
    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->consumed_at == 0);
}

TEST_CASE("ApprovalManager: the CAS still wins when the row is consumed during the recheck",
          "[approval_manager][approval]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    // The window the design deliberately accepts: row read, lock released,
    // callback runs, lock retaken, CAS runs. Force that exact interleaving by
    // consuming the ticket from inside the callback. The outer consume must
    // LOSE — a denial, never a second consume.
    auto outer =
        mgr.consume_ticket(*id, "operator1",
                           [&mgr, &id](const Approval&) -> std::expected<void, std::string> {
                               (void)mgr.consume_ticket(*id, "operator2");
                               return {};
                           });
    REQUIRE(!outer.has_value());
    CHECK(outer.error().kind == ConsumeFailure::kNotConsumable);

    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->consumed_by == "operator2"); // consumed exactly once, by the winner
}

TEST_CASE("ApprovalManager: a throwing recheck denies without consuming and does not escape",
          "[approval_manager][approval]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    // The callback is caller code running on an httplib worker. A throw must
    // not leave a store method as an exception, and must not be reported as a
    // decision the callback never made.
    auto threw = mgr.consume_ticket(
        *id, "operator1", [](const Approval&) -> std::expected<void, std::string> {
            throw std::runtime_error("rotation lookup failed");
        });
    REQUIRE(!threw.has_value());
    CHECK(threw.error().kind == ConsumeFailure::kStoreError); // NOT kPrecondition
    CHECK(threw.error().message.find("pre-consume recheck failed") != std::string::npos);
    // The callback's own text must NOT ride along: this message reaches the MCP
    // envelope, and e.what() is unvetted. Asserting only the inclusion above
    // would still pass if someone appended it again.
    CHECK(threw.error().message.find("rotation lookup failed") == std::string::npos);
    CHECK(mgr.get(*id)->consumed_at == 0); // still recallable

    // A non-std throw takes the same path.
    auto odd = mgr.consume_ticket(
        *id, "operator1",
        [](const Approval&) -> std::expected<void, std::string> { throw 42; });
    REQUIRE(!odd.has_value());
    CHECK(odd.error().kind == ConsumeFailure::kStoreError);
    CHECK(mgr.get(*id)->consumed_at == 0);
}

TEST_CASE("ApprovalManager: a store failure during the recheck is not reported as spent",
          "[approval_manager][approval]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());

    // The defect this whole seam re-introduced once: the pre-consume read used
    // get(), which reports a FAILED read and a missing row identically. Drop
    // the table to force a real read failure and confirm the caller is told the
    // store broke, NOT that its human-approved capability is spent.
    REQUIRE(sqlite3_exec(tdb.db, "DROP TABLE approvals", nullptr, nullptr, nullptr) == SQLITE_OK);

    bool ran = false;
    auto r = mgr.consume_ticket(*id, "operator1",
                                [&ran](const Approval&) -> std::expected<void, std::string> {
                                    ran = true;
                                    return {};
                                });
    REQUIRE(!r.has_value());
    CHECK(r.error().kind == ConsumeFailure::kStoreError); // NOT kNotConsumable
    CHECK(!ran); // no row to hand the callback

    // And the same read through get_checked directly.
    CHECK(!mgr.get_checked(*id).has_value());
}

TEST_CASE("ApprovalManager: a store failure on the TWO-argument path is not reported as spent",
          "[approval_manager][approval]") {
    // #2442 made the row read unconditional, so a read failure became reachable
    // on the two-argument overload for the first time. The case above covers the
    // three-argument path only; this is the same property on the other one.
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());
    REQUIRE(sqlite3_exec(tdb.db, "DROP TABLE approvals", nullptr, nullptr, nullptr) == SQLITE_OK);

    auto flat = mgr.consume_ticket(*id, "operator1");
    REQUIRE(!flat.has_value());
    // The flat overload discards the kind, so the string is all a caller has.
    // The property that matters is the negative: it must NOT read as spent, or
    // an operator is told to discard a live human-approved capability. (A
    // dropped table fails at prepare, not at step, so the text is "prepare
    // failed" rather than get_checked's "read failed" — both are kStoreError.)
    CHECK(flat.error().find("not consumable") == std::string::npos);
    CHECK(flat.error().find("already used") == std::string::npos);
    CHECK(flat.error().find("failed") != std::string::npos);

    // And the kind is right on the overload that exposes it.
    auto typed = mgr.consume_ticket(*id, "operator1", {});
    REQUIRE(!typed.has_value());
    CHECK(typed.error().kind == ConsumeFailure::kStoreError);
}

TEST_CASE("ApprovalManager: an unrecognised origin column value is refused, not exempted",
          "[approval_manager][approval][security]") {
    // The decode used to fold anything unknown into kUnspecified. #2442 made
    // kUnspecified the value that GRANTS redemption, so that fold would have made
    // the composite fail OPEN even though the predicate fails closed.
    CHECK(approval_origin_from_string("") == ApprovalOrigin::kUnspecified);
    CHECK(approval_origin_from_string("mcp") == ApprovalOrigin::kMcp);
    CHECK(approval_origin_from_string("MCP") == ApprovalOrigin::kUnrecognised); // case-sensitive
    CHECK(approval_origin_from_string("nonsense") == ApprovalOrigin::kUnrecognised);
    CHECK(declares_non_mcp_surface(ApprovalOrigin::kUnrecognised));

    // End to end: a row written by a newer binary, read back by this one.
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();
    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kMcp);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());
    REQUIRE(sqlite3_exec(tdb.db, "UPDATE approvals SET origin = 'future_surface'", nullptr, nullptr,
                         nullptr) == SQLITE_OK);

    auto denied = mgr.consume_ticket(*id, "operator1", {});
    REQUIRE(!denied.has_value());
    CHECK(denied.error().kind == ConsumeFailure::kForeignOrigin);
    CHECK(mgr.get(*id)->consumed_at == 0);
}

TEST_CASE("ApprovalManager: a saturated pending queue drains itself instead of wedging",
          "[approval_manager][approval]") {
    // The sweep is the ONLY thing that expires an approval and it runs only
    // inside submit(). With the pending cap checked BEFORE it, a queue at 1000
    // returned early forever: nothing aged out, the count never fell, and every
    // approval surface was permanently denied. This pins the ordering.
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    // Fill to the cap with rows already older than the 7-day window.
    REQUIRE(sqlite3_exec(tdb.db,
                         "INSERT INTO approvals (id, definition_id, status, submitted_by, "
                         "submitted_at, reviewed_by, reviewed_at, review_comment, "
                         "scope_expression, consumed_at, consumed_by, schedule_id, origin) "
                         "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n "
                         "WHERE i < 1000) "
                         "SELECT 'stale-' || i, 'def', 'pending', 'operator1', 1, '', 0, '', "
                         "'{}', 0, '', '', '' FROM n",
                         nullptr, nullptr, nullptr) == SQLITE_OK);
    REQUIRE(mgr.pending_count() == 1000);

    // At the cap, but every row is expirable: the mint must succeed because the
    // sweep runs first. Before the reorder this returned "approval queue is
    // full" and no subsequent call could ever recover it.
    auto minted = mgr.submit("def", "operator1", "{}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(minted.has_value());
    CHECK(mgr.pending_count() == 1); // the 1000 stale rows aged out, ours remains
}

TEST_CASE("ApprovalManager: the cap still refuses when nothing is expirable",
          "[approval_manager][approval]") {
    // The positive control for the case above: moving the sweep first must not
    // disarm the cap for a queue of genuinely fresh pending rows.
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    REQUIRE(sqlite3_exec(tdb.db,
                         "INSERT INTO approvals (id, definition_id, status, submitted_by, "
                         "submitted_at, reviewed_by, reviewed_at, review_comment, "
                         "scope_expression, consumed_at, consumed_by, schedule_id, origin) "
                         "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n "
                         "WHERE i < 1000) "
                         "SELECT 'fresh-' || i, 'def', 'pending', 'operator1', "
                         "strftime('%s','now'), '', 0, '', '{}', 0, '', '', '' FROM n",
                         nullptr, nullptr, nullptr) == SQLITE_OK);

    auto refused = mgr.submit("def", "operator1", "{}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(!refused.has_value());
    CHECK(refused.error().find("queue is full") != std::string::npos);
}

TEST_CASE("ApprovalManager: find_pending skips a ticket the recall would refuse",
          "[approval_manager][approval][security]") {
    // The MCP mint's dedup must not hand back a foreign-origin ticket, or an
    // admin spends an approval on something that can never redeem.
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto rest = mgr.submit("mcp.quarantine_device", "operator1", "{\"agent_id\":\"a1\"}", "",
                           ApprovalOrigin::kInstruction);
    REQUIRE(rest.has_value());
    // Same (definition_id, submitted_by, scope) tuple the MCP mint would look up.
    CHECK(!mgr.find_pending("mcp.quarantine_device", "operator1", "{\"agent_id\":\"a1\"}")
               .has_value());

    // An eligible ticket BEHIND the foreign one is still found — the scan takes
    // the newest ELIGIBLE row rather than letting a foreign one at the front
    // hide it. Both submits land in the same wall-clock second, so
    // `ORDER BY submitted_at DESC` would tie and the assertion would hold
    // whether or not the loop ever skipped: push the eligible row explicitly
    // OLDER so it can only be reached by skipping past the foreign one.
    auto mcp = mgr.submit("mcp.quarantine_device", "operator1", "{\"agent_id\":\"a1\"}", "",
                          ApprovalOrigin::kMcp);
    REQUIRE(mcp.has_value());
    REQUIRE(sqlite3_exec(tdb.db,
                         ("UPDATE approvals SET submitted_at = submitted_at - 60 WHERE id = '" +
                          *mcp + "'")
                             .c_str(),
                         nullptr, nullptr, nullptr) == SQLITE_OK);

    auto found = mgr.find_pending("mcp.quarantine_device", "operator1", "{\"agent_id\":\"a1\"}");
    REQUIRE(found.has_value());
    CHECK(found->id == *mcp);
}

TEST_CASE("ApprovalManager: migration v6 applies to an existing v5 store",
          "[approval_manager][db]") {
    TestDb tdb;
    // A v5-shaped store: every column through `origin`, schema_meta pinned at 5,
    // and only the four pre-v6 indexes.
    REQUIRE(sqlite3_exec(tdb.db,
                         "CREATE TABLE schema_meta (store TEXT PRIMARY KEY,"
                         " version INTEGER NOT NULL, upgraded_at INTEGER NOT NULL DEFAULT 0);"
                         "INSERT INTO schema_meta (store, version, upgraded_at)"
                         " VALUES ('approval_manager', 5, 0);"
                         "CREATE TABLE approvals ("
                         "id TEXT PRIMARY KEY, definition_id TEXT NOT NULL,"
                         "status TEXT NOT NULL DEFAULT 'pending',"
                         "submitted_by TEXT NOT NULL DEFAULT '',"
                         "submitted_at INTEGER NOT NULL DEFAULT 0,"
                         "reviewed_by TEXT NOT NULL DEFAULT '',"
                         "reviewed_at INTEGER NOT NULL DEFAULT 0,"
                         "review_comment TEXT NOT NULL DEFAULT '',"
                         "scope_expression TEXT NOT NULL DEFAULT '',"
                         "consumed_at INTEGER NOT NULL DEFAULT 0,"
                         "consumed_by TEXT NOT NULL DEFAULT '',"
                         "schedule_id TEXT NOT NULL DEFAULT '',"
                         "origin TEXT NOT NULL DEFAULT '');"
                         "INSERT INTO approvals (id, definition_id, status, submitted_by)"
                         " VALUES ('v5-row', 'inventory.audit', 'approved', 'operator1');",
                         nullptr, nullptr, nullptr) == SQLITE_OK);

    ApprovalManager mgr(tdb.db);
    mgr.create_tables();
    REQUIRE(mgr.is_open()); // a failed v6 would null db_ and fail the probes

    // Both v6 indexes exist, and the pre-existing row is untouched.
    auto has_index = [&tdb](const char* name) {
        SqliteStmt st;
        REQUIRE(sqlite3_prepare_v2(tdb.db,
                                   "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?", -1,
                                   st.addr(), nullptr) == SQLITE_OK);
        sqlite3_bind_text(st.get(), 1, name, -1, SQLITE_TRANSIENT);
        return sqlite3_step(st.get()) == SQLITE_ROW;
    };
    CHECK(has_index("idx_approvals_status_submitted"));
    CHECK(has_index("idx_approvals_status_consumed_reviewed"));
    // And that migration SIX is what put them there: index existence alone
    // would also hold if v6 were folded back into an earlier migration.
    CHECK(MigrationRunner::current_version(tdb.db, "approval_manager") == 6);
    auto row = mgr.get("v5-row");
    REQUIRE(row.has_value());
    CHECK(row->definition_id == "inventory.audit");
}

TEST_CASE("ApprovalManager: the recheck may read the store without deadlocking",
          "[approval_manager][approval]") {
    // The callback runs with mtx_ RELEASED, so a precondition that consults the
    // approval store (a plausible shape: "no newer ticket supersedes this one")
    // is safe. Under a lock-held design this self-deadlocks on the
    // non-recursive mutex.
    //
    // Three things about the shape below, each from a reviewer who reproduced
    // the alternative. It runs on its own thread with a bounded wait, because a
    // deadlocked assertion in the test body hangs the whole binary until the CI
    // job times out. On timeout the thread is DETACHED before the assertion
    // fires: a joinable std::thread destroyed during an assertion's unwind
    // calls std::terminate, which aborts the run and loses every remaining
    // test — worse than the hang it replaced. And joining instead is not an
    // option, because by then the thread is genuinely deadlocked.
    //
    // Detaching is only safe because the fixture is shared_ptr-owned and
    // captured BY VALUE: a thread parked on the mutex outlives this scope, and
    // under by-reference captures it would hold a dangling ApprovalManager and
    // a closed sqlite3*.
    struct Fixture {
        TestDb tdb;
        ApprovalManager mgr{tdb.db};
        std::promise<bool> done;
    };
    auto fx = std::make_shared<Fixture>();
    fx->mgr.create_tables();

    auto id = fx->mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(id.has_value());
    REQUIRE(fx->mgr.approve(*id, "admin1", "").has_value());

    auto fut = fx->done.get_future();
    std::thread worker([fx, ticket = *id] {
        auto consumed = fx->mgr.consume_ticket(
            ticket, "operator1", [fx](const Approval& a) -> std::expected<void, std::string> {
                (void)fx->mgr.get(a.id);
                (void)fx->mgr.pending_count();
                (void)fx->mgr.query({});
                return {};
            });
        fx->done.set_value(consumed.has_value());
    });

    // Under `--abort` even a CHECK throws, so the join below can be unwound past.
    // The guard makes "joined or detached exactly once" true on every path
    // rather than on the paths we thought of.
    struct Reaper {
        std::thread& t;
        ~Reaper() {
            if (t.joinable())
                t.detach();
        }
    } reaper{worker};

    const bool finished = fut.wait_for(std::chrono::seconds(10)) == std::future_status::ready;
    if (!finished) {
        // Deadlocked, so unjoinable. The Fixture outlives this scope through the
        // worker's own shared_ptr and leaks for the process lifetime — a
        // deliberate trade on an already-failing run, and the reason the
        // captures are by value.
        FAIL("timed out - the precondition ran with mtx_ held, self-deadlocking on the "
             "non-recursive mutex");
    }
    CHECK(fut.get());
    worker.join();
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

    auto stale = mgr.submit("def-old", "operator1", "scope", "", ApprovalOrigin::kUnspecified);
    REQUIRE(stale.has_value());
    backdate(tdb.db, *stale, "submitted_at", k8Days);

    REQUIRE(mgr.submit("def-new", "operator1", "scope", "", ApprovalOrigin::kUnspecified).has_value()); // triggers the sweep

    auto row = mgr.get(*stale);
    REQUIRE(row.has_value());
    CHECK(row->status == "expired");
}

TEST_CASE("ApprovalManager: approved-but-unconsumed tickets expire 7 days after review",
          "[approval_manager][approval]") {
    TestDb tdb;
    ApprovalManager mgr(tdb.db);
    mgr.create_tables();

    auto id = mgr.submit("mcp.quarantine_device", "operator1", "{}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "ok").has_value());
    backdate(tdb.db, *id, "reviewed_at", k8Days);

    REQUIRE(mgr.submit("def-new", "operator1", "scope", "", ApprovalOrigin::kUnspecified).has_value()); // triggers the sweep

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

    auto id = mgr.submit("mcp.delete_tag", "operator1", "{}", "", ApprovalOrigin::kUnspecified);
    REQUIRE(id.has_value());
    REQUIRE(mgr.approve(*id, "admin1", "").has_value());
    REQUIRE(mgr.consume_ticket(*id, "operator1").has_value());
    backdate(tdb.db, *id, "reviewed_at", k8Days);

    REQUIRE(mgr.submit("def-new", "operator1", "scope", "", ApprovalOrigin::kUnspecified).has_value()); // triggers the sweep

    auto row = mgr.get(*id);
    REQUIRE(row.has_value());
    CHECK(row->status == "approved");        // untouched — it is evidence, not a capability
    CHECK(row->consumed_by == "operator1");  // trail intact
}
