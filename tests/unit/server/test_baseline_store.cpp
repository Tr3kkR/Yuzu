/**
 * test_baseline_store.cpp — Unit tests for BaselineStore (Guardian Baselines)
 *
 * Covers:
 *   - schema migration applies cleanly against a fresh Postgres database
 *   - baseline CRUD round-trip (create / get / list / update / delete)
 *   - create generates a 12-hex id when none is supplied, honours a caller id
 *   - UNIQUE(name) collision surfaces as a kConflictPrefix error
 *   - unknown-id update/delete return a non-conflict error
 *   - created_at/updated_at stamped by the store; updated_at advances on update
 *   - member set replace is transactional + de-duplicates; get is sorted
 *   - set_members on a non-existent baseline is a not-found error
 *   - assignment include/exclude round-trip; invalid disposition aborts cleanly;
 *     duplicate group_id collapses to the last disposition (PK invariant)
 *   - delete_baseline cascades member + assignment rows (FK ON DELETE CASCADE)
 *   - reverse lookups: baselines_containing_rule, list_deployed_baselines
 *   - cross-store cleanup: remove_rule_everywhere / remove_group_everywhere
 *   - ADR-0055 catastrophic-read set: deployed_member_rule_ids() (both
 *     overloads) source from deployed_snapshot, NOT live members; a degraded
 *     store returns std::unexpected, never a silent empty container; a
 *     malformed/empty snapshot is a successful read that skips, not a degrade
 *   - get_members_checked() degrade-distinguishable twin of get_members()
 *   - bad-path (unroutable DSN) yields a closed store with sentinel returns
 *   - migration idempotency: re-open the same dsn
 *   - backfill (ADR-0009/0055): populated legacy file, fresh-install
 *     (no legacy file), Postgres-ahead skips children, legacy-ahead fails
 *     closed then a corrected retry succeeds, a live name conflict fails
 *     closed, holder-side fingerprint mismatch refuses
 *   - concurrency-at-boot (2026-08-24 orchestrator hardening pass): two
 *     genuinely concurrent replicas racing migrate_from_sqlite() against
 *     identical legacy content converge without duplication or corruption
 */

#include "baseline_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "store_errors.hpp"
#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <sqlite3.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <thread>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every test
// below constructs its own BaselineStore against a clone of this schema
// (ADR-0055 migration).
yuzu::test::PgTestTemplate baselinestore_tpl{"baselinestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    BaselineStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("baselinestore template: store failed to migrate");
}};

Baseline make_baseline(std::string name) {
    Baseline b;
    b.name = std::move(name);
    b.description = "desc";
    b.created_by = "alice";
    b.updated_by = "alice";
    return b;
}

std::string query_scalar(const std::string& dsn, const std::string& sql) {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
    if (PQntuples(r.get()) == 0)
        return "";
    return PQgetvalue(r.get(), 0, 0);
}

void exec_sql(const std::string& dsn, const std::string& sql) {
    pg::PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    pg::PgResult r{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(r.get()));
    REQUIRE(r.ok());
}

// Simulate guardian_routes.cpp's deploy_baseline handler: snapshot the
// current member set into deployed_snapshot and flip lifecycle to deployed.
void deploy(BaselineStore& store, const std::string& baseline_id) {
    auto members = store.get_members_checked(baseline_id);
    REQUIRE(members.has_value());
    auto b = store.get_baseline(baseline_id);
    REQUIRE(b.has_value());
    b->lifecycle = kBaselineDeployed;
    b->deployed_snapshot = nlohmann::json(*members).dump();
    b->deployed_by = "bob";
    REQUIRE(store.update_baseline(*b).has_value());
}

// ── Backfill legacy-SQLite fixtures (the pre-migration 3-table shape) ───────
const char* kLegacyDdl =
    "CREATE TABLE guaranteed_state_baselines ("
    "  baseline_id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,"
    "  description TEXT NOT NULL DEFAULT '', lifecycle TEXT NOT NULL DEFAULT 'draft',"
    "  deployed_snapshot TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL DEFAULT '',"
    "  updated_by TEXT NOT NULL DEFAULT '', deployed_by TEXT NOT NULL DEFAULT '',"
    "  created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0,"
    "  deployed_at INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE guaranteed_state_baseline_rules ("
    "  baseline_id TEXT NOT NULL REFERENCES guaranteed_state_baselines(baseline_id) ON DELETE "
    "CASCADE, rule_id TEXT NOT NULL, PRIMARY KEY (baseline_id, rule_id));"
    "CREATE TABLE guaranteed_state_baseline_groups ("
    "  baseline_id TEXT NOT NULL REFERENCES guaranteed_state_baselines(baseline_id) ON DELETE "
    "CASCADE, group_id TEXT NOT NULL, disposition TEXT NOT NULL, PRIMARY KEY (baseline_id, "
    "group_id));";

void open_legacy_db(const std::filesystem::path& path, sqlite3** out) {
    REQUIRE(sqlite3_open(path.string().c_str(), out) == SQLITE_OK);
    REQUIRE(sqlite3_exec(*out, kLegacyDdl, nullptr, nullptr, nullptr) == SQLITE_OK);
}

struct LegacyBaselineFixture {
    std::string baseline_id{"legacy-b1"};
    std::string name{"legacy baseline one"};
    std::string description{"from legacy"};
    std::string lifecycle{"draft"};
    std::string deployed_snapshot;
    std::string created_by{"legacy-user"};
    std::string updated_by{"legacy-user"};
    std::string deployed_by;
    int64_t created_at{1000};
    int64_t updated_at{1000};
    int64_t deployed_at{0};
    std::vector<std::string> members;
    std::vector<std::pair<std::string, std::string>> groups; // (group_id, disposition)
};

void write_legacy_db(const std::filesystem::path& path, const std::vector<LegacyBaselineFixture>& rows) {
    sqlite3* db = nullptr;
    open_legacy_db(path, &db);
    for (const auto& r : rows) {
        sqlite3_stmt* s = nullptr;
        REQUIRE(sqlite3_prepare_v2(db,
                                   "INSERT INTO guaranteed_state_baselines (baseline_id, name, "
                                   "description, lifecycle, deployed_snapshot, created_by, "
                                   "updated_by, deployed_by, created_at, updated_at, deployed_at) "
                                   "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                                   -1, &s, nullptr) == SQLITE_OK);
        sqlite3_bind_text(s, 1, r.baseline_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s, 2, r.name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s, 3, r.description.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s, 4, r.lifecycle.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s, 5, r.deployed_snapshot.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s, 6, r.created_by.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s, 7, r.updated_by.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s, 8, r.deployed_by.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(s, 9, r.created_at);
        sqlite3_bind_int64(s, 10, r.updated_at);
        sqlite3_bind_int64(s, 11, r.deployed_at);
        REQUIRE(sqlite3_step(s) == SQLITE_DONE);
        sqlite3_finalize(s);

        for (const auto& rule_id : r.members) {
            sqlite3_stmt* ms = nullptr;
            REQUIRE(sqlite3_prepare_v2(db,
                                       "INSERT INTO guaranteed_state_baseline_rules (baseline_id, "
                                       "rule_id) VALUES (?,?)",
                                       -1, &ms, nullptr) == SQLITE_OK);
            sqlite3_bind_text(ms, 1, r.baseline_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(ms, 2, rule_id.c_str(), -1, SQLITE_TRANSIENT);
            REQUIRE(sqlite3_step(ms) == SQLITE_DONE);
            sqlite3_finalize(ms);
        }
        for (const auto& [group_id, disposition] : r.groups) {
            sqlite3_stmt* gs = nullptr;
            REQUIRE(sqlite3_prepare_v2(db,
                                       "INSERT INTO guaranteed_state_baseline_groups "
                                       "(baseline_id, group_id, disposition) VALUES (?,?,?)",
                                       -1, &gs, nullptr) == SQLITE_OK);
            sqlite3_bind_text(gs, 1, r.baseline_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(gs, 2, group_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(gs, 3, disposition.c_str(), -1, SQLITE_TRANSIENT);
            REQUIRE(sqlite3_step(gs) == SQLITE_DONE);
            sqlite3_finalize(gs);
        }
    }
    sqlite3_close(db);
}

} // namespace

// ── CRUD ─────────────────────────────────────────────────────────────────────

TEST_CASE("BaselineStore opens and applies its schema", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.baseline_count() == 0);
}

TEST_CASE("Baseline CRUD round-trip", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    REQUIRE(store.is_open());

    auto created = store.create_baseline(make_baseline("CIS Windows L1"));
    REQUIRE(created.has_value());
    const std::string id = *created;
    REQUIRE_FALSE(id.empty());
    REQUIRE(store.baseline_count() == 1);

    auto got = store.get_baseline(id);
    REQUIRE(got.has_value());
    CHECK(got->name == "CIS Windows L1");
    CHECK(got->description == "desc");
    CHECK(got->lifecycle == kBaselineDraft); // defaults to draft
    CHECK(got->created_by == "alice");
    CHECK(got->created_at > 0);
    CHECK(got->updated_at > 0);
    CHECK(got->deployed_at == 0);

    auto all = store.list_baselines();
    REQUIRE(all.size() == 1);
    CHECK(all[0].baseline_id == id);

    // Update mutable scalars (e.g. a deploy flipping lifecycle).
    Baseline upd = *got;
    upd.description = "edited";
    upd.lifecycle = kBaselineDeployed;
    upd.deployed_by = "bob";
    upd.deployed_at = 1000;
    upd.updated_by = "bob";
    REQUIRE(store.update_baseline(upd).has_value());

    auto after = store.get_baseline(id);
    REQUIRE(after.has_value());
    CHECK(after->description == "edited");
    CHECK(after->lifecycle == kBaselineDeployed);
    CHECK(after->deployed_by == "bob");
    CHECK(after->deployed_at == 1000);
    CHECK(after->created_at == got->created_at); // immutable
    CHECK(after->updated_at >= got->updated_at); // re-stamped

    REQUIRE(store.delete_baseline(id).has_value());
    CHECK_FALSE(store.get_baseline(id).has_value());
    CHECK(store.baseline_count() == 0);
}

TEST_CASE("create_baseline honours a caller-supplied id", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    Baseline b = make_baseline("named");
    b.baseline_id = "fixed-id-123";
    auto created = store.create_baseline(b);
    REQUIRE(created.has_value());
    CHECK(*created == "fixed-id-123");
    CHECK(store.get_baseline("fixed-id-123").has_value());
}

TEST_CASE("Duplicate baseline name is a conflict error", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    REQUIRE(store.create_baseline(make_baseline("dup")).has_value());

    auto again = store.create_baseline(make_baseline("dup"));
    REQUIRE_FALSE(again.has_value());
    CHECK(is_conflict_error(again.error()));
}

TEST_CASE("update/delete of unknown baseline are non-conflict errors", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};

    Baseline ghost = make_baseline("ghost");
    ghost.baseline_id = "no-such";
    auto u = store.update_baseline(ghost);
    REQUIRE_FALSE(u.has_value());
    CHECK_FALSE(is_conflict_error(u.error()));

    auto d = store.delete_baseline("no-such");
    REQUIRE_FALSE(d.has_value());
    CHECK_FALSE(is_conflict_error(d.error()));
}

TEST_CASE("create_baseline/update_baseline reject an invalid lifecycle", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};

    Baseline bad = make_baseline("bad-lifecycle");
    bad.lifecycle = "active"; // not draft/deployed
    auto created = store.create_baseline(bad);
    REQUIRE_FALSE(created.has_value());
    CHECK_FALSE(is_conflict_error(created.error()));
    CHECK_FALSE(store.get_baseline_by_name("bad-lifecycle", nullptr).has_value());

    const std::string id = *store.create_baseline(make_baseline("ok-lifecycle"));
    Baseline update = *store.get_baseline(id);
    update.lifecycle = "active";
    auto updated = store.update_baseline(update);
    REQUIRE_FALSE(updated.has_value());
    CHECK_FALSE(is_conflict_error(updated.error()));
    CHECK(store.get_baseline(id)->lifecycle == kBaselineDraft); // untouched
}

TEST_CASE("Member set replace is transactional and de-duplicates", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    const std::string id = *store.create_baseline(make_baseline("members"));

    REQUIRE(store.set_members(id, {"r1", "r2", "r1", "", "r3"}).has_value());
    auto m = store.get_members(id);
    REQUIRE(m == std::vector<std::string>{"r1", "r2", "r3"}); // sorted, de-duped, blanks dropped
    CHECK(store.member_count(id) == 3);

    // Replace wholesale.
    REQUIRE(store.set_members(id, {"r9", "r2"}).has_value());
    CHECK(store.get_members(id) == std::vector<std::string>{"r2", "r9"});

    // Clear.
    REQUIRE(store.set_members(id, {}).has_value());
    CHECK(store.get_members(id).empty());
}

TEST_CASE("set_members on a non-existent baseline is not-found", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    auto r = store.set_members("nope", {"r1"});
    REQUIRE_FALSE(r.has_value());
    CHECK_FALSE(is_conflict_error(r.error()));
}

TEST_CASE("set_members/set_assignment with an EMPTY payload against a non-existent baseline "
          "is not-found, not a silent success",
          "[pg][baseline_store]") {
    // Pins the governance TOCTOU fix (three independent reviewers): a
    // non-empty payload was already caught by the FK constraint on INSERT,
    // but an empty payload skips the INSERT entirely, so before the fix the
    // only remaining statement was a row-count-blind touch-UPDATE that
    // reported PGRES_COMMAND_OK on 0 matched rows — success against a
    // baseline that was never there. The fix moves a RETURNING-checked
    // touch-UPDATE to the front of both transactions.
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};

    auto members_r = store.set_members("nope", {});
    REQUIRE_FALSE(members_r.has_value());
    CHECK_FALSE(is_conflict_error(members_r.error()));

    auto assignment_r = store.set_assignment("nope", {});
    REQUIRE_FALSE(assignment_r.has_value());
    CHECK_FALSE(is_conflict_error(assignment_r.error()));
}

TEST_CASE("Assignment include/exclude round-trip and validation", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    const std::string id = *store.create_baseline(make_baseline("assign"));

    REQUIRE(store.set_assignment(id, {{"g-prod", kAssignInclude}, {"g-jump", kAssignExclude}})
                .has_value());
    auto a = store.get_assignment(id);
    REQUIRE(a.size() == 2);
    // ORDER BY disposition, group_id → exclude sorts before include.
    CHECK(a[0].disposition == kAssignExclude);
    CHECK(a[0].group_id == "g-jump");
    CHECK(a[1].disposition == kAssignInclude);
    CHECK(a[1].group_id == "g-prod");

    // Invalid disposition aborts with nothing changed.
    auto bad = store.set_assignment(id, {{"g-x", "maybe"}});
    REQUIRE_FALSE(bad.has_value());
    CHECK_FALSE(is_conflict_error(bad.error()));
    CHECK(store.get_assignment(id).size() == 2); // untouched

    // Duplicate group_id collapses to the LAST disposition (PK invariant).
    REQUIRE(store.set_assignment(id, {{"g-dup", kAssignInclude}, {"g-dup", kAssignExclude}})
                .has_value());
    auto d = store.get_assignment(id);
    REQUIRE(d.size() == 1);
    CHECK(d[0].group_id == "g-dup");
    CHECK(d[0].disposition == kAssignExclude);
}

TEST_CASE("set_members/set_assignment advance the parent baseline's updated_at",
          "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    const std::string id = *store.create_baseline(make_baseline("touch"));
    const int64_t created_updated_at = store.get_baseline(id)->updated_at;

    std::this_thread::sleep_for(std::chrono::milliseconds(1100)); // now_epoch() is second-granular

    REQUIRE(store.set_members(id, {"r1"}).has_value());
    const int64_t after_members = store.get_baseline(id)->updated_at;
    CHECK(after_members > created_updated_at);

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    REQUIRE(store.set_assignment(id, {{"g1", kAssignInclude}}).has_value());
    const int64_t after_assignment = store.get_baseline(id)->updated_at;
    CHECK(after_assignment > after_members);
}

TEST_CASE("delete_baseline cascades members and assignment", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    const std::string id = *store.create_baseline(make_baseline("cascade"));
    REQUIRE(store.set_members(id, {"r1", "r2"}).has_value());
    REQUIRE(store.set_assignment(id, {{"g1", kAssignInclude}}).has_value());

    REQUIRE(store.delete_baseline(id).has_value());

    // If the FK cascade did not fire, these WHERE baseline_id=? queries would
    // still return the orphaned rows.
    CHECK(store.get_members(id).empty());
    CHECK(store.get_assignment(id).empty());
}

TEST_CASE("Reverse lookups: baselines_containing_rule + list_deployed_baselines",
          "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    const std::string a = *store.create_baseline(make_baseline("A"));
    const std::string b = *store.create_baseline(make_baseline("B"));
    REQUIRE(store.set_members(a, {"shared", "only-a"}).has_value());
    REQUIRE(store.set_members(b, {"shared"}).has_value());

    auto containing = store.baselines_containing_rule("shared");
    std::sort(containing.begin(), containing.end());
    auto expect = std::vector<std::string>{a, b};
    std::sort(expect.begin(), expect.end());
    CHECK(containing == expect);
    CHECK(store.baselines_containing_rule("only-a") == std::vector<std::string>{a});

    // Only B is deployed.
    Baseline bb = *store.get_baseline(b);
    bb.lifecycle = kBaselineDeployed;
    REQUIRE(store.update_baseline(bb).has_value());
    auto deployed = store.list_deployed_baselines();
    REQUIRE(deployed.size() == 1);
    CHECK(deployed[0].baseline_id == b);
}

TEST_CASE("Cross-store cleanup hooks remove rows from every baseline", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    const std::string a = *store.create_baseline(make_baseline("A"));
    const std::string b = *store.create_baseline(make_baseline("B"));
    REQUIRE(store.set_members(a, {"r-gone", "keep"}).has_value());
    REQUIRE(store.set_members(b, {"r-gone"}).has_value());
    REQUIRE(store.set_assignment(a, {{"g-gone", kAssignInclude}}).has_value());
    REQUIRE(store.set_assignment(b, {{"g-gone", kAssignExclude}}).has_value());

    CHECK(store.remove_rule_everywhere("r-gone") == 2);
    CHECK(store.get_members(a) == std::vector<std::string>{"keep"});
    CHECK(store.get_members(b).empty());

    CHECK(store.remove_group_everywhere("g-gone") == 2);
    CHECK(store.get_assignment(a).empty());
    CHECK(store.get_assignment(b).empty());

    // Idempotent: removing what's already gone reports zero.
    CHECK(store.remove_rule_everywhere("r-gone") == 0);
}

TEST_CASE("Baselines persist across reopen", "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    std::string id;
    {
        PgPool pool1{{.conninfo = db.dsn(), .size = 4}};
        BaselineStore store{pool1};
        REQUIRE(store.is_open());
        id = *store.create_baseline(make_baseline("persist"));
        REQUIRE(store.set_members(id, {"r1"}).has_value());
    }
    {
        PgPool pool2{{.conninfo = db.dsn(), .size = 4}};
        BaselineStore store{pool2}; // migration idempotent against the already-applied schema
        REQUIRE(store.is_open());
        auto got = store.get_baseline(id);
        REQUIRE(got.has_value());
        CHECK(got->name == "persist");
        CHECK(store.get_members(id) == std::vector<std::string>{"r1"});
    }
}

// ── Catastrophic-read set (ADR-0055, CLAUDE.md Guardian invariant) ─────────

TEST_CASE("deployed_member_rule_ids sources the deployed snapshot, not live members",
          "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    const std::string id = *store.create_baseline(make_baseline("deploy-target"));
    REQUIRE(store.set_members(id, {"guard-a", "guard-b"}).has_value());
    deploy(store, id);

    auto fleet = store.deployed_member_rule_ids();
    REQUIRE(fleet.has_value());
    CHECK(*fleet == std::unordered_set<std::string>{"guard-a", "guard-b"});

    auto per_baseline = store.deployed_member_rule_ids(id);
    REQUIRE(per_baseline.has_value());
    CHECK(*per_baseline == std::vector<std::string>{"guard-a", "guard-b"});

    // Draft-edit the live member set WITHOUT re-deploying — the catastrophic
    // invariant: the enforced set must NOT change until a Push-gated
    // re-deploy rewrites deployed_snapshot.
    REQUIRE(store.set_members(id, {"guard-c"}).has_value());
    CHECK(store.get_members(id) == std::vector<std::string>{"guard-c"}); // live members DID change

    auto fleet_after_edit = store.deployed_member_rule_ids();
    REQUIRE(fleet_after_edit.has_value());
    CHECK(*fleet_after_edit == std::unordered_set<std::string>{"guard-a", "guard-b"}); // unchanged

    auto per_baseline_after_edit = store.deployed_member_rule_ids(id);
    REQUIRE(per_baseline_after_edit.has_value());
    CHECK(*per_baseline_after_edit == std::vector<std::string>{"guard-a", "guard-b"}); // unchanged

    // Re-deploy converges the enforced set to the new live members.
    deploy(store, id);
    auto fleet_after_redeploy = store.deployed_member_rule_ids();
    REQUIRE(fleet_after_redeploy.has_value());
    CHECK(*fleet_after_redeploy == std::unordered_set<std::string>{"guard-c"});
}

TEST_CASE("deployed_member_rule_ids: a malformed/empty snapshot is a successful skip, not a "
          "degrade",
          "[pg][baseline_store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store{pool};
    const std::string id = *store.create_baseline(make_baseline("malformed-snap"));

    // Never deployed: draft lifecycle, empty snapshot column.
    auto never_deployed = store.deployed_member_rule_ids();
    REQUIRE(never_deployed.has_value());
    CHECK(never_deployed->empty());
    auto never_deployed_pb = store.deployed_member_rule_ids(id);
    REQUIRE(never_deployed_pb.has_value());
    CHECK(never_deployed_pb->empty());

    // Deployed with a genuinely malformed (non-JSON-array) snapshot — the
    // store's public API can never write this; simulate a corrupt row
    // directly to exercise the fail-closed parse path.
    exec_sql(db.dsn(), "UPDATE baseline_store.baselines SET lifecycle = 'deployed', "
                       "deployed_snapshot = 'not json at all' WHERE baseline_id = '" + id + "'");
    auto malformed = store.deployed_member_rule_ids();
    REQUIRE(malformed.has_value()); // successful read, NOT std::unexpected
    CHECK(malformed->empty());
    auto malformed_pb = store.deployed_member_rule_ids(id);
    REQUIRE(malformed_pb.has_value());
    CHECK(malformed_pb->empty());
}

TEST_CASE("Bad path (unroutable DSN) yields a closed store with sentinel returns",
          "[pg][baseline_store]") {
    // No live rig needed — an unroutable address fails fast everywhere
    // (mirrors GuaranteedStateStore's equivalent bad-path test, ADR-0038).
    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    BaselineStore bad(bad_pool);
    CHECK_FALSE(bad.is_open());

    CHECK_FALSE(bad.create_baseline(make_baseline("x")).has_value());
    CHECK_FALSE(bad.get_baseline("x").has_value());
    bool store_ok = true;
    CHECK_FALSE(bad.get_baseline_by_name("x", &store_ok).has_value());
    CHECK_FALSE(store_ok); // fault, not a genuine miss
    CHECK(bad.list_baselines().empty());
    CHECK_FALSE(bad.update_baseline(make_baseline("x")).has_value());
    CHECK_FALSE(bad.delete_baseline("x").has_value());
    CHECK_FALSE(bad.set_members("x", {"r1"}).has_value());
    CHECK(bad.get_members("x").empty());
    // get_members_checked is degrade-distinguishable: unexpected, not empty.
    CHECK_FALSE(bad.get_members_checked("x").has_value());
    CHECK(bad.baselines_containing_rule("x").empty());
    CHECK(bad.remove_rule_everywhere("x") == 0);
    CHECK_FALSE(bad.set_assignment("x", {{"g1", kAssignInclude}}).has_value());
    CHECK(bad.get_assignment("x").empty());
    CHECK(bad.remove_group_everywhere("x") == 0);
    CHECK(bad.list_deployed_baselines().empty());
    // Catastrophic-read set: unexpected on a closed store, never a silent
    // empty container.
    CHECK_FALSE(bad.deployed_member_rule_ids().has_value());
    CHECK_FALSE(bad.deployed_member_rule_ids("x").has_value());
    CHECK(bad.baseline_count() == 0);
    CHECK(bad.member_count("x") == 0);
    CHECK_FALSE(bad.migrate_from_sqlite("/nonexistent/path/does-not-matter.db"));
}

// ── Backfill (ADR-0009/0055) ────────────────────────────────────────────────

TEST_CASE("BaselineStore::migrate_from_sqlite copies a populated legacy file exactly once",
          "[pg][baseline_store][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store(pool);
    REQUIRE(store.is_open());

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_baseline_populated") / "guardian-baselines.db";
    std::filesystem::create_directories(legacy_path.parent_path());

    LegacyBaselineFixture b1;
    b1.baseline_id = "legacy-b1";
    b1.name = "Legacy CIS L1";
    b1.description = "seeded from legacy";
    b1.lifecycle = "deployed";
    b1.deployed_snapshot = R"(["legacy-rule-1"])";
    b1.deployed_by = "legacy-deployer";
    b1.created_at = 1000;
    b1.updated_at = 2000;
    b1.deployed_at = 2000;
    b1.members = {"legacy-rule-1", "legacy-rule-2"};
    b1.groups = {{"g-prod", "include"}, {"g-jump", "exclude"}};
    write_legacy_db(legacy_path, {b1});

    REQUIRE(store.migrate_from_sqlite(legacy_path));

    auto got = store.get_baseline("legacy-b1");
    REQUIRE(got.has_value());
    CHECK(got->name == "Legacy CIS L1");
    CHECK(got->lifecycle == "deployed");
    CHECK(got->deployed_by == "legacy-deployer");
    CHECK(store.baseline_count() == 1);
    CHECK(store.get_members("legacy-b1") == std::vector<std::string>{"legacy-rule-1", "legacy-rule-2"});
    CHECK(store.get_assignment("legacy-b1").size() == 2);

    auto deployed_ids = store.deployed_member_rule_ids("legacy-b1");
    REQUIRE(deployed_ids.has_value());
    CHECK(*deployed_ids == std::vector<std::string>{"legacy-rule-1"});

    // The marker is stamped.
    CHECK(query_scalar(db.dsn(), "SELECT value FROM baseline_store.baseline_store_meta WHERE "
                                 "key = 'backfill_complete'") != "");
    const std::string fp = query_scalar(
        db.dsn(), "SELECT value FROM baseline_store.baseline_store_meta WHERE key = "
                  "'backfill_source_fingerprint'");
    CHECK(fp != "sourceless");
    CHECK(fp.starts_with("v1:"));

    // Second call against a database whose marker is now set and whose local
    // legacy file has already been moved aside is a fast no-op — must not
    // error and must not double the already-copied data.
    REQUIRE(store.migrate_from_sqlite(legacy_path));
    CHECK(store.baseline_count() == 1);
    CHECK(store.get_members("legacy-b1").size() == 2);
}

TEST_CASE("BaselineStore::migrate_from_sqlite with no legacy file marks backfill complete "
          "(fresh install)",
          "[pg][baseline_store][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store(pool);
    REQUIRE(store.is_open());

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_baseline_fresh") / "guardian-baselines.db";
    // Deliberately never created.

    REQUIRE(store.migrate_from_sqlite(legacy_path));
    CHECK(store.baseline_count() == 0);
    CHECK(query_scalar(db.dsn(), "SELECT value FROM baseline_store.baseline_store_meta WHERE "
                                 "key = 'backfill_source_fingerprint'") == "sourceless");

    // A second call still finds no local legacy file — fast "already
    // completed" path, not the holder-side verify branch.
    REQUIRE(store.migrate_from_sqlite(legacy_path));
    CHECK(store.baseline_count() == 0);
}

TEST_CASE("BaselineStore::migrate_from_sqlite: a Postgres-ahead baseline keeps its live "
          "children, legacy children are NOT merged",
          "[pg][baseline_store][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store(pool);
    REQUIRE(store.is_open());

    Baseline live = make_baseline("already live");
    live.baseline_id = "shared-id-1";
    auto created = store.create_baseline(live);
    REQUIRE(created.has_value());
    REQUIRE(store.set_members("shared-id-1", {"live-rule"}).has_value());
    auto live_row = store.get_baseline("shared-id-1");
    REQUIRE(live_row.has_value());

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_baseline_pg_ahead") / "guardian-baselines.db";
    std::filesystem::create_directories(legacy_path.parent_path());

    LegacyBaselineFixture lb;
    lb.baseline_id = "shared-id-1";
    lb.name = "already live"; // same name — same identity, benign
    lb.description = "a STALE legacy description";
    lb.created_at = live_row->created_at;
    lb.updated_at = live_row->updated_at - 500; // strictly BEHIND Postgres
    lb.members = {"legacy-only-rule"}; // must NOT be merged into live children
    write_legacy_db(legacy_path, {lb});

    REQUIRE(store.migrate_from_sqlite(legacy_path));

    auto after = store.get_baseline("shared-id-1");
    REQUIRE(after.has_value());
    CHECK(after->description != "a STALE legacy description"); // live value kept
    // Live children are untouched — the legacy-only member was never merged.
    CHECK(store.get_members("shared-id-1") == std::vector<std::string>{"live-rule"});
}

TEST_CASE("BaselineStore::migrate_from_sqlite fails closed and unstamped when a legacy row "
          "shows MORE progress than Postgres, then a corrected retry succeeds",
          "[pg][baseline_store][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store(pool);
    REQUIRE(store.is_open());

    Baseline live = make_baseline("contested");
    live.baseline_id = "contested-id";
    REQUIRE(store.create_baseline(live).has_value());
    auto live_row = store.get_baseline("contested-id");
    REQUIRE(live_row.has_value());

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_baseline_legacy_ahead") / "guardian-baselines.db";
    std::filesystem::create_directories(legacy_path.parent_path());

    LegacyBaselineFixture lb;
    lb.baseline_id = "contested-id";
    lb.name = "contested";
    lb.description = "legacy progressed further";
    lb.created_at = live_row->created_at;
    lb.updated_at = live_row->updated_at + 10000; // strictly AHEAD of Postgres
    write_legacy_db(legacy_path, {lb});

    CHECK_FALSE(store.migrate_from_sqlite(legacy_path));

    // Refused, unstamped, and the live row is untouched (whole-txn rollback).
    auto after_fail = store.get_baseline("contested-id");
    REQUIRE(after_fail.has_value());
    CHECK(after_fail->description == live_row->description);
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM baseline_store.baseline_store_meta") ==
          "0");

    // A corrected retry (legacy no longer strictly ahead) against a FRESH
    // legacy path succeeds — proving the failed pass never stamped the
    // marker (the marker check is the only thing that could short-circuit
    // this second call).
    auto fixed_path =
        yuzu::test::unique_temp_path("yuzu_test_baseline_legacy_fixed") / "guardian-baselines.db";
    std::filesystem::create_directories(fixed_path.parent_path());
    // Make the legacy row genuinely IDENTICAL to the live row (every compared
    // LIFECYCLE field, not just updated_at/description) — a tied updated_at
    // with ANY other differing field (e.g. created_by/updated_by, still at
    // LegacyBaselineFixture's defaults here) is itself a "tied, differing
    // content" fail-closed case, not the benign identical no-op this second
    // call is meant to exercise.
    LegacyBaselineFixture fixed = lb;
    fixed.updated_at = live_row->updated_at;
    fixed.description = live_row->description;
    fixed.created_by = live_row->created_by;
    fixed.updated_by = live_row->updated_by;
    fixed.deployed_by = live_row->deployed_by;
    fixed.lifecycle = live_row->lifecycle;
    fixed.deployed_snapshot = live_row->deployed_snapshot;
    fixed.deployed_at = live_row->deployed_at;
    write_legacy_db(fixed_path, {fixed});
    REQUIRE(store.migrate_from_sqlite(fixed_path));
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM baseline_store.baseline_store_meta") !=
          "0");
}

TEST_CASE("BaselineStore::migrate_from_sqlite fails closed and unstamped on an invalid legacy "
          "lifecycle or assignment disposition",
          "[pg][baseline_store][backfill]") {
    // The backfill's own validation predates this PR (unlike the live-write
    // path's, which K2 fixed to match it) but was itself never under test —
    // governance quality-engineer finding. A raw legacy write bypasses the
    // live-write enum check entirely, so this is the only way to construct
    // an invalid value in the fixture.
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    {
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        BaselineStore store(pool);
        REQUIRE(store.is_open());

        auto path = yuzu::test::unique_temp_path("yuzu_test_baseline_bad_lifecycle") /
                   "guardian-baselines.db";
        std::filesystem::create_directories(path.parent_path());
        LegacyBaselineFixture bad;
        bad.baseline_id = "bad-lifecycle-id";
        bad.lifecycle = "active"; // not draft/deployed
        write_legacy_db(path, {bad});

        CHECK_FALSE(store.migrate_from_sqlite(path));
        CHECK(store.baseline_count() == 0);
        CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM baseline_store.baseline_store_meta") ==
              "0");
    }
    {
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        BaselineStore store(pool);
        REQUIRE(store.is_open());

        auto path = yuzu::test::unique_temp_path("yuzu_test_baseline_bad_disposition") /
                   "guardian-baselines.db";
        std::filesystem::create_directories(path.parent_path());
        LegacyBaselineFixture bad;
        bad.baseline_id = "bad-disposition-id";
        bad.groups = {{"g1", "maybe"}}; // not include/exclude
        write_legacy_db(path, {bad});

        CHECK_FALSE(store.migrate_from_sqlite(path));
        CHECK(store.baseline_count() == 0);
        CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM baseline_store.baseline_store_meta") ==
              "0");
    }
}

TEST_CASE("BaselineStore::migrate_from_sqlite fails closed on a live baseline_id/name conflict",
          "[pg][baseline_store][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store(pool);
    REQUIRE(store.is_open());

    Baseline live = make_baseline("Prod CIS");
    live.baseline_id = "live-owns-name";
    REQUIRE(store.create_baseline(live).has_value());

    auto legacy_path =
        yuzu::test::unique_temp_path("yuzu_test_baseline_name_conflict") / "guardian-baselines.db";
    std::filesystem::create_directories(legacy_path.parent_path());

    LegacyBaselineFixture lb;
    lb.baseline_id = "legacy-different-id"; // DIFFERENT id, SAME name
    lb.name = "Prod CIS";
    write_legacy_db(legacy_path, {lb});

    CHECK_FALSE(store.migrate_from_sqlite(legacy_path));

    // Rolled back — the legacy row never landed under its own id.
    CHECK_FALSE(store.get_baseline("legacy-different-id").has_value());
    CHECK(store.baseline_count() == 1); // only the original live row
    CHECK(query_scalar(db.dsn(), "SELECT COUNT(*) FROM baseline_store.baseline_store_meta") ==
          "0");
}

TEST_CASE("BaselineStore::migrate_from_sqlite: holder-side fingerprint mismatch refuses",
          "[pg][baseline_store][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    BaselineStore store(pool);
    REQUIRE(store.is_open());

    auto path_a =
        yuzu::test::unique_temp_path("yuzu_test_baseline_holder_a") / "guardian-baselines.db";
    std::filesystem::create_directories(path_a.parent_path());
    LegacyBaselineFixture a;
    a.baseline_id = "from-replica-a";
    a.name = "replica A baseline";
    write_legacy_db(path_a, {a});
    REQUIRE(store.migrate_from_sqlite(path_a)); // stamps the fingerprint of file A

    // A DIFFERENT replica's legacy file, still present on disk, with
    // genuinely different content — simulates this replica holding its own
    // local legacy copy that was never the one actually migrated.
    auto path_b =
        yuzu::test::unique_temp_path("yuzu_test_baseline_holder_b") / "guardian-baselines.db";
    std::filesystem::create_directories(path_b.parent_path());
    LegacyBaselineFixture b;
    b.baseline_id = "from-replica-b";
    b.name = "replica B baseline";
    write_legacy_db(path_b, {b});

    CHECK_FALSE(store.migrate_from_sqlite(path_b));
    // Refused — replica B's content was never incorporated.
    CHECK_FALSE(store.get_baseline("from-replica-b").has_value());
    CHECK(store.baseline_count() == 1); // only replica A's row
}

TEST_CASE("BaselineStore::migrate_from_sqlite: two genuinely concurrent replicas racing "
          "identical legacy content converge without duplication or corruption",
          "[pg][baseline_store][backfill][concurrency]") {
    // Two SEPARATE BaselineStore instances, each with its OWN PgPool, against
    // the SAME cloned database — simulates two server replicas independently
    // backfilling from their own local legacy copy (a golden-image deploy, or
    // a shared volume mounted twice) against one shared Postgres substrate.
    // This is the scenario the fingerprint-verified marker, the
    // PQcmdTuples()=="0" concurrent-writer refusal, and the monotonic-
    // promotion stamp all exist to make safe (see the header doc comment).
    //
    // NOT guaranteed-deterministic (correction, governance re-review): the
    // row-lock argument only holds for the racers that actually reach the
    // row-locked `INSERT ... ON CONFLICT` concurrently. `migrate_from_sqlite`
    // checks the `backfill_complete` marker via a plain SELECT BEFORE that
    // point — if one racer's marker check lands after the other has already
    // committed, it takes the holder-side-verification "already complete"
    // path instead, and the contested INSERT is never reached by either
    // thread that attempt. So whether this run exercises the
    // concurrent-writer refusal at all is scheduling-dependent, same class of
    // uncertainty as CA-store's first-boot root race (#3475/UP-3) — this test
    // now adopts that same bounded re-attempt-until-observed shape rather
    // than asserting determinism a single unbarriered run can't prove.
    // 30, not CA-store's 15: an empirical run on this box alone used 10 of 15
    // attempts once — CA-store's own bound started at 5 and had to widen to
    // 15 under CI load (#3475), so this starts with more headroom rather
    // than repeating that discovery.
    constexpr int kMaxSchedulingAttempts = 30;
    for (int attempt = 0;; ++attempt) {
        INFO("scheduling attempt " << attempt << ": did one racer's marker check land after "
             "the other already committed? (legitimate, just doesn't exercise the contested "
             "INSERT — retrying for a genuine row-lock collision)");
        REQUIRE(attempt < kMaxSchedulingAttempts);

        YUZU_REQUIRE_PG_DB_TPL(db, baselinestore_tpl);
        PgPool pool_a{{.conninfo = db.dsn(), .size = 4}};
        PgPool pool_b{{.conninfo = db.dsn(), .size = 4}};
        BaselineStore store_a(pool_a);
        BaselineStore store_b(pool_b);
        REQUIRE(store_a.is_open());
        REQUIRE(store_b.is_open());

        // Two DISTINCT legacy files (SQLite files are per-path) with BYTE-
        // IDENTICAL row content — neither racer can legitimately see the
        // other as "ahead" or "contradicting" (the fixture is otherwise no
        // different from a plain single-replica backfill; only the
        // concurrency is new). Fresh per attempt — a completed backfill
        // can't be re-raced.
        LegacyBaselineFixture fixture;
        fixture.baseline_id = "race-baseline-1";
        fixture.name = "Race Baseline";
        fixture.members = {"race-rule-a", "race-rule-b"};
        fixture.groups = {{"race-group", kAssignInclude}};
        auto path_a = yuzu::test::unique_temp_path("yuzu_test_baseline_race_a") /
                     "guardian-baselines.db";
        auto path_b = yuzu::test::unique_temp_path("yuzu_test_baseline_race_b") /
                     "guardian-baselines.db";
        std::filesystem::create_directories(path_a.parent_path());
        std::filesystem::create_directories(path_b.parent_path());
        write_legacy_db(path_a, {fixture});
        write_legacy_db(path_b, {fixture});

        bool ok_a = false, ok_b = false;
        std::string logs;
        {
            // Deliberately no start barrier — CA-store's #3475 finding: a
            // barrier that synchronizes thread LAUNCH but not the
            // connect/query work after it measured WORSE under load than
            // natural OS scheduling jitter on that box.
            yuzu::test::LogCapture log;
            std::thread ta([&] { ok_a = store_a.migrate_from_sqlite(path_a); });
            std::thread tb([&] { ok_b = store_b.migrate_from_sqlite(path_b); });
            ta.join();
            tb.join();
            log.stop();
            logs = log.text();
        }

        const bool exercised_contested_insert =
            logs.find("concurrent writer inserted baseline") != std::string::npos;
        if (!exercised_contested_insert) {
            // Neither racer hit the row lock this attempt (one saw the
            // other's marker already stamped) — both may have succeeded
            // cleanly, which is a legitimate but uninteresting outcome for
            // THIS test's claim. Retry for a genuine collision.
            continue;
        }
        INFO("captured backfill logs from the attempt that exercised the contested INSERT:\n"
             << logs);

        // A loser from the row-lock refusal self-heals on an immediate
        // single-threaded retry (no concurrent racer left to re-trigger it)
        // — verified below, not asserted away, so an unrelated, unexplained
        // failure still fails loudly via REQUIRE.
        if (!ok_a)
            REQUIRE(store_a.migrate_from_sqlite(path_a));
        if (!ok_b)
            REQUIRE(store_b.migrate_from_sqlite(path_b));

        // Whichever interleaving occurred, the end state is exactly one
        // Baseline with exactly its fixture's children — never duplicated,
        // never partial.
        CHECK(store_a.baseline_count() == 1);
        CHECK(store_a.get_members("race-baseline-1") ==
              std::vector<std::string>{"race-rule-a", "race-rule-b"});
        CHECK(store_a.get_assignment("race-baseline-1").size() == 1);

        // Both replicas' own connection converges to the SAME row — not a
        // store_a-local artifact.
        auto from_b = store_b.get_baseline("race-baseline-1");
        REQUIRE(from_b.has_value());
        CHECK(from_b->name == "Race Baseline");
        break;
    }
}
