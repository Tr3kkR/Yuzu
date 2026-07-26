/**
 * test_result_set_store.cpp — Unit tests for the scope-walking result-set store.
 *
 * Covers: synchronous + asynchronous create, membership + lineage, alias
 * resolution, pin/unpin (+ cap), delete (pinned-rejected), quota, async
 * materialisation, touch TTL extension, and GC sweep. Migrated Postgres store
 * (ADR-0036, schema `result_set_store`). PG-gated: skips when
 * YUZU_TEST_POSTGRES_DSN is unset, fails when it is set but broken.
 */

#include "result_set_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): every test
// below constructs its own ResultSetStore against a clone of this schema.
yuzu::test::PgTestTemplate result_set_tpl{"resultset", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResultSetStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("resultset template: store failed to migrate");
}};

CreateRequest req(const std::string& owner, const std::string& name = "",
                  std::optional<std::string> parent = std::nullopt) {
    CreateRequest r;
    r.owner_principal = owner;
    r.name = name;
    r.parent_id = std::move(parent);
    r.source_kind = std::string(source_kind::kInventoryQuery);
    r.source_payload = R"({"query":"os.platform == \"windows\""})";
    return r;
}

// Run a raw SQL statement against the test database on a second connection —
// lets a test simulate TTL expiry / form a parent_id cycle that the public API
// deliberately cannot produce.
void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql.c_str())};
    REQUIRE(r.ok());
}

// Unwrap helpers for the four type-distinguishable-error reads (ADR-0036 /
// docs/postgres-store-playbook.md "authoritative reads must be
// type-distinguishable"): every call below hits a live, healthy Postgres, so
// a DbError here is a genuine test-infrastructure failure, not an expected
// branch — REQUIRE it away loudly and hand back the plain
// optional/bool/set the pre-widening tests were written against.
std::optional<ResultSet> get_ok(ResultSetStore& s, const std::string& id) {
    auto r = s.get(id);
    REQUIRE(r.has_value());
    return *r;
}
bool contains_ok(ResultSetStore& s, const std::string& id, const std::string& device_id) {
    auto r = s.contains(id, device_id);
    REQUIRE(r.has_value());
    return *r;
}
std::optional<std::string> resolve_alias_ok(ResultSetStore& s, const std::string& owner,
                                            const std::string& name) {
    auto r = s.resolve_alias(owner, name);
    REQUIRE(r.has_value());
    return *r;
}
std::unordered_set<std::string> member_set_owned_ok(ResultSetStore& s, const std::string& id,
                                                    const std::string& owner) {
    auto r = s.member_set_owned(id, owner);
    REQUIRE(r.has_value());
    return *r;
}

} // namespace

TEST_CASE("ResultSetStore: synchronous create, get, members", "[pg][result_set][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    std::vector<std::string> members = {"dev-a", "dev-b", "dev-c"};
    auto rs = store.create_materialized(req("alice", "win-fleet"), members);
    REQUIRE(rs.has_value());
    CHECK(rs->id.starts_with("rs_"));
    CHECK(rs->status == ResultSetStatus::Materialized);
    CHECK(rs->device_count == 3);
    CHECK(rs->name == "win-fleet");
    CHECK_FALSE(rs->pinned);

    auto got = get_ok(store, rs->id);
    REQUIRE(got.has_value());
    CHECK(got->owner_principal == "alice");

    std::string cursor;
    auto devs = store.members(rs->id, "", 100, cursor);
    REQUIRE(devs.size() == 3);
    CHECK(cursor.empty());
    CHECK(contains_ok(store, rs->id, "dev-b"));
    CHECK_FALSE(contains_ok(store, rs->id, "dev-z"));
}

TEST_CASE("ResultSetStore: lineage walks parent chain root-first", "[pg][result_set][lineage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto g = store.create_materialized(req("alice", "all"), {"a", "b", "c", "d"});
    REQUIRE(g.has_value());
    auto mid = store.create_materialized(req("alice", "windows", g->id), {"a", "b"});
    REQUIRE(mid.has_value());
    auto leaf = store.create_materialized(req("alice", "suspects", mid->id), {"a"});
    REQUIRE(leaf.has_value());

    auto chain = store.lineage(leaf->id, "alice");
    REQUIRE(chain.size() == 3);
    CHECK(chain.front().name == "all");     // root first
    CHECK(chain.back().name == "suspects"); // leaf last
    CHECK(chain.front().device_count == 4);
}

TEST_CASE("ResultSetStore: alias resolution is owner-scoped", "[pg][result_set][alias]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto a = store.create_materialized(req("alice", "chrome"), {"x"});
    REQUIRE(a.has_value());
    store.create_materialized(req("bob", "chrome"), {"y"});

    auto resolved = resolve_alias_ok(store, "alice", "chrome");
    REQUIRE(resolved.has_value());
    CHECK(*resolved == a->id);
    CHECK_FALSE(resolve_alias_ok(store, "alice", "nonexistent").has_value());
    CHECK_FALSE(resolve_alias_ok(store, "carol", "chrome").has_value());
}

TEST_CASE("ResultSetStore: pin/unpin and pinned-delete rejection", "[pg][result_set][pin]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto rs = store.create_materialized(req("alice", "pinme"), {"a"});
    REQUIRE(rs.has_value());

    auto pinned = store.pin(rs->id);
    REQUIRE(pinned.has_value());
    CHECK(pinned->pinned);
    CHECK(pinned->ttl_at == INT64_MAX);

    // Delete of a pinned set must be rejected.
    auto del = store.delete_set(rs->id);
    REQUIRE_FALSE(del.has_value());
    CHECK(del.error() == ResultSetError::Pinned);

    auto unpinned = store.unpin(rs->id);
    REQUIRE(unpinned.has_value());
    CHECK_FALSE(unpinned->pinned);
    CHECK(unpinned->ttl_at < INT64_MAX);

    // Now deletable.
    CHECK(store.delete_set(rs->id).has_value());
    CHECK_FALSE(get_ok(store, rs->id).has_value());
}

TEST_CASE("ResultSetStore: async create -> materialize", "[pg][result_set][async]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    CreateRequest r = req("alice", "tar-suspects");
    r.source_kind = std::string(source_kind::kTarQuery);
    r.source_payload = R"({"sql":"SELECT 1"})";
    auto rs = store.create_pending(r, "exec-123");
    REQUIRE(rs.has_value());
    CHECK(rs->status == ResultSetStatus::Pending);
    CHECK(rs->device_count == 0);

    auto pending = store.list_pending();
    REQUIRE(pending.size() == 1);
    CHECK(pending[0].source_execution_id == "exec-123");
    CHECK(pending[0].source_kind == source_kind::kTarQuery);

    auto m = store.materialize(rs->id, {"dev-1", "dev-2"});
    REQUIRE(m.has_value());

    auto got = get_ok(store, rs->id);
    REQUIRE(got.has_value());
    CHECK(got->status == ResultSetStatus::Materialized);
    CHECK(got->device_count == 2);
    CHECK(store.list_pending().empty());
    CHECK(contains_ok(store, rs->id, "dev-1"));
}

TEST_CASE("ResultSetStore: touch extends TTL", "[pg][result_set][ttl]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto rs = store.create_materialized(req("alice"), {"a"});
    REQUIRE(rs.has_value());
    int64_t orig_ttl = rs->ttl_at;

    store.touch(rs->id);
    auto got = get_ok(store, rs->id);
    REQUIRE(got.has_value());
    CHECK(got->ttl_at >= orig_ttl);
    CHECK(got->last_used_at >= rs->last_used_at);
}

TEST_CASE("ResultSetStore: GC sweep removes expired unpinned sets", "[pg][result_set][gc]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto live = store.create_materialized(req("alice", "live"), {"a"});
    auto pinned = store.create_materialized(req("alice", "kept"), {"b"});
    REQUIRE(live.has_value());
    REQUIRE(pinned.has_value());
    REQUIRE(store.pin(pinned->id).has_value());

    // No expired rows yet (default TTL is 1h in the future).
    CHECK(store.gc_sweep() == 0);
    CHECK(get_ok(store, live->id).has_value());
    CHECK(get_ok(store, pinned->id).has_value());
}

TEST_CASE("ResultSetStore: per-owner quota enforced", "[pg][result_set][quota]") {
    // The hard cap is 10k which is impractical to hit in a unit test directly,
    // so this asserts the count helper that drives the cap and a representative
    // create succeeds; the cap branch is covered by the REST-layer test.
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    for (int i = 0; i < 5; ++i)
        REQUIRE(store.create_materialized(req("alice"), {"a"}).has_value());
    CHECK(store.count_for_owner("alice") == 5);
    CHECK(store.count_for_owner("bob") == 0);
}

TEST_CASE("ResultSetStore: GC sweep deletes expired unpinned rows and returns the count",
          "[pg][result_set][gc]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto expired = store.create_materialized(req("alice", "stale"), {"a", "b"});
    auto pinned = store.create_materialized(req("alice", "kept"), {"c"});
    auto live = store.create_materialized(req("alice", "fresh"), {"d"});
    REQUIRE(expired.has_value());
    REQUIRE(pinned.has_value());
    REQUIRE(live.has_value());
    REQUIRE(store.pin(pinned->id).has_value());

    // Force the unpinned row's TTL into the past; pinned keeps INT64_MAX, live
    // stays an hour out. Only `expired` should be swept (exercises the actual
    // DELETE branch the prior GC test never hit — review finding O/D).
    // created_at must stay <= ttl_at (schema CHECK), so age the row wholesale.
    exec_sql(db.dsn(), "UPDATE result_set_store.result_sets SET created_at = 1, ttl_at = 2 WHERE "
                       "id = '" +
                          expired->id + "';");

    int swept = store.gc_sweep();
    CHECK(swept == 1);
    CHECK_FALSE(get_ok(store, expired->id).has_value());
    CHECK(get_ok(store, pinned->id).has_value());
    CHECK(get_ok(store, live->id).has_value());
    CHECK_FALSE(contains_ok(store, expired->id, "a")); // members cascade-deleted
}

TEST_CASE("ResultSetStore: per-set member cap is enforced", "[pg][result_set][cap]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    std::vector<std::string> members;
    members.reserve(ResultSetStore::kMaxMembersPerSet + 1);
    for (int i = 0; i <= ResultSetStore::kMaxMembersPerSet; ++i)
        members.push_back("dev-" + std::to_string(i));

    auto rs = store.create_materialized(req("alice", "toobig"), members);
    REQUIRE_FALSE(rs.has_value());
    CHECK(rs.error() == ResultSetError::TooManyMembers);
}

TEST_CASE("ResultSetStore: device_count reflects distinct members", "[pg][result_set][dedup]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto rs = store.create_materialized(req("alice", "dups"), {"a", "a", "b", "b", "b", "c"});
    REQUIRE(rs.has_value());
    CHECK(rs->device_count == 3); // ON CONFLICT DO NOTHING dedups; the count must agree (L)
    std::string cursor;
    CHECK(store.members(rs->id, "", 100, cursor).size() == 3);
}

TEST_CASE("ResultSetStore: member_set_owned is owner-scoped", "[pg][result_set][owner]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto rs = store.create_materialized(req("alice", "set"), {"a", "b", "c"});
    REQUIRE(rs.has_value());

    auto owned = member_set_owned_ok(store, rs->id, "alice");
    CHECK(owned.size() == 3);
    CHECK(owned.contains("b"));
    // A non-owner sees an empty membership — the authorization gate for B1.
    CHECK(member_set_owned_ok(store, rs->id, "bob").empty());
}

TEST_CASE("ResultSetStore: lineage stops at a cross-owner ancestor", "[pg][result_set][lineage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto root = store.create_materialized(req("alice", "alice-root"), {"a"});
    REQUIRE(root.has_value());
    // Bob parents his set onto alice's row (the store does not owner-check the
    // parent edge — the REST layer does). lineage(bob's leaf, "bob") must NOT
    // leak alice's node (review finding B2).
    auto leaf = store.create_materialized(req("bob", "bob-leaf", root->id), {"b"});
    REQUIRE(leaf.has_value());

    auto chain = store.lineage(leaf->id, "bob");
    REQUIRE(chain.size() == 1);
    CHECK(chain.front().name == "bob-leaf");

    auto achain = store.lineage(root->id, "alice"); // alice still sees her own
    REQUIRE(achain.size() == 1);
    CHECK(achain.front().name == "alice-root");
}

TEST_CASE("ResultSetStore: lineage terminates on a parent_id cycle", "[pg][result_set][lineage]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    auto a = store.create_materialized(req("alice", "A"), {"x"});
    auto b = store.create_materialized(req("alice", "B", a->id), {"y"});
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    // Close the loop A->B->A with a direct write the public API can't make (J).
    exec_sql(db.dsn(), "UPDATE result_set_store.result_sets SET parent_id = '" + b->id +
                          "' WHERE id = '" + a->id + "';");

    auto chain = store.lineage(a->id, "alice"); // must not spin forever
    CHECK(chain.size() <= static_cast<size_t>(ResultSetStore::kLineageDepthCap));
    CHECK(chain.size() >= 1);
}

TEST_CASE("ResultSetStore: members paginate past the page size", "[pg][result_set][pagination]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);

    std::vector<std::string> members;
    members.reserve(6000);
    for (int i = 0; i < 6000; ++i)
        members.push_back("dev-" + std::to_string(100000 + i)); // fixed width → sortable
    auto rs = store.create_materialized(req("alice", "big"), members);
    REQUIRE(rs.has_value());
    CHECK(rs->device_count == 6000);

    // Walk with separate in/out cursors (the correct idiom — review B3) and
    // confirm the loop terminates and returns every distinct member.
    std::unordered_set<std::string> seen;
    std::string cur;
    int iterations = 0;
    while (true) {
        std::string next;
        auto page = store.members(rs->id, cur, 5000, next);
        seen.insert(page.begin(), page.end());
        if (next.empty())
            break;
        cur = next;
        REQUIRE(++iterations < 10); // guard: must not loop forever
    }
    CHECK(seen.size() == 6000);
}

// gov fjarvis B1 (offline_endpoint_store precedent): a reachable database whose
// schema migration FAILS must leave the store !is_open() — server.cpp wires
// that to startup_failed_ (fail closed, not serve-degraded). Force the failure
// by pre-seeding a conflicting table with no schema_meta row: the migration
// runner's schema-drift guard refuses (version 0 but tables exist).
TEST_CASE("ResultSetStore reports !is_open on a migration failure", "[pg][result_set]") {
    YUZU_REQUIRE_PG_DB(db);

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA result_set_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE result_set_store.result_sets (bogus int)")};
        REQUIRE(t.ok());
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ResultSetStore store{pool};
    CHECK_FALSE(store.is_open()); // → server.cpp sets startup_failed_ = true
}

// Backfill (ADR-0009): idempotent, fails closed on a legacy-file read error,
// and is a safe no-op stamping the marker when no legacy file exists.
TEST_CASE("ResultSetStore::migrate_from_sqlite backfill contract", "[pg][result_set][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    SECTION("no legacy file: stamps the marker and returns true, idempotently") {
        auto missing = yuzu::test::unique_temp_path("yuzu_test_rs_missing") / "result_sets.db";
        CHECK(store.migrate_from_sqlite(missing));
        CHECK(store.migrate_from_sqlite(missing)); // second call is a no-op success
    }

    SECTION("already backfilled: a second call is a cheap no-op success") {
        auto missing = yuzu::test::unique_temp_path("yuzu_test_rs_missing2") / "result_sets.db";
        REQUIRE(store.migrate_from_sqlite(missing));
        // Even though the (still-missing) path never changes, the marker row
        // short-circuits before any filesystem check on the second call.
        CHECK(store.migrate_from_sqlite(missing));
    }
}
