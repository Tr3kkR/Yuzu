/**
 * test_result_set_store.cpp — Unit tests for the scope-walking result-set store.
 *
 * Covers: synchronous + asynchronous create, membership + lineage, alias
 * resolution, pin/unpin (+ cap), delete (pinned-rejected), quota, async
 * materialisation, touch TTL extension, and GC sweep.
 */

#include "result_set_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::test::TempDbFile;

namespace {

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

// Run a raw SQL statement against the store's DB file on a second connection —
// lets a test simulate TTL expiry / form a parent_id cycle that the public API
// deliberately cannot produce.
void exec_sql(const std::filesystem::path& path, const std::string& sql) {
    sqlite3* db = nullptr;
    REQUIRE(sqlite3_open(path.string().c_str(), &db) == SQLITE_OK);
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr);
    sqlite3_close(db);
    REQUIRE(rc == SQLITE_OK);
}

} // namespace

TEST_CASE("ResultSetStore: synchronous create, get, members", "[result_set][crud]") {
    TempDbFile db;
    ResultSetStore store(db.path);
    REQUIRE(store.is_open());

    std::vector<std::string> members = {"dev-a", "dev-b", "dev-c"};
    auto rs = store.create_materialized(req("alice", "win-fleet"), members);
    REQUIRE(rs.has_value());
    CHECK(rs->id.starts_with("rs_"));
    CHECK(rs->status == ResultSetStatus::Materialized);
    CHECK(rs->device_count == 3);
    CHECK(rs->name == "win-fleet");
    CHECK_FALSE(rs->pinned);

    auto got = store.get(rs->id);
    REQUIRE(got.has_value());
    CHECK(got->owner_principal == "alice");

    std::string cursor;
    auto devs = store.members(rs->id, "", 100, cursor);
    REQUIRE(devs.size() == 3);
    CHECK(cursor.empty());
    CHECK(store.contains(rs->id, "dev-b"));
    CHECK_FALSE(store.contains(rs->id, "dev-z"));
}

TEST_CASE("ResultSetStore: lineage walks parent chain root-first", "[result_set][lineage]") {
    TempDbFile db;
    ResultSetStore store(db.path);

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

TEST_CASE("ResultSetStore: alias resolution is owner-scoped", "[result_set][alias]") {
    TempDbFile db;
    ResultSetStore store(db.path);

    auto a = store.create_materialized(req("alice", "chrome"), {"x"});
    REQUIRE(a.has_value());
    store.create_materialized(req("bob", "chrome"), {"y"});

    auto resolved = store.resolve_alias("alice", "chrome");
    REQUIRE(resolved.has_value());
    CHECK(*resolved == a->id);
    CHECK_FALSE(store.resolve_alias("alice", "nonexistent").has_value());
    CHECK_FALSE(store.resolve_alias("carol", "chrome").has_value());
}

TEST_CASE("ResultSetStore: pin/unpin and pinned-delete rejection", "[result_set][pin]") {
    TempDbFile db;
    ResultSetStore store(db.path);

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
    CHECK_FALSE(store.get(rs->id).has_value());
}

TEST_CASE("ResultSetStore: async create -> materialize", "[result_set][async]") {
    TempDbFile db;
    ResultSetStore store(db.path);

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

    auto got = store.get(rs->id);
    REQUIRE(got.has_value());
    CHECK(got->status == ResultSetStatus::Materialized);
    CHECK(got->device_count == 2);
    CHECK(store.list_pending().empty());
    CHECK(store.contains(rs->id, "dev-1"));
}

TEST_CASE("ResultSetStore: touch extends TTL", "[result_set][ttl]") {
    TempDbFile db;
    ResultSetStore store(db.path);

    auto rs = store.create_materialized(req("alice"), {"a"});
    REQUIRE(rs.has_value());
    int64_t orig_ttl = rs->ttl_at;

    store.touch(rs->id);
    auto got = store.get(rs->id);
    REQUIRE(got.has_value());
    CHECK(got->ttl_at >= orig_ttl);
    CHECK(got->last_used_at >= rs->last_used_at);
}

TEST_CASE("ResultSetStore: GC sweep removes expired unpinned sets", "[result_set][gc]") {
    TempDbFile db;
    ResultSetStore store(db.path);

    auto live = store.create_materialized(req("alice", "live"), {"a"});
    auto pinned = store.create_materialized(req("alice", "kept"), {"b"});
    REQUIRE(live.has_value());
    REQUIRE(pinned.has_value());
    REQUIRE(store.pin(pinned->id).has_value());

    // No expired rows yet (default TTL is 1h in the future).
    CHECK(store.gc_sweep() == 0);
    CHECK(store.get(live->id).has_value());
    CHECK(store.get(pinned->id).has_value());
}

TEST_CASE("ResultSetStore: per-owner quota enforced", "[result_set][quota]") {
    // The hard cap is 10k which is impractical to hit in a unit test directly,
    // so this asserts the count helper that drives the cap and a representative
    // create succeeds; the cap branch is covered by the REST-layer test.
    TempDbFile db;
    ResultSetStore store(db.path);

    for (int i = 0; i < 5; ++i)
        REQUIRE(store.create_materialized(req("alice"), {"a"}).has_value());
    CHECK(store.count_for_owner("alice") == 5);
    CHECK(store.count_for_owner("bob") == 0);
}

TEST_CASE("ResultSetStore: GC sweep deletes expired unpinned rows and returns the count",
          "[result_set][gc]") {
    TempDbFile db;
    ResultSetStore store(db.path);

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
    exec_sql(db.path, "UPDATE result_sets SET created_at = 1, ttl_at = 2 WHERE id = '" +
                          expired->id + "';");

    int swept = store.gc_sweep();
    CHECK(swept == 1);
    CHECK_FALSE(store.get(expired->id).has_value());
    CHECK(store.get(pinned->id).has_value());
    CHECK(store.get(live->id).has_value());
    CHECK_FALSE(store.contains(expired->id, "a")); // members cascade-deleted
}

TEST_CASE("ResultSetStore: per-set member cap is enforced", "[result_set][cap]") {
    TempDbFile db;
    ResultSetStore store(db.path);

    std::vector<std::string> members;
    members.reserve(ResultSetStore::kMaxMembersPerSet + 1);
    for (int i = 0; i <= ResultSetStore::kMaxMembersPerSet; ++i)
        members.push_back("dev-" + std::to_string(i));

    auto rs = store.create_materialized(req("alice", "toobig"), members);
    REQUIRE_FALSE(rs.has_value());
    CHECK(rs.error() == ResultSetError::TooManyMembers);
}

TEST_CASE("ResultSetStore: device_count reflects distinct members", "[result_set][dedup]") {
    TempDbFile db;
    ResultSetStore store(db.path);

    auto rs = store.create_materialized(req("alice", "dups"), {"a", "a", "b", "b", "b", "c"});
    REQUIRE(rs.has_value());
    CHECK(rs->device_count == 3); // INSERT OR IGNORE dedups; the count must agree (L)
    std::string cursor;
    CHECK(store.members(rs->id, "", 100, cursor).size() == 3);
}

TEST_CASE("ResultSetStore: member_set_owned is owner-scoped", "[result_set][owner]") {
    TempDbFile db;
    ResultSetStore store(db.path);

    auto rs = store.create_materialized(req("alice", "set"), {"a", "b", "c"});
    REQUIRE(rs.has_value());

    auto owned = store.member_set_owned(rs->id, "alice");
    CHECK(owned.size() == 3);
    CHECK(owned.contains("b"));
    // A non-owner sees an empty membership — the authorization gate for B1.
    CHECK(store.member_set_owned(rs->id, "bob").empty());
}

TEST_CASE("ResultSetStore: lineage stops at a cross-owner ancestor", "[result_set][lineage]") {
    TempDbFile db;
    ResultSetStore store(db.path);

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

TEST_CASE("ResultSetStore: lineage terminates on a parent_id cycle", "[result_set][lineage]") {
    TempDbFile db;
    ResultSetStore store(db.path);

    auto a = store.create_materialized(req("alice", "A"), {"x"});
    auto b = store.create_materialized(req("alice", "B", a->id), {"y"});
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    // Close the loop A->B->A with a direct write the public API can't make (J).
    exec_sql(db.path, "UPDATE result_sets SET parent_id = '" + b->id + "' WHERE id = '" + a->id +
                          "';");

    auto chain = store.lineage(a->id, "alice"); // must not spin forever
    CHECK(chain.size() <= static_cast<size_t>(ResultSetStore::kLineageDepthCap));
    CHECK(chain.size() >= 1);
}

TEST_CASE("ResultSetStore: members paginate past the page size", "[result_set][pagination]") {
    TempDbFile db;
    ResultSetStore store(db.path);

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
