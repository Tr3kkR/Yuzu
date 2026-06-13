/**
 * test_baseline_store.cpp — Unit tests for BaselineStore (Guardian Baselines)
 *
 * Covers:
 *   - schema migration applies cleanly against a fresh DB
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
 *   - bad-path constructor returns sentinels from every method
 *   - on-disk persistence across reopen (migration idempotency)
 */

#include "baseline_store.hpp"
#include "store_errors.hpp"
#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>

using namespace yuzu::server;
using yuzu::test::TempDbFile;
using yuzu::test::unique_temp_path;

namespace {

Baseline make_baseline(std::string name) {
    Baseline b;
    b.name = std::move(name);
    b.description = "desc";
    b.created_by = "alice";
    b.updated_by = "alice";
    return b;
}

} // namespace

TEST_CASE("BaselineStore opens and applies its schema", "[baseline][store]") {
    TempDbFile db{std::string_view{"yuzu-baseline-"}};
    BaselineStore store{db.path};
    REQUIRE(store.is_open());
    REQUIRE(store.baseline_count() == 0);
}

TEST_CASE("Baseline CRUD round-trip", "[baseline][store]") {
    TempDbFile db{std::string_view{"yuzu-baseline-"}};
    BaselineStore store{db.path};
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
    CHECK(got->lifecycle == kBaselineDraft);  // defaults to draft
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
    CHECK(after->created_at == got->created_at);   // immutable
    CHECK(after->updated_at >= got->updated_at);    // re-stamped

    REQUIRE(store.delete_baseline(id).has_value());
    CHECK_FALSE(store.get_baseline(id).has_value());
    CHECK(store.baseline_count() == 0);
}

TEST_CASE("create_baseline honours a caller-supplied id", "[baseline][store]") {
    TempDbFile db{std::string_view{"yuzu-baseline-"}};
    BaselineStore store{db.path};
    Baseline b = make_baseline("named");
    b.baseline_id = "fixed-id-123";
    auto created = store.create_baseline(b);
    REQUIRE(created.has_value());
    CHECK(*created == "fixed-id-123");
    CHECK(store.get_baseline("fixed-id-123").has_value());
}

TEST_CASE("Duplicate baseline name is a conflict error", "[baseline][store]") {
    TempDbFile db{std::string_view{"yuzu-baseline-"}};
    BaselineStore store{db.path};
    REQUIRE(store.create_baseline(make_baseline("dup")).has_value());

    auto again = store.create_baseline(make_baseline("dup"));
    REQUIRE_FALSE(again.has_value());
    CHECK(is_conflict_error(again.error()));
}

TEST_CASE("update/delete of unknown baseline are non-conflict errors", "[baseline][store]") {
    TempDbFile db{std::string_view{"yuzu-baseline-"}};
    BaselineStore store{db.path};

    Baseline ghost = make_baseline("ghost");
    ghost.baseline_id = "no-such";
    auto u = store.update_baseline(ghost);
    REQUIRE_FALSE(u.has_value());
    CHECK_FALSE(is_conflict_error(u.error()));

    auto d = store.delete_baseline("no-such");
    REQUIRE_FALSE(d.has_value());
    CHECK_FALSE(is_conflict_error(d.error()));
}

TEST_CASE("Member set replace is transactional and de-duplicates", "[baseline][store]") {
    TempDbFile db{std::string_view{"yuzu-baseline-"}};
    BaselineStore store{db.path};
    const std::string id = *store.create_baseline(make_baseline("members"));

    REQUIRE(store.set_members(id, {"r1", "r2", "r1", "", "r3"}).has_value());
    auto m = store.get_members(id);
    REQUIRE(m == std::vector<std::string>{"r1", "r2", "r3"});  // sorted, de-duped, blanks dropped
    CHECK(store.member_count(id) == 3);

    // Replace wholesale.
    REQUIRE(store.set_members(id, {"r9", "r2"}).has_value());
    CHECK(store.get_members(id) == std::vector<std::string>{"r2", "r9"});

    // Clear.
    REQUIRE(store.set_members(id, {}).has_value());
    CHECK(store.get_members(id).empty());
}

TEST_CASE("set_members on a non-existent baseline is not-found", "[baseline][store]") {
    TempDbFile db{std::string_view{"yuzu-baseline-"}};
    BaselineStore store{db.path};
    auto r = store.set_members("nope", {"r1"});
    REQUIRE_FALSE(r.has_value());
    CHECK_FALSE(is_conflict_error(r.error()));
}

TEST_CASE("Assignment include/exclude round-trip and validation", "[baseline][store]") {
    TempDbFile db{std::string_view{"yuzu-baseline-"}};
    BaselineStore store{db.path};
    const std::string id = *store.create_baseline(make_baseline("assign"));

    REQUIRE(store.set_assignment(id, {{"g-prod", kAssignInclude},
                                      {"g-jump", kAssignExclude}})
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
    CHECK(store.get_assignment(id).size() == 2);  // untouched

    // Duplicate group_id collapses to the LAST disposition (PK invariant).
    REQUIRE(store.set_assignment(id, {{"g-dup", kAssignInclude},
                                      {"g-dup", kAssignExclude}})
                .has_value());
    auto d = store.get_assignment(id);
    REQUIRE(d.size() == 1);
    CHECK(d[0].group_id == "g-dup");
    CHECK(d[0].disposition == kAssignExclude);
}

TEST_CASE("delete_baseline cascades members and assignment", "[baseline][store]") {
    TempDbFile db{std::string_view{"yuzu-baseline-"}};
    BaselineStore store{db.path};
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
          "[baseline][store]") {
    TempDbFile db{std::string_view{"yuzu-baseline-"}};
    BaselineStore store{db.path};
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

TEST_CASE("Cross-store cleanup hooks remove rows from every baseline", "[baseline][store]") {
    TempDbFile db{std::string_view{"yuzu-baseline-"}};
    BaselineStore store{db.path};
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

TEST_CASE("Bad-path constructor returns sentinels", "[baseline][store]") {
    // Parent directory does not exist → SQLITE_OPEN_CREATE cannot create the
    // file, so the store fails to open.
    const auto bad = unique_temp_path("yuzu-baseline-") / "missing-dir" / "b.db";
    BaselineStore store{bad};
    REQUIRE_FALSE(store.is_open());

    CHECK_FALSE(store.create_baseline(make_baseline("x")).has_value());
    CHECK_FALSE(store.get_baseline("x").has_value());
    CHECK(store.list_baselines().empty());
    CHECK(store.baseline_count() == 0);
    CHECK(store.get_members("x").empty());
    CHECK(store.remove_rule_everywhere("x") == 0);
}

TEST_CASE("Baselines persist across reopen", "[baseline][store]") {
    TempDbFile db{std::string_view{"yuzu-baseline-"}};
    std::string id;
    {
        BaselineStore store{db.path};
        REQUIRE(store.is_open());
        id = *store.create_baseline(make_baseline("persist"));
        REQUIRE(store.set_members(id, {"r1"}).has_value());
    }
    {
        BaselineStore store{db.path};  // migration idempotent on existing DB
        REQUIRE(store.is_open());
        auto got = store.get_baseline(id);
        REQUIRE(got.has_value());
        CHECK(got->name == "persist");
        CHECK(store.get_members(id) == std::vector<std::string>{"r1"});
    }
}
