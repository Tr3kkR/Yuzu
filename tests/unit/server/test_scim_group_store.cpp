/**
 * test_scim_group_store.cpp — Unit tests for the SCIM v2 Groups storage layer
 * (#2021, slice 2: storage + config foundation only — no routes, no JSON
 * codec, no role-application logic).
 *
 * Covers:
 *   - migration to schema version 2 creates scim_groups + scim_group_members
 *   - group CRUD round-trip (create/get by id/get by display_name/update/delete)
 *   - list_groups() pagination + count_groups() total
 *   - membership: add/remove/set (replace-all) + both idempotent no-ops
 *   - list_group_member_user_scim_ids (forward lookup)
 *   - list_group_display_names_for_user (the reverse lookup the role-
 *     application task depends on) across multiple groups
 *   - delete_group cascades its scim_group_members rows away, so the reverse
 *     lookup never dangles on a deleted group
 */

#include <yuzu/server/scim_store.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <fstream>
#include <string_view>

using namespace yuzu::server;

namespace {

/// Pre-create an empty file at `path`. Production ScimStore no longer opens
/// with SQLITE_OPEN_CREATE (S-DROP-CREATE — AuthDB is always the one that
/// creates+chmods-0600 auth.db first, see scim_store.cpp), so a standalone-
/// ScimStore fixture with no live AuthDB in the loop must ensure the file
/// exists before construction.
bool touch_file(const std::filesystem::path& path) {
    std::ofstream f(path, std::ios::binary);
    return f.good();
}

/// Owns a standalone ScimStore over its own temp file.
struct ScimFixture {
    yuzu::test::TempDbFile db_file{std::string_view{"yuzu-scim-group-"}};
    bool touched_{touch_file(db_file.path)};
    ScimStore store{db_file.path};
};

} // namespace

// ── Migration ─────────────────────────────────────────────────────────────

TEST_CASE("ScimStore: migration to v2 creates scim_groups and scim_group_members",
         "[scim][group][migration]") {
    ScimFixture f;
    REQUIRE(f.store.is_open());

    // Exercised indirectly: if the tables didn't exist, every group/member
    // call below would fail outright rather than returning an empty/false
    // result — this is the black-box confirmation the migration ran.
    auto created = f.store.create_group("Engineering");
    REQUIRE(created.has_value());

    int total = -1;
    auto groups = f.store.list_groups(1, 10, total);
    CHECK(total == 1);
    REQUIRE(groups.size() == 1);
    CHECK(groups[0].display_name == "Engineering");

    CHECK(f.store.add_group_member(created->scim_id, "user-1"));
    auto members = f.store.list_group_member_user_scim_ids(created->scim_id);
    REQUIRE(members.size() == 1);
    CHECK(members[0] == "user-1");
}

// ── Group CRUD ────────────────────────────────────────────────────────────

TEST_CASE("ScimStore: create_group round-trips through every getter", "[scim][group]") {
    ScimFixture f;

    auto created = f.store.create_group("Engineering", "ext-grp-1");
    REQUIRE(created.has_value());
    CHECK_FALSE(created->scim_id.empty());
    CHECK(created->external_id == "ext-grp-1");
    CHECK(created->display_name == "Engineering");
    CHECK(created->active);
    CHECK(created->etag_version == 1);
    CHECK_FALSE(created->created_at.empty());
    CHECK_FALSE(created->updated_at.empty());

    auto by_id = f.store.get_group_by_id(created->scim_id);
    REQUIRE(by_id.has_value());
    CHECK(by_id->display_name == "Engineering");

    auto by_name = f.store.get_group_by_display_name("Engineering");
    REQUIRE(by_name.has_value());
    CHECK(by_name->scim_id == created->scim_id);
}

TEST_CASE("ScimStore: group lookups miss cleanly for absent keys", "[scim][group]") {
    ScimFixture f;

    CHECK_FALSE(f.store.get_group_by_id("does-not-exist").has_value());
    CHECK_FALSE(f.store.get_group_by_display_name("Nobody").has_value());
}

TEST_CASE("ScimStore: create_group rejects an empty display_name", "[scim][group]") {
    ScimFixture f;
    CHECK_FALSE(f.store.create_group("").has_value());
}

TEST_CASE("ScimStore: update_group changes fields and bumps etag", "[scim][group]") {
    ScimFixture f;
    auto created = f.store.create_group("Sales", "ext-1");
    REQUIRE(created.has_value());

    REQUIRE(f.store.update_group(created->scim_id, "Sales EMEA", "ext-2"));

    auto after = f.store.get_group_by_id(created->scim_id);
    REQUIRE(after.has_value());
    CHECK(after->display_name == "Sales EMEA");
    CHECK(after->external_id == "ext-2");
    CHECK(after->etag_version == 2);

    // Old display_name no longer resolves; new one does.
    CHECK_FALSE(f.store.get_group_by_display_name("Sales").has_value());
    CHECK(f.store.get_group_by_display_name("Sales EMEA").has_value());
}

TEST_CASE("ScimStore: update_group on unknown scim_id fails", "[scim][group]") {
    ScimFixture f;
    CHECK_FALSE(f.store.update_group("no-such-id", "X", ""));
}

TEST_CASE("ScimStore: list_groups paginates with 1-based startIndex and reports total",
         "[scim][group][list]") {
    ScimFixture f;
    for (int i = 0; i < 5; ++i) {
        REQUIRE(f.store.create_group("group" + std::to_string(i)).has_value());
    }

    CHECK(f.store.count_groups() == 5);

    int total = -1;
    auto page1 = f.store.list_groups(/*start_index=*/1, /*count=*/2, total);
    CHECK(total == 5);
    REQUIRE(page1.size() == 2);
    CHECK(page1[0].display_name == "group0");
    CHECK(page1[1].display_name == "group1");

    auto page2 = f.store.list_groups(/*start_index=*/3, /*count=*/2, total);
    CHECK(total == 5);
    REQUIRE(page2.size() == 2);
    CHECK(page2[0].display_name == "group2");
    CHECK(page2[1].display_name == "group3");

    auto page3 = f.store.list_groups(/*start_index=*/5, /*count=*/2, total);
    CHECK(total == 5);
    REQUIRE(page3.size() == 1);
    CHECK(page3[0].display_name == "group4");
}

// ── Group deletion ────────────────────────────────────────────────────────

TEST_CASE("ScimStore: delete_group removes the row", "[scim][group]") {
    ScimFixture f;
    auto created = f.store.create_group("Temp");
    REQUIRE(created.has_value());

    auto first = f.store.delete_group(created->scim_id);
    REQUIRE(first.has_value());
    CHECK(*first);
    CHECK_FALSE(f.store.get_group_by_id(created->scim_id).has_value());

    // Idempotent: deleting again reports "no match" (false), not a DB error
    // (nullopt) — mirrors delete_by_scim_id's tri-state contract.
    auto second = f.store.delete_group(created->scim_id);
    REQUIRE(second.has_value());
    CHECK_FALSE(*second);
}

TEST_CASE("ScimStore: delete_group cascades membership rows, reverse lookup no longer sees it",
         "[scim][group]") {
    ScimFixture f;
    auto grp = f.store.create_group("Doomed");
    REQUIRE(grp.has_value());
    REQUIRE(f.store.add_group_member(grp->scim_id, "user-cascade"));

    // Pre-condition: the reverse lookup sees the group before deletion.
    auto before = f.store.list_group_display_names_for_user("user-cascade");
    REQUIRE(before.size() == 1);
    CHECK(before[0] == "Doomed");

    auto deleted = f.store.delete_group(grp->scim_id);
    REQUIRE(deleted.has_value());
    CHECK(*deleted);

    // The join-table row is gone too (not just harmless) — the reverse
    // lookup for this user is now empty, and the forward lookup on the
    // deleted group_scim_id is empty.
    auto after = f.store.list_group_display_names_for_user("user-cascade");
    CHECK(after.empty());
    auto members = f.store.list_group_member_user_scim_ids(grp->scim_id);
    CHECK(members.empty());
}

// ── Membership ────────────────────────────────────────────────────────────

TEST_CASE("ScimStore: add_group_member is idempotent", "[scim][group][membership]") {
    ScimFixture f;
    auto grp = f.store.create_group("Team");
    REQUIRE(grp.has_value());

    CHECK(f.store.add_group_member(grp->scim_id, "user-a"));
    CHECK(f.store.add_group_member(grp->scim_id, "user-a")); // no-op, still true

    auto members = f.store.list_group_member_user_scim_ids(grp->scim_id);
    REQUIRE(members.size() == 1);
    CHECK(members[0] == "user-a");
}

TEST_CASE("ScimStore: remove_group_member is idempotent", "[scim][group][membership]") {
    ScimFixture f;
    auto grp = f.store.create_group("Team");
    REQUIRE(grp.has_value());
    REQUIRE(f.store.add_group_member(grp->scim_id, "user-a"));

    CHECK(f.store.remove_group_member(grp->scim_id, "user-a"));
    CHECK(f.store.list_group_member_user_scim_ids(grp->scim_id).empty());

    // Removing an absent member is still a harmless success, not a failure.
    CHECK(f.store.remove_group_member(grp->scim_id, "user-a"));
    CHECK(f.store.remove_group_member(grp->scim_id, "never-was-a-member"));
}

TEST_CASE("ScimStore: set_group_members replaces the full membership set",
         "[scim][group][membership]") {
    ScimFixture f;
    auto grp = f.store.create_group("Team");
    REQUIRE(grp.has_value());
    REQUIRE(f.store.add_group_member(grp->scim_id, "stale-1"));
    REQUIRE(f.store.add_group_member(grp->scim_id, "stale-2"));

    REQUIRE(f.store.set_group_members(grp->scim_id, {"user-a", "user-b", "user-c"}));

    auto members = f.store.list_group_member_user_scim_ids(grp->scim_id);
    std::sort(members.begin(), members.end());
    REQUIRE(members.size() == 3);
    CHECK(members[0] == "user-a");
    CHECK(members[1] == "user-b");
    CHECK(members[2] == "user-c");

    // Replace with a smaller/disjoint set — the stale members must be gone.
    REQUIRE(f.store.set_group_members(grp->scim_id, {"user-z"}));
    auto after = f.store.list_group_member_user_scim_ids(grp->scim_id);
    REQUIRE(after.size() == 1);
    CHECK(after[0] == "user-z");
}

TEST_CASE("ScimStore: set_group_members with an empty vector clears membership",
         "[scim][group][membership]") {
    ScimFixture f;
    auto grp = f.store.create_group("Team");
    REQUIRE(grp.has_value());
    REQUIRE(f.store.add_group_member(grp->scim_id, "user-a"));

    REQUIRE(f.store.set_group_members(grp->scim_id, {}));
    CHECK(f.store.list_group_member_user_scim_ids(grp->scim_id).empty());
}

// ── Reverse lookup (role-application dependency) ─────────────────────────

TEST_CASE("ScimStore: list_group_display_names_for_user spans multiple groups",
         "[scim][group][membership][reverse]") {
    ScimFixture f;
    auto eng = f.store.create_group("Engineering");
    auto ops = f.store.create_group("Ops");
    auto sales = f.store.create_group("Sales");
    REQUIRE(eng.has_value());
    REQUIRE(ops.has_value());
    REQUIRE(sales.has_value());

    REQUIRE(f.store.add_group_member(eng->scim_id, "user-multi"));
    REQUIRE(f.store.add_group_member(ops->scim_id, "user-multi"));
    // user-multi is deliberately NOT added to Sales.
    REQUIRE(f.store.add_group_member(sales->scim_id, "user-other"));

    auto names = f.store.list_group_display_names_for_user("user-multi");
    std::sort(names.begin(), names.end());
    REQUIRE(names.size() == 2);
    CHECK(names[0] == "Engineering");
    CHECK(names[1] == "Ops");

    auto other = f.store.list_group_display_names_for_user("user-other");
    REQUIRE(other.size() == 1);
    CHECK(other[0] == "Sales");

    auto none = f.store.list_group_display_names_for_user("user-none");
    CHECK(none.empty());
}
