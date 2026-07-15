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

#include "migration_runner.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

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

namespace {

bool table_exists(sqlite3* db, const char* table) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT name FROM sqlite_master WHERE type='table' AND name=?1",
                          -1, &stmt, nullptr) != SQLITE_OK)
        return false;
    sqlite3_bind_text(stmt, 1, table, -1, SQLITE_TRANSIENT);
    bool found = sqlite3_step(stmt) == SQLITE_ROW;
    sqlite3_finalize(stmt);
    return found;
}

} // namespace

// qa-8: migration v1 -> v2 from a genuinely pre-existing v1 database (not a
// freshly-created-at-v2 store, unlike the test above). Duplicates the v1-
// only migration SQL (mirrors scim_store.cpp's kScimMigrations[0] — kept in
// sync manually, same pattern as test_auth_sso_identity.cpp's kV1ToV5)
// so a raw connection can be pinned at exactly v1 before ScimStore ever
// touches the file.
const std::vector<Migration> kScimV1Only = {
    {1, R"(
        CREATE TABLE IF NOT EXISTS scim_resources (
            scim_id TEXT PRIMARY KEY,
            external_id TEXT,
            username TEXT NOT NULL UNIQUE,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            etag_version INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_scim_resources_external_id
            ON scim_resources(external_id);

        CREATE TABLE IF NOT EXISTS scim_tokens (
            id INTEGER PRIMARY KEY,
            token_hash TEXT NOT NULL,
            label TEXT,
            created_at TEXT NOT NULL,
            revoked_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_scim_tokens_active
            ON scim_tokens(revoked_at) WHERE revoked_at IS NULL;
    )"},
};

TEST_CASE("ScimStore: migration v1 -> v2 from an existing v1 db preserves scim_resources rows "
         "(qa-8)",
         "[scim][group][migration]") {
    yuzu::test::TempDbFile db_file{std::string_view{"yuzu-scim-group-migration-"}};

    // Build a genuine pre-#2021 (v1) scim schema and seed a scim_resources
    // row, entirely via a raw connection — ScimStore never touches the file
    // at this point. Inner scope: close the raw handle before ScimStore
    // reopens the SAME file (Windows can't open a file another handle still
    // holds — same rationale as test_auth_sso_identity.cpp's migration
    // test).
    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open_v2(db_file.path.string().c_str(), &raw,
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                                nullptr) == SQLITE_OK);
        REQUIRE(MigrationRunner::run(raw, "scim", kScimV1Only));
        REQUIRE(MigrationRunner::current_version(raw, "scim") == 1);
        CHECK_FALSE(table_exists(raw, "scim_groups"));
        CHECK_FALSE(table_exists(raw, "scim_group_members"));

        char* err = nullptr;
        int rc = sqlite3_exec(raw,
                              "INSERT INTO scim_resources (scim_id, external_id, username, "
                              "active, created_at, updated_at, etag_version) VALUES "
                              "('res1', '', 'legacyuser', 1, '2026-01-01', '2026-01-01', 1)",
                              nullptr, nullptr, &err);
        REQUIRE(rc == SQLITE_OK);
        sqlite3_close(raw);
    }

    // Open via the production path — this applies ONLY v2 (current==1).
    ScimStore store(db_file.path);
    REQUIRE(store.is_open());

    // The pre-existing scim_resources row survived the migration untouched.
    auto legacy = store.get_by_username("legacyuser");
    REQUIRE(legacy.has_value());
    CHECK(legacy->scim_id == "res1");

    // The new Groups tables now exist and are fully functional.
    {
        sqlite3* ro = nullptr;
        REQUIRE(sqlite3_open_v2(db_file.path.string().c_str(), &ro, SQLITE_OPEN_READONLY,
                                nullptr) == SQLITE_OK);
        CHECK(table_exists(ro, "scim_groups"));
        CHECK(table_exists(ro, "scim_group_members"));
        sqlite3_close(ro);
    }

    auto created = store.create_group("Engineering");
    REQUIRE(created.has_value());
    CHECK(store.add_group_member(created->scim_id, legacy->scim_id));
    auto members = store.list_group_member_user_scim_ids(created->scim_id);
    REQUIRE(members.size() == 1);
    CHECK(members[0] == legacy->scim_id);
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

// ── Atomic replace (replace_group_and_members, #2127 review fix) ──────────
//
// PUT/PATCH previously committed the display_name rename (update_group) and
// the membership change (set_group_members) as separate transactions, so a
// membership-write failure after a committed rename left partial state +
// stale roles. replace_group_and_members is the durable one-transaction fix.

TEST_CASE("ScimStore: replace_group_and_members updates identity and membership together",
         "[scim][group][membership][atomic]") {
    ScimFixture f;
    auto grp = f.store.create_group("Sales", "ext-1");
    REQUIRE(grp.has_value());
    REQUIRE(f.store.add_group_member(grp->scim_id, "stale-1"));
    REQUIRE(f.store.add_group_member(grp->scim_id, "stale-2"));

    auto result =
        f.store.replace_group_and_members(grp->scim_id, "Sales EMEA", "ext-2",
                                          {"user-a", "user-b"});
    REQUIRE(result.has_value());
    CHECK(*result);

    auto after = f.store.get_group_by_id(grp->scim_id);
    REQUIRE(after.has_value());
    CHECK(after->display_name == "Sales EMEA");
    CHECK(after->external_id == "ext-2");
    CHECK(after->etag_version == 2);

    auto members = f.store.list_group_member_user_scim_ids(grp->scim_id);
    std::sort(members.begin(), members.end());
    REQUIRE(members.size() == 2);
    CHECK(members[0] == "user-a");
    CHECK(members[1] == "user-b");
}

TEST_CASE("ScimStore: replace_group_and_members on unknown scim_id returns false, no side effects",
         "[scim][group][membership][atomic]") {
    ScimFixture f;
    auto result =
        f.store.replace_group_and_members("no-such-id", "X", "", {"user-a"});
    REQUIRE(result.has_value());
    CHECK_FALSE(*result);

    // No stray group or membership row was created.
    CHECK_FALSE(f.store.get_group_by_id("no-such-id").has_value());
    CHECK(f.store.list_group_member_user_scim_ids("no-such-id").empty());
}

TEST_CASE("ScimStore: replace_group_and_members rolls back fully on a mid-transaction failure "
         "(safety-S2)",
         "[scim][group][membership][atomic][transaction]") {
    ScimFixture f;
    auto grp = f.store.create_group("Sales", "ext-1");
    REQUIRE(grp.has_value());
    REQUIRE(f.store.set_group_members(grp->scim_id, {"old-a", "old-b"}));

    // Poison a specific member id so the INSERT loop fails partway through,
    // AFTER the display_name UPDATE and the membership-clearing DELETE have
    // already run in the same transaction.
    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open_v2(f.db_file.path.string().c_str(), &raw, SQLITE_OPEN_READWRITE,
                                nullptr) == SQLITE_OK);
        REQUIRE(sqlite3_exec(raw,
                            "CREATE TRIGGER poison_replace_insert BEFORE INSERT ON "
                            "scim_group_members WHEN NEW.user_scim_id = 'POISON' "
                            "BEGIN SELECT RAISE(ABORT, 'induced failure'); END;",
                            nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }

    auto result = f.store.replace_group_and_members(grp->scim_id, "Sales EMEA", "ext-2",
                                                     {"new-1", "POISON", "new-2"});
    REQUIRE_FALSE(result.has_value());

    // Neither half of the write leaked: the rename did NOT persist...
    auto after = f.store.get_group_by_id(grp->scim_id);
    REQUIRE(after.has_value());
    CHECK(after->display_name == "Sales");
    CHECK(after->external_id == "ext-1");
    CHECK(after->etag_version == 1);

    // ...and the pre-existing membership is UNCHANGED (the clearing DELETE
    // that ran earlier in the same transaction was also rolled back).
    auto members = f.store.list_group_member_user_scim_ids(grp->scim_id);
    std::sort(members.begin(), members.end());
    REQUIRE(members.size() == 2);
    CHECK(members[0] == "old-a");
    CHECK(members[1] == "old-b");
}

TEST_CASE("ScimStore: replace_group_and_members embedded-NUL display_name round-trips at full "
         "length",
         "[scim][group][membership][atomic][embedded_nul]") {
    ScimFixture f;
    auto grp = f.store.create_group("Team");
    REQUIRE(grp.has_value());

    std::string name = std::string("Admins") + std::string(1, '\0') + std::string("decoy");
    REQUIRE(name.size() == 12);

    auto result = f.store.replace_group_and_members(grp->scim_id, name, "", {"user-a"});
    REQUIRE(result.has_value());
    CHECK(*result);

    auto after = f.store.get_group_by_id(grp->scim_id);
    REQUIRE(after.has_value());
    CHECK(after->display_name.size() == 12);
    CHECK(after->display_name == name);
    CHECK(after->display_name != "Admins");
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

// UP-3: embedded-NUL displayName round-trips at full byte length, not
// truncated to the substring before the NUL. This is the store-level guard
// for the fix in row_to_group's/list_group_display_names_for_user's
// text_col construction (explicit-length std::string, not an implicit
// strlen() via a NUL-terminated char*) — a truncating read would silently
// turn "Admins\0decoy" into "Admins" for role-resolution purposes, a
// privilege-escalation vector via a crafted SCIM group name.
TEST_CASE("ScimStore: embedded-NUL displayName round-trips at full length, not truncated (UP-3)",
         "[scim][group][embedded_nul]") {
    ScimFixture f;
    std::string name = std::string("Admins") + std::string(1, '\0') + std::string("decoy");
    REQUIRE(name.size() == 12);

    auto created = f.store.create_group(name);
    REQUIRE(created.has_value());
    CHECK(created->display_name.size() == 12);
    CHECK(created->display_name == name);

    auto by_id = f.store.get_group_by_id(created->scim_id);
    REQUIRE(by_id.has_value());
    CHECK(by_id->display_name.size() == 12);
    CHECK(by_id->display_name == name);
    CHECK(by_id->display_name != "Admins");

    REQUIRE(f.store.add_group_member(created->scim_id, "nul-user"));
    auto names = f.store.list_group_display_names_for_user("nul-user");
    REQUIRE(names.size() == 1);
    CHECK(names[0].size() == 12);
    CHECK(names[0] == name);
    CHECK(names[0] != "Admins");
}

// ── Transaction safety (safety-S2, SqliteTxnGuard rollback) ────────────────
//
// Both tests below install a `RAISE(ABORT, ...)` trigger via a second raw
// connection to force a genuine step-time failure partway through a
// multi-statement transaction, then confirm SqliteTxnGuard's destructor-time
// ROLLBACK undid EVERY statement in that transaction — not just the one
// that failed — so no partial/torn state is ever observable by a caller
// that only sees the false/nullopt return.

TEST_CASE("ScimStore: set_group_members rolls back fully on a mid-transaction failure "
         "(safety-S2)",
         "[scim][group][transaction]") {
    ScimFixture f;
    auto grp = f.store.create_group("Team");
    REQUIRE(grp.has_value());
    REQUIRE(f.store.set_group_members(grp->scim_id, {"old-a", "old-b"}));

    // Poison a specific member id so the INSERT loop fails partway through
    // (after "new-1" has already been inserted, before "new-2").
    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open_v2(f.db_file.path.string().c_str(), &raw, SQLITE_OPEN_READWRITE,
                                nullptr) == SQLITE_OK);
        REQUIRE(sqlite3_exec(raw,
                            "CREATE TRIGGER poison_insert BEFORE INSERT ON scim_group_members "
                            "WHEN NEW.user_scim_id = 'POISON' "
                            "BEGIN SELECT RAISE(ABORT, 'induced failure'); END;",
                            nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }

    CHECK_FALSE(f.store.set_group_members(grp->scim_id, {"new-1", "POISON", "new-2"}));

    // The pre-existing membership (old-a, old-b) is UNCHANGED — the
    // clearing DELETE that ran earlier in the SAME transaction was also
    // rolled back, not just the failed INSERT. A half-applied outcome
    // (e.g. just "new-1" persisted, or an empty set) would be the bug this
    // test guards against.
    auto members = f.store.list_group_member_user_scim_ids(grp->scim_id);
    std::sort(members.begin(), members.end());
    REQUIRE(members.size() == 2);
    CHECK(members[0] == "old-a");
    CHECK(members[1] == "old-b");
}

TEST_CASE("ScimStore: delete_group rolls back fully on a mid-transaction failure (safety-S2)",
         "[scim][group][transaction]") {
    ScimFixture f;
    auto grp = f.store.create_group("Doomed");
    REQUIRE(grp.has_value());
    REQUIRE(f.store.set_group_members(grp->scim_id, {"POISON", "member-b"}));

    // delete_group deletes the scim_groups row FIRST, then the
    // scim_group_members rows — poison the member-delete step so the
    // scim_groups deletion (which already ran, in the same transaction)
    // must also be undone.
    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open_v2(f.db_file.path.string().c_str(), &raw, SQLITE_OPEN_READWRITE,
                                nullptr) == SQLITE_OK);
        REQUIRE(sqlite3_exec(raw,
                            "CREATE TRIGGER poison_member_delete BEFORE DELETE ON "
                            "scim_group_members WHEN OLD.user_scim_id = 'POISON' "
                            "BEGIN SELECT RAISE(ABORT, 'induced failure'); END;",
                            nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }

    auto result = f.store.delete_group(grp->scim_id);
    REQUIRE_FALSE(result.has_value());

    // The group row is STILL THERE — the earlier `DELETE FROM scim_groups`
    // in the same transaction was rolled back too, not left applied
    // alongside the failed membership cleanup.
    auto still_there = f.store.get_group_by_id(grp->scim_id);
    REQUIRE(still_there.has_value());
    CHECK(still_there->display_name == "Doomed");

    auto members = f.store.list_group_member_user_scim_ids(grp->scim_id);
    std::sort(members.begin(), members.end());
    REQUIRE(members.size() == 2);
    CHECK(members[0] == "POISON");
    CHECK(members[1] == "member-b");
}
