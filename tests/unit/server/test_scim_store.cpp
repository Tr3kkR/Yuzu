/**
 * test_scim_store.cpp — Unit tests for the SCIM v2 provisioning storage
 * layer (slice 1: data + token layer only — no routes, no JSON codec).
 *
 * Covers:
 *   - bearer token set/validate/revoke (constant-time compare path)
 *   - resource CRUD round-trip (create/get/find/list/update/delete)
 *   - set_active toggling + etag_version bump
 *   - list() pagination + total count (1-based startIndex per SCIM)
 *   - the UNIQUE(username) constraint on scim_resources
 *   - ScimStore opening a second connection to the SAME auth.db file
 *     AuthDB owns, confirming the "scim" MigrationRunner component track
 *     is independent of AuthDB's own "auth_db" track (schema_meta is
 *     keyed by component string — verified against migration_runner.cpp)
 *   - the v7 auth.db `provisioning_source` column + AuthDB accessors
 */

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>
#include <yuzu/server/scim_store.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <memory>
#include <string_view>

using namespace yuzu::server;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::Role;

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

/// Owns a standalone ScimStore over its own temp file — used by tests that
/// don't need to exercise coexistence with a live AuthDB connection.
struct ScimFixture {
    yuzu::test::TempDbFile db_file{std::string_view{"yuzu-scim-"}};
    bool touched_{touch_file(db_file.path)};
    ScimStore store{db_file.path};
};

} // namespace

// ── Bearer token ──────────────────────────────────────────────────────────

TEST_CASE("ScimStore: correct token validates", "[scim][token]") {
    ScimFixture f;
    REQUIRE(f.store.is_open());
    REQUIRE_FALSE(f.store.has_token());

    REQUIRE(f.store.set_token("s3cret-scim-token", "primary"));
    CHECK(f.store.has_token());
    CHECK(f.store.validate_token("s3cret-scim-token"));
}

TEST_CASE("ScimStore: wrong token rejected", "[scim][token]") {
    ScimFixture f;
    REQUIRE(f.store.set_token("s3cret-scim-token", "primary"));

    CHECK_FALSE(f.store.validate_token("wrong-token"));
    // Same length as the real token but different content — exercises the
    // CRYPTO_memcmp equal-length comparison path rather than the early
    // length-mismatch short-circuit.
    CHECK_FALSE(f.store.validate_token("s3cret-scim-tokeX"));
}

TEST_CASE("ScimStore: empty token rejected", "[scim][token]") {
    ScimFixture f;
    REQUIRE(f.store.set_token("s3cret-scim-token", "primary"));

    CHECK_FALSE(f.store.validate_token(""));
}

TEST_CASE("ScimStore: revoked token rejected, replacement validates", "[scim][token]") {
    ScimFixture f;
    REQUIRE(f.store.set_token("old-token", "primary"));
    REQUIRE(f.store.validate_token("old-token"));

    // set_token upserts by label: re-setting "primary" revokes the old row.
    REQUIRE(f.store.set_token("new-token", "primary"));

    CHECK_FALSE(f.store.validate_token("old-token"));
    CHECK(f.store.validate_token("new-token"));
    CHECK(f.store.has_token());
}

TEST_CASE("ScimStore: distinct labels coexist as separate active tokens", "[scim][token]") {
    ScimFixture f;
    REQUIRE(f.store.set_token("token-a", "label-a"));
    REQUIRE(f.store.set_token("token-b", "label-b"));

    CHECK(f.store.validate_token("token-a"));
    CHECK(f.store.validate_token("token-b"));
}

// ── Resource CRUD ────────────────────────────────────────────────────────

TEST_CASE("ScimStore: create_resource round-trips through every getter", "[scim][resource]") {
    ScimFixture f;

    auto created = f.store.create_resource("alice", "ext-123");
    REQUIRE(created.has_value());
    CHECK_FALSE(created->scim_id.empty());
    CHECK(created->external_id == "ext-123");
    CHECK(created->username == "alice");
    CHECK(created->active);
    CHECK(created->etag_version == 1);
    CHECK_FALSE(created->created_at.empty());
    CHECK_FALSE(created->updated_at.empty());

    auto by_id = f.store.get_by_scim_id(created->scim_id);
    REQUIRE(by_id.has_value());
    CHECK(by_id->username == "alice");

    auto by_username = f.store.get_by_username("alice");
    REQUIRE(by_username.has_value());
    CHECK(by_username->scim_id == created->scim_id);

    auto by_external = f.store.find_by_external_id("ext-123");
    REQUIRE(by_external.has_value());
    CHECK(by_external->scim_id == created->scim_id);
}

TEST_CASE("ScimStore: lookups miss cleanly for absent keys", "[scim][resource]") {
    ScimFixture f;

    CHECK_FALSE(f.store.get_by_scim_id("does-not-exist").has_value());
    CHECK_FALSE(f.store.get_by_username("nobody").has_value());
    CHECK_FALSE(f.store.find_by_external_id("").has_value());
    CHECK_FALSE(f.store.find_by_external_id("no-such-ext").has_value());
}

TEST_CASE("ScimStore: username uniqueness is enforced", "[scim][resource]") {
    ScimFixture f;

    REQUIRE(f.store.create_resource("alice").has_value());
    // Same username again — the UNIQUE(username) constraint on
    // scim_resources should reject the second INSERT.
    CHECK_FALSE(f.store.create_resource("alice").has_value());
}

TEST_CASE("ScimStore: set_active toggles and bumps etag_version", "[scim][resource]") {
    ScimFixture f;
    auto created = f.store.create_resource("bob");
    REQUIRE(created.has_value());
    CHECK(created->active);
    CHECK(created->etag_version == 1);

    REQUIRE(f.store.set_active(created->scim_id, false));
    auto after = f.store.get_by_scim_id(created->scim_id);
    REQUIRE(after.has_value());
    CHECK_FALSE(after->active);
    CHECK(after->etag_version == 2);

    REQUIRE(f.store.set_active(created->scim_id, true));
    auto again = f.store.get_by_scim_id(created->scim_id);
    REQUIRE(again.has_value());
    CHECK(again->active);
    CHECK(again->etag_version == 3);
}

TEST_CASE("ScimStore: set_active on unknown scim_id fails", "[scim][resource]") {
    ScimFixture f;
    CHECK_FALSE(f.store.set_active("no-such-id", false));
}

TEST_CASE("ScimStore: update_resource changes fields and bumps etag", "[scim][resource]") {
    ScimFixture f;
    auto created = f.store.create_resource("carol", "ext-1");
    REQUIRE(created.has_value());

    REQUIRE(f.store.update_resource(created->scim_id, "carol.renamed", "ext-2"));

    auto after = f.store.get_by_scim_id(created->scim_id);
    REQUIRE(after.has_value());
    CHECK(after->username == "carol.renamed");
    CHECK(after->external_id == "ext-2");
    CHECK(after->etag_version == 2);

    // Old username no longer resolves; new one does.
    CHECK_FALSE(f.store.get_by_username("carol").has_value());
    CHECK(f.store.get_by_username("carol.renamed").has_value());
}

TEST_CASE("ScimStore: delete_by_scim_id removes the row", "[scim][resource]") {
    ScimFixture f;
    auto created = f.store.create_resource("dave");
    REQUIRE(created.has_value());

    // Tri-state return (UP-N4/FIX-4): nullopt = DB error, true = a row was
    // deleted, false = no row matched (already gone) — a real success, not
    // an error, so it must NOT collapse to the same falsy shape as nullopt.
    auto first = f.store.delete_by_scim_id(created->scim_id);
    REQUIRE(first.has_value());
    CHECK(*first);
    CHECK_FALSE(f.store.get_by_scim_id(created->scim_id).has_value());

    // Deleting again reports "no match" (false), not a DB error (nullopt) —
    // this is the idempotent-DELETE case the routes layer relies on to
    // return 204 rather than 500 on a concurrent/duplicate DELETE.
    auto second = f.store.delete_by_scim_id(created->scim_id);
    REQUIRE(second.has_value());
    CHECK_FALSE(*second);
}

TEST_CASE("ScimStore: delete_by_scim_id surfaces a genuine step-time error as nullopt, "
         "never false",
         "[scim][resource]") {
    // Gate-8 round-2 MEDIUM (CC6.8): a step-time failure (SQLITE_BUSY/
    // LOCKED/IOERR/CORRUPT/...) must NOT collapse to `false` ("already
    // gone") — that would make the DELETE handler 204 a failed teardown
    // instead of 500ing it. Cheaply induce a genuine step() error by
    // truncating the backing file out from under the already-open
    // connection: `sqlite3_prepare_v2` still succeeds (SQL text parses
    // against the cached schema), but `sqlite3_step` fails when it tries to
    // read/write a page that is no longer there — never SQLITE_ROW or
    // SQLITE_DONE.
    ScimFixture f;
    auto created = f.store.create_resource("erin");
    REQUIRE(created.has_value());

    std::filesystem::resize_file(f.db_file.path, 0);

    auto result = f.store.delete_by_scim_id(created->scim_id);
    CHECK_FALSE(result.has_value());
}

TEST_CASE("ScimStore: list paginates with 1-based startIndex and reports total",
         "[scim][resource][list]") {
    ScimFixture f;
    for (int i = 0; i < 5; ++i) {
        REQUIRE(f.store.create_resource("user" + std::to_string(i)).has_value());
    }

    int total = -1;
    auto page1 = f.store.list(/*start_index=*/1, /*count=*/2, total);
    CHECK(total == 5);
    REQUIRE(page1.size() == 2);
    CHECK(page1[0].username == "user0");
    CHECK(page1[1].username == "user1");

    auto page2 = f.store.list(/*start_index=*/3, /*count=*/2, total);
    CHECK(total == 5);
    REQUIRE(page2.size() == 2);
    CHECK(page2[0].username == "user2");
    CHECK(page2[1].username == "user3");

    auto page3 = f.store.list(/*start_index=*/5, /*count=*/2, total);
    CHECK(total == 5);
    REQUIRE(page3.size() == 1);
    CHECK(page3[0].username == "user4");
}

TEST_CASE("ScimStore: list with zero count returns nothing but still reports total",
         "[scim][resource][list]") {
    ScimFixture f;
    REQUIRE(f.store.create_resource("solo").has_value());

    int total = -1;
    auto page = f.store.list(1, 0, total);
    CHECK(total == 1);
    CHECK(page.empty());
}

// ── Coexistence with AuthDB on the same auth.db file ────────────────────

TEST_CASE("ScimStore: opens a second connection to the same auth.db AuthDB owns",
         "[scim][coexistence]") {
    auto data_dir = yuzu::test::unique_temp_path("yuzu-scim-coexist-");
    std::filesystem::create_directories(data_dir);

    AuthDB db(data_dir, /*cleanup_interval_secs=*/0);
    REQUIRE(db.initialize().has_value());
    REQUIRE(db.is_ready());

    auto salt = AuthManager::random_bytes(16);
    auto salt_hex = AuthManager::bytes_to_hex(salt);
    auto hash = AuthManager::pbkdf2_sha256("pw", salt, 1000);
    REQUIRE(db.upsert_user("eve", hash, salt_hex, Role::user).has_value());

    // A second, independent sqlite3 connection to the identical file path
    // AuthDB is using. If the two MigrationRunner tracks ("auth_db" vs
    // "scim") collided on schema_meta, either this construction or the
    // subsequent AuthDB read would fail.
    ScimStore scim(data_dir / "auth.db");
    REQUIRE(scim.is_open());
    REQUIRE(scim.create_resource("eve").has_value());

    // AuthDB is still fully functional after ScimStore's migration ran on
    // the same file.
    auto user = db.get_user("eve");
    REQUIRE(user.has_value());
    CHECK(user->username == "eve");

    auto mapped = scim.get_by_username("eve");
    REQUIRE(mapped.has_value());
    CHECK(mapped->username == "eve");
}

// ── AuthDB v7 provisioning_source ───────────────────────────────────────

TEST_CASE("AuthDB: provisioning_source defaults to local and round-trips via SCIM setter",
         "[scim][auth_db][provisioning_source]") {
    auto data_dir = yuzu::test::unique_temp_path("yuzu-provsrc-");
    std::filesystem::create_directories(data_dir);

    AuthDB db(data_dir, /*cleanup_interval_secs=*/0);
    REQUIRE(db.initialize().has_value());

    auto salt = AuthManager::random_bytes(16);
    auto salt_hex = AuthManager::bytes_to_hex(salt);
    auto hash = AuthManager::pbkdf2_sha256("pw", salt, 1000);
    REQUIRE(db.upsert_user("frank", hash, salt_hex, Role::admin).has_value());

    // Pre-v7 rows (and any row nobody has touched) default to 'local' with
    // zero migration backfill.
    auto initial = db.get_provisioning_source("frank");
    REQUIRE(initial.has_value());
    CHECK(*initial == "local");

    auto set_result = db.set_provisioning_source("frank", "scim");
    REQUIRE(set_result.has_value());

    auto after = db.get_provisioning_source("frank");
    REQUIRE(after.has_value());
    CHECK(*after == "scim");
}

TEST_CASE("AuthDB: provisioning_source accessors reject unknown/invalid usernames",
         "[scim][auth_db][provisioning_source]") {
    auto data_dir = yuzu::test::unique_temp_path("yuzu-provsrc-invalid-");
    std::filesystem::create_directories(data_dir);

    AuthDB db(data_dir, /*cleanup_interval_secs=*/0);
    REQUIRE(db.initialize().has_value());

    // Malformed username (contains ':') -> InvalidUsername.
    auto bad = db.set_provisioning_source("bad:name", "scim");
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error() == AuthDBError::InvalidUsername);

    // Well-formed but absent user -> UserNotFound.
    auto missing = db.get_provisioning_source("ghost");
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error() == AuthDBError::UserNotFound);
}

// ── AuthDB::set_identity_source (S-IDENTITY-SRC) ────────────────────────

TEST_CASE("AuthDB: set_identity_source round-trips and defaults to local",
         "[scim][auth_db][identity_source]") {
    auto data_dir = yuzu::test::unique_temp_path("yuzu-identsrc-");
    std::filesystem::create_directories(data_dir);

    AuthDB db(data_dir, /*cleanup_interval_secs=*/0);
    REQUIRE(db.initialize().has_value());

    auto salt = AuthManager::random_bytes(16);
    auto salt_hex = AuthManager::bytes_to_hex(salt);
    auto hash = AuthManager::pbkdf2_sha256("pw", salt, 1000);
    REQUIRE(db.upsert_user("ida", hash, salt_hex, Role::user).has_value());

    // v6 default, before any SCIM provisioning touches it.
    auto before = db.get_user("ida");
    REQUIRE(before.has_value());
    CHECK(before->identity_source == "local");

    REQUIRE(db.set_identity_source("ida", "scim").has_value());

    auto after = db.get_user("ida");
    REQUIRE(after.has_value());
    CHECK(after->identity_source == "scim");
    // Distinct dimension — provisioning_source is untouched by this call.
    CHECK(db.get_provisioning_source("ida").value() == "local");
}

TEST_CASE("AuthDB: set_identity_source rejects unknown/invalid usernames",
         "[scim][auth_db][identity_source]") {
    auto data_dir = yuzu::test::unique_temp_path("yuzu-identsrc-invalid-");
    std::filesystem::create_directories(data_dir);

    AuthDB db(data_dir, /*cleanup_interval_secs=*/0);
    REQUIRE(db.initialize().has_value());

    auto bad = db.set_identity_source("bad:name", "scim");
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error() == AuthDBError::InvalidUsername);

    auto missing = db.set_identity_source("ghost", "scim");
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error() == AuthDBError::UserNotFound);
}

// ── AuthDB::reactivate_user (SCIM PATCH/PUT active=true un-suspend) ────────

TEST_CASE("AuthDB: reactivate_user revives a soft-deleted row and clears lockout state",
         "[scim][auth_db][reactivate]") {
    auto data_dir = yuzu::test::unique_temp_path("yuzu-reactivate-");
    std::filesystem::create_directories(data_dir);

    AuthDB db(data_dir, /*cleanup_interval_secs=*/0);
    REQUIRE(db.initialize().has_value());

    auto salt = AuthManager::random_bytes(16);
    auto salt_hex = AuthManager::bytes_to_hex(salt);
    auto hash = AuthManager::pbkdf2_sha256("pw", salt, 1000);
    REQUIRE(db.upsert_user("ivan", hash, salt_hex, Role::user).has_value());
    REQUIRE(db.set_provisioning_source("ivan", "scim").has_value());

    // Seed a real lockout (threshold=1 crosses immediately) BEFORE
    // deactivating, so clearing it after reactivation is a meaningful
    // assertion rather than an all-zero coincidence.
    auto lockout = db.record_failed_login("ivan", /*threshold=*/1, /*window_secs=*/3600);
    REQUIRE(lockout.has_value());
    REQUIRE(lockout->locked);

    REQUIRE(db.remove_user("ivan").has_value());
    // Soft-deleted: get_user (is_active=1 filter) can no longer see it.
    REQUIRE_FALSE(db.get_user("ivan").has_value());

    auto reactivated = db.reactivate_user("ivan");
    REQUIRE(reactivated.has_value());

    // The row resolves again...
    auto user = db.get_user("ivan");
    REQUIRE(user.has_value());
    CHECK(user->username == "ivan");
    CHECK(user->role == Role::user);
    // ...provisioning_source and role are untouched...
    auto source = db.get_provisioning_source("ivan");
    REQUIRE(source.has_value());
    CHECK(*source == "scim");
    // ...and the stale lockout is cleared, not inherited.
    auto status = db.lockout_status("ivan");
    REQUIRE(status.has_value());
    CHECK_FALSE(status->locked);
    CHECK(status->failed_count == 0);
}

TEST_CASE("AuthDB: reactivate_user is a harmless no-op on an already-active user",
         "[scim][auth_db][reactivate]") {
    auto data_dir = yuzu::test::unique_temp_path("yuzu-reactivate-noop-");
    std::filesystem::create_directories(data_dir);

    AuthDB db(data_dir, /*cleanup_interval_secs=*/0);
    REQUIRE(db.initialize().has_value());

    auto salt = AuthManager::random_bytes(16);
    auto salt_hex = AuthManager::bytes_to_hex(salt);
    auto hash = AuthManager::pbkdf2_sha256("pw", salt, 1000);
    REQUIRE(db.upsert_user("judy", hash, salt_hex, Role::user).has_value());

    REQUIRE(db.reactivate_user("judy").has_value());
    auto user = db.get_user("judy");
    REQUIRE(user.has_value());
    CHECK(user->username == "judy");
}

TEST_CASE("AuthDB: reactivate_user rejects unknown/invalid usernames",
         "[scim][auth_db][reactivate]") {
    auto data_dir = yuzu::test::unique_temp_path("yuzu-reactivate-invalid-");
    std::filesystem::create_directories(data_dir);

    AuthDB db(data_dir, /*cleanup_interval_secs=*/0);
    REQUIRE(db.initialize().has_value());

    auto bad = db.reactivate_user("bad:name");
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error() == AuthDBError::InvalidUsername);

    auto missing = db.reactivate_user("ghost");
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error() == AuthDBError::UserNotFound);
}
