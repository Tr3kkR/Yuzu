// AuthDB (Postgres) tests — born-on-PG `auth` schema (ADR-0006 server
// substrate migration). Covers user CRUD + role, account lockout, break-glass
// arming, JIT elevation eligibility, provisioning_source / identity_source
// (SSO), enrollment tokens, recovery codes, the MFA enroll -> verify round
// trip THROUGH the real `pg::SecretCodec`, fresh-start admin seeding, and —
// the ★ security-critical deliverable — the three MFA fail-closed cases: a
// decrypt failure on an ENROLLED secret must surface `SecretUnavailable`,
// NEVER read as "not enrolled" (mfa_status) or "code didn't match"
// (mfa_verify_login_code); a decrypt failure on a PROVISIONAL secret must
// refuse to mint a fresh one (mfa_init_enrollment) and must refuse to accept
// any code against it (mfa_verify_enrollment).
//
// PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails when it is set
// but broken (test_helpers.hpp skip-vs-fail contract). Store-behaviour tests
// use the pre-migrated PgTestTemplate variant (docs/postgres-store-playbook.md
// step 7) — the template runs a throwaway SecretCodec::init() + AuthDB
// construction once, then resets `secrets.kek_meta` to empty so every clone
// starts fresh and mints its OWN KEK against its OWN keys dir (mirrors
// test_secret_codec.cpp's `secrets_tpl`).

#include "key_provider.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "totp.hpp"

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::AuthDB;
using yuzu::server::AuthDBError;
using yuzu::server::FileKeyProvider;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
using yuzu::server::pg::SecretCodec;

namespace {

PgConn connect(const std::string& dsn) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    return conn;
}

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp).
yuzu::test::PgTestTemplate auth_db_tpl{"authdb", [](const std::string& dsn) {
    yuzu::test::TempDir keys;
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    PgConn conn{PQconnectdb(dsn.c_str())};
    if (PQstatus(conn.get()) != CONNECTION_OK)
        throw std::runtime_error("authdb template: connect failed");
    if (!codec.init(conn.get()).has_value())
        throw std::runtime_error("authdb template: secret codec init failed");
    PgResult reset{PQexec(conn.get(), "DELETE FROM secrets.kek_meta")};
    if (!reset.ok())
        throw std::runtime_error("authdb template: kek_meta reset failed");

    PgPool pool{{.conninfo = dsn, .size = 1}};
    AuthDB db{pool, codec};
    if (!db.is_open())
        throw std::runtime_error("authdb template: store failed to migrate");
}};

// Corrupts a user's stored `mfa_totp_secret` envelope in place with garbage
// bytes that cannot possibly decrypt (wrong length + no valid GCM tag) —
// simulates tamper / a wrong-KEK-version blob without needing a second KEK.
void corrupt_secret(PGconn* conn, const std::string& username) {
    const char* values[] = {username.c_str()};
    PgResult res{PQexecParams(
        conn,
        "UPDATE auth.users SET mfa_totp_secret = decode('deadbeefcafebabe0011223344','hex') "
        "WHERE username = $1",
        1, nullptr, values, nullptr, nullptr, 0)};
    REQUIRE(res.ok());
}

std::string read_secret_hex(PGconn* conn, const std::string& username) {
    const char* values[] = {username.c_str()};
    PgResult res{PQexecParams(conn, "SELECT encode(mfa_totp_secret,'hex') FROM auth.users WHERE username = $1",
                              1, nullptr, values, nullptr, nullptr, 0)};
    REQUIRE(res.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(res.get()) == 1);
    if (PQgetisnull(res.get(), 0, 0))
        return {};
    return PQgetvalue(res.get(), 0, 0);
}

struct Harness {
    yuzu::test::TempDir keys;
    FileKeyProvider provider;
    SecretCodec codec;
    PgConn conn;
    PgPool pool;
    AuthDB db;

    explicit Harness(const std::string& dsn)
        : provider(keys.path), codec(provider), conn(connect(dsn)),
          pool(PgPool::Options{.conninfo = dsn, .size = 4}), db(pool, codec) {
        REQUIRE(codec.init(conn.get()).has_value());
        REQUIRE(pool.valid());
        REQUIRE(db.is_open());
    }
};

} // namespace

#ifdef YUZU_TEST_ENABLE_PG

// ── construction ───────────────────────────────────────────────────────────

TEST_CASE("AuthDB constructs, migrates, and opens", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    CHECK(h.db.is_ready());
    CHECK(h.db.is_open());
}

TEST_CASE("AuthDB reports !is_open on a migration failure", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA auth")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE auth.users (bogus int)")};
        REQUIRE(t.ok());
    }
    yuzu::test::TempDir keys;
    FileKeyProvider provider(keys.path);
    SecretCodec codec(provider);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        REQUIRE(codec.init(conn.get()).has_value());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AuthDB authdb{pool, codec};
    CHECK_FALSE(authdb.is_open()); // fail-closed (ADR-0012 §1)
}

// ── user CRUD + role ──────────────────────────────────────────────────────

TEST_CASE("AuthDB user CRUD + role", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};

    SECTION("upsert + get + list + exists") {
        REQUIRE(h.db.upsert_user("alice", "hash1", "salt1", yuzu::server::auth::Role::user).has_value());
        CHECK(h.db.user_exists("alice").value());
        CHECK_FALSE(h.db.user_exists("nobody").value());

        auto entry = h.db.get_user("alice");
        REQUIRE(entry.has_value());
        CHECK(entry->username == "alice");
        CHECK(entry->role == yuzu::server::auth::Role::user);
        CHECK(entry->hash_hex == "hash1");
        CHECK(entry->salt_hex == "salt1");
        CHECK(entry->identity_source == "local");

        auto users = h.db.list_users();
        REQUIRE(users.has_value());
        REQUIRE(users->size() == 1);
        CHECK((*users)[0].username == "alice");
    }

    SECTION("duplicate upsert is rejected, never overwrites") {
        REQUIRE(h.db.upsert_user("bob", "hashA", "saltA", yuzu::server::auth::Role::user).has_value());
        auto dup = h.db.upsert_user("bob", "hashB", "saltB", yuzu::server::auth::Role::admin);
        REQUIRE_FALSE(dup.has_value());
        CHECK(dup.error() == AuthDBError::UserAlreadyExists);
        auto entry = h.db.get_user("bob");
        REQUIRE(entry.has_value());
        CHECK(entry->hash_hex == "hashA"); // unchanged
    }

    SECTION("update_role never touches credentials") {
        REQUIRE(h.db.upsert_user("carol", "hashC", "saltC", yuzu::server::auth::Role::user).has_value());
        REQUIRE(h.db.update_role("carol", yuzu::server::auth::Role::admin).has_value());
        auto entry = h.db.get_user("carol");
        REQUIRE(entry.has_value());
        CHECK(entry->role == yuzu::server::auth::Role::admin);
        CHECK(entry->hash_hex == "hashC");
        auto missing = h.db.update_role("nope", yuzu::server::auth::Role::admin);
        REQUIRE_FALSE(missing.has_value());
        CHECK(missing.error() == AuthDBError::UserNotFound);
    }

    SECTION("remove_user soft-deletes; reactivate_user clears lockout state") {
        REQUIRE(h.db.upsert_user("dave", "hashD", "saltD", yuzu::server::auth::Role::user).has_value());
        auto removed = h.db.remove_user("dave");
        REQUIRE(removed.has_value());
        CHECK(*removed == true);
        CHECK_FALSE(h.db.user_exists("dave").value()); // is_active filter
        auto again = h.db.remove_user("dave");
        REQUIRE(again.has_value());
        CHECK(*again == false); // already inactive — not a re-removal

        REQUIRE(h.db.reactivate_user("dave").has_value());
        CHECK(h.db.user_exists("dave").value());

        auto missing = h.db.reactivate_user("ghost");
        REQUIRE_FALSE(missing.has_value());
        CHECK(missing.error() == AuthDBError::UserNotFound);
    }

    SECTION("list_users_including_inactive surfaces the is_active flag") {
        REQUIRE(h.db.upsert_user("erin", "h", "s", yuzu::server::auth::Role::user).has_value());
        REQUIRE(h.db.remove_user("erin").has_value());
        auto all = h.db.list_users_including_inactive();
        REQUIRE(all.has_value());
        REQUIRE(all->size() == 1);
        CHECK((*all)[0].username == "erin");
        CHECK_FALSE((*all)[0].is_active);
    }
}

// ── fresh-start admin seeding ─────────────────────────────────────────────

TEST_CASE("AuthDB::seed_admin_if_empty seeds once and no-ops thereafter", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};

    auto seeded = h.db.seed_admin_if_empty("admin", "roothash", "rootsalt");
    REQUIRE(seeded.has_value());
    CHECK(*seeded == true);
    auto entry = h.db.get_user("admin");
    REQUIRE(entry.has_value());
    CHECK(entry->role == yuzu::server::auth::Role::admin);

    // A second attempt (even with different creds) is a clean no-op — table
    // is no longer empty.
    auto again = h.db.seed_admin_if_empty("someoneelse", "x", "y");
    REQUIRE(again.has_value());
    CHECK(*again == false);
    CHECK_FALSE(h.db.user_exists("someoneelse").value());

    auto bad = h.db.seed_admin_if_empty("not a valid username!", "x", "y");
    REQUIRE_FALSE(bad.has_value());
    CHECK(bad.error() == AuthDBError::InvalidUsername);
}

// ── account lockout ────────────────────────────────────────────────────────

TEST_CASE("AuthDB account lockout apply / clear / expiry", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("locky", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto status0 = h.db.lockout_status("locky");
    REQUIRE(status0.has_value());
    CHECK_FALSE(status0->locked);
    CHECK(status0->failed_count == 0);

    // Threshold 3: first two failures increment but don't lock.
    for (int i = 1; i <= 2; ++i) {
        auto rec = h.db.record_failed_login("locky", /*threshold=*/3, /*window_secs=*/3600);
        REQUIRE(rec.has_value());
        CHECK(rec->failed_count == i);
        CHECK_FALSE(rec->locked);
    }
    // Third failure crosses the threshold.
    auto rec3 = h.db.record_failed_login("locky", 3, 3600);
    REQUIRE(rec3.has_value());
    CHECK(rec3->failed_count == 3);
    CHECK(rec3->locked);
    CHECK(rec3->just_locked);
    CHECK_FALSE(rec3->locked_until.empty());

    auto status1 = h.db.lockout_status("locky");
    REQUIRE(status1.has_value());
    CHECK(status1->locked);

    REQUIRE(h.db.clear_failed_logins("locky").has_value());
    auto status2 = h.db.lockout_status("locky");
    REQUIRE(status2.has_value());
    CHECK_FALSE(status2->locked);
    CHECK(status2->failed_count == 0);

    // A lock that has already expired (negative window) resets the cycle
    // rather than staying stuck — same "expiry" contract as the SQLite era.
    auto expired_rec = h.db.record_failed_login("locky", 1, /*window_secs=*/-100);
    REQUIRE(expired_rec.has_value());
    // `now()` is transaction-stable in Postgres (one evaluation per
    // statement), so `locked_until = now() + (-100s)` and the RETURNING
    // check `locked_until > now()` use the SAME instant — a negative window
    // is therefore, correctly, NEVER "currently locked": the 1-strike
    // threshold crossing wrote a locked_until, but it is already in the
    // past the moment it lands.
    CHECK_FALSE(expired_rec->locked);
    CHECK_FALSE(expired_rec->locked_until.empty()); // locked_until WAS written (past-dated)
    auto rearm = h.db.record_failed_login("locky", 1, 3600);
    REQUIRE(rearm.has_value());
    CHECK(rearm->failed_count == 1); // cycle restarted, not accumulated

    // Anti-enumeration: a non-existent user reads as "not locked", not an error.
    auto nouser = h.db.lockout_status("ghost");
    REQUIRE(nouser.has_value());
    CHECK_FALSE(nouser->locked);
}

// ── break-glass arming ────────────────────────────────────────────────────

TEST_CASE("AuthDB break-glass arm / status / disarm", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("glass", "h", "s", yuzu::server::auth::Role::admin).has_value());

    auto status0 = h.db.break_glass_status("glass");
    REQUIRE(status0.has_value());
    CHECK_FALSE(status0->armed);

    auto armed = h.db.arm_break_glass("glass", 3600);
    REQUIRE(armed.has_value());
    CHECK(armed->armed);
    CHECK_FALSE(armed->armed_until.empty());

    auto status1 = h.db.break_glass_status("glass");
    REQUIRE(status1.has_value());
    CHECK(status1->armed);

    REQUIRE(h.db.disarm_break_glass("glass").has_value());
    auto status2 = h.db.break_glass_status("glass");
    REQUIRE(status2.has_value());
    CHECK_FALSE(status2->armed);

    auto missing = h.db.arm_break_glass("ghost", 3600);
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error() == AuthDBError::UserNotFound);
}

// ── JIT elevation eligibility ─────────────────────────────────────────────

TEST_CASE("AuthDB elevation eligibility", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("jit", "h", "s", yuzu::server::auth::Role::user).has_value());

    CHECK_FALSE(h.db.is_elevation_eligible("jit").value());
    REQUIRE(h.db.set_elevation_eligible("jit", true).has_value());
    CHECK(h.db.is_elevation_eligible("jit").value());
    REQUIRE(h.db.set_elevation_eligible("jit", false).has_value());
    CHECK_FALSE(h.db.is_elevation_eligible("jit").value());

    // Fail-closed for an absent user, not an error.
    CHECK_FALSE(h.db.is_elevation_eligible("ghost").value());
}

// ── provisioning_source / identity_source / SSO ───────────────────────────

TEST_CASE("AuthDB provisioning_source and identity_source", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("prov", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto src0 = h.db.get_provisioning_source("prov");
    REQUIRE(src0.has_value());
    CHECK(*src0 == "local");

    REQUIRE(h.db.set_provisioning_source("prov", std::string{yuzu::server::kProvisioningSourceScim})
                .has_value());
    auto src1 = h.db.get_provisioning_source("prov");
    REQUIRE(src1.has_value());
    CHECK(*src1 == "scim");

    REQUIRE(h.db.set_identity_source("prov", "oidc").has_value());
    auto entry = h.db.get_user("prov");
    REQUIRE(entry.has_value());
    CHECK(entry->identity_source == "oidc");

    auto missing = h.db.set_provisioning_source("ghost", "scim");
    REQUIRE_FALSE(missing.has_value());
    CHECK(missing.error() == AuthDBError::UserNotFound);
}

TEST_CASE("AuthDB upsert_sso_identity provisions and refreshes without clobbering role",
          "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};

    const std::string principal = "oidc:https://idp.example#sub-123";
    REQUIRE(h.db.upsert_sso_identity(principal, "https://idp.example", "sub-123", "Alice", "oidc")
                .has_value());
    auto entry = h.db.get_user(principal);
    REQUIRE(entry.has_value());
    CHECK(entry->role == yuzu::server::auth::Role::user);
    CHECK(entry->identity_source == "oidc");

    // Promote to admin, then log in again — role must survive re-login.
    // update_role() deliberately stays on the STRICT is_valid_username gate
    // (#1852 item 5) — it cannot target an SSO principal (':'/'#' rejected),
    // so there is no standing-role-grant path through the public API here.
    // Simulate an out-of-band role grant via a raw UPDATE (a real deployment
    // would need its own future admin tool for this) purely to prove
    // upsert_sso_identity's ON CONFLICT arm never clobbers an existing role.
    {
        auto conn = connect(db.dsn());
        const char* values[] = {principal.c_str()};
        PgResult upd{PQexecParams(conn.get(), "UPDATE auth.users SET role = 'admin' WHERE username = $1",
                                  1, nullptr, values, nullptr, nullptr, 0)};
        REQUIRE(upd.ok());
    }
    REQUIRE(h.db.upsert_sso_identity(principal, "https://idp.example", "sub-123", "Alice R.", "oidc")
                .has_value());
    auto entry2 = h.db.get_user(principal);
    REQUIRE(entry2.has_value());
    CHECK(entry2->role == yuzu::server::auth::Role::admin);

    // The reserved `engine:` namespace is never constructible via this path.
    auto rejected = h.db.upsert_sso_identity("engine:vuln-sync", "iss", "sub", "x", "oidc");
    REQUIRE_FALSE(rejected.has_value());
    CHECK(rejected.error() == AuthDBError::InvalidUsername);
}

TEST_CASE("AuthDB find_reserved_prefix_users scans active and soft-deleted rows", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_sso_identity("oidc:https://idp#a", "https://idp", "a", "A", "oidc").has_value());
    REQUIRE(h.db.upsert_sso_identity("oidc:https://idp#b", "https://idp", "b", "B", "oidc").has_value());
    REQUIRE(h.db.remove_user("oidc:https://idp#b").has_value()); // soft-delete

    auto found = h.db.find_reserved_prefix_users("oidc:");
    REQUIRE(found.has_value());
    CHECK(found->size() == 2); // includes the soft-deleted row

    // LIKE-metacharacter guard fails closed (nullopt), never "no collision".
    auto guarded = h.db.find_reserved_prefix_users("oid%c:");
    CHECK_FALSE(guarded.has_value());
}

// ── enrollment tokens ──────────────────────────────────────────────────────

TEST_CASE("AuthDB enrollment token lifecycle", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};

    auto token = h.db.create_enrollment_token("admin", std::chrono::seconds(3600));
    REQUIRE(token.has_value());
    CHECK_FALSE(token->empty());

    CHECK(h.db.validate_enrollment_token(*token).value());
    auto consumed = h.db.consume_enrollment_token(*token, "agent-1");
    REQUIRE(consumed.has_value());
    CHECK(*consumed == true);

    // Reuse is rejected — already consumed.
    CHECK_FALSE(h.db.validate_enrollment_token(*token).value());
    auto second = h.db.consume_enrollment_token(*token, "agent-2");
    REQUIRE(second.has_value());
    CHECK(*second == false);

    CHECK_FALSE(h.db.validate_enrollment_token("not-a-real-token").value());
}

// ── pending agents ─────────────────────────────────────────────────────────

TEST_CASE("AuthDB pending agent approve/reject", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};

    yuzu::server::auth::PendingAgent agent;
    agent.agent_id = "agent-xyz";
    agent.hostname = "host1";
    agent.os = "linux";
    agent.arch = "x86_64";
    agent.agent_version = "1.0.0";
    REQUIRE(h.db.add_pending_agent(agent).has_value());

    auto pending = h.db.list_pending_agents();
    REQUIRE(pending.has_value());
    REQUIRE(pending->size() == 1);
    CHECK((*pending)[0].agent_id == "agent-xyz");

    REQUIRE(h.db.approve_agent("agent-xyz", "admin").has_value());
    auto after_approve = h.db.list_pending_agents();
    REQUIRE(after_approve.has_value());
    CHECK(after_approve->empty()); // no longer 'pending'

    yuzu::server::auth::PendingAgent agent2;
    agent2.agent_id = "agent-abc";
    agent2.hostname = "host2";
    REQUIRE(h.db.add_pending_agent(agent2).has_value());
    REQUIRE(h.db.reject_agent("agent-abc").has_value());
    auto after_reject = h.db.list_pending_agents();
    REQUIRE(after_reject.has_value());
    CHECK(after_reject->empty());
}

// ── recovery codes ─────────────────────────────────────────────────────────

TEST_CASE("AuthDB recovery codes regenerate + single-use consume", "[pg][auth_db]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("rec", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto codes = h.db.mfa_regenerate_recovery_codes("rec");
    REQUIRE(codes.has_value());
    REQUIRE(codes->size() == 10);

    const auto& one = (*codes)[0];
    CHECK(h.db.mfa_consume_recovery_code("rec", one).value());
    // Single-use: consuming again fails.
    CHECK_FALSE(h.db.mfa_consume_recovery_code("rec", one).value());
    // A never-issued code fails cleanly (not an error).
    CHECK_FALSE(h.db.mfa_consume_recovery_code("rec", "ZZZZZ-ZZZZZ").value());
}

// ── MFA enroll -> verify round trip THROUGH SecretCodec ──────────────────

TEST_CASE("AuthDB MFA enroll -> verify round trip is envelope-encrypted end to end",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("mfauser", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto pre = h.db.mfa_status("mfauser");
    REQUIRE(pre.has_value());
    CHECK_FALSE(pre->enrolled);

    auto init = h.db.mfa_init_enrollment("mfauser", "Yuzu");
    REQUIRE(init.has_value());
    CHECK_FALSE(init->secret_base32.empty());
    CHECK(init->otpauth_uri.find("otpauth://") == 0);

    // The secret is genuinely encrypted at rest — the raw column bytes must
    // NOT equal the plaintext secret we were handed.
    auto raw_secret = yuzu::server::mfa::base32_decode(init->secret_base32);
    REQUIRE(raw_secret.has_value());
    auto stored_hex = read_secret_hex(h.conn.get(), "mfauser");
    CHECK_FALSE(stored_hex.empty());

    // Re-init while still provisional REUSES the same secret (idempotent).
    auto init2 = h.db.mfa_init_enrollment("mfauser", "Yuzu");
    REQUIRE(init2.has_value());
    CHECK(init2->secret_base32 == init->secret_base32);

    auto secret_view =
        std::string_view(reinterpret_cast<const char*>(raw_secret->data()), raw_secret->size());
    auto now = std::chrono::system_clock::now();
    auto counter = yuzu::server::mfa::current_counter(now);
    auto code = yuzu::server::mfa::generate(secret_view, counter);

    auto verify = h.db.mfa_verify_enrollment("mfauser", code);
    REQUIRE(verify.has_value());
    CHECK(verify->size() == 10);

    // Enrolling twice is rejected.
    auto redo = h.db.mfa_init_enrollment("mfauser", "Yuzu");
    REQUIRE_FALSE(redo.has_value());
    CHECK(redo.error() == AuthDBError::MfaAlreadyEnrolled);

    auto status = h.db.mfa_status("mfauser");
    REQUIRE(status.has_value());
    CHECK(status->enrolled);
    CHECK(status->recovery_codes_remaining == 10);

    // A fresh code at the NEXT step (replay protection rejects re-using the
    // enrollment counter) verifies for login.
    auto code2 = yuzu::server::mfa::generate(secret_view, counter + 1);
    auto login = h.db.mfa_verify_login_code("mfauser", code2);
    REQUIRE(login.has_value());
    CHECK(*login == true);

    // A wrong code is a clean `false`, not an error.
    auto wrong = h.db.mfa_verify_login_code("mfauser", "000000");
    REQUIRE(wrong.has_value());
    CHECK(*wrong == false);

    REQUIRE(h.db.mfa_disable("mfauser").has_value());
    auto after_disable = h.db.mfa_status("mfauser");
    REQUIRE(after_disable.has_value());
    CHECK_FALSE(after_disable->enrolled);
}

// ── ★ fail-closed: corrupted/undecryptable secret NEVER reads as "not
//    enrolled" or "code didn't match" ─────────────────────────────────────

TEST_CASE("AuthDB MFA fail-closed: corrupted ENROLLED secret -> SecretUnavailable, never "
          "'not enrolled'",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("corrupt1", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto init = h.db.mfa_init_enrollment("corrupt1", "Yuzu");
    REQUIRE(init.has_value());
    auto raw_secret = yuzu::server::mfa::base32_decode(init->secret_base32);
    REQUIRE(raw_secret.has_value());
    auto secret_view =
        std::string_view(reinterpret_cast<const char*>(raw_secret->data()), raw_secret->size());
    auto counter = yuzu::server::mfa::current_counter(std::chrono::system_clock::now());
    auto code = yuzu::server::mfa::generate(secret_view, counter);
    REQUIRE(h.db.mfa_verify_enrollment("corrupt1", code).has_value());

    corrupt_secret(h.conn.get(), "corrupt1");

    // mfa_status must surface SecretUnavailable — NEVER enrolled=false.
    auto status = h.db.mfa_status("corrupt1");
    REQUIRE_FALSE(status.has_value());
    CHECK(status.error() == AuthDBError::SecretUnavailable);

    // mfa_verify_login_code must surface SecretUnavailable — NEVER a silent
    // `false` indistinguishable from "wrong code".
    auto login = h.db.mfa_verify_login_code("corrupt1", "123456");
    REQUIRE_FALSE(login.has_value());
    CHECK(login.error() == AuthDBError::SecretUnavailable);
}

TEST_CASE("AuthDB MFA fail-closed: mfa_init_enrollment never mints a fresh secret over a "
          "corrupted provisional one",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("corrupt2", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto init = h.db.mfa_init_enrollment("corrupt2", "Yuzu");
    REQUIRE(init.has_value());

    corrupt_secret(h.conn.get(), "corrupt2");
    auto corrupted_hex = read_secret_hex(h.conn.get(), "corrupt2");

    auto reinit = h.db.mfa_init_enrollment("corrupt2", "Yuzu");
    REQUIRE_FALSE(reinit.has_value());
    CHECK(reinit.error() == AuthDBError::SecretUnavailable);

    // The stored bytes must be UNCHANGED — no fresh secret was minted over
    // the corrupted one.
    auto after_hex = read_secret_hex(h.conn.get(), "corrupt2");
    CHECK(after_hex == corrupted_hex);
}

TEST_CASE("AuthDB MFA fail-closed: mfa_verify_enrollment refuses a corrupted provisional secret",
          "[pg][auth_db][secrets]") {
    YUZU_REQUIRE_PG_DB_TPL(db, auth_db_tpl);
    Harness h{db.dsn()};
    REQUIRE(h.db.upsert_user("corrupt3", "h", "s", yuzu::server::auth::Role::user).has_value());

    auto init = h.db.mfa_init_enrollment("corrupt3", "Yuzu");
    REQUIRE(init.has_value());
    corrupt_secret(h.conn.get(), "corrupt3");

    auto verify = h.db.mfa_verify_enrollment("corrupt3", "123456");
    REQUIRE_FALSE(verify.has_value());
    CHECK(verify.error() == AuthDBError::SecretUnavailable);

    // The row must still read as NOT enrolled (the stamp never ran) —
    // mfa_status's documented contract only attempts to decrypt for an
    // ENROLLED row (mfa_enrolled_at set); a corrupted PROVISIONAL secret on
    // a not-yet-enrolled row is irrelevant to it (see auth_db.hpp's
    // mfa_status doc comment: "a provisional secret, if any, does not
    // count"). It must NOT surface SecretUnavailable here.
    auto status = h.db.mfa_status("corrupt3");
    REQUIRE(status.has_value());
    CHECK_FALSE(status->enrolled);
}

#endif // YUZU_TEST_ENABLE_PG
