/**
 * test_auth_session_store.cpp -- AuthManager ↔ durable SessionStore integration
 * (HA WS-1/1a, ADR-2002 §4).
 *
 * Exercises the store-backed AuthManager path: sessions written through to
 * Postgres, validated against it, and surviving on a FRESH AuthManager that
 * shares the same store — the stand-in for a second core replica / a restart
 * (the in-memory cache is cold there, so validation reads the durable row).
 *
 * A separate AuthManager with no store wired keeps the legacy in-memory path;
 * that is covered by test_auth_jit_elevation / test_mfa_step_up. Behind
 * YUZU_TEST_ENABLE_PG (server suite only) — skipped when the DSN is unset.
 */

#include <yuzu/server/auth.hpp>

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "session_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <memory>
#include <string>

using yuzu::server::SessionStore;
using yuzu::server::auth::AuthManager;
using yuzu::server::auth::effective_role;
using yuzu::server::auth::is_elevated;
using yuzu::server::auth::Role;
using yuzu::server::pg::PgPool;

namespace {

// Setup constructs the store (runs the migration), then closes all conns.
yuzu::test::PgTestTemplate authsess_tpl{"authsess", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    SessionStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("authsess template: store failed to migrate");
}};

// A store-backed AuthManager with no config file / AuthDB — just the session
// store, which is all the session lifecycle needs.
std::unique_ptr<AuthManager> make_mgr(SessionStore& store) {
    auto mgr = std::make_unique<AuthManager>();
    mgr->set_session_store(&store);
    return mgr;
}

// A store-backed AuthManager with a config file behind it, so user-management
// methods (upsert_user/update_role/remove_user) work in the config-file path.
std::unique_ptr<AuthManager> make_mgr_with_config(SessionStore& store) {
    auto mgr = std::make_unique<AuthManager>();
    auto cfg = yuzu::test::unique_temp_path("yuzu_test_authsess_");
    cfg += ".cfg";
    std::filesystem::create_directories(cfg.parent_path());
    std::filesystem::remove(cfg);
    mgr->load_config(cfg);
    mgr->set_session_store(&store);
    return mgr;
}

} // namespace

TEST_CASE("AuthManager+SessionStore: create_local_session → validate round-trips",
          "[auth][session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authsess_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());
    auto mgr = make_mgr(store);
    REQUIRE(mgr->is_session_store_ok());

    auto token = mgr->create_local_session("alice", Role::admin, /*mfa_verified=*/true);
    REQUIRE_FALSE(token.empty());

    auto s = mgr->validate_session(token);
    REQUIRE(s.has_value());
    CHECK(s->username == "alice");
    CHECK(s->role == Role::admin);
    CHECK(effective_role(*s) == Role::admin);
    CHECK(s->auth_source == "local");
    // MFA proof was seeded — the wall-clock timestamp round-trips as non-sentinel.
    CHECK(s->mfa_verified_at.time_since_epoch().count() != 0);

    // The raw token is NEVER the store row key (secret-at-rest): the durable row
    // is keyed by the SHA-256 hash, so a find on the raw token misses.
    auto by_raw = store.find(token);
    REQUIRE(by_raw.has_value());
    CHECK_FALSE(by_raw->has_value());
}

TEST_CASE("AuthManager+SessionStore: a session survives on a fresh replica",
          "[auth][session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authsess_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    auto a = make_mgr(store);
    auto token = a->create_local_session("bob", Role::user, /*mfa_verified=*/false);
    REQUIRE_FALSE(token.empty());

    // A fresh AuthManager sharing the same store = a second replica / a restart:
    // its cache is cold, so validation must read the durable row.
    auto b = make_mgr(store);
    auto s = b->validate_session(token);
    REQUIRE(s.has_value());
    CHECK(s->username == "bob");
    CHECK(s->role == Role::user);
}

TEST_CASE("AuthManager+SessionStore: elevation persists and is honored on a fresh replica",
          "[auth][session_store][pg][jit]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authsess_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    auto a = make_mgr(store);
    auto token = a->create_local_session("carol", Role::user, /*mfa_verified=*/true);
    REQUIRE_FALSE(token.empty());

    // Base role is user until elevated.
    CHECK(effective_role(*a->validate_session(token)) == Role::user);

    auto until = a->elevate_session(token, std::chrono::seconds(120));
    REQUIRE(until.has_value());

    // Reflected on the SAME manager…
    {
        auto s = a->validate_session(token);
        REQUIRE(s.has_value());
        CHECK(is_elevated(*s));
        CHECK(effective_role(*s) == Role::admin);
    }
    // …and on a FRESH replica: the elevation + its issued-at anchor round-trip
    // through the durable row, so the kMaxElevationWindow ceiling still admits
    // the (120s) window and is_elevated holds.
    {
        auto b = make_mgr(store);
        auto s = b->validate_session(token);
        REQUIRE(s.has_value());
        CHECK(is_elevated(*s));
        CHECK(effective_role(*s) == Role::admin);
    }

    // Revoke on A → the fresh replica no longer sees an elevation.
    CHECK(a->revoke_elevation(token).value_or(false));
    {
        auto c = make_mgr(store);
        auto s = c->validate_session(token);
        REQUIRE(s.has_value());
        CHECK_FALSE(is_elevated(*s));
        CHECK(effective_role(*s) == Role::user);
    }
}

TEST_CASE("AuthManager+SessionStore: invalidate deletes the durable session",
          "[auth][session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authsess_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    auto a = make_mgr(store);
    auto token = a->create_local_session("dave", Role::admin, /*mfa_verified=*/true);
    REQUIRE(a->validate_session(token).has_value());

    a->invalidate_session(token);
    // Gone on A (local cache + durable row erased)…
    CHECK_FALSE(a->validate_session(token).has_value());
    // …and on a fresh replica (the durable row is deleted).
    auto b = make_mgr(store);
    CHECK_FALSE(b->validate_session(token).has_value());
}

TEST_CASE("AuthManager+SessionStore: invalidate_user_sessions kills every device",
          "[auth][session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authsess_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    auto a = make_mgr(store);
    auto t1 = a->create_local_session("erin", Role::user, false);
    auto t2 = a->create_local_session("erin", Role::user, false);
    auto other = a->create_local_session("frank", Role::user, false);

    auto res = a->invalidate_user_sessions("erin");
    CHECK(res.db_persisted);
    CHECK(res.count == 2);

    auto b = make_mgr(store);
    CHECK_FALSE(b->validate_session(t1).has_value());
    CHECK_FALSE(b->validate_session(t2).has_value());
    CHECK(b->validate_session(other).has_value()); // frank untouched
}

TEST_CASE("AuthManager+SessionStore: a role change durably wipes the user's sessions",
          "[auth][session_store][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, authsess_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    auto a = make_mgr_with_config(store);
    REQUIRE(a->upsert_user("gina", "secret123456", Role::user));
    auto token = a->create_local_session("gina", Role::user, false);
    REQUIRE(a->validate_session(token).has_value());

    // Promote gina → the stale-role session must not survive on any replica:
    // wipe_user_sessions_durable deletes the durable rows (fail-closed on error).
    REQUIRE(a->update_role("gina", Role::admin));
    CHECK_FALSE(a->validate_session(token).has_value());
    auto b = make_mgr(store);
    CHECK_FALSE(b->validate_session(token).has_value()); // gone fleet-wide
}

TEST_CASE("AuthManager+SessionStore: a durable-clear failure fails revoke CLOSED, not false-ok",
          "[auth][session_store][pg][jit]") {
    // Adversarial C2: a durable elevation-clear that fails must be
    // type-distinguishable from a legitimate no-op, so the route fails closed
    // instead of auditing a false revocation while the elevation stays live.
    YUZU_REQUIRE_PG_DB_TPL(db, authsess_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    SessionStore store{pool};
    REQUIRE(store.is_open());

    auto a = make_mgr(store);
    auto token = a->create_local_session("jack", Role::user, /*mfa_verified=*/true);
    REQUIRE(a->elevate_session(token, std::chrono::seconds(120)).has_value());
    REQUIRE(is_elevated(*a->validate_session(token))); // live elevation, cached on `a`

    // Fault-inject: drop the schema so the durable clear_elevation UPDATE fails.
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        yuzu::server::pg::exec_params(lease.get(), "DROP SCHEMA session_store CASCADE",
                                      std::vector<std::string>{});
    }

    // revoke_elevation must return `unexpected` (a store error), NOT expected(false)
    // (a successful no-op). value_or(false) would mask it; assert on has_value().
    auto rev = a->revoke_elevation(token);
    CHECK_FALSE(rev.has_value()); // fail closed — the elevation is still live durably

    // revoke_user_elevations likewise surfaces the failure, not a false "0 cleared".
    auto rvu = a->revoke_user_elevations("jack");
    CHECK_FALSE(rvu.has_value());
}
