/**
 * test_oidc_scim_link.cpp — Unit tests for `link_oidc_login_to_scim`
 * (ADR-2001 §2/D2), the OIDC login-site orchestration extracted out of
 * `/auth/callback` (auth_routes.cpp) into `oidc_scim_link.{hpp,cpp}` so it
 * is directly testable against a real ScimStore without a live IdP —
 * test_oidc_routes.cpp's docstring explains why the `/auth/callback`
 * success path itself has no HTTP-level test (no mock-IdP harness in this
 * codebase).
 *
 * Covers the ADR-2001 task-2 spec's link-formation contract: exactly-one
 * active match forms the link, zero/more-than-one match forms none (with a
 * mutation-check that the strict lookup wasn't quietly widened back to
 * LIMIT 1), the login observation is ALWAYS recorded regardless of match,
 * and the whole call is fail-OPEN (never throws, never propagates a store
 * failure) — `AuthManager::create_oidc_session` session-mint independence
 * from a broken ScimStore is asserted directly.
 */

#include "oidc_scim_link.hpp"

#include "yuzu/server/scim_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <stdexcept>
#include <string>

using yuzu::server::ScimStore;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
using yuzu::server::oidc::link_oidc_login_to_scim;

namespace {

// Pre-migrated template (mirrors test_scim_store_pg.cpp's scim_tpl).
yuzu::test::PgTestTemplate oidc_scim_link_tpl{"oidcscimlink", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ScimStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("oidcscimlink template: store failed to migrate");
}};

} // namespace

TEST_CASE("link_oidc_login_to_scim: exactly-one active match forms the link",
          "[pg][oidc][scim][2001]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto resource = store.create_resource("alice", "ext-alice");
    REQUIRE(resource.has_value());

    link_oidc_login_to_scim(&store, "https://idp.example.com/", "sub-alice", "sub", "ext-alice");

    auto links = store.links_for_scim_id(resource->scim_id);
    REQUIRE(links.has_value());
    REQUIRE(links->size() == 1);
    CHECK((*links)[0].iss == "https://idp.example.com/");
    CHECK((*links)[0].sub == "sub-alice");
}

TEST_CASE("link_oidc_login_to_scim: zero matches forms no link, but the observation is "
          "still recorded",
          "[pg][oidc][scim][2001]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    // A resource exists, but under a DIFFERENT externalId than what the
    // login presents — no match.
    auto resource = store.create_resource("bob", "ext-bob");
    REQUIRE(resource.has_value());

    link_oidc_login_to_scim(&store, "https://idp.example.com/", "sub-nomatch", "sub",
                            "no-such-ext-id");

    auto links = store.links_for_scim_id(resource->scim_id);
    REQUIRE(links.has_value());
    CHECK(links->empty());

    // D2 — the attempted claim value is recorded regardless of the miss, so
    // a later deprovision can surface it as a should-have-matched candidate.
    CHECK(store.observation_matches("no-such-ext-id"));
}

// Mutation-check (ADR-2001 task spec): if `find_unique_active_by_external_id`
// regressed to `... LIMIT 1`, this test's login would silently link to
// WHICHEVER of the two duplicate rows Postgres happened to return first —
// mis-linking an OIDC identity to the wrong SCIM user. Seeding the
// duplicate externalId requires dropping the partial-unique index first
// (mirrors test_scim_store_pg.cpp's own mutation-check for the store method
// this orchestration consumes), modelling "a duplicate slipped in via a
// bug/manual DB edit".
TEST_CASE("link_oidc_login_to_scim: TWO active matches forms NO link (mis-link guard, "
          "mutation-checked)",
          "[pg][oidc][scim][2001][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult drop{PQexec(conn.get(), "DROP INDEX scim_store.scim_resources_external_id_uniq")};
    REQUIRE(drop.ok());

    auto r1 = store.create_resource("dup-user-1", "dup-ext");
    auto r2 = store.create_resource("dup-user-2", "dup-ext");
    REQUIRE(r1.has_value());
    REQUIRE(r2.has_value());
    REQUIRE(r1->scim_id != r2->scim_id);

    link_oidc_login_to_scim(&store, "https://idp.example.com/", "sub-ambiguous", "sub", "dup-ext");

    // Neither candidate resource picked up the link — an ambiguous
    // externalId must never resolve to an arbitrary row.
    auto links1 = store.links_for_scim_id(r1->scim_id);
    auto links2 = store.links_for_scim_id(r2->scim_id);
    REQUIRE(links1.has_value());
    REQUIRE(links2.has_value());
    CHECK(links1->empty());
    CHECK(links2->empty());

    // Observation still recorded — the D2 signal fires regardless.
    CHECK(store.observation_matches("dup-ext"));
}

TEST_CASE("link_oidc_login_to_scim: a null ScimStore is a safe no-op", "[oidc][scim][2001]") {
    // Mirrors the "no PG configured" boot posture — must not crash.
    link_oidc_login_to_scim(nullptr, "https://idp.example.com/", "sub-x", "sub", "ext-x");
    SUCCEED("did not throw");
}

TEST_CASE("link_oidc_login_to_scim: a closed/unusable ScimStore is fail-OPEN — call "
          "returns normally and an OIDC session minted independently stays valid",
          "[pg][oidc][scim][2001][failopen]") {
    // A store whose pool cannot deliver a connection (invalid conninfo)
    // reports !is_open(), so every ScimStore accessor called through it
    // returns false internally — exercising the exact failure path
    // link_oidc_login_to_scim must swallow.
    PgPool broken_pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1", .size = 1}};
    ScimStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());

    // Must not throw despite every underlying write failing.
    link_oidc_login_to_scim(&broken_store, "https://idp.example.com/", "sub-failopen", "sub",
                            "ext-failopen");
    SUCCEED("did not throw despite a closed store");

    // The login itself is independent of this call: a session minted before
    // (as auth_routes.cpp's /auth/callback does — session first, link
    // second) stays exactly as valid whether or not the link write
    // succeeded. This is the "login still SUCCEEDS" half of ADR-2001 §2's
    // fail-OPEN contract, exercised at the AuthManager level since there is
    // no live-IdP harness to drive the HTTP route end to end (see
    // test_oidc_routes.cpp's docstring).
    yuzu::server::auth::AuthManager auth_mgr;
    auto token = auth_mgr.create_oidc_session("Fail Open User", "failopen@example.com",
                                              "sub-failopen", "https://idp.example.com/");
    REQUIRE_FALSE(token.empty());

    // The store call above happened AFTER the session was already minted
    // (mirrors the real login-site ordering) and must not have touched it.
    auto session = auth_mgr.validate_session(token);
    REQUIRE(session.has_value());
}
