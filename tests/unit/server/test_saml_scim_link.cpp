/**
 * test_saml_scim_link.cpp — Unit tests for `link_saml_login_to_scim` and
 * `is_linkable_name_id_format` (ADR-2001 PR4a), the SAML analogue of
 * `test_oidc_scim_link.cpp` — the login-site orchestration extracted out of
 * the `/saml/acs` handler (`auth_routes.cpp`) into `saml_scim_link.{hpp,cpp}`
 * so it is directly testable against a real `ScimStore` without a live IdP.
 *
 * Covers the ADR-2001 PR4a spec's link-formation contract: exactly-one
 * active match forms the link, zero/more-than-one match forms none (with a
 * mutation-check that the strict lookup wasn't quietly widened back to
 * LIMIT 1), the NameID Format gate (architect BLOCK fix — persistent/
 * emailAddress link, transient/unspecified/missing do not, with a
 * mutation-check pinning the gate is actually load-bearing), and the whole
 * call is fail-OPEN (never throws, never propagates a store failure).
 */

#include "saml_scim_link.hpp"

#include "yuzu/server/scim_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <stdexcept>
#include <string>

using yuzu::server::ScimStore;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
using yuzu::server::saml::is_linkable_name_id_format;
using yuzu::server::saml::link_saml_login_to_scim;

namespace {

constexpr const char* kPersistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
constexpr const char* kEmail11    = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
constexpr const char* kTransient  = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

// Pre-migrated template (mirrors test_scim_store_pg.cpp's scim_tpl / the
// oidc_scim_link_tpl sibling in test_oidc_scim_link.cpp).
yuzu::test::PgTestTemplate saml_scim_link_tpl{"samlscimlink", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ScimStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("samlscimlink template: store failed to migrate");
}};

} // namespace

// ── is_linkable_name_id_format ───────────────────────────────────────────

TEST_CASE("is_linkable_name_id_format: persistent and 1.1 emailAddress are linkable",
          "[saml][scim][2001]") {
    CHECK(is_linkable_name_id_format(kPersistent));
    CHECK(is_linkable_name_id_format(kEmail11));
}

TEST_CASE("is_linkable_name_id_format: transient, empty, and an unrecognised format are "
          "NOT linkable",
          "[saml][scim][2001]") {
    CHECK_FALSE(is_linkable_name_id_format(kTransient));
    CHECK_FALSE(is_linkable_name_id_format(""));
    CHECK_FALSE(is_linkable_name_id_format("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"));
    CHECK_FALSE(is_linkable_name_id_format("not-a-format-uri-at-all"));
}

// ── link_saml_login_to_scim: link formation ───────────────────────────────

TEST_CASE("link_saml_login_to_scim: exactly-one active match with a persistent Format forms "
          "the link",
          "[pg][saml][scim][2001]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto resource = store.create_resource("alice", "alice@example.com");
    REQUIRE(resource.has_value());

    link_saml_login_to_scim(&store, "https://idp.example.com/saml/metadata", "alice@example.com",
                            kPersistent);

    auto links = store.saml_links_for_scim_id(resource->scim_id);
    REQUIRE(links.has_value());
    REQUIRE(links->size() == 1);
    CHECK((*links)[0].entity_id == "https://idp.example.com/saml/metadata");
    CHECK((*links)[0].name_id == "alice@example.com");
}

TEST_CASE("link_saml_login_to_scim: exactly-one active match with the SAML 1.1 emailAddress "
          "Format also forms the link",
          "[pg][saml][scim][2001]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto resource = store.create_resource("bob", "bob@example.com");
    REQUIRE(resource.has_value());

    link_saml_login_to_scim(&store, "https://idp.example.com/saml/metadata", "bob@example.com",
                            kEmail11);

    auto links = store.saml_links_for_scim_id(resource->scim_id);
    REQUIRE(links.has_value());
    REQUIRE(links->size() == 1);
}

TEST_CASE("link_saml_login_to_scim: a transient NameID Format forms NO link — the login "
          "site still mints a session independently (MUTATION-CHECK target, see the comment "
          "below)",
          "[pg][saml][scim][2001][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto resource = store.create_resource("carol", "carol@example.com");
    REQUIRE(resource.has_value());

    // externalId matches EXACTLY — only the Format is unstable. If the
    // Format gate were removed, this would form a link (mis-linking a
    // per-login-reassigned identifier into a durable row).
    link_saml_login_to_scim(&store, "https://idp.example.com/saml/metadata", "carol@example.com",
                            kTransient);

    // MUTATION-CHECK (manually verified during development): removing the
    // `if (!is_linkable_name_id_format(name_id_format)) return;` guard in
    // link_saml_login_to_scim makes this REQUIRE fail (a link forms) —
    // confirming this test actually exercises the Format gate rather than
    // passing vacuously because the externalId happened not to match.
    auto links = store.saml_links_for_scim_id(resource->scim_id);
    REQUIRE(links.has_value());
    CHECK(links->empty());

    // The login itself is independent of this call — mirrors
    // test_oidc_scim_link.cpp's fail-OPEN pattern: a session minted before
    // (as auth_routes.cpp's /saml/acs does — link, then mint) stays exactly
    // as valid whether or not a link formed.
    yuzu::server::auth::AuthManager auth_mgr;
    auto token = auth_mgr.create_saml_session("carol@example.com",
                                              "https://idp.example.com/saml/metadata");
    REQUIRE_FALSE(token.empty());
    auto session = auth_mgr.validate_session(token);
    REQUIRE(session.has_value());
}

TEST_CASE("link_saml_login_to_scim: a missing/empty NameID Format forms NO link",
          "[pg][saml][scim][2001][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto resource = store.create_resource("dave", "dave@example.com");
    REQUIRE(resource.has_value());

    link_saml_login_to_scim(&store, "https://idp.example.com/saml/metadata", "dave@example.com",
                            /*name_id_format=*/"");

    auto links = store.saml_links_for_scim_id(resource->scim_id);
    REQUIRE(links.has_value());
    CHECK(links->empty());
}

TEST_CASE("link_saml_login_to_scim: zero matches forms no link", "[pg][saml][scim][2001]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    // A resource exists, but under a DIFFERENT externalId than the login
    // presents — no match.
    auto resource = store.create_resource("erin", "erin@example.com");
    REQUIRE(resource.has_value());

    link_saml_login_to_scim(&store, "https://idp.example.com/saml/metadata",
                            "no-such-name-id@example.com", kPersistent);

    auto links = store.saml_links_for_scim_id(resource->scim_id);
    REQUIRE(links.has_value());
    CHECK(links->empty());
}

// Mutation-check (ADR-2001 PR4a spec, mirrors test_oidc_scim_link.cpp's own
// mis-link mutation-check): if `find_unique_active_by_external_id` regressed
// to `... LIMIT 1`, this test's login would silently link to WHICHEVER of
// the two duplicate rows Postgres happened to return first. Seeding the
// duplicate externalId requires dropping the partial-unique index first
// (mirrors test_scim_store_pg.cpp's own mutation-check for the store method
// this orchestration consumes).
TEST_CASE("link_saml_login_to_scim: TWO active matches forms NO link (mis-link guard, "
          "mutation-checked)",
          "[pg][saml][scim][2001][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, saml_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    PgConn conn{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult drop{PQexec(conn.get(), "DROP INDEX scim_store.scim_resources_external_id_uniq")};
    REQUIRE(drop.ok());

    auto r1 = store.create_resource("dup-user-1", "dup-name-id@example.com");
    auto r2 = store.create_resource("dup-user-2", "dup-name-id@example.com");
    REQUIRE(r1.has_value());
    REQUIRE(r2.has_value());
    REQUIRE(r1->scim_id != r2->scim_id);

    link_saml_login_to_scim(&store, "https://idp.example.com/saml/metadata",
                            "dup-name-id@example.com", kPersistent);

    auto links1 = store.saml_links_for_scim_id(r1->scim_id);
    auto links2 = store.saml_links_for_scim_id(r2->scim_id);
    REQUIRE(links1.has_value());
    REQUIRE(links2.has_value());
    CHECK(links1->empty());
    CHECK(links2->empty());
}

TEST_CASE("link_saml_login_to_scim: a null ScimStore is a safe no-op", "[saml][scim][2001]") {
    // Mirrors the "no PG configured" boot posture — must not crash.
    link_saml_login_to_scim(nullptr, "https://idp.example.com/saml/metadata", "x@example.com",
                            kPersistent);
    SUCCEED("did not throw");
}

TEST_CASE("link_saml_login_to_scim: a closed/unusable ScimStore is fail-OPEN — call returns "
          "normally and a SAML session minted independently stays valid",
          "[pg][saml][scim][2001][failopen]") {
    // A store whose pool cannot deliver a connection (invalid conninfo)
    // reports !is_open(), so every ScimStore accessor called through it
    // returns false/nullopt internally — exercising the exact failure path
    // link_saml_login_to_scim must swallow.
    PgPool broken_pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1", .size = 1}};
    ScimStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());

    // Must not throw despite every underlying write failing.
    link_saml_login_to_scim(&broken_store, "https://idp.example.com/saml/metadata",
                            "failopen@example.com", kPersistent);
    SUCCEED("did not throw despite a closed store");

    // The login itself is independent of this call (mint-then-link at the
    // real ACS handler; here we exercise the reverse order — link-then-mint
    // — which is the actual production order, see auth_routes.cpp).
    yuzu::server::auth::AuthManager auth_mgr;
    auto token = auth_mgr.create_saml_session("failopen@example.com",
                                              "https://idp.example.com/saml/metadata");
    REQUIRE_FALSE(token.empty());
    auto session = auth_mgr.validate_session(token);
    REQUIRE(session.has_value());
}
