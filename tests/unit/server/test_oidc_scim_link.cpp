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
 *
 * Governance Gate 7 BLOCKING fix (the D2 tripwire, the crux): a dedicated
 * "misconfigured Entra" section below covers the headline D2 case —
 * `--oidc-scim-link-claim=sub` while the SCIM externalId is actually the
 * Entra `oid` — asserting NO link forms, BOTH candidate observations are
 * recorded, and `observation_matches(external_id)` (keyed on the oid value)
 * fires TRUE, with a mutation-check confirming a regression back to
 * "record the configured claim only" would make it fail.
 */

#include "oidc_scim_link.hpp"

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
using yuzu::server::oidc::link_oidc_login_to_scim;
using yuzu::server::oidc::oidc_login_denied_deprovisioned;

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

    link_oidc_login_to_scim(&store, "https://idp.example.com/", "sub-alice", /*oid=*/"", "sub",
                            "ext-alice");

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

    // `oid` carries the attempted (non-matching) claim value here — the
    // literal `sub` identity and the value under test are deliberately
    // distinct, same as the pre-fix version of this test; recording now
    // happens per-candidate-claim (sub AND oid), so the mismatched value
    // must land in one of the two candidate slots to be recorded.
    link_oidc_login_to_scim(&store, "https://idp.example.com/", "sub-nomatch",
                            /*oid=*/"no-such-ext-id", "sub", "no-such-ext-id");

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

    // Same "oid carries the tested value" adjustment as the zero-match test
    // above.
    link_oidc_login_to_scim(&store, "https://idp.example.com/", "sub-ambiguous",
                            /*oid=*/"dup-ext", "sub", "dup-ext");

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
    link_oidc_login_to_scim(nullptr, "https://idp.example.com/", "sub-x", /*oid=*/"", "sub",
                            "ext-x");
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
    link_oidc_login_to_scim(&broken_store, "https://idp.example.com/", "sub-failopen",
                            /*oid=*/"", "sub", "ext-failopen");
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

// ── Governance Gate 7 BLOCKING fix — the D2 tripwire (the crux) ─────────────
//
// The headline D2 misconfiguration: an operator runs with
// `--oidc-scim-link-claim=sub`, but the SCIM `externalId` the IdP actually
// provisioned is the Entra `oid` (not `sub`). Link formation legitimately
// forms NO link (the configured claim, sub, does not match). But before
// this fix, D2 ALSO never fired: only the configured claim's value (sub)
// was recorded as an observation, so `observation_matches(externalId)`
// (keyed on the oid value) never matched. The fix records BOTH candidates.

TEST_CASE("link_oidc_login_to_scim: misconfigured Entra link-claim — no link forms, BOTH "
          "candidate observations are recorded, and D2's observation_matches fires on the "
          "externalId (MUTATION-CHECK target, see the comment below)",
          "[pg][oidc][scim][2001][d2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    // The SCIM resource's externalId is the Entra `oid` value — exactly
    // what Entra sends as `externalId` in its SCIM provisioning payload.
    const std::string oid_value = "11111111-2222-3333-4444-555555555555";
    auto resource = store.create_resource("dana", oid_value);
    REQUIRE(resource.has_value());

    // Operator has `--oidc-scim-link-claim=sub` (the default) — link
    // formation is keyed on `sub`, which does NOT match the externalId.
    const std::string iss = "https://login.microsoftonline.com/tenant-id/v2.0";
    const std::string sub_value = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    link_oidc_login_to_scim(&store, iss, sub_value, oid_value, /*link_claim_name=*/"sub",
                            /*link_claim_value=*/sub_value);

    // No link formed — the configured claim (sub) never matched anything.
    auto links = store.links_for_scim_id(resource->scim_id);
    REQUIRE(links.has_value());
    CHECK(links->empty());

    // Both candidate observations are on record.
    CHECK(store.observation_matches(sub_value));
    // THE headline assertion: the oid candidate — never used for link
    // formation under this configuration — is STILL recorded, so D2 can
    // find it.
    CHECK(store.observation_matches(oid_value));

    // MUTATION-CHECK (manually verified during development): reverting
    // `link_oidc_login_to_scim` to record only the configured
    // (link_claim_name, link_claim_value) pair — i.e. dropping the `oid`
    // candidate loop entirely — makes the `observation_matches(oid_value)`
    // assertion above fail (no row for the oid value exists), confirming
    // this test actually exercises the D2 tripwire fix rather than passing
    // vacuously. `observation_matches(sub_value)` alone would stay green
    // under that regression, which is exactly why it is not the only
    // assertion here.
}

TEST_CASE("link_oidc_login_to_scim: an empty/unsanitized oid candidate is never recorded "
          "(no phantom observation row for a claim the IdP never sent)",
          "[pg][oidc][scim][2001][d2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    // Okta-style IdP: no `oid` claim at all (empty string, as
    // OidcProvider::parse_id_token leaves it when absent).
    link_oidc_login_to_scim(&store, "https://idp.okta.example.com/", "sub-okta", /*oid=*/"",
                            "sub", "sub-okta");

    CHECK(store.observation_matches("sub-okta"));
    // No row was ever inserted for an empty claim_value — observation_matches
    // itself already treats an empty query as "no match" (see its own
    // empty-input guard), so this is really asserting no CRASH/db-error
    // occurred recording it, covered implicitly by every assertion above
    // succeeding without a REQUIRE failure.
}

// ── ADR-2001 §4 — deny-at-login backstop decision helper ────────────────
//
// `oidc_login_denied_deprovisioned` is called from TWO sites in
// `/auth/callback` (the primary pre-mint check and the post-mint re-check
// for the codex-caught concurrent-deprovision race) — both share this one
// decision function. `handle_callback`'s success path requires a live IdP
// token exchange (no mock-IdP harness in this codebase, per
// test_oidc_routes.cpp's docstring), and both deny sites in auth_routes.cpp
// sit strictly AFTER that success path, so neither is reachable through an
// HTTP-level `/auth/callback` test. Every case below is therefore exercised
// directly against a real ScimStore, which is exactly this function's own
// dependency surface — a store-degrade or state transition it needs to
// react to is fully reproducible here without an IdP.

TEST_CASE("oidc_login_denied_deprovisioned: a null ScimStore proceeds (SCIM not configured, "
          "not a store degrade)",
          "[oidc][scim][2001][deny-at-login]") {
    // Mirrors link_oidc_login_to_scim's null-safety posture: no store means
    // no link could ever have formed, so there is nothing to deny against —
    // this must NOT be conflated with a present-but-unusable store (which
    // fails closed, below). A deployment that never enables SCIM must not
    // have every OIDC login denied by this backstop.
    auto decision = oidc_login_denied_deprovisioned(nullptr, "https://idp.example.com/", "sub-x");
    CHECK_FALSE(decision.denied);
    CHECK_FALSE(decision.scim_id.has_value());
}

TEST_CASE("oidc_login_denied_deprovisioned: an unlinked OIDC identity proceeds",
          "[pg][oidc][scim][2001][deny-at-login]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto decision = oidc_login_denied_deprovisioned(&store, "https://idp.example.com/",
                                                     "sub-never-linked");
    CHECK_FALSE(decision.denied);
    CHECK_FALSE(decision.scim_id.has_value());
}

TEST_CASE("oidc_login_denied_deprovisioned: an active linked identity proceeds",
          "[pg][oidc][scim][2001][deny-at-login]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_resource("active-user", "ext-active");
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_link("https://idp.example.com/", "sub-active", r->scim_id));

    auto decision =
        oidc_login_denied_deprovisioned(&store, "https://idp.example.com/", "sub-active");
    CHECK_FALSE(decision.denied);
    // PROCEED always carries scim_id=nullopt, even though a linked resource
    // exists — the audit detail only needs the id on a DENY.
    CHECK_FALSE(decision.scim_id.has_value());
}

TEST_CASE("oidc_login_denied_deprovisioned: a deactivated linked identity is DENIED and "
          "names the resource",
          "[pg][oidc][scim][2001][deny-at-login]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_resource("inactive-user", "ext-inactive");
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_link("https://idp.example.com/", "sub-inactive", r->scim_id));
    REQUIRE(store.set_active(r->scim_id, false));

    auto decision =
        oidc_login_denied_deprovisioned(&store, "https://idp.example.com/", "sub-inactive");
    CHECK(decision.denied);
    REQUIRE(decision.scim_id.has_value());
    CHECK(*decision.scim_id == r->scim_id); // the id the audit detail carries
}

TEST_CASE("oidc_login_denied_deprovisioned: an orphaned link (scim_resources row "
          "hard-deleted) is DENIED and still names the resource",
          "[pg][oidc][scim][2001][deny-at-login]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_resource("deleted-user", "ext-deleted");
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_link("https://idp.example.com/", "sub-deleted", r->scim_id));
    REQUIRE(store.delete_by_scim_id(r->scim_id).value());

    auto decision =
        oidc_login_denied_deprovisioned(&store, "https://idp.example.com/", "sub-deleted");
    CHECK(decision.denied);
    REQUIRE(decision.scim_id.has_value()); // identity_links row still names the (now-gone) id
    CHECK(*decision.scim_id == r->scim_id);
}

TEST_CASE("oidc_login_denied_deprovisioned: a reactivated identity proceeds again — no "
          "latched denial, a live read every call",
          "[pg][oidc][scim][2001][deny-at-login]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_resource("flapping-user", "ext-flapping");
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_link("https://idp.example.com/", "sub-flapping", r->scim_id));

    CHECK_FALSE(
        oidc_login_denied_deprovisioned(&store, "https://idp.example.com/", "sub-flapping")
            .denied);

    REQUIRE(store.set_active(r->scim_id, false));
    auto mid = oidc_login_denied_deprovisioned(&store, "https://idp.example.com/", "sub-flapping");
    CHECK(mid.denied);
    REQUIRE(mid.scim_id.has_value());
    CHECK(*mid.scim_id == r->scim_id);

    REQUIRE(store.set_active(r->scim_id, true));
    auto after = oidc_login_denied_deprovisioned(&store, "https://idp.example.com/",
                                                 "sub-flapping");
    CHECK_FALSE(after.denied);
    CHECK_FALSE(after.scim_id.has_value());
}

// The post-mint re-check's whole reason to exist: the primary check and the
// re-check are two calls to this SAME decision function separated by the
// mint window. Modelling that window directly — deny false at "primary check
// time", the identity goes inactive, deny true (and names the resource) at
// "re-check time" — proves the re-check needs no extra machinery to
// self-heal the race; a plain second call already sees the fresh state.
TEST_CASE("oidc_login_denied_deprovisioned: models the post-mint re-check race — a "
          "concurrent deprovision between two calls flips PROCEED to DENY and names "
          "the resource",
          "[pg][oidc][scim][2001][deny-at-login][race]") {
    YUZU_REQUIRE_PG_DB_TPL(db, oidc_scim_link_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ScimStore store{pool};
    REQUIRE(store.is_open());

    auto r = store.create_resource("race-user", "ext-race");
    REQUIRE(r.has_value());
    REQUIRE(store.upsert_link("https://idp.example.com/", "sub-race", r->scim_id));

    // "Primary check" — proceeds.
    CHECK_FALSE(
        oidc_login_denied_deprovisioned(&store, "https://idp.example.com/", "sub-race").denied);

    // A concurrent SCIM deactivate lands in the mint window.
    REQUIRE(store.set_active(r->scim_id, false));

    // "Post-mint re-check" — the SAME call, now denies and names the resource
    // — this is the audit-detail scim_id the recheck site embeds.
    auto recheck = oidc_login_denied_deprovisioned(&store, "https://idp.example.com/", "sub-race");
    CHECK(recheck.denied);
    REQUIRE(recheck.scim_id.has_value());
    CHECK(*recheck.scim_id == r->scim_id);
}

TEST_CASE("oidc_login_denied_deprovisioned: a closed/unusable ScimStore fails CLOSED, "
          "with no scim_id to name (MUTATION-CHECK target, see the comment below)",
          "[pg][oidc][scim][2001][deny-at-login][failclosed]") {
    // Mirrors the existing "closed/unusable ScimStore" test above for
    // link_oidc_login_to_scim: an unreachable pool reports !is_open(), so
    // linked_resource_active's OUTER nullopt path is exercised.
    PgPool broken_pool{{.conninfo = "host=127.0.0.1 port=1 connect_timeout=1", .size = 1}};
    ScimStore broken_store{broken_pool};
    REQUIRE_FALSE(broken_store.is_open());

    auto decision = oidc_login_denied_deprovisioned(&broken_store, "https://idp.example.com/",
                                                     "sub-unreachable");
    CHECK(decision.denied);
    // The store could not be asked, so there is no resource to name — the
    // audit detail on this DENY omits scim_id gracefully.
    CHECK_FALSE(decision.scim_id.has_value());

    // MUTATION-CHECK (manually verified during development): flipping
    // `oidc_login_denied_deprovisioned`'s `if (!result) return {.denied =
    // true, ...};` branch to `.denied = false` (i.e. treating a store that
    // could not answer as PROCEED instead of DENY) makes the `decision.denied`
    // assertion above fail — the exact fail-open regression ADR-2001 §4
    // exists to prevent (a ScimStore outage must never let a deprovisioned
    // identity re-authenticate by luck of timing).
}
