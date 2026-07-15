/**
 * test_api_token_store.cpp — Unit tests for the Postgres-backed API token
 * authentication store (PR 4.1 port, schema `api_token_store`, ADR-0006/0012).
 *
 * PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, FAILS when it is set
 * but broken (test_helpers.hpp skip-vs-fail contract). Store-behaviour tests
 * clone a pre-migrated PgTestTemplate (one migration paid across the whole
 * file, not per test); the migration-failure test stays on plain
 * YUZU_REQUIRE_PG_DB — it needs an unmigrated database to pre-seed a
 * conflicting schema against.
 */

#include "api_token_store.hpp"
#include "engine_principal_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <latch>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp).
yuzu::test::PgTestTemplate api_token_tpl{"apitoken", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ApiTokenStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("apitoken template: store failed to migrate");
}};

} // namespace

// ── Construction fail-closed ──────────────────────────────────────────────
//
// ADR-0012 §1: construction is fail-CLOSED — a reachable database whose
// schema can't migrate leaves the store !is_open(), which server.cpp wires
// to startup_failed_ (refuse to start, not serve-degraded). Force the
// failure by pre-seeding the store's schema with a conflicting table and no
// schema_meta row: the migration runner's drift guard refuses. Mirrors
// test_preflight_run_store.cpp's "reports !is_open on a migration failure".
TEST_CASE("ApiTokenStore reports !is_open on a migration failure", "[pg][token][store]") {
    YUZU_REQUIRE_PG_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA api_token_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE api_token_store.api_tokens (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    ApiTokenStore store{pool};
    CHECK_FALSE(store.is_open()); // → server.cpp sets startup_failed_ (fail-closed)
}

// ── Regression guard: behaviour preserved verbatim across the PG port ────

TEST_CASE("ApiTokenStore: create and validate token", "[pg][token][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.create_token("Test Token", "admin");
    REQUIRE(result.has_value());
    CHECK(result->starts_with("yuzu_"));
    CHECK(result->size() == 37); // "yuzu_" + 32 chars

    auto validated = store.validate_token(*result);
    REQUIRE(validated.has_value());
    CHECK(validated->name == "Test Token");
    CHECK(validated->principal_id == "admin");
    CHECK(validated->created_at > 0);
}

TEST_CASE("ApiTokenStore: invalid token rejected", "[pg][token][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto validated = store.validate_token("yuzu_invalid_token_123456789012");
    CHECK(!validated.has_value());
}

TEST_CASE("ApiTokenStore: empty token rejected", "[pg][token][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto validated = store.validate_token("");
    CHECK(!validated.has_value());
}

TEST_CASE("ApiTokenStore: revoked token rejected", "[pg][token][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto raw = store.create_token("Revocable", "admin");
    REQUIRE(raw.has_value());

    // Validate before revocation
    auto valid1 = store.validate_token(*raw);
    REQUIRE(valid1.has_value());

    // Revoke
    bool revoked = store.revoke_token(valid1->token_id);
    CHECK(revoked);

    // Validate after revocation
    auto valid2 = store.validate_token(*raw);
    CHECK(!valid2.has_value());
}

TEST_CASE("ApiTokenStore: expired token rejected", "[pg][token][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    // Create token that expired 1 second ago
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    auto raw = store.create_token("Expired", "admin", now - 1);
    REQUIRE(raw.has_value());

    auto validated = store.validate_token(*raw);
    CHECK(!validated.has_value());
}

TEST_CASE("ApiTokenStore: list tokens", "[pg][token][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    store.create_token("Token A", "alice");
    store.create_token("Token B", "alice");
    store.create_token("Token C", "bob");

    auto all = store.list_tokens();
    CHECK(all.size() == 3);

    auto alice_tokens = store.list_tokens("alice");
    CHECK(alice_tokens.size() == 2);

    auto bob_tokens = store.list_tokens("bob");
    CHECK(bob_tokens.size() == 1);

    // Token hashes should never be exposed in listings
    for (const auto& t : all)
        CHECK(t.token_hash.empty());
}

TEST_CASE("ApiTokenStore: delete token", "[pg][token][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto raw = store.create_token("Deletable", "admin");
    REQUIRE(raw.has_value());

    auto valid = store.validate_token(*raw);
    REQUIRE(valid.has_value());

    bool deleted = store.delete_token(valid->token_id);
    CHECK(deleted);

    auto after = store.validate_token(*raw);
    CHECK(!after.has_value());

    auto list = store.list_tokens();
    CHECK(list.empty());
}

TEST_CASE("ApiTokenStore: last_used_at updated on validation", "[pg][token][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto raw = store.create_token("Usage", "admin");
    REQUIRE(raw.has_value());

    auto before = store.list_tokens();
    REQUIRE(before.size() == 1);
    CHECK(before[0].last_used_at == 0);

    store.validate_token(*raw);

    auto after = store.list_tokens();
    REQUIRE(after.size() == 1);
    CHECK(after[0].last_used_at > 0);
}

TEST_CASE("ApiTokenStore: empty name rejected", "[pg][token][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto result = store.create_token("", "admin");
    CHECK(!result.has_value());
}

TEST_CASE("ApiTokenStore: revoke nonexistent token", "[pg][token][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    bool revoked = store.revoke_token("nonexistent");
    CHECK(!revoked);
}

// ── get_token: metadata lookup for owner-scoped revoke (#222) ────────────────

TEST_CASE("ApiTokenStore: get_token returns metadata for ownership check",
          "[pg][token][crud][owner]") {
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto raw = store.create_token("Alice's token", "alice");
    REQUIRE(raw.has_value());
    auto listing = store.list_tokens("alice");
    REQUIRE(listing.size() == 1);
    auto token_id = listing[0].token_id;

    auto looked_up = store.get_token(token_id);
    REQUIRE(looked_up.has_value());
    CHECK(looked_up->token_id == token_id);
    CHECK(looked_up->principal_id == "alice");
    CHECK(looked_up->name == "Alice's token");
    CHECK(looked_up->revoked == false);
    // The raw hash must never surface through metadata lookups.
    CHECK(looked_up->token_hash.empty());
}

TEST_CASE("ApiTokenStore: get_token returns nullopt for unknown id",
          "[pg][token][crud][owner]") {
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    CHECK(!store.get_token("does-not-exist").has_value());
    CHECK(!store.get_token("").has_value());
}

TEST_CASE("ApiTokenStore: list_tokens(principal) scopes results to owner",
          "[pg][token][crud][owner]") {
    // Gate 4 consistency auditor finding C1: the Settings dashboard
    // `render_api_tokens_fragment` previously called list_tokens() with no
    // principal filter, rendering every user's token IDs, names, owners,
    // timestamps, and MCP tiers in the HTMX response body to anyone
    // holding `ApiToken:Read`. The fix scopes the fragment by
    // `session->username` for non-admin sessions. This test pins the
    // underlying store contract the fix depends on: list_tokens(principal)
    // must return ONLY that principal's tokens, with no leakage across
    // owners.
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    REQUIRE(store.create_token("alice-a", "alice").has_value());
    REQUIRE(store.create_token("alice-b", "alice").has_value());
    REQUIRE(store.create_token("bob-a", "bob").has_value());
    REQUIRE(store.create_token("root-a", "root").has_value());

    auto alice_tokens = store.list_tokens("alice");
    auto bob_tokens = store.list_tokens("bob");
    auto root_tokens = store.list_tokens("root");
    auto all_tokens = store.list_tokens();

    REQUIRE(alice_tokens.size() == 2);
    REQUIRE(bob_tokens.size() == 1);
    REQUIRE(root_tokens.size() == 1);
    REQUIRE(all_tokens.size() == 4);

    // Every token returned for alice is owned by alice — no cross-contamination.
    for (const auto& t : alice_tokens)
        CHECK(t.principal_id == "alice");
    for (const auto& t : bob_tokens)
        CHECK(t.principal_id == "bob");
    for (const auto& t : root_tokens)
        CHECK(t.principal_id == "root");

    // Bob's name does not appear in alice's listing under any column.
    for (const auto& t : alice_tokens) {
        CHECK(t.name != "bob-a");
        CHECK(t.name != "root-a");
    }
}

TEST_CASE("ApiTokenStore: get_token distinguishes owners for IDOR defense",
          "[pg][token][crud][owner]") {
    // This test encodes the core invariant that the REST DELETE handler
    // relies on to close #222: looking up a token by id must surface the
    // owning principal_id so the handler can reject cross-user revokes.
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    REQUIRE(store.create_token("alice-key", "alice").has_value());
    REQUIRE(store.create_token("bob-key", "bob").has_value());

    auto alice_tokens = store.list_tokens("alice");
    auto bob_tokens = store.list_tokens("bob");
    REQUIRE(alice_tokens.size() == 1);
    REQUIRE(bob_tokens.size() == 1);

    auto alice_looked_up = store.get_token(alice_tokens[0].token_id);
    auto bob_looked_up = store.get_token(bob_tokens[0].token_id);
    REQUIRE(alice_looked_up.has_value());
    REQUIRE(bob_looked_up.has_value());
    CHECK(alice_looked_up->principal_id == "alice");
    CHECK(bob_looked_up->principal_id == "bob");
    CHECK(alice_looked_up->principal_id != bob_looked_up->principal_id);
}

// ── New coverage (PR 4.1): principal_kind ─────────────────────────────────

TEST_CASE("ApiTokenStore: principal_kind defaults to 'human' for a row inserted without it",
          "[pg][token][crud][principal_kind]") {
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    // Bypass principal_kind entirely — the column's DEFAULT 'human' must
    // apply, mirroring every pre-port token row (the migration adds the
    // column with that default; existing rows never set it explicitly).
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(
            lease.get(),
            "INSERT INTO api_token_store.api_tokens (token_id, token_hash, name, principal_id) "
            "VALUES ($1,$2,$3,$4)",
            std::vector<std::string>{"legacy-row", "legacy-row-hash", "Legacy Token", "admin"});
        REQUIRE(res.ok());
    }

    auto looked_up = store.get_token("legacy-row");
    REQUIRE(looked_up.has_value());
    CHECK(looked_up->principal_kind == "human");

    auto listing = store.list_tokens("admin");
    REQUIRE(listing.size() == 1);
    CHECK(listing[0].principal_kind == "human");
}

TEST_CASE("ApiTokenStore: principal_kind round-trips through create -> validate/get/list",
          "[pg][token][crud][principal_kind]") {
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    // Engine block prerequisites (design doc §6/§7/§8): mcp_tier must be
    // "readonly", expires_at must be non-zero and within the 90-day ceiling,
    // and the referent resolver must be wired — a stub reporting Active,
    // matching how server.cpp wires the real EnginePrincipalStore.
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    auto human_raw = store.create_token("human-token", "alice");
    REQUIRE(human_raw.has_value());
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    auto engine_raw =
        store.create_token("engine-token", "svc-ci", now + 3600, "", "readonly", "engine");
    REQUIRE(engine_raw.has_value());

    auto human_v = store.validate_token(*human_raw);
    REQUIRE(human_v.has_value());
    CHECK(human_v->principal_kind == "human");

    auto engine_v = store.validate_token(*engine_raw);
    REQUIRE(engine_v.has_value());
    CHECK(engine_v->principal_kind == "engine");

    auto human_meta = store.get_token(human_v->token_id);
    REQUIRE(human_meta.has_value());
    CHECK(human_meta->principal_kind == "human");
    auto engine_meta = store.get_token(engine_v->token_id);
    REQUIRE(engine_meta.has_value());
    CHECK(engine_meta->principal_kind == "engine");

    auto listing = store.list_tokens();
    REQUIRE(listing.size() == 2);
    int human_count = 0, engine_count = 0;
    for (const auto& t : listing) {
        if (t.principal_kind == "human")
            ++human_count;
        else if (t.principal_kind == "engine")
            ++engine_count;
        else
            FAIL("unexpected principal_kind: " << t.principal_kind);
    }
    CHECK(human_count == 1);
    CHECK(engine_count == 1);
}

// ── New coverage (PR 4.1): RETURNING-based mutate-and-return idiom (#1033) ─

TEST_CASE("ApiTokenStore: revoke_token RETURNING contract — false for an unknown id, true "
          "and cache-invalidated for a real one",
          "[pg][token][crud][returning]") {
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    CHECK_FALSE(store.revoke_token("does-not-exist"));

    auto raw = store.create_token("returning-revoke", "admin");
    REQUIRE(raw.has_value());
    auto validated = store.validate_token(*raw); // populates the in-memory cache
    REQUIRE(validated.has_value());
    CHECK(store.cache_size() == 1);

    CHECK(store.revoke_token(validated->token_id));
    // Cache invalidation: a follow-up validate must not resurrect the
    // pre-revoke cached (revoked=false) entry within the 60s TTL window —
    // it must fall through to Postgres and see revoked=TRUE.
    CHECK_FALSE(store.validate_token(*raw).has_value());
}

TEST_CASE("ApiTokenStore: delete_token RETURNING contract — false for an unknown id, true "
          "and cache-invalidated for a real one",
          "[pg][token][crud][returning]") {
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    CHECK_FALSE(store.delete_token("does-not-exist"));

    auto raw = store.create_token("returning-delete", "admin");
    REQUIRE(raw.has_value());
    auto validated = store.validate_token(*raw);
    REQUIRE(validated.has_value());

    CHECK(store.delete_token(validated->token_id));
    CHECK_FALSE(store.validate_token(*raw).has_value());
    CHECK_FALSE(store.get_token(validated->token_id).has_value());
}

TEST_CASE("ApiTokenStore: revoke_for_principal returns the exact affected count and "
          "invalidates every cached hash",
          "[pg][token][crud][returning]") {
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto r1 = store.create_token("p1", "carol");
    auto r2 = store.create_token("p2", "carol");
    auto r3 = store.create_token("other-owner", "dave");
    REQUIRE(r1.has_value());
    REQUIRE(r2.has_value());
    REQUIRE(r3.has_value());

    // Populate the cache for all three so invalidation is actually exercised.
    REQUIRE(store.validate_token(*r1).has_value());
    REQUIRE(store.validate_token(*r2).has_value());
    REQUIRE(store.validate_token(*r3).has_value());
    CHECK(store.cache_size() == 3);

    auto n = store.revoke_for_principal("carol");
    CHECK(n == 2);

    // Carol's tokens are gone even via cache (invalidated) — not merely
    // revoked-in-the-database-but-still-cached-valid.
    CHECK_FALSE(store.validate_token(*r1).has_value());
    CHECK_FALSE(store.validate_token(*r2).has_value());
    // Dave's token, and his cache entry, are untouched.
    CHECK(store.validate_token(*r3).has_value());

    // No principal / unknown principal is a strict no-op — never a fail-open
    // "revoked everything".
    CHECK(store.revoke_for_principal("nobody") == 0);
    CHECK(store.revoke_for_principal("") == 0);
}

// ── New coverage (PR 4.1): revoke_generation_ cache TOCTOU guard ─────────
//
// The header/impl comment (api_token_store.hpp/.cpp) documents the contract:
// under the pool there is no single connection-wide mutex serializing a
// validate_token's SELECT against a concurrent revoke_token's UPDATE the way
// the old sqlite db_mtx_ did, so revoke_generation_ is the SOLE guard against
// a stale (revoked=false) cache write surviving a race.
//
// A literal single-threaded reproduction is not possible through the public
// API alone (there is no injection point to pause validate_token between its
// snapshot and its cache-write re-check without a store-side test hook,
// which is out of this port's scope). This test instead makes the race
// reliable — not luck-dependent — by exploiting a structural asymmetry:
// validate_token needs TWO sequential Postgres round trips (SELECT, then the
// last_used_at UPDATE) before it reaches the generation re-check, while
// revoke_token's generation bump is an in-memory fetch_add that runs BEFORE
// its own single UPDATE round trip even starts. Releasing both calls from
// the same std::latch means revoke_token's bump is essentially guaranteed to
// land inside validate_token's window every run on any real machine (an
// atomic increment vs. two live network round trips), so this is
// deterministic in practice even though it is two threads, not one.
TEST_CASE("ApiTokenStore: revoke_generation_ guard prevents a stale cache write racing a "
          "concurrent revoke",
          "[pg][token][auth][toctou]") {
    YUZU_REQUIRE_PG_DB_TPL(db, api_token_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("race-token", "admin");
    REQUIRE(raw.has_value());
    auto listing = store.list_tokens("admin");
    REQUIRE(listing.size() == 1);
    auto token_id = listing[0].token_id;

    std::latch start{2};
    std::optional<ApiToken> validated;
    bool revoked = false;
    std::thread t_validate([&] {
        start.arrive_and_wait();
        validated = store.validate_token(*raw);
    });
    std::thread t_revoke([&] {
        start.arrive_and_wait();
        revoked = store.revoke_token(token_id);
    });
    t_validate.join();
    t_revoke.join();

    CHECK(revoked);
    // Whatever validate_token itself returned for THIS race is secondary —
    // the guard's job is that no STALE cache entry survives. Assert against
    // the cache directly: a follow-up validate_token (strictly after both
    // threads have joined) must never resurrect a pre-revoke "still valid"
    // answer from a racy cache write.
    auto after = store.validate_token(*raw);
    CHECK_FALSE(after.has_value());
}
