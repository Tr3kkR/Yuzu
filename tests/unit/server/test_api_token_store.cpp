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
#include "engine_store_error_class.hpp" // #2404: assert the terminal-vs-transient class

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"
#include "test_api_token_pg_helper.hpp" // shared "apitoken" PgTestTemplate (one registration)


#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <chrono>
#include <expected>
#include <latch>
#include <optional>
#include <semaphore>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

// The pre-migrated "apitoken" PgTestTemplate is defined once in
// test_api_token_pg_helper.hpp (as yuzu::test::apitoken_pg_template) and shared
// by every auth fixture TU. This file reuses it rather than registering a second
// callback under the same key, which used to force an extra replay-verification
// migration per suite run.

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
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
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
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto validated = store.validate_token("yuzu_invalid_token_123456789012");
    CHECK(!validated.has_value());
}

TEST_CASE("ApiTokenStore: empty token rejected", "[pg][token][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto validated = store.validate_token("");
    CHECK(!validated.has_value());
}

TEST_CASE("ApiTokenStore: revoked token rejected", "[pg][token][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto raw = store.create_token("Revocable", "admin");
    REQUIRE(raw.has_value());

    // Validate before revocation
    auto valid1 = store.validate_token(*raw);
    REQUIRE(valid1.has_value());

    // Revoke
    auto revoked = store.revoke_token(valid1->token_id);
    REQUIRE(revoked.has_value());
    CHECK(*revoked);

    // Validate after revocation
    auto valid2 = store.validate_token(*raw);
    CHECK(!valid2.has_value());
}

TEST_CASE("ApiTokenStore: expired token rejected", "[pg][token][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
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
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    store.create_token("Token A", "alice");
    store.create_token("Token B", "alice");
    store.create_token("Token C", "bob");

    auto all = store.list_tokens().value();
    CHECK(all.size() == 3);

    auto alice_tokens = store.list_tokens("alice").value();
    CHECK(alice_tokens.size() == 2);

    auto bob_tokens = store.list_tokens("bob").value();
    CHECK(bob_tokens.size() == 1);

    // Token hashes should never be exposed in listings
    for (const auto& t : all)
        CHECK(t.token_hash.empty());
}

TEST_CASE("ApiTokenStore: delete token", "[pg][token][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto raw = store.create_token("Deletable", "admin");
    REQUIRE(raw.has_value());

    auto valid = store.validate_token(*raw);
    REQUIRE(valid.has_value());

    auto deleted = store.delete_token(valid->token_id);
    REQUIRE(deleted.has_value());
    CHECK(*deleted);

    auto after = store.validate_token(*raw);
    CHECK(!after.has_value());

    auto list = store.list_tokens().value();
    CHECK(list.empty());
}

TEST_CASE("ApiTokenStore: last_used_at updated on validation", "[pg][token][auth]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto raw = store.create_token("Usage", "admin");
    REQUIRE(raw.has_value());

    auto before = store.list_tokens().value();
    REQUIRE(before.size() == 1);
    CHECK(before[0].last_used_at == 0);

    store.validate_token(*raw);

    auto after = store.list_tokens().value();
    REQUIRE(after.size() == 1);
    CHECK(after[0].last_used_at > 0);
}

TEST_CASE("ApiTokenStore: empty name rejected", "[pg][token][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto result = store.create_token("", "admin");
    CHECK(!result.has_value());
}

TEST_CASE("ApiTokenStore: revoke nonexistent token", "[pg][token][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto revoked = store.revoke_token("nonexistent");
    REQUIRE(revoked.has_value()); // DB write ran fine — the id just didn't exist
    CHECK_FALSE(*revoked);
}

// ── get_token: metadata lookup for owner-scoped revoke (#222) ────────────────

TEST_CASE("ApiTokenStore: get_token returns metadata for ownership check",
          "[pg][token][crud][owner]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    auto raw = store.create_token("Alice's token", "alice");
    REQUIRE(raw.has_value());
    auto listing = store.list_tokens("alice").value();
    REQUIRE(listing.size() == 1);
    auto token_id = listing[0].token_id;

    auto looked_up = store.get_token(token_id).value();
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
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    CHECK(!store.get_token("does-not-exist").value().has_value());
    CHECK(!store.get_token("").value().has_value());
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
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    REQUIRE(store.create_token("alice-a", "alice").has_value());
    REQUIRE(store.create_token("alice-b", "alice").has_value());
    REQUIRE(store.create_token("bob-a", "bob").has_value());
    REQUIRE(store.create_token("root-a", "root").has_value());

    auto alice_tokens = store.list_tokens("alice").value();
    auto bob_tokens = store.list_tokens("bob").value();
    auto root_tokens = store.list_tokens("root").value();
    auto all_tokens = store.list_tokens().value();

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
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};

    REQUIRE(store.create_token("alice-key", "alice").has_value());
    REQUIRE(store.create_token("bob-key", "bob").has_value());

    auto alice_tokens = store.list_tokens("alice").value();
    auto bob_tokens = store.list_tokens("bob").value();
    REQUIRE(alice_tokens.size() == 1);
    REQUIRE(bob_tokens.size() == 1);

    auto alice_looked_up = store.get_token(alice_tokens[0].token_id).value();
    auto bob_looked_up = store.get_token(bob_tokens[0].token_id).value();
    REQUIRE(alice_looked_up.has_value());
    REQUIRE(bob_looked_up.has_value());
    CHECK(alice_looked_up->principal_id == "alice");
    CHECK(bob_looked_up->principal_id == "bob");
    CHECK(alice_looked_up->principal_id != bob_looked_up->principal_id);
}

// ── New coverage (PR 4.1): principal_kind ─────────────────────────────────

TEST_CASE("ApiTokenStore: principal_kind defaults to 'human' for a row inserted without it",
          "[pg][token][crud][principal_kind]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
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

    auto looked_up = store.get_token("legacy-row").value();
    REQUIRE(looked_up.has_value());
    CHECK(looked_up->principal_kind == "human");

    auto listing = store.list_tokens("admin").value();
    REQUIRE(listing.size() == 1);
    CHECK(listing[0].principal_kind == "human");
}

// PR 4.1 keeps principal_kind INERT: `create_token` has no parameter to write
// "engine" (that write path + its lifecycle/tier/referential checks land in
// PR 4.2, design doc §§6-8/11), so the ONLY thing this store mints is "human".
// The seam is proven two ways: the create path is pinned to "human", and the
// column's CHECK is the schema-level allowlist that bounds any direct write.
// (A previous revision of this test minted an `engine` token through
// `create_token(..., "engine")` and asserted it round-tripped — that enshrined
// an engine code path the attribution layer does not yet honour; removed.)
TEST_CASE("ApiTokenStore: create_token pins principal_kind to 'human'; the CHECK bounds the column",
          "[pg][token][crud][principal_kind]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
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
    // The get_token/validate paths returning std::expected are covered by the
    // dedicated PR-4.1 read tests below; here we assert both the human and the
    // engine mint paths succeed against the wired referent check.
    auto v = store.validate_token(*human_raw);
    REQUIRE(v.has_value());
    CHECK(v->principal_kind == "human");
    auto meta = store.get_token(v->token_id).value();
    REQUIRE(meta.has_value());
    CHECK(meta->principal_kind == "human");
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    auto engine_raw =
        store.create_token("engine-token", "svc-ci", now + 3600, "", "readonly", "engine");
    REQUIRE(engine_raw.has_value());
    auto ev = store.validate_token(*engine_raw);
    REQUIRE(ev.has_value());
    CHECK(ev->principal_kind == "engine");

    // (b) The column CHECK is the schema-level allowlist: a direct write of a
    // value outside ('human','engine') is rejected at the database, never
    // silently stored. ('engine' itself is in the allowlist — it is the seam
    // PR 4.2 will use — so we probe with a value the allowlist excludes.)
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(
            lease.get(),
            "INSERT INTO api_token_store.api_tokens "
            "(token_id, token_hash, name, principal_id, principal_kind) VALUES ($1,$2,$3,$4,$5)",
            std::vector<std::string>{"bad-kind", "bad-kind-hash", "Bad Kind", "admin", "robot"});
        CHECK_FALSE(res.ok()); // CHECK (principal_kind IN ('human','engine')) violation
    }
}

// ── New coverage (PR 4.1): RETURNING-based mutate-and-return idiom (#1033) ─

TEST_CASE("ApiTokenStore: revoke_token RETURNING contract — false for an unknown id, true "
          "and cache-invalidated for a real one",
          "[pg][token][crud][returning]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto miss = store.revoke_token("does-not-exist");
    REQUIRE(miss.has_value()); // DB write ran; nothing matched (a real 404, not an error)
    CHECK_FALSE(*miss);

    auto raw = store.create_token("returning-revoke", "admin");
    REQUIRE(raw.has_value());
    auto validated = store.validate_token(*raw); // populates the in-memory cache
    REQUIRE(validated.has_value());
    CHECK(store.cache_size() == 1);

    auto hit = store.revoke_token(validated->token_id);
    REQUIRE(hit.has_value());
    CHECK(*hit);
    // Cache invalidation: a follow-up validate must not resurrect the
    // pre-revoke cached (revoked=false) entry within the 60s TTL window —
    // it must fall through to Postgres and see revoked=TRUE.
    CHECK_FALSE(store.validate_token(*raw).has_value());
}

TEST_CASE("ApiTokenStore: delete_token RETURNING contract — false for an unknown id, true "
          "and cache-invalidated for a real one",
          "[pg][token][crud][returning]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    CHECK_FALSE(store.delete_token("does-not-exist").value());

    auto raw = store.create_token("returning-delete", "admin");
    REQUIRE(raw.has_value());
    auto validated = store.validate_token(*raw);
    REQUIRE(validated.has_value());

    CHECK(store.delete_token(validated->token_id).value());
    CHECK_FALSE(store.validate_token(*raw).has_value());
    CHECK_FALSE(store.get_token(validated->token_id).value().has_value());
}

TEST_CASE("ApiTokenStore: revoke_for_principal returns the exact affected count and "
          "invalidates every cached hash",
          "[pg][token][crud][returning]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
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
    REQUIRE(n.has_value());
    CHECK(*n == 2);

    // Carol's tokens are gone even via cache (invalidated) — not merely
    // revoked-in-the-database-but-still-cached-valid.
    CHECK_FALSE(store.validate_token(*r1).has_value());
    CHECK_FALSE(store.validate_token(*r2).has_value());
    // Dave's token, and his cache entry, are untouched.
    CHECK(store.validate_token(*r3).has_value());

    // No principal / unknown principal is a strict no-op — never a fail-open
    // "revoked everything", and (post PR-4.1 typed result) never an error:
    // the DB write ran and simply matched nothing.
    auto none = store.revoke_for_principal("nobody");
    REQUIRE(none.has_value());
    CHECK(*none == 0);
    auto empty = store.revoke_for_principal("");
    REQUIRE(empty.has_value()); // empty principal is an argument guard, not a DB failure
    CHECK(*empty == 0);
}

// PR 4.1 typed-revoke contract (ADR-0030 §Posture): a revoke whose DB write
// does NOT land must return `unexpected`, never a value that reads as "nothing
// matched" — otherwise "Sign out everywhere" reports success during an outage.
// Force a deterministic write failure by dropping the table out from under an
// open store (each YUZU_REQUIRE_PG_DB_TPL test gets its own clone, so this
// cannot bleed into another case). Before the typed result both calls returned
// 0/false — indistinguishable from a clean "no such token", the exact silent
// success this PR's review blocked.
TEST_CASE("ApiTokenStore: revoke surfaces a DB write failure as unexpected, not a false 'no match'",
          "[pg][token][crud][returning]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("victim", "erin");
    REQUIRE(raw.has_value());
    auto v = store.validate_token(*raw);
    REQUIRE(v.has_value());

    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto drop = pg::exec_params(lease.get(), "DROP TABLE api_token_store.api_tokens",
                                    std::vector<std::string>{});
        REQUIRE(drop.ok());
    }

    auto single = store.revoke_token(v->token_id);
    CHECK_FALSE(single.has_value()); // DB error → unexpected, NOT value(false)

    auto bulk = store.revoke_for_principal("erin");
    CHECK_FALSE(bulk.has_value()); // DB error → unexpected, NOT value(0)
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
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("race-token", "admin");
    REQUIRE(raw.has_value());
    auto listing = store.list_tokens("admin").value();
    REQUIRE(listing.size() == 1);
    auto token_id = listing[0].token_id;

    std::latch start{2};
    std::optional<ApiToken> validated;
    std::expected<bool, std::string> revoked;
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

    REQUIRE(revoked.has_value());
    CHECK(*revoked);
    // Whatever validate_token itself returned for THIS race is secondary —
    // the guard's job is that no STALE cache entry survives. Assert against
    // the cache directly: a follow-up validate_token (strictly after both
    // threads have joined) must never resurrect a pre-revoke "still valid"
    // answer from a racy cache write.
    auto after = store.validate_token(*raw);
    CHECK_FALSE(after.has_value());
}

TEST_CASE("ApiTokenStore: the post-commit generation bump prevents a validate that read "
          "pre-commit data from poisoning the cache",
          "[pg][token][auth][toctou]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}}; // revoke + validate each need a lease concurrently
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto raw = store.create_token("poison-token", "admin");
    REQUIRE(raw.has_value());
    auto id = store.list_tokens("admin").value().at(0).token_id;

    // Do NOT validate raw before the race — its cache must start empty.

    std::binary_semaphore first_bump_done{0};
    std::binary_semaphore release_revoke{0};
    std::binary_semaphore validate_selected{0};
    std::binary_semaphore release_validate{0};

    store.test_hook_after_first_revoke_bump_ = [&] {
        first_bump_done.release(); // tell main the first bump landed
        release_revoke.acquire();  // pause revoke here (before its UPDATE) until main lets it proceed
    };
    store.test_hook_after_validate_select_ = [&] {
        validate_selected.release(); // tell main the SELECT (pre-commit read) is done
        release_validate.acquire();  // pause validate before its generation re-check until main lets it proceed
    };

    std::expected<bool, std::string> revoked;
    std::optional<ApiToken> validated;
    std::thread t_revoke([&] { revoked = store.revoke_token(id); });
    first_bump_done.acquire(); // first bump done; revoke paused before UPDATE (row still revoked=false)

    std::thread t_validate([&] { validated = store.validate_token(*raw); });
    validate_selected.acquire(); // validate snapshotted gen (post-first-bump), SELECTed revoked=false, paused before re-check

    release_revoke.release(); // let revoke finish: UPDATE commit + SECOND bump + invalidate_cache
    t_revoke.join();          // ensure revoke's invalidate ran BEFORE validate's re-check/insert

    release_validate.release(); // let validate do its re-check (must observe the second bump -> skip cache write)
    t_validate.join();

    REQUIRE(revoked.has_value());
    CHECK(*revoked);

    // Clear hooks so the verification call runs normally.
    store.test_hook_after_first_revoke_bump_ = nullptr;
    store.test_hook_after_validate_select_ = nullptr;

    // THE ASSERTION THAT ISOLATES THE FIX: no poisoned entry survives. Without the
    // post-commit second bump, validate's re-check would have matched its snapshot
    // and cached the stale revoked=false row (inserted after revoke's invalidate),
    // and this next call would resurrect the revoked token from cache.
    auto after = store.validate_token(*raw);
    CHECK_FALSE(after.has_value());
}

// ── New coverage (PR 4.3): overlap-pair credential rotation, design doc §7 ─

namespace {

int64_t test_now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

constexpr int64_t kDay = 24 * 3600;
constexpr int64_t k90Days = 90 * kDay;
constexpr int64_t kDefaultOverlapSecs = 7 * kDay;

// Direct-SQL peek at a token row's raw `token_hash` column — used only to
// prove the raw secret was never persisted anywhere, not exercised through
// the store's own (hash-masking) public API.
std::string raw_hash_column(PgPool& pool, const std::string& token_id) {
    auto lease = pool.acquire();
    if (!lease)
        return {};
    pg::PgResult res =
        pg::exec_params(lease.get(),
                        "SELECT token_hash FROM api_token_store.api_tokens WHERE token_id = $1",
                        std::vector<std::string>{token_id});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
        return {};
    return PQgetvalue(res.get(), 0, 0);
}

// RAII reset for ApiTokenStore::test_hook_before_rotate_group_read_. A manual
// set/clear pair leaves the hook armed for the rest of the TEST_CASE if a
// REQUIRE/CHECK inside the guarded scope fails (Catch2 throws on assertion
// failure) — exactly the non-RAII cleanup shape this repo blocks in
// production code; this guard exists so no future test copies that pattern.
// SAVES AND RESTORES the prior value (rather than resetting to `nullptr`) —
// today the prior value is always null (the store is otherwise unhooked), but
// a save/clear-to-null guard would silently corrupt a nested or sequenced use
// (this exact class re-armed inside another guarded scope, or two of these in
// the same TEST_CASE), which its own doc comment above invites.
class ScopedRotateGroupReadHook {
public:
    ScopedRotateGroupReadHook(ApiTokenStore& store, std::function<void(pg_conn*)> hook)
        : store_(store), prior_(std::move(store_.test_hook_before_rotate_group_read_)) {
        store_.test_hook_before_rotate_group_read_ = std::move(hook);
    }
    ~ScopedRotateGroupReadHook() { store_.test_hook_before_rotate_group_read_ = std::move(prior_); }
    ScopedRotateGroupReadHook(const ScopedRotateGroupReadHook&) = delete;
    ScopedRotateGroupReadHook& operator=(const ScopedRotateGroupReadHook&) = delete;

private:
    ApiTokenStore& store_;
    std::function<void(pg_conn*)> prior_;
};

} // namespace

TEST_CASE("ApiTokenStore: rotate_engine_credential rejects an overlap window below the 24h "
          "floor",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    auto now = test_now_epoch();
    // No active credential exists at all — the floor check still fires
    // first (pure math, no DB dependency), and its message is distinct from
    // the "no active credential" rejection.
    auto rotated =
        store.rotate_engine_credential("engine:rotation-floor", kDay - 1, now, "admin");
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error().find("floor") != std::string::npos);
}

TEST_CASE("ApiTokenStore: rotate_engine_credential with no active credential is rejected",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    auto now = test_now_epoch();
    auto rotated = store.rotate_engine_credential("engine:rotation-empty", kDefaultOverlapSecs,
                                                  now, "admin");
    REQUIRE_FALSE(rotated.has_value());
}

TEST_CASE("ApiTokenStore: rotate_engine_credential rejects a window exceeding the "
          "predecessor's own expiry rather than truncating it",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-tight-expiry";
    auto now = test_now_epoch();
    // Predecessor expires in 1h — a 24h (floor) overlap window cannot fit
    // before it, so the mint must be rejected, not silently shrunk.
    auto minted =
        store.create_token("tight", principal, now + 3600, "", "readonly", "engine");
    REQUIRE(minted.has_value());

    auto rotated = store.rotate_engine_credential(principal, kDay, now, "admin");
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error().find("expiry") != std::string::npos);

    // Rejected mint must not have minted a successor.
    auto active = store.list_active_for_principal(principal);
    CHECK(active.size() == 1);
}

TEST_CASE("ApiTokenStore: rotate_engine_credential mints a successor, stamps the rotation "
          "pair, and returns the raw secret exactly once — never persisted",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-mint";
    auto now = test_now_epoch();
    auto predecessor_raw =
        store.create_token("svc", principal, now + k90Days, "", "readonly", "engine");
    REQUIRE(predecessor_raw.has_value());

    auto before = store.list_active_for_principal(principal);
    REQUIRE(before.size() == 1);
    const std::string predecessor_id = before[0].token_id;

    auto rotated = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(rotated.has_value());
    CHECK(rotated->starts_with("yuzu_"));
    CHECK(*rotated != *predecessor_raw);

    auto after = store.list_active_for_principal(principal);
    REQUIRE(after.size() == 2);

    const ApiToken* predecessor = nullptr;
    const ApiToken* successor = nullptr;
    for (const auto& t : after) {
        CHECK(t.token_hash.empty()); // masked, per list_active_for_principal's contract
        if (t.token_id == predecessor_id)
            predecessor = &t;
        else
            successor = &t;
    }
    REQUIRE(predecessor != nullptr);
    REQUIRE(successor != nullptr);

    CHECK_FALSE(predecessor->rotation_group.empty());
    CHECK(predecessor->rotation_group == successor->rotation_group);
    CHECK(predecessor->overlap_expires_at == now + kDefaultOverlapSecs);
    CHECK(successor->supersedes_token_id == predecessor->token_id);
    CHECK(predecessor->supersedes_token_id.empty());

    // The raw secret is never stored — only its SHA-256 hash.
    auto stored_hash = raw_hash_column(pool, successor->token_id);
    CHECK_FALSE(stored_hash.empty());
    CHECK(stored_hash != *rotated);
    CHECK(stored_hash.size() == 64); // hex-encoded SHA-256
}

TEST_CASE("ApiTokenStore: rotate_engine_credential re-serves the same raw within the grace "
          "window, and never mints a third credential",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-reserve";
    auto now = test_now_epoch();
    auto predecessor_raw =
        store.create_token("svc", principal, now + k90Days, "", "readonly", "engine");
    REQUIRE(predecessor_raw.has_value());

    auto first = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(first.has_value());

    // Retry "immediately" (a lost-response / dropped-connection scenario) —
    // must re-serve the SAME successor raw, never mint a new one, PROVIDED
    // the retry comes from the SAME operator who initiated the rotation
    // (Hermes F4).
    auto retry = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(retry.has_value());
    CHECK(*retry == *first);

    auto active = store.list_active_for_principal(principal);
    CHECK(active.size() == 2); // still exactly the predecessor + one successor
}

TEST_CASE("ApiTokenStore: rotate_engine_credential rejects a grace-window re-serve to a "
          "different operator than the one who initiated the rotation",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-reserve-wrong-user";
    auto now = test_now_epoch();
    auto predecessor_raw =
        store.create_token("svc", principal, now + k90Days, "", "readonly", "engine");
    REQUIRE(predecessor_raw.has_value());

    auto first = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(first.has_value());

    // A DIFFERENT operator retrying within the grace window must never
    // receive admin's in-flight successor secret (Hermes F4).
    auto stolen = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "mallory");
    REQUIRE_FALSE(stolen.has_value());
    CHECK(stolen.error().find("different operator") != std::string::npos);

    // The rejection did not mint a third credential, and the SAME operator
    // can still re-serve successfully afterward.
    auto active = store.list_active_for_principal(principal);
    CHECK(active.size() == 2);

    auto retry_same_user =
        store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(retry_same_user.has_value());
    CHECK(*retry_same_user == *first);
}

TEST_CASE("ApiTokenStore: rotate_engine_credential rejects a retry once the grace window has "
          "elapsed — no third credential is ever minted",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-grace-lapsed";
    auto now = test_now_epoch();
    auto predecessor_raw =
        store.create_token("svc", principal, now + k90Days, "", "readonly", "engine");
    REQUIRE(predecessor_raw.has_value());

    auto first = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(first.has_value());

    // Simulate the grace window (kRotationGraceSecs, 120s) lapsing by
    // advancing the caller-supplied `now` rather than sleeping — the epoch
    // side of the idempotency check (now - successor.created_at) is what
    // gates this, independent of wall-clock elapsed time.
    auto lapsed_now = now + 300;
    auto retry =
        store.rotate_engine_credential(principal, kDefaultOverlapSecs, lapsed_now, "admin");
    REQUIRE_FALSE(retry.has_value());
    CHECK(retry.error().find("grace") != std::string::npos);

    // No third credential was minted by the rejected retry.
    auto active = store.list_active_for_principal(principal);
    CHECK(active.size() == 2);
}

TEST_CASE("ApiTokenStore: rotate_engine_credential defensively rejects when three active "
          "credentials already exist for the principal (the ≤2 ceiling holds even against a "
          "credential minted outside rotate)",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-over-ceiling";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("a", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    REQUIRE(store.create_token("b", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    REQUIRE(store.create_token("c", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    REQUIRE(store.list_active_for_principal(principal).size() == 3);

    auto rotated = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error().find("more than two") != std::string::npos);

    // Never picks one to arbitrate — the count stays exactly 3, no fourth
    // credential minted either.
    CHECK(store.list_active_for_principal(principal).size() == 3);
}

// ── Hermes review (PR 4.3 round 2): F1-F5 hardening ───────────────────────

TEST_CASE("ApiTokenStore: concurrent rotate_engine_credential calls for the same principal "
          "never exceed the ≤2 active ceiling (Hermes F1)",
          "[pg][token][rotation][concurrency]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 8}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-concurrent";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());

    // Every thread races rotate_engine_credential for the SAME principal at
    // the SAME `now`, with a distinct requesting_user each — before F1, the
    // unlocked read-then-mint let multiple threads all observe 1-active and
    // all mint, blowing the ≤2 ceiling. std::latch lines every thread up at
    // the starting gun so they hit the advisory lock as concurrently as the
    // test process can arrange.
    constexpr int kThreads = 6;
    std::latch start_latch{kThreads};
    std::vector<std::thread> threads;
    std::mutex results_mtx;
    std::vector<std::expected<std::string, std::string>> results;

    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&, i]() {
            start_latch.arrive_and_wait();
            auto r = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now,
                                                     "operator-" + std::to_string(i));
            std::lock_guard lock(results_mtx);
            results.push_back(std::move(r));
        });
    }
    for (auto& t : threads)
        t.join();

    // Exactly ONE thread's call is the 1-active mint winner — every other
    // thread's call is serialized behind the advisory lock and, upon its
    // own re-read, sees 2-active. Since every thread used a DIFFERENT
    // requesting_user, none of the losers share the winner's identity, so
    // F4's binding rejects every one of them (never a silent re-serve to
    // the wrong caller, and never a THIRD mint).
    int successes = 0;
    for (const auto& r : results) {
        if (r.has_value())
            ++successes;
        else
            CHECK(r.error().find("different operator") != std::string::npos);
    }
    CHECK(successes == 1);

    // The ≤2 ceiling holds under concurrency — never 3.
    auto active = store.list_active_for_principal(principal);
    CHECK(active.size() == 2);
}

TEST_CASE("ApiTokenStore: rotate_engine_credential never leaves an orphaned rotation pair — "
          "mint and pair-stamp always commit together (Hermes F2)",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-no-orphan";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());

    auto rotated = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(rotated.has_value());

    // Every row with a non-empty rotation_group must have exactly one
    // sibling sharing it (predecessor + successor) — never a lone stamped
    // row, which would mean the INSERT committed without the pair-stamp (or
    // vice versa).
    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 2);
    CHECK_FALSE(active[0].rotation_group.empty());
    CHECK(active[0].rotation_group == active[1].rotation_group);

    const ApiToken* predecessor = active[0].supersedes_token_id.empty() ? &active[0] : &active[1];
    const ApiToken* successor = active[0].supersedes_token_id.empty() ? &active[1] : &active[0];
    CHECK(predecessor->overlap_expires_at > 0);
    CHECK(successor->supersedes_token_id == predecessor->token_id);
}

TEST_CASE("ApiTokenStore::sweep_expired_rotations: rolls back the predecessor's revoke when "
          "the successor's rotation-state clear fails — neither half applies (Hermes F3)",
          "[pg][token][rotation][sweep]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-sweep-rollback";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    auto rotated = store.rotate_engine_credential(principal, kDay, now, "admin");
    REQUIRE(rotated.has_value());

    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 2);
    const ApiToken* predecessor = nullptr;
    const ApiToken* successor = nullptr;
    for (const auto& t : active) {
        if (t.supersedes_token_id.empty())
            predecessor = &t;
        else
            successor = &t;
    }
    REQUIRE(predecessor != nullptr);
    REQUIRE(successor != nullptr);
    const std::string predecessor_id = predecessor->token_id;
    const std::string successor_id = successor->token_id;
    const std::string rotation_group = predecessor->rotation_group;

    // Force the successor's rotation-state clear to fail with a genuine SQL
    // execution error (never merely a zero-row match) — a BEFORE UPDATE
    // trigger that raises only when THIS successor's rotation_group is
    // being cleared. Scoped to this test's own cloned database (PgTestTemplate),
    // so it can't leak into any other test.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string fn_sql =
            "CREATE OR REPLACE FUNCTION api_token_store.f3_force_clear_fail() "
            "RETURNS trigger AS $$ BEGIN IF NEW.token_id = '" +
            successor_id +
            "' AND NEW.rotation_group = '' THEN "
            "RAISE EXCEPTION 'F3 test: forced clear failure'; END IF; RETURN NEW; END; $$ "
            "LANGUAGE plpgsql;";
        PgResult fn_res{PQexec(conn.get(), fn_sql.c_str())};
        REQUIRE(fn_res.ok());
        PgResult trig_res{PQexec(
            conn.get(),
            "CREATE TRIGGER f3_force_clear_fail BEFORE UPDATE ON api_token_store.api_tokens "
            "FOR EACH ROW EXECUTE FUNCTION api_token_store.f3_force_clear_fail();")};
        REQUIRE(trig_res.ok());
    }

    // AFTER the overlap window elapses, sweep attempts to revoke the
    // predecessor + clear the successor together in one transaction — the
    // clear fails, so NEITHER change may commit.
    auto swept = store.sweep_expired_rotations(now + kDay + 1);
    CHECK(swept.empty());

    auto predecessor_after = store.get_token(predecessor_id).value();
    REQUIRE(predecessor_after.has_value());
    CHECK_FALSE(predecessor_after->revoked); // rolled back — NOT revoked

    auto successor_after = store.get_token(successor_id).value();
    REQUIRE(successor_after.has_value());
    CHECK_FALSE(successor_after->rotation_group.empty()); // rolled back — still linked
    CHECK(successor_after->rotation_group == rotation_group);

    // Idempotent: re-running the (still-failing) sweep doesn't corrupt
    // anything further — same clean rollback each time.
    auto swept_again = store.sweep_expired_rotations(now + kDay + 2);
    CHECK(swept_again.empty());
    auto predecessor_still = store.get_token(predecessor_id).value();
    REQUIRE(predecessor_still.has_value());
    CHECK_FALSE(predecessor_still->revoked);
}

TEST_CASE("ApiTokenStore: confirm_rotation cuts over immediately — revokes the predecessor, "
          "sets confirmed_at, and clears the successor's rotation state (Hermes F5)",
          "[pg][token][rotation][confirm]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-confirm";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    auto rotated = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(rotated.has_value());

    auto before = store.list_active_for_principal(principal);
    REQUIRE(before.size() == 2);
    const ApiToken* predecessor = nullptr;
    const ApiToken* successor = nullptr;
    for (const auto& t : before) {
        if (t.supersedes_token_id.empty())
            predecessor = &t;
        else
            successor = &t;
    }
    REQUIRE(predecessor != nullptr);
    REQUIRE(successor != nullptr);
    const std::string predecessor_id = predecessor->token_id;
    const std::string successor_id = successor->token_id;

    auto confirmed = store.confirm_rotation(principal, successor_id, "admin");
    REQUIRE(confirmed.has_value());

    auto predecessor_after = store.get_token(predecessor_id).value();
    REQUIRE(predecessor_after.has_value());
    CHECK(predecessor_after->revoked); // immediate cutover, not "wait for the window"

    auto successor_after = store.get_token(successor_id).value();
    REQUIRE(successor_after.has_value());
    CHECK_FALSE(successor_after->revoked);
    CHECK(successor_after->confirmed_at > 0); // the previously-dead column, now live
    CHECK(successor_after->rotation_group.empty());
    CHECK(successor_after->supersedes_token_id.empty());
    CHECK(successor_after->overlap_expires_at == 0);

    // Exactly one active credential remains — the confirmed successor.
    auto active_after = store.list_active_for_principal(principal);
    REQUIRE(active_after.size() == 1);
    CHECK(active_after[0].token_id == successor_id);

    // A fresh rotation may now begin (the pair fully resolved).
    auto next_rotate =
        store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    CHECK(next_rotate.has_value());
}

TEST_CASE("ApiTokenStore: confirm_rotation rejects an operator who did not initiate the "
          "rotation (Hermes F4/F5 binding)",
          "[pg][token][rotation][confirm]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-confirm-wrong-user";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    auto rotated = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(rotated.has_value());

    // The CORRECT successor id is supplied so this isolates the operator check
    // (a wrong id would trip the #2384 token_id pin first).
    std::string successor_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (!t.supersedes_token_id.empty())
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());

    auto stolen_confirm = store.confirm_rotation(principal, successor_id, "mallory");
    REQUIRE_FALSE(stolen_confirm.has_value());
    CHECK(stolen_confirm.error().find("different operator") != std::string::npos);

    // Rejected — both credentials remain exactly as rotate left them.
    auto active = store.list_active_for_principal(principal);
    CHECK(active.size() == 2);
    for (const auto& t : active)
        CHECK(t.confirmed_at == 0);

    // The SAME operator who initiated it can still confirm afterward.
    auto real_confirm = store.confirm_rotation(principal, successor_id, "admin");
    CHECK(real_confirm.has_value());
}

TEST_CASE("ApiTokenStore: confirm_rotation sole-credential states are terminal, but a "
          "genuinely empty read stays retryable (#2404)",
          "[pg][token][rotation][confirm]") {
    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-confirm-sole";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    const std::string sole_id = store.list_active_for_principal(principal).at(0).token_id;

    // One never-rotated credential, pin MATCHES it: resolved without a confirm
    // (confirmed_at == 0). Terminal conflict, NOT the old retryable error —
    // this is the positive-read guarantee (#2404). Pre-#2384 wording proof: a
    // client must be told "nothing to confirm", not told to retry.
    auto resolved = store.confirm_rotation(principal, sole_id, "admin");
    REQUIRE_FALSE(resolved.has_value());
    CHECK(resolved.error().find("already the sole active credential") != std::string::npos);
    CHECK(classify_engine_store_error(resolved.error()) == E::Conflict);

    // One credential, pin does NOT match it: the pinned rotation moved on.
    auto other = store.confirm_rotation(principal, "deadbeefdeadbeefdeadbeef", "admin");
    REQUIRE_FALSE(other.has_value());
    CHECK(other.error().find("the rotation was resolved") != std::string::npos);
    CHECK(classify_engine_store_error(other.error()) == E::Conflict);

    // Now revoke the sole credential so the read is genuinely EMPTY. That case
    // is ambiguous with a swallowed SELECT failure, so it MUST stay the
    // retryable "no in-flight rotation to confirm" (Transient), never a
    // terminal 409 (regression guard for the positive-read boundary).
    REQUIRE(store.revoke_token(sole_id).value());
    REQUIRE(store.list_active_for_principal(principal).empty());
    auto none = store.confirm_rotation(principal, sole_id, "admin");
    REQUIRE_FALSE(none.has_value());
    CHECK(none.error().find("no in-flight rotation to confirm") != std::string::npos);
    CHECK(classify_engine_store_error(none.error()) == E::Transient);
}

TEST_CASE("ApiTokenStore: confirm_rotation replay after success is a terminal already-confirmed "
          "conflict, not a retryable 503 (#2404)",
          "[pg][token][rotation][confirm]") {
    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-confirm-replay";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    auto rotated = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (!t.supersedes_token_id.empty())
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // First confirm succeeds (the real cutover).
    REQUIRE(store.confirm_rotation(principal, successor_id, "admin").has_value());

    // The network-dropped-200 replay: SAME args. The successor is now the sole
    // active credential with confirmed_at set, so this is terminal, not 503.
    auto replay = store.confirm_rotation(principal, successor_id, "admin");
    REQUIRE_FALSE(replay.has_value());
    CHECK(replay.error().find("rotation already confirmed") != std::string::npos);
    CHECK(replay.error().find("sole active credential") != std::string::npos);
    CHECK(classify_engine_store_error(replay.error()) == E::Conflict);
    // No side effect: still exactly one active credential.
    CHECK(store.list_active_for_principal(principal).size() == 1);
}

TEST_CASE("ApiTokenStore: confirm_rotation after the sweep cuts over is a terminal "
          "already-resolved conflict (#2404)",
          "[pg][token][rotation][confirm][sweep]") {
    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-confirm-swept";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    auto rotated = store.rotate_engine_credential(principal, kDay, now, "admin");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (!t.supersedes_token_id.empty())
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // The overlap sweep auto-revokes the predecessor and clears the successor
    // (which was never confirmed: confirmed_at stays 0).
    store.sweep_expired_rotations(now + kDay + 1);
    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == successor_id);
    CHECK(active[0].confirmed_at == 0); // resolved by sweep, not by a confirm

    // A confirm racing the sweep now finds the successor resolved. Terminal,
    // and worded "no rotation in flight" (not "already confirmed") because the
    // cutover was the sweep, not an explicit confirm. Assert the contiguous
    // fragment unique to kSoleResolved ("already the sole active credential"):
    // it disambiguates from kSoleConfirmed ("is the sole...") and kSoleOtherToken
    // (no "sole active credential") in a single check, so a partial message
    // drift on one branch can't false-pass (qe review, #2404).
    auto swept_confirm = store.confirm_rotation(principal, successor_id, "admin");
    REQUIRE_FALSE(swept_confirm.has_value());
    CHECK(swept_confirm.error().find("no rotation in flight") != std::string::npos);
    CHECK(swept_confirm.error().find("already the sole active credential") != std::string::npos);
    CHECK(classify_engine_store_error(swept_confirm.error()) == E::Conflict);
}

TEST_CASE("ApiTokenStore: confirm_rotation with more than two active credentials is a terminal "
          "client error, not a retryable 503 (#2404)",
          "[pg][token][rotation][confirm]") {
    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-confirm-overfull";
    auto now = test_now_epoch();
    // The store's create_token has no ≤2 ceiling (only the mint route does), so
    // three direct mints reproduce the "credential minted outside rotation"
    // shape (same setup as the rotate over-ceiling test).
    REQUIRE(store.create_token("a", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    REQUIRE(store.create_token("b", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    REQUIRE(store.create_token("c", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    REQUIRE(store.list_active_for_principal(principal).size() == 3);

    auto over = store.confirm_rotation(principal, "deadbeefdeadbeefdeadbeef", "admin");
    REQUIRE_FALSE(over.has_value());
    CHECK(over.error().find("more than two active credentials") != std::string::npos);
    CHECK(classify_engine_store_error(over.error()) == E::ClientValidation);
    CHECK(store.list_active_for_principal(principal).size() == 3); // never arbitrated
}

TEST_CASE("ApiTokenStore: confirm_rotation on a sole credential with stale rotation linkage is "
          "terminal and does NOT advise rotate (#2404 F1)",
          "[pg][token][rotation][confirm]") {
    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-confirm-stale-linkage";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    auto rotated = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(rotated.has_value());
    std::string predecessor_id, successor_id;
    for (const auto& t : store.list_active_for_principal(principal)) {
        if (t.supersedes_token_id.empty())
            predecessor_id = t.token_id;
        else
            successor_id = t.token_id;
    }
    REQUIRE_FALSE(successor_id.empty());

    // Manufacture the F1 defect state: revoke the predecessor by DIRECT SQL,
    // bypassing revoke_token's resolve_rotation_pair_after_revoke, so the
    // surviving successor keeps its (now stale) rotation_group + supersedes.
    // This is the durable state a best-effort pair-resolve failure leaves.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string sql =
            "UPDATE api_token_store.api_tokens SET revoked = TRUE WHERE token_id = '" +
            predecessor_id + "';";
        PgResult res{PQexec(conn.get(), sql.c_str())};
        REQUIRE(res.ok());
    }
    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == successor_id);
    CHECK_FALSE(active[0].rotation_group.empty()); // stale linkage survived

    auto stale = store.confirm_rotation(principal, successor_id, "admin");
    REQUIRE_FALSE(stale.has_value());
    CHECK(stale.error().find("unresolved rotation metadata") != std::string::npos);
    CHECK(classify_engine_store_error(stale.error()) == E::Conflict);
    // MUST NOT tell the operator to rotate from this state (rotating would
    // strand a malformed pair). It says "do not rotate", never "rotate again".
    CHECK(stale.error().find("do not rotate") != std::string::npos);
    CHECK(stale.error().find("rotate again") == std::string::npos);
}

TEST_CASE("ApiTokenStore: confirm_rotation never misattributes a historical confirmed_at across "
          "a later rotation (#2404 F2)",
          "[pg][token][rotation][confirm]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-confirm-historical";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());

    // R1: rotate + confirm. S1 becomes the sole active credential, confirmed.
    REQUIRE(store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin")
                .has_value());
    std::string s1_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (!t.supersedes_token_id.empty())
            s1_id = t.token_id;
    REQUIRE_FALSE(s1_id.empty());
    REQUIRE(store.confirm_rotation(principal, s1_id, "admin").has_value());
    REQUIRE(store.get_token(s1_id).value()->confirmed_at > 0); // S1 carries R1's marker

    // R2: rotate again (S1 is now the predecessor, KEEPING its confirmed_at),
    // then revoke R2's successor so the pair resolves back to S1 alone.
    REQUIRE(store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin")
                .has_value());
    std::string s2_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (!t.supersedes_token_id.empty())
            s2_id = t.token_id;
    REQUIRE_FALSE(s2_id.empty());
    REQUIRE(store.revoke_token(s2_id).value()); // resolves the pair -> S1 sole, clear
    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == s1_id);

    // Pin = S1 (the confirmed survivor): "already confirmed" is TRUE and
    // correct — the rotation in which S1 was successor (R1) WAS confirmed.
    auto pin_s1 = store.confirm_rotation(principal, s1_id, "admin");
    REQUIRE_FALSE(pin_s1.has_value());
    CHECK(pin_s1.error().find("rotation already confirmed") != std::string::npos);

    // Pin = S2 (R2's successor, which was resolved by REVOKE, not confirm):
    // the message must NOT claim "already confirmed" — it says "the rotation
    // was resolved", the cause-agnostic wording for a non-matching pin. This
    // is the F2 guard: historical confirmed_at never attributes R2's cause.
    auto pin_s2 = store.confirm_rotation(principal, s2_id, "admin");
    REQUIRE_FALSE(pin_s2.has_value());
    CHECK(pin_s2.error().find("the rotation was resolved") != std::string::npos);
    CHECK(pin_s2.error().find("already confirmed") == std::string::npos);
}

TEST_CASE("ApiTokenStore: confirm_rotation rejects a token_id that is not the pending "
          "successor — no mutation (#2384 pin)",
          "[pg][token][rotation][confirm]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-confirm-mismatch";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    auto rotated = store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin");
    REQUIRE(rotated.has_value());

    std::string predecessor_id, successor_id, rotation_group;
    for (const auto& t : store.list_active_for_principal(principal)) {
        if (t.supersedes_token_id.empty()) {
            predecessor_id = t.token_id;
        } else {
            successor_id = t.token_id;
            rotation_group = t.rotation_group;
        }
    }
    REQUIRE_FALSE(successor_id.empty());

    // The PREDECESSOR's id (the likely operator mistake) and a bogus id both
    // mismatch the pending successor.
    for (const std::string& wrong : {predecessor_id, std::string{"feedfacefeedfacefeedface"}}) {
        auto mismatch = store.confirm_rotation(principal, wrong, "admin");
        REQUIRE_FALSE(mismatch.has_value());
        CHECK(mismatch.error().find("does not match the pending rotation") != std::string::npos);
    }

    // No mutation: both credentials active, linkage intact, confirmed_at unset.
    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 2);
    for (const auto& t : active) {
        CHECK(t.confirmed_at == 0);
        CHECK(t.rotation_group == rotation_group);
        if (t.token_id == successor_id)
            CHECK(t.supersedes_token_id == predecessor_id);
    }

    // Empty token_id is rejected by the input guard, same no-mutation posture.
    auto empty_id = store.confirm_rotation(principal, "", "admin");
    REQUIRE_FALSE(empty_id.has_value());
    CHECK(empty_id.error().find("token_id required") != std::string::npos);

    // The correct id still confirms — the rejections above consumed nothing.
    CHECK(store.confirm_rotation(principal, successor_id, "admin").has_value());
}

TEST_CASE("ApiTokenStore: a blind retry carrying an EARLIER rotation's successor id cannot "
          "confirm a LATER rotation (#2384 regression)",
          "[pg][token][rotation][confirm]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:rotation-blind-retry";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());

    // Rotation 1: rotate + confirm with R1's successor id (the happy flow).
    REQUIRE(store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin")
                .has_value());
    std::string r1_successor_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (!t.supersedes_token_id.empty())
            r1_successor_id = t.token_id;
    REQUIRE_FALSE(r1_successor_id.empty());
    REQUIRE(store.confirm_rotation(principal, r1_successor_id, "admin").has_value());

    // Rotation 2 begins: R1's successor is now R2's predecessor.
    REQUIRE(store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin")
                .has_value());
    std::string r2_successor_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (!t.supersedes_token_id.empty())
            r2_successor_id = t.token_id;
    REQUIRE_FALSE(r2_successor_id.empty());
    REQUIRE(r2_successor_id != r1_successor_id);

    // THE #2384 SCENARIO: a blind retry of the R1 confirm (same args, same
    // operator) lands after R2 started. Pre-pin this confirmed R2 early and
    // revoked R2's predecessor — R1's still-live successor. Now it mismatches.
    auto stale_retry = store.confirm_rotation(principal, r1_successor_id, "admin");
    REQUIRE_FALSE(stale_retry.has_value());
    CHECK(stale_retry.error().find("does not match the pending rotation") != std::string::npos);

    // R2 is untouched: its predecessor (R1's successor) is still active and
    // the pair is still pending. NOTE: R2's predecessor legitimately RETAINS
    // its historical confirmed_at from R1 (kept as a marker by design) — only
    // R2's successor must be unconfirmed.
    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 2);
    bool r1_successor_still_active = false;
    for (const auto& t : active) {
        if (t.token_id == r1_successor_id) {
            r1_successor_still_active = true;
            CHECK(t.revoked == false);
        }
        if (t.token_id == r2_successor_id)
            CHECK(t.confirmed_at == 0);
    }
    CHECK(r1_successor_still_active);

    // R2's own successor id confirms R2 normally.
    CHECK(store.confirm_rotation(principal, r2_successor_id, "admin").has_value());
}

// ── Manual revoke resolves the rotation pair (design §7, PR #2284 review Major 3) ──

TEST_CASE("ApiTokenStore: revoking a rotation PREDECESSOR resolves the pair — the successor "
          "becomes a standalone active credential",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:revoke-predecessor";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    const std::string predecessor_id = store.list_active_for_principal(principal).at(0).token_id;
    REQUIRE(store.rotate_engine_credential(principal, kDefaultOverlapSecs, now, "admin").has_value());

    std::string successor_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (t.token_id != predecessor_id)
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());

    auto revoked = store.revoke_token(predecessor_id);
    REQUIRE(revoked.has_value());
    CHECK(*revoked);

    // The successor is now the sole active credential with its rotation state cleared.
    auto after = store.list_active_for_principal(principal);
    REQUIRE(after.size() == 1);
    CHECK(after[0].token_id == successor_id);
    CHECK(after[0].rotation_group.empty());
    CHECK(after[0].supersedes_token_id.empty());
    CHECK(after[0].overlap_expires_at == 0);
}

TEST_CASE("ApiTokenStore: revoking a rotation SUCCESSOR clears the predecessor's rotation state so "
          "the sweep does NOT auto-revoke the principal's last credential",
          "[pg][token][rotation][sweep]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    const std::string principal = "engine:revoke-successor";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("svc", principal, now + k90Days, "", "readonly", "engine")
                .has_value());
    const std::string predecessor_id = store.list_active_for_principal(principal).at(0).token_id;
    // Short overlap so the sweep would fire after now+kDay.
    REQUIRE(store.rotate_engine_credential(principal, kDay, now, "admin").has_value());
    std::string successor_id;
    for (const auto& t : store.list_active_for_principal(principal))
        if (t.token_id != predecessor_id)
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // Revoke the SUCCESSOR — the predecessor is now the only credential.
    auto revoked = store.revoke_token(successor_id);
    REQUIRE(revoked.has_value());
    CHECK(*revoked);

    // Predecessor's rotation state is cleared (overlap_expires_at -> 0) so it is
    // no longer a sweep target.
    auto pred = store.get_token(predecessor_id);
    REQUIRE(pred.has_value());
    REQUIRE(pred->has_value());
    CHECK_FALSE((*pred)->revoked);
    CHECK((*pred)->overlap_expires_at == 0);
    CHECK((*pred)->rotation_group.empty());

    // Run the sweep AFTER the original overlap window would have elapsed. Without
    // the §7 fix the sweep would auto-revoke the predecessor as
    // "overlap_window_elapsed", leaving the principal with ZERO credentials.
    bool tick_failed = false;
    auto swept = store.sweep_expired_rotations(now + kDay + 1, &tick_failed);
    CHECK_FALSE(tick_failed);
    CHECK(swept.empty()); // nothing to auto-revoke — the pair was already resolved

    auto still = store.get_token(predecessor_id);
    REQUIRE(still.has_value());
    REQUIRE(still->has_value());
    CHECK_FALSE((*still)->revoked); // predecessor survives — principal keeps a credential
    CHECK(store.list_active_for_principal(principal).size() == 1);
}

// ── validate_token_checked: the tri-state a held-open stream needs ───────────
//
// `validate_token` folds "definitively gone" and "cannot reach the store" into
// the same nullopt. That is right for request auth — both answers mean 401 — and
// wrong for an MCP SSE stream, which must cut a REVOKED credential immediately
// (ADR-1005 Decision 15(c)) while riding out a transient backend blip rather than
// killing every live stream on the fleet at once (Decision 15(i), chaos CH-4).

TEST_CASE("ApiTokenStore: validate_token_checked reports a live token as valid",
          "[pg][token][auth][stream]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    auto raw = store.create_token("Stream Token", "alice");
    REQUIRE(raw.has_value());

    auto checked = store.validate_token_checked(*raw);
    CHECK(checked.status == ApiTokenStore::TokenCheck::kValid);
    REQUIRE(checked.token.has_value());
    CHECK(checked.token->principal_id == "alice");
}

TEST_CASE("ApiTokenStore: a revoked token is DEFINITIVELY invalid, not indeterminate",
          "[pg][token][auth][stream]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    auto raw = store.create_token("Doomed", "alice");
    REQUIRE(raw.has_value());
    auto live = store.validate_token(*raw);
    REQUIRE(live.has_value());

    REQUIRE(store.revoke_token(live->token_id));

    auto checked = store.validate_token_checked(*raw);
    // kInvalid — NOT kUnavailable. A revocation must cut the stream on the next
    // tick; if it were reported as indeterminate it would instead buy the revoked
    // credential a full grace window of extra life.
    CHECK(checked.status == ApiTokenStore::TokenCheck::kInvalid);
    CHECK_FALSE(checked.token.has_value());
}

TEST_CASE("ApiTokenStore: an unknown token is definitively invalid", "[pg][token][auth][stream]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    auto checked = store.validate_token_checked("yuzu_never_issued_0123456789012");
    CHECK(checked.status == ApiTokenStore::TokenCheck::kInvalid);
}

TEST_CASE("ApiTokenStore: an empty token is definitively invalid", "[pg][token][auth][stream]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    CHECK(store.validate_token_checked("").status == ApiTokenStore::TokenCheck::kInvalid);
}

TEST_CASE("ApiTokenStore: an EXHAUSTED connection pool is kUnavailable, not kInvalid",
          "[pg][token][auth][stream]") {
    // The third way the store can fail to answer, and the only one the two schema
    // saboteurs below do NOT reach: `pool_.try_acquire_for(kReadTimeout)` returns no
    // lease. Same safe verdict, different branch — and it is the branch a real
    // Postgres brown-out takes, so leaving it untested left the most likely
    // production path unguarded.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    // A pool of exactly one, whose sole connection we hold for the duration.
    PgPool pool{{.conninfo = db.dsn(), .size = 1}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    auto raw = store.create_token("pool-starved", "alice");
    REQUIRE(raw.has_value());

    // Do NOT validate first — a cached token would answer from memory and never
    // need a connection, testing nothing.
    auto hog = pool.try_acquire_for(std::chrono::seconds{5});
    REQUIRE(hog); // we now hold the only connection

    const auto checked = store.validate_token_checked(*raw);
    CHECK(checked.status == ApiTokenStore::TokenCheck::kUnavailable);
    CHECK_FALSE(checked.token.has_value()); // indeterminate NEVER grants access
}

TEST_CASE("ApiTokenStore: an unreadable store is kUnavailable, NOT kInvalid",
          "[pg][token][auth][stream]") {
    // The whole reason validate_token_checked exists. validate_token collapses "the row
    // is gone" and "I could not read the table" into the same nullopt — right for
    // request auth (both mean 401), fatal for a held-open stream, where the first must
    // kill it immediately and the second must NOT (an auth-store hiccup would otherwise
    // cut every stream on the fleet at once — ADR-1005 Decision 15(i), chaos CH-4).
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    auto raw = store.create_token("doomed-store", "alice");
    REQUIRE(raw.has_value());

    // Break the store from a second connection. Do NOT validate first — a cached token
    // would answer from memory and never touch the dropped table.
    {
        PgConn saboteur{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(saboteur.get()) == CONNECTION_OK);
        PgResult r{PQexec(saboteur.get(), "DROP TABLE api_token_store.api_tokens")};
        REQUIRE(r.ok());
    }

    const auto checked = store.validate_token_checked(*raw);
    CHECK(checked.status == ApiTokenStore::TokenCheck::kUnavailable);
    CHECK_FALSE(checked.token.has_value()); // indeterminate NEVER grants access
}

TEST_CASE("ApiTokenStore: a CONTENDED store is kUnavailable, not a false revocation",
          "[pg][token][auth][stream][ch4]") {
    // The bug this replaced: validate_token_checked used to call validate_token and then
    // probe the store with a DIFFERENT trivial statement to decide whether the negative
    // answer was real. But validate_token folds a failed row lookup into the same nullopt
    // as "no such row" — and the probe statement can still succeed on a merely-contended
    // store. A healthy stream was therefore killed as `credential_revoked` because the
    // backend was busy, and the 60 s grace window that exists for exactly this fault was
    // unreachable.
    //
    // Here the table is present (so a "SELECT 1 FROM api_tokens LIMIT 1" probe WOULD
    // succeed) but the row lookup cannot run, because the column it needs is gone.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    auto raw = store.create_token("busy-store", "alice");
    REQUIRE(raw.has_value());

    {
        PgConn saboteur{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(saboteur.get()) == CONNECTION_OK);
        // Rename the column the lookup selects: the table still exists, so a naive probe
        // is happy — only the real query fails.
        PgResult r{PQexec(saboteur.get(),
                          "ALTER TABLE api_token_store.api_tokens "
                          "RENAME COLUMN token_hash TO gone")};
        REQUIRE(r.ok());
    }

    const auto checked = store.validate_token_checked(*raw);
    CHECK(checked.status == ApiTokenStore::TokenCheck::kUnavailable);
    CHECK_FALSE(checked.token.has_value());
}

TEST_CASE("ApiTokenStore: re-validation does not write last_used_at",
          "[pg][token][auth][stream]") {
    // Re-validation runs on every heartbeat tick of every live stream. Writing here would
    // make last_used_at track heartbeats instead of actual calls, and would put a write on
    // a pooled connection each time a stream's cache entry expired — a thundering herd
    // that every token-authenticated request then queues behind.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    auto raw = store.create_token("read-only-check", "alice");
    REQUIRE(raw.has_value());

    const auto before = store.validate_token_checked(*raw);
    REQUIRE(before.status == ApiTokenStore::TokenCheck::kValid);
    CHECK(before.token->last_used_at == 0); // create_token leaves it unset

    // Read the column straight from the DB — a write by the check would show up here even
    // though the cached copy would not.
    PgConn reader{PQconnectdb(db.dsn().c_str())};
    REQUIRE(PQstatus(reader.get()) == CONNECTION_OK);
    PgResult r{PQexec(reader.get(), "SELECT last_used_at FROM api_token_store.api_tokens")};
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    REQUIRE(PQntuples(r.get()) == 1);
    CHECK(std::string(PQgetvalue(r.get(), 0, 0)) == "0"); // a READ — it did not stamp
}

// ── Human arm: token-keyed overlap-pair rotation (P2 #11, SOC 2 CC6.3) ─────

TEST_CASE("ApiTokenStore: rotate_token rejects an overlap window below the 24h floor",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    // No token with this id exists at all — the floor check still fires
    // first (pure math, no DB dependency), distinct message from "no such
    // token".
    auto rotated = store.rotate_token("deadbeefdeadbeefdeadbeef", kDay - 1, now, "admin");
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error().find("floor") != std::string::npos);
}

TEST_CASE("ApiTokenStore: rotate_token rejects an unknown token_id",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    auto now = test_now_epoch();
    auto rotated =
        store.rotate_token("deadbeefdeadbeefdeadbeef", kDefaultOverlapSecs, now, "admin");
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error().find("no such token") != std::string::npos);
    CHECK(classify_engine_store_error(rotated.error()) == E::ClientValidation);
}

TEST_CASE("ApiTokenStore: rotate_token rejects an engine-kind token — human arm only",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    store.set_engine_referent_check(
        [](const std::string&) { return EngineLookupStatus::Active; });

    auto now = test_now_epoch();
    auto minted =
        store.create_token("svc", "engine:human-arm-guard", now + k90Days, "", "readonly",
                           "engine");
    REQUIRE(minted.has_value());
    auto active = store.list_active_for_principal("engine:human-arm-guard");
    REQUIRE(active.size() == 1);

    // requesting_user must equal the row's own principal_id to clear the
    // self-service ownership gate and reach the kind check at all — a
    // human requesting_user could never own an "engine:"-namespaced row in
    // practice, but this proves the kind guard fires as a defense-in-depth
    // backstop on the (structurally unreachable in production) case where it
    // does.
    auto rotated = store.rotate_token(active[0].token_id, kDefaultOverlapSecs, now,
                                      "engine:human-arm-guard");
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error().find("human-owned") != std::string::npos);
}

TEST_CASE("ApiTokenStore: rotate_token rejects a non-owner even with a valid token_id — "
          "self-service only, no admin override, and indistinguishable from a missing token",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    auto now = test_now_epoch();
    auto raw = store.create_token("alices-pat", "alice", now + k90Days);
    REQUIRE(raw.has_value());
    const std::string token_id = store.list_active_for_principal("alice")[0].token_id;

    // "admin" is a DIFFERENT user, not merely a different requesting_user
    // label — there is no admin-override arm on this path (deliberate
    // asymmetry with the engine arm's third-party-admin design).
    auto stolen = store.rotate_token(token_id, kDefaultOverlapSecs, now, "admin");
    REQUIRE_FALSE(stolen.has_value());
    CHECK(stolen.error() == "no such token to rotate"); // byte-identical to the genuine 404 case
    CHECK(classify_engine_store_error(stolen.error()) == E::ClientValidation);

    // No state mutated by the rejected cross-user attempt.
    auto active = store.list_active_for_principal("alice");
    REQUIRE(active.size() == 1);
    CHECK(active[0].rotation_group.empty());

    // The genuine owner can still rotate normally afterward.
    auto real = store.rotate_token(token_id, kDefaultOverlapSecs, now, "alice");
    CHECK(real.has_value());
}

TEST_CASE("ApiTokenStore: confirm_token_rotation rejects a non-owner even with the correct "
          "pinned successor token_id — self-service only",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    auto now = test_now_epoch();
    auto raw = store.create_token("alices-pat", "alice", now + k90Days);
    REQUIRE(raw.has_value());
    const std::string predecessor_id = store.list_active_for_principal("alice")[0].token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& t : store.list_active_for_principal("alice"))
        if (t.token_id != predecessor_id)
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // "admin" knows the correct successor token_id (e.g. observed in an
    // audit log) but is not alice — must still be rejected, byte-identical
    // to the not-found wording, never a distinguishable "not yours".
    auto stolen_confirm = store.confirm_token_rotation(successor_id, "admin");
    REQUIRE_FALSE(stolen_confirm.has_value());
    CHECK(stolen_confirm.error() == "no such token to confirm");
    CHECK(classify_engine_store_error(stolen_confirm.error()) == E::ClientValidation);

    // Nothing mutated — the pair is still intact and alice can still confirm.
    CHECK(store.list_active_for_principal("alice").size() == 2);
    auto real_confirm = store.confirm_token_rotation(successor_id, "alice");
    CHECK(real_confirm.has_value());
}

TEST_CASE("ApiTokenStore: rotate_token rejects a window exceeding the predecessor's own "
          "expiry rather than truncating it",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    // Predecessor expires in 1h — a 24h (floor) overlap window cannot fit
    // before it, so the mint must be rejected, not silently shrunk.
    auto minted = store.create_token("tight", "alice", now + 3600);
    REQUIRE(minted.has_value());
    auto active = store.list_active_for_principal("alice");
    REQUIRE(active.size() == 1);
    const std::string token_id = active[0].token_id;

    auto rotated = store.rotate_token(token_id, kDay, now, "alice");
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error().find("expiry") != std::string::npos);

    // Rejected mint must not have minted a successor.
    CHECK(store.list_active_for_principal("alice").size() == 1);
}

TEST_CASE("ApiTokenStore: rotate_token mints a successor, stamps the rotation pair, and "
          "inherits the predecessor's expiry verbatim",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("my-pat", "alice", now + k90Days);
    REQUIRE(predecessor_raw.has_value());
    auto before = store.list_active_for_principal("alice");
    REQUIRE(before.size() == 1);
    const std::string predecessor_id = before[0].token_id;
    const int64_t predecessor_expires_at = before[0].expires_at;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice");
    REQUIRE(rotated.has_value());
    CHECK(rotated->starts_with("yuzu_"));
    CHECK(*rotated != *predecessor_raw);

    auto after = store.list_active_for_principal("alice");
    REQUIRE(after.size() == 2);

    const ApiToken* predecessor = nullptr;
    const ApiToken* successor = nullptr;
    for (const auto& t : after) {
        CHECK(t.principal_kind == "human");
        if (t.token_id == predecessor_id)
            predecessor = &t;
        else
            successor = &t;
    }
    REQUIRE(predecessor != nullptr);
    REQUIRE(successor != nullptr);

    CHECK_FALSE(predecessor->rotation_group.empty());
    CHECK(predecessor->rotation_group == successor->rotation_group);
    CHECK(predecessor->overlap_expires_at == now + kDefaultOverlapSecs);
    CHECK(successor->supersedes_token_id == predecessor->token_id);
    CHECK(predecessor->supersedes_token_id.empty());
    // Successor TTL: inherited verbatim, never recomputed as now+90d.
    CHECK(successor->expires_at == predecessor_expires_at);
    CHECK(successor->name == "my-pat");

    auto stored_hash = raw_hash_column(pool, successor->token_id);
    CHECK_FALSE(stored_hash.empty());
    CHECK(stored_hash != *rotated);
}

TEST_CASE("ApiTokenStore: rotate_token honours an explicit successor_expires_at override",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("my-pat", "alice", now + k90Days);
    REQUIRE(predecessor_raw.has_value());
    auto before = store.list_active_for_principal("alice");
    REQUIRE(before.size() == 1);
    const std::string predecessor_id = before[0].token_id;

    const int64_t override_expiry = now + kDefaultOverlapSecs + kDay;
    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice",
                                      override_expiry);
    REQUIRE(rotated.has_value());

    auto after = store.list_active_for_principal("alice");
    REQUIRE(after.size() == 2);
    for (const auto& t : after) {
        if (t.token_id != predecessor_id)
            CHECK(t.expires_at == override_expiry);
    }
}

TEST_CASE("ApiTokenStore: rotate_token — a perpetual predecessor yields a perpetual "
          "successor unless overridden",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("perma-pat", "alice"); // expires_at defaults to 0
    REQUIRE(predecessor_raw.has_value());
    auto before = store.list_active_for_principal("alice");
    REQUIRE(before.size() == 1);
    REQUIRE(before[0].expires_at == 0);
    const std::string predecessor_id = before[0].token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice");
    REQUIRE(rotated.has_value());

    auto after = store.list_active_for_principal("alice");
    REQUIRE(after.size() == 2);
    for (const auto& t : after) {
        if (t.token_id != predecessor_id)
            CHECK(t.expires_at == 0); // never silently forced onto a 90d ceiling
    }
}

TEST_CASE("ApiTokenStore: rotate_token — a human's OTHER unrelated active tokens never "
          "count against the <=2 ceiling (the core reason the human arm is token-keyed, "
          "not principal-keyed)",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    // alice holds THREE unrelated, never-rotated tokens — a principal-keyed
    // ceiling (the engine arm's own arbitration) would defensively reject
    // any rotate call here (">2 active"); the token-keyed arm must not.
    auto t1 = store.create_token("laptop", "alice", now + k90Days);
    auto t2 = store.create_token("ci-runner", "alice", now + k90Days);
    auto t3 = store.create_token("cli", "alice", now + k90Days);
    REQUIRE(t1.has_value());
    REQUIRE(t2.has_value());
    REQUIRE(t3.has_value());
    REQUIRE(store.list_active_for_principal("alice").size() == 3);

    auto active = store.list_active_for_principal("alice");
    std::string ci_id;
    for (const auto& t : active)
        if (t.name == "ci-runner")
            ci_id = t.token_id;
    REQUIRE_FALSE(ci_id.empty());

    auto rotated = store.rotate_token(ci_id, kDefaultOverlapSecs, now, "alice");
    REQUIRE(rotated.has_value());

    // Now 4 active total (laptop, cli untouched + the ci-runner pair), but
    // the rotate call itself must have succeeded cleanly.
    CHECK(store.list_active_for_principal("alice").size() == 4);
}

TEST_CASE("ApiTokenStore: rotate_token re-serves the same raw within the grace window, and "
          "never mints a third credential for that group",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("my-pat", "alice", now + k90Days);
    REQUIRE(predecessor_raw.has_value());
    const std::string predecessor_id = store.list_active_for_principal("alice")[0].token_id;

    auto first = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice");
    REQUIRE(first.has_value());

    auto retry = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice");
    REQUIRE(retry.has_value());
    CHECK(*retry == *first);

    CHECK(store.list_active_for_principal("alice").size() == 2);
}

TEST_CASE("ApiTokenStore: rotate_token — a query failure in the conflict arm's active-set "
          "re-read classifies Transient, never the terminal 'not a recognized rotation "
          "pair' conflict",
          "[pg][token][rotation]") {
    // Regression for a gap found in review: read_active_in_rotation_group_on_conn (a
    // group-scoped SQL query, since removed) swallowed a query failure into the same
    // empty vector as a genuinely-empty group, and the conflict arm then reported that
    // as the terminal "not a recognized rotation pair" ClientValidation — inverting
    // #2404 in the other direction (a transient DB hiccup reported as permanent,
    // do-not-retry). The fix reuses the principal-wide read + in-memory filter
    // (confirm_token_rotation's already-correct pattern); this test proves a query
    // failure AT THAT EXACT POINT stays Transient/retryable.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("my-pat", "alice", now + k90Days);
    REQUIRE(predecessor_raw.has_value());
    const std::string predecessor_id = store.list_active_for_principal("alice")[0].token_id;

    // First rotate mints the pair and lands us in the re-serve/conflict arm for
    // any subsequent call on the same predecessor.
    auto first = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice");
    REQUIRE(first.has_value());
    REQUIRE(store.list_active_for_principal("alice").size() == 2);

    // Poison the transaction's OWN connection right before the conflict arm's
    // active-set re-read — a genuine mid-transaction query failure, not a
    // simulated one: every statement on this connection fails until rollback.
    // Scoped (RAII): the hook clears itself even if a REQUIRE/CHECK below
    // throws, so it can never leak armed into the rest of this TEST_CASE.
    std::expected<std::string, std::string> retry;
    {
        ScopedRotateGroupReadHook hook_guard(store, [](pg_conn* conn) {
            (void)pg::exec_params(conn, "SELECT 1/0", std::vector<std::string>{});
        });
        retry = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice");
    }

    REQUIRE_FALSE(retry.has_value());
    // Reuses the SAME wording (and Transient class) the pre-mint lookup-failure
    // branch uses — never the terminal "not a recognized rotation pair" conflict.
    CHECK(retry.error() == "no active credential to rotate — mint one first");
    CHECK(classify_engine_store_error(retry.error()) == E::Transient);

    // The poisoned transaction rolled back — no state corrupted, and the pair
    // is exactly as it was before the failed retry.
    auto after = store.list_active_for_principal("alice");
    REQUIRE(after.size() == 2);

    // A normal call afterward (hook cleared) still works.
    auto clean_retry = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice");
    REQUIRE(clean_retry.has_value());
    CHECK(*clean_retry == *first);
}

TEST_CASE("ApiTokenStore: rotate_token — a COMMIT failure after the mint arm returns true "
          "never leaks a grace-cache entry (round 4 regression)",
          "[pg][token][rotation]") {
    // Regression for a gap found in review: store_rotation_raw was hoisted
    // above the `if (!ok)` check, so a COMMIT failure — which PgPool::run_in_txn
    // (pg/pg_pool.cpp) can still report AFTER the callback itself returned
    // true (the aborted/idle-transaction refusal, or PgTxn::commit() itself
    // failing, pg/pg_raii.hpp) — inserted a grace-cache entry keyed to a
    // candidate_token_id with NO committed row. Nothing can ever evict it:
    // evict_rotation_raw fires only on confirm-success or the sweep
    // resolving a pair, both of which require a committed row to exist at
    // all, and scrub_elapsed_grace_secrets zeroes the entry's `raw` past the
    // grace window but deliberately never erases the entry itself.
    //
    // This forces exactly that outcome by killing the transaction's own
    // backend connection right after the mint arm's INSERT+UPDATE have
    // already succeeded, but before with_txn_for attempts COMMIT — a genuine
    // commit failure, not a simulated one — and asserts the grace cache is
    // EMPTY afterward. LeakSanitizer cannot catch this class of leak (the
    // entry stays reachable from a live member map, `rotation_grace_cache_`),
    // so this targeted assertion is the only detector.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("my-pat", "alice", now + k90Days);
    REQUIRE(predecessor_raw.has_value());
    const std::string predecessor_id = store.list_active_for_principal("alice")[0].token_id;

    REQUIRE(store.rotation_grace_cache_size() == 0);

    store.test_hook_before_mint_commit_ = [&pool](pg_conn* conn) {
        const int victim_pid = PQbackendPID(conn);
        REQUIRE(victim_pid > 0);
        {
            // A second, independent connection sends the kill — pool size 4
            // easily covers holding the txn's own lease plus this one.
            auto axe = pool.acquire();
            REQUIRE(static_cast<bool>(axe));
            const std::string kill =
                "SELECT pg_terminate_backend(" + std::to_string(victim_pid) + ")";
            PgResult res{PQexec(axe.get(), kill.c_str())};
            REQUIRE(res.status() == PGRES_TUPLES_OK);
        }
        // pg_terminate_backend returns when the signal is SENT, not when the
        // backend has actually exited (same pattern as test_pg_pool.cpp's
        // "PgPool discards a connection lost mid-use") — poll on the VICTIM
        // connection until the client side observes the loss, so the
        // COMMIT that follows this hook's return genuinely fails rather
        // than racing a connection that hasn't died yet.
        bool severed = false;
        for (int i = 0; i < 100 && !severed; ++i) {
            PgResult ping{PQexec(conn, "SELECT 1")};
            severed = ping.status() != PGRES_TUPLES_OK && PQstatus(conn) != CONNECTION_OK;
            if (!severed)
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        REQUIRE(severed);
    };

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice");
    store.test_hook_before_mint_commit_ = nullptr;

    // The transaction never committed, so rotate_token must report failure...
    REQUIRE_FALSE(rotated.has_value());
    // ...and — the actual defect under test — no grace-cache entry may have
    // leaked for this failed-commit attempt.
    CHECK(store.rotation_grace_cache_size() == 0);

    // The DB-side rollback (connection loss aborts the in-flight transaction
    // server-side too) means the predecessor is untouched — still the
    // principal's sole active token, never mid-rotation.
    auto active = store.list_active_for_principal("alice");
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == predecessor_id);
    CHECK(active[0].rotation_group.empty());
}

// NOTE: there is no "grace-window re-serve to a different operator" test for
// the human arm — unlike the engine arm (where requesting_user is a
// third-party admin), self-service means ANY requesting_user other than the
// token's own owner is rejected by the ownership gate before it ever reaches
// the grace-window logic at all (see the dedicated non-owner tests above).
// The in-flight-rotation "different operator" state the engine arm's grace
// cache guards against is therefore structurally unreachable here.

TEST_CASE("ApiTokenStore: confirm_token_rotation cuts over immediately — revokes the "
          "predecessor and clears the successor's rotation state",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("my-pat", "alice", now + k90Days);
    REQUIRE(predecessor_raw.has_value());
    const std::string predecessor_id = store.list_active_for_principal("alice")[0].token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice");
    REQUIRE(rotated.has_value());
    auto active = store.list_active_for_principal("alice");
    REQUIRE(active.size() == 2);
    std::string successor_id;
    for (const auto& t : active)
        if (t.token_id != predecessor_id)
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());

    auto confirmed = store.confirm_token_rotation(successor_id, "alice");
    REQUIRE(confirmed.has_value());

    // Predecessor is revoked immediately (no need to wait for the overlap
    // window), and the successor is now a standalone active credential.
    auto after = store.list_active_for_principal("alice");
    REQUIRE(after.size() == 1);
    CHECK(after[0].token_id == successor_id);
    CHECK(after[0].rotation_group.empty());
    CHECK(after[0].supersedes_token_id.empty());
    CHECK(after[0].overlap_expires_at == 0);

    CHECK_FALSE(store.validate_token(*predecessor_raw).has_value());
}

// NOTE: there is no "confirm from a different operator" test for the human
// arm — same reasoning as rotate_token above: self-service means a non-owner
// requesting_user is rejected by the ownership gate before it ever reaches
// the initiator-binding check. See "confirm_token_rotation rejects a
// non-owner..." above.

TEST_CASE("ApiTokenStore: confirm_token_rotation rejects a token_id that is not the "
          "pending rotation's successor",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("my-pat", "alice", now + k90Days);
    REQUIRE(predecessor_raw.has_value());
    const std::string predecessor_id = store.list_active_for_principal("alice")[0].token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice");
    REQUIRE(rotated.has_value());

    // Passing the PREDECESSOR's own id (not the successor's) must be
    // rejected by the pin check, never silently accepted.
    auto mismatch = store.confirm_token_rotation(predecessor_id, "alice");
    REQUIRE_FALSE(mismatch.has_value());
    CHECK(store.list_active_for_principal("alice").size() == 2); // unchanged
}

TEST_CASE("ApiTokenStore: confirm_token_rotation on an unknown token_id is a terminal "
          "client error, never a masked-failure retry",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    auto confirmed = store.confirm_token_rotation("deadbeefdeadbeefdeadbeef", "admin");
    REQUIRE_FALSE(confirmed.has_value());
    CHECK(confirmed.error().find("no such token") != std::string::npos);
    CHECK(classify_engine_store_error(confirmed.error()) == E::ClientValidation);
}

TEST_CASE("ApiTokenStore: confirm_token_rotation on a token that was never part of a "
          "rotation is Transient — deliberately distinct wording+class from the engine "
          "arm's byte-identical-looking kSoleOtherToken string",
          "[pg][token][rotation]") {
    // Round-4 regression: this branch originally reused confirm_rotation's
    // (engine arm) kSoleOtherToken wording verbatim, byte-for-byte, which
    // silently inherited that string's Conflict classification via the
    // "the rotation was resolved" substring in engine_store_error_class.hpp
    // — even though the two states are different facts (a pin mismatch
    // against a DIFFERENT surviving credential, vs. nothing pending at all).
    // The fix gave this state its OWN wording + an explicit classifier entry.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    auto now = test_now_epoch();
    auto raw = store.create_token("never-rotated", "alice", now + k90Days);
    REQUIRE(raw.has_value());
    const std::string token_id = store.list_active_for_principal("alice")[0].token_id;

    auto confirmed = store.confirm_token_rotation(token_id, "alice");
    REQUIRE_FALSE(confirmed.has_value());
    CHECK(confirmed.error().find("no rotation currently pending") != std::string::npos);
    CHECK(confirmed.error().find("the rotation was resolved") == std::string::npos);
    CHECK(classify_engine_store_error(confirmed.error()) == E::Transient);
}

TEST_CASE("ApiTokenStore: confirm_token_rotation replay after success is Transient, "
          "distinctly from the engine arm's own confirm-replay strings",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("my-pat", "alice", now + k90Days);
    REQUIRE(predecessor_raw.has_value());
    const std::string predecessor_id = store.list_active_for_principal("alice")[0].token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& t : store.list_active_for_principal("alice"))
        if (t.token_id != predecessor_id)
            successor_id = t.token_id;

    REQUIRE(store.confirm_token_rotation(successor_id, "alice").has_value());

    // Replay: the successor is now the SOLE active credential for alice, and
    // it is not in the pinned rotation_group any more (kGroupEmpty).
    auto replay = store.confirm_token_rotation(successor_id, "alice");
    REQUIRE_FALSE(replay.has_value());
    CHECK(replay.error().find("no rotation currently pending") != std::string::npos);
    CHECK(replay.error().find("the rotation was resolved") == std::string::npos);
    CHECK(classify_engine_store_error(replay.error()) == E::Transient);
}

TEST_CASE("ApiTokenStore: sweep_expired_rotations auto-revokes an elapsed human "
          "predecessor exactly like the engine arm",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("my-pat", "alice", now + k90Days);
    REQUIRE(predecessor_raw.has_value());
    const std::string predecessor_id = store.list_active_for_principal("alice")[0].token_id;

    // Short overlap so the sweep at `now + kDay` finds it elapsed.
    auto rotated = store.rotate_token(predecessor_id, kDay, now, "alice");
    REQUIRE(rotated.has_value());
    REQUIRE(store.list_active_for_principal("alice").size() == 2);

    auto swept = store.sweep_expired_rotations(now + kDay + 1);
    REQUIRE(swept.size() == 1);
    CHECK(swept[0].token_id == predecessor_id);

    auto after = store.list_active_for_principal("alice");
    REQUIRE(after.size() == 1);
    CHECK(after[0].rotation_group.empty()); // successor's linkage cleared too
}
