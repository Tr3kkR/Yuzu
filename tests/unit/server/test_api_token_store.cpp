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

// RAII reset for any ApiTokenStore `std::function<void(pg_conn*)>` test-only
// hook member (test_hook_before_rotate_group_read_,
// test_hook_before_mint_commit_, and any future sibling of the same shape —
// takes the member BY REFERENCE rather than hardcoding one, so a second
// hook never needs its own hand-rolled copy of this class). A manual
// set/clear pair leaves the hook armed for the rest of the TEST_CASE if a
// REQUIRE/CHECK inside the guarded scope fails (Catch2 throws on assertion
// failure) — exactly the non-RAII cleanup shape this repo blocks in
// production code; this guard exists so no test needs to hand-roll that
// pattern for a new hook (round 6: a test doing exactly that for
// test_hook_before_mint_commit_, four REQUIREs deep in the hook body, was
// the defect this generalisation closes).
// SAVES AND RESTORES the prior value (rather than resetting to `nullptr`) —
// today the prior value is always null (the store is otherwise unhooked), but
// a save/clear-to-null guard would silently corrupt a nested or sequenced use
// (this exact class re-armed inside another guarded scope, or two of these in
// the same TEST_CASE), which its own doc comment above invites.
class ScopedPgConnHook {
public:
    ScopedPgConnHook(std::function<void(pg_conn*)>& slot, std::function<void(pg_conn*)> hook)
        : slot_(slot), prior_(std::move(slot_)) {
        slot_ = std::move(hook);
    }
    ~ScopedPgConnHook() { slot_ = std::move(prior_); }
    ScopedPgConnHook(const ScopedPgConnHook&) = delete;
    ScopedPgConnHook& operator=(const ScopedPgConnHook&) = delete;

private:
    std::function<void(pg_conn*)>& slot_;
    std::function<void(pg_conn*)> prior_;
};

// P2 #11: manually wires two already-created tokens into the overlap-pair
// rotation shape `rotate_engine_credential` (and, for a human principal, the
// sibling `rotate_token`, both present in this tree) would leave behind:
// predecessor gets `rotation_group` + `overlap_expires_at`; successor gets
// the SAME `rotation_group` + `supersedes_token_id == predecessor's
// token_id`. `rotate_token` itself always produces a well-formed pair
// through its own validation, so this direct-SQL seam exists ONLY for tests
// that need an arbitrary/malformed pair shape (e.g. an orphaned or
// mismatched group) `rotate_token`'s own validation would refuse to create —
// matching the file's existing direct-SQL precedent (raw_hash_column above,
// the F3 trigger seam below).
void wire_manual_rotation_pair(PgPool& pool, const std::string& rotation_group,
                               const std::string& predecessor_id, const std::string& successor_id,
                               int64_t overlap_expires_at) {
    auto lease = pool.acquire();
    REQUIRE(lease);
    pg::PgResult r1 = pg::exec_params(
        lease.get(),
        "UPDATE api_token_store.api_tokens SET rotation_group = $1, overlap_expires_at = $2 "
        "WHERE token_id = $3",
        std::vector<std::string>{rotation_group, std::to_string(overlap_expires_at), predecessor_id});
    REQUIRE(r1.ok());
    pg::PgResult r2 = pg::exec_params(
        lease.get(),
        "UPDATE api_token_store.api_tokens SET rotation_group = $1, supersedes_token_id = $2 "
        "WHERE token_id = $3",
        std::vector<std::string>{rotation_group, predecessor_id, successor_id});
    REQUIRE(r2.ok());
}

} // namespace

TEST_CASE("ApiTokenStore::sweep_expired_rotations: a HUMAN rotation pair's swept predecessor "
          "reports principal_kind=='human' — the signal server.cpp's sweep driver "
          "(rotation_sweep_names_for_kind) keys its metric/audit routing on (P2 #11)",
          "[pg][token][rotation][sweep][principal_kind]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    const std::string principal = "alice-p2-11-sweep";
    auto now = test_now_epoch();
    // principal_kind defaults to "human" — create_token's public signature
    // has no way to mint anything else without ALSO passing "engine" (which
    // triggers the engine-only referent-check block), so the default arm
    // exercised here IS the human path under test.
    REQUIRE(store.create_token("pred", principal, now + k90Days).has_value());
    REQUIRE(store.create_token("succ", principal, now + k90Days).has_value());

    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 2);
    const ApiToken* predecessor = active[0].name == "pred" ? &active[0] : &active[1];
    const ApiToken* successor = active[0].name == "succ" ? &active[0] : &active[1];
    REQUIRE(predecessor->principal_kind == "human");
    REQUIRE(successor->principal_kind == "human");

    // Overlap window already elapsed — this tick's sweep must pick it up.
    wire_manual_rotation_pair(pool, predecessor->token_id, predecessor->token_id,
                              successor->token_id, now - 1);

    bool tick_failed = false;
    auto swept = store.sweep_expired_rotations(now, &tick_failed);
    REQUIRE_FALSE(tick_failed);
    REQUIRE(swept.size() == 1);
    CHECK(swept[0].token_id == predecessor->token_id);
    // THE ASSERTION THIS TEST EXISTS FOR: the store hands the driver a real
    // "human" tag on the swept row — not a value that quietly defaults to
    // "engine" or gets lost between the scan and the returned ApiToken. A
    // wrong value here would misroute EVERY human rotation to the engine
    // metric/audit family regardless of how correct the driver's own
    // branching logic is.
    CHECK(swept[0].principal_kind == "human");
}

TEST_CASE("ApiTokenStore::list_rotations_nearing_expiry_unused: a HUMAN pair nearing expiry "
          "reports principal_kind=='human' on BOTH halves of the returned pair (P2 #11)",
          "[pg][token][rotation][sweep][principal_kind]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    const std::string principal = "alice-p2-11-nearing";
    auto now = test_now_epoch();
    REQUIRE(store.create_token("pred", principal, now + k90Days).has_value());
    REQUIRE(store.create_token("succ", principal, now + k90Days).has_value());

    auto active = store.list_active_for_principal(principal);
    REQUIRE(active.size() == 2);
    const ApiToken* predecessor = active[0].name == "pred" ? &active[0] : &active[1];
    const ApiToken* successor = active[0].name == "succ" ? &active[0] : &active[1];

    // Window ends 1h from now (inside a 24h warn lead); successor's
    // last_used_at stays 0 (create_token never touches it) — the "never
    // presented" precondition this half's query requires.
    wire_manual_rotation_pair(pool, predecessor->token_id, predecessor->token_id,
                              successor->token_id, now + 3600);

    auto nearing = store.list_rotations_nearing_expiry_unused(now, 24 * 3600);
    REQUIRE(nearing.size() == 1);
    CHECK(nearing[0].predecessor.token_id == predecessor->token_id);
    CHECK(nearing[0].successor.token_id == successor->token_id);
    // Both halves must carry "human" — server.cpp's successor-unused path
    // keys its family/action off pair.predecessor.principal_kind.
    CHECK(nearing[0].predecessor.principal_kind == "human");
    CHECK(nearing[0].successor.principal_kind == "human");
}

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
    // does. caller_mcp_tier is passed matching the row's own "readonly" tier
    // so the authority-inheritance guard (checked earlier in the sequence)
    // clears and this test reaches — and isolates — the kind check it
    // targets.
    auto rotated = store.rotate_token(active[0].token_id, kDefaultOverlapSecs, now,
                                      "engine:human-arm-guard", std::nullopt, "readonly", "");
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

// ── Authority-inheritance guard (governance Gate 7 CRITICAL fix) ───────────
//
// `rotate_token` used to copy the predecessor's `mcp_tier`/`scope_service`
// verbatim into the successor with no check that the CALLER's own current
// authority matched — so an operator-tier caller could pick their own
// untiered sibling token as the predecessor and receive an untiered,
// perpetual, full-authority successor. These three cases pin the fix.

TEST_CASE("ApiTokenStore: rotate_token refuses when the caller's own mcp_tier does not match "
          "the predecessor's — authority-inheritance guard, no successor row inserted",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    using yuzu::server::detail::classify_engine_store_error;
    using E = yuzu::server::detail::EngineStoreErrorClass;

    auto now = test_now_epoch();
    // Predecessor is UNTIERED, no scope_service, perpetual — the classic
    // full-authority credential the finding traces.
    auto raw = store.create_token("alices-untiered-pat", "alice", 0);
    REQUIRE(raw.has_value());
    const std::string token_id = store.list_active_for_principal("alice")[0].token_id;
    REQUIRE(store.list_active_for_principal("alice").size() == 1);

    // Caller presents an operator-tier authority the predecessor does NOT
    // carry — without the guard this would mint a fresh untiered/perpetual
    // successor for an operator-tier caller: exactly the escalation this
    // fix closes.
    auto rotated = store.rotate_token(token_id, kDefaultOverlapSecs, now, "alice", std::nullopt,
                                      "operator", "");
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error() == "no such token to rotate"); // same wording as absent/not-owned —
                                                          // not an authority-probing oracle
    CHECK(classify_engine_store_error(rotated.error()) == E::ClientValidation);

    // No successor minted — row count for the principal is unchanged, and
    // the predecessor was never stamped into a rotation pair either.
    auto active = store.list_active_for_principal("alice");
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == token_id);
    CHECK(active[0].rotation_group.empty());
}

TEST_CASE("ApiTokenStore: rotate_token succeeds when the caller's tier/scope match the "
          "predecessor's, and the successor inherits both verbatim",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto raw = store.create_token("alices-operator-pat", "alice", now + k90Days, "svc-a",
                                  "operator");
    REQUIRE(raw.has_value());
    const std::string token_id = store.list_active_for_principal("alice")[0].token_id;

    auto rotated = store.rotate_token(token_id, kDefaultOverlapSecs, now, "alice", std::nullopt,
                                      "operator", "svc-a");
    REQUIRE(rotated.has_value());

    // Pins inheritance itself — nothing else in this suite asserts the
    // minted successor's mcp_tier/scope_service against the predecessor's.
    std::string successor_id;
    for (const auto& t : store.list_active_for_principal("alice"))
        if (t.token_id != token_id)
            successor_id = t.token_id;
    REQUIRE_FALSE(successor_id.empty());
    auto successor = store.get_token(successor_id);
    REQUIRE(successor.has_value());
    REQUIRE(successor->has_value());
    CHECK((*successor)->mcp_tier == "operator");
    CHECK((*successor)->scope_service == "svc-a");
}

TEST_CASE("ApiTokenStore: rotate_token refuses on a scope_service mismatch even when the tier "
          "matches — the guard checks BOTH dimensions",
          "[pg][token][rotation]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto raw = store.create_token("alices-scoped-pat", "alice", now + k90Days, "svc-a",
                                  "operator");
    REQUIRE(raw.has_value());
    const std::string token_id = store.list_active_for_principal("alice")[0].token_id;
    REQUIRE(store.list_active_for_principal("alice").size() == 1);

    // Same tier as the predecessor, DIFFERENT scope_service — the caller's
    // own token is scoped to a different service than the one being
    // rotated.
    auto rotated = store.rotate_token(token_id, kDefaultOverlapSecs, now, "alice", std::nullopt,
                                      "operator", "svc-b");
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error() == "no such token to rotate");

    auto active = store.list_active_for_principal("alice");
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == token_id);
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
        ScopedPgConnHook hook_guard(store.test_hook_before_rotate_group_read_, [](pg_conn* conn) {
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

    // Scoped (RAII): the hook clears itself even if one of the several
    // REQUIREs inside its body throws (Catch2 assertion-failure semantics),
    // so it can never leak armed into the rest of this TEST_CASE — same
    // discipline as the conflict-arm hook above, via the same guard class.
    std::expected<std::string, std::string> rotated;
    {
        ScopedPgConnHook hook_guard(store.test_hook_before_mint_commit_, [&pool](pg_conn* conn) {
            const int victim_pid = PQbackendPID(conn);
            REQUIRE(victim_pid > 0);
            {
                // A second, independent connection sends the kill. Bounded
                // acquire + REQUIRE rather than a bare `pool.acquire()`: this
                // re-enters the pool from inside a live txn callback while
                // already holding the txn's own lease — safe today at
                // size = 4, but a bare acquire would hang CI forever (a
                // silent self-deadlock) if the pool size were ever reduced.
                // A bounded wait turns that into a loud, fast test failure
                // instead.
                auto axe = pool.try_acquire_for(std::chrono::seconds(5));
                REQUIRE(static_cast<bool>(axe));
                const std::string kill =
                    "SELECT pg_terminate_backend(" + std::to_string(victim_pid) + ")";
                PgResult res{PQexec(axe.get(), kill.c_str())};
                REQUIRE(res.status() == PGRES_TUPLES_OK);
            }
            // pg_terminate_backend returns when the signal is SENT, not when
            // the backend has actually exited (same pattern as
            // test_pg_pool.cpp's "PgPool discards a connection lost
            // mid-use") — poll on the VICTIM connection until the client
            // side observes the loss, so the COMMIT that follows this
            // hook's return genuinely fails rather than racing a connection
            // that hasn't died yet.
            bool severed = false;
            for (int i = 0; i < 100 && !severed; ++i) {
                PgResult ping{PQexec(conn, "SELECT 1")};
                severed = ping.status() != PGRES_TUPLES_OK && PQstatus(conn) != CONNECTION_OK;
                if (!severed)
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            REQUIRE(severed);
        });
        rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "alice");
    }

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
          "rotation is a terminal Conflict — own wording, arm-parity with the engine "
          "arm's kSoleOtherToken (round 5 adjudication)",
          "[pg][token][rotation]") {
    // Round-4 review found this branch originally reused confirm_rotation's
    // (engine arm) kSoleOtherToken wording verbatim, byte-for-byte, and so
    // silently inherited that string's classification via the "the rotation
    // was resolved" substring — a genuine bug, since the two states are
    // different FACTS (a pin mismatch against a DIFFERENT surviving
    // credential, vs. nothing pending at all) even though both happen to be
    // Conflict. Round 4's fix gave this state its own wording but ALSO
    // reclassified it to Transient, reasoning from the "call rotate again"
    // prose — round 5 adjudication refuted that: #2404 precedent, arm parity
    // with `kSoleOtherToken` (identical "rotate again" guidance, Conflict),
    // and `rotation_confirm_state.hpp`'s own "every terminal state ->
    // Conflict or ClientValidation" contract all say Conflict. This state
    // keeps its own (round-4) wording — own classifier entry, correct class.
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
    CHECK(classify_engine_store_error(confirmed.error()) == E::Conflict);
}

TEST_CASE("ApiTokenStore: confirm_token_rotation replay after success is a terminal "
          "Conflict, own wording distinct from the engine arm's own confirm-replay "
          "strings",
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
    // it is not in the pinned rotation_group any more (kGroupEmpty) — a
    // POSITIVE fact (rotation_confirm_state.hpp), terminal Conflict.
    auto replay = store.confirm_token_rotation(successor_id, "alice");
    REQUIRE_FALSE(replay.has_value());
    CHECK(replay.error().find("no rotation currently pending") != std::string::npos);
    CHECK(replay.error().find("the rotation was resolved") == std::string::npos);
    CHECK(classify_engine_store_error(replay.error()) == E::Conflict);
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

// ── P2 #11 / SOC 2 CC6.3: token-keyed rotation for HUMAN-owned tokens ──────
//
// `rotate_token`/`confirm_token_rotation` do not exist on ApiTokenStore as of
// this writing — this section is written against their PINNED signatures (P5
// task brief) precisely so it is an INDEPENDENT regression suite for whoever
// lands the implementation, not a test written by the same author grading
// their own blind spots. It will not compile until both land with exactly:
//
//   [[nodiscard]] std::expected<std::string, std::string>
//   rotate_token(const std::string& predecessor_token_id, int64_t overlap_secs,
//                int64_t now, const std::string& requesting_user,
//                std::optional<int64_t> successor_expires_at = std::nullopt);
//
//   [[nodiscard]] std::expected<void, std::string>
//   confirm_token_rotation(const std::string& successor_token_id,
//                          const std::string& requesting_user);
//
// THE regression this whole section exists to catch: `rotate_engine_credential`
// / `confirm_rotation` above arbitrate on `read_active_for_principal_on_conn`'s
// PRINCIPAL-scoped count — correct for an engine principal, which owns exactly
// one rotation lineage, but wrong for a human, who routinely holds N unrelated
// tokens under the SAME principal_id (their username). A naive port that
// reused the principal-scoped read would mean a user with exactly 2 tokens can
// NEVER rotate either one (an unrelated second token always reads as
// "rotation already in flight"), and a user with 3+ ALWAYS hits the >2-active
// defensive reject — for every token, every time. `rotate_token` takes a
// TOKEN id, not a PRINCIPAL id, specifically so the ≤2 ceiling is scoped to
// the predecessor's own rotation GROUP, never the principal's whole set.
//
// Classifier calibration below: substrings already pinned as GENERIC shared
// vocabulary in engine_store_error_class.hpp (floor/ceiling/expiry/
// different-operator/grace-window/pin-mismatch — none of it says "engine")
// are asserted verbatim, since the header's own docstring says it classifies
// EnginePrincipalStore *and* ApiTokenStore errors generically. Confirm-side
// rotation-STATE wording (sole/resolved/unresolved), which is more likely to
// be reworded for a "rotation group" mental model instead of a "principal"
// one, is asserted only via `classify_engine_store_error`'s returned CLASS —
// still a real tripwire (per the header's #2404 doctrine, a reworded message
// that drops every keyed substring silently reclassifies to the retryable
// Transient default, and an honest client then retries a terminal failure
// forever), without hard-pinning prose this suite's author cannot know yet.

namespace {

using yuzu::server::detail::classify_engine_store_error;
using ClsE = yuzu::server::detail::EngineStoreErrorClass;

} // namespace

// ── Item 1: THE regression — group-scoped, not principal-scoped ───────────

TEST_CASE("ApiTokenStore: rotate_token on a human token is GROUP-scoped, not "
          "principal-scoped — a user holding 3 unrelated active tokens can "
          "rotate ONE without hitting the engine machine's principal-wide "
          "ceiling (P2 #11 THE regression)",
          "[pg][token][rotation][human]") {
    // Defect this catches: if rotate_token were ported by reusing
    // read_active_for_principal_on_conn's principal-keyed count (as
    // rotate_engine_credential does), alice's 3rd active token would put her
    // principal-wide count at 3 BEFORE rotate even starts, landing the >2
    // defensive reject on every call — this is the exact production shape
    // (any user with 2+ unrelated tokens can never rotate any of them) and is
    // the entire reason rotate_token takes a token_id, not a principal_id.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t1 = store.create_token("CI token", "alice", now + k90Days);
    auto t2 = store.create_token("Laptop PAT", "alice", now + k90Days);
    auto t3 = store.create_token("Backup script", "alice", now + k90Days);
    REQUIRE(t1.has_value());
    REQUIRE(t2.has_value());
    REQUIRE(t3.has_value());
    REQUIRE(store.list_active_for_principal("alice").size() == 3);

    auto v2 = store.validate_token(*t2);
    REQUIRE(v2.has_value());
    const std::string t2_id = v2->token_id;

    auto rotated = store.rotate_token(t2_id, kDefaultOverlapSecs, now, "alice");
    REQUIRE(rotated.has_value());
    CHECK(rotated->starts_with("yuzu_"));

    // t1 and t3 are completely untouched: still active, no rotation state.
    auto v1 = store.validate_token(*t1);
    REQUIRE(v1.has_value());
    CHECK(v1->rotation_group.empty());
    auto v3 = store.validate_token(*t3);
    REQUIRE(v3.has_value());
    CHECK(v3->rotation_group.empty());

    // alice now has 4 active credentials fleet-wide (t1, t3, predecessor t2,
    // successor) — a principal-wide ≤2 ceiling would have instantly rejected
    // this rotate. It succeeded anyway.
    CHECK(store.list_active_for_principal("alice").size() == 4);
}

// ── Item 2: ≤2 ceiling is per-GROUP, other tokens irrelevant ───────────────

TEST_CASE("ApiTokenStore: rotate_token's ≤2 ceiling is scoped to the "
          "predecessor's rotation GROUP — a same-user unrelated token never "
          "trips, or is tripped by, another group's arbitration",
          "[pg][token][rotation][human]") {
    // Defect this catches: if the arbitration read counted the principal's
    // whole active set, rotating token A twice (predecessor+successor = 2)
    // while bob ALSO holds unrelated token B would see 3-active and hit the
    // defensive ">2 active, resolve manually" reject — even though B has
    // nothing to do with A's rotation. A group-scoped read must ignore B.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto a = store.create_token("Token A", "bob", now + k90Days);
    auto b = store.create_token("Token B", "bob", now + k90Days);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    auto va = store.validate_token(*a);
    REQUIRE(va.has_value());
    const std::string a_id = va->token_id;

    // First rotate of A mints a successor -> A's group now has 2 rows.
    auto first = store.rotate_token(a_id, kDefaultOverlapSecs, now, "bob");
    REQUIRE(first.has_value());

    // A same-operator retry within grace re-serves the SAME raw — the
    // in-flight-pair re-serve arm, exercised at A's group scope alone.
    auto retry = store.rotate_token(a_id, kDefaultOverlapSecs, now, "bob");
    REQUIRE(retry.has_value());
    CHECK(*retry == *first);

    // A non-owner probing A's in-flight pair is rejected by the store-level
    // self-service ownership gate (item 7's dedicated coverage), never by
    // the F4-style "different operator" grace-window conflict — under
    // self-service there is only ONE legitimate requesting_user per token,
    // so that state is unreachable via a wrong caller (see :851 in the
    // checklist). No distinguishable wording is asserted here on purpose —
    // asserting one would itself be an enumeration-oracle regression (item
    // 7b). B, held by the SAME principal, plays no part in this rejection.
    auto stolen = store.rotate_token(a_id, kDefaultOverlapSecs, now, "mallory");
    REQUIRE_FALSE(stolen.has_value());

    // B is completely unaffected throughout.
    auto vb = store.validate_token(*b);
    REQUIRE(vb.has_value());
    CHECK(vb->rotation_group.empty());
    CHECK_FALSE(vb->revoked);
}

// ── Item 2b: Hermes F2 atomic pair-commit (token-keyed twin of :1012) ─────

TEST_CASE("ApiTokenStore: rotate_token never leaves an orphaned rotation "
          "pair — mint and pair-stamp always commit together (Hermes F2, "
          "human arm)",
          "[pg][token][rotation][human]") {
    // Token-keyed twin of :1012. Every prior human-arm test asserted the
    // SUCCESSOR side of the pair (supersedes_token_id, TTL inheritance,
    // etc.) but never fetched the PREDECESSOR row after a successful
    // rotate_token and checked IT was stamped. Defect this catches: an
    // implementation whose successor INSERT and predecessor pair-stamp
    // UPDATE are not the same atomic transaction could mint a
    // correctly-linked successor while the predecessor's own
    // rotation_group/overlap_expires_at are left at their pre-rotation
    // defaults — an orphaned pair, invisible to every assertion this suite
    // made before this test, and exactly F2's defect class. It matters more
    // here than in the engine arm: `sweep_expired_rotations`'s auto-revoke
    // depends entirely on the predecessor's own `overlap_expires_at` being
    // stamped (see the two tests below), so an orphan here silently
    // disables the sweep for that credential, not just the pairing record.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Pair-commit PAT", "priya", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string predecessor_id = vt->token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "priya");
    REQUIRE(rotated.has_value());

    auto active = store.list_active_for_principal("priya");
    REQUIRE(active.size() == 2);
    const ApiToken* predecessor = nullptr;
    const ApiToken* successor = nullptr;
    for (const auto& tok : active) {
        if (tok.token_id == predecessor_id)
            predecessor = &tok;
        else
            successor = &tok;
    }
    REQUIRE(predecessor != nullptr);
    REQUIRE(successor != nullptr);

    // The full triple :1012 asserts — predecessor side included, which is
    // exactly the half every earlier test in this section skipped.
    CHECK_FALSE(predecessor->rotation_group.empty());
    CHECK(predecessor->rotation_group == successor->rotation_group);
    CHECK(predecessor->overlap_expires_at > 0);
    CHECK(successor->supersedes_token_id == predecessor->token_id);
    CHECK(predecessor->supersedes_token_id.empty());
}

TEST_CASE("ApiTokenStore: sweep_expired_rotations auto-revokes a human "
          "predecessor whose overlap window has lapsed, and clears the "
          "surviving successor's rotation state",
          "[pg][token][rotation][human][sweep]") {
    // Defect this catches: `sweep_expired_rotations` is untouched by
    // anything else in this section — if it were never invoked here it
    // would ship with zero coverage on the token-keyed path despite being
    // the SOLE enforcement of predecessor auto-revoke (validate_token never
    // checks overlap_expires_at, per its own doc comment). This also
    // exercises the F2 pair-stamp's SECOND-ORDER consequence the previous
    // test names: the sweep only finds this predecessor eligible because
    // rotate_token stamped its overlap_expires_at correctly.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Sweep PAT", "sanjay", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string predecessor_id = vt->token_id;

    // A short overlap window so the sweep fires shortly after `now`.
    auto rotated = store.rotate_token(predecessor_id, kDay, now, "sanjay");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& tok : store.list_active_for_principal("sanjay"))
        if (tok.supersedes_token_id == predecessor_id)
            successor_id = tok.token_id;
    REQUIRE_FALSE(successor_id.empty());

    bool tick_failed = false;
    auto swept = store.sweep_expired_rotations(now + kDay + 1, &tick_failed);
    CHECK_FALSE(tick_failed);
    bool predecessor_in_swept = false;
    for (const auto& tok : swept)
        if (tok.token_id == predecessor_id)
            predecessor_in_swept = true;
    CHECK(predecessor_in_swept);

    auto active = store.list_active_for_principal("sanjay");
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == successor_id);
    CHECK(active[0].rotation_group.empty());       // cleared by the sweep
    CHECK(active[0].supersedes_token_id.empty());
    CHECK(active[0].overlap_expires_at == 0);

    auto pred = store.get_token(predecessor_id);
    REQUIRE(pred.has_value());
    REQUIRE(pred->has_value());
    CHECK((*pred)->revoked); // the predecessor was actually revoked
}

TEST_CASE("ApiTokenStore: list_rotations_nearing_expiry_unused surfaces a "
          "human rotation pair whose overlap window is about to lapse and "
          "whose successor has never been presented",
          "[pg][token][rotation][human][sweep]") {
    // Defect this catches: like sweep_expired_rotations, this read-only T12
    // half is never exercised anywhere else in this section — an
    // implementation whose rotate_token mints a pair with the fields this
    // query filters on populated INCORRECTLY (e.g. `last_used_at` stamped
    // at mint time, or `overlap_expires_at` left outside the warn window)
    // would silently never surface the "successor unused, window closing"
    // operational-health signal for a human PAT, with no test catching it.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Unused-successor PAT", "tanya", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string predecessor_id = vt->token_id;

    // Overlap window ends in exactly 1 day — ask for pairs whose window
    // ends within 2 days, so this pair is within the warn threshold but its
    // window has NOT yet elapsed.
    auto rotated = store.rotate_token(predecessor_id, kDay, now, "tanya");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& tok : store.list_active_for_principal("tanya"))
        if (tok.supersedes_token_id == predecessor_id)
            successor_id = tok.token_id;
    REQUIRE_FALSE(successor_id.empty());

    auto nearing = store.list_rotations_nearing_expiry_unused(now, /*warn_within_secs=*/2 * kDay);
    bool found = false;
    for (const auto& pair : nearing) {
        if (pair.predecessor.token_id == predecessor_id) {
            found = true;
            CHECK(pair.successor.token_id == successor_id);
            CHECK(pair.successor.last_used_at == 0); // never presented
        }
    }
    CHECK(found);

    // A rotation NOT nearing expiry (fresh, full-length overlap) must NOT be
    // surfaced — proves this isn't just "every in-flight pair, unfiltered".
    auto t2 = store.create_token("Not-nearing PAT", "tanya", now + k90Days);
    REQUIRE(t2.has_value());
    auto vt2 = store.validate_token(*t2);
    REQUIRE(vt2.has_value());
    auto rotated2 =
        store.rotate_token(vt2->token_id, kDefaultOverlapSecs, now, "tanya"); // 7d overlap
    REQUIRE(rotated2.has_value());
    auto nearing2 = store.list_rotations_nearing_expiry_unused(now, /*warn_within_secs=*/2 * kDay);
    for (const auto& pair : nearing2)
        CHECK(pair.predecessor.token_id != vt2->token_id);
}

// ── Item 2c: group-scoped >2 active defensive reject (token-keyed twin of
//    :921/:1356) ──────────────────────────────────────────────────────────
//
// Distinct from item 1's regression (unrelated same-principal tokens must
// NOT trip a ceiling) — this is the opposite-direction property: THREE
// active rows sharing the SAME rotation_group must still be defensively
// rejected, never silently arbitrated. Both matter, and each needs its own
// case because they pull in opposite directions: item 1 proves the
// arbitration read must NOT be principal-wide; this proves it must still
// correctly detect an overfull GROUP once it is properly group-scoped.
// Manufactured via raw SQL (create_token exposes no rotation_group
// parameter) — the same manufactured-state technique already used for the
// :1389 stale-linkage twin above. Both the classifier CLASS and the
// verbatim substring `"more than two active credentials"` are asserted
// here — NOT the confirm-side rotation-state-prose exemption this
// section's calibration rule applies elsewhere. That substring is already
// generic, non-engine-scoped classifier vocabulary
// (engine_store_error_class.hpp:118, "more than two active credentials"),
// and both engine references pin it verbatim (:921, :1356) — the
// implementer has no legitimate wording freedom the classifier doesn't
// already claim. A class-only assertion here would be too weak: an
// unrelated ClientValidation failure (e.g. a bad successor_expires_at
// colliding with the manufactured state) would satisfy it without the >2
// branch ever firing, proving nothing about what this test claims to
// cover.

TEST_CASE("ApiTokenStore: rotate_token defensively rejects when three "
          "active rows already share ONE rotation_group, rather than "
          "arbitrating which pair is authoritative — token-keyed twin of "
          ":921",
          "[pg][token][rotation][human]") {
    // Defect this catches: resolve_rotation_pair_after_revoke
    // (api_token_store.cpp:686-716) already scopes its own UPDATE by
    // rotation_group — a group-scoped defensive ">2" branch is exactly the
    // kind of port detail a naive implementation, having correctly moved
    // the ARBITRATION read from principal-wide to group-scoped (item 1),
    // could still drop: e.g. by reusing the OLD principal-wide ">2" check
    // (which would reject this case for the wrong reason and ALSO wrongly
    // reject item 1's legitimately-unrelated-tokens case), or by never
    // checking group size at all and instead picking an arbitrary pair
    // from the 3 rows to treat as authoritative — silently discarding the
    // third credential's rotation eligibility with no error.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Overfull-group PAT", "wendy", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string predecessor_id = vt->token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "wendy");
    REQUIRE(rotated.has_value());
    std::string rotation_group;
    for (const auto& tok : store.list_active_for_principal("wendy"))
        if (tok.token_id == predecessor_id)
            rotation_group = tok.rotation_group;
    REQUIRE_FALSE(rotation_group.empty());

    // Manufacture a THIRD active row sharing that same rotation_group —
    // create_token has no rotation_group parameter, so this can only be
    // done by raw SQL, mirroring the resolve_rotation_pair_after_revoke
    // implementation's own column set.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string sql =
            "INSERT INTO api_token_store.api_tokens "
            "(token_id, token_hash, name, principal_id, scope_service, mcp_tier, "
            " principal_kind, created_at, expires_at, revoked, rotation_group) "
            "VALUES ('overfull0000000000000001', 'fakehash-overfull-rotate-01', "
            "'Manufactured extra', 'wendy', '', '', 'human', " +
            std::to_string(now) + ", " + std::to_string(now + k90Days) +
            ", FALSE, '" + rotation_group + "');";
        PgResult res{PQexec(conn.get(), sql.c_str())};
        REQUIRE(res.ok());
    }
    auto overfull = store.list_active_for_principal("wendy");
    int in_group = 0;
    for (const auto& tok : overfull)
        if (tok.rotation_group == rotation_group)
            ++in_group;
    REQUIRE(in_group == 3);

    auto over = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "wendy");
    REQUIRE_FALSE(over.has_value());
    CHECK(over.error().find("more than two active credentials") != std::string::npos);
    CHECK(classify_engine_store_error(over.error()) == ClsE::ClientValidation);

    // Never arbitrates — the group stays at exactly 3, no fourth row minted.
    auto after = store.list_active_for_principal("wendy");
    int still_in_group = 0;
    for (const auto& tok : after)
        if (tok.rotation_group == rotation_group)
            ++still_in_group;
    CHECK(still_in_group == 3);
}

TEST_CASE("ApiTokenStore: confirm_token_rotation on a group with three "
          "active rows is a terminal client error, not retryable — "
          "token-keyed twin of :1356",
          "[pg][token][rotation][human][confirm]") {
    // Defect this catches: the confirm-side counterpart to the test above —
    // an implementation could correctly defend rotate_token's mint path
    // against an overfull group while leaving confirm_token_rotation to
    // fall through to the generic "no in-flight rotation" retryable
    // default, which would tell an idempotent-hint-honouring client to
    // retry a call that can never succeed from this state.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Overfull-confirm PAT", "xena", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string predecessor_id = vt->token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "xena");
    REQUIRE(rotated.has_value());
    std::string successor_id, rotation_group;
    for (const auto& tok : store.list_active_for_principal("xena")) {
        if (tok.supersedes_token_id == predecessor_id) {
            successor_id = tok.token_id;
            rotation_group = tok.rotation_group;
        }
    }
    REQUIRE_FALSE(successor_id.empty());

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string sql =
            "INSERT INTO api_token_store.api_tokens "
            "(token_id, token_hash, name, principal_id, scope_service, mcp_tier, "
            " principal_kind, created_at, expires_at, revoked, rotation_group) "
            "VALUES ('overfull0000000000000002', 'fakehash-overfull-confirm-02', "
            "'Manufactured extra', 'xena', '', '', 'human', " +
            std::to_string(now) + ", " + std::to_string(now + k90Days) +
            ", FALSE, '" + rotation_group + "');";
        PgResult res{PQexec(conn.get(), sql.c_str())};
        REQUIRE(res.ok());
    }
    auto overfull = store.list_active_for_principal("xena");
    int in_group = 0;
    for (const auto& tok : overfull)
        if (tok.rotation_group == rotation_group)
            ++in_group;
    REQUIRE(in_group == 3);

    auto over = store.confirm_token_rotation(successor_id, "xena");
    REQUIRE_FALSE(over.has_value());
    CHECK(over.error().find("more than two active credentials") != std::string::npos);
    CHECK(classify_engine_store_error(over.error()) == ClsE::ClientValidation);

    // Never arbitrates: no confirmed_at stamped, group untouched at 3.
    auto after = store.list_active_for_principal("xena");
    int still_in_group = 0;
    for (const auto& tok : after) {
        if (tok.rotation_group == rotation_group) {
            ++still_in_group;
            CHECK(tok.confirmed_at == 0);
        }
    }
    CHECK(still_in_group == 3);
}

// ── Item 3: concurrency ─────────────────────────────────────────────────

TEST_CASE("ApiTokenStore: concurrent rotate_token calls for the SAME "
          "predecessor and SAME owner never exceed the ≤2 active ceiling, "
          "and every call succeeds with the identical raw secret (human "
          "twin of Hermes F1)",
          "[pg][token][rotation][human][concurrency]") {
    // Defect this catches: an unlocked (or principal-scoped-locked but
    // group-blind) read-then-mint would let multiple racing threads all
    // observe "1 in this group" and all mint, blowing the ≤2 ceiling for a
    // SINGLE token's rotation lineage — mirrors :953's engine test's core
    // property, keyed by token_id. The per-thread OUTCOME deliberately
    // differs from :953: under the store-level self-service rule
    // (requesting_user must equal the token's own principal_id on every
    // call), there is exactly ONE legitimate requesting_user for a given
    // token, so :953's shape — distinct "operator-N" identities, each
    // individually rejected by the F4 binding — has no human analog (see
    // :851 in the round-4 checklist: that state is unreachable here, a
    // non-owner is bounced by the ownership gate before ever reaching it).
    // The realistic human race is the SAME owner double-clicking "rotate"
    // in two tabs: every thread below shares carol's identity, so every
    // thread must succeed, and every success must carry the IDENTICAL raw
    // secret (the losers hit the re-serve arm, not a rejection).
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 8}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Racy PAT", "carol", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    constexpr int kThreads = 6;
    std::latch start_latch{kThreads};
    std::vector<std::thread> threads;
    std::mutex results_mtx;
    std::vector<std::expected<std::string, std::string>> results;

    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&]() {
            start_latch.arrive_and_wait();
            auto r = store.rotate_token(t_id, kDefaultOverlapSecs, now, "carol");
            std::lock_guard lock(results_mtx);
            results.push_back(std::move(r));
        });
    }
    for (auto& th : threads)
        th.join();

    // Every thread is carol racing her own token: every call must succeed
    // (the winner mints, every loser re-serves), and no two calls may
    // return DIFFERENT raw values — that would mean a second successor was
    // minted, which the ceiling check below would also catch.
    REQUIRE(results.size() == static_cast<std::size_t>(kThreads));
    for (const auto& r : results)
        REQUIRE(r.has_value());
    for (const auto& r : results)
        CHECK(*r == *results.front());

    // The ≤2 ceiling for THIS token's group holds under concurrency — never
    // a third mint from a lost race.
    int related = 0;
    for (const auto& tok : store.list_active_for_principal("carol"))
        if (tok.token_id == t_id || tok.supersedes_token_id == t_id)
            ++related;
    CHECK(related == 2);
}

TEST_CASE("ApiTokenStore: concurrent rotate_token calls on TWO DIFFERENT "
          "tokens owned by the SAME principal both succeed",
          "[pg][token][rotation][human][concurrency]") {
    // Defect this catches: if the advisory lock (or any other serialization
    // point) keys on principal_id rather than the predecessor's own rotation
    // group, two genuinely independent rotations for the same user would
    // contend the SAME lock. Contention alone is harmless (they just
    // serialize) — but if the arbitration read is ALSO principal-scoped, the
    // second call to acquire the lock would observe 3-active (its own
    // unrelated predecessor + the first rotation's now-2-active pair) and
    // hit the defensive >2 reject. Both must succeed regardless of
    // interleaving — this is item 1/2's group-scoping guarantee, but proven
    // under genuine concurrency rather than sequential calls.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 8}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto a = store.create_token("Token A", "dave", now + k90Days);
    auto b = store.create_token("Token B", "dave", now + k90Days);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    auto va = store.validate_token(*a);
    auto vb = store.validate_token(*b);
    REQUIRE(va.has_value());
    REQUIRE(vb.has_value());
    const std::string a_id = va->token_id;
    const std::string b_id = vb->token_id;

    std::latch start_latch{2};
    std::expected<std::string, std::string> result_a, result_b;
    std::thread ta([&]() {
        start_latch.arrive_and_wait();
        result_a = store.rotate_token(a_id, kDefaultOverlapSecs, now, "dave");
    });
    std::thread tb([&]() {
        start_latch.arrive_and_wait();
        result_b = store.rotate_token(b_id, kDefaultOverlapSecs, now, "dave");
    });
    ta.join();
    tb.join();

    REQUIRE(result_a.has_value());
    REQUIRE(result_b.has_value());
    CHECK(store.list_active_for_principal("dave").size() == 4); // 2 groups x 2 rows
}

// ── Item 4: successor TTL inheritance ───────────────────────────────────

TEST_CASE("ApiTokenStore: rotate_token's successor inherits the "
          "predecessor's absolute expires_at verbatim, never resetting to a "
          "fresh 90-day window",
          "[pg][token][rotation][human]") {
    // Defect this catches: the engine arm always mints a fresh now+90-days
    // candidate (see candidate_expires_at in rotate_engine_credential) — a
    // naive port would silently widen (or shrink) a human PAT's lifetime on
    // every rotation instead of preserving the operator's original choice.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    const int64_t predecessor_expiry = now + 180 * kDay; // deliberately NOT 90 days
    auto t = store.create_token("Long-lived PAT", "erin", predecessor_expiry);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    auto rotated = store.rotate_token(t_id, kDefaultOverlapSecs, now, "erin");
    REQUIRE(rotated.has_value());

    auto active = store.list_active_for_principal("erin");
    const ApiToken* successor = nullptr;
    for (const auto& tok : active)
        if (tok.supersedes_token_id == t_id)
            successor = &tok;
    REQUIRE(successor != nullptr);
    CHECK(successor->expires_at == predecessor_expiry);
}

TEST_CASE("ApiTokenStore: rotate_token on a PERPETUAL predecessor "
          "(expires_at == 0) yields a perpetual successor",
          "[pg][token][rotation][human]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Perpetual PAT", "frank"); // expires_at defaults 0
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;
    auto pre = store.get_token(t_id);
    REQUIRE(pre.has_value());
    REQUIRE(pre->has_value());
    REQUIRE((*pre)->expires_at == 0);

    auto rotated = store.rotate_token(t_id, kDefaultOverlapSecs, now, "frank");
    REQUIRE(rotated.has_value());

    auto active = store.list_active_for_principal("frank");
    const ApiToken* successor = nullptr;
    for (const auto& tok : active)
        if (tok.supersedes_token_id == t_id)
            successor = &tok;
    REQUIRE(successor != nullptr);
    CHECK(successor->expires_at == 0); // perpetual, not defaulted to a 90-day window
}

TEST_CASE("ApiTokenStore: rotate_token's optional successor_expires_at "
          "override is honoured when supplied and valid",
          "[pg][token][rotation][human]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Overridable PAT", "grace", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    // A valid override in the future, past the overlap window's own end.
    const int64_t override_expiry = now + 30 * kDay;
    auto rotated =
        store.rotate_token(t_id, kDefaultOverlapSecs, now, "grace", override_expiry);
    REQUIRE(rotated.has_value());

    auto active = store.list_active_for_principal("grace");
    const ApiToken* successor = nullptr;
    for (const auto& tok : active)
        if (tok.supersedes_token_id == t_id)
            successor = &tok;
    REQUIRE(successor != nullptr);
    CHECK(successor->expires_at == override_expiry); // caller's value, not inherited
}

TEST_CASE("ApiTokenStore: rotate_token rejects a successor_expires_at "
          "override that has already elapsed — never silently swapped for "
          "the inherited value",
          "[pg][token][rotation][human]") {
    // Defect this catches: an implementation that only conditionally uses
    // the override when non-empty, without validating the SUPPLIED value's
    // own sanity, would mint a successor that is already expired the
    // instant it is issued.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("PAT", "heidi", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    auto rotated =
        store.rotate_token(t_id, kDefaultOverlapSecs, now, "heidi", now - 1);
    REQUIRE_FALSE(rotated.has_value());

    // No successor minted; predecessor untouched.
    auto active = store.list_active_for_principal("heidi");
    REQUIRE(active.size() == 1);
    CHECK(active[0].rotation_group.empty());
}

TEST_CASE("ApiTokenStore: rotate_token rejects a successor_expires_at "
          "override that would fall before the overlap window's own end",
          "[pg][token][rotation][human]") {
    // Token-keyed analog of the "overlap window would exceed the successor
    // credential's expiry" ClientValidation substring already pinned in
    // engine_store_error_class.hpp — the successor's own candidate expiry,
    // whether inherited or overridden, must never be exceeded by the
    // requested overlap window.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("PAT", "ivy", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    // Overlap window ends at now+kDefaultOverlapSecs (7d); override the
    // successor to expire at now+1d — BEFORE the window it would need to
    // survive.
    auto rotated = store.rotate_token(t_id, kDefaultOverlapSecs, now, "ivy", now + kDay);
    REQUIRE_FALSE(rotated.has_value());
    CHECK(classify_engine_store_error(rotated.error()) == ClsE::ClientValidation);

    auto active = store.list_active_for_principal("ivy");
    REQUIRE(active.size() == 1); // no successor minted
}

TEST_CASE("ApiTokenStore: rotate_token rejects an overlap window that would "
          "exceed the predecessor's near-expiry, rather than silently "
          "truncating it",
          "[pg][token][rotation][human]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    // Predecessor expires in 1 day — far less than the requested overlap.
    auto t = store.create_token("Nearly-expired PAT", "ivan", now + kDay);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    auto rotated = store.rotate_token(t_id, kDefaultOverlapSecs, now, "ivan");
    REQUIRE_FALSE(rotated.has_value());
    CHECK(rotated.error().find("expiry") != std::string::npos);
    CHECK(classify_engine_store_error(rotated.error()) == ClsE::ClientValidation);

    // No successor minted, no truncated window silently applied.
    auto active = store.list_active_for_principal("ivan");
    REQUIRE(active.size() == 1);
    CHECK(active[0].rotation_group.empty());
    CHECK(active[0].expires_at == now + kDay); // untouched, not truncated
}

// ── Item 5: classifier round-trip — the remaining reachable rotate_token
//    error paths not already covered (with classify checks) above ─────────

TEST_CASE("ApiTokenStore: rotate_token error classification round-trip — "
          "floor/ceiling/requesting_user/grace-elapsed (#2404 tripwire, "
          "human arm)",
          "[pg][token][rotation][human][classifier]") {
    // Each scenario's defect: a new or reworded rotate_token error message
    // that drops the keyed substring classify_engine_store_error already
    // commits to silently reclassifies to the retryable Transient default —
    // an honest client then retries a terminal client/conflict error
    // forever. This is the tripwire.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    auto now = test_now_epoch();

    // Floor: below the 24h minimum. Pure-math input validation — asserted
    // (like the engine floor test at :705) against a bogus token_id, on the
    // assumption it fires before any DB lookup of the predecessor.
    {
        auto r = store.rotate_token("deadbeefdeadbeefdeadbeef", kDay - 1, now, "admin");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("floor") != std::string::npos);
        CHECK(classify_engine_store_error(r.error()) == ClsE::ClientValidation);
    }

    // Ceiling: absurdly large overlap window (well past any sane maximum).
    {
        constexpr int64_t kAbsurdOverlap = 11LL * 365 * kDay;
        auto r = store.rotate_token("deadbeefdeadbeefdeadbeef", kAbsurdOverlap, now, "admin");
        REQUIRE_FALSE(r.has_value());
        CHECK(classify_engine_store_error(r.error()) == ClsE::ClientValidation);
    }

    // requesting_user required — a REAL token so the empty-user guard is
    // isolated from any "token not found" ambiguity.
    {
        auto t = store.create_token("Guard PAT", "judy-req", now + k90Days);
        REQUIRE(t.has_value());
        auto vt = store.validate_token(*t);
        REQUIRE(vt.has_value());
        auto r = store.rotate_token(vt->token_id, kDefaultOverlapSecs, now, "");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("required") != std::string::npos);
        CHECK(classify_engine_store_error(r.error()) == ClsE::ClientValidation);
    }

    // Grace window elapsed: a same-operator retry more than kRotationGraceSecs
    // after the successor's own mint (epoch side, no sleep needed). Mirrors
    // :887, which — beyond the rejection itself — re-reads the active set to
    // prove the rejected retry minted no THIRD credential; the rejection
    // alone is only half the property.
    {
        auto t = store.create_token("Grace PAT", "judy-grace", now + k90Days);
        REQUIRE(t.has_value());
        auto vt = store.validate_token(*t);
        REQUIRE(vt.has_value());
        auto first = store.rotate_token(vt->token_id, kDefaultOverlapSecs, now, "judy-grace");
        REQUIRE(first.has_value());
        auto lapsed = store.rotate_token(vt->token_id, kDefaultOverlapSecs, now + 300,
                                         "judy-grace");
        REQUIRE_FALSE(lapsed.has_value());
        CHECK(lapsed.error().find("grace") != std::string::npos);
        CHECK(classify_engine_store_error(lapsed.error()) == ClsE::Conflict);

        // No third credential was minted by the rejected retry (:887's other
        // half).
        CHECK(store.list_active_for_principal("judy-grace").size() == 2);
    }
}

TEST_CASE("ApiTokenStore: confirm_token_rotation error classification "
          "round-trip — input validation (#2404 tripwire, human arm)",
          "[pg][token][rotation][human][classifier]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());
    auto now = test_now_epoch();

    // Empty successor_token_id.
    {
        auto r = store.confirm_token_rotation("", "admin");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("required") != std::string::npos);
        CHECK(classify_engine_store_error(r.error()) == ClsE::ClientValidation);
    }

    // Empty requesting_user, against a real token so the outcome isn't
    // confounded with a "token not found" branch.
    {
        auto t = store.create_token("Confirm-guard PAT", "kelly", now + k90Days);
        REQUIRE(t.has_value());
        auto vt = store.validate_token(*t);
        REQUIRE(vt.has_value());
        auto r = store.confirm_token_rotation(vt->token_id, "");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().find("required") != std::string::npos);
        CHECK(classify_engine_store_error(r.error()) == ClsE::ClientValidation);
    }
}

// ── Item 6: confirm_token_rotation replay / terminal states ────────────

TEST_CASE("ApiTokenStore: confirm_token_rotation on a never-rotated solo "
          "credential is terminal, not retryable (#2404, human arm)",
          "[pg][token][rotation][human][confirm]") {
    // Defect this catches: collapsing this into the same "no in-flight
    // rotation" retryable bucket as a genuinely empty read (item 6's other
    // half, below) would tell an idempotent-hint-honouring client to retry a
    // call that can never succeed — there was never a rotation to confirm.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Solo PAT", "leo", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());

    // Confirm-side rotation-STATE wording is asserted via classifier CLASS
    // only, never verbatim (calibration rule stated in this section's header
    // comment) — this scenario is more likely to be reworded for a "rotation
    // group" model than the generic floor/ceiling/operator-binding strings.
    auto resolved = store.confirm_token_rotation(vt->token_id, "leo");
    REQUIRE_FALSE(resolved.has_value());
    CHECK(classify_engine_store_error(resolved.error()) == ClsE::Conflict);
}

TEST_CASE("ApiTokenStore: confirm_token_rotation replay after success is a "
          "terminal already-confirmed conflict, not a retryable 503 "
          "(#2404, human arm)",
          "[pg][token][rotation][human][confirm]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Replay PAT", "mia", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    auto rotated = store.rotate_token(t_id, kDefaultOverlapSecs, now, "mia");
    REQUIRE(rotated.has_value());
    auto active = store.list_active_for_principal("mia");
    std::string successor_id;
    for (const auto& tok : active)
        if (tok.supersedes_token_id == t_id)
            successor_id = tok.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // First confirm succeeds (the real cutover).
    REQUIRE(store.confirm_token_rotation(successor_id, "mia").has_value());

    // The network-dropped-200 replay: SAME args. Terminal, not 503.
    auto replay = store.confirm_token_rotation(successor_id, "mia");
    REQUIRE_FALSE(replay.has_value());
    CHECK(classify_engine_store_error(replay.error()) == ClsE::Conflict);
    CHECK(store.list_active_for_principal("mia").size() == 1); // no side effect
}

TEST_CASE("ApiTokenStore: confirm_token_rotation rejects a stale/mismatched "
          "successor id while a DIFFERENT rotation is pending (#2384 twin, "
          "human arm)",
          "[pg][token][rotation][human][confirm]") {
    // Token-keyed analog of :1501/:1556 — a blind retry (or an operator's
    // copy-paste of the wrong id) carrying an id that does not match the
    // pending successor must never mutate state.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Mismatch PAT", "nina", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string predecessor_id = vt->token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "nina");
    REQUIRE(rotated.has_value());

    std::string successor_id, rotation_group;
    for (const auto& tok : store.list_active_for_principal("nina")) {
        if (tok.supersedes_token_id == predecessor_id) {
            successor_id = tok.token_id;
            rotation_group = tok.rotation_group;
        }
    }
    REQUIRE_FALSE(successor_id.empty());

    // The PREDECESSOR's own id (the likely operator mistake) resolves to a
    // REAL row nina owns, currently in-rotation but holding the WRONG role
    // in the pair (predecessor, not successor) — this genuinely reaches the
    // pin-mismatch branch.
    auto mismatch = store.confirm_token_rotation(predecessor_id, "nina");
    REQUIRE_FALSE(mismatch.has_value());
    CHECK(mismatch.error().find("does not match the pending rotation") != std::string::npos);
    CHECK(classify_engine_store_error(mismatch.error()) == ClsE::Conflict);

    // A FABRICATED id never resolves to any row at all, so it CANNOT reach
    // the pin-mismatch branch (which requires a resolved, owned row to
    // compare a role against) — it is deliberately NOT asserted to produce
    // the pin-mismatch message here. Engine-precedent mismatch, recorded so
    // the next reader does not "fix" this back: the engine arm resolves
    // confirm by PRINCIPAL, so it can compare any supplied id against a
    // known successor without a row lookup first; the human arm is
    // TOKEN-keyed and must resolve the id to a row before it can compare
    // roles — an id that never resolves can never reach that comparison.
    // Instead, the store folds "never existed" into the SAME response as
    // "exists, but belongs to someone else" — the enumeration-resistance
    // property item 7b already establishes — so this is asserted by
    // comparing the fabricated id's result DIRECTLY against a genuinely
    // not-owned real token_id's result, not against a hardcoded
    // string/class, so it keeps holding regardless of the implementer's
    // chosen not-found wording.
    auto other_owner = store.create_token("Not nina's PAT", "mallory-2384", now + k90Days);
    REQUIRE(other_owner.has_value());
    auto vt_other = store.validate_token(*other_owner);
    REQUIRE(vt_other.has_value());

    auto fabricated = store.confirm_token_rotation("feedfacefeedfacefeedface", "nina");
    auto not_owned = store.confirm_token_rotation(vt_other->token_id, "nina");
    REQUIRE_FALSE(fabricated.has_value());
    REQUIRE_FALSE(not_owned.has_value());
    CHECK(fabricated.error() == not_owned.error());
    CHECK(classify_engine_store_error(fabricated.error()) ==
          classify_engine_store_error(not_owned.error()));

    // No mutation: both of nina's credentials active, linkage intact,
    // unconfirmed.
    auto active = store.list_active_for_principal("nina");
    REQUIRE(active.size() == 2);
    for (const auto& tok : active) {
        CHECK(tok.confirmed_at == 0);
        CHECK(tok.rotation_group == rotation_group);
    }

    // The correct id still confirms — the rejections above consumed nothing.
    CHECK(store.confirm_token_rotation(successor_id, "nina").has_value());
}

TEST_CASE("ApiTokenStore: a blind retry carrying an EARLIER rotation's "
          "successor id cannot confirm a LATER rotation on the SAME token "
          "lineage (#2384 twin, human arm)",
          "[pg][token][rotation][human][confirm]") {
    // Token-keyed analog of :1556. The id that mismatches here is not a
    // bogus/unrelated string (that's the previous test) — it is a REAL,
    // currently-active token_id that legitimately played TWO roles: R1's
    // (already-confirmed) successor, and R2's (still-pending) predecessor.
    // Defect this catches: a confirm that resolves its target row by
    // token_id and then checks ONLY "is this row part of an active,
    // in-flight pair" — without also requiring it be the PAIR'S SUCCESSOR —
    // would find r1_successor_id sitting right there as R2's live
    // predecessor and could wrongly treat the replay as legitimate,
    // confirming R2 (and revoking R2's actual, still-unconfirmed
    // predecessor) using an id the caller never associated with R2 at all.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Blind-retry PAT", "paul", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    // R1: rotate + confirm with R1's successor id (the happy flow).
    auto r1 = store.rotate_token(t_id, kDefaultOverlapSecs, now, "paul");
    REQUIRE(r1.has_value());
    std::string r1_successor_id;
    for (const auto& tok : store.list_active_for_principal("paul"))
        if (tok.supersedes_token_id == t_id)
            r1_successor_id = tok.token_id;
    REQUIRE_FALSE(r1_successor_id.empty());
    REQUIRE(store.confirm_token_rotation(r1_successor_id, "paul").has_value());

    // R2 begins: R1's successor is now R2's predecessor.
    auto r2 = store.rotate_token(r1_successor_id, kDefaultOverlapSecs, now, "paul");
    REQUIRE(r2.has_value());
    std::string r2_successor_id;
    for (const auto& tok : store.list_active_for_principal("paul"))
        if (tok.supersedes_token_id == r1_successor_id)
            r2_successor_id = tok.token_id;
    REQUIRE_FALSE(r2_successor_id.empty());
    REQUIRE(r2_successor_id != r1_successor_id);

    // THE #2384 SCENARIO, token-keyed: a blind retry of the R1 confirm (same
    // args, same operator) lands after R2 started.
    auto stale_retry = store.confirm_token_rotation(r1_successor_id, "paul");
    REQUIRE_FALSE(stale_retry.has_value());
    CHECK(stale_retry.error().find("does not match the pending rotation") != std::string::npos);
    CHECK(classify_engine_store_error(stale_retry.error()) == ClsE::Conflict);

    // R2 is untouched: r1_successor_id (R2's predecessor) is still active and
    // unrevoked; R2's own successor remains unconfirmed. NOTE: r1_successor_id
    // legitimately RETAINS its historical confirmed_at from R1 (a marker, by
    // design) — only R2's successor must be unconfirmed.
    auto active = store.list_active_for_principal("paul");
    REQUIRE(active.size() == 2);
    bool r1_successor_still_active = false;
    for (const auto& tok : active) {
        if (tok.token_id == r1_successor_id) {
            r1_successor_still_active = true;
            CHECK_FALSE(tok.revoked);
        }
        if (tok.token_id == r2_successor_id)
            CHECK(tok.confirmed_at == 0);
    }
    CHECK(r1_successor_still_active);

    // R2's own successor id confirms R2 normally.
    CHECK(store.confirm_token_rotation(r2_successor_id, "paul").has_value());
}

TEST_CASE("ApiTokenStore: a successor id from ONE token's already-resolved "
          "rotation cannot confirm a pending rotation on a DIFFERENT token "
          "owned by the same user (cross-lineage #2384 twin, human arm)",
          "[pg][token][rotation][human][confirm]") {
    // Defect this catches: group-scoped arbitration (items 1/2) means a
    // single user can have MULTIPLE lineages in flight simultaneously — a
    // shape the engine arm never has (one principal owns exactly one
    // lineage). If confirm resolves "the pending pair" by scanning the
    // PRINCIPAL's whole active set for ANY 2-row rotation pair, instead of
    // resolving the SPECIFIC group the supplied token_id itself belongs to,
    // an id from lineage A could be accepted against lineage B's unrelated
    // in-flight pair — silently confirming (and cutting over) the WRONG
    // rotation. If that happened here, `cross.has_value()` below would be
    // true and lineage B would show one confirmed/one revoked row instead of
    // two untouched, unconfirmed ones.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();

    // Lineage A: rotate + confirm, fully resolved — its former successor A2
    // is now sole and carries a historical confirmed_at, no live group.
    auto a = store.create_token("Lineage A", "quinn", now + k90Days);
    REQUIRE(a.has_value());
    auto va = store.validate_token(*a);
    REQUIRE(va.has_value());
    const std::string a1_id = va->token_id;
    auto ra = store.rotate_token(a1_id, kDefaultOverlapSecs, now, "quinn");
    REQUIRE(ra.has_value());
    std::string a2_id;
    for (const auto& tok : store.list_active_for_principal("quinn"))
        if (tok.supersedes_token_id == a1_id)
            a2_id = tok.token_id;
    REQUIRE_FALSE(a2_id.empty());
    REQUIRE(store.confirm_token_rotation(a2_id, "quinn").has_value());

    // Lineage B: a SEPARATE token for the SAME user, rotated but NOT yet
    // confirmed — a genuinely pending, unrelated pair, and (crucially) the
    // ONLY 2-row pending pair this principal currently has.
    auto b = store.create_token("Lineage B", "quinn", now + k90Days);
    REQUIRE(b.has_value());
    auto vb = store.validate_token(*b);
    REQUIRE(vb.has_value());
    const std::string b1_id = vb->token_id;
    auto rb = store.rotate_token(b1_id, kDefaultOverlapSecs, now, "quinn");
    REQUIRE(rb.has_value());
    std::string b2_id;
    for (const auto& tok : store.list_active_for_principal("quinn"))
        if (tok.supersedes_token_id == b1_id)
            b2_id = tok.token_id;
    REQUIRE_FALSE(b2_id.empty());

    // A2 (lineage A's resolved-away successor id) must NOT confirm lineage
    // B's pending pair.
    auto cross = store.confirm_token_rotation(a2_id, "quinn");
    REQUIRE_FALSE(cross.has_value());
    CHECK(classify_engine_store_error(cross.error()) == ClsE::Conflict);

    // Lineage B is completely untouched: still exactly 2 active rows in its
    // own group, unconfirmed, unrevoked.
    int b_group_active = 0;
    for (const auto& tok : store.list_active_for_principal("quinn")) {
        if (tok.token_id == b1_id || tok.token_id == b2_id) {
            ++b_group_active;
            CHECK(tok.confirmed_at == 0);
            CHECK_FALSE(tok.revoked);
        }
    }
    CHECK(b_group_active == 2);

    // B's own successor id still confirms B normally.
    CHECK(store.confirm_token_rotation(b2_id, "quinn").has_value());
}

TEST_CASE("ApiTokenStore: confirm_token_rotation on a group already resolved "
          "by REVOKE is a terminal fact even though the OWNER's overall "
          "active read is non-empty (positive read vs. genuinely empty, "
          "human arm)",
          "[pg][token][rotation][human][confirm]") {
    // The subtle half of item 6: this must NOT be confused with a genuinely
    // empty/ambiguous read. karen's active-set read is non-empty throughout
    // (the predecessor survives, plus an unrelated token) — the fact that
    // THIS SPECIFIC group has zero in-flight rows is a POSITIVE result, so
    // the rejection must be terminal, never the retryable "no in-flight
    // rotation" reserved for a read that came back with nothing at all.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Group A", "karen", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    // Unrelated token proving karen's active-set read is genuinely non-empty
    // throughout this test.
    auto b = store.create_token("Unrelated B", "karen", now + k90Days);
    REQUIRE(b.has_value());

    auto rotated = store.rotate_token(t_id, kDefaultOverlapSecs, now, "karen");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& tok : store.list_active_for_principal("karen"))
        if (tok.supersedes_token_id == t_id)
            successor_id = tok.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // Resolve the pair by REVOKING the successor directly (not confirming) —
    // the §7 manual-revoke-resolves-the-pair contract (mirrors the engine
    // tests at :1621/:1657): the predecessor `t_id` survives as karen's sole
    // credential for that lineage, rotation state cleared.
    REQUIRE(store.revoke_token(successor_id).value());
    auto after_revoke = store.get_token(t_id);
    REQUIRE(after_revoke.has_value());
    REQUIRE(after_revoke->has_value());
    CHECK((*after_revoke)->rotation_group.empty());

    // A confirm naming the now-revoked successor id must be told the
    // rotation resolved — terminal — never the retryable "no in-flight
    // rotation" (reserved below for a genuinely empty read).
    auto resolved = store.confirm_token_rotation(successor_id, "karen");
    REQUIRE_FALSE(resolved.has_value());
    CHECK(classify_engine_store_error(resolved.error()) == ClsE::Conflict);
}

TEST_CASE("ApiTokenStore: confirm_token_rotation on a revoked, "
          "never-rotated token_id is a terminal nothing-to-confirm, not "
          "retryable (#2404, human arm)",
          "[pg][token][rotation][human][confirm]") {
    // RENAMED + RECLASSIFIED post-merge review. Originally named "...on a
    // genuinely EMPTY read stays retryable..." and asserted Transient — but
    // this scenario does not reach the read-ambiguity state that name
    // describes. confirm_token_rotation resolves the PINNED row by
    // token_id FIRST; that row is FOUND here (it exists, merely revoked),
    // and its own rotation_group field is empty — a definite POSITIVE fact
    // ("this token_id was never part of any rotation"). It never touches a
    // principal-wide or group-scoped active read, so the "indistinguishable
    // from a swallowed SELECT failure" reasoning this test used to cite
    // does not apply here.
    //
    // Formally adjudicated to Conflict after this suite was first written,
    // on three grounds: #2404 already litigated the identical shape on the
    // engine arm, where a 503 made an idempotent-hint-honouring client
    // retry a permanently-failing call forever; the engine's
    // kSoleOtherToken (same "rotate again" guidance) is Conflict; and
    // rotation_confirm_state.hpp documents every terminal state as
    // Conflict or ClientValidation, never Transient. Do NOT flip this back
    // to Transient.
    //
    // The genuinely-ambiguous kAmbiguousEmpty path — where the pinned row
    // DOES have a non-empty rotation_group (so a partner read is actually
    // attempted) and that group-scoped read itself comes back empty,
    // indistinguishable from a swallowed SELECT failure — is a DIFFERENT,
    // narrower state this test does not exercise. It was not added here:
    // constructing it needs knowledge of which specific query the
    // group-scoped partner read runs (to sabotage that query alone while
    // leaving the single-row pin lookup intact), and that implementation
    // detail is not visible from this worktree (the merged implementation
    // lives outside it). Reachability and worth are open questions for
    // whoever holds the merged source, not answered here.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Doomed PAT", "oscar", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    REQUIRE(store.revoke_token(t_id).value());
    REQUIRE(store.list_active_for_principal("oscar").empty());

    auto none = store.confirm_token_rotation(t_id, "oscar");
    REQUIRE_FALSE(none.has_value());
    CHECK(classify_engine_store_error(none.error()) == ClsE::Conflict);
}

TEST_CASE("ApiTokenStore: confirm_token_rotation on a sole credential with "
          "stale rotation linkage is terminal and does NOT mutate — token-"
          "keyed twin of :1389 (#2404 F1, human arm)",
          "[pg][token][rotation][human][confirm]") {
    // Token-keyed twin of :1389. Manufactures the F1 defect state: revoke
    // the predecessor by DIRECT SQL, bypassing the store's own
    // resolve_rotation_pair_after_revoke, so the surviving successor keeps
    // its (now stale) rotation_group/supersedes linkage — the durable state
    // a best-effort pair-resolve failure leaves. Defect this catches: a
    // confirm that trusts a non-empty rotation_group as proof of a LIVE,
    // recognizable pair (without checking the partner it names still
    // exists) would either wrongly report a normal in-flight rotation, or
    // — far worse — silently accept and mutate from a state where rotating
    // would strand a malformed pair, exactly what the F1 remediation
    // guidance ("do not rotate") exists to prevent. Prose-level wording
    // ("do not rotate" vs "rotate again") is confirm-side rotation-state
    // text and is deliberately NOT hard-pinned here per this section's
    // calibration rule — only the terminal CLASS and the no-mutation
    // invariant are asserted, both of which are structurally verifiable
    // regardless of the implementer's chosen wording.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Stale-linkage PAT", "uma", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string predecessor_id = vt->token_id;

    auto rotated = store.rotate_token(predecessor_id, kDefaultOverlapSecs, now, "uma");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& tok : store.list_active_for_principal("uma"))
        if (tok.supersedes_token_id == predecessor_id)
            successor_id = tok.token_id;
    REQUIRE_FALSE(successor_id.empty());

    // Revoke the predecessor by RAW SQL, bypassing revoke_token's own
    // pair-resolve helper — the successor's rotation_group/supersedes
    // linkage survives, now stale.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        const std::string sql =
            "UPDATE api_token_store.api_tokens SET revoked = TRUE WHERE token_id = '" +
            predecessor_id + "';";
        PgResult res{PQexec(conn.get(), sql.c_str())};
        REQUIRE(res.ok());
    }
    auto active = store.list_active_for_principal("uma");
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == successor_id);
    CHECK_FALSE(active[0].rotation_group.empty()); // stale linkage survived

    auto stale = store.confirm_token_rotation(successor_id, "uma");
    REQUIRE_FALSE(stale.has_value());
    CHECK(classify_engine_store_error(stale.error()) == ClsE::Conflict);

    // No mutation: the successor's stale linkage is untouched, not silently
    // "cleaned up" or cut over by the rejected confirm.
    auto after = store.list_active_for_principal("uma");
    REQUIRE(after.size() == 1);
    CHECK(after[0].token_id == successor_id);
    CHECK(after[0].confirmed_at == 0);
    CHECK_FALSE(after[0].rotation_group.empty());
}

TEST_CASE("ApiTokenStore: a credential's historical confirmed_at survives a "
          "LATER rotation and is never reset or transferred to a "
          "differently-resolved successor — token-keyed twin of :1445 "
          "(#2404 F2, human arm)",
          "[pg][token][rotation][human][confirm]") {
    // Token-keyed twin of :1445, asserted on the STORE'S DATA rather than
    // confirm's error prose (this section's calibration rule: confirm-side
    // rotation-state WORDING is classify()-only; the field itself is not
    // wording, so it is asserted directly and can still fail on its own
    // terms). Defect this catches: an implementation that clears or
    // reassigns confirmed_at when a LATER rotation on the same lineage
    // resolves (whether by confirm or by revoke) would destroy the
    // historical "this credential's own rotation WAS confirmed" marker —
    // exactly the misattribution #2404 F2 exists to prevent, just observed
    // on the row instead of in the message.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Historical-marker PAT", "vince", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());

    // R1: rotate + confirm. S1 becomes the sole active credential, confirmed.
    auto r1 = store.rotate_token(vt->token_id, kDefaultOverlapSecs, now, "vince");
    REQUIRE(r1.has_value());
    std::string s1_id;
    for (const auto& tok : store.list_active_for_principal("vince"))
        if (!tok.supersedes_token_id.empty())
            s1_id = tok.token_id;
    REQUIRE_FALSE(s1_id.empty());
    REQUIRE(store.confirm_token_rotation(s1_id, "vince").has_value());
    auto s1_after_r1 = store.get_token(s1_id);
    REQUIRE(s1_after_r1.has_value());
    REQUIRE(s1_after_r1->has_value());
    const int64_t s1_confirmed_at = (*s1_after_r1)->confirmed_at;
    REQUIRE(s1_confirmed_at > 0); // S1 carries R1's marker

    // R2: rotate again — S1 is now R2's predecessor and must KEEP its
    // confirmed_at. Then resolve R2 by REVOKING its successor (not
    // confirming), so the pair resolves back to S1 alone.
    auto r2 = store.rotate_token(s1_id, kDefaultOverlapSecs, now, "vince");
    REQUIRE(r2.has_value());
    std::string s2_id;
    for (const auto& tok : store.list_active_for_principal("vince"))
        if (tok.supersedes_token_id == s1_id)
            s2_id = tok.token_id;
    REQUIRE_FALSE(s2_id.empty());
    REQUIRE(store.revoke_token(s2_id).value()); // resolves the pair -> S1 sole, clear

    auto active = store.list_active_for_principal("vince");
    REQUIRE(active.size() == 1);
    CHECK(active[0].token_id == s1_id);

    // THE assertion: S1's confirmed_at is EXACTLY what it was after R1's
    // confirm — untouched by R2 starting, and untouched by R2 being
    // resolved via revoke rather than confirm.
    CHECK(active[0].confirmed_at == s1_confirmed_at);

    // S2 (R2's successor, resolved by revoke, never confirmed) must NOT
    // have been stamped with any confirmed_at of its own.
    auto s2_final = store.get_token(s2_id);
    REQUIRE(s2_final.has_value());
    REQUIRE(s2_final->has_value());
    CHECK((*s2_final)->confirmed_at == 0);
    CHECK((*s2_final)->revoked);
}

// ── Item 7: strictly self-service — requesting_user IS the owner ─────────

TEST_CASE("ApiTokenStore: rotate_token is strictly self-service — a second "
          "session for the SAME owner re-serves identically, a DIFFERENT "
          "user is rejected even before any rotation is in flight",
          "[pg][token][rotation][human]") {
    // Defect this catches: the engine arm's requesting_user binding (F4)
    // only fires on the RE-SERVE arm (2-active, grace window) — the
    // 1-active MINT path accepts ANY requesting_user, because an engine
    // credential is rotated by an admin operator ACTING ON BEHALF OF the
    // engine principal, not by the principal itself. A human PAT has no such
    // delegate: requesting_user must equal the token's own principal_id on
    // EVERY call, including the very first mint, or any authenticated user
    // could rotate any other user's token the moment they knew its
    // token_id — an authorization bypass with no analog in the engine arm.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Alice's PAT", "alice-owner", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;

    // A DIFFERENT user, before any rotation is in flight, is rejected.
    auto stolen = store.rotate_token(t_id, kDefaultOverlapSecs, now, "mallory");
    REQUIRE_FALSE(stolen.has_value());
    auto after_stolen = store.list_active_for_principal("alice-owner");
    REQUIRE(after_stolen.size() == 1);
    CHECK(after_stolen[0].rotation_group.empty()); // no successor minted

    // The genuine owner — a "second session", i.e. a fresh call carrying the
    // SAME identity — succeeds normally.
    auto real = store.rotate_token(t_id, kDefaultOverlapSecs, now, "alice-owner");
    REQUIRE(real.has_value());

    // And a further same-owner call re-serves idempotently (second session,
    // still within grace) rather than erroring or minting a third row.
    auto second_session = store.rotate_token(t_id, kDefaultOverlapSecs, now, "alice-owner");
    REQUIRE(second_session.has_value());
    CHECK(*second_session == *real);
}

TEST_CASE("ApiTokenStore: confirm_token_rotation is strictly self-service — "
          "a DIFFERENT user may not confirm someone else's in-flight "
          "rotation, but the owner's own second session can",
          "[pg][token][rotation][human]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto t = store.create_token("Bob's PAT", "bob-owner", now + k90Days);
    REQUIRE(t.has_value());
    auto vt = store.validate_token(*t);
    REQUIRE(vt.has_value());
    const std::string t_id = vt->token_id;
    auto rotated = store.rotate_token(t_id, kDefaultOverlapSecs, now, "bob-owner");
    REQUIRE(rotated.has_value());

    std::string successor_id;
    for (const auto& tok : store.list_active_for_principal("bob-owner"))
        if (tok.supersedes_token_id == t_id)
            successor_id = tok.token_id;
    REQUIRE_FALSE(successor_id.empty());

    auto stolen_confirm = store.confirm_token_rotation(successor_id, "mallory");
    REQUIRE_FALSE(stolen_confirm.has_value());
    for (const auto& tok : store.list_active_for_principal("bob-owner"))
        CHECK(tok.confirmed_at == 0); // both credentials unchanged

    // The owner's own confirm (a fresh call — "second session") still works.
    CHECK(store.confirm_token_rotation(successor_id, "bob-owner").has_value());
}

// ── Item 7b: absence of a token_id enumeration oracle ──────────────────
//
// The design fact the two self-service tests above do NOT prove: a wrong-owner
// call must be rejected INDISTINGUISHABLY from a genuinely nonexistent
// token_id. Both tests above only ever exercise wrong-owner against a real,
// existing token — an implementation that returns a distinguishable error
// (different string, or a different classifier class) for "no such token_id"
// versus "that token_id exists but isn't yours" would let any authenticated
// caller binary-search token_id space to learn which ids correspond to real,
// live credentials belonging to OTHER users — an IDOR-adjacent enumeration
// oracle. This is the exact property `DELETE /api/v1/tokens/{id}`
// (rest_api_v1.cpp:2619-2641) already enforces: missing-id and not-owner both
// return a byte-identical 404 body precisely so the endpoint can't be probed
// this way. The assertions below compare the two returned messages TO EACH
// OTHER, not to a hardcoded literal, so the test keeps holding regardless of
// which wording the implementer picks.

TEST_CASE("ApiTokenStore: rotate_token rejects a nonexistent token_id "
          "identically to another user's real, active token_id — no "
          "enumeration oracle",
          "[pg][token][rotation][human][enumeration]") {
    // Defect this catches: if rotate_token resolves the row by id FIRST (to
    // report a distinct "not found") and only THEN checks ownership (to
    // report a distinct "not yours"), an attacker who doesn't own ANY
    // tokens can still learn — one guess at a time, from the error alone —
    // which token_ids belong to real, active credentials of other users.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto owned = store.create_token("Rachel's PAT", "rachel-target", now + k90Days);
    REQUIRE(owned.has_value());
    auto vt = store.validate_token(*owned);
    REQUIRE(vt.has_value());
    const std::string real_other_users_id = vt->token_id;

    auto against_nonexistent =
        store.rotate_token("0000000000000000deadbeef", kDefaultOverlapSecs, now, "attacker");
    auto against_real_other =
        store.rotate_token(real_other_users_id, kDefaultOverlapSecs, now, "attacker");

    REQUIRE_FALSE(against_nonexistent.has_value());
    REQUIRE_FALSE(against_real_other.has_value());
    CHECK(against_nonexistent.error() == against_real_other.error());
    CHECK(classify_engine_store_error(against_nonexistent.error()) ==
          classify_engine_store_error(against_real_other.error()));

    // Neither call touched rachel's token.
    auto after = store.list_active_for_principal("rachel-target");
    REQUIRE(after.size() == 1);
    CHECK(after[0].rotation_group.empty());
}

TEST_CASE("ApiTokenStore: rotate_token rejects a nonexistent token_id "
          "identically to another user's REVOKED token_id — the "
          "timing-independent sibling",
          "[pg][token][rotation][human][enumeration]") {
    // Defect this catches: a row that EXISTS but is revoked is a different
    // internal state than "no row at all" — an implementation that finds
    // the (revoked) row and reports something like "token revoked" or
    // "no active credential" distinct from a bare "not found" would let an
    // attacker distinguish "never existed" from "existed once, now dead"
    // for another user's token_id, which is still an enumeration oracle
    // (and, unlike the active-token case above, is NOT timing-equivalent to
    // a wrong-owner-of-a-live-token rejection, so it needs its own case).
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto owned = store.create_token("Sam's dead PAT", "sam-target", now + k90Days);
    REQUIRE(owned.has_value());
    auto vt = store.validate_token(*owned);
    REQUIRE(vt.has_value());
    const std::string revoked_id = vt->token_id;
    REQUIRE(store.revoke_token(revoked_id).value());

    auto against_nonexistent =
        store.rotate_token("1111111111111111deadbeef", kDefaultOverlapSecs, now, "attacker");
    auto against_revoked =
        store.rotate_token(revoked_id, kDefaultOverlapSecs, now, "attacker");

    REQUIRE_FALSE(against_nonexistent.has_value());
    REQUIRE_FALSE(against_revoked.has_value());
    CHECK(against_nonexistent.error() == against_revoked.error());
    CHECK(classify_engine_store_error(against_nonexistent.error()) ==
          classify_engine_store_error(against_revoked.error()));
}

TEST_CASE("ApiTokenStore: confirm_token_rotation rejects a nonexistent "
          "successor_token_id identically to another user's real, "
          "PENDING successor_token_id — no enumeration oracle",
          "[pg][token][rotation][human][enumeration]") {
    // Defect this catches: same property as the rotate_token case above, on
    // the confirm path — an attacker who can distinguish "no such
    // successor_token_id" from "that id is a real, pending rotation
    // successor, but not yours to confirm" learns which token_ids
    // correspond to LIVE, in-flight rotations belonging to other users
    // (worse than the rotate case: it also confirms a rotation is
    // in-progress right now for that user).
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto owned = store.create_token("Sam's PAT", "sam-pending", now + k90Days);
    REQUIRE(owned.has_value());
    auto vt = store.validate_token(*owned);
    REQUIRE(vt.has_value());
    const std::string sam_predecessor_id = vt->token_id;
    auto rotated = store.rotate_token(sam_predecessor_id, kDefaultOverlapSecs, now, "sam-pending");
    REQUIRE(rotated.has_value());
    std::string sam_successor_id;
    for (const auto& tok : store.list_active_for_principal("sam-pending"))
        if (tok.supersedes_token_id == sam_predecessor_id)
            sam_successor_id = tok.token_id;
    REQUIRE_FALSE(sam_successor_id.empty());

    auto against_nonexistent = store.confirm_token_rotation("2222222222222222deadbeef", "attacker");
    auto against_real_pending = store.confirm_token_rotation(sam_successor_id, "attacker");

    REQUIRE_FALSE(against_nonexistent.has_value());
    REQUIRE_FALSE(against_real_pending.has_value());
    CHECK(against_nonexistent.error() == against_real_pending.error());
    CHECK(classify_engine_store_error(against_nonexistent.error()) ==
          classify_engine_store_error(against_real_pending.error()));

    // Sam's pending pair is completely untouched.
    auto after = store.list_active_for_principal("sam-pending");
    REQUIRE(after.size() == 2);
    for (const auto& tok : after)
        CHECK(tok.confirmed_at == 0);
}

TEST_CASE("ApiTokenStore: confirm_token_rotation rejects a nonexistent "
          "successor_token_id identically to another user's REVOKED "
          "(cut-over) predecessor token_id — the timing-independent sibling",
          "[pg][token][rotation][human][enumeration]") {
    // Defect this catches: the confirm path's own revoked-row shape — a
    // predecessor that WAS revoked by a completed confirm is a different
    // internal state than "id never existed", and (per the rotate-side
    // sibling above) needs its own case rather than assuming the
    // active-pending comparison covers it.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto owned = store.create_token("Tara's PAT", "tara-resolved", now + k90Days);
    REQUIRE(owned.has_value());
    auto vt = store.validate_token(*owned);
    REQUIRE(vt.has_value());
    const std::string tara_predecessor_id = vt->token_id;
    auto rotated =
        store.rotate_token(tara_predecessor_id, kDefaultOverlapSecs, now, "tara-resolved");
    REQUIRE(rotated.has_value());
    std::string tara_successor_id;
    for (const auto& tok : store.list_active_for_principal("tara-resolved"))
        if (tok.supersedes_token_id == tara_predecessor_id)
            tara_successor_id = tok.token_id;
    REQUIRE_FALSE(tara_successor_id.empty());
    // The confirm revokes the predecessor.
    REQUIRE(store.confirm_token_rotation(tara_successor_id, "tara-resolved").has_value());

    auto against_nonexistent = store.confirm_token_rotation("3333333333333333deadbeef", "attacker");
    auto against_revoked_predecessor =
        store.confirm_token_rotation(tara_predecessor_id, "attacker");

    REQUIRE_FALSE(against_nonexistent.has_value());
    REQUIRE_FALSE(against_revoked_predecessor.has_value());
    CHECK(against_nonexistent.error() == against_revoked_predecessor.error());
    CHECK(classify_engine_store_error(against_nonexistent.error()) ==
          classify_engine_store_error(against_revoked_predecessor.error()));
}

// ── Item 8: cache cutover on confirm ────────────────────────────────────

TEST_CASE("ApiTokenStore: confirm_token_rotation cuts the revoked "
          "predecessor over IMMEDIATELY — it must not keep validating from "
          "the 60s token cache (double revoke_generation_ bump, human arm)",
          "[pg][token][rotation][human]") {
    // Defect this catches: if confirm_token_rotation forgets the SECOND
    // revoke_generation_ bump (or the invalidate_cache(revoked_hash) call)
    // that confirm_rotation's own doc comment (#2188) requires for exactly
    // this reason, a validate_token call racing the commit could repopulate
    // the in-memory cache with the now-stale predecessor row AFTER the
    // invalidation ran, letting a revoked credential authenticate for up to
    // kTokenCacheTtl (60s) past an explicit operator-confirmed cutover —
    // exactly the immediate-cutover guarantee confirm exists to provide.
    // Reachable and asserted purely through the public API — no internals
    // touched.
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::apitoken_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ApiTokenStore store{pool};
    REQUIRE(store.is_open());

    auto now = test_now_epoch();
    auto predecessor_raw = store.create_token("Cached PAT", "judy-cache", now + k90Days);
    REQUIRE(predecessor_raw.has_value());

    // Populate the 60s validate_token cache for the predecessor BEFORE
    // rotating — this is the entry that must not survive the confirm.
    auto pre_cache = store.validate_token(*predecessor_raw);
    REQUIRE(pre_cache.has_value());
    const std::string t_id = pre_cache->token_id;

    auto rotated = store.rotate_token(t_id, kDefaultOverlapSecs, now, "judy-cache");
    REQUIRE(rotated.has_value());
    std::string successor_id;
    for (const auto& tok : store.list_active_for_principal("judy-cache"))
        if (tok.supersedes_token_id == t_id)
            successor_id = tok.token_id;
    REQUIRE_FALSE(successor_id.empty());

    REQUIRE(store.confirm_token_rotation(successor_id, "judy-cache").has_value());

    // The predecessor's raw token must be rejected NOW, not up to 60s from
    // now — proving the cache entry populated above was actually evicted,
    // not merely left to expire on its own TTL.
    auto post = store.validate_token(*predecessor_raw);
    CHECK_FALSE(post.has_value());
}
