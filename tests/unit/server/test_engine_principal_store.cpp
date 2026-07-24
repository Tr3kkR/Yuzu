// EnginePrincipalStore tests (PR 4.2 gate task, T1) — the reserved-namespace +
// classification validation on create(), the create→get round-trip, terminal
// soft-retained revoke, transfer_owner, and — the central deliverable — the
// three-state `get_for_auth` contract (Active / MissingOrRevoked /
// StoreUnreachable) per docs/auth-engine-principals-design.md §3.1/§12
// decision 1. Born-on-Postgres store, schema `engine_principal_store`.
// PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails when it is set
// but broken (test_helpers.hpp skip-vs-fail contract). The StoreUnreachable
// case needs no live database (an invalid pool never connects) and is not
// PG-gated, mirroring test_pg_pool.cpp's "PgPool failed construction".

#include "engine_principal_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <atomic>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::EngineLookup;
using yuzu::server::EngineLookupStatus;
using yuzu::server::EnginePrincipalRow;
using yuzu::server::EngineLivenessTestAccess;
using yuzu::server::EnginePrincipalStore;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp).
yuzu::test::PgTestTemplate engine_principal_tpl{
    "engineprincipal", [](const std::string& dsn) {
        PgPool pool{{.conninfo = dsn, .size = 1}};
        EnginePrincipalStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("engine_principal template: store failed to migrate");
    }};

} // namespace

// ── Construction fail-closed ──────────────────────────────────────────────

// ADR-0012 §1: construction is fail-CLOSED — a reachable database whose
// schema can't migrate leaves the store !is_open(), which server.cpp wires
// to startup_failed_ (refuse to start, not serve-degraded). Force the
// failure by pre-seeding the store's schema with a conflicting table and no
// schema_meta row: the migration runner's drift guard refuses. Mirrors
// test_preflight_run_store.cpp / test_api_token_store.cpp's equivalent test.
TEST_CASE("EnginePrincipalStore reports !is_open on a migration failure",
          "[pg][engine_principal][store]") {
    YUZU_REQUIRE_PG_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA engine_principal_store")};
        REQUIRE(s.ok());
        PgResult t{
            PQexec(conn.get(), "CREATE TABLE engine_principal_store.engine_principals (bogus int)")};
        REQUIRE(t.ok());
    }
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    EnginePrincipalStore store{pool};
    CHECK_FALSE(store.is_open()); // → server.cpp sets startup_failed_ (fail-closed)
}

// ── construction + is_open (happy path) ───────────────────────────────────

TEST_CASE("EnginePrincipalStore constructs, migrates, and opens", "[pg][engine_principal][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    EnginePrincipalStore store{pool};
    CHECK(store.is_open());
}

// ── create() validation ───────────────────────────────────────────────────

TEST_CASE("EnginePrincipalStore::create rejects invalid classification and namespace",
          "[pg][engine_principal][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE(store.is_open());

    SECTION("empty classification is rejected") {
        auto r = store.create("Vuln Sync", "alice", "cloud IAM parity", /*classification=*/"",
                              "admin", "engine:vuln");
        REQUIRE_FALSE(r.has_value());
        auto fetched = store.get("engine:vuln");
        REQUIRE(fetched.has_value());
        CHECK_FALSE(fetched->has_value());
    }

    SECTION("garbage classification is rejected") {
        auto r = store.create("Vuln Sync", "alice", "cloud IAM parity", "nonsense", "admin",
                              "engine:vuln");
        REQUIRE_FALSE(r.has_value());
        auto fetched = store.get("engine:vuln");
        REQUIRE(fetched.has_value());
        CHECK_FALSE(fetched->has_value());
    }

    SECTION("principal_id missing the engine: prefix is rejected") {
        auto r = store.create("Vuln Sync", "alice", "cloud IAM parity", "internal", "admin",
                              "not-engine-prefixed");
        REQUIRE_FALSE(r.has_value());
    }

    SECTION("principal_id with an empty slug is rejected") {
        auto r = store.create("Vuln Sync", "alice", "cloud IAM parity", "internal", "admin",
                              "engine:");
        REQUIRE_FALSE(r.has_value());
    }

    SECTION("valid internal/external classifications are accepted") {
        auto internal_r = store.create("Vuln Sync", "alice", "cloud IAM parity", "internal",
                                       "admin", "engine:vuln");
        REQUIRE(internal_r.has_value());
        auto external_r = store.create("Vendor Sync", "bob", "third-party feed", "external",
                                       "admin", "engine:vendor");
        REQUIRE(external_r.has_value());
    }

    // G7 (governance hardening, compliance MEDIUM): justification mirrors the
    // classification requirement — the access-review evidence field must be
    // captured at creation.
    SECTION("empty owner_username is rejected") {
        auto r = store.create("Vuln Sync", "", "cloud IAM parity", "internal", "admin",
                              "engine:no-owner");
        REQUIRE_FALSE(r.has_value());
        auto fetched = store.get("engine:no-owner");
        REQUIRE(fetched.has_value());
        CHECK_FALSE(fetched->has_value());
    }

    SECTION("empty justification is rejected") {
        auto r = store.create("Vuln Sync", "alice", /*justification=*/"", "internal", "admin",
                              "engine:no-justification");
        REQUIRE_FALSE(r.has_value());
        auto fetched = store.get("engine:no-justification");
        REQUIRE(fetched.has_value());
        CHECK_FALSE(fetched->has_value());
    }

    // G4 (governance hardening, UP-4): the slug (part after "engine:") is
    // restricted to a conservative identifier charset, closing an
    // injection/XSS-shaped principal_id from ever being stored.
    SECTION("a slug outside the allowed charset is rejected") {
        auto r = store.create("Vuln Sync", "alice", "cloud IAM parity", "internal", "admin",
                              "engine:<script>alert(1)</script>");
        REQUIRE_FALSE(r.has_value());
    }

    SECTION("a slug with uppercase letters is rejected") {
        auto r = store.create("Vuln Sync", "alice", "cloud IAM parity", "internal", "admin",
                              "engine:VulnSync");
        REQUIRE_FALSE(r.has_value());
    }

    SECTION("a slug with spaces is rejected") {
        auto r = store.create("Vuln Sync", "alice", "cloud IAM parity", "internal", "admin",
                              "engine:vuln sync");
        REQUIRE_FALSE(r.has_value());
    }

    SECTION("a slug using only the allowed charset (lowercase, digits, '.', '_', '-') is accepted") {
        auto r = store.create("Vuln Sync", "alice", "cloud IAM parity", "internal", "admin",
                              "engine:vuln-sync.v2_1");
        REQUIRE(r.has_value());
    }
}

// ── create() duplicate principal_id ────────────────────────────────────────

TEST_CASE("EnginePrincipalStore::create rejects a duplicate principal_id (PK conflict)",
          "[pg][engine_principal][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create("Vuln Sync", "alice", "cloud IAM parity", "internal", "admin",
                         "engine:dup")
               .has_value());

    // Same principal_id, even with otherwise-different fields — the PK
    // constraint (and the store's INSERT, no ON CONFLICT clause) must reject
    // the second create rather than silently overwriting the first.
    auto second = store.create("Different Name", "bob", "different reason", "external", "admin",
                               "engine:dup");
    REQUIRE_FALSE(second.has_value());

    // The original row is untouched.
    auto row = store.get("engine:dup");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->display_name == "Vuln Sync");
    CHECK((*row)->owner_username == "alice");
    CHECK((*row)->classification == "internal");
}

// ── create → get round-trip ────────────────────────────────────────────────

TEST_CASE("EnginePrincipalStore::create → get round-trips every field",
          "[pg][engine_principal][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE(store.is_open());

    auto created = store.create("Vuln Sync", "alice", "cloud IAM parity norm", "internal",
                                "admin", "engine:vuln-rt");
    REQUIRE(created.has_value());
    CHECK(created->principal_id == "engine:vuln-rt");
    CHECK(created->display_name == "Vuln Sync");
    CHECK(created->owner_username == "alice");
    CHECK(created->justification == "cloud IAM parity norm");
    CHECK(created->classification == "internal");
    CHECK(created->lifecycle_state == "active");
    CHECK(created->superseded_by.empty());
    CHECK(created->created_by == "admin");
    CHECK(created->created_at > 0);
    CHECK(created->revoked_at == 0);

    auto fetched = store.get("engine:vuln-rt");
    REQUIRE(fetched.has_value());
    REQUIRE(fetched->has_value());
    CHECK((*fetched)->principal_id == created->principal_id);
    CHECK((*fetched)->display_name == created->display_name);
    CHECK((*fetched)->owner_username == created->owner_username);
    CHECK((*fetched)->justification == created->justification);
    CHECK((*fetched)->classification == created->classification);
    CHECK((*fetched)->lifecycle_state == created->lifecycle_state);
    CHECK((*fetched)->superseded_by == created->superseded_by);
    CHECK((*fetched)->created_at == created->created_at);
    CHECK((*fetched)->revoked_at == created->revoked_at);
    CHECK((*fetched)->created_by == created->created_by);
}

// ── revoke: terminal + soft-retained ───────────────────────────────────────

TEST_CASE("EnginePrincipalStore::revoke is terminal and soft-retained",
          "[pg][engine_principal][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create("Vuln Sync", "alice", "j", "internal", "admin", "engine:revoke-me")
               .has_value());

    SECTION("revoke succeeds once, records superseded_by, row survives (soft-retain)") {
        auto revoked = store.revoke("engine:revoke-me", "engine:revoke-me-v2");
        REQUIRE(revoked.has_value());
        CHECK(*revoked);
        auto row = store.get("engine:revoke-me"); // never hard-deleted
        REQUIRE(row.has_value());
        REQUIRE(row->has_value());
        CHECK((*row)->lifecycle_state == "revoked");
        CHECK((*row)->superseded_by == "engine:revoke-me-v2");
        CHECK((*row)->revoked_at > 0);
    }

    SECTION("revoke is terminal — a second revoke is a no-op, not a re-revoke") {
        auto first = store.revoke("engine:revoke-me");
        REQUIRE(first.has_value());
        CHECK(*first);
        auto second = store.revoke("engine:revoke-me");
        REQUIRE(second.has_value()); // DB write ran fine — already revoked, not an error
        CHECK_FALSE(*second);
    }

    SECTION("revoking an unknown principal returns false (no-op), not a failure") {
        auto revoked = store.revoke("engine:does-not-exist");
        REQUIRE(revoked.has_value());
        CHECK_FALSE(*revoked);
    }
}

// ── revoke/get/transfer_owner: infrastructure-failure state ────────────────
//
// The finding this task fixes: get/revoke/transfer_owner previously collapsed
// a genuine store/lease/query FAILURE into the same result as legitimate
// not-found / no-op. Proving a real lease/query failure (e.g. a live
// connection dropped mid-query) is impractical in this harness — the closed
// (!is_open()) arm below is the practical equivalent: it exercises the exact
// same early-return guard the lease/query failure paths share
// (`std::unexpected("database not open")`), and is the same substitution
// test_engine_principal_store.cpp's own StoreUnreachable get_for_auth section
// uses. The lease-acquire-timeout and query-error arms inside get/revoke/
// transfer_owner are structurally identical to get_for_auth's (same
// try_acquire_for + res.status() != PGRES_TUPLES_OK checks, reviewed
// line-by-line against get_for_auth's already-tested equivalents) and are
// noted here as review-by-code rather than re-proven with a live-connection
// fault injection this harness cannot express.
TEST_CASE("EnginePrincipalStore::get/revoke/transfer_owner return unexpected (not "
          "not-found/no-op) when the store is not open",
          "[pg][engine_principal][store]") {
    // No live DB needed — a malformed conninfo means PgPool::valid() is false
    // and acquire() never attempts a connection, mirroring the
    // get_for_auth StoreUnreachable section above.
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE_FALSE(store.is_open());

    SECTION("get returns unexpected, not nullopt") {
        auto r = store.get("engine:whatever");
        CHECK_FALSE(r.has_value());
        CHECK_FALSE(r.error().empty());
    }

    SECTION("revoke returns unexpected, not false") {
        auto r = store.revoke("engine:whatever");
        CHECK_FALSE(r.has_value());
        CHECK_FALSE(r.error().empty());
    }

    SECTION("transfer_owner returns unexpected, not false") {
        auto r = store.transfer_owner("engine:whatever", "bob");
        CHECK_FALSE(r.has_value());
        CHECK_FALSE(r.error().empty());
    }
}

// ── transfer_owner ──────────────────────────────────────────────────────────

TEST_CASE("EnginePrincipalStore::transfer_owner reassigns ownership of an active principal",
          "[pg][engine_principal][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create("Vuln Sync", "alice", "j", "internal", "admin", "engine:xfer")
               .has_value());

    SECTION("transfer succeeds and round-trips the new owner") {
        auto transferred = store.transfer_owner("engine:xfer", "bob");
        REQUIRE(transferred.has_value());
        CHECK(*transferred);
        auto row = store.get("engine:xfer");
        REQUIRE(row.has_value());
        REQUIRE(row->has_value());
        CHECK((*row)->owner_username == "bob");
    }

    SECTION("transfer on a revoked principal is a no-op — not an active row") {
        auto revoked = store.revoke("engine:xfer");
        REQUIRE(revoked.has_value());
        CHECK(*revoked);
        auto transferred = store.transfer_owner("engine:xfer", "bob");
        REQUIRE(transferred.has_value());
        CHECK_FALSE(*transferred);
    }

    SECTION("transfer on an unknown principal is a no-op, not a failure") {
        auto transferred = store.transfer_owner("engine:does-not-exist", "bob");
        REQUIRE(transferred.has_value());
        CHECK_FALSE(*transferred);
    }
}

// ── the central deliverable: three-state get_for_auth ─────────────────────

TEST_CASE("EnginePrincipalStore::get_for_auth — Active vs MissingOrRevoked vs StoreUnreachable "
          "are observably distinct",
          "[pg][engine_principal][store]") {
    SECTION("Active: a live row") {
        YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        REQUIRE(pool.valid());
        EnginePrincipalStore store{pool};
        REQUIRE(store.is_open());
        REQUIRE(store.create("Vuln Sync", "alice", "j", "internal", "admin", "engine:auth-active")
                   .has_value());

        EngineLookup lookup = store.get_for_auth("engine:auth-active");
        CHECK(lookup.status == EngineLookupStatus::Active);
        REQUIRE(lookup.row.has_value());
        CHECK(lookup.row->principal_id == "engine:auth-active");
    }

    SECTION("MissingOrRevoked: absent id") {
        YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        REQUIRE(pool.valid());
        EnginePrincipalStore store{pool};
        REQUIRE(store.is_open());

        EngineLookup lookup = store.get_for_auth("engine:never-existed");
        CHECK(lookup.status == EngineLookupStatus::MissingOrRevoked);
        CHECK_FALSE(lookup.row.has_value()); // row set iff status == Active
    }

    SECTION("MissingOrRevoked: a revoked row") {
        YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        REQUIRE(pool.valid());
        EnginePrincipalStore store{pool};
        REQUIRE(store.is_open());
        REQUIRE(store.create("Vuln Sync", "alice", "j", "internal", "admin", "engine:auth-revoked")
                   .has_value());
        auto revoked = store.revoke("engine:auth-revoked");
        REQUIRE(revoked.has_value());
        REQUIRE(*revoked);

        EngineLookup lookup = store.get_for_auth("engine:auth-revoked");
        CHECK(lookup.status == EngineLookupStatus::MissingOrRevoked);
        CHECK_FALSE(lookup.row.has_value());
    }

    SECTION("StoreUnreachable: the store never opened (invalid pool — no live DB needed, "
            "mirrors test_pg_pool.cpp's failed-construction case)") {
        // Malformed conninfo: PgPool::valid() is false and acquire() never
        // attempts a connection, so this section needs no YUZU_REQUIRE_PG_DB
        // gate — it exercises the !open_ branch of get_for_auth directly.
        PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
        REQUIRE_FALSE(pool.valid());
        EnginePrincipalStore store{pool};
        REQUIRE_FALSE(store.is_open());

        EngineLookup lookup = store.get_for_auth("engine:whatever");
        CHECK(lookup.status == EngineLookupStatus::StoreUnreachable);
        CHECK_FALSE(lookup.row.has_value());
    }
}

// ── get_for_auth_revalidate: the #2367 liveness cache ──────────────────────

TEST_CASE("get_for_auth_revalidate caches Active while get_for_auth stays uncached",
          "[pg][engine_principal][store][cache]") {
    YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.create("Vuln Sync", "alice", "j", "internal", "admin", "engine:cache-warm")
               .has_value());

    // First revalidate reads through (miss) and installs the entry. A
    // read-through is authoritative, so from_cache is false.
    {
        const auto first = EngineLivenessTestAccess::revalidate(store, "engine:cache-warm");
        CHECK(first.status == EngineLookupStatus::Active);
        CHECK_FALSE(first.from_cache);
    }
    CHECK(store.revalidate_cache_misses() == 1);
    CHECK(store.revalidate_cache_hits() == 0);
    CHECK(store.revalidate_cache_size() == 1);

    // Subsequent ticks are served from cache — this is the whole point: N
    // streams x per-tick revalidation stops being N Postgres reads per tick.
    // Each hit must announce itself as cached, or the pump would reset its
    // grace budget on an answer nobody re-confirmed.
    for (int i = 0; i < 5; ++i) {
        const auto l = EngineLivenessTestAccess::revalidate(store, "engine:cache-warm");
        CHECK(l.status == EngineLookupStatus::Active);
        CHECK(l.from_cache);
    }
    CHECK(store.revalidate_cache_hits() == 5);
    CHECK(store.revalidate_cache_misses() == 1); // unchanged — no further reads

    // get_for_auth is the authoritative chokepoint and must NOT consult or
    // populate the cache: fresh authorization decisions always read through.
    const auto hits_before = store.revalidate_cache_hits();
    const auto misses_before = store.revalidate_cache_misses();
    for (int i = 0; i < 3; ++i)
        CHECK(store.get_for_auth("engine:cache-warm").status == EngineLookupStatus::Active);
    CHECK(store.revalidate_cache_hits() == hits_before);
    CHECK(store.revalidate_cache_misses() == misses_before);
}

TEST_CASE("revoke invalidates the revalidate cache — no stale Active survives the write",
          "[pg][engine_principal][store][cache]") {
    // THE security test for #2367. A cached Active must not outlive its
    // principal: on the writing replica the stream is cut on the very next
    // tick, not after kAuthCacheTtl.
    YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.create("Vuln Sync", "alice", "j", "internal", "admin", "engine:cache-revoke")
               .has_value());

    REQUIRE(EngineLivenessTestAccess::revalidate(store, "engine:cache-revoke").status ==
            EngineLookupStatus::Active);
    REQUIRE(store.revalidate_cache_size() == 1);

    auto revoked = store.revoke("engine:cache-revoke");
    REQUIRE(revoked.has_value());
    REQUIRE(*revoked);
    CHECK(store.revalidate_cache_size() == 0); // dropped by the write, not by TTL

    // Next tick observes the revocation immediately.
    CHECK(EngineLivenessTestAccess::revalidate(store, "engine:cache-revoke").status ==
          EngineLookupStatus::MissingOrRevoked);
    // ...and stays uncached, so it cannot be resurrected by a later hit.
    CHECK(store.revalidate_cache_size() == 0);
    CHECK(EngineLivenessTestAccess::revalidate(store, "engine:cache-revoke").status ==
          EngineLookupStatus::MissingOrRevoked);
}

TEST_CASE("a revoked principal is never served Active again, however the clock flaps (#2367 CH-2)",
          "[pg][engine_principal][store][cache]") {
    // Gate-5 chaos CH-2, the core security invariant: once a principal is
    // revoked, no amount of time passing or re-querying can make the liveness
    // cache report it Active again. This composes revoke + repeated reads +
    // clock advances across TTL boundaries into one explicit immortality-bound
    // test (the pieces are covered separately above; this is the composition
    // the chaos pass asked to have pinned, not inferred).
    YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.create("Flap", "alice", "j", "internal", "admin", "engine:flap").has_value());

    auto fake_now = std::chrono::steady_clock::now(); // outlives `store`
    store.set_clock_for_test([&] { return fake_now; });

    // Warm it live, then revoke.
    REQUIRE(EngineLivenessTestAccess::revalidate(store, "engine:flap").status ==
            EngineLookupStatus::Active);
    auto revoked = store.revoke("engine:flap");
    REQUIRE(revoked.has_value());
    REQUIRE(*revoked);

    // Now hammer it across many TTL windows. It must be MissingOrRevoked on
    // EVERY call -- a revoked principal has no path back to Active, and nothing
    // (not a cache hit, not TTL expiry, not a re-query) resurrects it.
    for (int i = 0; i < 10; ++i) {
        const auto r = EngineLivenessTestAccess::revalidate(store, "engine:flap");
        CHECK(r.status == EngineLookupStatus::MissingOrRevoked);
        CHECK_FALSE(r.from_cache); // MissingOrRevoked is never cached, so always a fresh read
        fake_now += std::chrono::seconds(20); // step past a full TTL each iteration
    }
    CHECK(store.revalidate_cache_size() == 0);

    store.set_clock_for_test({}); // restore before fake_now dies
}

TEST_CASE("transfer_owner invalidates the revalidate cache",
          "[pg][engine_principal][store][cache]") {
    YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.create("Vuln Sync", "alice", "j", "internal", "admin", "engine:cache-xfer")
               .has_value());

    REQUIRE(EngineLivenessTestAccess::revalidate(store, "engine:cache-xfer").status ==
            EngineLookupStatus::Active);
    REQUIRE(store.revalidate_cache_size() == 1);

    auto moved = store.transfer_owner("engine:cache-xfer", "bob");
    REQUIRE(moved.has_value());
    REQUIRE(*moved);
    CHECK(store.revalidate_cache_size() == 0);

    // The next lookup is a genuine read-through, not a cache hit.
    const auto after = EngineLivenessTestAccess::revalidate(store, "engine:cache-xfer");
    CHECK(after.status == EngineLookupStatus::Active);
    CHECK_FALSE(after.from_cache);

    // The revalidate result deliberately carries no row, so the owner change is
    // observed through the authoritative read. (Withholding the row is what
    // makes a stale owner_username unreadable by construction.)
    auto row = store.get("engine:cache-xfer");
    REQUIRE(row.has_value());
    REQUIRE(row->has_value());
    CHECK((*row)->owner_username == "bob");
}

TEST_CASE("get_for_auth_revalidate caches ONLY Active — never MissingOrRevoked, never "
          "StoreUnreachable",
          "[pg][engine_principal][store][cache]") {
    SECTION("MissingOrRevoked is re-read every call (no negative caching)") {
        YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
        PgPool pool{{.conninfo = db.dsn(), .size = 4}};
        REQUIRE(pool.valid());
        EnginePrincipalStore store{pool};
        REQUIRE(store.is_open());

        for (int i = 0; i < 3; ++i)
            CHECK(EngineLivenessTestAccess::revalidate(store, "engine:never-existed").status ==
                  EngineLookupStatus::MissingOrRevoked);
        CHECK(store.revalidate_cache_size() == 0);
        CHECK(store.revalidate_cache_hits() == 0);
        CHECK(store.revalidate_cache_misses() == 3);

        // Not negative-caching is what lets a freshly created principal be seen
        // immediately, with no create() invalidation hook.
        REQUIRE(store.create("Late", "alice", "j", "internal", "admin", "engine:never-existed")
                   .has_value());
        CHECK(EngineLivenessTestAccess::revalidate(store, "engine:never-existed").status ==
              EngineLookupStatus::Active);
    }

    SECTION("StoreUnreachable is never cached — caching it would extend the outage") {
        // Invalid pool: never connects, so no live DB needed (mirrors the
        // get_for_auth StoreUnreachable section above).
        PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
        REQUIRE_FALSE(pool.valid());
        EnginePrincipalStore store{pool};
        REQUIRE_FALSE(store.is_open());

        for (int i = 0; i < 3; ++i)
            CHECK(EngineLivenessTestAccess::revalidate(store, "engine:whatever").status ==
                  EngineLookupStatus::StoreUnreachable);
        CHECK(store.revalidate_cache_size() == 0);
        CHECK(store.revalidate_cache_hits() == 0);
    }
}

TEST_CASE("a revoke racing a revalidate's cache-write cannot poison the cache (#2367 TOCTOU)",
          "[pg][engine_principal][store][cache]") {
    // Deterministic interleave at the exact poisoning point, mirroring
    // ApiTokenStore's #2179 regression test. The hook fires after the
    // read-through (which saw an Active row) and before the generation
    // re-check, i.e. precisely where a naive implementation would install an
    // entry that outlives the revoke by a full TTL.
    YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.create("Vuln Sync", "alice", "j", "internal", "admin", "engine:cache-race")
               .has_value());

    bool fired = false;
    store.test_hook_after_revalidate_read_ = [&] {
        if (fired)
            return; // the revoke's own path must not recurse
        fired = true;
        auto revoked = store.revoke("engine:cache-race");
        REQUIRE(revoked.has_value());
        REQUIRE(*revoked);
    };

    // This call read an Active row before the revoke landed, so returning
    // Active once is permitted (documented bounded window). What is NOT
    // permitted is caching it.
    (void)EngineLivenessTestAccess::revalidate(store, "engine:cache-race");
    store.test_hook_after_revalidate_read_ = nullptr;
    REQUIRE(fired);

    CHECK(store.revalidate_cache_size() == 0); // generation bump defeated the write
    CHECK(EngineLivenessTestAccess::revalidate(store, "engine:cache-race").status ==
          EngineLookupStatus::MissingOrRevoked);
}

TEST_CASE("revalidate cache entries expire and are re-read (clock seam)",
          "[pg][engine_principal][store][cache]") {
    YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    auto fake_now = std::chrono::steady_clock::now(); // outlives `store` by construction
    EnginePrincipalStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.create("Vuln Sync", "alice", "j", "internal", "admin", "engine:cache-ttl")
               .has_value());
    store.set_clock_for_test([&] { return fake_now; });

    REQUIRE_FALSE(EngineLivenessTestAccess::revalidate(store, "engine:cache-ttl").from_cache);
    CHECK(EngineLivenessTestAccess::revalidate(store, "engine:cache-ttl").from_cache); // warm

    // Just inside the jittered TTL floor (TTL minus its maximum jitter): still
    // a hit for certain.
    fake_now += std::chrono::seconds(10);
    CHECK(EngineLivenessTestAccess::revalidate(store, "engine:cache-ttl").from_cache);
    CHECK(store.revalidate_cache_size() == 1);

    // Past the full TTL: expired for certain, whatever jitter was drawn. The
    // answer is still Active, but it is authoritative again — which is what
    // lets the pump reset its grace budget.
    fake_now += std::chrono::seconds(20);
    CHECK(store.revalidate_cache_size() == 0); // expired entries are not "cached"
    const auto after = EngineLivenessTestAccess::revalidate(store, "engine:cache-ttl");
    CHECK(after.status == EngineLookupStatus::Active);
    CHECK_FALSE(after.from_cache);
}

TEST_CASE("an unreachable store is rate-limited, not re-asked on every tick",
          "[engine_principal][store][cache]") {
    // BLOCKER-2 regression. Without the backoff the positive cache fixes only
    // the warm steady state: once entries age out during a sustained brownout,
    // every stream reads through on every ~3 s tick — the O(streams x tick)
    // amplifier #2367 exists to remove, merely postponed by one TTL.
    // Invalid pool never connects, so no live DB is needed.
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    auto fake_now = std::chrono::steady_clock::now(); // outlives `store` by construction
    EnginePrincipalStore store{pool};
    REQUIRE_FALSE(store.is_open());
    store.set_clock_for_test([&] { return fake_now; });

    // First call actually asks and fails.
    CHECK(EngineLivenessTestAccess::revalidate(store, "engine:brownout").status ==
          EngineLookupStatus::StoreUnreachable);
    CHECK(store.revalidate_cache_misses() == 1);
    CHECK(store.revalidate_backoff_suppressed() == 0);

    // The next several ticks repeat that answer without asking again.
    for (int i = 0; i < 10; ++i) {
        CHECK(EngineLivenessTestAccess::revalidate(store, "engine:brownout").status ==
              EngineLookupStatus::StoreUnreachable);
    }
    CHECK(store.revalidate_cache_misses() == 1); // no further reads attempted
    CHECK(store.revalidate_backoff_suppressed() == 10);

    // Backoff is short by design — recovery must be noticed promptly, so past
    // the window (plus its maximum jitter) the store is probed again.
    fake_now += std::chrono::seconds(11);
    CHECK(EngineLivenessTestAccess::revalidate(store, "engine:brownout").status ==
          EngineLookupStatus::StoreUnreachable);
    CHECK(store.revalidate_cache_misses() == 2);
}

TEST_CASE("the revalidate cache is physically bounded, not just filtered",
          "[pg][engine_principal][store][cache]") {
    // BLOCKER-3 regression. The earlier version of this test asserted only on
    // revalidate_cache_size(), which reports UNEXPIRED entries -- so deleting
    // the ceiling and the sweep entirely would still have passed it. These
    // assertions go through the physical-residency seam, so they fail if the
    // bound is removed.
    YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
    auto fake_now = std::chrono::steady_clock::now(); // declared BEFORE the store
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE(store.is_open());
    store.set_clock_for_test([&] { return fake_now; });
    store.set_max_entries_for_test(3);

    for (int i = 0; i < 3; ++i) {
        const auto id = "engine:cap-" + std::to_string(i);
        REQUIRE(store.create("B", "alice", "j", "internal", "admin", id).has_value());
        REQUIRE(EngineLivenessTestAccess::revalidate(store, id).status == EngineLookupStatus::Active);
    }
    CHECK(store.revalidate_cache_resident_for_test() == 3);

    // Full, and every entry still live: the sweep frees nothing, so a fourth
    // principal must be DECLINED rather than evicting a live entry. It still
    // gets a correct answer -- read-through is slower, never wrong.
    REQUIRE(store.create("B", "alice", "j", "internal", "admin", "engine:cap-overflow")
               .has_value());
    const auto overflow = EngineLivenessTestAccess::revalidate(store, "engine:cap-overflow");
    CHECK(overflow.status == EngineLookupStatus::Active);
    CHECK_FALSE(overflow.from_cache);
    CHECK(store.revalidate_cache_resident_for_test() == 3); // ceiling held
    // ...and it was not cached, so the next call reads through again.
    CHECK_FALSE(EngineLivenessTestAccess::revalidate(store, "engine:cap-overflow").from_cache);

    // Once the incumbents expire, the sweep reclaims their slots on the next
    // insert -- residency must come DOWN, which a filtered count cannot show.
    fake_now += std::chrono::seconds(30);
    REQUIRE(EngineLivenessTestAccess::revalidate(store, "engine:cap-overflow").status ==
            EngineLookupStatus::Active);
    CHECK(store.revalidate_cache_resident_for_test() == 1);
}

TEST_CASE("a revoke racing a failed read does not install a shadowing backoff (#2367 C1)",
          "[engine_principal][store][cache]") {
    // Adversarial-review finding C1 (PR #2462): the Active-insert arm
    // re-checks the revoke generation under the mutex before caching; the
    // StoreUnreachable BACKOFF-insert arm must do the
    // same. Otherwise a read that failed during a brownout installs a backoff
    // entry AFTER a concurrent revoke has erased the maps -- and that backoff
    // then answers StoreUnreachable (no read-through) for its whole window once
    // the store recovers, so a just-revoked principal's stream rides grace
    // instead of being cut on the next tick (contradicting ADR-0031).
    //
    // Invalid pool -> get_for_auth returns StoreUnreachable deterministically
    // without a lease. The after-read hook stands in for the concurrent revoke
    // by bumping the generation through invalidate_revalidate_cache (revoke's
    // own gen-bump path; revoke() itself early-returns on a closed store, so it
    // cannot be used directly here).
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE_FALSE(store.is_open());

    bool fired = false;
    store.test_hook_after_revalidate_read_ = [&] {
        if (fired)
            return;
        fired = true;
        store.invalidate_revalidate_cache("engine:c1"); // the racing revoke's gen bump
    };

    // The read fails; the generation moved between the pre-read snapshot and
    // the insert, so NO backoff is installed -- the next tick reads through.
    CHECK(EngineLivenessTestAccess::revalidate(store, "engine:c1").status ==
          EngineLookupStatus::StoreUnreachable);
    store.test_hook_after_revalidate_read_ = nullptr;
    REQUIRE(fired);
    CHECK(store.revalidate_backoff_resident_for_test() == 0);

    // Guard against a vacuous pass: with NO intervening bump, a StoreUnreachable
    // read DOES install a backoff. (Reverting the C1 fix makes the check above
    // fail while this one still passes.)
    CHECK(EngineLivenessTestAccess::revalidate(store, "engine:c1-baseline").status ==
          EngineLookupStatus::StoreUnreachable);
    CHECK(store.revalidate_backoff_resident_for_test() == 1);
}

TEST_CASE("the failure-backoff map is bounded on its own insert path",
          "[engine_principal][store][cache]") {
    // The backoff map is filled ONLY during an outage, which is exactly when
    // the positive-insert path (the other sweep site) never runs. Bounding one
    // map and not the other bounds neither.
    auto fake_now = std::chrono::steady_clock::now();
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE_FALSE(store.is_open());
    store.set_clock_for_test([&] { return fake_now; });
    store.set_max_entries_for_test(3);

    for (int i = 0; i < 8; ++i) {
        const auto id = "engine:backoff-" + std::to_string(i);
        CHECK(EngineLivenessTestAccess::revalidate(store, id).status == EngineLookupStatus::StoreUnreachable);
    }
    CHECK(store.revalidate_backoff_resident_for_test() <= 3);

    // After the windows elapse the sweep reclaims them on the next insert.
    fake_now += std::chrono::seconds(30);
    CHECK(EngineLivenessTestAccess::revalidate(store, "engine:backoff-late").status ==
          EngineLookupStatus::StoreUnreachable);
    CHECK(store.revalidate_backoff_resident_for_test() == 1);
}

TEST_CASE("a revoke clears the failure backoff, so a revoked principal is not held alive",
          "[pg][engine_principal][store][cache]") {
    // Without this the backoff would answer StoreUnreachable -> kIndeterminate
    // for its whole window, keeping a JUST-REVOKED principal's stream alive in
    // grace -- contradicting "the writing replica cuts the stream next tick".
    YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.create("B", "alice", "j", "internal", "admin", "engine:backoff-revoke")
               .has_value());
    REQUIRE(EngineLivenessTestAccess::revalidate(store, "engine:backoff-revoke").status ==
            EngineLookupStatus::Active);

    store.invalidate_revalidate_cache("engine:backoff-revoke");
    CHECK(store.revalidate_backoff_resident_for_test() == 0);

    auto revoked = store.revoke("engine:backoff-revoke");
    REQUIRE(revoked.has_value());
    CHECK(store.revalidate_cache_resident_for_test() == 0);
    CHECK(store.revalidate_backoff_resident_for_test() == 0);
    CHECK(EngineLivenessTestAccess::revalidate(store, "engine:backoff-revoke").status ==
          EngineLookupStatus::MissingOrRevoked);
}

TEST_CASE("concurrent revalidate + revoke never leaves a stale Active (TSan)",
          "[pg][engine_principal][store][cache]") {
    // The deterministic hook test above proves the generation-guard ARITHMETIC
    // but runs on one thread, so it gives TSan nothing to inspect and never
    // contends revalidate_cache_mu_. This drives real threads through the
    // reader path, the writer path, and the metrics path at once -- the shape
    // ApiTokenStore's own TOCTOU regression uses.
    //
    // The VALUE of this case is running it under TSan (a real data race on the
    // shared mutex/atomics is reported). The stale_after_revoke CHECK_FALSE is
    // a weak logical assertion by design: a single one-shot revoke's insert
    // window is microseconds wide, so it would almost never fire even if the
    // generation guard were removed -- do not read a green CHECK as proof of the
    // guard (the hook test is that proof). Under a non-TSan build this is a
    // liveness smoke test only.
    YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 8}};
    REQUIRE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.create("Race", "alice", "j", "internal", "admin", "engine:race")
               .has_value());

    std::atomic<bool> stop{false};
    std::atomic<bool> stale_after_revoke{false};
    std::atomic<bool> revoked_done{false};

    std::vector<std::thread> readers;
    for (int i = 0; i < 4; ++i) {
        readers.emplace_back([&] {
            while (!stop.load(std::memory_order_acquire)) {
                // Snapshot BEFORE the call, not after. THE invariant is that a
                // call which STARTS after the revoke has returned can never
                // report the principal live. Sampling afterwards instead would
                // misattribute a call that began before the revoke and
                // legitimately returned a cached Active -- the documented
                // bounded single-call window -- and flake under TSan
                // scheduling.
                const bool already_revoked = revoked_done.load(std::memory_order_acquire);
                const auto r = EngineLivenessTestAccess::revalidate(store, "engine:race");
                if (already_revoked && r.status == EngineLookupStatus::Active) {
                    stale_after_revoke.store(true, std::memory_order_release);
                }
            }
        });
    }
    // Metrics-path reader: exercises the same mutex from a third role.
    std::thread poller([&] {
        while (!stop.load(std::memory_order_acquire))
            (void)store.revalidate_cache_size();
    });

    // Capture the revoke outcome but do NOT assert on it yet: a throwing
    // REQUIRE here, with the reader/poller threads still joinable, would call
    // ~thread on a joinable thread (std::terminate) and the running threads
    // would touch these destructing stack locals (UAF). Stop + join FIRST on
    // every path, then assert.
    auto revoked = store.revoke("engine:race");
    revoked_done.store(true, std::memory_order_release);

    // Let the readers observe the post-revoke world before tearing down.
    for (int i = 0; i < 200; ++i)
        (void)store.revalidate_cache_size();

    stop.store(true, std::memory_order_release);
    for (auto& t : readers)
        t.join();
    poller.join();

    // Threads are joined; assertions are now safe to throw.
    REQUIRE(revoked.has_value());
    REQUIRE(*revoked);
    CHECK_FALSE(stale_after_revoke.load());
    CHECK(EngineLivenessTestAccess::revalidate(store, "engine:race").status ==
          EngineLookupStatus::MissingOrRevoked);
}

TEST_CASE("concurrent StoreUnreachable exercises the backoff map under contention (TSan)",
          "[engine_principal][store][cache]") {
    // The positive-cache TSan test above uses a VALID pool, so it never drives
    // the revalidate_backoff_ map -- that path only fills on StoreUnreachable.
    // An invalid pool answers StoreUnreachable without a lease, so N threads
    // hammering distinct keys insert/erase/sweep the backoff map (and bump
    // revalidate_backoff_suppressed_) concurrently while a poller reads its
    // size, bringing that mutex/counter discipline under the sanitizer. No live
    // DB needed (the pool never connects).
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE_FALSE(store.is_open());
    store.set_max_entries_for_test(16); // force sweep/decline churn on the backoff map

    std::atomic<bool> stop{false};
    std::atomic<bool> wrong_status{false};

    std::vector<std::thread> readers;
    for (int i = 0; i < 4; ++i) {
        readers.emplace_back([&, i] {
            int n = 0;
            while (!stop.load(std::memory_order_acquire)) {
                // Distinct keys per thread so inserts spread across the map;
                // an unreachable store must ALWAYS deny (either read-through or
                // backoff -- both StoreUnreachable), never admit.
                const auto id = "engine:bo-" + std::to_string(i) + "-" + std::to_string(n++ % 64);
                if (EngineLivenessTestAccess::revalidate(store, id).status !=
                    EngineLookupStatus::StoreUnreachable) {
                    wrong_status.store(true, std::memory_order_release);
                }
            }
        });
    }
    std::thread poller([&] {
        while (!stop.load(std::memory_order_acquire))
            (void)store.revalidate_backoff_resident_for_test();
    });

    for (int i = 0; i < 500; ++i)
        (void)store.revalidate_backoff_resident_for_test();

    stop.store(true, std::memory_order_release);
    for (auto& t : readers)
        t.join();
    poller.join();

    CHECK_FALSE(wrong_status.load());               // fail-closed held throughout
    CHECK(store.revalidate_backoff_resident_for_test() <= 16); // ceiling held under contention
}

TEST_CASE("invalidate_revalidate_cache clears one principal or all of them",
          "[pg][engine_principal][store][cache]") {
    YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE(store.is_open());
    REQUIRE(store.create("A", "alice", "j", "internal", "admin", "engine:inv-a").has_value());
    REQUIRE(store.create("B", "alice", "j", "internal", "admin", "engine:inv-b").has_value());
    REQUIRE(EngineLivenessTestAccess::revalidate(store, "engine:inv-a").status == EngineLookupStatus::Active);
    REQUIRE(EngineLivenessTestAccess::revalidate(store, "engine:inv-b").status == EngineLookupStatus::Active);
    REQUIRE(store.revalidate_cache_size() == 2);

    store.invalidate_revalidate_cache("engine:inv-a");
    CHECK(store.revalidate_cache_size() == 1);

    store.invalidate_revalidate_cache(); // empty id = clear all
    CHECK(store.revalidate_cache_size() == 0);
}

// ── list_all ────────────────────────────────────────────────────────────────

TEST_CASE("EnginePrincipalStore::list_all returns created principals, ordered, with the "
          "include_revoked filter",
          "[pg][engine_principal][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.create("Vuln Sync", "alice", "j", "internal", "admin", "engine:list-active")
               .has_value());
    REQUIRE(store.create("Vendor Sync", "bob", "j", "external", "admin", "engine:list-revoked")
               .has_value());
    REQUIRE(store.revoke("engine:list-revoked"));

    SECTION("include_revoked=true (default) returns both") {
        auto rows = store.list_all();
        CHECK(rows.size() == 2);
        bool saw_active = false, saw_revoked = false;
        for (const auto& r : rows) {
            if (r.principal_id == "engine:list-active") {
                saw_active = true;
                CHECK(r.lifecycle_state == "active");
            }
            if (r.principal_id == "engine:list-revoked") {
                saw_revoked = true;
                CHECK(r.lifecycle_state == "revoked");
            }
        }
        CHECK(saw_active);
        CHECK(saw_revoked);
        // ordered by created_at — the first created principal sorts first.
        CHECK(rows.front().principal_id == "engine:list-active");
    }

    SECTION("include_revoked=false filters to active only") {
        auto rows = store.list_all(/*include_revoked=*/false);
        REQUIRE(rows.size() == 1);
        CHECK(rows.front().principal_id == "engine:list-active");
        CHECK(rows.front().lifecycle_state == "active");
    }
}

TEST_CASE("EnginePrincipalStore::list_all returns empty on an unreachable store",
          "[pg][engine_principal][store]") {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE_FALSE(store.is_open());

    CHECK(store.list_all().empty());
    CHECK(store.list_all(false).empty());
}

// ── count_active_owned_by ──────────────────────────────────────────────────

TEST_CASE("EnginePrincipalStore::count_active_owned_by counts only active principals for the "
          "given owner",
          "[pg][engine_principal][store]") {
    YUZU_REQUIRE_PG_DB_TPL(db, engine_principal_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE(store.is_open());

    // owner X: 2 active + 1 revoked.
    REQUIRE(store.create("A1", "userx", "j", "internal", "admin", "engine:x-active-1")
               .has_value());
    REQUIRE(store.create("A2", "userx", "j", "internal", "admin", "engine:x-active-2")
               .has_value());
    REQUIRE(store.create("A3", "userx", "j", "internal", "admin", "engine:x-revoked")
               .has_value());
    REQUIRE(store.revoke("engine:x-revoked"));

    // owner Y: 1 active.
    REQUIRE(store.create("B1", "usery", "j", "internal", "admin", "engine:y-active")
               .has_value());

    auto x_count = store.count_active_owned_by("userx");
    REQUIRE(x_count.has_value());
    CHECK(*x_count == 2);

    auto y_count = store.count_active_owned_by("usery");
    REQUIRE(y_count.has_value());
    CHECK(*y_count == 1);

    // owner Z: no principals at all.
    auto z_count = store.count_active_owned_by("userz");
    REQUIRE(z_count.has_value());
    CHECK(*z_count == 0);
}

TEST_CASE("EnginePrincipalStore::count_active_owned_by returns nullopt on an unreachable store "
          "(fail-closed for the owner-delete guard)",
          "[pg][engine_principal][store]") {
    PgPool pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 2}};
    REQUIRE_FALSE(pool.valid());
    EnginePrincipalStore store{pool};
    REQUIRE_FALSE(store.is_open());

    CHECK_FALSE(store.count_active_owned_by("alice").has_value());
}
