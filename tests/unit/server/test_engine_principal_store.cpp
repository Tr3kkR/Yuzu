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

#include <stdexcept>
#include <string>

using yuzu::server::EngineLookup;
using yuzu::server::EngineLookupStatus;
using yuzu::server::EnginePrincipalRow;
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
        CHECK_FALSE(store.get("engine:vuln").has_value());
    }

    SECTION("garbage classification is rejected") {
        auto r = store.create("Vuln Sync", "alice", "cloud IAM parity", "nonsense", "admin",
                              "engine:vuln");
        REQUIRE_FALSE(r.has_value());
        CHECK_FALSE(store.get("engine:vuln").has_value());
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
        CHECK_FALSE(store.get("engine:no-owner").has_value());
    }

    SECTION("empty justification is rejected") {
        auto r = store.create("Vuln Sync", "alice", /*justification=*/"", "internal", "admin",
                              "engine:no-justification");
        REQUIRE_FALSE(r.has_value());
        CHECK_FALSE(store.get("engine:no-justification").has_value());
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
    CHECK(row->display_name == "Vuln Sync");
    CHECK(row->owner_username == "alice");
    CHECK(row->classification == "internal");
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
    CHECK(fetched->principal_id == created->principal_id);
    CHECK(fetched->display_name == created->display_name);
    CHECK(fetched->owner_username == created->owner_username);
    CHECK(fetched->justification == created->justification);
    CHECK(fetched->classification == created->classification);
    CHECK(fetched->lifecycle_state == created->lifecycle_state);
    CHECK(fetched->superseded_by == created->superseded_by);
    CHECK(fetched->created_at == created->created_at);
    CHECK(fetched->revoked_at == created->revoked_at);
    CHECK(fetched->created_by == created->created_by);
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
        CHECK(store.revoke("engine:revoke-me", "engine:revoke-me-v2"));
        auto row = store.get("engine:revoke-me"); // never hard-deleted
        REQUIRE(row.has_value());
        CHECK(row->lifecycle_state == "revoked");
        CHECK(row->superseded_by == "engine:revoke-me-v2");
        CHECK(row->revoked_at > 0);
    }

    SECTION("revoke is terminal — a second revoke is a no-op, not a re-revoke") {
        CHECK(store.revoke("engine:revoke-me"));
        CHECK_FALSE(store.revoke("engine:revoke-me")); // already revoked → false
    }

    SECTION("revoking an unknown principal returns false") {
        CHECK_FALSE(store.revoke("engine:does-not-exist"));
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
        CHECK(store.transfer_owner("engine:xfer", "bob"));
        auto row = store.get("engine:xfer");
        REQUIRE(row.has_value());
        CHECK(row->owner_username == "bob");
    }

    SECTION("transfer on a revoked principal fails — not an active row") {
        REQUIRE(store.revoke("engine:xfer"));
        CHECK_FALSE(store.transfer_owner("engine:xfer", "bob"));
    }

    SECTION("transfer on an unknown principal fails") {
        CHECK_FALSE(store.transfer_owner("engine:does-not-exist", "bob"));
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
        REQUIRE(store.revoke("engine:auth-revoked"));

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
