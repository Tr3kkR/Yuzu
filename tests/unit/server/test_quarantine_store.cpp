/**
 * test_quarantine_store.cpp — `QuarantineStore` (Guardian device-quarantine
 * bookkeeping, Guardian design §11.7). Migrated Postgres store
 * (ADR-0006/0009, schema `quarantine_store`).
 *
 * Covers:
 *  - quarantine_device: success, empty agent_id rejected, ON CONFLICT
 *    (agent_id) WHERE status='active' verified race-safe against a live
 *    Postgres instance (docs/postgres-store-playbook.md's explicit warning
 *    that this syntax is easy to get subtly wrong by reasoning alone).
 *  - release_device: success (single guarded UPDATE), not-quarantined.
 *  - get_status: found, genuinely-absent (nullopt value, not an error), and
 *    empty agent_id (precondition miss, not a store failure).
 *  - list_quarantined / get_history: multiple records, newest-first
 *    ordering, history survives release + re-quarantine cycles.
 *  - fail-closed construction (migration-drift case).
 *
 * Migrated Postgres store (ADR-0047, authoritative/fail-hard per ADR-0012
 * §1). PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails when set
 * but broken (test_helpers.hpp skip-vs-fail contract). Store-behaviour cases
 * use the pre-migrated PgTestTemplate variant
 * (docs/postgres-store-playbook.md step 7); the fail-closed construction
 * case uses plain YUZU_REQUIRE_PG_DB, per the plain-migration-test carve-out
 * documented on that macro.
 *
 * No legacy-SQLite backfill test coverage: the dedicated migrate_from_sqlite
 * TEST_CASE suite was removed as part of a fresh-start-by-default policy
 * change (ADR-0009 amendment) -- no production fleet has ever run a
 * pre-Postgres build. QuarantineStore::migrate_from_sqlite() itself is
 * UNCHANGED and still present in production code; only this file's test
 * coverage of it was removed.
 */

#include "quarantine_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <string>
#include <vector>

using yuzu::server::QuarantineRecord;
using yuzu::server::QuarantineStore;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

yuzu::test::PgTestTemplate quarantine_tpl{"quarantinestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    QuarantineStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("quarantine_store template: store failed to migrate");
}};

} // namespace

// ── Construction fail-closed ────────────────────────────────────────────────

TEST_CASE("QuarantineStore: construction fails closed on migration drift", "[pg][quarantine]") {
    YUZU_REQUIRE_PG_MIGRATION_DB(db);

    // Pre-seed: create the quarantine_store schema + a conflicting table, but
    // no public.schema_meta row — the drift guard refuses (version 0 but
    // tables exist).
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA quarantine_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE quarantine_store.quarantine_records (bogus int)")};
        REQUIRE(t.ok());
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    QuarantineStore store{pool};
    CHECK_FALSE(store.is_open()); // → server.cpp sets startup_failed_ = true
}

// ── CRUD ─────────────────────────────────────────────────────────────────────

TEST_CASE("QuarantineStore: quarantine and release device", "[pg][quarantine][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    auto result =
        store.quarantine_device("agent-001", "admin", "Suspicious activity", "10.0.0.1,10.0.0.2");
    REQUIRE(result.has_value());

    auto status = store.get_status("agent-001");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->status == "active");
    CHECK((*status)->quarantined_by == "admin");
    CHECK((*status)->reason == "Suspicious activity");
    CHECK((*status)->whitelist == "10.0.0.1,10.0.0.2");
    CHECK((*status)->quarantined_at > 0);

    auto release = store.release_device("agent-001");
    REQUIRE(release.has_value());

    auto after = store.get_status("agent-001");
    REQUIRE(after.has_value()); // the READ succeeded
    CHECK_FALSE(after->has_value()); // ...it just found nothing active
}

TEST_CASE("QuarantineStore: quarantine_device rejects an empty agent_id", "[pg][quarantine][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.quarantine_device("", "admin", "reason", "");
    CHECK_FALSE(result.has_value());
    // gov-fix(quality-engineer): exact message, not just has_value() --
    // this precondition-miss must stay UNPREFIXED (a 400 business error, not
    // a db_error:-prefixed 503) or the REST/MCP classification silently
    // misroutes it.
    CHECK(result.error() == "agent_id is required");
}

// Verifies the ON CONFLICT (agent_id) WHERE status = 'active' DO NOTHING
// syntax against a live Postgres instance — the partial-unique-index
// arbiter this store relies on to replace the legacy check-then-insert-
// under-mutex race (docs/postgres-store-playbook.md's explicit warning:
// this class of syntax is easy to get subtly wrong by reasoning alone).
TEST_CASE("QuarantineStore: double quarantine rejected (partial unique index race-safe)",
          "[pg][quarantine][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    auto first = store.quarantine_device("agent-002", "admin", "First", "");
    REQUIRE(first.has_value());
    auto second = store.quarantine_device("agent-002", "admin", "Second", "");
    CHECK_FALSE(second.has_value());
    CHECK(second.error() == "device is already quarantined");

    // Exactly one active row, carrying the FIRST call's reason (the conflict
    // truly did nothing — it did not silently overwrite).
    auto status = store.get_status("agent-002");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->reason == "First");

    // A device can be re-quarantined after release (the partial index only
    // excludes a SECOND simultaneously-active row, not history).
    REQUIRE(store.release_device("agent-002").has_value());
    auto third = store.quarantine_device("agent-002", "admin", "Third", "");
    CHECK(third.has_value());
}

TEST_CASE("QuarantineStore: release non-quarantined device", "[pg][quarantine][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    auto result = store.release_device("agent-nonexistent");
    CHECK_FALSE(result.has_value());
    CHECK(result.error() == "device is not quarantined");
}

TEST_CASE("QuarantineStore: non-quarantined device has no active status", "[pg][quarantine][status]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    auto status = store.get_status("agent-clean");
    REQUIRE(status.has_value()); // the READ succeeded
    CHECK_FALSE(status->has_value()); // ...it just found nothing

    auto empty_id = store.get_status("");
    REQUIRE(empty_id.has_value());
    CHECK_FALSE(empty_id->has_value());
}

TEST_CASE("QuarantineStore: list quarantined devices", "[pg][quarantine][list]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.quarantine_device("agent-list-1", "admin", "Reason 1", "").has_value());
    REQUIRE(store.quarantine_device("agent-list-2", "admin", "Reason 2", "").has_value());

    auto list = store.list_quarantined();
    REQUIRE(list.has_value()); // AUTHORITATIVE read succeeded
    int found = 0;
    for (const auto& r : *list)
        if (r.agent_id == "agent-list-1" || r.agent_id == "agent-list-2")
            ++found;
    CHECK(found == 2);

    REQUIRE(store.release_device("agent-list-1").has_value());
    auto list2 = store.list_quarantined();
    REQUIRE(list2.has_value());
    bool has_1 = false, has_2 = false;
    for (const auto& r : *list2) {
        if (r.agent_id == "agent-list-1")
            has_1 = true;
        if (r.agent_id == "agent-list-2")
            has_2 = true;
    }
    CHECK_FALSE(has_1); // released, no longer active
    CHECK(has_2);
}

TEST_CASE("QuarantineStore: history tracking survives release + re-quarantine cycles",
          "[pg][quarantine][history]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.quarantine_device("agent-hist", "admin", "First quarantine", "").has_value());
    REQUIRE(store.release_device("agent-hist").has_value());

    REQUIRE(store.quarantine_device("agent-hist", "security-team", "Second quarantine",
                                    "10.0.0.1")
                .has_value());
    REQUIRE(store.release_device("agent-hist").has_value());

    auto history = store.get_history("agent-hist");
    REQUIRE(history.has_value());
    REQUIRE(history->size() == 2);
    // Most recent first.
    CHECK((*history)[0].reason == "Second quarantine");
    CHECK((*history)[0].status == "released");
    CHECK((*history)[1].reason == "First quarantine");
}

TEST_CASE("QuarantineStore: get_history on an empty agent_id returns an empty result, not degraded",
          "[pg][quarantine][history]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    auto history = store.get_history("");
    REQUIRE(history.has_value());
    CHECK(history->empty());
}
