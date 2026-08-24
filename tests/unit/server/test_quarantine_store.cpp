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
 *  - MANDATORY backfill (ADR-0009): fresh install marks complete with no
 *    legacy file; migrates legacy rows (active + released) and is
 *    idempotent on re-run; refuses (fail-closed) on a corrupt legacy file,
 *    a 0-byte legacy file, an unrecognised legacy status value, and a
 *    fingerprint mismatch / sourceless-then-real-content holder-side
 *    verification race (ADR-0047 "Backfill").
 *
 * Migrated Postgres store (ADR-0047, authoritative/fail-hard per ADR-0012
 * §1). PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails when set
 * but broken (test_helpers.hpp skip-vs-fail contract). Store-behaviour cases
 * use the pre-migrated PgTestTemplate variant
 * (docs/postgres-store-playbook.md step 7); the fail-closed construction
 * case uses plain YUZU_REQUIRE_PG_DB, per the plain-migration-test carve-out
 * documented on that macro.
 */

#include "quarantine_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <sqlite3.h>

#include <filesystem>
#include <fstream>
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
    YUZU_REQUIRE_PG_DB(db);

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

// ── Endpoint-confirmation state (#3425 schema v2) ──────────────────────────

TEST_CASE("QuarantineStore: mark_endpoint_applied/confirmed happy path, read back via get_status",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.quarantine_device("agent-001", "admin", "reason", "10.0.0.1").has_value());

    auto fresh = store.get_status("agent-001");
    REQUIRE(fresh.has_value());
    REQUIRE(fresh->has_value());
    CHECK((*fresh)->last_applied_at == 0); // never, matches released_at's sentinel
    CHECK((*fresh)->last_confirmed_at == 0);

    REQUIRE(store.mark_endpoint_applied("agent-001", (*fresh)->id, 1000).has_value());
    auto after_apply = store.get_status("agent-001");
    REQUIRE(after_apply.has_value());
    REQUIRE(after_apply->has_value());
    CHECK((*after_apply)->last_applied_at == 1000);
    CHECK((*after_apply)->last_confirmed_at == 0); // apply alone is not confirmation

    REQUIRE(store.mark_endpoint_confirmed("agent-001", (*fresh)->id, 2000).has_value());
    auto after_confirm = store.get_status("agent-001");
    REQUIRE(after_confirm.has_value());
    REQUIRE(after_confirm->has_value());
    CHECK((*after_confirm)->last_applied_at == 1000); // unaffected by the confirm write
    CHECK((*after_confirm)->last_confirmed_at == 2000);
}

TEST_CASE("QuarantineStore: mark_endpoint_applied/confirmed on a non-quarantined device is a "
          "business error, not a store failure",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    auto applied = store.mark_endpoint_applied("never-quarantined", /*record_id=*/0, 1000);
    REQUIRE_FALSE(applied.has_value());
    CHECK(applied.error() == "device is not quarantined");
    CHECK_FALSE(applied.error().starts_with(yuzu::server::kQuarantineDbErrorPrefix));

    auto confirmed = store.mark_endpoint_confirmed("never-quarantined", /*record_id=*/0, 1000);
    REQUIRE_FALSE(confirmed.has_value());
    CHECK(confirmed.error() == "device is not quarantined");
}

TEST_CASE("QuarantineStore: mark_endpoint_applied/confirmed on a RELEASED (not active) record "
          "is also a business error — the guarded UPDATE only matches status='active'",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.quarantine_device("agent-002", "admin", "reason", "").has_value());
    auto before_release = store.get_status("agent-002");
    REQUIRE(before_release.has_value());
    REQUIRE(before_release->has_value());
    const auto record_id = (*before_release)->id;
    REQUIRE(store.release_device("agent-002").has_value());

    // Even with the CORRECT (real, pre-release) id, status != 'active' alone
    // still fails the guarded UPDATE — id-scoping is additive, not a
    // replacement for the status check.
    auto applied = store.mark_endpoint_applied("agent-002", record_id, 1000);
    REQUIRE_FALSE(applied.has_value());
    CHECK(applied.error() == "device is not quarantined");
}

TEST_CASE("QuarantineStore: mark_endpoint_applied/confirmed with the WRONG record id (a "
          "release-then-requarantine race) is a business error, never silently stamps the new "
          "record (governance Gate 4, unhappy-path Finding A)",
          "[pg][quarantine][reconciler][regression]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.quarantine_device("agent-003", "admin", "malware", "10.0.0.1").has_value());
    auto old_status = store.get_status("agent-003");
    REQUIRE(old_status.has_value());
    REQUIRE(old_status->has_value());
    const auto old_id = (*old_status)->id;

    // Simulates the race: the OLD record is released and a NEW, unrelated
    // active record now exists for the same agent_id by the time the write
    // for the OLD record's dispatch arrives.
    REQUIRE(store.release_device("agent-003").has_value());
    REQUIRE(
        store.quarantine_device("agent-003", "admin", "NEW-reason", "99.99.99.99").has_value());
    auto new_status = store.get_status("agent-003");
    REQUIRE(new_status.has_value());
    REQUIRE(new_status->has_value());
    const auto new_id = (*new_status)->id;
    REQUIRE(new_id != old_id); // a genuinely different row

    // Using the STALE (old) record id must fail — id AND status='active' AND
    // agent_id all have to match; the id alone belonging to a real row that
    // once existed is not enough.
    auto applied = store.mark_endpoint_applied("agent-003", old_id, 1000);
    REQUIRE_FALSE(applied.has_value());
    CHECK(applied.error() == "device is not quarantined");
    auto confirmed = store.mark_endpoint_confirmed("agent-003", old_id, 1000);
    REQUIRE_FALSE(confirmed.has_value());
    CHECK(confirmed.error() == "device is not quarantined");

    // The NEW record must be completely untouched by either failed call —
    // this is the exact misattribution Finding A described.
    auto after = store.get_status("agent-003");
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK((*after)->id == new_id);
    CHECK((*after)->last_applied_at == 0);
    CHECK((*after)->last_confirmed_at == 0);

    // Using the CURRENT (new) record id succeeds, proving id-scoping isn't
    // simply broken/over-strict.
    REQUIRE(store.mark_endpoint_applied("agent-003", new_id, 1000).has_value());
}

TEST_CASE("QuarantineStore: mark_endpoint_applied/confirmed share quarantine_device's "
          "empty-agent_id precondition guard",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    // A precondition the store enforces BEFORE ever touching the pool — the
    // db_error PREFIX contract on a genuine store failure is exercised
    // end-to-end by the construction-fails-closed test above.
    auto applied = store.mark_endpoint_applied("", /*record_id=*/0, 1000);
    REQUIRE_FALSE(applied.has_value());
    CHECK(applied.error() == "agent_id is required");

    auto confirmed = store.mark_endpoint_confirmed("", /*record_id=*/0, 1000);
    REQUIRE_FALSE(confirmed.has_value());
    CHECK(confirmed.error() == "agent_id is required");
}

// UP-7 pattern (test_api_token_store.cpp's v2->v3 case): every other test in
// this file clones `quarantine_tpl`, already at v2 — the real v1->v2 upgrade
// path (PgMigrationRunner applying v2's ALTER against a genuinely-populated
// v1 table) is otherwise untested. Hand-seeds v1 DDL verbatim (copied from
// migrations() in quarantine_store.cpp, file-local and not exported), stamps
// schema_meta at v1, and inserts an active row BEFORE handing the database
// to a real QuarantineStore construction.
TEST_CASE("QuarantineStore: a genuine v1->v2 upgrade (real ALTER against a populated table) "
          "opens cleanly and the new columns default to 0 on the pre-existing row",
          "[pg][quarantine][store][migration]") {
    YUZU_REQUIRE_PG_DB(db);
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);

        PgResult meta{PQexec(conn.get(),
                             "CREATE TABLE public.schema_meta ("
                             "  store       TEXT PRIMARY KEY,"
                             "  version     INTEGER NOT NULL,"
                             "  upgraded_at BIGINT NOT NULL)")};
        REQUIRE(meta.ok());
        PgResult schema{PQexec(conn.get(), "CREATE SCHEMA quarantine_store")};
        REQUIRE(schema.ok());

        // v1 DDL, copied from migrations() in quarantine_store.cpp — but
        // SCHEMA-QUALIFIED throughout, unlike the source: the real
        // migration runs its unqualified DDL under a transaction whose
        // search_path PgMigrationRunner sets to the store schema (see that
        // file's own "Unqualified DDL" comment), which a raw PQexec on a
        // plain connection does NOT do (mirrors the api_token_store UP-7
        // precedent's own schema-qualified copy, for the identical reason).
        PgResult v1{PQexec(conn.get(),
                           "CREATE TABLE quarantine_store.quarantine_records ("
                           "  id              BIGSERIAL PRIMARY KEY,"
                           "  agent_id        TEXT NOT NULL,"
                           "  status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN "
                           "('active', 'released')),"
                           "  quarantined_by  TEXT NOT NULL DEFAULT '',"
                           "  quarantined_at  BIGINT NOT NULL DEFAULT 0,"
                           "  released_at     BIGINT NOT NULL DEFAULT 0,"
                           "  whitelist       TEXT NOT NULL DEFAULT '',"
                           "  reason          TEXT NOT NULL DEFAULT '');"
                           "CREATE INDEX idx_quarantine_agent ON "
                           "quarantine_store.quarantine_records(agent_id);"
                           "CREATE UNIQUE INDEX idx_quarantine_agent_active ON "
                           "quarantine_store.quarantine_records(agent_id) WHERE status = 'active';"
                           "CREATE TABLE quarantine_store.quarantine_meta ("
                           "  key   TEXT PRIMARY KEY,"
                           "  value TEXT NOT NULL"
                           ")")};
        REQUIRE(v1.ok());
        PgResult stamp{PQexec(conn.get(),
                              "INSERT INTO public.schema_meta (store, version, upgraded_at) "
                              "VALUES ('quarantine_store', 1, extract(epoch FROM now())::bigint)")};
        REQUIRE(stamp.ok());

        // A row genuinely present BEFORE the v2 ALTER runs.
        PgResult seed{PQexec(conn.get(),
                             "INSERT INTO quarantine_store.quarantine_records "
                             "(agent_id, status, quarantined_by, quarantined_at, whitelist, "
                             "reason) VALUES ('pre-v2-agent', 'active', 'admin', 1000, "
                             "'10.0.0.1', 'pre-upgrade')")};
        REQUIRE(seed.ok());
    }

    // The real construction path: PgMigrationRunner::run reads version 1
    // from schema_meta and applies v2's ALTER against the table seeded above.
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    // Pin the new columns from the OUTSIDE: get_status's kRecordCols
    // projection now includes both, and the pre-existing row reads 0/0 (the
    // DEFAULT), not an error.
    auto status = store.get_status("pre-v2-agent");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->quarantined_by == "admin"); // untouched by the ALTER
    CHECK((*status)->last_applied_at == 0);
    CHECK((*status)->last_confirmed_at == 0);

    // And mark_endpoint_applied/confirmed round-trip through the now-v2
    // schema end-to-end for that same pre-existing row.
    REQUIRE(store.mark_endpoint_applied("pre-v2-agent", (*status)->id, 5000).has_value());
    auto after = store.get_status("pre-v2-agent");
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK((*after)->last_applied_at == 5000);
}

// ── Mandatory backfill (ADR-0009, fingerprint-verified per ADR-0040/0047) ──

namespace {

struct LegacyRow {
    std::string agent_id, status, quarantined_by, whitelist, reason;
    std::int64_t quarantined_at{0}, released_at{0};
};

void make_legacy_quarantine_db(const std::filesystem::path& path,
                               const std::vector<LegacyRow>& rows) {
    yuzu::server::SqliteDb db;
    REQUIRE(sqlite3_open_v2(path.string().c_str(), db.addr(),
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
    const char* ddl =
        "CREATE TABLE quarantine_records (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "agent_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', quarantined_by TEXT, "
        "quarantined_at INTEGER NOT NULL DEFAULT 0, released_at INTEGER NOT NULL DEFAULT 0, "
        "whitelist TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL DEFAULT '');";
    REQUIRE(sqlite3_exec(db.get(), ddl, nullptr, nullptr, nullptr) == SQLITE_OK);
    for (const auto& r : rows) {
        yuzu::server::SqliteStmt s;
        REQUIRE(sqlite3_prepare_v2(db.get(),
                                   "INSERT INTO quarantine_records (agent_id, status, "
                                   "quarantined_by, quarantined_at, released_at, whitelist, "
                                   "reason) VALUES (?,?,?,?,?,?,?)",
                                   -1, s.addr(), nullptr) == SQLITE_OK);
        sqlite3_bind_text(s.get(), 1, r.agent_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 2, r.status.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 3, r.quarantined_by.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(s.get(), 4, r.quarantined_at);
        sqlite3_bind_int64(s.get(), 5, r.released_at);
        sqlite3_bind_text(s.get(), 6, r.whitelist.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 7, r.reason.c_str(), -1, SQLITE_TRANSIENT);
        REQUIRE(sqlite3_step(s.get()) == SQLITE_DONE);
    }
}

std::string scalar(const std::string& dsn, const std::string& sql) {
    PgConn c{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(c.get()) == CONNECTION_OK);
    PgResult r{PQexec(c.get(), sql.c_str())};
    REQUIRE(r.status() == PGRES_TUPLES_OK);
    return PQntuples(r.get()) ? std::string(PQgetvalue(r.get(), 0, 0)) : std::string{};
}

} // namespace

TEST_CASE("QuarantineStore: backfill of a no-legacy path marks fresh", "[pg][quarantine][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.migrate_from_sqlite("/nonexistent-yuzu-test/quarantine.db"));
    CHECK(scalar(db.dsn(), "SELECT value FROM quarantine_store.quarantine_meta WHERE key = "
                          "'backfill_complete'") != "");
    CHECK(scalar(db.dsn(), "SELECT value FROM quarantine_store.quarantine_meta WHERE key = "
                          "'backfill_source_fingerprint'") == "sourceless");
    // gov-fix(compliance-officer C-5): completeness evidence, queryable
    // post-boot, not just an implicit "boot succeeded".
    CHECK(scalar(db.dsn(), "SELECT value FROM quarantine_store.quarantine_meta WHERE key = "
                          "'backfill_row_count'") == "0");
}

TEST_CASE("QuarantineStore: backfill migrates legacy records (active + released) and is idempotent",
          "[pg][quarantine][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    yuzu::test::TempDbFile legacy{"yuzu_test_quarantine_legacy_"};
    std::filesystem::remove(legacy.path);
    make_legacy_quarantine_db(
        legacy.path,
        {LegacyRow{"agent-legacy-active", "active", "admin", "10.0.0.1", "Active record", 1000, 0},
         LegacyRow{"agent-legacy-released", "released", "admin", "", "Released record", 500, 900}});

    REQUIRE(store.migrate_from_sqlite(legacy.path));
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM quarantine_store.quarantine_records") == "2");
    CHECK(scalar(db.dsn(), "SELECT value FROM quarantine_store.quarantine_meta WHERE key = "
                          "'backfill_complete'") != "");
    // gov-fix(compliance-officer C-5): completeness evidence, queryable
    // post-boot, not just an implicit "boot succeeded".
    CHECK(scalar(db.dsn(), "SELECT value FROM quarantine_store.quarantine_meta WHERE key = "
                          "'backfill_row_count'") == "2");
    CHECK_FALSE(std::filesystem::exists(legacy.path)); // moved aside after verified backfill

    auto active = store.get_status("agent-legacy-active");
    REQUIRE(active.has_value());
    REQUIRE(active->has_value());
    CHECK((*active)->quarantined_by == "admin");
    CHECK((*active)->whitelist == "10.0.0.1");
    CHECK((*active)->quarantined_at == 1000);

    auto released_history = store.get_history("agent-legacy-released");
    REQUIRE(released_history.has_value());
    REQUIRE(released_history->size() == 1);
    CHECK((*released_history)[0].status == "released");
    CHECK((*released_history)[0].released_at == 900);

    // Second call short-circuits on the marker (legacy already gone).
    REQUIRE(store.migrate_from_sqlite(legacy.path));
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM quarantine_store.quarantine_records") == "2");
}

TEST_CASE("QuarantineStore: backfill refuses on a fingerprint mismatch (holder-side verification)",
          "[pg][quarantine][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};

    // "Replica A" migrates its own legacy file — stamps the real marker +
    // fingerprint, moves its file aside.
    {
        QuarantineStore store_a{pool};
        REQUIRE(store_a.is_open());
        yuzu::test::TempDbFile legacy_a{"yuzu_test_quarantine_fp_a_"};
        std::filesystem::remove(legacy_a.path);
        make_legacy_quarantine_db(
            legacy_a.path, {LegacyRow{"agent-fp-a", "active", "admin", "", "A", 1000, 0}});
        REQUIRE(store_a.migrate_from_sqlite(legacy_a.path));
    }

    // "Replica B" — same shared Postgres, but boots holding a DIFFERENT
    // legacy file with different real content, after the marker is already
    // stamped with Replica A's fingerprint.
    QuarantineStore store_b{pool};
    REQUIRE(store_b.is_open());
    yuzu::test::TempDbFile legacy_b{"yuzu_test_quarantine_fp_b_"};
    std::filesystem::remove(legacy_b.path);
    make_legacy_quarantine_db(
        legacy_b.path, {LegacyRow{"agent-fp-b", "active", "admin", "", "B", 2000, 0}});

    CHECK_FALSE(store_b.migrate_from_sqlite(legacy_b.path));
    // Refused, not silently accepted or silently re-migrated: Replica B's
    // file survives untouched, and its content never lands in Postgres.
    CHECK(std::filesystem::exists(legacy_b.path));
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM quarantine_store.quarantine_records WHERE "
                          "agent_id = 'agent-fp-b'") == "0");
}

TEST_CASE("QuarantineStore: backfill refuses a sourceless sibling's marker when this replica "
          "holds real legacy content",
          "[pg][quarantine][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};

    // "Replica A" — no local legacy file, stamps the shared marker sourceless.
    {
        QuarantineStore store_a{pool};
        REQUIRE(store_a.is_open());
        REQUIRE(store_a.migrate_from_sqlite("/nonexistent-yuzu-test/quarantine-a.db"));
    }

    // "Replica B" — same shared Postgres, genuinely holds a legacy file with
    // real content, boots AFTER the marker was already stamped sourceless.
    QuarantineStore store_b{pool};
    REQUIRE(store_b.is_open());
    yuzu::test::TempDbFile legacy{"yuzu_test_quarantine_sourceless_race_"};
    std::filesystem::remove(legacy.path);
    make_legacy_quarantine_db(
        legacy.path, {LegacyRow{"agent-src-race", "active", "admin", "", "R", 3000, 0}});

    CHECK_FALSE(store_b.migrate_from_sqlite(legacy.path));
    CHECK(std::filesystem::exists(legacy.path)); // untouched
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM quarantine_store.quarantine_records WHERE "
                          "agent_id = 'agent-src-race'") == "0");
}

TEST_CASE("QuarantineStore: backfill refuses a corrupt legacy file (fail-closed)",
          "[pg][quarantine][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    yuzu::test::TempDbFile legacy{"yuzu_test_quarantine_corrupt_"};
    std::filesystem::remove(legacy.path);
    {
        std::ofstream f(legacy.path, std::ios::binary);
        f << "this is not a sqlite database";
    }

    CHECK_FALSE(store.migrate_from_sqlite(legacy.path));
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM quarantine_store.quarantine_records") == "0");
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM quarantine_store.quarantine_meta WHERE key = "
                          "'backfill_complete'") == "0");
    CHECK(std::filesystem::exists(legacy.path)); // left in place for the operator
}

TEST_CASE("QuarantineStore: backfill of a legacy db with no quarantine_records table marks fresh",
          "[pg][quarantine][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    yuzu::test::TempDbFile legacy{"yuzu_test_quarantine_empty_"};
    std::filesystem::remove(legacy.path);
    {
        yuzu::server::SqliteDb legacy_db;
        REQUIRE(sqlite3_open_v2(legacy.path.string().c_str(), legacy_db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        REQUIRE(sqlite3_exec(legacy_db.get(), "CREATE TABLE unrelated (x INTEGER)", nullptr,
                             nullptr, nullptr) == SQLITE_OK);
    }

    REQUIRE(store.migrate_from_sqlite(legacy.path));
    CHECK(scalar(db.dsn(), "SELECT value FROM quarantine_store.quarantine_meta WHERE key = "
                          "'backfill_source_fingerprint'") == "sourceless");
}

// A 0-byte file is a valid, empty SQLite database — indistinguishable
// downstream from the legitimate no-quarantine_records-table case unless
// caught explicitly. Never a fresh install (the old store only ever creates
// a file on first open).
TEST_CASE("QuarantineStore: backfill refuses a 0-byte legacy file (never a fresh install)",
          "[pg][quarantine][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    yuzu::test::TempDbFile legacy{"yuzu_test_quarantine_truncated_"};
    std::filesystem::remove(legacy.path);
    { std::ofstream f(legacy.path, std::ios::binary); } // create with zero bytes written

    CHECK_FALSE(store.migrate_from_sqlite(legacy.path));
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM quarantine_store.quarantine_meta WHERE key = "
                          "'backfill_complete'") == "0");
    CHECK(std::filesystem::exists(legacy.path)); // left in place for the operator
}

TEST_CASE("QuarantineStore: a 0-byte legacy file does not block boot once backfill already "
          "completed",
          "[pg][quarantine][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    yuzu::test::TempDbFile legacy{"yuzu_test_quarantine_poststray_"};
    std::filesystem::remove(legacy.path);
    make_legacy_quarantine_db(legacy.path,
                              {LegacyRow{"agent-poststray", "active", "admin", "", "R", 4000, 0}});
    REQUIRE(store.migrate_from_sqlite(legacy.path)); // real migration completes, marker stamped
    CHECK_FALSE(std::filesystem::exists(legacy.path)); // moved aside

    // A stray 0-byte file reappears at the same canonical path afterward.
    { std::ofstream f(legacy.path, std::ios::binary); }

    CHECK(store.migrate_from_sqlite(legacy.path)); // must NOT refuse boot
}

// Legacy enum-ish `status` values are validated BEFORE any row reaches
// Postgres — an unrecognised value fails the boot closed, never silently
// inserted (which the CHECK constraint would also reject, but with a less
// actionable error) or silently dropped.
TEST_CASE("QuarantineStore: backfill refuses an unrecognised legacy status value",
          "[pg][quarantine][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    yuzu::test::TempDbFile legacy{"yuzu_test_quarantine_badstatus_"};
    std::filesystem::remove(legacy.path);
    make_legacy_quarantine_db(
        legacy.path, {LegacyRow{"agent-bad-status", "pending", "admin", "", "R", 5000, 0}});

    CHECK_FALSE(store.migrate_from_sqlite(legacy.path));
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM quarantine_store.quarantine_records") == "0");
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM quarantine_store.quarantine_meta WHERE key = "
                          "'backfill_complete'") == "0");
    CHECK(std::filesystem::exists(legacy.path)); // left in place for the operator
}

// gov Gate 2 (security-guardian): the legacy SQLite schema never enforced "at
// most one active record per agent" at the database level (only the
// in-process mutex this migration retires did), so a legacy file could hold
// a duplicate from pre-existing corruption or a hand-edited file. Without a
// pre-check this would abort mid-transaction on a raw Postgres unique-
// constraint-violation error instead of a named, actionable log line.
TEST_CASE("QuarantineStore: backfill refuses a legacy file with two active records for the "
          "same agent",
          "[pg][quarantine][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, quarantine_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    QuarantineStore store{pool};
    REQUIRE(store.is_open());

    yuzu::test::TempDbFile legacy{"yuzu_test_quarantine_dupactive_"};
    std::filesystem::remove(legacy.path);
    make_legacy_quarantine_db(
        legacy.path,
        {LegacyRow{"agent-dup", "active", "admin", "", "First", 1000, 0},
         LegacyRow{"agent-dup", "active", "security-team", "10.0.0.1", "Second", 2000, 0}});

    CHECK_FALSE(store.migrate_from_sqlite(legacy.path));
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM quarantine_store.quarantine_records") == "0");
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM quarantine_store.quarantine_meta WHERE key = "
                          "'backfill_complete'") == "0");
    CHECK(std::filesystem::exists(legacy.path)); // left in place for the operator
}
