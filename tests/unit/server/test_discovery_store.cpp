/**
 * test_discovery_store.cpp — `DiscoveryStore` (network-discovered devices,
 * Issue 7.18). Migrated Postgres store (ADR-0006/0009, schema
 * `discovery_store`).
 *
 * Covers:
 *  - upsert ON CONFLICT semantics: mac_address/last_seen/subnet always
 *    refresh; hostname refreshes only when the new value is non-empty;
 *    discovered_at/discovered_by/managed/agent_id are untouched by a re-scan.
 *  - list_devices: all devices and subnet-filtered, newest-last-seen-first.
 *  - get_device: found, genuinely-absent (nullopt value, not an error), and
 *    empty ip_address (precondition miss, not a store failure).
 *  - mark_managed: success and not_found: prefix on an unknown ip_address.
 *  - clear_results: all rows and subnet-scoped.
 *  - fail-closed construction (migration-drift case).
 *  - MANDATORY backfill (ADR-0009): fresh install marks complete with no
 *    legacy file; migrates legacy rows and is idempotent on re-run; refuses
 *    (fail-closed) on a corrupt legacy file.
 *
 * Migrated Postgres store (ADR-0043, authoritative/fail-hard per ADR-0012
 * §1). PG-gated: skips when YUZU_TEST_POSTGRES_DSN is unset, fails when set
 * but broken (test_helpers.hpp skip-vs-fail contract). Store-behaviour cases
 * use the pre-migrated PgTestTemplate variant
 * (docs/postgres-store-playbook.md step 7); the fail-closed construction
 * case uses plain YUZU_REQUIRE_PG_DB, per the plain-migration-test carve-out
 * documented on that macro.
 */

#include "discovery_store.hpp"

#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "sqlite_raii.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>
#include <sqlite3.h>

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

using yuzu::server::DiscoveredDevice;
using yuzu::server::DiscoveryStore;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

yuzu::test::PgTestTemplate discovery_tpl{"discoverystore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    DiscoveryStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("discovery_store template: store failed to migrate");
}};

DiscoveredDevice make_device(const std::string& ip, const std::string& subnet = "10.0.0.0/24") {
    DiscoveredDevice d;
    d.ip_address = ip;
    d.mac_address = "aa:bb:cc:dd:ee:ff";
    d.hostname = "host-" + ip;
    d.discovered_by = "agent-scanner";
    d.subnet = subnet;
    return d;
}

const DiscoveredDevice* find(const std::vector<DiscoveredDevice>& v, const std::string& ip) {
    for (const auto& d : v)
        if (d.ip_address == ip)
            return &d;
    return nullptr;
}

} // namespace

// ── Construction fail-closed ────────────────────────────────────────────────

TEST_CASE("DiscoveryStore: construction fails closed on migration drift", "[pg][discovery]") {
    YUZU_REQUIRE_PG_DB(db);

    // Pre-seed: create the discovery_store schema + a conflicting table, but
    // no public.schema_meta row — the drift guard refuses (version 0 but
    // tables exist).
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult s{PQexec(conn.get(), "CREATE SCHEMA discovery_store")};
        REQUIRE(s.ok());
        PgResult t{PQexec(conn.get(), "CREATE TABLE discovery_store.discovered_devices (bogus int)")};
        REQUIRE(t.ok());
    }

    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    DiscoveryStore store{pool};
    CHECK_FALSE(store.is_open()); // → server.cpp sets startup_failed_ = true
}

// ── CRUD ─────────────────────────────────────────────────────────────────────

TEST_CASE("DiscoveryStore: upsert and list/get", "[pg][discovery][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, discovery_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DiscoveryStore store{pool};
    REQUIRE(store.is_open());

    SECTION("upsert then list finds the device") {
        auto d = make_device("10.0.0.5");
        REQUIRE(store.upsert_device(d));

        auto rows = store.list_devices();
        REQUIRE(rows.has_value());
        const auto* found = find(*rows, "10.0.0.5");
        REQUIRE(found != nullptr);
        CHECK(found->mac_address == "aa:bb:cc:dd:ee:ff");
        CHECK(found->hostname == "host-10.0.0.5");
        CHECK(found->subnet == "10.0.0.0/24");
        CHECK(found->managed == false);
        CHECK(found->discovered_at > 0);
        CHECK(found->last_seen > 0);
    }

    SECTION("an explicit discovered_at in the past does not also skew last_seen") {
        // Regression: discovered_at and last_seen must bind as SEPARATE
        // parameters. A caller-supplied discovered_at far in the past must
        // not leak into last_seen (which is always "now" on every call,
        // independent of discovered_at).
        auto d = make_device("10.0.0.8");
        d.discovered_at = 1000; // a fixed, clearly-in-the-past epoch second
        REQUIRE(store.upsert_device(d));

        auto got = store.get_device("10.0.0.8");
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        CHECK((*got)->discovered_at == 1000);
        CHECK((*got)->last_seen > 1000); // last_seen tracks "now", not discovered_at
    }

    SECTION("a fresh insert honors caller-supplied managed/agent_id") {
        // Regression: managed/agent_id must be part of the INSERT column
        // list — the "untouched by a re-scan" ON CONFLICT guarantee applies
        // only to an ALREADY-EXISTING row, never to a device's first insert.
        auto d = make_device("10.0.0.9");
        d.managed = true;
        d.agent_id = "agent-preexisting";
        REQUIRE(store.upsert_device(d));

        auto got = store.get_device("10.0.0.9");
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        CHECK((*got)->managed == true);
        CHECK((*got)->agent_id == "agent-preexisting");
    }

    SECTION("upsert on same ip_address overwrites mac/last_seen/subnet, preserves discovered_at") {
        auto first = make_device("10.0.0.6");
        REQUIRE(store.upsert_device(first));
        auto after_first = store.get_device("10.0.0.6");
        REQUIRE(after_first.has_value());
        REQUIRE(after_first->has_value());
        const auto discovered_at_1 = (*after_first)->discovered_at;

        auto second = make_device("10.0.0.6", "10.0.1.0/24");
        second.mac_address = "11:22:33:44:55:66";
        REQUIRE(store.upsert_device(second));

        auto rows = store.list_devices();
        REQUIRE(rows.has_value());
        const auto* found = find(*rows, "10.0.0.6");
        REQUIRE(found != nullptr);
        CHECK(found->mac_address == "11:22:33:44:55:66");
        CHECK(found->subnet == "10.0.1.0/24");
        // Exactly one row (PK conflict updated in place, not a new row).
        int count = 0;
        for (const auto& r : *rows)
            if (r.ip_address == "10.0.0.6")
                ++count;
        CHECK(count == 1);
        // discovered_at is first-seen, untouched by the re-scan.
        CHECK(found->discovered_at == discovered_at_1);
    }

    SECTION("upsert with empty hostname does not blank out a previously known one") {
        auto first = make_device("10.0.0.7");
        first.hostname = "known-host";
        REQUIRE(store.upsert_device(first));

        auto second = make_device("10.0.0.7");
        second.hostname = ""; // scan could not resolve a hostname this time
        REQUIRE(store.upsert_device(second));

        auto got = store.get_device("10.0.0.7");
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        CHECK((*got)->hostname == "known-host");
    }

    SECTION("upsert with empty ip_address is rejected") {
        DiscoveredDevice d;
        d.ip_address = "";
        auto r = store.upsert_device(d);
        CHECK_FALSE(r.has_value());
    }

    SECTION("list_devices filters by subnet") {
        REQUIRE(store.upsert_device(make_device("10.0.2.1", "10.0.2.0/24")));
        REQUIRE(store.upsert_device(make_device("10.0.3.1", "10.0.3.0/24")));

        auto filtered = store.list_devices("10.0.2.0/24");
        REQUIRE(filtered.has_value());
        CHECK(find(*filtered, "10.0.2.1") != nullptr);
        CHECK(find(*filtered, "10.0.3.1") == nullptr);
    }

    SECTION("get_device on a genuinely absent ip_address returns a value holding nullopt") {
        auto got = store.get_device("192.168.99.99");
        REQUIRE(got.has_value()); // the READ succeeded
        CHECK_FALSE(got->has_value()); // ...it just found nothing
    }

    SECTION("get_device with empty ip_address returns nullopt without a store round-trip") {
        auto got = store.get_device("");
        REQUIRE(got.has_value());
        CHECK_FALSE(got->has_value());
    }
}

TEST_CASE("DiscoveryStore: mark_managed", "[pg][discovery][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, discovery_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DiscoveryStore store{pool};
    REQUIRE(store.is_open());

    SECTION("marks an existing device managed") {
        REQUIRE(store.upsert_device(make_device("10.0.4.1")));
        REQUIRE(store.mark_managed("10.0.4.1", "agent-123"));

        auto got = store.get_device("10.0.4.1");
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        CHECK((*got)->managed == true);
        CHECK((*got)->agent_id == "agent-123");
    }

    SECTION("unknown ip_address reports not_found") {
        auto r = store.mark_managed("10.0.4.99", "agent-x");
        REQUIRE_FALSE(r.has_value());
        CHECK(r.error().starts_with("not_found:"));
    }

    SECTION("a re-scan after mark_managed does not clear managed/agent_id") {
        REQUIRE(store.upsert_device(make_device("10.0.4.2")));
        REQUIRE(store.mark_managed("10.0.4.2", "agent-456"));
        REQUIRE(store.upsert_device(make_device("10.0.4.2")));

        auto got = store.get_device("10.0.4.2");
        REQUIRE(got.has_value());
        REQUIRE(got->has_value());
        CHECK((*got)->managed == true);
        CHECK((*got)->agent_id == "agent-456");
    }
}

TEST_CASE("DiscoveryStore: clear_results", "[pg][discovery][crud]") {
    YUZU_REQUIRE_PG_DB_TPL(db, discovery_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DiscoveryStore store{pool};
    REQUIRE(store.is_open());

    SECTION("clears one subnet only") {
        REQUIRE(store.upsert_device(make_device("10.0.5.1", "10.0.5.0/24")));
        REQUIRE(store.upsert_device(make_device("10.0.6.1", "10.0.6.0/24")));
        REQUIRE(store.clear_results("10.0.5.0/24"));

        auto rows = store.list_devices();
        REQUIRE(rows.has_value());
        CHECK(find(*rows, "10.0.5.1") == nullptr);
        CHECK(find(*rows, "10.0.6.1") != nullptr);
    }

    SECTION("clears everything when no subnet given") {
        REQUIRE(store.upsert_device(make_device("10.0.7.1")));
        REQUIRE(store.upsert_device(make_device("10.0.7.2")));
        REQUIRE(store.clear_results());

        auto rows = store.list_devices();
        REQUIRE(rows.has_value());
        CHECK(find(*rows, "10.0.7.1") == nullptr);
        CHECK(find(*rows, "10.0.7.2") == nullptr);
    }
}

// ── Mandatory backfill (ADR-0009, fingerprint-verified per ADR-0040/#2703) ──

namespace {

void make_legacy_discovery_db(const std::filesystem::path& path,
                              const std::vector<DiscoveredDevice>& devices) {
    yuzu::server::SqliteDb db;
    REQUIRE(sqlite3_open_v2(path.string().c_str(), db.addr(),
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
    const char* ddl =
        "CREATE TABLE discovered_devices (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "ip_address TEXT NOT NULL UNIQUE, mac_address TEXT, hostname TEXT, managed INTEGER, "
        "agent_id TEXT, discovered_by TEXT, discovered_at INTEGER, last_seen INTEGER, "
        "subnet TEXT);";
    REQUIRE(sqlite3_exec(db.get(), ddl, nullptr, nullptr, nullptr) == SQLITE_OK);
    for (const auto& d : devices) {
        yuzu::server::SqliteStmt s;
        REQUIRE(sqlite3_prepare_v2(db.get(),
                                   "INSERT INTO discovered_devices (ip_address, mac_address, "
                                   "hostname, managed, agent_id, discovered_by, discovered_at, "
                                   "last_seen, subnet) VALUES (?,?,?,?,?,?,?,?,?)",
                                   -1, s.addr(), nullptr) == SQLITE_OK);
        sqlite3_bind_text(s.get(), 1, d.ip_address.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 2, d.mac_address.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 3, d.hostname.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(s.get(), 4, d.managed ? 1 : 0);
        sqlite3_bind_text(s.get(), 5, d.agent_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(s.get(), 6, d.discovered_by.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(s.get(), 7, d.discovered_at);
        sqlite3_bind_int64(s.get(), 8, d.last_seen);
        sqlite3_bind_text(s.get(), 9, d.subnet.c_str(), -1, SQLITE_TRANSIENT);
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

TEST_CASE("DiscoveryStore: backfill of a no-legacy path marks fresh", "[pg][discovery][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, discovery_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DiscoveryStore store{pool};
    REQUIRE(store.is_open());

    REQUIRE(store.migrate_from_sqlite("/nonexistent-yuzu-test/discovery.db"));
    CHECK(scalar(db.dsn(), "SELECT value FROM discovery_store.discovery_meta WHERE key = "
                          "'backfill_complete'") != "");
    CHECK(scalar(db.dsn(), "SELECT value FROM discovery_store.discovery_meta WHERE key = "
                          "'backfill_source_fingerprint'") == "sourceless");
}

TEST_CASE("DiscoveryStore: backfill migrates legacy devices and is idempotent",
          "[pg][discovery][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, discovery_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DiscoveryStore store{pool};
    REQUIRE(store.is_open());

    yuzu::test::TempDbFile legacy{"yuzu_test_discovery_legacy_"};
    std::filesystem::remove(legacy.path);
    std::vector<DiscoveredDevice> devices;
    auto managed = make_device("192.168.1.10");
    managed.managed = true;
    managed.agent_id = "agent-legacy";
    managed.discovered_at = 1000;
    managed.last_seen = 2000;
    devices.push_back(managed);
    devices.push_back(make_device("192.168.1.11"));
    make_legacy_discovery_db(legacy.path, devices);

    REQUIRE(store.migrate_from_sqlite(legacy.path));
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM discovery_store.discovered_devices") == "2");
    CHECK(scalar(db.dsn(), "SELECT value FROM discovery_store.discovery_meta WHERE key = "
                          "'backfill_complete'") != "");
    CHECK_FALSE(std::filesystem::exists(legacy.path)); // moved aside after verified backfill

    auto got = store.get_device("192.168.1.10");
    REQUIRE(got.has_value());
    REQUIRE(got->has_value());
    CHECK((*got)->managed == true);
    CHECK((*got)->agent_id == "agent-legacy");
    CHECK((*got)->discovered_at == 1000);
    CHECK((*got)->last_seen == 2000);

    // Second call short-circuits on the marker (legacy already gone).
    REQUIRE(store.migrate_from_sqlite(legacy.path));
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM discovery_store.discovered_devices") == "2");
}

// Holder-side verification, mismatch branch (mirrors
// test_rbac_store.cpp's "verifies a matching fingerprint" test's negative
// counterpart): a SECOND store instance against the SAME already-migrated
// Postgres database, holding its OWN legacy file with DIFFERENT real
// content, must refuse rather than silently accept a completion its own
// devices were never part of.
TEST_CASE("DiscoveryStore: backfill refuses on a fingerprint mismatch (holder-side verification)",
          "[pg][discovery][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, discovery_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};

    // "Replica A" migrates its own legacy file — stamps the real marker +
    // fingerprint, moves its file aside.
    {
        DiscoveryStore store_a{pool};
        REQUIRE(store_a.is_open());
        yuzu::test::TempDbFile legacy_a{"yuzu_test_discovery_fp_a_"};
        std::filesystem::remove(legacy_a.path);
        make_legacy_discovery_db(legacy_a.path, {make_device("10.1.1.1")});
        REQUIRE(store_a.migrate_from_sqlite(legacy_a.path));
    }

    // "Replica B" — same shared Postgres, but boots holding a DIFFERENT
    // legacy file with different real content, after the marker is already
    // stamped with Replica A's fingerprint.
    DiscoveryStore store_b{pool};
    REQUIRE(store_b.is_open());
    yuzu::test::TempDbFile legacy_b{"yuzu_test_discovery_fp_b_"};
    std::filesystem::remove(legacy_b.path);
    make_legacy_discovery_db(legacy_b.path, {make_device("10.2.2.2")});

    CHECK_FALSE(store_b.migrate_from_sqlite(legacy_b.path));
    // Refused, not silently accepted or silently re-migrated: Replica B's
    // file survives untouched, and its content never lands in Postgres.
    CHECK(std::filesystem::exists(legacy_b.path));
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM discovery_store.discovered_devices "
                          "WHERE ip_address = '10.2.2.2'") == "0");
}

// Holder-side verification, sourceless-marker branch (mirrors
// test_rbac_store.cpp's "refuses a sourceless sibling's marker on a later
// boot" test): a fileless sibling stamps the marker sourceless first; a
// later replica that DOES hold real content must refuse rather than
// fall-through and migrate on top of state the store may have already
// accepted live (e.g. a scan that landed between the two boots).
TEST_CASE("DiscoveryStore: backfill refuses a sourceless sibling's marker when this replica holds "
          "real legacy content",
          "[pg][discovery][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, discovery_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};

    // "Replica A" — no local legacy file, stamps the shared marker sourceless.
    {
        DiscoveryStore store_a{pool};
        REQUIRE(store_a.is_open());
        REQUIRE(store_a.migrate_from_sqlite("/nonexistent-yuzu-test/discovery-a.db"));
    }

    // "Replica B" — same shared Postgres, genuinely holds a legacy file with
    // real content, boots AFTER the marker was already stamped sourceless.
    DiscoveryStore store_b{pool};
    REQUIRE(store_b.is_open());
    yuzu::test::TempDbFile legacy{"yuzu_test_discovery_sourceless_race_"};
    std::filesystem::remove(legacy.path);
    make_legacy_discovery_db(legacy.path, {make_device("10.3.3.3")});

    CHECK_FALSE(store_b.migrate_from_sqlite(legacy.path));
    CHECK(std::filesystem::exists(legacy.path)); // untouched
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM discovery_store.discovered_devices "
                          "WHERE ip_address = '10.3.3.3'") == "0");
}

TEST_CASE("DiscoveryStore: backfill refuses a corrupt legacy file (fail-closed)",
          "[pg][discovery][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, discovery_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DiscoveryStore store{pool};
    REQUIRE(store.is_open());

    yuzu::test::TempDbFile legacy{"yuzu_test_discovery_corrupt_"};
    std::filesystem::remove(legacy.path);
    {
        std::ofstream f(legacy.path, std::ios::binary);
        f << "this is not a sqlite database";
    }

    CHECK_FALSE(store.migrate_from_sqlite(legacy.path));
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM discovery_store.discovered_devices") == "0");
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM discovery_store.discovery_meta WHERE key = "
                          "'backfill_complete'") == "0");
    CHECK(std::filesystem::exists(legacy.path)); // left in place for the operator
}

TEST_CASE("DiscoveryStore: backfill of a legacy db with no discovered_devices table marks fresh",
          "[pg][discovery][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, discovery_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DiscoveryStore store{pool};
    REQUIRE(store.is_open());

    yuzu::test::TempDbFile legacy{"yuzu_test_discovery_empty_"};
    std::filesystem::remove(legacy.path);
    {
        yuzu::server::SqliteDb legacy_db;
        REQUIRE(sqlite3_open_v2(legacy.path.string().c_str(), legacy_db.addr(),
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK);
        REQUIRE(sqlite3_exec(legacy_db.get(), "CREATE TABLE unrelated (x INTEGER)", nullptr,
                             nullptr, nullptr) == SQLITE_OK);
    }

    REQUIRE(store.migrate_from_sqlite(legacy.path));
    CHECK(scalar(db.dsn(), "SELECT value FROM discovery_store.discovery_meta WHERE key = "
                          "'backfill_source_fingerprint'") == "sourceless");
}

// A 0-byte file is a valid, empty SQLite database — indistinguishable
// downstream from the legitimate no-discovered_devices-table case unless
// caught explicitly. Unlike that case, a 0-byte file is never a fresh
// install (the old store only ever creates a file on first open), so it
// must refuse rather than silently take the "nothing to lose" path and
// mask a truncated real database as a clean fresh boot.
TEST_CASE("DiscoveryStore: backfill refuses a 0-byte legacy file (never a fresh install)",
          "[pg][discovery][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, discovery_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DiscoveryStore store{pool};
    REQUIRE(store.is_open());

    yuzu::test::TempDbFile legacy{"yuzu_test_discovery_truncated_"};
    std::filesystem::remove(legacy.path);
    { std::ofstream f(legacy.path, std::ios::binary); } // create with zero bytes written

    CHECK_FALSE(store.migrate_from_sqlite(legacy.path));
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM discovery_store.discovery_meta WHERE key = "
                          "'backfill_complete'") == "0");
    CHECK(std::filesystem::exists(legacy.path)); // left in place for the operator
}

// Content-aware reconciliation (row-count reconciliation alone cannot see
// this): a device already present in Postgres — standing in for a
// concurrent writer, e.g. a fileless sibling replica that already stamped
// its own sourceless marker and started serving live scans — steals the
// ON CONFLICT DO NOTHING slot for an IP this replica's legacy file records
// as managed=true. The backfill must refuse rather than stamp a marker
// that silently dropped the operator-set managed flag behind a row count
// that still balances.
TEST_CASE("DiscoveryStore: backfill refuses when a conflict-skipped row lost a legacy "
          "managed=true flag",
          "[pg][discovery][backfill]") {
    YUZU_REQUIRE_PG_DB_TPL(db, discovery_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    DiscoveryStore store{pool};
    REQUIRE(store.is_open());

    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{PQexec(conn.get(),
            "INSERT INTO discovery_store.discovered_devices "
            "(ip_address, mac_address, hostname, managed, agent_id, discovered_by, "
            "discovered_at, last_seen, subnet) VALUES "
            "('192.168.5.50', 'aa:bb:cc:00:00:01', 'live-host', false, '', 'live-scan', "
            "5000, 5000, '10.0.0.0/24')")};
        REQUIRE(r.ok());
    }

    yuzu::test::TempDbFile legacy{"yuzu_test_discovery_race_"};
    std::filesystem::remove(legacy.path);
    auto managed = make_device("192.168.5.50");
    managed.managed = true;
    managed.discovered_at = 1000;
    make_legacy_discovery_db(legacy.path, {managed});

    CHECK_FALSE(store.migrate_from_sqlite(legacy.path));
    // Refused, not silently accepted: the legacy file survives, no marker
    // is stamped, and the row already in Postgres keeps its managed=false —
    // never silently promoted OR silently trusted as the full migration.
    CHECK(std::filesystem::exists(legacy.path));
    CHECK(scalar(db.dsn(), "SELECT count(*) FROM discovery_store.discovery_meta WHERE key = "
                          "'backfill_complete'") == "0");
    CHECK(scalar(db.dsn(), "SELECT managed FROM discovery_store.discovered_devices WHERE "
                          "ip_address = '192.168.5.50'") == "f");
}
