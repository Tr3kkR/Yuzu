#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include "migration_runner.hpp"

using yuzu::server::Migration;
using yuzu::server::MigrationRunner;

namespace {

/// RAII wrapper around an in-memory SQLite handle for migration tests.
/// Uses `sqlite3_open_v2` + `SQLITE_OPEN_FULLMUTEX` to match the flags
/// used by every production store (see CLAUDE.md Darwin section). The
/// tests are single-threaded so the extra mutex is cheap but keeps the
/// test path from diverging from the production path.
struct TestDb {
    sqlite3* db = nullptr;
    TestDb() {
        sqlite3_open_v2(":memory:", &db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                        nullptr);
        REQUIRE(db != nullptr);
    }
    ~TestDb() {
        if (db)
            sqlite3_close(db);
    }
};

int count_rows(sqlite3* db, const char* table) {
    std::string sql = "SELECT COUNT(*) FROM " + std::string(table);
    sqlite3_stmt* stmt = nullptr;
    // A failed prepare (e.g. table missing due to a test typo) must be loud,
    // not silently return 0 — that would mask false-passing assertions.
    REQUIRE(sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK);
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

bool column_exists(sqlite3* db, const char* table, const char* column) {
    std::string sql = "PRAGMA table_info(" + std::string(table) + ")";
    sqlite3_stmt* stmt = nullptr;
    REQUIRE(sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        if (name && std::string(name) == column) {
            sqlite3_finalize(stmt);
            return true;
        }
    }
    sqlite3_finalize(stmt);
    return false;
}

} // namespace

TEST_CASE("MigrationRunner — empty migrations", "[migration]") {
    TestDb t;
    REQUIRE(MigrationRunner::run(t.db, "test_store", {}));
}

TEST_CASE("MigrationRunner — null db", "[migration]") {
    REQUIRE(MigrationRunner::run(nullptr, "test_store", {}));
}

TEST_CASE("MigrationRunner — single migration creates table", "[migration]") {
    TestDb t;
    std::vector<Migration> migrations = {
        {1, "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);"},
    };

    REQUIRE(MigrationRunner::run(t.db, "items_store", migrations));
    REQUIRE(MigrationRunner::current_version(t.db, "items_store") == 1);

    // Table should exist
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(t.db, "INSERT INTO items (name) VALUES ('test')", -1, &stmt, nullptr);
    REQUIRE(sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
}

TEST_CASE("MigrationRunner — sequential migrations", "[migration]") {
    TestDb t;
    std::vector<Migration> migrations = {
        {1, "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);"},
        {2, "ALTER TABLE items ADD COLUMN description TEXT;"},
        {3, "CREATE INDEX idx_items_name ON items(name);"},
    };

    REQUIRE(MigrationRunner::run(t.db, "items_store", migrations));
    REQUIRE(MigrationRunner::current_version(t.db, "items_store") == 3);
    REQUIRE(column_exists(t.db, "items", "description"));
}

TEST_CASE("MigrationRunner — idempotent re-run", "[migration]") {
    TestDb t;
    std::vector<Migration> migrations = {
        {1, "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);"},
    };

    REQUIRE(MigrationRunner::run(t.db, "items_store", migrations));
    REQUIRE(MigrationRunner::current_version(t.db, "items_store") == 1);

    // Running again should be a no-op
    REQUIRE(MigrationRunner::run(t.db, "items_store", migrations));
    REQUIRE(MigrationRunner::current_version(t.db, "items_store") == 1);
}

TEST_CASE("MigrationRunner — incremental migration", "[migration]") {
    TestDb t;

    // First run: v1 only
    std::vector<Migration> v1 = {
        {1, "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);"},
    };
    REQUIRE(MigrationRunner::run(t.db, "items_store", v1));
    REQUIRE(MigrationRunner::current_version(t.db, "items_store") == 1);

    // Insert data at v1
    sqlite3_exec(t.db, "INSERT INTO items (name) VALUES ('existing')", nullptr, nullptr, nullptr);

    // Second run: v1 + v2 — should only run v2
    std::vector<Migration> v1_v2 = {
        {1, "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);"},
        {2, "ALTER TABLE items ADD COLUMN status TEXT DEFAULT 'active';"},
    };
    REQUIRE(MigrationRunner::run(t.db, "items_store", v1_v2));
    REQUIRE(MigrationRunner::current_version(t.db, "items_store") == 2);
    REQUIRE(column_exists(t.db, "items", "status"));

    // Existing data preserved
    REQUIRE(count_rows(t.db, "items") == 1);
}

TEST_CASE("MigrationRunner — bad SQL rolls back", "[migration]") {
    TestDb t;
    std::vector<Migration> migrations = {
        {1, "CREATE TABLE items (id INTEGER PRIMARY KEY);"},
        {2, "THIS IS NOT VALID SQL;"},
    };

    // v1 succeeds, v2 fails
    REQUIRE_FALSE(MigrationRunner::run(t.db, "items_store", migrations));

    // v1 should still be recorded (it committed before v2 was attempted)
    REQUIRE(MigrationRunner::current_version(t.db, "items_store") == 1);
}

TEST_CASE("MigrationRunner — multiple stores independent", "[migration]") {
    TestDb t;

    std::vector<Migration> store_a = {
        {1, "CREATE TABLE table_a (id INTEGER PRIMARY KEY);"},
    };
    std::vector<Migration> store_b = {
        {1, "CREATE TABLE table_b (id INTEGER PRIMARY KEY);"},
        {2, "ALTER TABLE table_b ADD COLUMN value TEXT;"},
    };

    REQUIRE(MigrationRunner::run(t.db, "store_a", store_a));
    REQUIRE(MigrationRunner::run(t.db, "store_b", store_b));

    REQUIRE(MigrationRunner::current_version(t.db, "store_a") == 1);
    REQUIRE(MigrationRunner::current_version(t.db, "store_b") == 2);
}

TEST_CASE("MigrationRunner — untracked store returns version 0", "[migration]") {
    TestDb t;
    // Ensure meta table exists
    std::vector<Migration> dummy = {{1, "SELECT 1;"}};
    MigrationRunner::run(t.db, "dummy", dummy);

    REQUIRE(MigrationRunner::current_version(t.db, "nonexistent") == 0);
}

// ── Adoption scenarios (#339) ────────────────────────────────────────────────
// These exercise the path a v0.10 server takes when it opens a database that
// was created by an earlier build (pre-MigrationRunner-adoption): tables
// already exist, schema_meta does not, and v1's CREATE TABLE IF NOT EXISTS
// must be a safe no-op that only stamps the version.

TEST_CASE("MigrationRunner — adoption on pre-existing tables preserves data",
          "[migration][adoption]") {
    TestDb t;

    // Simulate pre-runner state: tables exist with data, no schema_meta row.
    sqlite3_exec(t.db,
                 "CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT);"
                 "INSERT INTO widgets (name) VALUES ('hammer');"
                 "INSERT INTO widgets (name) VALUES ('wrench');",
                 nullptr, nullptr, nullptr);

    REQUIRE(MigrationRunner::current_version(t.db, "widget_store") == 0);
    REQUIRE(count_rows(t.db, "widgets") == 2);

    // Adoption: v1 contains latest full schema as CREATE TABLE IF NOT EXISTS.
    std::vector<Migration> v1 = {
        {1, "CREATE TABLE IF NOT EXISTS widgets (id INTEGER PRIMARY KEY, name TEXT);"},
    };
    REQUIRE(MigrationRunner::run(t.db, "widget_store", v1));

    // Schema stamped at v1 and pre-existing data preserved.
    REQUIRE(MigrationRunner::current_version(t.db, "widget_store") == 1);
    REQUIRE(count_rows(t.db, "widgets") == 2);
}

TEST_CASE("MigrationRunner — adoption on fresh DB creates latest schema",
          "[migration][adoption]") {
    TestDb t;

    // v1 bakes in a column that would historically have been added by ALTER.
    std::vector<Migration> v1 = {
        {1, "CREATE TABLE IF NOT EXISTS widgets ("
            "  id INTEGER PRIMARY KEY,"
            "  name TEXT,"
            "  category TEXT NOT NULL DEFAULT ''"
            ");"},
    };
    REQUIRE(MigrationRunner::run(t.db, "widget_store", v1));
    REQUIRE(MigrationRunner::current_version(t.db, "widget_store") == 1);
    REQUIRE(column_exists(t.db, "widgets", "category"));
}

TEST_CASE("MigrationRunner — bad migration statement leaves clean connection state",
          "[migration][adoption]") {
    // This exercises the sqlite3_exec-failure path (bad DDL at line 100 of
    // migration_runner.cpp), not the COMMIT-failure path. Both paths call
    // ROLLBACK, but the sqlite3_exec path is the common case and the one
    // unit-testable without multi-process/multi-connection setup. Driving
    // a real COMMIT failure requires holding a side-channel lock on the
    // same DB file — that belongs in the chaos suite, not unit tests.
    //
    // The invariant we verify here: a failed migration on store A must
    // leave the shared connection in a state where a fresh migration on
    // store B can start a new BEGIN IMMEDIATE without inheriting the
    // aborted transaction.
    TestDb t;

    std::vector<Migration> v1 = {
        {1, "CREATE TABLE IF NOT EXISTS widgets (id INTEGER PRIMARY KEY);"},
    };
    REQUIRE(MigrationRunner::run(t.db, "widget_store", v1));
    REQUIRE(MigrationRunner::current_version(t.db, "widget_store") == 1);

    // v2 is deliberately invalid SQL. The runner's sqlite3_exec fails,
    // the runner issues ROLLBACK, and the caller gets `false`.
    std::vector<Migration> v1_v2 = {
        {1, "CREATE TABLE IF NOT EXISTS widgets (id INTEGER PRIMARY KEY);"},
        {2, "THIS IS NOT VALID SQL;"},
    };
    REQUIRE_FALSE(MigrationRunner::run(t.db, "widget_store", v1_v2));
    REQUIRE(MigrationRunner::current_version(t.db, "widget_store") == 1);

    // Prove the connection isn't stuck in a half-transaction by running
    // a fresh BEGIN/COMMIT via another store. If the rollback hadn't
    // cleared the transaction state, this would fail with SQLITE_ERROR
    // "cannot start a transaction within a transaction".
    std::vector<Migration> gadgets = {
        {1, "CREATE TABLE IF NOT EXISTS gadgets (id INTEGER PRIMARY KEY);"},
    };
    REQUIRE(MigrationRunner::run(t.db, "gadget_store", gadgets));
    REQUIRE(MigrationRunner::current_version(t.db, "gadget_store") == 1);
}

TEST_CASE("MigrationRunner — legacy compat shim + v1 adoption stays idempotent",
          "[migration][adoption]") {
    TestDb t;

    // Pre-runner DB: the old base schema, missing a column that a later
    // release added via a silent ALTER.
    sqlite3_exec(t.db,
                 "CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT);"
                 "INSERT INTO widgets (name) VALUES ('gasket');",
                 nullptr, nullptr, nullptr);

    // Legacy compat shim: apply the historical ALTER before the runner.
    // ADD COLUMN is idempotent here because the column is missing on the
    // simulated ancient DB; on a newer DB the duplicate-column error is
    // silently ignored by sqlite3_exec.
    sqlite3_exec(t.db,
                 "ALTER TABLE widgets ADD COLUMN category TEXT NOT NULL DEFAULT '';",
                 nullptr, nullptr, nullptr);

    std::vector<Migration> v1 = {
        {1, "CREATE TABLE IF NOT EXISTS widgets ("
            "  id INTEGER PRIMARY KEY,"
            "  name TEXT,"
            "  category TEXT NOT NULL DEFAULT ''"
            ");"},
    };
    REQUIRE(MigrationRunner::run(t.db, "widget_store", v1));
    REQUIRE(MigrationRunner::current_version(t.db, "widget_store") == 1);
    REQUIRE(column_exists(t.db, "widgets", "category"));
    REQUIRE(count_rows(t.db, "widgets") == 1);

    // Simulated restart: legacy shim runs again (silent duplicate-column
    // failure), runner sees v1 already stamped and does nothing.
    sqlite3_exec(t.db,
                 "ALTER TABLE widgets ADD COLUMN category TEXT NOT NULL DEFAULT '';",
                 nullptr, nullptr, nullptr);
    REQUIRE(MigrationRunner::run(t.db, "widget_store", v1));
    REQUIRE(MigrationRunner::current_version(t.db, "widget_store") == 1);
    REQUIRE(count_rows(t.db, "widgets") == 1);
}
