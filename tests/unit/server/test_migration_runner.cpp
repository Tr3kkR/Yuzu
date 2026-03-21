#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include "migration_runner.hpp"

using yuzu::server::Migration;
using yuzu::server::MigrationRunner;

namespace {

struct TestDb {
    sqlite3* db = nullptr;
    TestDb() { sqlite3_open(":memory:", &db); }
    ~TestDb() {
        if (db)
            sqlite3_close(db);
    }
};

int count_rows(sqlite3* db, const char* table) {
    std::string sql = "SELECT COUNT(*) FROM " + std::string(table);
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

bool column_exists(sqlite3* db, const char* table, const char* column) {
    std::string sql = "PRAGMA table_info(" + std::string(table) + ")";
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
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
