/**
 * test_concurrency_manager.cpp — Unit tests for ConcurrencyManager
 *
 * Covers: create_tables, try_acquire/release with unlimited, per-device,
 *         per-definition, and global:N modes, parse_global_limit, is_valid_mode.
 */

#include "concurrency_manager.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sqlite3.h>

#include <string>

using namespace yuzu::server;

// ── RAII wrapper for sqlite3* ──────────────────────────────────────────────

struct TestDb {
    sqlite3* db = nullptr;
    TestDb() { sqlite3_open(":memory:", &db); }
    ~TestDb() {
        if (db)
            sqlite3_close(db);
    }
};

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("ConcurrencyManager: create_tables succeeds", "[concurrency_manager][db]") {
    TestDb tdb;
    ConcurrencyManager mgr(tdb.db);
    mgr.create_tables(); // should not crash
    REQUIRE(true);
}

// ── unlimited mode ─────────────────────────────────────────────────────────

TEST_CASE("ConcurrencyManager: unlimited mode always returns true", "[concurrency_manager]") {
    TestDb tdb;
    ConcurrencyManager mgr(tdb.db);
    mgr.create_tables();

    CHECK(mgr.try_acquire("def-1", "exec-1", "unlimited") == true);
    CHECK(mgr.try_acquire("def-1", "exec-2", "unlimited") == true);
    CHECK(mgr.try_acquire("def-1", "exec-3", "unlimited") == true);
}

// ── per-device mode ────────────────────────────────────────────────────────

TEST_CASE("ConcurrencyManager: per-device mode always returns true", "[concurrency_manager]") {
    TestDb tdb;
    ConcurrencyManager mgr(tdb.db);
    mgr.create_tables();

    // per-device is agent-side enforcement, server always allows
    CHECK(mgr.try_acquire("def-1", "exec-1", "per-device") == true);
    CHECK(mgr.try_acquire("def-1", "exec-2", "per-device") == true);
}

// ── per-definition mode ────────────────────────────────────────────────────

TEST_CASE("ConcurrencyManager: per-definition blocks second acquire", "[concurrency_manager]") {
    TestDb tdb;
    ConcurrencyManager mgr(tdb.db);
    mgr.create_tables();

    CHECK(mgr.try_acquire("def-1", "exec-1", "per-definition") == true);
    CHECK(mgr.active_count("def-1") == 1);

    // Second acquire for same definition should be blocked
    CHECK(mgr.try_acquire("def-1", "exec-2", "per-definition") == false);
}

TEST_CASE("ConcurrencyManager: per-definition allows after release", "[concurrency_manager]") {
    TestDb tdb;
    ConcurrencyManager mgr(tdb.db);
    mgr.create_tables();

    CHECK(mgr.try_acquire("def-1", "exec-1", "per-definition") == true);
    CHECK(mgr.try_acquire("def-1", "exec-2", "per-definition") == false);

    mgr.release("def-1", "exec-1");
    CHECK(mgr.active_count("def-1") == 0);

    // Now a new acquire should succeed
    CHECK(mgr.try_acquire("def-1", "exec-3", "per-definition") == true);
}

TEST_CASE("ConcurrencyManager: per-definition allows different definitions", "[concurrency_manager]") {
    TestDb tdb;
    ConcurrencyManager mgr(tdb.db);
    mgr.create_tables();

    CHECK(mgr.try_acquire("def-1", "exec-1", "per-definition") == true);
    CHECK(mgr.try_acquire("def-2", "exec-2", "per-definition") == true);
}

// ── global:N mode ──────────────────────────────────────────────────────────

TEST_CASE("ConcurrencyManager: global:N allows up to N, blocks N+1", "[concurrency_manager]") {
    TestDb tdb;
    ConcurrencyManager mgr(tdb.db);
    mgr.create_tables();

    // global:3 — allow 3 concurrent executions
    CHECK(mgr.try_acquire("def-1", "exec-1", "global:3") == true);
    CHECK(mgr.try_acquire("def-1", "exec-2", "global:3") == true);
    CHECK(mgr.try_acquire("def-1", "exec-3", "global:3") == true);
    CHECK(mgr.active_count("def-1") == 3);

    // 4th should be blocked
    CHECK(mgr.try_acquire("def-1", "exec-4", "global:3") == false);
}

TEST_CASE("ConcurrencyManager: global:1 behaves like per-definition", "[concurrency_manager]") {
    TestDb tdb;
    ConcurrencyManager mgr(tdb.db);
    mgr.create_tables();

    CHECK(mgr.try_acquire("def-1", "exec-1", "global:1") == true);
    CHECK(mgr.try_acquire("def-1", "exec-2", "global:1") == false);
}

// ── release ────────────────────────────────────────────────────────────────

TEST_CASE("ConcurrencyManager: release decrements active_count", "[concurrency_manager]") {
    TestDb tdb;
    ConcurrencyManager mgr(tdb.db);
    mgr.create_tables();

    mgr.try_acquire("def-1", "exec-1", "global:5");
    mgr.try_acquire("def-1", "exec-2", "global:5");
    mgr.try_acquire("def-1", "exec-3", "global:5");
    CHECK(mgr.active_count("def-1") == 3);

    mgr.release("def-1", "exec-2");
    CHECK(mgr.active_count("def-1") == 2);

    mgr.release("def-1", "exec-1");
    CHECK(mgr.active_count("def-1") == 1);

    mgr.release("def-1", "exec-3");
    CHECK(mgr.active_count("def-1") == 0);
}

// ── parse_global_limit ─────────────────────────────────────────────────────

TEST_CASE("ConcurrencyManager: parse_global_limit extracts N", "[concurrency_manager]") {
    CHECK(ConcurrencyManager::parse_global_limit("global:50") == 50);
    CHECK(ConcurrencyManager::parse_global_limit("global:1") == 1);
    CHECK(ConcurrencyManager::parse_global_limit("global:100") == 100);
}

TEST_CASE("ConcurrencyManager: parse_global_limit returns 0 for invalid", "[concurrency_manager]") {
    CHECK(ConcurrencyManager::parse_global_limit("per-device") == 0);
    CHECK(ConcurrencyManager::parse_global_limit("unlimited") == 0);
    CHECK(ConcurrencyManager::parse_global_limit("global:") == 0);
    CHECK(ConcurrencyManager::parse_global_limit("global:abc") == 0);
    CHECK(ConcurrencyManager::parse_global_limit("global:0") == 0);
    CHECK(ConcurrencyManager::parse_global_limit("") == 0);
    CHECK(ConcurrencyManager::parse_global_limit("global:-1") == 0);
}

// ── is_valid_mode ──────────────────────────────────────────────────────────

TEST_CASE("ConcurrencyManager: is_valid_mode accepts valid modes", "[concurrency_manager]") {
    CHECK(ConcurrencyManager::is_valid_mode("unlimited") == true);
    CHECK(ConcurrencyManager::is_valid_mode("per-device") == true);
    CHECK(ConcurrencyManager::is_valid_mode("per-definition") == true);
    CHECK(ConcurrencyManager::is_valid_mode("per-set") == true);
    CHECK(ConcurrencyManager::is_valid_mode("global:10") == true);
}

TEST_CASE("ConcurrencyManager: is_valid_mode rejects invalid strings", "[concurrency_manager]") {
    CHECK(ConcurrencyManager::is_valid_mode("") == false);
    CHECK(ConcurrencyManager::is_valid_mode("invalid") == false);
    CHECK(ConcurrencyManager::is_valid_mode("global:") == false);
    CHECK(ConcurrencyManager::is_valid_mode("global:abc") == false);
    CHECK(ConcurrencyManager::is_valid_mode("PER-DEVICE") == false);
    CHECK(ConcurrencyManager::is_valid_mode("serial") == false);
}
