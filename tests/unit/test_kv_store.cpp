/**
 * test_kv_store.cpp -- Unit tests for KvStore (SQLite-backed plugin KV storage)
 *
 * Covers: basic CRUD, listing, plugin isolation, edge cases, concurrency.
 */

#include <yuzu/agent/kv_store.hpp>

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace fs = std::filesystem;
using namespace yuzu::agent;

// Per-uid suffix so multi-user hosts (e.g. WSL2 with both an interactive
// user and the github-runner CI account) don't collide on /tmp ownership.
// Without this, whichever uid wins the race owns /tmp/yuzu_test_kv 0700
// and locks the other uid out until someone runs `sudo rm`.
static std::string yuzu_test_uid_suffix() {
#ifdef _WIN32
    if (const char* u = std::getenv("USERNAME"))
        return std::string("_") + u;
    return "_unknown";
#else
    return "_" + std::to_string(static_cast<unsigned long>(::geteuid()));
#endif
}

// Helper: create a KvStore in a unique temp file. TempDbFile (adopt-a-path
// ctor) owns cleanup of the .db + -wal/-shm companions, exception-safely —
// the old manual dtor was the last of the #482-ported files still doing this
// by hand (#486). Declared FIRST so it destructs LAST: the KvStore closes
// its handle before the file is removed (Windows can't delete an open file).
struct TestKvStore {
    yuzu::test::TempDbFile db;
    KvStore store;
    fs::path path{db.path};

    TestKvStore(fs::path p, KvStore s) : db(std::move(p)), store(std::move(s)) {}
};

static TestKvStore make_test_store() {
    // Previously used `std::hash<std::thread::id>{} ^ steady_clock::now()` for
    // uniqueness — the pattern that flaked on Windows MSVC debug + Defender
    // (#473). Delegate to the shared salt+counter helper so KV tests don't
    // regress even though they haven't flaked in CI yet (#482).
    const auto dir = fs::temp_directory_path() / ("yuzu_test_kv" + yuzu_test_uid_suffix());
    const auto tmp = dir / (yuzu::test::unique_temp_path("kv_").filename().string() + ".db");
    auto result = KvStore::open(tmp);
    REQUIRE(result.has_value());
    return TestKvStore{tmp, std::move(*result)};
}

// ═══════════════════════════════════════════════════════════════════════════════
// Basic CRUD
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("KvStore: open creates database file", "[kv_store][lifecycle]") {
    auto t = make_test_store();
    CHECK(fs::exists(t.path));
}

TEST_CASE("KvStore: set and get round-trip", "[kv_store][crud]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("myplugin", "hostname", "WORKSTATION-01"));

    auto val = t.store.get("myplugin", "hostname");
    REQUIRE(val.has_value());
    CHECK(*val == "WORKSTATION-01");
}

TEST_CASE("KvStore: set overwrites existing value", "[kv_store][crud]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "key", "original"));
    REQUIRE(t.store.set("p1", "key", "updated"));

    auto val = t.store.get("p1", "key");
    REQUIRE(val.has_value());
    CHECK(*val == "updated");
}

TEST_CASE("KvStore: get non-existent key returns nullopt", "[kv_store][crud]") {
    auto t = make_test_store();
    auto val = t.store.get("p1", "no-such-key");
    CHECK_FALSE(val.has_value());
}

TEST_CASE("KvStore: delete key then get returns nullopt", "[kv_store][crud]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "to-delete", "value"));
    REQUIRE(t.store.del("p1", "to-delete"));

    auto val = t.store.get("p1", "to-delete");
    CHECK_FALSE(val.has_value());
}

TEST_CASE("KvStore: delete non-existent key returns true", "[kv_store][crud]") {
    auto t = make_test_store();
    // del returns true even when key didn't exist
    CHECK(t.store.del("p1", "never-existed"));
}

TEST_CASE("KvStore: exists for present key", "[kv_store][crud]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "present", "yes"));
    CHECK(t.store.exists("p1", "present"));
}

TEST_CASE("KvStore: exists for absent key", "[kv_store][crud]") {
    auto t = make_test_store();
    CHECK_FALSE(t.store.exists("p1", "absent"));
}

TEST_CASE("KvStore: exists returns false after delete", "[kv_store][crud]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "k", "v"));
    REQUIRE(t.store.del("p1", "k"));
    CHECK_FALSE(t.store.exists("p1", "k"));
}

TEST_CASE("KvStore: clear removes all keys for a plugin", "[kv_store][crud]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "a", "1"));
    REQUIRE(t.store.set("p1", "b", "2"));
    REQUIRE(t.store.set("p1", "c", "3"));

    int deleted = t.store.clear("p1");
    CHECK(deleted == 3);
    CHECK_FALSE(t.store.exists("p1", "a"));
    CHECK_FALSE(t.store.exists("p1", "b"));
    CHECK_FALSE(t.store.exists("p1", "c"));
}

TEST_CASE("KvStore: clear on empty plugin returns 0", "[kv_store][crud]") {
    auto t = make_test_store();
    int deleted = t.store.clear("empty-plugin");
    CHECK(deleted == 0);
}

TEST_CASE("KvStore: clear does not affect other plugins", "[kv_store][crud]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "key", "val1"));
    REQUIRE(t.store.set("p2", "key", "val2"));

    t.store.clear("p1");
    CHECK_FALSE(t.store.exists("p1", "key"));
    CHECK(t.store.exists("p2", "key"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Listing
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("KvStore: list with empty prefix returns all keys", "[kv_store][list]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "alpha", "1"));
    REQUIRE(t.store.set("p1", "beta", "2"));
    REQUIRE(t.store.set("p1", "gamma", "3"));

    auto keys = t.store.list("p1", "");
    REQUIRE(keys.size() == 3);
    // Keys should be ordered alphabetically
    CHECK(keys[0] == "alpha");
    CHECK(keys[1] == "beta");
    CHECK(keys[2] == "gamma");
}

TEST_CASE("KvStore: list with prefix filters keys", "[kv_store][list]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "net.interface.eth0", "up"));
    REQUIRE(t.store.set("p1", "net.interface.eth1", "down"));
    REQUIRE(t.store.set("p1", "net.dns.primary", "8.8.8.8"));
    REQUIRE(t.store.set("p1", "disk.usage", "75%"));

    auto net_iface_keys = t.store.list("p1", "net.interface.");
    REQUIRE(net_iface_keys.size() == 2);
    CHECK(net_iface_keys[0] == "net.interface.eth0");
    CHECK(net_iface_keys[1] == "net.interface.eth1");

    auto net_keys = t.store.list("p1", "net.");
    CHECK(net_keys.size() == 3);

    auto disk_keys = t.store.list("p1", "disk.");
    CHECK(disk_keys.size() == 1);
}

TEST_CASE("KvStore: list for non-existent plugin returns empty", "[kv_store][list]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "key", "val"));

    auto keys = t.store.list("nonexistent-plugin", "");
    CHECK(keys.empty());
}

TEST_CASE("KvStore: list with non-matching prefix returns empty", "[kv_store][list]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "alpha", "1"));
    REQUIRE(t.store.set("p1", "beta", "2"));

    auto keys = t.store.list("p1", "zzz");
    CHECK(keys.empty());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Plugin isolation
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("KvStore: plugin A cannot see plugin B keys", "[kv_store][isolation]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("pluginA", "secret", "A-value"));

    auto val = t.store.get("pluginB", "secret");
    CHECK_FALSE(val.has_value());
}

TEST_CASE("KvStore: same key name coexists across plugins", "[kv_store][isolation]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("pluginA", "count", "10"));
    REQUIRE(t.store.set("pluginB", "count", "20"));

    auto a_val = t.store.get("pluginA", "count");
    auto b_val = t.store.get("pluginB", "count");

    REQUIRE(a_val.has_value());
    REQUIRE(b_val.has_value());
    CHECK(*a_val == "10");
    CHECK(*b_val == "20");
}

TEST_CASE("KvStore: plugin A list only sees own keys", "[kv_store][isolation]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("pluginA", "a1", "v"));
    REQUIRE(t.store.set("pluginA", "a2", "v"));
    REQUIRE(t.store.set("pluginB", "b1", "v"));

    auto a_keys = t.store.list("pluginA", "");
    auto b_keys = t.store.list("pluginB", "");

    CHECK(a_keys.size() == 2);
    CHECK(b_keys.size() == 1);
}

TEST_CASE("KvStore: deleting plugin A key does not affect plugin B", "[kv_store][isolation]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("pluginA", "shared-name", "A"));
    REQUIRE(t.store.set("pluginB", "shared-name", "B"));

    REQUIRE(t.store.del("pluginA", "shared-name"));

    CHECK_FALSE(t.store.exists("pluginA", "shared-name"));
    CHECK(t.store.exists("pluginB", "shared-name"));
    auto b_val = t.store.get("pluginB", "shared-name");
    REQUIRE(b_val.has_value());
    CHECK(*b_val == "B");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Edge cases
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("KvStore: very long key (1000 chars)", "[kv_store][edge]") {
    auto t = make_test_store();
    std::string long_key(1000, 'k');
    REQUIRE(t.store.set("p1", long_key, "value-for-long-key"));

    auto val = t.store.get("p1", long_key);
    REQUIRE(val.has_value());
    CHECK(*val == "value-for-long-key");
    CHECK(t.store.exists("p1", long_key));
}

TEST_CASE("KvStore: very long value (100KB)", "[kv_store][edge]") {
    auto t = make_test_store();
    std::string long_value(100 * 1024, 'v');
    REQUIRE(t.store.set("p1", "big-blob", long_value));

    auto val = t.store.get("p1", "big-blob");
    REQUIRE(val.has_value());
    CHECK(val->size() == 100 * 1024);
    CHECK(*val == long_value);
}

TEST_CASE("KvStore: key with special characters", "[kv_store][edge]") {
    auto t = make_test_store();

    // Dots, dashes, underscores
    REQUIRE(t.store.set("p1", "net.interface-eth0_stats", "data"));
    auto val = t.store.get("p1", "net.interface-eth0_stats");
    REQUIRE(val.has_value());
    CHECK(*val == "data");

    // Slashes
    REQUIRE(t.store.set("p1", "path/to/resource", "found"));
    val = t.store.get("p1", "path/to/resource");
    REQUIRE(val.has_value());
    CHECK(*val == "found");

    // Colons and equals
    REQUIRE(t.store.set("p1", "key:with=symbols", "ok"));
    val = t.store.get("p1", "key:with=symbols");
    REQUIRE(val.has_value());
    CHECK(*val == "ok");
}

TEST_CASE("KvStore: empty value is stored and retrievable", "[kv_store][edge]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "empty-val", ""));

    auto val = t.store.get("p1", "empty-val");
    REQUIRE(val.has_value());
    CHECK(val->empty());
    CHECK(t.store.exists("p1", "empty-val"));
}

TEST_CASE("KvStore: empty key is stored and retrievable", "[kv_store][edge]") {
    auto t = make_test_store();
    // SQLite allows empty strings as text — the schema has no NOT NULL constraint
    // on the key column value, but the PRIMARY KEY(plugin, key) allows empty strings.
    // The implementation uses parameterized queries so empty key is just an empty TEXT.
    REQUIRE(t.store.set("p1", "", "value-for-empty-key"));

    auto val = t.store.get("p1", "");
    REQUIRE(val.has_value());
    CHECK(*val == "value-for-empty-key");
}

TEST_CASE("KvStore: value with newlines and tabs", "[kv_store][edge]") {
    auto t = make_test_store();
    std::string multiline = "line1\nline2\r\nline3\ttab";
    REQUIRE(t.store.set("p1", "multiline", multiline));

    auto val = t.store.get("p1", "multiline");
    REQUIRE(val.has_value());
    CHECK(*val == multiline);
}

TEST_CASE("KvStore: value with null bytes (binary)", "[kv_store][edge]") {
    auto t = make_test_store();
    // SQLite TEXT columns handle embedded NUL via length-specified binding,
    // but sqlite3_column_text returns a C string (stops at first NUL).
    // This test documents the actual behavior.
    std::string with_nul = std::string("before") + '\0' + "after";
    t.store.set("p1", "binary", with_nul);

    auto val = t.store.get("p1", "binary");
    // The get implementation uses sqlite3_column_text which is NUL-terminated,
    // so we expect truncation at the first NUL.
    REQUIRE(val.has_value());
    CHECK(*val == "before");
}

TEST_CASE("KvStore: multiple sets then clear returns correct count", "[kv_store][edge]") {
    auto t = make_test_store();
    for (int i = 0; i < 50; ++i) {
        REQUIRE(t.store.set("p1", "key-" + std::to_string(i), "val"));
    }
    int deleted = t.store.clear("p1");
    CHECK(deleted == 50);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Move semantics
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("KvStore: move constructor transfers ownership", "[kv_store][lifecycle]") {
    // Salted per-test path: the old fixed "move_ctor.db" filename lived in a
    // USERNAME/uid-suffixed dir — identical for all 4 runner agents on a
    // shared-identity CI box, so two concurrent jobs shared the exact path
    // and cleaned up each other's live DB (#1883). TempDbFile declared FIRST
    // so removal happens after the stores close.
    yuzu::test::TempDbFile db{"yuzu_test_kv_move_ctor-"};
    auto result = KvStore::open(db.path);
    REQUIRE(result.has_value());

    auto& original = *result;
    REQUIRE(original.set("p1", "k", "v"));

    KvStore moved{std::move(original)};
    auto val = moved.get("p1", "k");
    REQUIRE(val.has_value());
    CHECK(*val == "v");
}

TEST_CASE("KvStore: move assignment transfers ownership", "[kv_store][lifecycle]") {
    yuzu::test::TempDbFile db1{"yuzu_test_kv_move_a1-"};
    yuzu::test::TempDbFile db2{"yuzu_test_kv_move_a2-"};

    auto r1 = KvStore::open(db1.path);
    auto r2 = KvStore::open(db2.path);
    REQUIRE(r1.has_value());
    REQUIRE(r2.has_value());

    r1->set("p1", "from", "store1");
    r2->set("p1", "from", "store2");

    // Move-assign r2 into r1 (r1's old db should be closed)
    *r1 = std::move(*r2);
    auto val = r1->get("p1", "from");
    REQUIRE(val.has_value());
    CHECK(*val == "store2");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Concurrency
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("KvStore: concurrent set/get from multiple threads", "[kv_store][concurrency]") {
    auto t = make_test_store();

    constexpr int kThreads = 8;
    constexpr int kOpsPerThread = 100;

    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    // Catch2 assertion macros are not thread-safe (they write a process-global
    // line-info object), so worker threads record into an atomic and the
    // assertion happens on the main thread after join.
    std::atomic<bool> all_present{true};

    for (int tid = 0; tid < kThreads; ++tid) {
        threads.emplace_back([&store = t.store, &all_present, tid]() {
            std::string plugin = "plugin-" + std::to_string(tid);
            for (int i = 0; i < kOpsPerThread; ++i) {
                std::string key = "key-" + std::to_string(i);
                std::string val = std::to_string(tid * 1000 + i);

                store.set(plugin, key, val);
                auto got = store.get(plugin, key);
                // Value should always be present (we just set it); each thread
                // has its own plugin so there is no cross-thread overwrite.
                if (!got.has_value())
                    all_present.store(false, std::memory_order_relaxed);
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    CHECK(all_present.load());

    // Verify each thread's final state is intact
    for (int tid = 0; tid < kThreads; ++tid) {
        std::string plugin = "plugin-" + std::to_string(tid);
        auto keys = t.store.list(plugin, "");
        CHECK(keys.size() == kOpsPerThread);
    }
}

TEST_CASE("KvStore: concurrent set on same key from multiple threads", "[kv_store][concurrency]") {
    auto t = make_test_store();

    constexpr int kThreads = 8;
    constexpr int kOpsPerThread = 50;

    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int tid = 0; tid < kThreads; ++tid) {
        threads.emplace_back([&store = t.store, tid]() {
            for (int i = 0; i < kOpsPerThread; ++i) {
                std::string val = std::to_string(tid) + "-" + std::to_string(i);
                store.set("shared-plugin", "contested-key", val);
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    // Key should exist with some valid value (last writer wins)
    auto val = t.store.get("shared-plugin", "contested-key");
    REQUIRE(val.has_value());
    CHECK_FALSE(val->empty());
}

TEST_CASE("KvStore: concurrent list while writing", "[kv_store][concurrency]") {
    auto t = make_test_store();

    // Pre-populate some keys
    for (int i = 0; i < 20; ++i) {
        t.store.set("p1", "pre-" + std::to_string(i), "v");
    }

    std::atomic<bool> done{false};
    // Catch2 macros are not thread-safe; the reader records into an atomic.
    std::atomic<bool> list_consistent{true};

    // Writer thread
    std::thread writer([&]() {
        for (int i = 0; i < 100 && !done.load(); ++i) {
            t.store.set("p1", "write-" + std::to_string(i), "v");
        }
        done.store(true);
    });

    // Reader thread: list keys concurrently
    std::thread reader([&]() {
        while (!done.load()) {
            auto keys = t.store.list("p1", "");
            // Should always get a consistent snapshot (at least the 20 pre-populated)
            if (keys.size() < 20)
                list_consistent.store(false, std::memory_order_relaxed);
        }
    });

    writer.join();
    done.store(true);
    reader.join();

    CHECK(list_consistent.load());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Journal substrate primitives (item 7 PR-Ag C1)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("KvStore::list_entries returns key+value, empty is not an error", "[kv_store][entries]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "lc:n:0", "alpha"));
    REQUIRE(t.store.set("p1", "lc:n:1", "beta"));
    REQUIRE(t.store.set("p1", "other", "gamma"));

    auto rows = t.store.list_entries("p1", "lc:");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 2);
    CHECK((*rows)[0].key == "lc:n:0");
    CHECK((*rows)[0].value == "alpha");
    CHECK((*rows)[1].key == "lc:n:1");
    CHECK((*rows)[1].value == "beta");

    // A non-matching prefix is an empty result, NOT an error (distinct from list()).
    auto none = t.store.list_entries("p1", "zzz");
    REQUIRE(none.has_value());
    CHECK(none->empty());
}

TEST_CASE("KvStore::list_entries reads values byte-exact (NUL preserved)", "[kv_store][entries]") {
    auto t = make_test_store();
    const std::string with_nul = std::string("before") + '\0' + "after"; // 12 bytes
    REQUIRE(t.store.set("p1", "lc:n:0", with_nul));

    // get() truncates at the NUL (documented elsewhere); list_entries must not.
    auto rows = t.store.list_entries("p1", "lc:");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].value.size() == with_nul.size());
    CHECK((*rows)[0].value == with_nul);
}

TEST_CASE("KvStore::insert_if_absent reports Inserted vs Exists", "[kv_store][entries]") {
    auto t = make_test_store();
    CHECK(t.store.insert_if_absent("p1", "lc:n:0", "first") == KvInsert::Inserted);
    // Second insert on the same key does nothing and reports Exists.
    CHECK(t.store.insert_if_absent("p1", "lc:n:0", "second") == KvInsert::Exists);
    auto v = t.store.get("p1", "lc:n:0");
    REQUIRE(v.has_value());
    CHECK(*v == "first"); // value NOT overwritten
    // A different key is a fresh insert.
    CHECK(t.store.insert_if_absent("p1", "lc:n:1", "other") == KvInsert::Inserted);
}

TEST_CASE("KvStore::rename_key moves atomically, reports Conflict/NotFound", "[kv_store][entries]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "lc:n:0", "payload"));

    CHECK(t.store.rename_key("p1", "lc:n:0", "quarantine:lc:n:0") == KvRename::Renamed);
    CHECK_FALSE(t.store.exists("p1", "lc:n:0"));
    auto moved = t.store.get("p1", "quarantine:lc:n:0");
    REQUIRE(moved.has_value());
    CHECK(*moved == "payload"); // value preserved

    // Renaming a key that no longer exists.
    CHECK(t.store.rename_key("p1", "lc:n:0", "lc:n:9") == KvRename::NotFound);

    // Conflict: to_key already exists - both rows survive untouched.
    REQUIRE(t.store.set("p1", "lc:a", "A"));
    REQUIRE(t.store.set("p1", "lc:b", "B"));
    CHECK(t.store.rename_key("p1", "lc:a", "lc:b") == KvRename::Conflict);
    CHECK(t.store.get("p1", "lc:a").value_or("") == "A");
    CHECK(t.store.get("p1", "lc:b").value_or("") == "B");
}

TEST_CASE("KvStore::del_keys removes only the listed keys, returns count", "[kv_store][entries]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "a", "1"));
    REQUIRE(t.store.set("p1", "b", "2"));
    REQUIRE(t.store.set("p1", "c", "3"));

    CHECK(t.store.del_keys("p1", {"a", "c"}) == 2);
    CHECK_FALSE(t.store.exists("p1", "a"));
    CHECK(t.store.exists("p1", "b"));
    CHECK_FALSE(t.store.exists("p1", "c"));

    CHECK(t.store.del_keys("p1", {}) == 0);            // empty list
    CHECK(t.store.del_keys("p1", {"nope"}) == 0);      // absent key, no error
    CHECK(t.store.del_keys("p1", {"b", "nope"}) == 1); // counts only what existed
    CHECK_FALSE(t.store.exists("p1", "b"));
}

TEST_CASE("KvStore::pragma_synchronous reports a valid level", "[kv_store][entries]") {
    auto t = make_test_store();
    const int level = t.store.pragma_synchronous();
    // 0=OFF 1=NORMAL 2=FULL 3=EXTRA. The journal wants FULL; anything in range is
    // a valid read (the caller soft-warns on < FULL, never aborts).
    CHECK(level >= 0);
    CHECK(level <= 3);
}
