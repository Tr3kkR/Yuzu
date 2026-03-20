/**
 * test_kv_store.cpp -- Unit tests for KvStore (SQLite-backed plugin KV storage)
 *
 * Covers: basic CRUD, listing, plugin isolation, edge cases, concurrency.
 */

#include <yuzu/agent/kv_store.hpp>

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::agent;

// Helper: create a KvStore in a unique temp file, return it + the path for cleanup.
struct TestKvStore {
    KvStore store;
    fs::path path;

    ~TestKvStore() {
        // Move-from to close the db before deleting file
        { KvStore discard = std::move(store); }
        std::error_code ec;
        fs::remove(path, ec);
        // WAL and SHM files
        fs::remove(fs::path{path.string() + "-wal"}, ec);
        fs::remove(fs::path{path.string() + "-shm"}, ec);
    }
};

static TestKvStore make_test_store() {
    auto tmp = fs::temp_directory_path() / "yuzu_test_kv" /
               ("kv_" + std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id())) +
                "_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
                ".db");
    auto result = KvStore::open(tmp);
    REQUIRE(result.has_value());
    return TestKvStore{std::move(*result), tmp};
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
    auto tmp = fs::temp_directory_path() / "yuzu_test_kv" / "move_ctor.db";
    auto result = KvStore::open(tmp);
    REQUIRE(result.has_value());

    auto& original = *result;
    REQUIRE(original.set("p1", "k", "v"));

    KvStore moved{std::move(original)};
    auto val = moved.get("p1", "k");
    REQUIRE(val.has_value());
    CHECK(*val == "v");

    // Clean up
    { KvStore discard = std::move(moved); }
    std::error_code ec;
    fs::remove(tmp, ec);
    fs::remove(fs::path{tmp.string() + "-wal"}, ec);
    fs::remove(fs::path{tmp.string() + "-shm"}, ec);
}

TEST_CASE("KvStore: move assignment transfers ownership", "[kv_store][lifecycle]") {
    auto tmp1 = fs::temp_directory_path() / "yuzu_test_kv" / "move_a1.db";
    auto tmp2 = fs::temp_directory_path() / "yuzu_test_kv" / "move_a2.db";

    auto r1 = KvStore::open(tmp1);
    auto r2 = KvStore::open(tmp2);
    REQUIRE(r1.has_value());
    REQUIRE(r2.has_value());

    r1->set("p1", "from", "store1");
    r2->set("p1", "from", "store2");

    // Move-assign r2 into r1 (r1's old db should be closed)
    *r1 = std::move(*r2);
    auto val = r1->get("p1", "from");
    REQUIRE(val.has_value());
    CHECK(*val == "store2");

    // Clean up
    { KvStore discard = std::move(*r1); }
    std::error_code ec;
    for (auto& p : {tmp1, tmp2}) {
        fs::remove(p, ec);
        fs::remove(fs::path{p.string() + "-wal"}, ec);
        fs::remove(fs::path{p.string() + "-shm"}, ec);
    }
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

    for (int tid = 0; tid < kThreads; ++tid) {
        threads.emplace_back([&store = t.store, tid]() {
            std::string plugin = "plugin-" + std::to_string(tid);
            for (int i = 0; i < kOpsPerThread; ++i) {
                std::string key = "key-" + std::to_string(i);
                std::string val = std::to_string(tid * 1000 + i);

                store.set(plugin, key, val);
                auto got = store.get(plugin, key);
                // Value should always be present (we just set it), though
                // it may have been overwritten by another thread if they share
                // the same plugin+key — but here each thread has its own plugin.
                REQUIRE(got.has_value());
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

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
            CHECK(keys.size() >= 20);
        }
    });

    writer.join();
    done.store(true);
    reader.join();
}
