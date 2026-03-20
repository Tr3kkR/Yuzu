#pragma once

/**
 * kv_store.hpp -- Persistent key-value storage for Yuzu agent plugins
 *
 * SQLite-backed, file at {data_dir}/kv_store.db. Each plugin's keys are
 * namespaced by plugin name so plugins cannot access each other's state.
 *
 * Thread-safe: a std::mutex protects all sqlite3* operations (required
 * for macOS where SQLite's built-in threading may not suffice).
 */

#include <yuzu/plugin.h>

#include <expected>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

struct sqlite3; // Forward declaration — avoids exposing sqlite3.h in the header

namespace yuzu::agent {

struct KvStoreError {
    std::string message;
};

class YUZU_EXPORT KvStore {
public:
    /**
     * Open (or create) the KV store database at the given path.
     * Sets WAL mode and busy_timeout=5000.
     */
    static std::expected<KvStore, KvStoreError> open(const std::filesystem::path& db_path);

    ~KvStore();

    KvStore(KvStore&& other) noexcept;
    KvStore& operator=(KvStore&& other) noexcept;

    KvStore(const KvStore&) = delete;
    KvStore& operator=(const KvStore&) = delete;

    /** Store a key-value pair for the given plugin. Returns true on success. */
    bool set(std::string_view plugin, std::string_view key, std::string_view value);

    /** Retrieve a value. Returns std::nullopt if the key does not exist. */
    std::optional<std::string> get(std::string_view plugin, std::string_view key);

    /** Delete a key. Returns true on success (even if key did not exist). */
    bool del(std::string_view plugin, std::string_view key);

    /** Check if a key exists. Returns true if present. */
    bool exists(std::string_view plugin, std::string_view key);

    /** List all keys for a plugin matching the given prefix. */
    std::vector<std::string> list(std::string_view plugin, std::string_view prefix);

    /** Delete all keys for a plugin. Returns the number of deleted rows. */
    int clear(std::string_view plugin);

private:
    explicit KvStore(sqlite3* db);

    sqlite3* db_{nullptr};
    std::mutex mu_;
};

} // namespace yuzu::agent
