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

/// A key/value pair from list_entries(). The value is byte-exact — embedded NULs
/// survive — unlike get()/list(), which read via sqlite3_column_text and truncate
/// at the first NUL.
struct KvRow {
    std::string key;
    std::string value;
};

/// Result of insert_if_absent(): row created, already present, or op failed.
enum class KvInsert { Inserted, Exists, Error };

/// Result of rename_key(): moved, from-key absent, to-key already existed (PK
/// conflict), or op failed.
enum class KvRename { Renamed, NotFound, Conflict, Error };

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

    /**
     * Fallible, byte-exact, terminal-error-aware sibling of list(). Returns each
     * matching key WITH its value; distinguishes an empty result (empty vector)
     * from a DB error (unexpected) — which list()'s fail-open cannot. Values are
     * read as blobs so embedded NULs survive.
     */
    std::expected<std::vector<KvRow>, KvStoreError> list_entries(std::string_view plugin,
                                                                 std::string_view prefix);

    /**
     * Insert only if (plugin, key) is absent. Uses INSERT ... ON CONFLICT DO
     * NOTHING RETURNING, so it reports Inserted vs Exists WITHOUT the
     * sqlite3_changes()-after-step race (#1033) — letting a collision counter be
     * truthful.
     */
    KvInsert insert_if_absent(std::string_view plugin, std::string_view key,
                              std::string_view value);

    /**
     * Atomically rename (plugin, from_key) → (plugin, to_key) via a single UPDATE
     * of the key column, preserving the value. Conflict if to_key already exists.
     * Used for the quarantine move — never a non-atomic copy+delete.
     */
    KvRename rename_key(std::string_view plugin, std::string_view from_key,
                        std::string_view to_key);

    /**
     * Delete a set of keys for a plugin in ONE transaction. Returns the number
     * actually removed (via RETURNING, not sqlite3_changes()). All-or-nothing: on
     * error the transaction rolls back and 0 is returned.
     */
    int del_keys(std::string_view plugin, const std::vector<std::string>& keys);

    /**
     * The effective `PRAGMA synchronous` level (0=OFF, 1=NORMAL, 2=FULL,
     * 3=EXTRA), or -1 on error. The journal's power-loss-durability claim wants
     * FULL; the caller SOFT-warns on anything less (never a hard abort — config
     * drift must not kill an agent).
     */
    int pragma_synchronous();

private:
    explicit KvStore(sqlite3* db);

    sqlite3* db_{nullptr};
    std::mutex mu_;
};

} // namespace yuzu::agent
