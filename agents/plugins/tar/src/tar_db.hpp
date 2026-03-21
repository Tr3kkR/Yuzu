#pragma once

/**
 * tar_db.hpp -- SQLite-backed Timeline Activity Record database
 *
 * Stores timestamped events (process births/deaths, network connections,
 * service state changes, user sessions) with snapshot IDs for correlation.
 *
 * Schema:
 *   tar_events — core event log (timestamp, type, action, detail_json, snapshot_id)
 *   tar_state  — last-known state per collector for diff computation
 *   tar_config — key/value config (retention_days, redaction patterns, etc.)
 *
 * Thread-safe: a std::mutex guards all sqlite3* operations.
 * Uses WAL mode, busy_timeout=5000, secure_delete=ON.
 */

#include <cstdint>
#include <expected>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

struct sqlite3; // Forward declaration

namespace yuzu::tar {

struct TarEvent {
    int64_t id{0};              // row id (0 for new events)
    int64_t timestamp{0};       // epoch seconds
    std::string event_type;     // process, network, service, user
    std::string event_action;   // started, stopped, connected, disconnected, state_changed,
                                // login, logout
    std::string detail_json;    // JSON object with type-specific details
    int64_t snapshot_id{0};     // groups events from same collection cycle
};

struct TarStats {
    int64_t record_count{0};
    int64_t oldest_timestamp{0};
    int64_t newest_timestamp{0};
    int64_t db_size_bytes{0};
    int retention_days{7};
};

class TarDatabase {
public:
    /**
     * Open (or create) the TAR database at the given path.
     * Creates tables if they don't exist. Sets WAL mode, busy_timeout,
     * and secure_delete pragmas.
     */
    static std::expected<TarDatabase, std::string> open(const std::filesystem::path& path);

    ~TarDatabase();

    TarDatabase(TarDatabase&& other) noexcept;
    TarDatabase& operator=(TarDatabase&& other) noexcept;

    TarDatabase(const TarDatabase&) = delete;
    TarDatabase& operator=(const TarDatabase&) = delete;

    /**
     * Insert events in a single transaction (batched for performance).
     * Returns true on success.
     */
    bool insert_events(const std::vector<TarEvent>& events);

    /**
     * Query events by time range with optional type filter.
     * @param from         Start of time range (epoch seconds, inclusive).
     * @param to           End of time range (epoch seconds, inclusive).
     * @param type_filter  If non-empty, filters by event_type.
     * @param limit        Maximum number of results (default 1000).
     */
    std::vector<TarEvent> query(int64_t from, int64_t to,
                                const std::string& type_filter = "",
                                int limit = 1000);

    /**
     * Purge events older than the given timestamp.
     * Returns the number of deleted rows.
     */
    int purge(int64_t before_timestamp);

    /** Get database statistics. */
    TarStats stats();

    // ── Snapshot state management ────────────────────────────────────────────

    /**
     * Get the last-known state JSON for a collector (e.g. "process", "network").
     * Returns empty string if no state is stored.
     */
    std::string get_state(const std::string& collector);

    /**
     * Store the last-known state JSON for a collector.
     */
    void set_state(const std::string& collector, const std::string& json);

    // ── Config management ────────────────────────────────────────────────────

    /**
     * Get a config value by key, with an optional default.
     */
    std::string get_config(const std::string& key, const std::string& default_val = "");

    /**
     * Set a config value.
     */
    void set_config(const std::string& key, const std::string& value);

private:
    explicit TarDatabase(sqlite3* db);

    sqlite3* db_{nullptr};
    std::mutex mu_;
};

} // namespace yuzu::tar
