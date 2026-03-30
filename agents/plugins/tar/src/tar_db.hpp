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

// ── Typed event structs for warehouse tables ────────────────────────────────

struct ProcessEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action;   // started, stopped
    uint32_t pid{0};
    uint32_t ppid{0};
    std::string name;
    std::string cmdline;
    std::string user;
};

struct NetworkEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action;       // connected, disconnected
    std::string proto;
    std::string local_addr;
    int local_port{0};
    std::string remote_addr;
    std::string remote_host;
    int remote_port{0};
    std::string state;
    uint32_t pid{0};
    std::string process_name;
};

struct ServiceEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action;           // started, stopped, state_changed
    std::string name;
    std::string display_name;
    std::string status;
    std::string prev_status;
    std::string startup_type;
    std::string prev_startup_type;
};

struct UserEvent {
    int64_t ts{0};
    int64_t snapshot_id{0};
    std::string action;   // login, logout
    std::string user;
    std::string domain;
    std::string logon_type;
    std::string session_id;
};

/// Row from an arbitrary SQL query (used by tar.sql action).
using QueryRow = std::vector<std::string>;

struct QueryResult {
    std::vector<std::string> columns;  // column names
    std::vector<QueryRow> rows;
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
     * Get database statistics.
     * Queries typed warehouse tables (process_live, tcp_live, etc.)
     */
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

    // ── Warehouse schema management ─────────────────────────────────────────

    /** Get the current schema version (0 = legacy-only, 2 = typed tables). */
    int schema_version();

    /** Create all typed warehouse tables from the schema registry. */
    bool create_warehouse_tables();

    // ── Typed inserts ───────────────────────────────────────────────────────

    bool insert_process_events(const std::vector<ProcessEvent>& events);
    bool insert_network_events(const std::vector<NetworkEvent>& events);
    bool insert_service_events(const std::vector<ServiceEvent>& events);
    bool insert_user_events(const std::vector<UserEvent>& events);

    // ── Generic SQL execution (for warehouse queries and aggregation) ────────

    /**
     * Execute arbitrary read-only SQL and return results.
     * Used by tar.sql action. Returns error string on failure.
     * The caller is responsible for SQL validation (SELECT-only, etc.)
     * Enforces a maximum row limit to prevent agent DoS.
     */
    std::expected<QueryResult, std::string> execute_query(const std::string& sql,
                                                           int max_rows = 10000);

    /**
     * Execute arbitrary DDL/DML SQL (for rollup inserts, retention deletes).
     * Returns true on success.
     */
    bool execute_sql(const std::string& sql);

    /**
     * Execute parameterized SQL with two int64 bind values.
     * Used by rollup engine for time-range-bounded aggregation.
     */
    bool execute_sql_range(const std::string& sql, int64_t from, int64_t to);

private:
    explicit TarDatabase(sqlite3* db);

    /// Internal set_config that assumes caller already holds mu_.
    void set_config_locked(const std::string& key, const std::string& value);

    sqlite3* db_{nullptr};
    std::mutex mu_;
};

} // namespace yuzu::tar
