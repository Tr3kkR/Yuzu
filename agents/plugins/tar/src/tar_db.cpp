/**
 * tar_db.cpp -- SQLite-backed Timeline Activity Record database
 *
 * Tables:
 *   tar_events(id, timestamp, event_type, event_action, detail_json, snapshot_id)
 *   tar_state(collector PRIMARY KEY, state_json, updated_at)
 *   tar_config(key PRIMARY KEY, value)
 *
 * All queries use parameterized SQL to prevent injection.
 * A std::mutex guards all sqlite3* access for thread safety (Darwin pitfall).
 */

#include "tar_db.hpp"
#include "tar_schema_registry.hpp"

#include <sqlite3.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <format>
#include <memory>

namespace yuzu::tar {

namespace {

int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

struct StmtDeleter {
    void operator()(sqlite3_stmt* s) const { sqlite3_finalize(s); }
};
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

/// Schema DDL for all TAR tables.
constexpr const char* kCreateSchema = R"(
    CREATE TABLE IF NOT EXISTS tar_events (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp    INTEGER NOT NULL,
        event_type   TEXT    NOT NULL,
        event_action TEXT    NOT NULL,
        detail_json  TEXT    NOT NULL DEFAULT '{}',
        snapshot_id  INTEGER NOT NULL DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_tar_events_ts
        ON tar_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_tar_events_type_ts
        ON tar_events(event_type, timestamp);
    CREATE INDEX IF NOT EXISTS idx_tar_events_snapshot
        ON tar_events(snapshot_id);

    CREATE TABLE IF NOT EXISTS tar_state (
        collector   TEXT PRIMARY KEY,
        state_json  TEXT NOT NULL DEFAULT '{}',
        updated_at  INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS tar_config (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL DEFAULT ''
    );
)";

} // namespace

// ── Construction / destruction ───────────────────────────────────────────────

TarDatabase::TarDatabase(sqlite3* db) : db_{db} {}

TarDatabase::~TarDatabase() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

TarDatabase::TarDatabase(TarDatabase&& other) noexcept : db_{other.db_} {
    other.db_ = nullptr;
}

TarDatabase& TarDatabase::operator=(TarDatabase&& other) noexcept {
    if (this != &other) {
        if (db_)
            sqlite3_close(db_);
        db_ = other.db_;
        other.db_ = nullptr;
    }
    return *this;
}

std::expected<TarDatabase, std::string> TarDatabase::open(const std::filesystem::path& path) {
    // Ensure parent directory exists
    std::error_code ec;
    auto parent = path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return std::unexpected(
                std::format("failed to create directory {}: {}", parent.string(), ec.message()));
        }
    }

    sqlite3* raw_db = nullptr;
    int rc = sqlite3_open(path.string().c_str(), &raw_db);
    if (rc != SQLITE_OK) {
        std::string err = raw_db ? sqlite3_errmsg(raw_db) : "unknown error";
        if (raw_db)
            sqlite3_close(raw_db);
        return std::unexpected(std::format("failed to open tar.db: {}", err));
    }

    // WAL mode for concurrent read performance -- required for correctness
    char* err_msg = nullptr;
    rc = sqlite3_exec(raw_db, "PRAGMA journal_mode=WAL", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown";
        sqlite3_free(err_msg);
        sqlite3_close(raw_db);
        return std::unexpected(std::format("failed to enable WAL mode: {}", err));
    }
    sqlite3_free(err_msg);

    // Busy timeout for concurrent access
    sqlite3_busy_timeout(raw_db, 5000);

    // Secure delete -- zeroes deleted content; required for security
    err_msg = nullptr;
    rc = sqlite3_exec(raw_db, "PRAGMA secure_delete=ON", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown";
        sqlite3_free(err_msg);
        sqlite3_close(raw_db);
        return std::unexpected(std::format("failed to enable secure_delete: {}", err));
    }
    sqlite3_free(err_msg);

    // Create schema
    err_msg = nullptr;
    rc = sqlite3_exec(raw_db, kCreateSchema, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown error";
        sqlite3_free(err_msg);
        sqlite3_close(raw_db);
        return std::unexpected(std::format("failed to create TAR schema: {}", err));
    }

    // Set default retention if not already configured
    {
        const char* check_sql = "SELECT value FROM tar_config WHERE key = 'retention_days'";
        sqlite3_stmt* raw_stmt = nullptr;
        rc = sqlite3_prepare_v2(raw_db, check_sql, -1, &raw_stmt, nullptr);
        if (rc == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) != SQLITE_ROW) {
                // No retention_days configured -- set default
                const char* insert_sql =
                    "INSERT INTO tar_config (key, value) VALUES ('retention_days', '7')";
                sqlite3_exec(raw_db, insert_sql, nullptr, nullptr, nullptr);
            }
        }
    }

    auto db = TarDatabase{raw_db};

    // Migrate to warehouse schema if needed
    if (db.schema_version() < 2) {
        if (db.create_warehouse_tables()) {
            db.set_config("schema_version", "2");
            spdlog::info("TarDatabase: migrated to schema version 2 (typed warehouse tables)");
        } else {
            spdlog::warn("TarDatabase: warehouse table creation failed, continuing in legacy mode");
        }
    }

    // Disable load_extension for defense-in-depth (H2)
    sqlite3_db_config(raw_db, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, nullptr);

    // Version 3: retire legacy tar_events table (reclaim disk space)
    if (db.schema_version() == 2) {
        std::lock_guard lock(db.mu_);
        char* emsg = nullptr;
        // Use SAVEPOINT for atomicity
        sqlite3_exec(raw_db, "SAVEPOINT v3_migration", nullptr, nullptr, nullptr);
        int mrc = sqlite3_exec(raw_db, "DROP TABLE IF EXISTS tar_events", nullptr, nullptr, &emsg);
        if (mrc == SQLITE_OK) {
            sqlite3_free(emsg);
            sqlite3_exec(raw_db, "DROP INDEX IF EXISTS idx_tar_events_ts", nullptr, nullptr, nullptr);
            sqlite3_exec(raw_db, "DROP INDEX IF EXISTS idx_tar_events_type_ts", nullptr, nullptr, nullptr);
            sqlite3_exec(raw_db, "DROP INDEX IF EXISTS idx_tar_events_snapshot", nullptr, nullptr, nullptr);
            // Only set version to 3 if DROP succeeded
            db.set_config_locked("schema_version", "3");
            sqlite3_exec(raw_db, "RELEASE v3_migration", nullptr, nullptr, nullptr);
            spdlog::info("TarDatabase: migrated to schema version 3 (legacy tar_events retired)");
        } else {
            spdlog::warn("TarDatabase: failed to drop tar_events: {}", emsg ? emsg : "unknown");
            sqlite3_free(emsg);
            sqlite3_exec(raw_db, "ROLLBACK TO v3_migration", nullptr, nullptr, nullptr);
            sqlite3_exec(raw_db, "RELEASE v3_migration", nullptr, nullptr, nullptr);
        }
    }

    spdlog::info("TarDatabase opened: {} (schema v{})", path.string(), db.schema_version());
    return db;
}

// ── Statistics (queries typed warehouse tables) ─────────────────────────────

TarStats TarDatabase::stats() {
    std::lock_guard lock(mu_);
    TarStats s{};
    if (!db_)
        return s;

    // Aggregate record count across all live tables
    {
        const char* sql = "SELECT "
            "(SELECT COUNT(*) FROM process_live) + "
            "(SELECT COUNT(*) FROM tcp_live) + "
            "(SELECT COUNT(*) FROM service_live) + "
            "(SELECT COUNT(*) FROM user_live)";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW)
                s.record_count = sqlite3_column_int64(stmt.get(), 0);
        }
    }

    // Oldest timestamp across all live tables
    {
        const char* sql = "SELECT MIN(m) FROM ("
            "SELECT MIN(ts) AS m FROM process_live UNION ALL "
            "SELECT MIN(ts) FROM tcp_live UNION ALL "
            "SELECT MIN(ts) FROM service_live UNION ALL "
            "SELECT MIN(ts) FROM user_live)";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW)
                s.oldest_timestamp = sqlite3_column_int64(stmt.get(), 0);
        }
    }

    // Newest timestamp
    {
        const char* sql = "SELECT MAX(m) FROM ("
            "SELECT MAX(ts) AS m FROM process_live UNION ALL "
            "SELECT MAX(ts) FROM tcp_live UNION ALL "
            "SELECT MAX(ts) FROM service_live UNION ALL "
            "SELECT MAX(ts) FROM user_live)";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW)
                s.newest_timestamp = sqlite3_column_int64(stmt.get(), 0);
        }
    }

    // DB size (page_count * page_size)
    {
        const char* sql = "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW)
                s.db_size_bytes = sqlite3_column_int64(stmt.get(), 0);
        }
    }

    // Retention days from config
    {
        const char* sql = "SELECT value FROM tar_config WHERE key = 'retention_days'";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
                auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
                if (text) {
                    try { s.retention_days = std::stoi(text); } catch (...) { s.retention_days = 7; }
                }
            }
        }
    }

    return s;
}

// ── State management ─────────────────────────────────────────────────────────

std::string TarDatabase::get_state(const std::string& collector) {
    std::lock_guard lock(mu_);
    if (!db_)
        return {};

    const char* sql = "SELECT state_json FROM tar_state WHERE collector = ?";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::get_state prepare failed: {}", sqlite3_errmsg(db_));
        return {};
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, collector.c_str(), static_cast<int>(collector.size()),
                      SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        return text ? text : "";
    }
    return {};
}

void TarDatabase::set_state(const std::string& collector, const std::string& json) {
    std::lock_guard lock(mu_);
    if (!db_)
        return;

    const char* sql = R"(
        INSERT INTO tar_state (collector, state_json, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(collector) DO UPDATE SET state_json = excluded.state_json,
                                             updated_at = excluded.updated_at
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::set_state prepare failed: {}", sqlite3_errmsg(db_));
        return;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, collector.c_str(), static_cast<int>(collector.size()),
                      SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, json.c_str(), static_cast<int>(json.size()), SQLITE_STATIC);
    sqlite3_bind_int64(stmt.get(), 3, now_epoch_seconds());

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        spdlog::error("TarDatabase::set_state step failed: {}", sqlite3_errmsg(db_));
    }
}

// ── Config management ────────────────────────────────────────────────────────

std::string TarDatabase::get_config(const std::string& key, const std::string& default_val) {
    std::lock_guard lock(mu_);
    if (!db_)
        return default_val;

    const char* sql = "SELECT value FROM tar_config WHERE key = ?";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::get_config prepare failed: {}", sqlite3_errmsg(db_));
        return default_val;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, key.c_str(), static_cast<int>(key.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        return text ? text : default_val;
    }
    return default_val;
}

void TarDatabase::set_config(const std::string& key, const std::string& value) {
    std::lock_guard lock(mu_);
    set_config_locked(key, value);
}

void TarDatabase::set_config_locked(const std::string& key, const std::string& value) {
    if (!db_)
        return;

    const char* sql = R"(
        INSERT INTO tar_config (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::set_config prepare failed: {}", sqlite3_errmsg(db_));
        return;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, key.c_str(), static_cast<int>(key.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, value.c_str(), static_cast<int>(value.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        spdlog::error("TarDatabase::set_config step failed: {}", sqlite3_errmsg(db_));
    }
}

// ── Warehouse schema management ─────────────────────────────────────────────

int TarDatabase::schema_version() {
    auto v = get_config("schema_version", "0");
    try { return std::stoi(v); } catch (...) { return 0; }
}

bool TarDatabase::create_warehouse_tables() {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    auto ddl = generate_warehouse_ddl();
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, ddl.c_str(), nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::create_warehouse_tables failed: {}",
                       err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);
    return true;
}

// ── Typed inserts ───────────────────────────────────────────────────────────

bool TarDatabase::insert_process_events(const std::vector<ProcessEvent>& events) {
    std::lock_guard lock(mu_);
    if (!db_ || events.empty())
        return events.empty();

    char* err_msg = nullptr;
    int rc_begin = sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg);
    if (rc_begin != SQLITE_OK) {
        spdlog::error("insert_process_events BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO process_live (ts, snapshot_id, action, pid, ppid, name, cmdline, user)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_process_events prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& ev : events) {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
        sqlite3_bind_int64(stmt.get(), 1, ev.ts);
        sqlite3_bind_int64(stmt.get(), 2, ev.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, ev.action.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt.get(), 4, static_cast<int>(ev.pid));
        sqlite3_bind_int(stmt.get(), 5, static_cast<int>(ev.ppid));
        sqlite3_bind_text(stmt.get(), 6, ev.name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 7, ev.cmdline.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 8, ev.user.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_process_events step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
    }

    err_msg = nullptr;
    rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_process_events commit: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    return true;
}

bool TarDatabase::insert_network_events(const std::vector<NetworkEvent>& events) {
    std::lock_guard lock(mu_);
    if (!db_ || events.empty())
        return events.empty();

    char* err_msg = nullptr;
    int rc_begin = sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg);
    if (rc_begin != SQLITE_OK) {
        spdlog::error("insert_network_events BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO tcp_live (ts, snapshot_id, action, proto, local_addr, local_port,
                              remote_addr, remote_host, remote_port, state, pid, process_name)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_network_events prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& ev : events) {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
        sqlite3_bind_int64(stmt.get(), 1, ev.ts);
        sqlite3_bind_int64(stmt.get(), 2, ev.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, ev.action.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 4, ev.proto.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 5, ev.local_addr.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt.get(), 6, ev.local_port);
        sqlite3_bind_text(stmt.get(), 7, ev.remote_addr.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 8, ev.remote_host.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt.get(), 9, ev.remote_port);
        sqlite3_bind_text(stmt.get(), 10, ev.state.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt.get(), 11, static_cast<int>(ev.pid));
        sqlite3_bind_text(stmt.get(), 12, ev.process_name.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_network_events step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
    }

    err_msg = nullptr;
    rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_network_events commit: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    return true;
}

bool TarDatabase::insert_service_events(const std::vector<ServiceEvent>& events) {
    std::lock_guard lock(mu_);
    if (!db_ || events.empty())
        return events.empty();

    char* err_msg = nullptr;
    int rc_begin = sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg);
    if (rc_begin != SQLITE_OK) {
        spdlog::error("insert_service_events BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO service_live (ts, snapshot_id, action, name, display_name, status,
                                  prev_status, startup_type, prev_startup_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_service_events prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& ev : events) {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
        sqlite3_bind_int64(stmt.get(), 1, ev.ts);
        sqlite3_bind_int64(stmt.get(), 2, ev.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, ev.action.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 4, ev.name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 5, ev.display_name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 6, ev.status.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 7, ev.prev_status.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 8, ev.startup_type.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 9, ev.prev_startup_type.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_service_events step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
    }

    err_msg = nullptr;
    rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_service_events commit: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    return true;
}

bool TarDatabase::insert_user_events(const std::vector<UserEvent>& events) {
    std::lock_guard lock(mu_);
    if (!db_ || events.empty())
        return events.empty();

    char* err_msg = nullptr;
    int rc_begin = sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg);
    if (rc_begin != SQLITE_OK) {
        spdlog::error("insert_user_events BEGIN: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);

    const char* sql = R"(
        INSERT INTO user_live (ts, snapshot_id, action, user, domain, logon_type, session_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_user_events prepare: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& ev : events) {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
        sqlite3_bind_int64(stmt.get(), 1, ev.ts);
        sqlite3_bind_int64(stmt.get(), 2, ev.snapshot_id);
        sqlite3_bind_text(stmt.get(), 3, ev.action.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 4, ev.user.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 5, ev.domain.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 6, ev.logon_type.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 7, ev.session_id.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            spdlog::error("insert_user_events step: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
    }

    err_msg = nullptr;
    rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("insert_user_events commit: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    return true;
}

// ── Generic SQL execution ───────────────────────────────────────────────────

std::expected<QueryResult, std::string> TarDatabase::execute_query(const std::string& sql,
                                                                     int max_rows) {
    std::lock_guard lock(mu_);
    QueryResult result;
    if (!db_)
        return std::unexpected("database not open");

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        auto err = std::string(sqlite3_errmsg(db_));
        spdlog::error("execute_query prepare: {}", err);
        return std::unexpected(std::format("query failed: {}", err));
    }
    StmtPtr stmt(raw_stmt);

    // Extract column names
    int col_count = sqlite3_column_count(stmt.get());
    result.columns.reserve(col_count);
    for (int i = 0; i < col_count; ++i) {
        auto name = sqlite3_column_name(stmt.get(), i);
        result.columns.emplace_back(name ? name : "");
    }

    // Step through rows with enforced row limit (H1: prevent DoS via cross-joins)
    int row_count = 0;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        if (++row_count > max_rows) {
            spdlog::warn("execute_query: row limit ({}) exceeded, truncating", max_rows);
            break;
        }
        QueryRow row;
        row.reserve(col_count);
        for (int i = 0; i < col_count; ++i) {
            auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), i));
            row.emplace_back(text ? text : "");
        }
        result.rows.push_back(std::move(row));
    }

    return result;
}

bool TarDatabase::execute_sql(const std::string& sql) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("execute_sql failed: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }
    sqlite3_free(err_msg);
    return true;
}

bool TarDatabase::execute_sql_range(const std::string& sql, int64_t from, int64_t to) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("execute_sql_range prepare: {}", sqlite3_errmsg(db_));
        return false;
    }
    StmtPtr stmt(raw_stmt);

    // Bind all ? placeholders as repeating (from, to) pairs.
    // CONTRACT: All rollup SQL must use ? in (from, to) pairs with identical semantics.
    int param_count = sqlite3_bind_parameter_count(stmt.get());
    if (param_count % 2 != 0) {
        spdlog::error("execute_sql_range: odd parameter count {} — expected (from,to) pairs",
                       param_count);
        return false;
    }
    for (int i = 1; i <= param_count; i += 2) {
        sqlite3_bind_int64(stmt.get(), i, from);
        sqlite3_bind_int64(stmt.get(), i + 1, to);
    }

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        spdlog::error("execute_sql_range step: {}", sqlite3_errmsg(db_));
        return false;
    }
    return true;
}

} // namespace yuzu::tar
