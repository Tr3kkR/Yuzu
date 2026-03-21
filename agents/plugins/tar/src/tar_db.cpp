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

    spdlog::info("TarDatabase opened: {}", path.string());
    return TarDatabase{raw_db};
}

// ── Event operations ─────────────────────────────────────────────────────────

bool TarDatabase::insert_events(const std::vector<TarEvent>& events) {
    std::lock_guard lock(mu_);
    if (!db_ || events.empty())
        return events.empty(); // empty is vacuously successful

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::insert_events BEGIN failed: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return false;
    }

    const char* sql = R"(
        INSERT INTO tar_events (timestamp, event_type, event_action, detail_json, snapshot_id)
        VALUES (?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::insert_events prepare failed: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }
    StmtPtr stmt(raw_stmt);

    for (const auto& ev : events) {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());

        sqlite3_bind_int64(stmt.get(), 1, ev.timestamp);
        sqlite3_bind_text(stmt.get(), 2, ev.event_type.c_str(),
                          static_cast<int>(ev.event_type.size()), SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 3, ev.event_action.c_str(),
                          static_cast<int>(ev.event_action.size()), SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 4, ev.detail_json.c_str(),
                          static_cast<int>(ev.detail_json.size()), SQLITE_STATIC);
        sqlite3_bind_int64(stmt.get(), 5, ev.snapshot_id);

        rc = sqlite3_step(stmt.get());
        if (rc != SQLITE_DONE) {
            spdlog::error("TarDatabase::insert_events step failed: {}", sqlite3_errmsg(db_));
            sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
            return false;
        }
    }

    err_msg = nullptr;
    rc = sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::insert_events COMMIT failed: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        return false;
    }

    return true;
}

std::vector<TarEvent> TarDatabase::query(int64_t from, int64_t to,
                                          const std::string& type_filter, int limit) {
    std::lock_guard lock(mu_);
    std::vector<TarEvent> results;
    if (!db_)
        return results;

    std::string sql;
    if (type_filter.empty()) {
        sql = R"(
            SELECT id, timestamp, event_type, event_action, detail_json, snapshot_id
            FROM tar_events
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp ASC
            LIMIT ?
        )";
    } else {
        sql = R"(
            SELECT id, timestamp, event_type, event_action, detail_json, snapshot_id
            FROM tar_events
            WHERE timestamp >= ? AND timestamp <= ? AND event_type = ?
            ORDER BY timestamp ASC
            LIMIT ?
        )";
    }

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::query prepare failed: {}", sqlite3_errmsg(db_));
        return results;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_int64(stmt.get(), 1, from);
    sqlite3_bind_int64(stmt.get(), 2, to);

    if (type_filter.empty()) {
        sqlite3_bind_int(stmt.get(), 3, limit);
    } else {
        sqlite3_bind_text(stmt.get(), 3, type_filter.c_str(),
                          static_cast<int>(type_filter.size()), SQLITE_STATIC);
        sqlite3_bind_int(stmt.get(), 4, limit);
    }

    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        TarEvent ev;
        ev.id = sqlite3_column_int64(stmt.get(), 0);
        ev.timestamp = sqlite3_column_int64(stmt.get(), 1);

        auto col2 = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
        ev.event_type = col2 ? col2 : "";

        auto col3 = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 3));
        ev.event_action = col3 ? col3 : "";

        auto col4 = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 4));
        ev.detail_json = col4 ? col4 : "{}";

        ev.snapshot_id = sqlite3_column_int64(stmt.get(), 5);

        results.push_back(std::move(ev));
    }

    return results;
}

int TarDatabase::purge(int64_t before_timestamp) {
    std::lock_guard lock(mu_);
    if (!db_)
        return 0;

    const char* sql = "DELETE FROM tar_events WHERE timestamp < ?";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("TarDatabase::purge prepare failed: {}", sqlite3_errmsg(db_));
        return 0;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_int64(stmt.get(), 1, before_timestamp);

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        spdlog::error("TarDatabase::purge step failed: {}", sqlite3_errmsg(db_));
        return 0;
    }

    int deleted = sqlite3_changes(db_);
    if (deleted > 0) {
        spdlog::info("TarDatabase: purged {} events older than {}", deleted, before_timestamp);
    }
    return deleted;
}

TarStats TarDatabase::stats() {
    std::lock_guard lock(mu_);
    TarStats s{};
    if (!db_)
        return s;

    // Record count
    {
        const char* sql = "SELECT COUNT(*) FROM tar_events";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
                s.record_count = sqlite3_column_int64(stmt.get(), 0);
            }
        }
    }

    // Oldest timestamp
    {
        const char* sql = "SELECT MIN(timestamp) FROM tar_events";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
                s.oldest_timestamp = sqlite3_column_int64(stmt.get(), 0);
            }
        }
    }

    // Newest timestamp
    {
        const char* sql = "SELECT MAX(timestamp) FROM tar_events";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
                s.newest_timestamp = sqlite3_column_int64(stmt.get(), 0);
            }
        }
    }

    // DB size (page_count * page_size)
    {
        const char* sql = "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()";
        sqlite3_stmt* raw_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr) == SQLITE_OK) {
            StmtPtr stmt(raw_stmt);
            if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
                s.db_size_bytes = sqlite3_column_int64(stmt.get(), 0);
            }
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
                    try {
                        s.retention_days = std::stoi(text);
                    } catch (...) {
                        s.retention_days = 7;
                    }
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

} // namespace yuzu::tar
