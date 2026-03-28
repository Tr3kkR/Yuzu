#include "quarantine_store.hpp"

#include <spdlog/spdlog.h>

#include <chrono>
#include <mutex>

namespace yuzu::server {

static int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static const char* safe(const char* p) {
    return p ? p : "";
}

// ── Construction / teardown ──────────────────────────────────────────────────

QuarantineStore::QuarantineStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("QuarantineStore: failed to open {}: {}", db_path.string(),
                      sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    create_tables();
    spdlog::info("QuarantineStore: opened {}", db_path.string());
}

QuarantineStore::~QuarantineStore() {
    if (db_)
        sqlite3_close(db_);
}

bool QuarantineStore::is_open() const {
    return db_ != nullptr;
}

void QuarantineStore::create_tables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS quarantine_records (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id        TEXT NOT NULL,
            status          TEXT NOT NULL DEFAULT 'active',
            quarantined_by  TEXT,
            quarantined_at  INTEGER NOT NULL DEFAULT 0,
            released_at     INTEGER NOT NULL DEFAULT 0,
            whitelist       TEXT NOT NULL DEFAULT '',
            reason          TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_quarantine_agent ON quarantine_records(agent_id);
        CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine_records(status);
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("QuarantineStore: create_tables failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }
}

// ── Operations ───────────────────────────────────────────────────────────────

std::expected<void, std::string> QuarantineStore::quarantine_device(const std::string& agent_id,
                                                                    const std::string& by,
                                                                    const std::string& reason,
                                                                    const std::string& whitelist) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");

    // Check if already quarantined — atomic check+insert under lock
    auto current = get_status_impl(agent_id);
    if (current && current->status == "active")
        return std::unexpected("device is already quarantined");

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO quarantine_records "
                           "(agent_id, status, quarantined_by, quarantined_at, whitelist, reason) "
                           "VALUES (?, 'active', ?, ?, ?, ?);",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));

    auto now = now_epoch();
    sqlite3_bind_text(s, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 3, now);
    sqlite3_bind_text(s, 4, whitelist.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 5, reason.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return std::unexpected(sqlite3_errmsg(db_));
    return {};
}

std::expected<void, std::string> QuarantineStore::release_device(const std::string& agent_id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return std::unexpected("database not open");

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "UPDATE quarantine_records SET status = 'released', released_at = ? "
                           "WHERE agent_id = ? AND status = 'active';",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));

    sqlite3_bind_int64(s, 1, now_epoch());
    sqlite3_bind_text(s, 2, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);

    if (sqlite3_changes(db_) == 0)
        return std::unexpected("device is not quarantined");
    return {};
}

std::optional<QuarantineRecord> QuarantineStore::get_status(const std::string& agent_id) const {
    std::shared_lock lock(mtx_);
    return get_status_impl(agent_id);
}

std::optional<QuarantineRecord> QuarantineStore::get_status_impl(const std::string& agent_id) const {
    if (!db_)
        return std::nullopt;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "SELECT agent_id, status, quarantined_by, quarantined_at, released_at, whitelist, "
            "reason "
            "FROM quarantine_records WHERE agent_id = ? AND status = 'active' LIMIT 1;",
            -1, &s, nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(s, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<QuarantineRecord> result;
    if (sqlite3_step(s) == SQLITE_ROW) {
        QuarantineRecord r;
        r.agent_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        r.status = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        r.quarantined_by = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
        r.quarantined_at = sqlite3_column_int64(s, 3);
        r.released_at = sqlite3_column_int64(s, 4);
        r.whitelist = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 5)));
        r.reason = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 6)));
        result = std::move(r);
    }
    sqlite3_finalize(s);
    return result;
}

std::vector<QuarantineRecord> QuarantineStore::list_quarantined() const {
    std::shared_lock lock(mtx_);
    std::vector<QuarantineRecord> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "SELECT agent_id, status, quarantined_by, quarantined_at, released_at, whitelist, "
            "reason "
            "FROM quarantine_records WHERE status = 'active' ORDER BY quarantined_at DESC;",
            -1, &s, nullptr) != SQLITE_OK)
        return result;
    while (sqlite3_step(s) == SQLITE_ROW) {
        QuarantineRecord r;
        r.agent_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        r.status = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        r.quarantined_by = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
        r.quarantined_at = sqlite3_column_int64(s, 3);
        r.released_at = sqlite3_column_int64(s, 4);
        r.whitelist = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 5)));
        r.reason = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 6)));
        result.push_back(std::move(r));
    }
    sqlite3_finalize(s);
    return result;
}

std::vector<QuarantineRecord> QuarantineStore::get_history(const std::string& agent_id) const {
    std::shared_lock lock(mtx_);
    std::vector<QuarantineRecord> result;
    if (!db_)
        return result;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "SELECT agent_id, status, quarantined_by, quarantined_at, released_at, whitelist, "
            "reason "
            "FROM quarantine_records WHERE agent_id = ? ORDER BY quarantined_at DESC, rowid DESC;",
            -1, &s, nullptr) != SQLITE_OK)
        return result;
    sqlite3_bind_text(s, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(s) == SQLITE_ROW) {
        QuarantineRecord r;
        r.agent_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        r.status = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        r.quarantined_by = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
        r.quarantined_at = sqlite3_column_int64(s, 3);
        r.released_at = sqlite3_column_int64(s, 4);
        r.whitelist = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 5)));
        r.reason = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 6)));
        result.push_back(std::move(r));
    }
    sqlite3_finalize(s);
    return result;
}

} // namespace yuzu::server
