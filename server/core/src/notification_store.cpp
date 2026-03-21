#include "notification_store.hpp"

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <chrono>
#include <shared_mutex>

namespace yuzu::server {

NotificationStore::NotificationStore(const std::filesystem::path& db_path) {
    // M8: Canonicalize the path before opening to handle macOS /var -> /private/var
    // symlink and other platform-specific path resolution issues.
    auto canonical_path = db_path;
    {
        std::error_code ec;
        auto parent = db_path.parent_path();
        if (!parent.empty() && std::filesystem::exists(parent, ec)) {
            auto canon_parent = std::filesystem::canonical(parent, ec);
            if (!ec)
                canonical_path = canon_parent / db_path.filename();
        }
    }
    int rc = sqlite3_open(canonical_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("NotificationStore: failed to open {}: {}", canonical_path.string(),
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
    spdlog::info("NotificationStore: opened {}", canonical_path.string());
}

NotificationStore::~NotificationStore() {
    if (db_)
        sqlite3_close(db_);
}

bool NotificationStore::is_open() const {
    return db_ != nullptr;
}

void NotificationStore::create_tables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS notifications (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   INTEGER NOT NULL,
            level       TEXT    NOT NULL DEFAULT 'info',
            title       TEXT    NOT NULL,
            message     TEXT    NOT NULL DEFAULT '',
            read        INTEGER NOT NULL DEFAULT 0,
            dismissed   INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_notif_read_ts
            ON notifications(read, timestamp);
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("NotificationStore: create_tables failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }
}

int64_t NotificationStore::create(const std::string& level, const std::string& title,
                                  const std::string& message) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return -1;

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

    const char* sql = "INSERT INTO notifications (timestamp, level, title, message) VALUES (?, ?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return -1;

    sqlite3_bind_int64(stmt, 1, now);
    sqlite3_bind_text(stmt, 2, level.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, title.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, message.c_str(), -1, SQLITE_TRANSIENT);

    int64_t result = -1;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        result = sqlite3_last_insert_rowid(db_);
    }
    sqlite3_finalize(stmt);
    return result;
}

static Notification row_to_notification(sqlite3_stmt* stmt) {
    Notification n;
    n.id = sqlite3_column_int64(stmt, 0);
    n.timestamp = sqlite3_column_int64(stmt, 1);
    auto lv = sqlite3_column_text(stmt, 2);
    if (lv)
        n.level = reinterpret_cast<const char*>(lv);
    auto ti = sqlite3_column_text(stmt, 3);
    if (ti)
        n.title = reinterpret_cast<const char*>(ti);
    auto msg = sqlite3_column_text(stmt, 4);
    if (msg)
        n.message = reinterpret_cast<const char*>(msg);
    n.read = sqlite3_column_int(stmt, 5) != 0;
    n.dismissed = sqlite3_column_int(stmt, 6) != 0;
    return n;
}

std::vector<Notification> NotificationStore::list_unread(int limit) const {
    std::shared_lock lock(mtx_);
    std::vector<Notification> results;
    if (!db_)
        return results;

    const char* sql = "SELECT id, timestamp, level, title, message, read, dismissed "
                      "FROM notifications WHERE read = 0 AND dismissed = 0 "
                      "ORDER BY timestamp DESC LIMIT ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    sqlite3_bind_int(stmt, 1, limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        results.push_back(row_to_notification(stmt));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::vector<Notification> NotificationStore::list_all(int limit, int offset) const {
    std::shared_lock lock(mtx_);
    std::vector<Notification> results;
    if (!db_)
        return results;

    const char* sql = "SELECT id, timestamp, level, title, message, read, dismissed "
                      "FROM notifications ORDER BY timestamp DESC LIMIT ? OFFSET ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    sqlite3_bind_int(stmt, 1, limit);
    sqlite3_bind_int(stmt, 2, offset);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        results.push_back(row_to_notification(stmt));
    }
    sqlite3_finalize(stmt);
    return results;
}

void NotificationStore::mark_read(int64_t id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return;

    const char* sql = "UPDATE notifications SET read = 1 WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_int64(stmt, 1, id);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void NotificationStore::dismiss(int64_t id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return;

    const char* sql = "UPDATE notifications SET dismissed = 1 WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_int64(stmt, 1, id);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::size_t NotificationStore::count_unread() const {
    std::shared_lock lock(mtx_);
    if (!db_)
        return 0;

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM notifications WHERE read = 0 AND dismissed = 0",
                           -1, &stmt, nullptr) != SQLITE_OK)
        return 0;

    std::size_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 0));
    sqlite3_finalize(stmt);
    return count;
}

} // namespace yuzu::server
