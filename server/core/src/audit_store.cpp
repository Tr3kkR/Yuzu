#include "audit_store.hpp"

#include <chrono>

#include <spdlog/spdlog.h>
#include <sqlite3.h>

namespace yuzu::server {

AuditStore::AuditStore(const std::filesystem::path& db_path,
                       int retention_days,
                       int cleanup_interval_min)
    : retention_days_(retention_days),
      cleanup_interval_min_(cleanup_interval_min)
{
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("AuditStore: failed to open {}: {}",
                      db_path.string(), sqlite3_errmsg(db_));
        if (db_) { sqlite3_close(db_); db_ = nullptr; }
        return;
    }

    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    create_tables();
    spdlog::info("AuditStore: opened {} (retention={}d)", db_path.string(), retention_days_);
}

AuditStore::~AuditStore() {
    stop_cleanup();
    if (db_) sqlite3_close(db_);
}

bool AuditStore::is_open() const { return db_ != nullptr; }

void AuditStore::create_tables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS audit_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       INTEGER NOT NULL,
            principal       TEXT    NOT NULL,
            principal_role  TEXT    NOT NULL,
            action          TEXT    NOT NULL,
            target_type     TEXT,
            target_id       TEXT,
            detail          TEXT,
            source_ip       TEXT,
            user_agent      TEXT,
            session_id      TEXT,
            result          TEXT    NOT NULL,
            ttl_expires_at  INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_audit_ts
            ON audit_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_principal_ts
            ON audit_events(principal, timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_action_ts
            ON audit_events(action, timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_target_ts
            ON audit_events(target_type, target_id, timestamp);
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("AuditStore: create_tables failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }
}

void AuditStore::log(const AuditEvent& event) {
    if (!db_) return;

    const char* sql = R"(
        INSERT INTO audit_events (timestamp, principal, principal_role, action,
            target_type, target_id, detail, source_ip, user_agent, session_id, result, ttl_expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return;

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto ts = event.timestamp > 0 ? event.timestamp : now;
    auto ttl = retention_days_ > 0 ? now + retention_days_ * 86400LL : 0;

    sqlite3_bind_int64(stmt, 1, ts);
    sqlite3_bind_text(stmt, 2, event.principal.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, event.principal_role.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, event.action.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, event.target_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, event.target_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, event.detail.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, event.source_ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, event.user_agent.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, event.session_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, event.result.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 12, ttl);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::vector<AuditEvent> AuditStore::query(const AuditQuery& q) const {
    std::vector<AuditEvent> results;
    if (!db_) return results;

    std::string sql = "SELECT id, timestamp, principal, principal_role, action, target_type, target_id, detail, source_ip, user_agent, session_id, result FROM audit_events WHERE 1=1";
    std::vector<std::pair<int, std::string>> binds;
    int bind_idx = 1;

    if (!q.principal.empty()) {
        sql += " AND principal = ?";
        binds.emplace_back(bind_idx++, q.principal);
    }
    if (!q.action.empty()) {
        sql += " AND action = ?";
        binds.emplace_back(bind_idx++, q.action);
    }
    if (!q.target_type.empty()) {
        sql += " AND target_type = ?";
        binds.emplace_back(bind_idx++, q.target_type);
    }
    if (!q.target_id.empty()) {
        sql += " AND target_id = ?";
        binds.emplace_back(bind_idx++, q.target_id);
    }
    if (q.since > 0) {
        sql += " AND timestamp >= " + std::to_string(q.since);
    }
    if (q.until > 0) {
        sql += " AND timestamp <= " + std::to_string(q.until);
    }
    sql += " ORDER BY timestamp DESC";
    sql += " LIMIT " + std::to_string(q.limit);
    if (q.offset > 0) {
        sql += " OFFSET " + std::to_string(q.offset);
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return results;

    for (const auto& [idx, val] : binds) {
        sqlite3_bind_text(stmt, idx, val.c_str(), -1, SQLITE_TRANSIENT);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AuditEvent e;
        e.id             = sqlite3_column_int64(stmt, 0);
        e.timestamp      = sqlite3_column_int64(stmt, 1);
        auto col_text = [&](int c) -> std::string {
            auto t = sqlite3_column_text(stmt, c);
            return t ? reinterpret_cast<const char*>(t) : std::string{};
        };
        e.principal      = col_text(2);
        e.principal_role = col_text(3);
        e.action         = col_text(4);
        e.target_type    = col_text(5);
        e.target_id      = col_text(6);
        e.detail         = col_text(7);
        e.source_ip      = col_text(8);
        e.user_agent     = col_text(9);
        e.session_id     = col_text(10);
        e.result         = col_text(11);
        results.push_back(std::move(e));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::size_t AuditStore::total_count() const {
    if (!db_) return 0;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM audit_events", -1, &stmt, nullptr) != SQLITE_OK)
        return 0;
    std::size_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 0));
    sqlite3_finalize(stmt);
    return count;
}

void AuditStore::start_cleanup() {
    if (!db_ || cleanup_interval_min_ <= 0) return;
#ifdef __cpp_lib_jthread
    cleanup_thread_ = std::jthread([this](std::stop_token stop) { run_cleanup(stop); });
#else
    stop_requested_ = false;
    cleanup_thread_ = std::thread([this]() { run_cleanup(); });
#endif
}

void AuditStore::stop_cleanup() {
#ifdef __cpp_lib_jthread
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.request_stop();
        cleanup_thread_.join();
    }
#else
    stop_requested_ = true;
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
#endif
}

#ifdef __cpp_lib_jthread
void AuditStore::run_cleanup(std::stop_token stop) {
    while (!stop.stop_requested()) {
        for (int i = 0; i < cleanup_interval_min_ * 60 && !stop.stop_requested(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (stop.stop_requested()) break;
#else
void AuditStore::run_cleanup() {
    while (!stop_requested_.load()) {
        for (int i = 0; i < cleanup_interval_min_ * 60 && !stop_requested_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (stop_requested_.load()) break;
#endif

        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        char* err = nullptr;
        auto sql = "DELETE FROM audit_events WHERE ttl_expires_at > 0 AND ttl_expires_at < " + std::to_string(now);
        if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err) == SQLITE_OK) {
            auto deleted = sqlite3_changes(db_);
            if (deleted > 0) {
                spdlog::info("AuditStore: expired {} rows", deleted);
            }
        } else {
            spdlog::warn("AuditStore: cleanup error: {}", err ? err : "unknown");
            sqlite3_free(err);
        }
    }
}

}  // namespace yuzu::server
