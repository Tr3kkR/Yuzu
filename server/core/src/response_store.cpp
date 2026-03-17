#include "response_store.hpp"

#include <chrono>

#include <spdlog/spdlog.h>
#include <sqlite3.h>

namespace yuzu::server {

ResponseStore::ResponseStore(const std::filesystem::path& db_path,
                             int retention_days,
                             int cleanup_interval_min)
    : db_path_(db_path),
      retention_days_(retention_days),
      cleanup_interval_min_(cleanup_interval_min)
{
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("ResponseStore: failed to open {}: {}",
                      db_path.string(), sqlite3_errmsg(db_));
        if (db_) { sqlite3_close(db_); db_ = nullptr; }
        return;
    }

    // Enable WAL mode and busy timeout
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    create_tables();
    spdlog::info("ResponseStore: opened {} (retention={}d)", db_path.string(), retention_days_);
}

ResponseStore::~ResponseStore() {
    stop_cleanup();
    if (db_) sqlite3_close(db_);
}

bool ResponseStore::is_open() const { return db_ != nullptr; }

void ResponseStore::create_tables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS responses (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            instruction_id  TEXT    NOT NULL,
            agent_id        TEXT    NOT NULL,
            timestamp       INTEGER NOT NULL,
            status          INTEGER NOT NULL,
            output          TEXT    NOT NULL,
            error_detail    TEXT,
            ttl_expires_at  INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_resp_instr_ts
            ON responses(instruction_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_resp_agent_ts
            ON responses(agent_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_resp_ttl
            ON responses(ttl_expires_at) WHERE ttl_expires_at > 0;
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("ResponseStore: create_tables failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }
}

void ResponseStore::store(const StoredResponse& resp) {
    if (!db_) return;

    const char* sql = R"(
        INSERT INTO responses (instruction_id, agent_id, timestamp, status, output, error_detail, ttl_expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return;

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto ts = resp.timestamp > 0 ? resp.timestamp : now;
    auto ttl = resp.ttl_expires_at > 0
        ? resp.ttl_expires_at
        : (retention_days_ > 0 ? now + retention_days_ * 86400LL : 0);

    sqlite3_bind_text(stmt, 1, resp.instruction_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, resp.agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, ts);
    sqlite3_bind_int(stmt, 4, resp.status);
    sqlite3_bind_text(stmt, 5, resp.output.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, resp.error_detail.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 7, ttl);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::vector<StoredResponse> ResponseStore::query(const std::string& instruction_id,
                                                 const ResponseQuery& q) const {
    std::vector<StoredResponse> results;
    if (!db_) return results;

    std::string sql = "SELECT id, instruction_id, agent_id, timestamp, status, output, error_detail, ttl_expires_at FROM responses WHERE instruction_id = ?";
    std::vector<std::string> bind_texts;
    bind_texts.push_back(instruction_id);

    if (!q.agent_id.empty()) {
        sql += " AND agent_id = ?";
        bind_texts.push_back(q.agent_id);
    }
    if (q.status >= 0) {
        sql += " AND status = " + std::to_string(q.status);
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

    for (int i = 0; i < static_cast<int>(bind_texts.size()); ++i) {
        sqlite3_bind_text(stmt, i + 1, bind_texts[i].c_str(), -1, SQLITE_TRANSIENT);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        StoredResponse r;
        r.id             = sqlite3_column_int64(stmt, 0);
        r.instruction_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        r.agent_id       = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        r.timestamp      = sqlite3_column_int64(stmt, 3);
        r.status         = sqlite3_column_int(stmt, 4);
        auto out = sqlite3_column_text(stmt, 5);
        if (out) r.output = reinterpret_cast<const char*>(out);
        auto err = sqlite3_column_text(stmt, 6);
        if (err) r.error_detail = reinterpret_cast<const char*>(err);
        r.ttl_expires_at = sqlite3_column_int64(stmt, 7);
        results.push_back(std::move(r));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::vector<StoredResponse> ResponseStore::get_by_instruction(const std::string& instruction_id) const {
    return query(instruction_id);
}

std::size_t ResponseStore::total_count() const {
    if (!db_) return 0;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM responses", -1, &stmt, nullptr) != SQLITE_OK)
        return 0;
    std::size_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = static_cast<std::size_t>(sqlite3_column_int64(stmt, 0));
    sqlite3_finalize(stmt);
    return count;
}

std::uintmax_t ResponseStore::db_size_bytes() const {
    if (db_path_.empty() || db_path_.string() == ":memory:") return 0;
    std::error_code ec;
    return std::filesystem::file_size(db_path_, ec);
}

void ResponseStore::start_cleanup() {
    if (!db_ || cleanup_interval_min_ <= 0) return;
    cleanup_thread_ = std::jthread([this](std::stop_token stop) { run_cleanup(stop); });
}

void ResponseStore::stop_cleanup() {
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.request_stop();
        cleanup_thread_.join();
    }
}

void ResponseStore::run_cleanup(std::stop_token stop) {
    while (!stop.stop_requested()) {
        for (int i = 0; i < cleanup_interval_min_ * 60 && !stop.stop_requested(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (stop.stop_requested()) break;

        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        char* err = nullptr;
        auto sql = "DELETE FROM responses WHERE ttl_expires_at > 0 AND ttl_expires_at < " + std::to_string(now);
        if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err) == SQLITE_OK) {
            auto deleted = sqlite3_changes(db_);
            if (deleted > 0) {
                spdlog::info("ResponseStore: expired {} rows", deleted);
            }
        } else {
            spdlog::warn("ResponseStore: cleanup error: {}", err ? err : "unknown");
            sqlite3_free(err);
        }
    }
}

}  // namespace yuzu::server
