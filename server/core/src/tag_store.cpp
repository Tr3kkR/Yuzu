#include "tag_store.hpp"

#include <algorithm>
#include <chrono>
#include <regex>

#include <spdlog/spdlog.h>
#include <sqlite3.h>

namespace yuzu::server {

TagStore::TagStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("TagStore: failed to open {}: {}",
                      db_path.string(), sqlite3_errmsg(db_));
        if (db_) { sqlite3_close(db_); db_ = nullptr; }
        return;
    }

    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    create_tables();
    spdlog::info("TagStore: opened {}", db_path.string());
}

TagStore::~TagStore() {
    if (db_) sqlite3_close(db_);
}

bool TagStore::is_open() const { return db_ != nullptr; }

void TagStore::create_tables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS tags (
            agent_id    TEXT NOT NULL,
            key         TEXT NOT NULL,
            value       TEXT NOT NULL,
            source      TEXT NOT NULL DEFAULT 'server',
            updated_at  INTEGER NOT NULL,
            PRIMARY KEY (agent_id, key)
        );
        CREATE INDEX IF NOT EXISTS idx_tags_key_value
            ON tags(key, value);
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("TagStore: create_tables failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }
}

bool TagStore::validate_key(const std::string& key) {
    if (key.empty() || key.size() > 64) return false;
    for (char c : key) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == ':')) {
            return false;
        }
    }
    return true;
}

bool TagStore::validate_value(const std::string& value) {
    return value.size() <= 448;
}

void TagStore::set_tag(const std::string& agent_id, const std::string& key,
                       const std::string& value, const std::string& source) {
    if (!db_) return;
    if (!validate_key(key) || !validate_value(value)) return;

    const char* sql = R"(
        INSERT OR REPLACE INTO tags (agent_id, key, value, source, updated_at)
        VALUES (?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return;

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, value.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, source.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, now);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::string TagStore::get_tag(const std::string& agent_id, const std::string& key) const {
    if (!db_) return {};
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT value FROM tags WHERE agent_id = ? AND key = ?",
                           -1, &stmt, nullptr) != SQLITE_OK) return {};

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, key.c_str(), -1, SQLITE_TRANSIENT);

    std::string result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        auto t = sqlite3_column_text(stmt, 0);
        if (t) result = reinterpret_cast<const char*>(t);
    }
    sqlite3_finalize(stmt);
    return result;
}

bool TagStore::delete_tag(const std::string& agent_id, const std::string& key) {
    if (!db_) return false;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM tags WHERE agent_id = ? AND key = ?",
                           -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, key.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return sqlite3_changes(db_) > 0;
}

std::vector<DeviceTag> TagStore::get_all_tags(const std::string& agent_id) const {
    std::vector<DeviceTag> results;
    if (!db_) return results;

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
            "SELECT key, value, source, updated_at FROM tags WHERE agent_id = ? ORDER BY key",
            -1, &stmt, nullptr) != SQLITE_OK) return results;

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        DeviceTag t;
        t.agent_id   = agent_id;
        auto k = sqlite3_column_text(stmt, 0);
        if (k) t.key = reinterpret_cast<const char*>(k);
        auto v = sqlite3_column_text(stmt, 1);
        if (v) t.value = reinterpret_cast<const char*>(v);
        auto s = sqlite3_column_text(stmt, 2);
        if (s) t.source = reinterpret_cast<const char*>(s);
        t.updated_at = sqlite3_column_int64(stmt, 3);
        results.push_back(std::move(t));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::unordered_map<std::string, std::string> TagStore::get_tag_map(const std::string& agent_id) const {
    std::unordered_map<std::string, std::string> result;
    if (!db_) return result;

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT key, value FROM tags WHERE agent_id = ?",
                           -1, &stmt, nullptr) != SQLITE_OK) return result;

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto k = sqlite3_column_text(stmt, 0);
        auto v = sqlite3_column_text(stmt, 1);
        if (k && v) {
            result[reinterpret_cast<const char*>(k)] = reinterpret_cast<const char*>(v);
        }
    }
    sqlite3_finalize(stmt);
    return result;
}

void TagStore::sync_agent_tags(const std::string& agent_id,
                               const std::unordered_map<std::string, std::string>& tags) {
    if (!db_) return;

    // Delete all agent-sourced tags, then re-insert
    sqlite3_exec(db_, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_,
                "DELETE FROM tags WHERE agent_id = ? AND source = 'agent'",
                -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    for (const auto& [key, value] : tags) {
        if (!validate_key(key) || !validate_value(value)) continue;
        set_tag(agent_id, key, value, "agent");
    }

    sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, nullptr);
}

void TagStore::delete_all_tags(const std::string& agent_id) {
    if (!db_) return;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM tags WHERE agent_id = ?",
                           -1, &stmt, nullptr) != SQLITE_OK) return;

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::vector<std::string> TagStore::agents_with_tag(const std::string& key,
                                                   const std::string& value) const {
    std::vector<std::string> result;
    if (!db_) return result;

    std::string sql = "SELECT DISTINCT agent_id FROM tags WHERE key = ?";
    if (!value.empty()) sql += " AND value = ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return result;

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    if (!value.empty()) {
        sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_TRANSIENT);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto t = sqlite3_column_text(stmt, 0);
        if (t) result.emplace_back(reinterpret_cast<const char*>(t));
    }
    sqlite3_finalize(stmt);
    return result;
}

}  // namespace yuzu::server
