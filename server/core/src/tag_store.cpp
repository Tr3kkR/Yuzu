#include "tag_store.hpp"
#include "migration_runner.hpp"

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <mutex>
#include <regex>
#include <unordered_set>

namespace yuzu::server {

// ── Tag categories (compile-time fixed) ──────────────────────────────────────

const std::vector<TagCategory>& get_tag_categories() {
    static const std::vector<TagCategory> categories = {
        {"role", "Role", {}},
        {"environment", "Environment", {"Dev", "UAT", "Production"}},
        {"location", "Location", {}},
        {"service", "Service", {}},
    };
    return categories;
}

TagStore::TagStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open_v2(db_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("TagStore: failed to open {}: {}", db_path.string(), sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }

    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    create_tables();
    if (db_)
        spdlog::info("TagStore: opened {}", db_path.string());
}

TagStore::~TagStore() {
    if (db_)
        sqlite3_close(db_);
}

bool TagStore::is_open() const {
    return db_ != nullptr;
}

void TagStore::create_tables() {
    static const std::vector<Migration> kMigrations = {
        {1, R"(
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
        )"},
    };
    if (!MigrationRunner::run(db_, "tag_store", kMigrations)) {
        spdlog::error("TagStore: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool TagStore::validate_key(const std::string& key) {
    if (key.empty() || key.size() > 64)
        return false;
    for (char c : key) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.' || c == ':')) {
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
    std::unique_lock lock(mtx_);
    set_tag_impl(agent_id, key, value, source);
}

void TagStore::set_tag_impl(const std::string& agent_id, const std::string& key,
                            const std::string& value, const std::string& source) {
    if (!db_)
        return;
    if (!validate_key(key) || !validate_value(value))
        return;

    const char* sql = R"(
        INSERT OR REPLACE INTO tags (agent_id, key, value, source, updated_at)
        VALUES (?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, value.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, source.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, now);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::string TagStore::get_tag(const std::string& agent_id, const std::string& key) const {
    std::shared_lock lock(mtx_);
    return get_tag_impl(agent_id, key);
}

std::string TagStore::get_tag_impl(const std::string& agent_id, const std::string& key) const {
    if (!db_)
        return {};
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT value FROM tags WHERE agent_id = ? AND key = ?", -1, &stmt,
                           nullptr) != SQLITE_OK)
        return {};

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, key.c_str(), -1, SQLITE_TRANSIENT);

    std::string result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        auto t = sqlite3_column_text(stmt, 0);
        if (t)
            result = reinterpret_cast<const char*>(t);
    }
    sqlite3_finalize(stmt);
    return result;
}

bool TagStore::delete_tag(const std::string& agent_id, const std::string& key) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return false;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM tags WHERE agent_id = ? AND key = ?", -1, &stmt,
                           nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, key.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return sqlite3_changes(db_) > 0;
}

std::vector<DeviceTag> TagStore::get_all_tags(const std::string& agent_id) const {
    std::shared_lock lock(mtx_);
    std::vector<DeviceTag> results;
    if (!db_)
        return results;

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(
            db_, "SELECT key, value, source, updated_at FROM tags WHERE agent_id = ? ORDER BY key",
            -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        DeviceTag t;
        t.agent_id = agent_id;
        auto k = sqlite3_column_text(stmt, 0);
        if (k)
            t.key = reinterpret_cast<const char*>(k);
        auto v = sqlite3_column_text(stmt, 1);
        if (v)
            t.value = reinterpret_cast<const char*>(v);
        auto s = sqlite3_column_text(stmt, 2);
        if (s)
            t.source = reinterpret_cast<const char*>(s);
        t.updated_at = sqlite3_column_int64(stmt, 3);
        results.push_back(std::move(t));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::unordered_map<std::string, std::string>
TagStore::get_tag_map(const std::string& agent_id) const {
    std::shared_lock lock(mtx_);
    std::unordered_map<std::string, std::string> result;
    if (!db_)
        return result;

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT key, value FROM tags WHERE agent_id = ?", -1, &stmt,
                           nullptr) != SQLITE_OK)
        return result;

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
    std::unique_lock lock(mtx_);
    if (!db_)
        return;

    // Delete all agent-sourced tags, then re-insert
    sqlite3_exec(db_, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, "DELETE FROM tags WHERE agent_id = ? AND source = 'agent'", -1,
                               &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    for (const auto& [key, value] : tags) {
        if (!validate_key(key) || !validate_value(value))
            continue;
        set_tag_impl(agent_id, key, value, "agent");
    }

    sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, nullptr);
}

void TagStore::delete_all_tags(const std::string& agent_id) {
    std::unique_lock lock(mtx_);
    if (!db_)
        return;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM tags WHERE agent_id = ?", -1, &stmt, nullptr) !=
        SQLITE_OK)
        return;

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::vector<std::string> TagStore::agents_with_tag(const std::string& key,
                                                   const std::string& value) const {
    std::shared_lock lock(mtx_);
    std::vector<std::string> result;
    if (!db_)
        return result;

    std::string sql = "SELECT DISTINCT agent_id FROM tags WHERE key = ?";
    if (!value.empty())
        sql += " AND value = ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return result;

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    if (!value.empty()) {
        sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_TRANSIENT);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto t = sqlite3_column_text(stmt, 0);
        if (t)
            result.emplace_back(reinterpret_cast<const char*>(t));
    }
    sqlite3_finalize(stmt);
    return result;
}

std::expected<void, std::string>
TagStore::set_tag_checked(const std::string& agent_id, const std::string& key,
                          const std::string& value, const std::string& source) {
    if (!validate_key(key))
        return std::unexpected("invalid tag key");
    if (!validate_value(value))
        return std::unexpected("tag value exceeds maximum length");

    // Check if key matches a category with restricted values
    for (const auto& cat : get_tag_categories()) {
        if (cat.key == key && !cat.allowed_values.empty()) {
            bool found = false;
            for (auto av : cat.allowed_values) {
                if (av == value) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                std::string msg = "invalid value for '" + key + "': allowed values are";
                for (size_t i = 0; i < cat.allowed_values.size(); ++i) {
                    if (i > 0)
                        msg += ",";
                    msg += " ";
                    msg += cat.allowed_values[i];
                }
                return std::unexpected(msg);
            }
            break;
        }
    }

    std::unique_lock lock(mtx_);
    set_tag_impl(agent_id, key, value, source);
    return {};
}

std::vector<std::pair<std::string, std::vector<std::string>>>
TagStore::get_compliance_gaps() const {
    std::shared_lock lock(mtx_);
    std::vector<std::pair<std::string, std::vector<std::string>>> result;
    if (!db_)
        return result;

    // Get all distinct agent_ids
    std::vector<std::string> all_agents;
    {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, "SELECT DISTINCT agent_id FROM tags", -1, &stmt, nullptr) ==
            SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                auto t = sqlite3_column_text(stmt, 0);
                if (t)
                    all_agents.emplace_back(reinterpret_cast<const char*>(t));
            }
            sqlite3_finalize(stmt);
        }
    }

    // For each agent, find which category keys are missing
    for (const auto& agent_id : all_agents) {
        std::vector<std::string> missing;
        for (auto cat_key : kCategoryKeys) {
            std::string tag_val = get_tag_impl(agent_id, std::string(cat_key));
            if (tag_val.empty())
                missing.emplace_back(cat_key);
        }
        if (!missing.empty())
            result.emplace_back(agent_id, std::move(missing));
    }

    return result;
}

std::vector<std::string> TagStore::get_distinct_values(const std::string& key) const {
    std::shared_lock lock(mtx_);
    std::vector<std::string> result;
    if (!db_)
        return result;

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT DISTINCT value FROM tags WHERE key = ? ORDER BY value", -1,
                           &stmt, nullptr) != SQLITE_OK)
        return result;

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        auto t = sqlite3_column_text(stmt, 0);
        if (t)
            result.emplace_back(reinterpret_cast<const char*>(t));
    }
    sqlite3_finalize(stmt);
    return result;
}

} // namespace yuzu::server
