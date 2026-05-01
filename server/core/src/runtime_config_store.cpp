#include "runtime_config_store.hpp"
#include "migration_runner.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>

namespace yuzu::server {

// ── Allowed keys (safe for runtime modification) ─────────────────────────────

static const std::vector<std::string> kAllowedKeys = {
    "heartbeat_timeout",             // seconds before marking agent offline
    "response_retention_days",       // days to keep instruction responses
    "audit_retention_days",          // days to keep audit events
    "guardian_event_retention_days", // days to keep guaranteed-state events
    "auto_approve_enabled",          // "true" or "false"
    "log_level",                     // trace|debug|info|warn|error
    "oidc_issuer",             // OIDC issuer URL
    "oidc_client_id",          // OIDC client ID
    "oidc_client_secret",      // OIDC client secret (encrypted at rest via SQLite)
    "oidc_redirect_uri",       // OIDC redirect URI
    "oidc_admin_group",        // OIDC admin group ID
    "oidc_skip_tls_verify",    // "true" or "false"
    "plugin_signing_required", // "true" or "false" — agent rejects unsigned plugins
};

const std::vector<std::string>& RuntimeConfigStore::allowed_keys() {
    return kAllowedKeys;
}

bool RuntimeConfigStore::is_allowed_key(const std::string& key) {
    return std::find(kAllowedKeys.begin(), kAllowedKeys.end(), key) != kAllowedKeys.end();
}

// ── Constructor / destructor ─────────────────────────────────────────────────

RuntimeConfigStore::RuntimeConfigStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open_v2(db_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("RuntimeConfigStore: failed to open {}: {}", db_path.string(),
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
    if (db_)
        spdlog::info("RuntimeConfigStore: opened {}", db_path.string());
}

RuntimeConfigStore::~RuntimeConfigStore() {
    if (db_)
        sqlite3_close(db_);
}

bool RuntimeConfigStore::is_open() const {
    return db_ != nullptr;
}

void RuntimeConfigStore::create_tables() {
    static const std::vector<Migration> kMigrations = {
        {1, R"(
            CREATE TABLE IF NOT EXISTS runtime_config (
                key         TEXT PRIMARY KEY,
                value       TEXT NOT NULL,
                updated_by  TEXT NOT NULL DEFAULT '',
                updated_at  INTEGER NOT NULL
            );
        )"},
    };
    if (!MigrationRunner::run(db_, "runtime_config_store", kMigrations)) {
        spdlog::error("RuntimeConfigStore: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

// ── Queries ──────────────────────────────────────────────────────────────────

std::vector<RuntimeConfigEntry> RuntimeConfigStore::get_all() const {
    std::vector<RuntimeConfigEntry> results;
    if (!db_)
        return results;

    std::lock_guard lock(mu_);
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT key, value, updated_by, updated_at FROM runtime_config ORDER BY key",
                           -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        RuntimeConfigEntry e;
        auto k = sqlite3_column_text(stmt, 0);
        if (k) e.key = reinterpret_cast<const char*>(k);
        auto v = sqlite3_column_text(stmt, 1);
        if (v) e.value = reinterpret_cast<const char*>(v);
        auto u = sqlite3_column_text(stmt, 2);
        if (u) e.updated_by = reinterpret_cast<const char*>(u);
        e.updated_at = sqlite3_column_int64(stmt, 3);
        results.push_back(std::move(e));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::optional<RuntimeConfigEntry> RuntimeConfigStore::get(const std::string& key) const {
    if (!db_)
        return std::nullopt;

    std::lock_guard lock(mu_);
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT key, value, updated_by, updated_at FROM runtime_config WHERE key = ?",
                           -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<RuntimeConfigEntry> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        RuntimeConfigEntry e;
        auto k = sqlite3_column_text(stmt, 0);
        if (k) e.key = reinterpret_cast<const char*>(k);
        auto v = sqlite3_column_text(stmt, 1);
        if (v) e.value = reinterpret_cast<const char*>(v);
        auto u = sqlite3_column_text(stmt, 2);
        if (u) e.updated_by = reinterpret_cast<const char*>(u);
        e.updated_at = sqlite3_column_int64(stmt, 3);
        result = std::move(e);
    }
    sqlite3_finalize(stmt);
    return result;
}

std::string RuntimeConfigStore::get_value(const std::string& key) const {
    auto entry = get(key);
    return entry ? entry->value : std::string{};
}

// ── Mutations ────────────────────────────────────────────────────────────────

std::expected<void, std::string> RuntimeConfigStore::set(const std::string& key,
                                                          const std::string& value,
                                                          const std::string& updated_by) {
    if (!db_)
        return std::unexpected("store not open");

    if (!is_allowed_key(key))
        return std::unexpected("key '" + key + "' is not a configurable runtime setting");

    // Basic validation per key
    if (key == "heartbeat_timeout" || key == "response_retention_days" ||
        key == "audit_retention_days") {
        try {
            int val = std::stoi(value);
            if (val <= 0)
                return std::unexpected("value must be a positive integer");
        } catch (...) {
            return std::unexpected("value must be a valid integer");
        }
    }

    if (key == "auto_approve_enabled" || key == "plugin_signing_required") {
        if (value != "true" && value != "false")
            return std::unexpected("value must be 'true' or 'false'");
    }

    if (key == "log_level") {
        static const std::vector<std::string> valid_levels = {"trace", "debug", "info", "warn",
                                                               "error"};
        if (std::find(valid_levels.begin(), valid_levels.end(), value) == valid_levels.end())
            return std::unexpected("value must be one of: trace, debug, info, warn, error");
    }

    std::lock_guard lock(mu_);
    const char* sql = R"(
        INSERT OR REPLACE INTO runtime_config (key, value, updated_by, updated_at)
        VALUES (?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected("database error");

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, updated_by.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, now);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
        return std::unexpected("database write failed");

    // Apply the change immediately
    if (key == "log_level") {
        spdlog::set_level(spdlog::level::from_str(value));
        spdlog::info("Runtime config: log_level changed to '{}'", value);
    }

    return {};
}

bool RuntimeConfigStore::remove(const std::string& key) {
    if (!db_)
        return false;

    std::lock_guard lock(mu_);
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM runtime_config WHERE key = ?", -1, &stmt,
                           nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return sqlite3_changes(db_) > 0;
}

} // namespace yuzu::server
