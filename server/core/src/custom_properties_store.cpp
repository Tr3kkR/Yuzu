#include "custom_properties_store.hpp"

#include <spdlog/spdlog.h>

#include <chrono>
#include <regex>

namespace yuzu::server {

// ── Constructor / destructor ─────────────────────────────────────────────────

CustomPropertiesStore::CustomPropertiesStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("CustomPropertiesStore: failed to open {}: {}", db_path.string(),
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
    spdlog::info("CustomPropertiesStore: opened {}", db_path.string());
}

CustomPropertiesStore::~CustomPropertiesStore() {
    if (db_)
        sqlite3_close(db_);
}

bool CustomPropertiesStore::is_open() const {
    return db_ != nullptr;
}

void CustomPropertiesStore::create_tables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS custom_properties (
            agent_id    TEXT NOT NULL,
            key         TEXT NOT NULL,
            value       TEXT NOT NULL,
            type        TEXT NOT NULL DEFAULT 'string',
            updated_at  INTEGER NOT NULL,
            PRIMARY KEY (agent_id, key)
        );
        CREATE INDEX IF NOT EXISTS idx_custom_props_agent
            ON custom_properties(agent_id);

        CREATE TABLE IF NOT EXISTS custom_property_schemas (
            key               TEXT PRIMARY KEY,
            display_name      TEXT,
            type              TEXT NOT NULL DEFAULT 'string',
            description       TEXT,
            validation_regex  TEXT
        );
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("CustomPropertiesStore: create_tables failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }
}

// ── Validation ───────────────────────────────────────────────────────────────

bool CustomPropertiesStore::validate_key(const std::string& key) {
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

bool CustomPropertiesStore::validate_value(const std::string& value) {
    return value.size() <= 1024;
}

std::expected<void, std::string>
CustomPropertiesStore::validate_against_schema(const std::string& key,
                                                const std::string& value) const {
    // Check if a schema exists for this key (caller must hold mu_)
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT type, validation_regex FROM custom_property_schemas WHERE key = ?",
                           -1, &stmt, nullptr) != SQLITE_OK)
        return {}; // No schema = no validation

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);

    std::string schema_type;
    std::string validation_regex;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        auto t = sqlite3_column_text(stmt, 0);
        if (t) schema_type = reinterpret_cast<const char*>(t);
        auto r = sqlite3_column_text(stmt, 1);
        if (r) validation_regex = reinterpret_cast<const char*>(r);
    }
    sqlite3_finalize(stmt);

    if (schema_type.empty())
        return {}; // No schema found

    // Type validation
    if (schema_type == "int") {
        try {
            (void)std::stoll(value);
        } catch (...) {
            return std::unexpected("value must be a valid integer for property '" + key + "'");
        }
    } else if (schema_type == "bool") {
        if (value != "true" && value != "false")
            return std::unexpected("value must be 'true' or 'false' for property '" + key + "'");
    }
    // "string" and "datetime" accept any text

    // Regex validation
    if (!validation_regex.empty()) {
        try {
            std::regex re(validation_regex, std::regex::ECMAScript);
            if (!std::regex_match(value, re))
                return std::unexpected("value does not match validation pattern for '" + key + "'");
        } catch (const std::regex_error&) {
            spdlog::warn("CustomPropertiesStore: invalid regex for schema key '{}': {}", key,
                         validation_regex);
        }
    }

    return {};
}

// ── Property CRUD ────────────────────────────────────────────────────────────

std::vector<CustomProperty>
CustomPropertiesStore::get_properties(const std::string& agent_id) const {
    std::vector<CustomProperty> results;
    if (!db_)
        return results;

    std::lock_guard lock(mu_);
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT key, value, type, updated_at FROM custom_properties "
                           "WHERE agent_id = ? ORDER BY key",
                           -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CustomProperty p;
        p.agent_id = agent_id;
        auto k = sqlite3_column_text(stmt, 0);
        if (k) p.key = reinterpret_cast<const char*>(k);
        auto v = sqlite3_column_text(stmt, 1);
        if (v) p.value = reinterpret_cast<const char*>(v);
        auto t = sqlite3_column_text(stmt, 2);
        if (t) p.type = reinterpret_cast<const char*>(t);
        p.updated_at = sqlite3_column_int64(stmt, 3);
        results.push_back(std::move(p));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::optional<CustomProperty>
CustomPropertiesStore::get_property(const std::string& agent_id, const std::string& key) const {
    if (!db_)
        return std::nullopt;

    std::lock_guard lock(mu_);
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT value, type, updated_at FROM custom_properties "
                           "WHERE agent_id = ? AND key = ?",
                           -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, key.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<CustomProperty> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        CustomProperty p;
        p.agent_id = agent_id;
        p.key = key;
        auto v = sqlite3_column_text(stmt, 0);
        if (v) p.value = reinterpret_cast<const char*>(v);
        auto t = sqlite3_column_text(stmt, 1);
        if (t) p.type = reinterpret_cast<const char*>(t);
        p.updated_at = sqlite3_column_int64(stmt, 2);
        result = std::move(p);
    }
    sqlite3_finalize(stmt);
    return result;
}

std::string CustomPropertiesStore::get_value(const std::string& agent_id,
                                              const std::string& key) const {
    auto prop = get_property(agent_id, key);
    return prop ? prop->value : std::string{};
}

std::unordered_map<std::string, std::string>
CustomPropertiesStore::get_property_map(const std::string& agent_id) const {
    std::unordered_map<std::string, std::string> result;
    if (!db_)
        return result;

    std::lock_guard lock(mu_);
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT key, value FROM custom_properties WHERE agent_id = ?",
                           -1, &stmt, nullptr) != SQLITE_OK)
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

std::expected<void, std::string>
CustomPropertiesStore::set_property(const std::string& agent_id, const std::string& key,
                                     const std::string& value, const std::string& type) {
    if (!db_)
        return std::unexpected("store not open");
    if (!validate_key(key))
        return std::unexpected("invalid property key (1-64 chars, alphanumeric/._:-)");
    if (!validate_value(value))
        return std::unexpected("property value exceeds maximum length (1024 bytes)");

    std::lock_guard lock(mu_);

    // Validate against schema if one exists
    auto schema_result = validate_against_schema(key, value);
    if (!schema_result)
        return schema_result;

    const char* sql = R"(
        INSERT OR REPLACE INTO custom_properties (agent_id, key, value, type, updated_at)
        VALUES (?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected("database error");

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();

    // Use schema type if available, otherwise use the provided type
    std::string effective_type = type;
    {
        sqlite3_stmt* schema_stmt = nullptr;
        if (sqlite3_prepare_v2(db_,
                               "SELECT type FROM custom_property_schemas WHERE key = ?",
                               -1, &schema_stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(schema_stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(schema_stmt) == SQLITE_ROW) {
                auto t = sqlite3_column_text(schema_stmt, 0);
                if (t) effective_type = reinterpret_cast<const char*>(t);
            }
            sqlite3_finalize(schema_stmt);
        }
    }

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, value.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, effective_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, now);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc == SQLITE_DONE ? std::expected<void, std::string>{}
                             : std::unexpected(std::string("database write failed"));
}

bool CustomPropertiesStore::delete_property(const std::string& agent_id, const std::string& key) {
    if (!db_)
        return false;

    std::lock_guard lock(mu_);
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "DELETE FROM custom_properties WHERE agent_id = ? AND key = ?",
                           -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, key.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return sqlite3_changes(db_) > 0;
}

void CustomPropertiesStore::delete_all_properties(const std::string& agent_id) {
    if (!db_)
        return;

    std::lock_guard lock(mu_);
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "DELETE FROM custom_properties WHERE agent_id = ?",
                           -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// ── Schema CRUD ──────────────────────────────────────────────────────────────

std::vector<CustomPropertySchema> CustomPropertiesStore::list_schemas() const {
    std::vector<CustomPropertySchema> results;
    if (!db_)
        return results;

    std::lock_guard lock(mu_);
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT key, display_name, type, description, validation_regex "
                           "FROM custom_property_schemas ORDER BY key",
                           -1, &stmt, nullptr) != SQLITE_OK)
        return results;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CustomPropertySchema s;
        auto k = sqlite3_column_text(stmt, 0);
        if (k) s.key = reinterpret_cast<const char*>(k);
        auto d = sqlite3_column_text(stmt, 1);
        if (d) s.display_name = reinterpret_cast<const char*>(d);
        auto t = sqlite3_column_text(stmt, 2);
        if (t) s.type = reinterpret_cast<const char*>(t);
        auto desc = sqlite3_column_text(stmt, 3);
        if (desc) s.description = reinterpret_cast<const char*>(desc);
        auto r = sqlite3_column_text(stmt, 4);
        if (r) s.validation_regex = reinterpret_cast<const char*>(r);
        results.push_back(std::move(s));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::optional<CustomPropertySchema>
CustomPropertiesStore::get_schema(const std::string& key) const {
    if (!db_)
        return std::nullopt;

    std::lock_guard lock(mu_);
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT key, display_name, type, description, validation_regex "
                           "FROM custom_property_schemas WHERE key = ?",
                           -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<CustomPropertySchema> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        CustomPropertySchema s;
        auto k = sqlite3_column_text(stmt, 0);
        if (k) s.key = reinterpret_cast<const char*>(k);
        auto d = sqlite3_column_text(stmt, 1);
        if (d) s.display_name = reinterpret_cast<const char*>(d);
        auto t = sqlite3_column_text(stmt, 2);
        if (t) s.type = reinterpret_cast<const char*>(t);
        auto desc = sqlite3_column_text(stmt, 3);
        if (desc) s.description = reinterpret_cast<const char*>(desc);
        auto r = sqlite3_column_text(stmt, 4);
        if (r) s.validation_regex = reinterpret_cast<const char*>(r);
        result = std::move(s);
    }
    sqlite3_finalize(stmt);
    return result;
}

std::expected<void, std::string>
CustomPropertiesStore::upsert_schema(const CustomPropertySchema& schema) {
    if (!db_)
        return std::unexpected("store not open");
    if (!validate_key(schema.key))
        return std::unexpected("invalid schema key");

    // Validate type
    static const std::vector<std::string> valid_types = {"string", "int", "bool", "datetime"};
    if (std::find(valid_types.begin(), valid_types.end(), schema.type) == valid_types.end())
        return std::unexpected("type must be one of: string, int, bool, datetime");

    // Validate regex if provided
    if (!schema.validation_regex.empty()) {
        try {
            std::regex re(schema.validation_regex, std::regex::ECMAScript);
            (void)re;
        } catch (const std::regex_error& e) {
            return std::unexpected(std::string("invalid validation regex: ") + e.what());
        }
    }

    std::lock_guard lock(mu_);
    const char* sql = R"(
        INSERT OR REPLACE INTO custom_property_schemas (key, display_name, type, description, validation_regex)
        VALUES (?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected("database error");

    sqlite3_bind_text(stmt, 1, schema.key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, schema.display_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, schema.type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, schema.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, schema.validation_regex.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc == SQLITE_DONE ? std::expected<void, std::string>{}
                             : std::unexpected(std::string("database write failed"));
}

bool CustomPropertiesStore::delete_schema(const std::string& key) {
    if (!db_)
        return false;

    std::lock_guard lock(mu_);
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "DELETE FROM custom_property_schemas WHERE key = ?",
                           -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return sqlite3_changes(db_) > 0;
}

} // namespace yuzu::server
