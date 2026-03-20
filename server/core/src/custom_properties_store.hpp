#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

struct CustomProperty {
    std::string agent_id;
    std::string key;
    std::string value;
    std::string type; // "string", "int", "bool", "datetime"
    int64_t updated_at{0};
};

struct CustomPropertySchema {
    std::string key;
    std::string display_name;
    std::string type; // "string", "int", "bool", "datetime"
    std::string description;
    std::string validation_regex;
};

/// Typed custom metadata for devices, usable in scope expressions via `props.<key>`.
class CustomPropertiesStore {
public:
    explicit CustomPropertiesStore(const std::filesystem::path& db_path);
    ~CustomPropertiesStore();

    CustomPropertiesStore(const CustomPropertiesStore&) = delete;
    CustomPropertiesStore& operator=(const CustomPropertiesStore&) = delete;

    bool is_open() const;

    // ── Property CRUD ────────────────────────────────────────────────────

    /// Get all custom properties for an agent.
    std::vector<CustomProperty> get_properties(const std::string& agent_id) const;

    /// Get a single property.
    std::optional<CustomProperty> get_property(const std::string& agent_id,
                                               const std::string& key) const;

    /// Get property value as a string (empty if not found).
    std::string get_value(const std::string& agent_id, const std::string& key) const;

    /// Get all properties as a map (for scope evaluation).
    std::unordered_map<std::string, std::string> get_property_map(
        const std::string& agent_id) const;

    /// Set a property. Validates against schema if one exists.
    std::expected<void, std::string> set_property(const std::string& agent_id,
                                                   const std::string& key,
                                                   const std::string& value,
                                                   const std::string& type = "string");

    /// Delete a property.
    bool delete_property(const std::string& agent_id, const std::string& key);

    /// Delete all properties for an agent.
    void delete_all_properties(const std::string& agent_id);

    // ── Schema CRUD ──────────────────────────────────────────────────────

    /// List all defined property schemas.
    std::vector<CustomPropertySchema> list_schemas() const;

    /// Get a single schema.
    std::optional<CustomPropertySchema> get_schema(const std::string& key) const;

    /// Create or update a property schema.
    std::expected<void, std::string> upsert_schema(const CustomPropertySchema& schema);

    /// Delete a property schema.
    bool delete_schema(const std::string& key);

    // ── Validation ───────────────────────────────────────────────────────

    /// Validate key: 1-64 chars, [a-zA-Z0-9_.-:]
    static bool validate_key(const std::string& key);

    /// Validate value: max 1024 bytes
    static bool validate_value(const std::string& value);

private:
    sqlite3* db_{nullptr};
    mutable std::mutex mu_;

    void create_tables();

    /// Validate a value against the schema for a key (if one exists).
    std::expected<void, std::string> validate_against_schema(const std::string& key,
                                                              const std::string& value) const;
};

} // namespace yuzu::server
