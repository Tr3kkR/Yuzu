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

struct RuntimeConfigEntry {
    std::string key;
    std::string value;
    std::string updated_by;
    int64_t updated_at{0};
};

/// Persistent runtime configuration overrides.
/// Stores key/value pairs in SQLite that override startup defaults.
/// Only a fixed set of safe keys are allowed (no secrets).
class RuntimeConfigStore {
public:
    explicit RuntimeConfigStore(const std::filesystem::path& db_path);
    ~RuntimeConfigStore();

    RuntimeConfigStore(const RuntimeConfigStore&) = delete;
    RuntimeConfigStore& operator=(const RuntimeConfigStore&) = delete;

    bool is_open() const;

    /// Get all config entries.
    std::vector<RuntimeConfigEntry> get_all() const;

    /// Get a single config entry.
    std::optional<RuntimeConfigEntry> get(const std::string& key) const;

    /// Get the value of a config key, or empty string if not set.
    std::string get_value(const std::string& key) const;

    /// Set a config value. Returns error if the key is not in the allow-list.
    std::expected<void, std::string> set(const std::string& key, const std::string& value,
                                         const std::string& updated_by);

    /// Delete a config override (revert to default).
    bool remove(const std::string& key);

    /// Check if a key is in the allow-list of safe runtime-configurable keys.
    static bool is_allowed_key(const std::string& key);

    /// Returns the list of allowed config keys.
    static const std::vector<std::string>& allowed_keys();

private:
    sqlite3* db_{nullptr};
    mutable std::mutex mu_;

    void create_tables();
};

} // namespace yuzu::server
