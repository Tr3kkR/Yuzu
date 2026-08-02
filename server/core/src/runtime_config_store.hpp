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
/// Only a fixed set of allowed keys is accepted. One of them
/// (oidc_client_secret) IS a secret and is stored plaintext today —
/// its envelope encryption lands with the Postgres migration (ADR-0010).
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

    /// True if this key's VALUE is a credential and must never be emitted in
    /// plaintext — not to a log, not to an API response, not to a config dump.
    /// The store still returns the real value (callers such as the startup override
    /// pass need it); redaction is the emitter's job, and this is the one predicate
    /// every emitter must consult so a newly-added secret key cannot be missed.
    static bool is_secret_key(const std::string& key);

    /// What to print in place of a secret. Single spelling so log scrapers and API
    /// consumers see one token.
    static const char* redacted_placeholder() { return "<redacted>"; }

    /// Returns the list of allowed config keys.
    static const std::vector<std::string>& allowed_keys();

private:
    sqlite3* db_{nullptr};
    mutable std::mutex mu_;

    void create_tables();
};

} // namespace yuzu::server
