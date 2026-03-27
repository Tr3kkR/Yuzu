#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

namespace yuzu::server {

struct DeviceAuthToken {
    std::string token_id;       // Short display ID (prefix of hash)
    std::string name;           // Human-readable label
    std::string principal_id;   // Username who created it
    std::string device_id;      // Scoped to this device (empty = any device)
    std::string definition_id;  // Scoped to this instruction definition (empty = any)
    int64_t created_at{0};
    int64_t expires_at{0};      // 0 = never
    int64_t last_used_at{0};
    bool revoked{false};
};

class DeviceTokenStore {
public:
    explicit DeviceTokenStore(const std::filesystem::path& db_path);
    ~DeviceTokenStore();

    DeviceTokenStore(const DeviceTokenStore&) = delete;
    DeviceTokenStore& operator=(const DeviceTokenStore&) = delete;

    bool is_open() const;

    /// Create a new device authorization token. Returns the raw token string (shown once).
    std::expected<std::string, std::string>
    create_token(const std::string& name, const std::string& principal_id,
                 const std::string& device_id, const std::string& definition_id,
                 int64_t expires_at);

    /// Validate a raw token. Returns the DeviceAuthToken if valid (not expired, not revoked).
    std::optional<DeviceAuthToken> validate_token(const std::string& raw_token) const;

    /// List all tokens, optionally filtered by principal_id.
    std::vector<DeviceAuthToken> list_tokens(const std::string& principal_id = {}) const;

    /// Revoke a token by ID.
    bool revoke_token(const std::string& token_id);

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_;

    void create_tables();
    std::string hash_token(const std::string& raw) const;
};

} // namespace yuzu::server
