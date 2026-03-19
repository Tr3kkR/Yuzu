#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

struct ApiToken {
    std::string token_id;      // Short display ID (prefix of hash)
    std::string token_hash;    // SHA-256 hash of raw token (stored, never the raw token)
    std::string name;          // Human-readable label
    std::string principal_id;  // Username who created it
    std::string scope_service; // Non-empty = scoped to this IT service (change window token)
    int64_t created_at{0};
    int64_t expires_at{0}; // 0 = never
    int64_t last_used_at{0};
    bool revoked{false};
};

class ApiTokenStore {
public:
    explicit ApiTokenStore(const std::filesystem::path& db_path);
    ~ApiTokenStore();

    ApiTokenStore(const ApiTokenStore&) = delete;
    ApiTokenStore& operator=(const ApiTokenStore&) = delete;

    bool is_open() const;

    /// Create a new API token. Returns the raw token string (shown to user once).
    /// If scope_service is non-empty, the token is scoped to that IT service.
    std::expected<std::string, std::string>
    create_token(const std::string& name, const std::string& principal_id, int64_t expires_at = 0,
                 const std::string& scope_service = {});

    /// Validate a raw Bearer token. Returns the ApiToken if valid and not expired/revoked.
    std::optional<ApiToken> validate_token(const std::string& raw_token);

    /// List all tokens (for admin UI). Raw token values are never returned.
    std::vector<ApiToken> list_tokens(const std::string& principal_id = {}) const;

    /// Revoke a token by ID.
    bool revoke_token(const std::string& token_id);

    /// Delete a token permanently.
    bool delete_token(const std::string& token_id);

private:
    sqlite3* db_{nullptr};

    void create_tables();
    std::string generate_raw_token() const;
    std::string sha256_hex(const std::string& input) const;
};

} // namespace yuzu::server
