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
    std::string token_id;      // Short display ID (prefix of hash)
    std::string name;          // Human-readable label
    std::string principal_id;  // Username who created it
    std::string device_id;     // Scoped to this device (empty = any device)
    std::string definition_id; // Scoped to this instruction definition (empty = any)
    int64_t created_at{0};
    int64_t expires_at{0}; // 0 = never
    int64_t last_used_at{0};
    bool revoked{false};
};

/// Why validate_token failed. The typed enum lets callers attribute rejections
/// in audit rows and Prometheus counters without re-parsing free-form strings.
/// `binding_mismatch` is the #824 case — token presented by an agent that is
/// not the device the token was bound to. SOC 2 CC6.1 + auth-architecture
/// standing invariant "token presenter MUST equal token subject."
enum class DeviceTokenValidateError {
    /// Empty / malformed raw token, or database closed. Indistinguishable from
    /// not_found at the wire layer to deny token-shape oracles, but separate
    /// here for SIEM filtering.
    invalid_input,
    /// Hash does not match any row in `device_auth_tokens`.
    not_found,
    /// Row exists but `revoked = 1`.
    revoked,
    /// Row exists and `expires_at > 0 && now > expires_at`.
    expired,
    /// Row exists, not revoked, not expired, but the stored `device_id` is
    /// empty — a legacy / pre-#824 row that has no enforceable binding. We
    /// refuse to validate such tokens loudly rather than allow any presenter
    /// to pass the empty-comparison short-circuit (W1.2 R2 HIGH-1/HIGH-2).
    /// Operator must re-issue with explicit binding.
    unbound_legacy,
    /// Row exists, not revoked, not expired, stored `device_id` is non-empty,
    /// but the agent presenting the token does not match `device_id` (#824
    /// stolen-token impersonation).
    binding_mismatch,
};

class DeviceTokenStore {
public:
    explicit DeviceTokenStore(const std::filesystem::path& db_path);
    ~DeviceTokenStore();

    DeviceTokenStore(const DeviceTokenStore&) = delete;
    DeviceTokenStore& operator=(const DeviceTokenStore&) = delete;

    bool is_open() const;

    /// Create a new device authorization token. Returns the raw token string (shown once).
    std::expected<std::string, std::string> create_token(const std::string& name,
                                                         const std::string& principal_id,
                                                         const std::string& device_id,
                                                         const std::string& definition_id,
                                                         int64_t expires_at);

    /// Validate a raw token. Returns the DeviceAuthToken on success, or a typed
    /// error on rejection. `presenting_agent_id` is the agent_id the caller
    /// has authenticated by an independent channel (TLS client cert subject,
    /// gateway-side agent identity, etc.) and is matched against the token's
    /// `device_id` (#824 — prevents a stolen token being replayed by a
    /// different agent).
    ///
    /// As of W1.2 R2 (HIGH-1/HIGH-2) tokens with empty stored `device_id` are
    /// rejected with `unbound_legacy` rather than treated as any-device, so a
    /// pre-#824 row cannot be replayed from any presenter. Operators wanting a
    /// legitimate any-device token must opt in via a future explicit API.
    /// Callers MUST NOT silently treat an empty `presenting_agent_id` as
    /// "skip the check" — that recreates the #824 vulnerability.
    [[nodiscard]] std::expected<DeviceAuthToken, DeviceTokenValidateError>
    validate_token(const std::string& raw_token, const std::string& presenting_agent_id) const;

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
