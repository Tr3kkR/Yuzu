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
///
/// **Wire-boundary contract (#1052, W1.3).** This typed surface is for SIEM
/// and operator-visible metrics ONLY. Every caller that maps the rejection
/// to an HTTP/gRPC response MUST collapse all five variants to a single
/// status code + envelope (`yuzu::server::DEVICE_TOKEN_REJECTION_PUBLIC_*`).
/// Variant-specific status leaks token-existence and binding context to an
/// attacker holding a stolen valid token. See `device_token_rejection.hpp`.
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

/// Rich rejection context returned from `validate_token` on failure
/// (#1053, W1.3 prereq). Combines the typed `error` with whatever
/// row context is available WITHOUT requiring the handler to re-SELECT
/// the row (which would (a) add latency and (b) create a timing oracle
/// distinguishing `binding_mismatch` from `not_found`).
///
/// Field population by variant:
///
/// | variant            | token_id | bound_device_id | bound_principal_id |
/// |--------------------|----------|-----------------|--------------------|
/// | invalid_input      | empty    | empty           | empty              |
/// | not_found          | empty    | empty           | empty              |
/// | revoked            | set      | set             | set                |
/// | expired            | set      | set             | set                |
/// | unbound_legacy     | set      | empty           | set                |
/// | binding_mismatch   | set      | set             | set                |
///
/// `unbound_legacy` deliberately leaves `bound_device_id` empty because
/// the row has empty `device_id` by construction — propagating "" would
/// mislead audit readers into thinking a binding existed.
struct RejectedToken {
    DeviceTokenValidateError error{DeviceTokenValidateError::invalid_input};
    std::string token_id;
    std::string bound_device_id;
    std::string bound_principal_id;
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

    /// Validate a raw token. Returns the DeviceAuthToken on success, or a
    /// rich `RejectedToken` (typed error + bound context) on rejection.
    /// `presenting_agent_id` is the agent_id the caller has authenticated
    /// by an independent channel (TLS client cert subject, gateway-side
    /// agent identity, etc.) and is matched against the token's `device_id`
    /// (#824 — prevents a stolen token being replayed by a different agent).
    ///
    /// As of W1.2 R2 (HIGH-1/HIGH-2) tokens with empty stored `device_id`
    /// are rejected with `unbound_legacy` rather than treated as any-device,
    /// so a pre-#824 row cannot be replayed from any presenter. Operators
    /// wanting a legitimate any-device token must opt in via a future
    /// explicit API. Callers MUST NOT silently treat an empty
    /// `presenting_agent_id` as "skip the check" — that recreates the #824
    /// vulnerability.
    ///
    /// **#1053 rich-rejection contract (W1.3).** On `binding_mismatch`,
    /// `revoked`, `expired` we populate `bound_device_id` and
    /// `bound_principal_id` so the handler can emit a complete audit row
    /// (`presenter=X bound=Y bound_principal=Z`) WITHOUT a second SELECT.
    /// A second SELECT would (a) add latency and (b) create a timing
    /// oracle distinguishing `binding_mismatch` from `not_found`. See
    /// `RejectedToken` doc for per-variant population.
    [[nodiscard]] std::expected<DeviceAuthToken, RejectedToken>
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
