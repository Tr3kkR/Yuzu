#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server::auth {

enum class Role { user, admin };

struct UserEntry {
    std::string username;
    Role        role;
    std::string salt_hex;
    std::string hash_hex;
};

struct Session {
    std::string username;
    Role        role;
    std::chrono::steady_clock::time_point expires_at;
};

// ── Enrollment tokens (Tier 2) ──────────────────────────────────────────────

struct EnrollmentToken {
    std::string token_id;      // Short display ID (first 8 hex chars)
    std::string token_hash;    // SHA-256 hash of the actual token (stored, never raw)
    std::string label;         // Admin-assigned label (e.g. "NYC office rollout")
    int         max_uses;      // 0 = unlimited
    int         use_count;     // How many times this token has been used
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;  // time_point::max() = never
    bool        revoked;
};

// ── Pending agents (Tier 1) ─────────────────────────────────────────────────

enum class PendingStatus { pending, approved, denied };

struct PendingAgent {
    std::string agent_id;
    std::string hostname;
    std::string os;
    std::string arch;
    std::string agent_version;
    std::chrono::system_clock::time_point requested_at;
    PendingStatus status;
};

class AuthManager {
public:
    static constexpr auto kSessionDuration = std::chrono::hours(8);
    static constexpr int  kPbkdf2Iterations = 100'000;

    /// Load users from config file. Returns false if file missing/corrupt.
    bool load_config(const std::filesystem::path& cfg_path);

    /// Persist current user list to disk.
    bool save_config() const;

    /// Interactive first-run: prompt for admin + user credentials, write config.
    static bool first_run_setup(const std::filesystem::path& cfg_path);

    /// Authenticate; returns session token on success.
    std::optional<std::string> authenticate(const std::string& username,
                                            const std::string& password);

    /// Look up a session by cookie token.
    std::optional<Session> validate_session(const std::string& token) const;

    /// Destroy a session (logout).
    void invalidate_session(const std::string& token);

    /// List all configured users (password hashes omitted from caller view).
    std::vector<UserEntry> list_users() const;

    /// Add or overwrite a user.
    bool upsert_user(const std::string& username,
                     const std::string& password, Role role);

    /// Remove a user by name.
    bool remove_user(const std::string& username);

    /// Check whether any users are configured.
    bool has_users() const;

    const std::filesystem::path& config_path() const { return cfg_path_; }

    // -- Enrollment tokens (Tier 2) ---------------------------------------

    /// Create a new enrollment token. Returns the raw token string (show once).
    std::string create_enrollment_token(const std::string& label,
                                        int max_uses,
                                        std::chrono::seconds ttl);

    /// Create multiple enrollment tokens at once for batch deployment.
    /// Returns a vector of raw token strings (each shown once).
    std::vector<std::string> create_enrollment_tokens_batch(
        const std::string& label_prefix,
        int count,
        int max_uses_each,
        std::chrono::seconds ttl);

    /// Validate a raw enrollment token. Returns true and increments use_count
    /// if valid. Returns false if expired, revoked, or exhausted.
    bool validate_enrollment_token(const std::string& raw_token);

    /// List all enrollment tokens (for admin UI).
    std::vector<EnrollmentToken> list_enrollment_tokens() const;

    /// Revoke a token by its token_id.
    bool revoke_enrollment_token(const std::string& token_id);

    // -- Pending agents (Tier 1) ------------------------------------------

    /// Add an agent to the pending approval queue.
    void add_pending_agent(const std::string& agent_id,
                           const std::string& hostname,
                           const std::string& os,
                           const std::string& arch,
                           const std::string& agent_version);

    /// Check if an agent_id is pending, approved, or denied.
    std::optional<PendingStatus> get_pending_status(const std::string& agent_id) const;

    /// List all pending agents (for admin UI).
    std::vector<PendingAgent> list_pending_agents() const;

    /// Approve a pending agent.
    bool approve_pending_agent(const std::string& agent_id);

    /// Deny a pending agent.
    bool deny_pending_agent(const std::string& agent_id);

    /// Remove a pending agent entry (cleanup after enrollment or denial).
    bool remove_pending_agent(const std::string& agent_id);

    // -- Crypto primitives (platform-abstracted) --------------------------

    static std::vector<uint8_t> random_bytes(std::size_t n);
    static std::string          bytes_to_hex(const std::vector<uint8_t>& v);
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex);
    static std::string          pbkdf2_sha256(const std::string& password,
                                              const std::vector<uint8_t>& salt,
                                              int iterations);
    static std::string          sha256_hex(const std::string& input);

private:
    static std::string generate_session_token();

    /// Persist enrollment tokens to disk.
    bool save_tokens() const;
    /// Load enrollment tokens from disk.
    bool load_tokens();

    /// Persist pending agents to disk.
    bool save_pending() const;
    /// Load pending agents from disk.
    bool load_pending();

    mutable std::mutex mu_;
    std::filesystem::path cfg_path_;
    std::unordered_map<std::string, UserEntry> users_;
    mutable std::unordered_map<std::string, Session> sessions_;

    // Enrollment tokens keyed by token_id
    std::unordered_map<std::string, EnrollmentToken> enrollment_tokens_;

    // Pending agents keyed by agent_id
    std::unordered_map<std::string, PendingAgent> pending_agents_;
};

// OS-appropriate default paths.
std::filesystem::path default_config_path();
std::filesystem::path default_cert_dir();

std::string role_to_string(Role r);
Role        string_to_role(const std::string& s);

std::string pending_status_to_string(PendingStatus s);

}  // namespace yuzu::server::auth
