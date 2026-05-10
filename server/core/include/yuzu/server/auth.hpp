#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu { class MetricsRegistry; }
namespace yuzu::server { class AuthDB; }

namespace yuzu::server::auth {

/// Maximum session token length (64 hex chars = 32 bytes random). Reject longer to prevent DoS.
inline constexpr std::size_t kMaxSessionTokenLength = 64;

/// Maximum API token length (raw token before hashing). Raw tokens can be up to 256 chars.
inline constexpr std::size_t kMaxApiTokenLength = 256;

enum class Role { user, admin };

struct UserEntry {
    std::string username;
    Role role;
    std::string salt_hex;
    std::string hash_hex;
};

struct Session {
    std::string username;
    Role role;
    std::chrono::steady_clock::time_point expires_at;
    std::string auth_source{"local"};    // "local", "oidc", "api_token", or "mcp_token"
    std::string oidc_sub;                // OIDC subject claim (empty for local auth)
    std::string token_scope_service;     // Non-empty = token scoped to this service
    std::string mcp_tier;                // "readonly", "operator", "supervised", or "" (not MCP)
};

// ── Enrollment tokens (Tier 2) ──────────────────────────────────────────────

struct EnrollmentToken {
    std::string token_id;   // Short display ID (first 8 hex chars)
    std::string token_hash; // SHA-256 hash of the actual token (stored, never raw)
    std::string label;      // Admin-assigned label (e.g. "NYC office rollout")
    int max_uses;           // 0 = unlimited
    int use_count;          // How many times this token has been used
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at; // time_point::max() = never
    bool revoked;
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
    static constexpr int kPbkdf2Iterations = 100'000;

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
    bool upsert_user(const std::string& username, const std::string& password, Role role);

    /// Remove a user by name.
    bool remove_user(const std::string& username);

    /// Change a user's role. Uses AuthDB if available, otherwise updates in-memory + config.
    /// Returns false if user not found.
    bool update_role(const std::string& username, Role new_role);

    /// Look up a user's legacy role. Returns nullopt if user not found.
    std::optional<Role> get_user_role(const std::string& username) const;

    /// Check whether any users are configured.
    bool has_users() const;

    /// Set the AuthDB instance to use for persistence.
    /// If set, user operations go through the DB instead of config file.
    /// If not set, falls back to config file I/O (backwards compatible).
    void set_auth_db(yuzu::server::AuthDB* db) { auth_db_ = db; }

    /// True iff a configured AuthDB is set AND it reports `is_ready()`.
    /// Wired into /readyz; operators rely on this to detect a corrupt or
    /// half-migrated auth.db without having to scrape spdlog. Returns
    /// true in the legacy config-file-only path (auth_db_ == nullptr is
    /// fine — the deployment isn't using AuthDB) so the readyz signal
    /// only fires on an actual AuthDB integrity failure.
    bool is_auth_db_ok() const noexcept;

    /// Set the metrics registry for emitting login-latency histograms.
    /// Optional; if null, authenticate() emits no metric (used by tests
    /// that don't construct the server's MetricsRegistry).
    void set_metrics_registry(yuzu::MetricsRegistry* m) { metrics_ = m; }

    /// Create a session for an externally-authenticated user (OIDC).
    /// Role: admin if user is in the admin group, or email/name matches a local admin.
    std::string create_oidc_session(const std::string& display_name, const std::string& email,
                                    const std::string& oidc_sub,
                                    const std::vector<std::string>& groups = {},
                                    const std::string& admin_group_id = {});

    const std::filesystem::path& config_path() const { return cfg_path_; }

    /// Set an explicit data directory for runtime state files (enrollment
    /// tokens, pending agents). If not set, defaults to cfg_path_ parent.
    void set_data_dir(const std::filesystem::path& dir) { data_dir_ = dir; }

    /// Re-load enrollment tokens and pending agents from the current state_dir().
    /// Call after set_data_dir() to pick up files from the new location.
    void reload_state() { load_tokens(); load_pending(); }

    // -- Enrollment tokens (Tier 2) ---------------------------------------

    /// Create a new enrollment token. Returns the raw token string (show once).
    std::string create_enrollment_token(const std::string& label, int max_uses,
                                        std::chrono::seconds ttl);

    /// Create multiple enrollment tokens at once for batch deployment.
    /// Returns a vector of raw token strings (each shown once).
    std::vector<std::string> create_enrollment_tokens_batch(const std::string& label_prefix,
                                                            int count, int max_uses_each,
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
    void add_pending_agent(const std::string& agent_id, const std::string& hostname,
                           const std::string& os, const std::string& arch,
                           const std::string& agent_version);

    /// Mark an agent as enrolled (approved). Creates the entry if it doesn't
    /// exist, or sets an existing entry to approved. This ensures reconnecting
    /// agents are recognized without re-enrollment.
    /// Returns false if the agent has been explicitly denied by an admin —
    /// tokens do not override admin denials.
    bool ensure_enrolled(const std::string& agent_id, const std::string& hostname,
                         const std::string& os, const std::string& arch,
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
    static std::string bytes_to_hex(const std::vector<uint8_t>& v);
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex);
    static std::string pbkdf2_sha256(const std::string& password, const std::vector<uint8_t>& salt,
                                     int iterations);
    static std::string sha256_hex(const std::string& input);

    /// Constant-time comparison of two hex strings (timing-attack safe).
    static bool constant_time_compare(const std::string& a, const std::string& b);

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

    /// Returns the directory for runtime state files.
    std::filesystem::path state_dir() const {
        return data_dir_.empty() ? cfg_path_.parent_path() : data_dir_;
    }

    mutable std::shared_mutex mu_;
    std::filesystem::path cfg_path_;
    std::filesystem::path data_dir_;
    std::unordered_map<std::string, UserEntry> users_;
    mutable std::unordered_map<std::string, Session> sessions_;

    // Non-owning pointer to AuthDB; if set, persistence goes through DB.
    yuzu::server::AuthDB* auth_db_ = nullptr;

    // Non-owning pointer to MetricsRegistry; null in tests/CLI tools.
    yuzu::MetricsRegistry* metrics_ = nullptr;

    // Enrollment tokens keyed by token_id
    std::unordered_map<std::string, EnrollmentToken> enrollment_tokens_;

    // Pending agents keyed by agent_id
    std::unordered_map<std::string, PendingAgent> pending_agents_;
};

// OS-appropriate default paths.
std::filesystem::path default_config_path();
std::filesystem::path default_cert_dir();

std::string role_to_string(Role r);
Role string_to_role(const std::string& s);

std::string pending_status_to_string(PendingStatus s);

} // namespace yuzu::server::auth
