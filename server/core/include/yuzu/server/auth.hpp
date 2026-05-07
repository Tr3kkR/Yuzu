#pragma once

#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}
namespace yuzu::server {
class AuthDB;
}

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
    std::string auth_source{"local"}; // "local", "oidc", "api_token", or "mcp_token"
    std::string oidc_sub;             // OIDC subject claim (empty for local auth)
    std::string token_scope_service;  // Non-empty = token scoped to this service
    std::string mcp_tier;             // "readonly", "operator", "supervised", or "" (not MCP)
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
    /// Last agent_id that consumed this token (W1.4 / #827). Populated on
    /// every successful consume so the lost-race audit detail can name the
    /// winner ("already_consumed_by=<agent_id>"). Empty on a freshly-created
    /// token or on a multi-use token before its first consume. Never the
    /// raw token — only the agent_id presented to consume_enrollment_token.
    std::string last_consumed_by_agent_id;
};

/// Typed rejection reason for `AuthManager::consume_enrollment_token`
/// (W1.4 / #827). Naming style matches W1.2's `DeviceTokenValidateError`
/// (snake_case variants) so SIEM filters can grep across both. Variants
/// are operator-facing — they surface in audit `detail` rows and as
/// Prometheus label values; the public wire shape is uniform ("invalid,
/// expired, or exhausted enrollment token") so no token-shape oracle leaks.
enum class EnrollmentTokenError {
    /// Empty / oversize / structurally malformed raw token. Length-bound
    /// enforced at handler entry (W1.1 UP-H2 pattern, > 256 chars → reject).
    invalid_input,
    /// Hash does not match any token in the store.
    not_found,
    /// Token row exists but `revoked = true`.
    revoked,
    /// Token row exists but `now > expires_at`.
    expired,
    /// Token row exists, not revoked, not expired, but `use_count >=
    /// max_uses` at consume time — either it was previously exhausted, or
    /// a concurrent consume won the race for the last available use. The
    /// race-lost case is distinguishable from "stale exhausted" by
    /// comparing `claim_when_consumed.last_consumed_by_agent_id` against
    /// the current presenter; the caller surfaces this in audit detail.
    already_consumed,
    /// Internal error during consume (lock unavailable, persistence
    /// failure). Caller treats as a hard reject and pages SRE.
    internal_error,
};

/// Successful claim returned from `AuthManager::consume_enrollment_token`.
/// Carries enough context for the success-path audit row and for telling
/// "this consume won an actual race" from "this consume was uncontested".
/// `prior_use_count` is the use_count BEFORE this consume — when it's > 0
/// for a max_uses > 1 token, this consume shared the token with prior
/// agents (legitimate multi-use). The token_id is the public-display
/// short ID (8 hex chars), safe to emit in audit detail.
struct EnrollmentClaim {
    std::string token_id;
    int max_uses{0};        // 0 = unlimited
    int use_count_after{0}; // After this consume
    bool single_use{false}; // max_uses == 1 → token is now exhausted
};

/// Maximum raw enrollment token length accepted at handler entry. Raw
/// tokens are 64 hex chars (32-byte CSPRNG output → bytes_to_hex). Tighter
/// than the 256-char W1.1 UP-H2 bound but uses the same `invalid_input_
/// length` audit detail to keep operator filters consistent across the
/// auth surfaces. Rationale: an enrollment token presented over the
/// gRPC Register RPC has no legitimate path that exceeds this bound —
/// anything longer is request-level garbage to be rejected before any
/// SHA-256 / map lookup work.
inline constexpr std::size_t kMaxEnrollmentTokenLength = 256;

/// Maximum agent_id length accepted at handler entry (W1.4 R2 / UP-H1).
/// Caps `RegisterRequest.info.agent_id` at the gRPC Register and gateway
/// ProxyRegister entry, before any audit emission, any auth-mgr lookup,
/// or any SHA-256 work. Without this cap a presenter can supply an
/// arbitrarily long agent_id (the protobuf has no length constraint) and
/// every downstream audit/analytics row carries the full string verbatim,
/// inflating audit-store I/O and SQLite row size into the megabyte range.
/// 256 chars matches `kMaxEnrollmentTokenLength` for parity — any legitimate
/// hostname-derived or UUID-derived agent_id fits in well under 100 chars.
inline constexpr std::size_t kMaxAgentIdLength = 256;

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

    /// Outcome of `invalidate_user_sessions`. The in-memory `count` is the
    /// number of session cookies erased; `db_persisted` is true iff the
    /// AuthDB DELETE returned success (or the deployment is config-file
    /// only and AuthDB is not configured). When `db_persisted=false` the
    /// caller MUST surface the partial outcome in any audit row — a
    /// "success" audit row that hides a DB write failure produces fictional
    /// SOC 2 CC6.3/CC6.6 evidence (Gate 6 COMPL-H1 / authdb-H1 / UP-3).
    struct RevokeResult {
        std::size_t count{0};
        bool db_persisted{true};
    };

    /// Wipe every session for a username, both in-memory and (if AuthDB
    /// is configured) persisted in `auth.db`. The DB DELETE happens
    /// FIRST, outside `mu_`, mirroring the lock-ordering of `remove_user`
    /// and `update_role`. The in-memory wipe runs unconditionally — even
    /// after a DB failure — so the actively-validating session is killed
    /// immediately for the operator's "stop NOW" use case; the caller is
    /// responsible for surfacing `db_persisted=false` so the operator
    /// knows a server restart may resurrect persisted rows.
    ///
    /// Caller is responsible for audit emission; this method does no
    /// logging or event publishing so it can run while the caller holds
    /// unrelated locks.
    [[nodiscard]] RevokeResult invalidate_user_sessions(const std::string& username);

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
    void reload_state() {
        load_tokens();
        load_pending();
    }

    // -- Enrollment tokens (Tier 2) ---------------------------------------

    /// Create a new enrollment token. Returns the raw token string (show once).
    std::string create_enrollment_token(const std::string& label, int max_uses,
                                        std::chrono::seconds ttl);

    /// Create multiple enrollment tokens at once for batch deployment.
    /// Returns a vector of raw token strings (each shown once).
    std::vector<std::string> create_enrollment_tokens_batch(const std::string& label_prefix,
                                                            int count, int max_uses_each,
                                                            std::chrono::seconds ttl);

    /// Read-only validity check for a raw enrollment token. Returns true
    /// iff the token exists, is not revoked, is not expired, and still has
    /// at least one use remaining. Does NOT mutate `use_count` and does
    /// NOT update `last_consumed_by_agent_id` — call
    /// `consume_enrollment_token` for the atomic check-and-consume.
    ///
    /// W1.4 R2 / UP-H2 semantic restoration: pre-W1.4 R2 this wrapper
    /// silently delegated to `consume_enrollment_token`, meaning any
    /// "is this token usable" probe would burn a use. That broke the
    /// caller's stated intent (name says "validate") and made
    /// `max_uses=1` tokens unreachable to any caller that wanted to
    /// observe-before-act. Restored to true read-only semantics. The
    /// only callers in-tree are tests; production Register / ProxyRegister
    /// handlers call `consume_enrollment_token` directly so they can
    /// emit the lost-race audit row.
    bool validate_enrollment_token(const std::string& raw_token);

    /// Atomic check-and-consume of an enrollment token (W1.4 / #827).
    ///
    /// **The race the function closes.** The prior `validate_enrollment_
    /// token` returned a bare bool. A second concurrent Register that
    /// presented the same token could pass the validity check before the
    /// first call's `++use_count` landed, allowing a single-use token to
    /// enroll N agents in the race window. This function does the validity
    /// check and the use-count increment under the SAME `unique_lock` so
    /// no second consumer can interleave. The token's `last_consumed_by_
    /// agent_id` is written under the same lock, giving the lost-race
    /// audit row enough context to name the winner.
    ///
    /// **Why an `EnrollmentClaim` on success.** The handler needs the
    /// public token_id (for audit detail), the new use_count (so a
    /// successful multi-use consume can still emit a "M of N uses
    /// remaining" log line), and `single_use` so the response can
    /// summarise the token's lifecycle.
    ///
    /// **Why a typed error on failure.** Audit/metric variant lives in the
    /// typed error; public wire response uniformly says "invalid, expired,
    /// or exhausted enrollment token" so the response shape is the same
    /// regardless of variant. This is the same wire-collapse rule that
    /// W1.3 enforces for `DeviceTokenValidateError` — a presenter cannot
    /// discriminate `not_found` from `already_consumed` (which would tell
    /// them the token existed and someone beat them to it). Operator-
    /// visible variance lives in audit rows + Prometheus counters.
    ///
    /// `consuming_agent_id` is the agent_id presented to Register. It is
    /// written into the token's `last_consumed_by_agent_id` on a winning
    /// consume so a subsequent loser can audit `already_consumed_by=<id>`.
    [[nodiscard]] std::expected<EnrollmentClaim, EnrollmentTokenError>
    consume_enrollment_token(std::string_view raw_token, std::string_view consuming_agent_id);

    /// Look up the most-recent consumer's agent_id for a token (hash-keyed).
    /// Used by the Register handler's lost-race audit emission so the
    /// "already_consumed_by=<X>" detail can name the winning agent without
    /// requiring a second locked traversal in the consume path.
    /// Returns empty string if no record / token not found / never consumed.
    std::string last_consumer_for_token_hash(std::string_view token_hash) const;

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
