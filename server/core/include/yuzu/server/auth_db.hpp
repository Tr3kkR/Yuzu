#pragma once

/**
 * auth_db.hpp — SQLite-backed authentication persistence for Yuzu Server
 * 
 * Provides persistent storage for users, sessions, enrollment tokens,
 * and pending agents. Replaces config-file-based auth persistence.
 * 
 * Security features:
 * - All SQL uses prepared statements (no string concatenation)
 * - Thread-safe (SQLITE_OPEN_FULLMUTEX + WAL mode)
 * - PRAGMA integrity_check on startup
 * - Atomic enrollment token consumption
 * - Input validation on all user-controlled data
 * - Separate update_role() method (never touches credentials)
 */

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "yuzu/server/auth.hpp"  // For Role, UserEntry, Session, etc.

namespace yuzu::server {

// ── Error Types ──────────────────────────────────────────────────────────────

// Explicit underlying type — locks ABI/serialization width so adding new
// values can never silently widen the enum across the plugin/wire boundary.
enum class AuthDBError : std::uint8_t {
    CannotCreateDirectory,
    CannotOpenDatabase,
    DatabaseCorrupt,
    SchemaCreationFailed,
    StatementPrepareFailed,
    WriteFailed,
    QueryFailed,
    UserNotFound,
    SessionNotFound,
    InvalidUsername,
    InvalidCredentials,
    UserAlreadyExists,
    /// Returned when an MFA-domain operation finds the user already
    /// enrolled (e.g. mfa_init_enrollment called twice). Distinct from
    /// `UserAlreadyExists` (which is a create-time conflict for the
    /// users row) so SIEM rules and call-site error handlers can
    /// distinguish "you already have MFA — disable first" from "user
    /// account already exists at creation" — both surface as 409 to
    /// the wire, but the audit-detail and operator messaging differ.
    MfaAlreadyEnrolled,
};

// ── AuthDB Class ─────────────────────────────────────────────────────────────

class AuthDB {
public:
    /// Construct with the directory where auth.db should live.
    /// Call initialize() before any other method.
    explicit AuthDB(const std::filesystem::path& data_dir);

    /// Construct with an explicit cleanup-thread cadence.
    /// `cleanup_interval_secs` ≤ 0 disables the background reaper
    /// entirely — used by unit tests that construct + destruct many
    /// AuthDB instances back-to-back (see PR #1199: on macOS arm64 the
    /// rapid `std::jthread` create/destroy cycle was triggering a
    /// non-deterministic SIGSEGV in `test_mfa_store.cpp`). Production
    /// callers use the single-argument overload and inherit the
    /// 60-second default.
    AuthDB(const std::filesystem::path& data_dir, int cleanup_interval_secs);

    ~AuthDB();

    // Non-copyable, non-movable
    AuthDB(const AuthDB&) = delete;
    AuthDB& operator=(const AuthDB&) = delete;
    AuthDB(AuthDB&&) = delete;
    AuthDB& operator=(AuthDB&&) = delete;

    /// Open/create the database and run migrations.
    /// Must be called once before any other method.
    std::expected<void, AuthDBError> initialize();

    /// True iff initialize() succeeded AND the SQLite handle is still
    /// open (integrity_check passed, schema migrations ran cleanly).
    /// Wired into /readyz so an operator can detect a corrupt or
    /// half-migrated auth.db without having to scrape spdlog. Lock-free.
    bool is_ready() const noexcept;

    // ── User Operations ──────────────────────────────────────────────────

    /// Create or update a user.
    /// Username is validated (alphanumeric + ._- only, 1-64 chars).
    /// For new users: password_hash and salt_hex are required.
    /// For existing users: all fields are updated (password + role).
    std::expected<void, AuthDBError> upsert_user(
        const std::string& username,
        const std::string& password_hash,
        const std::string& salt_hex,
        auth::Role role
    );

    /// Get a user by username. Returns UserEntry on success.
    std::expected<auth::UserEntry, AuthDBError> get_user(const std::string& username);

    /// List all active users.
    std::expected<std::vector<auth::UserEntry>, AuthDBError> list_users();

    /// Stamp `users.last_login_at = CURRENT_TIMESTAMP` for the named
    /// user. Called by AuthManager after every successful local /
    /// recovery-code login (the MFA-verified login path stamps it as
    /// part of the same UPDATE that advances mfa_last_counter, so
    /// this method is only needed for the no-MFA and OIDC paths).
    /// SOC 2 CC7.2 — without it, `last_login_at` reports stale data on
    /// dashboards and access reviews. Best-effort; failure is logged
    /// but not surfaced to the caller (session creation has already
    /// succeeded at the call site).
    void touch_last_login(const std::string& username);

    /// Soft-delete a user (sets is_active = 0).
    /// Also invalidates all sessions for this user.
    std::expected<bool, AuthDBError> remove_user(const std::string& username);

    /// Check if a user exists (active only).
    std::expected<bool, AuthDBError> user_exists(const std::string& username);

    /// Change a user's role. ONLY updates the role column — never touches
    /// password_hash or salt_hex. This is critical for security: role changes
    /// must never overwrite credentials (C1 fix, Red Team finding).
    std::expected<void, AuthDBError> update_role(
        const std::string& username,
        auth::Role new_role
    );

    // ── Session Operations ───────────────────────────────────────────────
    //
    // v1 status: AuthManager retains its in-memory `sessions_` map and does
    // NOT delegate session lifecycle to AuthDB. The methods below WRITE
    // through to the DB (so role-change / user-delete cascades hit the
    // sessions table) but the in-memory map is the authoritative read path.
    // Persistence-across-restart for sessions is v2 (see governance H-Round
    // arch-S1) — when that lands, AuthManager will call validate_session
    // on AuthDB during validate_session() and the dead-write gap closes.
    //
    // The methods are kept on the surface (rather than #if-gated out) so
    // the v2 wire-up is mechanical: only the AuthManager call sites change.

    /// Create a new session. Returns the session token.
    /// Note: Sessions do NOT persist across restarts (by design, v1).
    ///       Session restoration is tracked as future work.
    std::expected<std::string, AuthDBError> create_session(
        const std::string& username,
        auth::Role role,
        const std::string& auth_source = "password",
        const std::string& oidc_sub = ""
    );

    /// Validate a session token. Returns Session on success.
    /// Note: Does NOT check expiry — caller (AuthManager) must validate
    ///       expires_at against current time.
    std::expected<auth::Session, AuthDBError> validate_session(const std::string& token);

    /// Destroy a single session (logout).
    std::expected<void, AuthDBError> invalidate_session(const std::string& token);

    /// Destroy all sessions for a user (logout all devices).
    std::expected<void, AuthDBError> invalidate_all_sessions(const std::string& username);

    /// Remove expired sessions. Returns count of sessions removed.
    /// Called periodically by the background cleanup thread that
    /// `initialize()` spawns; safe to call manually as well.
    std::expected<int, AuthDBError> cleanup_expired_sessions();

    /// Reap provisional MFA enrollment rows (init'd but never verified)
    /// older than `older_than`. Clears `mfa_totp_secret` to NULL on any
    /// row whose `mfa_enrolled_at IS NULL` AND `updated_at` is older
    /// than the cutoff. Returns the count of rows cleared. SOC 2 CC6.6 —
    /// dangling provisional secrets are usable until verified, and a
    /// stale provisional row that survives indefinitely is a CC6.6
    /// finding. Called on the same 60 s cadence as
    /// `cleanup_expired_sessions`.
    std::expected<int, AuthDBError>
    cleanup_provisional_mfa(std::chrono::seconds older_than = std::chrono::hours(1));

    // ── MFA / TOTP Operations ────────────────────────────────────────────
    //
    // SOC 2 CC6.6 (privileged access). See docs/auth-mfa-design.md and
    // `/auth-and-authz` skill gap matrix entry P0 #1.
    //
    // Lifecycle: mfa_init_enrollment writes a fresh 20-byte HMAC-SHA1
    // secret to users.mfa_totp_secret but leaves mfa_enrolled_at NULL —
    // the row is "provisional" until mfa_verify_enrollment lands a code
    // that proves the user has actually scanned the otpauth URI. Calling
    // mfa_init_enrollment again on a provisional row rotates the secret
    // and resets mfa_last_counter; calling it on an already-enrolled row
    // returns AuthDBError::UserAlreadyExists (caller must mfa_disable first).
    //
    // Replay protection: mfa_verify_login_code persists the matched
    // counter as mfa_last_counter and rejects any subsequent code <= that
    // value within the ±skew window. The skew is hard-coded to ±1 step
    // (90 s effective window) — RFC 6238 recommends a small skew and the
    // server clock is assumed to be NTP-synced.

    struct MfaStatus {
        bool enrolled{false};
        // SQLite DATETIME strings ("YYYY-MM-DD HH:MM:SS UTC") or empty.
        // Returned as strings rather than parsed time_points because v1 only
        // displays them; converting at the DB boundary would require chrono
        // parsing helpers that aren't yet in tree.
        std::string enrolled_at;
        std::string disabled_at;
        int recovery_codes_remaining{0};
    };

    struct MfaEnrollmentInit {
        std::string secret_base32;
        std::string otpauth_uri;
    };

    /// Read MFA status for a user. Returns a zero-initialised MfaStatus
    /// (enrolled=false, recovery_codes_remaining=0) if the row exists
    /// but has no MFA configured.
    std::expected<MfaStatus, AuthDBError> mfa_status(const std::string& username);

    /// Generate a fresh TOTP secret and write it as provisional. Returns
    /// the base32 form + otpauth URI for the enrollment UI. Idempotent on
    /// provisional rows; returns UserAlreadyExists on already-enrolled rows.
    std::expected<MfaEnrollmentInit, AuthDBError>
    mfa_init_enrollment(const std::string& username, std::string_view issuer);

    /// Verify the first code against the provisional secret. On success,
    /// stamps mfa_enrolled_at = CURRENT_TIMESTAMP, generates 10 recovery
    /// codes (returned raw, hashed in DB), and returns the codes for the
    /// one-time reveal. Idempotent on already-enrolled rows: returns
    /// UserAlreadyExists.
    std::expected<std::vector<std::string>, AuthDBError>
    mfa_verify_enrollment(const std::string& username, std::string_view code);

    /// Verify a TOTP code for login or step-up. Persists the matched
    /// counter to mfa_last_counter on success. Returns true on match,
    /// false on no-match. Rejects (false) if the user is not enrolled.
    std::expected<bool, AuthDBError> mfa_verify_login_code(const std::string& username,
                                                          std::string_view code);

    /// Consume a single recovery code for login or step-up. Returns true
    /// if the code matched an unconsumed row (and that row is now
    /// consumed). False on no-match (also false if the user has no
    /// recovery codes / is not enrolled).
    std::expected<bool, AuthDBError> mfa_consume_recovery_code(const std::string& username,
                                                               std::string_view raw_code);

    /// Wipe the user's existing recovery codes and issue 10 fresh ones.
    /// Returns the raw codes for one-time display. Requires the user to
    /// be enrolled; returns UserNotFound on no enrollment.
    std::expected<std::vector<std::string>, AuthDBError>
    mfa_regenerate_recovery_codes(const std::string& username);

    /// Disable MFA for a user. Clears the secret blob, stamps
    /// mfa_disabled_at, and deletes all recovery codes. Idempotent on
    /// not-enrolled rows.
    std::expected<void, AuthDBError> mfa_disable(const std::string& username);

    /// Update sessions.mfa_verified_at = CURRENT_TIMESTAMP on the row
    /// matching session_token. Returns SessionNotFound if no row.
    /// In-memory session state (AuthManager::sessions_) is updated by
    /// the caller — this method only persists to DB.
    std::expected<void, AuthDBError>
    mfa_mark_session_stepup(const std::string& session_token);

    // ── Enrollment Token Operations ───────────────────────────────────────

    /// Create a new enrollment token. Returns the raw token (show once).
    /// The token is stored as a SHA-256 hash — plaintext never persisted.
    std::expected<std::string, AuthDBError> create_enrollment_token(
        const std::string& created_by,
        std::chrono::seconds validity
    );

    /// Validate an enrollment token without consuming it.
    /// Returns true if token exists, is unused, and hasn't expired.
    std::expected<bool, AuthDBError> validate_enrollment_token(const std::string& plain_token);

    /// Consume an enrollment token atomically.
    /// Returns true if token was valid and consumed, false if already used/invalid.
    /// C2 FIX: Persists to DB BEFORE returning — survives server restart.
    /// Defense-in-depth: Also checks expiry in same atomic operation.
    std::expected<bool, AuthDBError> consume_enrollment_token(
        const std::string& plain_token,
        const std::string& agent_id
    );

    // ── Pending Agent Operations ─────────────────────────────────────────

    /// Add an agent to the pending approval queue.
    std::expected<void, AuthDBError> add_pending_agent(const auth::PendingAgent& agent);

    /// List all pending agents.
    std::expected<std::vector<auth::PendingAgent>, AuthDBError> list_pending_agents();

    /// Approve a pending agent.
    std::expected<void, AuthDBError> approve_agent(
        const std::string& agent_id,
        const std::string& approved_by
    );

    /// Reject a pending agent.
    std::expected<void, AuthDBError> reject_agent(const std::string& agent_id);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    /// Create database schema (idempotent — safe to call multiple times).
    std::expected<void, AuthDBError> create_schema();
};

// ── Utility Functions ────────────────────────────────────────────────────────

/// Validate username format.
/// Rules: 1-64 chars, alphanumeric + . _ - only, no ':' (config injection).
bool is_valid_username(const std::string& username);

} // namespace yuzu::server