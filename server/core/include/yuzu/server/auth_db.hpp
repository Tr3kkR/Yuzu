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

#include <chrono>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "yuzu/server/auth.hpp"  // For Role, UserEntry, Session, etc.

namespace yuzu::server {

// ── Error Types ──────────────────────────────────────────────────────────────

enum class AuthDBError {
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
};

// ── AuthDB Class ─────────────────────────────────────────────────────────────

class AuthDB {
public:
    /// Construct with the directory where auth.db should live.
    /// Call initialize() before any other method.
    explicit AuthDB(const std::filesystem::path& data_dir);
    ~AuthDB();

    // Non-copyable, non-movable
    AuthDB(const AuthDB&) = delete;
    AuthDB& operator=(const AuthDB&) = delete;
    AuthDB(AuthDB&&) = delete;
    AuthDB& operator=(AuthDB&&) = delete;

    /// Open/create the database and run migrations.
    /// Must be called once before any other method.
    std::expected<void, AuthDBError> initialize();

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
    std::expected<int, AuthDBError> cleanup_expired_sessions();

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