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

/// Canonical `users.provisioning_source` values (auth.db migration v7). Every
/// read/write site MUST go through these constants rather than a raw string
/// literal — a typo in either fails the SCIM provenance guard OPEN (S-PROV-
/// CONST, consistency S2): a mismatched write would tag a fresh account with
/// an unrecognised source (never revivable by SCIM), and a mismatched read in
/// `provenance_ok` would refuse to recognise a legitimately SCIM-owned row.
inline constexpr std::string_view kProvisioningSourceScim = "scim";
inline constexpr std::string_view kProvisioningSourceLocal = "local";

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

/// `list_users_including_inactive()` row — same fields as `auth::UserEntry`
/// plus the `is_active` flag `list_users()` deliberately filters out. A NEW
/// type rather than extending `auth::UserEntry` itself: that struct is a
/// broadly-shared read contract (session/login paths never care about
/// disabled accounts), so adding a field there would be a cross-cutting
/// change out of scope for the one caller (periodic access reviews, CC6.2)
/// that needs to see disabled-but-still-granted users.
struct UserWithStatus {
    std::string username;
    auth::Role role;
    std::string identity_source{"local"};
    bool is_active{true};
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

    /// Auto-provision (or refresh) a durable row for an SSO-authenticated
    /// principal (#1852). The gate is `is_valid_principal` — a SUPERSET of
    /// `is_valid_username`: it accepts EITHER a strict local username OR a
    /// `"oidc:"`/`"saml:"`/`"ad:"`-reserved-prefixed identity; it does NOT
    /// require the reserved prefix (a bare local-shaped string is also
    /// accepted — rejected only when neither shape matches, InvalidUsername).
    /// `source` is NOT validated against `{oidc,saml,ad}` — it is written
    /// verbatim into `identity_source`, so a caller can construct a row
    /// with any `identity_source` string (a security test deliberately does
    /// this, passing `source="local"`, to build a legacy-shaped attack row
    /// for the elevate handler's source-scope guard — see
    /// `docs/security-reviews/sso-durable-identity-2026-07-03.md`).
    /// TODO(#1915): tighten this seam to enforce a reserved prefix
    /// on `principal` and `source ∈ {oidc,saml,ad}` — this call site is the
    /// ONLY intended caller (the OIDC callback), so today's looseness is
    /// latent, not actively exploitable, but it is a landmine for any future
    /// caller.
    /// On first login this INSERTs a row with `password_hash`/`salt_hex` = ''
    /// (never resolvable on the local login path — see file header note),
    /// `role='user'`, `elevation_eligible=0`. On every subsequent login the
    /// `ON CONFLICT` arm refreshes ONLY `display_name`/`last_seen_at`/
    /// `is_active` — it deliberately does NOT touch `role` or
    /// `elevation_eligible`, so an admin's standing role grant and JIT-
    /// elevation eligibility for this principal survive re-login. Call from
    /// the OIDC callback AFTER minting the session (independent auth.db I/O,
    /// not under AuthManager's `mu_`); a failure here degrades to "this
    /// principal cannot elevate", never "cannot log in" (fail-soft — see
    /// `AuthManager::provision_sso_identity`).
    std::expected<void, AuthDBError> upsert_sso_identity(const std::string& principal,
                                                          const std::string& iss,
                                                          const std::string& sub,
                                                          const std::string& display_name,
                                                          const std::string& source);

    /// Get a user by username. Returns UserEntry on success.
    std::expected<auth::UserEntry, AuthDBError> get_user(const std::string& username);

    /// List all active users.
    std::expected<std::vector<auth::UserEntry>, AuthDBError> list_users();

    /// List EVERY user row (active AND disabled), each carrying its
    /// `is_active` flag. Mirrors `list_users()`'s query with no `WHERE
    /// is_active` filter — deliberately does NOT modify or replace
    /// `list_users()` (other callers depend on its active-only contract).
    /// The sole intended caller is the periodic access review builder
    /// (`access_review_model.cpp`): a disabled user still holding a grant is
    /// materially different CC6.2 evidence than an "orphan" grant with no
    /// matching roster row at all, so the reviewer needs the full roster,
    /// not just the active slice.
    std::expected<std::vector<UserWithStatus>, AuthDBError> list_users_including_inactive();

    /// Read-only prefix scan over `users.username` (active AND soft-deleted)
    /// — backs the T8 startup collision-scan preflight (auth-engine-
    /// principals design decision log #3). `prefix` must be a code-
    /// controlled literal (e.g. `"engine:"`) — see the `.cpp` for the
    /// LIKE-metacharacter fail-closed guard. Returns an empty vector on any
    /// error (no error channel — a scan-time DB failure is logged, not
    /// surfaced structurally, matching the caller's own preflight contract).
    // Returns nullopt on a scan error (prepare failure / mid-scan SQLITE error)
    // so the collision-scan preflight can fail CLOSED — an empty vector means a
    // genuinely-completed scan with no collision, never a failed scan (symmetric
    // with RbacStore::find_local_groups_with_prefix; governance G3 residual).
    std::optional<std::vector<std::string>> find_reserved_prefix_users(const std::string& prefix);

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

    /// Set/clear the per-user JIT-elevation eligibility flag (SOC 2 CC6.3/CC6.6):
    /// who may activate a time-boxed admin elevation via POST /api/v1/elevate,
    /// distinct from holding standing admin. Admin-managed. Single
    /// UPDATE ... RETURNING (no sqlite3_changes() — #1033); UserNotFound when no
    /// active row matched, InvalidUsername for malformed input. Never touches
    /// credentials or role.
    std::expected<void, AuthDBError> set_elevation_eligible(const std::string& username,
                                                            bool eligible);

    /// Read the per-user JIT-elevation eligibility flag. Returns false for an
    /// absent/inactive user (fail-closed — not eligible). InvalidUsername for
    /// malformed input.
    std::expected<bool, AuthDBError> is_elevation_eligible(const std::string& username);

    /// Set the provenance marker for a user (SCIM v2 provisioning, slice 1 —
    /// storage layer only). Distinct from `identity_source` (v6, how a user
    /// authenticates): this is the security seam that lets a future SCIM
    /// deprovisioning path refuse to deactivate/delete a user it did not
    /// create. `source` is caller-supplied ("local" | "scim") — this
    /// storage-layer accessor does not itself enforce the enum; the SCIM
    /// route layer is the trusted caller. Single UPDATE ... RETURNING (no
    /// sqlite3_changes() — #1033). UserNotFound when no active row matched,
    /// InvalidUsername for malformed input. Never touches credentials or role.
    std::expected<void, AuthDBError> set_provisioning_source(const std::string& username,
                                                              const std::string& source);

    /// Read the provenance marker for a user. UNLIKE most accessors on this
    /// class, this deliberately reads REGARDLESS of `is_active` (soft-deleted
    /// rows included) — the SCIM provenance guard must be able to approve a
    /// PATCH/PUT active=true reactivation while the row is still inactive,
    /// i.e. exactly the moment before `reactivate_user` flips it back.
    /// UserNotFound only when no row (active or not) matched; InvalidUsername
    /// for malformed input.
    std::expected<std::string, AuthDBError>
    get_provisioning_source(const std::string& username);

    /// Set the `identity_source` marker (auth.db migration v6) directly —
    /// distinct from `set_provisioning_source` (WHO manages the account's
    /// lifecycle) — this is HOW the account authenticates, the same column
    /// `upsert_sso_identity` writes for OIDC rows and the Settings user list
    /// reads to render the "SSO" badge (S-IDENTITY-SRC). SCIM provisioning is
    /// its own login surface (IdP-driven, no local password usable — see
    /// `scim_routes.cpp`), so it gets its own value rather than being rendered
    /// as `'local'`-login-capable. `source` is caller-supplied; this storage-
    /// layer accessor does not itself enforce an enum. Single UPDATE ...
    /// RETURNING (no sqlite3_changes() — #1033). UserNotFound when no active
    /// row matched, InvalidUsername for malformed input. Never touches
    /// credentials, role, or provisioning_source.
    std::expected<void, AuthDBError> set_identity_source(const std::string& username,
                                                          const std::string& source);

    /// Reactivate a soft-deleted (`is_active = 0`) user row — the SCIM v2
    /// PATCH/PUT `active: true` (un-suspend) path, and the only writer of
    /// `is_active = 1` on an EXISTING row (every other UPDATE in this file
    /// filters `WHERE ... AND is_active = 1`, and `upsert_user` is INSERT ...
    /// ON CONFLICT DO NOTHING — neither can revive a soft-deleted row).
    /// Single UPDATE ... RETURNING (no sqlite3_changes() — #1033).
    ///
    /// Semantics (deliberate, do not "improve" without a fresh security
    /// review): clears `failed_login_count` / `last_failed_login_at` /
    /// `locked_until` — a returning user must not inherit a stale lockout
    /// from before they were deprovisioned. Does NOT touch
    /// `mfa_totp_secret` / MFA enrollment state — `remove_user` wiped that
    /// deliberately on deactivation (see its header comment) and this does
    /// NOT restore it; the user re-enrolls per the configured MFA
    /// enforcement mode. Does NOT touch `provisioning_source` or `role` —
    /// both stay whatever they were before deactivation.
    ///
    /// UserNotFound when no row (active OR inactive) matched `username`,
    /// InvalidUsername for malformed input. Reactivating an ALREADY-active
    /// user is a harmless no-op (still returns success).
    std::expected<void, AuthDBError> reactivate_user(const std::string& username);

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

    /// Destroy all sessions for a user (logout all devices). `username` is
    /// validated with `is_valid_principal` (governance round cons-S1) — a
    /// target-lookup DELETE, so a durable SSO principal (`oidc:<iss>#<sub>`)
    /// is accepted alongside a strict local username.
    std::expected<void, AuthDBError> invalidate_all_sessions(const std::string& username);

    /// Remove expired sessions. Returns count of sessions removed.
    /// Called periodically by the background cleanup thread that
    /// `initialize()` spawns; safe to call manually as well.
    std::expected<int, AuthDBError> cleanup_expired_sessions();

    /// Best-effort durable mirror of a session's `last_activity_at` for the
    /// idle-timeout feature (SOC 2 CC6.3). The in-memory session map is the
    /// authoritative idle-timeout read path; AuthManager throttles this call to
    /// at most once per session per `kActivityPersistGranularity`, so it is not
    /// a per-request SQL write. Parameterised, no `sqlite3_changes()` (#1033).
    std::expected<void, AuthDBError> touch_session_activity(const std::string& session_token);

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

    // ── Account-lockout Operations ───────────────────────────────────────
    //
    // SOC 2 CC6.3 — brute-force / credential-stuffing protection on the
    // local-password login path. See `/auth-and-authz` skill gap matrix
    // entry P0 #2 and docs/auth-architecture.md. Lockout state lives as
    // three columns on the users table (migration v3): failed_login_count,
    // last_failed_login_at, locked_until. A non-existent username has no
    // row, so spraying random usernames cannot grow storage and cannot lock
    // a non-existent account. Policy (threshold + window) is owned by the
    // caller (ServerConfig) and passed in, so AuthDB stays policy-free and
    // an operator can retune without a schema change. The lockout is
    // temporary/auto-expiring (locked_until is a future timestamp), so it
    // cannot be weaponised to permanently DoS a legitimate principal.

    struct LockoutStatus {
        bool locked{false};       // locked_until is set AND still in the future
        int failed_count{0};      // current consecutive-failure counter
        std::string locked_until; // SQLite DATETIME string, or "" when unlocked
    };

    struct LockoutRecord {
        int failed_count{0};      // counter value AFTER this failure
        bool locked{false};       // account is locked after this failure
        bool just_locked{false};  // this failure is the one that crossed the threshold
        std::string locked_until; // SQLite DATETIME string, or "" when not locked
    };

    /// Read-only lockout pre-check. Returns a zero-initialised LockoutStatus
    /// (locked=false) when the user row is absent — callers treat "no such
    /// user" as "not locked" so the bad-username path is indistinguishable
    /// from the bad-password path (anti-enumeration). Returns InvalidUsername
    /// for malformed input.
    std::expected<LockoutStatus, AuthDBError> lockout_status(const std::string& username);

    /// Record one failed local-password attempt. Increments the counter,
    /// stamps last_failed_login_at, and sets locked_until = now + window the
    /// moment the counter reaches `threshold`. Single UPDATE ... RETURNING
    /// (no sqlite3_changes() — #1033). No-op (failed_count=0, not locked)
    /// when `threshold <= 0` or the user row is absent.
    std::expected<LockoutRecord, AuthDBError>
    record_failed_login(const std::string& username, int threshold, int window_secs);

    /// Clear lockout state on a successful login or admin unlock. Resets the
    /// counter to 0 and NULLs both timestamps. Idempotent; no-op on absent
    /// rows. Returns InvalidUsername for malformed input.
    std::expected<void, AuthDBError> clear_failed_logins(const std::string& username);

    // ── Break-glass arming (hardened mode) ───────────────────────────────
    //
    // SOC 2 CC6.6. See docs/auth-architecture.md "Hardened mode". The single
    // configured break-glass account (Config::break_glass_user) is exempt from
    // --auth-mode=sso-only ONLY while armed. "Armed" is a future timestamp in
    // users.break_glass_armed_until, evaluated in SQL against CURRENT_TIMESTAMP
    // exactly like locked_until, so the exemption auto-expires and is never a
    // permanent standing bypass. Arming is an out-of-band host operation
    // (--break-glass-arm), not a session-authenticated route, so it works when
    // the IdP is down (the case break-glass exists for).

    struct BreakGlassStatus {
        bool armed{false};        // break_glass_armed_until set AND still in the future
        std::string armed_until;  // SQLite DATETIME string, or "" when dormant
    };

    /// Read-only break-glass arm check. Returns a zero-initialised
    /// BreakGlassStatus (armed=false) when the user row is absent. Returns
    /// InvalidUsername for malformed input.
    std::expected<BreakGlassStatus, AuthDBError> break_glass_status(const std::string& username);

    /// Arm the break-glass account for `window_secs` from now
    /// (break_glass_armed_until = datetime('now', '+N seconds')). Single
    /// UPDATE ... RETURNING (no sqlite3_changes() — #1033). Returns
    /// UserNotFound when no active user row matched (so the host operator gets a
    /// clear error rather than a silent no-op), InvalidUsername for malformed
    /// input.
    std::expected<BreakGlassStatus, AuthDBError> arm_break_glass(const std::string& username,
                                                                 int window_secs);

    /// Disarm the break-glass account (set break_glass_armed_until = NULL).
    /// Used as the compensating un-arm when the mandatory `auth.breakglass.armed`
    /// audit row fails to persist after `arm_break_glass` succeeded — so the
    /// exemption is never left standing without an evidence row (review #1735
    /// HIGH-2; honours the "never granted without a record" guarantee in
    /// docs/ops-runbooks/auth-db-recovery.md). Idempotent; InvalidUsername for
    /// malformed input. Parameterised, no sqlite3_changes() (#1033).
    std::expected<void, AuthDBError> disarm_break_glass(const std::string& username);

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

/// True iff `username` begins with a reserved SSO-principal or engine-
/// principal namespace prefix (`oidc:`, `saml:`, `ad:`, `engine:`; case-
/// insensitive). Defense-in-depth for the LOCAL-user CREATE path only —
/// `is_valid_username`'s existing ':' rejection already makes the exact
/// stable-principal string `oidc:<iss>#<sub>` (or `engine:<slug>`)
/// unconstructable as a local username, but an explicit reservation
/// documents the intent and survives a future loosening of that charset.
/// `engine:` reservation is the auth-engine-principals design §3.3 / PR 4.2.
/// Without it, an admin could otherwise create a local user that collides
/// with (or is later made to collide with) an SSO-derived principal — that
/// local user's row would supply the eligibility/TOTP an SSO principal
/// deliberately lacks (#1837), re-opening the elevation-borrow hazard.
/// Deliberately NOT folded into `is_valid_username` (used at ~20 sites; its
/// contract must stay charset-only). Callers apply this ONLY at user-creation
/// chokepoints, never at target-lookup/validation sites for existing users.
bool is_reserved_identity_prefix(const std::string& username);

/// Validate a value that may be EITHER a strict local username OR a durable
/// SSO principal (`"oidc:"`/`"saml:"`/`"ad:"` + issuer + `#` + subject,
/// #1852). A strict superset of `is_valid_username`: anything the strict
/// validator accepts is accepted here unchanged; a reserved-prefixed string
/// is additionally accepted after a narrow control-byte / SQL-metacharacter
/// blocklist (permits `: # / . _ - @ ~ % |` — the IdP issuer URL + opaque
/// sub alphabet), capped at 255 bytes. Use ONLY at target-lookup/validation
/// chokepoints for an EXISTING user (elevation eligibility, session revoke)
/// — never at user-creation chokepoints, which must keep using
/// `is_valid_username` (+ `is_reserved_identity_prefix` to reserve the SSO
/// namespace) so a local account can never be created inside it.
/// `is_reserved_identity_prefix` now also reserves `engine:` — this widens
/// the *format* this validator accepts, but no `users` row can ever actually
/// carry that prefix: local creation stays blocked by `is_valid_username`'s
/// ':' ban, and `upsert_sso_identity`'s principal is always
/// `source + ":" + iss + "#" + sub` with `source` a caller-controlled
/// literal in {"oidc","saml","ad"} — never "engine".
bool is_valid_principal(const std::string& s);

/// Validate that `username` is usable as the hardened-mode break-glass account:
/// a syntactically valid username naming an existing ACTIVE user that has MFA
/// enrolled. Returns std::nullopt when usable, otherwise an operator-facing
/// reason string. Mandatory-MFA is enforced here, fail-closed (SOC 2 CC6.6) so
/// the sso-only escape hatch can never be a bare-password account; a store read
/// error is also a problem (never report a broken account as usable). Because
/// `mfa_status` filters `is_active = 1`, a soft-deleted user reads as
/// not-enrolled and is correctly rejected. Shared by the server boot guard and
/// the `--break-glass-arm` one-shot so both apply one contract.
std::optional<std::string> break_glass_account_problem(AuthDB& db, const std::string& username);

} // namespace yuzu::server