/**
 * auth_db.cpp — SQLite-backed authentication persistence for Yuzu Server
 *
 * Fixes implemented from Red Team review:
 * - C1: Role parameter stripped from user creation (admin-only via separate endpoint)
 * - C2: Enrollment token consumption is atomic + persisted immediately
 * - C3: OIDC admin role ONLY via group membership (removed local username matching)
 * - H1: Username validation (alphanumeric + ._- only, no ':' config injection)
 * - QA-1: PRAGMA integrity_check on DB open
 */

#include <yuzu/server/auth_db.hpp>
#include "migration_runner.hpp"
#include "totp.hpp"
#include <sqlite3.h>
#include <spdlog/spdlog.h>

// MSVC's STL does not transitively include these via <regex>/<chrono>/<filesystem>.
// Keep them explicit (cf. governance round 7ea7be6 + xp-B1 / cpp-SH-2).
#include <atomic>
#include <cctype> // std::isalnum
#include <chrono>
#include <cstring>
#include <ctime> // std::time_t (downstream dependency for chrono format)
#include <filesystem>
#include <format> // std::format chrono — replaces thread-unsafe std::gmtime
#include <regex>
#include <thread>

namespace yuzu::server {

// ── Username Validation (H1 Fix) ─────────────────────────────────────────────

bool is_valid_username(const std::string& username) {
    // Length check: 1-64 characters
    if (username.empty() || username.size() > 64) {
        spdlog::warn("Username validation failed: invalid length ({})", username.size());
        return false;
    }

    // Character check: alphanumeric + . _ - only
    // Explicitly reject ':' to prevent config file format injection
    for (char c : username) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '_' && c != '-') {
            spdlog::warn("Username validation failed: invalid character '{}' in '{}'", c, username);
            return false;
        }
    }

    return true;
}

// ── SQLite column-text accessor (null-safe) ──────────────────────────────────
//
// sqlite3_column_text returns nullptr when the column value is SQL NULL.
// Direct construction of std::string from nullptr is UB. The previous code
// reinterpret_cast'd and assigned without a null check at every call site;
// any column with a nullable type (e.g. oidc_sub at sessions.oidc_sub) was
// a latent UB site (governance round cpp-SH-1).
//
// Returns "" on null, the UTF-8 column text otherwise.
namespace {
std::string col_text(sqlite3_stmt* stmt, int idx) {
    const unsigned char* p = sqlite3_column_text(stmt, idx);
    return p ? std::string(reinterpret_cast<const char*>(p)) : std::string{};
}

// Replaces std::strftime + std::gmtime, which on glibc returns a pointer
// into a single static buffer shared across all threads — concurrent
// create_session / create_enrollment_token calls produced corrupt
// timestamps under load (governance round xp-S1). std::format chrono is
// thread-safe and requires no scratch buffer.
std::string format_sqlite_utc(std::chrono::system_clock::time_point tp) {
    return std::format("{:%Y-%m-%d %H:%M:%S}", std::chrono::floor<std::chrono::seconds>(tp));
}

/// RAII guard around a `BEGIN IMMEDIATE … COMMIT` pair on a sqlite3
/// connection. Defaults to ROLLBACK at destruction; `commit()` switches
/// to COMMIT. Used by `remove_user`, `mfa_disable`, and
/// `mfa_regenerate_recovery_codes` to make their multi-statement state
/// mutations atomic (Gate 3 cpp-safety BLOCKING + authdb F3 + sre
/// SHOULD + compliance CC6.8 BLOCKING).
///
/// `BEGIN IMMEDIATE` acquires the RESERVED lock up front so a write
/// from another connection cannot interleave between BEGIN and the
/// first inner UPDATE. Matches the pattern in `migration_runner.cpp:99`.
class TxnGuard {
public:
    explicit TxnGuard(sqlite3* db) : db_(db) {
        char* err = nullptr;
        if (sqlite3_exec(db_, "BEGIN IMMEDIATE;", nullptr, nullptr, &err) != SQLITE_OK) {
            spdlog::warn("auth_db: BEGIN IMMEDIATE failed: {}", err ? err : "unknown");
            sqlite3_free(err);
            db_ = nullptr; // signal "no transaction live"
        }
    }
    ~TxnGuard() {
        if (db_) {
            sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
        }
    }
    TxnGuard(const TxnGuard&) = delete;
    TxnGuard& operator=(const TxnGuard&) = delete;
    bool active() const noexcept { return db_ != nullptr; }
    [[nodiscard]] bool commit() {
        if (!db_)
            return false;
        char* err = nullptr;
        auto rc = sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            spdlog::error("auth_db: COMMIT failed: {}", err ? err : "unknown");
            sqlite3_free(err);
            return false;
        }
        db_ = nullptr;
        return true;
    }

private:
    sqlite3* db_;
};
} // namespace

// ── AuthDB Implementation ────────────────────────────────────────────────────

struct AuthDB::Impl {
    sqlite3* db = nullptr;
    std::filesystem::path db_path;

    /// Cleanup-thread cadence in seconds. Set from the AuthDB constructor;
    /// `<=0` means the background reaper is not spawned. Production
    /// callers default to 60 s.
    int cleanup_interval_secs = 60;

    // Background expired-session reaper (governance round comp-B3).
    // Mirrors the AuditStore / GuaranteedStateStore pattern: jthread when
    // available (libstdc++ 11+, libc++ 18+, MSVC STL 19.34+), fallback to
    // std::thread + atomic stop flag for older toolchains.
#ifdef __cpp_lib_jthread
    std::jthread cleanup_thread;
#else
    std::thread cleanup_thread;
    std::atomic<bool> stop_cleanup{false};
#endif

    // Prepared statements (initialized once, reused for lifetime)
    sqlite3_stmt* stmt_upsert_user = nullptr;
    sqlite3_stmt* stmt_get_user = nullptr;
    sqlite3_stmt* stmt_list_users = nullptr;
    sqlite3_stmt* stmt_remove_user = nullptr;
    sqlite3_stmt* stmt_user_exists = nullptr;

    sqlite3_stmt* stmt_create_session = nullptr;
    sqlite3_stmt* stmt_get_session = nullptr;
    sqlite3_stmt* stmt_invalidate_session = nullptr;
    sqlite3_stmt* stmt_invalidate_all_sessions = nullptr;
    sqlite3_stmt* stmt_cleanup_expired_sessions = nullptr;

    sqlite3_stmt* stmt_create_enrollment_token = nullptr;
    sqlite3_stmt* stmt_consume_enrollment_token = nullptr; // C2 FIX: Atomic operation
    sqlite3_stmt* stmt_get_enrollment_token = nullptr;

    sqlite3_stmt* stmt_add_pending_agent = nullptr;
    sqlite3_stmt* stmt_get_pending_agent = nullptr;
    sqlite3_stmt* stmt_list_pending_agents = nullptr;
    sqlite3_stmt* stmt_approve_agent = nullptr;
    sqlite3_stmt* stmt_reject_agent = nullptr;

    ~Impl() {
        // Stop the cleanup thread BEFORE finalizing statements / closing
        // the connection. The thread may be mid-step on
        // stmt_cleanup_expired_sessions (or its inline counterpart) and a
        // race here would land sqlite3_step on a half-finalized statement.
#ifdef __cpp_lib_jthread
        if (cleanup_thread.joinable()) {
            cleanup_thread.request_stop();
            cleanup_thread.join();
        }
#else
        stop_cleanup.store(true);
        if (cleanup_thread.joinable()) {
            cleanup_thread.join();
        }
#endif

        // Finalize all prepared statements
        finalize_statement(stmt_upsert_user);
        finalize_statement(stmt_get_user);
        finalize_statement(stmt_list_users);
        finalize_statement(stmt_remove_user);
        finalize_statement(stmt_user_exists);

        finalize_statement(stmt_create_session);
        finalize_statement(stmt_get_session);
        finalize_statement(stmt_invalidate_session);
        finalize_statement(stmt_invalidate_all_sessions);
        finalize_statement(stmt_cleanup_expired_sessions);

        finalize_statement(stmt_create_enrollment_token);
        finalize_statement(stmt_consume_enrollment_token);
        finalize_statement(stmt_get_enrollment_token);

        finalize_statement(stmt_add_pending_agent);
        finalize_statement(stmt_get_pending_agent);
        finalize_statement(stmt_list_pending_agents);
        finalize_statement(stmt_approve_agent);
        finalize_statement(stmt_reject_agent);

        // Close database connection
        if (db) {
            sqlite3_close(db);
        }
    }

    void finalize_statement(sqlite3_stmt*& stmt) {
        if (stmt) {
            sqlite3_finalize(stmt);
            stmt = nullptr;
        }
    }
};

AuthDB::AuthDB(const std::filesystem::path& data_dir, int cleanup_interval_secs)
    : impl_(std::make_unique<Impl>()) {
    impl_->cleanup_interval_secs = cleanup_interval_secs;
    impl_->db_path = data_dir / "auth.db";
}

AuthDB::AuthDB(const std::filesystem::path& data_dir) : impl_(std::make_unique<Impl>()) {
    impl_->db_path = data_dir / "auth.db";
}

AuthDB::~AuthDB() = default;

bool AuthDB::is_ready() const noexcept {
    // initialize() closes impl_->db on every failure path: open error,
    // migration failure, integrity_check != "ok". So a non-null handle
    // here is a true positive for "ready to serve queries". No lock —
    // the pointer is set once during initialize() before the server
    // starts accepting traffic, and never reassigned thereafter.
    return impl_ && impl_->db != nullptr;
}

// ── Database Initialization ──────────────────────────────────────────────────

std::expected<void, AuthDBError> AuthDB::initialize() {
    namespace fs = std::filesystem;

    // Ensure parent directory exists
    std::error_code ec;
    fs::create_directories(impl_->db_path.parent_path(), ec);
    if (ec) {
        spdlog::error("Failed to create auth DB directory: {}", ec.message());
        return std::unexpected(AuthDBError::CannotCreateDirectory);
    }

    // Tighten parent-dir permissions to owner-only (governance round
    // sec-H1 / comp-B2). Best-effort — on Windows std::filesystem maps
    // owner_all to a no-op; the production-deploy doc note covers the
    // ACL-equivalent posture there. Errors are logged but non-fatal so
    // deployments on read-only / squashfs / unusual mounts still boot.
    fs::permissions(impl_->db_path.parent_path(), fs::perms::owner_all, fs::perm_options::replace,
                    ec);
    if (ec) {
        spdlog::warn("Failed to chmod 0700 auth DB parent dir: {}", ec.message());
        ec.clear();
    }

    // Open database with full mutex (thread-safe) + WAL mode.
    // db_path.string().c_str() (not db_path.c_str() directly) -- on
    // Windows MSVC, std::filesystem::path::value_type is wchar_t, so
    // path::c_str() returns const wchar_t*, which cannot bind to
    // sqlite3_open_v2's const char* parameter (MSVC C2664). The
    // .string() conversion narrows to const char* via the system
    // locale; matches the pattern used in every other store
    // (response_store, instruction_store, etc.).
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX;
    int rc = sqlite3_open_v2(impl_->db_path.string().c_str(), &impl_->db, flags, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to open auth DB: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::CannotOpenDatabase);
    }

    // Tighten the auth.db file mode to 0600 (owner read+write only).
    // SQLite creates the file using the process umask, which is 0644
    // (world-readable) in default Docker / systemd contexts — leaving
    // PBKDF2 hashes + session tokens readable to any unprivileged
    // co-tenant on the host (governance round sec-H1 HIGH). Apply on
    // every open so a chmod-changed file gets restored.
    // The same call is made for auth.db-wal / auth.db-shm sidecars
    // immediately below; SQLite creates those lazily, so the chmod call
    // may no-op until WAL writes happen — re-running the tightening is
    // harmless.
    fs::permissions(impl_->db_path, fs::perms::owner_read | fs::perms::owner_write,
                    fs::perm_options::replace, ec);
    if (ec) {
        spdlog::warn("Failed to chmod 0600 auth.db: {}", ec.message());
        ec.clear();
    }

    // QA FIX: Run integrity check on startup
    sqlite3_stmt* integrity_stmt = nullptr;
    rc = sqlite3_prepare_v2(impl_->db, "PRAGMA integrity_check", -1, &integrity_stmt, nullptr);
    if (rc == SQLITE_OK) {
        rc = sqlite3_step(integrity_stmt);
        if (rc == SQLITE_ROW) {
            // col_text is null-safe (cpp-SH-1) — sqlite3_column_text on
            // a NULL column would otherwise UB on std::string ctor.
            std::string result = col_text(integrity_stmt, 0);
            if (result != "ok") {
                spdlog::error("Auth DB integrity check failed: {}", result);
                sqlite3_finalize(integrity_stmt);
                sqlite3_close(impl_->db);
                impl_->db = nullptr;
                return std::unexpected(AuthDBError::DatabaseCorrupt);
            }
        }
        sqlite3_finalize(integrity_stmt);
    }

    // Set busy timeout (5 seconds) — handles concurrent access gracefully
    sqlite3_busy_timeout(impl_->db, 5000);

    // Enable WAL mode for better concurrency
    rc = sqlite3_exec(impl_->db, "PRAGMA journal_mode=WAL", nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::warn("Failed to enable WAL mode: {}", sqlite3_errmsg(impl_->db));
        // Non-fatal, continue anyway
    }

    // Create schema (idempotent — safe to call multiple times)
    auto schema_result = create_schema();
    if (!schema_result) {
        return std::unexpected(schema_result.error());
    }

    // Spawn the expired-session reaper (governance round comp-B3). The
    // sessions table grows monotonically without it; under SOC 2 CC6.6
    // an unbounded credential store is a finding. Sweep cadence defaults
    // to 60 s for v1 — every other store uses minutes; sessions need
    // tighter cadence because session expiry windows are typically <1h.
    //
    // Tests that construct + destruct many AuthDB instances back-to-back
    // pass `cleanup_interval_secs <= 0` via the second constructor to
    // skip the spawn entirely. This is PR #1199's permanent answer to a
    // macOS-arm64-only SIGSEGV that surfaced when 100+ jthreads were
    // created and joined in rapid succession across a single test
    // process — confirmed via env-var diagnostic, then promoted to this
    // constructor parameter so the production behaviour stays
    // unchanged.
    const int interval = impl_->cleanup_interval_secs;
    if (interval <= 0) {
        spdlog::info("Auth DB initialized at {} (cleanup thread disabled, interval={})",
                     impl_->db_path.string(), interval);
        return {};
    }
#ifdef __cpp_lib_jthread
    impl_->cleanup_thread = std::jthread([this, interval](std::stop_token stop) {
        while (!stop.stop_requested()) {
            for (int i = 0; i < interval && !stop.stop_requested(); ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            if (stop.stop_requested())
                break;
            auto result = cleanup_expired_sessions();
            if (!result) {
                spdlog::warn("AuthDB: periodic session cleanup failed: error={}",
                             static_cast<int>(result.error()));
            } else if (*result > 0) {
                spdlog::info("AuthDB: reaped {} expired sessions", *result);
            }
            // Same cadence sweep for stale provisional MFA secrets.
            auto mfa_result = cleanup_provisional_mfa();
            if (!mfa_result) {
                spdlog::warn("AuthDB: periodic provisional-MFA cleanup failed: error={}",
                             static_cast<int>(mfa_result.error()));
            }
        }
    });
#else
    impl_->cleanup_thread = std::thread([this, interval]() {
        while (!impl_->stop_cleanup.load()) {
            for (int i = 0; i < interval && !impl_->stop_cleanup.load(); ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            if (impl_->stop_cleanup.load())
                break;
            auto result = cleanup_expired_sessions();
            if (!result) {
                spdlog::warn("AuthDB: periodic session cleanup failed: error={}",
                             static_cast<int>(result.error()));
            } else if (*result > 0) {
                spdlog::info("AuthDB: reaped {} expired sessions", *result);
            }
            // Same cadence sweep for stale provisional MFA secrets.
            auto mfa_result = cleanup_provisional_mfa();
            if (!mfa_result) {
                spdlog::warn("AuthDB: periodic provisional-MFA cleanup failed: error={}",
                             static_cast<int>(mfa_result.error()));
            }
        }
    });
#endif

    spdlog::info("Auth DB initialized at {}", impl_->db_path.string());
    return {};
}

std::expected<void, AuthDBError> AuthDB::create_schema() {
    // Adopt the project-wide MigrationRunner pattern (governance round
    // arch-B2). Every other yuzu store (audit_store, response_store,
    // instruction_store, guaranteed_state_store, ~18 total) registers
    // schema as `std::vector<Migration>{{1, sql}, {2, alter}, ...}` and
    // delegates to MigrationRunner::run. Migrations are recorded in
    // MigrationRunner's `schema_meta` table; the previous AuthDB-local
    // `schema_migrations` table is left in place for forward compat
    // (it was a leftover of the inline-schema design and reading from
    // it elsewhere never landed) but is no longer authoritative.
    //
    // Backwards compatibility: every CREATE here is `IF NOT EXISTS`,
    // so an AuthDB initialised by a pre-MigrationRunner v1 binary
    // (PR-merge through this PR window) re-runs idempotently and
    // MigrationRunner stamps `schema_meta` to v1. Subsequent `ALTER
    // TABLE` migrations would land as `{2, ...}` entries.
    const std::vector<Migration> kMigrations = {
        {1, R"(
            -- Users table
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt_hex TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_login_at DATETIME,
                is_active INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active) WHERE is_active = 1;

            -- Sessions table
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                auth_source TEXT NOT NULL DEFAULT 'password',
                oidc_sub TEXT,
                expires_at DATETIME NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_activity_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
            CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
            CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);

            -- Enrollment tokens table
            CREATE TABLE IF NOT EXISTS enrollment_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                created_by TEXT NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                is_used INTEGER NOT NULL DEFAULT 0,
                used_at DATETIME,
                used_by_agent_id TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_enrollment_token_hash ON enrollment_tokens(token_hash);
            CREATE INDEX IF NOT EXISTS idx_enrollment_expires ON enrollment_tokens(expires_at);

            -- Pending agents table
            CREATE TABLE IF NOT EXISTS pending_agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL UNIQUE,
                hostname TEXT NOT NULL,
                os TEXT,
                arch TEXT,
                agent_version TEXT,
                enrollment_token_id INTEGER,
                requested_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                approved_at DATETIME,
                approved_by TEXT,
                status TEXT NOT NULL DEFAULT 'pending'
            );
            CREATE INDEX IF NOT EXISTS idx_pending_agents_agent_id ON pending_agents(agent_id);
            CREATE INDEX IF NOT EXISTS idx_pending_agents_status ON pending_agents(status);
        )"},
        // v2: MFA / TOTP support. SOC 2 CC6.6 (privileged access) — see
        // docs/auth-mfa-design.md and `/auth-and-authz` skill gap matrix
        // entry P0 #1. Columns are nullable so existing rows survive the
        // migration without backfill; mfa_last_counter has DEFAULT 0 so
        // the NOT NULL constraint holds on rewritten rows.
        //
        // mfa_totp_secret is the raw 20-byte HMAC-SHA1 key (RFC 4226 §4 R6).
        // The v1 at-rest protection is the inherited auth.db mode 0600 +
        // parent dir 0700 — same posture as password_hash. Encryption-at-
        // rest with AES-256-GCM + auth_kv master key is a follow-up; the
        // empty auth_kv scaffolding is provisioned here so the v3 wire-up
        // does not require another migration.
        //
        // Recovery codes use the same PBKDF2-SHA256 hashing as password_hash
        // (auth.cpp::AuthManager::pbkdf2_sha256). Single-use enforced via
        // consumed_at IS NOT NULL.
        {2, R"(
            ALTER TABLE users ADD COLUMN mfa_totp_secret BLOB;
            ALTER TABLE users ADD COLUMN mfa_enrolled_at DATETIME;
            ALTER TABLE users ADD COLUMN mfa_disabled_at DATETIME;
            ALTER TABLE users ADD COLUMN mfa_last_counter INTEGER NOT NULL DEFAULT 0;

            ALTER TABLE sessions ADD COLUMN mfa_verified_at DATETIME;

            CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                code_salt TEXT NOT NULL,
                consumed_at DATETIME,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_mfa_recovery_username ON mfa_recovery_codes(username);
            CREATE INDEX IF NOT EXISTS idx_mfa_recovery_unconsumed
                ON mfa_recovery_codes(username) WHERE consumed_at IS NULL;

            CREATE TABLE IF NOT EXISTS auth_kv (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        )"},
        // v3: Account lockout — brute-force / credential-stuffing protection
        // on the local-password login path. SOC 2 CC6.3 — see the
        // `/auth-and-authz` skill gap matrix entry P0 #2 and
        // docs/auth-architecture.md. Three columns on the existing users
        // table (no separate table): a non-existent username has no row, so
        // an attacker spraying random usernames creates no storage growth.
        // Columns are defaulted/nullable so existing rows survive the
        // migration without backfill. The lockout is temporary/auto-expiring
        // (locked_until is a future timestamp, not a permanent flag) so it
        // cannot be weaponised to permanently DoS a legitimate principal.
        // Policy (threshold + window) lives in ServerConfig, not the schema,
        // so operators retune without a migration. locked_until NULL = not
        // locked.
        {3, R"(
            ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE users ADD COLUMN last_failed_login_at DATETIME;
            ALTER TABLE users ADD COLUMN locked_until DATETIME;
        )"},
        // v4: Break-glass arming for hardened mode (--auth-mode=sso-only).
        // SOC 2 CC6.6 — see the `/auth-and-authz` skill gap matrix entry P0 #3
        // and docs/auth-architecture.md "Hardened mode". One nullable column on
        // the existing users table: the "who" (which account is the break-glass
        // principal) is operator config (Config::break_glass_user), the "when"
        // (armed until) is this column. NULL = dormant; a future timestamp =
        // armed, evaluated lazily at login against CURRENT_TIMESTAMP so the
        // exemption auto-expires and is never a permanent standing bypass.
        // Defaulted nullable so existing rows survive without backfill.
        {4, R"(
            ALTER TABLE users ADD COLUMN break_glass_armed_until DATETIME;
        )"},
    };

    if (!MigrationRunner::run(impl_->db, "auth_db", kMigrations)) {
        spdlog::error("AuthDB: schema migration failed");
        return std::unexpected(AuthDBError::SchemaCreationFailed);
    }

    return {};
}

// ── User Operations ──────────────────────────────────────────────────────────

std::expected<void, AuthDBError> AuthDB::upsert_user(const std::string& username,
                                                     const std::string& password_hash,
                                                     const std::string& salt_hex, auth::Role role) {
    // H1 FIX: Validate username before any DB operations
    if (!is_valid_username(username)) {
        spdlog::warn("upsert_user rejected invalid username: '{}'", username);
        return std::unexpected(AuthDBError::InvalidUsername);
    }

    // C1 FIX: Only allow 'admin' or 'user' roles — no arbitrary strings
    std::string role_str = (role == auth::Role::admin) ? "admin" : "user";

    // Use INSERT ... ON CONFLICT DO NOTHING instead of DO UPDATE.
    // This prevents the TOCTOU race where two concurrent requests could both
    // pass user_exists(), then one overwrites the other's credentials.
    // Instead, if the user already exists, we return an error and the caller
    // should use update_role() for role changes or a dedicated password
    // change method for credential updates.
    const char* sql = R"(
        INSERT INTO users (username, password_hash, salt_hex, role, updated_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(username) DO NOTHING
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare upsert_user statement: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, salt_hex.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, role_str.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        spdlog::error("upsert_user failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }

    // Check if insert succeeded or user already existed
    int changes = sqlite3_changes(impl_->db);
    if (changes == 0) {
        // User already exists — don't silently overwrite credentials.
        // Use update_role() for role changes, or a password change method.
        spdlog::warn("upsert_user: user already exists, not overwriting: '{}'", username);
        return std::unexpected(AuthDBError::UserAlreadyExists);
    }

    spdlog::info("User upserted: {} (role={})", username, role_str);
    return {};
}

std::expected<auth::UserEntry, AuthDBError> AuthDB::get_user(const std::string& username) {
    static const char* sql = R"(
        SELECT username, role, password_hash, salt_hex
        FROM users
        WHERE username = ? AND is_active = 1
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare get_user statement: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return std::unexpected(AuthDBError::UserNotFound);
    }

    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        spdlog::error("get_user query failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::QueryFailed);
    }

    auth::UserEntry entry;
    // col_text is null-safe (cpp-SH-1) — every nullable column on the
    // users table goes through it. Schema declares NOT NULL on these
    // columns, so the safety net is defense-in-depth against schema
    // drift / missed migration.
    entry.username = col_text(stmt, 0);
    entry.role = auth::string_to_role(col_text(stmt, 1));
    entry.hash_hex = col_text(stmt, 2);
    entry.salt_hex = col_text(stmt, 3);
    // Note: is_active and last_login_at exist in DB but not in UserEntry struct.
    // DB query filters is_active=1, so all returned users are active.

    sqlite3_finalize(stmt);
    return entry;
}

std::expected<std::vector<auth::UserEntry>, AuthDBError> AuthDB::list_users() {
    static const char* sql = R"(
        SELECT username, role
        FROM users
        WHERE is_active = 1
        ORDER BY username
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare list_users statement: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }

    std::vector<auth::UserEntry> users;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        auth::UserEntry entry;
        entry.username = col_text(stmt, 0);
        entry.role = auth::string_to_role(col_text(stmt, 1));
        users.push_back(std::move(entry));
    }

    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        spdlog::error("list_users query failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::QueryFailed);
    }

    return users;
}

std::expected<bool, AuthDBError> AuthDB::remove_user(const std::string& username) {
    // SOC 2 CC6.8 — credential revocation on termination. The soft-delete
    // also wipes MFA enrollment material: clears users.mfa_totp_secret
    // (the live HMAC key), the enrolled-at marker, and DELETEs every
    // recovery_codes row owned by the user. Otherwise a re-activation
    // workflow (planned for a future PR) would silently restore both
    // factors of a terminated principal. UPDATE+UPDATE+DELETE under one
    // BEGIN IMMEDIATE so a kill mid-call cannot leave is_active=0 with
    // a live secret. RETURNING 1 carries the matched-row signal so we
    // can dodge the #1033 sqlite3_changes() race the previous shape
    // exposed (Gate 3 compliance BLOCKING).
    TxnGuard txn(impl_->db);
    if (!txn.active()) {
        return std::unexpected(AuthDBError::WriteFailed);
    }

    static const char* sql = R"(
        UPDATE users SET
            is_active = 0,
            mfa_totp_secret = NULL,
            mfa_enrolled_at = NULL,
            mfa_disabled_at = CURRENT_TIMESTAMP,
            mfa_last_counter = 0,
            updated_at = CURRENT_TIMESTAMP
        WHERE username = ?
        RETURNING 1
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare remove_user statement: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        spdlog::error("remove_user failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }

    bool removed = (rc == SQLITE_ROW);
    if (removed) {
        // Drop recovery codes for the soft-deleted user. DELETE returns
        // SQLITE_DONE whether 0 or N rows matched — we don't gate on
        // count, only on prepare/step success.
        static const char* del_sql = "DELETE FROM mfa_recovery_codes WHERE username = ?";
        sqlite3_stmt* del = nullptr;
        if (sqlite3_prepare_v2(impl_->db, del_sql, -1, &del, nullptr) != SQLITE_OK) {
            return std::unexpected(AuthDBError::StatementPrepareFailed);
        }
        sqlite3_bind_text(del, 1, username.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(del) != SQLITE_DONE) {
            sqlite3_finalize(del);
            return std::unexpected(AuthDBError::WriteFailed);
        }
        sqlite3_finalize(del);

        if (!txn.commit()) {
            return std::unexpected(AuthDBError::WriteFailed);
        }
        spdlog::info("User removed (MFA state cleared): {}", username);
        // Also invalidate all sessions for this user. Per cpp-SH-5, the
        // return must be checked: a swallowed failure here means a
        // demoted-or-deleted user could still authenticate via a
        // session row that AuthDB believed it had wiped. Failure is
        // logged but does not propagate — the user-row write already
        // committed and the in-memory sessions_ map is the v1
        // authoritative read path (see header).
        if (auto inv = invalidate_all_sessions(username); !inv) {
            spdlog::error("remove_user: invalidate_all_sessions for '{}' failed: error={}",
                          username, static_cast<int>(inv.error()));
        }
    } else {
        spdlog::warn("User not found for removal: {}", username);
    }

    return removed;
}

void AuthDB::touch_last_login(const std::string& username) {
    if (!is_valid_username(username)) {
        return;
    }
    static const char* sql = R"(
        UPDATE users SET last_login_at = CURRENT_TIMESTAMP
        WHERE username = ? AND is_active = 1
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::warn("touch_last_login prepare failed for '{}': {}", username,
                     sqlite3_errmsg(impl_->db));
        return;
    }
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        spdlog::warn("touch_last_login failed for '{}': {}", username, sqlite3_errmsg(impl_->db));
    }
    sqlite3_finalize(stmt);
}

std::expected<bool, AuthDBError> AuthDB::user_exists(const std::string& username) {
    static const char* sql = R"(
        SELECT COUNT(*) FROM users WHERE username = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare user_exists statement: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    bool exists = false;
    if (rc == SQLITE_ROW) {
        exists = sqlite3_column_int(stmt, 0) > 0;
    }

    sqlite3_finalize(stmt);
    return exists;
}

// ── Session Operations ───────────────────────────────────────────────────────

std::expected<std::string, AuthDBError> AuthDB::create_session(const std::string& username,
                                                               auth::Role role,
                                                               const std::string& auth_source,
                                                               const std::string& oidc_sub) {
    // Generate secure random session token
    auto token_bytes = auth::AuthManager::random_bytes(32);
    std::string session_token = auth::AuthManager::bytes_to_hex(token_bytes);

    // Calculate expiry (24 hours from now)
    auto now = std::chrono::system_clock::now();
    auto expires = now + std::chrono::hours(24);

    // Format thread-safely via std::format chrono (xp-S1). The previous
    // std::strftime + std::gmtime path raced on a process-wide static
    // buffer under glibc and emitted corrupt timestamps under concurrent
    // create_session calls.
    std::string expires_str = format_sqlite_utc(expires);

    const char* sql = R"(
        INSERT INTO sessions (session_token, username, role, auth_source, oidc_sub, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare create_session statement: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }

    sqlite3_bind_text(stmt, 1, session_token.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, auth::role_to_string(role).c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, auth_source.c_str(), -1, SQLITE_STATIC);
    if (!oidc_sub.empty()) {
        sqlite3_bind_text(stmt, 5, oidc_sub.c_str(), -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 5);
    }
    sqlite3_bind_text(stmt, 6, expires_str.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        spdlog::error("create_session failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }

    spdlog::info("Session created for user: {} (expires={})", username, expires_str);
    return session_token;
}

std::expected<auth::Session, AuthDBError> AuthDB::validate_session(const std::string& token) {
    static const char* sql = R"(
        SELECT username, role, auth_source, oidc_sub, expires_at
        FROM sessions
        WHERE session_token = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare validate_session statement: {}",
                      sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }

    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return std::unexpected(AuthDBError::SessionNotFound);
    }

    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        spdlog::error("validate_session query failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::QueryFailed);
    }

    auth::Session session;
    session.username = col_text(stmt, 0);
    session.role = auth::string_to_role(col_text(stmt, 1));
    session.auth_source = col_text(stmt, 2);
    // sessions.oidc_sub is genuinely nullable; col_text returns "" on
    // NULL which is the same shape as the previous explicit check.
    session.oidc_sub = col_text(stmt, 3);

    // Note: Expiry check is done by caller (AuthManager) — this is intentional
    // to allow session cleanup without modifying this function's signature.

    sqlite3_finalize(stmt);
    return session;
}

std::expected<void, AuthDBError> AuthDB::invalidate_session(const std::string& token) {
    static const char* sql = R"(
        DELETE FROM sessions WHERE session_token = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare invalidate_session statement: {}",
                      sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }

    sqlite3_bind_text(stmt, 1, token.c_str(), -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        spdlog::error("invalidate_session failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }

    return {};
}

std::expected<void, AuthDBError> AuthDB::invalidate_all_sessions(const std::string& username) {
    // Defence-in-depth (authdb-H2): every public AuthDB write taking a
    // username must validate. `sqlite3_bind_text(..., -1, SQLITE_STATIC)`
    // truncates at the first NUL byte, so a NUL-embedded username would
    // delete the wrong rows while the in-memory `==` comparison in
    // AuthManager would match no one — the layers would silently
    // diverge. Sibling primitives `add_user` and `update_role` validate
    // here for the same reason.
    if (!is_valid_username(username)) {
        spdlog::warn("invalidate_all_sessions: invalid username");
        return std::unexpected(AuthDBError::InvalidUsername);
    }

    static const char* sql = R"(
        DELETE FROM sessions WHERE username = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare invalidate_all_sessions statement: {}",
                      sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        spdlog::error("invalidate_all_sessions failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }

    spdlog::info("All sessions invalidated for user: {}", username);
    return {};
}

std::expected<int, AuthDBError>
AuthDB::cleanup_provisional_mfa(std::chrono::seconds older_than) {
    // NULL the secret blob on any users row that is still provisional
    // (mfa_enrolled_at IS NULL — never completed the verify step) and
    // whose last touch is older than the cutoff. RETURNING 1 carries
    // the count of cleared rows so we sidestep the #1033
    // sqlite3_changes() race even though this runs single-threadedly
    // from the cleanup jthread.
    auto secs = older_than.count();
    // Cap the lower bound — a zero/negative cutoff would clear every
    // provisional row including ones the operator is actively
    // scanning, defeating the enrollment UX.
    if (secs < 60)
        secs = 60;
    auto cutoff = std::string("-") + std::to_string(secs) + " seconds";

    static const char* sql = R"(
        UPDATE users
        SET mfa_totp_secret = NULL,
            mfa_last_counter = 0,
            updated_at = CURRENT_TIMESTAMP
        WHERE mfa_enrolled_at IS NULL
          AND mfa_totp_secret IS NOT NULL
          AND updated_at < datetime('now', ?)
        RETURNING 1
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("cleanup_provisional_mfa prepare failed: {}",
                      sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    sqlite3_bind_text(stmt, 1, cutoff.c_str(), -1, SQLITE_TRANSIENT);

    int cleared = 0;
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        ++cleared;
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        spdlog::error("cleanup_provisional_mfa failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }
    if (cleared > 0) {
        spdlog::info("AuthDB: reaped {} stale provisional MFA enrollments", cleared);
    }
    return cleared;
}

std::expected<int, AuthDBError> AuthDB::cleanup_expired_sessions() {
    static const char* sql = R"(
        DELETE FROM sessions WHERE expires_at < datetime('now')
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare cleanup_expired_sessions statement: {}",
                      sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        spdlog::error("cleanup_expired_sessions failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }

    int deleted = sqlite3_changes(impl_->db);
    if (deleted > 0) {
        spdlog::info("Cleaned up {} expired sessions", deleted);
    }

    return deleted;
}

// ── Account-lockout Operations ────────────────────────────────────────────────
//
// SOC 2 CC6.3 — brute-force / credential-stuffing protection on the
// local-password login path. See `/auth-and-authz` skill gap matrix entry
// P0 #2 and docs/auth-architecture.md. State lives in three columns on the
// users table (migration v3). Policy (threshold + window) is owned by the
// caller (ServerConfig) and passed in, so AuthDB stays policy-free and an
// operator can retune without a schema change. A non-existent username has
// no row, so spraying random usernames cannot grow storage and cannot lock
// an account that does not exist (anti-enumeration).

std::expected<AuthDB::LockoutStatus, AuthDBError>
AuthDB::lockout_status(const std::string& username) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    // is_locked is computed in SQL against CURRENT_TIMESTAMP so the
    // "still locked?" decision uses the DB clock, not a parsed string.
    static const char* sql = R"(
        SELECT failed_login_count,
               COALESCE(locked_until, ''),
               (locked_until IS NOT NULL AND locked_until > CURRENT_TIMESTAMP)
        FROM users
        WHERE username = ? AND is_active = 1
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("Failed to prepare lockout_status statement: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

    LockoutStatus out;
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        out.failed_count = sqlite3_column_int(stmt, 0);
        out.locked_until = col_text(stmt, 1);
        out.locked = sqlite3_column_int(stmt, 2) != 0;
    } else if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        spdlog::error("lockout_status query failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::QueryFailed);
    }
    // rc == SQLITE_DONE → no active row for this username → return the
    // zero-initialised (not-locked) status. The caller treats "no such
    // user" identically to "not locked" so the bad-username and
    // bad-password paths stay indistinguishable on the wire.
    sqlite3_finalize(stmt);
    return out;
}

std::expected<AuthDB::LockoutRecord, AuthDBError>
AuthDB::record_failed_login(const std::string& username, int threshold, int window_secs) {
    LockoutRecord out;
    // Feature disabled — record nothing, report a clean not-locked state.
    // The threshold check DELIBERATELY precedes is_valid_username: when
    // lockout is off this is a pure no-op regardless of input, and the sole
    // caller already gates on `cfg_.auth_lockout_threshold > 0`, so the
    // ordering is unreachable in practice. Do not "fix" it to validate first.
    if (threshold <= 0) {
        return out;
    }
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    if (window_secs < 1) {
        window_secs = 1; // a 0/negative window would unlock instantly
    }
    // Bound modifier string for datetime('now', ?) — same idiom as
    // cleanup_provisional_mfa. Value form is "+900 seconds".
    std::string window = std::string("+") + std::to_string(window_secs) + " seconds";

    // Single atomic statement (no read-then-write race; RETURNING carries
    // the post-update state so there is no sqlite3_changes() race either —
    // #1033). Two cases:
    //
    //   * A prior lock has FULLY EXPIRED (locked_until <= now): this failure
    //     starts a fresh cycle. The counter resets to 1 and the stale lock
    //     clears, so a legitimate user who waited out the window gets their
    //     full attempt budget back (and a genuine re-lock later is audited
    //     as a clean threshold crossing rather than a silent bump).
    //
    //   * Otherwise (never locked, or an active in-window lock): increment.
    //     The lock arms the moment the *new* counter reaches the threshold;
    //     an already-armed in-window lock is preserved (ELSE keeps the
    //     existing locked_until) so a late failure cannot shorten it.
    //
    // SQLite can't reference a just-assigned column in a sibling SET clause,
    // so the expiry test is repeated in both clauses rather than factored.
    static const char* sql = R"(
        UPDATE users
        SET failed_login_count = CASE
                WHEN locked_until IS NOT NULL AND locked_until <= CURRENT_TIMESTAMP THEN 1
                ELSE failed_login_count + 1
            END,
            last_failed_login_at = CURRENT_TIMESTAMP,
            locked_until = CASE
                WHEN locked_until IS NOT NULL AND locked_until <= CURRENT_TIMESTAMP
                    THEN CASE WHEN 1 >= ?1 THEN datetime('now', ?2) ELSE NULL END
                ELSE CASE WHEN failed_login_count + 1 >= ?1 THEN datetime('now', ?2)
                          ELSE locked_until END
            END
        WHERE username = ?3 AND is_active = 1
        RETURNING failed_login_count,
                  COALESCE(locked_until, ''),
                  (locked_until IS NOT NULL AND locked_until > CURRENT_TIMESTAMP)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("Failed to prepare record_failed_login statement: {}",
                      sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    sqlite3_bind_int(stmt, 1, threshold);
    sqlite3_bind_text(stmt, 2, window.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, username.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        out.failed_count = sqlite3_column_int(stmt, 0);
        out.locked_until = col_text(stmt, 1);
        out.locked = sqlite3_column_int(stmt, 2) != 0;
        // The threshold-crossing edge fires exactly once per lock cycle:
        // the counter equals `threshold` only on the failure that armed it
        // (subsequent failures push it past). Lets the caller emit a single
        // audit row instead of one per blocked attempt.
        out.just_locked = out.locked && (out.failed_count == threshold);
        sqlite3_finalize(stmt);
        return out;
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        spdlog::error("record_failed_login failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }
    // SQLITE_DONE with no row → no such active user → clean not-locked state
    // (we deliberately never create a row for a non-existent account).
    return out;
}

std::expected<void, AuthDBError> AuthDB::clear_failed_logins(const std::string& username) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    // Reset on a successful login or an admin unlock. Idempotent; matches
    // 0 rows for an absent user without error. The `is_active = 1` filter
    // matches lockout_status / record_failed_login (governance UP-12): a
    // soft-deleted principal carries no live lockout state worth clearing,
    // so this never touches an inactive row.
    static const char* sql = R"(
        UPDATE users
        SET failed_login_count = 0,
            last_failed_login_at = NULL,
            locked_until = NULL
        WHERE username = ? AND is_active = 1
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("Failed to prepare clear_failed_logins statement: {}",
                      sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        spdlog::error("clear_failed_logins failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }
    return {};
}

// ── Break-glass arming (hardened mode) ───────────────────────────────────────

std::expected<AuthDB::BreakGlassStatus, AuthDBError>
AuthDB::break_glass_status(const std::string& username) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    // armed is computed in SQL against CURRENT_TIMESTAMP so the "still armed?"
    // decision uses the DB clock, not a parsed string — mirrors lockout_status.
    static const char* sql = R"(
        SELECT COALESCE(break_glass_armed_until, ''),
               (break_glass_armed_until IS NOT NULL
                AND break_glass_armed_until > CURRENT_TIMESTAMP)
        FROM users
        WHERE username = ? AND is_active = 1
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("Failed to prepare break_glass_status statement: {}",
                      sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

    BreakGlassStatus out;
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        out.armed_until = col_text(stmt, 0);
        out.armed = sqlite3_column_int(stmt, 1) != 0;
    } else if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        spdlog::error("break_glass_status query failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::QueryFailed);
    }
    // rc == SQLITE_DONE → no active row → zero-initialised (not-armed) status.
    sqlite3_finalize(stmt);
    return out;
}

std::expected<AuthDB::BreakGlassStatus, AuthDBError>
AuthDB::arm_break_glass(const std::string& username, int window_secs) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    if (window_secs < 1) {
        window_secs = 1; // a 0/negative window would expire instantly
    }
    // Bound modifier string for datetime('now', ?) — same idiom as
    // record_failed_login. Value form is "+86400 seconds".
    std::string window = std::string("+") + std::to_string(window_secs) + " seconds";

    // Single UPDATE ... RETURNING (no sqlite3_changes() race — #1033). The
    // RETURNING row both confirms a row matched (UserNotFound otherwise, so the
    // host operator isn't told an arm "succeeded" against a typo'd username) and
    // carries the post-update armed state for the audit detail.
    static const char* sql = R"(
        UPDATE users
        SET break_glass_armed_until = datetime('now', ?1)
        WHERE username = ?2 AND is_active = 1
        RETURNING COALESCE(break_glass_armed_until, ''),
                  (break_glass_armed_until IS NOT NULL
                   AND break_glass_armed_until > CURRENT_TIMESTAMP)
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("Failed to prepare arm_break_glass statement: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    sqlite3_bind_text(stmt, 1, window.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);

    BreakGlassStatus out;
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        out.armed_until = col_text(stmt, 0);
        out.armed = sqlite3_column_int(stmt, 1) != 0;
        sqlite3_finalize(stmt);
        return out;
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        spdlog::error("arm_break_glass failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }
    // SQLITE_DONE with no row → no such active user → tell the caller, don't
    // silently report a successful arm.
    return std::unexpected(AuthDBError::UserNotFound);
}

std::expected<void, AuthDBError> AuthDB::disarm_break_glass(const std::string& username) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    // Compensating un-arm: clear the armed window. Idempotent (a no-match or
    // already-NULL row is success — the desired post-state is "not armed").
    // No sqlite3_changes() (#1033) — match-vs-not is irrelevant.
    static const char* sql = R"(
        UPDATE users SET break_glass_armed_until = NULL WHERE username = ?
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("Failed to prepare disarm_break_glass statement: {}",
                      sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        spdlog::error("disarm_break_glass failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }
    return {};
}

std::optional<std::string> break_glass_account_problem(AuthDB& db, const std::string& username) {
    if (!is_valid_username(username)) {
        return "not a valid username";
    }
    auto exists = db.user_exists(username);
    if (!exists) {
        return "auth store error while checking the account";
    }
    if (!*exists) {
        return "account does not exist";
    }
    // mfa_status filters is_active=1, so a soft-deleted (inactive) user reads as
    // not-enrolled here and is rejected fail-closed (governance UP-10). The
    // message names both causes because `user_exists` does not filter is_active,
    // so an inactive account passes the existence check above and surfaces here
    // rather than as "does not exist" (Hermes LOW — operator clarity during
    // recovery; the fail-closed behaviour itself is correct either way).
    auto mfa = db.mfa_status(username);
    if (!mfa) {
        return "auth store error while checking MFA enrollment";
    }
    if (!mfa->enrolled) {
        return "account has no MFA enrolled, or the account is deactivated (a break-glass account "
               "must be active and carry a second factor)";
    }
    return std::nullopt;
}

// ── MFA / TOTP Operations ────────────────────────────────────────────────────
//
// See docs/auth-mfa-design.md for the full design. v1 surface:
//   mfa_status / mfa_init_enrollment / mfa_verify_enrollment /
//   mfa_verify_login_code / mfa_consume_recovery_code /
//   mfa_regenerate_recovery_codes / mfa_disable / mfa_mark_session_stepup.

namespace {

constexpr int kRecoveryCodeCount = 10;
constexpr int kRecoveryCodePbkdfIters = 100'000;

// Txn-free core of recovery-code regeneration: DELETE the user's existing
// codes and INSERT `kRecoveryCodeCount` fresh ones. The CALLER MUST hold an
// open TxnGuard — this function neither begins nor commits, so it can be
// composed atomically with another mutation (e.g. the enrollment-verify
// stamp; governance UP-12). Returns the raw codes for one-time display, or
// an error with the transaction left for the caller to roll back.
[[nodiscard]] std::expected<std::vector<std::string>, AuthDBError>
regenerate_recovery_codes_locked(sqlite3* db, const std::string& username) {
    static const char* del_sql = "DELETE FROM mfa_recovery_codes WHERE username = ?";
    sqlite3_stmt* del = nullptr;
    if (sqlite3_prepare_v2(db, del_sql, -1, &del, nullptr) != SQLITE_OK) {
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    sqlite3_bind_text(del, 1, username.c_str(), -1, SQLITE_STATIC);
    if (sqlite3_step(del) != SQLITE_DONE) {
        sqlite3_finalize(del);
        return std::unexpected(AuthDBError::WriteFailed);
    }
    sqlite3_finalize(del);

    static const char* ins_sql = R"(
        INSERT INTO mfa_recovery_codes (username, code_hash, code_salt)
        VALUES (?, ?, ?)
    )";
    std::vector<std::string> raw_codes;
    raw_codes.reserve(kRecoveryCodeCount);
    for (int i = 0; i < kRecoveryCodeCount; ++i) {
        auto code = mfa::random_recovery_code();
        // Normalise for hashing (strip '-', uppercase) — same shape the
        // consumer will pass into mfa_consume_recovery_code.
        std::string norm;
        norm.reserve(code.size());
        for (char c : code) {
            if (c == '-' || c == ' ')
                continue;
            norm += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        auto salt = auth::AuthManager::random_bytes(16);
        auto salt_hex = auth::AuthManager::bytes_to_hex(salt);
        auto hash = auth::AuthManager::pbkdf2_sha256(norm, salt, kRecoveryCodePbkdfIters);

        sqlite3_stmt* ins = nullptr;
        if (sqlite3_prepare_v2(db, ins_sql, -1, &ins, nullptr) != SQLITE_OK) {
            return std::unexpected(AuthDBError::StatementPrepareFailed);
        }
        sqlite3_bind_text(ins, 1, username.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(ins, 2, hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(ins, 3, salt_hex.c_str(), -1, SQLITE_TRANSIENT);
        auto rc = sqlite3_step(ins);
        sqlite3_finalize(ins);
        if (rc != SQLITE_DONE) {
            return std::unexpected(AuthDBError::WriteFailed);
        }
        raw_codes.push_back(std::move(code));
    }
    return raw_codes;
}

// Read the TOTP secret blob + enrolled-at + last-counter for a user.
// Returns empty optional if the user is not provisional and not enrolled
// (i.e. no secret blob). Caller wraps in higher-level error handling.
struct LoadedMfaRow {
    std::vector<uint8_t> secret;
    bool enrolled{false};
    int64_t last_counter{0};
};

std::optional<LoadedMfaRow> load_mfa_row(sqlite3* db, const std::string& username) {
    static const char* sql = R"(
        SELECT mfa_totp_secret, mfa_enrolled_at, mfa_last_counter
        FROM users
        WHERE username = ? AND is_active = 1
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        // SQLite may have partially allocated `stmt` even on prepare
        // failure; finalize unconditionally. `sqlite3_finalize(nullptr)`
        // is a documented no-op so this is safe in the non-allocated
        // case too.
        sqlite3_finalize(stmt);
        return std::nullopt;
    }
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    auto rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return std::nullopt;
    }
    LoadedMfaRow out;
    int blob_type = sqlite3_column_type(stmt, 0);
    if (blob_type == SQLITE_BLOB) {
        const void* p = sqlite3_column_blob(stmt, 0);
        int n = sqlite3_column_bytes(stmt, 0);
        if (p && n > 0) {
            out.secret.assign(static_cast<const uint8_t*>(p),
                              static_cast<const uint8_t*>(p) + n);
        }
    }
    out.enrolled = sqlite3_column_type(stmt, 1) != SQLITE_NULL;
    out.last_counter = sqlite3_column_int64(stmt, 2);
    sqlite3_finalize(stmt);
    if (out.secret.empty()) {
        return std::nullopt;
    }
    return out;
}

} // namespace

std::expected<AuthDB::MfaStatus, AuthDBError>
AuthDB::mfa_status(const std::string& username) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }

    static const char* sql = R"(
        SELECT mfa_enrolled_at, mfa_disabled_at
        FROM users
        WHERE username = ? AND is_active = 1
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("mfa_status prepare failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    auto rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return std::unexpected(AuthDBError::UserNotFound);
    }
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return std::unexpected(AuthDBError::QueryFailed);
    }
    MfaStatus status;
    if (sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
        status.enrolled = true;
        status.enrolled_at = col_text(stmt, 0);
    }
    if (sqlite3_column_type(stmt, 1) != SQLITE_NULL) {
        status.disabled_at = col_text(stmt, 1);
    }
    sqlite3_finalize(stmt);

    // Count unconsumed recovery codes.
    static const char* count_sql = R"(
        SELECT COUNT(*) FROM mfa_recovery_codes
        WHERE username = ? AND consumed_at IS NULL
    )";
    sqlite3_stmt* cstmt = nullptr;
    if (sqlite3_prepare_v2(impl_->db, count_sql, -1, &cstmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(cstmt, 1, username.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(cstmt) == SQLITE_ROW) {
            status.recovery_codes_remaining = sqlite3_column_int(cstmt, 0);
        }
        sqlite3_finalize(cstmt);
    }
    return status;
}

std::expected<AuthDB::MfaEnrollmentInit, AuthDBError>
AuthDB::mfa_init_enrollment(const std::string& username, std::string_view issuer) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }

    // Reject if the user is already enrolled (caller must mfa_disable first).
    auto status = mfa_status(username);
    if (!status)
        return std::unexpected(status.error());
    if (status->enrolled) {
        spdlog::warn("mfa_init_enrollment: already enrolled: {}", username);
        return std::unexpected(AuthDBError::MfaAlreadyEnrolled);
    }

    // Reuse, don't rotate (#1227). If a PROVISIONAL secret already exists
    // (not yet enrolled — we just checked — but a secret blob is present),
    // return its base32 + otpauth URI instead of minting a fresh one.
    // Re-initialising during the enrollment window — two browser tabs, a
    // retried `/login` bootstrap, a re-opened Settings panel — must not
    // invalidate the QR the operator already scanned. The provisional
    // secret is reaped by cleanup_provisional_mfa if abandoned, which
    // bounds the re-reveal window. (Once ENROLLED, init is rejected above,
    // so the confirmed secret is never re-revealed — invariant #1 holds for
    // enrolled secrets; provisional secrets are re-revealable to the
    // already-authenticated caller within the enrollment window.)
    if (auto existing = load_mfa_row(impl_->db, username);
        existing && !existing->secret.empty()) {
        // TOCTOU guard: load_mfa_row reads mfa_totp_secret AND mfa_enrolled_at
        // in one SELECT, so existing->enrolled is a consistent snapshot of the
        // row at this read. The mfa_status() enrolled-check above is a SEPARATE
        // statement; on a FULLMUTEX shared connection a concurrent
        // mfa_verify_enrollment can stamp enrolled between the two. Re-checking
        // the freshly-loaded row closes that window: if the secret is now
        // CONFIRMED we must never re-reveal it (invariant #1) — reject as
        // already-enrolled, exactly as the top check would have. Re-reveal is
        // limited to genuinely-provisional secrets within the enrollment window.
        if (existing->enrolled) {
            spdlog::warn("mfa_init_enrollment: enrolled between status-check and reuse-load "
                         "(concurrent verify) — refusing to re-reveal: {}",
                         username);
            return std::unexpected(AuthDBError::MfaAlreadyEnrolled);
        }
        auto secret_view = std::string_view(
            reinterpret_cast<const char*>(existing->secret.data()), existing->secret.size());
        auto secret_b32 = mfa::base32_encode(secret_view);
        auto uri = mfa::otpauth_uri(issuer, username, secret_b32);
        return MfaEnrollmentInit{std::move(secret_b32), std::move(uri)};
    }

    // Generate fresh secret + write as provisional (mfa_enrolled_at stays NULL).
    auto secret_bytes = mfa::random_secret();
    auto secret_view = std::string_view(reinterpret_cast<const char*>(secret_bytes.data()),
                                        secret_bytes.size());
    auto secret_b32 = mfa::base32_encode(secret_view);
    auto uri = mfa::otpauth_uri(issuer, username, secret_b32);

    // RETURNING 1 carries the "row matched" signal in the step return,
    // dodging the #1033 sqlite3_changes() data race on a FULLMUTEX
    // shared connection. SQLITE_ROW == found and updated; SQLITE_DONE
    // == no row matched (user not found / not active).
    static const char* sql = R"(
        UPDATE users
        SET mfa_totp_secret = ?,
            mfa_last_counter = 0,
            mfa_disabled_at = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE username = ? AND is_active = 1
        RETURNING 1
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("mfa_init_enrollment prepare failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    sqlite3_bind_blob(stmt, 1, secret_bytes.data(), static_cast<int>(secret_bytes.size()),
                      SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);
    auto rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc == SQLITE_DONE) {
        return std::unexpected(AuthDBError::UserNotFound);
    }
    if (rc != SQLITE_ROW) {
        spdlog::error("mfa_init_enrollment write failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }
    return MfaEnrollmentInit{std::move(secret_b32), std::move(uri)};
}

std::expected<std::vector<std::string>, AuthDBError>
AuthDB::mfa_verify_enrollment(const std::string& username, std::string_view code) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }

    auto status = mfa_status(username);
    if (!status)
        return std::unexpected(status.error());
    if (status->enrolled) {
        return std::unexpected(AuthDBError::MfaAlreadyEnrolled);
    }

    auto row = load_mfa_row(impl_->db, username);
    if (!row) {
        // No provisional secret — caller must call mfa_init_enrollment first.
        return std::unexpected(AuthDBError::UserNotFound);
    }

    auto secret_view =
        std::string_view(reinterpret_cast<const char*>(row->secret.data()), row->secret.size());
    auto current = mfa::current_counter(std::chrono::system_clock::now());
    auto matched = mfa::verify_window(secret_view, code, current, -1);
    if (!matched) {
        return std::unexpected(AuthDBError::InvalidCredentials);
    }

    // Stamp enrolled_at + generate recovery codes ATOMICALLY (governance
    // UP-12). Two failure modes the prior two-statement form left open:
    //   (a) the stamp UPDATE matched zero rows (user deactivated/deleted
    //       between load_mfa_row and here) but `SQLITE_DONE` reads as
    //       success → the user is "enrolled" with no enrolled_at and a
    //       session is minted. `RETURNING 1` makes `SQLITE_ROW` the proof
    //       that a row was actually written.
    //   (b) the stamp committed but recovery-code generation then failed
    //       → user enrolled with ZERO recovery codes, and a retry hits
    //       MfaAlreadyEnrolled → permanent lockout. Running both under one
    //       TxnGuard means a code-gen failure rolls the stamp back too, so
    //       the user stays provisional and can simply retry.
    TxnGuard txn(impl_->db);
    if (!txn.active()) {
        return std::unexpected(AuthDBError::WriteFailed);
    }

    static const char* sql = R"(
        UPDATE users
        SET mfa_enrolled_at = CURRENT_TIMESTAMP,
            mfa_last_counter = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE username = ? AND is_active = 1
        RETURNING 1
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    sqlite3_bind_int64(stmt, 1, *matched);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);
    auto rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_ROW) {
        // No row written (user deactivated/deleted mid-request) or a write
        // error — fail closed; TxnGuard rolls back.
        return std::unexpected(AuthDBError::WriteFailed);
    }

    auto raw_codes = regenerate_recovery_codes_locked(impl_->db, username);
    if (!raw_codes) {
        return std::unexpected(raw_codes.error()); // TxnGuard rolls back the stamp too
    }
    if (!txn.commit()) {
        return std::unexpected(AuthDBError::WriteFailed);
    }
    return raw_codes;
}

std::expected<bool, AuthDBError>
AuthDB::mfa_verify_login_code(const std::string& username, std::string_view code) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }

    auto row = load_mfa_row(impl_->db, username);
    if (!row || !row->enrolled) {
        return false;
    }
    auto secret_view =
        std::string_view(reinterpret_cast<const char*>(row->secret.data()), row->secret.size());
    auto current = mfa::current_counter(std::chrono::system_clock::now());
    auto matched = mfa::verify_window(secret_view, code, current, row->last_counter);
    if (!matched) {
        return false;
    }

    // Persist the matched counter as the new floor for replay protection.
    static const char* sql = R"(
        UPDATE users
        SET mfa_last_counter = ?, last_login_at = CURRENT_TIMESTAMP
        WHERE username = ? AND is_active = 1
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    sqlite3_bind_int64(stmt, 1, *matched);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);
    auto rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        return std::unexpected(AuthDBError::WriteFailed);
    }
    return true;
}

std::expected<bool, AuthDBError>
AuthDB::mfa_consume_recovery_code(const std::string& username, std::string_view raw_code) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }
    if (raw_code.empty()) {
        return false;
    }

    // Walk every unconsumed code for the user; PBKDF2-hash the presented
    // code under each row's salt and constant-time compare. We scan rather
    // than do an indexed lookup because the hash is salted per-row (so the
    // attacker getting the DB still has to grind one row at a time) — N is
    // bounded to kRecoveryCodeCount per user, so the cost is trivial.
    struct Candidate {
        sqlite3_int64 id;
        std::string code_hash;
        std::string code_salt;
    };
    std::vector<Candidate> candidates;

    static const char* select_sql = R"(
        SELECT id, code_hash, code_salt
        FROM mfa_recovery_codes
        WHERE username = ? AND consumed_at IS NULL
    )";
    sqlite3_stmt* sel = nullptr;
    if (sqlite3_prepare_v2(impl_->db, select_sql, -1, &sel, nullptr) != SQLITE_OK) {
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    sqlite3_bind_text(sel, 1, username.c_str(), -1, SQLITE_STATIC);
    while (sqlite3_step(sel) == SQLITE_ROW) {
        candidates.push_back({sqlite3_column_int64(sel, 0), col_text(sel, 1), col_text(sel, 2)});
    }
    sqlite3_finalize(sel);

    // Normalise: recovery codes are displayed with a '-' separator for
    // readability; accept with or without it. Case-insensitive base32.
    std::string normalised;
    normalised.reserve(raw_code.size());
    for (char c : raw_code) {
        if (c == '-' || c == ' ')
            continue;
        normalised += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }

    // Walk every candidate unconditionally — no early break on match.
    // The previous early-break leaked the position-in-list via wall-clock
    // (N×PBKDF2 for a wrong code vs K×PBKDF2 for a code matching at slot
    // K). Iterate the full set and merge `matched_id` via a constant-time
    // selector so the wall time is bounded by `candidates.size()`
    // regardless of which row matched (Gate 2 M6). N is bounded by
    // kRecoveryCodeCount = 10 so the worst-case extra cost is ~10 PBKDF2
    // ops per consume — acceptable for a per-login operation.
    sqlite3_int64 matched_id = -1;
    for (const auto& cand : candidates) {
        auto salt_bytes = auth::AuthManager::hex_to_bytes(cand.code_salt);
        auto presented_hash =
            auth::AuthManager::pbkdf2_sha256(normalised, salt_bytes, kRecoveryCodePbkdfIters);
        if (auth::AuthManager::constant_time_compare(presented_hash, cand.code_hash) &&
            matched_id < 0) {
            matched_id = cand.id;
        }
    }
    if (matched_id < 0) {
        return false;
    }

    // RETURNING id closes the #1033 race that sqlite3_changes() would
    // expose: a concurrent UPDATE on an unrelated `mfa_recovery_codes`
    // row would otherwise flip the count and let a double-spend race
    // silently succeed for the loser. With RETURNING, only the actual
    // row that this UPDATE altered (the one matching `id AND consumed_at
    // IS NULL`) drives the success signal.
    static const char* upd_sql = R"(
        UPDATE mfa_recovery_codes
        SET consumed_at = CURRENT_TIMESTAMP
        WHERE id = ? AND consumed_at IS NULL
        RETURNING id
    )";
    sqlite3_stmt* upd = nullptr;
    if (sqlite3_prepare_v2(impl_->db, upd_sql, -1, &upd, nullptr) != SQLITE_OK) {
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    sqlite3_bind_int64(upd, 1, matched_id);
    auto rc = sqlite3_step(upd);
    sqlite3_finalize(upd);
    if (rc == SQLITE_DONE) {
        // A concurrent consume won the race; this caller is the loser.
        return false;
    }
    if (rc != SQLITE_ROW) {
        return std::unexpected(AuthDBError::WriteFailed);
    }
    return true;
}

std::expected<std::vector<std::string>, AuthDBError>
AuthDB::mfa_regenerate_recovery_codes(const std::string& username) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }

    // DELETE + 10 INSERTs atomically. Without the txn, a crash mid-loop
    // would leave the operator with 0 < N < 10 valid codes AND no raw
    // codes returned (function fails before yielding the vector). The
    // operator would have to call mfa_disable to recover (Gate 3 cpp-
    // safety BLOCKING + performance S1). The DELETE+INSERT core is shared
    // with mfa_verify_enrollment via regenerate_recovery_codes_locked.
    TxnGuard txn(impl_->db);
    if (!txn.active()) {
        return std::unexpected(AuthDBError::WriteFailed);
    }
    auto raw_codes = regenerate_recovery_codes_locked(impl_->db, username);
    if (!raw_codes) {
        return std::unexpected(raw_codes.error()); // TxnGuard rolls back
    }
    if (!txn.commit()) {
        return std::unexpected(AuthDBError::WriteFailed);
    }
    return raw_codes;
}

std::expected<void, AuthDBError> AuthDB::mfa_disable(const std::string& username) {
    if (!is_valid_username(username)) {
        return std::unexpected(AuthDBError::InvalidUsername);
    }

    // UPDATE + DELETE atomically. Without the txn, a kill -9 between the
    // two statements would leave the row with secret=NULL but the recovery
    // codes still present — UI shows "Not enrolled" but consume succeeds.
    // The design doc's hard-invariant §3 ("no half-disabled state") is
    // load-bearing here (Gate 3 authdb F3 + cpp-safety BLOCKING).
    TxnGuard txn(impl_->db);
    if (!txn.active()) {
        return std::unexpected(AuthDBError::WriteFailed);
    }

    static const char* upd_sql = R"(
        UPDATE users
        SET mfa_totp_secret = NULL,
            mfa_enrolled_at = NULL,
            mfa_disabled_at = CURRENT_TIMESTAMP,
            mfa_last_counter = 0,
            updated_at = CURRENT_TIMESTAMP
        WHERE username = ? AND is_active = 1
    )";
    sqlite3_stmt* upd = nullptr;
    if (sqlite3_prepare_v2(impl_->db, upd_sql, -1, &upd, nullptr) != SQLITE_OK) {
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    sqlite3_bind_text(upd, 1, username.c_str(), -1, SQLITE_STATIC);
    auto rc = sqlite3_step(upd);
    sqlite3_finalize(upd);
    if (rc != SQLITE_DONE) {
        return std::unexpected(AuthDBError::WriteFailed);
    }

    static const char* del_sql = "DELETE FROM mfa_recovery_codes WHERE username = ?";
    sqlite3_stmt* del = nullptr;
    if (sqlite3_prepare_v2(impl_->db, del_sql, -1, &del, nullptr) != SQLITE_OK) {
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    sqlite3_bind_text(del, 1, username.c_str(), -1, SQLITE_STATIC);
    auto rc2 = sqlite3_step(del);
    sqlite3_finalize(del);
    if (rc2 != SQLITE_DONE) {
        return std::unexpected(AuthDBError::WriteFailed);
    }

    if (!txn.commit()) {
        return std::unexpected(AuthDBError::WriteFailed);
    }
    return {};
}

std::expected<void, AuthDBError>
AuthDB::mfa_mark_session_stepup(const std::string& session_token) {
    // Session-cookie auth row may not be persisted in v1 (in-memory map
    // is the authoritative read path; the column is provisioned for the
    // v2 session-persistence work). We don't need to discriminate
    // matched-vs-not — the operation is best-effort persist, and the
    // caller has already updated the in-memory session. No
    // sqlite3_changes() call required, dodging #1033.
    static const char* sql = R"(
        UPDATE sessions
        SET mfa_verified_at = CURRENT_TIMESTAMP, last_activity_at = CURRENT_TIMESTAMP
        WHERE session_token = ?
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    sqlite3_bind_text(stmt, 1, session_token.c_str(), -1, SQLITE_STATIC);
    auto rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        return std::unexpected(AuthDBError::WriteFailed);
    }
    return {};
}

std::expected<void, AuthDBError>
AuthDB::touch_session_activity(const std::string& session_token) {
    // Best-effort durable mirror of the in-memory session's last_activity_at
    // for the idle-timeout feature (SOC 2 CC6.3). The in-memory sessions_ map
    // is the authoritative idle-timeout read path; this column keeps the (v1
    // dead-write) sessions row fresh for housekeeping + the future v2
    // session-persistence work. AuthManager throttles the call to at most once
    // per session per kActivityPersistGranularity, so this is NOT a per-request
    // write. Same shape as mfa_mark_session_stepup: no sqlite3_changes() (#1033)
    // — match-vs-not doesn't matter for a best-effort persist.
    static const char* sql = R"(
        UPDATE sessions SET last_activity_at = CURRENT_TIMESTAMP WHERE session_token = ?
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    sqlite3_bind_text(stmt, 1, session_token.c_str(), -1, SQLITE_STATIC);
    auto rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        return std::unexpected(AuthDBError::WriteFailed);
    }
    return {};
}

// ── Enrollment Token Operations (C2 FIX: Atomic Consumption) ─────────────────

std::expected<std::string, AuthDBError>
AuthDB::create_enrollment_token(const std::string& created_by, std::chrono::seconds validity) {
    // Generate secure random token
    auto token_bytes = auth::AuthManager::random_bytes(32);
    std::string plain_token = auth::AuthManager::bytes_to_hex(token_bytes);

    // Hash token for storage (like password hashing)
    std::string token_hash = auth::AuthManager::sha256_hex(plain_token);

    // Calculate expiry
    auto now = std::chrono::system_clock::now();
    auto expires = now + validity;

    // Thread-safe via std::format chrono (xp-S1) — same fix as create_session.
    std::string expires_str = format_sqlite_utc(expires);

    const char* sql = R"(
        INSERT INTO enrollment_tokens (token_hash, created_by, expires_at)
        VALUES (?, ?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare create_enrollment_token statement: {}",
                      sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }

    sqlite3_bind_text(stmt, 1, token_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, created_by.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, expires_str.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        spdlog::error("create_enrollment_token failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }

    spdlog::info("Enrollment token created by {}", created_by);
    return plain_token; // Return plain token to user (hash is stored)
}

// C2 FIX: Atomic token consumption — persists BEFORE returning
// W1.4 / #827 / #1033: switched from sqlite3_changes() to RETURNING. The
// prior implementation called sqlite3_changes(impl_->db) immediately
// after sqlite3_step() on a FULLMUTEX connection — that's the canonical
// data race + correctness bug per #1033 (changes() reads db->nChange
// without the per-connection mutex, which can race a concurrent step()
// on the same handle from another thread). RETURNING carries the "did
// my UPDATE affect a row" signal in the step return code itself, so
// the answer is locked into the same per-statement write lock that
// guarantees atomicity of the UPDATE. Pattern matches ConcurrencyManager
// ::try_acquire which had the same migration in #1031.
std::expected<bool, AuthDBError> AuthDB::consume_enrollment_token(const std::string& plain_token,
                                                                  const std::string& agent_id) {
    // Hash the provided token
    std::string token_hash = auth::AuthManager::sha256_hex(plain_token);

    // RETURNING 1 is a no-payload sentinel: sqlite3_step() returns
    // SQLITE_ROW iff the UPDATE actually updated a row (a WHERE-excluded
    // no-op returns SQLITE_DONE). Do not change the literal `1` to a
    // column projection — the rc == SQLITE_ROW check is the sole signal
    // driving control flow. Defence-in-depth: the WHERE clause still
    // checks is_used = 0 AND expires_at > datetime('now') so a token
    // that's already consumed OR expired never produces a RETURNING row.
    const char* sql = R"(
        UPDATE enrollment_tokens
        SET is_used = 1, used_at = datetime('now'), used_by_agent_id = ?
        WHERE token_hash = ? AND is_used = 0 AND expires_at > datetime('now')
        RETURNING 1
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare consume_enrollment_token statement: {}",
                      sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, token_hash.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_ROW) {
        // RETURNING produced a row → the UPDATE actually wrote.
        spdlog::info("Enrollment token consumed: agent={}", agent_id);
        return true;
    }
    if (rc == SQLITE_DONE) {
        // No row matched the WHERE clause: token doesn't exist, already
        // consumed by a concurrent caller, or expired. The caller treats
        // all three as the same "rejected" outcome — discriminating them
        // here would leak token-shape oracles (see device_token_rejection
        // .hpp comments). Operators see the variant in the in-memory
        // AuthManager path's typed EnrollmentTokenError.
        spdlog::warn("Enrollment token consumption failed (no matching row): token={}..., agent={}",
                     plain_token.substr(0, 8), agent_id);
        return false;
    }
    // Anything else is a sqlite-layer failure.
    spdlog::error("consume_enrollment_token sqlite step failed rc={}: {}", rc,
                  sqlite3_errmsg(impl_->db));
    return std::unexpected(AuthDBError::WriteFailed);
}

std::expected<bool, AuthDBError> AuthDB::validate_enrollment_token(const std::string& plain_token) {
    std::string token_hash = auth::AuthManager::sha256_hex(plain_token);

    static const char* sql = R"(
        SELECT COUNT(*) FROM enrollment_tokens
        WHERE token_hash = ? AND is_used = 0 AND expires_at > datetime('now')
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare validate_enrollment_token statement: {}",
                      sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }

    sqlite3_bind_text(stmt, 1, token_hash.c_str(), -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    bool valid = false;
    if (rc == SQLITE_ROW) {
        valid = sqlite3_column_int(stmt, 0) > 0;
    }

    sqlite3_finalize(stmt);
    return valid;
}

// ── Role Update (C1 FIX — Separate from upsert_user to avoid password overwrite) ──

std::expected<void, AuthDBError> AuthDB::update_role(const std::string& username,
                                                     auth::Role new_role) {
    // Validate username
    if (!is_valid_username(username)) {
        spdlog::warn("update_role rejected invalid username: '{}'", username);
        return std::unexpected(AuthDBError::InvalidUsername);
    }

    // Allowlist role to 'admin' or 'user' only
    std::string role_str = (new_role == auth::Role::admin) ? "admin" : "user";

    static const char* sql = R"(
        UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP
        WHERE username = ? AND is_active = 1
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare update_role statement: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }

    sqlite3_bind_text(stmt, 1, role_str.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        spdlog::error("update_role failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }

    int changes = sqlite3_changes(impl_->db);
    if (changes == 0) {
        spdlog::warn("update_role: user not found or inactive: '{}'", username);
        return std::unexpected(AuthDBError::UserNotFound);
    }

    spdlog::info("User role updated: {} -> {}", username, role_str);

    // Force re-authentication — session role must reflect the new role.
    // Without this, a demoted admin retains admin access for up to 24 hours
    // via their cached session. Consistent with remove_user() which also
    // invalidates sessions.
    //
    // Per cpp-SH-4, the return must be checked. A swallowed failure here
    // means a demoted admin could continue to authenticate as admin via
    // their pre-change session. We log loudly; the in-memory sessions_
    // erasure that AuthManager performs in parallel is the v1 hard cut.
    if (auto inv = invalidate_all_sessions(username); !inv) {
        spdlog::error("update_role: invalidate_all_sessions for '{}' failed: error={}", username,
                      static_cast<int>(inv.error()));
    }
    spdlog::info("Sessions invalidated for role change: {}", username);

    return {};
}

// ── Pending Agent Operations ────────────────────────────────────────────────

// ── Pending Agent Operations ────────────────────────────────────────────────

std::expected<void, AuthDBError> AuthDB::add_pending_agent(const auth::PendingAgent& agent) {
    const char* sql = R"(
        INSERT INTO pending_agents (agent_id, hostname, os, arch, agent_version, status)
        VALUES (?, ?, ?, ?, ?, 'pending')
        ON CONFLICT(agent_id) DO NOTHING
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare add_pending_agent statement: {}",
                      sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }

    sqlite3_bind_text(stmt, 1, agent.agent_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, agent.hostname.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, agent.os.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, agent.arch.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, agent.agent_version.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        spdlog::error("add_pending_agent failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }

    spdlog::info("Pending agent added: {} ({})", agent.agent_id, agent.hostname);
    return {};
}

std::expected<std::vector<auth::PendingAgent>, AuthDBError> AuthDB::list_pending_agents() {
    static const char* sql = R"(
        SELECT agent_id, hostname, os, arch, agent_version, requested_at
        FROM pending_agents
        WHERE status = 'pending'
        ORDER BY requested_at DESC
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare list_pending_agents statement: {}",
                      sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }

    std::vector<auth::PendingAgent> agents;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        auth::PendingAgent agent;
        // pending_agents.os/arch/agent_version are nullable per schema;
        // col_text guards the std::string ctor against the NULL case.
        agent.agent_id = col_text(stmt, 0);
        agent.hostname = col_text(stmt, 1);
        agent.os = col_text(stmt, 2);
        agent.arch = col_text(stmt, 3);
        agent.agent_version = col_text(stmt, 4);
        agents.push_back(agent);
    }

    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        spdlog::error("list_pending_agents query failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::QueryFailed);
    }

    return agents;
}

std::expected<void, AuthDBError> AuthDB::approve_agent(const std::string& agent_id,
                                                       const std::string& approved_by) {
    const char* sql = R"(
        UPDATE pending_agents
        SET status = 'approved', approved_at = datetime('now'), approved_by = ?
        WHERE agent_id = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare approve_agent statement: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }

    sqlite3_bind_text(stmt, 1, approved_by.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, agent_id.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        spdlog::error("approve_agent failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }

    spdlog::info("Agent approved: {} by {}", agent_id, approved_by);
    return {};
}

std::expected<void, AuthDBError> AuthDB::reject_agent(const std::string& agent_id) {
    const char* sql = R"(
        UPDATE pending_agents
        SET status = 'rejected'
        WHERE agent_id = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare reject_agent statement: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }

    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        spdlog::error("reject_agent failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }

    spdlog::info("Agent rejected: {}", agent_id);
    return {};
}

} // namespace yuzu::server
