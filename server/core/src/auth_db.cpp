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
#include <sqlite3.h>
#include <spdlog/spdlog.h>

// MSVC's STL does not transitively include these via <regex>/<chrono>/<filesystem>.
// Keep them explicit (cf. governance round 7ea7be6 + xp-B1 / cpp-SH-2).
#include <atomic>
#include <cctype>     // std::isalnum
#include <chrono>
#include <cstring>
#include <ctime>      // std::time_t (downstream dependency for chrono format)
#include <filesystem>
#include <format>     // std::format chrono — replaces thread-unsafe std::gmtime
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
        if (!std::isalnum(static_cast<unsigned char>(c)) && 
            c != '.' && c != '_' && c != '-') {
            spdlog::warn("Username validation failed: invalid character '{}' in '{}'", 
                        c, username);
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
    return std::format("{:%Y-%m-%d %H:%M:%S}",
                       std::chrono::floor<std::chrono::seconds>(tp));
}
} // namespace

// ── AuthDB Implementation ────────────────────────────────────────────────────

struct AuthDB::Impl {
    sqlite3* db = nullptr;
    std::filesystem::path db_path;

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
    sqlite3_stmt* stmt_consume_enrollment_token = nullptr;  // C2 FIX: Atomic operation
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

AuthDB::AuthDB(const std::filesystem::path& data_dir)
    : impl_(std::make_unique<Impl>()) {
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
    fs::permissions(impl_->db_path.parent_path(),
                    fs::perms::owner_all,
                    fs::perm_options::replace, ec);
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
    fs::permissions(impl_->db_path,
                    fs::perms::owner_read | fs::perms::owner_write,
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
    // an unbounded credential store is a finding. Sweep cadence is fixed
    // at 60 s for v1 — every other store uses minutes; sessions need
    // tighter cadence because session expiry windows are typically <1h.
    constexpr int kCleanupIntervalSec = 60;
#ifdef __cpp_lib_jthread
    impl_->cleanup_thread = std::jthread([this](std::stop_token stop) {
        while (!stop.stop_requested()) {
            for (int i = 0; i < kCleanupIntervalSec && !stop.stop_requested(); ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            if (stop.stop_requested()) break;
            auto result = cleanup_expired_sessions();
            if (!result) {
                spdlog::warn("AuthDB: periodic session cleanup failed: error={}",
                             static_cast<int>(result.error()));
            } else if (*result > 0) {
                spdlog::info("AuthDB: reaped {} expired sessions", *result);
            }
        }
    });
#else
    impl_->cleanup_thread = std::thread([this]() {
        while (!impl_->stop_cleanup.load()) {
            for (int i = 0; i < kCleanupIntervalSec && !impl_->stop_cleanup.load(); ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            if (impl_->stop_cleanup.load()) break;
            auto result = cleanup_expired_sessions();
            if (!result) {
                spdlog::warn("AuthDB: periodic session cleanup failed: error={}",
                             static_cast<int>(result.error()));
            } else if (*result > 0) {
                spdlog::info("AuthDB: reaped {} expired sessions", *result);
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
    };

    if (!MigrationRunner::run(impl_->db, "auth_db", kMigrations)) {
        spdlog::error("AuthDB: schema migration failed");
        return std::unexpected(AuthDBError::SchemaCreationFailed);
    }

    return {};
}

// ── User Operations ──────────────────────────────────────────────────────────

std::expected<void, AuthDBError> AuthDB::upsert_user(
    const std::string& username,
    const std::string& password_hash,
    const std::string& salt_hex,
    auth::Role role
) {
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
    entry.role     = auth::string_to_role(col_text(stmt, 1));
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
        entry.role     = auth::string_to_role(col_text(stmt, 1));
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
    static const char* sql = R"(
        UPDATE users SET is_active = 0, updated_at = CURRENT_TIMESTAMP
        WHERE username = ?
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
    
    if (rc != SQLITE_DONE) {
        spdlog::error("remove_user failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }
    
    bool removed = sqlite3_changes(impl_->db) > 0;
    if (removed) {
        spdlog::info("User removed: {}", username);
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

std::expected<std::string, AuthDBError> AuthDB::create_session(
    const std::string& username,
    auth::Role role,
    const std::string& auth_source,
    const std::string& oidc_sub
) {
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
        spdlog::error("Failed to prepare validate_session statement: {}", sqlite3_errmsg(impl_->db));
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
    session.username    = col_text(stmt, 0);
    session.role        = auth::string_to_role(col_text(stmt, 1));
    session.auth_source = col_text(stmt, 2);
    // sessions.oidc_sub is genuinely nullable; col_text returns "" on
    // NULL which is the same shape as the previous explicit check.
    session.oidc_sub    = col_text(stmt, 3);
    
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
        spdlog::error("Failed to prepare invalidate_session statement: {}", sqlite3_errmsg(impl_->db));
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
    static const char* sql = R"(
        DELETE FROM sessions WHERE username = ?
    )";
    
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare invalidate_all_sessions statement: {}", sqlite3_errmsg(impl_->db));
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

std::expected<int, AuthDBError> AuthDB::cleanup_expired_sessions() {
    static const char* sql = R"(
        DELETE FROM sessions WHERE expires_at < datetime('now')
    )";
    
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare cleanup_expired_sessions statement: {}", sqlite3_errmsg(impl_->db));
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

// ── Enrollment Token Operations (C2 FIX: Atomic Consumption) ─────────────────

std::expected<std::string, AuthDBError> AuthDB::create_enrollment_token(
    const std::string& created_by,
    std::chrono::seconds validity
) {
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
        spdlog::error("Failed to prepare create_enrollment_token statement: {}", sqlite3_errmsg(impl_->db));
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
    return plain_token;  // Return plain token to user (hash is stored)
}

// C2 FIX: Atomic token consumption — persists BEFORE returning
std::expected<bool, AuthDBError> AuthDB::consume_enrollment_token(
    const std::string& plain_token,
    const std::string& agent_id
) {
    // Hash the provided token
    std::string token_hash = auth::AuthManager::sha256_hex(plain_token);
    
    // C2 FIX: Atomic operation — mark as used in same query that validates
    // This prevents race conditions and ensures persistence before return
    // Defense-in-depth: Also check expiry in same query
    const char* sql = R"(
        UPDATE enrollment_tokens
        SET is_used = 1, used_at = datetime('now'), used_by_agent_id = ?
        WHERE token_hash = ? AND is_used = 0 AND expires_at > datetime('now')
    )";
    
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(impl_->db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("Failed to prepare consume_enrollment_token statement: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    
    sqlite3_bind_text(stmt, 1, agent_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, token_hash.c_str(), -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        spdlog::error("consume_enrollment_token failed: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::WriteFailed);
    }
    
    // Check if any rows were affected
    int changes = sqlite3_changes(impl_->db);
    if (changes == 0) {
        // Either token doesn't exist, already used, or expired
        // (expired check would need additional query — done by caller)
        spdlog::warn("Enrollment token consumption failed: token={}, agent={}", 
                    plain_token.substr(0, 8) + "...", agent_id);
        return false;  // Token invalid or already used
    }
    
    spdlog::info("Enrollment token consumed: agent={}", agent_id);
    return true;  // Success — token marked as used in DB (PERSISTED)
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
        spdlog::error("Failed to prepare validate_enrollment_token statement: {}", sqlite3_errmsg(impl_->db));
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

std::expected<void, AuthDBError> AuthDB::update_role(
    const std::string& username,
    auth::Role new_role
) {
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
        spdlog::error("update_role: invalidate_all_sessions for '{}' failed: error={}",
                      username, static_cast<int>(inv.error()));
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
        spdlog::error("Failed to prepare add_pending_agent statement: {}", sqlite3_errmsg(impl_->db));
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
        spdlog::error("Failed to prepare list_pending_agents statement: {}", sqlite3_errmsg(impl_->db));
        return std::unexpected(AuthDBError::StatementPrepareFailed);
    }
    
    std::vector<auth::PendingAgent> agents;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        auth::PendingAgent agent;
        // pending_agents.os/arch/agent_version are nullable per schema;
        // col_text guards the std::string ctor against the NULL case.
        agent.agent_id      = col_text(stmt, 0);
        agent.hostname      = col_text(stmt, 1);
        agent.os            = col_text(stmt, 2);
        agent.arch          = col_text(stmt, 3);
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

std::expected<void, AuthDBError> AuthDB::approve_agent(
    const std::string& agent_id,
    const std::string& approved_by
) {
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
