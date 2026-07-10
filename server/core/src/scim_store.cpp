#include "yuzu/server/scim_store.hpp"

#include "yuzu/server/auth.hpp" // AuthManager::sha256_hex — reuses the shared hashing helper
#include "migration_runner.hpp"
#include "secure_random.hpp" // random_hex — CSPRNG-backed scim_id generation

#include <openssl/crypto.h> // CRYPTO_memcmp — constant-time token compare

#include <spdlog/spdlog.h>
#include <sqlite3.h>

namespace yuzu::server {

namespace {

/// Column order shared by every SELECT/RETURNING clause below — keep in
/// sync if the column list changes.
ScimResource row_to_resource(sqlite3_stmt* stmt) {
    ScimResource r;
    auto text_col = [&](int idx) -> std::string {
        const unsigned char* t = sqlite3_column_text(stmt, idx);
        return t ? reinterpret_cast<const char*>(t) : "";
    };
    r.scim_id = text_col(0);
    r.external_id = text_col(1);
    r.username = text_col(2);
    r.active = sqlite3_column_int(stmt, 3) != 0;
    r.created_at = text_col(4);
    r.updated_at = text_col(5);
    r.etag_version = sqlite3_column_int64(stmt, 6);
    return r;
}

constexpr const char* kResourceColumns =
    "scim_id, external_id, username, active, created_at, updated_at, etag_version";

} // namespace

ScimStore::ScimStore(const std::filesystem::path& db_path) {
    // Deliberately NO SQLITE_OPEN_CREATE (S-DROP-CREATE, authdb LOW): AuthDB
    // is the primary owner of this file and always creates it (chmod 0600)
    // before ScimStore ever opens a connection to it (see server.cpp boot
    // order). Without this, a boot-ordering bug could let ScimStore
    // race-create auth.db first, leaving it world-readable at default umask.
    int rc = sqlite3_open_v2(db_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("ScimStore: failed to open {}: {}", db_path.string(),
                      db_ ? sqlite3_errmsg(db_) : "unknown");
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }
    // AuthDB is the primary owner of this file and already sets WAL mode on
    // it; this second connection only needs its own busy_timeout so lock
    // contention against AuthDB's writes resolves by waiting instead of an
    // immediate SQLITE_BUSY.
    sqlite3_busy_timeout(db_, 5000);
    create_tables();
    if (db_)
        spdlog::info("ScimStore: opened {}", db_path.string());
}

ScimStore::~ScimStore() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool ScimStore::is_open() const noexcept {
    return db_ != nullptr;
}

void ScimStore::create_tables() {
    const std::vector<Migration> kScimMigrations = {
        {1, R"(
            CREATE TABLE IF NOT EXISTS scim_resources (
                scim_id TEXT PRIMARY KEY,
                external_id TEXT,
                username TEXT NOT NULL UNIQUE,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                etag_version INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_scim_resources_external_id
                ON scim_resources(external_id);

            CREATE TABLE IF NOT EXISTS scim_tokens (
                id INTEGER PRIMARY KEY,
                token_hash TEXT NOT NULL,
                label TEXT,
                created_at TEXT NOT NULL,
                revoked_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_scim_tokens_active
                ON scim_tokens(revoked_at) WHERE revoked_at IS NULL;
        )"},
    };
    if (!MigrationRunner::run(db_, "scim", kScimMigrations)) {
        spdlog::error("ScimStore: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

// ── Bearer token (SCIM credential) ───────────────────────────────────────────

bool ScimStore::set_token(const std::string& raw, const std::string& label) {
    if (!db_ || raw.empty())
        return false;

    std::string hash = auth::AuthManager::sha256_hex(raw);

    std::lock_guard lock(db_mtx_);

    // Upsert-by-label: revoke any existing active token sharing this label
    // first, so re-running config with the same label rotates the token
    // instead of leaving the old one both active and orphaned.
    {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_,
                               "UPDATE scim_tokens SET revoked_at = CURRENT_TIMESTAMP "
                               "WHERE label = ?1 AND revoked_at IS NULL",
                               -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, label.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO scim_tokens (token_hash, label, created_at) "
                           "VALUES (?1, ?2, CURRENT_TIMESTAMP)",
                           -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("ScimStore::set_token: prepare failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    sqlite3_bind_text(stmt, 1, hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, label.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool ScimStore::has_token() const {
    if (!db_)
        return false;
    std::lock_guard lock(db_mtx_);
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT 1 FROM scim_tokens WHERE revoked_at IS NULL LIMIT 1", -1,
                          &stmt, nullptr) != SQLITE_OK)
        return false;
    bool exists = sqlite3_step(stmt) == SQLITE_ROW;
    sqlite3_finalize(stmt);
    return exists;
}

bool ScimStore::validate_token(const std::string& raw) const {
    if (!db_ || raw.empty())
        return false;

    std::string hash = auth::AuthManager::sha256_hex(raw);

    std::lock_guard lock(db_mtx_);
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "SELECT token_hash FROM scim_tokens WHERE revoked_at IS NULL", -1,
                          &stmt, nullptr) != SQLITE_OK)
        return false;

    // Scan every active hash rather than short-circuiting on first match —
    // each individual comparison is constant-time via CRYPTO_memcmp, and not
    // early-returning keeps the total scan time independent of which row (if
    // any) matches.
    bool matched = false;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* text = sqlite3_column_text(stmt, 0);
        std::string candidate = text ? reinterpret_cast<const char*>(text) : "";
        if (candidate.size() == hash.size() &&
            CRYPTO_memcmp(candidate.data(), hash.data(), hash.size()) == 0) {
            matched = true;
        }
    }
    sqlite3_finalize(stmt);
    return matched;
}

// ── SCIM resources ────────────────────────────────────────────────────────

std::optional<ScimResource> ScimStore::create_resource(const std::string& username,
                                                        const std::string& external_id) {
    if (!db_ || username.empty())
        return std::nullopt;

    auto id_result = random_hex(16); // 16 CSPRNG bytes -> 32 hex chars
    if (!id_result.has_value())
        return std::nullopt;
    std::string scim_id = *id_result;

    std::lock_guard lock(db_mtx_);
    std::string sql = std::string("INSERT INTO scim_resources (scim_id, external_id, username, "
                                  "active, created_at, updated_at, etag_version) "
                                  "VALUES (?1, ?2, ?3, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1) "
                                  "RETURNING ") +
                     kResourceColumns;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("ScimStore::create_resource: prepare failed: {}", sqlite3_errmsg(db_));
        return std::nullopt;
    }
    sqlite3_bind_text(stmt, 1, scim_id.c_str(), -1, SQLITE_TRANSIENT);
    if (external_id.empty())
        sqlite3_bind_null(stmt, 2);
    else
        // L1 (2026-07-08 review): explicit length, not -1 — external_id is
        // IdP-supplied and a value containing an embedded NUL would
        // otherwise silently truncate at sqlite3_bind_text's strlen() scan.
        sqlite3_bind_text(stmt, 2, external_id.c_str(),
                          static_cast<int>(external_id.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, username.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<ScimResource> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = row_to_resource(stmt);
    }
    sqlite3_finalize(stmt);
    return result;
}

std::optional<ScimResource> ScimStore::get_by_scim_id(const std::string& scim_id) const {
    if (!db_ || scim_id.empty())
        return std::nullopt;

    std::lock_guard lock(db_mtx_);
    std::string sql =
        std::string("SELECT ") + kResourceColumns + " FROM scim_resources WHERE scim_id = ?1";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(stmt, 1, scim_id.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<ScimResource> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = row_to_resource(stmt);
    }
    sqlite3_finalize(stmt);
    return result;
}

std::optional<ScimResource> ScimStore::get_by_username(const std::string& username) const {
    if (!db_ || username.empty())
        return std::nullopt;

    std::lock_guard lock(db_mtx_);
    std::string sql =
        std::string("SELECT ") + kResourceColumns + " FROM scim_resources WHERE username = ?1";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<ScimResource> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = row_to_resource(stmt);
    }
    sqlite3_finalize(stmt);
    return result;
}

std::optional<ScimResource> ScimStore::find_by_external_id(const std::string& external_id) const {
    if (!db_ || external_id.empty())
        return std::nullopt;

    std::lock_guard lock(db_mtx_);
    std::string sql = std::string("SELECT ") + kResourceColumns +
                      " FROM scim_resources WHERE external_id = ?1 LIMIT 1";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;
    // L1 (2026-07-08 review): explicit length, not -1 — see the matching
    // comment in create_resource().
    sqlite3_bind_text(stmt, 1, external_id.c_str(), static_cast<int>(external_id.size()),
                      SQLITE_TRANSIENT);

    std::optional<ScimResource> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        result = row_to_resource(stmt);
    }
    sqlite3_finalize(stmt);
    return result;
}

std::vector<ScimResource> ScimStore::list(int start_index, int count, int& total_out) const {
    total_out = 0;
    std::vector<ScimResource> results;
    if (!db_)
        return results;

    std::lock_guard lock(db_mtx_);

    {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM scim_resources", -1, &stmt, nullptr) ==
            SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                total_out = sqlite3_column_int(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }
    }

    if (count <= 0)
        return results;
    // SCIM startIndex is 1-based (RFC 7644 §3.4.2); clamp anything below 1
    // (including 0/negative from a malformed caller) to the first page.
    int offset = start_index > 1 ? start_index - 1 : 0;

    std::string sql = std::string("SELECT ") + kResourceColumns +
                      " FROM scim_resources ORDER BY rowid ASC LIMIT ?1 OFFSET ?2";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return results;
    sqlite3_bind_int(stmt, 1, count);
    sqlite3_bind_int(stmt, 2, offset);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        results.push_back(row_to_resource(stmt));
    }
    sqlite3_finalize(stmt);
    return results;
}

bool ScimStore::set_active(const std::string& scim_id, bool active) {
    if (!db_ || scim_id.empty())
        return false;

    std::lock_guard lock(db_mtx_);
    static const char* sql = R"(
        UPDATE scim_resources
        SET active = ?1, etag_version = etag_version + 1, updated_at = CURRENT_TIMESTAMP
        WHERE scim_id = ?2
        RETURNING scim_id
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("ScimStore::set_active: prepare failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    sqlite3_bind_int(stmt, 1, active ? 1 : 0);
    sqlite3_bind_text(stmt, 2, scim_id.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_ROW;
}

bool ScimStore::update_resource(const std::string& scim_id, const std::string& username,
                                const std::string& external_id) {
    if (!db_ || scim_id.empty() || username.empty())
        return false;

    std::lock_guard lock(db_mtx_);
    static const char* sql = R"(
        UPDATE scim_resources
        SET username = ?1, external_id = ?2, etag_version = etag_version + 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE scim_id = ?3
        RETURNING scim_id
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("ScimStore::update_resource: prepare failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    if (external_id.empty())
        sqlite3_bind_null(stmt, 2);
    else
        // L1 (2026-07-08 review): explicit length, not -1 — see the matching
        // comment in create_resource().
        sqlite3_bind_text(stmt, 2, external_id.c_str(),
                          static_cast<int>(external_id.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, scim_id.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_ROW;
}

std::optional<bool> ScimStore::delete_by_scim_id(const std::string& scim_id) {
    if (!db_ || scim_id.empty())
        return std::nullopt;

    std::lock_guard lock(db_mtx_);
    static const char* sql = "DELETE FROM scim_resources WHERE scim_id = ?1 RETURNING scim_id";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("ScimStore::delete_by_scim_id: prepare failed: {}", sqlite3_errmsg(db_));
        return std::nullopt;
    }
    sqlite3_bind_text(stmt, 1, scim_id.c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    // true = a row matched and was deleted; false = no row matched (already
    // gone) — a real, idempotent-success outcome, not an error; nullopt =
    // a genuine step-time error (SQLITE_BUSY/LOCKED/IOERR/CORRUPT/...) —
    // must NOT be collapsed into "already gone", or the caller 204s a
    // failed teardown instead of 500ing it.
    if (rc == SQLITE_ROW)
        return true;
    if (rc == SQLITE_DONE)
        return false;
    spdlog::error("ScimStore::delete_by_scim_id: step failed: {}", sqlite3_errmsg(db_));
    return std::nullopt;
}

} // namespace yuzu::server
