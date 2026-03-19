#include "api_token_store.hpp"

#include <spdlog/spdlog.h>

#include <chrono>
#include <random>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// clang-format off
#include <windows.h>  // must precede bcrypt.h (defines NTSTATUS)
// clang-format on
#include <bcrypt.h>
#else
#include <openssl/sha.h>
#endif

namespace yuzu::server {

// ── Helpers ──────────────────────────────────────────────────────────────────

static int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static const char* safe(const char* p) {
    return p ? p : "";
}

// ── Construction / teardown ──────────────────────────────────────────────────

ApiTokenStore::ApiTokenStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("ApiTokenStore: failed to open {}: {}", db_path.string(),
                      sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
    create_tables();
    spdlog::info("ApiTokenStore: opened {}", db_path.string());
}

ApiTokenStore::~ApiTokenStore() {
    if (db_)
        sqlite3_close(db_);
}

bool ApiTokenStore::is_open() const {
    return db_ != nullptr;
}

// ── DDL ──────────────────────────────────────────────────────────────────────

void ApiTokenStore::create_tables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS api_tokens (
            token_id      TEXT PRIMARY KEY,
            token_hash    TEXT NOT NULL UNIQUE,
            name          TEXT NOT NULL,
            principal_id  TEXT NOT NULL,
            scope_service TEXT NOT NULL DEFAULT '',
            created_at    INTEGER NOT NULL DEFAULT 0,
            expires_at    INTEGER NOT NULL DEFAULT 0,
            last_used_at  INTEGER NOT NULL DEFAULT 0,
            revoked       INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
        CREATE INDEX IF NOT EXISTS idx_api_tokens_principal ON api_tokens(principal_id);
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("ApiTokenStore: create_tables failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }

    // Migration: add scope_service column if missing (existing databases)
    sqlite3_exec(db_, "ALTER TABLE api_tokens ADD COLUMN scope_service TEXT NOT NULL DEFAULT '';",
                 nullptr, nullptr, nullptr);
}

// ── Token generation and hashing ─────────────────────────────────────────────

std::string ApiTokenStore::generate_raw_token() const {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    static constexpr char chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::string token = "yuzu_"; // prefix for easy identification
    token.reserve(37);
    std::uniform_int_distribution<int> dist(0, 61);
    for (int i = 0; i < 32; ++i)
        token += chars[dist(rng)];
    return token;
}

std::string ApiTokenStore::sha256_hex(const std::string& input) const {
    unsigned char hash[32]{};

#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (alg) {
        BCRYPT_HASH_HANDLE h = nullptr;
        BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0);
        if (h) {
            BCryptHashData(h, reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())),
                           static_cast<ULONG>(input.size()), 0);
            BCryptFinishHash(h, hash, 32, 0);
            BCryptDestroyHash(h);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
#else
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
#endif

    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (unsigned char c : hash) {
        result += hex[c >> 4];
        result += hex[c & 0x0f];
    }
    return result;
}

// ── CRUD ─────────────────────────────────────────────────────────────────────

std::expected<std::string, std::string> ApiTokenStore::create_token(const std::string& name,
                                                                    const std::string& principal_id,
                                                                    int64_t expires_at,
                                                                    const std::string& scope_service) {
    if (!db_)
        return std::unexpected("database not open");
    if (name.empty())
        return std::unexpected("token name cannot be empty");
    if (!scope_service.empty() && expires_at <= 0)
        return std::unexpected("service-scoped tokens must have an expiration time");

    auto raw = generate_raw_token();
    auto hash = sha256_hex(raw);
    auto token_id = hash.substr(0, 12); // Short display ID
    auto now = now_epoch();

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO api_tokens (token_id, token_hash, name, principal_id, "
                           "scope_service, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?);",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(sqlite3_errmsg(db_));

    sqlite3_bind_text(s, 1, token_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, principal_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 5, scope_service.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 6, now);
    sqlite3_bind_int64(s, 7, expires_at);

    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return std::unexpected(std::string("failed to create token: ") + sqlite3_errmsg(db_));
    return raw; // Return the raw token (shown once to user)
}

std::optional<ApiToken> ApiTokenStore::validate_token(const std::string& raw_token) {
    if (!db_ || raw_token.empty())
        return std::nullopt;

    auto hash = sha256_hex(raw_token);
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "SELECT token_id, token_hash, name, principal_id, scope_service, created_at, "
            "expires_at, last_used_at, revoked FROM api_tokens WHERE token_hash = ?;",
            -1, &s, nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(s, 1, hash.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<ApiToken> result;
    if (sqlite3_step(s) == SQLITE_ROW) {
        ApiToken t;
        t.token_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        t.token_hash = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        t.name = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
        t.principal_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 3)));
        t.scope_service = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 4)));
        t.created_at = sqlite3_column_int64(s, 5);
        t.expires_at = sqlite3_column_int64(s, 6);
        t.last_used_at = sqlite3_column_int64(s, 7);
        t.revoked = sqlite3_column_int(s, 8) != 0;

        // Check revocation
        if (t.revoked) {
            sqlite3_finalize(s);
            return std::nullopt;
        }

        // Check expiration
        auto now = now_epoch();
        if (t.expires_at > 0 && now > t.expires_at) {
            sqlite3_finalize(s);
            return std::nullopt;
        }

        result = std::move(t);
    }
    sqlite3_finalize(s);

    // Update last_used_at
    if (result) {
        sqlite3_stmt* upd = nullptr;
        sqlite3_prepare_v2(db_, "UPDATE api_tokens SET last_used_at = ? WHERE token_hash = ?;", -1,
                           &upd, nullptr);
        sqlite3_bind_int64(upd, 1, now_epoch());
        sqlite3_bind_text(upd, 2, hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(upd);
        sqlite3_finalize(upd);
    }

    return result;
}

std::vector<ApiToken> ApiTokenStore::list_tokens(const std::string& principal_id) const {
    std::vector<ApiToken> result;
    if (!db_)
        return result;

    std::string sql =
        "SELECT token_id, '', name, principal_id, scope_service, created_at, expires_at, "
        "last_used_at, revoked FROM api_tokens";
    if (!principal_id.empty())
        sql += " WHERE principal_id = ?";
    sql += " ORDER BY created_at DESC;";

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &s, nullptr) != SQLITE_OK)
        return result;
    if (!principal_id.empty())
        sqlite3_bind_text(s, 1, principal_id.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(s) == SQLITE_ROW) {
        ApiToken t;
        t.token_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        t.token_hash = ""; // Never expose hash in listing
        t.name = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
        t.principal_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 3)));
        t.scope_service = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 4)));
        t.created_at = sqlite3_column_int64(s, 5);
        t.expires_at = sqlite3_column_int64(s, 6);
        t.last_used_at = sqlite3_column_int64(s, 7);
        t.revoked = sqlite3_column_int(s, 8) != 0;
        result.push_back(std::move(t));
    }
    sqlite3_finalize(s);
    return result;
}

bool ApiTokenStore::revoke_token(const std::string& token_id) {
    if (!db_)
        return false;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "UPDATE api_tokens SET revoked = 1 WHERE token_id = ?;", -1, &s,
                           nullptr) != SQLITE_OK)
        return false;
    sqlite3_bind_text(s, 1, token_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return sqlite3_changes(db_) > 0;
}

bool ApiTokenStore::delete_token(const std::string& token_id) {
    if (!db_)
        return false;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, "DELETE FROM api_tokens WHERE token_id = ?;", -1, &s, nullptr) !=
        SQLITE_OK)
        return false;
    sqlite3_bind_text(s, 1, token_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return sqlite3_changes(db_) > 0;
}

} // namespace yuzu::server
