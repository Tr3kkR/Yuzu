#include "device_token_store.hpp"
#include "migration_runner.hpp"

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
#pragma comment(lib, "bcrypt.lib")
#else
#include <openssl/sha.h>
#endif

namespace yuzu::server {

// -- Helpers ------------------------------------------------------------------

static int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

static const char* safe(const char* p) {
    return p ? p : "";
}

// -- Construction / teardown --------------------------------------------------

DeviceTokenStore::DeviceTokenStore(const std::filesystem::path& db_path) {
    // Canonicalize parent path (Darwin /var -> /private/var symlink)
    auto canonical_path = db_path;
    {
        std::error_code ec;
        auto parent = db_path.parent_path();
        if (!parent.empty() && std::filesystem::exists(parent, ec)) {
            auto canon_parent = std::filesystem::canonical(parent, ec);
            if (!ec)
                canonical_path = canon_parent / db_path.filename();
        }
    }
    int rc = sqlite3_open_v2(canonical_path.string().c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("DeviceTokenStore: failed to open {}: {}", canonical_path.string(),
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
    if (db_)
        spdlog::info("DeviceTokenStore: opened {}", canonical_path.string());
}

DeviceTokenStore::~DeviceTokenStore() {
    if (db_)
        sqlite3_close(db_);
}

bool DeviceTokenStore::is_open() const {
    return db_ != nullptr;
}

// -- DDL ----------------------------------------------------------------------

void DeviceTokenStore::create_tables() {
    static const std::vector<Migration> kMigrations = {
        {1, R"(
            CREATE TABLE IF NOT EXISTS device_auth_tokens (
                token_id      TEXT PRIMARY KEY,
                token_hash    TEXT NOT NULL UNIQUE,
                name          TEXT NOT NULL DEFAULT '',
                principal_id  TEXT NOT NULL,
                device_id     TEXT NOT NULL DEFAULT '',
                definition_id TEXT NOT NULL DEFAULT '',
                created_at    INTEGER NOT NULL DEFAULT 0,
                expires_at    INTEGER NOT NULL DEFAULT 0,
                last_used_at  INTEGER NOT NULL DEFAULT 0,
                revoked       INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_device_token_hash ON device_auth_tokens(token_hash);
            CREATE INDEX IF NOT EXISTS idx_device_token_device ON device_auth_tokens(device_id);
        )"},
    };
    if (!MigrationRunner::run(db_, "device_token_store", kMigrations)) {
        spdlog::error("DeviceTokenStore: schema migration failed, closing database");
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

// -- Token generation and hashing ---------------------------------------------

std::string DeviceTokenStore::hash_token(const std::string& raw) const {
    unsigned char hash[32]{};

#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (alg) {
        BCRYPT_HASH_HANDLE h = nullptr;
        BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0);
        if (h) {
            BCryptHashData(h, reinterpret_cast<PUCHAR>(const_cast<char*>(raw.data())),
                           static_cast<ULONG>(raw.size()), 0);
            BCryptFinishHash(h, hash, 32, 0);
            BCryptDestroyHash(h);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
#else
    SHA256(reinterpret_cast<const unsigned char*>(raw.data()), raw.size(), hash);
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

static std::string generate_raw_device_token() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string token = "ydt_"; // yuzu device token prefix
    token.reserve(68);          // 4 prefix + 64 hex chars (32 bytes)
    std::uniform_int_distribution<int> dist(0, 15);
    for (int i = 0; i < 64; ++i)
        token += hex_chars[dist(rng)];
    return token;
}

static std::string generate_token_id() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string id;
    id.reserve(32); // 16 bytes = 32 hex chars
    std::uniform_int_distribution<int> dist(0, 15);
    for (int i = 0; i < 32; ++i)
        id += hex_chars[dist(rng)];
    return id;
}

// -- CRUD ---------------------------------------------------------------------

std::expected<std::string, std::string>
DeviceTokenStore::create_token(const std::string& name, const std::string& principal_id,
                               const std::string& device_id, const std::string& definition_id,
                               int64_t expires_at) {
    if (!db_)
        return std::unexpected("database not open");
    if (principal_id.empty())
        return std::unexpected("principal_id cannot be empty");

    std::unique_lock lock(mtx_);

    auto raw = generate_raw_device_token();
    auto hashed = hash_token(raw);
    auto token_id = generate_token_id();
    auto now = now_epoch();

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "INSERT INTO device_auth_tokens "
                           "(token_id, token_hash, name, principal_id, device_id, "
                           "definition_id, created_at, expires_at) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                           -1, &s, nullptr) != SQLITE_OK)
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

    sqlite3_bind_text(s, 1, token_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 2, hashed.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 3, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 4, principal_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 5, device_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(s, 6, definition_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 7, now);
    sqlite3_bind_int64(s, 8, expires_at);

    int rc = sqlite3_step(s);
    sqlite3_finalize(s);
    if (rc != SQLITE_DONE)
        return std::unexpected(std::string("failed to create token: ") + sqlite3_errmsg(db_));

    spdlog::info("DeviceTokenStore: created token '{}' for principal '{}' (device='{}', def='{}')",
                 name, principal_id, device_id, definition_id);
    return raw; // Return raw token (shown once to user)
}

std::optional<DeviceAuthToken>
DeviceTokenStore::validate_token(const std::string& raw_token) const {
    if (!db_ || raw_token.empty())
        return std::nullopt;

    auto hashed = hash_token(raw_token);

    // Use a single unique_lock for the entire read+update to avoid TOCTOU
    // (a shared_lock that drops and re-acquires as unique would allow a
    // concurrent revoke_token to slip through between the read and write)
    std::unique_lock lock(mtx_);

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(
            db_,
            "SELECT token_id, name, principal_id, device_id, definition_id, "
            "created_at, expires_at, last_used_at, revoked "
            "FROM device_auth_tokens WHERE token_hash = ?;",
            -1, &s, nullptr) != SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(s, 1, hashed.c_str(), -1, SQLITE_TRANSIENT);

    std::optional<DeviceAuthToken> result;
    if (sqlite3_step(s) == SQLITE_ROW) {
        DeviceAuthToken t;
        t.token_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        t.name = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        t.principal_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
        t.device_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 3)));
        t.definition_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 4)));
        t.created_at = sqlite3_column_int64(s, 5);
        t.expires_at = sqlite3_column_int64(s, 6);
        t.last_used_at = sqlite3_column_int64(s, 7);
        t.revoked = sqlite3_column_int(s, 8) != 0;

        // Check revocation
        if (t.revoked) {
            sqlite3_finalize(s);
            return std::nullopt;
        }

        // Check expiration (expires_at == 0 means no expiry)
        auto now = now_epoch();
        if (t.expires_at > 0 && now > t.expires_at) {
            sqlite3_finalize(s);
            return std::nullopt;
        }

        result = std::move(t);
    }
    sqlite3_finalize(s);

    // Update last_used_at (already holding unique_lock)
    if (result) {
        sqlite3_stmt* upd = nullptr;
        if (sqlite3_prepare_v2(db_,
                               "UPDATE device_auth_tokens SET last_used_at = ? "
                               "WHERE token_hash = ?;",
                               -1, &upd, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(upd, 1, now_epoch());
            sqlite3_bind_text(upd, 2, hashed.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(upd);
            sqlite3_finalize(upd);
        }
    }

    return result;
}

std::vector<DeviceAuthToken>
DeviceTokenStore::list_tokens(const std::string& principal_id) const {
    std::vector<DeviceAuthToken> result;
    if (!db_)
        return result;

    std::shared_lock lock(mtx_);

    std::string sql =
        "SELECT token_id, name, principal_id, device_id, definition_id, "
        "created_at, expires_at, last_used_at, revoked "
        "FROM device_auth_tokens";
    if (!principal_id.empty())
        sql += " WHERE principal_id = ?";
    sql += " ORDER BY created_at DESC;";

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &s, nullptr) != SQLITE_OK)
        return result;
    if (!principal_id.empty())
        sqlite3_bind_text(s, 1, principal_id.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(s) == SQLITE_ROW) {
        DeviceAuthToken t;
        t.token_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 0)));
        t.name = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 1)));
        t.principal_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 2)));
        t.device_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 3)));
        t.definition_id = safe(reinterpret_cast<const char*>(sqlite3_column_text(s, 4)));
        t.created_at = sqlite3_column_int64(s, 5);
        t.expires_at = sqlite3_column_int64(s, 6);
        t.last_used_at = sqlite3_column_int64(s, 7);
        t.revoked = sqlite3_column_int(s, 8) != 0;
        result.push_back(std::move(t));
    }
    sqlite3_finalize(s);
    return result;
}

bool DeviceTokenStore::revoke_token(const std::string& token_id) {
    if (!db_)
        return false;

    std::unique_lock lock(mtx_);

    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "UPDATE device_auth_tokens SET revoked = 1 WHERE token_id = ?;",
                           -1, &s, nullptr) != SQLITE_OK)
        return false;
    sqlite3_bind_text(s, 1, token_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s);
    sqlite3_finalize(s);
    return sqlite3_changes(db_) > 0;
}

} // namespace yuzu::server
