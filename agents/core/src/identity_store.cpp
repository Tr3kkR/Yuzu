#include <yuzu/agent/identity_store.hpp>

#include <sqlite3.h>

#ifdef _WIN32
#include <bcrypt.h>
#include <windows.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <openssl/rand.h>
#endif

#include <array>
#include <cstdlib>
#include <format>
#include <memory>
#include <stdexcept>

namespace yuzu::agent {

namespace {

struct SqliteDbDeleter {
    void operator()(sqlite3* db) const { sqlite3_close(db); }
};
struct SqliteStmtDeleter {
    void operator()(sqlite3_stmt* s) const { sqlite3_finalize(s); }
};
using SqliteDb = std::unique_ptr<sqlite3, SqliteDbDeleter>;
using SqliteStmt = std::unique_ptr<sqlite3_stmt, SqliteStmtDeleter>;

void crypto_random_bytes(uint8_t* buf, size_t n) {
#ifdef _WIN32
    auto status =
        BCryptGenRandom(nullptr, buf, static_cast<ULONG>(n), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        throw std::runtime_error("BCryptGenRandom failed");
    }
#else
    if (RAND_bytes(buf, static_cast<int>(n)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
#endif
}

std::string generate_uuid_v4() {
    uint8_t bytes[16];
    crypto_random_bytes(bytes, sizeof(bytes));

    uint64_t hi = 0, lo = 0;
    for (int i = 0; i < 8; ++i) {
        hi = (hi << 8) | bytes[i];
        lo = (lo << 8) | bytes[i + 8];
    }

    // Set version 4 (bits 48-51 of hi)
    hi = (hi & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;
    // Set variant 1 (bits 62-63 of lo)
    lo = (lo & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;

    auto byte = [&](uint64_t val, int idx) -> uint8_t {
        return static_cast<uint8_t>((val >> (56 - idx * 8)) & 0xFF);
    };

    return std::format("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:"
                       "02x}{:02x}{:02x}{:02x}{:02x}",
                       byte(hi, 0), byte(hi, 1), byte(hi, 2), byte(hi, 3), byte(hi, 4), byte(hi, 5),
                       byte(hi, 6), byte(hi, 7), byte(lo, 0), byte(lo, 1), byte(lo, 2), byte(lo, 3),
                       byte(lo, 4), byte(lo, 5), byte(lo, 6), byte(lo, 7));
}

} // namespace

auto default_data_dir() -> std::filesystem::path {
#ifdef _WIN32
    char* local = nullptr;
    size_t local_len = 0;
    if (_dupenv_s(&local, &local_len, "LOCALAPPDATA") == 0 && local && *local) {
        std::filesystem::path path = std::filesystem::path(local) / "yuzu";
        free(local);
        return path;
    }
    free(local);
    return std::filesystem::current_path() / "yuzu_data";
#elif defined(__APPLE__)
    if (const char* home = std::getenv("HOME"); home && *home) {
        return std::filesystem::path(home) / "Library" / "Application Support" / "yuzu";
    }
    return std::filesystem::current_path() / "yuzu_data";
#else
    if (const char* xdg = std::getenv("XDG_DATA_HOME"); xdg && *xdg) {
        return std::filesystem::path(xdg) / "yuzu";
    }
    if (const char* home = std::getenv("HOME"); home && *home) {
        return std::filesystem::path(home) / ".local" / "share" / "yuzu";
    }
    return std::filesystem::current_path() / "yuzu_data";
#endif
}

auto resolve_agent_id(std::string_view cli_override, const std::filesystem::path& db_path)
    -> std::expected<std::string, IdentityError> {

    if (!cli_override.empty()) {
        return std::string(cli_override);
    }

    // Ensure parent directory exists
    std::error_code ec;
    std::filesystem::create_directories(db_path.parent_path(), ec);
    if (ec) {
        return std::unexpected(
            IdentityError{std::format("failed to create data directory {}: {}",
                                      db_path.parent_path().string(), ec.message())});
    }

    sqlite3* raw_db = nullptr;
    int rc = sqlite3_open(db_path.string().c_str(), &raw_db);
    SqliteDb db(raw_db);
    if (rc != SQLITE_OK) {
        return std::unexpected(IdentityError{std::format(
            "failed to open database {}: {}", db_path.string(), sqlite3_errmsg(db.get()))});
    }

    // Create table if needed
    const char* create_sql =
        "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)";
    char* err_msg = nullptr;
    rc = sqlite3_exec(db.get(), create_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown error";
        sqlite3_free(err_msg);
        return std::unexpected(IdentityError{std::format("failed to create kv table: {}", err)});
    }

    // Try to read existing agent_id
    const char* select_sql = "SELECT value FROM kv WHERE key = 'agent_id'";
    sqlite3_stmt* raw_stmt = nullptr;
    rc = sqlite3_prepare_v2(db.get(), select_sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        return std::unexpected(
            IdentityError{std::format("failed to prepare SELECT: {}", sqlite3_errmsg(db.get()))});
    }

    {
        SqliteStmt stmt(raw_stmt);
        rc = sqlite3_step(stmt.get());
        if (rc == SQLITE_ROW) {
            auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
            return std::string(text ? text : "");
        }
        if (rc != SQLITE_DONE) {
            return std::unexpected(IdentityError{
                std::format("failed to query agent_id: {}", sqlite3_errmsg(db.get()))});
        }
    }

    // Generate new UUID and insert
    std::string new_id = generate_uuid_v4();

    const char* insert_sql = "INSERT INTO kv (key, value) VALUES ('agent_id', ?)";
    raw_stmt = nullptr;
    rc = sqlite3_prepare_v2(db.get(), insert_sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        return std::unexpected(
            IdentityError{std::format("failed to prepare INSERT: {}", sqlite3_errmsg(db.get()))});
    }

    SqliteStmt insert_stmt(raw_stmt);
    sqlite3_bind_text(insert_stmt.get(), 1, new_id.c_str(), -1, SQLITE_STATIC);
    rc = sqlite3_step(insert_stmt.get());

    if (rc != SQLITE_DONE) {
        return std::unexpected(
            IdentityError{std::format("failed to insert agent_id: {}", sqlite3_errmsg(db.get()))});
    }

    return new_id;
}

} // namespace yuzu::agent
