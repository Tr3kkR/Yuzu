#include <yuzu/agent/identity_store.hpp>

#include <sqlite3.h>

#include <array>
#include <cstdlib>
#include <format>
#include <random>

namespace yuzu::agent {

namespace {

std::string generate_uuid_v4() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;

    uint64_t hi = dist(gen);
    uint64_t lo = dist(gen);

    // Set version 4 (bits 48-51 of hi)
    hi = (hi & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;
    // Set variant 1 (bits 62-63 of lo)
    lo = (lo & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;

    auto byte = [&](uint64_t val, int idx) -> uint8_t {
        return static_cast<uint8_t>((val >> (56 - idx * 8)) & 0xFF);
    };

    return std::format(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        byte(hi, 0), byte(hi, 1), byte(hi, 2), byte(hi, 3),
        byte(hi, 4), byte(hi, 5),
        byte(hi, 6), byte(hi, 7),
        byte(lo, 0), byte(lo, 1),
        byte(lo, 2), byte(lo, 3), byte(lo, 4), byte(lo, 5), byte(lo, 6), byte(lo, 7)
    );
}

}  // namespace

auto default_data_dir() -> std::filesystem::path {
#ifdef _WIN32
    if (const char* local = std::getenv("LOCALAPPDATA"); local && *local) {
        return std::filesystem::path(local) / "yuzu";
    }
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

auto resolve_agent_id(
    std::string_view cli_override,
    const std::filesystem::path& db_path
) -> std::expected<std::string, IdentityError> {

    if (!cli_override.empty()) {
        return std::string(cli_override);
    }

    // Ensure parent directory exists
    std::error_code ec;
    std::filesystem::create_directories(db_path.parent_path(), ec);
    if (ec) {
        return std::unexpected(IdentityError{
            std::format("failed to create data directory {}: {}",
                        db_path.parent_path().string(), ec.message())});
    }

    sqlite3* db = nullptr;
    int rc = sqlite3_open(db_path.string().c_str(), &db);
    if (rc != SQLITE_OK) {
        std::string err = sqlite3_errmsg(db);
        sqlite3_close(db);
        return std::unexpected(IdentityError{
            std::format("failed to open database {}: {}", db_path.string(), err)});
    }

    // Create table if needed
    const char* create_sql =
        "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)";
    char* err_msg = nullptr;
    rc = sqlite3_exec(db, create_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown error";
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return std::unexpected(IdentityError{
            std::format("failed to create kv table: {}", err)});
    }

    // Try to read existing agent_id
    const char* select_sql = "SELECT value FROM kv WHERE key = 'agent_id'";
    sqlite3_stmt* stmt = nullptr;
    rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::string err = sqlite3_errmsg(db);
        sqlite3_close(db);
        return std::unexpected(IdentityError{
            std::format("failed to prepare SELECT: {}", err)});
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        // Found existing ID
        auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        std::string existing_id = text ? text : "";
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return existing_id;
    }
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        std::string err = sqlite3_errmsg(db);
        sqlite3_close(db);
        return std::unexpected(IdentityError{
            std::format("failed to query agent_id: {}", err)});
    }

    // Generate new UUID and insert
    std::string new_id = generate_uuid_v4();

    const char* insert_sql = "INSERT INTO kv (key, value) VALUES ('agent_id', ?)";
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::string err = sqlite3_errmsg(db);
        sqlite3_close(db);
        return std::unexpected(IdentityError{
            std::format("failed to prepare INSERT: {}", err)});
    }

    sqlite3_bind_text(stmt, 1, new_id.c_str(), -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        std::string err = sqlite3_errmsg(db);
        sqlite3_close(db);
        return std::unexpected(IdentityError{
            std::format("failed to insert agent_id: {}", err)});
    }

    sqlite3_close(db);
    return new_id;
}

}  // namespace yuzu::agent
