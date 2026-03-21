/**
 * kv_store.cpp -- Persistent SQLite-backed key-value storage for plugins
 *
 * Table schema:
 *   CREATE TABLE IF NOT EXISTS kv_store (
 *       plugin     TEXT NOT NULL,
 *       key        TEXT NOT NULL,
 *       value      TEXT,
 *       updated_at INTEGER,
 *       PRIMARY KEY(plugin, key)
 *   );
 *
 * All queries use parameterized SQL to prevent injection.
 * A std::mutex guards all sqlite3* access for thread safety (Darwin pitfall).
 */

#include <yuzu/agent/kv_store.hpp>

#include <sqlite3.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <format>
#include <string>

namespace yuzu::agent {

namespace {

int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

struct StmtDeleter {
    void operator()(sqlite3_stmt* s) const { sqlite3_finalize(s); }
};
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

} // namespace

// Private constructor
KvStore::KvStore(sqlite3* db) : db_{db} {}

KvStore::~KvStore() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

KvStore::KvStore(KvStore&& other) noexcept : db_{other.db_} {
    other.db_ = nullptr;
}

KvStore& KvStore::operator=(KvStore&& other) noexcept {
    if (this != &other) {
        if (db_)
            sqlite3_close(db_);
        db_ = other.db_;
        other.db_ = nullptr;
    }
    return *this;
}

std::expected<KvStore, KvStoreError> KvStore::open(const std::filesystem::path& db_path) {
    // Ensure parent directory exists
    std::error_code ec;
    auto parent = db_path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return std::unexpected(KvStoreError{
                std::format("failed to create directory {}: {}", parent.string(), ec.message())});
        }
    }

    sqlite3* raw_db = nullptr;
    int rc = sqlite3_open(db_path.string().c_str(), &raw_db);
    if (rc != SQLITE_OK) {
        std::string err = raw_db ? sqlite3_errmsg(raw_db) : "unknown error";
        if (raw_db)
            sqlite3_close(raw_db);
        return std::unexpected(
            KvStoreError{std::format("failed to open kv_store.db: {}", err)});
    }

    // WAL mode for better concurrent read performance
    char* err_msg = nullptr;
    rc = sqlite3_exec(raw_db, "PRAGMA journal_mode=WAL", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::warn("KvStore: WAL mode failed: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
    }

    // Busy timeout for concurrent access
    sqlite3_busy_timeout(raw_db, 5000);

    // Create table
    const char* create_sql = R"(
        CREATE TABLE IF NOT EXISTS kv_store (
            plugin     TEXT NOT NULL,
            key        TEXT NOT NULL,
            value      TEXT,
            updated_at INTEGER,
            PRIMARY KEY(plugin, key)
        )
    )";
    err_msg = nullptr;
    rc = sqlite3_exec(raw_db, create_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown error";
        sqlite3_free(err_msg);
        sqlite3_close(raw_db);
        return std::unexpected(
            KvStoreError{std::format("failed to create kv_store table: {}", err)});
    }

    spdlog::info("KvStore opened: {}", db_path.string());
    return KvStore{raw_db};
}

bool KvStore::set(std::string_view plugin, std::string_view key, std::string_view value) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    const char* sql = R"(
        INSERT INTO kv_store (plugin, key, value, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(plugin, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("KvStore::set prepare failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, plugin.data(), static_cast<int>(plugin.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 3, value.data(), static_cast<int>(value.size()), SQLITE_STATIC);
    sqlite3_bind_int64(stmt.get(), 4, now_epoch_seconds());

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        spdlog::error("KvStore::set step failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    return true;
}

std::optional<std::string> KvStore::get(std::string_view plugin, std::string_view key) {
    std::lock_guard lock(mu_);
    if (!db_)
        return std::nullopt;

    const char* sql = "SELECT value FROM kv_store WHERE plugin = ? AND key = ?";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("KvStore::get prepare failed: {}", sqlite3_errmsg(db_));
        return std::nullopt;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, plugin.data(), static_cast<int>(plugin.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        return std::string(text ? text : "");
    }
    return std::nullopt;
}

bool KvStore::del(std::string_view plugin, std::string_view key) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    const char* sql = "DELETE FROM kv_store WHERE plugin = ? AND key = ?";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("KvStore::del prepare failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, plugin.data(), static_cast<int>(plugin.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        spdlog::error("KvStore::del step failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    return true;
}

bool KvStore::exists(std::string_view plugin, std::string_view key) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    const char* sql = "SELECT 1 FROM kv_store WHERE plugin = ? AND key = ? LIMIT 1";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("KvStore::exists prepare failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, plugin.data(), static_cast<int>(plugin.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    return rc == SQLITE_ROW;
}

std::vector<std::string> KvStore::list(std::string_view plugin, std::string_view prefix) {
    std::lock_guard lock(mu_);
    std::vector<std::string> result;
    if (!db_)
        return result;

    // L6: Escape LIKE wildcards (%, _, \) in the prefix to prevent unintended matching
    std::string escaped_prefix;
    escaped_prefix.reserve(prefix.size());
    for (char c : prefix) {
        if (c == '%' || c == '_' || c == '\\') {
            escaped_prefix += '\\';
        }
        escaped_prefix += c;
    }
    escaped_prefix += '%';

    const char* sql = "SELECT key FROM kv_store WHERE plugin = ? AND key LIKE ? ESCAPE '\\' ORDER BY key";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("KvStore::list prepare failed: {}", sqlite3_errmsg(db_));
        return result;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, plugin.data(), static_cast<int>(plugin.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, escaped_prefix.c_str(), static_cast<int>(escaped_prefix.size()), SQLITE_STATIC);

    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        if (text)
            result.emplace_back(text);
    }
    return result;
}

int KvStore::clear(std::string_view plugin) {
    std::lock_guard lock(mu_);
    if (!db_)
        return 0;

    const char* sql = "DELETE FROM kv_store WHERE plugin = ?";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("KvStore::clear prepare failed: {}", sqlite3_errmsg(db_));
        return 0;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, plugin.data(), static_cast<int>(plugin.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        spdlog::error("KvStore::clear step failed: {}", sqlite3_errmsg(db_));
        return 0;
    }
    return sqlite3_changes(db_);
}

} // namespace yuzu::agent
