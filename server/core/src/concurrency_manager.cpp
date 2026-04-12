#include "concurrency_manager.hpp"

#include <spdlog/spdlog.h>

#include <chrono>
#include <regex>

namespace yuzu::server {

namespace {

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

ConcurrencyManager::ConcurrencyManager(sqlite3* db) : db_(db) {}

void ConcurrencyManager::create_tables() {
    if (!db_)
        return;

    const char* ddl = R"(
        CREATE TABLE IF NOT EXISTS concurrency_locks (
            definition_id TEXT NOT NULL,
            execution_id TEXT NOT NULL,
            acquired_at INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (definition_id, execution_id)
        );
    )";
    sqlite3_exec(db_, ddl, nullptr, nullptr, nullptr);
}

bool ConcurrencyManager::try_acquire(const std::string& definition_id,
                                     const std::string& execution_id,
                                     const std::string& concurrency_mode) {
    if (!db_)
        return false;

    // Agent-side enforcement or no limit — always allow
    if (concurrency_mode == "unlimited" || concurrency_mode == "per-device" ||
        concurrency_mode == "per-set") {
        return true;
    }

    int limit = 0;
    if (concurrency_mode == "per-definition") {
        limit = 1;
    } else {
        limit = parse_global_limit(concurrency_mode);
        if (limit <= 0) {
            spdlog::warn("concurrency: invalid mode '{}', rejecting", concurrency_mode);
            return false;
        }
    }

    // Single-statement atomic conditional insert. The COUNT subquery and the
    // INSERT execute as one SQL statement, so SQLite holds the write lock for
    // the duration. This closes the SELECT-then-INSERT TOCTOU race that
    // SQLITE_OPEN_FULLMUTEX cannot guard against (FULLMUTEX serializes
    // individual API calls but not multi-statement sequences).
    const char* sql = R"(
        INSERT OR IGNORE INTO concurrency_locks (definition_id, execution_id, acquired_at)
        SELECT ?, ?, ?
        WHERE (SELECT COUNT(*) FROM concurrency_locks WHERE definition_id = ?) < ?
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("concurrency: prepare insert failed: {}", sqlite3_errmsg(db_));
        return false;
    }

    auto now = now_epoch();
    sqlite3_bind_text(stmt, 1, definition_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, execution_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, now);
    sqlite3_bind_text(stmt, 4, definition_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, limit);

    int rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db_);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        spdlog::error("concurrency: insert failed for definition='{}' execution='{}': {}",
                      definition_id, execution_id, sqlite3_errmsg(db_));
        return false;
    }

    if (changes > 0) {
        return true;
    }

    // The conditional insert was a no-op. Either the limit is reached, or this
    // (definition_id, execution_id) lock is already held (idempotent re-acquire
    // by the same caller). Distinguish so re-acquire stays idempotent.
    const char* exists_sql =
        "SELECT 1 FROM concurrency_locks WHERE definition_id = ? AND execution_id = ? LIMIT 1";
    sqlite3_stmt* check = nullptr;
    if (sqlite3_prepare_v2(db_, exists_sql, -1, &check, nullptr) != SQLITE_OK) {
        spdlog::info("concurrency: limit {} reached for '{}'", limit, definition_id);
        return false;
    }
    sqlite3_bind_text(check, 1, definition_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(check, 2, execution_id.c_str(), -1, SQLITE_TRANSIENT);
    bool already_held = (sqlite3_step(check) == SQLITE_ROW);
    sqlite3_finalize(check);

    if (already_held) {
        return true;
    }

    spdlog::info("concurrency: limit {} reached for '{}'", limit, definition_id);
    return false;
}

void ConcurrencyManager::release(const std::string& definition_id,
                                 const std::string& execution_id) {
    if (!db_)
        return;

    const char* sql = "DELETE FROM concurrency_locks WHERE definition_id = ? AND execution_id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("concurrency: prepare delete failed: {}", sqlite3_errmsg(db_));
        return;
    }

    sqlite3_bind_text(stmt, 1, definition_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, execution_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

int ConcurrencyManager::active_count(const std::string& definition_id) const {
    if (!db_)
        return 0;

    const char* sql = "SELECT COUNT(*) FROM concurrency_locks WHERE definition_id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return 0;

    sqlite3_bind_text(stmt, 1, definition_id.c_str(), -1, SQLITE_TRANSIENT);

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int(stmt, 0);

    sqlite3_finalize(stmt);
    return count;
}

int ConcurrencyManager::parse_global_limit(const std::string& mode) {
    // Match "global:" followed by one or more digits
    if (mode.size() <= 7 || mode.substr(0, 7) != "global:")
        return 0;

    auto num_str = mode.substr(7);
    if (num_str.empty())
        return 0;

    for (char c : num_str) {
        if (c < '0' || c > '9')
            return 0;
    }

    try {
        int val = std::stoi(num_str);
        return val > 0 ? val : 0;
    } catch (...) {
        return 0;
    }
}

bool ConcurrencyManager::is_valid_mode(const std::string& mode) {
    static const std::regex pattern(
        R"(^(per-device|per-definition|per-set|unlimited|global:\d+)$)");
    return std::regex_match(mode, pattern);
}

} // namespace yuzu::server
