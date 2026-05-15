#pragma once

#include <sqlite3.h>

#include <string>

namespace yuzu::server {

class ConcurrencyManager {
public:
    explicit ConcurrencyManager(sqlite3* db);
    ~ConcurrencyManager() = default;

    ConcurrencyManager(const ConcurrencyManager&) = delete;
    ConcurrencyManager& operator=(const ConcurrencyManager&) = delete;

    void create_tables();

    // Returns true if execution can proceed, false if blocked by concurrency limits
    bool try_acquire(const std::string& definition_id, const std::string& execution_id,
                     const std::string& concurrency_mode);

    // Release lock when execution completes
    void release(const std::string& definition_id, const std::string& execution_id);

    // Count active executions for a definition
    int active_count(const std::string& definition_id) const;

    // Parse "global:N" mode to extract N, returns 0 for non-global modes
    static int parse_global_limit(const std::string& mode);

    // Validate that a concurrency mode string is valid
    static bool is_valid_mode(const std::string& mode);

private:
    sqlite3* db_;
    // Caller-contract: db_ must be opened with SQLITE_OPEN_FULLMUTEX, so
    // each individual SQLite API call on it is serialized. No
    // application-level mutex is needed because try_acquire's conditional
    // INSERT carries a RETURNING clause — "was a row inserted?" is the
    // result of stepping that single statement, never a separate
    // sqlite3_changes() call. (sqlite3_changes() reads db->nChange without
    // the per-connection mutex and would data-race a concurrent step()
    // from another thread holding the same handle. Issue #1033 tracks
    // 24 other store sites that still carry that anti-pattern.)
};

} // namespace yuzu::server
