#pragma once

#include <sqlite3.h>

#include <mutex>
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
    // SQLITE_OPEN_FULLMUTEX serializes individual SQLite API calls but not
    // multi-call sequences. try_acquire pairs sqlite3_step() with
    // sqlite3_changes(), and sqlite3_changes() reads db->nChange without
    // taking the connection mutex — so a concurrent step() on the same
    // connection both data-races the read and can corrupt the observed
    // change count. mutex_ makes each manager operation atomic end-to-end.
    mutable std::mutex mutex_;
};

} // namespace yuzu::server
