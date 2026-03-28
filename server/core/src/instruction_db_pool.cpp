#include "instruction_db_pool.hpp"

#include <spdlog/spdlog.h>

namespace yuzu::server {

InstructionDbPool::InstructionDbPool(const std::filesystem::path& db_path) {
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("InstructionDbPool: failed to open {}: {}", db_path.string(),
                      db_ ? sqlite3_errmsg(db_) : "unknown error");
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);
}

InstructionDbPool::~InstructionDbPool() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

} // namespace yuzu::server
