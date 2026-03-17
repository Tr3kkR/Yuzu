#include "instruction_store.hpp"

#include <spdlog/spdlog.h>

namespace yuzu::server {

InstructionStore::InstructionStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("InstructionStore: failed to open DB {}: {}",
                      db_path.string(), sqlite3_errmsg(db_));
        if (db_) { sqlite3_close(db_); db_ = nullptr; }
        return;
    }
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);

    const char* ddl = R"(
        CREATE TABLE IF NOT EXISTS instruction_definitions (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT NOT NULL DEFAULT '1.0',
            type TEXT NOT NULL,
            plugin TEXT NOT NULL,
            action TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            instruction_set_id TEXT NOT NULL DEFAULT '',
            gather_ttl_seconds INTEGER NOT NULL DEFAULT 300,
            response_ttl_days INTEGER NOT NULL DEFAULT 90,
            created_by TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS instruction_sets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL DEFAULT 0
        );
    )";
    sqlite3_exec(db_, ddl, nullptr, nullptr, nullptr);
}

InstructionStore::~InstructionStore() {
    if (db_) sqlite3_close(db_);
}

bool InstructionStore::is_open() const {
    return db_ != nullptr;
}

std::vector<InstructionDefinition> InstructionStore::query_definitions(const InstructionQuery& /*q*/) const {
    return {};
}

std::optional<InstructionDefinition> InstructionStore::get_definition(const std::string& /*id*/) const {
    return std::nullopt;
}

std::expected<std::string, std::string> InstructionStore::create_definition(const InstructionDefinition& /*def*/) {
    return std::unexpected("instruction store not yet implemented");
}

std::expected<void, std::string> InstructionStore::update_definition(const InstructionDefinition& /*def*/) {
    return std::unexpected("instruction store not yet implemented");
}

bool InstructionStore::delete_definition(const std::string& /*id*/) {
    return false;
}

std::string InstructionStore::export_definition_json(const std::string& /*id*/) const {
    return "{}";
}

std::expected<std::string, std::string> InstructionStore::import_definition_json(const std::string& /*json*/) {
    return std::unexpected("instruction store not yet implemented");
}

std::vector<InstructionSet> InstructionStore::list_sets() const {
    return {};
}

std::expected<std::string, std::string> InstructionStore::create_set(const InstructionSet& /*s*/) {
    return std::unexpected("instruction store not yet implemented");
}

bool InstructionStore::delete_set(const std::string& /*id*/) {
    return false;
}

}  // namespace yuzu::server
