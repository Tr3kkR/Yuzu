#include "approval_manager.hpp"

#include <spdlog/spdlog.h>

namespace yuzu::server {

ApprovalManager::ApprovalManager(sqlite3* db) : db_(db) {}

void ApprovalManager::create_tables() {
    if (!db_)
        return;

    const char* ddl = R"(
        CREATE TABLE IF NOT EXISTS approvals (
            id TEXT PRIMARY KEY,
            definition_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            submitted_by TEXT NOT NULL DEFAULT '',
            submitted_at INTEGER NOT NULL DEFAULT 0,
            reviewed_by TEXT NOT NULL DEFAULT '',
            reviewed_at INTEGER NOT NULL DEFAULT 0,
            review_comment TEXT NOT NULL DEFAULT '',
            scope_expression TEXT NOT NULL DEFAULT ''
        );
    )";
    sqlite3_exec(db_, ddl, nullptr, nullptr, nullptr);
}

std::vector<Approval> ApprovalManager::query(const ApprovalQuery& /*q*/) const {
    return {};
}

int ApprovalManager::pending_count() const {
    return 0;
}

std::expected<void, std::string> ApprovalManager::approve(const std::string& /*id*/,
                                                          const std::string& /*reviewer*/,
                                                          const std::string& /*comment*/) {
    return std::unexpected("approval manager not yet implemented");
}

std::expected<void, std::string> ApprovalManager::reject(const std::string& /*id*/,
                                                         const std::string& /*reviewer*/,
                                                         const std::string& /*comment*/) {
    return std::unexpected("approval manager not yet implemented");
}

} // namespace yuzu::server
