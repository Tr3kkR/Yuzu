#include "execution_tracker.hpp"

#include <spdlog/spdlog.h>

namespace yuzu::server {

ExecutionTracker::ExecutionTracker(sqlite3* db) : db_(db) {}

void ExecutionTracker::create_tables() {
    if (!db_) return;

    const char* ddl = R"(
        CREATE TABLE IF NOT EXISTS executions (
            id TEXT PRIMARY KEY,
            definition_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            scope_expression TEXT NOT NULL DEFAULT '',
            parameter_values TEXT NOT NULL DEFAULT '',
            dispatched_by TEXT NOT NULL DEFAULT '',
            dispatched_at INTEGER NOT NULL DEFAULT 0,
            agents_targeted INTEGER NOT NULL DEFAULT 0,
            agents_responded INTEGER NOT NULL DEFAULT 0,
            agents_success INTEGER NOT NULL DEFAULT 0,
            agents_failure INTEGER NOT NULL DEFAULT 0,
            completed_at INTEGER NOT NULL DEFAULT 0,
            parent_id TEXT NOT NULL DEFAULT '',
            rerun_of TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS agent_exec_status (
            execution_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            dispatched_at INTEGER NOT NULL DEFAULT 0,
            first_response_at INTEGER NOT NULL DEFAULT 0,
            completed_at INTEGER NOT NULL DEFAULT 0,
            exit_code INTEGER NOT NULL DEFAULT 0,
            error_detail TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (execution_id, agent_id)
        );
    )";
    sqlite3_exec(db_, ddl, nullptr, nullptr, nullptr);
}

std::vector<Execution> ExecutionTracker::query_executions(const ExecutionQuery& /*q*/) const {
    return {};
}

std::optional<Execution> ExecutionTracker::get_execution(const std::string& /*id*/) const {
    return std::nullopt;
}

ExecutionSummary ExecutionTracker::get_summary(const std::string& id) const {
    ExecutionSummary s;
    s.id = id;
    return s;
}

std::vector<AgentExecStatus> ExecutionTracker::get_agent_statuses(const std::string& /*execution_id*/) const {
    return {};
}

std::vector<Execution> ExecutionTracker::get_children(const std::string& /*parent_id*/) const {
    return {};
}

std::expected<std::string, std::string> ExecutionTracker::create_rerun(
    const std::string& /*original_id*/,
    const std::string& /*user*/,
    bool /*failed_only*/)
{
    return std::unexpected("execution tracker not yet implemented");
}

void ExecutionTracker::mark_cancelled(const std::string& /*id*/, const std::string& /*user*/) {
    // stub
}

}  // namespace yuzu::server
