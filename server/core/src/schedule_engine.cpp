#include "schedule_engine.hpp"

#include <spdlog/spdlog.h>

namespace yuzu::server {

ScheduleEngine::ScheduleEngine(sqlite3* db) : db_(db) {}

void ScheduleEngine::create_tables() {
    if (!db_) return;

    const char* ddl = R"(
        CREATE TABLE IF NOT EXISTS schedules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            definition_id TEXT NOT NULL,
            frequency_type TEXT NOT NULL DEFAULT 'once',
            interval_minutes INTEGER NOT NULL DEFAULT 60,
            time_of_day TEXT NOT NULL DEFAULT '00:00',
            day_of_week INTEGER NOT NULL DEFAULT 0,
            day_of_month INTEGER NOT NULL DEFAULT 1,
            scope_expression TEXT NOT NULL DEFAULT '',
            requires_approval INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            next_execution_at INTEGER NOT NULL DEFAULT 0,
            last_executed_at INTEGER NOT NULL DEFAULT 0,
            execution_count INTEGER NOT NULL DEFAULT 0,
            created_by TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL DEFAULT 0
        );
    )";
    sqlite3_exec(db_, ddl, nullptr, nullptr, nullptr);
}

void ScheduleEngine::stop() {
    // stub — will stop the scheduler tick thread when implemented
}

std::vector<InstructionSchedule> ScheduleEngine::query_schedules(const ScheduleQuery& /*q*/) const {
    return {};
}

std::expected<std::string, std::string> ScheduleEngine::create_schedule(const InstructionSchedule& /*sched*/) {
    return std::unexpected("schedule engine not yet implemented");
}

bool ScheduleEngine::delete_schedule(const std::string& /*id*/) {
    return false;
}

void ScheduleEngine::set_enabled(const std::string& /*id*/, bool /*enabled*/) {
    // stub
}

}  // namespace yuzu::server
