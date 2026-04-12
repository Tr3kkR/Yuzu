#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace yuzu::server {

struct InstructionSchedule {
    std::string id;
    std::string name;
    std::string definition_id;
    std::string frequency_type;
    int interval_minutes{60};
    std::string time_of_day;
    int day_of_week{0};
    int day_of_month{1};
    std::string scope_expression;
    bool requires_approval{false};
    bool enabled{true};
    int64_t next_execution_at{0};
    int64_t last_executed_at{0};
    int execution_count{0};
    std::string created_by;
    int64_t created_at{0};
};

struct ScheduleQuery {
    std::string definition_id;
    bool enabled_only{false};
};

class ScheduleEngine {
public:
    explicit ScheduleEngine(sqlite3* db);
    ~ScheduleEngine() = default;

    ScheduleEngine(const ScheduleEngine&) = delete;
    ScheduleEngine& operator=(const ScheduleEngine&) = delete;

    void create_tables();
    void stop();

    std::vector<InstructionSchedule> query_schedules(const ScheduleQuery& q = {}) const;
    std::expected<std::string, std::string> create_schedule(const InstructionSchedule& sched);
    bool delete_schedule(const std::string& id);
    void set_enabled(const std::string& id, bool enabled);

    std::vector<InstructionSchedule> evaluate_due() const;
    void advance_schedule(const std::string& id);

private:
    sqlite3* db_;
    // No application-level mutex: every method prepare-and-finalizes its
    // statements, so SQLITE_OPEN_FULLMUTEX on the shared instructions.db
    // connection is sufficient. Cached prepared statements would change this.
};

} // namespace yuzu::server
