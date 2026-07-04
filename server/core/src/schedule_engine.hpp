#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <shared_mutex>
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

    /// Owner-scoped delete (M-01, #1806): `created_by` is REQUIRED (no
    /// default) so a caller cannot accidentally pass an empty principal and
    /// have it silently match every legacy row with an empty created_by —
    /// that would reopen the exact cross-tenant mutation gap this closes.
    /// Returns false for a wrong-owner id exactly like a nonexistent one, so
    /// this cannot be used to probe id existence across owners.
    bool delete_schedule(const std::string& id, const std::string& created_by);

    /// Owner-scoped enable/disable (M-01, #1806) — same required-`created_by`
    /// contract as delete_schedule. Returns true iff a row matched (id AND
    /// created_by), so the route can audit only on an actual change.
    bool set_enabled(const std::string& id, bool enabled, const std::string& created_by);

    std::vector<InstructionSchedule> evaluate_due() const;
    void advance_schedule(const std::string& id);

private:
    sqlite3* db_;
    // M-03 (#1806): the poller thread (ScheduleRunner::tick(), on a
    // background thread) now calls evaluate_due()/advance_schedule()
    // concurrently with REST-handler threads calling query/create/delete/
    // set_enabled. SQLITE_OPEN_FULLMUTEX only serializes individual sqlite3
    // C-API calls; it does NOT make a read-modify-write sequence spanning
    // several calls (advance_schedule's SELECT-then-UPDATE) atomic with
    // respect to another thread's interleaved statements on the same
    // connection. Every public method takes this lock: mutators take it
    // exclusively, the const query methods take it shared.
    mutable std::shared_mutex mtx_;
};

} // namespace yuzu::server
