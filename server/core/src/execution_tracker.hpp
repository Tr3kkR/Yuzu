#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

struct Execution {
    std::string id;
    std::string definition_id;
    std::string status;
    std::string scope_expression;
    std::string parameter_values;
    std::string dispatched_by;
    int64_t dispatched_at{0};
    int agents_targeted{0};
    int agents_responded{0};
    int agents_success{0};
    int agents_failure{0};
    int64_t completed_at{0};
    std::string parent_id;
    std::string rerun_of;
    /// Most recent non-empty agent error_detail for this execution, computed
    /// via correlated subquery in `query_executions` / `get_execution` when
    /// the row had at least one agent failure. Empty otherwise. Populated for
    /// the executions list "first error" preview without an N×M lookup.
    std::string last_error_detail;
};

struct ExecutionQuery {
    std::string definition_id;
    std::string status;
    int limit{100};
};

struct ExecutionSummary {
    std::string id;
    std::string status;
    int agents_targeted{0};
    int agents_responded{0};
    int agents_success{0};
    int agents_failure{0};
    int progress_pct{0};
};

struct AgentExecStatus {
    std::string agent_id;
    std::string status;
    int64_t dispatched_at{0};
    int64_t first_response_at{0};
    int64_t completed_at{0};
    int exit_code{0};
    std::string error_detail;
};

// ── Execution statistics (capability 1.9) ────────────────────────────

struct AgentExecutionStats {
    std::string agent_id;
    int64_t total_executions{0};
    int64_t success_count{0};
    int64_t failure_count{0};
    double success_rate{0.0};
    double avg_duration_seconds{0.0};
    int64_t last_execution_at{0};
};

struct DefinitionExecutionStats {
    std::string definition_id;
    int64_t total_executions{0};
    int64_t total_agents{0};
    double success_rate{0.0};
    double avg_duration_seconds{0.0};
};

struct FleetExecutionSummary {
    int64_t total_executions{0};
    int64_t executions_today{0};
    int64_t active_agents{0};
    double overall_success_rate{0.0};
    double avg_duration_seconds{0.0};
};

struct ExecutionStatsQuery {
    std::string agent_id;
    std::string definition_id;
    int64_t since{0};
    int64_t until{0};
    int limit{50};
};

class ExecutionTracker {
public:
    explicit ExecutionTracker(sqlite3* db);
    ~ExecutionTracker() = default;

    ExecutionTracker(const ExecutionTracker&) = delete;
    ExecutionTracker& operator=(const ExecutionTracker&) = delete;

    void create_tables();

    // Query
    std::vector<Execution> query_executions(const ExecutionQuery& q = {}) const;
    std::optional<Execution> get_execution(const std::string& id) const;
    ExecutionSummary get_summary(const std::string& id) const;
    std::vector<AgentExecStatus> get_agent_statuses(const std::string& execution_id) const;
    std::vector<Execution> get_children(const std::string& parent_id) const;

    // Mutation
    std::expected<std::string, std::string> create_execution(const Execution& exec);
    void update_agent_status(const std::string& execution_id, const AgentExecStatus& status);
    void refresh_counts(const std::string& execution_id);

    std::expected<std::string, std::string> create_rerun(const std::string& original_id,
                                                         const std::string& user, bool failed_only);

    void mark_cancelled(const std::string& id, const std::string& user);

    // Statistics (capability 1.9)
    std::vector<AgentExecutionStats> get_agent_statistics(const ExecutionStatsQuery& q = {}) const;
    std::vector<DefinitionExecutionStats> get_definition_statistics(const ExecutionStatsQuery& q = {}) const;
    FleetExecutionSummary get_fleet_summary(int64_t since = 0) const;

private:
    sqlite3* db_;
    mutable std::recursive_mutex mtx_;
};

} // namespace yuzu::server
