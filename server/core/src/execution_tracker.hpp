#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <expected>
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
    std::expected<std::string, std::string> create_rerun(const std::string& original_id,
                                                         const std::string& user, bool failed_only);

    void mark_cancelled(const std::string& id, const std::string& user);

private:
    sqlite3* db_;
};

} // namespace yuzu::server
