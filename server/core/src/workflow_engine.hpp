#pragma once

#include <sqlite3.h>

#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

namespace yuzu::server {

// ── Data types ───────────────────────────────────────────────────────────────

struct WorkflowStep {
    int index{0};
    std::string instruction_id;     // InstructionDefinition ID to execute
    std::string condition;          // CEL/compliance expression — skip step if false
    int retry_count{0};             // Number of retries on failure
    int retry_delay_seconds{5};     // Delay between retries
    std::string foreach_source;     // If set, expand step per result item from previous step
    std::string label;              // Human-readable step label
    std::string on_failure;         // "abort" (default), "continue", "skip_remaining"
};

struct Workflow {
    std::string id;
    std::string name;
    std::string description;
    std::string yaml_source;
    std::vector<WorkflowStep> steps;
    int64_t created_at{0};
    int64_t updated_at{0};
};

enum class WorkflowExecutionStatus {
    kPending,
    kRunning,
    kCompleted,
    kFailed,
    kCancelled
};

enum class StepStatus {
    kPending,
    kRunning,
    kSuccess,
    kFailed,
    kSkipped
};

struct WorkflowStepResult {
    int step_index{0};
    std::string instruction_id;
    std::string status;         // "pending", "running", "success", "failed", "skipped"
    std::string result_json;    // JSON output from step execution
    int64_t started_at{0};
    int64_t completed_at{0};
    int attempt{1};             // Current attempt number (for retries)
};

struct WorkflowExecution {
    std::string id;
    std::string workflow_id;
    std::string status;         // "pending", "running", "completed", "failed", "cancelled"
    std::string agent_ids_json; // JSON array of target agent IDs
    int64_t started_at{0};
    int64_t completed_at{0};
    int current_step{0};

    // Populated by get_execution()
    std::vector<WorkflowStepResult> step_results;
};

struct WorkflowQuery {
    std::string name_filter;
    int limit{100};
};

// ── Dispatch callback type ───────────────────────────────────────────────────
// The workflow engine invokes this callback to dispatch a step to agents.
// Returns a JSON result string on success, or an error string on failure.
using StepDispatchFn = std::function<std::expected<std::string, std::string>(
    const std::string& instruction_id,
    const std::string& agent_ids_json,
    const std::string& parameters_json)>;

// ── Condition evaluator callback type ────────────────────────────────────────
// Evaluates a compliance/CEL expression against result fields.
// Returns true if the condition is satisfied.
using ConditionEvalFn = std::function<bool(
    const std::string& expression,
    const std::map<std::string, std::string>& result_fields)>;

// ── WorkflowEngine ──────────────────────────────────────────────────────────

class WorkflowEngine {
public:
    explicit WorkflowEngine(const std::filesystem::path& db_path);
    ~WorkflowEngine();

    WorkflowEngine(const WorkflowEngine&) = delete;
    WorkflowEngine& operator=(const WorkflowEngine&) = delete;

    bool is_open() const;

    // ── Workflow CRUD ────────────────────────────────────────────────────
    std::expected<std::string, std::string> create_workflow(const std::string& yaml_source);
    std::vector<Workflow> list_workflows(const WorkflowQuery& q = {}) const;
    std::optional<Workflow> get_workflow(const std::string& id) const;
    bool delete_workflow(const std::string& id);

    // ── Execution ────────────────────────────────────────────────────────
    /// Start a workflow execution against a set of agents.
    /// dispatch_fn is called for each step to send commands.
    /// condition_fn evaluates if-conditions on step results.
    std::expected<std::string, std::string> execute(
        const std::string& workflow_id,
        const std::vector<std::string>& agent_ids,
        StepDispatchFn dispatch_fn,
        ConditionEvalFn condition_fn = nullptr);

    /// Get execution status with step results.
    std::optional<WorkflowExecution> get_execution(const std::string& id) const;

    /// List recent executions for a workflow (or all if workflow_id is empty).
    std::vector<WorkflowExecution> list_executions(
        const std::string& workflow_id = {}, int limit = 50) const;

    /// Cancel a running execution.
    std::expected<void, std::string> cancel_execution(const std::string& id);

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_;

    void create_tables();
    std::string generate_id() const;

    // Internal helpers (caller must hold appropriate lock)
    void store_steps(const std::string& workflow_id, const std::vector<WorkflowStep>& steps);
    std::vector<WorkflowStep> load_steps(const std::string& workflow_id) const;

    void create_step_result(const std::string& execution_id, const WorkflowStepResult& sr);
    void update_step_result(const std::string& execution_id, int step_index,
                            const std::string& status, const std::string& result_json);
    void update_execution_status(const std::string& id, const std::string& status,
                                 int current_step = -1);

    // Expand foreach results into individual dispatch items
    std::vector<std::string> expand_foreach(const std::string& foreach_source,
                                             const std::string& prev_result_json) const;
};

} // namespace yuzu::server
