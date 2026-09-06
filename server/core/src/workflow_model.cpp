#include "workflow_model.hpp"

namespace yuzu::server {

namespace {

nlohmann::json workflow_step_json(const WorkflowStep& s) {
    return nlohmann::json{
        {"index", s.index},
        {"instruction_id", s.instruction_id},
        {"condition", s.condition},
        {"retry_count", s.retry_count},
        {"retry_delay_seconds", s.retry_delay_seconds},
        {"foreach", s.foreach_source},
        {"label", s.label},
        {"on_failure", s.on_failure},
    };
}

} // namespace

nlohmann::json workflow_row_json(const Workflow& w) {
    nlohmann::json steps = nlohmann::json::array();
    for (const auto& s : w.steps)
        steps.push_back(workflow_step_json(s));
    return nlohmann::json{
        {"id", w.id},
        {"name", w.name},
        {"description", w.description},
        {"steps", steps},
        {"step_count", static_cast<int64_t>(w.steps.size())},
        {"created_at", w.created_at},
        {"updated_at", w.updated_at},
    };
}

nlohmann::json workflow_detail_json(const Workflow& w) {
    auto j = workflow_row_json(w);
    j["yaml_source"] = w.yaml_source;
    return j;
}

nlohmann::json workflow_execution_detail_json(const WorkflowExecution& we,
                                              const authz::VisibleSet& scope) {
    // agent_ids_json is a stored JSON-text column; parse permissively
    // (malformed/legacy rows must not fail the whole response).
    auto parsed_agent_ids = nlohmann::json::parse(we.agent_ids_json, nullptr, false);
    nlohmann::json agent_ids = nlohmann::json::array();
    if (!parsed_agent_ids.is_discarded() && parsed_agent_ids.is_array()) {
        for (const auto& a : parsed_agent_ids) {
            if (!a.is_string())
                continue;
            const auto& id = a.get_ref<const std::string&>();
            if (!authz::in_scope(scope, id))
                continue;
            agent_ids.push_back(id);
        }
    }

    nlohmann::json steps = nlohmann::json::array();
    for (const auto& sr : we.step_results) {
        auto result = nlohmann::json::parse(sr.result_json, nullptr, false);
        steps.push_back(nlohmann::json{
            {"step_index", sr.step_index},
            {"instruction_id", sr.instruction_id},
            {"status", sr.status},
            {"result", result.is_discarded() ? nlohmann::json(nullptr) : result},
            {"started_at", sr.started_at},
            {"completed_at", sr.completed_at},
            {"attempt", sr.attempt},
        });
    }

    return nlohmann::json{
        {"id", we.id},
        {"workflow_id", we.workflow_id},
        {"status", we.status},
        {"agent_ids", agent_ids},
        {"current_step", we.current_step},
        {"started_at", we.started_at},
        {"completed_at", we.completed_at},
        {"steps", steps},
    };
}

nlohmann::json schedule_row_json(const InstructionSchedule& s) {
    return nlohmann::json{
        {"id", s.id},
        {"name", s.name},
        {"definition_id", s.definition_id},
        {"frequency_type", s.frequency_type},
        {"enabled", s.enabled},
        {"next_execution_at", s.next_execution_at},
        {"execution_count", s.execution_count},
    };
}

} // namespace yuzu::server
