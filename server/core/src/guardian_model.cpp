#include "guardian_model.hpp"

#include "guaranteed_state_store.hpp"

namespace yuzu::server {

std::optional<GuardianStatusRollup>
guardian_status_rollup(GuaranteedStateStore& store,
                       const std::optional<std::vector<std::string>>& agent_scope) {
    // ADR-0038 catastrophic-read set: a degraded read must never render as a
    // silent 0 that would misreport the fleet as compliant (mirrors the
    // pre-existing inline logic this replaces in rest_api_v1.cpp verbatim).
    auto rule_names_result = store.rule_names();
    auto errored_result = store.errored_rule_count(agent_scope);
    if (!rule_names_result || !errored_result)
        return std::nullopt;
    GuardianStatusRollup out;
    out.total_rules = static_cast<std::int64_t>(rule_names_result->size());
    out.compliant_rules = 0;
    out.drifted_rules = 0;
    out.errored_rules = static_cast<std::int64_t>(*errored_result);
    return out;
}

std::optional<std::vector<GuardianRuleAgentStatusRow>>
guardian_rule_agent_status_rows(GuaranteedStateStore& store, const std::string& rule_id) {
    auto statuses = store.agent_rule_statuses(rule_id);
    if (!statuses)
        return std::nullopt;
    std::vector<GuardianRuleAgentStatusRow> out;
    out.reserve(statuses->size());
    for (const auto& s : *statuses) {
        GuardianRuleAgentStatusRow row;
        row.agent_id = s.agent_id;
        row.state = s.state;
        row.updated_at = s.updated_at;
        out.push_back(std::move(row));
    }
    return out;
}

std::optional<std::vector<GuardianDeviceGuardRow>>
guardian_device_all_guards(GuaranteedStateStore& store, const std::string& agent_id) {
    auto statuses = store.agent_rule_statuses_for_agent(agent_id);
    if (!statuses)
        return std::nullopt;
    std::vector<std::string> rule_ids;
    rule_ids.reserve(statuses->size());
    for (const auto& s : *statuses)
        rule_ids.push_back(s.rule_id);
    auto names = store.rule_names_for(rule_ids);
    if (!names)
        return std::nullopt;
    std::vector<GuardianDeviceGuardRow> out;
    out.reserve(statuses->size());
    for (const auto& s : *statuses) {
        GuardianDeviceGuardRow row;
        row.rule_id = s.rule_id;
        const auto it = names->find(s.rule_id);
        row.name = (it != names->end() && !it->second.empty()) ? it->second : s.rule_id;
        row.state = s.state;
        row.updated_at = s.updated_at;
        out.push_back(std::move(row));
    }
    return out;
}

} // namespace yuzu::server
