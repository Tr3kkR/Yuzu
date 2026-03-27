#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

struct InventoryCondition {
    std::string plugin;
    std::string field;
    std::string op;    // "==", "!=", ">=", "<=", ">", "<", "contains", "exists", "version_gte", "version_lte"
    std::string value;
};

struct InventoryEvalRequest {
    std::string agent_id;
    std::vector<InventoryCondition> conditions;
    std::string combine = "all";  // "all" (AND) or "any" (OR)
};

struct InventoryEvalResult {
    std::string agent_id;
    bool match;
    std::string matched_value;
    std::string plugin;
    int64_t collected_at;
};

/// Evaluate inventory conditions against a set of records.
/// @param req       The evaluation request specifying agent, conditions, and combine mode.
/// @param records   A vector of (agent_id + "|" + plugin, data_json) pairs.
/// @return          Results for agents whose inventory matches the request conditions.
std::vector<InventoryEvalResult> evaluate_inventory(
    const InventoryEvalRequest& req,
    const std::vector<std::pair<std::string, std::string>>& records);

} // namespace yuzu::server
