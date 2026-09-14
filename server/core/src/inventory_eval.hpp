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

/// Gate 6 sre BLOCKING fix (#2146 Batch B2 review): evaluate_inventory() is
/// O(conditions x records) with the "any" combine mode's short-circuit
/// trivially defeated by conditions that never match, so an uncapped
/// conditions[] array lets a single request pin a worker thread on the
/// shared httplib pool for an unbounded time - every caller (both
/// create_result_set_from_inventory_query transports, plus the pre-existing
/// POST /api/v1/inventory/evaluate) MUST reject a conditions[] array larger
/// than this before calling evaluate_inventory(). A few hundred is generous
/// for any real query; conditions are per-field predicates, not device IDs
/// (device_ids' own 100000-item cap is the wrong analog).
inline constexpr std::size_t kMaxInventoryConditions = 500;

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
