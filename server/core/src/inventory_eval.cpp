#include "inventory_eval.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <charconv>
#include <string_view>

namespace yuzu::server {

namespace {

/// Extract a value from JSON via dot-path notation.
/// Supports object keys and numeric array indices (e.g., "items.0.version").
std::optional<nlohmann::json> json_path(const nlohmann::json& root, std::string_view path) {
    const nlohmann::json* current = &root;

    while (!path.empty()) {
        auto dot = path.find('.');
        auto segment = path.substr(0, dot);
        path = (dot == std::string_view::npos) ? std::string_view{} : path.substr(dot + 1);

        if (current->is_object()) {
            std::string key{segment};
            auto it = current->find(key);
            if (it == current->end()) {
                return std::nullopt;
            }
            current = &(*it);
        } else if (current->is_array()) {
            std::size_t index = 0;
            auto [ptr, ec] = std::from_chars(segment.data(), segment.data() + segment.size(), index);
            if (ec != std::errc{} || ptr != segment.data() + segment.size()) {
                return std::nullopt;
            }
            if (index >= current->size()) {
                return std::nullopt;
            }
            current = &(*current)[index];
        } else {
            return std::nullopt;
        }
    }

    return std::optional<nlohmann::json>{*current};
}

/// Split a version string on '.' and collect numeric segments.
std::vector<int64_t> parse_version_segments(std::string_view ver) {
    std::vector<int64_t> segments;
    while (!ver.empty()) {
        auto dot = ver.find('.');
        auto part = ver.substr(0, dot);
        int64_t num = 0;
        [[maybe_unused]] auto [ptr, ec] = std::from_chars(part.data(), part.data() + part.size(), num);
        if (ec != std::errc{}) {
            num = 0;
        }
        segments.push_back(num);
        ver = (dot == std::string_view::npos) ? std::string_view{} : ver.substr(dot + 1);
    }
    return segments;
}

/// Compare two version strings lexicographically by numeric segments.
/// Returns <0 if a < b, 0 if equal, >0 if a > b.
int compare_versions(std::string_view a, std::string_view b) {
    auto segs_a = parse_version_segments(a);
    auto segs_b = parse_version_segments(b);

    auto max_len = std::max(segs_a.size(), segs_b.size());
    segs_a.resize(max_len, 0);
    segs_b.resize(max_len, 0);

    for (std::size_t i = 0; i < max_len; ++i) {
        if (segs_a[i] < segs_b[i]) return -1;
        if (segs_a[i] > segs_b[i]) return 1;
    }
    return 0;
}

/// Convert a JSON value to its string representation for comparisons and result output.
std::string json_value_to_string(const nlohmann::json& val) {
    if (val.is_string()) {
        return val.get<std::string>();
    }
    if (val.is_number_integer()) {
        return std::to_string(val.get<int64_t>());
    }
    if (val.is_number_float()) {
        return std::to_string(val.get<double>());
    }
    if (val.is_boolean()) {
        return val.get<bool>() ? "true" : "false";
    }
    if (val.is_null()) {
        return "";
    }
    return val.dump();
}

/// Evaluate a single condition against parsed JSON data.
bool eval_condition(const nlohmann::json& data, const InventoryCondition& cond,
                    std::string& matched_value_out) {
    // "exists" checks presence and non-null
    if (cond.op == "exists") {
        auto val = json_path(data, cond.field);
        if (val.has_value() && !val->is_null()) {
            matched_value_out = json_value_to_string(*val);
            return true;
        }
        return false;
    }

    auto val = json_path(data, cond.field);
    if (!val.has_value() || val->is_null()) {
        return false;
    }

    auto val_str = json_value_to_string(*val);
    matched_value_out = val_str;

    if (cond.op == "==" ) return val_str == cond.value;
    if (cond.op == "!=" ) return val_str != cond.value;
    if (cond.op == "contains") return val_str.find(cond.value) != std::string::npos;

    // Version comparisons
    if (cond.op == "version_gte") return compare_versions(val_str, cond.value) >= 0;
    if (cond.op == "version_lte") return compare_versions(val_str, cond.value) <= 0;

    // Numeric comparisons — attempt to parse both sides as numbers
    double lhs = 0.0;
    double rhs = 0.0;
    bool lhs_ok = false, rhs_ok = false;
#if defined(__cpp_lib_to_chars) && __cpp_lib_to_chars >= 201611L
    [[maybe_unused]] auto [lp, le] = std::from_chars(val_str.data(), val_str.data() + val_str.size(), lhs);
    [[maybe_unused]] auto [rp, re] = std::from_chars(cond.value.data(), cond.value.data() + cond.value.size(), rhs);
    lhs_ok = (le == std::errc{});
    rhs_ok = (re == std::errc{});
#else
    // Apple Clang fallback: std::from_chars for double may not be available
    try { size_t pos = 0; lhs = std::stod(val_str, &pos); lhs_ok = (pos == val_str.size()); } catch (...) {}
    try { size_t pos = 0; rhs = std::stod(cond.value, &pos); rhs_ok = (pos == cond.value.size()); } catch (...) {}
#endif

    if (!lhs_ok || !rhs_ok) {
        // Fall back to lexicographic comparison for non-numeric values
        if (cond.op == ">=" ) return val_str >= cond.value;
        if (cond.op == "<=" ) return val_str <= cond.value;
        if (cond.op == ">"  ) return val_str >  cond.value;
        if (cond.op == "<"  ) return val_str <  cond.value;
        return false;
    }

    if (cond.op == ">=" ) return lhs >= rhs;
    if (cond.op == "<=" ) return lhs <= rhs;
    if (cond.op == ">"  ) return lhs >  rhs;
    if (cond.op == "<"  ) return lhs <  rhs;

    return false;
}

} // namespace

std::vector<InventoryEvalResult> evaluate_inventory(
    const InventoryEvalRequest& req,
    const std::vector<std::pair<std::string, std::string>>& records) {

    std::vector<InventoryEvalResult> results;
    bool combine_all = (req.combine != "any");

    for (const auto& [key, data_json] : records) {
        // Parse the composite key: "agent_id|plugin"
        auto sep = key.find('|');
        if (sep == std::string::npos) {
            continue;
        }
        auto record_agent_id = key.substr(0, sep);
        auto record_plugin = key.substr(sep + 1);

        // If the request targets a specific agent, skip non-matching records
        if (!req.agent_id.empty() && record_agent_id != req.agent_id) {
            continue;
        }

        nlohmann::json data;
        try {
            data = nlohmann::json::parse(data_json);
        } catch (const nlohmann::json::parse_error&) {
            continue;
        }

        bool overall_match = combine_all;  // true for AND, false for OR
        std::string last_matched_value;

        for (const auto& cond : req.conditions) {
            // If condition specifies a plugin, skip records from other plugins
            if (!cond.plugin.empty() && cond.plugin != record_plugin) {
                if (combine_all) {
                    overall_match = false;
                    break;
                }
                continue;
            }

            std::string matched_value;
            bool cond_result = eval_condition(data, cond, matched_value);

            if (cond_result) {
                last_matched_value = matched_value;
            }

            if (combine_all) {
                if (!cond_result) {
                    overall_match = false;
                    break;
                }
            } else {
                if (cond_result) {
                    overall_match = true;
                    break;
                }
            }
        }

        if (overall_match) {
            int64_t collected_at = 0;
            if (data.contains("collected_at") && data["collected_at"].is_number_integer()) {
                collected_at = data["collected_at"].get<int64_t>();
            }

            results.push_back(InventoryEvalResult{
                .agent_id = record_agent_id,
                .match = true,
                .matched_value = last_matched_value,
                .plugin = record_plugin,
                .collected_at = collected_at,
            });
        }
    }

    return results;
}

} // namespace yuzu::server
