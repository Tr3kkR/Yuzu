#pragma once

/// @file preflight_eval.hpp
/// Shared (non-pure) glue between the pure verdict layer (preflight_parse.hpp)
/// and the server's ResponseStore + run-store, used IDENTICALLY by the routes
/// (live render of a running run) and the background runner (persist). Keeps the
/// dispatch + correlation + (de)serialization in ONE place so the two paths can
/// never compute a grid differently.
///
/// Correlation: each check in a run gets its own execution_id
/// `preflight-<run_id>-<check_key>`. Every (re-)dispatch of that check reuses it,
/// so ResponseStore::query_by_execution unions all command_ids per agent and
/// latest_per_agent picks the best — the re-dispatch-on-reconnect aggregation
/// falls out for free (the PolicyEvaluator pattern). The `preflight-` prefix is
/// skipped by AgentServiceImpl::notify_exec_tracker (like `polchk-`) so these
/// never reach the executions drawer.

#include "preflight_parse.hpp"

#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

class ResponseStore;

namespace preflight {

/// Per-check execution_id for a run.
std::string check_execution_id(const std::string& run_id, std::string_view check_key);

/// A check runs only when configured: `app` needs a target name; the rest always.
bool check_applicable(std::string_view key, const PreflightConfig& cfg);

/// The applicable (key, label) checks for a config, in catalogue order.
std::vector<std::pair<std::string, std::string>> applicable_checks(const PreflightConfig& cfg);

/// The plugin/action parameters for a check dispatch (app → {name}, disk → {path}).
std::unordered_map<std::string, std::string> dispatch_params(std::string_view key,
                                                             const PreflightConfig& cfg);

/// Collect each applicable check's per-agent best response via the ResponseStore
/// (query_by_execution on the per-check execution_id + latest_per_agent). MUST
/// NOT be called while holding a PreflightRunStore lease (ADR-0012). Feeds
/// compute_device_results.
std::vector<PreflightCheckResponses>
collect_check_responses(ResponseStore& store, const std::string& run_id,
                        const std::vector<std::pair<std::string, std::string>>& applicable);

/// (De)serialize a device's checks for run_device.checks_json. Agent-derived
/// values → dump uses the replace error-handler (never throws on odd bytes).
std::string checks_to_json(const std::vector<PreflightDeviceCheck>& checks);
std::vector<PreflightDeviceCheck> checks_from_json(const std::string& json);

/// (De)serialize the thresholds for run.config_json so the runner reconstructs
/// them without re-parsing the request.
std::string config_to_json(const PreflightConfig& cfg);
PreflightConfig config_from_json(const std::string& json);

} // namespace preflight
} // namespace yuzu::server
