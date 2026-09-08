#pragma once

/// @file execution_model.hpp
/// Shared, pure JSON row builders for the ExecutionTracker/ResponseStore read
/// surface (executions list, per-agent status expansion, KPI summary,
/// execution-scoped responses) — REST v1 (`rest_api_v1.cpp`) and MCP
/// (`mcp_server.cpp`) call these SAME functions so their JSON shapes cannot
/// drift from each other by construction (`docs/api-twin-recipe.md` Rule 1).
///
/// No `httplib.h`, no MCP-specific include — pure, I/O-free. Each function
/// takes only the domain struct(s) the caller has already fetched (and
/// already applied confinement/visibility decisions to, via
/// `execution_scope_rules.hpp`'s `execution_visible`/`confined_projection`)
/// and returns `nlohmann::json`.
///
/// #4030: executions/workflows/schedules read-twin programme.

#include "execution_tracker.hpp"
#include "response_store.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::server {

/// One row of a resolved, already-confined execution-list read. The caller
/// is responsible for resolving `definition_name` (an
/// `InstructionStore::get_definition` lookup — memoize per request, the
/// fragment's own per-row lookup is an accepted N+1 at its LIMIT 50; a v1
/// list route capped at 500 must not repeat it unmemoized) and
/// `error_preview` (a truncated `last_error_detail` — taken from
/// `ConfinedCounts::last_error_detail` under confinement, never the raw
/// `Execution::last_error_detail`, which is unconfined fleet-wide data).
/// This struct is the FINAL, display-ready shape, not a re-derivation seam.
struct ExecutionListRow {
    std::string id;
    std::string definition_id;
    std::string definition_name; // empty if unresolved/unknown
    std::string status;
    std::string dispatched_by;
    int64_t dispatched_at{0};
    int agents_targeted{0};
    int agents_responded{0};
    int agents_success{0};
    int agents_failure{0};
    int64_t completed_at{0};
    std::string rerun_of;
    std::string error_preview; // truncated last_error_detail; empty if none
};

/// `GET /fragments/executions`'s fuller field set (definition name + error
/// preview + the agents_success/agents_failure split) reconciled onto REST
/// v1's new `GET /api/v1/executions` list route and MCP's widened
/// `list_executions` tool (#4030).
nlohmann::json execution_list_row_json(const ExecutionListRow& row);

/// Per-agent status/duration row for the execution-detail per-agent
/// expansion (`?include=agents` on `GET /api/v1/executions/{id}` and MCP
/// `get_execution_status`'s `include` param) — same field set as the
/// pre-existing legacy `GET /api/executions/{id}/agents` route
/// (`server.cpp:17291`), so #4030's new v1/MCP surface is a genuine twin of
/// it rather than a third independent shape.
nlohmann::json execution_agent_status_json(const AgentExecStatus& a);

/// KPI summary (succeeded/failed counts + p50/p95 duration in ms) computed
/// from a set of already-fetched, already-confined `AgentExecStatus` rows.
/// Only TERMINAL rows (success/failure/timeout/rejected — matches
/// `execution_scope_rules.hpp::confined_projection`'s definition of
/// "responded") with a usable `completed_at >= dispatched_at` contribute a
/// duration sample; an agent still `running` has no duration yet and must
/// not skew the percentile.
struct ExecutionKpi {
    int total{0};
    int succeeded{0};
    int failed{0};
    double p50_ms{0};
    double p95_ms{0};
    /// false when no terminal row had a usable duration (e.g. every agent
    /// still running) — the fragment's own "—" fallback for this case.
    bool has_duration_data{false};
};
[[nodiscard]] ExecutionKpi compute_execution_kpi(const std::vector<AgentExecStatus>& agents);
nlohmann::json execution_kpi_json(const ExecutionKpi& k);

/// Execution-scoped response row for `GET /api/v1/executions/{id}/responses`
/// (mirrors MCP `query_responses`'s `execution_id`-filtered field set --
/// FIELD-SET PARITY only, not a shared builder: `query_responses` builds its
/// row inline in `mcp_server.cpp` rather than calling this function, so a
/// future field change to one will not propagate to the other without a
/// human remembering both, unlike this file's other builders (#4030 Gate 3,
/// consistency-auditor -- retrofitting `query_responses` onto this function
/// is deliberately out of scope for the Gate 8 fix round; tracked open).
nlohmann::json execution_response_row_json(const StoredResponse& r);

} // namespace yuzu::server
