#pragma once

/// @file workflow_model.hpp
/// Shared, pure JSON row builders for the WorkflowEngine/ScheduleEngine read
/// surface (workflow list/detail, workflow-execution detail, schedule list)
/// — REST v1 (`workflow_routes.cpp`) and MCP (`mcp_server.cpp`) call these
/// SAME functions so their JSON shapes cannot drift from each other by
/// construction (`docs/api-twin-recipe.md` Rule 1).
///
/// No `httplib.h`, no MCP-specific include — pure, I/O-free.
///
/// #4030: executions/workflows/schedules read-twin programme.

#include "authz_model.hpp" // authz::VisibleSet / authz::in_scope
#include "schedule_engine.hpp"
#include "workflow_engine.hpp"

#include <nlohmann/json.hpp>

namespace yuzu::server {

/// List-row shape for `GET /api/workflows` / `GET /api/v1/workflows` / MCP
/// `list_workflows` — per-step summary (no `yaml_source`). Unlike the
/// pre-existing legacy `/api/workflows` list handler, this always includes
/// `retry_delay_seconds` per step (the legacy list omits it while the legacy
/// single-item route includes it — a pre-existing field drift within that
/// one file, not something #4030's new v1/MCP twin should carry forward).
nlohmann::json workflow_row_json(const Workflow& w);

/// Single-item detail shape for `GET /api/workflows/{id}` /
/// `GET /api/v1/workflows/{id}` / MCP `get_workflow` — full step list plus
/// `yaml_source`.
nlohmann::json workflow_detail_json(const Workflow& w);

/// Detail shape for `GET /api/workflow-executions/{id}` /
/// `GET /api/v1/workflow-executions/{id}` / MCP `get_workflow_execution` —
/// per-step results. `agent_ids_json`/`WorkflowStepResult::result_json` are
/// stored as JSON-text columns; this builder parses them permissively
/// (`nlohmann::json::parse(..., nullptr, false)`, matching the legacy
/// route's own tolerance for malformed/legacy rows) rather than failing the
/// whole response over one bad column.
///
/// `scope`, when engaged (non-nullopt), restricts the emitted `agent_ids`
/// array to `authz::in_scope(scope, id)` members (workflow-execution
/// confinement decision, #4030 — a caller confined by `fleet_read_fn` sees
/// only in-scope agent ids). `std::nullopt` is unrestricted, matching every
/// other `VisibleSet` consumer in the tree.
nlohmann::json workflow_execution_detail_json(const WorkflowExecution& we,
                                              const authz::VisibleSet& scope);

/// `GET /fragments/schedules` / `GET /api/v1/schedules` / MCP
/// `list_schedules` row — adds `execution_count` (a real, already-populated
/// `InstructionSchedule` field) to `list_schedules`' pre-#4030 output.
nlohmann::json schedule_row_json(const InstructionSchedule& s);

} // namespace yuzu::server
