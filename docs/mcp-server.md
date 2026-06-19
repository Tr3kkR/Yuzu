# MCP (Model Context Protocol) Server

Yuzu embeds an MCP server at `POST /mcp/v1/` using JSON-RPC 2.0 transport. This allows AI models (e.g., Claude Desktop) to securely query fleet status, check compliance, investigate agents, and — with appropriate authorization — execute instructions on endpoints.

CLAUDE.md keeps only the load-bearing invariants (embed point, tier-before-RBAC ordering, kill switches, audit pattern). This document is the full architecture and tool reference.

## Architecture

- **Embedded in existing server** — MCP runs inside the same cpp-httplib server as the REST API and dashboard. It reuses auth middleware, RBAC, rate limiting, CORS, and audit logging with zero duplication.
- **Module:** `server/core/src/mcp_server.hpp` / `mcp_server.cpp` — mirrors `RestApiV1` pattern (injected store pointers, same callback signatures).
- **JSON-RPC helpers:** `mcp_jsonrpc.hpp` (header-only) — parse/build JSON-RPC 2.0 envelopes.
- **Tier policy:** `mcp_policy.hpp` (header-only) — static allow-lists per tier, checked before RBAC.
- **Output serialization:** Uses local `JObj`/`JArr` string builders (same pattern as `rest_api_v1.cpp`) to avoid the 56GB nlohmann template bloat. `nlohmann::json` is used for parsing only.

## Security Model

- **Three authorization tiers** enforced *before* RBAC: `readonly` (read only), `operator` (+ tag writes, auto-approved executions), `supervised` (all ops via approval workflow).
- **MCP tokens** use the existing API token system (`api_token_store`) with a new `mcp_tier` column. MCP tokens require mandatory expiration (max 90 days).
- **Approval workflow** — Operations that `requires_approval(tier, type, op)` returns true for are routed to the `ApprovalManager`. Admins approve/reject via Settings UI or REST API. All admins see all pending approvals (both AI-initiated and human-initiated).
- **Kill switch:** `--mcp-disable` rejects all `/mcp/v1/` requests with `kMcpDisabled` JSON-RPC error. `--mcp-read-only` blocks non-read tools.
- **Audit:** Every MCP tool call logged with `action: "mcp.<tool_name>"` and `mcp_tool` field on `AuditEvent`.

## Phase 1 (Implemented)

- 26 read-only tools: `list_agents`, `get_agent_details`, `query_audit_log`, `list_definitions`, `get_definition`, `query_responses`, `aggregate_responses`, `query_inventory`, `list_inventory_tables`, `get_agent_inventory`, `get_tags`, `search_agents_by_tag`, `list_policies`, `get_compliance_summary`, `get_fleet_compliance`, `list_management_groups`, `get_execution_status`, `list_executions`, `list_schedules`, `validate_scope`, `preview_scope_targets`, `list_pending_approvals`, `get_guardian_schemas`, `list_dex_signals`, `get_dex_signal_scope`, `get_dex_signal_detail`
  - **DEX read tools (`list_dex_signals` / `get_dex_signal_scope` / `get_dex_signal_detail`)** are the MCP parity for the `/api/v1/dex/*` REST surface — same `GuaranteedStateStore` aggregations, gated on `GuaranteedState:Read`, with a `window` of `24h`/`7d`/`30d`/`all`. The audit boundary mirrors REST: the rollup and per-OS scope are fleet aggregates (only the generic `mcp.<tool>` tool-call audit), while `get_dex_signal_detail` returns a most-affected **devices** list (behavioral) and additionally emits a **`dex.signal.view`** audit (`target_type=ObsType`) so one SIEM filter catches the dashboard, REST and MCP behavioral-access surfaces alike. `obs_type` is validated against `[A-Za-z0-9._-]{1,64}` (malformed → `kInvalidParams`).
- 1 write/execute tool: `execute_instruction` — dispatches plugin commands to agents. Auto-approved for `operator` tier; `supervised` tier returns "not implemented" (approval re-dispatch path not yet built). If neither `scope` nor `agent_ids` is provided, targets all agents.
- **Live-query bundle tools (`execute_bundle` / `get_bundle_result`)** — MCP parity for the `POST`/`GET /api/v1/bundles` REST surface (ADR-0011). `execute_bundle` (write/execute, `Execution:Execute`) fans one instruction into 1–32 plugin actions on **one** device via server-side async fan-out and returns `{execution_id, expected}` immediately; `get_bundle_result` (`Response:Read`) collates to `{complete, received, expected, steps[]}` in request order. Use instead of N `execute_instruction` calls when refreshing a device (N round-trips → 1). The agent is unchanged — each step is an ordinary command under one `bundle-…` correlation id; per-step `bundle.<plugin>.<action>` audit (`target_type=Agent`) mirrors REST, and collate enforces an ownership (IDOR) guard. Bundles are caller-polled, **not** in the executions drawer; v1 manifests are per-surface + in-memory (durable Postgres store is a committed follow-up — ADR-0011).
- 3 resources: `yuzu://server/health`, `yuzu://compliance/fleet`, `yuzu://audit/recent`
- 4 prompts: `fleet_overview`, `investigate_agent`, `compliance_report`, `audit_investigation`
- Settings UI section with enable/disable and read-only toggles

## Phase 2 (Planned)

- 5 remaining write tools: `set_tag`, `delete_tag`, `approve_request`, `reject_request`, `quarantine_device`
- Approval workflow re-dispatch (supervised tier execution after admin approval)
- SSE streaming for execution progress
