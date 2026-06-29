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
- **Response-collection scope (`query_responses`) — #1634, PARTIAL.** A per-agent `check_scoped_permission` filter is applied to the returned rows, **but it is INERT under the current global `Response:Read` gate** — a holder of global `Response:Read` (the only principal that passes the gate) admits every agent, so no rows are dropped and a caller currently **does** see other operators' execution rows by id; a management-group-confined operator is 403'd at the gate before the filter runs. So this does **not** yet provide cross-operator isolation; its only active effect today is failing **closed** (zero rows) on a corrupt/load-failed `rbac.db`. Effective isolation needs the admit-then-filter gate change tracked in #1634. When a row IS dropped (the corrupt-store path), `query_responses` emits a **second** audit row `result=denied` (`detail` carries the distinct dropped-agent count) **in addition to** the `result=success` row — a SIEM rule must treat the two as a pair for one call (informational access-boundary evidence for CC6.1, not a failed call); under normal operation this `denied` row does not fire. RBAC-off → no filter (legacy-open). The result object carries `audit_persisted:false` if any of that call's audit rows could not persist, and `result_truncated_by_cap:true` if the raw query hit the row cap before filtering (incomplete page). *(The same inert per-agent filter + corrupt-store fail-closed now also covers `aggregate_responses`, REST `/executions/{id}/visualization` + `/api/responses/*`; the dashboard `/fragments/results` family and workflow execution-detail reader remain flat-`Response:Read` and **fail OPEN on a corrupt `rbac.db`** — all tracked in #1634.)*

## Error envelope

JSON-RPC error responses from the tier-denied paths (read-only mode, tier policy, approval-required) carry a structured `error.data` field (A4, per `docs/agentic-first-principle.md`):

```json
{ "correlation_id": "req-<hex-ms>-<hex-seq>", "retry_after_ms": null, "remediation": "use a higher-tier MCP token, or the REST API / dashboard" }
```

> **Supervised-tier / approval-gated operations.** An operation that requires
> approval is **denied** with `kTierDenied` (-32004), not `kApprovalRequired`
> (-32006). Approval re-dispatch is Phase 2 (below): there is no pollable
> approval to return, and the A4 contract reserves `kApprovalRequired` for the
> case where the envelope can carry `approval_id` + `status_url`. The denial's
> `remediation` points the caller at the REST API / dashboard, where the
> supervised tier's approval workflow is wired.

`correlation_id` is a per-error token (`req-<hex-ms>-<hex-seq>`, the same format as the REST `X-Correlation-Id` header) returned to the caller in the error body, so a client can cite a stable handle when reporting a failure. **It is not persisted to the audit log today** — the audit row for a denied call (`mcp.<tool>`) is written separately and does not carry the token — so server-side correlation relies on any `spdlog` line the handler emits at that moment, not on `audit.db`. `retry_after_ms` is `null` on tier/approval-denial errors (the denial is not retryable as-is); `remediation` carries an actionable hint — escalate to a higher-tier token, or use the REST API / dashboard. Per-tool validation errors (e.g. the dex-perf tools) populate `correlation_id`, a `null` `retry_after_ms`, and a field-specific `remediation`. Parse `error.code` for the error class and `error.data.correlation_id` for client-side traceability.

## Phase 1 (Implemented)

- Read-only tools (the **authoritative, complete table** is `docs/user-manual/mcp.md` — this list is illustrative, not a count): `list_agents`, `get_agent_details`, `query_audit_log`, `list_definitions`, `get_definition`, `query_responses`, `aggregate_responses`, `query_inventory`, `list_inventory_tables`, `get_agent_inventory`, `query_installed_software`, `get_tags`, `search_agents_by_tag`, `list_policies`, `get_compliance_summary`, `get_fleet_compliance`, `list_management_groups`, `get_execution_status`, `list_executions`, `list_schedules`, `validate_scope`, `preview_scope_targets`, `list_pending_approvals`, `get_guardian_schemas`, `list_dex_signals`, `get_dex_signal_scope`, `get_dex_signal_detail`, the DEX-perf + network tools, and `list_issued_certs`
  - **`query_installed_software`** is the typed daily-sync software-inventory read (ADR-0016), gated on `Inventory:Read` (with a per-agent management-group drop filter that is **not yet verified effective under the global gate — see ADR-0017 / #1716**) — distinct from the generic `query_inventory`/`get_agent_inventory` (generic blob store, `Infrastructure:Read`).
  - **DEX read tools (`list_dex_signals` / `get_dex_signal_scope` / `get_dex_signal_detail`)** are the MCP parity for the `/api/v1/dex/*` REST surface — same `GuaranteedStateStore` aggregations, gated on `GuaranteedState:Read`, with a `window` of `24h`/`7d`/`30d`/`all`. The audit boundary mirrors REST: the rollup and per-OS scope are fleet aggregates (only the generic `mcp.<tool>` tool-call audit), while `get_dex_signal_detail` returns a most-affected **devices** list (behavioral) and additionally emits a **`dex.signal.view`** audit (`target_type=ObsType`) so one SIEM filter catches the dashboard, REST and MCP behavioral-access surfaces alike. `obs_type` is validated against `[A-Za-z0-9._-]{1,64}` (malformed → `kInvalidParams`). When the `dex.signal.view` audit row cannot persist, `get_dex_signal_detail` **set-and-proceeds** and carries `audit_persisted:false` in the result (absent on success — consumers key on absence), matching the `query_responses` / `revoke_certificate` convention; JSON-RPC has no header channel, so this is the MCP equivalent of the REST `Sec-Audit-Failed` header (#1647). The REST `dex.signal.view` sibling instead fails closed — different surface, different posture.
- 2 write/execute tools: `execute_instruction` — dispatches plugin commands to agents (auto-approved for `operator` tier; `supervised` tier returns "not implemented"; if neither `scope` nor `agent_ids` is provided, targets all agents) — and `execute_bundle` (below).
- **Live-query bundle tools (`execute_bundle` / `get_bundle_result`)** — MCP parity for the `POST`/`GET /api/v1/bundles` REST surface (ADR-0011). `execute_bundle` (write/execute, `Execution:Execute`) fans one instruction into 1–32 plugin actions on **one** device via server-side async fan-out and returns `{execution_id, expected}` immediately; `get_bundle_result` (`Response:Read`) collates to `{complete, received, expected, steps[]}` in request order. Use instead of N `execute_instruction` calls when refreshing a device (N round-trips → 1). The agent is unchanged — each step is an ordinary command under one `bundle-…` correlation id; per-step `bundle.<plugin>.<action>` audit (`target_type=Agent`) mirrors REST, and collate enforces an ownership (IDOR) guard. Bundles are caller-polled, **not** in the executions drawer; v1 manifests are per-surface + in-memory (durable Postgres store is a committed follow-up — ADR-0011).
- 3 resources: `yuzu://server/health`, `yuzu://compliance/fleet`, `yuzu://audit/recent`
- 4 prompts: `fleet_overview`, `investigate_agent`, `compliance_report`, `audit_investigation`
- Settings UI section with enable/disable and read-only toggles

## Phase 2 (Planned)

- 5 remaining write tools: `set_tag`, `delete_tag`, `approve_request`, `reject_request`, `quarantine_device`
- Approval workflow re-dispatch (supervised tier execution after admin approval)
- SSE streaming for execution progress
