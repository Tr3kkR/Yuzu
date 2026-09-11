- **REST v1 + MCP read twins for workflows, workflow-executions, the confined executions
  list/detail expansion, execution-scoped responses, and schedules** (api-parity programme,
  #2146/#4030). New routes: `GET /api/v1/workflows`, `GET /api/v1/workflows/{id}`,
  `GET /api/v1/workflow-executions/{id}` (record-level fleet-read confined — a caller with no
  visibility into an execution's target agents gets the same 404 as a nonexistent id, not a
  narrower-but-still-present record; a correction over the legacy route's plain permission check,
  which had no confinement of any kind), `GET /api/v1/executions` (a fleet-read-confined list
  route, matching the existing `list_executions` MCP tool rather than the dashboard fragment's
  weaker gate), `GET /api/v1/executions/{id}?include=agents` (per-agent status/duration + KPI
  expansion on the existing detail route), and `GET /api/v1/executions/{id}/responses` (mirrors
  MCP `query_responses`' `execution_id` filter; does not accept `offset` — the result set orders
  by a non-unique, actively-growing timestamp, so offset-based paging would silently skip or
  duplicate rows while an execution is non-terminal, matching `query_responses`' own posture).
  New MCP tools: `list_workflows`, `get_workflow`, `get_workflow_execution`. Widened MCP tool
  output: `list_executions` (definition name, agents_success/agents_failure split, error
  preview), `list_schedules` (execution_count), `get_execution_status` (`include:["agents"]`).
  REST and MCP share the same pure JSON row builders (`execution_model.{hpp,cpp}`,
  `workflow_model.{hpp,cpp}`) so the two surfaces cannot drift on JSON *shape* independently —
  this does not by itself guarantee the *admitted result set* matches between twins; `list_executions`'
  MCP confinement (own-dispatches-only) remains narrower than the REST route's
  visible-agent-or-owner admission, a pre-existing, disclosed (not silent) difference predating
  this PR.
