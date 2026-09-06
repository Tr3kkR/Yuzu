- **REST v1 + MCP read twins for workflows, workflow-executions, the confined executions
  list/detail expansion, execution-scoped responses, and schedules** (api-parity programme,
  #2146/#4030). New routes: `GET /api/v1/workflows`, `GET /api/v1/workflows/{id}`,
  `GET /api/v1/workflow-executions/{id}` (fleet-read confined — a correction over the legacy
  route's plain permission check), `GET /api/v1/executions` (a fleet-read-confined list route,
  matching the existing `list_executions` MCP tool rather than the dashboard fragment's weaker
  gate), `GET /api/v1/executions/{id}?include=agents` (per-agent status/duration + KPI
  expansion on the existing detail route), and `GET /api/v1/executions/{id}/responses` (mirrors
  MCP `query_responses`' `execution_id` filter). New MCP tools: `list_workflows`, `get_workflow`,
  `get_workflow_execution`. Widened MCP tool output: `list_executions` (definition name,
  agents_success/agents_failure split, error preview), `list_schedules` (execution_count),
  `get_execution_status` (`include:["agents"]`). REST and MCP share the same pure JSON row
  builders (`execution_model.{hpp,cpp}`, `workflow_model.{hpp,cpp}`) so the two surfaces cannot
  drift independently.
- **RBAC seeding fix (prerequisite):** `Workflow` was used as an RBAC securable throughout
  `workflow_routes.cpp` but was never seeded into `RbacStore`'s securable-types catalogue or its
  MCP mirror — meaning no role, including Administrator, could be granted `Workflow:Read` while
  RBAC was enabled. Seeded, with `Read` granted to Administrator (via the standard CRUD seed),
  PlatformEngineer, Operator, ITServiceOwner, and Viewer (the same footprint `Schedule:Read`
  already has). Scoped to `Workflow` only — the identical `ProductPack`/`Directory` gap is fixed
  independently by #4029/#4031.
