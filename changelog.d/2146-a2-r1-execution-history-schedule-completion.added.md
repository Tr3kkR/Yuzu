- **Execution child-query REST v1 + MCP twins, `get_execution_status` field parity, and
  `list_schedules`/`GET /api/v1/schedules` filters** (api-parity programme, #2146 A2-R1). New
  route `GET /api/v1/executions/{id}/children` and new MCP tool `get_execution_children` twin the
  legacy `GET /api/executions/{id}/children` — same `Execution:Read` fleet-read gate, same #3789
  confinement rule (a visible parent does not by itself disclose a child dispatched by, or
  targeting, someone else; each child is checked independently, one batched per-child status
  lookup rather than N+1), and a new shared `execution_child_row_json` builder
  (`execution_model.{hpp,cpp}`) all three surfaces — REST v1, the legacy route, and MCP — now call,
  so the row shape cannot drift between them. `get_execution_status`'s output gains
  `parameter_values` (redacted to `"(redacted - confined view)"` for a confined caller, exactly
  like `scope_expression` already was) plus `completed_at`/`parent_id`/`rerun_of`, which stay
  truthful for every caller — closing a field-parity gap against the REST v1 detail route
  (`GET /api/v1/executions/{id}`), which already returned all four. `GET /api/v1/schedules` and
  MCP `list_schedules` gain optional `definition_id`/`enabled_only` filters, threaded into the
  same `ScheduleQuery` the legacy `GET /api/schedules` route already populates.
