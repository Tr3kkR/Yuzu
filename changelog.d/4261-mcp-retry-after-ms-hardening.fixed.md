- **MCP tools and their REST twins now carry honest `retry_after_ms` hints on
  transient store/query faults.** Found via a #2146 Batch A audit: 23
  confirmed store/query-fault branches across the executions/workflows,
  product-packs/definitions, and Guardian read-twin batches (plus two
  pre-existing, non-Batch-A instruction tools) — mostly one transport
  correctly signalled a backoff hint on a degraded-store condition while its
  twin's matching branch silently didn't (REST-correct/MCP-missing for most
  of the batch; MCP-correct/REST-missing for the pre-flight/deploy reads and
  5 Guardian REST routes found in a second audit pass, one of them the true
  `get_guardian_device_guards` twin — `GET
  /api/v1/guaranteed-state/agents/{agent_id}/rules` — and two more on the
  untwinned `GET /api/v1/guaranteed-state/status/{agent_id}` rollup, fixed
  for domain consistency even though it has no MCP counterpart), but for the
  product-packs/definitions group neither side had it. Also bounds
  `list_guardian_events`'s previously-unbounded `rule_id`/`severity` input
  fields. A new CI gate, `scripts/ci/check-mcp-retry-hints.py`, now fails a
  PR that adds an MCP tool with an unexempted store/query-fault branch
  missing this hint, and fails closed if it cannot read the target file at
  all.
