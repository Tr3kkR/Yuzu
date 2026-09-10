- **MCP tools now carry honest `retry_after_ms` hints on transient store/query
  faults, matching their REST twins.** Found via a #2146 Batch A audit: 13
  confirmed cases across the executions/workflows, product-packs/definitions,
  and Guardian read-twin batches where the REST route correctly signalled a
  backoff hint on a degraded-store condition and the MCP twin's matching
  branch silently didn't (and, for the pre-flight/deploy read twins, the
  reverse — REST was missing what its own MCP twin already had). Also bounds
  `list_guardian_events`'s previously-unbounded `rule_id`/`severity` input
  fields. A new CI gate, `scripts/ci/check-mcp-retry-hints.py`, now fails a
  PR that adds an MCP tool with an unexempted store/query-fault branch
  missing this hint.
