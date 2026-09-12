- **Security fix: `get_guardian_device_compliance` (MCP) and `GET /api/v1/guaranteed-state/device-compliance` (REST) now audit only after all reads complete (#2146).**
  Both surfaces previously emitted the `guardian.device.view` access audit row right after
  the first of four underlying reads (baseline lookup), so a degrade in any of the
  remaining three (`deployed_member_rule_ids`, `rule_names_for`,
  `agent_rule_statuses_for_agent`) could still surface a 503 the audit row had already
  called "success" - the same audit-timing defect class this PR fixed for the sibling
  `get_guardian_agent_status` tool via extraction, initially missed here. Both surfaces
  now share a new `guardian_device_compliance_rollup()` builder (`guardian_model.{hpp,cpp}`)
  that completes all four reads before returning, closing the gap on both transports and
  the REST/MCP duplication flagged in review at the same time.
