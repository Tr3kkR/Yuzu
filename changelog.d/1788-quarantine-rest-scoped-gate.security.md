- **`POST /api/v1/quarantine` and `DELETE /api/v1/quarantine/{agent_id}` now authorize per-target,
  matching their MCP `quarantine_device` twin (#1788).** Both routes previously gated on a single
  flat `Security:Execute` permission with no per-device check — a management-group-confined
  operator holding `Security:Execute` only through a group was refused with a 403 on every
  quarantine/release, even for devices inside their own group, while the identical caller was
  already admitted by the MCP tool. Both REST routes now authorize via the same per-target scoped
  gate the MCP twin uses: an in-scope operator succeeds (`201`/`200`), an out-of-scope operator is
  refused (`403`), and the gate fails **closed** (`500`) rather than falling back to the old global
  check if it is ever left unwired. `GET /api/v1/quarantine` is scoped the same way (admit-then-filter):
  the response now lists only quarantine records for devices the caller can see, instead of every
  quarantined device fleet-wide regardless of the caller's management-group membership.
