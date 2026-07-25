- MCP tool dispatch now fails closed on security-registration drift (#2383): a
  served tool missing its internal security-tier registration is denied at
  dispatch with a distinct misconfiguration error (logged, counted via
  `yuzu_mcp_tool_security_misconfig_total`, and audited) instead of silently
  skipping the generic tier + approval gate, and the server refuses to boot
  (fatal at construction, naming every offender) if the tool table, the
  security registrations, and the read-only write-tool set disagree — including
  duplicate registrations and any securable type or operation outside the
  closed RBAC catalogue, which would otherwise bypass its intended approval
  rule. Unknown tool names still return the standard "Unknown tool" error,
  untouched by the new gate.
