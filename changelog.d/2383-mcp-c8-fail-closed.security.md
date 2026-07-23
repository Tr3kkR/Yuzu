- MCP tool dispatch now fails closed on security-registration drift (#2383): a
  served tool missing its `kToolSecurity` row is denied at dispatch with a
  distinct misconfiguration error instead of silently skipping the generic
  tier + approval gate, and the server refuses to boot (fatal at construction)
  if the tool table, the security registrations, and the read-only write-tool
  set disagree — including registrations whose operation falls outside the
  closed RBAC operation catalogue, which would otherwise bypass their intended
  approval rule. Unknown tool names still return the standard "Unknown tool"
  error, untouched by the new gate.
