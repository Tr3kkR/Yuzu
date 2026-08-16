- MCP `tools/call` now audits an unknown tool name with `result="denied"` instead of
  `result="failure"` (#2445), matching every other client-caused rejection on the
  surface (tier, read-only, schema, input-bounds, per-submitter-cap denials); `failure`
  stays reserved for server-side faults like the tool-security misconfiguration branch.
  SIEM rules that split `denied`-vs-`failure` traffic on `mcp.*` should re-classify this
  row.
