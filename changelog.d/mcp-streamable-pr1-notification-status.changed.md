- **MCP notification POSTs to `/mcp/v1/` now answer `HTTP 202 Accepted` (was `204 No Content`).**
  A JSON-RPC notification (a request with no `id`, e.g. `notifications/initialized`)
  returns `202` with an empty body, per the MCP Streamable HTTP spec — applied
  unconditionally (independent of the `--mcp-no-streaming` kill switch). Only a
  strict client that asserts the status is exactly `204` is affected; the
  reference clients (mcp-remote, Claude Desktop) are unaffected. `initialize`
  responses also gain an additive `Mcp-Session-Id` header (safely ignored by
  clients that don't use it) and now **negotiate** the protocol revision —
  echoing a supported client-requested `2025-03-26`/`2025-06-18` instead of
  always returning `2025-03-26` (legacy clients that request `2025-03-26` or
  nothing are unaffected). See `docs/user-manual/server-admin.md` § Upgrade
  Notes.
