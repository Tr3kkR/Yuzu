- **MCP Streamable HTTP transport — session lifecycle (ADR-1005 Decision 15, track 2f, PR 1).**
  The `/mcp/v1/` endpoint now mints a principal-bound `Mcp-Session-Id` on
  `initialize` (a ≥128-bit CSPRNG value; never required — plain-POST clients are
  unaffected), validates it when presented (unknown/expired/foreign → `404`, the
  client re-initializes), and supports `DELETE /mcp/v1/` to end a session. Every
  method now validates the `Origin` header against a configured allowlist
  (`--mcp-allowed-origin`, repeatable; absent Origin is allowed on this
  credential-gated endpoint, an empty allowlist rejects any present Origin) and
  the `MCP-Protocol-Version` header (supported: `2025-03-26`, `2025-06-18`).
  Sessions are in-memory and bounded (idle TTL, per-principal and global caps
  that reject rather than evict a live session); a server restart drops them and
  the client re-initializes, per spec. Session open/close and every denial
  (origin, unknown session, cap) are audited (`mcp.session.open` / `.close` /
  `.reject`). A `--mcp-no-streaming` kill switch disables the transport (no
  minting; `GET`/`DELETE` → `405`; plain JSON-RPC POST only). `GET /mcp/v1/` is a
  `405` placeholder in this rung (the SSE channel and progress bridge follow in
  2f PR 2/3).
