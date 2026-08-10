- **MCP streamed-POST admission: `reserve()`'s own server-wide record cap gets its own
  reject reason.** `McpStreamBridge::reserve()`'s internal `global_record_cap` check (256
  by default, bounding every progress-token-bearing bridge record server-wide — streamed
  or not) previously shared the `reason=post_global_cap` label with the unrelated
  pre-admission `StreamBudget` check, so `yuzu_mcp_stream_rejects_total{reason}` and the
  `mcp.session.reject` audit detail could not tell the two causes apart. It now emits its
  own `reason=post_record_cap`, pre-seeded on the counter alongside the other streamed-POST
  admission labels. `docs/mcp-server.md`'s admission table gains a row for this cause,
  distinct from the shared-budget row above it (#2918).
