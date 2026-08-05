# Runbook: MCP replay-ring pin displacement / unpinned final

**Alerts:** `YuzuMcpStreamPinDisplaced`, `YuzuMcpStreamFinalUnpinned`
**Severity:** warning. **This is not a page and needs no remediation.** No data is
lost, no restart helps, and clients recover on their own — the alert exists so the
underlying accounting bug gets filed, not so anyone intervenes.

## What has happened

Every streamed MCP request's final response frame is committed to the session's replay
ring and **pinned** (exempt from ring eviction) so a client that reconnects late can
still resume it. The bridge admits streamed requests against the same per-session cap
the pin-slot array is sized to, so the slots can never legitimately fill.

- `yuzu_mcp_stream_pin_displaced_total` moving means a session filled every slot
  anyway — the admission count and the pin count have drifted apart. The server
  degrades gracefully: the **oldest** pinned terminal (likeliest already consumed)
  yields its exemption to the newest. The displaced final stays committed and
  delivered; it merely becomes evictable if the ring wraps before its client resumes.
- `yuzu_mcp_stream_final_unpinned_total` moving means a final was committed with no
  pin at all. That is structurally unreachable while the slot array is non-empty, so
  it indicates the displacement path was bypassed or the array was sized to zero —
  a worse variant of the same accounting drift.

## Client impact

Worst case, a client resuming a displaced-and-since-evicted terminal gets its session
terminated with a coherent `404`, re-initializes, and fetches the result durably by
`execution_id` — the standard eviction ladder, no silent gap. Most of the time there
is no client impact at all.

## What to do

1. Capture the stream metric family (`yuzu_mcp_stream_*`, `yuzu_mcp_bridge_*`) and
   any `mcp.stream.attach` / `mcp.stream.close` audit rows around the increment.
2. File a bug titled "MCP streamed-POST admission accounting drift" with that
   capture. The interesting question is how `pinned_count() + unpinned` and the
   admission cap disagreed.
3. Do **not** restart the server for this: the counters are cumulative diagnostics,
   the degraded behavior is self-limiting, and a restart destroys the in-memory
   session state you would want to inspect.
