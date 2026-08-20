- **The MCP progress bridge now coalesces `notifications/progress` to a single
  latest-wins snapshot per drain, instead of queuing every event in a 16-slot
  ring.** `progress` counts are monotone, so only the newest snapshot at drain
  time was ever useful to a client; queuing every intervening event cost an
  allocation per bus event (even ones the old ring immediately dropped under
  fast-producer pressure) and, on a large fan-out, could emit many redundant
  `notifications/progress` frames for one execution. The listener now assigns
  each new snapshot into a reusable buffer and swaps it into a single
  per-record slot (allocation-free once the buffer reaches its steady-state
  payload size); the projector swaps the slot out to extract. A snapshot
  overwritten before the projector ever sees it now counts in the existing
  `yuzu_mcp_bridge_progress_suppressed_total` (#2438) alongside H1's
  monotonic-progress suppressions - both are "a progress candidate that never
  reached the wire". `yuzu_mcp_bridge_mailbox_drops_total` is retired (kept
  registered at zero for scrape/dashboard continuity): there is no longer a
  bounded ring to drop from. No change to the wire contract itself - progress
  is still fire-and-forget and still strictly increasing where it does reach
  the wire (H1 unaffected). (#2412)
