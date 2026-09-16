- **A rare mutex fault inside the MCP progress-bridge's teardown could crash the
  whole server process; it is now contained.** `teardown_claimed` had four
  `rec->mu` lock acquisitions not wrapped in the function's own exception
  containment, unlike every other step in the same function — a lock failure
  there (the same modelled mutex fault this subsystem already treats as
  reachable under severe platform trouble) escaped its `noexcept` boundary and
  terminated the process, taking down every client's connections, not just the
  one record being torn down. All four sites are now contained, each with
  behavior appropriate to what it was doing: the earliest one leaves the
  record's bookkeeping untouched (this attempt is treated as never having
  happened) rather than risk continuing on unknown state.
- **`yuzu_mcp_bridge_progress_suppressed_total` (#2438) is now properly
  registered.** It previously had no `/metrics` HELP text and would not appear
  in a scrape until the first suppression event, unlike every sibling counter.
