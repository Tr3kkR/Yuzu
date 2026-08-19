- **New `yuzu_mcp_bridge_progress_suppressed_total` counter for the MCP progress bridge.**
  Counts `notifications/progress` frames dropped by the H1 monotonic-progress rule (a
  duplicate or momentarily-decreasing snapshot from the bus, never forwarded to the
  client). Previously this suppression was correct but invisible — only a unit test would
  have caught a regression that stopped suppressing. (#2438)
