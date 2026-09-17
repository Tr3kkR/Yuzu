- **A failed MCP progress-bridge teardown is now retried instead of being retained until
  the next process restart.** `teardown_claimed`'s per-step containment previously bailed
  permanently on the first failure of any of its three steps (bus unsubscribe, releasing
  the streamed admission charge, erasing the correlation record), stranding a record — and
  the bus channel, replay buffer, and per-session admission slot it held — for the rest of
  the process's life on a fault that is transient by nature (a broken platform mutex). A
  record now gets up to `Config::teardown_retry_max` retries beyond its first attempt (4
  total attempts by default), each on a later sweep tick. New
  `yuzu_mcp_bridge_teardown_retry_total{outcome=recovered|exhausted}` and the
  `mcp.bridge.teardown_retry` audit action; new alert `YuzuMcpBridgeTeardownRetryExhausted`
  is now the actual permanent-retention signal, and the existing
  `YuzuMcpBridgeTeardownIncomplete` alert is windowed rather than a raw counter test, since
  most of its movement now recovers on its own. See
  `docs/ops-runbooks/mcp-bridge-teardown-recovery.md` for the updated remediation guidance.
  (#2513)
