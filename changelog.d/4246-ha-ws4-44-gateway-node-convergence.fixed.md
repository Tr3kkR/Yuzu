- **Gateway-fronted agents no longer lose dispatchability after every circuit-recovery replay.**
  `ProxyRegister` previously replaced an adopted session's connection metadata with a fresh, empty
  one on every reconnect replay — even on a single, otherwise-healthy replica — silently making the
  agent unreachable via its gateway until it happened to reconnect. The server now decides
  adopt-vs-refuse before installing anything, and a genuinely stale/superseded replay is refused
  outright and forces the agent to reconnect fresh instead of desyncing silently (HA WS-4 4.4,
  `#4246` #6).
