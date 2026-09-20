- **Gateway-fronted agents no longer lose dispatchability after every circuit-recovery replay.**
  `ProxyRegister` previously replaced an adopted session's connection metadata with a fresh, empty
  one on every reconnect replay — even on a single, otherwise-healthy replica — silently making the
  agent unreachable via its gateway until it happened to reconnect. The server now decides
  adopt-vs-refuse before installing anything, converges placement via the gateway's own
  re-announcement, and refuses a genuinely stale/superseded replay outright rather than desyncing
  silently (HA WS-4 4.4, `#4246` #6). At fleet-reconnect-storm scale a re-announcement can itself be
  dropped under load; that case now self-heals within the existing route lease's TTL+grace window
  rather than persisting indefinitely, and is observable via a new drop counter — closing that window
  further is tracked as a follow-up.
