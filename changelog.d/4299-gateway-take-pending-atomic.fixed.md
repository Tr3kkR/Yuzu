- **Gateway pending-registration admission is now atomic (HA WS-4).**
  `yuzu_gw_registry:take_pending/1` was documented as an atomic retrieve-and-delete but was a
  non-atomic `ets:lookup` followed by a separate `ets:delete` on a `public` ETS table, and it is
  called directly from each per-stream `Subscribe` handler process. Two concurrent `Subscribe`s
  presenting the same session id could therefore both consume the one pending registration, each
  spawning an agent process and each emitting its own `CONNECTED` notification for that session — the
  stock agent's sequential connection loop never does this, but a non-stock or misbehaving client
  could, transiently losing its own route. It now uses `ets:take/2` (a single atomic
  retrieve-and-delete), so exactly one of N racing consumers wins; a new concurrent-barrier test pins
  the property.
