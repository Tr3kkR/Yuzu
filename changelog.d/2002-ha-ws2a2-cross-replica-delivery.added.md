- **HA: cross-replica execution-event delivery (ADR-2002 §5, WS-2a-2).** The durable
  `event_outbox` (WS-2a-1) is now drained cross-replica: each server replica runs a ~2s poll that
  re-publishes execution-history events (`agent-transition` / `execution-progress` /
  `execution-completed`) which originated on *other* replicas onto its own live SSE bus, so a
  subscriber connected to one replica sees live execution progress driven from any replica. The
  poll cursors on a Postgres commit-settle horizon (`w_xid < pg_snapshot_xmin(pg_current_snapshot())`)
  so its live forward delivery never straddles an in-flight event, skips the replica's own
  already-published rows, and is at-least-once (duplicates tolerated). New metric
  `yuzu_exec_outbox_poll_published_total`. The live SSE `id:` remains the reconnect-safe per-channel
  counter (unchanged) — the durable global `event_outbox.event_id` is kept in the outbox for the
  cross-replica poll cursor and for the later durable failover-replay slice, deliberately NOT put on
  the live bus (that would let a commit-order inversion strand a committed event from a cursor-based
  subscriber). Single-replica deployments are unaffected (the poll finds nothing foreign to deliver).
  Loss-free reconnect across replicas (durable outbox replay ordered by `event_id`) is a WS-2a-2
  follow-up and a precondition for enabling a second replica.
