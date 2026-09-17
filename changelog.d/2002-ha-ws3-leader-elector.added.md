- **HA: fenced leader-election primitive (ADR-2002 §3/§6/§10, WS-3 slice 3.1).** Added a
  Postgres-backed `LeaderElector` — the coordination primitive that will let exactly one core replica
  run the singleton background loops (schedule tick, policy remediation, reconcilers) once a second
  server replica is enabled. It owns a dedicated, never-recycled connection holding a session advisory
  lock, and mints a strictly-monotonic **epoch** on each acquisition (recorded in a new
  `leader_elector.leader_state` table); a side-effecting claim fences on that epoch so a paused
  ex-leader whose lock silently moved cannot commit. This slice ships the primitive and its schema
  **only** — no background loop is wired to it yet, so there is no runtime behaviour change; gating the
  loops (3.2) and the transactional command outbox (3.3/3.4) follow. Enabling a second replica remains
  gated on the full WS-3 stack landing (see the HA delivery matrix).
