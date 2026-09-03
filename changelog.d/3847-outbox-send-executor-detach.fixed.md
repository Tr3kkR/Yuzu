- Agent: **Lands dormant — no deployment setting to review.** Guardian does not route
  detection through Spark in any shipped build, and this change ships no user-facing
  behavior. The drain worker that ships Guardian compliance, health, and lifecycle-audit
  events to the server no longer blocks its own journal-maintenance work behind a stalled
  send. Previously, a sink that stopped responding — a half-open TCP connection, for
  example — could wedge the worker's retention and replay-paging cadence for as long as
  the stall lasted. The send now runs on its own bounded, detached worker with a per-lane
  slot (one for lifecycle events, one for compliance/health events, so a slow lifecycle
  send cannot silently delay compliance/health delivery either), covered by the same
  orphan-exit shutdown contract already used for Guardian's other detached background
  work. `prefer_spark` (the same switch the Guardian journal entries in this release refer
  to) is a compile-time default that cannot be changed without a rebuild, so the existing
  detection path is unaffected. (#3847, #2233 item 4)
