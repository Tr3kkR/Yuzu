- **A device quarantined while offline now re-contains itself automatically on reconnect
  (#3425).** After #881/#3127, a device quarantined while off ended up contained at the
  control plane (the dispatch gate refused every command to it) but NOT at its own firewall
  — nothing consulted containment state on reconnect, so the endpoint stayed unfirewalled
  until an operator noticed and manually re-issued the quarantine. `QuarantineContainmentReconciler`
  closes that gap: a heartbeat from a device with an active-but-unconfirmed record (the fast
  path) or a periodic ~20s tick (the backstop, for anything the heartbeat path missed)
  re-drives the **stored** whitelist — never a fresh or caller-supplied one, the same #3127
  rule — through the same recipe MCP's `quarantine_device` already_active retry path uses
  (now extracted into a shared chokepoint, `quarantine_reapply.hpp`, so both callers share one
  copy of the stored-whitelist-only invariant). Dispatch acceptance alone is not treated as
  proof of containment: a follow-up `quarantine.status` read must report `state|active` before
  the device is marked confirmed, and a previously-confirmed device re-verifies on either of two
  independent signals: its live agent session changes (a reboot, a service restart — re-verifies
  via `status` first, rather than blindly re-applying), or its active record is replaced
  (released, then requarantined, possibly with a different whitelist, while the agent stayed
  connected the whole time — resets straight to a fresh apply instead, since a status read would
  prove nothing about whether the NEW record's whitelist was ever applied). A confirm is also
  checked against the session that was live when the
  verifying status dispatch was actually sent, not just whichever session is live at confirm
  time, closing a narrow reboot window in between. The trigger deliberately does NOT hook agent
  registration — the gRPC command stream is not yet established at that point, so a dispatch
  fired from there would be silently dropped; the heartbeat path fires after the stream
  exists. A system-initiated re-application is audited under its own verb, `quarantine.reapply`
  (`principal=system`), distinct from an operator-initiated `quarantine.enable`. The divergence
  itself is now visible even when re-dispatch keeps failing: `yuzu_server_quarantine_endpoint_unconfirmed{reachability}`
  (a per-replica gauge — never sum across instances) and the `YuzuQuarantineEndpointUnconfirmed`
  alert, which deliberately excludes `reachability="offline"` — a device quarantined while off
  is legitimately unconfirmed for its whole offline duration, and paging on that would be
  paging on correct behaviour. `yuzu_server_quarantine_reapply_total{result}` breaks down every
  outcome, including `busy` (the agent-side mutation gate, #3429, answered `status|busy`
  — treated as in-progress, never a failure) and `rate_limited` (the per-agent claim mechanism
  that keeps a busy or offline device from spinning the reconciler). `QuarantineStore` gains
  schema v2 (`last_applied_at`/`last_confirmed_at`, both defaulting to 0/never) so confirmation
  state is queryable and survives a restart. `GET /api/v1/quarantine` and the MCP
  `quarantine_record` envelope now expose both fields. A sustained `response_store` outage
  while a dispatched command's response is being polled now escalates backoff like every
  other repeated-failure path in the reconciler's state machine, instead of retrying at a
  flat ~60s cadence for as long as the outage lasts. `yuzu_server_quarantine_reconciler_tick_healthy`
  is a new gauge distinguishing "the reconciler's last periodic tick reached its normal
  publish" (however many or few records it found — including zero) from "the last tick
  couldn't check" — `yuzu_server_quarantine_endpoint_unconfirmed` silently freezes at its last
  value during a sustained `quarantine_store` outage, and this is the freshness signal that
  catches it.

- **BREAKING — `POST /api/v1/quarantine` now validates `whitelist` at write time (#3425).**
  Previously this route wrote the field unchecked, regardless of shape — a malformed value
  (a CIDR range, a hostname, anything outside `[0-9A-Fa-f.:]`) was recorded successfully and
  only ever discovered later, as a repeating `validation_failed` outcome on every subsequent
  reconciler tick, never surfaced to the caller. It is now validated against the same rule
  MCP's `quarantine_device` already enforced (≤512 characters total, each comma-separated
  token ≤45 characters, `[0-9A-Fa-f.:]` only) and rejected with `400` instead of written. Any
  caller relying on this route's historical permissiveness for CIDR or hostname whitelist
  entries will now receive `400` on a call that previously returned `201` — and, because this
  route only ever creates a NEW record (rejected with 400 if the device is already
  quarantined), a caller that ignores the `400` gets no containment at all for that device,
  where previously a malformed-but-persisted record still left it denied at the #881
  control-plane dispatch gate even though its endpoint firewall could never be enforced. An
  already-quarantined device is unaffected either way — this route can't mutate an existing
  record's whitelist, so no in-place containment is ever lost by this change.
