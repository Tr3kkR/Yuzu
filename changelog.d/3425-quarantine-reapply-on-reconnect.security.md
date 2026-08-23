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
  the device is marked confirmed, and a previously-confirmed device whose live agent session
  changes (a reboot, a service restart) drops confirmation and re-verifies via `status` first
  rather than blindly re-applying. The trigger deliberately does NOT hook agent
  registration — the gRPC command stream is not yet established at that point, so a dispatch
  fired from there would be silently dropped; the heartbeat path fires after the stream
  exists. A system-initiated re-application is audited under its own verb, `quarantine.reapply`
  (`principal=system`), distinct from an operator-initiated `quarantine.enable`. The divergence
  itself is now visible even when re-dispatch keeps failing: `yuzu_server_quarantine_endpoint_unconfirmed{reachability}`
  (a per-replica gauge — never sum across instances) and the `YuzuQuarantineEndpointUnconfirmed`
  alert, which deliberately excludes `reachability="offline"` — a device quarantined while off
  is legitimately unconfirmed for its whole offline duration, and paging on that would be
  paging on correct behaviour. `yuzu_server_quarantine_reapply_total{result}` breaks down every
  outcome, including `busy` (the agent-side mutation gate, open PR #3429, answered `status|busy`
  — treated as in-progress, never a failure) and `rate_limited` (the per-agent claim mechanism
  that keeps a busy or offline device from spinning the reconciler). `QuarantineStore` gains
  schema v2 (`last_applied_at`/`last_confirmed_at`, both defaulting to 0/never) so confirmation
  state is queryable and survives a restart. `GET /api/v1/quarantine` and the MCP
  `quarantine_record` envelope now expose both fields.
