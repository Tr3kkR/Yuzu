- **Quarantine now actually blocks dispatch to a contained agent (#881).** An active
  quarantine record was bookkeeping only — nothing at the dispatch layer consulted it, so an
  operator/automation/background command still reached a quarantined device through every one
  of the six production dispatch sites, including the unfiltered `send_to_all_unfiltered` fast
  path that `command_dispatch_fn`'s system caller and `forward_legacy_command`'s Broadcast arm
  hit in production. Containment is now enforced at the single per-arm chokepoint `dispatch_confined_arms`
  (#1788's own seam) rather than per route, so a future dispatch surface inherits the gate instead
  of needing its own copy: every arm — Ids, Group, Scope, and Broadcast including the previously-
  unfiltered fast path — skips any id with an active quarantine record, after the existing
  visible-set intersection and before the send. The quarantine plugin's own control channel
  is exempted, without touching the store, so release/re-isolation can never be blocked by the
  containment they manage, including through a Postgres outage. The exemption is keyed on the
  `(plugin, action)` pair against the closed set the plugin declares today — `quarantine`,
  `unquarantine`, `status`, `whitelist` — not on the plugin name alone, so a fifth action added
  later arrives gated rather than silently inheriting a bypass. Every other dispatch reads `list_quarantined()` at most once per dispatch — never
  per agent — and serves a bounded-staleness (60s) last-known-good snapshot on a transient read
  failure rather than failing the whole fleet closed; a durably unavailable store, or a snapshot
  past that budget, fails closed as ADR-0012 §1 requires. Every denial is counted
  (`yuzu_server_dispatch_target_rejected_total{reason="quarantined"}`,
  `yuzu_server_quarantine_gate_total{outcome}`) and audited
  (`quarantine.dispatch_denied`) per agent up to a cap of 25 rows per dispatch, after which one
  summary row records how many were elided — a fail-closed denial, which covers the whole
  connected fleet at once, gets a single aggregate row instead. The counter moves by the true
  denial count in every shape, so the metric stays exact where the audit is deliberately bounded.
  `/api/command` now distinguishes its three ways of reaching zero — containment unreadable,
  every target quarantined, or genuinely nobody reachable — instead of answering all three as a
  transport failure, and reports `withheld_quarantined` on a partial dispatch.
  The `YuzuDispatchTargetRejected` alert now excludes `reason="quarantined"`: correct enforcement
  would otherwise fire it — one looping automation against a single contained host clears the
  `>3/15m` threshold, and a fail-closed episode increments by the whole connected fleet at once —
  and a rule that pages on correct behaviour gets silenced, taking the genuine #2500 near-miss
  signal with it. Quarantine denials keep their own evidence: the audit row per denial and the
  `yuzu_server_quarantine_gate_total{outcome}` series, whose `fail_closed` value is the one that
  warrants an alert.
