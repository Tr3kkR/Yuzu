- Fleet-wide Prometheus rollup for the Guardian durable lifecycle-audit journal:
  the 22 `yuzu.guardian_journal_*` per-agent heartbeat counters (staging loss,
  persist, retention/quarantine, and replay integrity) now sum into unlabelled
  `yuzu_fleet_guardian_journal_*` gauges on every fleet-health sweep. Previously
  these integrity and loss signals existed only inside each endpoint's own
  heartbeat, so a lost lifecycle audit record was invisible to `/metrics` and to
  any evidence automation that scrapes it. The most important of them,
  `yuzu_fleet_guardian_journal_evicted_no_send_evidence`, counts journal batches
  that aged out with no evidence their records were ever transmitted - a potential
  CC7.3 integrity gap (the classification is best-effort, so a rise suggests loss
  rather than establishing it).

  The families follow the fleet-rollup **absent-not-zero** convention: the agent
  emits a journal tag only when the counter is non-zero, and the server publishes a
  family only if some retained agent reported it, so an absent family means "no
  retained agent currently reports a non-zero value" rather than a fabricated `0`.
  A flatline zero would read as "checked, nothing lost" when nothing was checked. Values are
  hostile-input parsed (garbage, negative, overlong and implausible all mean "did
  not report", never `0`), so no single agent can destroy a fleet sum with an
  overflowing or implausible magnitude. A forged-but-plausible value from an
  enrolled agent still sets the gauge - that is inside the heartbeat trust
  boundary, which is why the shipped alert templates stay warning-grade. Gauge
  names, tag keys and HELP text live in one table that also drives the metric
  registration, and a pin test binds that table to the agent's real emitter - with
  a test-build `static_assert` that turns "added a journal counter but forgot
  its fleet gauge" into a compile error.

  Two meta-signals sit outside that table and publish on every sweep **including
  at zero**: `yuzu_fleet_guardian_journal_reporting` (the coverage denominator -
  `0` while agents are connected means either the telemetry path is dark or
  nothing has been journalled anywhere since restart; note neither meta-signal
  detects a stalled sweep, since they are never cleared and retain their last
  value) and `..._tag_rejected` (values
  that failed the forged-value parse, which would otherwise be a silent drop). No
  alert rules are enabled: no sound alerting form exists over an unlabelled fleet
  sum of per-agent cumulative counters that can distinguish a new increment from a
  returning agent, so the reviewed group in
  `docs/prometheus/yuzu-alerts.yml` ships commented out and the 22 counters are
  monitor-only. See
  [metrics.md → Guardian journal fleet gauges](docs/user-manual/metrics.md).
