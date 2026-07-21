- Fleet-wide Prometheus rollup for the Guardian durable lifecycle-audit journal:
  the 22 `yuzu.guardian_journal_*` per-agent heartbeat counters (staging loss,
  persist, retention/quarantine, and replay integrity) now sum into unlabelled
  `yuzu_fleet_guardian_journal_*` gauges on every fleet-health sweep. Previously
  these integrity and loss signals existed only inside each endpoint's own
  heartbeat, so a lost lifecycle audit record was invisible to `/metrics` and to
  any evidence automation that scrapes it. The most important of them,
  `yuzu_fleet_guardian_journal_evicted_no_send_evidence`, counts journal batches
  that aged out with no evidence their records were ever transmitted - a CC7.3
  integrity gap.

  The families follow the fleet-rollup **absent-not-zero** convention: the agent
  emits a journal tag only when the counter is non-zero, so a healthy, quiescent,
  or inert fleet reports nothing and every family is absent rather than a
  fabricated `0` - a flatline zero on a loss counter would read as "checked,
  nothing lost" on a fleet whose journal is not even running. Values are
  hostile-input parsed (garbage, negative, overlong and implausible all mean "did
  not report", never `0`), so one rogue agent cannot poison a fleet gauge. Gauge
  names, tag keys and HELP text live in one table that also drives the metric
  registration, and a pin test binds that table to the agent's real emitter - with
  a `static_assert` that turns "added a journal counter but forgot its fleet
  gauge" into a build failure. See
  [metrics.md → Guardian journal fleet gauges](docs/user-manual/metrics.md).
