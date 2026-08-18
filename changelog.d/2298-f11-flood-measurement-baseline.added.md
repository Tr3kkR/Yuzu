- **Guardian Spark flood-measurement baseline.** The `guard.unhealthy` wire-message
  ceiling for a stuck-Unknown rule under Spark's errored-refresh backstop and
  priority-lane demotion is now a measured number, not an extrapolation: 1 edge +
  288 refreshes/rule/agent/day on the 60s-cadence lanes (service/registry), 1 edge +
  180/day on the 600s file lane (accounting for the scheduler's default +/-20%
  jitter), replacing a pre-fix ~17k/day estimate that predated both the edge-emission
  fix and the refresh/demotion backstop. The previously local-only measurement
  harness (a Windows resource sampler + a REST load generator) is now tracked under
  `docs/spark-rebuild-baselines/`. Spark stays dormant in every shipped build;
  nothing here changes runtime behavior.
