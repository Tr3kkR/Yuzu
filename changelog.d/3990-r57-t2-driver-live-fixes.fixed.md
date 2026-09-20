- **Guardian: two `#3990` R5.7 driver bugs found live during the actual DGRHP re-measurement
  run (rung 9c PR-6 item 2), fixed same session.** (1) `GuardianEngine::wire_spark_engine()`
  returns before constructing `spark_runtime_` when `--spark-disable` is set, so
  `detach_all()`'s T0d line never fires under legacy - the driver now synthesizes `t0d = t0`
  for legacy instead of waiting on a line that can never appear (legacy never needed the
  epoch fence anyway: its arms are synchronous on the same thread as T0/T1, with no
  stale-prior-application race to guard against). (2) `build_verdict_lines()` grouped rows by
  `(comparison_id, run_id, label, phase)`, but legacy and spark are separate `cmd_run()`
  invocations with different `run_id`s by construction, so the two backends could never be
  paired for a comparison - every verdict silently read INCONCLUSIVE regardless of how much
  valid data existed. Fixed to pair on `(comparison_id, label, phase)` only. Selftest fixture
  F12 extended to cover cross-`run_id` pairing explicitly.
