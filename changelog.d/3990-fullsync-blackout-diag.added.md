- **Guardian: recorded the required legacy-vs-spark `full_sync` blackout-duration diagnostic
  for #3990** (ruling-13 on #3850). New committed instrument
  (`docs/spark-rebuild-baselines/fullsync_blackout_diag.py`) and run record
  (`docs/spark-rebuild-baselines/3990-fullsync-blackout-run.md`); `docs/spark-flip-gate.md` §5
  gained a `#3990` risk-accept entry. The intended backend comparison came back inconclusive -
  neither backend reached the pre-registered sample floor - due to an unresolved bug in the
  new driver's own trigger-detection logic; every `full_sync` independently confirmed to have
  actually run completed in under 8.3 seconds on both backends, with no evidence of any slow
  or stalled trigger. Raw per-repeat data committed alongside the run doc.
