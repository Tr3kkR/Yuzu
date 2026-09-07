- **Guardian: recorded the required legacy-vs-spark `full_sync` blackout-duration diagnostic
  for #3990** (ruling-13 on #3850). New committed instrument
  (`docs/spark-rebuild-baselines/fullsync_blackout_diag.py`) and run record
  (`docs/spark-rebuild-baselines/3990-fullsync-blackout-run.md`); `docs/spark-flip-gate.md` §5
  gained a `#3990` risk-accept entry. The intended backend comparison came back inconclusive,
  but the run surfaced a real, reproducible queueing/pile-up effect under closely-spaced
  `full_sync` triggers, affecting both backends similarly - recorded in the run doc.
