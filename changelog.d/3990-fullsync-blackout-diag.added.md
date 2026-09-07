- **Guardian: recorded the required legacy-vs-spark `full_sync` blackout-duration diagnostic
  for #3990** (ruling-13 on #3850). New committed instrument
  (`docs/spark-rebuild-baselines/fullsync_blackout_diag.py`) and run record
  (`docs/spark-rebuild-baselines/3990-fullsync-blackout-run.md`); `docs/spark-flip-gate.md` §5
  gained a `#3990` risk-accept entry. First attempt came back inconclusive, traced to the
  agent's `--log-file` sink having no flush policy (`main.cpp` never calls `flush_on`)
  interacting with the driver's polling timeout, not a system delay. After widening the
  timeout, a same-day re-run reached the pre-registered sample floor on both backends: Phase B
  median 53ms (legacy) vs 77ms (spark), Phase B2 median 66ms vs 74ms, both within the
  predeclared non-inferiority margin. Raw per-repeat data for both attempts committed
  alongside the run doc.
