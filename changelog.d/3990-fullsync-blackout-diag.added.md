- **Guardian: recorded the required legacy-vs-spark `full_sync` blackout-duration diagnostic
  for #3990** (ruling-13 on #3850). New committed instrument
  (`docs/spark-rebuild-baselines/fullsync_blackout_diag.py`) and run record
  (`docs/spark-rebuild-baselines/3990-fullsync-blackout-run.md`); `docs/spark-flip-gate.md` §5
  gained a `#3990` risk-accept entry. First attempt came back inconclusive, traced to the
  agent's `--log-file` sink having no flush policy (`main.cpp` never calls `flush_on`)
  interacting with the driver's polling timeout, not a system delay. After widening the
  timeout, a same-day re-run collected the intended sample counts: Phase B median 53ms
  (legacy) vs 77ms (spark), Phase B2 median 66ms vs 74ms - numerically within the predeclared
  non-inferiority margin, BUT the pre-registered decision rule's functional-validity
  precondition was not met by any repeat (a cohort-composition gap, 3 of 20 service-watch
  rules target services genuinely stopped on the rig, 2 more intermittently so), so the FORMAL
  outcome remains inconclusive/invalid by cohort design, not a pass. Raw per-repeat data for
  both attempts committed alongside the run doc.
