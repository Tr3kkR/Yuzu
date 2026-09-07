- **Guardian: recorded the required legacy-vs-spark `full_sync` blackout-duration diagnostic
  for #3990** (ruling-13 on #3850). New committed instrument
  (`docs/spark-rebuild-baselines/fullsync_blackout_diag.py`) and run record
  (`docs/spark-rebuild-baselines/3990-fullsync-blackout-run.md`); `docs/spark-flip-gate.md` §5
  gained a `#3990` risk-accept entry. First attempt came back inconclusive, traced to the
  agent's `--log-file` sink having no flush policy (`main.cpp` never calls `flush_on`)
  interacting with the driver's polling timeout, not a system delay. A same-day re-run
  collected the intended sample counts numerically within the predeclared non-inferiority
  margin, but the pre-registered decision rule's functional-validity precondition was not met
  by any repeat (a driver bug - the precondition was computed but never gated on - compounded
  by a cohort-composition gap: 3 of 20 service-watch rules targeted services genuinely stopped
  on the rig, 2 more intermittently so), so that round's formal outcome was
  inconclusive/invalid by cohort design, not a pass. Both defects were then fixed (the wiring
  bug, and the 5 affected service targets replaced with ones confirmed stable) and the
  diagnostic re-run clean same day: Phase B median 70ms (legacy) vs 127ms (spark), Phase B2
  86ms vs 140ms, all 16 counted repeats independently satisfying the full pre-registered rule -
  a genuine PASS, within the predeclared non-inferiority margin. Raw per-repeat data for all
  three attempts committed alongside the run doc.
