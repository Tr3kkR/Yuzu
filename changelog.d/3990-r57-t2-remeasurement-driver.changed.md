- **Guardian: `#3990` blackout diagnostic (`fullsync_blackout_diag.py`) re-measurement
  methodology (R5.7, rung 9c PR-6 item 2).** The clean-v2 pre-registered PASS on record was
  measured against a pre-rung-9c-PR-2 binary; on current `origin/dev` the driver's `T1_RE`
  no longer matches (`apply_rules ok` gained a `pending=` field) and Window B (`T1 - T0`) no
  longer brackets synchronous arm completion under the NonWaiting attach model. The driver now
  adds an application-fence protocol (new `T0D_RE`/`T2_RE` runtime log lines, epoch-identity
  membership, a two-class instrument-vs-genuine void taxonomy, `run_id`-scoped Phase B2 trigger
  ids closing a real trigger-ID-reuse trap, bounded functional-validity polling, and an offline
  `selftest` subcommand covering the fence logic end to end) and reports C = T2_last - T0 as the
  headline measurand, with B retained for continuity only. Requires the companion runtime
  instrumentation (`GuardianSparkRuntime::detach_all()`/`commit_new_generation_locked()`).
