- **Guardian: R5.7 T2 re-measurement results for the `#3990` blackout diagnostic** (rung 9c
  PR-6 item 2), recorded against the current NonWaiting attach model
  (`origin/dev@f0f07d4d8`-merged build). Phase B (baseline re-deploy trigger) reached a
  pre-registered PASS: legacy C median 74.0ms vs spark 98.0ms, 5/5 valid both backends, zero
  voids. Phase B2 (bare rule-create trigger, `#3990`'s own literal shape) is INCONCLUSIVE:
  legacy reached its 3-repeat floor cleanly, spark reached only 2/3 across its full 10-attempt
  budget (8 instrument-invalid voids, zero genuine failures) - not relaxed post hoc. The prior
  `clean-v2` PASS (measured on the waiting attach model) stands unedited as its own record for
  that build; this is a separate, later result for the current model. Raw per-repeat data
  appended to `fullsync-blackout-results.jsonl` under `label="t2-v1"`.
