- **Guardian: pre-registered the R5.7 T2 re-measurement of the `#3990` blackout diagnostic**
  (rung 9c PR-6 item 2) before any rig time, per the diagnostic's own established discipline.
  Records the estimand (a commit-latency proxy, not end-to-end blackout), the primary measurand
  (C = T2_last - T0, replacing Window B's now-broken bracketing under the NonWaiting attach
  model), four pre-registered hypotheses, and a two-gate (reliability, then latency) acceptance
  criterion identical in shape to the existing clean-v2 result but evaluated on C. The prior
  clean-v2 PASS (measured on the waiting attach model) is preserved unedited; this is a
  separate, later section.
