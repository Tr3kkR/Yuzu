- **A CI gate now measures the audit-retention alert family's actual restart-cadence
  coverage, not just that the rules parse.** `tests/prometheus/blind_band_sweep.py`
  (previously a hand-run measurement instrument, not wired into CI) now runs
  `--check` in the `Prometheus alert rules` job on every PR, comparing a fresh sweep
  against the committed `tests/prometheus/blind_band_manifest.json`. The property
  measured inverted from "the alert stays silent for a dead reaper" to "the alert
  stays continuously firing for a dead reaper" — a rule that fires intermittently
  (the auto-resolve hole) now shows up as uncovered too, not just a rule that never
  fires at all. A PR that changes `docs/prometheus/yuzu-alerts.yml`'s audit-retention
  rules and widens or narrows that coverage will see this check redden; re-run
  `python3 tests/prometheus/blind_band_sweep.py --emit` and commit the regenerated
  manifest alongside the rule change. (#2854)
