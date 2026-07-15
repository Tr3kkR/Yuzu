- **Weekly issue-tracker report + operator-run triage sweep (ADR-3001 pillar 5).** A new
  `tracker-report` workflow runs a weekly, **read-only, no-LLM** dashboard generator
  (`scripts/tracker/tracker_report.py`) that posts one comment to the `triage-sweep` tracking
  issue: telemetry keyed on the active backlog (`is:open -label:roadmap`), a leak scan (reusing the
  close workflow's single planning path, so it can never disagree with it), issue-standard §4
  label-hygiene invariants, duplicate candidates clustered by cited file path, and a
  closure-integrity sample. It closes, reopens, and relabels nothing, relays no user-authored text
  into the bot comment, and pins each report with a candidate-set hash. The workflow is dormant as a
  cron until it reaches `main`, pins `ref: dev` (a scheduled run otherwise checks out the default
  branch), and self-scopes its failure alert so it never collides with the close workflow's shared
  alert issue. Judgment stays human: the on-demand `/issue-triage` skill reads the latest dashboard
  and writes a reviewed `decisions.json` (held-open issues printed but never proposed; security/P0/P1
  closes capped at three per run and each requiring a typed `verified_gone_at` line; budget ten
  decisions per run). The only mutating layer, `scripts/tracker/apply_decisions.py`, applies that
  list **fail-closed**: it refuses the whole batch with zero mutations on any of seven rules
  (never-close-union member, unverified high-risk close, roadmap-in-judgment, cap, stale/breach,
  stale report), re-validates against live state immediately before every close (a two-layer
  validate-to-PATCH TOCTOU guard), refuses to run under a CI/bot token, posts a per-run ledger to the
  tracking issue **before** any close, and reverses an exact batch with `--revert` (each reopen gated
  on that run's own trusted marker). There is deliberately no autonomous closure tier. A deterministic
  zizmor guard fails any PR that deletes `tracker-report.yml`, moves it off its cron/dispatch trigger,
  or drops its `ref: dev` pin.
