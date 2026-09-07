- **HA: background-job replica-safety classification + the last #2508 clock guards (ADR-2002 WS-10,
  slices 10.1/10.2).** Every server background pass is now classified for replica-safety in a
  checked-in, CI-auditable table (`server/core/src/background_jobs.hpp`) — ReplicaSafe /
  FencedLeaderOnly / DisabledUntilFixed, one entry per *pass* (a single thread runs many), each with
  its single-writer rationale; a `consteval` site-gate makes an unclassified pass a build failure, and
  a table test pins consistency + completeness. Enabling a second replica needs this so a background
  job cannot silently double-run. Separately, the three remaining bare wall-clock retention deletes
  (`app_perf_fleet_store`, `preflight_run_store`, `deployment_run_store`, #2508) and the
  `concurrency_claims` stale-claim reconciler are now clock-guarded and **SINGLE-WRITER-safe** — the
  three prunes via one shared `pg::run_clock_guarded_prune` helper (the full seven-part guard + a
  `pg_try_advisory_xact_lock`, reading Postgres `now()` in-SQL), the reconciler via the same advisory
  lock. No operator-visible behaviour change; this is HA-foundation hardening (see
  `docs/ha-background-jobs.md`, `docs/clock-guarded-retention.md`). Fenced-leader-only *enforcement*
  (gating those passes on the leader) lands with WS-3 3.2.
