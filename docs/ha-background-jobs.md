# Background-job replica-safety (WS-10)

ADR-2002 §Decomposition item 10. Active-active means every background pass must be
safe to run on more than one core replica. This is the operator/reviewer-facing
companion to the **authoritative source of truth**, which is code:
`server/core/src/background_jobs.hpp` (`kBackgroundJobs`). If this doc and the
table disagree, the table wins.

## The three classes

- **ReplicaSafe** — correct to run on every replica at once: read-only/local,
  idempotent, an execute-once CAS, or an advisory-lock SINGLE-WRITER retention
  pass. Some ReplicaSafe passes MUST run per-replica and must never be
  leader-gated — the event-outbox poll (`poll_event_outbox_once`) is the reference
  case (ADR-2002 §5: every replica polls its own bus, or non-leader SSE goes dark).
- **FencedLeaderOnly** — side-effecting singleton work that double-fires across
  replicas (agent dispatch: schedule tick, policy remediation, quarantine
  reconcile; CRL numbering). Runs only on the WS-3 fenced leader. *Enforcement is
  WS-10 slice 10.3, which rides WS-3 3.2 — the classification exists now; the
  leader-gate wiring lands with the leader.*
- **DisabledUntilFixed** — not yet replica-safe and not yet leader-gated; must not
  run per-replica until its named fix lands (today: `nvd_sync.do_sync`, pending
  its engine-tier migration, ADR-1005 Phase 7).

## The unit is the PASS, not the thread

One thread multiplexes many passes of different classes — `result_set_maint_thread_`
runs 11 (the per-replica poll, several advisory-locked reaps, gauge refreshes),
`health_recompute_thread_` ~9 (read-only gauges, a fleet-wide CRL re-publish, a
per-replica stream teardown). Classifying a thread wholesale would falsely certify
an unsafe pass riding a mostly-safe thread, so each `kBackgroundJobs` entry is one
unit of work.

## How "nothing silently escapes"

- `kBackgroundJobs` is the checked-in, git-auditable, CI-compiled inventory.
- Each catastrophic-class pass dispatch site carries `YUZU_ASSERT_BACKGROUND_JOB(...)`
  — a `consteval` lookup that makes an unclassified pass a **build failure** (the
  `command_capability.hpp` ExecuteGate precedent).
- `tests/unit/server/test_background_jobs.cpp` pins internal consistency,
  completeness (a count tripwire), and the load-bearing per-pass classes.
- Adding a background pass is therefore a diff against `kBackgroundJobs` plus the
  routed-concern review (`cpp-safety` + `sre` + `compliance-officer`), never a
  silent addition.

## Clock-guarded retention (the #2508 residue, WS-10 10.2)

The three formerly-bare wall-clock prunes — `app_perf_fleet_store`,
`preflight_run_store`, `deployment_run_store` — now run through the shared
`pg::run_clock_guarded_prune` helper (`server/core/src/pg/pg_retention_guard.hpp`):
the full seven-part clock guard + a `pg_try_advisory_xact_lock` making it
SINGLE-WRITER-safe, reading Postgres `now()` in-SQL (the shared clock). The
`concurrency_claims` reconciler, already seven-part compliant, gained the same
advisory lock. See `docs/clock-guarded-retention.md` for the rule these satisfy.
