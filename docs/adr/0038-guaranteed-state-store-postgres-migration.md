# ADR-0038: GuaranteedStateStore → PostgreSQL (Wave 1)

- **Status:** Proposed
- **Date:** 2026-07-31
- **Deciders:** pg workstream, security-guardian + docs-writer review (Guardian routing per CLAUDE.md)
- **Parents:** ADR-0006/0007/0008 (+Correction), ADR-0009, ADR-0012; conventions from the
  pilot migrations ADR-0036 (ResultSetStore) and ADR-0037 (InventoryStore);
  `docs/yuzu-guardian-design-v1.1.md` §9.1 (schema) + §24 (standing invariants).

## Context

`GuaranteedStateStore` is the server-side Guardian state store (`guaranteed-state.db`
today): five tables — `guaranteed_state_rules` (operator-authored rule rows, the content
`Push` fans out), `guaranteed_state_events` (agent-reported enforcement/violation history,
TTL'd, default 30 d), `guardian_observations` (the ruleless DEX signal projection — PII
class, TTL'd in lockstep with events), `guardian_agent_rule_status` (per-agent×rule
reconcile state), and `guardian_meta` (k/v; carries `policy_generation`, the counter agent
reconciliation is keyed on). High-write (heartbeat/status + observation ingest), a
vuln-graph join input, and the `/dex` analytics substrate (~25 aggregate reads).

It is the first Wave 1 store, next in `docs/postgres-migration-ladder.md` order.

## Decision

Migrate to PostgreSQL schema **`guaranteed_state_store`** (ADR-0008 naming), construction
fail-closed (ADR-0012 §1), on the shared server `PgPool`. The agent side is untouched
(agent stays SQLite; the wire protocol and the `__guard__`/`__observation__` payloads do
not change).

### Schema

The five tables port column-for-column with SQLite idioms translated (INTEGER booleans →
`BOOLEAN`, `TEXT` timestamps stay ISO-8601 `TEXT` where the SQLite store used them —
behavior-preserving; a TIMESTAMPTZ normalisation is a separate, later decision). The
**published enum CHECK constraints must stay byte-identical to the SQLite DDL**: the
H2/G9 cross-check tests bind schema enums to the agent's per-type support arrays — add or
remove a type in both or neither (CLAUDE.md Guardian §). Indexes carry over; the DEX
aggregate reads get the same composite indexes the SQLite store maintains.

### Posture (ADR-0012 §1) — split by table family, decided by consumer blast radius

- **Rules + meta reads: AUTHORITATIVE, type-distinguishable (the catastrophic read).**
  `list_rules`/`get_rule`/`rule_names` feed `guardian_routes`' Push fan-out and the
  baseline deploy surface. A degraded read collapsing to *silent empty* would push an
  EMPTY rule set — a fleet-wide disarm, the Guardian analogue of the pilots'
  `NOT from_result_set:` inversion. These reads move to
  `std::expected<..., std::string>` / `std::optional<Container>`-nullopt-on-degrade
  (playbook "Authoritative reads must be type-distinguishable"), and every push/reconcile
  consumer aborts (503 / no-op push) on degrade — never fans out an empty set it cannot
  distinguish from "no rules configured". Single-object `get_rule` keeps
  found/absent/degraded three-state.
- **Rule/meta writes: fail-hard** (`std::expected`, surfaced to the REST caller; a lost
  rule write is operator-visible config loss). `bump_policy_generation` becomes one
  atomic `UPDATE ... RETURNING` — it is now cross-process state; the read-modify-write
  idiom does not port.
- **Event/observation ingest: FAIL-SOFT** (mirrors ADR-0037 ingest): a dropped
  enforcement-history row is re-derivable operational telemetry from the agent's next
  report cycle; ingest must never block the gRPC thread. Drops are counted
  (`yuzu_guardian_ingest_dropped_total{reason}`, the ADR-0037 label conventions incl.
  constants).
- **Status upserts: fail-soft with the same counter** (reconcile heals on the next
  heartbeat), but status **reads** feeding the enforce-gate/dashboard stay
  degrade-distinguishable (empty ≠ unknown).
- **DEX analytic reads: deferred widening (explicit, playbook-sanctioned).** The ~20 DEX
  aggregate reads keep their plain `std::vector<T>` signatures THIS PR (empty-on-degrade,
  behavior-identical to the SQLite store today), because the type change fans out to ~68
  call sites across five consumer files (dashboard fragments need the htmx 200+inline-note
  convention, REST twins 503, MCP a third shape) — each an individually-reviewed decision,
  not a mechanical sweep, and none feeds an enforce/target decision (the playbook's
  deny-or-benign class; same deferral the ResultSetStore pilot recorded for
  `list_by_owner`/`members`/`lineage`). What this PR DOES land at the store seam:
  `yuzu_guardian_read_degrade_total{reason}` + `DegradeSampler` logging on every DEX read
  (a degrade is counted and visible even while the return stays empty). The
  `std::optional` widening + per-route degrade sweep is a tracked follow-up (issue filed
  with this PR), amendable per-file. The `kDexCohortFloor` no-singling-out flooring stays
  where it lives today (model/route layer), untouched.
  The type-distinguishable set THIS PR: `list_rules` / `get_rule` / `rule_names` /
  `rule_names_for` (Push/reconcile inputs) and `agent_rule_statuses` (enforce-gate/census
  input) — the catastrophic-read set — plus all write paths.

### Backfill (ADR-0009) — mandatory, all five tables, one transaction

Rules and meta are operator-authored config and the generation counter — losing them
disarms or re-arms Guardian incoherently; events/observations are *bounded* (30-day TTL)
but NOT re-derivable (agent-reported history, and the observations projection is
works-council-audited PII whose disposal evidence we keep); status is cheap and keeps
reconcile warm. So: single-transaction backfill of all five tables from the legacy
`guaranteed-state.db`, idempotent via a `sqlite_backfill` marker row (ADR-0036 shape —
never row-count-inferred), per-row SQLSTATE discrimination exactly as ADR-0037 H1 settled
it (22xxx/23xxx/54xxx = skip + persisted `skipped_bad`; anything else aborts UNSTAMPED and
the boot log carries the operator remediation line). Legacy file retained read-only for
one release. TTL-expired legacy rows are skipped at read time (WHERE clause), not
migrated-then-reaped.

### Retention (the part that must not port as-is)

The SQLite store's background cleanup thread issues **bare wall-clock TTL deletes** on
`guaranteed_state_events` + `guardian_observations` — on the routed-concern
"Clock-guarded retention" non-compliance list (#2508). The port adopts the **#2496
`gc_sweep` reference shape** (first PG implementation of the guard): shared
`gc_meta`-style rows (`last_pass_now` + `last_anomaly_facts`) in the store schema, one
sweeping replica per pass via `pg_try_advisory_xact_lock('guaranteed_state_store:reap',0)`,
outcome probe excluding implausibly-ahead rows, `audit_retention_rules::classify` +
fact-set decline-once, **unconditional per-pass cap** (substrate-tuned constant; events
and observations reaped in the same guarded pass so the PII projection never outlives its
parent event — the lockstep invariant survives). The `events_reaped_`/
`observations_reaped_` counters (compliance WS-E disposal evidence on `/metrics`) are
kept and now also exported with a `result` label per the #2634 direction, so this store
does not reproduce the observability gap #2634 tracks on ResultSetStore.

### Lifecycle

The in-process cleanup thread goes away; the guarded reap runs from the server maintenance
tick (like ResultSetStore's). `stop()` unwires borrowed pointers in the ingest services
before `pg_pool_.reset()` (pilot convention); `/readyz` **and `/healthz`** both carry the
store (the #2636 healthz/readyz drift class — this PR also fixes #2636's
`result_set_store` one-liner while in that conjunction).

### Concurrency

`mtx_` (the SQLite single-writer mutex) is deleted; Postgres real concurrency replaces it.
The two read-modify-write sites (`bump_policy_generation`, status upsert-with-transition)
become single-statement `UPDATE/INSERT ... ON CONFLICT ... RETURNING`. No
`sqlite3_changes()`-after-step survives (#1033): every counted mutation uses `RETURNING`
or `PQcmdTuples` on its own single-owner result.

## Considered and rejected

- **Skippable backfill for events/observations** (pure ADR-0009 reading): rejected —
  bounded but not re-derivable, and the observation rows' disposal evidence chain
  (works-council/WS-E) argues for continuity across the cutover.
- **TIMESTAMPTZ normalisation during the port**: rejected — behavior-preserving port
  first; a type change rides its own change with its own tests.
- **Keeping the dedicated cleanup thread**: rejected — a per-process thread × N replicas
  multiplies the reap rate and cannot honor the single-sweeper advisory-lock requirement
  the clock-guard invariant imposes on Postgres stores.

## Consequences

- Guardian rules/events join the vuln-graph query-owner seam (ADR-0012 §3) when scoring
  lands; the DEX dashboard reads become fleet-consistent across server replicas.
- The Push fan-out gains an explicit degraded-store abort path (503, audited) — a
  behavior change: previously a broken store could push an empty rule set; now it
  refuses. Changelog fragment + `docs/user-manual/guaranteed-state.md` note required.
- Tests: store-behaviour tests move to `YUZU_REQUIRE_PG_DB_TPL` + a file-local
  `PgTestTemplate` (`"guaranteedstate"` key); migration/fresh-DB tests keep plain
  `YUZU_REQUIRE_PG_DB`. The H2/G9 enum cross-check tests must pass unchanged against the
  PG DDL.

## Follow-ups

- #2634-parity counters land here from day one (this ADR's retention section).
- Keyset pagination for the heaviest DEX reads if `/dex` route budgets demand it
  (measure first).
