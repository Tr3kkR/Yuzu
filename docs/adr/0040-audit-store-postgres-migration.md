# ADR-0040: AuditStore → PostgreSQL (Wave 1.3)

- **Status:** Proposed
- **Date:** 2026-08-01
- **Deciders:** pg workstream; security-guardian + docs-writer + compliance-officer (Gate 2/6)
- **Parents:** ADR-0006/0007/0008(+Correction), ADR-0009, ADR-0012; conventions from
  ADR-0036 (ResultSetStore), ADR-0037 (InventoryStore), ADR-0038 (GuaranteedStateStore),
  **ADR-0039 (ResponseStore)** — which established `sanitize_pg_text` (UTF-8 + NUL) and the
  clock-guarded reap with durable dedup + advisory lock that this store extends. #2360 is the
  retention clock guard whose behaviour is migration-REQUIRED here.

## Context

`AuditStore` (`audit.db` today, `server/core/src/audit_store.{hpp,cpp}`) is the **SOC 2 evidence
chain**: operator actions, agent enrolment, fleet-topology events, background schedule execution,
and every behavioural-PII access. It is the highest-stakes store on the ladder — a lost or
silently-truncated audit trail is a compliance failure (CC6.6/CC7.2), not degraded telemetry.

SQLite schema (v3): `audit_events` (id, timestamp, principal, principal_role, action,
target_type, target_id, detail, source_ip, user_agent, session_id, result, `principal_class`
[schema v2], `ttl_expires_at`), the four query indexes (`idx_audit_ts` / `_principal_ts` /
`_action_ts` / `_target_ts`), the partial retention index `idx_audit_ttl_id ON
(ttl_expires_at, id) WHERE ttl_expires_at > 0`, and `audit_retention_meta` (k/v — the durable
half of the #2360 clock guard). Public API: `log()` (bool — the evidence-integrity contract),
`query()`, `total_count()`, eight metric accessors, and the retention `cleanup_once` / cleanup
thread.

Wave 1.3 on the ladder, after ResponseStore (ADR-0039).

## Decision

Migrate to PostgreSQL schema **`audit_store`** (ADR-0008), construction fail-closed
(ADR-0007/0012 §1), on the shared server PgPool. `mtx_` deleted; PG concurrency + an advisory
lease replace the single-writer assumption.

### Schema

`audit_events` ports column-for-column (INTEGER id → `BIGINT GENERATED ALWAYS AS IDENTITY`;
timestamps stay BIGINT epoch; text columns TEXT). All four query indexes carry over, plus the
partial `idx_audit_ttl_id ON (ttl_expires_at, id) WHERE ttl_expires_at > 0` the reaper needs.
`audit_retention_meta` (k/v) carries over — and gains the reaper's **durable dedup** rows (see
Retention). Unlike SQLite, the partial index is created in the migration (Postgres index builds
don't take the fail-closed-on-failure hazard the SQLite `ensure_retention_index` guards against
— PG runs it inside the migration txn and a failure correctly fails the migration, which for an
evidence store is the right fail-closed posture).

### Posture (ADR-0012 §1)

- **Write (`log`): FAIL-HARD.** This is the distinguishing decision vs ResponseStore's fail-soft
  ingest — a dropped audit event is a compliance failure, not re-derivable telemetry. `log()`
  keeps its `bool` contract: a store-not-open / pool-acquire-timeout / query error returns
  `false`, and callers already fail-closed on `false` (behavioural-PII REST routes → `503` +
  `Sec-Audit-Failed`; `emit_behavioral_audit`, #1647). No fail-soft drop, no silent swallow.
  `emit_failed_` counts every `false`. The write is a single `INSERT` (fail-hard via
  `PQresultStatus`), never a SAVEPOINT-tolerant path.
- **Reads (`query` / `total_count`): degrade-distinguishable, DENY on degrade.** The audit trail
  is authoritative evidence — a store/pool failure MUST NOT read as "no audit events" (that would
  let a reviewer or a SIEM conclude an absence of activity from an infrastructure blip). `query`
  becomes degrade-distinguishable at the seam (`std::optional<std::vector<AuditEvent>>` /
  nullopt-on-degrade) and the audit-log REST/dashboard consumers surface `503`, never a
  false-empty. This is stricter than ResponseStore's deny-or-benign carve-out: the audit read is
  evidence, so degrade → deny, not degrade → render-empty.
- **Retention (`cleanup_once`): migration-REQUIRED clock guard** (see below). Fail-hard within
  its advisory-lease-held transaction; a probe/delete failure declines the pass (never a blind
  delete).

### Backfill (ADR-0009) — MANDATORY

Unlike ResponseStore (skippable TTL telemetry), the audit trail is **SOC 2 evidence retained
365 days**: pre-cutover rows MUST come across. This is the ADR-0009 **mandatory** class and the
primary new element vs the three prior migrations.

- On first boot against an empty `audit_store.audit_events` with a legacy `audit.db` present,
  stream every `audit_events` row (all columns incl. `principal_class` and `ttl_expires_at`, so
  the retention horizon is preserved exactly) into PG in **bounded batches** (memory-safe — the
  legacy table can reach tens of millions of rows / ~16 GB; a whole-table read would OOM,
  cf. #2661). `audit_retention_meta` (the clock-guard reading) is copied too.
- **Idempotent + resumable:** a one-time `backfill_complete` marker row in `audit_retention_meta`
  gates re-runs; a crash mid-backfill re-streams from `MAX(id)` already in PG (id-ordered,
  ON CONFLICT DO NOTHING) so no duplication and no loss. Row-count reconciliation
  (legacy count vs migrated count) is logged and asserted.
- **Fail-closed on backfill failure** (ADR-0012 mandatory-backfill contract): a failed/partial
  backfill refuses boot with a loud diagnostic and is retried on the next start — the server
  never serves with a knowingly-incomplete evidence chain. Backfill work is RAII-guarded
  (degrade audit + `yuzu_server_audit_backfill_*` metric).
- The legacy `audit.db` is moved aside (not deleted) after a verified backfill, per the
  operator-managed-backup convention, so the pre-cutover evidence remains recoverable.

### Retention (clock-guarded) — the single-writer assumption does NOT port

The #2360 clock guard (`classify` decline-once + `kMaxAuditDeletesPerPass` cap + `would_wipe`
whole-window-jump detection + `big_step` + `prev_unusable`) is **migration-REQUIRED** — dropping
it reinstates an unbounded clock-driven `DELETE` on the evidence chain.

The load-bearing port problem (ladder row): the dedup state — `last_reported_` (the previous
pass's `Facts`) and `loaded_meta_unusable_` — is a **per-PROCESS member**, while the clock
reading it pairs with (`last_pass_now`) is **durable**. On SQLite with one server that is
correct. On PG with N servers, each process holds its own `last_reported_`, so N processes each
spend the guard independently — a condition reported by server A re-reports on server B, and
worse, the dedup that stops a legitimately-all-expired store from declining forever breaks.

Fix (the ADR-0039 reap pattern, already shipped, generalised): **single-sweeper advisory lease**
(`pg_try_advisory_xact_lock('audit_store:reap')`) so exactly one process sweeps per tick, AND
move the per-process dedup state into **durable `audit_retention_meta` rows** (`last_anomaly_facts`
alongside `last_pass_now`) so the fact-set comparison survives across processes and restarts —
exactly what ResponseStore's `reap_expired` does with `gc_meta`. `kMaxAuditDeletesPerPass`
(25 000) is then preserved as a per-pass drain rate for the ONE sweeping process (the advisory
lease makes "N × 25k" impossible), so the calibration stays valid.

`loaded_meta_unusable_` (the boot-time "durable reading present but unusable" flag) also becomes a
durable fact folded into the same `audit_retention_meta` state, so it is not lost when a
different replica runs the first post-boot pass.

**Deliberate dedup-semantics change (multi-process correctness).** The SQLite guard had an
`is_event` exemption: a clock *movement* (a `Step`, or a `BadState` accompanied by a clock event)
re-reported **every** pass even against an identical prior report, because in a single process a
second movement is a genuinely new incident. That exemption does NOT port: with the dedup state
now **durable and shared across replicas**, "always re-report an event" would make each of N
processes re-announce the *same* incident every tick — double-counting an anomaly rather than
deduplicating it. The PG guard therefore uses the ResponseStore fact-set model uniformly: report
once per distinct serialized `Facts` set, stand down when it clears. The catastrophic protection
is fully preserved — the dead-CMOS-then-NTP sequence flips `would_wipe`, which is a *different*
fact set, so it still reports (the failure the original `is_event` logic was added to stop was an
enum-collapse comparison, which the whole-fact-set string never had). The only thing lost is a
second *identical-magnitude* clock step re-emitting `clock_anomaly_skips`; that is an
alerting-granularity trade accepted in exchange for correct cross-replica deduplication, and is
called out here for the consistency/security gates.

### Untrusted byte columns (UTF-8 + NUL)

`detail`, `user_agent`, `source_ip`, `principal`, `session_id` and friends are client- or
agent-supplied free text. Per the ADR-0039 generalisation, they are scrubbed with
`sanitize_pg_text` (UTF-8-invalid → U+FFFD **and** embedded NUL → U+FFFD) before the `INSERT`,
so a hostile or mis-encoded value can never fail the fail-hard write (SQLSTATE 22021 / NUL
truncation) and take an audit event down. `result`/`principal_class` are enum-controlled and not
sanitized. This closes the same class #1593 guards, on the evidence path.

### Lifecycle

`stop()` unwires from the writers then resets before `pg_pool_`; store in `/readyz` AND
`/healthz`. The retention pass runs on an advisory-lease-gated cadence (keeping the existing
`cleanup_interval_min`, default 60m; the lease makes a per-process thread safe — only the lease
winner sweeps). The in-process cleanup thread's join-before-store-teardown contract is preserved.

## Considered and rejected

- **Fail-soft ingest (ResponseStore's posture)**: rejected — the audit trail is evidence, not
  telemetry; a silently-dropped event is a CC6.6 failure. `log()` stays fail-hard/bool.
- **Skippable backfill**: rejected — 365-day SOC 2 retention makes pre-cutover rows mandatory
  evidence; a fresh-start would destroy the compliance record.
- **Per-process dedup kept as-is**: rejected — N-server independent guard spending is the exact
  hazard the ladder row calls out; advisory lease + durable dedup is required.
- **Whole-table backfill read**: rejected — OOM risk on a multi-GB evidence table (#2661);
  bounded batched streaming with id-resumable ON CONFLICT is required.

## Consequences

- Audit history is **preserved** across the Postgres cutover (mandatory backfill), then
  fleet-consistent across replicas. First boot after upgrade pays a one-time streamed backfill
  (and, on a large `audit.db`, a widened startup budget — `upgrading.md`).
- Retention is single-swept fleet-wide via the advisory lease; the eight retention/write metrics
  keep their names and now reflect the coordinated single-sweeper.
- Tests → `YUZU_REQUIRE_PG_DB_TPL` + a file-local `"auditstore"` `PgTestTemplate`; backfill /
  migration / fresh-DB tests use plain `YUZU_REQUIRE_PG_DB`.

## Follow-ups

- The `sanitize_pg_text` (UTF-8 + NUL) + advisory-lease-durable-dedup conventions are now used by
  three stores (ResponseStore, AuditStore, and the GS reap) — promote to the postgres-store
  playbook as the canonical untrusted-column + clock-guard recipe.
