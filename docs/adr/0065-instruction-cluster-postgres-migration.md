# ADR-0065: Instruction Cluster (ScheduleEngine / ApprovalManager / ExecutionTracker) → PostgreSQL

- **Status:** Proposed (this ADR lands with commit 1/3 of the PR, and now covers commit 2/3;
  ExecutionTracker's section is a placeholder until commit 3 lands — see its TODO marker below.
  Flip to Accepted once all three components are ported and the sections below are verified.)
- **Date:** 2026-08-30 (commits 1-2/3); TBD (final)
- **Deciders:** pg workstream (migration-programme PR 5, the last of the 7-store SQLite→Postgres
  ladder, #1328/#1325/#3653)
- **Parents:** ADR-0006/0007/0008 (+Correction), ADR-0009 (including its 2026-08-25
  fresh-start-by-default amendment), ADR-0012 (substrate/store contract); ADR-0063
  (`DirectorySync` → PostgreSQL — the freshest per-store template this ADR follows); ADR-0061/
  0062/0063/0064 (siblings 1/2/3/4 of this same ladder); `docs/postgres-store-playbook.md`;
  `docs/postgres-migration-ladder.md`.

## Context

`ExecutionTracker`, `ApprovalManager`, and `ScheduleEngine` (`server/core/src/{execution_tracker,
approval_manager,schedule_engine}.{hpp,cpp}`) are the last 3 of the 7 production-wired SQLite
components missed by the original migration ladder (found 2026-08-27, tracked #1328/#1325/#3653).
Unlike the four already-migrated Wave 4 components, these three do not each own a private SQLite
file — all three share one `instructions.db` connection via `InstructionDbPool`
(`server/core/src/instruction_db_pool.{hpp,cpp}`), a construct that exists ONLY because they share
that one file; each store keeps its own private, unrelated table set (no SQL-level joins between
them — every apparent relationship is stitched in C++). This ADR treats them as one cluster because
they migrate in one PR (staged as 3 commits so governance can review each store's diff separately),
and `InstructionDbPool` is deleted once all three have moved off it — the pool has exactly one
consumer, `server.cpp`, verified by a repo-wide grep before this PR started.

Each of the three moves to its own independent Postgres schema — `schedule_engine`,
`approval_manager`, `execution_tracker` — following ADR-0008's schema-per-store naming rule
extended (per the ladder's Wave 4 note) to non-`Store`-suffix class names.

## Decision

### Component 1/3: ScheduleEngine (this commit)

`ScheduleEngine` (`schedule_engine.{hpp,cpp}`) stores recurring instruction schedules
(`schedules`, one table, 17 columns) and is polled by `ScheduleRunner`'s background tick thread
(`server.cpp`) to fire due occurrences.

**Pre-existing gap closed by this port, not a regression it introduces:** the SQLite era had NO
`is_open()`/availability flag at all — a migration failure was `spdlog::error`-only
(`schedule_engine.cpp:134-136` on `origin/dev` before this port), so `server.cpp` never checked
availability and the store was silently fail-open. This is a **posture upgrade** (ADR-0012 §1):
construction is now fail-**closed** — a reachable database whose schema can't migrate/open is a
fatal startup error (`startup_failed_`), matching every other migrated store in this ladder.

**Schema** (Postgres schema `schedule_engine`, one table, folding the SQLite-era v1+v2 ladder into
one PG v1 DDL — v2 only added the `parameter_values` column, PR1.5a):

```sql
CREATE TABLE schedules (
    id                 TEXT    PRIMARY KEY,
    name               TEXT    NOT NULL,
    definition_id      TEXT    NOT NULL,
    frequency_type     TEXT    NOT NULL DEFAULT 'once',
    interval_minutes   INTEGER NOT NULL DEFAULT 60,
    time_of_day        TEXT    NOT NULL DEFAULT '00:00',
    day_of_week        INTEGER NOT NULL DEFAULT 0,
    day_of_month       INTEGER NOT NULL DEFAULT 1,
    scope_expression   TEXT    NOT NULL DEFAULT '',
    requires_approval  BOOLEAN NOT NULL DEFAULT FALSE,
    enabled            BOOLEAN NOT NULL DEFAULT TRUE,
    next_execution_at  BIGINT  NOT NULL DEFAULT 0,
    last_executed_at   BIGINT  NOT NULL DEFAULT 0,
    execution_count    INTEGER NOT NULL DEFAULT 0,
    created_by         TEXT    NOT NULL DEFAULT '',
    created_at         BIGINT  NOT NULL DEFAULT 0,
    parameter_values   TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_schedules_due ON schedules(next_execution_at)
  WHERE enabled AND next_execution_at > 0;
```

`idx_schedules_due` is **net new** — the SQLite era had no indexes at all, so `evaluate_due()`'s
poller-tick hot path (`WHERE enabled=1 AND next_execution_at>0 AND next_execution_at<=now ORDER BY
next_execution_at`) full-scanned every row on every tick. The partial index's predicate matches
that WHERE clause and its column matches the ORDER BY exactly.

**`advance_schedule` collapses a two-statement race into one atomic statement.** The SQLite era
performed a locked SELECT, computed the next occurrence in C++ by branching on `frequency_type`,
then issued a separate UPDATE — a read-modify-write spanning two statements, which is the actual
race an app-level `std::shared_mutex` existed to cover (`SQLITE_OPEN_FULLMUTEX` only serializes
each individual call, not the pair). The Postgres port moves the frequency arithmetic into a SQL
`CASE` inside a single `UPDATE ... RETURNING`, so the whole read-compute-write happens in one round
trip under Postgres's own per-row locking — no app-level lock needed at all. The `std::shared_mutex`
(`mtx_`) is deleted entirely, not narrowed: every method now takes a per-call bounded pool lease
instead (`kReadTimeout=1500ms` for reads via `try_acquire_for`, degrade-to-empty on lease failure;
`kWriteTimeout=2000ms` for writes via `with_txn_for`, matching `PatchManager`/`DirectorySync`'s
constants). A zero-row-affected UPDATE (unknown id) stays today's silent no-op.

**Owner-scoped mutators keep their exact SQLite-era shape**: `delete_schedule`/`set_enabled` are
`DELETE`/`UPDATE ... WHERE id=$1 AND created_by=$2 RETURNING id` — wrong-owner is indistinguishable
from missing, same as before, just against Postgres.

**Posture (ADR-0012 §1):** runtime read/write method signatures are UNCHANGED — plain
`std::vector`/`bool`/`std::expected<std::string,std::string>` shapes, matching `PatchManager`'s
precedent of not upgrading call-site contracts during a storage-backend swap. `ScheduleRunner`
needs no changes (borrowed raw pointer only).

**Consumers (unchanged public API, no signature churn):** `ScheduleRoutes`/`schedule_routes.cpp`
(REST), `mcp_server.cpp` (`list_schedules`), `ScheduleRunner`/`schedule_runner.cpp` (poller,
borrowed pointer), `workflow_routes.cpp`. Verified: no consumer touches `sqlite3` directly or
constructs `ScheduleEngine` itself — `server.cpp` is the sole construction site.

**`/readyz`/`/healthz`:** both are **net-new rows** for this store — the SQLite era had no
availability flag to key either probe on, so neither existed. `/readyz`'s `StoreCheck` gains
`schedule_engine_ && schedule_engine_->is_open()`; `/healthz` gains `schedule_engine_ok` in the
`all_stores_ok` conjunction and a `schedule_engine` entry in the `stores` JSON map, following the
exact pattern `patch_manager_ok`/`directory_sync_ok` already established.

**No backfill (ADR-0009's 2026-08-25 fresh-start-by-default amendment):** no
`migrate_from_sqlite`, unconditionally. The legacy `instructions.db` (shared with the still-SQLite
ExecutionTracker/ApprovalManager siblings until commits 2/3 of this PR) is never read for data.
Construction logs a one-time `ScheduleEngine initialized (schema schedule_engine) — fresh start, no
legacy backfill` line; `server.cpp` calls the shared `legacy_sqlite_probe::warn_if_legacy_rows()`
helper (already established by the earlier Wave 4 PRs) over `instructions.db`, naming the
`schedules` table, to warn (never fail, never block boot) if the legacy file still holds rows.

### Component 2/3: ApprovalManager (this commit)

`ApprovalManager` (`approval_manager.{hpp,cpp}`) stores one-time MCP approval tickets and REST
instruction-approval requests (`approvals`, one table, 13 columns) — a security control, not
ordinary CRUD state.

**Not a posture upgrade, unlike ScheduleEngine.** This store was ALREADY fail-closed in the
SQLite era (a failed migration nulled `db_`, and `server.cpp` never checked `is_open()` before
this migration only because it never needed to — the null-`db_` state degraded every method to a
no-op/empty-return, not a crash). Construction is fail-**closed** exactly as before; `server.cpp`
now additionally checks `is_open()` and sets `startup_failed_` on failure, matching the ladder's
uniform wiring pattern, but the store's own internal posture is unchanged.

**Schema** (Postgres schema `approval_manager`, one table, folding the SQLite-era v1..v7 ladder
into one PG v1 DDL — every column the ladder ever added is present from creation, and all six
indexes the ladder accumulated are included; v7's `origin='legacy'` back-fill has no fresh-start
equivalent — see "Considered and rejected"):

```sql
CREATE TABLE approvals (
    id                TEXT    PRIMARY KEY,
    definition_id     TEXT    NOT NULL,
    status            TEXT    NOT NULL DEFAULT 'pending',
    submitted_by      TEXT    NOT NULL DEFAULT '',
    submitted_at      BIGINT  NOT NULL DEFAULT 0,
    reviewed_by       TEXT    NOT NULL DEFAULT '',
    reviewed_at       BIGINT  NOT NULL DEFAULT 0,
    review_comment    TEXT    NOT NULL DEFAULT '',
    scope_expression  TEXT    NOT NULL DEFAULT '',
    consumed_at       BIGINT  NOT NULL DEFAULT 0,
    consumed_by       TEXT    NOT NULL DEFAULT '',
    schedule_id       TEXT    NOT NULL DEFAULT '',
    origin            TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX idx_approvals_status ON approvals(status);
CREATE INDEX idx_approvals_submitted_at ON approvals(submitted_at);
CREATE INDEX idx_approvals_definition ON approvals(definition_id);
CREATE INDEX idx_approvals_schedule_id ON approvals(schedule_id);
CREATE INDEX idx_approvals_status_submitted ON approvals(status, submitted_at);
CREATE INDEX idx_approvals_status_consumed_reviewed ON approvals(status, consumed_at, reviewed_at);
```

**`consume_ticket`'s one-time CAS ports shape-for-shape** — `UPDATE approval_manager.approvals SET
consumed_at=$1, consumed_by=$2 WHERE id=$3 AND status='approved' AND consumed_at=0 RETURNING 1`,
row-count-checked via `PQntuples` instead of a bare affected-row count — a security control
preserved exactly, not a mechanical schema translation. The `#2442` cross-surface/cross-submitter
binding check (a `get_checked` read ahead of the CAS) is unchanged; it deliberately stays
non-locking (`FOR UPDATE` was considered and rejected — the origin/submitter fields are immutable
after insert, and the CAS itself re-checks `status`/`consumed_at`, so there is no TOCTOU window a
row lock would close).

**The one genuinely non-mechanical consumer seam in the whole cluster: the SQLite-error
discriminator.** `StoreReadError`/`ConsumeError`'s `int extended_errcode` (a raw
`sqlite3_extended_errcode()`) — consumed by `mcp_approval_error.hpp::approval_store_error_body` to
pick the MCP A4 permanent-vs-transient error arm — is replaced by a `std::string sqlstate` field.
New `server/core/src/pg_error_class.hpp::is_permanent_pg_error(std::string_view)` replaces
`sqlite_error_class.hpp::is_permanent_sqlite_error` (deleted — verified single includer). Permanent
= class `42` prefix (schema drift — the closest Postgres analogue of `SQLITE_NOTADB`, and the same
family `engine_principal_store.cpp`'s own file-local `is_permanent_sqlstate` classifier matches,
#2456 UP-17), `XX001`/`XX002` (corruption, analogue of `SQLITE_CORRUPT`), `53100` (disk_full,
analogue of `SQLITE_FULL`), `25006` (read_only_sql_transaction, analogue of `SQLITE_READONLY`);
everything else — `08*` connection, `40001`/`40P01` serialization/deadlock, `55P03` lock timeout,
`57014` query canceled, `P0001` a plpgsql `RAISE EXCEPTION` — stays transient, matching this
repo's existing narrow-classifier precedent. An empty `sqlstate` (no Postgres origin — store not
open, missing argument, a pool-acquire timeout) classifies transient on its own, exactly as `0`
did for the SQLite field; the `!mgr.is_open()` disjunct in `approval_store_error_body` is what
forces the permanent arm for the store-never-opened case regardless.

**Deliberate template divergence, not an oversight:** `ApprovalManager`'s reads do NOT
degrade-to-empty the way `ScheduleEngine`/`PatchManager` do — a pool-acquire timeout on a read
surfaces as `StoreReadError{sqlstate=""}` (transient) rather than a silent empty result. This seam
exists specifically to carry fidelity into the MCP A4 error envelope; collapsing it to
degrade-to-empty would make a transient pool blip on the recall path indistinguishable from "no
such ticket."

**Contention tests ported to a Postgres-native technique.** The two SQLite `BEGIN EXCLUSIVE`
tests pinning the masked-denial classification (`test_approval_manager.cpp`) port to
`test_engine_principal_store.cpp`'s `.lock_timeout_ms` technique (#2456 precedent): a second raw
connection holds `LOCK TABLE approval_manager.approvals IN ACCESS EXCLUSIVE MODE`, and the store's
own pool is built with a short `lock_timeout_ms` so its blocked read fails deterministically with
SQLSTATE `55P03` — no sleep/retry loop needed, same determinism guarantee the SQLite
rollback-journal trick gave. A third test (the CAS-step-only fault, negative control for
`binding_check_unevaluated`) ports its SQLite `BEFORE UPDATE ... RAISE(ABORT)` trigger to a
Postgres `BEFORE UPDATE` trigger function raising a plpgsql exception (`P0001`, correctly transient
by the classifier above).

**One MCP-level integration test has NO Postgres equivalent and is deleted, not ported** (see
"Considered and rejected") — the identical mechanism it tested is pinned precisely at the store
level by the ported chaos test above.

**Expiry-sweep clock-guard adjudication (routed-concerns row 38, recorded per its part 6):** the
lazy 7-day expiry sweep inside `submit()` is a wall-clock-cutoff bulk `UPDATE` (two statements —
stale-pending and approved-unconsumed), never a `DELETE`. The clock-guard seven-part apparatus's
own trigger condition (bulk *deletes* driven by a wall clock) is not met by this store — rows are
state-transitioned to `'expired'`, never removed, and remain queryable/auditable indefinitely. This
is a deliberate reading, not a silent skip: the sweep ports shape-preserved (same two statements,
same 7-day window, same RETURNING-based counting), and `mtx_` narrows to guard only this
compound cap-check + sweep + insert sequence — `consume_ticket`'s CAS and every read method no
longer take it at all, since a single Postgres statement is already atomic under the target row's
own lock.

### Component 3/3: ExecutionTracker + `InstructionDbPool` deletion — TODO, lands with commit 3

Per claim-discipline, same caveat as above. Planned shape:

- Schema `execution_tracker`, folding the SQLite-era v1+v2 ladder (the `plugin_result_status`
  column) into one PG v1 DDL.
- The one `sqlite3_changes()` call in the whole cluster (`refresh_counts`, gating the terminal-
  transition SSE publish) becomes `UPDATE ... RETURNING` — closing the #1033-class shared-connection
  race this store carried.
- The `recursive_mutex` (needed because `refresh_counts` re-enters `get_execution` on the same
  thread) is restructured away in favor of a lease-free private helper, or replaced with a plain
  mutex if re-entrancy is removed instead.
- The two-publish SSE ordering invariant (progress-flagged-terminal event precedes the real
  terminal event — `docs/executions-history-ladder.md`'s `first_terminal_id` contract) is preserved
  exactly; this is a routed concern and re-verified at governance time regardless of what this ADR
  claims.
- `InstructionDbPool` (`instruction_db_pool.{hpp,cpp}`) is deleted, along with its `server.cpp`
  member, construction block, and teardown line — this is the point at which the legacy
  `instructions.db` file stops being written to by any Yuzu store.
- `/readyz`'s existing `execution_tracker` row re-keys from `instr_db_pool_->is_open() &&
  execution_tracker_->schema_ok()` to the store's own new `is_open()`.

**This section will be rewritten, not merely appended to, once commit 3 lands.**

## Considered and rejected

- **Migrating the three stores as separate PRs/ADRs instead of one cluster PR.** Rejected — they
  share `InstructionDbPool`, and the pool's deletion is only safe once all three have moved off it;
  splitting the PR would leave the pool half-consumed by a mix of SQLite and Postgres stores for an
  indeterminate stretch, and the pool itself has no independent value once even one consumer moves.
  Staged as 3 commits within one PR instead, so governance can still review each store's diff in
  isolation.
- **A single fixture template covering all three stores everywhere.** Rejected for test isolation
  — see the per-commit test sections; a fixture that always builds the full trio would fail an
  approval-only test on an unrelated `ScheduleEngine` schema break, and `PgTestTemplate`'s
  replay-fingerprint guard would reject a subset-setup sharing that key from a different call site.
  Per-store templates plus one composite template (for the handful of call sites needing 2-3 stores
  together) instead.
- **Porting v7's `origin='legacy'` back-fill as a Postgres migration step.** Rejected — on a fresh
  PG v1 schema there are no pre-existing `''`-origin rows for it to rewrite (the population it
  targeted was specifically pre-v5-column and pre-v7-migration SQLite rows), so the migration would
  be dead code from creation. The DECODE-side property it protected — an unrecognised stored
  `origin` value refuses redemption, never grants it — is unaffected and still pinned directly by
  `approval_origin_from_string`'s own tests.
- **Isolating the origin-check-specific chaos fault through the full MCP handler** (mirroring the
  SQLite-era countdown-authorizer test that faulted rung 2 only, letting rung 1's identical-SQL
  lookup through first). Rejected as infeasible under Postgres's pooled-connection model: a
  table-level lock (the technique that replaces it for the lookup-rung-only case) blocks the FIRST
  read to reach the table, which is rung 1's own lookup — it cannot selectively let one read
  through and fault only the next, the way SQLite's per-connection authorizer callback could.
  Faithfully isolating rung 2 alone (not rung 1) is preserved instead at the store level, directly
  against `consume_ticket`, where the origin-check read genuinely is the first and only read for
  that call.
- **`FOR UPDATE` on the `#2442` binding-check read.** Rejected — the fields it would protect
  (origin, submitted_by) are immutable after insert, and the CAS UPDATE already re-checks
  `status`/`consumed_at` atomically; a row lock would tax every consume call for a race that does
  not exist.

## Consequences

- **Any recurring-schedule state from a pre-Postgres build is lost on upgrade** (component 1 of
  3). The operator re-creates schedules via `POST /api/schedules`. Documented in
  `docs/user-manual/upgrading.md`.
- **`/readyz` and `/healthz` now report ScheduleEngine's availability** where it was previously
  invisible (the SQLite era had no availability flag for this store at all) — a monitoring-
  visibility improvement, not a new failure mode: a broken schedule store previously failed silently
  (the poller simply never fired anything), it now fails loudly at boot.
- **Any pending/approved/consumed approval-ticket evidence from a pre-Postgres build is lost on
  upgrade** (component 2 of 3). A pending MCP recall or REST instruction-approval outstanding at
  upgrade must be re-requested; consumed-ticket audit history (the `submitted_by → reviewed_by →
  consumed_by` evidence chain) does not carry forward. Documented in `docs/user-manual/upgrading.md`.
- **The MCP A4 error envelope's permanent-vs-transient discriminator is now a Postgres SQLSTATE
  string, not a SQLite extended errcode** — an internal type change with no client-visible
  behavior change (the same two response bodies, chosen by the same two-discriminator rule).
- Consequences for ExecutionTracker: TODO, commit 3.

## Follow-ups

- `execution_tracker.cpp`'s `#1033`-class shared-connection race: tracked to be closed by commit 3
  of this PR, not a separate follow-up.
- ADR-2002 (High Availability) forward-pointers, one per component, to be added as each commit
  lands: ExecutionTracker's `ExecutionEventBus` stays process-local (cross-replica SSE delivery is
  ADR-2002's concern); ApprovalManager's queue-cap/expiry-sweep check-then-act is process-local
  (multi-replica coordination is ADR-2002's concern); ScheduleEngine's `SELECT ... FOR UPDATE`
  (now a single atomic UPDATE, so this specific hazard is closed) still leaves concurrent
  *dispatch* of the same due schedule across replicas unaddressed — ADR-2002 already commits to a
  fenced-leader + transactional-outbox model for exactly this class of problem. All three are
  irrelevant on today's single-server design (`docs/adr/2002-high-availability-architecture.md`).
