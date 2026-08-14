# ADR-0047: QuarantineStore → PostgreSQL (Wave 2)

- **Status:** Accepted
- **Date:** 2026-08-14
- **Deciders:** pg workstream; security-guardian + docs-writer (governance)
- **Parents:** ADR-0006/0007/0008(+Correction), ADR-0009, ADR-0012; conventions from
  ADR-0040/0041/0044 (esp. `sanitize_pg_text`, fail-closed boot, mandatory-backfill-with-
  fingerprint-verification, the RbacStore/DiscoveryStore sourceless-fingerprint precedent this
  store ports).

## Context

`QuarantineStore` (`quarantine.db` today, `server/core/src/quarantine_store.{hpp,cpp}`, ~54 + 226
lines) holds Guardian device-quarantine records: the server-side bookkeeping of which agents are
currently network-isolated, who isolated them, why, and their full history. Single table
(`quarantine_records`), two indexes, no foreign keys, no secret-bearing columns. Postgres ladder
Wave 2, batch 2.

A quarantine record is not expendable telemetry — it is the server's only durable record of an
**active security containment**. Per the Guardian design (`docs/yuzu-guardian-design-v1.1.md`
§11.7), "Quarantine is a terminal state — once activated, it persists until an administrator
explicitly lifts it." Losing an active record on cutover silently un-quarantines a device in the
server's view (the agent-side firewall enforcement is a separate, agent-local mechanism this
migration does not touch — see "Out of scope" below) — this is Wave 2's "operator state that
cannot be lost" framing (the same framing `DiscoveryStore`/ADR-0044 used for its `managed` flag),
not purely ephemeral telemetry. Backfill is therefore mandatory.

## Decision

Migrate to PostgreSQL schema **`quarantine_store`** (ADR-0008), construction fail-closed
(ADR-0007/0012 §1), on the shared server `PgPool`. The SQLite `shared_mutex` is retired —
Postgres's real per-connection concurrency, plus a partial unique index (see below), replaces the
single-writer serialization the mutex + check-then-insert previously provided.

### Schema

```sql
CREATE TABLE quarantine_records (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'released')),
    quarantined_by  TEXT NOT NULL DEFAULT '',
    quarantined_at  BIGINT NOT NULL DEFAULT 0,
    released_at     BIGINT NOT NULL DEFAULT 0,
    whitelist       TEXT NOT NULL DEFAULT '',
    reason          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_quarantine_agent ON quarantine_records(agent_id);
CREATE INDEX idx_quarantine_status ON quarantine_records(status);
CREATE UNIQUE INDEX idx_quarantine_agent_active ON quarantine_records(agent_id) WHERE status = 'active';
CREATE TABLE quarantine_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
```

Ports column-for-column from the legacy SQLite schema (`quarantined_by` becomes `NOT NULL DEFAULT
''` instead of nullable TEXT — the read path already defaulted a NULL to `""`, so this is a
value-preserving tightening, not a behavior change). The `id` column is internal-only: no REST/MCP
response ever exposes it (verified — `rest_api_v1.cpp`'s quarantine JSON bodies emit only
`agent_id`/`status`/`quarantined_by`/`quarantined_at`/`whitelist`/`reason`), so nothing depends on
SQLite rowid semantics surviving the cutover, and Postgres is free to assign fresh `BIGSERIAL`
values on backfill.

**New: a partial unique index enforces "at most one active record per agent" at the database
level** (`idx_quarantine_agent_active`), replacing the legacy check-then-insert-under-mutex
pattern with a single race-safe statement (see "Race-safe writes" below) — the legacy in-process
mutex could not protect against concurrent Postgres connections the way it protected a single
`sqlite3*` handle.

### Reads — authoritative, type-distinguishable

Per the 2026-07-25 program policy (`docs/postgres-store-playbook.md` "Authoritative reads must be
type-distinguishable"), every read is type-distinguishable from "no rows": `list_quarantined` and
`get_history` return `std::optional<std::vector<QuarantineRecord>>` (`nullopt` = degraded, empty
vector = genuinely no records); `get_status` returns
`std::expected<std::optional<QuarantineRecord>, std::string>` (`unexpected` = degraded, a value
holding `nullopt` = genuinely not quarantined). This closes the specific fail-open the kickoff
review flagged: a `get_status` that returned `nullopt` on a DB error previously read as "not
quarantined," and an empty `list_quarantined` on a degraded read previously read as "nothing
quarantined" — both masked an ACTIVE containment. `GET /api/v1/quarantine`
(`rest_api_v1.cpp`) now checks for `nullopt` and returns 503 rather than rendering an empty
quarantine list.

### Race-safe writes (no in-process mutex)

**Neither mutator trusts a bare `PGRES_COMMAND_OK`/`PGRES_TUPLES_OK` status to mean its `WHERE`
actually matched a row** — that status is identical whether the predicate matched zero rows or
one, the same defect class the `NotificationStore` Postgres port's `mark_read`/`dismiss` shipped
(bare-status-only, no row-affected confirmation). The stakes differ in direction, not in kind, from
that store's read-adjacent case: a silent no-op `release_device` is the INVERSE of a fail-open
read — the device stays quarantined while the caller (and any automation reading the `200`
response) believes it was just freed. Both mutators here confirm via `RETURNING` +
`PQntuples()`, never a bare command-status check:

- `quarantine_device`: a single `INSERT ... ON CONFLICT (agent_id) WHERE status = 'active' DO
  NOTHING RETURNING id`, targeting the partial unique index above. `PQntuples() == 0` means the
  conflict fired (an active record already exists) → `unexpected("device is already
  quarantined")` — the playbook's generic `RETURNING` + `PQntuples() == 1` idiom for a
  first-writer-wins insert. Replaces the legacy check-then-insert-under-mutex; verified against a
  live Postgres instance (`docs/postgres-store-playbook.md`'s explicit warning that `ON CONFLICT
  ... WHERE` semantics are easy to get subtly wrong by reasoning alone).
- `release_device`: a single guarded `UPDATE ... SET status = 'released', released_at = $1 WHERE
  agent_id = $2 AND status = 'active' RETURNING id` (the `#3062`/`cancel_job` pattern this
  kickoff's lessons-learned section calls out). `PQntuples() == 0` → `unexpected("device is not
  quarantined")` — the row-confirmation check the kickoff's lessons-learned item 6 names the
  *pattern* for but does not itself spell out the verification step; named explicitly here so a
  future edit cannot regress to a bare status check without touching a comment that says why not.

Both retire `sqlite3_changes()` (#1033) in favor of `RETURNING`.

**`is_open()` checked at every entry point, not just reads.** All three surfaces —
`GET`/`POST /api/v1/quarantine`, `DELETE /api/v1/quarantine/{agent_id}`, and the MCP
`quarantine_device` tool — gate on `quarantine_store && quarantine_store->is_open()` before doing
any store work, not merely a null-pointer check. This closes the same asymmetry left as an
unresolved LOW on the `NotificationStore` Postgres port (its `POST` routes null-checked the store
pointer but skipped `is_open()`, while its `GET` route checked both) — widened here from "reads"
to every route so quarantine does not inherit that gap.

**`400` vs `503` classification (`kQuarantineDbErrorPrefix`).** Every genuine store/pool/query
failure on `quarantine_device`/`release_device` is prefixed `"db_error: "`; a business/state error
("already quarantined" / "not quarantined") is not. `rest_api_v1.cpp`'s `is_quarantine_db_error`
(and the MCP `quarantine_device` handler's equivalent check) key off this shared constant to answer
`503` (retryable) vs `400` (retrying will not help) — mirroring `DeploymentStore`'s
`kDeploymentDbErrorPrefix`/`is_deployment_db_error`, added after an adversarial-review MEDIUM
finding on that store (2026-08-12) that its write routes previously collapsed every failure,
including genuine outages, to `400`. Applied here from the start rather than shipping the same
defect class and fixing it in a later round.

### Backfill (ADR-0009) — MANDATORY, fingerprint-verified, single-transaction

One-time, idempotent, fail-closed backfill from the legacy `quarantine.db`, ported from the
`RbacStore`/`DiscoveryStore` sourceless-fingerprint mechanism (ADR-0040/0041/0044 shape).

**Design difference from `DiscoveryStore`: no natural per-row key.** `discovered_devices` has a
UNIQUE `ip_address` to `ON CONFLICT DO NOTHING` against, making its backfill insert loop
naturally idempotent/crash-resumable per row. `quarantine_records` is a pure append-only history
table with no such key (an agent can have many historical rows; `agent_id` alone is not unique).
Rather than synthesize an artificial per-row key (rejected — a SQLite-rowid-derived key would
collide across two independently-numbered legacy files in the pathological case of two replicas
each holding *different* real content, silently dropping one replica's real rows with no error),
the row inserts, the `backfill_complete` marker, and the `backfill_source_fingerprint` marker are
committed together in **one transaction**, guarded by a leading
`pg_advisory_xact_lock(hashtextextended('quarantine_store:backfill', 0))` statement (its own
statement, strictly before the check-and-mutate work, per the playbook's `RbacStore`-derived
warning that a lock embedded via CTE in the same statement as the check does not re-evaluate a
statement's already-fixed snapshot).

This is the exception ADR-0012 §2(b) explicitly reserves: "the sole documented exception is a
fail-closed, pre-serving, one-time legacy backfill whose atomic insert-plus-completion stamp
requires one transaction while it streams a bounded row from the legacy store." Justification
required by that clause:

- **Per-row memory is capped**: the legacy file is read once into an in-memory snapshot
  (`read_legacy_snapshot`), and the count is capped at `kMaxBackfillRows` (500,000) — refused
  (fail-closed, operator remediation required) rather than silently truncated if exceeded.
  Quarantine records are manually-curated security events, not a high-volume telemetry stream;
  this ceiling is a sanity/DoS guard, not an expected-to-bind limit.
- **Retry behavior is explicit**: under the advisory lock, the transaction re-checks the
  `backfill_complete` marker (a concurrent racer may have committed between this replica's
  earlier short-lease marker check and this transaction acquiring the lock) — if now present, the
  transaction commits as a no-op and the caller retries through the top-level marker-check path
  (bounded at 2 attempts total), which performs the same holder-side fingerprint verification the
  `DiscoveryStore` marker-present branch performs. A same-content race (two replicas backfilling
  the identical shared file) verifies clean and skips; a different-content race fails closed with
  an operator-actionable log line, exactly like `DiscoveryStore`'s HOLDER-SIDE VERIFICATION
  FAILED case.
- **The sourceless (no-local-file) stamp path reuses the same advisory-locked transaction
  helper** (with an empty row set) rather than `DiscoveryStore`'s separate lock-free
  promotable-upsert — unifying both paths through one lock removes the need to separately reason
  about a sourceless stamper racing a real-content backfiller across two different locking
  schemes.
- **Legacy `status` values are validated BEFORE any row reaches Postgres**: any row whose status
  is not `active`/`released` fails the backfill closed (never silently inserted, never silently
  dropped) — the CHECK constraint would also reject it, but validating up front produces a
  clear, actionable log line naming the offending row instead of a generic constraint-violation
  error surfacing from mid-transaction.
- **No IDENTITY/LIFECYCLE column-conflict partition (unlike `DeploymentStore`/#3062).** That
  partition exists to resolve a real row *already present in Postgres* (from a prior backfill or
  live traffic) disagreeing with the legacy row trying to land on top of it via `ON CONFLICT DO
  UPDATE`. `quarantine_records`' backfill never does that: the advisory lock excludes every other
  first-ever-migration attempt, and no live traffic is possible from *any* replica before *some*
  replica's backfill has committed (every replica gates serving on its own backfill success), so
  there is no window in which a legacy row could collide with an already-live-written row. Once
  a marker is present, this store's backfill never touches `quarantine_records` again — only
  fresh runtime writes do.
- **0-byte legacy file guard**: identical two-branch treatment to `DiscoveryStore` (refused
  unconditionally on a first-ever migration; safe to skip once a real migration has already
  completed for the fleet) — ported verbatim, same rationale (SQLite opens a 0-byte file as a
  valid empty database, indistinguishable from the legitimate no-`quarantine_records`-table case).

### Lifecycle

Construction moves inside `server.cpp`'s `if (pg_pool_ && !startup_failed_)` guard; a failed
migration or backfill sets `startup_failed_` (fail-closed boot, never serve on top of
partially-migrated quarantine data). Added to both the `/healthz` and `/readyz` check lists.

## Out of scope

This ADR covers only the server-side bookkeeping store. The agent-side quarantine firewall
enforcement (WFP/nftables/pf block-all + exceptions, §11.7 of the Guardian design) is a separate,
agent-local mechanism, untouched by this migration — `quarantine_device`/`release_device` still
dispatch the live isolation command via the same `DispatchFn` chain as before; only the
record-keeping substrate changed.

## Considered and rejected

- **A synthetic per-row backfill key** (legacy SQLite rowid as a `legacy_id UNIQUE` column,
  mirroring `DiscoveryStore`'s `ip_address` `ON CONFLICT DO NOTHING` idiom). Rejected: SQLite
  rowids restart from 1 per file, so two independently-numbered legacy files (a pathological but
  possible multi-replica state) could collide on an unrelated row and silently drop one replica's
  real data with no error — worse than the single-transaction/advisory-lock design, which either
  cleanly serializes concurrent same-content backfills or fails closed on genuinely divergent
  content.
- **Skippable backfill** (the `ResponseStore` precedent): rejected — an active quarantine record
  is live security containment state, not regenerable telemetry.
- **Plain marker-only backfill idempotency** (no fingerprint): rejected for the same reason
  `DiscoveryStore`/`RbacStore` rejected it — cannot distinguish "this replica's own completed
  migration" from "a different replica's migration this replica's data was never part of."

## Consequences

- Active quarantine records, and full quarantine history, are preserved across the cutover.
- `GET /api/v1/quarantine` gains a new 503 branch on a degraded read (previously: SQLite's
  local-file reads essentially never failed short of file corruption, so this failure mode was
  not practically reachable).
- `quarantine_device`'s "already quarantined" check moves from an in-process mutex-guarded
  check-then-insert to a database-enforced partial unique index — safe under concurrent Postgres
  connections in a way the legacy mutex, scoped to one `sqlite3*` handle, never had to be.
- Tests → `YUZU_REQUIRE_PG_DB_TPL` + a file-local `"quarantinestore"` `PgTestTemplate`
  (`tests/unit/server/test_quarantine_store.cpp`); construction-fail-closed and backfill tests
  use plain `YUZU_REQUIRE_PG_DB`.

## Follow-ups

- None identified at migration time. `get_status`/`get_history` currently have no REST/MCP
  caller (confirmed by repo-wide grep) — pre-existing, unrelated to this migration; the
  type-distinguishable read contract is applied to them anyway for API consistency with
  `list_quarantined`, per the playbook's "most migrated stores are authoritative" default.
