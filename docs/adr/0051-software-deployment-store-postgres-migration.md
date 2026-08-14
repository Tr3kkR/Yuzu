---
status: accepted
date: 2026-08-14
owner: platform (Postgres substrate migration program)
deciders: parallel Wave 2 batch-3 migration worker, following the ladder assignment in
  `docs/postgres-migration-ladder.md` (Wave 2)
scope: server — `SoftwareDeploymentStore` (capability 7.6, software packaging + fleet deployment
  catalog), its cutover from SQLite to PostgreSQL, its ADR-0009 backfill, and its dormancy record
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend, no SQLite fallback),
  ADR-0008 (substrate architecture), ADR-0009 (per-store first-boot backfill cutover),
  ADR-0012 (server Postgres store contract)
related: docs/postgres-migration-ladder.md (Wave 2 -> Done); docs/adr/0043-deployment-store-postgres-migration.md
  (closest precedent — also a TEXT-keyed, status-machined deployment store); docs/adr/0048-license-store-postgres-migration.md
  (same dormancy family, same era)
---

# 0051 — `SoftwareDeploymentStore` Postgres migration (authoritative, dormant, with backfill)

## Context

`SoftwareDeploymentStore` (`server/core/src/software_deployment_store.{hpp,cpp}`) is a
lightweight software packaging + fleet deployment catalog (capability 7.6): operators register
`SoftwarePackage` installers, create `SoftwareDeployment` jobs against a scope expression, and
per-agent install outcomes are tracked in `AgentDeploymentStatus`. It is a Wave 2 store on
`docs/postgres-migration-ladder.md`. It was previously a SQLite store
(`software-deployment.db` by convention — the legacy path is caller-supplied, matching every
other migrated store), guarded by a single `shared_mutex`.

**Naming trap:** three "deployment store" classes exist in this codebase.
`SoftwareDeploymentStore` (this ADR) is capability 7.6's packaging/deployment catalog.
`DeploymentStore` (`deployment_store.*`, ADR-0043, already migrated) is the older, unrelated
concept of operator-initiated ad-hoc SSH/group-policy/manual installs (Issue 7.7).
`DeploymentRunStore` (`deployment_run_store.*`, born-on-Pg) is the `/auto` Deploy stage's
stage→execute state machine. This ADR does not touch either of the other two.

### DORMANT — verified 2026-08-14 against `origin/dev`

**Nothing in production constructs this store.** `rest_api_v1.hpp`'s `register_routes` overloads
take `SoftwareDeploymentStore* sw_deploy_store = nullptr`, and the `/api/v1/software-packages*` /
`/api/v1/software-deployments*` route family in `rest_api_v1.cpp` registers only
`if (sw_deploy_store)` — no call site anywhere in the server passes a non-null pointer. Pickaxe:
construction was wired by `acc6c481a` ("Add T2 capabilities") and removed by `2fcfb95b5`
("server.cpp god-object decomposition") — the same two commits that produced `LicenseStore`'s
dormancy (ADR-0048), confirmed by the operator (2026-08-14) as a deliberate shelving of the T2
capability, not an accidental regression. Re-verified independently for this store:
`git grep -nE 'make_unique<SoftwareDeploymentStore>|new SoftwareDeploymentStore'` across
`origin/dev` matches only `tests/unit/server/test_rest_software_packages.cpp`.

**Consequences of dormancy, recorded explicitly per the kickoff's instruction not to let this
read as an oversight:**

- **Re-wiring the store at boot is OUT OF SCOPE for this migration.** This ADR migrates the
  store's storage substrate; it does not resurrect the feature. A future re-wiring PR adds the
  `server.cpp` construction site, the `/readyz`/`/healthz` conjunction entries, and calls
  `migrate_from_sqlite` at boot before serving — none of that exists today, migrated or not.
- **`migrate_from_sqlite` has no production call site today.** It is fully implemented and
  covered by `tests/unit/server/test_software_deployment_store.cpp`'s backfill suite (a live
  Postgres instance, hand-constructed legacy SQLite files), but no boot path invokes it until
  re-wiring lands. This is the same shape as `LicenseStore`/ADR-0048.
- **Backfill is NOT skippable on the strength of dormancy.** The store WAS constructed during the
  `acc6c481a..2fcfb95b5` window, so an upgrade path through that window can hold a real legacy
  SQLite file with genuine packages/deployments/agent statuses. "No production fleet exists
  today" does not downgrade this obligation (standing rule, memory
  `project_no-production-fleet-fresh-build.md`). The standard ADR-0009 idempotent,
  fingerprint-verified backfill ships, guarded on legacy-file existence, ready for whenever
  re-wiring calls it.

## Decision

**Migrate `SoftwareDeploymentStore` to PostgreSQL as schema `software_deployment_store`, three
tables (`software_packages`, `software_deployments`, `agent_software_status`) with their
existing internal foreign keys preserved, with a standard ADR-0009 first-boot backfill.**

### Schema

- Schema name `software_deployment_store` (ADR-0008 Update naming rule).
- Three tables carry the existing columns unchanged in meaning and type mapping (`TEXT`→`TEXT`,
  `INTEGER` epoch-seconds/size columns→`BIGINT`, `INTEGER` counters→`INTEGER`):
  - `software_packages` (parent) — a write-once catalog row per installer. `id` stays a
    **client-generated 32-hex-char TEXT primary key** — the pre-migration `generate_id()` format
    (two `mt19937_64` 64-bit draws formatted as 16 hex chars each), unchanged (playbook: keep
    pre-migration ID contracts; this store's own `generate_id` predates and differs from
    `DeploymentStore`'s single-draw 16-hex format — the two are NOT interchangeable and this
    migration does not unify them).
  - `software_deployments` — `package_id TEXT NOT NULL REFERENCES software_packages(id)`. Same
    32-hex-char client-generated `id`.
  - `agent_software_status` — `deployment_id TEXT NOT NULL REFERENCES software_deployments(id)`,
    `PRIMARY KEY (deployment_id, agent_id)` (no surrogate id, unchanged from the pre-migration
    schema).
  - A fourth table, `sqlite_backfill_source (fingerprint TEXT PRIMARY KEY, completed_at BIGINT
    NOT NULL)`, is the backfill idempotency tracker (see Backfill below) — not part of the
    application data model, mirrors `DeploymentStore`/ADR-0043.
- **Postgres ENFORCES the two foreign keys; the pre-migration SQLite store never did** — its
  constructor never ran `PRAGMA foreign_keys=ON`. This is a genuine behavior change on the live
  path: `delete_package` now fails (a validation-shaped `unexpected`, not a DB error) if any
  deployment still references the package, where the SQLite original would silently leave an
  orphaned deployment behind. Treated as a strengthening, not a regression — see Consequences.
- No secrets. `content_hash`/`content_url` are integrity metadata; `silent_args`/
  `verify_command`/`rollback_command` are operator-authored command strings. Confirmed no
  embedded-credential pattern in the schema or the (dormant) REST layer's `#771` shell-metachar
  validator — this is why the store sits in Wave 2, not the secret-gated Wave 3.
- `agent_software_status(deployment_id)` drops the pre-migration SQLite schema's redundant
  `idx_agentstatus_dep` index — the `PRIMARY KEY (deployment_id, agent_id)` constraint already
  gives Postgres a leading-column btree index over `deployment_id` alone. `idx_agentstatus_agent`
  is kept (not covered by the PK's column order).

### Posture

**AUTHORITATIVE / fail-hard** (ADR-0012 §1), both construction and runtime — same reasoning as
`DeploymentStore` (ADR-0043): no in-memory authoritative layer sits above this data.

- **Construction fails closed**, same template as every migrated Postgres store: a schema that
  cannot migrate/open sets `startup_failed_` in `server.cpp` (once re-wired — see Dormancy above;
  the mechanism is present in the store's constructor today regardless).
- **Every reader/mutator returns `std::expected<..., std::string>`.** A genuine DB/lease failure
  is never papered over as an empty/false/not-found result. Every such failure is prefixed
  `kSwDeployDbErrorPrefix` (`"db_error: "`), exported from the header (mirrors
  `DeploymentStore::kDeploymentDbErrorPrefix`) so `rest_api_v1.cpp`'s `sw_deploy_error_status`
  classifier can map 503 (store outage) vs 400 (validation/business rule) without pattern-
  matching message text. This store's routes have no GET-by-id twin, so — like
  `DeploymentStore`'s own routes — a "not found"/"wrong state" business error also classifies as
  400, not 404 (matches `cancel_job`'s route precedent exactly).
- **`start_deployment`/`cancel_deployment`/`rollback_deployment` are each a single guarded
  `UPDATE ... WHERE status = <allowed set>` (the `DeploymentStore::cancel_job` pattern), race-safe
  against a concurrent second transition without a mutex. Each disambiguates not-found from
  wrong-state via a best-effort follow-up read on the zero-rows-matched case (same caveat as
  `cancel_job`: a race there can only change which business-error message is reported, never the
  guarded UPDATE's own correctness).
- **Write-path failures are classified, not just surfaced** (ADR-0051 applies the #3097
  precedent from day one, rather than needing a post-push fix round): `update_agent_status`,
  `refresh_counts`, and `delete_package` all return `std::expected<void, std::string>`
  (previously bare `bool`/`void` — bool-swallowing, per the kickoff's lesson from #3064's
  post-push blocker).
- **FK-violation classification.** `create_deployment` (bad `package_id`) and
  `update_agent_status` (bad `deployment_id`) both inspect `PG_DIAG_SQLSTATE` for `23503`
  (`foreign_key_violation`) and return a plain validation-shaped message
  (`"package_id does not exist"` / `"deployment_id does not exist"`) rather than the
  `kSwDeployDbErrorPrefix`-prefixed generic failure — the caller referenced a resource that does
  not exist, not a database outage.

### Backfill (ADR-0009)

**Mandatory** — an in-flight or completed deployment, or a real per-agent install outcome, is
real operator intent (matches the ladder's Wave 2 framing) — see the Dormancy section above for
why dormancy does not exempt this.

**Content-fingerprinted across all three tables in one snapshot, not a single fleet-wide
completion flag** — extends `DeploymentStore`/ADR-0043's design (itself the fix for a HIGH
finding: a fileless replica's "nothing to backfill" stamp permanently waving through a holder
replica's real data) from one table to three. A replica with no local legacy file (or a
present-but-schema-less one) computes and stamps a `sourceless` sentinel; a replica holding real
rows computes a SHA-256 fingerprint over ALL THREE tables' rows (each table's rows independently
sorted so physical SELECT order never affects the hash, each row length-prefix-encoded per field
for injectivity — the same `<byte-length>:<bytes>` netstring technique `DeploymentStore` uses —
and the three sections joined by literal `PKG`/`DEP`/`AGT` tags, which can never collide with a
row boundary because every row begins with a decimal digit) and checks/stamps that specific
value. `sqlite_backfill_source` is shared across all three tables — one fingerprint per legacy
FILE, not per table, since the three tables in one legacy file are one atomic snapshot.

**Three decisions beyond the single-table `DeploymentStore` precedent, all new for this store:**

1. **Partial legacy schema fails closed, is never treated as sourceless.** The pre-migration
   store's own `create_tables()` always creates all three tables together in one migration
   statement — a real legacy file produced by this store's code has all three tables or none. A
   file with `software_packages` present but `software_deployments` or `agent_software_status`
   missing cannot be a genuine fresh-install/no-data case; it is refused (fail-closed, "likely
   corruption") rather than silently treated as an empty/fresh file. Copying `DeploymentStore`'s
   single-table sourceless check verbatim (has-table ⇒ read; no-table ⇒ sourceless) would have
   missed this — a single-table store has no "partial" state to distinguish.
2. **Referential closure is validated CLIENT-SIDE, before any Postgres round trip.** Postgres
   enforces the `package_id`/`deployment_id` foreign keys the legacy SQLite store never did (see
   Schema above), so a wired-era legacy file can hold a genuine orphan — e.g. a deployment whose
   package was deleted via `delete_package` while the deployment row itself was never cleaned up
   (SQLite silently permitted this; Postgres cannot). Unlike an identity mismatch or a lifecycle
   disagreement — where both sides are independently valid data and an operator adjudicates which
   is correct — an orphan has no valid parent to satisfy the FK with; there is nothing to
   adjudicate, only data to repair. The whole backfill fails closed, naming the orphan row and
   its missing parent id, rather than either fabricating a placeholder parent or silently
   dropping the row (and, for a dangling deployment, its own child `agent_software_status` rows).
   This is checked against the CURRENT full-snapshot read set (packages/deployments read in this
   same pass), not against Postgres's live tables — the store re-reads the whole legacy file on
   every boot rather than incrementally (same trade-off `DeploymentStore` accepted), so a package
   migrated in an earlier pass is still present in the current read set as long as the legacy
   file itself still holds it.
3. **Two independent status enums, two independent (and store-specific) rank models.** Per-row
   conflict handling partitions columns into IDENTITY (write-once) vs LIFECYCLE (mutated by live
   post-migration traffic), the `DeploymentStore`/ADR-0043 shape — but the actual rank values
   differ per table:
   - `software_packages` is **ALL-IDENTITY** (a write-once catalog — `create_package` is the
     only write path, there is no update method at all). Any content difference on a conflicting
     `id` fails the boot closed; an identical re-encounter is a benign no-op. There is no
     lifecycle dimension to rank.
   - `software_deployments` IDENTITY = `package_id, scope_expression, created_by, created_at`;
     LIFECYCLE = `status, started_at, completed_at`, the three agent counters. **The rank model
     is NOT `DeploymentStore`'s** — copying that store's exact rank (which ties
     `completed`/`failed`/`cancelled` as terminal) would misclassify this store's data: this
     store's `rollback_deployment` guard is `WHERE status IN
     ('deploying','verifying','completed')`, so `completed` is reachable-FROM, not terminal —
     `rolled_back` is a subsequent state, not a sibling of `completed`. The derived rank, taken
     directly from this store's actual transition guards
     (`start_deployment`/`cancel_deployment`/`rollback_deployment`): `staged`(0) <
     `deploying`(1) < `verifying`(2) < `completed`(3) < {`cancelled`, `rolled_back`,
     `failed`}(4, tied terminal band). A Postgres value of `rolled_back` against a stale legacy
     snapshot of `completed` is therefore the ordinary "legacy behind, Postgres already
     progressed further" benign no-op (rank 4 > rank 3) — NOT a terminal disagreement, which it
     would be misclassified as under `DeploymentStore`'s literal rank set. Only
     `staged`/`deploying`/`cancelled`/`rolled_back` have a live writer today (the three guarded
     transitions); `verifying`/`completed`/`failed` are part of the documented status contract
     with no current writer — legacy rows may still hold them from the store's wired era or a
     future orchestration engine, so backfill validates and accepts all seven, it does not
     restrict to the four reachable-today values.
   - `agent_software_status` has PK `(deployment_id, agent_id)` as its write-once IDENTITY;
     LIFECYCLE = `status, started_at, completed_at, error`. Rank (from the documented status
     comment, `pending`(0) < `downloading`(1) < `installing`(2) < `verifying`(3) <
     {`success`,`failed`,`rolled_back`}(4, tied)) is applied identically in shape to the
     deployments table's direction check — BUT `update_agent_status` is an **unguarded upsert**
     on the live path (`ON CONFLICT (deployment_id, agent_id) DO UPDATE`, no transition guard at
     all), unlike the deployment table's three guarded transitions. The backfill's "legacy
     ahead"/"terminal disagreement" classification for this table is therefore a documented-
     contract **heuristic**, not a proven-safe direction check — an out-of-order live write could
     in principle cause the backfill to fail closed on data that was actually fine. Accepted: the
     safe direction for a per-agent install-outcome disagreement to err in is refusing and asking
     an operator to look, not silently discarding one side.

**Per-row conflict handling shape** (mirrors `DeploymentStore`/ADR-0043 exactly, extended to
three tables): insert `ON CONFLICT (<key>) DO NOTHING RETURNING <key>`, check `PQntuples()` (never
bare `PGRES_COMMAND_OK` — proves the statement executed, not that THIS row won the conflict, the
`docs/postgres-store-playbook.md` anti-pattern `AuditStore::stamp_complete`/ADR-0040 motivated).
On conflict, read the existing row back and compare per the IDENTITY/LIFECYCLE partition above.
Insertion order within the transaction is parents-first (packages, then deployments, then agent
status) — the referential-closure check above guarantees every child's parent is either already
in Postgres or inserted earlier in the SAME transaction, so the FK never rejects a legitimate
insert ordering.

**Trade-off accepted, same as `DeploymentStore`:** this design reads the local legacy file on
every boot for as long as it remains in place (never short-circuits on a single marker before
hashing), because "already migrated" is a content-addressed question. Accepted as negligible —
this store's tables are not high-volume, and once re-wired, boots are infrequent.

## Considered and rejected

- **Switching `id` (packages, deployments) to a Postgres `SERIAL`/`IDENTITY` column.** Rejected
  — same reasoning as `DeploymentStore`: no REST route in this (dormant) codebase depends on the
  ID format today, but changing it anyway would gratuitously diverge from "keep pre-migration ID
  contracts" for zero benefit (the 32-hex client-generated key is already adequately unique).
- **Reusing `DeploymentStore::generate_id()`'s 16-hex single-draw format.** Rejected — this
  store's own pre-migration `generate_id()` used a 32-hex two-draw format; the two stores'
  generators are historically independent and this migration preserves each store's own
  pre-existing contract rather than unifying them.
- **Skipping backfill on the strength of dormancy.** Rejected — see the Dormancy section's
  "Backfill is NOT skippable" bullet.
- **Treating an orphan child row (dangling `package_id`/`deployment_id`) as a skip-with-warning
  instead of a whole-backfill fail-closed.** Considered, rejected: unlike an identity mismatch or
  a lifecycle disagreement, there is no valid value to adjudicate toward for an orphan — the
  parent is simply gone. Skipping would silently drop the orphan row's history with no operator
  visibility beyond a log line; failing the whole backfill closed forces the operator to actually
  look at the retained legacy file before any of that boot's data lands. Revisit if this proves
  too coarse in practice (e.g. failing an entire large backfill over one unrelated orphan) — not
  measured as a problem here because the store is dormant and this path is untested against real
  production data.
- **Wiring `sw_deploy_store_` into `/readyz`/`/healthz`.** Not done — mirrors `LicenseStore`/
  ADR-0048's identical reasoning: there is no construction site in `server.cpp` at all (see
  Dormancy above), so there is nothing to wire a pointer that never exists into. When a future
  change re-wires construction, add the `/readyz`/`/healthz` conjunction entries at that time,
  matching every other migrated authoritative store's pattern (`rbac_store`, `result_set_store`,
  `access_review_store`, `deployment_store`, ...).

## Consequences

- Every package/deployment/agent-status read/write now surfaces a genuine database error to its
  (currently dormant) REST caller as a 503 instead of a silently-empty/-false
  SQLite-mutex-guarded result, once re-wired.
- **`delete_package` now enforces referential integrity that SQLite never did.** A package
  referenced by a live deployment cannot be deleted (a 400-class validation error, not a 503) —
  the pre-migration store would silently leave the deployment pointing at a vanished package. A
  behavior change, but a strengthening: the prior silent-orphan state is exactly the shape the
  referential-closure backfill check above has to defend against for legacy data.
- The legacy SQLite file (once re-wiring defines its path) is retained for one release (ADR-0009
  rollback window), then removed per the standard cadence — no different from any other migrated
  store, just not yet exercised since nothing constructs the store to read one today.
- `SoftwareDeploymentStore` moves from "SQLite, mutex-serialized" to "Postgres, pool-concurrent"
  — matches every other migrated store's concurrency model; no separate follow-up needed.
- A fileless replica can never permanently block a holder replica's real
  package/deployment/agent-status history from reaching Postgres (the same class of fix
  `DeploymentStore`/ADR-0043 shipped, extended to three tables) — covered by
  `tests/unit/server/test_software_deployment_store.cpp`'s backfill suite against a live Postgres
  instance, including the referential-closure and partial-schema cases this ADR adds beyond that
  precedent.
- Re-wiring this store into `server.cpp` (construction, `/readyz`/`/healthz`, calling
  `migrate_from_sqlite` at boot, and actually passing the store into `register_routes`) remains
  entirely out of scope for this migration and is not tracked by a follow-up issue here — the
  kickoff's instruction was explicit that resurrecting the shelved capability is a separate,
  future, explicit decision.
