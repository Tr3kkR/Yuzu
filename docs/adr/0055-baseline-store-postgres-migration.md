# ADR-0055: BaselineStore → PostgreSQL

- **Status:** Proposed
- **Date:** 2026-08-19
- **Deciders:** pg workstream, security-guardian + docs-writer review (Guardian routing per CLAUDE.md)
- **Parents:** ADR-0006/0007/0008 (+Correction), ADR-0009, ADR-0012; ADR-0038
  (`GuaranteedStateStore` → PostgreSQL, the closest Guardian-domain precedent — this
  ADR follows its posture/catastrophic-read reasoning directly); the TagStore (ADR-0050)
  / RbacStore (#2703) fingerprint-verified backfill shape; `docs/yuzu-guardian-design-v1.1.md`
  §9.1 (schema) + §24 (standing invariants); `docs/guardian-baseline-model.md`.

## Context

`BaselineStore` (`server/core/src/baseline_store.{hpp,cpp}`) is the server-side Guardian
**Baseline** store — the named, deployable collection of Guards
(`docs/guardian-baseline-model.md`). Three tables today (`guardian-baselines.db`, SQLite):
`guaranteed_state_baselines` (the Baseline row, including `deployed_snapshot` — the
member set captured at last deploy), `guaranteed_state_baseline_rules` (M:N live
members), `guaranteed_state_baseline_groups` (assignment: included − excluded
management groups). Bounded operator-authored config, not a high-write/telemetry
store — no retention reaper.

CLAUDE.md "Guardian engine — stores" names this store's catastrophic invariant
directly: push fan-out + heartbeat reconcile gate on `deployed_member_rule_ids()`,
sourced from each deploy's `deployed_snapshot`, **not** the live member set — what's
enforced stays behind `Push`, not `Write`.

## Decision

Migrate to PostgreSQL schema **`baseline_store`** (ADR-0008 naming), construction
fail-closed (ADR-0012 §1), on the shared server `PgPool`. The agent is untouched —
this is pure control-plane config; the agent never hears the word "Baseline".

### Schema

The three tables port with SQLite idioms translated (`INTEGER` timestamps → `BIGINT`;
short table names per the current naming convention — `baselines` / `baseline_rules` /
`baseline_groups`, schema-qualification replacing the legacy `guaranteed_state_baseline*`
flat-namespace prefix). The in-schema FK from the two child tables to `baselines` (`ON
DELETE CASCADE`) ports unchanged; the deliberate absence of a `rule_id`/`group_id` FK
(those reference `guaranteed_state_store`/`management_group_store` — different schemas)
also ports unchanged, matching the pre-migration store's cross-file reasoning.

### Posture (ADR-0012 §1) — uniformly authoritative

Unlike ADR-0038's split-by-table-family posture, every table here is operator-authored
Guardian enforcement config with no bounded/re-derivable telemetry tier to carve out —
so the whole store is **authoritative**, simpler than its GuaranteedStateStore sibling:

- **Baseline CRUD writes — fail-hard** (unchanged from pre-migration):
  `create_baseline`/`update_baseline`/`delete_baseline`/`set_members`/`set_assignment`
  stay `std::expected<..., std::string>`, `kConflictPrefix`-tagged conflicts mapping to
  HTTP 409.
- **The catastrophic-read set (CLAUDE.md Guardian invariant).** `deployed_member_rule_ids()`
  — **both overloads** (the fleet-union used by the push fan-out + heartbeat reconcile,
  and the per-Baseline form used by the baseline-anchored per-device compliance REST
  view) — move to `std::expected<..., std::string>`. The pre-migration SQLite store
  returned a plain container, empty-on-degrade; that was fine under SQLite's
  open-or-not binary failure mode but is exactly the fail-open shape ADR-0036/0038
  closed elsewhere under Postgres's richer failure surface (lease timeout, query
  error). Every push/reconcile/REST consumer now aborts (503 / no-op push, sentinel
  `-2`) on `!result`, mirroring `GuaranteedStateStore::list_rules()`'s handling exactly
  — never fans out an empty deployed-set indistinguishable from "nothing deployed" (a
  fleet-wide silent disarm) or renders a device falsely "compliant" (0 guards reported).
  A malformed **or genuinely empty** stored `deployed_snapshot` is **not** a degrade —
  it is a successful read that contributes nothing to the union, unchanged,
  fail-closed-by-construction behavior pinned by the pre-migration store's own doc
  comment.
- **`get_members_checked()`** — a new degrade-distinguishable twin of the pre-existing
  plain `get_members()`, for the ONE call site (the deploy handler,
  `guardian_routes.cpp`) that writes a live-member read into a **durable** enforced
  snapshot. A lease timeout there previously (silently) risked persisting
  `deployed_snapshot = "[]"` — a durable disarm of that Baseline, strictly worse than a
  transient read failure elsewhere, and a real Postgres runtime path (pool-lease
  timeout) that SQLite's single-file-open-or-not model never exercised. Every other
  `get_members()` caller (dashboard fragments, the "drifted from deployed" diff) stays
  render-only / deny-or-benign and keeps the plain empty-on-degrade container
  (ADR-0038 "deferred widening" class) — a full widening of every read touches ~10
  call sites for no additional safety, out of scope for this PR.
- Every other read (`list_baselines`/`get_assignment`/`baselines_containing_rule`/
  `list_deployed_baselines`/counts) stays plain container/`size_t`, empty-on-degrade —
  dashboard display only, never an enforce/target decision.

### Backfill (ADR-0009) — mandatory, fingerprint-verified

Deployed baselines + their snapshots are live enforcement state — a lost deploy
snapshot disarms or mis-scopes enforcement — so backfill is mandatory, not skippable.
Follows the **TagStore/RbacStore post-#2703 shape**
(`docs/postgres-store-playbook.md` "Local source absence never creates terminal
migration state on its own"), not ADR-0038's simpler marker-only shape which predates
that lesson: a `baseline_store_meta` k/v marker pair (`backfill_complete` +
`backfill_source_fingerprint`, a SHA-256 over the canonicalized legacy content,
`"v1:<hex>"`), stamped together in one transaction as a monotonic promotion (a
`sourceless` value may be promoted by a real fingerprint; a real value is never
overwritten). A replica that still holds its own local legacy file when the marker is
already set **verifies that file's content against the stored fingerprint**
(holder-side verification) before trusting the marker — refusing
("HOLDER-SIDE VERIFICATION FAILED") rather than silently accepting a completion this
replica's data was never part of.

**Scaled to three tables with FKs — the specific design this ADR records:**

- All three legacy tables are read inside **one deferred SQLite transaction** (load-
  bearing here, unlike TagStore's single-table case: a torn read across the parent and
  its two child tables could fingerprint/migrate a parent whose children were captured
  from a different instant).
- **Parent rows** (`baselines`) are migrated per-row, **direction-aware on
  `updated_at`** (the DeploymentStore/TagStore shape) — IDENTITY is `baseline_id` (a PK
  match); every other column is LIFECYCLE. Identical → benign no-op. Postgres
  strictly ahead → benign no-op, warn-logged. Legacy strictly ahead, or tied with
  differing content → **fails closed**, unstamped (a future boot retries). A fresh
  legacy `name` colliding with a DIFFERENT already-live `baseline_id`'s `UNIQUE(name)`
  also fails closed — a name conflict between this replica's legacy data and live
  Postgres data cannot be auto-resolved.
- **Child rows** (member + assignment) are copied **only for a parent freshly inserted
  this pass.** A baseline that already existed live (Postgres-ahead or identical)
  already has complete, authoritative children via `set_members`/`set_assignment`'s
  own atomic full-replace semantics — re-merging its legacy children row-by-row would
  be redundant at best and a stale partial overwrite at worst. This is safe against a
  concurrent writer: the freshly-inserted parent row is uncommitted-and-invisible to
  every other transaction until this one commits, so nothing else could have written a
  member/assignment row against it in the interim. This is the one place BaselineStore's
  three-table M:N-with-atomic-replace shape diverges from TagStore's flat single-table
  design, and from GuaranteedStateStore's five-independent-tables design — it was
  chosen because it is simpler AND provably correct for this specific shape, not
  because it was copied from a precedent.
- Legacy file retained read-only, moved aside (`.migrated-<epoch>`) after a verified
  backfill — one release rollback window, matching every other migrated store.

### Lifecycle / concurrency

No background thread (bounded operator config, no retention reaper — unchanged from
pre-migration). The SQLite single-writer `shared_mutex` is deleted; Postgres real
concurrency replaces it. Mutate-and-return uses `RETURNING` (#1033); no
`sqlite3_changes()`-after-step survives.

## Considered and rejected

- **ADR-0038's simpler marker-only backfill** (no fingerprint, no holder-side verify):
  rejected — it predates the #2697/#2703 lesson and the kickoff plan for this
  migration explicitly calls for fingerprint verification; Baseline data is
  operator-authored fleet-wide config (the RbacStore/TagStore/CustomPropertiesStore
  family), not GuaranteedStateStore's bulk-telemetry-plus-config mix.
- **DeploymentStore/LicenseStore's per-distinct-legacy-file `sqlite_backfill_source`
  table** (multiple independently-valid legacy files, each fingerprinted and marked
  separately): rejected — that shape fits genuinely per-host-divergent data
  (ad-hoc deployment jobs, license activations). Baselines are a single shared
  fleet-wide control surface (like tags, RBAC, custom properties), so the single
  global marker + holder-side-verify shape is the correct family match.
- **Full `std::optional`/`std::expected` widening of every read** (list_baselines,
  get_assignment, etc.): rejected for this PR — none of those reads feeds an
  enforce/target decision (the playbook's deny-or-benign class); tracked as a
  follow-up if a future consumer changes that classification.
- **Merging legacy children into an already-live parent's member/assignment set**
  (union rather than skip): rejected — `set_members`/`set_assignment` are
  whole-set-replace by design; a merge would silently resurrect a Guard/group an
  operator had deliberately removed post-cutover on the live side.

## Consequences

- The push fan-out and heartbeat reconcile gain an explicit degraded-store abort path
  (503 / sentinel `-2` / audited `degraded` result) — a behavior change: previously a
  broken store could (in principle) fan out an empty deployed-set; now it refuses.
  Changelog fragment + a `docs/user-manual/guaranteed-state.md` note if warranted.
- The baseline-anchored per-device compliance REST view (`GET
  /api/v1/guaranteed-state/baselines/{name}/devices/{agent_id}`, `rest_api_v1.cpp`)
  now 503s on a degraded `deployed_member_rule_ids(baseline_id)` read instead of
  silently rendering "0 guards, fully compliant".
- Tests: `tests/unit/server/test_baseline_store.cpp` moves to
  `YUZU_REQUIRE_PG_DB_TPL` + a file-local `PgTestTemplate` (`"baselinestore"` key,
  shared with any other file needing the same store set — `test_guardian_routes.cpp`
  and `test_rest_guaranteed_state.cpp` both attach to it). New coverage: the
  catastrophic-read set's snapshot-not-live-members invariant, malformed-snapshot-is-
  a-skip-not-a-degrade, `get_members_checked()`'s degrade-distinguishability, and five
  backfill scenarios (populated/idempotent, fresh-install, Postgres-ahead-skips-
  children, legacy-ahead-fails-then-retry-succeeds, live-name-conflict-fails,
  holder-side-mismatch-refuses).

## Follow-ups

- Full read-widening of the deny-or-benign reads, if a future consumer starts feeding
  one into an enforce/target decision (none does today).
- `remove_rule_everywhere()`/`remove_group_everywhere()` (the Guard-delete /
  management-group-delete cross-store cleanup hooks) remain unwired from any live
  caller — unchanged from pre-migration; wiring them is a later slice
  (`docs/guardian-baseline-model.md`).
