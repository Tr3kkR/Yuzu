---
status: accepted
date: 2026-08-14
owner: platform (Postgres substrate migration program)
deciders: parallel Wave 2 migration worker (batch 2), following the ladder assignment in
  `docs/postgres-migration-ladder.md` (Wave 2)
scope: server — `LicenseStore` (product license activation/entitlement, capability 22.3), its
  cutover from SQLite to PostgreSQL, and its ADR-0009 backfill
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend, no SQLite fallback),
  ADR-0008 (substrate architecture), ADR-0009 (per-store first-boot backfill cutover),
  ADR-0010 (secrets at rest), ADR-0012 (server Postgres store contract)
related: docs/postgres-migration-ladder.md (Wave 2); docs/adr/0043-deployment-store-postgres-migration.md
  (the authoritative-with-backfill/IDENTITY-LIFECYCLE template this migration follows most closely)
---

# 0048 — `LicenseStore` Postgres migration (authoritative, dormant, with backfill)

## Context

`LicenseStore` (`server/core/src/license_store.{hpp,cpp}`) persists product license activations
and their derived alerts (capability 22.3). It is a Wave 2 store on
`docs/postgres-migration-ladder.md`. It was previously a SQLite store (`license.db`, tables
`licenses` and `license_alerts`) guarded by a single `shared_mutex`.

**This store is deliberately DORMANT on `dev` as of this writing — verified, not assumed.**
`git grep -nE 'make_unique<LicenseStore>|new LicenseStore'` across the repository finds no
production construction site — no code path builds a `LicenseStore` via `make_unique`/`new`.
That grep pattern cannot see stack-allocated construction, and one exists: this migration also
found `tests/unit/server/test_rest_api_t2.cpp` stack-constructing a `LicenseStore` directly (six
call sites), missed by the kickoff doc's own verification command — re-verify with a broader
pattern before trusting "outside tests" as a claim about which files, not just which allocation
form. Both test files (`test_license_store.cpp` and `test_rest_api_t2.cpp`) are migrated to the
Postgres API in this same PR. `rest_api_v1.{hpp,cpp}`
takes `LicenseStore* license_store = nullptr` and registers `/api/v1/license*` routes behind
`if (license_store)`; with no construction site the routes never register. History (pickaxe):
construction was added in `acc6c481a` ("Add T2 capabilities") and removed by `2fcfb95b5`
("Decompose server.cpp god object"). Dave confirmed 2026-08-14 that this dormancy is
purposeful — licensing is shelved for now, not accidentally broken — so this ADR records it as
a deliberate current state, not a defect, and files no issue for it.

**Re-wiring the store at boot is explicitly OUT OF SCOPE for this migration.** This ADR migrates
the store's persistence layer only.

**Backfill is NOT skippable on the strength of that dormancy.** The store WAS constructed during
the `acc6c481a..2fcfb95b5` window, so a deployment that upgraded through that window can hold a
real `license.db` with genuinely activated licenses. There is no production fleet today (memory:
"fresh-build does not downgrade a defect/obligation" is the standing rule this ADR follows), so
the backfill code path below is shipped and unit-tested but has, like the store's own
construction, zero production callers as of this writing — `server.cpp` calls neither. It is
wired the moment a future change re-constructs `LicenseStore`; the expected legacy filename is
`license.db` (the pre-removal construction site's argument), recorded here so that future
re-wiring does not have to archaeology it out of history.

## Decision

**Migrate `LicenseStore` to PostgreSQL as schema `license_store`, tables `licenses` and
`license_alerts`, with a standard ADR-0009 first-boot backfill.**

### Schema

- Schema name `license_store` (ADR-0008 Update naming rule: `snake_case(FullClassName)`
  including the `Store` suffix — this also happens to match the original SQLite
  `MigrationRunner::run(db_, "license_store", ...)` tracking name unchanged).
- `licenses` carries the existing columns unchanged in meaning and type mapping (`TEXT`→`TEXT`,
  `INTEGER` epoch-seconds/count columns→`BIGINT`). `id` stays a **client-generated `TEXT`
  primary key** using the ORIGINAL 32-hex-character `generate_id()` format (16 random bytes via
  `mt19937_64`, not `DeploymentStore`'s 16-hex/8-byte format) — pre-migration ID contracts are
  kept exactly, per the Wave 2 lesson from #3062, and that lesson is about preserving the
  **existing** format, not converging every store onto the same one.
- `license_alerts` carries its existing columns, with `id` remapped from SQLite `INTEGER PRIMARY
  KEY AUTOINCREMENT` to Postgres `BIGSERIAL PRIMARY KEY` (a DB-generated surrogate — legacy
  integer alert ids are NOT preserved across backfill, only re-minted; nothing external
  references an alert id as a stable identifier). `acknowledged` becomes `BOOLEAN`. A new
  `UNIQUE (license_id, alert_type, triggered_at)` constraint is added — see Backfill below for
  why.
- A new table, `sqlite_backfill_source (fingerprint TEXT PRIMARY KEY, completed_at BIGINT NOT
  NULL)`, is the backfill idempotency tracker (see Backfill below) — not part of the application
  data model.
- No foreign keys — `license_alerts.license_id` remains a **soft reference**, matching the
  pre-migration schema exactly (an alert row is never rejected for referencing a license id that
  doesn't currently exist; `remove_license` deletes a license's alerts explicitly rather than via
  cascade).

### Secrets (ADR-0010)

The license key is stored **hash-only** (`license_key_hash`, SHA-256 via the existing
cross-platform `hash_key()` helper — BCrypt on Windows, OpenSSL elsewhere, kept as-is). The raw
key is never persisted; `activate_license` receives it, hashes it, and discards it. This is a
verify-only hash column, not envelope-encrypted secret material, so `SecretCodec` is not
involved — this is exactly why this store sits in Wave 2 rather than the secret-gated Wave 3.
No other column holds secret material — confirmed by the `security-guardian` Gate 2 governance
review (2026-08-14).

### Posture

**AUTHORITATIVE / fail-hard** (ADR-0012 §1), both construction and runtime:

- **Construction fails closed**, same template as every other Postgres-backed store.
- **The database is the source of truth for license entitlement.** A silently-empty
  `get_active_license`/`has_feature` on a degraded read would silently drop licensed features —
  the exact fail-open shape ADR-0012's type-distinguishability rule exists to close (confirmed
  against the #3064/DiscoveryStore precedent cited in the kickoff). Every reader/mutator
  therefore returns `std::expected<..., std::string>` (or `std::expected<std::optional<T>,
  std::string>` for "found vs not-found vs degraded" reads), never a bare `bool`/`vector`/scalar
  that collapses "no data" and "couldn't read" into the same falsy value.
- Every genuine DB/lease failure is prefixed `db_error: ` (`kLicenseDbErrorPrefix`, a
  store-local constant — deliberately not a reuse of `kDeploymentDbErrorPrefix`: the two stores'
  routes live in different files and have no reason to share a symbol, so a rename of one must
  not risk silently affecting the other). `rest_api_v1.cpp` gets a local three-way classifier,
  `license_error_status`, mirroring `access_review_error_status`'s contract-pin style:
  `not_found: ` → 404, `db_error: ` → 503, anything else (validation / business-rule errors —
  e.g. "license key already activated") → 400. This preserves the pre-migration route's 404 for
  a missing license id on `DELETE`, which a blanket `DeploymentStore`-style binary classifier
  would have regressed to 400.
- `activate_license`'s duplicate-key check moves from a check-then-insert (a TOCTOU race in the
  original SQLite code — a `SELECT` followed by a separate `INSERT`) to a single atomic
  `INSERT ... ON CONFLICT (license_key_hash) DO NOTHING RETURNING id`, reading `PQntuples()` to
  learn whether this call's row actually won. This is a deliberate hardening beyond a literal
  port, endorsed by `docs/postgres-store-playbook.md`'s own anti-pattern guidance preferring an
  atomic upsert over check-then-act.
- `remove_license` now runs inside one bounded transaction (`with_txn_for`) that deletes the
  license's alerts and then the license row itself, instead of two independent best-effort
  statements — so a delete either fully lands or fully doesn't, never leaving an orphaned alert
  or a removed license with its alerts still present.
- `validate()` (the periodic status-recompute pass) is likewise wrapped in one bounded
  transaction: every status transition and the alerts it produces for one `validate()` call
  commit atomically, or none do. This is a deliberate strengthening over the original — which
  processed each active license independently, best-effort, ignoring write failures — consistent
  with "surface failures, don't swallow" for a write path (kickoff lesson #3, the #3064
  precedent).
- `has_feature`/`seat_count`/`days_remaining`/`get_status` are converted to
  `std::expected<T, std::string>` even though nothing in the current tree calls them outside
  `rest_api_v1.cpp` (the first two) and tests (all four) — `has_feature` in particular is
  exactly the ADR-0036 worked shape ("could a silently-false read gate a downstream
  grant/enforce decision?"): a future caller using it to gate an enterprise feature must not be
  able to receive `false` for both "genuinely unlicensed" and "the database is down" without a
  way to tell them apart. The store exposes the typed channel unconditionally per ADR-0036's
  "the store exposes the type regardless of the current caller" rule; it is the caller's job to
  fail closed on `unexpected` once one exists.
- The four redundant single-column queries (`has_feature`/`seat_count`/`days_remaining`/
  `get_status` each independently re-select the most-recent-active-license row for one column)
  are preserved as-is, not consolidated — this predates the migration and consolidating it is
  unrelated scope creep against the "small changes, small files" standing rule.

### `/readyz` / `/healthz`

**Not wired.** Every other migrated authoritative store on this ladder is wired into both
conjunctions, but `LicenseStore` has no construction site in `server.cpp` at all (see Context) —
mirroring how the store is not constructed, it is not probed either. There is nothing to wire a
pointer that never exists into. Recorded explicitly, per the kickoff's instruction not to let
this read as an oversight: when a future change re-wires construction, add the `/readyz`/
`/healthz` conjunction entries at that time, matching the other migrated stores' pattern.

### Backfill (ADR-0009)

**Mandatory, standard shape, fingerprint-verified** — matches the `DeploymentStore`/#3062
reference most closely of the already-migrated Wave 2 stores (client-generated surrogate `id`,
no small-human-chosen-identifier collision risk `RbacStore` has to guard against).

- A replica with no local `license.db` (or a present-but-schema-less one) computes and stamps a
  `sourceless` sentinel fingerprint, exactly as `DeploymentStore` does.
- **Half-schema legacy case, decided explicitly (not present in the single-table
  `DeploymentStore` reference — this store has two tables to probe):** the shipped SQLite
  migration (`license_store.cpp`'s `create_tables()`, pre-migration) creates `licenses` and
  `license_alerts` together, atomically, in one `MigrationRunner` step — no version of the
  shipped binary can produce a file holding exactly one of the two tables. So: neither table
  present → `sourceless`; both present → read and fingerprint both; **exactly one present fails
  the whole backfill closed**, treated as the same hand-edited/corrupted-file class as an
  unrecognised enum value, rather than silently treating the present table as the whole story.
- A replica holding real rows computes a SHA-256 fingerprint of a canonicalized, sorted
  serialization of **both tables' own rows**, versioned (`license-legacy-fingerprint-v1`), with
  an explicit row-count prefix ahead of each table's section — not just a per-field length
  prefix. A per-field length prefix alone makes one row's encoding injective, but does not make
  the SEQUENCE of two variable-length sections (`licenses` rows, then `license_alerts` rows)
  injective: a 10-field license row's encoding can be byte-identical to two consecutive 5-field
  alert rows' concatenated encoding, so `{licenses:[X,Z], alerts:[]}` could otherwise collide
  with `{licenses:[X], alerts:[Y1,Y2]}` where `encode(Z) == encode(Y1)+encode(Y2)`. Prefixing
  each section with its own row count closes this the same way `DeploymentStore`'s per-field
  length prefix closes the field-boundary case — this is the identical injectivity class
  `fjarvis` blocked #3062 on, one level up (rows within a section vs. sections within a file).
- **`licenses` conflict handling partitions columns into IDENTITY and LIFECYCLE, per the
  kickoff's explicit classification:** `license_key_hash`, `organization`, `seat_count`,
  `issued_at`, `expires_at`, `edition`, `features_json` are IDENTITY (write-once at INSERT — no
  other method mutates them; `seat_count` was initially omitted from both this list and the
  `identity_matches` comparison in code — a HIGH gov security-guardian finding, since it meets
  this same write-once criterion and a legacy-only seat_count divergence would otherwise have
  been silently discarded as "identical content" — fixed in both places); `status` and
  `activated_at` are LIFECYCLE. Note that `activated_at` is, in the
  CURRENT code, also write-once in practice (no method updates it post-insert) — it is
  classified LIFECYCLE anyway, per the kickoff's explicit instruction, because that is the
  forgiving direction: a mismatch on a field that never actually diverges in today's code warns
  and keeps Postgres's value rather than bricking the boot, and costs nothing if a future
  renewal/reactivation flow ever legitimately re-touches it. A conflicting row whose IDENTITY
  columns differ fails the backfill closed, naming both sides. A LIFECYCLE-only difference is
  resolved by direction, mirroring `DeploymentStore` exactly: a `status` rank of
  `active`(0) < `{expired, exceeded, invalid}`(1, tied) < unrecognised(2, backfill-rejected before
  ever reaching Postgres) decides which side is "ahead"; Postgres strictly ahead or a same-status
  tie is a benign no-op (WARNING-logged); the legacy row strictly ahead, or a same-rank pair
  disagreeing on WHICH terminal status, fails the boot closed (the ADR-0009
  rollback-then-roll-forward shape `DeploymentStore`'s Findings A and UP-E document). `activated_at`
  participates only in the equality check (benign-no-op vs. needs-a-direction-decision), never in
  deciding the direction itself — same role `started_at`/`completed_at`/`error` play in
  `DeploymentStore`.
- **`license_alerts` gets a deliberately SIMPLER treatment than `licenses`**, justified by what
  the two tables represent: alerts are derived/notification records regenerable by `validate()`,
  not independent operator-authored entitlement state — losing an alert's `acknowledged`
  transition on an adversarial multi-replica-diverging-snapshot backfill is a minor UX
  inconvenience (re-acknowledge it), not a security- or compliance-relevant silent loss, unlike
  `licenses.status` which gates `has_feature`/seat enforcement. Concretely: `license_alerts` has
  no legacy-preserved identity column to conflict on (its `id` is always freshly minted by
  Postgres), so a plain per-row `INSERT` with no matching key would duplicate an alert already
  migrated by an overlapping-but-differently-fingerprinted legacy snapshot from a sibling
  replica (the license-table analogue of the "identical-content conflict is a benign no-op" case
  `DeploymentStore`'s superset test exercises). The fix is a `UNIQUE (license_id, alert_type,
  triggered_at)` constraint plus `ON CONFLICT (license_id, alert_type, triggered_at) DO NOTHING`
  on the backfill insert — semantically sound (the same license, alert type, and trigger second
  is definitionally the same event) and, as of this writing, never tripped by live traffic
  (`add_alert`'s 24-hour app-level dedup window means two genuinely-distinct alerts of the same
  type for the same license are never generated in the same second either — a future change
  that shrinks that window would need to re-examine this claim). An `INSERT ... WHERE NOT EXISTS`
  without the DB constraint was considered and rejected: it reopens the READ COMMITTED
  fixed-snapshot race the playbook documents at length under `RbacStore`'s round-4
  bug — a concurrent revoke-and-reinsert can blow past a `WHERE NOT EXISTS` taken from a stale
  snapshot. The constraint makes the insert atomic and race-free without needing an explicit
  advisory lock.
- Legacy files are read READ-ONLY and never deleted/moved — retained for the ADR-0009
  one-release rollback window.
- Every legacy `status`/`alert_type` value is validated against the known enum set **before** it
  reaches Postgres — an unrecognised value fails the whole backfill closed, before any Postgres
  round trip, mirroring `DeploymentStore`'s `lifecycle_rank`-based legacy-status validation
  (kickoff item: "Validate legacy enum-ish fields... BEFORE they reach Postgres").
- The mid-scan-corruption guard is the same shape as `DeploymentStore`'s: the terminal SQLite
  step code for each table's scan must be `SQLITE_DONE`, never merely "loop exited", so a
  corrupt page is never silently treated as an empty/complete table.

## Considered and rejected

- **Sharing `kDeploymentDbErrorPrefix` instead of defining `kLicenseDbErrorPrefix`.**
  `DiscoveryStore`'s routes (which happen to live in the same `discovery_routes.cpp` file as
  `DeploymentStore`'s) do this. Rejected here: `LicenseStore`'s routes live in `rest_api_v1.cpp`,
  a different file with no existing dependency on `deployment_store.hpp`, and there is no reason
  to couple the two stores' error-prefix constants together — a future rename of one must not be
  able to silently affect the other's route classification.
- **A binary (prefix-only) error classifier**, matching `DeploymentStore`/`discovery_routes.cpp`'s
  "not the db-error prefix → 400" shape exactly. Rejected: the pre-migration `DELETE
  /api/v1/license/:id` route already distinguished 404 (not found) from a generic failure: a
  blanket binary classifier would regress that to 400 for a dormant route with zero behavioral
  cost today, but would be a needless behavioral regression the moment the route is ever
  re-wired live. A three-way classifier (`not_found:` / `db_error:` / else) costs one `if` more
  and keeps parity with `access_review_error_status`'s existing precedent in the same file.
- **Preserving legacy `license_alerts.id` (AUTOINCREMENT) values across backfill.** Rejected —
  nothing external references an alert id as a stable cross-boot identifier (no REST route takes
  an alert id as a path parameter; `acknowledge_alert(id)` is looked up within a single boot's
  lifetime), so remapping to a Postgres-assigned `BIGSERIAL` is the plain, playbook-endorsed
  choice ("license_alerts.id AUTOINCREMENT maps to identity per the playbook").
- **Consolidating the four single-column `has_feature`/`seat_count`/`days_remaining`/
  `get_status` queries into one call sharing `get_active_license`'s result.** Rejected as
  unrelated scope creep — the redundancy predates this migration and this ADR ports behavior,
  not opinions about it.

## Consequences

- Every license read/write now surfaces a genuine database error to its REST caller as a 503
  instead of a silently-empty/-false SQLite-mutex-guarded result. Because the store is dormant,
  this has zero production behavioral effect today — it takes effect the moment a future change
  re-constructs `LicenseStore`.
- The legacy `license.db` is retained for one release (ADR-0009 rollback window) once a future
  re-wiring gives it somewhere to be found, then removed per the standard cadence.
- `LicenseStore` moves from "SQLite, mutex-serialized" to "Postgres, pool-concurrent" — matches
  every other migrated store's concurrency model; no separate follow-up needed.
- The store's dormancy is now a recorded, deliberate fact (this ADR + the ladder row) rather than
  something a future reader has to re-derive from a two-commit pickaxe search.
