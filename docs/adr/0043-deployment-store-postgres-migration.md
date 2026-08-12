---
status: accepted
date: 2026-08-12
owner: platform (Postgres substrate migration program)
deciders: parallel Wave 2 migration worker, following the ladder assignment in
  `docs/postgres-migration-ladder.md` (Wave 2)
scope: server — `DeploymentStore` (operator-initiated ad-hoc deployment jobs, Issue 7.7), its
  cutover from SQLite to PostgreSQL, and its ADR-0009 backfill
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend, no SQLite fallback),
  ADR-0008 (substrate architecture), ADR-0009 (per-store first-boot backfill cutover),
  ADR-0012 (server Postgres store contract)
related: docs/postgres-migration-ladder.md (Wave 2 -> Done); docs/adr/0036-result-set-store-postgres-migration.md
  (the authoritative-with-backfill template this migration follows)
---

# 0043 — `DeploymentStore` Postgres migration (authoritative, with backfill)

## Context

`DeploymentStore` (`server/core/src/deployment_store.{hpp,cpp}`) persists operator-initiated
ad-hoc deployment jobs — SSH / group-policy / manual agent installs (Issue 7.7). It is a Wave 2
store on `docs/postgres-migration-ladder.md`. It was previously a SQLite store
(`deployment-jobs.db`, table `deployment_jobs`) guarded by a single `shared_mutex`.

**Naming trap:** `DeploymentStore` is a different, older concept from `DeploymentRunStore` (the
`/auto` Deploy feature's stage->execute state machine, schema `deployment_run_store`, already
Born-on-PG). Same English word, unrelated stores — this ADR does not touch
`deployment_run_store.*`/`deployment_engine.*`.

## Decision

**Migrate `DeploymentStore` to PostgreSQL as schema `deployment_store`, table `deployment_jobs`,
with a standard ADR-0009 first-boot backfill.**

### Schema

- Schema name `deployment_store` (ADR-0008 Update naming rule: `snake_case(FullClassName)`
  including the `Store` suffix).
- `deployment_jobs` carries the existing columns unchanged in meaning and type mapping
  (`TEXT`→`TEXT`, `INTEGER` epoch-seconds columns→`BIGINT`). No foreign keys, no constraint
  changes.
- `id` stays a **client-generated `TEXT` primary key** (`DeploymentStore::generate_id()` — a
  64-bit `mt19937_64` value formatted as 16 hex chars, mirrors
  `AccessReviewStore::generate_campaign_id`). Deliberately NOT switched to a Postgres-generated
  identity column — that would change the ID format/contract for any existing caller
  (`/api/deployment-jobs/:id`'s route regex is anchored on `[a-f0-9]+`).
- A new table, `sqlite_backfill_source (fingerprint TEXT PRIMARY KEY, completed_at BIGINT NOT
  NULL)`, is the backfill idempotency tracker (see Backfill below) — not part of the application
  data model.
- No secrets. Every column is plain application data (hostnames, OS/method enums, status,
  timestamps, an operator- or agent-supplied error string) — no `SecretCodec` involvement.

### Posture

**AUTHORITATIVE / fail-hard** (ADR-0012 §1), both construction and runtime:

- **Construction fails closed**, same template as every other Postgres-backed store: a schema
  that cannot migrate/open sets `startup_failed_` in `server.cpp`.
- **The database IS the source of truth for deployment-job state.** There is no in-memory
  authoritative layer above this store. A silently-empty `list_jobs` would read as "no
  deployments ever ran"; a silently-`false` `update_status`/`cancel_job` would let an operator
  believe a state change landed when it didn't. Both are correctness failures, not merely
  durability ones, so every reader/mutator returns `std::expected<..., std::string>` — a DB
  error is never papered over as an empty/not-found result (playbook "Authoritative reads must
  be type-distinguishable"). `get_job` in particular returns
  `std::expected<std::optional<DeploymentJob>, std::string>`: `nullopt` is a successful read of
  zero rows, `unexpected` is a genuine failure — the two REST call sites in
  `discovery_routes.cpp` were updated accordingly (503 on `unexpected`, 404 only on `nullopt`;
  previously a DB blip on the SQLite path silently read as 404).
- Every genuine DB/lease failure across all five store methods is prefixed `db_error: `
  (`kDbErrorPrefix`) -- a machine-checkable idiom mirroring `AccessReviewStore`'s `not_found: `
  convention (`rest_api_v1.cpp`'s `access_review_error_status`) -- so `discovery_routes.cpp` can
  classify a route's `unexpected` as 503 (DB outage) vs 400/404 (validation/business rule)
  without pattern-matching ad hoc message text. Hardening-round fix (adversarial review,
  2026-08-12): the initial cut only fixed the two READ routes; `create_job`/`cancel_job`
  collapsed every failure -- including a genuine Postgres outage -- to 400 until Kimi and Codex
  both independently found this and it was closed the same round.
- `cancel_job` mutates via a single guarded `UPDATE ... WHERE status IN ('pending','running')`
  rather than a check-then-write pair, so it stays race-safe against a concurrent second
  cancel/status-update without the SQLite version's `shared_mutex`. The zero-rows-matched
  follow-up read that distinguishes "not found" from "wrong state" for the error message is
  best-effort under concurrency (a race there can only change which message is reported, never
  the mutation's correctness).

### Backfill (ADR-0009)

**Mandatory** — an in-flight or completed deployment job is real, irreducible operator intent
(matches the ladder's Wave 2 framing: "operator state that cannot be lost").

**Content-fingerprinted, not a single fleet-wide completion flag** (revised in an
adversarial-review hardening round, 2026-08-12 -- Kimi and Codex both independently found, then
jointly confirmed under cross-examination after Kimi initially missed it, that the ORIGINAL
single-row `sqlite_backfill` marker violated the playbook's "Local source absence never creates
terminal migration state on its own" rule: a fileless replica's "nothing to backfill" stamp
would permanently wave through a DIFFERENT, holder replica's real legacy data on its next boot,
because the marker's `SELECT 1 ... LIMIT 1` short-circuit didn't care WHICH replica set it or
why). The shipped design instead tracks completion PER DISTINCT LEGACY-FILE CONTENT in
`sqlite_backfill_source (fingerprint TEXT PRIMARY KEY, completed_at BIGINT)`:

- A replica with no local legacy file (or a present-but-schema-less one) computes and stamps a
  `sourceless` sentinel fingerprint.
- A replica holding real rows computes a SHA-256 fingerprint of a canonicalized, sorted
  serialization of ITS OWN rows and checks/stamps THAT specific value.
- A holder's real fingerprint is a different primary-key value than `sourceless` and can never be
  satisfied by another replica's sourceless stamp, so it always proceeds to copy its own data --
  the anti-pattern is closed structurally, not by re-ordering two checks.
- The mid-scan-corruption guard is unchanged in shape: the terminal SQLite step code must be
  `SQLITE_DONE`, not merely "loop exited", so a corrupt page never gets silently treated as an
  empty table and fingerprinted/stamped. This check now runs BEFORE any Postgres round trip at
  all (fingerprinting happens client-side, before the completion lookup), so a corrupt file can
  never even reach the fingerprint check.
- Legacy files are read READ-ONLY and never deleted/moved -- retained for the ADR-0009
  one-release rollback window (matches `ResultSetStore`'s choice, not `RbacStore`'s move-aside).
- `server.cpp` treats a backfill failure exactly like a migration/open failure -- fatal,
  `startup_failed_`, never a serve-degraded state.

**Deliberately simpler than `RbacStore`'s post-#2703 reference shape** (single marker + stored
fingerprint + refuse-on-mismatch/refuse-on-sourceless-stored branches,
`docs/ops-runbooks/rbac-store-backfill-recovery.md`): that complexity exists there because RBAC
identifiers (role/group names) are small and human-chosen, so a late real backfill risks silently
clobbering live post-cutover grants sharing the same name -- the reference implementation refuses
and asks an operator to adjudicate rather than guess. `DeploymentStore`'s `id` is a 64-bit random
surrogate key (`generate_id()`); collision across independently-generated ids across replicas is
practically impossible, so every replica's real content is safe to copy independently and
idempotently (`ON CONFLICT (id) DO NOTHING`) whenever its own fingerprint hasn't been seen before
-- there is no clobber risk to reason about and no operator-adjudicated refuse path needed. This
is a deliberate, documented divergence from the reference shape (playbook: "copy the SHAPE...
record which way you went"), not an oversight.

**Trade-off accepted:** unlike `RbacStore` (which stats the legacy path cheaply before touching
Postgres, and skips entirely once the file is moved aside post-migration), this design reads the
local legacy file on every boot for as long as it remains in place, because "already migrated" is
now a content-addressed question that can only be answered by hashing the content. Accepted as
negligible here -- the file is small (ad hoc deployment jobs, not a high-volume table) and boots
are infrequent.

## Considered and rejected

- **Switching `id` to a Postgres `SERIAL`/`IDENTITY` column.** Rejected — see Schema above; would
  break the REST route's id format contract for no benefit (uniqueness is already adequate via
  the 64-bit RNG surrogate key).
- **`cancel_job` as an explicit `SELECT ... FOR UPDATE` + `UPDATE` transaction** (to make the
  not-found-vs-wrong-state error message race-free too, not just the mutation). Rejected as
  disproportionate: this is a low-frequency, operator-driven action (a human cancelling one job),
  not a security invariant — the single guarded `UPDATE` already makes the state transition
  itself correct under concurrency, and a mis-attributed error message under a genuine
  concurrent-write race is a cosmetic edge case, not a correctness one.
- **Wiring `deployment_store_` into `/readyz`/`/healthz`.** Initially deferred (see git history)
  with the rationale that sibling Phase-7 SQLite stores (`DirectorySync`, `PatchManager`,
  `DiscoveryStore`) aren't wired into either conjunction either. **Reversed in the governance
  Gate 3 sre review**: that comparison was to the wrong reference class — those three are
  pre-migration SQLite stores that predate the readyz-wiring discipline entirely, not evidence
  that omission is normal for a migrated Postgres store. Every OTHER migrated authoritative
  store on this ladder (`rbac_store`, `result_set_store`, `access_review_store`,
  `mgmt_group_store`, `api_token_store`, `engine_principal_store`, ...) IS wired into both.
  `DeploymentStore` was the sole exception. sre also verified `open_` is set exactly once
  (constructor success) with no runtime path that ever flips it back to `false`, so wiring it in
  carries zero risk of a spurious readyz/healthz flip — it is now wired into both, for parity and
  to stop this store being cited as precedent for a future genuinely-regressable one.
- **Fixing the pre-existing, dead `deployment_discovery_routes.inc` fragment's stale API calls
  in this PR.** Kimi's [DS-3]/Codex's [C-PG-004] (both LOW) found that this orphaned file --
  superseded by `discovery_routes.cpp` before this migration started, retained only as a fixture
  for `test_body_cap_route_inventory.cpp`'s route-inventory scan, never `#include`d or built
  (verified: `rg -n "deployment_discovery_routes"` finds no include/meson entry) -- still calls
  `DeploymentStore`'s pre-migration signatures and would fail to compile if ever resurrected.
  Deferred rather than fixed here: the file predates this migration and isn't part of its diff;
  fixing it is unrelated scope creep against the "small changes, small files" standing rule.
  Tracked as a follow-up issue instead.

## Consequences

- Every deployment-job read/write now surfaces a genuine database error to its REST caller as a
  503 instead of a silently-empty/-false SQLite-mutex-guarded result — an operator sees "service
  unavailable" instead of a misleading "no jobs"/404/generic 400 on a transient database blip.
  (Initially true only for the two read routes; the two write routes were fixed to match in the
  2026-08-12 hardening round -- see Posture above.)
- The legacy `deployment-jobs.db` is retained for one release (ADR-0009 rollback window), then
  removed per the standard cadence.
- `DeploymentStore` moves from "SQLite, mutex-serialized" to "Postgres, pool-concurrent" —
  matches every other migrated store's concurrency model; no separate follow-up needed.
- A fileless replica can never permanently block a holder replica's real deployment-job history
  from reaching Postgres (the HIGH finding this ADR's Backfill section documents closing) --
  verified by the empirical fix, not just by design review: `tests/unit/server/test_deployment_
  store.cpp`'s backfill test suite covers the sourceless/real/idempotent/mid-scan-corruption
  cases against a live Postgres instance.
