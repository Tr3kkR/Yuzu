# ADR-0041: RbacStore → PostgreSQL (Wave 2.1)

- **Status:** Accepted (governance-resolved 2026-08-01 — the deferred cache-coherence
  decision below was adjudicated by the security/architect/performance/compliance gates in favour
  of the generation-token interval; see "Permission cache")
- **Date:** 2026-08-01
- **Deciders:** pg workstream; security-guardian + architect + performance + docs-writer (governance)
- **Parents:** ADR-0006/0007/0008(+Correction), ADR-0009, ADR-0012, ADR-0017 (management-group
  confinement / `authorize_list_read`), ADR-0031 (engine-principal default-deny); conventions
  from ADR-0036/0037/0038/0039/0040 (esp. `sanitize_pg_text`, the fail-closed-boot + advisory
  patterns). ADR-1005 (RBAC enforced at the API).

## Context

`RbacStore` (`rbac.db` today, `server/core/src/rbac_store.{hpp,cpp}` — the LARGEST store on the
ladder, ~2.5k LOC) is the **authorization substrate**: role definitions, role→permission grants,
principal→role assignments, RBAC groups + membership, and the global `rbac_enabled` flag.
`require_permission` / `require_scoped_permission` / `authorize_list_read` (World-A confinement,
ADR-0017) / the engine-principal default-deny path (ADR-0031) all resolve through it. A migration
defect here is a **fleet-wide authorization failure** — the highest-blast-radius store on the
queue. First row of Wave 2 (authoritative config that cannot be lost).

Two properties make this migration materially harder than the Wave-1 stores:

1. **The hot authz reads return `bool`.** `check_permission` / `check_scoped_permission` /
   `holds_permission_via_any_group` / `check_role_has_permission` answer allow/deny. The SQLite
   implementation **fails CLOSED** on any error (`if (!db_) return false;`, prepare-fail →
   `return false`, no rows → deny). That deny-on-error posture is a *security invariant*, not an
   incidental — it must survive the port byte-for-byte in meaning.
2. **There is an in-process permission result cache** (`perm_cache_`) invalidated by a
   **process-local** `write_generation_` counter (a local mutation bumps it; a read clears the
   cache when generations differ). On one SQLite server that is correct. Under PostgreSQL with
   **N replicas**, replica A's `assign_role`/`unassign_role`/`set_permission` bumps only A's
   counter — replica B keeps serving its stale cache, i.e. **a revoked permission stays allowed
   on B** (stale-allow) until B happens to do a local write. That is a cross-replica coherence
   hole the substrate flip introduces, and on the authz store it is a security defect, not a perf
   nit.

## Decision

Migrate to PostgreSQL schema **`rbac_store`** (ADR-0008), construction fail-closed
(ADR-0007/0012 §1), on the shared server PgPool. `mtx_`/`shared_mutex` deleted; PG concurrency
replaces the single-writer.

### Schema

`roles`, `role_permissions`, `principal_roles`, `groups`, `group_members` port column-for-column;
a `rbac_meta` k/v table holds the durable `rbac_enabled` flag **and** the cross-replica
`write_generation` counter (below). All indexes carry over. `sqlite3_changes()` → `RETURNING` /
`PQcmdTuples` (#1033) on every mutator.

### Reads FAIL CLOSED (the load-bearing invariant)

Every authz read keeps its `bool`/deny-on-error contract: a store-not-open, pool-acquire timeout,
or query error returns **deny** (`false` for the bool checks; the empty/most-restrictive result
for the list/scope reads), NEVER allow. This is asserted with dedicated fail-closed tests
(unroutable-DSN pool → every `check_*` returns false; a mid-query degrade denies). The migration
must not convert any deny-on-error into an engaged-allow. Where a caller needs to distinguish
"denied" from "store degraded" for a 403-vs-503 decision, that is exposed via a **separate**
`std::expected`/tri-state accessor (e.g. for `authorize_list_read`) — the plain `bool` path stays
deny-on-error so no existing chokepoint can regress to fail-open. (This also closes the standing
"`authorize_list_read` fails open on a corrupt `rbac.db`" concern the routed-concern notes flag:
a corrupt/unreachable `rbac_store` now denies, never admits.)

### Permission cache — shared PG generation token (cross-replica coherence)

The process-local `write_generation_` becomes a **durable `rbac_meta.write_generation` counter**,
bumped **in the same transaction** as every mutation (`assign_role`, `unassign_role`,
`set_permission`, `remove_permission`, `create/update/delete_role`, group changes,
`set_rbac_enabled`). Each replica keeps its in-process `perm_cache_` but validates it against the
DURABLE generation:

- A read refreshes its cached view of the durable generation at most once per short interval
  (`kRbacGenerationRefreshMs`, proposed **1000 ms** — one cheap indexed `SELECT` of a single
  counter row, not a re-query of permissions); on a generation change it clears `perm_cache_`.
- A local mutation bumps the durable counter and clears the local cache immediately (so the
  writing replica is always coherent with itself).

This bounds cross-replica staleness to the refresh interval under normal conditions: a revoke on
replica A is typically visible to replica B within `kRbacGenerationRefreshMs`. That bound is a
target, not a hard guarantee — the interval-gating timestamp is claimed before the refresh query
runs (deliberately, to prevent a stampede), so a reader racing a genuinely slow in-flight refresh
can observe staleness beyond it. That condition is measured via a separate completion-only
timestamp and a `stale_beyond_accepted_bound` degrade (fjarvis #2703 F3) rather than silently
assumed; the read still proceeds from the existing cache. Deny-on-error on the generation read
itself is mandatory (a failed generation refresh must NOT extend trust — treat as "assume changed"
→ clear cache, and count a `generation_refresh_failed` degrade).

**Gate decision (2026-08-01) — ACCEPTED: the generation-token interval, ~1s bounded stale-allow.**
The security, architect, performance, and compliance gates converged: dropping the cache (option
a) turns every authorized request into 2 PG round-trips on the shared pool, whose fail-closed
result under saturation is *spurious denials* (an availability regression); the ~1s cross-replica
window is well inside the fleet's existing revocation-latency envelope (heartbeat + session/token
TTLs measured in minutes); and `LISTEN/NOTIFY` (option b) is the right *eventual* answer (window →
0 without the per-check pool tax) but adds a listener connection + reconnect/missed-notify
handling that belongs in its own hardening round. The bounded window is an **accepted, recorded
residual risk**, not an open question. LISTEN/NOTIFY remains the named follow-up.

### Backfill (ADR-0009) — MANDATORY, with a critical flag-preservation clause

RBAC state is authoritative operator-authored config that **cannot be re-derived**: custom roles,
every principal→role grant, groups, and membership. Losing them silently reverts the fleet to the
seeded defaults — an authorization change nobody authorized. So a one-time, single-shot, idempotent
(retried from scratch on interruption — not a cursor-resumed stream, unlike AuditStore's larger
dataset), reconciled, **fail-CLOSED** backfill from the legacy `rbac.db` (the ADR-0040 marker+
fingerprint pattern, right-sized for a small non-resumable dataset — governance re-review, #2703),
seeding defaults first then backfilling operator rows via `ON CONFLICT DO NOTHING`. A built-in
default the operator explicitly revoked before upgrading is **deleted** post-seed — matching legacy
exactly, a plain absent row — scoped to (role, securable_type) pairs the legacy catalogue actually
knew about; a securable a later seed adds (e.g. `EnginePrincipal`, #2376) is untouched. The
revocation is recorded SEPARATELY, as pure reseed-suppression bookkeeping in a dedicated
`revoked_seed_defaults` table consulted ONLY by the seed step's own grant helper — never by any
authorization-decision code path — so the idempotent every-boot reseed cannot silently resurrect it
without the deleted row ever becoming a real authorization fact again. This mirrors
`remove_permission()`'s own permanent mechanism for the identical hazard beyond the one-time cutover
(fjarvis #2703 F1). THREE earlier versions of this fix each reintroduced a hazard, all caught by
governance before merge (none ever pushed to `origin`): a plain DELETE with no marker resurrects on
the very next restart (the idempotent reseed has nothing left to suppress it); an `effect='deny'`
tombstone avoids that but is a REAL authorization fact — `check_permission()`/
`check_scoped_permission()`/`authorize_list_read()` all apply "deny overrides everything, across ALL
of a principal's held roles" (pre-existing, identical in the legacy store), so the tombstone
silently changed the OUTCOME for any principal holding a second role that independently grants the
same permission, on both the global and the management-group-scoped read paths; the DELETE+marker
design that fixes both of those has its own concurrency hazard (CHAOS-1, found by chaos-injector
governance) — `seed_defaults()`'s grant() (`INSERT ... WHERE NOT EXISTS(marker) ... ON CONFLICT DO
NOTHING`) fixes its READ COMMITTED snapshot at statement start; if that snapshot predates a
concurrent revoke's marker commit, but grant() then blocks on the `ON CONFLICT` arbiter waiting for
that revoke's uncommitted DELETE, Postgres only re-checks the conflict target after unblocking —
never the `WHERE NOT EXISTS` subquery — so grant()'s already-computed row lands anyway once the
revoke commits, resurrecting the permission with the marker present but ineffective. Most likely to
fire during a fleet-wide rolling restart, where many replicas' `seed_defaults()` calls run
concurrently with another replica's one-time backfill. Closed with a `pg_advisory_xact_lock`,
acquired in its own statement strictly BEFORE the check-and-mutate statement, in an explicit
transaction, in all three writers (`grant()`, `remove_permission()`, the backfill's own revoke
step) — verified empirically with two real Postgres connections. The `revoked_seed_defaults` table
plus this lock close all three: absence on the read path restores exact legacy semantics, the
marker survives every future reseed, and the lock makes the marker-then-reseed sequencing safe
under concurrent writers.

**The `rbac_enabled` flag is the single most dangerous row to lose.** If an operator ENABLED RBAC
and the flag is not carried across, the fleet silently boots RBAC-**off** — every confined
operator becomes fleet-wide-authorized (catastrophic fail-open). The flag is therefore migrated
first and its transfer is verified (read-back-after-write) before the store is considered open;
a flag-backfill failure fails the whole backfill closed. Reconciliation counts roles + grants +
groups + members and refuses the completion marker on any shortfall. Legacy `rbac.db` moved aside
after a verified backfill.

### Untrusted columns

Role/group names and principal ids are operator- or agent-supplied. They are already
charset-validated at the API, but any free-text column is scrubbed with `sanitize_pg_text`
(UTF-8 + NUL, ADR-0039/0040 generalization) before an INSERT so no value can fail a write.

### Lifecycle

`stop()` unwires the store from every consumer (the `require_permission`/`authorize_list_read`
seams) then resets before `pg_pool_`; store in `/readyz` AND `/healthz`. No background thread is
added (the generation refresh is inline, bounded).

## Considered and rejected

- **Fresh-start / re-seed only (the AuthDB precedent)**: rejected — AuthDB could re-seed the
  config-file admin, but RBAC grants/custom-roles are irreducible operator intent; a reset would
  silently drop authorization the operator authored. Mandatory backfill.
- **Keep the process-local generation counter**: rejected — it is the cross-replica stale-allow
  hole; the counter must be durable/shared.
- **Per-check generation read (no interval)**: rejected as the default — a PG round-trip per
  authz check defeats the cache and loads the hot path; the bounded refresh is the compromise
  (gates may still choose drop-the-cache).

## Consequences

- Authorization is fleet-consistent across replicas within a bounded window; a corrupt/unreachable
  RBAC substrate denies (fail-closed) instead of the prior corrupt-`rbac.db` fail-open.
- RBAC config (roles/grants/groups/enabled) is preserved across the cutover (mandatory backfill).
- Tests → `YUZU_REQUIRE_PG_DB_TPL` + a file-local `"rbacstore"` `PgTestTemplate`; backfill /
  fresh-DB / fail-closed-degrade tests use plain `YUZU_REQUIRE_PG_DB`.

## Follow-ups

- If the gates choose LISTEN/NOTIFY over the generation-token interval, it lands as a hardening
  round with its own perf measurement.
- Wave 2 continues with `ManagementGroupStore` (authz/targeting) next.

## Update (2026-08-11) — bounded stale-serve on refresh failure supersedes "assume changed"

The Decision section above states, as a mandatory requirement: "a failed generation refresh
must NOT extend trust — treat as 'assume changed' → clear cache". A follow-on availability-
hardening pass (#2703 Gate 7 merge-slice items 1A-1C, operator-adjudicated design parameters)
deliberately supersedes that specific requirement — the rest of the Decision (durable
generation token, ~1s refresh interval, deny-on-degrade as the eventual outcome) is unchanged.

**What changed:** a failed generation refresh (pool-acquire timeout, query error, or a
fail-fast circuit breaker denying the attempt without touching the pool) no longer clears
`perm_cache_` immediately. Trust is extended for a bounded **~5s** window
(`kRbacStaleServeBoundMs`) past the last confirmed-good refresh — a deliberate
bounded-staleness-for-continuity tradeoff, chosen because clearing the cache on every
transient blip turned a brief pool hiccup into an immediate fleet-wide authorization outage,
which is a worse availability posture than tolerating a few seconds of staleness. Only once
the 5s bound is exceeded does the store fall back to the original "assume changed" behavior
and clear the cache. **This bound covers two distinct pieces of cached trust, not one:**
`perm_cache_` (individual cached allow/deny verdicts) as described above, and separately the
cached `rbac_enabled` view that `rbac_enforcement_in_effect()` consults — a refresh failure
inside the bound does not degrade EITHER, so a confinement-critical caller keeps trusting the
last-known-good `rbac_enabled` state (not just cached permission verdicts) through the same
short blip; only once the bound is exceeded does `rbac_enabled_view_degraded()` report true
and `rbac_enforcement_in_effect()` fail closed to "enforcement in effect" regardless of what
the raw flag last read. A new fail-fast circuit breaker (2 consecutive pool-acquire/query
failures) independently bounds how long an uncached check can block on a doomed pool, without
itself affecting cache validity. That bound is tight (well under a second) ONLY for pool
exhaustion — a connection that cannot be acquired within the 250ms budget. A query that DOES
acquire a connection and then blocks on a PostgreSQL-side lock is bounded instead by PgPool's
`lock_timeout` (10s default); measured ~18.5s for 2 such attempts against a live held
`ACCESS EXCLUSIVE` lock on `rbac_meta` (#3016) — both modes converge on the same fail-closed
deny, not the same speed. See `docs/auth-architecture.md`'s "Cross-replica coherence"
section and `docs/enterprise-readiness-soc2-first-customer.md`'s "Availability posture under
PostgreSQL degradation" note for the full mechanism and its CAIQ characterization.

**Why this doesn't weaken the deny-on-degrade invariant:** the store never falls through to an
*allow* it hasn't already validated — it continues serving a previously-validated cached
decision for a bounded window, then denies. The invariant this ADR's Decision protects
(no engaged allow on a degraded read) holds throughout; only the timing of when a degraded
read converts to a deny changed.
