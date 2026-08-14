# ADR-0049: AnalyticsEventStore → PostgreSQL (Wave 2, batch 3)

- **Status:** Proposed
- **Date:** 2026-08-14
- **Deciders:** pg workstream; security-guardian + docs-writer (Gate 2) — construction-posture
  divergence flagged for Dave's explicit confirmation (see "Construction posture" below).
- **Parents:** ADR-0006/0007/0008(+Correction), ADR-0009, ADR-0012; closest posture precedent
  ADR-0039 (ResponseStore) — fail-soft ingest, expendable telemetry, skippable backfill. Drain
  claim pattern extends the single-sweeper advisory lease shipped in `audit_store.cpp` /
  `result_set_store.cpp` / `software_inventory_store.cpp` (ADR-0040).

## Context

`AnalyticsEventStore` (`analytics.db` today, `server/core/src/analytics_event_store.{hpp,cpp}`)
is an **outbox/spool**, not operator state: `emit()` inserts a JSON-serialized `AnalyticsEvent`
into `analytics_buffer`; a background thread (default 10s interval, batch 100) drains undrained
rows to registered `AnalyticsEventSink`s (JSONL file, ClickHouse HTTP) and marks them drained.
Writers include the auth/SCIM routes (login/MFA/OIDC/SAML/role-elevation events) and the
agent/gateway service handlers (command lifecycle events) — roughly 15 call sites, all already
null-guarding the store (`if (analytics_store_) { ... }`).

Public API: `emit(AnalyticsEvent)`, `query_recent(limit)`, `pending_count()`, `total_emitted()`,
`add_sink()`, `start_drain()`, `stop_drain()`, `is_open()`.

Wave 2 batch 3 on the ladder. The ladder row said `authoritative?` with "may suit a
TTL/ephemeral posture" — this ADR settles it.

## Decision

Migrate to PostgreSQL schema **`analytics_event_store`** (ADR-0008), on the shared server
`PgPool`.

### Schema

Single table, collapsed to v1 (the SQLite original had no later migrations to carry forward):

```sql
CREATE TABLE analytics_buffer (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_json TEXT   NOT NULL,
    created_at BIGINT NOT NULL,
    drained    BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX analytics_buffer_pending_idx ON analytics_buffer (id) WHERE NOT drained;
```

**Partial index, not the SQLite original's plain `(drained, id)`.** The retention decision below
keeps drained rows forever, so the working set the drain claim and `pending_count()` actually
scan is only the undrained rows — indexing the whole ever-growing table would waste space on
entries neither query ever touches. Precedented (`idx_audit_ttl_id`, `idx_resp_ttl`).

### Posture (ADR-0012 §1)

- **Ingest (`emit`): FAIL-SOFT.** A dropped analytics event must never fail the operation that
  emitted it — writers include the auth/SCIM routes, so a hard-failing emit would put analytics
  availability in the auth path. `emit()` stays `void`; every drop is counted
  (`yuzu_server_analytics_emit_dropped_total{reason}`, reasons `store_not_open` /
  `pool_acquire_timeout` / `query_error` / `serialize_error`) and logged at debug — fail-soft
  means the caller continues, never that the failure is invisible (lesson from the merged wave
  PRs). Bounded acquire is short (250ms) since this runs on hot request paths.
- **Reads (`query_recent`, `pending_count`): degrade-distinguishable at the seam.**
  `std::optional<T>`, `nullopt` on a DB error (store not open / pool timeout / query error) —
  distinct from a genuinely empty buffer. Both feed only diagnostics (`/api/analytics/status`,
  `/api/analytics/recent` — operator-facing display, not a grant/target/enforce/skip decision),
  so per the playbook's deny-or-benign carve-out the REST handlers 503 on a degraded read rather
  than rendering a false `pending_count: 0` — honest-degraded, not fail-open.
- **`total_emitted()`: changed from a `COUNT(*)` query to an in-process atomic counter**,
  incremented on every successful insert. The SQLite original's own doc comment already said
  "since store was opened" — an atomic counter is a more literal match for that contract than a
  full-table `COUNT(*)`, and it sidesteps the playbook's counting-aggregate anti-pattern
  (`AuditStore`'s ADR-0040 finding: an unqualified count visits every row, including the
  ever-growing drained set this store's own retention decision below keeps around forever).

### Backfill (ADR-0009) — SKIPPABLE

The spool is transient by design and a **drained row is already delivered** — losing it costs
nothing. The honest exception is **undrained rows at cutover**: in healthy operation that's
bounded by the drain interval (≤10s of events), but if sinks were failing pre-upgrade it could be
up to whatever backlog had accumulated. Recorded as a deliberate, bounded loss, not assumed by
analogy to ResponseStore: no backfill, the legacy `analytics.db` is never read on upgrade.
**Correction (adversarial review, 2026-08-14):** the boot log recording this is a steady-state
`info` line on every successful open, not a one-time warning — the ResponseStore precedent this
originally matched has the identical shape (a `warn` that fires on every restart, not just the
actual cutover boot), and copying it uncorrected would have shipped the same doc/code mismatch
here. There is no cheap way to distinguish "this is the actual cutover boot" from "the 400th boot
since," so the log is phrased as an ongoing fact ("analytics spool on Postgres — legacy
analytics.db is not migrated"), not a one-time event notification.

### Secrets — none

Grepped every `emit()` call site's `attributes`/`payload` construction (auth_routes.cpp,
scim_routes.cpp, agent_service_impl.cpp, gateway_service_impl.cpp): usernames, source IPs, reason
strings, method/status labels, durations, byte/exit-code counts. No plaintext password, TOTP
code, session token, or API token fragment is ever assigned into an `AnalyticsEvent` field.
Plain columns, no `SecretCodec`.

### Untrusted bytes (UTF-8) — handled at serialization, not at bind

Event fields (hostname, agent_version, correlation_id, error text, ...) are agent- or
client-supplied and can carry invalid UTF-8. Unlike `ResponseStore`/`AuditStore`, this store
serializes the whole event to a JSON string via `nlohmann::json::dump()` *before* binding —
`dump(-1, ' ', false, nlohmann::json::error_handler_t::replace)` substitutes U+FFFD for invalid
UTF-8 instead of throwing (the `bundle_service.cpp`/`preflight_eval.cpp`/`dex_event.cpp` idiom),
so a malformed field degrades a fail-soft emit to "logged and dropped," never an exception into
the caller's request path. `dump()` also unconditionally escapes control characters (including
NUL) as `\uXXXX`, so the emitted JSON text carries no raw `0x00` byte — no separate
`sanitize_pg_text`/embedded-NUL guard is needed on the bind, unlike `ResponseStore`/`AuditStore`'s
raw untrusted columns.

### Retention — deliberately unchanged (growth caveat, not fixed here)

The SQLite original never deleted drained rows. This migration **keeps that behavior exactly**
rather than adding a clock-driven cleanup pass, per the kickoff hazard: any bulk delete keyed off
wall-clock age is a clock-guarded retention pass (the full #2360/#2508 shape — routed concern),
and building that machinery for a store whose growth has never been measured against production
volume is out of scope here. Caveat, sharper on Postgres than it was on SQLite: growth now lands
on the **shared substrate** (disk, autovacuum, backups), not an isolated per-process
`analytics.db` file. Tracked as a follow-up (#2508-adjacent) rather than solved in this PR.

### Drain — single-sweeper claim, then send with no lease held, then revert on failure

The AuditStore/ResultSetStore advisory-lease pattern (`pg_try_advisory_xact_lock`) doesn't port
unmodified: a pure reap pass does all its work inside one transaction, but this store's "reap"
step is `sink->send()` — network I/O (a ClickHouse HTTP POST) — and ADR-0012 §5 forbids holding a
lease across external work. So the drain pass is three phases, never overlapping a lease with
sink I/O:

1. **CLAIM** — one transaction: `pg_try_advisory_xact_lock('analytics_event_store:drain')`
   (exactly one replica drains per tick fleet-wide) then
   `UPDATE analytics_buffer SET drained = true WHERE id IN (SELECT id FROM analytics_buffer
   WHERE NOT drained ORDER BY id LIMIT $1) RETURNING id, event_json`. Committing releases the
   lock.
2. **SEND** — `sink->send()` for every registered sink, **no lease held**. All sinks must
   succeed for the batch to count delivered (preserves the SQLite original's `all_ok` gate).
3. **REVERT** — only on a partial/total sink failure: a separate, later transaction sets
   `drained = false` back on the claimed ids so the next tick retries them.

**Delivery semantics, stated explicitly:**
- **At-most-once on a crash between phases 1 and 2** — rows are already committed
  `drained = true` but never sent. Accepted: expendable, best-effort telemetry, and the same
  class of loss the SQLite original had on an unclean shutdown mid-batch.
- **At-least-once on a sink that fails then recovers** — phase 3 un-claims for retry, same
  outcome as the SQLite original's `all_ok` gate.
- **A batch row whose JSON fails to parse is claimed in phase 1 but never added to the
  send/revert sets, so it drains exactly once and is dropped.** This is a deliberate improvement
  over the SQLite original, which re-selected (and re-failed to parse) a poison-pill row every
  tick, forever.
- **A revert that itself fails to acquire a connection or errors** is logged at error level
  naming the stuck id count; those rows stay `drained = true` without confirmed delivery
  (silent-loss risk on a already-rare double-failure path — sink down AND pool exhausted in the
  same tick — accepted for expendable telemetry, not counted on a dedicated metric today).

Single-sweeper via the advisory lock means `FOR UPDATE SKIP LOCKED` inside the claim's subquery
would be redundant — no second replica ever reaches that SELECT concurrently.

### Construction posture — a deliberate, recorded divergence

The playbook's default: "a Postgres store that cannot open is a fatal startup error," applied
uniformly to `OfflineEndpointStore`/`PreflightRunStore`/`DeploymentRunStore`/etc. This store
diverges: **on a migration/open failure, `server.cpp` logs and disables the feature for the run
(`analytics_store_.reset()`) rather than setting `startup_failed_`.** Reasoning:

- `--no-analytics` defaults **off** (analytics collection is on by default) — so this is not a
  low-blast-radius opt-in feature where "just don't turn it on" is the escape hatch; most
  deployments carry it.
- Every one of the ~15 call sites already treats `analytics_store_` as optional
  (`if (analytics_store_) { ... }`) — nothing downstream is load-bearing on it existing. The
  store's own posture bundle (fail-soft ingest, degrade-distinguishable reads, skippable
  backfill) is "this data is expendable" end to end; gating the whole server's boot — auth, RBAC,
  every other store — on this one non-critical table's migration succeeding would contradict
  that posture at the one point that matters most (whether the server starts at all).

`/readyz` still surfaces the distinction Pattern E governance has repeatedly flagged (a
not-open-but-should-be-open store silently reads as healthy): `!cfg_.analytics_enabled ||
(analytics_store_ && analytics_store_->is_open())` reports true when the feature is off, false
when it's on but dead — visible to on-call without gating the rest of the fleet's readiness on a
non-critical telemetry store.

**This is the one point in this migration that isn't a straight port of an existing pattern —
flagged here explicitly for confirmation, per the kickoff doc's governance checkpoint.**

## Considered and rejected

- **Mandatory backfill**: rejected — the buffer is a transient spool; a drained row is already
  delivered and undrained rows are, by design, in flight rather than durable state.
- **Fatal construction failure (the uniform playbook default)**: rejected for the reasons above —
  recorded as the divergence, not silently applied by copying `OfflineEndpointStore`.
- **`FOR UPDATE SKIP LOCKED` in the claim query**: redundant given the advisory-lock
  single-sweeper — no second replica ever reaches the claim SELECT concurrently.
- **Retention/cleanup of drained rows in this PR**: rejected — no measured production growth
  rate to size a clock-guarded pass against yet; the kickoff hazard is explicit that any cleanup
  here means committing to the full #2360 shape. Deferred, tracked as a follow-up.

## Consequences

- Any events undrained at Postgres cutover are lost (bounded by the drain interval in healthy
  operation) — a steady-state boot `info` log (not a one-time event, see the Backfill section's
  correction above) + `changelog.d/` "Changed" fragment + a `docs/user-manual`/`docs/upgrading.md`
  note record the deliberate reset.
- `total_emitted()` semantics narrow slightly: an in-process atomic (matches the store's own
  documented "since opened" contract) rather than a durable `COUNT(*)` — a value that used to
  survive a process restart (by re-querying SQLite) now resets to 0 on restart, same as
  `ResponseStore`'s analogous in-memory-only pieces.
- `query_recent`/`pending_count` callers (the two `/api/analytics/*` diagnostics routes) now
  503 on a degraded read instead of silently rendering an empty/zero result.
- Drained-row growth is unbounded (deliberately, per the retention decision above) — now a
  shared-substrate concern, not an isolated file; flagged, not fixed.
- Tests → `YUZU_REQUIRE_PG_DB_TPL` + the shared `"analytics"` `PgTestTemplate` (the store's own
  `test_analytics_event.cpp` and the ten other fixture files that construct it as a secondary
  dependency, via the new `test_analytics_pg_helper.hpp` `AnalyticsEventStorePg` bundle, share
  the same template key so the migration is paid once per suite run).

## Follow-ups

- Drained-row retention/cleanup — needs production growth data before sizing a #2360-class
  clock-guarded pass; tracked adjacent to #2508.
- A revert-phase failure (pool exhausted or a query error while un-claiming a failed batch)
  leaves the affected rows `drained = true` without confirmed delivery and is logged but not
  separately counted on a metric — small blast radius (requires sink-down AND pool-exhausted in
  the same tick) but not yet observable in Prometheus.
- `docs/user-manual`/settings UI: the settings page's "Enabled"/"Disabled" analytics status
  label reads `cfg_.analytics_enabled` directly, so it can show "Enabled" even when construction
  silently disabled the feature (migration failure). Cosmetic accuracy gap, not fixed here.
