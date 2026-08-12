# ADR-0043: DiscoveryStore → PostgreSQL (Wave 2)

- **Status:** Accepted
- **Date:** 2026-08-12
- **Deciders:** pg workstream; security-guardian + docs-writer (governance)
- **Parents:** ADR-0006/0007/0008(+Correction), ADR-0009, ADR-0012; conventions from ADR-0040/0041/0042
  (esp. `sanitize_pg_text`, fail-closed boot, mandatory-backfill-with-fingerprint-verification, the
  RbacStore ADR-0041 sourceless-fingerprint precedent this store ports).

## Context

`DiscoveryStore` (`discovery.db` today, `server/core/src/discovery_store.{hpp,cpp}`, ~250 lines)
holds network-discovered devices (Issue 7.18): raw scan results agents report before an operator
promotes a device to a managed agent. Single table (`discovered_devices`), three indexes, no
foreign keys, no secret-bearing columns. Tracked under issue #1328 (Postgres ladder 4c, leaf-store
batch).

The `managed` flag on a discovered device is operator-set state — an operator has looked at a
discovered IP and confirmed "yes, this is my enrolled agent." That confirmation, along with
first-seen discovery provenance (`discovered_at`/`discovered_by`), is real state that cannot be
re-derived from a re-scan. This is Wave 2's "operator state that cannot be lost" framing, not
purely ephemeral telemetry — backfill is therefore mandatory, matching `RbacStore`/`ManagementGroupStore`,
not `ResponseStore`'s unconditional-skip precedent.

## Decision

Migrate to PostgreSQL schema **`discovery_store`** (ADR-0008), construction fail-closed
(ADR-0007/0012 §1), on the shared server `PgPool`. `sqlite3_changes()` (used by the legacy
`mark_managed`) is retired in favor of `RETURNING` (#1033). The SQLite `shared_mutex` is retired —
Postgres's real per-connection concurrency replaces the single-writer serialization.

### Schema

`discovered_devices` (id BIGSERIAL, ip_address UNIQUE, mac_address, hostname, managed BOOLEAN,
agent_id, discovered_by, discovered_at, last_seen, subnet) ports column-for-column from the
legacy SQLite schema, with `managed` becoming a native `BOOLEAN` (was SQLite `INTEGER`). A new
`discovery_meta` k/v table carries the one-time backfill marker + source fingerprint (see below).

### Reads — authoritative, type-distinguishable

Per the 2026-07-25 program policy (`docs/postgres-store-playbook.md` "Authoritative reads must be
type-distinguishable"), every read whose result could feed a fleet-visibility decision is
type-distinguishable from "no rows": `list_devices` returns `std::optional<std::vector<...>>`
(`nullopt` = degraded, empty vector = genuinely no devices); `get_device` returns
`std::expected<std::optional<DiscoveredDevice>, std::string>` (`unexpected` = degraded, a value
holding `nullopt` = genuinely absent). `GET /api/discovery/results` (`discovery_routes.cpp`) checks
for `nullopt` and returns 503 rather than rendering an empty device list — closing the fail-open
that a silently-empty discovered-device list would otherwise represent (an operator scanning for
rogue/unmanaged devices on the network must not be told "nothing found" when the real answer is
"could not ask").

### ON CONFLICT semantics (verified against the legacy implementation)

`upsert_device`'s `ON CONFLICT (ip_address) DO UPDATE` preserves the legacy SQLite behavior
exactly: `mac_address`/`last_seen`/`subnet` always refresh (most-recent-seen); `hostname`
refreshes only when the new value is non-empty (a scan that could not resolve a hostname does not
blank out a previously known one); `discovered_at`/`discovered_by`/`managed`/`agent_id` are NOT
touched by the conflict branch — a re-scan cannot silently un-manage an already-managed device or
overwrite first-seen provenance. `managed`/`agent_id` ARE part of the INSERT column list, so a
fresh insert honors caller-supplied values; the "untouched by a re-scan" guarantee applies only to
an already-existing row.

### Backfill (ADR-0009) — MANDATORY, fingerprint-verified

One-time, idempotent, fail-closed backfill from the legacy `discovery.db`, ported from the
`RbacStore`/#2703 sourceless-fingerprint mechanism (ADR-0040/0041 shape) and scaled down to one
table. The marker (`backfill_complete`) and a SHA-256 fingerprint of the migrated content
(`backfill_source_fingerprint`) are stamped together in one transaction — this closes the
"local source absence never creates terminal migration state on its own" hazard
(`docs/postgres-store-playbook.md`): a replica finding no local `discovery.db` cannot distinguish
"genuine fresh install" from "a sibling replica holds the real file," so a sourceless stamp is a
promotable sentinel, never a terminal fact. A later boot that still holds its own legacy file
verifies its fingerprint against the stored one before trusting the marker, refusing (fail-closed)
on a mismatch or an unreadable file. Row-count reconciliation after the insert transaction is a
weak backstop (it can only catch an out-of-band concurrent delete between commit and count, not a
partial insert — the per-statement status check inside the transaction already aborts the whole
transaction on any INSERT failure).

### Lifecycle

Construction moves inside `server.cpp`'s `if (pg_pool_ && !startup_failed_)` guard; a failed
migration or backfill sets `startup_failed_` (fail-closed boot, never serve on top of
partially-migrated discovery data). Added to the `/readyz` check list.

## Considered and rejected

- **Skippable backfill** (the `ResponseStore` precedent): rejected — the operator-set `managed`
  flag is irreducible operator intent, not regenerable telemetry.
- **Plain marker-only backfill idempotency** (no fingerprint): rejected in favor of the
  fingerprint-verified shape — a marker-only scheme cannot distinguish "this replica's own
  completed migration" from "a different replica's migration this replica's data was never part
  of," which is exactly the multi-replica hazard `docs/postgres-store-playbook.md` documents as a
  measured defect class (RbacStore's own first port missed it).

## Consequences

- Discovered-device inventory, including the operator-set `managed` flag, is preserved across the
  cutover.
- `GET /api/discovery/results` gains a new 503 branch on a degraded read (previously: SQLite's
  local-file reads essentially never failed short of file corruption, so this failure mode was not
  practically reachable).
- Tests → `YUZU_REQUIRE_PG_DB_TPL` + a file-local `"discoverystore"` `PgTestTemplate`
  (`tests/unit/server/test_discovery_store.cpp`); construction-fail-closed and backfill tests use
  plain `YUZU_REQUIRE_PG_DB`.

## Follow-ups

- `mark_managed`/`clear_results` have no REST route today (only `upsert_device` via
  `POST /api/discovery/scan` and `list_devices` via `GET /api/discovery/results` are reachable) —
  pre-existing, unrelated to this migration.
- `POST /api/discovery/scan`'s handler always responds `200`/audits `"success"` even when every
  individual `upsert_device` call fails (e.g. under a degraded pool) — pre-existing, unrelated to
  this migration, flagged by Gate 2 security-guardian for a follow-up issue.
