# ADR-0039: ResponseStore → PostgreSQL (Wave 1.2)

- **Status:** Proposed
- **Date:** 2026-07-31
- **Deciders:** pg workstream; security-guardian + docs-writer (Gate 2)
- **Parents:** ADR-0006/0007/0008(+Correction), ADR-0009, ADR-0012; conventions from
  ADR-0036 (ResultSetStore), ADR-0037 (InventoryStore), ADR-0038 (GuaranteedStateStore).

## Context

`ResponseStore` (`response.db` today) persists agentic command/instruction **responses** —
two tables: `responses` (per-agent result rows: status, output, error, plugin,
`execution_id`, `ttl_expires_at`) and `response_facets` (denormalised column values powering
the dashboard's facet filters). High-write (every command result from every agent), TTL'd
(default 90-day retention via a background cleanup thread), a `/tar`- and executions-drawer
read source. Read surface is compact: `query` / `query_by_execution` / `get_by_instruction`
/ `query_by_ids`, `aggregate` / `distinct_agent_ids` / `facet_values` / `facet_agent_ids` /
`facet_response_ids`.

Next after ADR-0038 on the ladder. (The ladder's prior Wave-1.2 entry, FleetTopologyStore,
is **not** a SQLite store — it is an in-memory topology cache built `(fetcher, nvd)` with no
persistence, so it is out of ADR-0006 scope; the ladder row is corrected in this PR.)

## Decision

Migrate to PostgreSQL schema **`response_store`** (ADR-0008), construction fail-closed
(ADR-0012 §1), on the shared server PgPool. `sqlite3_changes()` (delete_by_instruction) →
`RETURNING`/`PQcmdTuples` (#1033). `mtx_` deleted; PG concurrency replaces the single-writer.

### Schema

`responses` + `response_facets` port column-for-column (INTEGER→BOOLEAN/BIGINT as apt; TEXT
timestamps/output stay TEXT — behavior-preserving). All indexes carry over incl. the partial
`idx_resp_ttl WHERE ttl_expires_at > 0` the reaper uses.

### Posture (ADR-0012 §1)

- **Response ingest (`store`): FAIL-SOFT** (ADR-0037 shape) — a dropped result row is
  re-derivable operational telemetry (the executions ladder tracks the command; the agent's
  result is best-effort persisted for the drawer/TAR). Ingest must never block the gRPC
  thread. Drops counted (`yuzu_server_response_ingest_dropped_total{reason}`, kReason*
  constants).
- **Reads (`query`/`query_by_execution`/`aggregate`/facets/…): degrade-distinguishable at
  the store seam** (`std::optional<vector>` nullopt-on-degrade + `yuzu_server_response_read_
  degrade_total{reason}` + sampled logs). **NOT the catastrophic class** — these feed the
  executions drawer / TAR dashboard, not an enforce/target/authz decision, so per the
  playbook's deny-or-benign carve-out the consumers may render degraded (503 on the REST
  twin, empty+degrade-banner on the dashboard) — but the seam MUST distinguish empty from
  degraded so a future authz-adjacent consumer can't misread a blip as "no responses." The
  #1634 group-scoped-read seam (`ResponseQuery{.agent_id}`) is preserved exactly.
- **Writes other than store** (`delete_by_instruction`): fail-hard (`RETURNING` count).

### Backfill (ADR-0009) — SKIPPABLE

Responses are TTL'd 90-day operational data, not authoritative config and not compliance
evidence — losing pre-cutover responses degrades only historical drawer/TAR views, which
self-refill as new commands run. So **no backfill** (the ADR-0009 skippable class, the
`ResponseStore` precedent the ladder cites): the legacy `response.db` is not read on upgrade;
a one-time loud "response history reset on Postgres cutover" boot log. (Matches
`ApiTokenStore`'s fresh-start precedent in spirit — no legacy read, no marker table needed.)
Rationale recorded here so it is a deliberate decision, not an omission.

### Retention (clock-guarded)

The cleanup thread's bare wall-clock TTL delete ports to the #2496 `gc_sweep` shape
(the routed-concern requires it; #2508): shared `gc_meta` reading + advisory
`pg_try_advisory_xact_lock('response_store:reap', 0)` (single sweeper) +
`audit_retention_rules::classify` decline-once + unconditional per-pass cap (substrate-tuned
to response write volume; the implausibly-ahead bound sized to the 90-day retention horizon,
NOT copied from a shorter-TTL store — the ADR-0038 lesson) + `yuzu_server_response_reap_
passes_total{result}`. Reaped from the maintenance tick (like GS/ResultSetStore); the
in-process cleanup thread goes away.

### Lifecycle

`stop()` unwires from the ingest service(s) then resets before `pg_pool_`; store in `/readyz`
AND `/healthz`. Reap piggybacks the existing maintenance thread (respecting each store's own
is_open gate — the ADR-0038 JC-6 decoupling pattern).

## Considered and rejected

- **Mandatory backfill**: rejected — responses are expendable TTL'd telemetry (ADR-0009
  skippable); a mandatory multi-GB backfill of a high-write table would add boot latency and
  OOM risk (cf. #2661) for data that self-refills.
- **Catastrophic-read type-distinguishable everywhere**: unnecessary — no response read feeds
  an enforce/target/authz decision; the seam stays degrade-distinguishable but consumers may
  render degraded (the ResultSetStore `list_by_owner` precedent).

## Consequences

- Response history is reset on the Postgres cutover (skippable backfill) — a CHANGELOG
  "Changed" note + `docs/user-manual` mention; operationally invisible after one command
  cycle. Executions drawer / TAR read fleet-consistent across replicas afterward.
- Tests → `YUZU_REQUIRE_PG_DB_TPL` + a file-local `"responsestore"` `PgTestTemplate`;
  migration/fresh-DB tests keep plain `YUZU_REQUIRE_PG_DB`.

## Follow-ups

- #2634-parity reap counters land here from day one.
- The #1634 management-group-scoped response read (already threaded via `ResponseQuery`)
  stays defense-in-depth; no change.
