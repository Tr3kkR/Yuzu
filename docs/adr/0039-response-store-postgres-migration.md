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
`audit_retention_rules::classify` decline-once + unconditional per-pass cap (10 000,
substrate-tuned to response write volume) + `yuzu_server_response_reap_passes_total{result}`.
Reaped from the maintenance tick (like GS/ResultSetStore); the in-process cleanup thread goes
away.

The implausibly-ahead bound is **DERIVED from the store's own `retention_days` at 2×
(floored ~120 d)**, not a fixed constant — `response_retention_days` is operator-configurable
and unclamped, so a fixed bound would silently reintroduce the ADR-0038 false-decline class
the moment retention passed it (every live row's honest `ttl_expires_at` would land past the
bound → excluded from `datable` → `would_wipe` trips → perpetual decline → the table never
reaps). "Size to THIS store's retention, NOT copied" (the ADR-0038 lesson) is taken literally:
the bound tracks the horizon rather than a magic number.

The per-pass cap is observable: a pass that deletes the full cap records
`result="capped"` (distinct from `swept`), so on-call can tell a healthy fully-draining reaper
from one whose 10 000/pass ceiling is being outrun by ingest on this high-write store — the
`AuditStore` cap-reached signal, ported.

### Lifecycle

`stop()` unwires from the ingest service(s) then resets before `pg_pool_`; store in `/readyz`
AND `/healthz`. Reap piggybacks the existing maintenance thread (respecting each store's own
is_open gate — the ADR-0038 JC-6 decoupling pattern).

### Untrusted byte columns (UTF-8)

`output` and `error_detail` are agent-supplied plugin bytes, not server-authored text — a
plugin can legitimately emit non-UTF-8 content (binary data, a mis-decoded code page, a raw
`0xff`). SQLite's permissive `TEXT` affinity stored those bytes as-is; Postgres `TEXT` requires
valid server-encoding (UTF8) and rejects an invalid sequence outright at `INSERT` time
(SQLSTATE 22021). Left unhandled, that turns governance #1593's guarantee — "malformed plugin
output must still render, defanged, never 500" — into a silent **drop**: the fail-soft ingest
path would count it as an ordinary transient failure and the row would simply never land,
which is a regression, not a preserved behaviour.

Fix: `store()` sanitizes `output` and `error_detail` to U+FFFD (the replacement character) via
the shared `sanitize_utf8_strict` helper (`utf8_sanitize.hpp` — the same implementation the
inventory and app_perf ingest seams already use for their own untrusted text) **before**
binding the `INSERT`. `finalize_terminal_status` applies the identical sanitize to the
agent-supplied `error_detail` it binds — otherwise a non-UTF-8 byte would fail the terminal-frame
`UPDATE` (SQLSTATE 22021), leaving the RUNNING row never finalized and no fallback frame, which
is the #1593 gap reopened on the finalize path rather than the ingest path. The row still lands; byte-for-byte fidelity is not required for
expendable, TTL'd operational telemetry (consistent with the store's overall fail-soft/
skippable-backfill posture). This also removes a class of render-time risk at the source —
invalid bytes never reach `aggregate_to_json`/any downstream JSON serializer in the first
place, rather than relying on every consumer to defend against them independently. `status` is server/enum-controlled and is NOT sanitized. `plugin` (agent-supplied
plugin name) and `instruction_id` (the agent-echoed command id) DO arrive on the wire, so a
hostile agent could emit non-UTF-8 there — but a malformed value simply fail-soft-drops the
whole row at INSERT (a garbage/hostile response defangs to a counted drop, by design), which
is NOT the #1593 legitimate-output-must-surface case. Sanitization is applied only to the two
free-text RESULT columns (`output`, `error_detail`) where dropping a real result would be the
regression #1593 guards against.

One more byte the plain scrub does NOT catch: **NUL (U+0000)**. `sanitize_utf8_strict` treats
it as a valid ASCII byte and keeps it, but PostgreSQL `TEXT` cannot store an embedded NUL and
libpq's text-format bind C-string-**truncates** the value at the first NUL — silently dropping
everything after it (the same "real output vanishes" regression, on any binary/mis-decoded
result carrying a `0x00`, which is exactly the ADR's motivating case). So a thin store-local
wrapper `sanitize_pg_text` runs `sanitize_utf8_strict` and then replaces any remaining NUL with
U+FFFD too. `utf8_sanitize.hpp` itself is NOT edited — it is byte-identical with the agent's
installed_software copy (the canonical-hash invariant); NUL handling is a PG-bind concern local
to this store. Facets derive from the same `sanitize_pg_text` output, so a stored `output` and
its facet values never diverge across a NUL.

### Facet ingest — one savepoint, not one-per-facet

Facets are written as a **single batched multi-row `INSERT` under ONE `SAVEPOINT`**, not the
per-facet-savepoint loop the first cut used. The savepoint still delivers the ADR-0038
guarantee (a facet-batch failure rolls back to the savepoint and the response row still
commits — Postgres aborts the whole txn on any failed statement, unlike SQLite's silent skip),
but one savepoint mints **one** subtransaction XID regardless of facet cardinality. The
per-facet loop minted a subxid per distinct value, so a wide tabular output (>64 distinct facet
values — a routine process/vuln list) **suboverflowed** the ingest txn's snapshot and forced
cluster-wide `pg_subtrans` SLRU lookups on the SHARED server pool (a blast radius beyond this
store). The batch is chunked so `3 + 3·chunk` params stay under libpq's 65 535-param ceiling.

**Generalises**: any future store migrating an untrusted-byte `TEXT` column from SQLite to
Postgres needs the same UTF-8 **and NUL** treatment — `AuditStore` is the next store on the
ladder with agent-supplied free text and should sanitize the same way rather than rediscovering
#1593 the hard way. Any store porting SQLite's "tolerate one bad sub-insert" behaviour to PG
should reach for one batch-under-one-savepoint, not a savepoint per row (subxid suboverflow).

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
- **Accepted limitation (chaos Gate 5 R4):** the convenience scalar reads
  (`total_count` / `facet_agent_count` / `facet_line_count`) return a plain `0` on a
  pool-timeout / query error, indistinguishable from a genuine `0` and NOT counted on
  `yuzu_server_response_read_degrade_total`. Benign today — no caller treats these as a
  trigger for a destructive/skip action (the reap uses its own probe, not these), and they
  feed display/metrics only. If a future authz-adjacent consumer reads one, promote it to the
  `std::optional`-nullopt seam like the row/aggregate readers. Recorded so it is a deliberate
  carve-out, not an omission.
