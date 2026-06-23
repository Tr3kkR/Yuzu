---
status: accepted
date: 2026-06-08
accepted: 2026-06-09
owner: "@lesault (Andy Younie)"
deciders: Nathan Dornbrook (decision); @fjarvis + FortitudeEtc (requested a standalone server DB); @lesault (indifferent)
scope: platform — affects Guardian, viz, vuln-scan graph, offline-state, secrets
note: supersedes the standing "SQLite for embedded storage" principle for server-side derived/durable state; agent-side SQLite (the federated edge warehouse) is unchanged
generalised-by: ADR-0006 — the 2026-06-09 widening made Postgres the standard server substrate for ALL server stores; this ADR is its first instance
---

# 0004 — Introduce server-side PostgreSQL; agent SQLite stays the federated edge warehouse

> **Implementation status (2026-06-18 conformance audit):** The server-side PostgreSQL substrate this ADR introduced is **shipped** (generalised by ADR-0006/0007/0008; the server now runs on Postgres and fails closed without it — behaviorally verified). The reachability-graph–specific application (scored graph + pgvector identity matching) is **not yet built** — spike-grade (PR #1206). See `docs/reviews/codebase-conformance-2026-06-18`.

## Context

Yuzu's stated architecture is "SQLite for embedded storage," and the server already runs
~24 separate SQLite stores. For the vuln-scan graph alone, an embedded store would suffice
(the *derived* graph is small). But the decision is not being made in isolation: Guardian
wants to store more than SQLite comfortably serves at >1M agents; we need durable
server-side state to answer about **offline endpoints**; secrets want an off-box home; and
fuzzy software-identity → CPE matching (ADR-0005, §2.2 of the design doc) wants vector
search. The earlier instinct to keep the graph embedded held *in isolation* but not once
these drivers are on the table.

## Decision

Introduce **server-side PostgreSQL** as the substrate for the **derived scored graph +
last-known endpoint state + the cross-store join that is the scoring operation
(`edges ⨝ findings ⨝ value ⨝ guardian_state`) + pgvector** (identity matching). The
**agent's SQLite warehouse stays the federated edge store** for raw flow-summary history
(ADR-0003) — the firehose never reaches the server, which is precisely why plain Postgres
(not a columnar engine) is sufficient: the server holds only small, derived, joinable state.
Attack-path/chokepoint computation runs in a server background thread (the `PolicyEvaluator`
pattern) over an in-memory adjacency loaded from Postgres; no Neo4j/pgrouting (depth-bounded
paths don't need a graph-native store).

## Considered and rejected

- **Keep everything embedded in SQLite.** Correct for the graph alone; rejected once
  Guardian-scale, offline-state, and pgvector are weighed, and because cross-store joins
  across 24 SQLite files make scoring an application-layer join nightmare.
- **ClickHouse for raw flow history.** Removed by ADR-0003 — the firehose stays at the edge,
  so the server never ingests the high-cardinality time-series that would justify a columnar
  engine.

## Consequences

- This **supersedes the embedded-SQLite principle** for server-side derived/durable state
  and is a real operational departure (a server-attached Postgres, likely on a separate
  box). **Platform buy-in obtained 2026-06-09** — @fjarvis and FortitudeEtc requested a
  standalone server database, @lesault indifferent, Nathan decided; implementation is now
  unblocked. The agent-side SQLite edge warehouse (ADR-0003) is unchanged.
- **Secrets caveat (load-bearing):** "off-box durable state" ≠ "secrets in a Postgres
  column." Secrets require app-side envelope encryption behind the `KeyProvider` seam — see
  ADR-0010 for the full model. Do not let this ADR quietly become "we put secrets in a table."
- **Auth/CA stores — out of scope for this substrate decision (scope fence, load-bearing):**
  the identity and credential stores — `auth.db` (AuthDB invariants: file-mode, migration,
  lifetime, seed-vs-live) and `ca.db` (`CaStore` + the PKI `key_ref` / `KeyProvider` seam,
  where the CA root private key is *never* in the DB) — are **out of scope for this ADR**.
  This ADR covers the *derived scored graph + offline-state*, not identity or credentials.
  The "secrets want an off-box home" driver in the Context motivates Postgres for the graph;
  it must **not** be read as license to migrate the auth/CA stores as a side effect of
  graph-substrate work. Any later migration of `auth.db`/`ca.db` follows ADR-0006/0007/0008
  + a per-store decision requiring `authdb` + `security-guardian` + PKI review + ADR-0010
  secret handling — it is a separate decision, not a consequence of this one.
- Federated-pull + offline-answering tension is resolved here: the server persists
  **last-known summaries** so offline hosts still appear (stale-flagged); fresh detail is
  online-only.
