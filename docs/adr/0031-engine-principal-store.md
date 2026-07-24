---
status: accepted
date: 2026-07-16
owner: platform (engine-principals program)
deciders: maintainer decision (Tr3kkR) — engine-principals PR 4.1/4.2 program; security-guardian
  to confirm the no-secret classification
scope: server — `EnginePrincipalStore` (the identity store for the new `engine` RBAC principal
  class), its schema, failure posture, and relationship to `ApiTokenStore` (credential) and
  `RbacStore` (authority)
builds-on: ADR-0006 (Postgres substrate), ADR-0008 (substrate architecture — schema naming),
  ADR-0012 (server Postgres store contract), ADR-0030 (`ApiTokenStore` Postgres migration +
  `principal_kind`, PR 4.1 of this same program), ADR-1005 item 2b (engine principals &
  delegation — `docs/auth-engine-principals-design.md`)
related: docs/postgres-migration-ladder.md (Done); docs/postgres-store-playbook.md step 9 (this
  ADR closes the gap it flagged — PR 4.1/4.2 shipped `EnginePrincipalStore` without one);
  docs/ops-runbooks/engine-principal-store-recovery.md; #2202 (engine-principals PR 4.2 fix round)
---

# 0031 — `EnginePrincipalStore`: identity registry for the `engine` RBAC principal class

## Context

`docs/auth-engine-principals-design.md` (ADR-1005 item 2b) introduces a third RBAC principal
class, `engine`, for the durable identity behind an autonomous use-case-engine (UCE) module —
distinct from a `user` (a human) and existing `agent` sessions. PR 4.1 added the `principal_kind`
column to `ApiTokenStore` (ADR-0030) so an engine-kind bearer token could be minted; PR 4.2 (this
program's slice, #2188/#2202) built the identity store that credential resolves against, the
`RbacStore` resolution/authoring plumbing that lets an engine principal be granted roles, and the
session-authorization semantics that make "no assignments ⇒ no authority" actually true (see
`docs/auth-architecture.md` "Engine principals & delegation").

`docs/postgres-store-playbook.md` step 9 requires a per-store ADR (schema + posture + secrets)
for every server Postgres store. `EnginePrincipalStore` shipped in PR 4.1/4.2 (commit `ae1d0007`)
without one — a review gap surfaced during PR #2202's external adversarial review round. This ADR
is that missing per-store ADR, written after the code (the store is implemented and tested; this
document records the decisions already made in `server/core/src/engine_principal_store.{hpp,cpp}`
rather than proposing new ones).

## Decision

**`EnginePrincipalStore` is a born-on-Postgres store, schema `engine_principal_store`, table
`engine_principals`, holding the identity-only metadata for each `engine:<slug>` principal. It
holds no secret material — the credential is a separate `engine`-kind row in `ApiTokenStore`
(ADR-0030) — and its posture is authoritative/fail-hard per ADR-0012 §1.**

### Schema

- Schema name `engine_principal_store` (ADR-0008 Update naming rule:
  `snake_case(FullClassName)` including the `Store` suffix).
- Table `engine_principals`:

  | Column | Type | Notes |
  |---|---|---|
  | `principal_id` | `TEXT PRIMARY KEY` | `CHECK (principal_id LIKE 'engine:_%')` — the reserved `engine:<slug>` namespace (design §3.3), slug non-empty. Mirrors the C++-side create-path prefix/slug guard exactly, so a hand-run `INSERT` can't smuggle in a malformed id the application layer would have rejected. |
  | `display_name` | `TEXT NOT NULL DEFAULT ''` | UI/audit label. |
  | `owner_username` | `TEXT NOT NULL` | Named responsible human (design §3.1 — every engine principal has a human owner of record). Indexed (`engine_principals_owner_idx`) for the eventual "principals I own" admin view (PR 4.3). |
  | `justification` | `TEXT NOT NULL DEFAULT ''` | Grant justification captured at creation — SOC 2 evidence for *why* an autonomous identity exists. |
  | `classification` | `TEXT NOT NULL CHECK IN ('internal','external')` | Required at creation, no default — an engine principal must be explicitly classified, never silently defaulted (see `create()`'s pre-insert validation). |
  | `lifecycle_state` | `TEXT NOT NULL DEFAULT 'active' CHECK IN ('active','revoked')` | Terminal, not reversible (see Posture below). |
  | `superseded_by` | `TEXT NOT NULL DEFAULT ''` | Predecessor→successor link when a revoke is paired with minting a replacement principal (a compromise response never un-revokes, it supersedes). |
  | `created_at` / `revoked_at` | `BIGINT NOT NULL DEFAULT 0` | Epoch seconds (matches `ApiTokenStore`'s epoch-seconds idiom — not milliseconds; do not cross this boundary with `VulnFindingStore`'s epoch-ms columns). |
  | `created_by` | `TEXT NOT NULL DEFAULT ''` | Audit anchor — who minted this principal. |

  No FK to `ApiTokenStore` or `RbacStore` — see "Relationship to sibling stores" below for why
  that's a deliberate cross-store seam rather than a join.

### Posture

**AUTHORITATIVE / fail-hard (ADR-0012 §1)**, both at construction and at runtime — this store
backs the auth-lookup chokepoint for every engine-credential session:

- **Construction fails closed.** If the Postgres schema cannot be opened or migrated,
  `is_open()` stays `false`; `server.cpp` wires that to `startup_failed_` — a Postgres store that
  can't open is a fatal startup error (playbook step 6), not a silently-disabled feature.
- **The auth-lookup chokepoint (`get_for_auth`) is three-state, not boolean.** Every consumer
  resolving an engine credential's authority MUST route through it (never a plain `get()`, which
  answers admin/test reads only and does not distinguish "store unreachable" from "no such
  row"):
  - `Active` — a live row; the request may proceed to RBAC resolution.
  - `MissingOrRevoked` — no row, or `lifecycle_state != 'active'`. Terminal, 401-class: deny and
    stop.
  - `StoreUnreachable` — the store is closed, or a lease/query failed. Retryable, 503-class: deny
    and back off.

  **Both non-`Active` outcomes deny the request** — the split changes retry behavior only, never
  the authorization outcome. There is no downgrade path from "unreachable" to "admitted": a
  transient Postgres blip reading as "credential revoked" would risk an autonomous module
  abandoning a healthy credential (annoying but safe); treating "unreachable" as "admitted" would
  be a fail-open bypass, which this design forbids outright regardless of which failure mode is
  worse in the abstract.
- **`get`/`revoke`/`transfer_owner` are typed `std::expected<..., std::string>`** (PR 4.2 fix
  round — see below), mirroring `ApiTokenStore::get_token`/`revoke_token`: a genuine lease/query
  failure surfaces as `unexpected(msg)` and is never conflated with the legitimate not-found /
  no-op case (`nullopt` / `false`). A lease/query failure is never a silent success and never
  reads as "no such row".
- **Revoke is terminal and soft-retained.** `active → revoked` is one-way (never un-revoked — a
  false-positive compromise response mints a successor principal instead, linked via
  `superseded_by`); a revoked row is never hard-deleted, so audit attribution against a
  since-revoked engine principal survives indefinitely.

### No secret material — ADR-0010 does not apply here

`EnginePrincipalStore` holds identity metadata only (owner, justification, classification,
lifecycle, audit anchors) — no credential, no hash, no key reference. The engine principal's
actual bearer credential lives entirely in `ApiTokenStore` (`token_hash`, verify-only SHA-256,
ADR-0030), keyed by `principal_id` but stored in a separate table this store does not touch. This
mirrors the design's own "a dedicated store, not columns bolted onto `ApiTokenStore`" framing
(`engine_principal_store.hpp` file comment): the identity (who is this, who owns it, why does it
exist) outlives any one credential, and keeping the two concerns in separate stores means a
credential rotation never touches identity rows and an identity edit (rename, reclassify,
re-owner) never touches token rows. `SecretCodec` (ADR-0010) is not invoked anywhere in this
store — there is nothing here for it to protect.

### Relationship to `ApiTokenStore` and `RbacStore`

Three stores cooperate to give an engine principal a working, authorized identity, each owning a
distinct concern with no FK between them (ADR-0012 §3's cross-store-seam pattern — a resolver
function wired post-construction in `server.cpp`, not a join):

- **`EnginePrincipalStore`** (this ADR) — *who is this identity, and is it still alive.* The
  `get_for_auth` chokepoint.
- **`ApiTokenStore`** (ADR-0030) — *what credential proves it.* `create_token`'s engine block
  calls `EnginePrincipalStore::get_for_auth` at mint time via a resolver seam (referential check
  — you cannot mint an engine token for a principal that doesn't exist or is revoked), but the
  hash itself lives only in `ApiTokenStore`.
  - **Destruction order is load-bearing.** `server.cpp` declares `api_token_store_` before
    `engine_principal_store_` so it destructs *second* (after) — its resolver seam derefs
    `engine_principal_store_` and must never observe it mid-reset.
- **`RbacStore`** (pre-existing, extended by PR 4.2) — *what can it do.* The third
  `principal_type='engine'` UNION arm in `RbacStore`'s role-collection query resolves
  `(principal="engine:<slug>", role, scope)` grants written through the
  `/api/v1/engine-principals/{id}/roles` authoring surface (see `docs/user-manual/rest-api.md`
  "Engine Principals"). `AuthRoutes::require_permission`/`require_scoped_permission` resolve an
  `engine`-kind session's authority *exclusively* against `RbacStore` — no legacy fallback, no
  service-scoped fallback (`docs/auth-architecture.md` "Session-authorization semantics").

None of the three stores is the other's cache or the other's source of truth for its own concern
— each fails closed independently, and a failure in one (e.g. `RbacStore` unreachable) denies the
request without needing to consult the other two.

## Considered and rejected

- **Columns on `ApiTokenStore` instead of a dedicated store.** Rejected in the design doc itself
  (`engine_principal_store.hpp` file comment) — identity metadata (owner, justification,
  classification, lifecycle) outlives any one credential; bolting it onto the token table would
  couple a credential rotation to an identity edit and vice versa, and would make "list every
  engine principal" a `DISTINCT` scan over a token table rather than a direct read of an identity
  table.
- **A hard FK from `EnginePrincipalStore` to `ApiTokenStore`/`RbacStore`.** Rejected —
  ADR-0012 §3's cross-store contract is a resolver-function seam under one lease per logical
  operation, not a join; a Postgres FK across schemas here would also invert the intended
  ownership (the token/RBAC side references the identity, not the reverse) and complicate the
  destructor-order contract each store already documents independently.
- **Reusing `lifecycle_state` on the token instead of a separate identity-level state.** Rejected
  — a revoked *credential* (token expired/rotated) and a revoked *identity* (the module itself is
  decommissioned) are different events with different consequences: rotating a token must not
  revoke the identity, and revoking the identity must deny *every* credential issued against it,
  including ones minted after the revoke (closed by `get_for_auth` gating on the identity row,
  not the token row, at every auth check).

## Consequences

- `EnginePrincipalStore` holds a `pg::PgPool&`, runs its migration at construction on a pinned
  lease, and schema-qualifies every runtime statement (`engine_principal_store.engine_principals`)
  per the playbook's substrate contract. Bounded lease acquires throughout (1500 ms read /
  2000 ms write per ADR-0012 §2) — auth lookups sit on a hot(ish) path (every engine-credential
  session synthesis falls through `get_for_auth`), so the read budget is deliberately short.
- `docs/postgres-migration-ladder.md`'s `EnginePrincipalStore` row (Done section) is updated to
  cite this ADR instead of the placeholder "ADR-0006/ADR-0012, engine-principals PR 4.2" text it
  shipped with.
- **PR 4.2 fix-round hardening folded into this store's contract** (commit `38f6b3e9`, closing an
  external-review HIGH finding): `get`/`revoke`/`transfer_owner` moved from a bare
  `optional`/`bool` to `std::expected<..., std::string>` so a genuine store failure can no longer
  be read as "no such row" / "nothing to do" by a caller — the ripple was test-only (no
  behavior-changing caller existed yet outside tests), but the typed contract is now load-bearing
  for every future caller.
- **No operator CRUD yet.** Nothing in PR 4.1/4.2 mints or revokes an engine principal outside a
  test/admin code path — `create`/`revoke`/`transfer_owner` are store primitives with no route or
  MCP tool wrapping them. That authoring surface (dashboard + REST + MCP for the identity itself,
  as opposed to PR 4.2's role-*assignment* surface) is PR 4.3 scope; this ADR does not change
  that boundary.
- **Liveness re-checks are cached; authorization decisions are not** (#2367). `get_for_auth`
  remains the authoritative chokepoint and always reads through to Postgres. A sibling,
  `get_for_auth_revalidate`, serves the per-tick "is this already-authenticated stream's backing
  principal still alive?" question from a 60 s positive cache, and has exactly one caller:
  `AuthRoutes::engine_credential_state`, reached only from `revalidate_stream`. The split is the
  security argument. That path already tolerates staleness of the same order by design — on
  `StoreUnreachable` the stream rides out a ~60 s grace window (Decision 15(i), CH-4) — so caching
  there changes no posture, whereas caching session synthesis or an on-behalf-of target check
  would widen revocation latency on a path that tolerates none. Without the cache, every engine
  stream cost one uncached lease-bounded read per ~3 s tick, which under a pool brownout was
  self-amplifying (unreachable → indeterminate → keep retrying) and starved the data plane, not
  just the streaming feature. Only `Active` is cached: `MissingOrRevoked` is terminal and rare
  (and negative-caching it would need `create()` invalidation to avoid masking a fresh principal),
  and caching `StoreUnreachable` would extend the outage the cache exists to damp. `revoke()` and
  `transfer_owner()` invalidate synchronously **after** their write, guarded by a generation
  counter copied from `ApiTokenStore` — so the writing replica cuts the stream on the next tick,
  and the cross-replica window is bounded by the TTL, the same residual property the token cache
  already carries.
- A boot-time collision scan (`server.cpp`, hardened alongside this store in the PR 4.2 fix round
  to require `rbac_store_->is_open()` before trusting a clean result) refuses to start the server
  if a pre-existing `engine:`-named local user or RBAC group predates the reservation — see
  `docs/ops-runbooks/engine-principal-store-recovery.md` for the pre-upgrade check and recovery
  procedure, and the `## ⚠️ Breaking` section of `docs/user-manual/upgrading.md`.
