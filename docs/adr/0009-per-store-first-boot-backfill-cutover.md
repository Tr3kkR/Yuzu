---
status: accepted
date: 2026-06-09
owner: Nathan Dornbrook (platform)
deciders: Nathan Dornbrook; grill-with-docs design session 2026-06-09
scope: platform — how each existing server SQLite store cuts over to Postgres
builds-on: ADR-0006 (Postgres substrate), ADR-0008 (substrate architecture)
---

# 0009 — Existing stores cut over via a one-time, idempotent first-boot backfill

## Context

ADR-0006 migrates ~29 existing server SQLite stores to Postgres incrementally (strangler), each
behind its own per-store ADR. This ADR fixes the *mechanism* every such migration uses, so the
per-store ADRs don't each re-invent it. The risk is data loss / corruption on a live store
during cutover. The stores fall into classes with different durability needs: TTL'd ephemeral
(response 90d), SOC 2 retained (audit 365d), config/reference (rbac, tags, baselines,
management-groups, policies, custom-properties, product-packs — operator state that cannot be
lost), and build-time-seeded (instructions — re-seeded from embedded content, plus operator
additions). The upgrade-test rig (`scripts/test/docker-compose.upgrade-test.yml`) already
exercises previous-release → new-release and is the natural gate.

## Decision

**Big-bang per store via a one-time, idempotent first-boot backfill.** When a migrated store
comes up on Postgres, finds its Postgres schema empty **and** a legacy `<name>.db` SQLite file
present, it copies rows over (a per-store `migrate_from_sqlite()` step) and stamps itself
migrated; subsequent boots skip it. The backfill runs **at startup, before the server serves**,
and **fails closed** on any error (the server refuses to start rather than serve half-migrated
data).

- **Backfill is mandatory** for config/reference stores and for `audit` (SOC 2 retention).
- **Backfill may be skipped** (behind a flag) for purely TTL'd ephemeral stores (`response`) —
  history ages out, so a clean cut with a bounded gap is acceptable.
- **The legacy SQLite file is retained read-only for one release** as a rollback net, then
  removed in the following release.
- Each per-store migration's upgrade-test must assert that config/reference/audit data survives
  the previous-release-SQLite → new-release-Postgres transition.

## Considered and rejected

- **Dual-write window per store** (write both engines, read SQLite, flip reads to Postgres,
  then drop SQLite). Zero-gap and trivially reversible, but ~29× the complexity and a
  long-lived two-engine code path running through the entire multi-quarter program — the exact
  cost ADR-0007's single-backend decision exists to avoid.
- **Cutover with no backfill (fresh start everywhere).** Simplest code, but it discards
  operator config and SOC 2 audit history — unacceptable for the reference and audit stores.

## Consequences

- Each per-store migration carries a `migrate_from_sqlite()` implementation and an upgrade-test
  assertion; the recipe is uniform, so per-store ADRs focus on schema, not mechanism.
- The rollback window is exactly one release (the read-only legacy file). A defect discovered
  after the legacy file is removed has no in-place rollback — so the one-release retention and
  the upgrade-test gate are load-bearing, not optional.
- **Secrets stores (`api_token`, `ca`) are explicitly out of scope for this mechanism.** They
  migrate last and only behind a dedicated secrets-at-rest ADR (envelope encryption / KMS /
  `pgcrypto`) + `security-guardian` review — a plain `migrate_from_sqlite()` copy into Postgres
  columns is forbidden for secret material (the ADR-0004/0006 carve-out).

  **Update (ADR-0010, 2026-06-10):** the dedicated secrets-at-rest ADR landed as ADR-0010,
  with a scope ruling that differs from the sentence above: `api_token` and `ca` are
  hash-only / key_ref-only (no plaintext secret columns) and are **unblocked** onto the
  normal ladder; the stores that actually require the secrets mechanism are `auth`,
  `webhooks`, `offload_targets`, and `runtime_config`. The decided mechanism is app-side
  AES-256-GCM envelope encryption (`SecretCodec`); `pgcrypto` was considered and rejected.
  Backfills that touch secret columns transform (encrypt/hash), never copy — see ADR-0010.
