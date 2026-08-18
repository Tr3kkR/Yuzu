---
status: accepted
date: 2026-08-18
owner: platform (Postgres substrate migration program)
deciders: parallel Wave 3 migration worker (batch 4), following the ladder assignment in
  `docs/postgres-migration-ladder.md` (Wave 3)
scope: server — `CaStore` (Yuzu internal CA inventory + lifecycle: root, issued-cert inventory,
  CRL version history), its cutover from SQLite to PostgreSQL, and its ADR-0009 backfill
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend, no SQLite fallback),
  ADR-0008 (substrate architecture), ADR-0009 (per-store first-boot backfill cutover),
  ADR-0010 (secrets at rest), ADR-0012 (server Postgres store contract), ADR-0036
  (authoritative-read type-distinguishability program policy)
related: docs/postgres-migration-ladder.md (Wave 3); docs/pki-architecture.md (routed reference);
  docs/adr/0048-license-store-postgres-migration.md (the authoritative-with-backfill /
  IDENTITY-LIFECYCLE / kXxxDbErrorPrefix template this migration follows most closely)
---

# 0053 — `CaStore` Postgres migration (authoritative, PKI routed-concern, with backfill)

## Context

`CaStore` (`server/core/src/ca_store.{hpp,cpp}`) is the inventory + lifecycle store for Yuzu's
internal CA: the root certificate (metadata only — the private key lives behind `KeyProvider`,
never in this store), the issued-certificate inventory, and the CRL version history. It is a
Wave 3 store on `docs/postgres-migration-ladder.md`, listed there as "unblocked" ahead of its
Wave-3 siblings because it holds no envelope-encrypted secret column — `key_ref` is an opaque
`KeyProvider` reference, not key material, so `SecretCodec` is not involved (confirmed below).

This is a PKI routed-concern store (`.claude/routed-concerns.md`): the catastrophic invariants —
key-never-in-the-DB, the shared `sign_agent_csr` signer, and the revoked-status read path staying
fail-closed — are preserved unchanged by this migration; only the storage engine changes.

`CaStore` was previously SQLite (`ca.db`, tables `ca_root`, `ca_issued`, `ca_crl_versions`,
migrations v1–v5) guarded by a single connection mutex, with a second, coarser `crl_publish_mu_`
serialising CRL-number allocation. It is wired live in `server.cpp` (`ca_store_`), consumed by
`ca_routes.cpp` (the `/api/v1/ca/*` REST surface + the Settings CA panel), `mcp_server.cpp`
(`list_issued_certs`/`revoke_certificate`), and `default_certs.cpp` (first-boot bootstrap).

## Decision

**Migrate `CaStore` to PostgreSQL as schema `ca_store`, tables `ca_root`, `ca_issued`,
`ca_crl_versions`, with a standard ADR-0009 first-boot backfill.**

### Schema

Schema name `ca_store` (ADR-0008 Update naming rule). A single consolidated `v1` migration folds
in every column the SQLite store's five migrations (v1–v5) added incrementally — those existed
only to upgrade already-deployed local files; no Postgres database predates this schema, so there
is nothing to incrementally ALTER. The partial index `idx_ca_issued_status ON ca_issued(status)
WHERE status = 'revoked'` carries across as-is (Postgres supports partial indexes natively).
`ca_crl_versions.der` becomes `BYTEA` (was `BLOB`); every other column keeps its pre-migration
type and name unchanged (`TEXT`→`TEXT`, `INTEGER` epoch-seconds/count columns→`BIGINT`).
`serial_hex TEXT PRIMARY KEY` and `ca_root.id INTEGER PRIMARY KEY CHECK (id = 1)` are kept exactly
(pre-migration ID contracts, per the Wave 2/3 lesson).

A new table, `sqlite_backfill_source (fingerprint TEXT PRIMARY KEY, completed_at BIGINT NOT
NULL)`, is the backfill idempotency tracker — not part of the application data model.

### Secrets (ADR-0010) — resolves the Wave 3 "unblocked" note

**Asserted and unchanged by this migration: `key_ref` is the ONLY root-key-adjacent column, and
it is an opaque `KeyProvider` reference (a file path in Milestone 1), never the key itself.** No
column in any of the three tables holds secret material — `cert_pem` values are PUBLIC certs, not
keys. `SecretCodec` is therefore not involved; this store does not belong in a future secrets-seam
wave.

### Posture

**AUTHORITATIVE / fail-hard** (ADR-0012 §1), both construction and runtime — the database is the
source of truth for the revoked-certificate set. A silently-empty/-false read on `is_revoked` /
`list_revoked` would silently accept a certificate that should have been rejected, or publish a
CRL that omits a real revocation — exactly the fail-open shape ADR-0036 exists to close. Every
reader/mutator whose false/empty result could feed that class of decision returns
`std::expected<..., std::string>`, prefixed `kCaDbErrorPrefix` ("`db_error: `") on a genuine
DB/lease failure — **with one deliberate, documented exception: `is_revoked()`**.

#### `is_revoked()` stays a plain `bool`, fails closed to `true`

This is the mTLS-accept security gate (`ServerImpl::is_peer_cert_revoked`), on the per-heartbeat/
Subscribe/Register-reauth hot path. Rather than expose a third ("couldn't tell") state a caller
could accidentally fold into "not revoked," every degradation mode — a non-hex serial (pre-
existing), a lease timeout, a query error (both new failure modes a networked Postgres substrate
makes far more likely than a local SQLite file) — returns `true`: "treat as revoked, refuse."
This mirrors `ApiTokenStore::validate_token`'s existing hot-path-degrades-to-the-safe-answer
precedent (both are auth-gate reads with the same shape). The catastrophic-if-violated PKI
invariant this store's kickoff cited verbatim: *"Degrade → error → treat as revoked / refuse,
never silent-pass."*

**Operational consequence, stated explicitly:** during a sustained Postgres outage, every
heartbeat/Subscribe/Register-reauth is rejected fleet-wide, not just genuinely-revoked agents.
Since the return value alone cannot distinguish "the DB is down" from "a real mass-revocation
sweep," `is_revoked()` emits a distinct, explicit log line on every degraded-path return
(`CaStore::is_revoked: database unavailable ... this is a DEGRADED-DB rejection, NOT a real
revocation`) so an operator diagnosing mass rejection has the signal in hand without having to
infer it.

#### `list_revoked()` — type-distinguishable, and its callers must abort, never proceed on empty

`list_revoked()` feeds CRL construction (`publish_crl()`'s revoked-set) and the PR3 HIGH-2
re-issue-block guard (`sign_agent_csr`'s scan for an existing revoked, non-expired cert on the
requesting `agent_id`). A silently-empty read on either call site is dangerous in a DIFFERENT way
than `is_revoked`'s own degradation: it does not merely deny one request, it can (a) publish a CRL
that claims nobody is revoked when real revocations exist (un-revoking every cert in every cache
that trusts that CRL), or (b) let a revocation-bypass re-enrollment through — the exact bug class
HIGH-2 (#1239) closed. Both `server.cpp` call sites were updated to treat a `list_revoked()`
`unexpected` as an abort signal (refuse to publish / refuse to issue), never as "empty means
nothing is revoked."

#### Root-singleton first-boot race (the one genuinely new problem)

Under per-instance SQLite this race never existed — each server instance held its own local
`ca.db`. A shared Postgres substrate makes it possible for two instances to independently generate
CA root material (their own key, their own self-signed cert, their own three default leaves,
written to their own local cert directory via `FileKeyProvider`) and race to establish it as
canonical.

**Resolution — split the write API:**

- **`try_insert_root(root)`** — the NEW, race-safe first-boot entry point. `INSERT ... ON
  CONFLICT (id) DO NOTHING RETURNING ...`: at most one caller's row is ever inserted. Every
  caller, winner or loser, reads back the SAME row that is now canonical — the loser does **not**
  get told "you lost" as a bare boolean; it gets handed the actual winning `CaRoot`, and MUST
  compare its returned fingerprint against what it generated to learn which happened (never
  locally infer "I won" from anything but the returned value).
- **`set_root(root)`** — kept, unconditional REPLACE (`ON CONFLICT (id) DO UPDATE`), the
  pre-migration `INSERT OR REPLACE` contract verbatim. Used by the two callers that legitimately
  intend a replace: PR6 subordinate-CA import (`ServerImpl::import_subordinate_chain` — an
  explicit, single-writer, operator-triggered re-root of an ALREADY-established root) and test
  seeding. **Never called from first-boot generation** — porting `set_root`'s semantics onto that
  path (as a naive migration might) would have the RACE LOSER silently clobber the winner's root
  with its own, orphaning the winner's already-enrolled agents in the instant between — the
  precise wrong outcome kickoff flagged.

**The loser's side, decided explicitly (`default_certs.cpp`):** a losing caller has already
generated complete, unusable key material (nobody else holds its private key — the shared-
cert-volume topology, where it exists, shares live cert *files*, not a yuzu-server process's
in-memory key). Full cross-replica cert-material handoff (the loser somehow adopting and serving
under the winner's identity) is **out of scope** for this migration — a topology-dependent,
tracked follow-up if true multi-replica HA over one shared `ca_store` Postgres becomes a supported
deployment shape (it is not today; every other "HA/multi-instance" caveat already on this store —
see CRL numbering below — is consistently framed the same way). What THIS migration guarantees is
DB-level: **exactly one root is ever established**, and every other racer fails closed (refuses to
write its marker, refuses to serve under material nobody else recognises, returns `false` from
`ensure_default_certs`) rather than silently operating under, or overwriting, a different one.

**Tested** (`try_insert_root — a losing caller reads back the winner, never clobbers it`,
`[ca_store][pg][root][security]`): two `try_insert_root` calls with distinct root material against
the same store — the second call returns the FIRST call's root verbatim (fingerprint and
`cert_pem`), and a subsequent `get_root()` confirms the stored row is still exactly the winner's.

#### `has_root()` / `get_root()` split — B-2's re-root guard needed the typed channel, three other callers did not

`get_root()` becomes `std::expected<std::optional<CaRoot>, std::string>`. A NEW `has_root()`
convenience collapses a degraded read to `false` — kept **only** because three of the four
production call sites are safe with that collapse (a background CRL-freshness-sweep tick
skipping harmlessly; the `/readyz` `ca_root` signal, where "can't prove a root exists" SHOULD
read as unhealthy anyway). The FOURTH — `default_certs.cpp`'s B-2 guard ("never silently re-root a
populated CA," #1238) — was switched to call `get_root()` directly and fail closed (refuse to
proceed) on a genuine read error, because collapsing that ONE call site's degraded read to "no
root" would let a fresh CA generation proceed and silently re-root a fleet that already has one —
precisely the danger B-2 exists to prevent, and precisely the ADR-0036 reviewer test ("could a
silently-false read gate a downstream generate/replace decision? If yes, fail closed, never
empty").

### Write-path failure classification (#3097 precedent)

- **`record_issued`** — `std::expected<void, std::string>`. A PG unique-violation (SQLSTATE
  `23505`) on `ca_issued.serial_hex` is classified distinctly, prefixed `kCaDuplicateSerialPrefix`
  ("`duplicate_serial: `"), separate from `kCaDbErrorPrefix` — resolves the #1276 flake lead
  (kickoff item 2). **Finding:** `x509_ca` mints a random 128-bit serial per issuance
  (`x509_ca.hpp`), so a genuine production collision is astronomically unlikely; no repro of a
  real collision was found in this migration's test fixtures or in the current tree. The
  classification is real infrastructure regardless — a future caller can retry issuance with a
  freshly-minted serial on this specific error rather than treating it as an outage — but this
  narrows, rather than closes, #1276: the flake is more likely a test-fixture serial reuse than a
  live collision, and is left open for whoever last touched it to close or re-scope with this
  finding in hand.
- **`revoke`** — `std::expected<bool, std::string>`. `Ok(true)` = transitioned; `Ok(false)` = a
  genuine, successful business answer (unknown/already-revoked — audited `result=denied`, per
  `docs/pki-architecture.md`'s existing taxonomy); `unexpected` = a genuine DB/lease failure,
  audited `result=failure` and surfaced as REST 503 / MCP `kInternalError` — **never folded into
  `denied`**, which would falsely record a database outage as a rejected revoke attempt (a false
  compliance record). `ca_routes.cpp`'s `RevokeOutcome` enum gained a `StoreError` member
  alongside the existing `NotFound`/`RevokedCrlStale`/`RevokedCrlPublished`, mapped to 503 on both
  the REST and dashboard-wrapper revoke handlers; `mcp_server.cpp`'s `revoke_certificate` handler
  mirrors the same three-way split.
- **`next_crl_number`** — `std::expected<std::uint64_t, std::string>`. The pre-migration SQLite
  version silently returned `1` on ANY read error — safe by accident under SQLite (a stray `1`
  either collides loudly against `record_crl`'s duplicate-refusal once real CRLs exist, or is
  merely stale-but-harmless before any CRL has ever been published) but unsafe to carry forward
  once the table can hold real cross-boot history: `server.cpp`'s `publish_crl()` now aborts the
  whole publish attempt on a `next_crl_number` error rather than substituting a default.

### CRL version continuity (kickoff item 4 — stated explicitly)

The CRL sequence must not regress or fork across cutover. Three parts:

1. **Backfill resumes above the legacy max, never regresses to 1.** Legacy CRL rows are inserted
   into `ca_crl_versions` before the store ever computes `next_crl_number()` in steady state, so
   `MAX(version)+1` naturally resumes above the highest backfilled version — tested explicitly
   (`migrate_from_sqlite — full happy-path backfill`: after backfilling a CRL at version 1,
   `next_crl_number()` returns 2, never 1).
2. **A version collision is always loud, never a silent clobber** — unchanged by this migration:
   `record_crl` is a plain `INSERT` (never `ON CONFLICT ... DO UPDATE`), so a duplicate version is
   refused, not overwritten. This was already true under SQLite; it remains true under Postgres.
3. **Cross-instance CRL numbering remains a tracked, NOT-newly-introduced limitation.** The
   pre-migration `ca_store.hpp` already documented this exact gap for a hypothetical HA/multi-
   instance/DB-restore scenario (#1240 UP-4) — true durable cross-instance numbering (an
   auto-retry-on-conflict republish loop spanning the CA-key-load-and-sign step) is explicitly
   OUT OF SCOPE for this migration, which ports the persistence layer, not a new HA feature nobody
   asked for here. `server.cpp`'s `publish_crl()` keeps its existing shape: `next_crl_number()`
   and `record_crl()` as two separate, short-lived leases with NO lease held across the CA-key-
   load-and-sign step in between (unchanged — the correct "never hold a lease across disk/signing
   work" shape, ADR-0012 §2) under its own process-local `crl_publish_mu_` member (unrelated to
   `CaStore::publish_next_crl`'s own, differently-scoped mutex — see below).

### `CaStore::publish_next_crl` — kept, zero production callers (verified)

Grep across the whole tree (`.cpp`/`.hpp`, excluding its own definition and test file) finds no
call site outside `ca_store.{hpp,cpp}` and `test_ca_store.cpp`. `server.cpp`'s actual production
CRL-publish path (`publish_crl()`) reimplements the same allocate→build→record shape manually,
under its OWN `crl_publish_mu_` member, calling `next_crl_number()`/`list_revoked()`/`record_crl()`
directly rather than through this method's `CrlBuilder`-callback abstraction. Kept for API/test
parity (it is unit-tested and may be a future convenience surface); internally hardened to abort
(return `nullopt`, consume nothing) on a `next_crl_number()`/`list_revoked()` read failure rather
than silently building a CRL over a wrong number or a possibly-incomplete revoked set — the same
fix class as the production path's own hardening above, applied so the untested-in-production
method does not carry a latent version of the identical bug.

### Backfill (ADR-0009)

**Mandatory, three-table, fingerprint-verified** — extends `LicenseStore`'s (ADR-0048) two-table
canonicalization design to three: `ca_root`, `ca_issued`, `ca_crl_versions`. All three are created
together, atomically, by the pre-migration SQLite `CaStore`'s v1 migration — no version of the
shipped binary can produce a legacy file holding some-but-not-all of the three, so that shape
fails the whole backfill closed (the same corrupt/hand-edited-file bias as an unrecognised enum
value).

- **`ca_root` (0-or-1 row, singleton):** ALL-IDENTITY, per the kickoff's explicit classification —
  any mismatch against an already-established row fails the backfill closed. The insert uses the
  SAME `ON CONFLICT (id) DO NOTHING`-then-readback-and-compare shape as `try_insert_root()`, so it
  is race-safe against a concurrent `try_insert_root()` caller or a concurrent sibling backfill by
  construction (whichever INSERT lands first wins; everyone else reads back that row).
- **`ca_issued`:** IDENTITY (`subject`, `san`, `purpose`, `not_after`, `issued_at`, `issued_by`,
  `enrollment_request_id`, `cert_pem`, `issuer_fingerprint`, `issuer_key_id` — write-once at
  `record_issued()`, no other method mutates them) vs LIFECYCLE (`status`, `revocation_reason`,
  `revoked_at` — mutated only by `revoke()`). Direction resolved by a `cert_status_rank`
  (`active`=0 < `revoked`=1 terminal < unrecognised=2, rejected before ever reaching Postgres):
  Postgres strictly ahead (already revoked; the legacy snapshot predates it) is a benign
  WARNING-logged no-op, keeping Postgres's revoked state; **legacy strictly ahead, or both
  revoked but disagreeing on `revocation_reason`/`revoked_at`, fails the boot closed** — the
  kickoff's explicit instruction, verbatim: *"revoked-in-legacy/active-in-PG fails closed, never
  un-revoke."*
- **`ca_crl_versions`:** `version` is the natural conflict key. Byte-identical `der` at the same
  version is a benign no-op (the same CRL, backfilled twice); a DIFFERENT `der` under the SAME
  version is an RFC 5280 crlNumber fork and fails the boot closed — never silently pick a side.
- Every legacy `status` value is validated against the known enum set BEFORE it can reach
  Postgres (mirrors `LicenseStore`'s precedent for the identical class of exposure).
- Legacy files are read READ-ONLY and never deleted/moved — retained for the ADR-0009
  one-release rollback window.

### `/readyz` / `/healthz`

Unchanged wiring — `has_root()` (now the fail-soft convenience, not the B-2 gate) already feeds
the existing `/readyz` `ca_root` signal (`server.cpp`); `is_open()` already joins the standard
store conjunction. No new wiring needed; the existing signal now correctly reflects a genuine
Postgres read failure as "unhealthy" rather than the pre-migration file-open check.

### Upgrade-test coverage — known gap, not unique to this store

`scripts/test/test-upgrade-stack.sh` carries exactly one store-specific data-survival assertion
(the original ADR-0009 generic-inventory pilot, `git log` shows no other touch to this file or
`test-fixtures-verify.sh`). None of the sibling Wave 2/3 migrations that followed it — LicenseStore
(ADR-0048), DeploymentStore, SoftwareDeploymentStore (ADR-0051) — added their own dedicated
previous-release-SQLite → new-release-Postgres assertion either; each relies on the harness's
generic `fixtures-verify` pass (asserts overall server health/migration success post-upgrade, not
per-store content). This migration follows that same precedent rather than being the first to
diverge from it: CA issued-cert + CRL history backfill is exercised by `test_ca_store.cpp`'s
dedicated `migrate_from_sqlite` suite (real legacy-schema fixtures, fingerprint verification,
idempotent-rerun) but not by the end-to-end upgrade harness. Closing this gap — for CaStore and
its siblings alike — is tracked as a follow-up on `docs/postgres-migration-ladder.md`, not solved
here.

## Considered and rejected

- **Folding `has_root()` entirely into `get_root()` and updating all four call sites to the typed
  form.** Rejected as unnecessary churn: three of the four call sites are demonstrably safe with a
  degraded-collapses-to-false read (a background sweep tick, `/readyz`), and forcing them onto the
  richer type would add call-site verbosity with no behavioral benefit. Keeping `has_root()` as a
  documented, narrow convenience — with an explicit doc-comment warning against using it for a
  re-root safety gate — was judged clearer than either extreme (blanket-typed everywhere, or
  blanket-bool everywhere).
- **Solving cross-instance CRL numbering (auto-retry-on-conflict) as part of this migration.**
  Rejected as scope creep beyond "migrate the persistence layer" — it is a pre-existing, already-
  tracked (#1240 UP-4) limitation this migration does not worsen (a collision was always refused
  loudly, never silently), and building the retry loop correctly requires re-running the CA-key-
  load-and-sign step, which crosses into `server.cpp`'s signing orchestration, not this store.
- **A single shared `kCaDuplicateSerialPrefix`/`kCaDbErrorPrefix` reused from another store's
  constants.** Rejected per the established Wave 2/3 precedent (ADR-0048's "Considered and
  rejected"): each store's error-prefix constants stay local so a future rename of one cannot
  silently affect another.

## Consequences

- Every CA read/write now surfaces a genuine database error to its REST/MCP/dashboard caller as a
  503/`kInternalError`/error-panel instead of a silently-empty/-false SQLite-mutex-guarded result,
  EXCEPT `is_revoked()`, which deliberately keeps its bool/fail-closed-to-`true` shape by design
  (see above) — this is a live behavioral change for every already-wired CA surface, unlike
  `LicenseStore`'s dormant-store precedent.
- The first-boot CA-root race is now handled correctly for the first time — under SQLite it was
  structurally impossible (each instance had its own file), so there was never a "correct"
  behavior to preserve; this migration is establishing new, tested behavior, not porting existing
  behavior.
- `CaStore` moves from "SQLite, single-connection-mutex-serialized" to "Postgres, pool-concurrent"
  — matches every other migrated store's concurrency model.
- The legacy `ca.db` is retained for one release (ADR-0009 rollback window), then removed per the
  standard cadence.
- `#1276`'s flake lead is narrowed (see "Write-path failure classification" above) but not closed
  — a genuine production serial collision remains believed-negligible given random 128-bit
  serials, and this migration adds the typed-retry infrastructure without asserting the flake's
  root cause is fully diagnosed.
