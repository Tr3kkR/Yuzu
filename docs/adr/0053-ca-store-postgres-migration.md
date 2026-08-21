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

#### `has_root()` / `get_root()` split — two callers needed the typed channel, two did not

`get_root()` becomes `std::expected<std::optional<CaRoot>, std::string>`. A NEW `has_root()`
convenience collapses a degraded read to `false` — kept **only** for the two production call
sites genuinely safe with that collapse: a background CRL-freshness-sweep tick skipping
harmlessly, and the `/readyz` `ca_root` signal, where "can't prove a root exists" SHOULD read as
unhealthy anyway. Two other call sites needed the typed channel instead:

- `default_certs.cpp`'s B-2 guard ("never silently re-root a populated CA," #1238) calls
  `get_root()` directly and fails closed (refuses to proceed) on a genuine read error — collapsing
  this ONE call site's degraded read to "no root" would let a fresh CA generation proceed and
  silently re-root a fleet that already has one, precisely the danger B-2 exists to prevent.
- **`server.cpp`'s boot-time PKI wiring block** (the `run()` code that wires the per-agent cert
  signer, the revocation checker, and the peer-cert recognizer) was **initially left on
  `has_root()`** in this migration's first two commits — an oversight caught by adversarial review
  (Kimi + Codex, both independently, 2026-08-20), not by the author. `has_root()`'s collapse turns
  a transient Postgres lease/query failure at this ONE call site into "no root," which silently
  skips wiring the revocation checker for the rest of the process's life — no retry, no periodic
  re-check. A revoked Yuzu-issued agent cert would then pass `Register`/`Subscribe`/heartbeat
  unchecked until the next restart: a fail-open security regression, and exactly the ADR-0036
  reviewer test this store's OTHER read paths were built to satisfy ("could a silently-false read
  gate a downstream grant/enforce/skip decision? If yes, fail closed, never empty") — just missed
  on this one call site. **Fixed**: the block now calls `get_root()` directly; an `unexpected` sets
  `startup_failed_ = true` and returns from `run()` immediately — this call site runs BEFORE
  `BuildAndStart()`, so nothing is listening yet, matching the bare-`return`-on-failure precedent
  the TLS-credential checks a few dozen lines below already use at this same pre-`BuildAndStart`
  point in `run()` (no listener to tear down, unlike the later SCIM-boot-failure recheck, which
  fires AFTER `BuildAndStart()` and so needs the heavier `stop()` call to close what is already
  open). A genuinely-empty root (`nullopt` — operator brought their own certs) is unchanged: skip
  wiring, no signer, same pre-PKI contract as before.

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

- **Folding `has_root()` entirely into `get_root()` and updating every call site to the typed
  form.** Rejected as unnecessary churn: the two remaining `has_root()` callers (a background
  sweep tick, `/readyz`) are demonstrably safe with a degraded-collapses-to-false read, and
  forcing them onto the richer type would add call-site verbosity with no behavioral benefit.
  Keeping `has_root()` as a documented, narrow convenience — with an explicit doc-comment warning
  against using it for a security-relevant gate — was judged clearer than either extreme
  (blanket-typed everywhere, or blanket-bool everywhere). That doc-comment warning existed from
  this migration's first commit; it just did not stop the author from missing one of its own
  call sites (see "Adversarial review" below) — a warning comment narrows the class of mistake, it
  does not substitute for checking every call site against it.
- **Solving cross-instance CRL numbering (auto-retry-on-conflict) as part of this migration.**
  Rejected as scope creep beyond "migrate the persistence layer" — it is a pre-existing, already-
  tracked (#1240 UP-4) limitation this migration does not worsen (a collision was always refused
  loudly, never silently), and building the retry loop correctly requires re-running the CA-key-
  load-and-sign step, which crosses into `server.cpp`'s signing orchestration, not this store.
- **A single shared `kCaDuplicateSerialPrefix`/`kCaDbErrorPrefix` reused from another store's
  constants.** Rejected per the established Wave 2/3 precedent (ADR-0048's "Considered and
  rejected"): each store's error-prefix constants stay local so a future rename of one cannot
  silently affect another.

## Adversarial review (2026-08-20, pre-push)

Two independent external models (Kimi K2.7, Codex GPT-5.5 at high reasoning), each compiling this
branch and running the real Postgres-backed `[pki]`/full-server test suite, cross-examined this
migration against the anchors above (`docs/pki-architecture.md`, ADR-0006/0007/0008/0009/0010/0012,
`docs/postgres-store-playbook.md`, this ADR, ADR-0048). Both independently found and, after
cross-examination, converged on:

- **HIGH (fixed):** the boot-time `has_root()` mischaracterization above — the security-relevant
  regression this section already describes in full. Both reviewers cited the same anchors
  (`docs/pki-architecture.md`'s fail-closed contract, this ADR's own `has_root()`/`get_root()`
  split text, ADR-0036/the playbook's type-distinguishable-reads rule) independently before
  cross-examining each other, which is the strongest class of finding this process produces.
- **MEDIUM (fixed):** `ServerImpl::stop()` did not explicitly `ca_store_.reset()` before
  `pg_pool_.reset()`, unlike every sibling Postgres store in the same function
  (`result_set_store_`, `quarantine_store_`, `notification_store_`, ...). Reverse-declaration-order
  destruction made this safe for `~ServerImpl` (`ca_store_` is declared after `pg_pool_`, so it
  destructs first), and `stop()` already nulls the PKI callbacks before this point — so nothing
  live actually touched a dangling pool reference — but `stop()` bypasses that declaration-order
  protection by resetting `pg_pool_` explicitly mid-function, and both reviewers judged relying on
  declaration order alone (rather than the explicit-reset discipline every sibling store follows)
  a latent lifecycle gap worth closing now rather than after a future change adds a pool-touching
  path to `CaStore`. Fixed: `ca_store_.reset();` added immediately before `pg_pool_.reset();`.
- **LOW (not fixed, out of scope):** REST (`ca_routes.cpp`) and MCP (`mcp_server.cpp`) reject a
  colon/whitespace-decorated serial (e.g. `AB:CD:12`, common OpenSSL/browser copy-paste form) that
  `CaStore::normalize_serial_hex` itself would accept and canonicalize. Both reviewers confirmed via
  `git show` against this branch's merge-base that the REST validator predates this migration —
  it is a pre-existing REST/MCP-vs-store parity gap, not introduced here, and is a usability defect
  (rejects too much) rather than a security bypass (`is_revoked()`/`revoke()` still canonicalize
  and fail closed on the store side). Left for a separate, appropriately-scoped fix rather than
  folded into this migration.

Full transcripts: `/tmp/advrev-ca-store/{kimi,codex}.phase{1,2}.md` (local scratch, not committed).

## Governance Gate 3 findings (2026-08-21, pre-push)

The full `/governance` pipeline's Gate 3 (architect, cpp-expert, cpp-safety, quality-engineer,
run in parallel) found one further HIGH the adversarial-review round above did not — a distinct
first-boot cross-replica race, in a different part of the boot sequence than the one already
fixed:

- **HIGH (fixed, architect):** `default_certs.cpp`'s unscoped inventory purge
  (`ca_store->delete_issued_by("system:default-certs")`) originally ran BEFORE the root race
  resolved (`try_insert_root`, further down the function) — meaning two racing instances could
  BOTH pass the B-2 empty-root check, both proceed to purge (a no-op the first time) and generate
  + `record_issued()` their own three leaf rows, and whichever instance's purge landed SECOND
  would delete the FIRST instance's already-committed rows via the same unscoped `issued_by`
  match — including, if the first instance went on to WIN the root race, its own now-live,
  in-service default certs. The result: an established root with in-service leaves whose
  `ca_issued` rows are gone — permanently unrevocable through the normal control (`revoke()`
  returns "not found" forever) and silently absent from every future CRL. Fixed by moving
  `try_insert_root()` (and the local-file key storage it depends on) to run BEFORE any leaf
  generation, purge, or `record_issued()` call — a losing instance now returns immediately,
  having touched no shared `ca_store` inventory state at all, and the purge only ever runs after
  this instance has confirmed it is the sole legitimate writer going forward. Closes the same
  finding class as the LOW noted below it (a loser's own orphaned leaf rows, since a loser no
  longer records any). Regression test: `test_default_certs.cpp`'s "two racing first-boot
  instances never cross-purge each other's leaf inventory" — two real `std::thread`s racing
  `ensure_default_certs` against one shared `CaStore`, asserting exactly the winner's 3 leaves
  survive (verified red against the pre-fix code, reproducing the exact `issued->size() == 5`
  corruption the bug produces, before being fixed to pass green).
- **SHOULD (fixed, cpp-safety):** `ServerImpl::stop()` nulled `agent_service_`'s PKI callbacks
  but not `gateway_service_`'s copy of the same `agent_cert_signer` lambda, inconsistent with the
  `set_blast_radius_detector`/`set_dex_alert_router` parity a few lines above in the same
  function. Not a proven UAF (`gateway_service_` shares `agent_server_`'s `Shutdown(deadline)`
  drain), but closes the belt-and-braces gap for consistency. Fixed: added the matching
  `gateway_service_->set_agent_cert_signer(nullptr)` call.
- **SHOULD (fixed, quality-engineer):** the a14138449 HIGH fix (boot-time `get_root()` vs
  `has_root()`) had no dedicated regression test — its correctness rested on compilation, the
  existing suite still passing, and manual inspection. quality-engineer identified this
  codebase's own established pattern for exactly this test class (`test_deployment_store.cpp`/
  `test_api_token_store.cpp`'s "sabotage the store, assert the typed method reports `unexpected`"
  shape) as directly applicable without needing to boot a real `ServerImpl`. Added: a
  `test_ca_store.cpp` case that establishes a real root, drops `ca_store.ca_root` out from under
  the open `CaStore` instance, and asserts `get_root()` returns `unexpected` (prefixed
  `kCaDbErrorPrefix`) while `has_root()` — the SAME underlying failure — collapses to `false`,
  pinning the exact contract the boot-wiring fix depends on.
- Two further SHOULD findings (quality-engineer: `try_insert_root`'s winner/loser coverage is
  sequential-call-order rather than genuine concurrent-thread; new `StoreError`/503 REST branches
  are exercised via injected outcomes rather than a real degraded store) and one NICE
  (cpp-expert: `kCaDuplicateSerialPrefix` has no production consumer yet — `sign_agent_csr`
  doesn't currently retry on it, so the doc comment describing a retry overstates current
  behavior) were reviewed and left open — bounded blast radius, not a policy floor, and
  appropriately scoped to a future change rather than this migration.

Full agent reports: this run's governance transcript (session-local, not committed).

## Governance Gate 4 findings (2026-08-21, pre-push)

Gate 4 (happy-path PASS; consistency-auditor PASS-with-SHOULDs; unhappy-path) found two further
HIGHs — both newly reachable specifically because of this migration's fail-closed posture, and
both fixed in this round:

- **HIGH (fixed, unhappy-path UP-1):** the ~15s revocation-sweep tick (`server.cpp`, tears down
  any live Subscribe stream whose agent leaf has since been revoked) called the same
  `is_peer_cert_revoked()` used at the per-request mTLS-accept gate — which, by design (see
  `CaStore::is_revoked`'s doc comment), fails CLOSED (treats as revoked) on ANY degraded read. A
  single degraded mTLS accept failing closed is the correct, bounded posture; reusing that same
  call once per LIVE AGENT inside the sweep tick meant a transient Postgres outage made the sweep
  indistinguishable from "every enrolled agent was just revoked" — every Subscribe stream torn
  down, AND a `session.cert_revoked|denied` audit row written for each. That second half is the
  gating fact: a durable SOC 2 evidence row asserting a revocation-driven access termination that
  never actually happened is a false compliance record (I3), not merely an availability blip
  (I5/MEDIUM on its own). Newly reachable by this migration: verified against the pre-migration
  SQLite `is_revoked()`, which returned `false` (fail-OPEN) on a null `db_` and had no comparable
  transient-failure mode, so the sweep could never mass-fire on degradation before this diff.
  Fixed: the sweep tick now reads the revoked set ONCE per tick via the typed `list_revoked()`
  and ABORTS the sweep entirely on a degraded read (logs + a new
  `yuzu_server_ca_revocation_sweep_read_failures_total` counter; live streams are left untouched
  rather than treated as mass-revoked), instead of calling the fail-closed per-request gate once
  per agent. The per-request gate (`is_peer_cert_revoked`) is untouched — still fails closed, as
  documented and intended for a single bounded mTLS accept. Shared PEM→serial resolution
  (`resolve_yuzu_peer_serial`, issuer-scoped via `is_yuzu_issued`) factored out so both the live
  gate and the new set-membership sweep variant (`is_peer_cert_revoked_in`) use identical
  issuer-scoping — a foreign cert cannot collide with a revoked Yuzu serial in either path.
  Residual, recorded deliberately rather than fixed: an agent revoked immediately before an
  outage keeps its live stream for the outage's duration (the per-request gate still fails closed
  on its own next use, so no *new* access is granted) — the sweep is defense-in-depth on top of
  that, not the only enforcement point.
- **HIGH (fixed, unhappy-path UP-2; caused_by: b11be3551):** the Gate 3 HIGH fix above resolves
  the first-boot root race by moving `try_insert_root()` BEFORE all leaf generation — correct,
  and not reverted here — but it also WIDENED the crash-recovery gap on the other side of that
  same call: a crash between `try_insert_root()` succeeding and the completion marker being
  written now leaves the entire leaf sequence (3 `record_issued()` round-trips, key stores, file
  writes) exposed, versus the pre-fix window of essentially one JSON write. Before this fix, the
  ONLY documented recovery from that state was B-2's heavyweight "clean re-root" operator runbook
  (`docs/pki-architecture.md`) — appropriate for an established, enrolled fleet, but disproportionate
  for a FRESH install with zero enrolled agents that simply didn't finish. Fixed: `default_certs.cpp`
  gained a self-heal arm inside the B-2 refusal path — before refusing, check whether THIS instance
  can prove it minted the root ca_store already holds: the local "default-ca" key file (never
  shared state, unlike `ca_store`) still resolves at the exact `key_ref` path ca_store recorded,
  AND its private key cryptographically pairs with the stored root cert
  (`pki::cert_matches_key`). If both hold, resume completing the SAME root (purge + regenerate the
  3 leaves + write the marker) rather than refusing. `FileKeyProvider`'s existing `within_base`
  scoping is what keeps this fail-closed for the genuine danger case: a different instance/host/
  directory has no local key file at another instance's absolute `key_ref` path, so it still hits
  the original refusal unchanged — verified by a dedicated test (two separate `TempDir`s against
  one shared `CaStore`).
  **Superseded — see "Governance Gate 8 findings" below.** This proof establishes DIRECTORY
  ACCESS to the material that minted the root, not INSTANCE IDENTITY — every process sharing the
  same cert directory (e.g. two HA replicas against one shared volume) passes it identically, and
  as originally shipped in this commit nothing serialized two such processes both reaching the
  purge-and-regenerate work below concurrently. Gate 8 added the missing mutual exclusion.
  The purge + leaf-generation + marker-write tail was factored into a
  shared `complete_default_cert_set()` helper so both the normal winning-the-race path and this
  self-heal path run identical code. Regression tests (`test_default_certs.cpp`): the pre-existing
  B-2 test ("refuses to re-root a populated ca.db") encoded exactly the old, now-superseded
  contract for this precise scenario (delete a leaf file, keep the local CA key + ca_store root) —
  updated in place to assert self-heal completion instead of refusal (root fingerprint unchanged,
  3 leaves re-recorded), per the advisor-prescribed red-first recipe; a new adjacent test covers
  the genuine-refusal case (two distinct directories, one shared `CaStore`).

Two further findings reviewed and left open, not blocking:

- **SHOULD (consistency-auditor UP-3):** a losing HA replica (one that lost the first-boot root
  race) never self-heals its own default-cert set from disk — it discards its freshly-generated
  material and returns `false`, so `ensure_default_certs` must be re-invoked (a restart) to pick
  up the winning root's certs. Documented rather than fixed here — a background retry loop is a
  larger, separately scoped change: `docs/user-manual/upgrading.md`'s ADR-0053 section gained an
  explicit HA note (a losing replica needs a restart to pick up the winner's certs).
- **NICE (unhappy-path UP-4):** `rec.subject`/`rec.san` fields in `record_issued()` are not
  explicitly NUL-sanitized before the Postgres write; a NUL byte would truncate silently at read
  time in some clients. Bounded blast radius (server-controlled subject/SAN strings, not
  attacker-influenced), left open.

Full agent reports: this run's governance transcript (session-local, not committed).

## Governance Gate 8 findings (2026-08-21, pre-push)

Gate 8 re-review (security-guardian + unhappy-path, run against the UP-1/UP-2 fix diff
specifically, per the standing rule that Gate 8 re-runs every gate whose domain the fix diff
touches) found the fix round above was itself incomplete — two BLOCKING findings, both
converged on independently by both reviewers for the first, the second unhappy-path-only but
well-evidenced:

- **HIGH (fixed, both reviewers — 2-reporter convergence):** the UP-2 self-heal arm's ownership
  proof (local CA key resolves at the exact recorded path + cryptographically pairs with the
  stored root) is a STATIC predicate — every process sharing the same cert directory satisfies it
  IDENTICALLY. It is not a claim/CAS, so nothing prevented two such processes (two HA replicas
  restarting against one shared volume — a topology this fix round's own `upgrading.md` HA note
  describes what happens under, NOT one this ADR's Decision section calls officially supported; or
  a self-heal resumer racing the ORIGINAL instance, which was merely slow, not actually dead — this
  second case needs no HA topology at all, a single host is enough) from both reaching
  `complete_default_cert_set()` concurrently. Per-file writes are atomic (temp+rename) but the
  3-cert/3-key/marker SET is not atomic as a unit, so two racers could interleave a purpose's
  on-disk `.pem` from one process with its `.key` from the other — a cryptographically mismatched
  pair, invisible at boot (the idempotent fast path chain-verifies but never checks key-pairing)
  and invisible at TLS-listener startup (httplib's `SSLServer` never calls
  `SSL_CTX_check_private_key`) — a full fleet outage with no log line pointing at the cause, since
  `default-server.pem`/`.key` is both the agent-facing listener AND the server's own outbound mTLS
  client cert to the gateway. Fixed: both `complete_default_cert_set()` callers (self-heal AND the
  normal winning-the-race path, for one mutual-exclusion mechanism rather than two) now route
  through a new Postgres session advisory lock (`hashtextextended('yuzu:default_certs_bootstrap',
  0)`, non-blocking try + bounded retry, mirroring `kek_op_lock.hpp`'s reusable
  `PgSessionAdvisoryLockGuard` idiom) — and, critically, RE-VALIDATE inside the lock (re-run the
  idempotent fast-path check) before purging/re-minting, so a racer that loses the lock but finds
  its sibling already finished uses that result instead of clobbering it. Regression test
  (`test_default_certs.cpp`): two real threads racing `ensure_default_certs` against ONE shared
  `TempDir` (not two, unlike the Gate 3 fresh-root-race test) from a simulated crash-mid-completion
  state; asserts both succeed, exactly 3 issued rows survive, and every on-disk cert/key pair still
  cryptographically matches (`pki::cert_matches_key`) — the specific corruption class this finding
  identified.
  **Closure evidence caveat (advisor-flagged, verified 2026-08-21):** this test does NOT reliably
  reproduce the pre-fix corruption — run 60x against the pre-lock commit (`f4631a78a`) in a
  throwaway worktree, it passed 60/60. The vulnerable window (two threads' `fs::rename()` calls to
  the same cert/key paths landing in an interleaved, mismatched order) is real — confirmed by three
  independent code readings (security-guardian, unhappy-path, cpp-safety), none of which found a
  serialization mechanism before this fix — but too narrow for ordinary OS thread scheduling to hit
  reliably in a two-thread, same-process test. Closure for this finding rests on the by-construction
  verification of the lock's mutual exclusion (lease/guard destruction ordering, confirmed correct
  by cpp-safety against every early-return path), not on the test having been shown red; the test
  still catches a fully-broken/absent lock and is retained for that value plus its correctness
  assertions, but is not cited as red/green closure evidence on its own.
- **HIGH (fixed, unhappy-path):** the UP-1 fix's revocation-sweep tick read the full
  `list_revoked()` (returns `cert_pem` blobs, `ORDER BY revoked_at`, no row cap, and nothing prunes
  `ca_issued` — so the query gets more expensive over an install's life) while the per-request
  `is_revoked()` gate is a cheap indexed point lookup. Both share one pool, but a load/contention
  pattern specific to the heavier query is a real, nameable corridor where `list_revoked()` fails
  while `is_revoked()` keeps succeeding — new connections stay correctly gated, but the ONLY
  mechanism that tears down an already-live stream for an already-revoked agent silently does
  nothing, indefinitely, with no "the database is down" to point to: a security control quietly
  not holding, not merely an availability blip. Fixed: added `CaStore::list_revoked_serials()` —
  same WHERE clause and partial index (`idx_ca_issued_status`) as `list_revoked()`, but no
  `cert_pem`, no `ORDER BY` — and the sweep now reads that instead. `list_revoked()` is unchanged
  and still used by CRL publishing (which needs `revoked_at` per entry) and the
  `sign_agent_csr` reissue-block check (which needs `subject`/`not_after`). Left as-is deliberately
  (unhappy-path, Gate 8 narrow re-verify, 2026-08-21): the sharper reason isn't just that these two
  are lower-frequency than the ~15s sweep, it's that a degraded read on EITHER one fails CLOSED and
  LOUD — `sign_agent_csr` refuses to issue (an operator-visible enrollment failure), `publish_crl`
  aborts the publish and increments its own failures counter while consumers keep serving the last
  still-valid CRL. The sweep's ORIGINAL defect was fail-OPEN and SILENT — a control quietly not
  holding, invisible without correlating a metric — which is the specific risk class this fix
  exists to close; the residual asymmetry on the other two callers stays a bounded, observable
  availability blip, not a silent security-control gap, so fixing only the sweep is neither an
  under-fix nor an over-fix. Regression tests (`test_ca_store.cpp`): parity between
  `list_revoked_serials()` and `list_revoked()`'s serial set, and the same sabotage-the-store
  pattern used elsewhere in this file confirming a genuine failure returns `unexpected`, never a
  silently-empty "nobody is revoked" set.
- **NICE (fixed, security-guardian):** the self-heal branch's `KeyZeroGuard` was constructed only
  AFTER `cert_matches_key` succeeded, leaving the load-succeeds-but-match-fails case (a real
  operational case — a stale/mistaken local key from a botched restore) unwiped in freed heap.
  Fixed: moved immediately after `load_key()` succeeds, matching every other key-load in the file.
  Regression test added for the present-but-wrong-key path specifically (previously uncovered — the
  existing "still refuses" test never reached `load_key()` at all, since `has_key()` short-circuits
  for an absent file).

**cpp-safety domain-trigger re-review (2026-08-21).** The Gate 8 fix above introduced a new
concurrency primitive (a Postgres session advisory lock in `default_certs.cpp`) — routed-concerns
mandates cpp-safety on any C++ source change, and the prior Gate 8 pair (security-guardian +
unhappy-path) reviewed for security/availability properties, not C++ resource-ownership/lifetime
idioms specifically. **PASSES — no BLOCKING findings.** The lease/guard destruction-ordering claim
(the diff's central safety property: `PgSessionAdvisoryLockGuard`'s destructor, which runs
`pg_advisory_unlock`, must fire before the `pg::PgPool::Lease` returns the connection to the pool)
was verified correct by construction and against every early-return path. One SHOULD, fixed in the
same round: `complete_default_cert_set_locked()` holds its own pool lease for the whole critical
section while the function it calls makes its own nested per-call leases on the SAME pool — an
N-way race needs roughly `N + 1` simultaneous connections, so a tightly-sized
`--postgres-pool-size` (down to the allowed minimum of 1) self-contends. Fails CLOSED and LOUDLY
when it does (a nested-acquire timeout surfaces as an ordinary `record_issued` failure → refuse to
start), never a hang or silent corruption, so this is now a documented constraint (comment at
`kBootstrapLockAcquireTimeout`) rather than a code fix. Two NICE items also fixed: the new guard's
constructor comment now carries the same "deliberately NOT noexcept" rationale
`KekOpLockGuard`'s does (the identical, already-accepted, OOM-only leaked-lock window this diff
mirrors, not a new one); `list_revoked_serials()` now routes through the file's shared `text_col()`
helper for idiom consistency with `list_revoked()`'s identical column (the raw `PQgetvalue` it
replaced was never actually reachable — `serial_hex` is `PRIMARY KEY`/`NOT NULL` today).

**Gate 8 narrow closure re-verify (2026-08-21).** Per this repo's standing rule that only the
reporting domain (or another instance of it) can credibly sign off its own finding as fixed —
never the fix author — security-guardian and unhappy-path each independently re-read the current
code (not the diff, not the commit message) and confirmed their own original findings:

- **Finding A: CLOSED** (both reviewers, independently). Exactly two live call sites reach
  `complete_default_cert_set()` unlocked: inside `complete_default_cert_set_locked()`'s own
  critical section, and the `!ca_store` local-only fallback (which can't host the race at all — no
  shared root CAS substrate, no lock substrate, and ADR-0006/0007 refuse to boot without a reachable
  Postgres DSN, so "no ca_store" is single-instance-only). Both racing paths (self-heal resume,
  normal winning-the-race) route through the lock. Neither reviewer cited the concurrent-self-heal
  test as closure evidence, matching `b37ecf042`'s own framing — closure rests on the lease/guard
  destruction-ordering walk, independently confirmed against every early-return path.
- **Finding B: CLOSED**, and the scoping decision (fix only the ~15s sweep, leave `list_revoked()`
  unchanged for the two lower-frequency callers) is correct for a sharper reason than frequency
  alone — see the fail-open/fail-closed distinction folded into the finding's own paragraph above.
- One follow-up fixed in this round: an operator-facing log line in the self-heal resume path still
  said "this instance provably minted it" — the exact overclaim the nearby comment was already
  corrected away from (security-guardian). Reworded to describe the proof accurately (directory
  access, arbitrated under the lock) rather than repeating the retracted claim.
- The pool-size SHOULD's framing was sharpened (unhappy-path): at `--postgres-pool-size=1`
  specifically this is not "self-contends under a race" but a **deterministic** failure on every
  boot needing cert generation, zero racers required, since the outer lease alone exhausts a
  pool of size 1. Still fails closed and loud, still non-blocking — the comment at
  `kBootstrapLockAcquireTimeout` now says this precisely.

Full agent reports: this run's governance transcript (session-local, not committed).

## Governance Gate 5/6 findings (2026-08-21, pre-push)

Gate 5 (chaos-injector, triggered because Gate 4 produced findings) and Gate 6 (compliance-officer
+ sre + enterprise-readiness, mandatory) ran together against the full branch diff
(`origin/dev..HEAD`), plus a narrow closure re-verify (security-guardian + unhappy-path, confirming
Findings A/B from the prior round independently, per this repo's rule that only the reporting
domain can sign off its own finding) and an architect domain-trigger pass on the two new `CaStore`
API additions.

**HIGH (fixed, chaos-injector Gate 5, finding C5-1) — a fencing-token gap in the Gate 8 lock
itself.** The advisory lock closes "two processes both think they can proceed" but not "this
process's lock-holding CONNECTION dies mid-critical-section without the PROCESS dying"
(`pg_terminate_backend`, an `idle_session_timeout`, a network blackhole to just that one socket).
Postgres releases the session advisory lock the instant that session ends — silently, since every
write inside the critical section draws its OWN fresh per-call lease from the pool rather than
reusing the lock-holding connection, so nothing before this fix would ever notice the lock was
gone. A sibling racer's retry loop then acquires the now-free lock and starts its own
purge-and-regenerate concurrently with the first attempt's still-in-flight writes — reopening
Finding A's exact corruption class via a broader, more realistic trigger population than "two
processes racing at boot." Worse than Finding A's original defect: the idempotent fast path
(`try_use_existing_complete_set()`) chain-verified every leaf but never checked cert/key pairing,
so a corrupted pair would have validated as intact FOREVER — permanent, silent corruption, not a
self-healing crash-recovery gap. Fixed, two layers (chaos-injector's own success criteria):
(1) **prevention** — `lock_connection_alive()`, a real `SELECT 1` round-trip (not `PQstatus` alone,
stale until the next I/O; not re-issuing `pg_try_advisory_lock`, re-entrant on the same
connection — would falsely reconfirm exclusivity while silently incrementing the hold count rather
than proving liveness) on the SAME connection holding the lock, checked immediately before the
marker write; a failed check aborts without writing the marker. (2) **detection** —
`try_use_existing_complete_set()` now also verifies `pki::cert_matches_key()` for every leaf/key
pair, so a mismatched pair that lands on disk despite (1) — from ANY cause, not just this one —
self-heals on the very next boot instead of validating forever. Regression test
(`test_default_certs.cpp`): directly plants a mismatched key at a leaf's path (bypassing the need
to actually win a race) and asserts the next boot detects it and regenerates, rather than accepting
it as intact — this scenario, unlike Finding A's original race, is deterministically reproducible
without timing dependence, so red/green is legitimate closure evidence here.
- **Not separately fixed (chaos-injector C5-1's success criterion #3):** a fully deterministic
  end-to-end repro (capture the lock connection's real backend PID, `pg_terminate_backend` it
  mid-flight, assert the race then manifests) was considered and deliberately not built — it would
  need a test-only hook exposing an internal connection handle across the anonymous-namespace
  boundary, which this session judged not worth the production-code surface given the
  prevention+detection test above already exercises both fix layers directly and deterministically.
  Documented here rather than silently narrowed.
- **MEDIUM, documented not fixed (chaos-injector C5-2):** the inverse case — a lock HELD too long
  because the holder's HOST (not just the connection) dies without a clean disconnect — is an
  availability/diagnosability gap, not a corruption risk (nothing writes concurrently). Postgres's
  server-side `tcp_keepalives_*` GUCs (not this PR's `pg_pool.hpp` client-side `keepalives_idle_s`,
  which only detects a dead SERVER) govern how long a genuinely-dead session's lock stays held —
  potentially hours on defaults. Added a stuck-lock diagnosis pointer to `upgrading.md`'s HA note.

**Two-reporter closure re-verify (security-guardian + unhappy-path, independent re-reads of the
CURRENT code, not the diff):** both confirm Finding A and Finding B (prior round) CLOSED. One
follow-up each, both folded into this round: an operator-facing log line still said "provably
minted it" — the exact overclaim the adjacent comment had already been corrected away from
(security-guardian); the pool-size SHOULD's framing was sharpened from "self-contends" to
"deterministic at pool-size=1" (unhappy-path, folded into the prior round's entry above).

**compliance-officer (Gate 6): PASS**, conditional on standard pre-merge evidentiary items (a
`governance.d/` ledger fragment, an open PR, an independently-attested green CI run) rather than
any control-design gap — every control-relevant defect found this run (boot-wiring fail-open,
sweep false-audit-record, self-heal race, revoke taxonomy inversion) is verified fixed in code, not
merely claimed fixed in prose. Confirmed the branch's own two mid-review self-corrections
(the ownership-proof overclaim, the non-reproducing test) do not constitute a policy-floor
violation, since both were caught and retracted before being used as sign-off evidence, not after.

**sre (Gate 6): PASS with findings**, none blocking. Fixed in this round: the new
`yuzu_server_ca_revocation_sweep_read_failures_total` counter had no `describe()`/boot-time
pre-seed, so it was entirely ABSENT from `/metrics` (not present-at-0) until its first failure —
useless for an `absent()`-based alert (F1); the "Deliberate clean re-root" TRUNCATE runbook didn't
say to stop every server sharing the substrate first, a real hazard since `is_revoked()` reads are
live and uncached (F4); the HA note's "restart-on-unready policy" mischaracterized the actual
mechanism — a losing replica EXITS, it never reaches a running-but-unready state a readiness probe
would catch (F5). Documented as follow-ups, not fixed inline: the whole CA counter family has no
alert rules, pre-existing beyond this PR (F2); the new lock's pool-size floor isn't in the
operator-facing capacity-planning doc (F3); `ca_issued` is unpruned and will keep growing (F6).

**enterprise-readiness (Gate 6): PASS with findings**, none blocking, enterprise-pilot-ready as-is.
Two real doc/code reconciliation gaps found independently of the chaos/sre passes above, both
fixed: the self-heal mechanism is NOT scoped to first-boot — it fires on any boot with a corrupted
on-disk leaf, including an established, long-running install (a bad partial restore, a lost volume
file) — `server-admin.md`'s "refuses to start" claim was stale for this exact reason, and the
`default_certs.cpp` log line said "first-boot install" when it can now fire on either (Finding A,
fixed: `server-admin.md`, `upgrading.md`, the log line, all corrected). Separately, and sharper: a
THIRD instance of the exact overclaiming pattern this branch's review process had already caught
and corrected twice — this round's own Gate 8 finding text, alongside the code comment, asserted
`upgrading.md`'s HA note "describes [multi-replica HA] as supported," when this ADR's own Decision
section states plainly that topology is "not today" supported (Finding B, fixed: the ADR text and
code comment now say what happens under that topology without calling it endorsed).

**docs-writer: two SHOULD-fix, one structural follow-up.** Fixed: "UP-2" governance-jargon leaked
into an operator-facing log line (every sibling log line in the same function is plain-language,
this was the outlier); `server-admin.md`'s B-2 bullet needed the self-heal exception (same root
cause as enterprise-readiness's Finding A, fixed together). Follow-up, not fixed here: this ADR has
drifted from the sibling-ADR convention of folding fixes inline into `## Decision` — four stacked
governance-round sections now hold ~40% of the file's length, with the self-heal mechanism's
current truth spread across four non-contiguous locations. The forward/backward pointers are
handled correctly (no silent contradiction anywhere), so this is navigability debt, not an
accuracy gap — recommend a follow-up pass to fold each fix's final state back into `## Decision`
once this branch stabilizes, demoting the round-by-round sections to a trailing historical
appendix.

**architect: no BLOCKING findings, all SHOULD/NICE (design taste).** `CaStore::pool()` is a new
accessor pattern (no other store exposes its borrowed pool) but not a real encapsulation breach —
`PgPool` is shared cross-store infrastructure by ADR-0008 design, not something `CaStore` privately
owns; a cleaner alternative would have threaded `pg::PgPool&` through `ensure_default_certs()`'s
signature instead, since the sole caller already has it in scope directly, but the current form
costs nothing at its actual (2-call-site) scope. The proposed alternative of moving the lock
entirely inside `CaStore` (a `run_under_bootstrap_lock()` method) was explicitly rejected — it
would pull filesystem/PKI orchestration into a store whose file header scopes it to "METADATA
ONLY"; `default_certs.cpp` is the architecturally correct layer for this policy. `list_revoked_serials()`'s
one-line WHERE-clause duplication against `list_revoked()` matches this codebase's established
convention (`response_store.hpp`, `management_group_store.hpp` precedent) — not a smell. The
try-lock probe's tri-state-result shape is now a third near-identical copy across
`kek_op_lock.hpp`/`api_token_store.cpp`/`default_certs.cpp` (a legitimate rule-of-three extraction
candidate), but this migration inherited rather than introduced that duplication. Both left as
follow-up issues, not fixed in this branch.

Full agent reports: this run's governance transcript (session-local, not committed).

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
