---
status: accepted
date: 2026-06-10
owner: Nathan Dornbrook (platform)
deciders: Nathan Dornbrook; HITL session 2026-06-10 (#1319)
scope: platform — secret material at rest in the server's Postgres substrate
builds-on: ADR-0006 (PostgreSQL substrate); ADR-0008 (substrate architecture); ADR-0009 (backfill cutover)
---

# 0010 — Secrets at rest: app-side envelope encryption behind the KeyProvider seam

## Context

ADR-0004/0006/0009 all carry the same load-bearing carve-out: "server-side durable state in
Postgres" is **not** "secrets in a plain Postgres column." The api-token and CA store
migrations were deferred behind this ADR.

Inventorying what the server actually persists reshapes the problem. The stores the carve-out
named turn out to be the clean ones: `api_tokens.db` holds only SHA-256 token hashes
(verify-only), and `ca.db` holds cert metadata plus an opaque `key_ref` — the CA root private
key already lives **outside** the database behind the `KeyProvider` seam
(`server/core/src/key_provider.hpp`: `FileKeyProvider` 0600 PEM in a 0700 dir today, a future
`Pkcs11KeyProvider`/`HsmKeyProvider` with zero caller change). The recover-plaintext secret
columns are elsewhere:

| Secret | Store / column | Today |
|---|---|---|
| Session tokens | `auth.db` `sessions.session_token` | plaintext, TTL-cleaned |
| MFA TOTP secrets | `auth.db` `users.mfa_totp_secret` | plaintext BLOB (v3 encryption deferred) |
| Webhook signing secrets | `webhooks.db` `webhooks.secret` | plaintext (omitted from `list()`) |
| Offload-target credentials | `offload_targets.db` `auth_credential` | plaintext |
| OIDC client secret | `runtime_config.db` (`oidc_client_secret` key) | plaintext |

Verify-only material — operator password PBKDF2 hashes, API/device/enrollment token SHA-256
hashes, MFA recovery-code hashes, license-key hashes — is not secret-recoverable and is fine
in plain columns on any substrate.

The threat model this ADR must answer: (a) **db-dump exposure** — a stolen `pg_dump`, a
mis-secured backup, or a snapshot of the Postgres volume; (b) **insider with SQL access** — an
operator or attacker who can run queries but does not own the server host; (c) what lands in
routine backups.

**Residual risk (explicit non-goals).** This design does **not** defend against: compromise
of the server host itself — an attacker who can read the 0600 KEK file recovers everything
(the answer to that is the PKCS#11/KMS provider swap, not this ADR); plaintext secrets in
live process memory (mitigated only by zeroization discipline); and note that the
SQL-insider coverage rests on the assumption that SQL access does not imply read access to
the server's keys directory — true for a separate or managed Postgres and for SQL-only
access on colocated deploys, but it is an assumption, stated here so reviewers don't infer
coverage the design doesn't have.

## Decision

**Secret columns in Postgres are envelope-encrypted app-side. The KEK lives behind the
existing `KeyProvider` seam and never enters Postgres.**

1. **Mechanism.** AES-256-GCM via the OpenSSL the server already links. Each secret value is
   encrypted with a fresh data-encryption key (DEK); the DEK is wrapped by the install's
   key-encryption key (KEK). One opaque column holds a versioned blob:

   ```
   ver || kek_version || wrap_nonce || wrapped_dek || wrap_tag || data_nonce || data_tag || ciphertext
   ```

   Normative rules (the implementation PR's security review checks conformance to these,
   it does not re-derive them):
   - **AAD binding (anti-swap):** both the payload encryption and the DEK wrap use AES-GCM
     AAD = `(ver, store namespace, table, column, row primary key, kek_version)`. Encrypted
     values are therefore **non-relocatable** — an insider with SQL *write* access cannot
     swap blobs between rows/columns and have the server decrypt one secret in another's
     context (e.g. recovering an offload credential through the webhook-HMAC path).
   - **Wrap algorithm:** AES-256-GCM with its own independent random nonce (`wrap_nonce`);
     one primitive throughout rather than a separate AES-KW dependency.
   - **Nonces and DEK single-use:** 96-bit nonces, fresh per encryption; a DEK encrypts
     exactly one value exactly once — updating a secret mints a fresh DEK (never DEK reuse
     under a new nonce). KEK rotation re-wraps only; it never touches `data_nonce`/payload.
   - **Decrypt-failure semantics:** a GCM tag failure is the tamper signal — fail closed
     (refuse the operation), emit an audit event + metric, and **never** degrade to an
     empty secret. This is load-bearing: `webhooks.secret` and
     `offload_targets.auth_credential` both have existing "empty means no auth" code paths
     (`webhook_store.cpp`, `offload_target_store.cpp`), so an empty-on-failure idiom would
     silently disable signing/auth.
   - **Zeroization:** `SecretCodec` `secure_zero`s DEKs and decrypted plaintext buffers
     once consumed (mirrors the `KeyProvider::load_key` caller contract).

   Decryption happens in the store class, never in SQL.
2. **Key custody.** The KEK is 32 bytes from `RAND_bytes`, generated on first boot (same
   bootstrap pattern as the default certs), stored base64-encoded through
   `KeyProvider::store_key` (`key_id = "secrets-kek-v<N>"`) — exactly like the CA root key:
   `FileKeyProvider` 0600/0700 today; PKCS#11/KMS/HSM later by swapping the provider, with
   `key_ref` opaque to all callers. The KEK is never written to Postgres, never logged,
   never exported by any API. If encrypted values exist but the KEK ref does not resolve,
   the server **fails closed** at boot (`startup_failed()`), matching ADR-0007's posture —
   a loudly-down server over one silently serving with unreadable secrets.
3. **Key hierarchy & rotation.** KEK rotation mints `secrets-kek-v<N+1>` and re-wraps DEKs
   (cheap: re-encrypt the small wrapped-DEK blob, not the payload). The blob's
   `kek_version` field makes rotation incremental and interruptible. DEK-per-secret means
   a single leaked DEK exposes one value, not a class.
4. **The substrate rule** (replaces the store-name carve-out): **no plaintext
   recover-plaintext secret may land in a Postgres column.** Secret columns are either
   (a) verify-only hashes, or (b) envelope-encrypted blobs as above. Every store migration
   that touches a secret column gets `security-guardian` review.
5. **Session tokens stop being secrets at rest.** They are bearer values looked up by
   presented value (verified: every access path in `auth_db.cpp` keys by presented token or
   by username; the REST surface revokes by username/self and never lists stored values), so
   they convert to SHA-256 hashed (verify-only) storage during the `auth.db` migration — the
   same pattern as API/device/enrollment tokens — rather than being encrypted. One less
   recover-plaintext class. Preconditions recorded: unsalted SHA-256 is sound here *only*
   because session tokens are 256-bit server-generated random values (it would not be for
   low-entropy material), and any future "list active sessions" UX must use display IDs
   (precedent: `api_token_store.cpp` `hash.substr(0,24)`), never recovered tokens.
   Sequencing note: AuthDB session rows are currently dead-writes (the in-memory
   `AuthManager::sessions_` map is the authoritative read path), so the hash conversion
   should ride with the session-persistence work rather than migrating the column twice.
6. **Key material stays out of the database entirely.** The CA root key, default-cert and TLS
   private keys remain behind `KeyProvider` as today. This ADR does not move them and no
   future store migration may.
7. **Scope ruling for the deferred stores.** Because `api_token` (hash-only) and `ca`
   (key_ref-only) contain no plaintext secret columns, their Postgres migrations are
   **unblocked** onto the normal ladder (per-store ADR + `security-guardian` review as
   already mandated). The stores this ADR actually gates are the ones with recover-plaintext
   columns: `auth` (TOTP secrets; sessions convert to hashes), `webhooks`, `offload_targets`,
   and `runtime_config` (OIDC client secret).

## Considered and rejected

- **`pgcrypto` (db-side encryption).** Rejected. Keys must be supplied to SQL, so they
  transit statement text — visible to `pg_stat_activity`, statement logging, slow-query
  logs, and any insider with SQL access, which is precisely the adversary in the threat
  model. It also ties crypto policy to the database engine and puts key handling on the
  wrong side of the connection.
- **Keeping all secrets out of Postgres in a dedicated encrypted home (extended
  KeyProvider-style vault).** Rejected as the *general* mechanism. It is the right shape for
  single-row trust anchors (CA root, TLS keys — where it remains the rule), but for
  row-per-entity secrets (a TOTP secret per operator, a signing secret per webhook) it
  creates a second durable store that must be operated, backed up, and kept transactionally
  consistent with the row data it shadows — reintroducing the multi-store coordination
  problem the Postgres consolidation exists to remove.
- **Transparent disk/volume encryption only (LUKS/FDE/cloud-volume).** Not a substitute: it
  protects against stolen disks, not against `pg_dump` exfiltration or SQL-level access, and
  is invisible to backups taken through the database.
- **Encrypting verify-only hashes too.** Rejected as scope creep; hashes are already
  non-recoverable, and uniform encryption would complicate lookup-by-hash indexes for no
  threat-model gain.

## Consequences

- **Backups.** `pg_dump` and volume snapshots contain ciphertext and wrapped DEKs only — a
  database backup alone recovers no secrets. The KEK file (or future KMS handle) must be
  backed up **separately and offline**, exactly like the CA root key (same SRE note as
  `key_provider.hpp`): losing the KEK orphans TOTP enrollments, webhook secrets,
  offload-target credentials, and the OIDC client secret. All are re-enrollable/re-issuable,
  but at operator pain; the restore-verification drill must cover the KEK alongside the CA
  root.
- **The pg substrate (#1320) grows a `SecretCodec` helper** (`server/core/src/pg/`):
  encrypt/wrap/unwrap/decrypt + KEK-version bookkeeping, used by every store that owns a
  secret column. It takes a `KeyProvider&`; tests use a temp-dir `FileKeyProvider`.
- **Migration backfills that touch secret columns transform, not copy** (ADR-0009 note):
  plaintext SQLite values are encrypted (or hashed, for sessions) on the way in. The legacy
  read-only `.db` retained for one release still contains plaintext — do **not** scrub it
  (that breaks ADR-0009's rollback net), but the window is hardened, not merely documented:
  (a) the cutover verifies/forces 0600 on retained secret-bearing legacy files; (b) an
  operator purge flag allows early deletion once rollback confidence exists; (c) the
  per-store ADR instructs operators to treat window-era data-dir backups as secret-bearing
  and to rotate webhook/offload/OIDC secrets after the window if backup posture is unknown
  (all are re-issuable); (d) the next-release deletion is implemented and upgrade-tested,
  not left aspirational.
- **Operational cost.** One more trust-anchor file in the certs/keys directory; KEK rotation
  is an operator procedure (incremental re-wrap) to document in the user manual; per-value
  AES-GCM cost is negligible at our volumes.
- **`security-guardian` review is structural:** any PR adding or migrating a secret column
  cites this ADR and carries that review (the routed-concern row in CLAUDE.md).

## Review record

`security-guardian` design review, 2026-06-10 (#1319): **APPROVE-WITH-CHANGES**, all changes
folded into this text. Verified against code: the session-token access patterns (§Decision 5),
the api_token/ca clean-store claims (§Decision 7), and inventory completeness (independent
sweep of all 38 schema-bearing server stores found exactly the five columns above, no others —
Entra directory-sync client secrets are request-scoped and never persisted). Findings folded:
AAD anti-swap binding, wrap-algorithm/nonce/DEK-single-use rules, versioned blob format,
decrypt-failure semantics, zeroization, KEK provisioning + fail-closed boot (S-1…S-7);
residual-risk statement (T-1); session preconditions + sequencing (T-2/T-3); hardened
one-release retention window (R-1). Code note fixed alongside: `runtime_config_store` falsely
commented `oidc_client_secret` as "encrypted at rest" (I-1).
