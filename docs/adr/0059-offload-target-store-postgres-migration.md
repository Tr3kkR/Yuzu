# ADR-0059: OffloadTargetStore → PostgreSQL

- **Status:** Proposed
- **Date:** 2026-08-25
- **Deciders:** pg workstream, security-guardian + cpp-safety + docs-writer review (ADR-0010
  secrets seam is mandatory on this migration)
- **Parents:** ADR-0006/0007/0008 (+Correction), ADR-0009, ADR-0012 (substrate/backfill/store
  contract); ADR-0010 (secrets envelope — this is ADR-0010's third production consumer, after
  `AuthDB.users.mfa_totp_secret` and `WebhookStore.webhooks.secret`); ADR-0057
  (`WebhookStore` → PostgreSQL — **in flight, not yet merged as of this writing** — this store's
  direct twin: same targets+deliveries shape, wildcard `event_types`, an `enabled` flag, and the
  first store to work out the `has_credential`/secret-column CHECK-constraint pattern this ADR
  adopts verbatim); `docs/postgres-store-playbook.md`; `docs/postgres-migration-ladder.md`
  Wave 3.

## Context

`OffloadTargetStore` (`server/core/src/offload_target_store.{hpp,cpp}`, Phase 8.3 / #255) is the
response-offload control plane: configurable external HTTP endpoints that receive response data
in real time, with typed auth (none/bearer/basic/hmac), server-side batching, and a per-target
delivery log. It is functionally WebhookStore's twin, built to reuse its delivery pattern, and is
named directly in ADR-0010 §7 as one of the four stores gated behind the secrets seam because its
`auth_credential` column is recover-plaintext — HMAC signing needs the raw credential, so a
verify-only hash (the api_token/device_token pattern) is impossible here.

`fire_event` scans every enabled target on EVERY dispatched event (agent registration, execution
completion, DEX signals). This is a hot path the sibling stores in this wave don't share as
sharply: the SQLite-era schema carried a partial index (`WHERE enabled = 1`) specifically because
a full scan showed up in profiles at N>~50 targets (perf-S2). That index is carried across.

## Decision

### Schema

Postgres schema `offload_target_store` (ADR-0008 naming rule: `snake_case(FullClassName)`
including `Store`), two tables, table names unchanged from the SQLite era (`offload_targets`,
`offload_deliveries` — WebhookStore kept its own table names too; the table name is baked
permanently into the ADR-0010 AAD tuple, so it is chosen once and never renamed without a
decrypt-and-re-encrypt migration):

```sql
CREATE TABLE offload_targets (
    id              BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name            TEXT    NOT NULL UNIQUE,
    url             TEXT    NOT NULL,
    auth_type       TEXT    NOT NULL DEFAULT 'none',
    auth_credential BYTEA,                      -- SecretCodec envelope, or NULL
    has_credential  BOOLEAN NOT NULL DEFAULT FALSE,
    event_types     TEXT    NOT NULL DEFAULT '*',
    batch_size      INTEGER NOT NULL DEFAULT 1,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      BIGINT  NOT NULL,
    CHECK ((has_credential AND auth_credential IS NOT NULL) OR
           (NOT has_credential AND auth_credential IS NULL))
);
CREATE TABLE offload_deliveries (
    id           BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target_id    BIGINT  NOT NULL REFERENCES offload_targets(id) ON DELETE CASCADE,
    event_type   TEXT    NOT NULL,
    event_count  INTEGER NOT NULL DEFAULT 1,
    payload      TEXT    NOT NULL,
    status_code  INTEGER NOT NULL DEFAULT 0,
    delivered_at BIGINT  NOT NULL,
    error        TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX idx_offload_delivery_target_ts ON offload_deliveries(target_id, delivered_at);
CREATE INDEX idx_offload_targets_enabled ON offload_targets(enabled) WHERE enabled;
CREATE TABLE sqlite_backfill_source (fingerprint TEXT PRIMARY KEY, completed_at BIGINT NOT NULL);
```

`created_at`/`delivered_at` stay BIGINT epoch-seconds (not `TIMESTAMPTZ`) — the REST surface emits
both as integers today, and switching representations would be a wire-contract break for zero
benefit. The partial index (`WHERE enabled` — Postgres accepts a bare boolean column as the
predicate; `auth_db.cpp`'s `users_active_idx` is this codebase's existing precedent for the exact
shape) is load-bearing: it is the direct SQLite-era `WHERE enabled = 1` index carried across
verbatim, kept because `fire_event`'s query shape (`SELECT ... WHERE enabled`) is exactly what it
serves.

### Posture (ADR-0012 §1)

`offload_targets` create/list/get/get_by_name/delete are **AUTHORITATIVE/fail-hard** — this is
operator-authored integration config, also referenced by name from
`spec.offload.targets` in InstructionDefinition YAML, so a silently-empty/false/not-found answer
on a DB error would be actively wrong. This is a **posture upgrade** from the SQLite era, where
construction was unconditional and best-effort (no `startup_failed_` gate) — deliberate, matching
every other born-on-PG store.

- `create_target`/`delete_target` return a typed `std::expected<T, OffloadWriteError>`
  (`invalid_input` → 400 caller error; `store_unavailable`/`db_error` → 503, distinct in the
  audit record even though the HTTP status collapses — the #3097 classification).
- `list()` returns `std::optional<std::vector<OffloadTarget>>` — `nullopt` means the read
  degraded, never "no targets configured".
- `get()`/`get_by_name()` take an optional `bool* store_ok` out-param (`BaselineStore::
  get_baseline` precedent): `nullopt` + `store_ok=true` is a genuine not-found (a legitimate
  business answer, distinct from degradation); `nullopt` + `store_ok=false` is a degraded read.

`fire_event`'s enabled-target scan and `record_delivery`'s write are **deliberately fail-soft**:
they run off the gRPC/dispatch caller's thread or a worker-pool thread, a degraded read there
just means "this tick's events are not delivered", and there is no in-memory authoritative layer
to fall back on (ADR-0036 deny-or-benign carve-out). `fire_event`'s scan uses a short bounded
acquire (300ms) distinct from the ordinary 1.5s/2s read/write budgets, since it can run on a
gRPC handler thread. `get_deliveries` stays a plain container, empty on error — delivery history
is an audit convenience, not a decision surface.

### Secrets (ADR-0010) — adopted from WebhookStore/ADR-0057 verbatim

`auth_credential` is a SecretCodec envelope blob (`{"offload_target_store", "offload_targets",
"auth_credential", <bigint id>}`), never plaintext. `has_credential` is an INDEPENDENT boolean
column, never inferred from column emptiness (the anti-downgrade rule) — the CHECK constraint
above makes the pairing structural, not just app-level: an SQL-insider `UPDATE ... SET
auth_credential = NULL` on a `has_credential=true` row is refused by Postgres itself, verified in
`test_offload_target_store.cpp`'s CHECK-violation tests (both directions).

- **Empty credential is a real, first-class state.** An empty `auth_credential` argument at
  `create_target` means `has_credential=false`, bound as SQL NULL — never an envelope of an empty
  string. An unsigned/unauthenticated target is a supported configuration (matches every
  `auth_type`, including `bearer`/`basic`/`hmac` with no credential set — dispatch simply omits
  the auth header/signature), never conflated with "credential configured but unreadable".
- **Serial-PK allocate-before-encrypt** (ADR-0010 Amendment): `create_target` reserves the row id
  via `nextval(pg_get_serial_sequence(...))` on its own short lease (released before encrypting),
  encrypts with that id as the AAD row-PK, then `INSERT ... OVERRIDING SYSTEM VALUE` on a fresh
  lease — never INSERT-then-UPDATE.
- **Decrypt-on-use, per-delivery, never batch-cached.** `deliver_single` decrypts
  `auth_credential` immediately before building the auth header/HMAC signature and lets the
  `SecureBuffer` fall out of scope right after, on every exit path including an exception. ADR-0010
  §Consequences permits caching the decrypted credential for a whole delivery batch; this
  migration declines that option, matching WebhookStore/ADR-0057's stricter choice.
- **Fail-closed on decrypt failure — never fire unsigned, never fire with an empty credential.**
  A target whose `has_credential=true` row fails to decrypt is skipped ENTIRELY: no HTTP call is
  made, `record_delivery` logs `status_code=0, error="credential_unavailable"`, and the metric
  `yuzu_server_offload_delivery_credential_unavailable_total` increments.
- **`hmac_sha256`/`base64_encode` take `std::string_view`, never `std::string`**, for the
  credential parameter — passing a decrypted `SecureBuffer` through a `const std::string&` would
  make an unzeroized copy. Building the final `Authorization` header VALUE still needs an
  ordinary `std::string` (httplib's `Headers` type) — that string is not separately zeroized, the
  same accepted tradeoff every existing secret-bearing HTTP call site in this codebase makes.
- **Instance model — own `SecretCodec`, shared `KeyProvider`.** `server.cpp` constructs a
  dedicated `offload_secret_codec_`, reusing `auth_key_provider_` (the same `FileKeyProvider`
  `auth_secret_codec_`/`plugin_config_secret_codec_` already share — one KEK per database is
  install-wide custody, not a per-store resource). Construction order mirrors `AuthDB`'s/
  `PluginConfigStore`'s block exactly: codec ctor → `OffloadTargetStore` ctor (registers
  `{"offload_target_store","offload_targets","auth_credential","id"}`) → `is_open()` gate →
  `SecretCodec::init()` on a pinned lease → `migrate_from_sqlite`.
- **KEK-rotation enrollment.** `offload_secret_codec_` is added to `kek_enrolled_codecs()`
  (server.cpp) so an operator's `/rotate`/`/rewrap` request re-wraps `auth_credential` too — not
  left as an open item the way ADR-3005 (PluginConfigStore) recorded for its own codec. The
  per-store `yuzu_server_secret_decrypt_failures_total` fan-in (server.cpp, ~ADR-0010 §Decision 3)
  is generalized in this same change from a single hardcoded `auth_secret_codec_` read to a loop
  over every `kek_enrolled_codecs()` instance — closing an identical pre-existing gap on
  `plugin_config_secret_codec_`'s decrypt failures as a side effect, via the same chokepoint the
  rotate/rewrap/status surfaces already share.
- **Teardown ordering.** `OffloadTargetStore` dispatches deliveries on a bounded worker pool that
  can still be decrypting a credential through `offload_secret_codec_` (and, transitively,
  `auth_key_provider_`) right up until `quiesce()` proves it drained — which happens well after
  the gRPC drain, ~200 lines past where `auth_key_provider_.reset()` used to run unconditionally
  in `stop()`. Resetting the shared provider before that quiesce would be a UAF against a live
  delivery's `KeyProvider::unwrap_dek` call. `stop()`'s `auth_key_provider_.reset()` call is moved
  to run immediately after `offload_target_store_.reset()` (which itself runs after the
  `quiesce(60s)` bound both webhook and offload deliveries already share) — the same class of bug
  WebhookStore/ADR-0057 independently found and fixed for its own (not-yet-migrated-on-this-branch,
  at the time of writing) secret codec.

### Backfill (ADR-0009) — mandatory, fingerprint-verified, both tables

Both `offload_targets` and `offload_deliveries` are MANDATORY backfill — unlike `ResponseStore`,
there is no TTL/prune on `offload_deliveries`, so the ADR-0009 skippable-telemetry exception does
not apply (the same ruling ADR-0057 records for webhook deliveries).

- **Idempotency model: a per-legacy-CONTENT fingerprint set** (`sqlite_backfill_source`), not a
  single marker row — SHA-256 over a canonical, length-prefixed serialization of every target and
  delivery field, run BEFORE the write transaction so an already-migrated legacy file is a cheap
  no-op read.
- **Fingerprint excludes the plaintext credential bytes** — a deliberate, security-motivated
  choice (ADR-0057's identical ruling): hashing a low-entropy legacy credential into an at-rest
  fingerprint would let a SQL-insider brute-force it offline against the stored hash. Only a
  has-credential bit is folded in.
- **Secrets transform, never copy.** Every legacy plaintext credential is encrypted BEFORE the
  write transaction opens, in one pass over all legacy targets; a single encrypt failure aborts
  the WHOLE backfill closed (never a partial write, never plaintext at rest). The transient
  plaintext is cleansed (`OPENSSL_cleanse`) immediately after, via an RAII wiper that fires on
  every exit path.
- **Conflict handling, IDENTITY vs the credential.** IDENTITY = `(name, url, auth_type,
  event_types, batch_size, enabled, created_at)`. On a same-id conflict (a prior partial/
  interrupted backfill, or a legacy id that happens to collide with a row created live before
  this backfill ever ran): an identity mismatch fails the backfill closed, naming the row; an
  identity match is a benign skip, and **`auth_credential`/`has_credential` are never compared or
  rewritten** on conflict — whatever Postgres already holds wins, unconditionally (the
  "rotated-secret PG-wins" rule, covered by a dedicated test that live-creates a target, then
  backfills a same-id legacy row with different credential state, and asserts the live value
  survives untouched).
- **Orphaned delivery rows fail closed.** A legacy delivery whose `target_id` matches no target
  (neither freshly inserted nor pre-existing) hits the `offload_deliveries` FK constraint
  (SQLSTATE 23503), which this migration classifies distinctly in its log line and fails the
  whole backfill — never silently dropped.
- **Sequence fixup — the `OVERRIDING SYSTEM VALUE` gap.** Both tables' identity sequences do NOT
  auto-advance when rows are inserted with explicit (legacy) ids. Without a `setval(...,
  MAX(id))` at the end of a non-empty backfill, the first post-backfill `create_target()`/
  delivery-log write would collide on the PRIMARY KEY. `create_target`'s own conflict handler
  additionally distinguishes a PK collision (`PG_DIAG_CONSTRAINT_NAME = 'offload_targets_pkey'`)
  from a genuine duplicate-name collision, so a sequence bug can never masquerade as operator
  error even if the fixup were ever missed.
- **Legacy file disposition:** 0600 forced on the file AND `-wal`/`-shm` sidecars (POSIX-only;
  Windows has no compensating ACL step here — the same carve-out WebhookStore/ADR-0057 records,
  tracked on issue #3593); moved aside on a verified success, never deleted, sidecars carried
  across; next-release deletion tracked on the ladder, same as every Wave-3 sibling.

### Public API modernization

`create_target`/`list`/`get`/`get_by_name`/`delete_target` all change return shape from the
SQLite-era bare `int64_t`/`std::vector`/`std::optional`/`bool` to the typed forms above —
matching `DeviceTokenStore`'s (ADR-0052) identical precedent for exactly the same reason: a bare
sentinel return type cannot distinguish "degraded" from "business fact", which is a fail-open-
shaped gap on a store whose reads gate REST 404-vs-503 classification and whose writes gate
credential-bearing config changes. `get_deliveries`/`fire_event`/`flush_all`/`quiesce`/
`set_metrics`/`is_open` keep their pre-migration shape (no caller-visible reason to change them).

## Considered and rejected

- **Sharing `webhook_secret_codec_`'s eventual `SecretCodec` instance.** Rejected — ADR-0010's
  "Instance model" is explicit that each secret-bearing store gets its own codec instance;
  sharing the underlying `FileKeyProvider` (not the codec) is the correct and sufficient reuse.
- **Renaming `offload_targets`/`offload_deliveries` to shorter unqualified names** (the way
  `PluginConfigStore` uses bare `configs`/`secrets`/`kill_switches` inside its own schema).
  Rejected for a migrating (not greenfield) store: the table name is permanently baked into the
  ADR-0010 AAD tuple, and there is no reader-facing benefit to renaming a table whose schema
  already provides the namespace.
- **Copying WebhookStore's decision not to carry a partial index.** Rejected — webhook's `enabled`
  filter was never backed by an index even in its SQLite original; offload's SQLite original
  explicitly added one (perf-S2) because its dispatch volume showed up in profiles. Each store's
  own precedent governs; this is not a case of the twins diverging by oversight.

## Consequences

- **Backup/restore pairing invariant applies** (ADR-0010 §Consequences): a `pg_dump` of this
  schema alone recovers no target credentials; the keys directory must be restored alongside it.
  Losing the KEK orphans every configured offload credential — re-issuable, at operator pain
  (every affected target's credential must be re-entered).
- **Operational cost.** One more AES-GCM encrypt/decrypt per delivery for credential-bearing
  targets (negligible at this store's volumes — batched/immediate HTTP POST already dominates the
  per-delivery cost); one more codec instance enrolled in the KEK rotation/rewrap surface.
- **`security-guardian` + `cpp-safety` + `docs-writer` review is structural** for this PR (the
  CLAUDE.md routed-concern row for the ADR-0010 seam).

## Follow-ups

- Windows legacy-file ACL hardening (the 0600-equivalent step) is out of scope here, same as
  webhook's — tracked on #3593, not duplicated.
- `docs/user-manual/rest-api.md`'s offload-targets section needs the `has_credential` field
  documented in the response shape (docs-writer, Gate 2).
