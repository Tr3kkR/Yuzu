---
status: accepted
date: 2026-08-25
owner: platform (Postgres substrate migration program)
deciders: parallel wave batch-8 migration worker — the LAST un-started store on
  `docs/postgres-migration-ladder.md`
scope: server — `RuntimeConfigStore` (persistent runtime configuration overrides), its cutover
  from SQLite to PostgreSQL, its ADR-0009 backfill, and the ADR-0010 secrets seam for
  `oidc_client_secret` — the store's own per-KEY (not per-column) secrecy model
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend, no SQLite fallback),
  ADR-0008 (substrate architecture), ADR-0009 (per-store first-boot backfill cutover),
  ADR-0010 (secrets-at-rest envelope encryption), ADR-0012 (server Postgres store contract),
  ADR-0036 (authoritative-read type-distinguishability)
related: docs/postgres-migration-ladder.md (Wave 3 -> Done, last row); ADR-3005
  (`PluginConfigStore`, the precedent for a shared config namespace where only SOME
  entries are secret); AuthDB `mfa_totp_secret` (the precedent for a secret column most
  rows never populate)
---

# 0060 — `RuntimeConfigStore` Postgres migration (per-key secrecy, last store on the ladder)

## Context

`RuntimeConfigStore` (`server/core/src/runtime_config_store.{hpp,cpp}`, 289 lines pre-migration —
the smallest store on the ladder) persists a fixed allow-list of key/value overrides
(`allowed_keys()`) that override startup CLI/env defaults: retention windows, `log_level`,
`plugin_signing_required`, DEX alert-routing knobs, and the six `oidc_*` Settings-configurable
OIDC parameters. One key, `oidc_client_secret`, is a credential. It was stored **plaintext**
pre-migration — the redaction hardening (`config_secret_keys.{hpp,cpp}`,
`runtime_config_view.{hpp,cpp}`, `test_runtime_config_secret_redaction.cpp`) closed four
plaintext-*disclosure* paths (startup log, `GET /api/config`, the `config.update` audit detail,
the PUT response echo) but explicitly left at-rest encryption for this migration, per its own
header comment.

This is the LAST un-started store on `docs/postgres-migration-ladder.md`'s Wave 3 (secret-gated)
table — every other server store either has already migrated to Postgres or is in flight
(`WebhookStore`/ADR-0057, `InstructionStore`/ADR-0058, `OffloadTargetStore`/ADR-0059, all pending
review at the time of this ADR). When this merges, every server store is on the Postgres
substrate (NvdDatabase excluded by a recorded owner override, M1a).

**The headline problem this ADR resolves is per-KEY, not per-column, secrecy.** Unlike
`WebhookStore`/`OffloadTargetStore` (one secret column per row) or `AuthDB` (one secret column,
`mfa_totp_secret`, NULL for most rows but every row is the SAME kind of thing — a user), this
store's single `runtime_config` table holds MANY DIFFERENT keys sharing one `value` column, and
`is_secret_config_key(key)` decides — at the row level, by key — whether that value is a
credential. `SecretCodec::register_secret_column` registers a whole (schema, table, column);
its rotation/rewrap scan and `oldest_kek_version_in_use` walk EVERY row in that column with only
an `IS NOT NULL` filter (`secret_codec.cpp`) — so a single shared `value` column mixing plaintext
config and ciphertext secrets was never viable without forking the codec (`config_secret_keys.hpp`
is the correct place to extend this class of decision — never fork `SecretCodec` itself).

## Decision

### Schema: `runtime_config_store`

```sql
CREATE TABLE runtime_config (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL DEFAULT '',
    updated_by  TEXT NOT NULL DEFAULT '',
    updated_at  BIGINT NOT NULL
);

CREATE TABLE runtime_config_secrets (
    key          TEXT PRIMARY KEY,
    sealed_value BYTEA NOT NULL,
    updated_by   TEXT NOT NULL DEFAULT '',
    updated_at   BIGINT NOT NULL
);

CREATE TABLE runtime_config_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
```

### Secrets discrimination: a TABLE split, not a nullable column or a type tag

`is_secret_config_key(key)` decides which table a key's row lives in — never both, with one
deliberate transitional exception (below). This is the same shape `PluginConfigStore` (ADR-3005)
uses for its `configs`/`secrets` split, and it is the precedent this ADR follows, NOT
`AuthDB`'s nullable-`mfa_totp_secret`-in-one-table shape: `PluginConfigStore`'s namespace is
"plugin config, where the CALLER decides per-entry whether a `(plugin, key)` pair is a secret" —
structurally identical to "runtime config, where `is_secret_config_key` decides per-entry whether
a key is a secret." `AuthDB` was considered and rejected as the primary precedent because its
secret column lives on a table whose rows are all the SAME kind of thing (a user); ours are not
(a `heartbeat_timeout` row and an `oidc_client_secret` row have nothing in common except sharing
an allow-list).

Registered secret column: `{"runtime_config_store", "runtime_config_secrets", "sealed_value",
"key"}` — `key` (TEXT) is directly supported as the AAD pk_column (no `encode_bigint_pk`
translation needed, unlike AuthDB's BIGINT `id`).

**Empty-secret rule, preserved exactly.** `runtime_config_secrets.sealed_value` is `NOT NULL`
because the row's mere PRESENCE is the "has a real, non-empty secret" signal — the store never
writes an empty ciphertext there. Setting a secret key to `""` deletes any `runtime_config_secrets`
row for that key and instead upserts `runtime_config(key, value='', updated_by, updated_at)` —
the SAME plain table a non-secret key's empty value would use. This is why an explicitly-cleared
secret still reports `updated_by`/`updated_at` (pinned by
`test_runtime_config_secret_redaction.cpp`'s "an EMPTY secret survives redaction as empty" case):
the attribution lives in a real row, just not an encrypted one, because there is nothing to
encrypt. Redaction (`get()`/`get_all()`) is unaffected — `is_secret_key()` decides whether to
redact, not which table the value came from.

**Becomes-secret-later story.** A key not currently in `kSecretKeys` that gains a plaintext row
in `runtime_config`, then LATER gets added to `kSecretKeys` in some future release, is not
retroactively encrypted by this migration — it keeps its plaintext row in `runtime_config` until
the NEXT `set()` call. Reads (`get_with_secrets`/`get_all_with_secrets`) check
`runtime_config_secrets` FIRST and fall back to the plain `runtime_config` row for a key that
`is_secret_config_key` now classifies as secret but has no ciphertext row yet — so the value is
never silently lost, just not yet encrypted. `set()` is the ONLY path that materializes the
transform: writing a non-empty value for a secret key encrypts it into
`runtime_config_secrets` AND deletes any stale `runtime_config` row for the same key in the SAME
transaction, so the plaintext echo does not persist past the next write. "Next write envelopes
it" is the accepted answer, matching this ADR's own backfill precedent (below) rather than a
retroactive re-encryption pass, which no other store on the ladder implements either.

### Posture: authoritative / fail-closed (ADR-0012 §1)

Runtime config feeds auth/OIDC behaviour directly: the startup override pass
(`apply_runtime_config_overrides`) populates `cfg_.oidc_client_secret` from
`get_all_with_secrets()`, and `GET /api/config` is the route `security-hardening.md` tells an
operator to check before deciding whether to rotate a disclosed credential. A silently-empty read
on either path is a fail-open (the pre-existing, tracked CH-2/Task#10 defect this migration
closes as a side effect of adopting the ADR-0036 typed-read contract, not as separately-scoped
work). Widened to `std::expected<..., std::string>`: `get_all()`, `get_all_with_secrets()`,
`get()`, `get_with_secrets()`. `set()` already returned `std::expected<void, std::string>`
pre-migration; DB/crypto failures now carry the `kRuntimeConfigDbErrorPrefix` marker so
`server.cpp`'s PUT handler classifies 503 (genuine failure) vs. 400 (caller-input validation),
mirroring `ProductPackStore`/`TagStore`'s `*DbErrorPrefix` convention.

**`get_value()`/`get_value_with_secrets()` are deliberately NOT widened** — the playbook's
explicit deferral clause ("say so, don't leave it unstated"). Every current call site was audited:
DEX alert-routing/blast-radius/cohort-export knobs are deny-or-benign (a degraded read means "no
routes configured," not a security decision); `plugin_signing_required` feeds only a UI status
badge (`render_plugin_signing_fragment`) and an ADMIN-ONLY, manually-`curl`'d distribution
endpoint (`GET /api/v1/agent/plugin-policy`, `docs/user-manual/agent-plugins.md`: "the manual
workflow today is `curl` + `jq` + write... Automatic agent-side fetch is a forthcoming change") —
confirmed by grep that no code in `agents/` consumes that route today, and confirmed that the
REAL server-side pack-install enforcement gate (`ProductPackStore::require_signed_packs_`) is set
from the `--allow-unsigned-packs` CLI flag at boot (`server.cpp`), never from this store. If a
future caller wires either into a genuine grant/enforce/skip decision, it must switch to
`get()`/`get_with_secrets()`.

### Backfill (ADR-0009): mandatory, fingerprinted, transform-not-copy for secrets

`migrate_from_sqlite()` follows `TagStore`'s reference shape (content fingerprint + completion
marker stamped together via a monotonic-promotion upsert on `runtime_config_meta`; holder-side
fingerprint verification on a later boot that still holds its own legacy file) — `key` is
IDENTITY, `value`/`updated_by`/`updated_at` are LIFECYCLE, same as `TagStore`'s
`(agent_id, key)`/`value` split.

**Non-secret keys** use `TagStore`'s direction-aware conflict rule unchanged: identical ->
benign no-op; Postgres strictly ahead on `updated_at` -> benign no-op (warned); legacy strictly
ahead, or a tied `updated_at` with differing content -> fail closed (never silently discard the
operator's later write).

**Secret keys use a SIMPLER, different rule** — envelopes don't byte-compare against legacy
plaintext, so direction-aware comparison is not meaningful. ANY existing Postgres content for a
secret key (a `runtime_config_secrets` row, OR a non-empty `runtime_config` row — the
becomes-secret-later fallback shape) wins UNCONDITIONALLY; the legacy value is skipped as a
benign no-op, never compared, never used to overwrite. A non-empty legacy secret with no existing
Postgres content is ENCRYPTED during the copy (ADR-0009/0040 "transform, never copy a secret
column during backfill") — plaintext never lands in `runtime_config` for a key
`is_secret_config_key` classifies as secret. An empty legacy secret backfills into the plain
table (`value=''`), matching the empty-secret rule above.

**Legacy-file disposition: move-aside-after-verified-complete** (`TagStore`'s shape, the newest
precedent on the ladder) — a successful backfill moves the legacy `runtime-config.db` to
`<path>.migrated-<timestamp>` rather than leaving it in place untouched (`ProductPackStore`'s
choice). Reasoning: this store's legacy file is small, config-only, and holds no cross-replica
erasure-consistency hazard (`ProductPackStore`'s uninstall-tombstone problem does not apply —
nothing here is ever "deleted then potentially resurrected by a stale replica's legacy file"; a
`remove()`'d key simply has no row, and a stale legacy file backfilling it again would only ever
lose the direction-aware compare in the operator's favor or (for a secret) be unconditionally
ignored). Move-aside keeps the rollback window (ADR-0009: retained one release) without adding
tombstone machinery this store has no correctness need for.

### `/readyz` / `/healthz`

Already wired pre-migration (`server.cpp`'s health conjunction:
`{"runtime_config_store", runtime_config_store_ && runtime_config_store_->is_open()}`) —
unchanged by this migration; `is_open()` never flips post-construction, so this stays
belt-and-braces, matching every other migrated store on the ladder.

### `SecretCodec` instance model

Own instance (`runtime_config_secret_codec_`), constructed over the SHARED `auth_key_provider_`
(the KEK material is install-wide, ADR-0010 §2 — this is the THIRD `SecretCodec` instance backing
that one `FileKeyProvider`, after `auth_secret_codec_` and `plugin_config_secret_codec_`).
Construction sequence in `server.cpp` mirrors `PluginConfigStore`'s exactly: construct the codec
(ctor only) -> construct `RuntimeConfigStore` (registers `runtime_config_secrets.sealed_value`
immediately after its own schema migration) -> `SecretCodec::init()` on a pinned lease -> the
ADR-0009 backfill -> the boot override pass. Any failure at any step is a fatal startup error
(`startup_failed_ = true`), never a serve-degraded config plane.

## Considered and rejected

- **A nullable `value_enc BYTEA` column alongside the existing `value TEXT` column, in the SAME
  `runtime_config` table** (the initial design sketch, before `PluginConfigStore`'s already-merged
  `configs`/`secrets` table split was found). Rejected once the closer precedent was found: a
  second column still requires the same "does this row's secrecy live in column A or column B"
  branching at every read/write call site that a table split gets for free via presence, AND it
  would have been a NOVEL discrimination scheme on the ladder rather than reusing an
  already-reviewed, already-merged one.
- **Widening `get_value()`/`get_value_with_secrets()` to `std::expected`.** Rejected as
  disproportionate — no live call site feeds a security decision (verified above), and widening
  would touch ~15 call sites across `server.cpp`/`settings_routes.cpp` and two test files for no
  behavioral benefit. Recorded explicitly per the playbook's deferral clause rather than left
  unstated.
- **Retroactively re-encrypting a becomes-secret-later plaintext row at boot**, instead of
  "next write envelopes it." Rejected — no other store on the ladder does this, and a boot-time
  encrypt-on-read would mean `get_with_secrets` (a read) has a write side effect, which none of
  its callers expect and which would need its own transaction/failure-handling story for a
  scenario that (today) can never actually occur — `kSecretKeys` has exactly one entry and it
  has always been secret.
- **Never mutating the legacy SQLite file (`ProductPackStore`'s choice).** Rejected — this store
  has no erasure-consistency hazard that never-mutate exists to close, and `TagStore`'s
  move-aside-on-success is the newer, simpler default absent a specific reason to deviate.

## Consequences

- `RuntimeConfigStore`'s constructor signature changes from `(const std::filesystem::path&)` to
  `(pg::PgPool&, pg::SecretCodec&)` — every construction site (`server.cpp`,
  `test_settings_routes_oidc.cpp`, `test_settings_routes_dex_alerts.cpp`,
  `test_runtime_config_secret_redaction.cpp`) updated to the PG substrate contract.
- `get_all()`, `get_all_with_secrets()`, `get()`, `get_with_secrets()` return
  `std::expected<..., std::string>` instead of a plain container/`optional` — closes the
  pre-existing CH-2/Task#10 defect (a degraded store silently reading as "nothing configured") as
  a consequence of adopting the ADR-0036 typed-read contract this migration requires anyway, not
  as separately-scoped work.
- `PUT /api/config/:key` now returns 503 (not 400) on a genuine DB/crypto write failure,
  distinguished via the `kRuntimeConfigDbErrorPrefix` marker on `set()`'s error string; `GET
  /api/config` returns 503 on a genuine read failure from `get_all()` (previously this route
  could not distinguish a degraded read from "nothing configured" at all).
- `apply_runtime_config_overrides()` (boot) now returns `bool`; a read failure is a fatal startup
  error (`startup_failed_ = true`) rather than a silently-skipped override pass.
- No REST/API-visible change to `GET /api/config`'s success-path JSON shape, `PUT
  /api/config/:key`'s 200 response, or any Settings UI behavior — the migration is
  storage-layer-only from an operator's perspective.
- `test_runtime_config_store.cpp` is new (no general store test file existed pre-migration);
  `test_runtime_config_secret_redaction.cpp` keeps every pre-migration assertion's INTENT, adapted
  to the widened `std::expected` API and `PgTestTemplate` construction.
