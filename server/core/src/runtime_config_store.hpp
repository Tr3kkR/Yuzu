#pragma once

/// @file runtime_config_store.hpp
/// Migrated Postgres store (ADR-0006/0009/0060, schema `runtime_config_store`).
/// Persistent runtime configuration overrides — key/value pairs that override
/// startup defaults (CLI/env). Only a fixed allow-list of keys is accepted
/// (`allowed_keys()`); one of them (`oidc_client_secret`) is a credential.
///
/// **Posture: AUTHORITATIVE / fail-closed (ADR-0012 §1).** Runtime config
/// feeds auth/OIDC behaviour (the startup override pass populates
/// `cfg_.oidc_client_secret`) and DEX alerting config — a silently-empty
/// read on a degraded store is a fail-open, not a benign "nothing
/// configured". `get_all()`/`get_all_with_secrets()`/`get()`/
/// `get_with_secrets()` return `std::expected<..., std::string>`
/// (ADR-0036 typed-read policy) so a genuine DB error is never collapsed
/// into "no overrides set". `get_value()`/`get_value_with_secrets()` stay
/// plain `std::string` convenience wrappers — deliberately NOT widened.
/// Every current call site was audited (kickoff review, 2026-08-25): DEX
/// alert-routing knobs are deny-or-benign (a degraded read just means no
/// routes/defaults, not a security decision); `plugin_signing_required`
/// feeds only a UI status badge and an admin-only manual-fetch distribution
/// endpoint (`GET /api/v1/agent/plugin-policy` — server-side pack-install
/// enforcement is gated by `ProductPackStore::require_signed_packs_`, set
/// from the CLI flag at boot, never from this store; confirmed no agent
/// code consumes that route today, `agents/` grep). If a future caller
/// wires either into a real grant/enforce/skip decision, it MUST switch to
/// `get()`/`get_with_secrets()` and treat `unexpected` as fail-closed —
/// this deferral is explicit, per the playbook's "say so" escape hatch, not
/// an oversight.
///
/// Substrate contract (ADR-0008): the store holds a `pg::PgPool&` (not a
/// `sqlite3*`), runs its schema migration at construction on a pinned,
/// unbounded, construction-only lease, and schema-qualifies every runtime
/// statement (`runtime_config_store.*`) — pooled connections carry no
/// per-store `search_path`. Mutate-and-return uses `RETURNING` (the
/// #1033-banning idiom), never `sqlite3_changes()`.
///
/// **Secrets (ADR-0010): per-KEY, not per-column — `is_secret_config_key()`
/// decides.** Storage discrimination is a TABLE split, not a nullable
/// column: a secret key's non-empty value lives ONLY in
/// `runtime_config_secrets.sealed_value` (SecretCodec envelope, one row per
/// secret key, `key` as the AAD pk_column — mirrors `PluginConfigStore`'s
/// `configs`/`secrets` split, ADR-3005, the closest existing precedent for
/// "some keys in this namespace are secret, most aren't"); every other
/// value — including an EMPTY secret — lives in the plain `runtime_config`
/// table. Reading a secret key checks `runtime_config_secrets` first and
/// falls back to `runtime_config` only for legacy/transitional plaintext
/// (see `set()`'s doc comment for the becomes-secret-later story); this
/// means presence in `runtime_config_secrets` is a HARD invariant that the
/// row is never empty, so `set()` never encrypts an empty string — it
/// deletes any stale ciphertext row instead and stores `value=''` in the
/// plain table (same table an empty NON-secret value would use), which is
/// what lets an empty secret keep its `updated_by`/`updated_at`
/// attribution (see the redaction test) without ever holding a live DEK
/// over zero bytes. Own `SecretCodec` instance (ADR-0010 per-store model,
/// AuthDB/PluginConfigStore precedent): the caller constructs one over the
/// shared `FileKeyProvider` and passes it in; this store's constructor
/// registers `runtime_config_secrets.sealed_value` immediately after its
/// own schema migration, and the caller runs `SecretCodec::init()` on a
/// pinned lease right after construction returns (register-before-init).
///
/// **Backfill (ADR-0009): mandatory, one-time, idempotent, fail-closed.**
/// Operator-set runtime config is irreducible intent. `migrate_from_sqlite()`
/// follows the `TagStore`/`RbacStore` post-#2703 reference shape (content
/// fingerprint stamped with the completion marker in the SAME transaction
/// via a monotonic-promotion upsert; holder-side verification on later
/// boots) with ONE addition: secret-key rows never plain-copy (ADR-0009 /
/// ADR-0040 "transform, never copy a secret column during backfill") — a
/// non-empty legacy `oidc_client_secret` is ENCRYPTED during the copy,
/// landing in `runtime_config_secrets`, never in the plaintext table. Row
/// conflicts are DIRECTION-AWARE for non-secret keys (`TagStore`'s
/// updated_at comparison: a Postgres row strictly ahead, or identical, is a
/// benign no-op; a legacy row strictly ahead, or a tied `updated_at` with
/// differing content, fails the backfill closed). Secret keys use a
/// SIMPLER rule per the kickoff review: an envelope blob does not
/// byte-compare against legacy plaintext, so ANY existing Postgres content
/// for a secret key (`runtime_config_secrets` row present, OR a non-empty
/// `runtime_config` row) wins unconditionally — the legacy value is
/// skipped as a benign no-op, never compared or overwritten.

#include "config_secret_keys.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
class SecretCodec;
}

namespace yuzu::server {

struct RuntimeConfigEntry {
    std::string key;
    std::string value;
    std::string updated_by;
    int64_t updated_at{0};
};

/// Machine-checkable prefix on every `RuntimeConfigStore` `unexpected()` that
/// represents a genuine DB/lease/crypto failure rather than caller-input
/// validation (unknown key, bad value shape, the redaction-placeholder
/// guard). Callers classify: this prefix -> 503, else -> 400 (mirrors
/// `TagStore::kTagDbErrorPrefix` / `ProductPackStore::kProductPackDbErrorPrefix`).
inline constexpr const char* kRuntimeConfigDbErrorPrefix = "db_error: ";

class RuntimeConfigStore {
public:
    /// Borrows the shared pool and the CALLER'S OWN `SecretCodec` instance
    /// (ADR-0010 per-store model — see the file header). Runs the
    /// `runtime_config_store` schema migration on a pinned, unbounded,
    /// construction-only lease, then registers
    /// `runtime_config_secrets.sealed_value` as a secret column. `is_open()`
    /// is false if the lease was empty, the migration failed, or column
    /// registration failed.
    RuntimeConfigStore(pg::PgPool& pool, pg::SecretCodec& secret_codec);

    RuntimeConfigStore(const RuntimeConfigStore&) = delete;
    RuntimeConfigStore& operator=(const RuntimeConfigStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for the backfill-result counter
    /// (`yuzu_server_runtime_config_backfill_total{result}`) and the read
    /// accessors' degrade counter (`yuzu_server_runtime_config_read_degrade_total{reason}`,
    /// matching ProductPackStore/CustomPropertiesStore's #1675 convention).
    /// Set ONCE during single-threaded startup — BEFORE `migrate_from_sqlite()`
    /// (#3261/#3294 wiring-order class), so the backfill counter is live on
    /// the one pass that matters. A null registry (the default, e.g. in unit
    /// tests) disables emission.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// THE THREE PLAIN READ ACCESSORS REDACT; plaintext requires a
    /// `_with_secrets` name. Naming it at the call site is the point: an
    /// emitter that does not think about secrets gets the safe behaviour.
    ///
    /// A secret's value is replaced by `redacted_placeholder()`. An EMPTY
    /// secret is left empty: there is nothing to protect, and the
    /// emptiness is the only set-vs-unset signal a caller has
    /// (`GET /api/config` derives `is_set` from it).
    ///
    /// `unexpected(msg)` (prefixed `kRuntimeConfigDbErrorPrefix`) is a
    /// genuine read failure (lease timeout, query error, or a
    /// `runtime_config_secrets` row that fails to decrypt) — NEVER treat it
    /// as "nothing configured". A caller feeding a grant/enforce/skip
    /// decision from this store must fail closed on it (ADR-0036); the two
    /// production callers today (the boot override pass, `GET
    /// /api/config`) both do.

    /// All entries, secrets redacted.
    [[nodiscard]] std::expected<std::vector<RuntimeConfigEntry>, std::string> get_all() const;

    /// All entries with real values. ONE legitimate caller today: the
    /// startup override pass, which must apply the real secret. Anything
    /// that EMITS -- a log, an API response, an audit detail, a dashboard
    /// fragment -- must not use this.
    ///
    /// Runs the plain-table and secrets-table SELECTs as two separate
    /// statements on one lease, not one transaction: a concurrent `set()`
    /// moving a key between tables (the becomes-secret / empty-secret
    /// transitions) can make that key transiently ABSENT from this merge if
    /// it lands between the two reads (already deleted from one table, not
    /// yet visible in the other's post-commit read). Accepted -- an admin
    /// config read racing an admin config write, not a security boundary --
    /// matching `ProductPackStore`'s recorded-not-fixed uninstall race.
    [[nodiscard]] std::expected<std::vector<RuntimeConfigEntry>, std::string>
    get_all_with_secrets() const;

    /// A single config entry, secret redacted. `nullopt` = read fine,
    /// genuinely no override set for this key (use the default).
    [[nodiscard]] std::expected<std::optional<RuntimeConfigEntry>, std::string>
    get(const std::string& key) const;

    /// A single entry with its real value. Same rule as
    /// `get_all_with_secrets()`.
    [[nodiscard]] std::expected<std::optional<RuntimeConfigEntry>, std::string>
    get_with_secrets(const std::string& key) const;

    /// Convenience string getter, secret redacted. NOT typed: a DB error
    /// collapses to "", the same as "key not set" -- see the file header
    /// for why every current call site accepts that (deny-or-benign;
    /// none feeds a live grant/enforce/skip decision). Prefer `get()` for
    /// anything that does.
    [[nodiscard]] std::string get_value(const std::string& key) const;

    /// Convenience string getter, real value. Same non-typed caveat as
    /// `get_value()`, plus the `get_with_secrets()` scoping rule: use only
    /// where the credential itself is required.
    [[nodiscard]] std::string get_value_with_secrets(const std::string& key) const;

    /// Set a config value. Returns an error if the key is not in the
    /// allow-list, if validation fails, or if the value is the redaction
    /// placeholder for a secret key. `unexpected(msg)` prefixed
    /// `kRuntimeConfigDbErrorPrefix` is a genuine DB/crypto failure (503 at
    /// the REST seam); anything else is caller-input validation (400).
    ///
    /// For a secret key, this is also the ONLY path that materializes the
    /// becomes-secret-later transform: a non-empty value is encrypted and
    /// written to `runtime_config_secrets`, and any stale plaintext row for
    /// the same key in `runtime_config` (left over from before the key was
    /// classified secret, or from a legacy SQLite backfill row not yet
    /// re-written) is deleted in the SAME transaction. An empty value does
    /// the reverse: any `runtime_config_secrets` row is deleted, and
    /// `runtime_config` gets `value=''` (so `updated_by`/`updated_at`
    /// survive an explicit clear).
    ///
    /// [[nodiscard]] deliberately: discarding this used to be harmless
    /// because the only failure was an unknown key, which no in-tree caller
    /// could produce. The placeholder guard made it reachable, and a caller
    /// that ignored it reported "saved" for a write the store refused --
    /// with the live in-memory config already updated, so the two diverged
    /// and a restart silently healed it.
    [[nodiscard]] std::expected<void, std::string> set(const std::string& key,
                                                        const std::string& value,
                                                        const std::string& updated_by);

    /// Delete a config override (revert to default). Removes any row for
    /// `key` from BOTH `runtime_config` and `runtime_config_secrets` --
    /// exactly one is ever populated under normal operation, but a
    /// transitional becomes-secret-later state can have a stale row in
    /// each. Returns true if either delete removed a row.
    bool remove(const std::string& key);

    /// Legacy-SQLite backfill (ADR-0009). Call once at server startup,
    /// before serving, after construction has proven the Postgres schema is
    /// open. Idempotent (content-fingerprinted, `TagStore`'s reference
    /// shape). Fails CLOSED on any error. Returns true (no-op) when
    /// `legacy_db_path` does not exist or holds no `runtime_config` table
    /// (fresh install). See the file header for the secret-key transform
    /// and direction-aware conflict rules.
    [[nodiscard]] bool migrate_from_sqlite(const std::filesystem::path& legacy_db_path);

    /// Check if a key is in the allow-list of safe runtime-configurable keys.
    static bool is_allowed_key(const std::string& key);

    /// True if this key's VALUE is a credential and must never be emitted in
    /// plaintext - not to a log, not to an API response, not to an audit detail, not
    /// to a config dump. Prefer get_all(), which applies this for you; consult the
    /// predicate directly only where the value does not come from the store (the
    /// PUT handler audits a caller-supplied value, which is the path that leaked
    /// past the first version of this fix).
    static bool is_secret_key(const std::string& key);

    /// What to print in place of a secret. Delegates to the shared leaf so there is
    /// exactly one spelling in the tree (see config_secret_keys.hpp).
    static const char* redacted_placeholder() { return kRedactedPlaceholder; }

    /// Returns the list of allowed config keys.
    static const std::vector<std::string>& allowed_keys();

private:
    pg::PgPool& pool_;
    pg::SecretCodec& secret_codec_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
