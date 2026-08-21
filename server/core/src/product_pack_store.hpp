#pragma once

/// @file product_pack_store.hpp
/// Migrated Postgres store (ADR-0006/0009/0054, schema `product_pack_store`) for operator-
/// installed product packs — multi-document YAML bundles that install into the
/// `InstructionStore`/`PolicyStore`/`WorkflowEngine` catalogs via a caller-supplied
/// `ItemInstallFn`/`ItemUninstallFn`. Two tables, one real internal FK with `ON DELETE CASCADE`
/// (`product_pack_items.pack_id -> product_packs.id`), ported unchanged.
///
/// Posture (ADR-0012 §1): AUTHORITATIVE / fail-hard, both construction and runtime — packs are
/// operator-installed content (build-time-seeded packs plus operator additions), not a cache.
/// `install`/`uninstall` already returned `std::expected` pre-migration; `list`/`get` are widened
/// to `std::expected` here (ADR-0036 typed-read policy) so a genuine DB error is never collapsed
/// into "no packs installed" / "not found" — matching `LicenseStore`/`ResultSetStore`'s `get`
/// shape (`std::expected<std::optional<T>, std::string>`).
///
/// Substrate contract (ADR-0008): the store holds a `pg::PgPool&` (not a `sqlite3*`), runs its
/// schema migration at construction on a pinned lease, and schema-qualifies every runtime
/// statement (`product_pack_store.product_packs` / `product_pack_store.product_pack_items`) —
/// pooled connections carry no per-store search_path. Mutate-and-return uses `RETURNING` where a
/// caller needs to distinguish "inserted" from "conflicted", never `sqlite3_changes()`.
///
/// **`install()` no longer holds a `pool_` lease across the `ItemInstallFn` callback loop.**
/// The pre-migration SQLite version wrapped the whole install (metadata insert + per-document
/// `install_fn` calls into `InstructionStore`/`PolicyStore`/`WorkflowEngine`) inside one
/// `BEGIN IMMEDIATE` on `db_`. Under the Postgres substrate that shape is forbidden
/// (`docs/postgres-store-playbook.md`: "never call another store while holding a lease" — those
/// sibling stores draw from the SAME shared `PgPool`, so holding our own lease while they try to
/// acquire theirs risks starving a saturated pool). This was never a genuine cross-store
/// transaction even pre-migration: `install_fn`'s callees write to THEIR OWN `db_`/pool, never
/// ours, so a rollback of our own txn never undid an already-succeeded sibling install either.
/// The new shape preserves that same atomicity boundary explicitly: `install_fn` is called with
/// no lease of ours held; once every document has been resolved, the pack row + its successfully-
/// installed item rows are written in ONE `pool_` transaction (parent-before-child, satisfying the
/// FK). A total-failure install (zero items installed) never touches Postgres at all.
///
/// **No `mtx_` (the pre-migration `shared_mutex` is dropped).** Postgres's MVCC + the pool's own
/// connection-level concurrency replace the SQLite single-writer mutex, matching every other
/// migrated store on the ladder. This is a deliberate, accepted trade: two concurrent
/// `uninstall(id, ...)` calls for the SAME id can both pass the `get(id)` existence check and
/// both invoke `uninstall_fn` on the sibling stores before either's delete transaction runs —
/// the sibling-store uninstalls are themselves idempotent-ish (a missing item is just a `false`
/// return, logged, not fatal) and the final Postgres delete is a plain `DELETE ... WHERE id=$1`
/// (harmless if the row is already gone). A small race window, not a security boundary —
/// `ResultSetStore`'s per-owner quota/pin-limit soft-enforcement is the ladder's precedent for
/// recording this class of trade explicitly rather than silently.
///
/// No secrets (ADR-0010 N/A): `yaml_source` is pack content — verified against
/// `docs/Instruction-Engine.md` / `docs/yaml-dsl-spec.md`, neither of which defines a
/// secret-typed/credential-bearing YAML field; the only crypto-adjacent fields are the public
/// `signature`/`publicKey` pair, which are not secret material. Free-text columns
/// (`name`/`description`/`yaml_source` and the item equivalents) are still `sanitize_pg_text`'d
/// before every write — libpq's text-format binding is C-string-based, so an embedded NUL byte
/// would otherwise silently TRUNCATE the stored value at that point (worse than the
/// pre-migration `sqlite3_bind_text(..., -1, ...)`, which had the identical truncation behavior
/// — U+FFFD replacement is a strict improvement, not a new risk). Sanitization is at-rest
/// storage hygiene only; it does not re-verify the Ed25519 signature over the sanitized bytes —
/// `verify_signature` runs once, before sanitization, over the exact bytes that were signed.

#include <atomic>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

/// Machine-checkable prefix on every `ProductPackStore` `unexpected()` that represents a genuine
/// DB/lease failure rather than caller-input validation, a signature/policy rejection, or a
/// not-found error (mirrors `LicenseStore::kLicenseDbErrorPrefix` / `AccessReviewStore`'s
/// `"not_found: "` idiom). Callers classify: `"not_found:"` prefix -> 404, this prefix -> 503,
/// else -> 400 (see `workflow_routes.cpp`'s `product_pack_error_status`).
inline constexpr const char* kProductPackDbErrorPrefix = "db_error: ";

// ── Data types ───────────────────────────────────────────────────────────────

struct ProductPackItem {
    std::string kind;        // "InstructionDefinition", "PolicyFragment", etc.
    std::string item_id;     // ID assigned when the item was installed
    std::string name;        // Display name from the YAML
    std::string yaml_source; // Verbatim YAML for this document
};

struct ProductPack {
    std::string id;
    std::string name;
    std::string version;
    std::string description;
    std::string yaml_source; // The full multi-document YAML bundle
    int64_t installed_at{0};
    bool verified{false}; // Whether the Ed25519 signature was verified

    // Populated by get()
    std::vector<ProductPackItem> items;
};

struct ProductPackQuery {
    std::string name_filter;
    int limit{100};
};

// ── Callbacks for delegating item install/uninstall to existing stores ────────

/// Called for each YAML document during install.
/// Returns the assigned item ID on success, or an error string.
using ItemInstallFn = std::function<std::expected<std::string, std::string>(
    const std::string& kind, const std::string& yaml_source)>;

/// Called for each item during uninstall to remove it from its origin store.
using ItemUninstallFn = std::function<bool(const std::string& kind, const std::string& item_id)>;

// ── ProductPackStore ────────────────────────────────────────────────────────

class ProductPackStore {
public:
    /// Borrows the shared pool and runs the `product_pack_store` schema migration on a pinned
    /// lease. `is_open()` is false if the lease was empty or the migration failed.
    explicit ProductPackStore(pg::PgPool& pool);

    ProductPackStore(const ProductPackStore&) = delete;
    ProductPackStore& operator=(const ProductPackStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for the backfill-result counter
    /// (`yuzu_server_product_pack_backfill_total{result}`) and `list`/`get`'s read-degrade
    /// counter (`yuzu_server_product_pack_read_degrade_total{reason}`), matching
    /// `CustomPropertiesStore`/`DiscoveryStore`'s #1675 convention. Set ONCE during
    /// single-threaded startup — BEFORE `migrate_from_sqlite()`, so the backfill counter is
    /// live on the one pass that matters (the #3261/#3294 wiring-order class; see the
    /// construction-site comment in server.cpp). A null registry (the default, e.g. in unit
    /// tests) disables emission.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// Legacy-SQLite backfill (ADR-0009/0054). Call once at server startup, before serving, after
    /// construction has proven the Postgres schema is open. Idempotent PER DISTINCT LEGACY-FILE
    /// CONTENT (a SHA-256 fingerprint over BOTH tables' rows, or a sourceless sentinel) —
    /// `LicenseStore`'s two-table backfill is the closest reference. Fails CLOSED on any error,
    /// including a legacy file holding exactly one of the two expected tables (no version of the
    /// shipped binary can produce that shape — treated as corruption). Transparently handles a
    /// pre-7.13 legacy file whose `product_packs` table predates the `verified` column (defaults
    /// `verified=0` for that vintage, matching the pre-migration raw-`ALTER TABLE` shim this
    /// migration retires). Returns true (no-op) when `legacy_db_path` does not exist or holds
    /// neither table (fresh install). Opens the legacy file READ-ONLY and never deletes/moves it.
    [[nodiscard]] bool migrate_from_sqlite(const std::filesystem::path& legacy_db_path);

    /// When true, packs WITHOUT a `signature` field are rejected at install time. Packs with a
    /// signature are always verified regardless of this flag — failed verification rejects
    /// unconditionally. Defaults to true since #802 / W7.4: unsigned packs are a fleet-wide
    /// arbitrary-code-execution surface. Operators with legacy unsigned packs must explicitly
    /// opt out via the `--allow-unsigned-packs` / `YUZU_ALLOW_UNSIGNED_PACKS` server flag, which
    /// calls `set_require_signed_packs(false)` and emits a `server.unsigned_packs_allowed`
    /// startup audit event.
    ///
    /// gov W7.4 R1 SHOULD-1 (cpp-expert): the field is `std::atomic<bool>` because `install`
    /// reads it OUTSIDE any lease (perf/ordering — the check happens before the DB write phase).
    /// The setter is called at startup, before any concurrent reader exists, but TSAN has no way
    /// to know that — atomic load/store with relaxed memory order silences TSAN AND
    /// future-proofs against any later runtime-toggle endpoint.
    void set_require_signed_packs(bool require) {
        require_signed_packs_.store(require, std::memory_order_relaxed);
    }
    bool require_signed_packs() const {
        return require_signed_packs_.load(std::memory_order_relaxed);
    }

    /// Install a product pack from a multi-document YAML bundle.
    /// Each `---` separated document is parsed for its `kind:` field and
    /// delegated to the appropriate store via install_fn.
    /// The ProductPack metadata is extracted from the document with kind: ProductPack.
    ///
    /// SECURITY INVARIANT (#802 / W7.4): this is the SOLE gate for `require_signed_packs_`. All
    /// code that materialises a `ProductPack` from external (operator-supplied or
    /// network-fetched) input MUST route through this method — direct writes via the underlying
    /// `product_pack_store.product_packs` table, or callbacks that bypass `install`, defeat the
    /// #802 protection and re-introduce the fleet-wide arbitrary-code-execution surface. If a
    /// future bulk-import, hot-reload, sync-from-registry, or content-distribution feature is
    /// added, it MUST either call `install()` (preferred) or implement an equivalent signature
    /// check AND emit a `product_pack.install` audit row with `result=denied` on rejection. The
    /// sole production caller today is `workflow_routes.cpp` `POST /api/product-packs`; any new
    /// caller must update this comment to remain accurate.
    ///
    /// `install_fn` is invoked with NO `pool_` lease of ours held (see the file header) — it is
    /// free to call into its own sibling stores without risking pool starvation.
    std::expected<std::string, std::string> install(const std::string& yaml_bundle,
                                                    ItemInstallFn install_fn);

    /// List installed product packs, newest-installed first. `unexpected(msg)` (prefixed
    /// `kProductPackDbErrorPrefix`) is a genuine read failure — never treat it as "no packs
    /// installed".
    std::expected<std::vector<ProductPack>, std::string> list(const ProductPackQuery& q = {});

    /// Get a single product pack with its items. `nullopt` = a successful read finding none;
    /// `unexpected(msg)` (prefixed `kProductPackDbErrorPrefix`) = a genuine read failure — never
    /// treat the latter as "not found".
    std::expected<std::optional<ProductPack>, std::string> get(const std::string& id);

    /// Uninstall a product pack, removing all contained items via uninstall_fn.
    /// `unexpected("not_found: ...")` when no pack with this id exists; any other
    /// `unexpected(msg)` (prefixed `kProductPackDbErrorPrefix`) is a genuine failure.
    std::expected<void, std::string> uninstall(const std::string& id, ItemUninstallFn uninstall_fn);

    // Minimal YAML value extraction — public so install callbacks can use it
    static std::string extract_yaml_value(const std::string& yaml, const std::string& key);

    /// Verify an Ed25519 signature over content.
    /// Uses OpenSSL EVP_DigestVerify on every platform (see the .cpp file header for the
    /// BCrypt-was-actually-ECDSA-not-Ed25519 history).
    /// @param content     The data that was signed
    /// @param signature_hex  Hex-encoded Ed25519 signature (128 hex chars = 64 bytes)
    /// @param public_key_hex Hex-encoded Ed25519 public key (64 hex chars = 32 bytes)
    /// @return true if signature is valid, false otherwise
    static bool verify_signature(const std::string& content, const std::string& signature_hex,
                                 const std::string& public_key_hex);

private:
    pg::PgPool& pool_;
    bool open_{false};
    /// Security-by-default since #802 (W7.4): see the setter doc above.
    std::atomic<bool> require_signed_packs_{true};
    yuzu::MetricsRegistry* metrics_{nullptr};

    // Split multi-document YAML on "---" boundaries
    static std::vector<std::string> split_yaml_documents(const std::string& bundle);
};

} // namespace yuzu::server
