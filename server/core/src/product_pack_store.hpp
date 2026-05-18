#pragma once

#include <sqlite3.h>

#include <atomic>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

namespace yuzu::server {

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
    explicit ProductPackStore(const std::filesystem::path& db_path);
    ~ProductPackStore();

    /// When true, packs WITHOUT a `signature` field are rejected at install
    /// time. Packs with a signature are always verified regardless of this
    /// flag — failed verification rejects unconditionally. Defaults to
    /// true since #802 / W7.4: unsigned packs are a fleet-wide arbitrary-
    /// code-execution surface (MITM on pack delivery or an unprivileged
    /// uploader with pack-install permission can inject malicious payloads
    /// that execute on every enrolled agent). Operators with legacy
    /// unsigned packs must explicitly opt out via the
    /// `--allow-unsigned-packs` / `YUZU_ALLOW_UNSIGNED_PACKS` server
    /// flag, which calls `set_require_signed_packs(false)` and emits a
    /// `server.unsigned_packs_allowed` startup audit event.
    ///
    /// gov W7.4 R1 SHOULD-1 (cpp-expert): the field is `std::atomic<bool>`
    /// because `install` reads it OUTSIDE the `mtx_` (perf — the lock is
    /// only acquired after the check, for the DB write phase). The setter
    /// is called at startup, before any concurrent reader exists, but TSAN
    /// has no way to know that — atomic load/store with relaxed memory
    /// order silences TSAN AND future-proofs against any later runtime-
    /// toggle endpoint.
    void set_require_signed_packs(bool require) {
        require_signed_packs_.store(require, std::memory_order_relaxed);
    }
    bool require_signed_packs() const {
        return require_signed_packs_.load(std::memory_order_relaxed);
    }

    ProductPackStore(const ProductPackStore&) = delete;
    ProductPackStore& operator=(const ProductPackStore&) = delete;

    bool is_open() const;

    /// Install a product pack from a multi-document YAML bundle.
    /// Each `---` separated document is parsed for its `kind:` field and
    /// delegated to the appropriate store via install_fn.
    /// The ProductPack metadata is extracted from the document with kind: ProductPack.
    ///
    /// SECURITY INVARIANT (#802 / W7.4): this is the SOLE gate for
    /// `require_signed_packs_`. All code that materialises a `ProductPack`
    /// from external (operator-supplied or network-fetched) input MUST
    /// route through this method — direct writes via the underlying
    /// `product_packs` SQLite table, or callbacks that bypass `install`,
    /// defeat the #802 protection and re-introduce the fleet-wide
    /// arbitrary-code-execution surface. If a future bulk-import,
    /// hot-reload, sync-from-registry, or content-distribution feature is
    /// added, it MUST either call `install()` (preferred) or implement an
    /// equivalent signature check AND emit a `product_pack.install` audit
    /// row with `result=denied` on rejection. The sole production caller
    /// today is `workflow_routes.cpp` `POST /api/product-packs`; any new
    /// caller must update this comment to remain accurate.
    std::expected<std::string, std::string> install(const std::string& yaml_bundle,
                                                    ItemInstallFn install_fn);

    /// List installed product packs.
    std::vector<ProductPack> list(const ProductPackQuery& q = {}) const;

    /// Get a single product pack with its items.
    std::optional<ProductPack> get(const std::string& id) const;

    /// Uninstall a product pack, removing all contained items via uninstall_fn.
    std::expected<void, std::string> uninstall(const std::string& id, ItemUninstallFn uninstall_fn);

    // Minimal YAML value extraction — public so install callbacks can use it
    static std::string extract_yaml_value(const std::string& yaml, const std::string& key);

    /// Verify an Ed25519 signature over content.
    /// Uses OpenSSL EVP_DigestVerify on Unix, BCrypt on Windows.
    /// @param content     The data that was signed
    /// @param signature_hex  Hex-encoded Ed25519 signature (128 hex chars = 64 bytes)
    /// @param public_key_hex Hex-encoded Ed25519 public key (64 hex chars = 32 bytes)
    /// @return true if signature is valid, false otherwise
    static bool verify_signature(const std::string& content, const std::string& signature_hex,
                                 const std::string& public_key_hex);

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_;
    /// Security-by-default since #802 (W7.4): packs without a `signature`
    /// field are rejected at install time. Operators with legacy unsigned
    /// packs must opt out explicitly via `--allow-unsigned-packs` /
    /// `YUZU_ALLOW_UNSIGNED_PACKS=1`, which calls
    /// `set_require_signed_packs(false)` at startup and emits a loud
    /// `server.unsigned_packs_allowed` audit event. The historical default
    /// (false) shipped a critical fleet-wide arbitrary-code-execution
    /// surface: any operator with pack upload permission, or a MITM on
    /// pack delivery, could install an unsigned pack containing
    /// `InstructionDefinition` or plugin payloads that would execute on
    /// every enrolled agent.
    /// Atomic because `install` reads it outside the mtx_; see the setter
    /// doc above.
    std::atomic<bool> require_signed_packs_{true};

    void create_tables();
    std::string generate_id() const;

    // Store/load pack items (caller must hold mtx_)
    void store_item(const std::string& pack_id, const ProductPackItem& item);
    std::vector<ProductPackItem> load_items(const std::string& pack_id) const;

    // Split multi-document YAML on "---" boundaries
    static std::vector<std::string> split_yaml_documents(const std::string& bundle);
};

} // namespace yuzu::server
