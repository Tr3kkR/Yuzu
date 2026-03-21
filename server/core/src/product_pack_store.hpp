#pragma once

#include <sqlite3.h>

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
    std::string kind;       // "InstructionDefinition", "PolicyFragment", etc.
    std::string item_id;    // ID assigned when the item was installed
    std::string name;       // Display name from the YAML
    std::string yaml_source; // Verbatim YAML for this document
};

struct ProductPack {
    std::string id;
    std::string name;
    std::string version;
    std::string description;
    std::string yaml_source;    // The full multi-document YAML bundle
    int64_t installed_at{0};
    bool verified{false};       // Whether the Ed25519 signature was verified

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
    const std::string& kind,
    const std::string& yaml_source)>;

/// Called for each item during uninstall to remove it from its origin store.
using ItemUninstallFn = std::function<bool(
    const std::string& kind,
    const std::string& item_id)>;

// ── ProductPackStore ────────────────────────────────────────────────────────

class ProductPackStore {
public:
    explicit ProductPackStore(const std::filesystem::path& db_path);
    ~ProductPackStore();

    /// When true, packs that include a signature field MUST pass verification
    /// or they are rejected. Unsigned packs (no signature field) are still
    /// allowed as a separate policy question.
    /// Defaults to false for backward compatibility.
    void set_require_signed_packs(bool require) { require_signed_packs_ = require; }
    bool require_signed_packs() const { return require_signed_packs_; }

    ProductPackStore(const ProductPackStore&) = delete;
    ProductPackStore& operator=(const ProductPackStore&) = delete;

    bool is_open() const;

    /// Install a product pack from a multi-document YAML bundle.
    /// Each `---` separated document is parsed for its `kind:` field and
    /// delegated to the appropriate store via install_fn.
    /// The ProductPack metadata is extracted from the document with kind: ProductPack.
    std::expected<std::string, std::string> install(
        const std::string& yaml_bundle,
        ItemInstallFn install_fn);

    /// List installed product packs.
    std::vector<ProductPack> list(const ProductPackQuery& q = {}) const;

    /// Get a single product pack with its items.
    std::optional<ProductPack> get(const std::string& id) const;

    /// Uninstall a product pack, removing all contained items via uninstall_fn.
    std::expected<void, std::string> uninstall(
        const std::string& id,
        ItemUninstallFn uninstall_fn);

    // Minimal YAML value extraction — public so install callbacks can use it
    static std::string extract_yaml_value(const std::string& yaml, const std::string& key);

    /// Verify an Ed25519 signature over content.
    /// Uses OpenSSL EVP_DigestVerify on Unix, BCrypt on Windows.
    /// @param content     The data that was signed
    /// @param signature_hex  Hex-encoded Ed25519 signature (128 hex chars = 64 bytes)
    /// @param public_key_hex Hex-encoded Ed25519 public key (64 hex chars = 32 bytes)
    /// @return true if signature is valid, false otherwise
    static bool verify_signature(const std::string& content,
                                 const std::string& signature_hex,
                                 const std::string& public_key_hex);

private:
    sqlite3* db_{nullptr};
    mutable std::shared_mutex mtx_;
    bool require_signed_packs_{false};

    void create_tables();
    std::string generate_id() const;

    // Store/load pack items (caller must hold mtx_)
    void store_item(const std::string& pack_id, const ProductPackItem& item);
    std::vector<ProductPackItem> load_items(const std::string& pack_id) const;

    // Split multi-document YAML on "---" boundaries
    static std::vector<std::string> split_yaml_documents(const std::string& bundle);
};

} // namespace yuzu::server
