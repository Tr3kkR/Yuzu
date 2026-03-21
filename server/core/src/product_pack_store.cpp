#include "product_pack_store.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <random>
#include <shared_mutex>
#include <stdexcept>

// Platform-specific crypto for Ed25519 signature verification
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <openssl/evp.h>
#endif

namespace yuzu::server {

// ── Helpers ──────────────────────────────────────────────────────────────────

namespace {

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string col_text(sqlite3_stmt* stmt, int col) {
    auto p = sqlite3_column_text(stmt, col);
    return p ? std::string(reinterpret_cast<const char*>(p)) : std::string{};
}

std::string gen_id() {
    static std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist;
    auto hi = dist(rng);
    auto lo = dist(rng);
    char buf[33];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx",
                  static_cast<unsigned long long>(hi),
                  static_cast<unsigned long long>(lo));
    return std::string(buf, 32);
}

} // namespace

// ── Static helpers ──────────────────────────────────────────────────────────

std::string ProductPackStore::extract_yaml_value(const std::string& yaml,
                                                   const std::string& key) {
    auto search = key + ":";
    auto pos = yaml.find(search);
    while (pos != std::string::npos) {
        if (pos > 0 && yaml[pos - 1] != '\n' && yaml[pos - 1] != ' ' && yaml[pos - 1] != '\t') {
            pos = yaml.find(search, pos + 1);
            continue;
        }
        auto vstart = pos + search.size();
        while (vstart < yaml.size() && (yaml[vstart] == ' ' || yaml[vstart] == '\t'))
            ++vstart;
        if (vstart >= yaml.size() || yaml[vstart] == '\n')
            return {};
        auto eol = yaml.find('\n', vstart);
        if (eol == std::string::npos)
            eol = yaml.size();
        auto val = yaml.substr(vstart, eol - vstart);
        while (!val.empty() && (val.back() == ' ' || val.back() == '\t' || val.back() == '\r'))
            val.pop_back();
        if (val.size() >= 2 &&
            ((val.front() == '"' && val.back() == '"') ||
             (val.front() == '\'' && val.back() == '\''))) {
            val = val.substr(1, val.size() - 2);
        }
        if (val == ">" || val == "|")
            return {};
        return val;
    }
    return {};
}

std::vector<std::string> ProductPackStore::split_yaml_documents(const std::string& bundle) {
    std::vector<std::string> docs;
    std::string::size_type pos = 0;

    // Skip leading whitespace/newlines
    while (pos < bundle.size() && (bundle[pos] == '\n' || bundle[pos] == '\r' ||
                                    bundle[pos] == ' ' || bundle[pos] == '\t'))
        ++pos;

    while (pos < bundle.size()) {
        // Find next "---" document separator (must be at start of line)
        auto sep = bundle.find("\n---", pos);
        std::string doc;

        if (sep == std::string::npos) {
            doc = bundle.substr(pos);
            pos = bundle.size();
        } else {
            doc = bundle.substr(pos, sep - pos);
            pos = sep + 4; // skip "\n---"
            // Skip trailing newline after separator
            while (pos < bundle.size() && (bundle[pos] == '\n' || bundle[pos] == '\r'))
                ++pos;
        }

        // Strip leading "---" if present at document start
        auto trimmed = doc;
        auto first = trimmed.find_first_not_of(" \t\r\n");
        if (first != std::string::npos) {
            if (trimmed.substr(first, 3) == "---") {
                trimmed = trimmed.substr(first + 3);
                // Skip newline after ---
                auto nl = trimmed.find_first_not_of(" \t\r\n");
                if (nl != std::string::npos)
                    trimmed = trimmed.substr(nl);
                else
                    trimmed.clear();
            }
        }

        // Only add non-empty documents
        auto content_start = trimmed.find_first_not_of(" \t\r\n");
        if (content_start != std::string::npos && !trimmed.empty()) {
            docs.push_back(trimmed);
        }
    }

    return docs;
}

// ── Hex decode helper ───────────────────────────────────────────────────────

namespace {

bool hex_decode(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2 != 0)
        return false;
    out.resize(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte = 0;
        auto hi = hex[i];
        auto lo = hex[i + 1];

        auto hex_val = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
            return -1;
        };

        int h = hex_val(hi);
        int l = hex_val(lo);
        if (h < 0 || l < 0)
            return false;
        byte = static_cast<unsigned int>((h << 4) | l);
        out[i / 2] = static_cast<uint8_t>(byte);
    }
    return true;
}

} // namespace

// ── Ed25519 signature verification ──────────────────────────────────────────

bool ProductPackStore::verify_signature(const std::string& content,
                                        const std::string& signature_hex,
                                        const std::string& public_key_hex) {
    // Decode hex strings
    std::vector<uint8_t> sig_bytes;
    std::vector<uint8_t> key_bytes;

    if (!hex_decode(signature_hex, sig_bytes) || sig_bytes.size() != 64) {
        spdlog::warn("ProductPackStore: invalid signature hex (expected 128 hex chars / 64 bytes)");
        return false;
    }
    if (!hex_decode(public_key_hex, key_bytes) || key_bytes.size() != 32) {
        spdlog::warn("ProductPackStore: invalid public key hex (expected 64 hex chars / 32 bytes)");
        return false;
    }

#ifdef _WIN32
    // Windows: BCrypt Ed25519 verification
    // Note: Ed25519 support requires Windows 10 1809+ with BCRYPT_ECC_CURVE_25519
    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) {
        spdlog::warn("ProductPackStore: BCryptOpenAlgorithmProvider failed: 0x{:08x}",
                      static_cast<unsigned int>(status));
        return false;
    }

    // Set the Ed25519 curve
    status = BCryptSetProperty(alg, BCRYPT_ECC_CURVE_NAME,
                               reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_ECC_CURVE_25519)),
                               static_cast<ULONG>((wcslen(BCRYPT_ECC_CURVE_25519) + 1) * sizeof(wchar_t)),
                               0);
    if (!BCRYPT_SUCCESS(status)) {
        spdlog::warn("ProductPackStore: BCrypt Ed25519 curve not available (0x{:08x}). "
                      "Ed25519 requires Windows 10 1809+", static_cast<unsigned int>(status));
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    // Build the public key blob: BCRYPT_ECCKEY_BLOB header + 32 bytes of public key
    struct {
        BCRYPT_ECCKEY_BLOB header;
        uint8_t key_data[32];
    } key_blob;
    key_blob.header.dwMagic = BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC;
    key_blob.header.cbKey = 32;
    std::memcpy(key_blob.key_data, key_bytes.data(), 32);

    BCRYPT_KEY_HANDLE key_handle = nullptr;
    status = BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                                  &key_handle, reinterpret_cast<PUCHAR>(&key_blob),
                                  sizeof(key_blob), 0);
    if (!BCRYPT_SUCCESS(status)) {
        spdlog::warn("ProductPackStore: BCryptImportKeyPair failed: 0x{:08x}",
                      static_cast<unsigned int>(status));
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    // Verify the signature
    status = BCryptVerifySignature(key_handle, nullptr,
                                   reinterpret_cast<PUCHAR>(const_cast<char*>(content.data())),
                                   static_cast<ULONG>(content.size()),
                                   const_cast<PUCHAR>(sig_bytes.data()),
                                   static_cast<ULONG>(sig_bytes.size()), 0);

    bool valid = BCRYPT_SUCCESS(status);
    BCryptDestroyKey(key_handle);
    BCryptCloseAlgorithmProvider(alg, 0);
    return valid;

#else
    // Unix: OpenSSL EVP Ed25519 verification
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                   key_bytes.data(), key_bytes.size());
    if (!pkey) {
        spdlog::warn("ProductPackStore: EVP_PKEY_new_raw_public_key (Ed25519) failed");
        return false;
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return false;
    }

    bool valid = false;
    if (EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        int rc = EVP_DigestVerify(md_ctx,
                                   sig_bytes.data(), sig_bytes.size(),
                                   reinterpret_cast<const unsigned char*>(content.data()),
                                   content.size());
        valid = (rc == 1);
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return valid;
#endif
}

// ── Construction / destruction ──────────────────────────────────────────────

ProductPackStore::ProductPackStore(const std::filesystem::path& db_path) {
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("ProductPackStore: failed to open DB {}: {}", db_path.string(),
                      sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);

    create_tables();
    spdlog::info("ProductPackStore: opened {}", db_path.string());
}

ProductPackStore::~ProductPackStore() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool ProductPackStore::is_open() const {
    return db_ != nullptr;
}

void ProductPackStore::create_tables() {
    const char* ddl = R"(
        CREATE TABLE IF NOT EXISTS product_packs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT NOT NULL DEFAULT '1.0.0',
            description TEXT NOT NULL DEFAULT '',
            yaml_source TEXT NOT NULL,
            installed_at INTEGER NOT NULL DEFAULT 0,
            verified INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS product_pack_items (
            pack_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            item_id TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            yaml_source TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (pack_id, item_id),
            FOREIGN KEY (pack_id) REFERENCES product_packs(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_pack_items_pack ON product_pack_items(pack_id);
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, ddl, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("ProductPackStore: DDL failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }

    // Migration: add `verified` column for databases created before 7.13
    sqlite3_exec(db_, "ALTER TABLE product_packs ADD COLUMN verified INTEGER NOT NULL DEFAULT 0;",
                 nullptr, nullptr, nullptr);
}

std::string ProductPackStore::generate_id() const {
    return gen_id();
}

// ── Install ─────────────────────────────────────────────────────────────────

std::expected<std::string, std::string> ProductPackStore::install(
    const std::string& yaml_bundle,
    ItemInstallFn install_fn) {

    if (!install_fn)
        return std::unexpected("install callback is required");

    auto documents = split_yaml_documents(yaml_bundle);
    if (documents.empty())
        return std::unexpected("no YAML documents found in bundle");

    // Find the ProductPack metadata document
    std::string pack_name;
    std::string pack_version = "1.0.0";
    std::string pack_description;
    int pack_doc_idx = -1;

    for (int i = 0; i < static_cast<int>(documents.size()); ++i) {
        auto kind = extract_yaml_value(documents[i], "kind");
        if (kind == "ProductPack") {
            pack_name = extract_yaml_value(documents[i], "displayName");
            if (pack_name.empty())
                pack_name = extract_yaml_value(documents[i], "name");
            pack_version = extract_yaml_value(documents[i], "version");
            if (pack_version.empty())
                pack_version = "1.0.0";
            pack_description = extract_yaml_value(documents[i], "description");
            pack_doc_idx = i;
            break;
        }
    }

    if (pack_name.empty()) {
        // If no ProductPack document, use the first document's name
        if (!documents.empty()) {
            pack_name = extract_yaml_value(documents[0], "displayName");
            if (pack_name.empty())
                pack_name = extract_yaml_value(documents[0], "name");
        }
        if (pack_name.empty())
            pack_name = "Unnamed Pack";
    }

    // ── Ed25519 signature verification (Issue 7.13) ─────────────────────
    // If the ProductPack document includes a `signature` field, verify it
    // against the content using a public key from `publicKey` in metadata.
    bool pack_verified = false;
    std::string pack_signature;
    std::string pack_public_key;

    if (pack_doc_idx >= 0) {
        pack_signature = extract_yaml_value(documents[pack_doc_idx], "signature");
        pack_public_key = extract_yaml_value(documents[pack_doc_idx], "publicKey");
    }

    if (!pack_signature.empty() && !pack_public_key.empty()) {
        // Build the content to verify: all non-metadata documents concatenated
        std::string content_to_verify;
        for (int i = 0; i < static_cast<int>(documents.size()); ++i) {
            if (i == pack_doc_idx)
                continue;
            if (!content_to_verify.empty())
                content_to_verify += "\n---\n";
            content_to_verify += documents[i];
        }

        pack_verified = verify_signature(content_to_verify, pack_signature, pack_public_key);
        if (pack_verified) {
            spdlog::info("ProductPackStore: signature verified for '{}'", pack_name);
        } else {
            spdlog::warn("ProductPackStore: signature verification FAILED for '{}' — "
                          "pack will be installed as unverified", pack_name);
        }
    } else if (!pack_signature.empty()) {
        spdlog::warn("ProductPackStore: pack '{}' has signature but no publicKey — "
                      "cannot verify", pack_name);
    } else {
        spdlog::info("ProductPackStore: pack '{}' has no signature — installing as unverified",
                      pack_name);
    }

    auto pack_id = generate_id();
    auto now = now_epoch();

    std::unique_lock lock(mtx_);

    // Insert pack record
    {
        const char* sql = "INSERT INTO product_packs "
                          "(id, name, version, description, yaml_source, installed_at, verified) "
                          "VALUES (?, ?, ?, ?, ?, ?, ?)";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

        sqlite3_bind_text(stmt, 1, pack_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, pack_name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, pack_version.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, pack_description.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, yaml_bundle.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 6, now);
        sqlite3_bind_int(stmt, 7, pack_verified ? 1 : 0);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE)
            return std::unexpected(std::string("insert failed: ") + sqlite3_errmsg(db_));
    }

    // Install each content document (skip the ProductPack metadata doc)
    int installed_count = 0;
    std::vector<std::string> errors;

    for (int i = 0; i < static_cast<int>(documents.size()); ++i) {
        if (i == pack_doc_idx)
            continue; // Skip the ProductPack metadata document itself

        auto kind = extract_yaml_value(documents[i], "kind");
        if (kind.empty()) {
            // Try to infer kind from content
            if (documents[i].find("execution:") != std::string::npos ||
                documents[i].find("plugin:") != std::string::npos) {
                kind = "InstructionDefinition";
            } else {
                errors.push_back("document " + std::to_string(i) + " has no kind");
                continue;
            }
        }

        // Delegate to the appropriate store via callback
        auto result = install_fn(kind, documents[i]);
        if (result) {
            auto item_name = extract_yaml_value(documents[i], "displayName");
            if (item_name.empty())
                item_name = extract_yaml_value(documents[i], "name");

            ProductPackItem item;
            item.kind = kind;
            item.item_id = *result;
            item.name = item_name;
            item.yaml_source = documents[i];
            store_item(pack_id, item);
            ++installed_count;
        } else {
            errors.push_back(kind + ": " + result.error());
        }
    }

    if (installed_count == 0 && !errors.empty()) {
        // Rollback the pack record — nothing was installed
        const char* del_sql = "DELETE FROM product_packs WHERE id = ?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, del_sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, pack_id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
        return std::unexpected("no items installed: " + errors[0]);
    }

    spdlog::info("ProductPackStore: installed '{}' v{} ({}), {} items, {} errors",
                 pack_name, pack_version, pack_id, installed_count, errors.size());
    return pack_id;
}

// ── List / Get ──────────────────────────────────────────────────────────────

std::vector<ProductPack> ProductPackStore::list(const ProductPackQuery& q) const {
    std::shared_lock lock(mtx_);
    std::vector<ProductPack> result;

    std::string sql = "SELECT id, name, version, description, yaml_source, installed_at, verified "
                      "FROM product_packs";
    std::vector<std::string> binds;
    if (!q.name_filter.empty()) {
        sql += " WHERE name LIKE ?";
        binds.push_back("%" + q.name_filter + "%");
    }
    sql += " ORDER BY installed_at DESC LIMIT ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return result;

    int idx = 1;
    for (auto& b : binds)
        sqlite3_bind_text(stmt, idx++, b.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, idx, q.limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ProductPack p;
        p.id = col_text(stmt, 0);
        p.name = col_text(stmt, 1);
        p.version = col_text(stmt, 2);
        p.description = col_text(stmt, 3);
        p.yaml_source = col_text(stmt, 4);
        p.installed_at = sqlite3_column_int64(stmt, 5);
        p.verified = (sqlite3_column_int(stmt, 6) != 0);
        p.items = load_items(p.id);
        result.push_back(std::move(p));
    }
    sqlite3_finalize(stmt);
    return result;
}

std::optional<ProductPack> ProductPackStore::get(const std::string& id) const {
    std::shared_lock lock(mtx_);

    const char* sql = "SELECT id, name, version, description, yaml_source, installed_at, verified "
                      "FROM product_packs WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return std::nullopt;
    }

    ProductPack p;
    p.id = col_text(stmt, 0);
    p.name = col_text(stmt, 1);
    p.version = col_text(stmt, 2);
    p.description = col_text(stmt, 3);
    p.yaml_source = col_text(stmt, 4);
    p.installed_at = sqlite3_column_int64(stmt, 5);
    p.verified = (sqlite3_column_int(stmt, 6) != 0);
    sqlite3_finalize(stmt);

    p.items = load_items(p.id);
    return p;
}

// ── Uninstall ───────────────────────────────────────────────────────────────

std::expected<void, std::string> ProductPackStore::uninstall(
    const std::string& id,
    ItemUninstallFn uninstall_fn) {

    if (!uninstall_fn)
        return std::unexpected("uninstall callback is required");

    auto pack = get(id);
    if (!pack)
        return std::unexpected("product pack not found: " + id);

    std::unique_lock lock(mtx_);

    // Remove each contained item from its origin store
    int removed = 0;
    for (const auto& item : pack->items) {
        if (uninstall_fn(item.kind, item.item_id))
            ++removed;
        else
            spdlog::warn("ProductPackStore: failed to remove {} item '{}'", item.kind, item.item_id);
    }

    // Delete pack items
    {
        const char* sql = "DELETE FROM product_pack_items WHERE pack_id = ?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    // Delete pack record
    {
        const char* sql = "DELETE FROM product_packs WHERE id = ?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    spdlog::info("ProductPackStore: uninstalled '{}', removed {} items", pack->name, removed);
    return {};
}

// ── Item storage helpers ────────────────────────────────────────────────────

void ProductPackStore::store_item(const std::string& pack_id, const ProductPackItem& item) {
    const char* sql = "INSERT INTO product_pack_items (pack_id, kind, item_id, name, yaml_source) "
                      "VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(stmt, 1, pack_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, item.kind.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, item.item_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, item.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, item.yaml_source.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::vector<ProductPackItem> ProductPackStore::load_items(const std::string& pack_id) const {
    std::vector<ProductPackItem> items;
    const char* sql = "SELECT kind, item_id, name, yaml_source "
                      "FROM product_pack_items WHERE pack_id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return items;

    sqlite3_bind_text(stmt, 1, pack_id.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ProductPackItem item;
        item.kind = col_text(stmt, 0);
        item.item_id = col_text(stmt, 1);
        item.name = col_text(stmt, 2);
        item.yaml_source = col_text(stmt, 3);
        items.push_back(std::move(item));
    }
    sqlite3_finalize(stmt);
    return items;
}

} // namespace yuzu::server
