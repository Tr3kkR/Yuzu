#pragma once

/// @file key_provider.hpp
/// Storage abstraction for CA / leaf private keys.
///
/// The CA root key is the install's crown jewel. `KeyProvider` is the seam that
/// keeps key custody policy out of the crypto engine (`x509_ca`) and the
/// inventory store (`ca_store`): Milestone 1 ships `FileKeyProvider` (0600 PEM
/// under an owner-only directory), and a future `Pkcs11KeyProvider` /
/// `HsmKeyProvider` can implement the same interface with `key_ref` = a PKCS#11
/// URI, with zero change to callers. This is skill gap #10's "preferred keyring
/// abstraction".
///
/// `key_ref` is an opaque token the caller persists (in `ca_store.ca_root`) and
/// hands back to `load_key`. For `FileKeyProvider` it is the absolute path to
/// the PEM; callers MUST treat it as opaque so the HSM swap stays transparent.

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server {

class KeyProvider {
public:
    virtual ~KeyProvider() = default;

    /// Persist `pem` under a logical `key_id`. Returns an opaque `key_ref` to
    /// store, or std::nullopt on failure. Implementations MUST persist the key
    /// material at rest with owner-only access.
    ///
    /// OPERATOR/SRE NOTE: the stored key (for FileKeyProvider, the 0600 PEM at
    /// `<base>/<key_id>.key`) is a trust anchor — losing the CA root key without
    /// a backup forces a full fleet re-enrollment. Back it up to offline /
    /// encrypted storage; verify a restore by comparing `CaRoot::fingerprint_sha256`
    /// (in ca.db) against `openssl x509 -fingerprint -sha256` on the restored cert.
    [[nodiscard]] virtual std::optional<std::string> store_key(std::string_view key_id,
                                                               std::string_view pem) = 0;

    /// Resolve a previously-stored key. Returns the PEM, or std::nullopt if the
    /// ref does not resolve / cannot be read. Callers should `secure_zero` the
    /// returned buffer once finished with it.
    [[nodiscard]] virtual std::optional<std::string> load_key(std::string_view key_ref) = 0;

    /// True iff `key_ref` currently resolves to a readable key.
    [[nodiscard]] virtual bool has_key(std::string_view key_ref) = 0;

    /// Best-effort removal (rotation / cleanup). Returns true if the key is
    /// gone afterwards (including the already-absent case).
    virtual bool delete_key(std::string_view key_ref) = 0;
};

/// File-backed key store. Keys live as `<base_dir>/<key_id>.key` with mode 0600
/// inside a 0700 directory. `key_ref` is the absolute file path.
class FileKeyProvider : public KeyProvider {
public:
    explicit FileKeyProvider(std::filesystem::path base_dir);

    [[nodiscard]] std::optional<std::string> store_key(std::string_view key_id,
                                                       std::string_view pem) override;
    [[nodiscard]] std::optional<std::string> load_key(std::string_view key_ref) override;
    [[nodiscard]] bool has_key(std::string_view key_ref) override;
    bool delete_key(std::string_view key_ref) override;

    /// Exposed for callers/tests that need the resolved on-disk location for a
    /// given id without storing anything.
    [[nodiscard]] std::filesystem::path path_for(std::string_view key_id) const;

private:
    std::filesystem::path base_dir_;

    /// Reject a key_id that is not a bare, safe filename component (prevents
    /// path traversal via a crafted id). Returns false on any of: empty, path
    /// separators, "..", or characters outside [A-Za-z0-9._-].
    [[nodiscard]] static bool is_safe_key_id(std::string_view key_id);

    /// Confirm `p` canonicalises to a location inside base_dir_ (defence in
    /// depth for load/has/delete, which take an opaque ref from the DB).
    [[nodiscard]] bool within_base(const std::filesystem::path& p) const;
};

} // namespace yuzu::server
