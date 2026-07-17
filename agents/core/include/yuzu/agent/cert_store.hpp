#pragma once

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <string>

namespace yuzu::agent {

/// Result of reading a certificate + private key from the OS certificate store.
/// Both fields are PEM-encoded strings suitable for grpc::SslCredentialsOptions.
struct YUZU_EXPORT CertStoreResult {
    std::string pem_cert_chain;  // PEM-encoded certificate (+ chain if available)
    std::string pem_private_key; // PEM-encoded private key
    std::string error;           // Non-empty on failure

    [[nodiscard]] bool ok() const noexcept { return error.empty(); }
};

/// Read a client certificate and private key from the OS certificate store.
///
/// @param store_name  Windows: store name (e.g. "MY" for Personal). Ignored on macOS/Linux.
/// @param subject     Subject CN or substring to match (e.g. "yuzu-agent", "*.corp.example.com").
/// @param thumbprint  Hex-encoded SHA-1 thumbprint. Takes priority over subject if non-empty.
///
/// On Windows, uses CryptoAPI to read from the Local Machine (falling back to
/// Current User) store.
/// On macOS, uses the Security framework (SecItemCopyMatching) to read an
/// identity — certificate chain + private key — from the current user's
/// LOGIN keychain only; System.keychain is never queried and no interactive
/// unlock/authentication prompt is ever forced. Requires Security.framework
/// at build time (YUZU_HAVE_SECURITY); an honest error CertStoreResult is
/// returned otherwise, never a fabricated success.
/// On Linux, returns an error — use PEM files instead.
YUZU_EXPORT CertStoreResult read_cert_from_store(const std::string& store_name,
                                                 const std::string& subject,
                                                 const std::string& thumbprint);

} // namespace yuzu::agent
