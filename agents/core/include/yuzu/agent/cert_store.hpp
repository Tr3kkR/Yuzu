#pragma once

#include <yuzu/plugin.h>  // YUZU_EXPORT

#include <string>

namespace yuzu::agent {

/// Result of reading a certificate + private key from the OS certificate store.
/// Both fields are PEM-encoded strings suitable for grpc::SslCredentialsOptions.
struct YUZU_EXPORT CertStoreResult {
    std::string pem_cert_chain;   // PEM-encoded certificate (+ chain if available)
    std::string pem_private_key;  // PEM-encoded private key
    std::string error;            // Non-empty on failure

    [[nodiscard]] bool ok() const noexcept { return error.empty(); }
};

/// Read a client certificate and private key from the OS certificate store.
///
/// @param store_name  Windows: store name (e.g. "MY" for Personal). Ignored on other platforms.
/// @param subject     Subject CN or substring to match (e.g. "yuzu-agent", "*.corp.example.com").
/// @param thumbprint  Hex-encoded SHA-1 thumbprint. Takes priority over subject if non-empty.
///
/// On Windows, uses CryptoAPI to read from the Local Machine store.
/// On Linux/macOS, returns an error — use PEM files or PKCS#11 instead.
YUZU_EXPORT CertStoreResult read_cert_from_store(
    const std::string& store_name,
    const std::string& subject,
    const std::string& thumbprint);

}  // namespace yuzu::agent
