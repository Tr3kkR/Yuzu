#pragma once

#include <yuzu/plugin.h>  // YUZU_EXPORT

#include <string>
#include <vector>

namespace yuzu::agent {

/// Result of cloud instance identity detection.
struct YUZU_EXPORT CloudIdentity {
    std::string provider;           // "aws", "azure", "gcp"
    std::string instance_id;        // Provider-specific instance ID
    std::string region;             // Cloud region (e.g. "us-east-1")
    std::vector<uint8_t> identity_document;  // Signed identity doc (PKCS7/JWT)
    std::string identity_signature; // Base64 signature (AWS) or unused

    bool valid() const { return !provider.empty() && !identity_document.empty(); }
};

/// Detect cloud provider via IMDS and fetch a signed identity document.
///
/// Probes each provider's metadata endpoint with a short timeout:
///   - AWS: IMDSv2 (169.254.169.254) — PKCS7-signed identity document
///   - Azure: IMDS (169.254.169.254) — attested document with JWT signature
///   - GCP: Metadata server (metadata.google.internal) — signed JWT identity token
///
/// Returns a CloudIdentity with valid()==false if not running on any cloud,
/// or if the metadata service is unreachable.
YUZU_EXPORT CloudIdentity detect_cloud_identity();

}  // namespace yuzu::agent
