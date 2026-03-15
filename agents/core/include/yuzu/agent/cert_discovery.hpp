#pragma once

#include <yuzu/plugin.h>  // YUZU_EXPORT

#include <filesystem>
#include <optional>
#include <string>

namespace yuzu::agent {

/// Result of automatic certificate discovery from well-known filesystem paths.
struct YUZU_EXPORT DiscoveredCert {
    std::filesystem::path cert_path;   // PEM certificate file
    std::filesystem::path key_path;    // PEM private key file
    std::string source;                // Where it was found (e.g. "convention", "env")
};

/// Search well-known paths for a client certificate and private key pair.
///
/// Priority order:
///   1. YUZU_CLIENT_CERT / YUZU_CLIENT_KEY environment variables
///   2. /etc/yuzu/agent.pem + /etc/yuzu/agent-key.pem
///   3. /etc/pki/tls/certs/yuzu-agent.pem + /etc/pki/tls/private/yuzu-agent.pem (RHEL)
///   4. /etc/ssl/certs/yuzu-agent.pem + /etc/ssl/private/yuzu-agent.pem (Debian)
///
/// Returns std::nullopt if no valid cert+key pair is found.
/// On Windows, only checks the environment variable path (use --cert-store instead).
YUZU_EXPORT std::optional<DiscoveredCert> discover_client_cert();

}  // namespace yuzu::agent
