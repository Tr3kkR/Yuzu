#pragma once

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <filesystem>
#include <optional>
#include <span>
#include <string>

namespace yuzu::agent {

/// Result of automatic certificate discovery from well-known filesystem paths.
struct YUZU_EXPORT DiscoveredCert {
    std::filesystem::path cert_path; // PEM certificate file
    std::filesystem::path key_path;  // PEM private key file
    std::string source;              // Where it was found (e.g. "convention", "env")
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

/// Discover the install CA at the standard shared-cert-volume path.
///
/// Secure-by-default (PKI #1289 / #1314): when TLS is enabled but no `--ca-cert`
/// was given, the agent promotes the discovered path into its effective CA so the
/// provisioning gate enrolls for a per-agent client leaf instead of silently
/// settling for server-authenticated-only TLS. The standard path is
/// `/etc/yuzu/certs/default-ca.pem` (POSIX) / `C:/ProgramData/Yuzu/certs/default-ca.pem`
/// (Windows). Returns the path only if it exists and is a non-empty regular file;
/// std::nullopt otherwise (the caller then falls back to the system trust store).
YUZU_EXPORT std::optional<std::filesystem::path> discover_install_ca_path();

/// Test seam for discover_install_ca_path(): scans the supplied candidate paths in
/// order and returns the first that exists and is a non-empty regular file (a
/// symlink at the leaf is rejected). The no-argument overload above forwards the
/// platform's standard install path(s) here. NOTE (#1314 L-2): callers must pass
/// only TRUSTED, code-controlled paths — there is no traversal/`..` guard, so this
/// overload must never be wired to operator/env/config-supplied input as-is.
YUZU_EXPORT std::optional<std::filesystem::path>
discover_install_ca_path(std::span<const std::filesystem::path> candidates);

} // namespace yuzu::agent
