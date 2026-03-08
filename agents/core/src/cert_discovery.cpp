#include <yuzu/agent/cert_discovery.hpp>

#include <spdlog/spdlog.h>

#include <array>
#include <cstdlib>
#include <filesystem>
#include <utility>

namespace yuzu::agent {

namespace {

struct CertKeyPair {
    const char* cert;
    const char* key;
    const char* source;
};

bool file_exists_and_readable(const std::filesystem::path& p) {
    std::error_code ec;
    auto status = std::filesystem::status(p, ec);
    if (ec) return false;
    return std::filesystem::is_regular_file(status);
}

}  // anonymous namespace

std::optional<DiscoveredCert> discover_client_cert() {
    // 1. Environment variables (all platforms)
    const char* env_cert = std::getenv("YUZU_CLIENT_CERT");
    const char* env_key  = std::getenv("YUZU_CLIENT_KEY");
    if (env_cert && env_key && env_cert[0] && env_key[0]) {
        std::filesystem::path cert_path{env_cert};
        std::filesystem::path key_path{env_key};
        if (file_exists_and_readable(cert_path) && file_exists_and_readable(key_path)) {
            spdlog::info("Auto-discovered client cert from environment: {}", cert_path.string());
            return DiscoveredCert{
                .cert_path = std::move(cert_path),
                .key_path  = std::move(key_path),
                .source    = "env"
            };
        }
        spdlog::debug("YUZU_CLIENT_CERT/KEY set but files not readable");
    }

#ifndef _WIN32
    // 2-4. Well-known paths (Linux/macOS only)
    static constexpr std::array<CertKeyPair, 3> kConventionPaths = {{
        // Yuzu-specific path (works with FreeIPA certmonger provisioning)
        {"/etc/yuzu/agent.pem", "/etc/yuzu/agent-key.pem", "convention:/etc/yuzu"},
        // RHEL / CentOS / Fedora (standard PKI paths, works with certmonger)
        {"/etc/pki/tls/certs/yuzu-agent.pem", "/etc/pki/tls/private/yuzu-agent.pem", "convention:/etc/pki"},
        // Debian / Ubuntu
        {"/etc/ssl/certs/yuzu-agent.pem", "/etc/ssl/private/yuzu-agent.pem", "convention:/etc/ssl"},
    }};

    for (const auto& pair : kConventionPaths) {
        std::filesystem::path cert_path{pair.cert};
        std::filesystem::path key_path{pair.key};

        if (file_exists_and_readable(cert_path) && file_exists_and_readable(key_path)) {
            spdlog::info("Auto-discovered client cert at {}", cert_path.string());
            return DiscoveredCert{
                .cert_path = std::move(cert_path),
                .key_path  = std::move(key_path),
                .source    = pair.source
            };
        }
        spdlog::debug("Cert discovery: {} not found", pair.cert);
    }
#else
    spdlog::debug("Cert discovery: skipping filesystem paths on Windows (use --cert-store)");
#endif

    return std::nullopt;
}

}  // namespace yuzu::agent
