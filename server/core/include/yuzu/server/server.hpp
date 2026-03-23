#pragma once

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>

namespace yuzu::server::auth {
class AuthManager;
}

namespace yuzu::server {

struct Config {
    std::string listen_address{"0.0.0.0:50051"};     // Agent-facing gRPC
    std::string management_address{"0.0.0.0:50052"}; // Operator-facing gRPC
    std::string web_address{"127.0.0.1"};             // HTMX web UI bind address
    int web_port{8080};                              // HTMX web UI port

    bool tls_enabled{true};
    std::filesystem::path tls_server_cert; // PEM server certificate
    std::filesystem::path tls_server_key;  // PEM server private key
    std::filesystem::path tls_ca_cert;     // For mTLS agent verification
    bool allow_one_way_tls{false};         // Permit TLS without client cert verification

    // Optional management listener TLS override.
    // If left empty, management reuses the agent listener credentials.
    std::filesystem::path mgmt_tls_server_cert;
    std::filesystem::path mgmt_tls_server_key;
    std::filesystem::path mgmt_tls_ca_cert;

    // Session management
    std::chrono::seconds session_timeout{
        90}; // Agents disconnected after this many seconds without heartbeat
    std::size_t max_agents{10'000};

    // Authentication
    std::filesystem::path auth_config_path; // yuzu-server.cfg path

    // Gateway upstream (Erlang gateway → C++ server control plane)
    std::string gateway_upstream_address; // Empty = disabled; e.g. "0.0.0.0:50053"
    bool gateway_mode{false};             // When true, relax peer-mismatch in Subscribe

    // NVD CVE feed
    std::string nvd_api_key; // Optional NVD API key for higher rate limits
    std::string nvd_proxy;   // HTTP proxy for NVD API (e.g. "http://proxy:8080")
    std::chrono::seconds nvd_sync_interval{4 * 3600}; // Default: 4 hours
    bool nvd_sync_enabled{true};

    // OTA agent updates
    std::filesystem::path
        update_dir;         // Directory for agent binaries (default: <config_dir>/agent-updates/)
    bool ota_enabled{true}; // Master switch for OTA updates

    // HTTPS for web dashboard
    bool https_enabled{true};
    int https_port{8443};
    std::filesystem::path https_cert_path;
    std::filesystem::path https_key_path;
    bool https_redirect{true}; // HTTP→HTTPS 301 redirect

    // Certificate hot-reload
    bool cert_reload_enabled{true};       // Auto-reload when cert/key files change on disk
    int cert_reload_interval_seconds{60}; // Polling interval in seconds

    // OIDC SSO
    std::string oidc_issuer;        // e.g. "https://login.microsoftonline.com/{tenant}/v2.0"
    std::string oidc_client_id;     // App registration client ID
    std::string oidc_client_secret; // Client secret (required for Entra web platform)
    std::string oidc_redirect_uri;  // Callback URL (auto-computed from web port if empty)
    std::string oidc_admin_group;   // Entra group ID that maps to admin role

    // Response persistence
    int response_retention_days{90};

    // Audit trail
    int audit_retention_days{365};

    // Analytics
    bool analytics_enabled{true};
    int analytics_drain_interval_seconds{10};
    int analytics_batch_size{100};
    std::string clickhouse_url; // empty = disabled
    std::string clickhouse_database{"yuzu"};
    std::string clickhouse_table{"yuzu_events"};
    std::string clickhouse_username;
    std::string clickhouse_password;
    std::filesystem::path analytics_jsonl_path; // empty = disabled

    // Metrics
    bool metrics_require_auth{true}; // Require auth for remote /metrics access

    // Rate limiting
    int rate_limit{100};      // Max API requests/second per IP
    int login_rate_limit{10}; // Max login attempts/second per IP
};

/**
 * Server manages inbound agent connections and exposes a management gRPC API.
 */
class Server {
public:
    virtual ~Server() = default;

    [[nodiscard]] static std::unique_ptr<Server> create(Config config, auth::AuthManager& auth_mgr);

    /** Block and serve until stop() is called. */
    virtual void run() = 0;

    /** Graceful shutdown. Thread-safe. */
    virtual void stop() noexcept = 0;
};

} // namespace yuzu::server
