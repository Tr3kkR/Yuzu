#pragma once

#include <yuzu/plugin.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace yuzu::agent {

struct Config {
    std::string server_address;       // e.g. "server.example.com:50051"
    std::string agent_id;             // Stable UUID; generated on first run if empty
    std::filesystem::path plugin_dir; // Directory to scan for plugin .so/.dll
    std::filesystem::path data_dir;   // Directory for persistent state (agent.db)
    std::chrono::seconds heartbeat_interval{30};
    bool tls_enabled{true};
    std::filesystem::path tls_ca_cert;     // PEM CA certificate for server verification
    std::filesystem::path tls_client_cert; // Optional mTLS client cert (PEM file)
    std::filesystem::path tls_client_key;  // Optional mTLS client key (PEM file)
    std::string cert_store;                // Windows cert store name (e.g. "MY")
    std::string cert_subject;              // Subject CN match for cert store lookup
    std::string cert_thumbprint;           // SHA-1 thumbprint for cert store lookup
    bool cert_auto_discovery{true};        // Auto-discover certs from well-known paths
    // PKI #1303: fail-closed posture. When TLS is on but NO CA can be pinned (no
    // --ca-cert AND no install CA auto-discovered, #1289), the agent refuses to start
    // rather than silently falling back to the system trust store (which does NOT
    // trust a Yuzu self-signed install CA — a fail-open MITM window on the command
    // fan-out plane). Set this ONLY when the server leaf chains to a CA already in the
    // system store (public CA / corporate root) — a deliberate operator choice.
    bool tls_allow_system_trust{false};    // --tls-system-roots / YUZU_TLS_SYSTEM_ROOTS
    // PKI PR3: directory for the auto-provisioned per-agent mTLS credential
    // (agent-client.{key,pem} + agent-ca.pem). When tls is enabled with a CA but
    // no explicit client cert/store, the agent generates a CSR at enrollment,
    // persists the server-issued leaf here (key 0600), and reconnects with mTLS.
    // Empty → defaults to data_dir/"certs". --no-auto-provision-cert disables it.
    std::filesystem::path cert_dir;
    bool auto_provision_cert{true};        // PKI PR3: enable CSR-at-enrollment flow
    std::string enrollment_token;          // Pre-shared enrollment token (Tier 2)
    std::string log_level{"info"};         // Current log level
    bool debug_mode{false};                // Debug mode flag (diagnostic features)
    bool verbose_logging{false};           // Verbose logging flag

    // Plugin security
    std::filesystem::path plugin_allowlist;     // --plugin-allowlist (sha256sum-format file)
    std::filesystem::path plugin_trust_bundle;  // --plugin-trust-bundle (PEM CA bundle for code-sig)
    bool plugin_require_signature{false};       // --plugin-require-signature

    // OTA updates
    bool auto_update{true};                               // --no-auto-update disables
    std::chrono::seconds update_check_interval{6 * 3600}; // --update-check-interval

    // Guardian DEX (Digital Experience) — fleet-wide crash recorder (slice 1)
    bool dex_disable{false}; // --dex-disable / YUZU_AGENT_DEX_DISABLE: deploy-time opt-out;
                             // when set, the crash recorder never arms and no crash
                             // telemetry is collected.
};

/**
 * Agent is the main object that manages the plugin lifecycle, gRPC connection
 * to the server, and the heartbeat/command dispatch loop.
 *
 * Usage:
 *   auto agent = yuzu::agent::Agent::create(config);
 *   agent->run();  // blocks until shutdown is requested
 */
class YUZU_EXPORT Agent {
public:
    virtual ~Agent() = default;

    [[nodiscard]] static std::unique_ptr<Agent> create(Config config);

    /** Block and run until stop() is called or a fatal error occurs. */
    virtual void run() = 0;

    /** Signal the agent to gracefully shut down. Thread-safe. */
    virtual void stop() noexcept = 0;

    /** Returns the stable agent ID (may be auto-generated). */
    [[nodiscard]] virtual std::string_view agent_id() const noexcept = 0;

    /** Returns the list of loaded plugins. */
    [[nodiscard]] virtual std::vector<std::string> loaded_plugins() const = 0;

    /**
     * True if run() returned because of a fatal STARTUP failure (e.g. the #1303
     * fail-closed TLS posture refused to connect with no pinnable CA), as opposed
     * to a normal stop(). main() maps it to a non-zero exit so systemd Restart= /
     * Docker / Windows SCM observe the failure instead of a silent EXIT_SUCCESS.
     */
    [[nodiscard]] virtual bool startup_failed() const noexcept = 0;
};

} // namespace yuzu::agent
