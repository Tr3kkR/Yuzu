#pragma once

#include <yuzu/plugin.hpp>

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace yuzu::agent {

struct Config {
    std::string              server_address;     // e.g. "server.example.com:50051"
    std::string              agent_id;           // Stable UUID; generated on first run if empty
    std::filesystem::path    plugin_dir;         // Directory to scan for plugin .so/.dll
    std::filesystem::path    data_dir;           // Directory for persistent state (agent.db)
    std::chrono::seconds     heartbeat_interval{30};
    bool                     tls_enabled{true};
    std::filesystem::path    tls_ca_cert;        // PEM CA certificate for server verification
    std::filesystem::path    tls_client_cert;    // Optional mTLS client cert
    std::filesystem::path    tls_client_key;     // Optional mTLS client key
    std::string              enrollment_token;   // Pre-shared enrollment token (Tier 2)
    std::string              log_level{"info"};  // Current log level
    bool                     debug_mode{false};  // Debug mode flag (diagnostic features)
    bool                     verbose_logging{false}; // Verbose logging flag
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
};

}  // namespace yuzu::agent
