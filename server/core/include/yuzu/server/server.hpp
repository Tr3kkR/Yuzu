#pragma once

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>

namespace yuzu::server {

struct Config {
    std::string           listen_address{"0.0.0.0:50051"};     // Agent-facing gRPC
    std::string           management_address{"0.0.0.0:50052"}; // Operator-facing gRPC
    std::string           web_address{"0.0.0.0"};              // HTMX web UI bind address
    int                   web_port{8080};                       // HTMX web UI port

    bool                  tls_enabled{true};
    std::filesystem::path tls_server_cert;   // PEM server certificate
    std::filesystem::path tls_server_key;    // PEM server private key
    std::filesystem::path tls_ca_cert;       // For mTLS agent verification
    bool                  allow_one_way_tls{false}; // Permit TLS without client cert verification

    // Optional management listener TLS override.
    // If left empty, management reuses the agent listener credentials.
    std::filesystem::path mgmt_tls_server_cert;
    std::filesystem::path mgmt_tls_server_key;
    std::filesystem::path mgmt_tls_ca_cert;

    // Session management
    std::chrono::seconds  session_timeout{90};  // Agents disconnected after this many seconds without heartbeat
    std::size_t           max_agents{10'000};
};

/**
 * Server manages inbound agent connections and exposes a management gRPC API.
 */
class Server {
public:
    virtual ~Server() = default;

    [[nodiscard]] static std::unique_ptr<Server> create(Config config);

    /** Block and serve until stop() is called. */
    virtual void run() = 0;

    /** Graceful shutdown. Thread-safe. */
    virtual void stop() noexcept = 0;
};

}  // namespace yuzu::server
