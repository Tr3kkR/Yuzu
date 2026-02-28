#include <yuzu/server/server.hpp>

#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <spdlog/spdlog.h>

// Generated headers (produced at build time)
// #include "yuzu/agent/v1/agent.grpc.pb.h"
// #include "yuzu/server/v1/management.grpc.pb.h"

#include <atomic>
#include <memory>
#include <string>

namespace yuzu::server {

namespace {

// ── AgentServiceImpl ──────────────────────────────────────────────────────────
// Implements the agent-facing gRPC service.
// TODO: wire up protobuf stub once codegen is integrated into the build.

class AgentServiceImpl /* : public yuzu::agent::v1::AgentService::Service */ {
public:
    // grpc::Status Register(...) { ... }
    // grpc::Status Heartbeat(...) { ... }
    // grpc::Status ExecuteCommand(...) { ... }
};

// ── ManagementServiceImpl ─────────────────────────────────────────────────────
// Implements the operator-facing management gRPC service.

class ManagementServiceImpl /* : public yuzu::server::v1::ManagementService::Service */ {
public:
    // grpc::Status ListAgents(...) { ... }
    // grpc::Status SendCommand(...) { ... }
    // grpc::Status WatchEvents(...) { ... }
};

}  // anonymous namespace

// ── ServerImpl ────────────────────────────────────────────────────────────────

class ServerImpl final : public Server {
public:
    explicit ServerImpl(Config cfg) : cfg_{std::move(cfg)} {}

    void run() override {
        grpc::EnableDefaultHealthCheckService(true);

        grpc::ServerBuilder agent_builder;
        agent_builder.AddListeningPort(
            cfg_.listen_address,
            cfg_.tls_enabled
                ? build_server_credentials()
                : grpc::InsecureServerCredentials()
        );
        // agent_builder.RegisterService(&agent_service_);

        grpc::ServerBuilder mgmt_builder;
        mgmt_builder.AddListeningPort(
            cfg_.management_address,
            grpc::InsecureServerCredentials()  // TODO: operator auth
        );
        // mgmt_builder.RegisterService(&mgmt_service_);

        agent_server_ = agent_builder.BuildAndStart();
        mgmt_server_  = mgmt_builder.BuildAndStart();

        spdlog::info("Yuzu Server listening on {} (agents) and {} (management)",
            cfg_.listen_address, cfg_.management_address);

        agent_server_->Wait();
    }

    void stop() noexcept override {
        spdlog::info("Shutting down server...");
        if (agent_server_) agent_server_->Shutdown();
        if (mgmt_server_)  mgmt_server_->Shutdown();
    }

private:
    [[nodiscard]] std::shared_ptr<grpc::ServerCredentials> build_server_credentials() const {
        grpc::SslServerCredentialsOptions ssl_opts;
        // TODO: load from cfg_.tls_server_cert / tls_server_key
        return grpc::SslServerCredentials(ssl_opts);
    }

    Config                            cfg_;
    AgentServiceImpl                  agent_service_;
    ManagementServiceImpl             mgmt_service_;
    std::unique_ptr<grpc::Server>     agent_server_;
    std::unique_ptr<grpc::Server>     mgmt_server_;
};

std::unique_ptr<Server> Server::create(Config config) {
    return std::make_unique<ServerImpl>(std::move(config));
}

}  // namespace yuzu::server
