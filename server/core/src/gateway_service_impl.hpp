#pragma once

/// @file gateway_service_impl.hpp
/// gRPC GatewayUpstream service: ProxyRegister, BatchHeartbeat, ProxyInventory.

#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>

#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include "agent.grpc.pb.h"
#include "gateway.grpc.pb.h"
#include "management.grpc.pb.h"
#include "agent_registry.hpp"
#include "event_bus.hpp"

// Forward declarations
namespace yuzu::server {
class ManagementGroupStore;
class InventoryStore;
} // namespace yuzu::server

namespace yuzu::server::detail {

namespace gw = ::yuzu::gateway::v1;
namespace pb = ::yuzu::agent::v1;

class GatewayUpstreamServiceImpl : public gw::GatewayUpstream::Service {
public:
    GatewayUpstreamServiceImpl(AgentRegistry& registry, EventBus& bus, auth::AuthManager& auth_mgr,
                               auth::AutoApproveEngine& auto_approve,
                               yuzu::MetricsRegistry* metrics = nullptr,
                               AgentHealthStore* health_store = nullptr);

    void set_mgmt_group_store(ManagementGroupStore* store) { mgmt_group_store_ = store; }
    void set_inventory_store(InventoryStore* store) { inventory_store_ = store; }

    grpc::Status ProxyRegister(grpc::ServerContext* context, const pb::RegisterRequest* request,
                               pb::RegisterResponse* response) override;

    grpc::Status BatchHeartbeat(grpc::ServerContext* context,
                                const gw::BatchHeartbeatRequest* request,
                                gw::BatchHeartbeatResponse* response) override;

    grpc::Status ProxyInventory(grpc::ServerContext* context,
                                const pb::InventoryReport* request,
                                pb::InventoryAck* response) override;

    grpc::Status NotifyStreamStatus(grpc::ServerContext* context,
                                    const gw::StreamStatusNotification* request,
                                    gw::StreamStatusAck* response) override;

    // Status accessors for dashboard
    std::size_t session_count() const;

private:
    AgentRegistry& registry_;
    EventBus& bus_;
    auth::AuthManager& auth_mgr_;
    auth::AutoApproveEngine& auto_approve_;
    yuzu::MetricsRegistry* metrics_{nullptr};
    AgentHealthStore* health_store_{nullptr};
    ManagementGroupStore* mgmt_group_store_{nullptr};
    InventoryStore* inventory_store_{nullptr};

    // Map of gateway session_id -> agent_id for validation.
    mutable std::mutex sessions_mu_;
    std::unordered_map<std::string, std::string> gateway_sessions_;
};

// -- ManagementServiceImpl (placeholder) --------------------------------------

class ManagementServiceImpl : public ::yuzu::server::v1::ManagementService::Service {
public:
    // Placeholder.
};

} // namespace yuzu::server::detail
