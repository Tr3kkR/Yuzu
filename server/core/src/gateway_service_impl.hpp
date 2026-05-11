#pragma once

/// @file gateway_service_impl.hpp
/// GatewayUpstream service handlers: ProxyRegister, BatchHeartbeat,
/// ProxyInventory, NotifyStreamStatus.
///
/// As of #376 PR 1c-5 the class no longer inherits from
/// `gw::GatewayUpstream::Service`. Handlers take fully-typed proto messages
/// + `transport::CallContext` and are registered with a
/// `transport::ServerListener` via `register_with()`. The wire format is
/// unchanged — both backends (grpc, msquic) speak the same proto envelope
/// under the lift. Same convention as `AgentServiceImpl` (PR 1c-2).

#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>

#include <spdlog/spdlog.h>

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/transport/transport.hpp>
#include "agent.pb.h"
#include "gateway.pb.h"
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

class GatewayUpstreamServiceImpl {
public:
    GatewayUpstreamServiceImpl(AgentRegistry& registry, EventBus& bus, auth::AuthManager& auth_mgr,
                               auth::AutoApproveEngine& auto_approve,
                               yuzu::MetricsRegistry* metrics = nullptr,
                               AgentHealthStore* health_store = nullptr);

    void set_mgmt_group_store(ManagementGroupStore* store) { mgmt_group_store_ = store; }
    void set_inventory_store(InventoryStore* store) { inventory_store_ = store; }

    /// Register this service's handlers against the transport listener.
    /// Wire-equivalent with the pre-#376 `grpc::ServerBuilder::RegisterService`
    /// path. Idempotent only relative to one listener instance — the
    /// listener itself rejects duplicate method names.
    void register_with(::yuzu::transport::ServerListener& listener);

    ::yuzu::transport::Status ProxyRegister(const ::yuzu::transport::CallContext& ctx,
                                            const pb::RegisterRequest& request,
                                            pb::RegisterResponse& response);

    ::yuzu::transport::Status BatchHeartbeat(const ::yuzu::transport::CallContext& ctx,
                                             const gw::BatchHeartbeatRequest& request,
                                             gw::BatchHeartbeatResponse& response);

    ::yuzu::transport::Status ProxyInventory(const ::yuzu::transport::CallContext& ctx,
                                             const pb::InventoryReport& request,
                                             pb::InventoryAck& response);

    ::yuzu::transport::Status NotifyStreamStatus(const ::yuzu::transport::CallContext& ctx,
                                                 const gw::StreamStatusNotification& request,
                                                 gw::StreamStatusAck& response);

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

} // namespace yuzu::server::detail
