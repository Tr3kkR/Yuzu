#include "gateway_service_impl.hpp"

#include "inventory_store.hpp"
#include "management_group_store.hpp"

namespace yuzu::server::detail {

// -- Constructor --------------------------------------------------------------

GatewayUpstreamServiceImpl::GatewayUpstreamServiceImpl(
    AgentRegistry& registry, EventBus& bus, auth::AuthManager& auth_mgr,
    auth::AutoApproveEngine& auto_approve, yuzu::MetricsRegistry* metrics,
    AgentHealthStore* health_store)
    : registry_(registry), bus_(bus), auth_mgr_(auth_mgr), auto_approve_(auto_approve),
      metrics_(metrics), health_store_(health_store) {}

// -- ProxyRegister ------------------------------------------------------------

grpc::Status GatewayUpstreamServiceImpl::ProxyRegister(grpc::ServerContext* /*context*/,
                                                       const pb::RegisterRequest* request,
                                                       pb::RegisterResponse* response) {
    const auto& info = request->info();

    // -- Tiered enrollment (same logic as AgentServiceImpl::Register) ----------
    const auto& enrollment_token = request->enrollment_token();

    if (!enrollment_token.empty()) {
        if (!auth_mgr_.validate_enrollment_token(enrollment_token)) {
            spdlog::warn("[gateway] Agent {} presented invalid enrollment token",
                         info.agent_id());
            response->set_accepted(false);
            response->set_reject_reason("invalid, expired, or exhausted enrollment token");
            response->set_enrollment_status("denied");
            return grpc::Status::OK;
        }
        spdlog::info("[gateway] Agent {} auto-enrolled via enrollment token", info.agent_id());
        auth_mgr_.remove_pending_agent(info.agent_id());
    } else {
        // Auto-approve policies (no peer IP available from gateway yet)
        auth::ApprovalContext approval_ctx;
        approval_ctx.hostname = info.hostname();
        approval_ctx.attestation_provider = request->attestation_provider();

        auto matched_rule = auto_approve_.evaluate(approval_ctx);
        if (!matched_rule.empty()) {
            spdlog::info("[gateway] Agent {} auto-approved by policy: {}", info.agent_id(),
                         matched_rule);
            auth_mgr_.remove_pending_agent(info.agent_id());
        } else {
            // Tier 1: pending queue
            auto pending_status = auth_mgr_.get_pending_status(info.agent_id());

            if (!pending_status) {
                auth_mgr_.add_pending_agent(info.agent_id(), info.hostname(),
                                            info.platform().os(), info.platform().arch(),
                                            info.agent_version());

                response->set_accepted(false);
                response->set_reject_reason("awaiting admin approval");
                response->set_enrollment_status("pending");
                bus_.publish("pending-agent", info.agent_id());
                spdlog::info("[gateway] Agent {} placed in pending queue", info.agent_id());
                return grpc::Status::OK;
            }

            switch (*pending_status) {
            case auth::PendingStatus::pending:
                response->set_accepted(false);
                response->set_reject_reason("still awaiting admin approval");
                response->set_enrollment_status("pending");
                return grpc::Status::OK;
            case auth::PendingStatus::denied:
                response->set_accepted(false);
                response->set_reject_reason("enrollment denied by administrator");
                response->set_enrollment_status("denied");
                return grpc::Status::OK;
            case auth::PendingStatus::approved:
                spdlog::info("[gateway] Agent {} enrolled (admin-approved)", info.agent_id());
                break;
            }
        }
    }

    // -- Enrolled -- register the agent ----------------------------------------
    registry_.register_agent(info);
    // Auto-add to root management group
    if (mgmt_group_store_ && mgmt_group_store_->is_open())
        mgmt_group_store_->add_member(ManagementGroupStore::kRootGroupId, info.agent_id());

    auto session_id =
        "gw-session-" + auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(16));
    response->set_session_id(session_id);
    response->set_accepted(true);
    response->set_enrollment_status("enrolled");

    {
        std::lock_guard lock(sessions_mu_);
        gateway_sessions_[session_id] = info.agent_id();
    }

    spdlog::info("[gateway] ProxyRegister succeeded: agent={}, session={}", info.agent_id(),
                 session_id);
    return grpc::Status::OK;
}

// -- BatchHeartbeat -----------------------------------------------------------

grpc::Status GatewayUpstreamServiceImpl::BatchHeartbeat(grpc::ServerContext* /*context*/,
                                                        const gw::BatchHeartbeatRequest* request,
                                                        gw::BatchHeartbeatResponse* response) {
    int acked = 0;
    for (const auto& hb : request->heartbeats()) {
        // Validate that the session is known
        std::string agent_id;
        {
            std::lock_guard lock(sessions_mu_);
            auto it = gateway_sessions_.find(hb.session_id());
            if (it != gateway_sessions_.end()) {
                agent_id = it->second;
            }
        }
        if (agent_id.empty()) {
            spdlog::debug("[gateway] BatchHeartbeat: unknown session {}", hb.session_id());
            continue;
        }
        // Store agent health from piggybacked status_tags
        if (health_store_) {
            health_store_->upsert(agent_id, hb.status_tags());
        }
        if (metrics_) {
            metrics_->counter("yuzu_heartbeats_received_total", {{"via", "gateway"}})
                .increment();
        }
        ++acked;
    }

    response->set_acknowledged_count(acked);
    spdlog::debug("[gateway] BatchHeartbeat from node '{}': {}/{} acked",
                  request->gateway_node(), acked, request->heartbeats_size());
    return grpc::Status::OK;
}

// -- ProxyInventory -----------------------------------------------------------

grpc::Status GatewayUpstreamServiceImpl::ProxyInventory(grpc::ServerContext* /*context*/,
                                                        const pb::InventoryReport* request,
                                                        pb::InventoryAck* response) {
    std::string agent_id;
    {
        std::lock_guard lock(sessions_mu_);
        auto it = gateway_sessions_.find(request->session_id());
        if (it != gateway_sessions_.end()) {
            agent_id = it->second;
        }
    }
    if (agent_id.empty()) {
        spdlog::warn("[gateway] ProxyInventory: unknown session {}", request->session_id());
        response->set_received(false);
        return grpc::Status::OK;
    }

    // Persist inventory data via InventoryStore (Issue 7.17)
    if (inventory_store_ && inventory_store_->is_open()) {
        int64_t collected_epoch = 0;
        if (request->has_collected_at()) {
            collected_epoch = request->collected_at().millis_epoch() / 1000;
        }
        for (const auto& [plugin_name, data_bytes] : request->plugin_data()) {
            std::string json_str(data_bytes.begin(), data_bytes.end());
            inventory_store_->upsert(agent_id, plugin_name, json_str, collected_epoch);
        }
        spdlog::info("[gateway] ProxyInventory persisted for agent={}, plugins={}",
                      agent_id, request->plugin_data_size());
    } else {
        spdlog::info("[gateway] ProxyInventory received for agent={}, plugins={} "
                      "(inventory store not available)",
                      agent_id, request->plugin_data_size());
    }
    response->set_received(true);
    return grpc::Status::OK;
}

// -- NotifyStreamStatus -------------------------------------------------------

grpc::Status GatewayUpstreamServiceImpl::NotifyStreamStatus(
    grpc::ServerContext* /*context*/, const gw::StreamStatusNotification* request,
    gw::StreamStatusAck* response) {
    const auto& agent_id = request->agent_id();
    const auto& session_id = request->session_id();

    // Verify session
    {
        std::lock_guard lock(sessions_mu_);
        auto it = gateway_sessions_.find(session_id);
        if (it == gateway_sessions_.end() || it->second != agent_id) {
            spdlog::warn("[gateway] NotifyStreamStatus: unknown session {} for agent {}",
                         session_id, agent_id);
            response->set_acknowledged(false);
            return grpc::Status::OK;
        }
    }

    switch (request->event()) {
    case gw::StreamStatusNotification::CONNECTED:
        registry_.set_gateway_node(agent_id, request->gateway_node());
        spdlog::info("[gateway] Agent {} stream CONNECTED at gateway node '{}'", agent_id,
                     request->gateway_node());
        break;

    case gw::StreamStatusNotification::DISCONNECTED:
        registry_.clear_stream(agent_id);
        registry_.remove_agent(agent_id);
        {
            std::lock_guard lock(sessions_mu_);
            gateway_sessions_.erase(session_id);
        }
        spdlog::info("[gateway] Agent {} stream DISCONNECTED at gateway node '{}'", agent_id,
                     request->gateway_node());
        break;

    default:
        spdlog::warn("[gateway] NotifyStreamStatus: unknown event {} for agent {}",
                     static_cast<int>(request->event()), agent_id);
        response->set_acknowledged(false);
        return grpc::Status::OK;
    }

    response->set_acknowledged(true);
    return grpc::Status::OK;
}

// -- session_count ------------------------------------------------------------

std::size_t GatewayUpstreamServiceImpl::session_count() const {
    std::lock_guard lock(sessions_mu_);
    return gateway_sessions_.size();
}

} // namespace yuzu::server::detail
