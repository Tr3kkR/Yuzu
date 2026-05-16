#include "gateway_service_impl.hpp"

#include <nlohmann/json.hpp>

#include "fleet_topology_store.hpp"
#include "heartbeat_ingestion.hpp"
#include "inventory_store.hpp"
#include "management_group_store.hpp"

namespace yuzu::server::detail {

// -- Constructor --------------------------------------------------------------

GatewayUpstreamServiceImpl::GatewayUpstreamServiceImpl(AgentRegistry& registry, EventBus& bus,
                                                       auth::AuthManager& auth_mgr,
                                                       auth::AutoApproveEngine& auto_approve,
                                                       yuzu::MetricsRegistry* metrics,
                                                       AgentHealthStore* health_store)
    : registry_(registry), bus_(bus), auth_mgr_(auth_mgr), auto_approve_(auto_approve),
      metrics_(metrics), health_store_(health_store) {}

// -- ProxyRegister ------------------------------------------------------------

namespace {
/// Extract bare IP from a gRPC peer string. Duplicates AgentServiceImpl's
/// helper deliberately — this TU does not include agent_service_impl.hpp
/// and we don't want to hoist a shared helper into agent_registry just
/// for two callers. Both copies trace to the gRPC peer encoding
/// documented at `parse_address.cc`. If a third caller appears, fold
/// into a shared `peer_ip.hpp`.
std::string extract_peer_ip(std::string_view peer) {
    auto colon = peer.find(':');
    if (colon == std::string_view::npos)
        return {};
    auto scheme = peer.substr(0, colon);
    auto rest = peer.substr(colon + 1);
    if (scheme == "ipv6") {
        if (rest.empty() || rest.front() != '[')
            return {};
        auto close = rest.find(']');
        if (close == std::string_view::npos)
            return {};
        return std::string(rest.substr(1, close - 1));
    }
    if (scheme == "ipv4") {
        auto port_colon = rest.rfind(':');
        if (port_colon == std::string_view::npos)
            return std::string(rest);
        return std::string(rest.substr(0, port_colon));
    }
    return {};
}
} // namespace

grpc::Status GatewayUpstreamServiceImpl::ProxyRegister(grpc::ServerContext* context,
                                                       const pb::RegisterRequest* request,
                                                       pb::RegisterResponse* response) {
    const auto& info = request->info();

    // #826: record the gateway's peer IP as a trusted gateway. Any
    // subsequent Subscribe stream arriving from this IP under
    // `--gateway-mode` is allowed to bypass the strict per-IP register/
    // subscribe match — which is the legitimate gateway-relayed flow.
    // We capture this BEFORE the enrollment branches so even denied
    // enrollments contribute to gateway-trust discovery (the gateway is
    // still trusted regardless of whether the proxied agent enrolls).
    if (context) {
        registry_.note_trusted_gateway_peer(extract_peer_ip(context->peer()));
    }

    // -- Tiered enrollment (same logic as AgentServiceImpl::Register) ----------

    // Fast path: agent already enrolled from a prior connection
    {
        auto prior = auth_mgr_.get_pending_status(info.agent_id());
        if (prior && *prior == auth::PendingStatus::approved) {
            spdlog::info("[gateway] Agent {} re-registering (already enrolled)", info.agent_id());
            goto gw_enrolled;
        }
    }

    {
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
            if (!auth_mgr_.ensure_enrolled(info.agent_id(), info.hostname(), info.platform().os(),
                                           info.platform().arch(), info.agent_version())) {
                response->set_accepted(false);
                response->set_reject_reason("enrollment denied by administrator");
                response->set_enrollment_status("denied");
                return grpc::Status::OK;
            }
        } else {
            // Auto-approve policies (no peer IP available from gateway yet)
            auth::ApprovalContext approval_ctx;
            approval_ctx.hostname = info.hostname();
            approval_ctx.attestation_provider = request->attestation_provider();

            auto matched_rule = auto_approve_.evaluate(approval_ctx);
            if (!matched_rule.empty()) {
                spdlog::info("[gateway] Agent {} auto-approved by policy: {}", info.agent_id(),
                             matched_rule);
                if (!auth_mgr_.ensure_enrolled(info.agent_id(), info.hostname(),
                                               info.platform().os(), info.platform().arch(),
                                               info.agent_version())) {
                    response->set_accepted(false);
                    response->set_reject_reason("enrollment denied by administrator");
                    response->set_enrollment_status("denied");
                    return grpc::Status::OK;
                }
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
    } // end enrollment checks

gw_enrolled:
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

    // Store session_id on the AgentSession so session-aware cleanup works.
    // Without this, remove_agent_if_session would always no-op for gateway agents.
    registry_.map_session(session_id, info.agent_id());

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
        // #1000 / arch-S2: shared HeartbeatIngestion keeps the per-heartbeat
        // work (health upsert, metrics, fleet_snapshot push) identical to
        // the direct-heartbeat path so the two cannot drift.
        //
        // Gate 7 UP-10 — per-entry try/catch. A gateway BatchHeartbeat can
        // carry thousands of agents' heartbeats in one RPC; if ingest()
        // throws on a single entry (std::bad_alloc on a near-cap map walk,
        // a malformed payload that slips past the parser's own guard, an
        // exception out of health_store_/metrics_), an unhandled throw
        // would abort the whole RPC handler and silently drop every
        // remaining heartbeat in the batch — a single bad agent could
        // blank a gateway's entire fleet. Isolate each entry.
        if (heartbeat_ingestion_) {
            try {
                heartbeat_ingestion_->ingest(hb, agent_id, "gateway");
            } catch (const std::exception& ex) {
                spdlog::warn("[gateway] BatchHeartbeat: ingest threw for agent {} — "
                             "skipping entry, batch continues: {}",
                             agent_id, ex.what());
                continue;
            } catch (...) {
                spdlog::warn("[gateway] BatchHeartbeat: ingest threw unknown exception for "
                             "agent {} — skipping entry, batch continues",
                             agent_id);
                continue;
            }
        }
        ++acked;
    }

    response->set_acknowledged_count(acked);
    spdlog::debug("[gateway] BatchHeartbeat from node '{}': {}/{} acked", request->gateway_node(),
                  acked, request->heartbeats_size());
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
        spdlog::info("[gateway] ProxyInventory persisted for agent={}, plugins={}", agent_id,
                     request->plugin_data_size());
    } else {
        spdlog::info("[gateway] ProxyInventory received for agent={}, plugins={} "
                     "(inventory store not available)",
                     agent_id, request->plugin_data_size());
    }
    response->set_received(true);
    return grpc::Status::OK;
}

// -- NotifyStreamStatus -------------------------------------------------------

grpc::Status
GatewayUpstreamServiceImpl::NotifyStreamStatus(grpc::ServerContext* /*context*/,
                                               const gw::StreamStatusNotification* request,
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
        registry_.clear_stream_if_session(agent_id, session_id);
        registry_.remove_agent_if_session(agent_id, session_id);
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
