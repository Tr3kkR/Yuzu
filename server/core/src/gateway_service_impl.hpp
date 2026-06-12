#pragma once

/// @file gateway_service_impl.hpp
/// gRPC GatewayUpstream service: ProxyRegister, BatchHeartbeat, ProxyInventory.

#include <cstddef>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

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
class FleetTopologyStore;
class HeartbeatIngestion;
class AnalyticsEventStore;
class AuditStore;
class GuaranteedStateStore;
class BlastRadiusDetector;
class DexAlertRouter;
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
    // PR 10 / UAT 2026-05-12: gateway-proxied heartbeats carry the
    // same fleet_snapshot_json field as direct heartbeats. Wire the
    // topology store so BatchHeartbeat ingests pushes from agents that
    // connect via the gateway. Without this hook, gateway-routed
    // fleets would still see /viz/fleet/topology fall back to the
    // dispatch path. nullptr disables for tests.
    void set_fleet_topology_store(FleetTopologyStore* store) { fleet_topology_store_ = store; }

    /// #1000 / arch-S2: shared HeartbeatIngestion (see AgentServiceImpl).
    void set_heartbeat_ingestion(HeartbeatIngestion* hi) { heartbeat_ingestion_ = hi; }

    /// W1.4 / #827: AnalyticsEventStore for the gateway enrollment path's
    /// `agent.enrollment_*` events (mirrors AgentServiceImpl's direct
    /// path). Without this set, the proxied-enrollment surface had no
    /// audit/analytics emission at all — a gap relative to direct
    /// connections that #827 closes alongside the race fix.
    void set_analytics_store(AnalyticsEventStore* store) { analytics_store_ = store; }

    /// W1.4 / #827: AuditStore wired for enrollment-token consume rows
    /// on the gateway-proxied path. See AgentServiceImpl::set_audit_store
    /// for the SOC 2 / wire-collapse rationale — same contract here.
    void set_audit_store(AuditStore* store) { audit_store_ = store; }

    /// Guardian Half B: store for ingesting unsolicited "__guard__" drift
    /// events forwarded from gateway-connected agents via
    /// ForwardGuardianMessage. Same store AgentServiceImpl uses on the direct
    /// Subscribe path; both call the shared ingest_guardian_response so they
    /// cannot diverge. nullptr disables ingest (tests / store-less configs).
    void set_guaranteed_state_store(GuaranteedStateStore* store) {
        guaranteed_state_store_ = store;
    }

    /// Fleet-wide DEX incident detector (blast radius, coverage-map D3) — the
    /// shared ingest feeds it ruleless observations from gateway-connected
    /// agents, same as the direct path. nullptr disables detection.
    void set_blast_radius_detector(BlastRadiusDetector* detector) {
        blast_radius_detector_ = detector;
    }

    /// Operator-routed per-signal alerting (coverage-map F1) — fed alongside
    /// the blast-radius detector at the same ingest chokepoint. nullptr
    /// disables routing.
    void set_dex_alert_router(DexAlertRouter* router) { dex_alert_router_ = router; }

    /// PR5d: per-agent CSR signer. Same signature as
    /// AgentServiceImpl::AgentCertSigner; server.cpp wires BOTH to the SAME
    /// `sign_agent_csr`, so they cannot semantically drift (a type change breaks
    /// both wirings at compile time). Lets ProxyRegister issue a per-agent client
    /// cert to a gateway-enrolled agent exactly as the direct Register path does —
    /// closing the gap where through-gateway agents never received one. nullptr
    /// (default) = no issuance (tests / CA inactive), identical to direct.
    using AgentCertSigner = std::function<std::optional<std::pair<std::string, std::string>>(
        const std::string& csr_pem, const std::string& agent_id)>;
    void set_agent_cert_signer(AgentCertSigner signer) { agent_cert_signer_ = std::move(signer); }

    grpc::Status ProxyRegister(grpc::ServerContext* context, const pb::RegisterRequest* request,
                               pb::RegisterResponse* response) override;

    grpc::Status BatchHeartbeat(grpc::ServerContext* context,
                                const gw::BatchHeartbeatRequest* request,
                                gw::BatchHeartbeatResponse* response) override;

    grpc::Status ProxyInventory(grpc::ServerContext* context, const pb::InventoryReport* request,
                                pb::InventoryAck* response) override;

    grpc::Status NotifyStreamStatus(grpc::ServerContext* context,
                                    const gw::StreamStatusNotification* request,
                                    gw::StreamStatusAck* response) override;

    grpc::Status ForwardGuardianMessage(grpc::ServerContext* context,
                                        const gw::ForwardGuardianRequest* request,
                                        gw::ForwardGuardianAck* response) override;

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
    FleetTopologyStore* fleet_topology_store_{nullptr};
    HeartbeatIngestion* heartbeat_ingestion_{nullptr};
    AnalyticsEventStore* analytics_store_{nullptr};
    AuditStore* audit_store_{nullptr};
    GuaranteedStateStore* guaranteed_state_store_{nullptr};
    BlastRadiusDetector* blast_radius_detector_{nullptr};
    DexAlertRouter* dex_alert_router_{nullptr};
    AgentCertSigner agent_cert_signer_;

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
