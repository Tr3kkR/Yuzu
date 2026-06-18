#pragma once

/**
 * heartbeat_ingestion.hpp — shared ingestion pipeline for heartbeat payloads.
 *
 * #1000 / arch-S2: both AgentServiceImpl::Heartbeat (direct) and
 * GatewayUpstreamServiceImpl::BatchHeartbeat (gateway-batch) perform the
 * same fan-out of work for each accepted heartbeat:
 *   • health_store_->upsert(agent_id, status_tags)
 *   • yuzu_heartbeats_received_total{via=...}++
 *   • optional fleet_snapshot.v1 parse + FleetTopologyStore::push_snapshot
 *   • yuzu_viz_topology_pushed_total{via=...}++ / push_parse_errors_total++
 *
 * Three independent ingestion features have followed this pattern. The
 * next will drift between the two paths in production unless the work
 * lives behind one entry point. HeartbeatIngestion owns that entry point;
 * each gRPC service is reduced to one call per heartbeat.
 *
 * The class holds non-owning pointers to the shared stores wired in
 * server bring-up. The `via` label is the only per-call difference
 * between the direct and gateway paths.
 */

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {
class FleetTopologyStore;
class OfflineEndpointStore;
} // namespace yuzu::server

namespace yuzu::server::detail {
class AgentRegistry;
class AgentHealthStore;
} // namespace yuzu::server::detail

namespace yuzu::agent::v1 {
class HeartbeatRequest;
}

namespace yuzu::server {

class HeartbeatIngestion {
public:
    HeartbeatIngestion(detail::AgentRegistry& registry, detail::AgentHealthStore* health_store,
                       FleetTopologyStore* fleet_topology_store, MetricsRegistry* metrics,
                       OfflineEndpointStore* offline_store = nullptr)
        : registry_(registry), health_store_(health_store),
          fleet_topology_store_(fleet_topology_store), metrics_(metrics),
          offline_store_(offline_store) {}

    HeartbeatIngestion(const HeartbeatIngestion&) = delete;
    HeartbeatIngestion& operator=(const HeartbeatIngestion&) = delete;

    /// Borrowed durable last-known-endpoint store (#1320 PR 3). Nulled in
    /// server stop() after the gRPC drain so a late ingest cannot touch the
    /// released store. Optional — null = no persistence (legacy behavior).
    void set_offline_endpoint_store(OfflineEndpointStore* s) { offline_store_ = s; }

    /// Ingest one heartbeat. `agent_id` is the session-resolved agent id
    /// (already validated by the caller). `via` is "direct" or "gateway"
    /// — the only label that varies between the two ingestion paths.
    void ingest(const ::yuzu::agent::v1::HeartbeatRequest& hb, std::string_view agent_id,
                std::string_view via);

    /// Guardian heartbeat reconcile (M5 / #1209). Invoked once per heartbeat that
    /// carries the `yuzu.guardian_generation` tag, with the agent's applied policy
    /// generation. The server wires this to compare against the current generation
    /// and re-push a lagging agent — the convergence path for an agent that was
    /// offline at push time or has just reconnected. Optional; unset = no reconcile.
    using GuardianReconcileFn =
        std::function<void(std::string_view agent_id, std::uint64_t agent_generation)>;
    void set_guardian_reconcile_fn(GuardianReconcileFn fn) {
        guardian_reconcile_fn_ = std::move(fn);
    }

private:
    detail::AgentRegistry& registry_;
    detail::AgentHealthStore* health_store_;
    FleetTopologyStore* fleet_topology_store_;
    MetricsRegistry* metrics_;
    OfflineEndpointStore* offline_store_{nullptr};
    GuardianReconcileFn guardian_reconcile_fn_;
};

} // namespace yuzu::server
