#include "heartbeat_ingestion.hpp"

#include "agent_registry.hpp"
#include "fleet_topology_store.hpp"

#include "agent.grpc.pb.h"

#include <yuzu/metrics.hpp>
#include <spdlog/spdlog.h>

#include <charconv>
#include <cstdint>
#include <string>

namespace yuzu::server {

void HeartbeatIngestion::ingest(const ::yuzu::agent::v1::HeartbeatRequest& hb,
                                std::string_view agent_id, std::string_view via) {
    const std::string agent_id_str(agent_id);
    const std::string via_str(via);

    if (health_store_) {
        health_store_->upsert(agent_id_str, hb.status_tags());
    }
    if (metrics_) {
        metrics_->counter("yuzu_heartbeats_received_total", {{"via", via_str}}).increment();
    }

    // Guardian heartbeat reconcile (M5 / #1209): if the agent reported its applied
    // policy generation, hand it to the reconcile hook so the server can re-push a
    // lagging agent (offline at push time / just reconnected). Parse defensively —
    // a malformed tag from a buggy agent must not disturb the rest of ingestion.
    if (guardian_reconcile_fn_) {
        const auto& tags = hb.status_tags();
        auto it = tags.find("yuzu.guardian_generation");
        if (it != tags.end()) {
            std::uint64_t gen = 0;
            const auto& v = it->second;
            auto [ptr, ec] = std::from_chars(v.data(), v.data() + v.size(), gen);
            // Require the WHOLE tag to parse (ptr at end) — "123abc" must be
            // rejected, not silently read as 123 (cpp-expert / #1209).
            if (ec == std::errc() && ptr == v.data() + v.size())
                guardian_reconcile_fn_(agent_id_str, gen);
        }
    }

    // PR 10 / UAT 2026-05-12 — fleet_snapshot.v1 ingestion. Parse failures
    // are non-fatal: a malformed payload from a buggy agent must not knock
    // the heartbeat path offline for the rest of the fleet.
    if (fleet_topology_store_ && !hb.fleet_snapshot_json().empty()) {
        std::string os_from_session;
        if (auto sess = registry_.get_session(agent_id_str))
            os_from_session = sess->os;
        std::string parse_err;
        auto parsed = FleetTopologyStore::parse_fleet_snapshot_json(
            hb.fleet_snapshot_json(), agent_id_str, os_from_session, &parse_err);
        if (parsed.has_value()) {
            fleet_topology_store_->push_snapshot(std::move(*parsed));
            if (metrics_) {
                metrics_->counter("yuzu_viz_topology_pushed_total", {{"via", via_str}}).increment();
            }
        } else {
            spdlog::warn("[{}] Heartbeat fleet_snapshot from agent={} rejected ({})", via_str,
                         agent_id_str, parse_err);
            if (metrics_) {
                metrics_->counter("yuzu_viz_topology_push_parse_errors_total", {{"via", via_str}})
                    .increment();
            }
        }
    }
}

} // namespace yuzu::server
