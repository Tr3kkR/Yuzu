#pragma once

/// @file agent_registry.hpp
/// Agent session tracking, scope evaluation, and fleet health aggregation.

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <ranges>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <yuzu/metrics.hpp>
#include "agent.grpc.pb.h"
#include "event_bus.hpp"
#include "scope_engine.hpp"

// Forward declarations
namespace yuzu::server {
class TagStore;
class CustomPropertiesStore;
class ResultSetStore;
class DeviceTokenStore;
} // namespace yuzu::server

namespace yuzu::server::detail {

namespace pb = ::yuzu::agent::v1;

// -- Plugin metadata ----------------------------------------------------------

struct PluginMeta {
    std::string name;
    std::string version;
    std::string description;
    std::vector<std::string> actions;
};

// -- Agent session (one per connected agent) ----------------------------------

struct AgentSession {
    std::string agent_id;
    std::string session_id; // Unique per connection — used to prevent stale cleanup races
    std::string hostname;
    std::string os;
    std::string arch;
    std::string agent_version;
    std::vector<std::string> plugin_names;
    std::vector<PluginMeta> plugin_meta;
    std::unordered_map<std::string, std::string> scopable_tags;
    std::string gateway_node; // Non-empty if agent is connected via gateway

    // Stream pointer -- valid only while Subscribe() RPC is active.
    grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream = nullptr;
    grpc::ServerContext* server_context = nullptr; // for timeout cancellation
    std::mutex stream_mu;

    // Last activity timestamp -- updated on Subscribe reads and Heartbeats.
    // Atomic to avoid acquiring the registry mutex on every stream Read.
    std::atomic<int64_t> last_activity_epoch_ms{
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count()};
};

// -- Agent registry -----------------------------------------------------------

class AgentRegistry {
public:
    explicit AgentRegistry(EventBus& bus, yuzu::MetricsRegistry& metrics);

    void register_agent(const pb::AgentInfo& info);

    void set_stream(const std::string& agent_id,
                    grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream,
                    grpc::ServerContext* context = nullptr);

    void clear_stream(const std::string& agent_id);

    /// Update last_activity timestamp for an agent (called on heartbeat + subscribe reads).
    void touch_activity(const std::string& agent_id);

    /// Cancel Subscribe streams for agents that haven't heartbeated within the timeout.
    void reap_stale_sessions(std::chrono::seconds timeout);

    void remove_agent(const std::string& agent_id);

    /// Remove an agent only if its current session_id matches (prevents stale
    /// Subscribe cleanup from clobbering a newer reconnection).
    void remove_agent_if_session(const std::string& agent_id, const std::string& session_id);

    /// Clear stream only if the session_id matches the current session.
    void clear_stream_if_session(const std::string& agent_id, const std::string& session_id);

    void set_gateway_node(const std::string& agent_id, const std::string& node);

    /// #826: record a peer-IP (e.g. `1.2.3.4`, no port, no scheme) as a
    /// trusted gateway. Populated by `GatewayUpstreamServiceImpl` when a
    /// gateway successfully proxy-registers an agent — the gateway's own
    /// peer becomes "known good" for the TTL window.
    ///
    /// Subscribe's peer-mismatch check (`agent_service_impl.cpp`) consults
    /// this map IN ADDITION to checking that the Subscribe peer IP equals
    /// the Register peer IP. A peer that is NEITHER the original Register
    /// peer NOR a recorded trusted gateway is always rejected, even when
    /// `--gateway-mode` is on (the old code skipped the check entirely
    /// under gateway-mode — the #826 vulnerability).
    ///
    /// **W1.3 R2 / UP-2 / UP-3.** The set used to be `unordered_set` with
    /// no eviction; in a churn-heavy NAT environment the map grew
    /// unboundedly, and an attacker who briefly controlled a routable IP
    /// would keep trust for the lifetime of the process. The map now
    /// records `peer_ip → last_seen` and lookups also require the entry to
    /// be within the TTL window (default 1 h). On every insert we
    /// opportunistically sweep stale entries; if at the entry cap (1024),
    /// we evict the oldest entry first to make room for the new one. Each
    /// successful insert/refresh emits the `yuzu_trusted_gateway_peer_set_size`
    /// gauge so the operator can dashboard the set's health.
    void note_trusted_gateway_peer(std::string_view peer_ip);

    /// Returns true if `peer_ip` was previously recorded via
    /// `note_trusted_gateway_peer` AND the entry is still within the TTL
    /// window. Empty `peer_ip` always returns false — a defence-in-depth
    /// guard so a caller that fails to extract the IP cannot accidentally
    /// satisfy the trusted check.
    bool is_trusted_gateway_peer(std::string_view peer_ip) const;

    /// W1.3 R2: trusted-gateway TTL (eviction window for an entry that
    /// has not been refreshed). Hard-coded for this PR — operator-tunable
    /// flag is tracked as a follow-up.
    static constexpr auto kTrustedGatewayTtl = std::chrono::hours(1);

    /// W1.3 R2: cap on the number of trusted-gateway entries the registry
    /// will hold simultaneously. At cap, the oldest entry is evicted on
    /// insert. 1024 is comfortable headroom for any realistic deployment
    /// (load-balanced gateway clusters have O(tens) of peers); the cap
    /// exists strictly as a memory-DoS guard.
    static constexpr std::size_t kTrustedGatewayCap = 1024;

    /// Test hook: number of entries currently in the trusted-gateway map.
    /// Mirrors `yuzu_trusted_gateway_peer_set_size` for unit tests that
    /// don't want to scrape the Prometheus surface.
    std::size_t trusted_gateway_peer_count() const;

    /// Test hook: subtract `offset` from every entry's last_seen, then
    /// re-publish the gauge. Pushes entries toward (or past) the TTL
    /// boundary without sleeping. Production code MUST NOT call this —
    /// no caller in `server/core/src/**` references it.
    void expire_trusted_gateway_for_test(std::chrono::seconds offset);

    /// W1.5 / #823: install the device-token store so `register_agent`
    /// revokes any device tokens issued under a previous incarnation of
    /// the same agent_id whenever a re-registration is detected. Optional
    /// — if never called, register_agent behaves as before and stale
    /// tokens survive re-registration. Wiring lives behind a setter rather
    /// than the constructor to avoid disturbing the existing AgentRegistry
    /// construction sites, and because production `server.cpp` does not
    /// yet construct a DeviceTokenStore (the call site exists in tests
    /// today; the invariant lands now so it can't be forgotten when the
    /// production wiring catches up).
    ///
    /// Thread contract: holds the registry mutex so a concurrent
    /// `register_agent` cannot observe a partially-installed pointer.
    /// In practice the only caller is the startup wiring path, but the
    /// lock costs nothing and removes a footgun.
    void set_device_token_store(DeviceTokenStore* store);

    // Send a command to a specific agent. Returns false if agent not found or write failed.
    // For gateway agents (no local stream), adds to gateway_pending and returns true.
    bool send_to(const std::string& agent_id, const pb::CommandRequest& cmd);

    // Send command to all connected agents. Returns count of agents sent to.
    int send_to_all(const pb::CommandRequest& cmd);

    struct GatewayPendingCmd {
        std::string agent_id;
        pb::CommandRequest cmd;
    };

    std::vector<GatewayPendingCmd> drain_gateway_pending();

    bool has_any() const;

    std::string display_name(const std::string& agent_id) const;

    // Build JSON array of all agents for the web UI (structured).
    nlohmann::json to_json_obj() const;

    // Build JSON array as a serialized string.
    std::string to_json() const;

    // Per-action description map: "plugin.action" -> human-readable description.
    static const std::unordered_map<std::string, std::string>& action_descriptions();

    // Build help catalog: deduplicated plugin metadata across all agents.
    std::string help_json() const;

    // Render help table as HTML fragment (thead + tbody rows).
    std::string help_html(std::string_view filter = "") const;

    // Render autocomplete dropdown items as HTML.
    std::string autocomplete_html(std::string_view query) const;

    // Render command palette instruction results as HTML.
    std::string palette_html(std::string_view query) const;

    // Get list of all agent IDs.
    std::vector<std::string> all_ids() const;

    // Look up the agent_id that was registered for a given Subscribe call.
    std::string find_agent_by_stream(
        grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream) const;

    std::size_t agent_count() const;

    // Map a session_id to an agent_id (called when Subscribe completes handshake).
    void map_session(const std::string& session_id, const std::string& agent_id);

    // Look up agent session by session_id (for heartbeat validation).
    std::shared_ptr<AgentSession> find_by_session(std::string_view session_id) const;

    // Get a session by agent_id (for scope evaluation).
    std::shared_ptr<AgentSession> get_session(const std::string& agent_id) const;

    // Evaluate a scope expression against all agents, return matching agent IDs.
    // `rs_store` resolves the `from_result_set:<id>` scope kind (capability
    // §30) to per-device membership; aliases must be pre-resolved to canonical
    // ids by the caller (which holds the owning session). Stale members
    // (offline / decommissioned agents not in the live registry) drop silently.
    std::vector<std::string>
    evaluate_scope(const yuzu::scope::Expression& expr, const TagStore* tag_store,
                   const CustomPropertiesStore* props_store = nullptr,
                   const ResultSetStore* rs_store = nullptr) const;

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, std::shared_ptr<AgentSession>> agents_;
    std::unordered_map<std::string, std::string> session_to_agent_;
    EventBus& bus_;
    yuzu::MetricsRegistry& metrics_;
    std::mutex gw_pending_mu_;
    std::vector<GatewayPendingCmd> gw_pending_;

    /// #826 + W1.3 R2: trusted gateway peer-IPs → last_seen timestamp
    /// (steady_clock). Lookups are read-mostly (every Subscribe consults
    /// the map, inserts happen only on ProxyRegister success). Could be a
    /// `shared_mutex`, but the map is small (capped at
    /// `kTrustedGatewayCap`) and contention is negligible — keep a plain
    /// `mutex` for simplicity.
    ///
    /// Map (not set) so insert/refresh-on-existing-key updates the
    /// last_seen timestamp in-place, and stale entries can be swept by
    /// last_seen. Eviction policy: TTL (kTrustedGatewayTtl) at lookup
    /// time; opportunistic sweep on every insert; oldest-first eviction
    /// when at cap.
    mutable std::mutex trusted_gateway_mu_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point>
        trusted_gateway_peer_ips_;

    /// W1.3 R2: shared eviction-and-publish helper called by
    /// `note_trusted_gateway_peer`. Sweeps any entry older than
    /// kTrustedGatewayTtl, then if the map is at kTrustedGatewayCap
    /// removes the single oldest entry. Caller MUST hold
    /// `trusted_gateway_mu_`. Republishes the Prometheus gauge after the
    /// edit lands.
    void sweep_and_publish_trusted_gateway_locked();

    /// W1.5 / #823: optional device-token store used by `register_agent`
    /// to revoke stale tokens on re-registration. Guarded by `mu_` (set
    /// via `set_device_token_store`, read inside `register_agent`).
    DeviceTokenStore* device_token_store_{nullptr};
};

// -- AgentHealthStore ---------------------------------------------------------
// Aggregates per-agent heartbeat status_tags into fleet-wide Prometheus metrics.

struct AgentHealthSnapshot {
    std::string agent_id;
    std::unordered_map<std::string, std::string> status_tags;
    std::chrono::steady_clock::time_point last_seen;
};

class AgentHealthStore {
public:
    void upsert(const std::string& agent_id,
                const google::protobuf::Map<std::string, std::string>& tags);

    void remove(const std::string& agent_id);

    void recompute_metrics(yuzu::MetricsRegistry& metrics, std::chrono::seconds staleness);

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, AgentHealthSnapshot> snapshots_;
};

} // namespace yuzu::server::detail
