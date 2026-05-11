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

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <yuzu/metrics.hpp>
#include <yuzu/transport/transport.hpp>
#include "agent.pb.h"
#include "event_bus.hpp"
#include "scope_engine.hpp"

// Forward declarations
namespace yuzu::server {
class TagStore;
class CustomPropertiesStore;
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
    // BidiStream is owned by the transport's per-call dispatcher; we hold
    // a non-owning pointer that remains valid until the Subscribe handler
    // returns. cancel() supersedes the legacy `grpc::ServerContext::
    // TryCancel()` path used to expire stale sessions (see #376 PR 1c-2).
    //
    // INVARIANT (gov round 7 architect S4): every read or write of `stream`
    // — including `stream->write(...)`, `stream->cancel()`, and the bare
    // `if (session->stream)` predicate — MUST hold `stream_mu`. The
    // Subscribe handler frame is the writer (sets the pointer at handler
    // entry, nulls it at handler exit via `clear_stream_if_session`); all
    // other call sites (`send_to`, `send_to_all`, `reap_stale_sessions`,
    // future SSE/gateway/broadcast paths) are readers. Without this
    // discipline a reader can dereference the pointer after the Subscribe
    // handler frame has unwound and the BidiStream has been destroyed by
    // the transport's `delete this` async-state-machine.
    ::yuzu::transport::BidiStream* stream = nullptr;
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

    void set_stream(const std::string& agent_id, ::yuzu::transport::BidiStream* stream);

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

    // Send a command to a specific agent. Returns false if agent not found or write failed.
    // For gateway agents (no local stream), adds to gateway_pending and returns true.
    bool send_to(const std::string& agent_id, const pb::CommandRequest& cmd);

    // Send command to all connected agents. Returns count of agents sent to.
    int send_to_all(const pb::CommandRequest& cmd);

    struct GatewayPendingCmd {
        std::string agent_id;
        pb::CommandRequest cmd;
        // #376 PR 1c-5 D.1 retry: per-command attempt counter. The
        // detached SendCommand thread in `forward_gateway_pending()`
        // increments this via `reenqueue_gateway_pending()` on each
        // `Unavailable` failure; commands hitting the 3-attempt cap are
        // dropped. In-memory only — same persistence model as
        // `gw_pending_` itself (lost on restart).
        int attempts{0};
    };

    std::vector<GatewayPendingCmd> drain_gateway_pending();

    /// Re-queue a previously-drained pending command after a transient
    /// failure. Increments `attempts` and re-pushes onto `gw_pending_` if
    /// the cap (3 total attempts) has not been hit. Returns true if the
    /// command was re-queued; false if dropped due to the cap. The cap
    /// matches today's pre-PR-1c-5 inline 3-strike-retry semantics.
    bool reenqueue_gateway_pending(GatewayPendingCmd cmd);

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
    std::string find_agent_by_stream(::yuzu::transport::BidiStream* stream) const;

    std::size_t agent_count() const;

    // Map a session_id to an agent_id (called when Subscribe completes handshake).
    void map_session(const std::string& session_id, const std::string& agent_id);

    // Look up agent session by session_id (for heartbeat validation).
    std::shared_ptr<AgentSession> find_by_session(std::string_view session_id) const;

    // Get a session by agent_id (for scope evaluation).
    std::shared_ptr<AgentSession> get_session(const std::string& agent_id) const;

    // Evaluate a scope expression against all agents, return matching agent IDs.
    std::vector<std::string>
    evaluate_scope(const yuzu::scope::Expression& expr, const TagStore* tag_store,
                   const CustomPropertiesStore* props_store = nullptr) const;

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, std::shared_ptr<AgentSession>> agents_;
    std::unordered_map<std::string, std::string> session_to_agent_;
    EventBus& bus_;
    yuzu::MetricsRegistry& metrics_;
    std::mutex gw_pending_mu_;
    std::vector<GatewayPendingCmd> gw_pending_;
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
