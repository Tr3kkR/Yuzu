#pragma once

/// @file agent_service_impl.hpp
/// gRPC AgentService implementation: Register, Heartbeat, Subscribe, OTA updates.

#include <atomic>
#include <chrono>
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include <yuzu/transport/transport.hpp>
#include "agent.pb.h"
#include "agent_registry.hpp"
#include "event_bus.hpp"

// Forward declarations to avoid pulling in full store headers
namespace yuzu::server {
class ResponseStore;
class TagStore;
class AnalyticsEventStore;
class ManagementGroupStore;
class NotificationStore;
class WebhookStore;
class OffloadTargetStore;
class InventoryStore;
class UpdateRegistry;
class ExecutionTracker;
struct UpdatePackage;
struct StoredResponse;
struct AnalyticsEvent;
enum class Severity;
} // namespace yuzu::server

namespace yuzu::server::detail {

namespace pb = ::yuzu::agent::v1;

/// Agent-facing service handlers for the gRPC `yuzu.agent.v1.AgentService`.
///
/// As of #376 PR 1c-2 the class no longer inherits from
/// `pb::AgentService::Service`. Handlers take fully-typed proto messages
/// + `transport::CallContext` and are registered with a
/// `transport::ServerListener` via `register_with()`. The wire format is
/// unchanged — both backends (grpc, msquic) speak the same proto
/// envelope under the lift.
class AgentServiceImpl {
public:
    AgentServiceImpl(AgentRegistry& registry, EventBus& bus, bool require_client_identity,
                     auth::AuthManager& auth_mgr, auth::AutoApproveEngine& auto_approve,
                     yuzu::MetricsRegistry& metrics, bool gateway_mode = false,
                     UpdateRegistry* update_registry = nullptr);

    void set_update_registry(UpdateRegistry* reg) { update_registry_ = reg; }
    void set_response_store(ResponseStore* store) { response_store_ = store; }

    /// Per-peer DownloadUpdate token bucket admission check (#913 /
    /// UP-116). Returns true if the request is admitted (a token was
    /// deducted); false if the bucket is exhausted (caller MUST return
    /// ResourceExhausted). Thread-safe under
    /// `download_update_buckets_mu_`. The peer key is the verified SAN
    /// identity when available (CallContext::peer_san_identities[0]),
    /// falling back to peer_uri (host:port) — fallbacks only fire in
    /// dev/UAT where mTLS is disabled. Internally also runs an
    /// opportunistic GC pass on stale entries (last_refill_at older
    /// than 24 h) so a long-lived server does not accumulate dead
    /// buckets from short-lived peers.
    ///
    /// **Public-but-internal**: the canonical production caller is
    /// `AgentServiceImpl::DownloadUpdate` (one site, marked at the
    /// call). Public visibility is retained so unit tests can drive
    /// bucket logic without standing up a full bidi-stream fixture —
    /// matches the existing pattern of public `record_execution_id` /
    /// `process_gateway_response` helpers in this class. Treat as part
    /// of the internal API: do not add new production call sites
    /// without first considering whether a shared `PerPeerRateLimiter`
    /// primitive should be extracted (architect S-1 / #933 documents
    /// the trigger condition for that extraction).
    ///
    /// **Sibling-handler asymmetry rationale.** Only `DownloadUpdate`
    /// goes through the per-peer admit/refund pair. `Register` and
    /// `Heartbeat` are unary, lightweight, and have their own
    /// backpressure paths (session limits + heartbeat-cycle pacing).
    /// `Subscribe` is a single long-lived bidi the agent must hold
    /// open — admission is meaningless because the saturation guard
    /// (#904 bidi pool bound) is the only relevant concept there.
    /// `CheckForUpdate` is a unary metadata RPC with no I/O cost
    /// worth metering. A future contributor adding a parallel rate
    /// limit on Subscribe should design refund-on-non-monopolising-
    /// failure from day one (architect S-2 follow-up).
    ///
    /// **Companion methods.** `refund_download_update` (per-call
    /// conditional credit on chunk-write-deadline failure, #934) and
    /// `set_ota_chunk_write_deadline` (boot-time-only operator-tunable
    /// deadline, #934). Three methods, three lifecycles. Grouping
    /// them behind a nested struct was considered (architect N-1)
    /// and deferred — the doc blocks encode the contract clearly
    /// enough at a 3-method footprint.
    bool admit_download_update(const std::string& peer);

    /// Refund a previously-consumed DownloadUpdate token (#934 /
    /// UP-206). Called when a `DownloadUpdate` call admitted via
    /// `admit_download_update` later fails for a reason that is NOT
    /// fleet-monopolisation — specifically, the chunk-write deadline
    /// (#911 / UP-101). A slow-link peer that hits the deadline is
    /// failing, not monopolising, so consuming a token would compound
    /// into the lockout described in #934. Refund cap is the bucket
    /// capacity (5 tokens); over-refund is silently clamped so this is
    /// safe to call defensively. Empty `peer` is a no-op (the
    /// production path always supplies a key — SAN identity or
    /// peer_uri — but tests may exercise the empty path). Thread-safe.
    void refund_download_update(const std::string& peer);

    /// Override the per-chunk write deadline applied during
    /// `DownloadUpdate` (#911 / UP-101 + #934 / UP-206). Wired by
    /// `ServerImpl` from `Config::ota_chunk_write_deadline_seconds`.
    /// Values <= 0 clamp to the default (30 s). Values above
    /// `kOtaChunkWriteDeadlineMaxSecs` (= 600 s, 10 min) clamp to that
    /// upper bound — chaos CH-101 / UP-301: an operator typo of
    /// `INT_MAX` would otherwise survive the narrowing cast and pin a
    /// bidi pool slot for ~68 years. Both clamp paths emit a
    /// `spdlog::warn` so a misconfigured value is operator-visible
    /// instead of silently swallowed (UP-302).
    ///
    /// **Boot-time-only invariant.** Today the only call site is
    /// `ServerImpl`'s constructor before the listener accepts. Wiring
    /// this to a runtime REST/MCP knob without first adding (a) an
    /// upper bound, (b) an audit event, (c) RBAC enforcement, would
    /// re-open UP-101 (slow-write peer pinning bidi pool slots) by
    /// way of an authenticated insider tuning the deadline arbitrarily
    /// high.
    ///
    /// Take care if called after the listener has accepted streams:
    /// the new value applies to the next call only — existing
    /// in-flight chunk writes continue with the deadline observed at
    /// the start of their loop (per-call snapshot, see
    /// `ota_chunk_write_deadline_secs_` doc).
    void set_ota_chunk_write_deadline(std::chrono::seconds deadline);

    /// Read-back of the live OTA chunk-write deadline. Test surface +
    /// startup-log surface; not a runtime config-reload primitive.
    /// Acquire-load matches the in-handler snapshot at the start of
    /// the chunk loop in `DownloadUpdate`.
    [[nodiscard]] std::chrono::seconds ota_chunk_write_deadline() const noexcept;

    /// Upper bound for `set_ota_chunk_write_deadline`. Above this the
    /// setter clamps and warns. 600 s (10 min) is a generous ceiling
    /// for satellite / residential 4G/LTE / congested corp WAN slow
    /// links — well above any realistic legitimate value while still
    /// bounding worst-case bidi pool slot residency to a number an
    /// operator can reason about (10 min × pool_size = pool-time
    /// pinned by stalled OTA peers).
    static constexpr int kOtaChunkWriteDeadlineMaxSecs = 600;
    static constexpr int kOtaChunkWriteDeadlineDefaultSecs = 30;

    void set_tag_store(TagStore* store) { tag_store_ = store; }
    void set_analytics_store(AnalyticsEventStore* store) { analytics_store_ = store; }
    void set_health_store(AgentHealthStore* store) { health_store_ = store; }
    void set_mgmt_group_store(ManagementGroupStore* store) { mgmt_group_store_ = store; }
    void set_notification_store(NotificationStore* store) { notification_store_ = store; }
    void set_webhook_store(WebhookStore* store) { webhook_store_ = store; }
    void set_offload_target_store(OffloadTargetStore* store) { offload_target_store_ = store; }
    void set_inventory_store(InventoryStore* store) { inventory_store_ = store; }

    /// UAT 2026-05-06 #8: when set, response-receipt paths (Subscribe +
    /// process_gateway_response) call `update_agent_status` so the
    /// executions detail drawer's per-agent KPI table populates as
    /// responses arrive, and the SSE `agent-transition` event fires
    /// (which the drawer client listens to for live updates without
    /// page reload). nullptr disables the wiring — used by tests that
    /// don't exercise the executions ladder.
    ///
    /// Stored atomically because `process_gateway_response` is invoked
    /// from detached `std::thread` workers spawned by `forward_gateway
    /// _pending` in server.cpp; those threads outlive the gRPC server's
    /// Shutdown drain (gateway-forward is a *client* of the gateway,
    /// not a server-side handler). Setting nullptr at shutdown lets
    /// in-flight forwarders observe the null and short-circuit
    /// `notify_exec_tracker` instead of dereferencing a destroyed
    /// `ExecutionTracker` (governance UAT 2026-05-06 Gate 7 re-review).
    void set_execution_tracker(ExecutionTracker* tracker) {
        execution_tracker_.store(tracker, std::memory_order_release);
    }

    /// Register this service's handlers against the transport listener.
    /// Wire-equivalent with the pre-#376 grpc::ServerBuilder::RegisterService
    /// path. Idempotent only relative to one listener instance — the
    /// listener itself rejects duplicate method names.
    void register_with(::yuzu::transport::ServerListener& listener);

    ::yuzu::transport::Status Register(const ::yuzu::transport::CallContext& ctx,
                                       const pb::RegisterRequest& request,
                                       pb::RegisterResponse& response);

    ::yuzu::transport::Status Heartbeat(const ::yuzu::transport::CallContext& ctx,
                                        const pb::HeartbeatRequest& request,
                                        pb::HeartbeatResponse& response);

    ::yuzu::transport::Status Subscribe(const ::yuzu::transport::CallContext& ctx,
                                        ::yuzu::transport::BidiStream& stream);

    // Record send time for latency measurement.
    void record_send_time(const std::string& command_id);

    /// Register the executions-tracker row id that this command_id belongs
    /// to (PR 2). Called by the dispatch path after `create_execution`
    /// returns the new id. The mapping is consumed by the response-receipt
    /// handlers and stamped onto every StoredResponse so the executions
    /// detail drawer can correlate exactly via `query_by_execution`. Empty
    /// `execution_id` removes any existing mapping for this command_id.
    void record_execution_id(const std::string& command_id, const std::string& execution_id);

    // Process a CommandResponse forwarded from the gateway.
    void process_gateway_response(const std::string& agent_id, const pb::CommandResponse& resp);

    // -- Server-rendered SSE row helpers ----------------------------------------
    // Parsing utilities (columns_for_plugin, split_fields, etc.) are in
    // result_parsing.hpp.  Only rendering helpers that depend on AgentServiceImpl
    // state remain here.

    static std::string thead_for_plugin(const std::string& plugin);
    static std::string render_row(const std::string& agent_name, const std::string& plugin,
                                  const std::string& line,
                                  const std::vector<std::string>& col_names);

    void publish_output_rows(const std::string& agent_id, const std::string& plugin,
                             const std::string& raw_output);

    // -- OTA Update RPCs -------------------------------------------------------

    ::yuzu::transport::Status CheckForUpdate(const ::yuzu::transport::CallContext& ctx,
                                             const pb::CheckForUpdateRequest& request,
                                             pb::CheckForUpdateResponse& response);

    /// Server-streaming RPC lifted onto BidiStream. The legacy gRPC
    /// server-streaming wire shape (one Req frame from client + END_STREAM,
    /// then N Resp frames + trailers) is byte-equivalent to a bidi stream
    /// where the client immediately calls writes_done() — see
    /// `transport.hpp` server-stream pattern doc.
    ::yuzu::transport::Status DownloadUpdate(const ::yuzu::transport::CallContext& ctx,
                                             ::yuzu::transport::BidiStream& stream);

private:
    AgentRegistry& registry_;
    EventBus& bus_;
    auth::AuthManager& auth_mgr_;
    auth::AutoApproveEngine& auto_approve_;
    yuzu::MetricsRegistry& metrics_;

    static constexpr std::string_view kSessionMetadataKey = "x-yuzu-session-id";
    static constexpr auto kPendingRegistrationTtl = std::chrono::seconds(60);

    // -- PendingRegistration (must be complete before use in unordered_map) -----
    struct PendingRegistration {
        std::string agent_id;
        std::string register_peer;
        std::vector<std::string> peer_identities;
        std::chrono::steady_clock::time_point created_at;
    };

    // Pending Register calls waiting for the corresponding Subscribe.
    std::mutex pending_mu_;
    std::unordered_map<std::string, PendingRegistration> pending_by_session_id_;

    // Command timing instrumentation
    std::mutex cmd_times_mu_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> cmd_send_times_;
    std::unordered_set<std::string> cmd_first_seen_;
    /// PR 2 in-memory mapping `command_id → execution_id`. Populated by
    /// the dispatch path (currently only `/api/instructions/:id/execute`
    /// in `workflow_routes.cpp`; MCP / dashboard / scheduled / rerun are
    /// known gaps tracked as PR 2.x follow-ups); consumed by the
    /// response-receipt branches in process_gateway_response / Subscribe
    /// to stamp the new responses.execution_id column. Guarded by
    /// cmd_times_mu_ for locality with the existing send-time map.
    ///
    /// **Multi-agent fan-out invariant (HF-1).** A single command_id is
    /// dispatched to N agents; each agent sends its own response with
    /// the same command_id. Entries are NOT erased on terminal status —
    /// erasing on the first agent's terminal would leave agents 2..N
    /// stamping empty execution_id. Entries persist until a future
    /// sweeper (PR 2.x) lands.
    ///
    /// **Known leak surface (sec-M1 / perf-S1).** Without a periodic
    /// sweeper, entries grow over time:
    ///   - Multi-agent dispatches: N entries until process restart.
    ///   - Agent crash / network drop / server restart with in-flight:
    ///     entries persist forever until process exits.
    /// Per-entry cost ~64 bytes (two SSO strings). Acceptable for typical
    /// dispatch rates over a service lifetime; bounded fix is a sweeper
    /// keyed on a steady_clock timestamp stored alongside each entry,
    /// evicting > max-command-timeout (default 1h). Filed as a hard
    /// predecessor for closing the executions-history ladder.
    std::unordered_map<std::string, std::string> cmd_execution_ids_;
    std::atomic<size_t> output_row_count_{0};
    std::vector<std::string> tar_dynamic_columns_; // TAR SQL dynamic schema cache
    bool require_client_identity_{false};
    bool gateway_mode_{false};
    UpdateRegistry* update_registry_{nullptr};
    ResponseStore* response_store_{nullptr};
    TagStore* tag_store_{nullptr};
    AnalyticsEventStore* analytics_store_{nullptr};
    AgentHealthStore* health_store_{nullptr};
    ManagementGroupStore* mgmt_group_store_{nullptr};
    NotificationStore* notification_store_{nullptr};
    WebhookStore* webhook_store_{nullptr};
    OffloadTargetStore* offload_target_store_{nullptr};
    InventoryStore* inventory_store_{nullptr};
    /// Atomic — see `set_execution_tracker` doc for why detached
    /// gateway-forward threads require the lock-free release/acquire
    /// pair instead of a plain raw pointer.
    std::atomic<ExecutionTracker*> execution_tracker_{nullptr};

    /// Per-peer DownloadUpdate token bucket (#913 / UP-116). Keyed by
    /// the peer's verified SAN identity (or peer_uri fallback when no
    /// SAN is available — e.g., in dev). Bucket capacity is 5 tokens;
    /// refill rate is one token per ~90 minutes (= update_check_interval
    /// default 6 h / 4) so a normally-behaved agent never hits the
    /// limit but a fast-valid attacker monopolising the pool does.
    /// Excess requests return ResourceExhausted (same wire status as
    /// pool saturation #904) so dashboards can group capacity rejects
    /// and per-peer rejects together when alerting on noisy fleets.
    /// Storage is process-local; restart resets buckets to full —
    /// matches the threat model (the limit is a fleet-monopolisation
    /// guard, not a persistent quota).
    struct DownloadUpdateBucket {
        // kInitialTokens is the default starting capacity. Pinned in
        // a separate constant so an anonymous-namespace
        // `static_assert` in `agent_service_impl.cpp` can prove the
        // NSDMI default matches `kBucketCapacity` (the cap shared by
        // admit + refund) at compile time. Without the indirection
        // the static_assert would have to construct a default
        // `DownloadUpdateBucket{}` whose `last_refill_at` NSDMI calls
        // non-constexpr `steady_clock::now()`. Closes cpp-expert
        // SHOULD-1 (ODR-drift mitigation comment alone wasn't enough).
        static constexpr double kInitialTokens = 5.0;
        double tokens = kInitialTokens;
        std::chrono::steady_clock::time_point last_refill_at = std::chrono::steady_clock::now();
    };
    std::mutex download_update_buckets_mu_;
    std::unordered_map<std::string, DownloadUpdateBucket> download_update_buckets_;
    std::chrono::steady_clock::time_point download_update_buckets_last_gc_ =
        std::chrono::steady_clock::now();

    /// Per-chunk write deadline (#911 / UP-101 + #934 / UP-206 operator
    /// tunable). Atomic so `DownloadUpdate` can read without the
    /// `download_update_buckets_mu_` lock — the deadline lives on a
    /// different concern from the rate-limit bucket. Set by
    /// `set_ota_chunk_write_deadline` from `ServerImpl`'s constructor.
    /// Stored as `int64_t` to match `std::chrono::seconds::rep` so the
    /// setter does not narrow on hosts where `seconds::rep` is wider
    /// than `int` (cpp-expert review of #934 + security LOW-1: the
    /// historical `std::atomic<int>` would have been a narrowing UB
    /// vector for an operator typo of `INT_MAX+1`; the `kOtaChunkWrite
    /// DeadlineMaxSecs` upper clamp is the primary defence, the
    /// widened atomic closes the residual cast hazard). Default 30
    /// seconds matches `kOtaChunkWriteDeadlineDefaultSecs`.
    std::atomic<int64_t> ota_chunk_write_deadline_secs_{kOtaChunkWriteDeadlineDefaultSecs};

    /// Match a claimed agent_id against the verified peer identities the
    /// transport surfaced via `CallContext::peer_san_identities`. The
    /// gRPC backend folds GetPeerIdentity + CN + SAN into that set; the
    /// msquic backend will follow the same authn contract.
    static bool peer_identity_matches_agent_id(const ::yuzu::transport::CallContext& ctx,
                                               const std::string& agent_id);
    static std::string client_metadata_value(const ::yuzu::transport::CallContext& ctx,
                                             std::string_view key);
    static bool has_identity_overlap(const std::vector<std::string>& lhs,
                                     const std::vector<std::string>& rhs);
    void prune_expired_pending_locked();
    static std::string extract_plugin(const std::string& command_id);

    /// UAT 2026-05-06 #8: notify the executions tracker of a per-agent
    /// state change for the given command_id. Resolves command_id →
    /// execution_id via cmd_execution_ids_ and calls
    /// `ExecutionTracker::update_agent_status` with a synthesised
    /// `AgentExecStatus` (status, exit_code, error_detail, timestamps).
    /// No-op if the tracker isn't wired or the command_id has no
    /// execution mapping (out-of-band dispatch). Each call publishes an
    /// `agent-transition` SSE event the drawer's client listens to for
    /// live-updates without a page reload.
    void notify_exec_tracker(const std::string& command_id, const std::string& agent_id,
                             const pb::CommandResponse& resp);
};

} // namespace yuzu::server::detail
