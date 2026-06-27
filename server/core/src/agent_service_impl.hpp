#pragma once

/// @file agent_service_impl.hpp
/// gRPC AgentService implementation: Register, Heartbeat, Subscribe, OTA updates.

#include <atomic>
#include <chrono>
#include <fstream>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include "agent.grpc.pb.h"
#include "agent_registry.hpp"
#include "cert_issuance_source.hpp"
#include "event_bus.hpp"

// Forward declarations to avoid pulling in full store headers
namespace yuzu::server {
class ResponseStore;
class TagStore;
class AnalyticsEventStore;
class AuditStore;
class ManagementGroupStore;
class NotificationStore;
class WebhookStore;
class OffloadTargetStore;
class InventoryStore;
class SoftwareInventoryStore;
class UpdateRegistry;
class ExecutionTracker;
class FleetTopologyStore;
class HeartbeatIngestion;
class GuaranteedStateStore;
class BlastRadiusDetector;
class DexAlertRouter;
struct UpdatePackage;
struct StoredResponse;
struct AnalyticsEvent;
enum class Severity;
} // namespace yuzu::server

namespace yuzu::server::detail {

namespace pb = ::yuzu::agent::v1;

class AgentServiceImpl : public pb::AgentService::Service {
public:
    AgentServiceImpl(AgentRegistry& registry, EventBus& bus, bool require_client_identity,
                     auth::AuthManager& auth_mgr, auth::AutoApproveEngine& auto_approve,
                     yuzu::MetricsRegistry& metrics, bool gateway_mode = false,
                     UpdateRegistry* update_registry = nullptr);

    void set_update_registry(UpdateRegistry* reg) { update_registry_ = reg; }
    /// #1128: operator-declared multi-egress NAT/proxy CIDRs for the NAT-aware
    /// Subscribe binding relaxation. Empty (default) keeps strict exact-match.
    void set_trusted_nat_cidrs(std::vector<std::string> cidrs) {
        trusted_nat_cidrs_ = std::move(cidrs);
    }
    /// #1128 / gov UP-2: opt-in to the mTLS-identity NAT accommodation. Default
    /// false; only safe with per-agent client certs (see Config doc).
    void set_nat_trust_mtls_identity(bool enabled) { nat_trust_mtls_identity_ = enabled; }
    void set_response_store(ResponseStore* store) { response_store_ = store; }
    void set_tag_store(TagStore* store) { tag_store_ = store; }
    void set_analytics_store(AnalyticsEventStore* store) { analytics_store_ = store; }
    /// W1.4 / #827: AuditStore wired for enrollment-token consume rows.
    /// SOC 2 CC7.2/CC7.3 require attributable credential-rejection logs;
    /// the Register handler emits one audit row per successful consume AND
    /// one per lost-race rejection (with `already_consumed_by=<agent_id>`
    /// detail naming the race winner). nullptr disables emission — used
    /// by the existing test harness that doesn't construct an AuditStore.
    /// W1.1 audit_log → bool: the handler observes the return so a
    /// dropped audit row surfaces as a counter increment plus an
    /// analytics-event severity escalation, never a silent loss.
    void set_audit_store(AuditStore* store) { audit_store_ = store; }
    void set_health_store(AgentHealthStore* store) { health_store_ = store; }
    void set_mgmt_group_store(ManagementGroupStore* store) { mgmt_group_store_ = store; }
    void set_notification_store(NotificationStore* store) { notification_store_ = store; }
    void set_webhook_store(WebhookStore* store) { webhook_store_ = store; }
    void set_offload_target_store(OffloadTargetStore* store) { offload_target_store_ = store; }
    void set_inventory_store(InventoryStore* store) { inventory_store_ = store; }
    /// Typed software-inventory projection (ADR-0016) — receives the
    /// installed_software daily-sync source via ReportInventory.
    void set_software_inventory_store(SoftwareInventoryStore* store) {
        software_inventory_store_ = store;
    }
    /// Guardian (Guaranteed State) store — receives drift/remediation events
    /// ingested from the agent `__guard__` side-channel on the Subscribe stream
    /// (contract G2/step 5). nullptr disables ingest — used by tests that don't
    /// build a Guardian store.
    void set_guaranteed_state_store(GuaranteedStateStore* store) {
        guaranteed_state_store_ = store;
    }
    /// Fleet-wide DEX incident detector (blast radius, coverage-map D3) — the
    /// shared Guardian ingest feeds it each ruleless observation. nullptr
    /// disables detection. Set-before-traffic, like the store setters above.
    void set_blast_radius_detector(BlastRadiusDetector* detector) {
        blast_radius_detector_ = detector;
    }
    /// Operator-routed per-signal alerting (coverage-map F1) — fed alongside
    /// the blast-radius detector at the same ingest chokepoint. nullptr
    /// disables routing. Set-before-traffic.
    void set_dex_alert_router(DexAlertRouter* router) { dex_alert_router_ = router; }

    /// UAT 2026-05-12: after a fresh agent registers, the next
    /// `/api/v1/viz/fleet/topology` call must not return a snapshot
    /// computed before this agent was on the dispatch list. Without
    /// this hook the cube renders as `stale, ts=0, procs=[]` for the
    /// remainder of the 60 s TTL window, which UAT flagged as a
    /// "this should not happen" state. nullptr disables the wiring —
    /// used by tests that don't build a topology store.
    ///
    /// Plain raw pointer (not atomic): registration runs on the gRPC
    /// dispatcher; setter runs once during server bring-up before the
    /// dispatcher accepts traffic.
    void set_fleet_topology_store(FleetTopologyStore* store) { fleet_topology_store_ = store; }

    /// #1000 / arch-S2: HeartbeatIngestion encapsulates the shared
    /// per-heartbeat work (health upsert, metrics, fleet_snapshot push)
    /// so both this service and GatewayUpstreamServiceImpl funnel
    /// through one entry point. Set after bring-up alongside the stores.
    void set_heartbeat_ingestion(HeartbeatIngestion* hi) { heartbeat_ingestion_ = hi; }

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

    /// PR3: per-agent mTLS issuance + enforcement. The signer (wired by ServerImpl
    /// after the default-cert bootstrap, when a CA issuing key is available) signs a
    /// client leaf bound to agent_id from the agent's CSR, returning
    /// {leaf_pem, ca_chain_pem}; nullopt = signing unavailable/failed. The revocation
    /// checker returns true iff a presented peer leaf PEM is revoked (checked against
    /// ca.db). set_require_client_identity recomputes the mTLS-identity-required
    /// posture AFTER bootstrap — require_client_identity_ is otherwise baked at ctor,
    /// before the default CA exists. All set once during bring-up, before the gRPC
    /// dispatcher accepts traffic.
    /// `src` records whether issuance entered via the direct Register path or the
    /// gateway proxy, threaded into the ca.cert.issued audit (#1290).
    using AgentCertSigner = std::function<std::optional<std::pair<std::string, std::string>>(
        const std::string& csr_pem, const std::string& agent_id, CertIssuanceSource src)>;
    void set_agent_cert_signer(AgentCertSigner signer) { agent_cert_signer_ = std::move(signer); }
    void set_revocation_checker(std::function<bool(const std::string& peer_cert_pem)> checker) {
        revocation_checker_ = std::move(checker);
    }
    /// Recognizer returning true iff a presented client leaf was issued by our
    /// internal CA (signature-verified). When set, the Register re-auth gate
    /// enforces identity/revocation ONLY for Yuzu-issued certs — a foreign cert in
    /// a multi-CA trust bundle falls through to bootstrap rather than being trusted
    /// as an agent identity (Hermes CRITICAL-1). Null = single-trust-root
    /// deployment: every authenticated cert is treated as an agent (legacy).
    void set_peer_cert_recognizer(std::function<bool(const std::string& peer_cert_pem)> r) {
        peer_cert_recognizer_ = std::move(r);
    }
    void set_require_client_identity(bool v) { require_client_identity_ = v; }

    grpc::Status Register(grpc::ServerContext* context, const pb::RegisterRequest* request,
                          pb::RegisterResponse* response) override;

    grpc::Status Heartbeat(grpc::ServerContext* context, const pb::HeartbeatRequest* request,
                           pb::HeartbeatResponse* response) override;

    grpc::Status
    Subscribe(grpc::ServerContext* context,
              grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream) override;

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

    /// #826: extract the bare IP from a gRPC peer string. gRPC encodes
    /// peer as `ipv4:1.2.3.4:5678` (and `ipv6:[::1]:5678`, `unix:/tmp/s`,
    /// etc.). Subscribe's peer-mismatch check operates on IPs because the
    /// port differs across the Register and Subscribe RPCs from the same
    /// agent — the meaningful security check is "same network endpoint",
    /// not "same TCP four-tuple". Returns an empty string for unparseable
    /// inputs; the caller MUST treat empty as a mismatch (never as a wild
    /// match) to avoid recreating the #826 skip.
    ///
    /// Public for unit testability — exercised in test_agent_service_impl.cpp.
    static std::string extract_peer_ip(std::string_view peer);

    /// #1128 — NAT-aware per-session peer-binding decision (pure). `exact_ok` is
    /// the strict result (Subscribe IP == Register IP, or a trusted-gateway IP
    /// under gateway-mode). When that fails, a mismatch is DOWNGRADED to advisory
    /// iff a stronger accommodation applies: a matching mTLS client identity
    /// (`client_identity_matches`), or both IPs sharing one operator-declared
    /// trusted NAT CIDR. Anything else is reject. An empty `register_ip` or
    /// `subscribe_ip` is always reject (#826: empty is a mismatch, never a
    /// wildcard) regardless of accommodation. Pure + static for unit testability.
    enum class PeerBindingOutcome { exact_ok, advisory_mtls, advisory_nat_cidr, reject };
    static PeerBindingOutcome evaluate_peer_binding(bool exact_ok, std::string_view register_ip,
                                                    std::string_view subscribe_ip,
                                                    bool client_identity_matches,
                                                    const std::vector<std::string>& trusted_nat_cidrs);

    void publish_output_rows(const std::string& agent_id, const std::string& plugin,
                             const std::string& raw_output);

    // -- OTA Update RPCs -------------------------------------------------------

    grpc::Status CheckForUpdate(grpc::ServerContext* context,
                                const pb::CheckForUpdateRequest* request,
                                pb::CheckForUpdateResponse* response) override;

    grpc::Status DownloadUpdate(grpc::ServerContext* context,
                                const pb::DownloadUpdateRequest* request,
                                grpc::ServerWriter<pb::DownloadUpdateChunk>* writer) override;

    // Direct daily-sync push (ADR-0016). Validates the session, resolves the
    // agent_id, and persists via the shared inventory ingest seam (identical to
    // the gateway ProxyInventory path).
    grpc::Status ReportInventory(grpc::ServerContext* context, const pb::InventoryReport* request,
                                 pb::InventoryAck* response) override;

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
    // #1128: operator-declared multi-egress NAT/proxy ranges (see Config). Empty
    // = strict exact-match peer binding (default). Set once at wiring time via
    // set_trusted_nat_cidrs; read-only on the Subscribe path thereafter.
    std::vector<std::string> trusted_nat_cidrs_;
    // #1128 / gov UP-2: gate for the mTLS-identity NAT accommodation. Default
    // false — identity-match relaxes the IP binding ONLY when the operator
    // affirms per-agent certs. See Config::nat_trust_mtls_identity.
    bool nat_trust_mtls_identity_{false};
    UpdateRegistry* update_registry_{nullptr};
    ResponseStore* response_store_{nullptr};
    TagStore* tag_store_{nullptr};
    AnalyticsEventStore* analytics_store_{nullptr};
    AuditStore* audit_store_{nullptr};
    AgentHealthStore* health_store_{nullptr};
    ManagementGroupStore* mgmt_group_store_{nullptr};
    NotificationStore* notification_store_{nullptr};
    WebhookStore* webhook_store_{nullptr};
    OffloadTargetStore* offload_target_store_{nullptr};
    InventoryStore* inventory_store_{nullptr};
    SoftwareInventoryStore* software_inventory_store_{nullptr};
    GuaranteedStateStore* guaranteed_state_store_{nullptr};
    BlastRadiusDetector* blast_radius_detector_{nullptr};
    DexAlertRouter* dex_alert_router_{nullptr};
    FleetTopologyStore* fleet_topology_store_{nullptr};
    HeartbeatIngestion* heartbeat_ingestion_{nullptr};
    /// Atomic — see `set_execution_tracker` doc for why detached
    /// gateway-forward threads require the lock-free release/acquire
    /// pair instead of a plain raw pointer.
    std::atomic<ExecutionTracker*> execution_tracker_{nullptr};

    // PR3 per-agent mTLS (set post-bootstrap; empty = disabled / legacy path).
    AgentCertSigner agent_cert_signer_;
    std::function<bool(const std::string&)> revocation_checker_;
    std::function<bool(const std::string&)> peer_cert_recognizer_;

    static std::vector<std::string> extract_peer_identities(const grpc::ServerContext& context);
    /// PR3: the presented client leaf PEM from the gRPC auth context (the
    /// x509_pem_cert property), or empty if no client cert was presented.
    static std::string extract_peer_cert_pem(const grpc::ServerContext& context);
    static bool peer_identity_matches_agent_id(const grpc::ServerContext& context,
                                               const std::string& agent_id);
    static std::string client_metadata_value(const grpc::ServerContext& context,
                                             std::string_view key);
    static bool has_identity_overlap(const std::vector<std::string>& lhs,
                                     const std::vector<std::string>& rhs);

    void prune_expired_pending_locked();
    static std::string extract_plugin(const std::string& command_id);

    /// PR3: if a Yuzu-issued client leaf is presented and revoked, return a
    /// non-OK status to send back; otherwise grpc::Status::OK. Lets the
    /// agent-initiated RPCs (Heartbeat, DownloadUpdate) lock out a revoked agent
    /// from liveness + OTA, not just the command channel — `Subscribe` keeps its
    /// own richer audited gate. No-op when no checker is wired or no/foreign cert
    /// is presented (the checker is issuer-scoped). `rpc` labels the metric/log.
    grpc::Status reject_revoked_peer(grpc::ServerContext* context, std::string_view rpc);

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
