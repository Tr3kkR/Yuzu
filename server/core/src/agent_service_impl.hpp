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

#include <grpcpp/grpcpp.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>
#include "agent.grpc.pb.h"
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
class InventoryStore;
class UpdateRegistry;
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
    void set_response_store(ResponseStore* store) { response_store_ = store; }
    void set_tag_store(TagStore* store) { tag_store_ = store; }
    void set_analytics_store(AnalyticsEventStore* store) { analytics_store_ = store; }
    void set_health_store(AgentHealthStore* store) { health_store_ = store; }
    void set_mgmt_group_store(ManagementGroupStore* store) { mgmt_group_store_ = store; }
    void set_notification_store(NotificationStore* store) { notification_store_ = store; }
    void set_webhook_store(WebhookStore* store) { webhook_store_ = store; }
    void set_inventory_store(InventoryStore* store) { inventory_store_ = store; }

    grpc::Status Register(grpc::ServerContext* context, const pb::RegisterRequest* request,
                          pb::RegisterResponse* response) override;

    grpc::Status Heartbeat(grpc::ServerContext* context, const pb::HeartbeatRequest* request,
                           pb::HeartbeatResponse* response) override;

    grpc::Status
    Subscribe(grpc::ServerContext* context,
              grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream) override;

    // Record send time for latency measurement.
    void record_send_time(const std::string& command_id);

    // Process a CommandResponse forwarded from the gateway.
    void process_gateway_response(const std::string& agent_id,
                                   const pb::CommandResponse& resp);

    // -- Server-rendered SSE row helpers ----------------------------------------

    static inline const std::vector<std::string> kDefaultColumns{"Agent", "Output"};

    static const std::vector<std::string>& columns_for_plugin(const std::string& plugin);
    static std::string thead_for_plugin(const std::string& plugin);
    static size_t find_unescaped_pipe(const std::string& s, size_t pos);
    static std::string unescape_pipes(const std::string& s);
    static std::vector<std::string> split_fields(const std::string& plugin,
                                                  const std::string& line);
    static std::string render_row(const std::string& agent_name,
                                   const std::string& plugin,
                                   const std::string& line,
                                   const std::vector<std::string>& col_names);

    void publish_output_rows(const std::string& agent_id,
                              const std::string& plugin,
                              const std::string& raw_output);

    // -- OTA Update RPCs -------------------------------------------------------

    grpc::Status CheckForUpdate(grpc::ServerContext* context,
                                const pb::CheckForUpdateRequest* request,
                                pb::CheckForUpdateResponse* response) override;

    grpc::Status DownloadUpdate(grpc::ServerContext* context,
                                const pb::DownloadUpdateRequest* request,
                                grpc::ServerWriter<pb::DownloadUpdateChunk>* writer) override;

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
    std::atomic<size_t> output_row_count_{0};
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
    InventoryStore* inventory_store_{nullptr};

    static std::vector<std::string> extract_peer_identities(const grpc::ServerContext& context);
    static bool peer_identity_matches_agent_id(const grpc::ServerContext& context,
                                               const std::string& agent_id);
    static std::string client_metadata_value(const grpc::ServerContext& context,
                                             std::string_view key);
    static bool has_identity_overlap(const std::vector<std::string>& lhs,
                                     const std::vector<std::string>& rhs);
    void prune_expired_pending_locked();
    static std::string extract_plugin(const std::string& command_id);
};

} // namespace yuzu::server::detail
