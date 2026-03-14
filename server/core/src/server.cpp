#include <yuzu/server/server.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <grpc/grpc_security_constants.h>

#include "agent.grpc.pb.h"
#include "management.grpc.pb.h"
#include "gateway.grpc.pb.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <httplib.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string_view>

// Defined in dashboard_ui.cpp (separate TU to isolate MSVC raw-string issues).
extern const char* const kDashboardIndexHtml;

// Legacy UIs kept for backward compatibility (redirect to /).
extern const char* const kChargenIndexHtml;
extern const char* const kProcfetchIndexHtml;

// Login and Settings pages (separate TUs).
extern const char* const kLoginHtml;
extern const char* const kSettingsHtml;

namespace yuzu::server {

namespace detail {

namespace pb = ::yuzu::agent::v1;
namespace gw = ::yuzu::gateway::v1;

// -- Platform-specific log path -----------------------------------------------

[[nodiscard]] std::filesystem::path server_log_path() {
#ifdef _WIN32
    return R"(C:\ProgramData\Yuzu\logs\agent.log)";
#elif defined(__APPLE__)
    return "/Library/Logs/Yuzu/agent.log";
#else
    return "/var/log/yuzu/agent.log";
#endif
}

// -- SSE Event ----------------------------------------------------------------

struct SseEvent {
    std::string event_type;
    std::string data;
};

// -- SSE Event Bus ------------------------------------------------------------

class EventBus {
public:
    using Listener = std::function<void(const SseEvent&)>;

    std::size_t subscribe(Listener fn) {
        std::lock_guard<std::mutex> lock(mu_);
        auto id = next_id_++;
        listeners_[id] = std::move(fn);
        return id;
    }

    void unsubscribe(std::size_t id) {
        std::lock_guard<std::mutex> lock(mu_);
        listeners_.erase(id);
    }

    void publish(const std::string& event_type, const std::string& data) {
        SseEvent ev{event_type, data};
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& [id, fn] : listeners_) {
            fn(ev);
        }
    }

private:
    std::mutex mu_;
    std::size_t next_id_ = 0;
    std::unordered_map<std::size_t, Listener> listeners_;
};

// -- Agent session (one per connected agent) ----------------------------------

struct AgentSession {
    std::string agent_id;
    std::string hostname;
    std::string os;
    std::string arch;
    std::string agent_version;
    std::vector<std::string> plugin_names;

    // Stream pointer — valid only while Subscribe() RPC is active.
    grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream = nullptr;
    std::mutex stream_mu;
};

// -- Agent registry -----------------------------------------------------------

class AgentRegistry {
public:
    explicit AgentRegistry(EventBus& bus) : bus_(bus) {}

    void register_agent(const pb::AgentInfo& info) {
        auto session = std::make_shared<AgentSession>();
        session->agent_id      = info.agent_id();
        session->hostname      = info.hostname();
        session->os            = info.platform().os();
        session->arch          = info.platform().arch();
        session->agent_version = info.agent_version();
        for (const auto& p : info.plugins()) {
            session->plugin_names.push_back(p.name());
        }

        {
            std::lock_guard lock(mu_);
            agents_[info.agent_id()] = session;
        }
        bus_.publish("agent-online", info.agent_id());
        spdlog::info("Agent registered: id={}, hostname={}, plugins={}",
            info.agent_id(), info.hostname(), info.plugins_size());
    }

    void set_stream(const std::string& agent_id,
                    grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream) {
        std::lock_guard lock(mu_);
        auto it = agents_.find(agent_id);
        if (it != agents_.end()) {
            std::lock_guard slock(it->second->stream_mu);
            it->second->stream = stream;
        }
    }

    void clear_stream(const std::string& agent_id) {
        std::shared_ptr<AgentSession> session;
        {
            std::lock_guard lock(mu_);
            auto it = agents_.find(agent_id);
            if (it == agents_.end()) return;
            session = it->second;
        }
        {
            std::lock_guard slock(session->stream_mu);
            session->stream = nullptr;
        }
    }

    void remove_agent(const std::string& agent_id) {
        {
            std::lock_guard lock(mu_);
            agents_.erase(agent_id);
        }
        bus_.publish("agent-offline", agent_id);
        spdlog::info("Agent removed: id={}", agent_id);
    }

    // Send a command to a specific agent. Returns false if agent not found or write failed.
    bool send_to(const std::string& agent_id, const pb::CommandRequest& cmd) {
        std::shared_ptr<AgentSession> session;
        {
            std::lock_guard lock(mu_);
            auto it = agents_.find(agent_id);
            if (it == agents_.end()) return false;
            session = it->second;
        }
        std::lock_guard slock(session->stream_mu);
        if (!session->stream) return false;
        return session->stream->Write(cmd, grpc::WriteOptions());
    }

    // Send command to all connected agents. Returns count of agents sent to.
    int send_to_all(const pb::CommandRequest& cmd) {
        std::vector<std::shared_ptr<AgentSession>> snapshot;
        {
            std::lock_guard lock(mu_);
            snapshot.reserve(agents_.size());
            for (auto& [id, s] : agents_) {
                snapshot.push_back(s);
            }
        }
        int count = 0;
        for (auto& s : snapshot) {
            std::lock_guard slock(s->stream_mu);
            if (s->stream && s->stream->Write(cmd, grpc::WriteOptions())) {
                ++count;
            }
        }
        return count;
    }

    bool has_any() const {
        std::lock_guard lock(mu_);
        return !agents_.empty();
    }

    // Build JSON array of all agents for the web UI.
    std::string to_json() const {
        std::lock_guard lock(mu_);
        std::string json = "[";
        bool first = true;
        for (const auto& [id, s] : agents_) {
            if (!first) json += ",";
            first = false;
            // Simple JSON escaping (agent metadata shouldn't contain quotes normally)
            json += "{\"agent_id\":\"" + s->agent_id +
                    "\",\"hostname\":\"" + s->hostname +
                    "\",\"os\":\"" + s->os +
                    "\",\"arch\":\"" + s->arch +
                    "\",\"agent_version\":\"" + s->agent_version + "\"}";
        }
        json += "]";
        return json;
    }

    // Get list of all agent IDs.
    std::vector<std::string> all_ids() const {
        std::lock_guard lock(mu_);
        std::vector<std::string> ids;
        ids.reserve(agents_.size());
        for (const auto& [id, s] : agents_) {
            ids.push_back(id);
        }
        return ids;
    }

    // Look up the agent_id that was registered for a given Subscribe call.
    // The Subscribe RPC needs to know which agent_id it's serving.
    std::string find_agent_by_stream(
        grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream) const {
        std::lock_guard lock(mu_);
        for (const auto& [id, s] : agents_) {
            std::lock_guard slock(s->stream_mu);
            if (s->stream == stream) return id;
        }
        return {};
    }

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, std::shared_ptr<AgentSession>> agents_;
    EventBus& bus_;
};

// -- SSE sink state (per-connection, shared with content provider) -------------

struct SseSinkState {
    std::mutex              mu;
    std::condition_variable cv;
    std::deque<SseEvent>    queue;
    std::atomic<bool>       closed = false;
    std::size_t             sub_id = 0;
};

// -- SSE content provider callback --------------------------------------------

bool sse_content_provider(
    const std::shared_ptr<SseSinkState>& state,
    size_t /*offset*/,
    httplib::DataSink& sink)
{
    std::unique_lock<std::mutex> lk(state->mu);
    state->cv.wait_for(lk, std::chrono::seconds(15), [&state] {
        return !state->queue.empty() || state->closed.load();
    });

    if (state->closed.load()) {
        return false;
    }

    while (!state->queue.empty()) {
        auto& ev = state->queue.front();
        std::string sse = "event: " + ev.event_type + "\ndata: " + ev.data + "\n\n";
        if (!sink.write(sse.data(), sse.size())) {
            return false;
        }
        state->queue.pop_front();
    }

    const char* keepalive = ": keepalive\n\n";
    sink.write(keepalive, std::strlen(keepalive));
    return true;
}

void sse_resource_release(
    const std::shared_ptr<SseSinkState>& state,
    EventBus& bus,
    bool /*success*/)
{
    state->closed.store(true);
    state->cv.notify_all();
    bus.unsubscribe(state->sub_id);
}

// -- AgentServiceImpl ---------------------------------------------------------

class AgentServiceImpl : public pb::AgentService::Service {
public:
    AgentServiceImpl(AgentRegistry& registry, EventBus& bus,
                     bool require_client_identity,
                     auth::AuthManager& auth_mgr,
                     auth::AutoApproveEngine& auto_approve,
                     bool gateway_mode = false)
        : registry_(registry), bus_(bus),
          require_client_identity_(require_client_identity),
          auth_mgr_(auth_mgr),
          auto_approve_(auto_approve),
          gateway_mode_(gateway_mode) {}

    grpc::Status Register(
        grpc::ServerContext* context,
        const pb::RegisterRequest* request,
        pb::RegisterResponse* response) override
    {
        const auto& info = request->info();

        if (require_client_identity_) {
            if (!context || !peer_identity_matches_agent_id(*context, info.agent_id())) {
                spdlog::warn("mTLS identity mismatch: claimed agent_id={}", info.agent_id());
                return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                                    "agent_id must match client certificate identity (CN/SAN)");
            }
        }

        // ── Tiered enrollment ────────────────────────────────────────────
        //
        //  Tier 2: Pre-shared enrollment token → auto-enroll
        //  Tier 1: No token → check pending queue → pending/approved/denied
        //

        const auto& enrollment_token = request->enrollment_token();

        if (!enrollment_token.empty()) {
            // Tier 2: Validate the pre-shared token
            if (!auth_mgr_.validate_enrollment_token(enrollment_token)) {
                spdlog::warn("Agent {} presented invalid enrollment token", info.agent_id());
                response->set_accepted(false);
                response->set_reject_reason("invalid, expired, or exhausted enrollment token");
                response->set_enrollment_status("denied");
                return grpc::Status::OK;
            }
            spdlog::info("Agent {} auto-enrolled via enrollment token", info.agent_id());
            // Remove from pending queue if it was there
            auth_mgr_.remove_pending_agent(info.agent_id());
        } else {
            // Tier 1.5: Auto-approve policies — check before pending queue
            auth::ApprovalContext approval_ctx;
            approval_ctx.hostname = info.hostname();
            approval_ctx.attestation_provider = request->attestation_provider();

            // Extract peer IP from gRPC context (format: "ipv4:1.2.3.4:port")
            if (context) {
                auto peer = context->peer();
                // Strip scheme prefix and port
                auto colon1 = peer.find(':');
                if (colon1 != std::string::npos) {
                    auto ip_start = colon1 + 1;
                    auto colon2 = peer.rfind(':');
                    if (colon2 > ip_start) {
                        approval_ctx.peer_ip = peer.substr(ip_start, colon2 - ip_start);
                    } else {
                        approval_ctx.peer_ip = peer.substr(ip_start);
                    }
                }
            }

            // TODO: Extract CA fingerprint from peer TLS cert chain
            // approval_ctx.ca_fingerprint_sha256 = ...

            auto matched_rule = auto_approve_.evaluate(approval_ctx);
            if (!matched_rule.empty()) {
                spdlog::info("Agent {} auto-approved by policy: {}",
                             info.agent_id(), matched_rule);
                auth_mgr_.remove_pending_agent(info.agent_id());
                // Fall through to normal registration
            } else {
            // Tier 1: No token, no policy match — check the pending queue
            auto pending_status = auth_mgr_.get_pending_status(info.agent_id());

            if (!pending_status) {
                // First time seeing this agent — add to pending queue
                auth_mgr_.add_pending_agent(
                    info.agent_id(),
                    info.hostname(),
                    info.platform().os(),
                    info.platform().arch(),
                    info.agent_version());

                response->set_accepted(false);
                response->set_reject_reason("awaiting admin approval");
                response->set_enrollment_status("pending");
                bus_.publish("pending-agent", info.agent_id());
                spdlog::info("Agent {} placed in pending approval queue", info.agent_id());
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
                    spdlog::info("Agent {} enrolled (admin-approved)", info.agent_id());
                    // Fall through to normal registration
                    break;
            }
            }  // auto-approve else
        }

        // ── Agent is enrolled — proceed with registration ────────────────

        registry_.register_agent(info);

        auto session_id = "session-" + auth::AuthManager::bytes_to_hex(
            auth::AuthManager::random_bytes(16));
        response->set_session_id(session_id);
        response->set_accepted(true);
        response->set_enrollment_status("enrolled");

        PendingRegistration pending;
        pending.agent_id = info.agent_id();
        pending.register_peer = context ? context->peer() : std::string{};
        pending.peer_identities = context ? extract_peer_identities(*context) : std::vector<std::string>{};
        pending.created_at = std::chrono::steady_clock::now();
        {
            std::lock_guard lock(pending_mu_);
            prune_expired_pending_locked();
            pending_by_session_id_[session_id] = std::move(pending);
        }

        return grpc::Status::OK;
    }

    grpc::Status Subscribe(
        grpc::ServerContext* context,
        grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream) override
    {
        if (!context) {
            return grpc::Status(grpc::StatusCode::INTERNAL, "missing server context");
        }

        const auto session_id = client_metadata_value(*context, kSessionMetadataKey);
        if (session_id.empty()) {
            spdlog::warn("Subscribe rejected: missing {} metadata", kSessionMetadataKey);
            return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                                "missing session metadata");
        }

        std::string agent_id;
        {
            std::lock_guard lock(pending_mu_);
            prune_expired_pending_locked();
            auto it = pending_by_session_id_.find(session_id);
            if (it == pending_by_session_id_.end()) {
                spdlog::warn("Subscribe rejected: unknown or expired session id");
                return grpc::Status(grpc::StatusCode::FAILED_PRECONDITION,
                                    "invalid or expired session");
            }

            if (!gateway_mode_ && it->second.register_peer != context->peer()) {
                spdlog::warn("Subscribe rejected: peer mismatch for session {}", session_id);
                return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "peer mismatch");
            }

            if (require_client_identity_) {
                const auto subscribe_ids = extract_peer_identities(*context);
                if (!has_identity_overlap(it->second.peer_identities, subscribe_ids)) {
                    spdlog::warn("Subscribe rejected: mTLS identity mismatch for session {}", session_id);
                    return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "peer identity mismatch");
                }
            }

            agent_id = it->second.agent_id;
            pending_by_session_id_.erase(it);
        }

        spdlog::info("Agent subscribe stream opened for {}", agent_id);
        registry_.set_stream(agent_id, stream);

        // Read loop — process responses from the agent
        pb::CommandResponse resp;
        while (stream->Read(&resp)) {
            if (resp.status() == pb::CommandResponse::RUNNING) {
                // Intercept __timing__ metadata
                if (resp.output().starts_with("__timing__|")) {
                    auto payload = resp.output().substr(11);
                    bus_.publish("timing",
                        resp.command_id() + "|" + payload + "|agent_total");
                    continue;
                }

                // Track first response for server-side latency
                {
                    std::lock_guard lock(cmd_times_mu_);
                    if (cmd_first_seen_.find(resp.command_id()) == cmd_first_seen_.end()) {
                        cmd_first_seen_.insert(resp.command_id());
                        auto it = cmd_send_times_.find(resp.command_id());
                        if (it != cmd_send_times_.end()) {
                            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - it->second).count();
                            bus_.publish("timing",
                                resp.command_id() + "|first_data_ms="
                                + std::to_string(elapsed) + "|first_data");
                        }
                    }
                }

                // Determine the plugin from command_id prefix (format: plugin-timestamp)
                std::string plugin = extract_plugin(resp.command_id());

                // Publish as generic output event: agent_id|plugin|data
                bus_.publish("output",
                    agent_id + "|" + plugin + "|" + resp.output());

            } else {
                spdlog::info("Command {} completed: status={}, exit_code={}",
                    resp.command_id(),
                    static_cast<int>(resp.status()),
                    resp.exit_code());

                std::string status_str =
                    (resp.status() == pb::CommandResponse::SUCCESS) ? "done" : "error";
                bus_.publish("command-status",
                    resp.command_id() + "|" + status_str);

                // Publish total round-trip and clean up timing maps
                {
                    std::lock_guard lock(cmd_times_mu_);
                    auto it = cmd_send_times_.find(resp.command_id());
                    if (it != cmd_send_times_.end()) {
                        auto total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - it->second).count();
                        bus_.publish("timing",
                            resp.command_id() + "|total_ms="
                            + std::to_string(total_ms) + "|complete");
                        cmd_send_times_.erase(it);
                    }
                    cmd_first_seen_.erase(resp.command_id());
                }
            }
        }

        // Agent disconnected
        registry_.clear_stream(agent_id);
        registry_.remove_agent(agent_id);
        spdlog::info("Agent subscribe stream closed for {}", agent_id);

        return grpc::Status::OK;
    }

    // Record send time for latency measurement.
    void record_send_time(const std::string& command_id) {
        std::lock_guard lock(cmd_times_mu_);
        cmd_send_times_[command_id] = std::chrono::steady_clock::now();
    }

private:
    struct PendingRegistration {
        std::string agent_id;
        std::string register_peer;
        std::vector<std::string> peer_identities;
        std::chrono::steady_clock::time_point created_at;
    };

    static std::vector<std::string> extract_peer_identities(const grpc::ServerContext& context) {
        std::vector<std::string> out;
        auto auth_ctx = context.auth_context();
        if (!auth_ctx || !auth_ctx->IsPeerAuthenticated()) {
            return out;
        }

        auto append_unique = [&out](std::string_view s) {
            if (s.empty()) return;
            for (const auto& existing : out) {
                if (existing == s) return;
            }
            out.emplace_back(s);
        };

        for (const auto& id : auth_ctx->GetPeerIdentity()) {
            append_unique(std::string_view{id.data(), id.size()});
        }
        for (const auto& cn : auth_ctx->FindPropertyValues(GRPC_X509_CN_PROPERTY_NAME)) {
            append_unique(std::string_view{cn.data(), cn.size()});
        }
        for (const auto& san : auth_ctx->FindPropertyValues(GRPC_X509_SAN_PROPERTY_NAME)) {
            append_unique(std::string_view{san.data(), san.size()});
        }

        return out;
    }

    static bool peer_identity_matches_agent_id(const grpc::ServerContext& context,
                                               const std::string& agent_id) {
        if (agent_id.empty()) return false;
        const auto identities = extract_peer_identities(context);
        for (const auto& id : identities) {
            if (id == agent_id) return true;
        }
        return false;
    }

    static std::string client_metadata_value(const grpc::ServerContext& context,
                                             std::string_view key) {
        const auto& md = context.client_metadata();
        auto it = md.find(std::string(key));
        if (it == md.end()) return {};
        return std::string(it->second.data(), it->second.length());
    }

    static bool has_identity_overlap(const std::vector<std::string>& lhs,
                                     const std::vector<std::string>& rhs) {
        for (const auto& left : lhs) {
            for (const auto& right : rhs) {
                if (left == right) return true;
            }
        }
        return false;
    }

    void prune_expired_pending_locked() {
        const auto now = std::chrono::steady_clock::now();
        for (auto it = pending_by_session_id_.begin(); it != pending_by_session_id_.end();) {
            if (now - it->second.created_at > kPendingRegistrationTtl) {
                it = pending_by_session_id_.erase(it);
            } else {
                ++it;
            }
        }
    }

    static std::string extract_plugin(const std::string& command_id) {
        // command_id format: "plugin-timestamp" e.g. "chargen-12345" or "netstat-12345"
        auto dash = command_id.find('-');
        if (dash != std::string::npos) {
            return command_id.substr(0, dash);
        }
        return command_id;
    }

    AgentRegistry& registry_;
    EventBus& bus_;
    auth::AuthManager& auth_mgr_;
    auth::AutoApproveEngine& auto_approve_;

    static constexpr std::string_view kSessionMetadataKey = "x-yuzu-session-id";
    static constexpr auto kPendingRegistrationTtl = std::chrono::seconds(60);

    // Pending Register calls waiting for the corresponding Subscribe.
    std::mutex pending_mu_;
    std::unordered_map<std::string, PendingRegistration> pending_by_session_id_;

    // Command timing instrumentation
    std::mutex cmd_times_mu_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> cmd_send_times_;
    std::unordered_set<std::string> cmd_first_seen_;
    bool require_client_identity_{false};
    bool gateway_mode_{false};
};

// -- ManagementServiceImpl ----------------------------------------------------

class ManagementServiceImpl : public ::yuzu::server::v1::ManagementService::Service {
public:
    // Placeholder.
};

// -- GatewayUpstreamServiceImpl -----------------------------------------------

class GatewayUpstreamServiceImpl : public gw::GatewayUpstream::Service {
public:
    GatewayUpstreamServiceImpl(AgentRegistry& registry, EventBus& bus,
                               auth::AuthManager& auth_mgr,
                               auth::AutoApproveEngine& auto_approve)
        : registry_(registry), bus_(bus),
          auth_mgr_(auth_mgr), auto_approve_(auto_approve) {}

    // -- ProxyRegister --------------------------------------------------------
    // Gateway forwards an agent's RegisterRequest.  We run the same enrollment
    // logic as AgentServiceImpl::Register but skip peer-identity checks (the
    // gateway is a trusted internal service).

    grpc::Status ProxyRegister(
        grpc::ServerContext* /*context*/,
        const pb::RegisterRequest* request,
        pb::RegisterResponse* response) override
    {
        const auto& info = request->info();

        // ── Tiered enrollment (same logic as AgentServiceImpl::Register) ─────
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
            spdlog::info("[gateway] Agent {} auto-enrolled via enrollment token",
                         info.agent_id());
            auth_mgr_.remove_pending_agent(info.agent_id());
        } else {
            // Auto-approve policies (no peer IP available from gateway yet)
            auth::ApprovalContext approval_ctx;
            approval_ctx.hostname = info.hostname();
            approval_ctx.attestation_provider = request->attestation_provider();

            auto matched_rule = auto_approve_.evaluate(approval_ctx);
            if (!matched_rule.empty()) {
                spdlog::info("[gateway] Agent {} auto-approved by policy: {}",
                             info.agent_id(), matched_rule);
                auth_mgr_.remove_pending_agent(info.agent_id());
            } else {
                // Tier 1: pending queue
                auto pending_status = auth_mgr_.get_pending_status(info.agent_id());

                if (!pending_status) {
                    auth_mgr_.add_pending_agent(
                        info.agent_id(),
                        info.hostname(),
                        info.platform().os(),
                        info.platform().arch(),
                        info.agent_version());

                    response->set_accepted(false);
                    response->set_reject_reason("awaiting admin approval");
                    response->set_enrollment_status("pending");
                    bus_.publish("pending-agent", info.agent_id());
                    spdlog::info("[gateway] Agent {} placed in pending queue",
                                 info.agent_id());
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
                        spdlog::info("[gateway] Agent {} enrolled (admin-approved)",
                                     info.agent_id());
                        break;
                }
            }
        }

        // ── Enrolled — register the agent ────────────────────────────────────
        registry_.register_agent(info);

        auto session_id = "gw-session-" + auth::AuthManager::bytes_to_hex(
            auth::AuthManager::random_bytes(16));
        response->set_session_id(session_id);
        response->set_accepted(true);
        response->set_enrollment_status("enrolled");

        {
            std::lock_guard lock(sessions_mu_);
            gateway_sessions_[session_id] = info.agent_id();
        }

        spdlog::info("[gateway] ProxyRegister succeeded: agent={}, session={}",
                     info.agent_id(), session_id);
        return grpc::Status::OK;
    }

    // -- BatchHeartbeat -------------------------------------------------------

    grpc::Status BatchHeartbeat(
        grpc::ServerContext* /*context*/,
        const gw::BatchHeartbeatRequest* request,
        gw::BatchHeartbeatResponse* response) override
    {
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
                spdlog::debug("[gateway] BatchHeartbeat: unknown session {}",
                              hb.session_id());
                continue;
            }
            // TODO: Update last-heartbeat timestamp in registry when session
            //       timeout tracking is implemented.
            ++acked;
        }

        response->set_acknowledged_count(acked);
        spdlog::debug("[gateway] BatchHeartbeat from node '{}': {}/{} acked",
                      request->gateway_node(), acked, request->heartbeats_size());
        return grpc::Status::OK;
    }

    // -- ProxyInventory -------------------------------------------------------

    grpc::Status ProxyInventory(
        grpc::ServerContext* /*context*/,
        const pb::InventoryReport* request,
        pb::InventoryAck* response) override
    {
        std::string agent_id;
        {
            std::lock_guard lock(sessions_mu_);
            auto it = gateway_sessions_.find(request->session_id());
            if (it != gateway_sessions_.end()) {
                agent_id = it->second;
            }
        }
        if (agent_id.empty()) {
            spdlog::warn("[gateway] ProxyInventory: unknown session {}",
                         request->session_id());
            response->set_received(false);
            return grpc::Status::OK;
        }

        // TODO: Persist inventory data once storage layer is implemented.
        spdlog::info("[gateway] ProxyInventory received for agent={}, plugins={}",
                     agent_id, request->plugin_data_size());
        response->set_received(true);
        return grpc::Status::OK;
    }

    // -- NotifyStreamStatus ---------------------------------------------------

    grpc::Status NotifyStreamStatus(
        grpc::ServerContext* /*context*/,
        const gw::StreamStatusNotification* request,
        gw::StreamStatusAck* response) override
    {
        const auto& agent_id  = request->agent_id();
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
                // The gateway now owns the Subscribe stream for this agent.
                // We don't have a local stream pointer, so we mark stream as null
                // but keep the agent registered (it was registered in ProxyRegister).
                spdlog::info("[gateway] Agent {} stream CONNECTED at gateway node '{}'",
                             agent_id, request->gateway_node());
                break;

            case gw::StreamStatusNotification::DISCONNECTED:
                registry_.clear_stream(agent_id);
                registry_.remove_agent(agent_id);
                {
                    std::lock_guard lock(sessions_mu_);
                    gateway_sessions_.erase(session_id);
                }
                spdlog::info("[gateway] Agent {} stream DISCONNECTED at gateway node '{}'",
                             agent_id, request->gateway_node());
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

private:
    AgentRegistry& registry_;
    EventBus& bus_;
    auth::AuthManager& auth_mgr_;
    auth::AutoApproveEngine& auto_approve_;

    // Map of gateway session_id → agent_id for validation.
    std::mutex sessions_mu_;
    std::unordered_map<std::string, std::string> gateway_sessions_;
};

// -- File-reading helper ------------------------------------------------------

std::string read_file_contents(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return {};
    return std::string(std::istreambuf_iterator<char>(f),
                       std::istreambuf_iterator<char>());
}

}  // namespace detail

// -- ServerImpl ---------------------------------------------------------------

class ServerImpl final : public Server {
public:
    explicit ServerImpl(Config cfg, auth::AuthManager& auth_mgr)
        : cfg_(std::move(cfg)),
          auth_mgr_(auth_mgr),
          registry_(event_bus_),
          agent_service_(registry_, event_bus_,
              cfg_.tls_enabled && !cfg_.tls_ca_cert.empty(),
              auth_mgr, auto_approve_, cfg_.gateway_mode)
    {
        // Create gateway upstream service if configured
        if (!cfg_.gateway_upstream_address.empty()) {
            gateway_service_ = std::make_unique<detail::GatewayUpstreamServiceImpl>(
                registry_, event_bus_, auth_mgr, auto_approve_);
        }

        // Load auto-approve policies
        auto approve_path = cfg_.auth_config_path.parent_path() / "auto-approve.cfg";
        auto_approve_.load(approve_path);
        // Setup file logger
        auto log_path = detail::server_log_path();
        auto parent = log_path.parent_path();
        if (!parent.empty()) {
            std::error_code ec;
            std::filesystem::create_directories(parent, ec);
            if (ec) {
                spdlog::warn("Could not create log directory {}: {}",
                    parent.string(), ec.message());
            }
        }
        try {
            file_logger_ = spdlog::basic_logger_mt(
                "server_file", log_path.string());
            file_logger_->set_pattern(
                "[%Y-%m-%d %H:%M:%S.%e] [server] %v");
            file_logger_->flush_on(spdlog::level::info);
            spdlog::info("Log file: {}", log_path.string());
        } catch (const spdlog::spdlog_ex& ex) {
            spdlog::error("Failed to create file logger: {}", ex.what());
        }
    }

    void run() override {
        spdlog::info("run(): entering");
        grpc::EnableDefaultHealthCheckService(true);

        std::shared_ptr<grpc::ServerCredentials> agent_creds = grpc::InsecureServerCredentials();
        std::shared_ptr<grpc::ServerCredentials> mgmt_creds = grpc::InsecureServerCredentials();
        if (cfg_.tls_enabled) {
            auto tls = build_tls_credentials(
                cfg_.tls_server_cert,
                cfg_.tls_server_key,
                cfg_.tls_ca_cert,
                cfg_.allow_one_way_tls,
                "agent listener");
            if (tls) {
                agent_creds = std::move(tls);
            } else {
                spdlog::error("TLS is enabled but credentials are invalid; refusing to start");
                return;
            }

            if (!cfg_.mgmt_tls_server_cert.empty() || !cfg_.mgmt_tls_server_key.empty() ||
                !cfg_.mgmt_tls_ca_cert.empty()) {
                auto mgmt_tls = build_tls_credentials(
                    cfg_.mgmt_tls_server_cert,
                    cfg_.mgmt_tls_server_key,
                    cfg_.mgmt_tls_ca_cert,
                    true,
                    "management listener");
                if (!mgmt_tls) {
                    spdlog::error("Management TLS credentials are invalid; refusing to start");
                    return;
                }
                mgmt_creds = std::move(mgmt_tls);
            } else {
                mgmt_creds = agent_creds;
            }
        }

        grpc::ServerBuilder builder;
        builder.AddChannelArgument(GRPC_ARG_KEEPALIVE_TIME_MS, 60000);
        builder.AddChannelArgument(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 20000);
        builder.AddChannelArgument(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS, 1);
        builder.AddChannelArgument(GRPC_ARG_HTTP2_MAX_PINGS_WITHOUT_DATA, 0);
        builder.AddChannelArgument(GRPC_ARG_HTTP2_MIN_RECV_PING_INTERVAL_WITHOUT_DATA_MS, 30000);
        builder.AddListeningPort(cfg_.listen_address, agent_creds);
        builder.AddListeningPort(cfg_.management_address, mgmt_creds);
        builder.RegisterService(&agent_service_);
        builder.RegisterService(&mgmt_service_);

        if (gateway_service_) {
            // Gateway upstream uses the same credentials as the management listener
            // (internal traffic, typically mTLS between gateway and server).
            builder.AddListeningPort(cfg_.gateway_upstream_address, mgmt_creds);
            builder.RegisterService(gateway_service_.get());
            spdlog::info("Gateway upstream service enabled on {}",
                         cfg_.gateway_upstream_address);
        }

        agent_server_ = builder.BuildAndStart();

        if (!agent_server_) {
            spdlog::error("Failed to start gRPC server -- check that ports {} and {} are available",
                cfg_.listen_address, cfg_.management_address);
            return;
        }

        spdlog::info("Yuzu Server listening on {} (agents) and {} (management)",
            cfg_.listen_address, cfg_.management_address);
        if (gateway_service_) {
            spdlog::info("Gateway upstream listening on {}", cfg_.gateway_upstream_address);
        }

        start_web_server();
        agent_server_->Wait();
    }

    void stop() noexcept override {
        spdlog::info("Shutting down server...");

        if (web_server_) {
            web_server_->stop();
        }
        if (web_thread_.joinable()) {
            web_thread_.join();
        }

        if (agent_server_) agent_server_->Shutdown();
        if (mgmt_server_)  mgmt_server_->Shutdown();
    }

private:
    // -- TLS ------------------------------------------------------------------

    [[nodiscard]] std::shared_ptr<grpc::ServerCredentials>
    build_tls_credentials(const std::filesystem::path& cert_path,
                          const std::filesystem::path& key_path,
                          const std::filesystem::path& ca_path,
                          bool allow_one_way_tls,
                          std::string_view listener_name) const {
        if (cert_path.empty() || key_path.empty()) {
            spdlog::error("{} TLS requires certificate and key", listener_name);
            return nullptr;
        }

        auto cert = detail::read_file_contents(cert_path);
        auto key  = detail::read_file_contents(key_path);
        if (cert.empty() || key.empty()) {
            spdlog::error("Failed to read {} TLS cert/key files", listener_name);
            return nullptr;
        }

        grpc::SslServerCredentialsOptions ssl_opts;
        grpc::SslServerCredentialsOptions::PemKeyCertPair pair;
        pair.private_key = std::move(key);
        pair.cert_chain  = std::move(cert);
        ssl_opts.pem_key_cert_pairs.push_back(std::move(pair));

        if (!ca_path.empty()) {
            auto ca = detail::read_file_contents(ca_path);
            if (ca.empty()) {
                spdlog::error("Failed to read {} CA cert from {}", listener_name, ca_path.string());
                return nullptr;
            }

            ssl_opts.pem_root_certs = std::move(ca);
            ssl_opts.client_certificate_request =
                GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;
        } else {
            if (!allow_one_way_tls) {
                spdlog::error("{} TLS requires --ca-cert (or enable --allow-one-way-tls)", listener_name);
                return nullptr;
            }
            spdlog::warn("{} TLS running without client certificate verification", listener_name);
        }

        return grpc::SslServerCredentials(ssl_opts);
    }

    // -- Web server -----------------------------------------------------------

    // -- Base64 decode --------------------------------------------------------

    static std::string base64_decode(const std::string& in) {
        static constexpr unsigned char kTable[256] = {
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,62,64,64,64,63,
            52,53,54,55,56,57,58,59,60,61,64,64,64,64,64,64,
            64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
            15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,
            64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
            41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
            64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64
        };
        std::string out;
        out.reserve(in.size() * 3 / 4);
        unsigned int val = 0;
        int bits = -8;
        for (unsigned char c : in) {
            if (kTable[c] == 64) continue;
            val = (val << 6) | kTable[c];
            bits += 6;
            if (bits >= 0) {
                out += static_cast<char>((val >> bits) & 0xFF);
                bits -= 8;
            }
        }
        return out;
    }

    // -- HTML helpers ---------------------------------------------------------

    static std::string html_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&':  out += "&amp;"; break;
                case '<':  out += "&lt;"; break;
                case '>':  out += "&gt;"; break;
                case '"':  out += "&quot;"; break;
                case '\'': out += "&#39;"; break;
                default:   out += c;
            }
        }
        return out;
    }

    // -- Auth helpers for HTTP ------------------------------------------------

    static std::string extract_session_cookie(const httplib::Request& req) {
        auto cookie = req.get_header_value("Cookie");
        // Find yuzu_session=<token>
        const std::string prefix = "yuzu_session=";
        auto pos = cookie.find(prefix);
        if (pos == std::string::npos) return {};
        pos += prefix.size();
        auto end = cookie.find(';', pos);
        return cookie.substr(pos, end == std::string::npos ? end : end - pos);
    }

    static std::string url_decode(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (std::size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '%' && i + 2 < s.size()) {
                auto hex = s.substr(i + 1, 2);
                out += static_cast<char>(std::stoul(hex, nullptr, 16));
                i += 2;
            } else if (s[i] == '+') {
                out += ' ';
            } else {
                out += s[i];
            }
        }
        return out;
    }

    static std::string extract_form_value(const std::string& body, const std::string& key) {
        auto needle = key + "=";
        auto pos = body.find(needle);
        if (pos == std::string::npos) return {};
        pos += needle.size();
        auto end = body.find('&', pos);
        auto raw = body.substr(pos, end == std::string::npos ? end : end - pos);
        return url_decode(raw);
    }

    std::optional<auth::Session> require_auth(const httplib::Request& req,
                                              httplib::Response& res) {
        auto token = extract_session_cookie(req);
        auto session = auth_mgr_.validate_session(token);
        if (!session) {
            res.status = 401;
            res.set_content(R"({"error":"unauthorized"})", "application/json");
        }
        return session;
    }

    bool require_admin(const httplib::Request& req, httplib::Response& res) {
        auto session = require_auth(req, res);
        if (!session) return false;
        if (session->role != auth::Role::admin) {
            res.status = 403;
            res.set_content(R"({"error":"admin role required"})", "application/json");
            return false;
        }
        return true;
    }

    // -- HTML fragment renderers for HTMX Settings page -------------------------

    std::string render_tls_fragment() {
        std::string checked = cfg_.tls_enabled ? " checked" : "";
        std::string status_color = cfg_.tls_enabled ? "#3fb950" : "#f85149";
        std::string status_text = cfg_.tls_enabled ? "Enabled" : "Disabled";
        std::string fields_opacity = cfg_.tls_enabled ? "1" : "0.4";

        std::string cert_name = cfg_.tls_server_cert.empty() ? "No file" : html_escape(cfg_.tls_server_cert.string());
        std::string key_name = cfg_.tls_server_key.empty() ? "No file" : html_escape(cfg_.tls_server_key.string());
        std::string ca_name = cfg_.tls_ca_cert.empty() ? "No file" : html_escape(cfg_.tls_ca_cert.string());

        return
            "<form id=\"tls-form\">"
            "<div class=\"form-row\">"
            "  <label>gRPC mTLS</label>"
            "  <label class=\"toggle\">"
            "    <input type=\"checkbox\" name=\"tls_enabled\" value=\"true\"" + checked +
            "           hx-post=\"/api/settings/tls\" hx-target=\"#tls-feedback\""
            "           hx-swap=\"innerHTML\">"
            "    <span class=\"slider\"></span>"
            "  </label>"
            "  <span style=\"font-size:0.75rem;color:" + status_color + ";margin-left:0.5rem\">"
            + status_text + "</span>"
            "</div>"
            "<div style=\"margin-top:1rem;opacity:" + fields_opacity + "\">"
            "  <div class=\"form-row\">"
            "    <label>Server Certificate</label>"
            "    <div class=\"file-upload\">"
            "      <form hx-post=\"/api/settings/cert-upload\" hx-target=\"#tls-feedback\" hx-swap=\"innerHTML\""
            "            hx-encoding=\"multipart/form-data\" style=\"display:flex;align-items:center;gap:0.75rem\">"
            "        <input type=\"hidden\" name=\"type\" value=\"cert\">"
            "        <input type=\"file\" name=\"file\" accept=\".pem,.crt,.cer\""
            "               onchange=\"this.form.requestSubmit()\" style=\"display:none\" id=\"cert-file\">"
            "        <button type=\"button\" class=\"btn btn-secondary\""
            "                onclick=\"document.getElementById('cert-file').click()\">Upload PEM</button>"
            "        <span class=\"file-name\">" + cert_name + "</span>"
            "      </form>"
            "    </div>"
            "  </div>"
            "  <div class=\"form-row\">"
            "    <label>Server Private Key</label>"
            "    <div class=\"file-upload\">"
            "      <form hx-post=\"/api/settings/cert-upload\" hx-target=\"#tls-feedback\" hx-swap=\"innerHTML\""
            "            hx-encoding=\"multipart/form-data\" style=\"display:flex;align-items:center;gap:0.75rem\">"
            "        <input type=\"hidden\" name=\"type\" value=\"key\">"
            "        <input type=\"file\" name=\"file\" accept=\".pem,.key\""
            "               onchange=\"this.form.requestSubmit()\" style=\"display:none\" id=\"key-file\">"
            "        <button type=\"button\" class=\"btn btn-secondary\""
            "                onclick=\"document.getElementById('key-file').click()\">Upload PEM</button>"
            "        <span class=\"file-name\">" + key_name + "</span>"
            "      </form>"
            "    </div>"
            "  </div>"
            "  <div class=\"form-row\">"
            "    <label>CA Certificate</label>"
            "    <div class=\"file-upload\">"
            "      <form hx-post=\"/api/settings/cert-upload\" hx-target=\"#tls-feedback\" hx-swap=\"innerHTML\""
            "            hx-encoding=\"multipart/form-data\" style=\"display:flex;align-items:center;gap:0.75rem\">"
            "        <input type=\"hidden\" name=\"type\" value=\"ca\">"
            "        <input type=\"file\" name=\"file\" accept=\".pem,.crt,.cer\""
            "               onchange=\"this.form.requestSubmit()\" style=\"display:none\" id=\"ca-file\">"
            "        <button type=\"button\" class=\"btn btn-secondary\""
            "                onclick=\"document.getElementById('ca-file').click()\">Upload PEM</button>"
            "        <span class=\"file-name\">" + ca_name + "</span>"
            "      </form>"
            "    </div>"
            "  </div>"
            "</div>"
            "</form>"
            "<div class=\"feedback\" id=\"tls-feedback\"></div>";
    }

    std::string render_users_fragment() {
        auto users = auth_mgr_.list_users();
        std::string html =
            "<table class=\"user-table\">"
            "  <thead><tr><th>Username</th><th>Role</th><th></th></tr></thead>"
            "  <tbody>";

        if (users.empty()) {
            html += "<tr><td colspan=\"3\" style=\"color:#484f58\">No users</td></tr>";
        } else {
            for (const auto& u : users) {
                auto role_str = auth::role_to_string(u.role);
                auto cls = (u.role == auth::Role::admin) ? "role-admin" : "role-user";
                html += "<tr><td>" + html_escape(u.username) + "</td>"
                        "<td><span class=\"role-badge " + std::string(cls) + "\">" +
                        html_escape(role_str) + "</span></td>"
                        "<td><button class=\"btn btn-danger\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                        "hx-delete=\"/api/settings/users/" + html_escape(u.username) + "\" "
                        "hx-target=\"#user-section\" hx-swap=\"innerHTML\" "
                        "hx-confirm=\"Remove user &quot;" + html_escape(u.username) + "&quot;?\""
                        ">Remove</button></td></tr>";
            }
        }

        html +=
            "  </tbody>"
            "</table>"
            "<form class=\"add-user-form\" hx-post=\"/api/settings/users\" "
            "      hx-target=\"#user-section\" hx-swap=\"innerHTML\">"
            "  <div class=\"mini-field\">"
            "    <label>Username</label>"
            "    <input type=\"text\" name=\"username\" placeholder=\"username\" required>"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>Password</label>"
            "    <input type=\"password\" name=\"password\" placeholder=\"password\" required>"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>Role</label>"
            "    <select name=\"role\">"
            "      <option value=\"user\">User</option>"
            "      <option value=\"admin\">Admin</option>"
            "    </select>"
            "  </div>"
            "  <button class=\"btn btn-primary\" type=\"submit\">Add User</button>"
            "</form>"
            "<div class=\"feedback\" id=\"user-feedback\"></div>";

        return html;
    }

    std::string render_tokens_fragment(const std::string& new_raw_token = {}) {
        auto tokens = auth_mgr_.list_enrollment_tokens();
        std::string html =
            "<table class=\"user-table\">"
            "  <thead><tr><th>ID</th><th>Label</th><th>Uses</th>"
            "  <th>Expires</th><th>Status</th><th></th></tr></thead>"
            "  <tbody>";

        if (tokens.empty()) {
            html += "<tr><td colspan=\"6\" style=\"color:#484f58\">No tokens created</td></tr>";
        } else {
            for (const auto& t : tokens) {
                auto uses = t.max_uses == 0
                    ? std::to_string(t.use_count) + " / \xe2\x88\x9e"
                    : std::to_string(t.use_count) + " / " + std::to_string(t.max_uses);

                std::string exp;
                if (t.expires_at == (std::chrono::system_clock::time_point::max)()) {
                    exp = "Never";
                } else {
                    auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
                        t.expires_at.time_since_epoch()).count();
                    exp = std::to_string(epoch);  // epoch seconds, formatted client-side
                }

                std::string status_cls, status_txt;
                if (t.revoked) {
                    status_cls = "role-user"; status_txt = "Revoked";
                } else if (t.max_uses > 0 && t.use_count >= t.max_uses) {
                    status_cls = "role-user"; status_txt = "Exhausted";
                } else {
                    status_cls = "role-admin"; status_txt = "Active";
                }

                html += "<tr><td><code>" + html_escape(t.token_id) + "</code></td>"
                        "<td>" + html_escape(t.label) + "</td>"
                        "<td>" + uses + "</td>"
                        "<td style=\"font-size:0.75rem\">" + exp + "</td>"
                        "<td><span class=\"role-badge " + status_cls + "\">" + status_txt + "</span></td>"
                        "<td>";
                if (!t.revoked) {
                    html += "<button class=\"btn btn-danger\" "
                            "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                            "hx-delete=\"/api/settings/enrollment-tokens/" + html_escape(t.token_id) + "\" "
                            "hx-target=\"#token-section\" hx-swap=\"innerHTML\" "
                            "hx-confirm=\"Revoke token &quot;" + html_escape(t.token_id) +
                            "&quot;? Agents using this token will no longer be able to enroll.\""
                            ">Revoke</button>";
                }
                html += "</td></tr>";
            }
        }

        html +=
            "  </tbody>"
            "</table>"
            "<form class=\"add-user-form\" hx-post=\"/api/settings/enrollment-tokens\" "
            "      hx-target=\"#token-section\" hx-swap=\"innerHTML\">"
            "  <div class=\"mini-field\">"
            "    <label>Label</label>"
            "    <input type=\"text\" name=\"label\" placeholder=\"e.g. NYC rollout\" style=\"width:160px\">"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>Max Uses</label>"
            "    <input type=\"text\" name=\"max_uses\" placeholder=\"0 = unlimited\" style=\"width:80px\">"
            "  </div>"
            "  <div class=\"mini-field\">"
            "    <label>TTL (hours)</label>"
            "    <input type=\"text\" name=\"ttl_hours\" placeholder=\"0 = never\" style=\"width:80px\">"
            "  </div>"
            "  <button class=\"btn btn-primary\" type=\"submit\">Generate Token</button>"
            "</form>"
            "<div class=\"feedback\" id=\"token-feedback\"></div>";

        // Show the one-time token reveal if a new token was just created
        if (!new_raw_token.empty()) {
            html +=
                "<div class=\"token-reveal\">"
                "  <div class=\"token-reveal-header\">"
                "    COPY THIS TOKEN NOW — it will not be shown again"
                "  </div>"
                "  <code>" + html_escape(new_raw_token) + "</code><br>"
                "  <button class=\"btn btn-secondary\" style=\"margin-top:0.5rem;font-size:0.7rem\" "
                "          data-copy-token>Copy to Clipboard</button>"
                "</div>";
        }

        return html;
    }

    std::string render_pending_fragment() {
        auto agents = auth_mgr_.list_pending_agents();
        std::string html =
            "<table class=\"user-table\">"
            "  <thead><tr><th>Agent ID</th><th>Hostname</th><th>OS</th>"
            "  <th>Version</th><th>Status</th><th></th></tr></thead>"
            "  <tbody>";

        if (agents.empty()) {
            html += "<tr><td colspan=\"6\" style=\"color:#484f58\">No pending agents</td></tr>";
        } else {
            for (const auto& a : agents) {
                auto status_str = auth::pending_status_to_string(a.status);
                std::string status_cls, status_style;
                if (a.status == auth::PendingStatus::approved) {
                    status_cls = "role-admin";
                } else if (a.status == auth::PendingStatus::denied) {
                    status_cls = "role-user";
                } else {
                    status_style = "background:var(--yellow);color:#000";
                }

                // Truncate agent ID for display
                auto short_id = a.agent_id.size() > 12
                    ? a.agent_id.substr(0, 12) + "..."
                    : a.agent_id;

                html += "<tr>"
                        "<td><code style=\"font-size:0.7rem\">" + html_escape(short_id) + "</code></td>"
                        "<td>" + html_escape(a.hostname) + "</td>"
                        "<td>" + html_escape(a.os) + " " + html_escape(a.arch) + "</td>"
                        "<td>" + html_escape(a.agent_version) + "</td>"
                        "<td><span class=\"role-badge " + status_cls + "\" style=\"" + status_style + "\">" +
                        html_escape(status_str) + "</span></td>"
                        "<td>";

                if (a.status == auth::PendingStatus::pending) {
                    html += "<button class=\"btn btn-primary\" "
                            "style=\"padding:0.2rem 0.6rem;font-size:0.7rem;margin-right:0.3rem\" "
                            "hx-post=\"/api/settings/pending-agents/" + html_escape(a.agent_id) + "/approve\" "
                            "hx-target=\"#pending-section\" hx-swap=\"innerHTML\""
                            ">Approve</button>"
                            "<button class=\"btn btn-danger\" "
                            "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                            "hx-post=\"/api/settings/pending-agents/" + html_escape(a.agent_id) + "/deny\" "
                            "hx-target=\"#pending-section\" hx-swap=\"innerHTML\" "
                            "hx-confirm=\"Deny agent enrollment?\""
                            ">Deny</button>";
                } else {
                    html += "<button class=\"btn btn-secondary\" "
                            "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                            "hx-delete=\"/api/settings/pending-agents/" + html_escape(a.agent_id) + "\" "
                            "hx-target=\"#pending-section\" hx-swap=\"innerHTML\""
                            ">Remove</button>";
                }

                html += "</td></tr>";
            }
        }

        html +=
            "  </tbody>"
            "</table>"
            "<div class=\"feedback\" id=\"pending-feedback\"></div>";

        return html;
    }

    std::string render_auto_approve_fragment() {
        auto rules = auto_approve_.list_rules();
        std::string html;

        // Mode selector
        html += "<div class=\"form-row\" style=\"margin-bottom:1rem\">"
                "<label>Match mode</label>"
                "<select name=\"mode\" "
                "hx-post=\"/api/settings/auto-approve/mode\" "
                "hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\" "
                "style=\"flex:0 0 auto;width:180px\">"
                "<option value=\"any\"" + std::string(auto_approve_.require_all() ? "" : " selected") + ">Any rule (first match)</option>"
                "<option value=\"all\"" + std::string(auto_approve_.require_all() ? " selected" : "") + ">All rules must match</option>"
                "</select>"
                "</div>";

        // Rules table
        html += "<table class=\"user-table\">"
                "<thead><tr><th>Type</th><th>Value</th><th>Label</th>"
                "<th>Enabled</th><th></th></tr></thead><tbody>";

        if (rules.empty()) {
            html += "<tr><td colspan=\"5\" style=\"color:#484f58\">No auto-approve rules configured</td></tr>";
        } else {
            auto type_str = [](auth::AutoApproveRuleType t) -> std::string {
                switch (t) {
                    case auth::AutoApproveRuleType::trusted_ca:     return "Trusted CA";
                    case auth::AutoApproveRuleType::hostname_glob:  return "Hostname Glob";
                    case auth::AutoApproveRuleType::ip_subnet:      return "IP Subnet";
                    case auth::AutoApproveRuleType::cloud_provider: return "Cloud Provider";
                }
                return "Unknown";
            };

            for (size_t i = 0; i < rules.size(); ++i) {
                const auto& r = rules[i];
                auto idx = std::to_string(i);
                html += "<tr>"
                        "<td>" + html_escape(type_str(r.type)) + "</td>"
                        "<td><code style=\"font-size:0.75rem\">" + html_escape(r.value) + "</code></td>"
                        "<td>" + html_escape(r.label) + "</td>"
                        "<td>"
                        "<label class=\"toggle\">"
                        "<input type=\"checkbox\"" + std::string(r.enabled ? " checked" : "") +
                        " hx-post=\"/api/settings/auto-approve/" + idx + "/toggle\" "
                        "hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\">"
                        "<span class=\"slider\"></span></label></td>"
                        "<td><button class=\"btn btn-danger\" "
                        "style=\"padding:0.2rem 0.6rem;font-size:0.7rem\" "
                        "hx-delete=\"/api/settings/auto-approve/" + idx + "\" "
                        "hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\" "
                        "hx-confirm=\"Remove this auto-approve rule?\" "
                        ">Remove</button></td></tr>";
            }
        }

        html += "</tbody></table>";

        // Add rule form
        html += "<div class=\"add-user-form\">"
                "<form hx-post=\"/api/settings/auto-approve\" "
                "hx-target=\"#auto-approve-section\" hx-swap=\"innerHTML\" "
                "style=\"display:flex;gap:0.5rem;align-items:flex-end;width:100%\">"
                "<div class=\"mini-field\">"
                "<label>Type</label>"
                "<select name=\"type\" style=\"width:140px\">"
                "<option value=\"hostname_glob\">Hostname Glob</option>"
                "<option value=\"ip_subnet\">IP Subnet</option>"
                "<option value=\"trusted_ca\">Trusted CA</option>"
                "<option value=\"cloud_provider\">Cloud Provider</option>"
                "</select></div>"
                "<div class=\"mini-field\" style=\"flex:1\">"
                "<label>Value</label>"
                "<input type=\"text\" name=\"value\" placeholder=\"*.prod.example.com\" required>"
                "</div>"
                "<div class=\"mini-field\" style=\"flex:1\">"
                "<label>Label</label>"
                "<input type=\"text\" name=\"label\" placeholder=\"Production servers\">"
                "</div>"
                "<button class=\"btn btn-primary\" type=\"submit\">Add Rule</button>"
                "</form></div>"
                "<div class=\"feedback\" id=\"auto-approve-feedback\"></div>";

        return html;
    }

    // -- Web server -----------------------------------------------------------

    void start_web_server() {
        web_server_ = std::make_unique<httplib::Server>();

        // -- Auth middleware (pre-routing) -----------------------------------
        web_server_->set_pre_routing_handler(
            [this](const httplib::Request& req, httplib::Response& res)
                -> httplib::Server::HandlerResponse {
                // Allow unauthenticated access to login page
                if (req.path == "/login") {
                    return httplib::Server::HandlerResponse::Unhandled;
                }

                // Check session cookie
                auto token = extract_session_cookie(req);
                auto session = auth_mgr_.validate_session(token);
                if (!session) {
                    // API calls get 401, pages get redirect
                    if (req.path.starts_with("/api/") || req.path == "/events") {
                        res.status = 401;
                        res.set_content(R"({"error":"unauthorized"})",
                                        "application/json");
                    } else {
                        res.set_redirect("/login");
                    }
                    return httplib::Server::HandlerResponse::Handled;
                }

                return httplib::Server::HandlerResponse::Unhandled;
            });

        // -- Login page -------------------------------------------------------
        web_server_->Get("/login", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(kLoginHtml, "text/html; charset=utf-8");
        });

        web_server_->Post("/login",
            [this](const httplib::Request& req, httplib::Response& res) {
                auto username = extract_form_value(req.body, "username");
                auto password = extract_form_value(req.body, "password");

                auto token = auth_mgr_.authenticate(username, password);
                if (!token) {
                    res.status = 401;
                    res.set_content(R"({"error":"Invalid username or password"})",
                                    "application/json");
                    return;
                }

                res.set_header("Set-Cookie",
                    "yuzu_session=" + *token +
                    "; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800");
                res.set_content(R"({"status":"ok"})", "application/json");
            });

        // -- Logout -----------------------------------------------------------
        web_server_->Post("/logout",
            [this](const httplib::Request& req, httplib::Response& res) {
                auto token = extract_session_cookie(req);
                if (!token.empty()) {
                    auth_mgr_.invalidate_session(token);
                }
                res.set_header("Set-Cookie",
                    "yuzu_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
                res.set_content(R"({"status":"ok"})", "application/json");
            });

        // -- Current user info (/api/me) --------------------------------------
        web_server_->Get("/api/me",
            [this](const httplib::Request& req, httplib::Response& res) {
                auto session = require_auth(req, res);
                if (!session) return;
                res.set_content(
                    "{\"username\":\"" + session->username +
                    "\",\"role\":\"" + auth::role_to_string(session->role) + "\"}",
                    "application/json");
            });

        // -- Dashboard (unified UI) -------------------------------------------
        web_server_->Get("/", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(kDashboardIndexHtml, "text/html; charset=utf-8");
        });

        // -- Settings page (admin only) ---------------------------------------
        web_server_->Get("/settings",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) {
                    res.set_redirect("/");
                    return;
                }
                res.set_content(kSettingsHtml, "text/html; charset=utf-8");
            });

        // -- Settings HTMX fragment endpoints -----------------------------------

        web_server_->Get("/fragments/settings/tls",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;
                res.set_content(render_tls_fragment(), "text/html; charset=utf-8");
            });

        web_server_->Get("/fragments/settings/users",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;
                res.set_content(render_users_fragment(), "text/html; charset=utf-8");
            });

        web_server_->Get("/fragments/settings/tokens",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;
                res.set_content(render_tokens_fragment(), "text/html; charset=utf-8");
            });

        web_server_->Get("/fragments/settings/pending",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;
                res.set_content(render_pending_fragment(), "text/html; charset=utf-8");
            });

        web_server_->Get("/fragments/settings/auto-approve",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;
                res.set_content(render_auto_approve_fragment(), "text/html; charset=utf-8");
            });

        // -- Settings API: TLS toggle (HTMX POST) ----------------------------
        web_server_->Post("/api/settings/tls",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;
                // HTMX sends form-encoded: tls_enabled=true (or absent if unchecked)
                auto val = extract_form_value(req.body, "tls_enabled");
                cfg_.tls_enabled = (val == "true");
                spdlog::info("TLS setting changed to {} (restart required)",
                             cfg_.tls_enabled ? "enabled" : "disabled");
                // Return updated TLS fragment
                res.set_header("HX-Retarget", "#tls-section");
                res.set_content(render_tls_fragment(), "text/html; charset=utf-8");
            });

        // -- Settings API: Certificate upload (admin only, multipart) ----------
        web_server_->Post("/api/settings/cert-upload",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;

                // HTMX sends multipart/form-data with "type" hidden field and "file" file input
                std::string type;
                std::string content;

                if (req.form.has_field("type")) {
                    type = req.form.get_field("type");
                } else if (req.has_param("type")) {
                    type = req.get_param_value("type");
                }

                if (req.form.has_file("file")) {
                    content = req.form.get_file("file").content;
                }

                if (type.empty() || content.empty()) {
                    res.status = 400;
                    res.set_content(
                        "<span class=\"feedback-error\">Type and file are required.</span>",
                        "text/html; charset=utf-8");
                    return;
                }

                // Ensure cert dir exists
                auto cert_dir = auth::default_cert_dir();
                std::error_code ec;
                std::filesystem::create_directories(cert_dir, ec);
                if (ec) {
                    res.status = 500;
                    res.set_content(
                        "<span class=\"feedback-error\">Cannot create cert directory.</span>",
                        "text/html; charset=utf-8");
                    return;
                }

                // Determine output filename
                std::string out_name;
                if (type == "cert")     out_name = "server.pem";
                else if (type == "key") out_name = "server-key.pem";
                else if (type == "ca")  out_name = "ca.pem";
                else {
                    res.status = 400;
                    res.set_content(
                        "<span class=\"feedback-error\">Type must be cert, key, or ca.</span>",
                        "text/html; charset=utf-8");
                    return;
                }

                auto out_path = cert_dir / out_name;
                {
                    std::ofstream f(out_path, std::ios::binary | std::ios::trunc);
                    if (!f.is_open()) {
                        res.status = 500;
                        res.set_content(
                            "<span class=\"feedback-error\">Cannot write cert file.</span>",
                            "text/html; charset=utf-8");
                        return;
                    }
                    f.write(content.data(), static_cast<std::streamsize>(content.size()));
                }

                // Update config
                if (type == "cert")     cfg_.tls_server_cert = out_path;
                else if (type == "key") cfg_.tls_server_key  = out_path;
                else if (type == "ca")  cfg_.tls_ca_cert     = out_path;

                spdlog::info("Certificate uploaded: {} → {}", type, out_path.string());
                // Re-render TLS section to show new file paths
                res.set_header("HX-Retarget", "#tls-section");
                res.set_content(render_tls_fragment(), "text/html; charset=utf-8");
            });

        // -- Settings API: User management (admin only, HTMX) ------------------
        web_server_->Post("/api/settings/users",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;
                auto username = extract_form_value(req.body, "username");
                auto password = extract_form_value(req.body, "password");
                auto role_str = extract_form_value(req.body, "role");

                if (username.empty() || password.empty()) {
                    res.status = 400;
                    res.set_content(render_users_fragment() +
                        "<script>document.getElementById('user-feedback').className='feedback feedback-error';"
                        "document.getElementById('user-feedback').textContent='Username and password required.';</script>",
                        "text/html; charset=utf-8");
                    return;
                }

                auto role = auth::string_to_role(role_str);
                auth_mgr_.upsert_user(username, password, role);
                auth_mgr_.save_config();
                spdlog::info("User '{}' added/updated (role={})", username, role_str);
                res.set_content(render_users_fragment(), "text/html; charset=utf-8");
            });

        // DELETE /api/settings/users/:username
        web_server_->Delete(R"(/api/settings/users/(.+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;
                auto username = req.matches[1].str();
                if (auth_mgr_.remove_user(username)) {
                    auth_mgr_.save_config();
                    spdlog::info("User '{}' removed", username);
                }
                res.set_content(render_users_fragment(), "text/html; charset=utf-8");
            });

        // -- Settings API: Enrollment tokens (admin only, HTMX) ----------------

        web_server_->Post("/api/settings/enrollment-tokens",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;
                auto label = extract_form_value(req.body, "label");
                auto max_uses_s = extract_form_value(req.body, "max_uses");
                auto ttl_s = extract_form_value(req.body, "ttl_hours");

                int max_uses = 0;
                int ttl_hours = 0;
                try {
                    if (!max_uses_s.empty()) max_uses = std::stoi(max_uses_s);
                    if (!ttl_s.empty()) ttl_hours = std::stoi(ttl_s);
                } catch (const std::exception&) {
                    res.status = 400;
                    res.set_content(R"({"error":"invalid numeric parameter"})", "application/json");
                    return;
                }

                auto ttl = ttl_hours > 0
                    ? std::chrono::seconds(ttl_hours * 3600)
                    : std::chrono::seconds(0);

                auto raw_token = auth_mgr_.create_enrollment_token(label, max_uses, ttl);

                // Return token list fragment with the one-time token reveal
                res.set_content(render_tokens_fragment(raw_token), "text/html; charset=utf-8");
            });

        web_server_->Delete(R"(/api/settings/enrollment-tokens/(.+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;
                auto token_id = req.matches[1].str();
                auth_mgr_.revoke_enrollment_token(token_id);
                res.set_content(render_tokens_fragment(), "text/html; charset=utf-8");
            });

        // -- Batch enrollment token generation (JSON API for scripting) ---------
        web_server_->Post("/api/settings/enrollment-tokens/batch",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;
                auto label = extract_json_string(req.body, "label");
                auto count_s = extract_json_string(req.body, "count");
                auto max_uses_s = extract_json_string(req.body, "max_uses");
                auto ttl_s = extract_json_string(req.body, "ttl_hours");

                int count = 10;
                int max_uses = 1;
                int ttl_hours = 0;
                try {
                    if (!count_s.empty()) count = std::stoi(count_s);
                    if (!max_uses_s.empty()) max_uses = std::stoi(max_uses_s);
                    if (!ttl_s.empty()) ttl_hours = std::stoi(ttl_s);
                } catch (const std::exception&) {
                    res.status = 400;
                    res.set_content(R"({"error":"invalid numeric parameter"})", "application/json");
                    return;
                }

                if (count < 1 || count > 10000) {
                    res.status = 400;
                    res.set_content(R"({"error":"count must be 1-10000"})", "application/json");
                    return;
                }

                auto ttl = ttl_hours > 0
                    ? std::chrono::seconds(ttl_hours * 3600)
                    : std::chrono::seconds(0);

                auto tokens = auth_mgr_.create_enrollment_tokens_batch(
                    label, count, max_uses, ttl);

                // Return JSON array for scripting/Ansible consumption
                std::string json = "{\"count\":" + std::to_string(tokens.size()) + ",\"tokens\":[";
                for (size_t i = 0; i < tokens.size(); ++i) {
                    if (i > 0) json += ",";
                    json += "\"" + tokens[i] + "\"";
                }
                json += "]}";
                res.set_content(json, "application/json");
            });

        // -- Settings API: Pending agents (admin only, HTMX) --------------------

        web_server_->Post(R"(/api/settings/pending-agents/(.+)/approve)",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;
                auto agent_id = req.matches[1].str();
                auth_mgr_.approve_pending_agent(agent_id);
                res.set_content(render_pending_fragment(), "text/html; charset=utf-8");
            });

        web_server_->Post(R"(/api/settings/pending-agents/(.+)/deny)",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;
                auto agent_id = req.matches[1].str();
                auth_mgr_.deny_pending_agent(agent_id);
                res.set_content(render_pending_fragment(), "text/html; charset=utf-8");
            });

        web_server_->Delete(R"(/api/settings/pending-agents/(.+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;
                auto agent_id = req.matches[1].str();
                auth_mgr_.remove_pending_agent(agent_id);
                res.set_content(render_pending_fragment(), "text/html; charset=utf-8");
            });

        // -- Settings API: Auto-approve rules (HTMX) -------------------------

        // Add a new rule
        web_server_->Post("/api/settings/auto-approve",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;
                auto type_s = extract_form_value(req.body, "type");
                auto value = extract_form_value(req.body, "value");
                auto label = extract_form_value(req.body, "label");

                auth::AutoApproveRuleType type;
                if (type_s == "trusted_ca")          type = auth::AutoApproveRuleType::trusted_ca;
                else if (type_s == "ip_subnet")      type = auth::AutoApproveRuleType::ip_subnet;
                else if (type_s == "cloud_provider")  type = auth::AutoApproveRuleType::cloud_provider;
                else                                  type = auth::AutoApproveRuleType::hostname_glob;

                auto_approve_.add_rule({type, value, label, true});
                spdlog::info("Auto-approve rule added: {}:{} ({})", type_s, value, label);
                res.set_content(render_auto_approve_fragment(), "text/html; charset=utf-8");
            });

        // Change mode (any/all)
        web_server_->Post("/api/settings/auto-approve/mode",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;
                auto mode = extract_form_value(req.body, "mode");
                auto_approve_.set_require_all(mode == "all");
                auto_approve_.save();
                spdlog::info("Auto-approve mode changed to {}", mode);
                res.set_content(render_auto_approve_fragment(), "text/html; charset=utf-8");
            });

        // Toggle rule enabled/disabled
        web_server_->Post(R"(/api/settings/auto-approve/(\d+)/toggle)",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;
                auto idx = static_cast<size_t>(std::stoul(req.matches[1].str()));
                auto rules = auto_approve_.list_rules();
                if (idx < rules.size()) {
                    auto_approve_.set_enabled(idx, !rules[idx].enabled);
                }
                res.set_content(render_auto_approve_fragment(), "text/html; charset=utf-8");
            });

        // Remove a rule
        web_server_->Delete(R"(/api/settings/auto-approve/(\d+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!require_admin(req, res)) return;
                auto idx = static_cast<size_t>(std::stoul(req.matches[1].str()));
                auto_approve_.remove_rule(idx);
                spdlog::info("Auto-approve rule {} removed", idx);
                res.set_content(render_auto_approve_fragment(), "text/html; charset=utf-8");
            });

        // Legacy routes — redirect to dashboard
        web_server_->Get("/chargen", [](const httplib::Request&, httplib::Response& res) {
            res.set_redirect("/");
        });
        web_server_->Get("/procfetch", [](const httplib::Request&, httplib::Response& res) {
            res.set_redirect("/");
        });

        // SSE endpoint
        web_server_->Get("/events",
            [this](const httplib::Request&, httplib::Response& res) {
            res.set_header("Cache-Control", "no-cache");
            res.set_header("X-Accel-Buffering", "no");

            auto sink_state = std::make_shared<detail::SseSinkState>();
            sink_state->sub_id = event_bus_.subscribe(
                [sink_state](const detail::SseEvent& ev) {
                    {
                        std::lock_guard<std::mutex> lk(sink_state->mu);
                        sink_state->queue.push_back(ev);
                    }
                    sink_state->cv.notify_one();
                });

            detail::EventBus* bus = &event_bus_;
            res.set_content_provider(
                "text/event-stream",
                [sink_state](size_t offset, httplib::DataSink& sink) -> bool {
                    return detail::sse_content_provider(sink_state, offset, sink);
                },
                [sink_state, bus](bool success) {
                    detail::sse_resource_release(sink_state, *bus, success);
                }
            );
        });

        // -- Agent listing API ------------------------------------------------

        web_server_->Get("/api/agents",
            [this](const httplib::Request&, httplib::Response& res) {
                res.set_content(registry_.to_json(), "application/json");
            });

        // -- Generic command dispatch API -------------------------------------

        // Plugins that require admin role to invoke
        static const std::unordered_set<std::string> kAdminOnlyPlugins = {
            "script_exec", "software_actions", "services", "processes",
            "filesystem", "agent_actions", "network_actions"
        };

        web_server_->Post("/api/command",
            [this](const httplib::Request& req, httplib::Response& res) {
                // Parse JSON body: { "plugin": "...", "action": "...", "agent_ids": [...] }
                auto plugin = extract_json_string(req.body, "plugin");
                auto action = extract_json_string(req.body, "action");
                auto agent_ids = extract_json_string_array(req.body, "agent_ids");

                if (plugin.empty() || action.empty()) {
                    res.status = 400;
                    res.set_content("{\"error\":\"plugin and action are required\"}",
                        "application/json");
                    return;
                }

                // All commands require authentication
                auto session = require_auth(req, res);
                if (!session) return;

                // Restricted plugins require admin role
                if (kAdminOnlyPlugins.contains(plugin) &&
                    session->role != auth::Role::admin) {
                    res.status = 403;
                    res.set_content("{\"error\":\"admin role required for plugin '" + plugin + "'\"}",
                        "application/json");
                    return;
                }

                if (!registry_.has_any()) {
                    res.status = 503;
                    res.set_content("{\"error\":\"no agent connected\"}",
                        "application/json");
                    return;
                }

                auto command_id = plugin + "-" + auth::AuthManager::bytes_to_hex(
                    auth::AuthManager::random_bytes(8));

                detail::pb::CommandRequest cmd;
                cmd.set_command_id(command_id);
                cmd.set_plugin(plugin);
                cmd.set_action(action);

                agent_service_.record_send_time(command_id);

                int sent = 0;
                if (agent_ids.empty()) {
                    // Broadcast to all agents
                    sent = registry_.send_to_all(cmd);
                } else {
                    for (const auto& aid : agent_ids) {
                        if (registry_.send_to(aid, cmd)) {
                            ++sent;
                        }
                    }
                }

                if (sent == 0) {
                    res.status = 503;
                    res.set_content("{\"error\":\"failed to send command to any agent\"}",
                        "application/json");
                    return;
                }

                spdlog::info("Command dispatched: {}:{} → {} agent(s)",
                    plugin, action, sent);
                res.set_content("{\"status\":\"sent\",\"command_id\":\"" + command_id +
                    "\",\"agents_reached\":" + std::to_string(sent) + "}",
                    "application/json");
            });

        // -- Legacy API endpoints (still functional, delegate to generic path) --

        web_server_->Post("/api/chargen/start",
            [this](const httplib::Request&, httplib::Response& res) {
                forward_legacy_command("chargen", "chargen_start", res);
            });

        web_server_->Post("/api/chargen/stop",
            [this](const httplib::Request&, httplib::Response& res) {
                forward_legacy_command("chargen", "chargen_stop", res);
            });

        web_server_->Post("/api/procfetch/fetch",
            [this](const httplib::Request&, httplib::Response& res) {
                forward_legacy_command("procfetch", "procfetch_fetch", res);
            });

        web_server_->Get("/api/chargen/status",
            [this](const httplib::Request&, httplib::Response& res) {
                res.set_content(
                    "{\"agent_connected\":" +
                    std::string(registry_.has_any() ? "true" : "false") + "}",
                    "application/json");
            });

        web_server_->Get("/api/procfetch/status",
            [this](const httplib::Request&, httplib::Response& res) {
                res.set_content(
                    "{\"agent_connected\":" +
                    std::string(registry_.has_any() ? "true" : "false") + "}",
                    "application/json");
            });

        web_thread_ = std::thread([this] {
            spdlog::info("Web UI available at http://{}:{}/",
                cfg_.web_address, cfg_.web_port);
            web_server_->listen(cfg_.web_address, cfg_.web_port);
        });
    }

    void forward_legacy_command(const std::string& plugin, const std::string& action,
                                httplib::Response& res) {
        if (!registry_.has_any()) {
            res.status = 503;
            res.set_content("{\"error\":\"no agent connected\"}", "application/json");
            return;
        }

        auto command_id = plugin + "-" + auth::AuthManager::bytes_to_hex(
            auth::AuthManager::random_bytes(8));

        detail::pb::CommandRequest cmd;
        cmd.set_command_id(command_id);
        cmd.set_plugin(plugin);
        cmd.set_action(action);

        agent_service_.record_send_time(command_id);
        int sent = registry_.send_to_all(cmd);

        if (sent == 0) {
            res.status = 503;
            res.set_content("{\"error\":\"failed to send command\"}", "application/json");
            return;
        }
        res.set_content("{\"status\":\"sent\"}", "application/json");
    }

    // -- Minimal JSON parsing (no external dependency) ------------------------

    static std::string extract_json_string(const std::string& json, const std::string& key) {
        auto needle = "\"" + key + "\"";
        auto pos = json.find(needle);
        if (pos == std::string::npos) return {};
        pos = json.find(':', pos + needle.size());
        if (pos == std::string::npos) return {};
        pos = json.find('"', pos + 1);
        if (pos == std::string::npos) return {};
        auto end = json.find('"', pos + 1);
        if (end == std::string::npos) return {};
        return json.substr(pos + 1, end - pos - 1);
    }

    static std::vector<std::string> extract_json_string_array(
            const std::string& json, const std::string& key) {
        std::vector<std::string> result;
        auto needle = "\"" + key + "\"";
        auto pos = json.find(needle);
        if (pos == std::string::npos) return result;
        pos = json.find('[', pos);
        if (pos == std::string::npos) return result;
        auto end = json.find(']', pos);
        if (end == std::string::npos) return result;
        auto arr = json.substr(pos + 1, end - pos - 1);
        // Extract all quoted strings from the array
        std::size_t i = 0;
        while (i < arr.size()) {
            auto q1 = arr.find('"', i);
            if (q1 == std::string::npos) break;
            auto q2 = arr.find('"', q1 + 1);
            if (q2 == std::string::npos) break;
            result.push_back(arr.substr(q1 + 1, q2 - q1 - 1));
            i = q2 + 1;
        }
        return result;
    }

    // -- Data members ---------------------------------------------------------

    Config                                     cfg_;
    auth::AuthManager&                         auth_mgr_;
    auth::AutoApproveEngine                    auto_approve_;
    detail::EventBus                           event_bus_;
    detail::AgentRegistry                      registry_;
    detail::AgentServiceImpl                   agent_service_;
    detail::ManagementServiceImpl              mgmt_service_;
    std::unique_ptr<detail::GatewayUpstreamServiceImpl> gateway_service_;
    std::shared_ptr<spdlog::logger>            file_logger_;
    std::unique_ptr<grpc::Server>              agent_server_;
    std::unique_ptr<grpc::Server>              mgmt_server_;
    std::unique_ptr<httplib::Server>           web_server_;
    std::thread                                web_thread_;
};

// -- Factory ------------------------------------------------------------------

std::unique_ptr<Server> Server::create(Config config, auth::AuthManager& auth_mgr) {
    return std::make_unique<ServerImpl>(std::move(config), auth_mgr);
}

}  // namespace yuzu::server
