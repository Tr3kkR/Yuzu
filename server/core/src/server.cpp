#include <yuzu/server/server.hpp>

#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <grpc/grpc_security_constants.h>

#include "agent.grpc.pb.h"
#include "management.grpc.pb.h"
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

namespace yuzu::server {

namespace detail {

namespace pb = ::yuzu::agent::v1;

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
    AgentServiceImpl(AgentRegistry& registry, EventBus& bus, bool require_client_identity)
        : registry_(registry), bus_(bus), require_client_identity_(require_client_identity) {}

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

        registry_.register_agent(info);

        auto session_id = "session-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count());
        response->set_session_id(session_id);
        response->set_accepted(true);

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

            if (it->second.register_peer != context->peer()) {
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
};

// -- ManagementServiceImpl ----------------------------------------------------

class ManagementServiceImpl : public ::yuzu::server::v1::ManagementService::Service {
public:
    // Placeholder.
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
    explicit ServerImpl(Config cfg)
        : cfg_(std::move(cfg)),
          registry_(event_bus_),
          agent_service_(registry_, event_bus_,
              cfg_.tls_enabled && !cfg_.tls_ca_cert.empty())
    {
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

        agent_server_ = builder.BuildAndStart();

        if (!agent_server_) {
            spdlog::error("Failed to start gRPC server -- check that ports {} and {} are available",
                cfg_.listen_address, cfg_.management_address);
            return;
        }

        spdlog::info("Yuzu Server listening on {} (agents) and {} (management)",
            cfg_.listen_address, cfg_.management_address);

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

    void start_web_server() {
        web_server_ = std::make_unique<httplib::Server>();

        // Dashboard (unified UI)
        web_server_->Get("/", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(kDashboardIndexHtml, "text/html; charset=utf-8");
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

                if (!registry_.has_any()) {
                    res.status = 503;
                    res.set_content("{\"error\":\"no agent connected\"}",
                        "application/json");
                    return;
                }

                auto command_id = plugin + "-" + std::to_string(
                    std::chrono::steady_clock::now().time_since_epoch().count());

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

        auto command_id = plugin + "-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count());

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
    detail::EventBus                           event_bus_;
    detail::AgentRegistry                      registry_;
    detail::AgentServiceImpl                   agent_service_;
    detail::ManagementServiceImpl              mgmt_service_;
    std::shared_ptr<spdlog::logger>            file_logger_;
    std::unique_ptr<grpc::Server>              agent_server_;
    std::unique_ptr<grpc::Server>              mgmt_server_;
    std::unique_ptr<httplib::Server>           web_server_;
    std::thread                                web_thread_;
};

// -- Factory ------------------------------------------------------------------

std::unique_ptr<Server> Server::create(Config config) {
    return std::make_unique<ServerImpl>(std::move(config));
}

}  // namespace yuzu::server
