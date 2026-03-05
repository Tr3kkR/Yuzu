#include <yuzu/server/server.hpp>

#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

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
#include <vector>

// Defined in chargen_ui.cpp (separate TU to isolate MSVC raw-string issues).
extern const char* const kChargenIndexHtml;

// Defined in procfetch_ui.cpp.
extern const char* const kProcfetchIndexHtml;

namespace yuzu::server {

namespace detail {

namespace pb = ::yuzu::agent::v1;

// -- Platform-specific log path -----------------------------------------------

[[nodiscard]] std::filesystem::path chargen_log_path() {
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
    std::string event_type;  // e.g. "chargen", "status"
    std::string data;
};

// -- SSE Event Bus ------------------------------------------------------------
// Broadcast mechanism: chargen output / status events -> all connected SSE clients.

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

// -- Chargen state (shared between gRPC agent handler and web UI) -------------

struct ChargenState {
    std::mutex                      mu;
    bool                            running = false;
    std::string                     target_agent_id;
    std::shared_ptr<spdlog::logger> file_logger;
    EventBus                        event_bus;
};

// -- Procfetch state (shared between gRPC agent handler and web UI) -----------

struct ProcfetchState {
    std::mutex mu;
    bool       fetching = false;
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

    // Drain all queued events
    while (!state->queue.empty()) {
        auto& ev = state->queue.front();
        std::string sse = "event: " + ev.event_type + "\ndata: " + ev.data + "\n\n";
        if (!sink.write(sse.data(), sse.size())) {
            return false;
        }
        state->queue.pop_front();
    }

    // Timeout with no data -- send a keepalive comment
    const char* keepalive = ": keepalive\n\n";
    sink.write(keepalive, std::strlen(keepalive));
    return true;
}

// -- SSE resource-release callback --------------------------------------------

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
    AgentServiceImpl(std::shared_ptr<ChargenState> cs,
                     std::shared_ptr<ProcfetchState> ps)
        : chargen_state_(std::move(cs)), procfetch_state_(std::move(ps)) {}

    grpc::Status Register(
        grpc::ServerContext* /*context*/,
        const pb::RegisterRequest* request,
        pb::RegisterResponse* response) override
    {
        const auto& info = request->info();
        spdlog::info("Agent registered: id={}, version={}, plugins={}",
            info.agent_id(), info.agent_version(), info.plugins_size());

        for (const auto& p : info.plugins()) {
            spdlog::info("  plugin: {} v{} — {}",
                p.name(), p.version(), p.description());
        }

        auto session_id = "session-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count());
        response->set_session_id(session_id);
        response->set_accepted(true);

        {
            std::lock_guard lock(agent_mu_);
            agent_id_ = info.agent_id();
        }

        return grpc::Status::OK;
    }

    grpc::Status Subscribe(
        grpc::ServerContext* /*context*/,
        grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream) override
    {
        spdlog::info("Agent subscribe stream opened");

        // Register this stream so web API can push commands
        {
            std::lock_guard lock(agent_mu_);
            agent_stream_ = stream;
        }

        // Read loop — process responses from the agent
        pb::CommandResponse resp;
        while (stream->Read(&resp)) {
            bool is_procfetch = resp.command_id().starts_with("procfetch");

            if (resp.status() == pb::CommandResponse::RUNNING) {
                if (is_procfetch) {
                    chargen_state_->event_bus.publish("procfetch", resp.output());
                } else {
                    on_chargen_output(resp.output());
                }
            } else {
                spdlog::info("Command {} completed: status={}, exit_code={}",
                    resp.command_id(),
                    static_cast<int>(resp.status()),
                    resp.exit_code());

                // -- procfetch completion -----------------------------------------
                if (is_procfetch) {
                    if (resp.status() == pb::CommandResponse::SUCCESS) {
                        std::lock_guard lock(procfetch_state_->mu);
                        procfetch_state_->fetching = false;
                        chargen_state_->event_bus.publish("procfetch-status", "done");
                    } else {
                        std::lock_guard lock(procfetch_state_->mu);
                        procfetch_state_->fetching = false;
                        chargen_state_->event_bus.publish("procfetch-status", "error");
                    }
                }

                // -- chargen completion ------------------------------------------
                // If a chargen command was rejected or failed, reset UI state
                if (resp.command_id().starts_with("chargen") &&
                    (resp.status() == pb::CommandResponse::REJECTED ||
                     resp.status() == pb::CommandResponse::FAILURE)) {
                    std::lock_guard lock(chargen_state_->mu);
                    if (chargen_state_->running) {
                        chargen_state_->running = false;
                        chargen_state_->event_bus.publish("status", "stopped");
                        chargen_state_->event_bus.publish("chargen",
                            "error: agent rejected command \xe2\x80\x94 " + resp.output());
                    }
                }

                // chargen_stop completed successfully — confirm state reset
                if (resp.command_id().starts_with("chargen-stop") &&
                    resp.status() == pb::CommandResponse::SUCCESS) {
                    std::lock_guard lock(chargen_state_->mu);
                    if (chargen_state_->running) {
                        chargen_state_->running = false;
                        chargen_state_->event_bus.publish("status", "stopped");
                    }
                }
            }
        }

        // Agent disconnected
        {
            std::lock_guard lock(agent_mu_);
            agent_stream_ = nullptr;
        }
        {
            std::lock_guard lock(chargen_state_->mu);
            if (chargen_state_->running) {
                chargen_state_->running = false;
                chargen_state_->event_bus.publish("status", "stopped");
            }
        }
        {
            std::lock_guard lock(procfetch_state_->mu);
            if (procfetch_state_->fetching) {
                procfetch_state_->fetching = false;
                chargen_state_->event_bus.publish("procfetch-status", "error");
            }
        }
        spdlog::info("Agent subscribe stream closed");

        return grpc::Status::OK;
    }

    // Send a command to the connected agent. Returns false if no agent.
    bool send_command(const pb::CommandRequest& cmd) {
        std::lock_guard lock(agent_mu_);
        if (!agent_stream_) return false;
        return agent_stream_->Write(cmd);
    }

    bool has_agent() const {
        std::lock_guard lock(agent_mu_);
        return agent_stream_ != nullptr;
    }

private:
    void on_chargen_output(const std::string& line) {
        auto& s = *chargen_state_;
        if (s.file_logger) {
            s.file_logger->info("{}", line);
        }
        s.event_bus.publish("chargen", line);
    }

    std::shared_ptr<ChargenState>  chargen_state_;
    std::shared_ptr<ProcfetchState> procfetch_state_;
    mutable std::mutex agent_mu_;
    std::string agent_id_;
    grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* agent_stream_ = nullptr;
};

// -- ManagementServiceImpl ----------------------------------------------------

class ManagementServiceImpl : public ::yuzu::server::v1::ManagementService::Service {
public:
    // Placeholder. SendCommand RPC would forward to the agent's ExecuteCommand stream.
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
          chargen_state_(std::make_shared<detail::ChargenState>()),
          procfetch_state_(std::make_shared<detail::ProcfetchState>()),
          agent_service_(chargen_state_, procfetch_state_)
    {
        // Setup chargen file logger
        auto log_path = detail::chargen_log_path();
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
            chargen_state_->file_logger = spdlog::basic_logger_mt(
                "chargen_file", log_path.string());
            chargen_state_->file_logger->set_pattern(
                "[%Y-%m-%d %H:%M:%S.%e] [chargen] %v");
            chargen_state_->file_logger->flush_on(spdlog::level::info);
            spdlog::info("Chargen log file: {}", log_path.string());
        } catch (const spdlog::spdlog_ex& ex) {
            spdlog::error("Failed to create chargen file logger: {}", ex.what());
        }
    }

    void run() override {
        spdlog::info("run(): entering");
        grpc::EnableDefaultHealthCheckService(true);

        auto agent_creds = grpc::InsecureServerCredentials();
        if (cfg_.tls_enabled) {
            if (auto tls = build_tls_credentials()) {
                agent_creds = std::move(tls);
            } else {
                spdlog::warn("TLS enabled but cert/key not provided -- falling back to insecure");
            }
        }

        grpc::ServerBuilder builder;
        builder.AddListeningPort(cfg_.listen_address, agent_creds);
        builder.AddListeningPort(cfg_.management_address, grpc::InsecureServerCredentials());
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
    build_tls_credentials() const {
        if (cfg_.tls_server_cert.empty() || cfg_.tls_server_key.empty()) {
            return nullptr;
        }

        auto cert = detail::read_file_contents(cfg_.tls_server_cert);
        auto key  = detail::read_file_contents(cfg_.tls_server_key);
        if (cert.empty() || key.empty()) {
            spdlog::error("Failed to read TLS cert or key files");
            return nullptr;
        }

        grpc::SslServerCredentialsOptions ssl_opts;
        grpc::SslServerCredentialsOptions::PemKeyCertPair pair;
        pair.private_key = std::move(key);
        pair.cert_chain  = std::move(cert);
        ssl_opts.pem_key_cert_pairs.push_back(std::move(pair));

        if (!cfg_.tls_ca_cert.empty()) {
            auto ca = detail::read_file_contents(cfg_.tls_ca_cert);
            if (!ca.empty()) {
                ssl_opts.pem_root_certs = std::move(ca);
                ssl_opts.client_certificate_request =
                    GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;
            }
        }

        return grpc::SslServerCredentials(ssl_opts);
    }

    // -- Web server -----------------------------------------------------------

    void start_web_server() {
        web_server_ = std::make_unique<httplib::Server>();

        web_server_->Get("/", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(kChargenIndexHtml, "text/html; charset=utf-8");
        });

        auto* cs = chargen_state_.get();

        // SSE endpoint
        web_server_->Get("/events", [cs](const httplib::Request&, httplib::Response& res) {
            res.set_header("Cache-Control", "no-cache");
            res.set_header("X-Accel-Buffering", "no");

            auto sink_state = std::make_shared<detail::SseSinkState>();
            sink_state->sub_id = cs->event_bus.subscribe(
                [sink_state](const detail::SseEvent& ev) {
                    {
                        std::lock_guard<std::mutex> lk(sink_state->mu);
                        sink_state->queue.push_back(ev);
                    }
                    sink_state->cv.notify_one();
                });

            detail::EventBus* bus = &cs->event_bus;
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

        // API endpoints — commands are forwarded to the agent via Subscribe stream
        web_server_->Post("/api/chargen/start",
            [this](const httplib::Request&, httplib::Response& res) {
                {
                    std::lock_guard<std::mutex> lock(chargen_state_->mu);
                    if (chargen_state_->running) {
                        res.set_content("{\"status\":\"already_running\"}",
                            "application/json");
                        return;
                    }
                }

                if (!agent_service_.has_agent()) {
                    res.status = 503;
                    res.set_content("{\"error\":\"no agent connected\"}",
                        "application/json");
                    return;
                }

                detail::pb::CommandRequest cmd;
                cmd.set_command_id("chargen-" + std::to_string(
                    std::chrono::steady_clock::now().time_since_epoch().count()));
                cmd.set_plugin("chargen");
                cmd.set_action("chargen_start");

                if (!agent_service_.send_command(cmd)) {
                    res.status = 503;
                    res.set_content("{\"error\":\"failed to send command to agent\"}",
                        "application/json");
                    return;
                }

                {
                    std::lock_guard<std::mutex> lock(chargen_state_->mu);
                    chargen_state_->running = true;
                }
                chargen_state_->event_bus.publish("status", "running");
                spdlog::info("Chargen started (command sent to agent)");
                res.set_content("{\"status\":\"started\"}", "application/json");
            });

        web_server_->Post("/api/chargen/stop",
            [this](const httplib::Request&, httplib::Response& res) {
                {
                    std::lock_guard<std::mutex> lock(chargen_state_->mu);
                    if (!chargen_state_->running) {
                        res.set_content("{\"status\":\"already_stopped\"}",
                            "application/json");
                        return;
                    }
                    chargen_state_->running = false;
                }

                detail::pb::CommandRequest cmd;
                cmd.set_command_id("chargen-stop-" + std::to_string(
                    std::chrono::steady_clock::now().time_since_epoch().count()));
                cmd.set_plugin("chargen");
                cmd.set_action("chargen_stop");
                agent_service_.send_command(cmd);

                chargen_state_->event_bus.publish("status", "stopped");
                spdlog::info("Chargen stop command sent to agent");
                res.set_content("{\"status\":\"stopped\"}", "application/json");
            });

        web_server_->Get("/api/chargen/status",
            [this](const httplib::Request&, httplib::Response& res) {
                std::lock_guard<std::mutex> lock(chargen_state_->mu);
                std::string status = chargen_state_->running ? "running" : "stopped";
                bool agent_connected = agent_service_.has_agent();
                res.set_content(
                    "{\"status\":\"" + status + "\","
                    "\"agent_connected\":" + (agent_connected ? "true" : "false") + "}",
                    "application/json");
            });

        // -- Process Fetch routes -------------------------------------------------

        web_server_->Get("/procfetch", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(kProcfetchIndexHtml, "text/html; charset=utf-8");
        });

        web_server_->Post("/api/procfetch/fetch",
            [this](const httplib::Request&, httplib::Response& res) {
                {
                    std::lock_guard<std::mutex> lock(procfetch_state_->mu);
                    if (procfetch_state_->fetching) {
                        res.set_content("{\"status\":\"already_fetching\"}",
                            "application/json");
                        return;
                    }
                }

                if (!agent_service_.has_agent()) {
                    res.status = 503;
                    res.set_content("{\"error\":\"no agent connected\"}",
                        "application/json");
                    return;
                }

                detail::pb::CommandRequest cmd;
                cmd.set_command_id("procfetch-" + std::to_string(
                    std::chrono::steady_clock::now().time_since_epoch().count()));
                cmd.set_plugin("procfetch");
                cmd.set_action("procfetch_fetch");

                if (!agent_service_.send_command(cmd)) {
                    res.status = 503;
                    res.set_content("{\"error\":\"failed to send command to agent\"}",
                        "application/json");
                    return;
                }

                {
                    std::lock_guard<std::mutex> lock(procfetch_state_->mu);
                    procfetch_state_->fetching = true;
                }
                chargen_state_->event_bus.publish("procfetch-status", "fetching");
                spdlog::info("Procfetch fetch command sent to agent");
                res.set_content("{\"status\":\"fetching\"}", "application/json");
            });

        web_server_->Get("/api/procfetch/status",
            [this](const httplib::Request&, httplib::Response& res) {
                std::lock_guard<std::mutex> lock(procfetch_state_->mu);
                std::string status = procfetch_state_->fetching ? "fetching" : "idle";
                bool agent_connected = agent_service_.has_agent();
                res.set_content(
                    "{\"status\":\"" + status + "\","
                    "\"agent_connected\":" + (agent_connected ? "true" : "false") + "}",
                    "application/json");
            });

        web_thread_ = std::thread([this] {
            spdlog::info("Web UI available at http://{}:{}/",
                cfg_.web_address, cfg_.web_port);
            web_server_->listen(cfg_.web_address, cfg_.web_port);
        });
    }

    // -- Data members ---------------------------------------------------------

    Config                                     cfg_;
    std::shared_ptr<detail::ChargenState>      chargen_state_;
    std::shared_ptr<detail::ProcfetchState>    procfetch_state_;
    detail::AgentServiceImpl                   agent_service_;
    detail::ManagementServiceImpl              mgmt_service_;
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
