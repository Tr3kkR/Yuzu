#include <yuzu/server/server.hpp>

#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <httplib.h>

#include <atomic>
#include <chrono>
#include <fstream>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

// Defined in chargen_ui.cpp (separate TU to isolate MSVC raw-string issues).
extern const char* const kChargenIndexHtml;

namespace yuzu::server {

namespace detail {

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

// -- SSE Event Bus ------------------------------------------------------------
// A simple broadcast mechanism: chargen output -> all connected SSE clients.

class EventBus {
public:
    using Listener = std::function<void(const std::string&)>;

    std::size_t subscribe(Listener fn) {
        std::lock_guard lock(mu_);
        auto id = next_id_++;
        listeners_[id] = std::move(fn);
        return id;
    }

    void unsubscribe(std::size_t id) {
        std::lock_guard lock(mu_);
        listeners_.erase(id);
    }

    void publish(const std::string& data) {
        std::lock_guard lock(mu_);
        for (auto& [id, fn] : listeners_) {
            fn(data);
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

// -- SSE sink state (per-connection, shared with content provider) -------------

struct SseSinkState {
    std::mutex              mu;
    std::condition_variable cv;
    std::deque<std::string> queue;
    std::atomic<bool>       closed = false;
    std::size_t             sub_id = 0;
};

// -- SSE content provider callback --------------------------------------------

bool sse_content_provider(
    const std::shared_ptr<SseSinkState>& state,
    size_t /*offset*/,
    httplib::DataSink& sink)
{
    std::unique_lock lk(state->mu);
    state->cv.wait_for(lk, std::chrono::seconds(15), [&state] {
        return !state->queue.empty() || state->closed.load();
    });

    if (state->closed.load()) {
        return false;
    }

    // Drain all queued lines
    while (!state->queue.empty()) {
        auto& line = state->queue.front();
        std::string evt = "event: chargen\ndata: " + line + "\n\n";
        if (!sink.write(evt.data(), evt.size())) {
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

class AgentServiceImpl /* : public yuzu::agent::v1::AgentService::Service */ {
public:
    explicit AgentServiceImpl(std::shared_ptr<ChargenState> cs)
        : chargen_state_(std::move(cs)) {}

    // Placeholder for the real gRPC service implementation.
    // When protobuf codegen is wired up, this class would inherit from
    // yuzu::agent::v1::AgentService::Service and implement the RPCs.
    //
    // The ExecuteCommand flow:
    //   1. Server sends CommandRequest (plugin="chargen", action="chargen_start")
    //   2. Agent runs the chargen plugin, which loops sending write_output()
    //   3. Each write_output() becomes a CommandResponse streamed back here
    //   4. We log each line and push it to the SSE event bus

    void on_chargen_output(const std::string& agent_id, const std::string& line) {
        auto& s = *chargen_state_;
        if (s.file_logger) {
            s.file_logger->info("[{}] {}", agent_id, line);
        }
        s.event_bus.publish(line);
    }

private:
    std::shared_ptr<ChargenState> chargen_state_;
};

// -- ManagementServiceImpl ----------------------------------------------------

class ManagementServiceImpl /* : public yuzu::server::v1::ManagementService::Service */ {
public:
    // Placeholder. SendCommand RPC would forward to the agent's ExecuteCommand stream.
};

}  // namespace detail

// -- ServerImpl ---------------------------------------------------------------

class ServerImpl final : public Server {
public:
    explicit ServerImpl(Config cfg)
        : cfg_(std::move(cfg)),
          chargen_state_(std::make_shared<detail::ChargenState>()),
          agent_service_(chargen_state_)
    {
    explicit ServerImpl(Config cfg)
    : cfg_{std::move(cfg)},
      chargen_state_{std::make_shared<ChargenState>()},
      agent_service_{chargen_state_}   // now safe — chargen_state_ already init'd
    {
        setup_chargen_logger();
    }

    void run() override;
    void stop() noexcept override;

private:
    [[nodiscard]] std::shared_ptr<grpc::ServerCredentials>
    build_server_credentials() const;

    void setup_chargen_logger();
    void start_web_server();
    void setup_sse_endpoint();
    void setup_api_endpoints();
    void start_chargen();
    void stop_chargen();

    Config                            cfg_;
    std::shared_ptr<detail::ChargenState> chargen_state_;
    detail::AgentServiceImpl             agent_service_;
    detail::ManagementServiceImpl        mgmt_service_;
    std::unique_ptr<grpc::Server>     agent_server_;
    std::unique_ptr<grpc::Server>     mgmt_server_;
    std::unique_ptr<httplib::Server>  web_server_;
    std::thread                       web_thread_;
    std::thread                       chargen_thread_;
};

// -- ServerImpl method definitions --------------------------------------------

void ServerImpl::run() {
    grpc::EnableDefaultHealthCheckService(true);

    auto agent_creds = grpc::InsecureServerCredentials();
    if (cfg_.tls_enabled) {
        auto tls = build_server_credentials();
        if (tls) {
            agent_creds = std::move(tls);
        } else {
            spdlog::warn("TLS enabled but cert/key not provided -- falling back to insecure");
        }
    }

    grpc::ServerBuilder agent_builder;
    agent_builder.AddListeningPort(cfg_.listen_address, agent_creds);
    // agent_builder.RegisterService(&agent_service_);

    grpc::ServerBuilder mgmt_builder;
    mgmt_builder.AddListeningPort(
        cfg_.management_address,
        grpc::InsecureServerCredentials()
    );
    // mgmt_builder.RegisterService(&mgmt_service_);

    agent_server_ = agent_builder.BuildAndStart();
    mgmt_server_  = mgmt_builder.BuildAndStart();

    spdlog::info("Yuzu Server listening on {} (agents) and {} (management)",
        cfg_.listen_address, cfg_.management_address);

    start_web_server();
    agent_server_->Wait();
}

void ServerImpl::stop() noexcept {
    spdlog::info("Shutting down server...");

    stop_chargen();

    if (web_server_) {
        web_server_->stop();
    }
    if (web_thread_.joinable()) {
        web_thread_.join();
    }

    if (agent_server_) agent_server_->Shutdown();
    if (mgmt_server_)  mgmt_server_->Shutdown();
}

std::shared_ptr<grpc::ServerCredentials>
ServerImpl::build_server_credentials() const {
    if (cfg_.tls_server_cert.empty() || cfg_.tls_server_key.empty()) {
        return nullptr;
    }

    auto read_file = [](const std::filesystem::path& p) -> std::string {
        std::ifstream f(p, std::ios::binary);
        if (!f) return {};
        return {std::istreambuf_iterator<char>(f),
                std::istreambuf_iterator<char>()};
    };

    auto cert = read_file(cfg_.tls_server_cert);
    auto key  = read_file(cfg_.tls_server_key);
    if (cert.empty() || key.empty()) {
        spdlog::error("Failed to read TLS cert or key files");
        return nullptr;
    }

    grpc::SslServerCredentialsOptions ssl_opts;
    ssl_opts.pem_key_cert_pairs.push_back({std::move(key), std::move(cert)});

    if (!cfg_.tls_ca_cert.empty()) {
        auto ca = read_file(cfg_.tls_ca_cert);
        if (!ca.empty()) {
            ssl_opts.pem_root_certs = std::move(ca);
            ssl_opts.client_certificate_request =
                GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY;
        }
    }

    return grpc::SslServerCredentials(ssl_opts);
}

void ServerImpl::setup_chargen_logger() {
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

void ServerImpl::start_web_server() {
    web_server_ = std::make_unique<httplib::Server>();

    // Serve the HTMX page
    web_server_->Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(kChargenIndexHtml, "text/html; charset=utf-8");
    });

    setup_sse_endpoint();
    setup_api_endpoints();

    web_thread_ = std::thread([this] {
        spdlog::info("Web UI available at http://{}:{}/",
            cfg_.web_address, cfg_.web_port);
        web_server_->listen(cfg_.web_address, cfg_.web_port);
    });
}

void ServerImpl::setup_sse_endpoint() {
    auto* cs = chargen_state_.get();

    web_server_->Get("/events", [cs](const httplib::Request&, httplib::Response& res) {
        res.set_header("Cache-Control", "no-cache");
        res.set_header("X-Accel-Buffering", "no");

        auto sink_state = std::make_shared<detail::SseSinkState>();

        sink_state->sub_id = cs->event_bus.subscribe(
            [sink_state](const std::string& line) {
                {
                    std::lock_guard lk(sink_state->mu);
                    sink_state->queue.push_back(line);
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
}

void ServerImpl::setup_api_endpoints() {
    web_server_->Post("/api/chargen/start",
        [this](const httplib::Request&, httplib::Response& res) {
            start_chargen();
            res.set_content("{\"status\":\"started\"}", "application/json");
        });

    web_server_->Post("/api/chargen/stop",
        [this](const httplib::Request&, httplib::Response& res) {
            stop_chargen();
            res.set_content("{\"status\":\"stopped\"}", "application/json");
        });

    web_server_->Get("/api/chargen/status",
        [this](const httplib::Request&, httplib::Response& res) {
            std::lock_guard lock(chargen_state_->mu);
            std::string status = chargen_state_->running ? "running" : "stopped";
            res.set_content("{\"status\":\"" + status + "\"}", "application/json");
        });
}

// -- Local chargen simulation -------------------------------------------------
// In a full implementation, this would dispatch a CommandRequest to a connected
// agent via the ExecuteCommand gRPC stream.  For now, we run the RFC 864
// generator directly on the server to demonstrate the full pipeline.

void ServerImpl::start_chargen() {
    std::lock_guard lock(chargen_state_->mu);
    if (chargen_state_->running) {
        spdlog::info("Chargen already running");
        return;
    }
    chargen_state_->running = true;
    spdlog::info("Chargen started");

    chargen_thread_ = std::thread([this] {
        constexpr int kFirstChar  = 32;
        constexpr int kLastChar   = 126;
        constexpr int kCharRange  = kLastChar - kFirstChar + 1;
        constexpr int kLineLength = 72;

        int offset = 0;

        while (true) {
            {
                std::lock_guard lk(chargen_state_->mu);
                if (!chargen_state_->running) break;
            }

            // Generate one RFC 864 line
            std::string line;
            line.reserve(kLineLength);
            for (int i = 0; i < kLineLength; ++i) {
                line.push_back(
                    static_cast<char>(kFirstChar + ((offset + i) % kCharRange)));
            }
            offset = (offset + 1) % kCharRange;

            // Log to file
            if (chargen_state_->file_logger) {
                chargen_state_->file_logger->info("{}", line);
            }

            // Broadcast to SSE clients
            chargen_state_->event_bus.publish(line);

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        spdlog::info("Chargen thread exited");
    });
}

void ServerImpl::stop_chargen() {
    {
        std::lock_guard lock(chargen_state_->mu);
        if (!chargen_state_->running) return;
        chargen_state_->running = false;
    }
    if (chargen_thread_.joinable()) {
        chargen_thread_.join();
    }
    spdlog::info("Chargen stopped");
}

// -- Factory ------------------------------------------------------------------

std::unique_ptr<Server> Server::create(Config config) {
    return std::make_unique<ServerImpl>(std::move(config));
}

}  // namespace yuzu::server
