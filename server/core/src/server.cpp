#include <yuzu/server/server.hpp>

#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <httplib.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace yuzu::server {

namespace {

// ── Platform-specific log path ───────────────────────────────────────────────

[[nodiscard]] std::filesystem::path chargen_log_path() {
#ifdef _WIN32
    return R"(C:\ProgramData\Yuzu\logs\agent.log)";
#elif defined(__APPLE__)
    return "/Library/Logs/Yuzu/agent.log";
#else
    return "/var/log/yuzu/agent.log";
#endif
}

// ── SSE Event Bus ────────────────────────────────────────────────────────────
// A simple broadcast mechanism: chargen output → all connected SSE clients.

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
    std::size_t next_id_{0};
    std::unordered_map<std::size_t, Listener> listeners_;
};

// ── Chargen state (shared between gRPC agent handler and web UI) ─────────────

struct ChargenState {
    std::mutex                      mu;
    bool                            running{false};
    std::string                     target_agent_id;
    std::shared_ptr<spdlog::logger> file_logger;
    EventBus                        event_bus;
};

// ── AgentServiceImpl ─────────────────────────────────────────────────────────

class AgentServiceImpl /* : public yuzu::agent::v1::AgentService::Service */ {
public:
    explicit AgentServiceImpl(std::shared_ptr<ChargenState> state)
        : chargen_state_{std::move(state)} {}

    // This is a placeholder for the real gRPC service implementation.
    // When protobuf codegen is wired up, this class would inherit from
    // yuzu::agent::v1::AgentService::Service and implement the RPCs.
    //
    // The ExecuteCommand flow:
    //   1. Server sends CommandRequest (plugin="chargen", action="chargen_start")
    //   2. Agent runs the chargen plugin, which loops sending write_output()
    //   3. Each write_output() becomes a CommandResponse streamed back here
    //   4. We log each line and push it to the SSE event bus

    void on_chargen_output(const std::string& agent_id, const std::string& line) {
        auto& state = *chargen_state_;
        if (state.file_logger) {
            state.file_logger->info("[{}] {}", agent_id, line);
        }
        state.event_bus.publish(line);
    }

private:
    std::shared_ptr<ChargenState> chargen_state_;
};

// ── ManagementServiceImpl ────────────────────────────────────────────────────

class ManagementServiceImpl /* : public yuzu::server::v1::ManagementService::Service */ {
public:
    // Placeholder. SendCommand RPC would forward to the agent's ExecuteCommand stream.
};

// ── Embedded HTML (served inline — no external files needed) ─────────────────

constexpr const char* kIndexHtml = R"html(<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Yuzu — Chargen Control</title>
  <script src="https://unpkg.com/htmx.org@2.0.4"></script>
  <script src="https://unpkg.com/htmx-ext-sse@2.3.0/sse.js"></script>
  <style>
    :root {
      --bg: #0d1117; --fg: #c9d1d9; --accent: #58a6ff;
      --green: #3fb950; --red: #f85149; --surface: #161b22;
      --border: #30363d; --mono: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
      background: var(--bg); color: var(--fg);
      display: flex; flex-direction: column; height: 100vh;
    }
    header {
      display: flex; align-items: center; gap: 1rem;
      padding: 1rem 1.5rem; border-bottom: 1px solid var(--border);
    }
    header h1 { font-size: 1.25rem; font-weight: 600; }
    .badge {
      font-size: 0.75rem; padding: 0.15rem 0.5rem;
      border-radius: 1rem; font-weight: 600;
    }
    .badge-stopped { background: var(--red); color: #fff; }
    .badge-running { background: var(--green); color: #fff; }
    .controls {
      display: flex; gap: 0.75rem;
      padding: 0.75rem 1.5rem; border-bottom: 1px solid var(--border);
    }
    button {
      font-size: 0.875rem; padding: 0.4rem 1rem;
      border: 1px solid var(--border); border-radius: 0.375rem;
      cursor: pointer; font-weight: 500; transition: opacity 0.15s;
    }
    button:hover { opacity: 0.85; }
    button:disabled { opacity: 0.4; cursor: not-allowed; }
    .btn-start { background: var(--green); color: #fff; border-color: var(--green); }
    .btn-stop  { background: var(--red);   color: #fff; border-color: var(--red); }
    .btn-clear { background: var(--surface); color: var(--fg); }
    .stats {
      display: flex; gap: 1.5rem; align-items: center;
      margin-left: auto; font-size: 0.8rem; color: #8b949e;
    }
    #terminal {
      flex: 1; overflow-y: auto; padding: 1rem 1.5rem;
      font-family: var(--mono); font-size: 0.8rem; line-height: 1.4;
      white-space: pre; background: var(--bg); color: var(--green);
    }
    footer {
      padding: 0.5rem 1.5rem; border-top: 1px solid var(--border);
      font-size: 0.75rem; color: #484f58;
    }
  </style>
</head>
<body>
  <header>
    <h1>Yuzu Chargen</h1>
    <span id="status-badge" class="badge badge-stopped">STOPPED</span>
  </header>

  <div class="controls">
    <button id="btn-start" class="btn-start"
            hx-post="/api/chargen/start" hx-swap="none">
      Start
    </button>
    <button id="btn-stop" class="btn-stop" disabled
            hx-post="/api/chargen/stop" hx-swap="none">
      Stop
    </button>
    <button id="btn-clear" class="btn-clear" onclick="clearTerminal()">
      Clear
    </button>
    <div class="stats">
      <span>Lines: <strong id="line-count">0</strong></span>
      <span>Bytes: <strong id="byte-count">0</strong></span>
    </div>
  </div>

  <div id="terminal"></div>

  <footer>
    Yuzu Server &mdash; RFC 864 Character Generator &mdash; Output logged to server
  </footer>

  <script>
    const terminal  = document.getElementById('terminal');
    const badge     = document.getElementById('status-badge');
    const btnStart  = document.getElementById('btn-start');
    const btnStop   = document.getElementById('btn-stop');
    const lineCount = document.getElementById('line-count');
    const byteCount = document.getElementById('byte-count');

    let lines = 0;
    let bytes = 0;
    let evtSource = null;
    const MAX_LINES = 2000;

    function setRunning(on) {
      badge.textContent = on ? 'RUNNING' : 'STOPPED';
      badge.className   = 'badge ' + (on ? 'badge-running' : 'badge-stopped');
      btnStart.disabled = on;
      btnStop.disabled  = !on;
    }

    function clearTerminal() {
      terminal.textContent = '';
      lines = 0; bytes = 0;
      lineCount.textContent = '0';
      byteCount.textContent = '0';
    }

    function connectSSE() {
      if (evtSource) evtSource.close();
      evtSource = new EventSource('/events');

      evtSource.addEventListener('chargen', function(e) {
        lines++;
        bytes += e.data.length;
        lineCount.textContent = lines.toLocaleString();
        byteCount.textContent = bytes.toLocaleString();

        terminal.textContent += e.data + '\n';

        // Trim old lines to avoid unbounded memory
        if (lines > MAX_LINES) {
          const text = terminal.textContent;
          const idx = text.indexOf('\n');
          if (idx !== -1) terminal.textContent = text.substring(idx + 1);
        }

        // Auto-scroll
        terminal.scrollTop = terminal.scrollHeight;
      });

      evtSource.addEventListener('status', function(e) {
        setRunning(e.data === 'running');
      });

      evtSource.onerror = function() {
        setTimeout(connectSSE, 2000);
      };
    }

    // HTMX after-request hooks
    document.body.addEventListener('htmx:afterRequest', function(evt) {
      const path = evt.detail.pathInfo.requestPath;
      if (path === '/api/chargen/start') setRunning(true);
      if (path === '/api/chargen/stop')  setRunning(false);
    });

    connectSSE();
  </script>
</body>
</html>
)html";

}  // anonymous namespace

// ── ServerImpl ───────────────────────────────────────────────────────────────

class ServerImpl final : public Server {
public:
    explicit ServerImpl(Config cfg) : cfg_{std::move(cfg)} {
        chargen_state_ = std::make_shared<ChargenState>();
        setup_chargen_logger();
    }

    void run() override {
        grpc::EnableDefaultHealthCheckService(true);

        grpc::ServerBuilder agent_builder;
        agent_builder.AddListeningPort(
            cfg_.listen_address,
            cfg_.tls_enabled
                ? build_server_credentials()
                : grpc::InsecureServerCredentials()
        );
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

        // Start embedded web server on a background thread
        start_web_server();

        agent_server_->Wait();
    }

    void stop() noexcept override {
        spdlog::info("Shutting down server...");

        // Stop chargen if running
        stop_chargen();

        // Stop web server
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
    [[nodiscard]] std::shared_ptr<grpc::ServerCredentials> build_server_credentials() const {
        grpc::SslServerCredentialsOptions ssl_opts;
        return grpc::SslServerCredentials(ssl_opts);
    }

    void setup_chargen_logger() {
        auto log_path = chargen_log_path();
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

    void start_web_server() {
        web_server_ = std::make_unique<httplib::Server>();

        // Serve the HTMX page
        web_server_->Get("/", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(kIndexHtml, "text/html; charset=utf-8");
        });

        // SSE endpoint — clients connect here for live chargen output
        web_server_->Get("/events", [this](const httplib::Request&, httplib::Response& res) {
            res.set_header("Cache-Control", "no-cache");
            res.set_header("X-Accel-Buffering", "no");  // nginx passthrough

            struct SinkState {
                std::mutex              mu;
                std::condition_variable cv;
                std::deque<std::string> queue;
                std::atomic<bool>       closed{false};
                std::size_t             sub_id{0};
            };

            auto sink_state = std::make_shared<SinkState>();

            // Subscribe to the event bus
            sink_state->sub_id = chargen_state_->event_bus.subscribe(
                [sink_state](const std::string& line) {
                    {
                        std::lock_guard lk(sink_state->mu);
                        sink_state->queue.push_back(line);
                    }
                    sink_state->cv.notify_one();
                });

            auto* state_ptr = chargen_state_.get();

            res.set_content_provider(
                "text/event-stream",
                [sink_state](size_t /*offset*/, httplib::DataSink& sink) -> bool {
                    std::unique_lock lk(sink_state->mu);
                    sink_state->cv.wait_for(lk, std::chrono::seconds(15), [&] {
                        return !sink_state->queue.empty() || sink_state->closed.load();
                    });

                    if (sink_state->closed.load()) return false;

                    // Drain all queued lines
                    while (!sink_state->queue.empty()) {
                        auto& line = sink_state->queue.front();
                        std::string evt = "event: chargen\ndata: " + line + "\n\n";
                        if (!sink.write(evt.data(), evt.size())) {
                            return false;
                        }
                        sink_state->queue.pop_front();
                    }

                    // If queue was empty (timeout), send a keepalive comment
                    if (sink_state->queue.empty()) {
                        const char* keepalive = ": keepalive\n\n";
                        sink.write(keepalive, std::strlen(keepalive));
                    }

                    return true;
                },
                [sink_state, state_ptr](bool /*success*/) {
                    sink_state->closed.store(true);
                    sink_state->cv.notify_all();
                    state_ptr->event_bus.unsubscribe(sink_state->sub_id);
                }
            );
        });

        // Start chargen (POST /api/chargen/start)
        web_server_->Post("/api/chargen/start", [this](const httplib::Request&, httplib::Response& res) {
            start_chargen();
            res.set_content("{\"status\":\"started\"}", "application/json");
        });

        // Stop chargen (POST /api/chargen/stop)
        web_server_->Post("/api/chargen/stop", [this](const httplib::Request&, httplib::Response& res) {
            stop_chargen();
            res.set_content("{\"status\":\"stopped\"}", "application/json");
        });

        // Status endpoint
        web_server_->Get("/api/chargen/status", [this](const httplib::Request&, httplib::Response& res) {
            std::lock_guard lock(chargen_state_->mu);
            std::string status = chargen_state_->running ? "running" : "stopped";
            res.set_content("{\"status\":\"" + status + "\"}", "application/json");
        });

        web_thread_ = std::thread([this] {
            spdlog::info("Web UI available at http://{}:{}/",
                cfg_.web_address, cfg_.web_port);
            web_server_->listen(cfg_.web_address, cfg_.web_port);
        });
    }

    // ── Local chargen simulation ─────────────────────────────────────────────
    // In a full implementation, this would dispatch a CommandRequest to a
    // connected agent via the ExecuteCommand gRPC stream. For now, we run the
    // RFC 864 generator directly on the server to demonstrate the full pipeline.

    void start_chargen() {
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

    void stop_chargen() {
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

    Config                            cfg_;
    std::shared_ptr<ChargenState>     chargen_state_;
    AgentServiceImpl                  agent_service_{chargen_state_};
    ManagementServiceImpl             mgmt_service_;
    std::unique_ptr<grpc::Server>     agent_server_;
    std::unique_ptr<grpc::Server>     mgmt_server_;
    std::unique_ptr<httplib::Server>  web_server_;
    std::thread                       web_thread_;
    std::thread                       chargen_thread_;
};

std::unique_ptr<Server> Server::create(Config config) {
    return std::make_unique<ServerImpl>(std::move(config));
}

}  // namespace yuzu::server
