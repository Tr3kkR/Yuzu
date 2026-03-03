#include <yuzu/agent/agent.hpp>
#include <yuzu/agent/plugin_loader.hpp>

#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>

// Generated protobuf headers (produced at build time)
// #include "yuzu/agent/v1/agent.grpc.pb.h"

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

namespace yuzu::agent {

namespace {

// ── Context implementations ────────────────────────────────────────────────────
// These are passed to plugins; they bridge the C ABI callbacks to gRPC streams.

struct PluginContextImpl {
    // TODO: hold reference to config map / secret store
};

struct CommandContextImpl {
    std::string* output_accumulator;  // Write streamed output here
};

}  // anonymous namespace

// ── C ABI context function implementations ────────────────────────────────────

extern "C" {

YUZU_EXPORT void yuzu_ctx_write_output(YuzuCommandContext* ctx, const char* text) {
    if (!ctx || !text) return;
    auto* impl = reinterpret_cast<CommandContextImpl*>(ctx);
    if (impl->output_accumulator) {
        impl->output_accumulator->append(text);
        impl->output_accumulator->push_back('\n');
    }
}

YUZU_EXPORT void yuzu_ctx_report_progress(YuzuCommandContext* ctx, int percent) {
    (void)ctx;
    spdlog::debug("Plugin progress: {}%", percent);
}

YUZU_EXPORT const char* yuzu_ctx_get_config(YuzuPluginContext* ctx, const char* key) {
    (void)ctx; (void)key;
    // TODO: look up in agent config map
    return nullptr;
}

YUZU_EXPORT const char* yuzu_ctx_get_secret(YuzuPluginContext* ctx, const char* key) {
    (void)ctx; (void)key;
    // TODO: look up in secret store
    return nullptr;
}

}  // extern "C"

// ── AgentImpl ─────────────────────────────────────────────────────────────────

class AgentImpl final : public Agent {
public:
    explicit AgentImpl(Config cfg) : cfg_{std::move(cfg)} {}

    void run() override {
        spdlog::info("Yuzu agent starting (id={})", cfg_.agent_id);

        // 1. Load plugins
        auto scan = PluginLoader::scan(cfg_.plugin_dir);
        for (auto& handle : scan.loaded) {
            // Call plugin init
            if (handle.descriptor()->init) {
                int rc = handle.descriptor()->init(nullptr);
                if (rc != 0) {
                    spdlog::warn("Plugin {} init returned {}, skipping",
                        handle.descriptor()->name, rc);
                    continue;
                }
            }
            plugin_names_.emplace_back(handle.descriptor()->name);
            plugins_.push_back(std::move(handle));
        }

        spdlog::info("Loaded {} plugin(s)", plugins_.size());

        // 2. Connect to server
        auto channel = grpc::CreateChannel(
            cfg_.server_address,
            cfg_.tls_enabled
                ? grpc::SslCredentials({})
                : grpc::InsecureChannelCredentials()
        );

        // 3. Main loop
        while (!stop_requested_.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(cfg_.heartbeat_interval);
            spdlog::debug("Heartbeat tick");
            // TODO: send HeartbeatRequest via gRPC stub
        }

        // 4. Shutdown plugins
        for (auto& handle : plugins_) {
            if (handle.descriptor()->shutdown) {
                handle.descriptor()->shutdown(nullptr);
            }
        }

        spdlog::info("Yuzu agent stopped");
    }

    void stop() noexcept override {
        stop_requested_.store(true, std::memory_order_release);
    }

    std::string_view agent_id() const noexcept override { return cfg_.agent_id; }

    std::vector<std::string> loaded_plugins() const override { return plugin_names_; }

private:
    Config                   cfg_;
    std::atomic<bool>        stop_requested_{false};
    std::vector<PluginHandle> plugins_;
    std::vector<std::string>  plugin_names_;
};

// ── Factory ───────────────────────────────────────────────────────────────────

std::unique_ptr<Agent> Agent::create(Config config) {
    return std::make_unique<AgentImpl>(std::move(config));
}

}  // namespace yuzu::agent
