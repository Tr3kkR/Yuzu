#ifdef _WIN32
#  include <io.h>
#  pragma section(".CRT$XCA", read)
static void __cdecl diag_dll_static_init() {
    const char msg[] = "[DIAG] DLL static-init starting (before proto registration)\n";
    _write(2, msg, sizeof(msg) - 1);
}
__declspec(allocate(".CRT$XCA")) static void (__cdecl *p_dll_diag)() = diag_dll_static_init;
#endif

#include <yuzu/agent/agent.hpp>
#include <yuzu/agent/plugin_loader.hpp>

#include <grpcpp/grpcpp.h>
#include <spdlog/spdlog.h>

// Generated protobuf/gRPC headers (flat output from YuzuProto.cmake)
#include "agent.grpc.pb.h"

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace yuzu::agent {

namespace {

namespace pb = ::yuzu::agent::v1;

// Stream type alias: agent writes CommandResponse, reads CommandRequest.
// (Subscribe RPC: stream CommandResponse → stream CommandRequest)
using SubscribeStream = grpc::ClientReaderWriter<pb::CommandResponse, pb::CommandRequest>;

// ── Context implementations ────────────────────────────────────────────────────
// These are passed to plugins; they bridge the C ABI callbacks to gRPC streams.

struct PluginContextImpl {
    // TODO: hold reference to config map / secret store
};

struct CommandContextImpl {
    SubscribeStream* stream;
    std::mutex*      write_mu;   // protects concurrent stream->Write()
    std::string      command_id;
};

}  // anonymous namespace

// ── C ABI context function implementations ────────────────────────────────────

extern "C" {

YUZU_EXPORT void yuzu_ctx_write_output(YuzuCommandContext* ctx, const char* text) {
    if (!ctx || !text) return;
    auto* impl = reinterpret_cast<CommandContextImpl*>(ctx);

    pb::CommandResponse resp;
    resp.set_command_id(impl->command_id);
    resp.set_status(pb::CommandResponse::RUNNING);
    resp.set_output(text);

    std::lock_guard lock(*impl->write_mu);
    impl->stream->Write(resp);
}

YUZU_EXPORT void yuzu_ctx_report_progress(YuzuCommandContext* ctx, int percent) {
    (void)ctx;
    spdlog::debug("Plugin progress: {}%", percent);
}

YUZU_EXPORT const char* yuzu_ctx_get_config(YuzuPluginContext* ctx, const char* key) {
    (void)ctx; (void)key;
    return nullptr;
}

YUZU_EXPORT const char* yuzu_ctx_get_secret(YuzuPluginContext* ctx, const char* key) {
    (void)ctx; (void)key;
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

        auto stub = pb::AgentService::NewStub(channel);

        // 3. Register with server
        {
            grpc::ClientContext ctx;
            pb::RegisterRequest req;
            auto* info = req.mutable_info();
            info->set_agent_id(cfg_.agent_id);
            info->set_agent_version("0.1.0");

            for (const auto& handle : plugins_) {
                auto* pi = info->add_plugins();
                pi->set_name(handle.descriptor()->name);
                pi->set_version(handle.descriptor()->version);
                pi->set_description(handle.descriptor()->description);
            }

            pb::RegisterResponse resp;
            auto status = stub->Register(&ctx, req, &resp);
            if (!status.ok()) {
                spdlog::error("Failed to register with server: {}",
                    status.error_message());
                goto shutdown_plugins;
            }
            if (!resp.accepted()) {
                spdlog::error("Server rejected registration: {}",
                    resp.reject_reason());
                goto shutdown_plugins;
            }
            session_id_ = resp.session_id();
            spdlog::info("Registered with server (session={})", session_id_);
        }

        // 4. Open Subscribe bidi stream
        {
            grpc::ClientContext sub_ctx;
            subscribe_ctx_.store(&sub_ctx, std::memory_order_release);

            auto stream = stub->Subscribe(&sub_ctx);
            if (!stream) {
                spdlog::error("Failed to open Subscribe stream");
                subscribe_ctx_.store(nullptr, std::memory_order_release);
                goto shutdown_plugins;
            }
            spdlog::info("Subscribe stream opened — waiting for commands");

            // 5. Read commands from server and dispatch to plugins
            pb::CommandRequest cmd;
            while (stream->Read(&cmd)) {
                if (stop_requested_.load(std::memory_order_acquire)) break;

                spdlog::info("Received command: plugin={}, action={}, id={}",
                    cmd.plugin(), cmd.action(), cmd.command_id());

                // Find the matching plugin
                const YuzuPluginDescriptor* target = nullptr;
                for (const auto& handle : plugins_) {
                    if (cmd.plugin() == handle.descriptor()->name) {
                        target = handle.descriptor();
                        break;
                    }
                }

                if (!target) {
                    spdlog::warn("No plugin '{}' found", cmd.plugin());
                    pb::CommandResponse resp;
                    resp.set_command_id(cmd.command_id());
                    resp.set_status(pb::CommandResponse::REJECTED);
                    resp.set_output("plugin not found: " + cmd.plugin());
                    std::lock_guard lock(stream_write_mu_);
                    stream->Write(resp);
                    continue;
                }

                // Dispatch execute() in a background thread.
                // chargen_start blocks until chargen_stop sets the atomic flag,
                // so concurrent dispatch is required.
                auto* raw_stream = stream.get();
                std::thread exec_thread([this, target, cmd, raw_stream]() {
                    CommandContextImpl ctx_impl{
                        .stream     = raw_stream,
                        .write_mu   = &stream_write_mu_,
                        .command_id = cmd.command_id(),
                    };
                    auto* raw_ctx = reinterpret_cast<YuzuCommandContext*>(&ctx_impl);

                    // Convert protobuf parameter map → C ABI YuzuParam array
                    std::vector<std::string> keys, values;
                    for (const auto& [k, v] : cmd.parameters()) {
                        keys.push_back(k);
                        values.push_back(v);
                    }
                    std::vector<YuzuParam> params;
                    for (size_t i = 0; i < keys.size(); ++i) {
                        params.push_back(YuzuParam{
                            keys[i].c_str(), values[i].c_str()});
                    }

                    int rc = target->execute(
                        raw_ctx,
                        cmd.action().c_str(),
                        params.data(),
                        params.size()
                    );

                    // Send final status
                    pb::CommandResponse final_resp;
                    final_resp.set_command_id(cmd.command_id());
                    final_resp.set_status(rc == 0
                        ? pb::CommandResponse::SUCCESS
                        : pb::CommandResponse::FAILURE);
                    final_resp.set_exit_code(rc);

                    std::lock_guard lock(stream_write_mu_);
                    raw_stream->Write(final_resp);

                    spdlog::info("Command {} finished (rc={})",
                        cmd.command_id(), rc);
                });

                {
                    std::lock_guard lock(exec_mu_);
                    exec_threads_.push_back(std::move(exec_thread));
                }
            }

            subscribe_ctx_.store(nullptr, std::memory_order_release);
            spdlog::info("Subscribe stream ended");
        }

    shutdown_plugins:
        // 6. Shutdown plugins (signals running commands like chargen to stop)
        for (auto& handle : plugins_) {
            if (handle.descriptor()->shutdown) {
                handle.descriptor()->shutdown(nullptr);
            }
        }

        // 7. Wait for executing command threads to finish
        {
            std::lock_guard lock(exec_mu_);
            for (auto& t : exec_threads_) {
                if (t.joinable()) t.join();
            }
            exec_threads_.clear();
        }

        spdlog::info("Yuzu agent stopped");
    }

    void stop() noexcept override {
        stop_requested_.store(true, std::memory_order_release);
        // Cancel the Subscribe stream to unblock the Read() call
        if (auto* ctx = subscribe_ctx_.load(std::memory_order_acquire)) {
            ctx->TryCancel();
        }
    }

    std::string_view agent_id() const noexcept override { return cfg_.agent_id; }

    std::vector<std::string> loaded_plugins() const override {
        return plugin_names_;
    }

private:
    Config                              cfg_;
    std::string                         session_id_;
    std::atomic<bool>                   stop_requested_{false};
    std::atomic<grpc::ClientContext*>   subscribe_ctx_{nullptr};
    std::vector<PluginHandle>           plugins_;
    std::vector<std::string>            plugin_names_;
    std::mutex                          stream_write_mu_;
    std::mutex                          exec_mu_;
    std::vector<std::thread>            exec_threads_;
};

// ── Factory ───────────────────────────────────────────────────────────────────

std::unique_ptr<Agent> Agent::create(Config config) {
    return std::make_unique<AgentImpl>(std::move(config));
}

}  // namespace yuzu::agent
