#ifdef _WIN32
#include <io.h>
#pragma section(".CRT$XCB", read)
static void __cdecl diag_dll_static_init() {
    const char msg[] = "[DIAG] DLL static-init starting (before proto registration)\n";
    _write(2, msg, sizeof(msg) - 1);
}
__declspec(allocate(".CRT$XCB")) static void(__cdecl* p_dll_diag)() = diag_dll_static_init;
#endif

#include <yuzu/agent/agent.hpp>
#include <yuzu/agent/cert_discovery.hpp>
#include <yuzu/agent/cert_store.hpp>
#include <yuzu/agent/cloud_identity.hpp>
#include <yuzu/agent/kv_store.hpp>
#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/agent/trigger_engine.hpp>
#include <yuzu/agent/updater.hpp>
#include <yuzu/metrics.hpp>
#include <yuzu/secure_zero.hpp>
#include <yuzu/version.hpp>

#include <grpcpp/grpcpp.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

// Generated protobuf/gRPC headers (flat output from YuzuProto.cmake)
#include "agent.grpc.pb.h"

#ifdef _WIN32
#include <winsock2.h> // gethostname
#else
#include <unistd.h> // gethostname
#endif

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace yuzu::agent {

namespace {

namespace pb = ::yuzu::agent::v1;
constexpr const char* kSessionMetadataKey = "x-yuzu-session-id";

#if defined(_WIN32)
constexpr const char* kAgentOs = "windows";
constexpr const char* kAgentArch = "x86_64";
#elif defined(__APPLE__)
#if defined(__aarch64__)
constexpr const char* kAgentOs = "darwin";
constexpr const char* kAgentArch = "aarch64";
#else
constexpr const char* kAgentOs = "darwin";
constexpr const char* kAgentArch = "x86_64";
#endif
#elif defined(__aarch64__)
constexpr const char* kAgentOs = "linux";
constexpr const char* kAgentArch = "aarch64";
#else
constexpr const char* kAgentOs = "linux";
constexpr const char* kAgentArch = "x86_64";
#endif

std::string read_file_contents(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f)
        return {};
    return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

// Stream type alias: agent writes CommandResponse, reads CommandRequest.
// (Subscribe RPC: stream CommandResponse -> stream CommandRequest)
using SubscribeStream = grpc::ClientReaderWriter<pb::CommandResponse, pb::CommandRequest>;

// ── Bounded Thread Pool ──────────────────────────────────────────────────────
// Replaces unbounded std::thread-per-command dispatch. Workers pull tasks from
// a shared queue protected by a mutex + condition variable. If the queue exceeds
// max_queue_size, submit() returns false so the caller can reject the command.

class ThreadPool {
public:
    explicit ThreadPool(size_t num_threads, size_t max_queue_size = 1000)
        : max_queue_size_{max_queue_size} {
        // Clamp thread count: min 4, max 32
        num_threads = std::max<size_t>(num_threads, 4);
        num_threads = std::min<size_t>(num_threads, 32);
        workers_.reserve(num_threads);
        for (size_t i = 0; i < num_threads; ++i) {
            workers_.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock lock(mu_);
                        cv_.wait(lock, [this] { return stop_ || !tasks_.empty(); });
                        if (stop_ && tasks_.empty())
                            return;
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }
                    task();
                }
            });
        }
        spdlog::info("Thread pool started: {} workers, max queue {}", num_threads, max_queue_size);
    }

    // Returns false if the queue is full (backpressure).
    bool submit(std::function<void()> task) {
        {
            std::lock_guard lock(mu_);
            if (stop_)
                return false;
            if (tasks_.size() >= max_queue_size_)
                return false;
            tasks_.push(std::move(task));
        }
        cv_.notify_one();
        return true;
    }

    ~ThreadPool() {
        {
            std::lock_guard lock(mu_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto& w : workers_) {
            if (w.joinable())
                w.join();
        }
    }

    // Non-copyable, non-movable
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mu_;
    std::condition_variable cv_;
    bool stop_ = false;
    size_t max_queue_size_;
};

// Context implementations
// These are passed to plugins; they bridge the C ABI callbacks to gRPC streams.

struct PluginContextImpl {
    std::unordered_map<std::string, std::string> config;
    KvStore* kv_store{nullptr};            // non-owning; lifetime managed by AgentImpl
    TriggerEngine* trigger_engine{nullptr}; // non-owning; lifetime managed by AgentImpl
    std::string plugin_name;               // set per-plugin during init/execute for KV namespacing
};

// Per-command output is buffered and flushed in a single gRPC Write instead of
// issuing one Write per line. This reduces serialized gRPC writes from N-per-
// command to 1-per-command for most plugins.
static constexpr size_t kOutputFlushThreshold = 64 * 1024; // 64 KB auto-flush

struct CommandContextImpl {
    std::shared_ptr<SubscribeStream> stream;
    std::mutex* write_mu; // protects concurrent stream->Write()
    std::string command_id;
    std::chrono::steady_clock::time_point start_time;
    std::atomic<bool> first_output_sent{false};

    // Buffered output — flushed once after execute(), or when buffer exceeds threshold
    std::vector<std::string> output_buffer;
    size_t output_buffer_bytes{0};
    std::mutex buf_mu;

    void append_output(const char* text) {
        std::lock_guard lock(buf_mu);
        size_t len = std::strlen(text);
        output_buffer.emplace_back(text, len);
        output_buffer_bytes += len;
        if (output_buffer_bytes >= kOutputFlushThreshold) {
            flush_output_locked();
        }
    }

    void flush_output() {
        std::lock_guard lock(buf_mu);
        flush_output_locked();
    }

private:
    void flush_output_locked() {
        if (output_buffer.empty())
            return;

        // Concatenate all buffered lines into a single payload
        std::string combined;
        combined.reserve(output_buffer_bytes + output_buffer.size()); // +size for newlines
        for (size_t i = 0; i < output_buffer.size(); ++i) {
            if (i > 0)
                combined += '\n';
            combined += output_buffer[i];
        }
        output_buffer.clear();
        output_buffer_bytes = 0;

        pb::CommandResponse resp;
        resp.set_command_id(command_id);
        resp.set_status(pb::CommandResponse::RUNNING);
        resp.set_output(std::move(combined));

        std::lock_guard lock(*write_mu);
        stream->Write(resp, grpc::WriteOptions());
    }
};

template <typename F> struct ScopeExit {
    F fn;
    ~ScopeExit() { fn(); }
};

} // anonymous namespace

// C ABI context function implementations

extern "C" {

YUZU_EXPORT void yuzu_ctx_write_output(YuzuCommandContext* ctx, const char* text) {
    if (!ctx || !text)
        return;
    auto* impl = reinterpret_cast<CommandContextImpl*>(ctx);
    impl->append_output(text);
}

YUZU_EXPORT void yuzu_ctx_report_progress(YuzuCommandContext* ctx, int percent) {
    (void)ctx;
    spdlog::debug("Plugin progress: {}%", percent);
}

YUZU_EXPORT const char* yuzu_ctx_get_config(YuzuPluginContext* ctx, const char* key) {
    if (!ctx || !key)
        return nullptr;
    auto* impl = reinterpret_cast<PluginContextImpl*>(ctx);
    auto it = impl->config.find(key);
    if (it == impl->config.end())
        return nullptr;
    return it->second.c_str();
}

YUZU_EXPORT const char* yuzu_ctx_get_secret(YuzuPluginContext* ctx, const char* key) {
    (void)ctx;
    (void)key;
    return nullptr;
}

// ── KV Storage C ABI (ABI v2) ────────────────────────────────────────────────

YUZU_EXPORT int yuzu_ctx_storage_set(YuzuPluginContext* ctx, const char* key, const char* value) {
    if (!ctx || !key || !value)
        return -1;
    auto* impl = reinterpret_cast<PluginContextImpl*>(ctx);
    if (!impl->kv_store || impl->plugin_name.empty())
        return -2;
    return impl->kv_store->set(impl->plugin_name, key, value) ? 0 : 1;
}

YUZU_EXPORT const char* yuzu_ctx_storage_get(YuzuPluginContext* ctx, const char* key) {
    if (!ctx || !key)
        return nullptr;
    auto* impl = reinterpret_cast<PluginContextImpl*>(ctx);
    if (!impl->kv_store || impl->plugin_name.empty())
        return nullptr;
    auto val = impl->kv_store->get(impl->plugin_name, key);
    if (!val.has_value())
        return nullptr;
    // Caller must free with yuzu_free_string()
    char* result = static_cast<char*>(std::malloc(val->size() + 1));
    if (!result)
        return nullptr;
    std::memcpy(result, val->c_str(), val->size() + 1);
    return result;
}

YUZU_EXPORT int yuzu_ctx_storage_delete(YuzuPluginContext* ctx, const char* key) {
    if (!ctx || !key)
        return -1;
    auto* impl = reinterpret_cast<PluginContextImpl*>(ctx);
    if (!impl->kv_store || impl->plugin_name.empty())
        return -2;
    return impl->kv_store->del(impl->plugin_name, key) ? 0 : 1;
}

YUZU_EXPORT int yuzu_ctx_storage_exists(YuzuPluginContext* ctx, const char* key) {
    if (!ctx || !key)
        return -1;
    auto* impl = reinterpret_cast<PluginContextImpl*>(ctx);
    if (!impl->kv_store || impl->plugin_name.empty())
        return -2;
    return impl->kv_store->exists(impl->plugin_name, key) ? 0 : 1;
}

YUZU_EXPORT const char* yuzu_ctx_storage_list(YuzuPluginContext* ctx, const char* prefix) {
    if (!ctx)
        return nullptr;
    auto* impl = reinterpret_cast<PluginContextImpl*>(ctx);
    if (!impl->kv_store || impl->plugin_name.empty())
        return nullptr;
    auto keys = impl->kv_store->list(impl->plugin_name, prefix ? prefix : "");

    // Build JSON array: ["key1","key2",...]
    std::string json = "[";
    for (size_t i = 0; i < keys.size(); ++i) {
        if (i > 0)
            json += ',';
        json += '"';
        // Escape any quotes in key names
        for (char c : keys[i]) {
            if (c == '"')
                json += "\\\"";
            else if (c == '\\')
                json += "\\\\";
            else
                json += c;
        }
        json += '"';
    }
    json += ']';

    char* result = static_cast<char*>(std::malloc(json.size() + 1));
    if (!result)
        return nullptr;
    std::memcpy(result, json.c_str(), json.size() + 1);
    return result;
}

YUZU_EXPORT int yuzu_register_trigger(YuzuPluginContext* /*ctx*/, const char* /*trigger_id*/,
                                      const char* /*trigger_type*/, const char* /*config_json*/) {
    // Trigger registration is handled by the trigger engine at the agent level.
    // Plugins call this to express intent; the agent wires it during init.
    // For now, return success — the agent's init sequence reads trigger configs
    // from the plugin's init() call and routes them to the TriggerEngine.
    return 0;
}

YUZU_EXPORT int yuzu_unregister_trigger(YuzuPluginContext* /*ctx*/, const char* /*trigger_id*/) {
    return 0;
}

} // extern "C"

// AgentImpl

class AgentImpl final : public Agent {
public:
    explicit AgentImpl(Config cfg) : cfg_{std::move(cfg)} {
        metrics_.describe("yuzu_agent_uptime_seconds", "Agent uptime in seconds", "gauge");
        metrics_.describe("yuzu_agent_commands_executed_total", "Total commands executed by plugin",
                          "counter");
        metrics_.describe("yuzu_agent_plugins_loaded", "Number of loaded plugins", "gauge");
    }

    void run() override {
        spdlog::info("Yuzu agent starting (id={})", cfg_.agent_id);

        // 1. Load plugins
        auto scan = PluginLoader::scan(cfg_.plugin_dir);

        // Collect successfully loaded handles first (before init)
        std::vector<PluginHandle> candidates;
        for (auto& handle : scan.loaded) {
            candidates.push_back(std::move(handle));
        }

        // Build the plugin context config map with agent state
        plugin_ctx_.config["agent.id"] = cfg_.agent_id;
        plugin_ctx_.config["agent.version"] = std::string{yuzu::kFullVersionString};
        plugin_ctx_.config["agent.build_number"] = std::to_string(yuzu::kBuildNumber);
        plugin_ctx_.config["agent.git_commit"] = std::string{yuzu::kGitCommitHash};
        plugin_ctx_.config["agent.server_address"] = cfg_.server_address;
        plugin_ctx_.config["agent.tls_enabled"] = cfg_.tls_enabled ? "true" : "false";
        plugin_ctx_.config["agent.heartbeat_interval"] =
            std::to_string(cfg_.heartbeat_interval.count());
        plugin_ctx_.config["agent.plugin_dir"] = cfg_.plugin_dir.string();
        plugin_ctx_.config["agent.data_dir"] = cfg_.data_dir.string();
        plugin_ctx_.config["agent.log_level"] = cfg_.log_level;
        plugin_ctx_.config["agent.debug_mode"] = cfg_.debug_mode ? "true" : "false";
        plugin_ctx_.config["agent.verbose_logging"] = cfg_.verbose_logging ? "true" : "false";
        plugin_ctx_.config["agent.reconnect_count"] = "0";

        // 1b. Open KV store for plugin persistent storage
        {
            auto kv_path = cfg_.data_dir / "kv_store.db";
            auto kv_result = KvStore::open(kv_path);
            if (kv_result.has_value()) {
                kv_store_ = std::make_unique<KvStore>(std::move(*kv_result));
                plugin_ctx_.kv_store = kv_store_.get();
                spdlog::info("KV store ready: {}", kv_path.string());
            } else {
                spdlog::error("Failed to open KV store: {}", kv_result.error().message);
                spdlog::warn("Plugin KV storage will be unavailable");
            }
        }

        // Record start time for uptime calculation
        auto start_epoch = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
        plugin_ctx_.config["agent.start_time_epoch"] = std::to_string(start_epoch);

        size_t module_index = 0;
        auto record_module = [this, &module_index](std::string_view name, std::string_view version,
                                                   std::string_view description,
                                                   std::string_view status) {
            auto prefix = std::format("agent.modules.{}", module_index++);
            plugin_ctx_.config[prefix + ".name"] = std::string{name};
            plugin_ctx_.config[prefix + ".version"] = std::string{version};
            plugin_ctx_.config[prefix + ".description"] = std::string{description};
            plugin_ctx_.config[prefix + ".status"] = std::string{status};
        };

        for (const auto& err : scan.errors) {
            auto module_name = std::filesystem::path{err.path}.stem().string();
            record_module(module_name, "", err.reason, "load_failed");
        }

        auto* raw_plugin_ctx = reinterpret_cast<YuzuPluginContext*>(&plugin_ctx_);

        for (auto& handle : candidates) {
            const auto* descriptor = handle.descriptor();
            // Set plugin name on context so KV storage is namespaced per-plugin
            plugin_ctx_.plugin_name = descriptor->name;
            if (handle.descriptor()->init) {
                int rc = handle.descriptor()->init(raw_plugin_ctx);
                if (rc != 0) {
                    spdlog::warn("Plugin {} init returned {}, skipping", handle.descriptor()->name,
                                 rc);
                    record_module(descriptor->name, descriptor->version,
                                  std::format("{} (init rc={})", descriptor->description, rc),
                                  "init_failed");
                    continue;
                }
            }
            record_module(descriptor->name, descriptor->version, descriptor->description, "loaded");
            plugin_names_.emplace_back(handle.descriptor()->name);
            plugins_.push_back(std::move(handle));
        }

        // Populate plugin list in config (available to all plugins via get_config)
        plugin_ctx_.config["agent.plugins.count"] = std::to_string(plugins_.size());
        plugin_ctx_.config["agent.modules.count"] = std::to_string(module_index);
        for (size_t i = 0; i < plugins_.size(); ++i) {
            auto prefix = std::format("agent.plugins.{}", i);
            plugin_ctx_.config[prefix + ".name"] = plugins_[i].descriptor()->name;
            plugin_ctx_.config[prefix + ".version"] = plugins_[i].descriptor()->version;
            plugin_ctx_.config[prefix + ".description"] = plugins_[i].descriptor()->description;
        }

        metrics_.gauge("yuzu_agent_plugins_loaded").set(static_cast<double>(plugins_.size()));
        start_time_ = std::chrono::steady_clock::now();
        spdlog::info("Loaded {} plugin(s)", plugins_.size());

        // Initialize bounded thread pool for command dispatch
        thread_pool_ = std::make_unique<ThreadPool>(
            std::thread::hardware_concurrency());

        // Scope guard: shutdown plugins and destroy thread pool on any exit path
        ScopeExit cleanup{[this]() {
            for (auto& handle : plugins_) {
                if (handle.descriptor()->shutdown) {
                    handle.descriptor()->shutdown(
                        reinterpret_cast<YuzuPluginContext*>(&plugin_ctx_));
                }
            }
            // Destroy the thread pool — signals stop, drains queue, joins workers
            thread_pool_.reset();
            spdlog::info("Yuzu agent stopped");
        }};

        // 2. Connect to server (tuned for low-latency bidirectional streaming)
        grpc::ChannelArguments ch_args;
        ch_args.SetInt(GRPC_ARG_KEEPALIVE_TIME_MS, 60000);
        ch_args.SetInt(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 20000);
        ch_args.SetInt(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS, 1);
        ch_args.SetInt(GRPC_ARG_HTTP2_MAX_PINGS_WITHOUT_DATA, 0);

        // Auto-discover client certificate if none explicitly configured
        if (cfg_.cert_auto_discovery && cfg_.tls_client_cert.empty() && cfg_.cert_store.empty()) {
            auto discovered = discover_client_cert();
            if (discovered) {
                cfg_.tls_client_cert = discovered->cert_path;
                cfg_.tls_client_key = discovered->key_path;
                spdlog::info("Using auto-discovered cert from {} (source: {})",
                             discovered->cert_path.string(), discovered->source);
            }
        }

        CloudIdentity cloud_id; // Populated before registration (step 2b)
        std::shared_ptr<grpc::ChannelCredentials> creds;
        std::shared_ptr<grpc::Channel> channel;
        std::unique_ptr<pb::AgentService::Stub> stub;
        if (cfg_.tls_enabled) {
            grpc::SslCredentialsOptions ssl_opts;
            if (!cfg_.tls_ca_cert.empty()) {
                ssl_opts.pem_root_certs = read_file_contents(cfg_.tls_ca_cert);
                if (ssl_opts.pem_root_certs.empty()) {
                    spdlog::error("Failed to read CA cert from {}", cfg_.tls_ca_cert.string());
                    return;
                }
            }

            // Client certificate: prefer cert store, fall back to PEM files
            if (!cfg_.cert_store.empty()) {
                // Read client cert + key from OS certificate store
                spdlog::info("Reading client certificate from {} store...", cfg_.cert_store);
                auto store_result =
                    read_cert_from_store(cfg_.cert_store, cfg_.cert_subject, cfg_.cert_thumbprint);

                if (!store_result.ok()) {
                    spdlog::error("Certificate store error: {}", store_result.error);
                    return;
                }

                ssl_opts.pem_cert_chain = std::move(store_result.pem_cert_chain);
                ssl_opts.pem_private_key = std::move(store_result.pem_private_key);
                spdlog::info("mTLS enabled: using certificate from {} store", cfg_.cert_store);
            } else {
                const bool has_client_cert = !cfg_.tls_client_cert.empty();
                const bool has_client_key = !cfg_.tls_client_key.empty();
                if (has_client_cert != has_client_key) {
                    spdlog::error("mTLS requires both --client-cert and --client-key");
                    return;
                }

                if (has_client_cert && has_client_key) {
                    ssl_opts.pem_cert_chain = read_file_contents(cfg_.tls_client_cert);
                    ssl_opts.pem_private_key = read_file_contents(cfg_.tls_client_key);
                    if (ssl_opts.pem_cert_chain.empty() || ssl_opts.pem_private_key.empty()) {
                        spdlog::error("Failed to read client cert/key for mTLS");
                        return;
                    } else {
                        spdlog::info("mTLS enabled: using client certificate files");
                    }
                }
            }
            creds = grpc::SslCredentials(ssl_opts);
            yuzu::secure_zero(ssl_opts.pem_private_key);
        } else {
            creds = grpc::InsecureChannelCredentials();
        }

        channel = grpc::CreateCustomChannel(cfg_.server_address, creds, ch_args);

        stub = pb::AgentService::NewStub(channel);

        // 2b. Detect cloud instance identity (for auto-approve)
        {
            cloud_id = detect_cloud_identity();
            if (cloud_id.valid()) {
                spdlog::info("Cloud identity detected: provider={}, instance={}, region={}",
                             cloud_id.provider, cloud_id.instance_id, cloud_id.region);
            }
        }

        // 3. Register with server
        {
            grpc::ClientContext ctx;
            pb::RegisterRequest req;
            auto* info = req.mutable_info();
            info->set_agent_id(cfg_.agent_id);
            info->set_agent_version(std::string{yuzu::kFullVersionString});

            // Set hostname for auto-approve hostname_glob matching
            {
                char host_buf[256] = {};
                if (gethostname(host_buf, sizeof(host_buf) - 1) == 0) {
                    info->set_hostname(host_buf);
                }
            }

            // Load agent tags from tags.json and populate scopable_tags
            {
                auto tags_path = cfg_.data_dir / "tags.json";
                std::error_code tag_ec;
                if (std::filesystem::exists(tags_path, tag_ec)) {
                    std::ifstream tags_file(tags_path);
                    if (tags_file) {
                        try {
                            std::string tags_content = read_file_contents(tags_path);
                            auto* tags_map = info->mutable_scopable_tags();
                            // Quick manual JSON parse for flat {"key":"value",...} objects
                            size_t pos = 0;
                            while ((pos = tags_content.find('"', pos)) != std::string::npos) {
                                size_t key_start = pos + 1;
                                size_t key_end = tags_content.find('"', key_start);
                                if (key_end == std::string::npos)
                                    break;
                                std::string key =
                                    tags_content.substr(key_start, key_end - key_start);
                                pos = key_end + 1;
                                pos = tags_content.find(':', pos);
                                if (pos == std::string::npos)
                                    break;
                                pos = tags_content.find('"', pos);
                                if (pos == std::string::npos)
                                    break;
                                size_t val_start = pos + 1;
                                size_t val_end = tags_content.find('"', val_start);
                                if (val_end == std::string::npos)
                                    break;
                                std::string val =
                                    tags_content.substr(val_start, val_end - val_start);
                                (*tags_map)[key] = val;
                                pos = val_end + 1;
                            }
                            if (!tags_map->empty()) {
                                spdlog::info("Loaded {} tags from {}", tags_map->size(),
                                             tags_path.string());
                            }
                        } catch (...) {
                            spdlog::warn("Failed to parse tags.json");
                        }
                    }
                }
            }

            for (const auto& handle : plugins_) {
                auto* pi = info->add_plugins();
                pi->set_name(handle.descriptor()->name);
                pi->set_version(handle.descriptor()->version);
                pi->set_description(handle.descriptor()->description);
                if (handle.descriptor()->actions) {
                    for (const char* const* a = handle.descriptor()->actions; *a; ++a) {
                        pi->add_capabilities(*a);
                    }
                }
            }

            // Tier 2: Include enrollment token if provided
            if (!cfg_.enrollment_token.empty()) {
                req.set_enrollment_token(cfg_.enrollment_token);
                spdlog::info("Including enrollment token in registration");
            }

            // Tier 3: Include cloud identity attestation if available
            if (cloud_id.valid()) {
                req.set_attestation_provider(cloud_id.provider);
                req.set_machine_certificate(cloud_id.identity_document.data(),
                                            cloud_id.identity_document.size());
                spdlog::info("Including {} cloud attestation in registration", cloud_id.provider);
            }

            pb::RegisterResponse resp;
            auto register_start = std::chrono::steady_clock::now();
            auto status = stub->Register(&ctx, req, &resp);
            if (!status.ok()) {
                spdlog::error("Failed to register with server: {}", status.error_message());
                return;
            }
            if (!resp.accepted()) {
                spdlog::error("Server rejected registration: {}", resp.reject_reason());
                return;
            }

            auto enrollment_status = resp.enrollment_status();
            if (enrollment_status == "pending") {
                spdlog::warn("Registration pending admin approval - agent will not receive "
                             "commands until approved");
                spdlog::info("Ask your administrator to approve agent '{}' in the server dashboard",
                             cfg_.agent_id);
                return;
            }

            session_id_ = resp.session_id();
            auto connected_since_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                          std::chrono::system_clock::now().time_since_epoch())
                                          .count();
            plugin_ctx_.config["agent.session_id"] = session_id_;
            plugin_ctx_.config["agent.connected_since"] = std::to_string(connected_since_ms);

            // Measure Register RPC latency
            auto register_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::steady_clock::now() - register_start)
                                        .count();
            plugin_ctx_.config["agent.latency_ms"] = std::to_string(register_elapsed);

            // Query gRPC channel state
            if (channel) {
                auto state = channel->GetState(false);
                const char* state_str = "UNKNOWN";
                switch (state) {
                case GRPC_CHANNEL_IDLE:
                    state_str = "IDLE";
                    break;
                case GRPC_CHANNEL_CONNECTING:
                    state_str = "CONNECTING";
                    break;
                case GRPC_CHANNEL_READY:
                    state_str = "READY";
                    break;
                case GRPC_CHANNEL_TRANSIENT_FAILURE:
                    state_str = "TRANSIENT_FAILURE";
                    break;
                case GRPC_CHANNEL_SHUTDOWN:
                    state_str = "SHUTDOWN";
                    break;
                }
                plugin_ctx_.config["agent.grpc_channel_state"] = state_str;
            }
            spdlog::info("Registered with server (session={}, enrollment={})", session_id_,
                         enrollment_status.empty() ? "enrolled" : enrollment_status);
        }

        // 3b. OTA updater: rollback check and old binary cleanup
        {
            updater_ = std::make_unique<Updater>(
                UpdateConfig{cfg_.auto_update, cfg_.update_check_interval}, cfg_.agent_id,
                std::string{yuzu::kFullVersionString}, kAgentOs, kAgentArch,
                current_executable_path());

            if (updater_->rollback_if_needed()) {
                spdlog::warn("OTA rollback was triggered - running previous binary");
            }
            updater_->cleanup_old_binary();
        }

        // 4. Open Subscribe bidi stream
        {
            grpc::ClientContext sub_ctx;
            if (!session_id_.empty()) {
                sub_ctx.AddMetadata(kSessionMetadataKey, session_id_);
            }
            subscribe_ctx_.store(&sub_ctx, std::memory_order_release);

            std::shared_ptr<SubscribeStream> stream{stub->Subscribe(&sub_ctx)};
            if (!stream) {
                spdlog::error("Failed to open Subscribe stream");
                subscribe_ctx_.store(nullptr, std::memory_order_release);
                return;
            }
            spdlog::info("Subscribe stream opened - waiting for commands");

            // 4b. Spawn OTA update check thread
            if (cfg_.auto_update && updater_) {
                auto* raw_stub = static_cast<void*>(stub.get());
                update_thread_ = std::thread([this, raw_stub]() {
                    spdlog::info("OTA update checker started (interval={}s)",
                                 cfg_.update_check_interval.count());
                    while (!stop_requested_.load(std::memory_order_acquire)) {
                        auto result = updater_->check_and_apply(raw_stub);
                        if (result.has_value() && result.value()) {
                            spdlog::info("OTA update applied - agent will restart");
                            stop();
                            return;
                        }
                        if (!result.has_value()) {
                            spdlog::warn("OTA update check failed: {}", result.error().message);
                        }
                        // Sleep in small increments so we can respond to stop quickly
                        auto remaining = cfg_.update_check_interval;
                        while (remaining.count() > 0 &&
                               !stop_requested_.load(std::memory_order_acquire)) {
                            auto sleep_time = std::min(remaining, std::chrono::seconds{5});
                            std::this_thread::sleep_for(sleep_time);
                            remaining -= sleep_time;
                        }
                    }
                });
            }

            // 4c. Spawn heartbeat thread — piggybacks agent metrics in status_tags
            {
                auto hb_stub = pb::AgentService::NewStub(channel);
                heartbeat_thread_ = std::thread([this, hb_stub = std::move(hb_stub)]() {
                    spdlog::info("Heartbeat thread started (interval={}s)",
                                 cfg_.heartbeat_interval.count());
                    while (!stop_requested_.load(std::memory_order_acquire)) {
                        // Sleep in small increments for responsive shutdown
                        auto remaining = cfg_.heartbeat_interval;
                        while (remaining.count() > 0 &&
                               !stop_requested_.load(std::memory_order_acquire)) {
                            auto sleep_time = std::min(remaining, std::chrono::seconds{5});
                            std::this_thread::sleep_for(sleep_time);
                            remaining -= sleep_time;
                        }
                        if (stop_requested_.load(std::memory_order_acquire))
                            break;

                        // Build heartbeat with piggybacked metrics
                        grpc::ClientContext ctx;
                        pb::HeartbeatRequest req;
                        req.set_session_id(session_id_);
                        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                          std::chrono::system_clock::now().time_since_epoch())
                                          .count();
                        req.mutable_sent_at()->set_millis_epoch(now_ms);

                        auto& tags = *req.mutable_status_tags();
                        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
                                          std::chrono::steady_clock::now() - start_time_)
                                          .count();
                        tags["yuzu.uptime_s"] = std::to_string(uptime);
                        tags["yuzu.commands_executed"] = std::to_string(static_cast<int64_t>(
                            metrics_.counter("yuzu_agent_commands_executed_total").value()));
                        tags["yuzu.plugins_loaded"] = std::to_string(plugins_.size());
                        tags["yuzu.os"] = kAgentOs;
                        tags["yuzu.arch"] = kAgentArch;
                        tags["yuzu.agent_version"] = std::string{yuzu::kFullVersionString};
                        tags["yuzu.healthy"] = "1";

                        pb::HeartbeatResponse resp;
                        auto status = hb_stub->Heartbeat(&ctx, req, &resp);
                        if (!status.ok()) {
                            spdlog::warn("Heartbeat failed: {}", status.error_message());
                        } else {
                            spdlog::debug("Heartbeat acknowledged (uptime={}s)", uptime);
                        }
                    }
                    spdlog::info("Heartbeat thread stopped");
                });
            }

            // 5. Read commands from server and dispatch to plugins
            bool update_verified = false;
            pb::CommandRequest cmd;
            while (stream->Read(&cmd)) {
                if (stop_requested_.load(std::memory_order_acquire))
                    break;

                // Write health marker after first successful read (OTA rollback guard)
                if (!update_verified) {
                    update_verified = true;
                    auto marker = current_executable_path().parent_path() / ".yuzu-update-verified";
                    std::ofstream{marker} << "ok";
                    spdlog::debug("Wrote update verification marker: {}", marker.string());
                }

                spdlog::info("Received command: plugin={}, action={}, id={}", cmd.plugin(),
                             cmd.action(), cmd.command_id());

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
                    stream->Write(resp, grpc::WriteOptions());
                    continue;
                }

                // Dispatch execute() via bounded thread pool.
                // chargen_start blocks until chargen_stop sets the atomic flag,
                // so concurrent dispatch is required.
                // Each task captures the shared_ptr to guarantee the stream
                // outlives all writers (fixes use-after-free risk from #66).
                bool submitted = thread_pool_->submit([this, target, cmd, stream]() {
                    // -- Stagger/delay: prevent thundering herd on large-fleet dispatch --
                    const int32_t stagger_s = cmd.stagger_seconds();
                    const int32_t delay_s = cmd.delay_seconds();
                    if (stagger_s > 0 || delay_s > 0) {
                        int32_t random_stagger = 0;
                        if (stagger_s > 0) {
                            std::random_device rd;
                            std::mt19937 gen(rd());
                            std::uniform_int_distribution<int32_t> dist(0, stagger_s);
                            random_stagger = dist(gen);
                        }
                        const int32_t total_delay = (delay_s > 0 ? delay_s : 0) + random_stagger;
                        spdlog::debug("Command {} stagger {}s + delay {}s = {}s",
                                      cmd.command_id(), random_stagger, delay_s, total_delay);

                        if (total_delay > 0) {
                            std::this_thread::sleep_for(std::chrono::seconds(total_delay));
                        }

                        // Check expiration after the delay — skip stale commands
                        if (cmd.has_expires_at() && cmd.expires_at().millis_epoch() > 0) {
                            auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count();
                            if (now_ms > cmd.expires_at().millis_epoch()) {
                                spdlog::warn("Command {} expired after stagger/delay (expired_at={}, now={})",
                                             cmd.command_id(), cmd.expires_at().millis_epoch(), now_ms);
                                pb::CommandResponse expired_resp;
                                expired_resp.set_command_id(cmd.command_id());
                                expired_resp.set_status(pb::CommandResponse::REJECTED);
                                expired_resp.set_output("command expired after stagger/delay");
                                auto epoch = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                 std::chrono::system_clock::now().time_since_epoch())
                                                 .count();
                                expired_resp.mutable_sent_at()->set_millis_epoch(epoch);

                                std::lock_guard lock(stream_write_mu_);
                                stream->Write(expired_resp, grpc::WriteOptions());
                                return;
                            }
                        }
                    }

                    metrics_
                        .counter("yuzu_agent_commands_executed_total", {{"plugin", cmd.plugin()}})
                        .increment();
                    CommandContextImpl ctx_impl{
                        .stream = stream,
                        .write_mu = &stream_write_mu_,
                        .command_id = cmd.command_id(),
                        .start_time = std::chrono::steady_clock::now(),
                    };
                    auto* raw_ctx = reinterpret_cast<YuzuCommandContext*>(&ctx_impl);

                    // Convert protobuf parameter map -> C ABI YuzuParam array
                    // Direct construction: single vector of YuzuParam pointing at proto map
                    // entries (no intermediate string copies — proto owns the data).
                    const auto& proto_params = cmd.parameters();
                    std::vector<YuzuParam> params;
                    params.reserve(proto_params.size());
                    for (const auto& [k, v] : proto_params) {
                        params.push_back(YuzuParam{k.c_str(), v.c_str()});
                    }

                    int rc = target->execute(raw_ctx, cmd.action().c_str(), params.data(),
                                             params.size());

                    // Flush any buffered output before sending timing/status
                    ctx_impl.flush_output();

                    auto end_time = std::chrono::steady_clock::now();
                    auto exec_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       end_time - ctx_impl.start_time)
                                       .count();

                    // Send timing metadata before the final status
                    {
                        pb::CommandResponse timing_resp;
                        timing_resp.set_command_id(cmd.command_id());
                        timing_resp.set_status(pb::CommandResponse::RUNNING);
                        timing_resp.set_output("__timing__|exec_ms=" + std::to_string(exec_ms));

                        std::lock_guard lock(stream_write_mu_);
                        stream->Write(timing_resp, grpc::WriteOptions());
                    }

                    // Send final status
                    {
                        pb::CommandResponse final_resp;
                        final_resp.set_command_id(cmd.command_id());
                        final_resp.set_status(rc == 0 ? pb::CommandResponse::SUCCESS
                                                      : pb::CommandResponse::FAILURE);
                        final_resp.set_exit_code(rc);

                        auto now_epoch = std::chrono::duration_cast<std::chrono::milliseconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count();
                        final_resp.mutable_sent_at()->set_millis_epoch(now_epoch);

                        std::lock_guard lock(stream_write_mu_);
                        stream->Write(final_resp, grpc::WriteOptions());
                    }

                    spdlog::info("Command {} finished (rc={}, exec={}ms)", cmd.command_id(), rc,
                                 exec_ms);
                });

                if (!submitted) {
                    spdlog::warn("Thread pool queue full — rejecting command {}", cmd.command_id());
                    pb::CommandResponse reject_resp;
                    reject_resp.set_command_id(cmd.command_id());
                    reject_resp.set_status(pb::CommandResponse::REJECTED);
                    reject_resp.set_output("agent overloaded: command queue full");
                    std::lock_guard lock(stream_write_mu_);
                    stream->Write(reject_resp, grpc::WriteOptions());
                }
            }

            subscribe_ctx_.store(nullptr, std::memory_order_release);

            // Shutdown plugins first - signals long-running commands (e.g. chargen)
            // to stop, so their exec threads can finish and release the stream.
            for (auto& handle : plugins_) {
                if (handle.descriptor()->shutdown) {
                    handle.descriptor()->shutdown(
                        reinterpret_cast<YuzuPluginContext*>(&plugin_ctx_));
                }
            }

            // Destroy thread pool BEFORE stream goes out of scope — this drains
            // the queue, waits for in-flight tasks, and joins all worker threads,
            // ensuring no task holds a dangling stream pointer.
            thread_pool_.reset();

            // Stop and join the OTA update thread
            if (updater_) {
                updater_->stop();
            }
            if (update_thread_.joinable()) {
                update_thread_.join();
            }

            // Stop and join the heartbeat thread
            if (heartbeat_thread_.joinable()) {
                heartbeat_thread_.join();
            }

            spdlog::info("Subscribe stream ended");
        }
    }

    void stop() noexcept override {
        stop_requested_.store(true, std::memory_order_release);
        if (updater_)
            updater_->stop();
        // Cancel the Subscribe stream to unblock the Read() call
        if (auto* ctx = subscribe_ctx_.load(std::memory_order_acquire)) {
            ctx->TryCancel();
        }
    }

    std::string_view agent_id() const noexcept override { return cfg_.agent_id; }

    std::vector<std::string> loaded_plugins() const override { return plugin_names_; }

private:
    Config cfg_;
    PluginContextImpl plugin_ctx_;
    // Per-plugin contexts: each plugin gets its own PluginContextImpl with the
    // correct plugin_name for KV storage namespacing. Stored as unique_ptrs so
    // pointers remain stable after map insertions.
    std::unordered_map<std::string, std::unique_ptr<PluginContextImpl>> per_plugin_ctx_;
    std::unique_ptr<KvStore> kv_store_;
    yuzu::MetricsRegistry metrics_;
    std::chrono::steady_clock::time_point start_time_;
    std::string session_id_;
    std::atomic<bool> stop_requested_{false};
    std::atomic<grpc::ClientContext*> subscribe_ctx_{nullptr};
    std::vector<PluginHandle> plugins_;
    std::vector<std::string> plugin_names_;
    std::mutex stream_write_mu_;
    std::unique_ptr<ThreadPool> thread_pool_;
    std::unique_ptr<Updater> updater_;
    std::thread update_thread_;
    std::thread heartbeat_thread_;
};

// Factory

std::unique_ptr<Agent> Agent::create(Config config) {
    return std::make_unique<AgentImpl>(std::move(config));
}

} // namespace yuzu::agent
