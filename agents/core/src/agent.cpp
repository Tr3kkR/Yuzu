#ifdef _WIN32
#include <io.h>
#pragma section(".CRT$XCB", read)
[[maybe_unused]] static void __cdecl diag_dll_static_init() {
    const char msg[] = "[DIAG] DLL static-init starting (before proto registration)\n";
    _write(2, msg, sizeof(msg) - 1);
}
__declspec(allocate(".CRT$XCB"))
    [[maybe_unused]] static void(__cdecl* p_dll_diag)() = diag_dll_static_init;
#endif

#include <yuzu/agent/agent.hpp>
#include <yuzu/agent/cert_discovery.hpp>
#include <yuzu/agent/cert_store.hpp>
#include <yuzu/agent/cloud_identity.hpp>
#include <yuzu/agent/guardian_engine.hpp>
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

// Local-only helper, exposed for unit testing.
#include "plugin_config_sync.hpp"

#ifdef _WIN32
#include <winsock2.h> // gethostname (must precede windows.h)
#include <windows.h>  // GetModuleHandleW, GetProcAddress
#include <winternl.h> // RTL_OSVERSIONINFOW (for RtlGetVersion)
#else
#include <sys/utsname.h> // uname (OS version)
#include <unistd.h>      // gethostname
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
#include <unordered_set>
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

// Returns the running OS version string (e.g. "10.0.26200" on Windows,
// "5.15.0-89-generic" on Linux, "23.4.0" on macOS). Empty string on
// failure. Used at registration time so the server's AgentInfo.platform
// can identify which build of which OS the agent is running on.
//
// On Windows we use RtlGetVersion via NTDLL rather than the deprecated
// GetVersionEx (which is subject to manifest-based version spoofing
// since Windows 8.1) — RtlGetVersion always reports the true OS version.
// On Unix we use the standard uname syscall.
[[nodiscard]] std::string get_os_version() {
#ifdef _WIN32
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return {};
    using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    auto fn = reinterpret_cast<RtlGetVersionFn>(::GetProcAddress(ntdll, "RtlGetVersion"));
    if (!fn)
        return {};
    RTL_OSVERSIONINFOW v{};
    v.dwOSVersionInfoSize = sizeof(v);
    if (fn(&v) != 0)
        return {};
    return std::format("{}.{}.{}", v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber);
#else
    struct utsname u {};
    if (::uname(&u) != 0)
        return {};
    return std::string{u.release};
#endif
}

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
    KvStore* kv_store{nullptr};             // non-owning; lifetime managed by AgentImpl
    TriggerEngine* trigger_engine{nullptr}; // non-owning; lifetime managed by AgentImpl
    std::string plugin_name;                // set per-plugin during init/execute for KV namespacing
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
template <typename F> ScopeExit(F) -> ScopeExit<F>;

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
        metrics_.describe("yuzu_agent_plugin_rejected_total",
                          "Plugins rejected at load time, labeled by reason", "counter");
    }

    void run() override {
        spdlog::info("Yuzu agent starting (id={})", cfg_.agent_id);

        // 1. Load plugins (with optional allowlist + code-signing verification)
        auto allowlist = load_plugin_allowlist(cfg_.plugin_allowlist);
        PluginSigningPolicy signing{cfg_.plugin_trust_bundle, cfg_.plugin_require_signature};
        // Fail-closed guard against silent fail-open. If the operator passed
        // --plugin-require-signature but forgot --plugin-trust-bundle (or
        // passed an empty path), PluginSigningPolicy::enabled() would be
        // false and the entire signing block in PluginLoader::scan() would
        // be skipped — so unsigned plugins would silently load while the
        // operator believed enforcement was active. Refuse to start.
        // Governance hardening round 1 (UP-7).
        if (cfg_.plugin_require_signature && !signing.enabled()) {
            spdlog::critical("--plugin-require-signature is set but --plugin-trust-bundle "
                             "is empty. Refusing to start: this combination would silently "
                             "fail-open (every plugin would load unverified).");
            std::exit(EXIT_FAILURE);
        }
        auto scan = PluginLoader::scan(cfg_.plugin_dir, allowlist, signing);

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

        // 1c. Initialise the Guardian engine (Phase 1 startup, pre-network).
        // The engine persists rules into the KV store and answers __guard__
        // dispatches once the Subscribe stream is open. Construction is
        // safe even when KV failed to open (it degrades to in-memory only).
        guardian_ = std::make_unique<GuardianEngine>(kv_store_.get(), cfg_.agent_id);
        if (auto r = guardian_->start_local(); !r) {
            spdlog::warn("Guardian engine start_local failed: {} — continuing without Guardian",
                         r.error());
        }

        // Record start time for uptime calculation
        auto start_epoch = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
        plugin_ctx_.config["agent.start_time_epoch"] = std::to_string(start_epoch);

        // Module roster — every plugin file in plugin_dir is recorded here,
        // both successful loads and load failures (signature_invalid,
        // reserved_name, etc.). The post-load sync_master_config_to_plugins
        // call below makes these `agent.modules.N.*` entries readable by
        // every successfully-loaded plugin via get_config(). Operators rely
        // on this for diagnostics (status_plugin's `do_modules` action), but
        // it does mean every loaded plugin can read the names + reasons of
        // plugins that were rejected. This is acceptable today (single trust
        // domain on the agent host) but is worth revisiting if a future
        // change introduces sandboxed / lower-trust plugin contexts.
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
            // #453 + #80: categorise rejections so operators can alert on
            // reserved-name attempts, signature failures, and generic
            // load failures separately. Order is most-specific first;
            // fall through to "load_failed" for everything else.
            std::string_view reason = "load_failed";
            if (err.reason.starts_with(yuzu::agent::kReservedNameReason)) {
                reason = "reserved_name";
            } else if (err.reason.starts_with(yuzu::agent::kSignatureMissingReason)) {
                reason = "signature_missing";
            } else if (err.reason.starts_with(yuzu::agent::kSignatureUntrustedReason)) {
                reason = "signature_untrusted_chain";
            } else if (err.reason.starts_with(yuzu::agent::kSignatureInvalidReason)) {
                reason = "signature_invalid";
            }
            metrics_.counter("yuzu_agent_plugin_rejected_total", {{"reason", std::string{reason}}})
                .increment();
        }

        for (auto& handle : candidates) {
            const auto* descriptor = handle.descriptor();
            // Create a per-plugin context with the correct plugin_name for KV namespacing.
            // Each plugin gets its own PluginContextImpl so concurrent executions
            // don't clobber each other's KV namespace (was a data corruption bug).
            auto pctx = std::make_unique<PluginContextImpl>();
            pctx->config = plugin_ctx_.config;
            pctx->kv_store = plugin_ctx_.kv_store;
            pctx->trigger_engine = plugin_ctx_.trigger_engine;
            pctx->plugin_name = descriptor->name;

            auto* raw_pctx = reinterpret_cast<YuzuPluginContext*>(pctx.get());
            if (handle.descriptor()->init) {
                int rc = handle.descriptor()->init(raw_pctx);
                if (rc != 0) {
                    spdlog::warn("Plugin {} init returned {}, skipping", handle.descriptor()->name,
                                 rc);
                    record_module(descriptor->name, descriptor->version,
                                  std::format("{} (init rc={})", descriptor->description, rc),
                                  "init_failed");
                    continue;
                }
            }
            per_plugin_ctx_[descriptor->name] = std::move(pctx);
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

        // Per-plugin contexts were snapshotted from plugin_ctx_.config during
        // the load loop above, so they are missing every key written after
        // their own snapshot point: agent.plugins.count, agent.modules.count,
        // the agent.plugins.N.* roster, and agent.modules.N.* entries for
        // any module recorded after the plugin's own init. Re-sync the master
        // map into every per-plugin context so calls like agent_actions:info
        // see the complete post-load state instead of "(not set)".
        //
        // Plugins whose init() is *itself* reading these keys cannot observe
        // them — init runs before this sync. agent_actions::info is dispatched
        // post-init via execute(), so the fix is correct for that consumer.
        // Runtime keys written AFTER this point (agent.session_id at register
        // time, agent.reconnect_count, agent.latency_ms, agent.grpc_channel_state,
        // agent.connected_since) do NOT propagate — see CONS-B1 follow-up.
        //
        // Implementation extracted to plugin_config_sync.hpp so it can be
        // unit-tested without exposing PluginContextImpl outside this TU.
        detail::sync_master_config_to_plugins(plugin_ctx_.config, per_plugin_ctx_);

        metrics_.gauge("yuzu_agent_plugins_loaded").set(static_cast<double>(plugins_.size()));
        start_time_ = std::chrono::steady_clock::now();
        spdlog::info("Loaded {} plugin(s)", plugins_.size());

        // Initialize bounded thread pool for command dispatch
        thread_pool_ = std::make_unique<ThreadPool>(std::thread::hardware_concurrency());

        // Scope guard: shutdown plugins and destroy thread pool on any exit path
        ScopeExit cleanup{[this]() {
            for (auto& handle : plugins_) {
                if (handle.descriptor()->shutdown) {
                    // Use per-plugin context if available, fall back to shared
                    auto it = per_plugin_ctx_.find(handle.descriptor()->name);
                    auto* ctx_ptr = (it != per_plugin_ctx_.end())
                                        ? reinterpret_cast<YuzuPluginContext*>(it->second.get())
                                        : reinterpret_cast<YuzuPluginContext*>(&plugin_ctx_);
                    handle.descriptor()->shutdown(ctx_ptr);
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

        // 3. Register with server — with reconnect loop
        int reconnect_count = 0;
        constexpr int kMaxReconnectDelaySecs = 300; // 5 minutes max backoff

        while (!stop_requested_.load(std::memory_order_acquire)) {
            if (reconnect_count > 0) {
                // Exponential backoff: 2^n seconds, capped at 5 minutes
                int delay = std::min(1 << std::min(reconnect_count, 8), kMaxReconnectDelaySecs);
                spdlog::info("Reconnecting in {}s (attempt #{})", delay, reconnect_count);
                plugin_ctx_.config["agent.reconnect_count"] = std::to_string(reconnect_count);
                for (int i = 0; i < delay && !stop_requested_.load(std::memory_order_acquire); ++i)
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                if (stop_requested_.load(std::memory_order_acquire))
                    break;
            }

            {
                grpc::ClientContext ctx;
                pb::RegisterRequest req;
                auto* info = req.mutable_info();
                info->set_agent_id(cfg_.agent_id);
                info->set_agent_version(std::string{yuzu::kFullVersionString});

                // Populate Platform sub-message so the server (and the dashboard
                // scope panel via /fragments/scope-list) can identify which OS
                // and architecture this agent is running on. kAgentOs and
                // kAgentArch are compile-time constants pinned per build target;
                // get_os_version() probes the running kernel for the version
                // string. The OTA updater also reads platform.os/arch to find
                // matching binaries, so this fix unblocks OTA selection too.
                {
                    auto* platform = info->mutable_platform();
                    platform->set_os(kAgentOs);
                    platform->set_arch(kAgentArch);
                    platform->set_version(get_os_version());
                }

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
                    spdlog::info("Including {} cloud attestation in registration",
                                 cloud_id.provider);
                }

                pb::RegisterResponse resp;
                auto register_start = std::chrono::steady_clock::now();
                auto status = stub->Register(&ctx, req, &resp);
                if (!status.ok()) {
                    spdlog::error("Failed to register with server: {}", status.error_message());
                    ++reconnect_count;
                    continue; // Retry registration
                }
                if (!resp.accepted()) {
                    if (resp.reject_reason().find("pending") != std::string::npos) {
                        spdlog::warn("Registration pending admin approval — retrying");
                        ++reconnect_count;
                        continue; // Retry until approved
                    }
                    spdlog::error("Server permanently rejected registration: {}",
                                  resp.reject_reason());
                    return; // Hard rejection — no retry
                }

                auto enrollment_status = resp.enrollment_status();
                if (enrollment_status == "pending") {
                    spdlog::warn("Registration pending admin approval - retrying in backoff");
                    ++reconnect_count;
                    continue; // Retry until approved
                }

                reconnect_count = 0; // Registration succeeded — reset backoff

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

                // Mark Guardian as network-connected. PR 4 will use this hook to
                // drain a buffered-events queue back over the command stream.
                if (guardian_)
                    guardian_->sync_with_server();
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
                    if (!stop_requested_.load(std::memory_order_acquire)) {
                        ++reconnect_count;
                        spdlog::warn("Subscribe failed — will attempt reconnect");
                        continue;
                    }
                    break;
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
                    heartbeat_stop_.store(false, std::memory_order_release);
                    auto hb_stub = pb::AgentService::NewStub(channel);
                    heartbeat_thread_ = std::thread([this, hb_stub = std::move(hb_stub)]() {
                        spdlog::info("Heartbeat thread started (interval={}s)",
                                     cfg_.heartbeat_interval.count());
                        auto should_stop = [this]() {
                            return stop_requested_.load(std::memory_order_acquire) ||
                                   heartbeat_stop_.load(std::memory_order_acquire);
                        };
                        while (!should_stop()) {
                            // Sleep in small increments for responsive shutdown
                            auto remaining = cfg_.heartbeat_interval;
                            while (remaining.count() > 0 && !should_stop()) {
                                auto sleep_time = std::min(remaining, std::chrono::seconds{5});
                                std::this_thread::sleep_for(sleep_time);
                                remaining -= sleep_time;
                            }
                            if (should_stop())
                                break;

                            // Build heartbeat with piggybacked metrics
                            grpc::ClientContext ctx;
                            heartbeat_ctx_.store(&ctx, std::memory_order_release);
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
                            heartbeat_ctx_.store(nullptr, std::memory_order_release);
                            if (!status.ok()) {
                                spdlog::warn("Heartbeat failed: {}", status.error_message());
                            } else {
                                spdlog::debug("Heartbeat acknowledged (uptime={}s)", uptime);
                            }
                        }
                        heartbeat_ctx_.store(nullptr, std::memory_order_release);
                        spdlog::info("Heartbeat thread stopped");
                    });
                }

                // 5. Read commands from server and dispatch to plugins
                dedup_current_.clear(); // Fresh dedup sets per connection
                dedup_previous_.clear();
                bool update_verified = false;
                pb::CommandRequest cmd;
                while (stream->Read(&cmd)) {
                    if (stop_requested_.load(std::memory_order_acquire))
                        break;

                    // Command replay protection: reject duplicate command_ids
                    if (cmd.command_id().empty()) {
                        spdlog::warn("Received command with empty command_id — replay "
                                     "protection cannot apply");
                    } else {
                        if (dedup_current_.count(cmd.command_id()) ||
                            dedup_previous_.count(cmd.command_id())) {
                            spdlog::warn("Replay detected: duplicate command_id={} — rejecting",
                                         cmd.command_id());
                            pb::CommandResponse replay_resp;
                            replay_resp.set_command_id(cmd.command_id());
                            replay_resp.set_status(pb::CommandResponse::REJECTED);
                            replay_resp.set_output("command replay rejected: duplicate command_id");
                            std::lock_guard lock(stream_write_mu_);
                            stream->Write(replay_resp, grpc::WriteOptions());
                            continue;
                        }
                        // Double-buffer rotation: when current fills, discard previous,
                        // swap current → previous, start fresh current.
                        if (dedup_current_.size() >= kMaxDedupEntries) {
                            spdlog::debug("Dedup buffer rotation ({} entries)", kMaxDedupEntries);
                            dedup_previous_ = std::move(dedup_current_);
                            dedup_current_.clear();
                        }
                        dedup_current_.insert(cmd.command_id());
                    }

                    // Write health marker after first successful read (OTA rollback guard)
                    if (!update_verified) {
                        update_verified = true;
                        auto marker =
                            current_executable_path().parent_path() / ".yuzu-update-verified";
                        std::ofstream{marker} << "ok";
                        spdlog::debug("Wrote update verification marker: {}", marker.string());
                    }

                    spdlog::info("Received command: plugin={}, action={}, id={}", cmd.plugin(),
                                 cmd.action(), cmd.command_id());

                    // Reserved-name dispatch — must run before the plugin match
                    // loop so a third-party plugin cannot shadow Guardian (the
                    // load-time check in plugin_loader.cpp also rejects reserved
                    // names, but defence-in-depth keeps both halves explicit).
                    // See docs/yuzu-guardian-design-v1.1.md §7.2.
                    if (cmd.plugin() == "__guard__") {
                        pb::CommandResponse resp;
                        resp.set_command_id(cmd.command_id());
                        auto epoch_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                            std::chrono::system_clock::now().time_since_epoch())
                                            .count();
                        resp.mutable_sent_at()->set_millis_epoch(epoch_ms);
                        if (!guardian_) {
                            resp.set_status(pb::CommandResponse::FAILURE);
                            resp.set_exit_code(1);
                            resp.set_output("guardian engine not initialised");
                        } else {
                            auto dr = guardian_->dispatch(cmd);
                            resp.set_status(dr.exit_code == 0 ? pb::CommandResponse::SUCCESS
                                                              : pb::CommandResponse::FAILURE);
                            resp.set_exit_code(dr.exit_code);
                            resp.set_output(std::move(dr.output));
                        }
                        metrics_
                            .counter("yuzu_agent_commands_executed_total",
                                     {{"plugin", "__guard__"}})
                            .increment();
                        std::lock_guard lock(stream_write_mu_);
                        stream->Write(resp, grpc::WriteOptions());
                        continue;
                    }

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
                        const int32_t stagger_s =
                            std::min(cmd.stagger_seconds(), int32_t{300}); // cap 5 min
                        const int32_t delay_s =
                            std::min(cmd.delay_seconds(), int32_t{300}); // cap 5 min
                        if (stagger_s > 0 || delay_s > 0) {
                            int32_t random_stagger = 0;
                            if (stagger_s > 0) {
                                std::random_device rd;
                                std::mt19937 gen(rd());
                                std::uniform_int_distribution<int32_t> dist(0, stagger_s);
                                random_stagger = dist(gen);
                            }
                            const int32_t total_delay = std::min(
                                (delay_s > 0 ? delay_s : 0) + random_stagger, int32_t{600});
                            spdlog::debug("Command {} stagger {}s + delay {}s = {}s",
                                          cmd.command_id(), random_stagger, delay_s, total_delay);

                            if (total_delay > 0) {
                                std::this_thread::sleep_for(std::chrono::seconds(total_delay));
                            }

                            // Check expiration after the delay — skip stale commands
                            if (cmd.has_expires_at() && cmd.expires_at().millis_epoch() > 0) {
                                auto now_ms =
                                    std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count();
                                if (now_ms > cmd.expires_at().millis_epoch()) {
                                    spdlog::warn("Command {} expired after stagger/delay "
                                                 "(expired_at={}, now={})",
                                                 cmd.command_id(), cmd.expires_at().millis_epoch(),
                                                 now_ms);
                                    pb::CommandResponse expired_resp;
                                    expired_resp.set_command_id(cmd.command_id());
                                    expired_resp.set_status(pb::CommandResponse::REJECTED);
                                    expired_resp.set_output("command expired after stagger/delay");
                                    auto epoch =
                                        std::chrono::duration_cast<std::chrono::milliseconds>(
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
                            .counter("yuzu_agent_commands_executed_total",
                                     {{"plugin", cmd.plugin()}})
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

                            auto now_epoch =
                                std::chrono::duration_cast<std::chrono::milliseconds>(
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
                        spdlog::warn("Thread pool queue full — rejecting command {}",
                                     cmd.command_id());
                        pb::CommandResponse reject_resp;
                        reject_resp.set_command_id(cmd.command_id());
                        reject_resp.set_status(pb::CommandResponse::REJECTED);
                        reject_resp.set_output("agent overloaded: command queue full");
                        std::lock_guard lock(stream_write_mu_);
                        stream->Write(reject_resp, grpc::WriteOptions());
                    }
                }

                subscribe_ctx_.store(nullptr, std::memory_order_release);

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

                // Signal heartbeat thread to exit and cancel any in-flight RPC
                heartbeat_stop_.store(true, std::memory_order_release);
                if (auto* hctx = heartbeat_ctx_.load(std::memory_order_acquire)) {
                    hctx->TryCancel();
                }
                if (heartbeat_thread_.joinable()) {
                    heartbeat_thread_.join();
                }

                // Only shutdown plugins on final exit — keep them loaded for reconnect
                if (stop_requested_.load(std::memory_order_acquire)) {
                    for (auto& handle : plugins_) {
                        if (handle.descriptor()->shutdown) {
                            auto it = per_plugin_ctx_.find(handle.descriptor()->name);
                            auto* ctx_ptr =
                                (it != per_plugin_ctx_.end())
                                    ? reinterpret_cast<YuzuPluginContext*>(it->second.get())
                                    : reinterpret_cast<YuzuPluginContext*>(&plugin_ctx_);
                            handle.descriptor()->shutdown(ctx_ptr);
                        }
                    }
                    plugins_.clear(); // Prevent ScopeExit from calling shutdown again
                }

                spdlog::info("Subscribe stream ended");

                // Re-create thread pool for next connection cycle
                thread_pool_ = std::make_unique<ThreadPool>(std::thread::hardware_concurrency());

                if (!stop_requested_.load(std::memory_order_acquire)) {
                    ++reconnect_count;
                    metrics_.counter("yuzu_agent_reconnections_total").increment();
                    spdlog::warn("Connection lost — will attempt reconnect");
                    continue; // Back to reconnect loop
                }
            }
            break; // stop_requested
        }          // end while (reconnect loop)
    }

    void stop() noexcept override {
        stop_requested_.store(true, std::memory_order_release);
        heartbeat_stop_.store(true, std::memory_order_release);
        if (guardian_)
            guardian_->stop();
        if (updater_)
            updater_->stop();
        // Cancel the Subscribe stream to unblock the Read() call
        if (auto* ctx = subscribe_ctx_.load(std::memory_order_acquire)) {
            ctx->TryCancel();
        }
        // Cancel any in-flight heartbeat RPC to unblock the heartbeat thread
        if (auto* hctx = heartbeat_ctx_.load(std::memory_order_acquire)) {
            hctx->TryCancel();
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
    std::unique_ptr<GuardianEngine> guardian_;
    yuzu::MetricsRegistry metrics_;
    std::chrono::steady_clock::time_point start_time_;
    std::string session_id_;
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> heartbeat_stop_{false};
    std::atomic<grpc::ClientContext*> subscribe_ctx_{nullptr};
    std::atomic<grpc::ClientContext*> heartbeat_ctx_{nullptr};
    std::vector<PluginHandle> plugins_;
    std::vector<std::string> plugin_names_;
    std::mutex stream_write_mu_;
    std::unique_ptr<ThreadPool> thread_pool_;
    std::unique_ptr<Updater> updater_;
    std::thread update_thread_;
    std::thread heartbeat_thread_;

    // M8: Command replay protection — double-buffer dedup of command IDs.
    // Two sets: "current" and "previous". When current fills, previous is
    // discarded, current becomes previous, and a fresh current starts.
    // Both sets are checked for duplicates, so recently-seen IDs are always
    // protected. Cleared on each reconnect.
    static constexpr size_t kMaxDedupEntries = 5000;
    std::unordered_set<std::string> dedup_current_;
    std::unordered_set<std::string> dedup_previous_;
};

// Factory

std::unique_ptr<Agent> Agent::create(Config config) {
    return std::make_unique<AgentImpl>(std::move(config));
}

} // namespace yuzu::agent
