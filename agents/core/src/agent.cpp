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
#include <yuzu/agent/agent_csr.hpp>
#include <yuzu/agent/cert_discovery.hpp>
#include <yuzu/agent/cert_store.hpp>
#include <yuzu/agent/cloud_identity.hpp>
#include <yuzu/agent/dex_observer.hpp>
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
#include "guaranteed_state.pb.h"

// Local-only helper, exposed for unit testing.
#include "plugin_config_sync.hpp"
#include "local_dispatcher.hpp"
#include "dex_event.hpp" // SignalObservation -> GuaranteedStateEvent mapping (proto-aware)
#include "dex_linux_proc.hpp" // A4 Linux heartbeat perf reads (parse_proc_stat / parse_commit_pct)
#include "dex_perf_breach.hpp" // A4: heartbeat device-utilization tags (perf counter reads)
#include "net_quality_sampler.hpp" // slice 4a: heartbeat network-quality facts

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
#include <iterator>
#include <optional>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
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
namespace gpb = ::yuzu::guardian::v1;
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

    // PR 10 / UAT 2026-05-12 — Push-based snapshot ingestion.
    //
    // When `capture` is non-null, plugin output is accumulated into
    // this string (newline-joined between calls) instead of being
    // streamed back to the server. The snapshot-pump thread uses this
    // path to invoke `tar.fleet_snapshot` locally and harvest the JSON
    // payload without touching the gRPC channel. `stream` and
    // `write_mu` are nullptr/unused in that mode; `flush_output_locked`
    // short-circuits.
    std::string* capture{nullptr};

    // PR 10 hardening — capture-mode upper bound (UP-9). The pump
    // ships the captured string in the next HeartbeatRequest; gRPC's
    // default 4 MiB inbound cap is the hard server-side ceiling, but
    // we want a tighter agent-side cap so an oversized snapshot is
    // *truncated with a marker* rather than retained-and-failing. The
    // 2 MiB value matches `FleetTopologyStore::kPushedSnapshotMaxBytes`
    // on the server (in-tree convention: same constant in two places
    // until typed proto lands and renders both moot).
    static constexpr std::size_t kCaptureMaxBytes = 2ull * 1024 * 1024;
    bool capture_truncated{false};

    void append_output(const char* text) {
        std::lock_guard lock(buf_mu);
        size_t len = std::strlen(text);
        if (capture) {
            // Capture mode: append directly to the operator-owned buffer
            // with a newline separator between successive writes, matching
            // the wire format the plugin would have emitted if streamed.
            if (capture_truncated)
                return;
            std::size_t prospective = capture->size() + (capture->empty() ? 0 : 1) + len;
            if (prospective > kCaptureMaxBytes) {
                // Truncate with a sentinel suffix so the server-side
                // parser cleanly rejects the payload as malformed JSON
                // rather than ingesting a half-finished structure. The
                // pump emits a WARN; next pump cycle overwrites.
                capture->append("\n/* TRUNCATED — exceeded kCaptureMaxBytes */");
                capture_truncated = true;
                return;
            }
            if (!capture->empty())
                capture->push_back('\n');
            capture->append(text, len);
            return;
        }
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
        // Capture mode keeps everything in `capture` already; nothing to
        // flush over the wire. Skipping this guard would call into
        // `stream->Write` on a null stream and crash the pump thread.
        if (capture)
            return;
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

// #1001 / arch-S3 — shim used by LocalDispatcher to invoke a plugin
// descriptor in-process with output captured into a caller-owned buffer.
// Kept here (rather than in local_dispatcher.cpp) because CommandContextImpl
// carries gRPC-typed streaming fields that would force local_dispatcher.cpp
// to pull in grpcpp; this shim is the narrow boundary that contains that
// coupling.
int dispatch_with_capture(const YuzuPluginDescriptor* descriptor, const char* action,
                          const YuzuParam* params, std::size_t param_count,
                          std::string* capture_out, bool* truncated_out, std::size_t capture_cap) {
    CommandContextImpl ctx_impl{};
    ctx_impl.command_id = "__local_dispatch__";
    ctx_impl.start_time = std::chrono::steady_clock::now();
    ctx_impl.capture = capture_out;
    // CommandContextImpl currently bakes the cap into its append_output
    // (kCaptureMaxBytes constant). LocalDispatcher::kCaptureMaxBytes
    // tracks the same value so the externally-visible policy lives in
    // one place; the static_assert below catches divergence at compile
    // time if either side drifts.
    static_assert(CommandContextImpl::kCaptureMaxBytes ==
                  yuzu::agent::LocalDispatcher::kCaptureMaxBytes);
    (void)capture_cap;

    auto* raw_ctx = reinterpret_cast<YuzuCommandContext*>(&ctx_impl);
    int rc = descriptor->execute(raw_ctx, action, params, param_count);
    ctx_impl.flush_output(); // no-op in capture mode
    if (truncated_out)
        *truncated_out = ctx_impl.capture_truncated;
    return rc;
}

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

YUZU_EXPORT int yuzu_register_trigger(YuzuPluginContext* ctx, const char* trigger_id,
                                      const char* trigger_type, const char* config_json) {
    if (!ctx || !trigger_id || !trigger_type || !config_json)
        return -1;
    auto* impl = reinterpret_cast<PluginContextImpl*>(ctx);
    if (!impl->trigger_engine) {
        // The agent did not wire a TriggerEngine into this context. Without
        // it the registration cannot take effect — fail loudly rather than
        // returning success and silently dropping the trigger (the old
        // stub's bug — it cost the whole interval-trigger feature).
        spdlog::error("yuzu_register_trigger('{}'): no TriggerEngine in plugin context",
                      trigger_id);
        return -2;
    }
    // No exception may cross this C ABI boundary -- doing so is UB. Catch
    // everything (parse_trigger_config is exception-safe, but
    // register_trigger does map/vector insertion that can throw bad_alloc).
    try {
        auto cfg = yuzu::agent::parse_trigger_config(trigger_id, trigger_type, config_json);
        if (!cfg) {
            // parse_trigger_config already logged the specific reason.
            return -3;
        }
        impl->trigger_engine->register_trigger(std::move(*cfg));
        return 0;
    } catch (const std::exception& e) {
        spdlog::error("yuzu_register_trigger('{}'): threw: {}", trigger_id, e.what());
        return -4;
    } catch (...) {
        spdlog::error("yuzu_register_trigger('{}'): threw non-std exception", trigger_id);
        return -4;
    }
}

YUZU_EXPORT int yuzu_unregister_trigger(YuzuPluginContext* ctx, const char* trigger_id) {
    if (!ctx || !trigger_id)
        return -1;
    auto* impl = reinterpret_cast<PluginContextImpl*>(ctx);
    if (!impl->trigger_engine)
        return -2;
    // No exception may cross this C ABI boundary.
    try {
        impl->trigger_engine->unregister_trigger(trigger_id);
        return 0;
    } catch (const std::exception& e) {
        spdlog::error("yuzu_unregister_trigger('{}'): threw: {}", trigger_id, e.what());
        return -4;
    } catch (...) {
        spdlog::error("yuzu_unregister_trigger('{}'): threw non-std exception", trigger_id);
        return -4;
    }
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
        metrics_.describe("yuzu_agent_dex_observer_armed",
                          "1 if the Guardian DEX signal observer is armed AND all its channel "
                          "subscriptions are live, else 0. Tracks runtime health: a runtime "
                          "EvtSubscribe error on any channel (EventLog restart / channel ACL "
                          "change) flips it to 0 via the observer error callback. NOT whether the "
                          "underlying reporters are enabled (a WER-disabled host stays armed=1 yet "
                          "emits no crash events). Surfaced fleet-wide via the heartbeat rollup "
                          "yuzu_fleet_agents_dex_observer_disarmed (the agent has no /metrics "
                          "endpoint).",
                          "gauge");
        // PKI PR3 (gov UP-9 / enterprise): make a stuck/failed per-agent mTLS
        // provisioning observable to fleet alerting, not just the agent log.
        metrics_.describe("yuzu_agent_cert_provision_failed_total",
                          "Per-agent mTLS provisioning failures, labeled by reason "
                          "(persist_failed|no_cert_issued)", "counter");
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

        // Wire the trigger engine into the master plugin context BEFORE the
        // per-plugin contexts are snapshotted from it (the load loop copies
        // plugin_ctx_.trigger_engine into each pctx). Plugins call
        // ctx.register_trigger() inside their own init(), which routes
        // through yuzu_register_trigger -> pctx->trigger_engine; if this
        // pointer is still null at init time, every registration is dropped.
        plugin_ctx_.trigger_engine = &trigger_engine_;

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

        // 1c-bis. Fleet-wide DEX signal observer (Guardian DEX, multi-signal).
        // RULELESS observations — records every catalogued reliability signal
        // (crash, hang, service failure, bugcheck, boot duration, …; see
        // dex_signal_catalog.cpp), independent of any rule. Windows/macOS/Linux each
        // have a real observer; no-op only on a platform without one.
        // Armed pre-network; emit_guardian_event() self-guards on the Subscribe
        // stream being up, so signals before first connect are dropped (like
        // guard events pre-sink; durable buffering is A3).
        // --dex-disable / YUZU_AGENT_DEX_DISABLE is a deploy-time opt-out: when set,
        // the observer never arms and NO DEX signal telemetry is collected.
        dex_observer_ = make_dex_observer();
        // Runtime health flag — the single source of truth for the heartbeat arm tag.
        // A shared_ptr<atomic> (NOT `this`) so the observer's error callback, which fires
        // on an OS threadpool thread and may outlive this agent, can flip it to false
        // without a use-after-free. A runtime EvtSubscribeActionError on ANY channel
        // (EventLog restart / channel ACL change → that channel goes deaf after a
        // successful start) flips it, so the next heartbeat reports armed=0 and the
        // fleet `disarmed` gauge rises — the arm signal tracks runtime health, not just
        // the initial arm (UP-1).
        // Seeded OPTIMISTICALLY true: the error callback may fire DURING start() (once
        // EvtSubscribe arms, before start() returns), so we must NOT blind-store the
        // start() result afterwards — that would clobber a false the callback wrote in
        // that window. The disable / not-armed branches clear it explicitly instead.
        dex_health_ = std::make_shared<std::atomic<bool>>(true);
        if (cfg_.dex_disable) {
            dex_health_->store(false, std::memory_order_relaxed);
            spdlog::info(
                "dex_observer: disabled by --dex-disable — no DEX signal telemetry collected");
        } else if (dex_observer_->start([this](const SignalObservation& obs) {
                       const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                               std::chrono::system_clock::now().time_since_epoch())
                                               .count();
                       const auto seq = dex_seq_.fetch_add(1, std::memory_order_relaxed);
                       // Include agent_id: the at-least-once event_id is a GLOBAL primary key
                       // server-side, so two agents observing in the same ms (e.g. a bad
                       // fleet-wide deploy) would otherwise mint identical ids and all but one
                       // would be dropped at ingest — losing signals exactly when they matter.
                       const std::string event_id = std::string(kObservationRuleSentinel) + "-" +
                                                     cfg_.agent_id + "-" + std::to_string(now_ms) +
                                                     "-" + std::to_string(seq);
                       // dex_seq_ (incremented above) doubles as the per-agent observed-signal
                       // total surfaced in the heartbeat → fleet rollup; no separate counter.
                       emit_guardian_event(signal_observation_to_event(obs, event_id));
                   },
                   [h = dex_health_] { h->store(false, std::memory_order_relaxed); })) {
            // Armed — leave dex_health_ as-is: true, or false if the error callback
            // already fired during start(). Do NOT blind-store — see the seed comment.
        } else {
            dex_health_->store(false, std::memory_order_relaxed);
            spdlog::debug("dex_observer: not armed on this platform — DEX signals disabled");
        }
        // Arm gauge: seeded from dex_health_ (so a during-start error is reflected) and
        // re-synced from it at each heartbeat, so it tracks runtime subscription health,
        // not just the initial arm (UP-1).
        metrics_.gauge("yuzu_agent_dex_observer_armed")
            .set(dex_health_->load(std::memory_order_relaxed) ? 1.0 : 0.0);

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
            } else if (err.reason.starts_with(yuzu::agent::kInvalidNameReason)) {
                // #822: a plugin declared a malformed name (empty, over-length,
                // or outside [A-Za-z0-9_]) — distinct from a reserved-name
                // attempt so operators can alert on crafted-name loads.
                reason = "invalid_name";
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
            // #1420 / #1434 — quiesce and join the Run()-spawned worker threads
            // (snapshot pump, heartbeat, OTA updater) FIRST, before any plugin
            // teardown. The snapshot pump dispatches `tar.fleet_snapshot` into
            // the TAR plugin through a borrowed descriptor, so it must not
            // outlive the plugins; and leaving any of these `this`-capturing
            // threads joinable on an early `return` out of Run() (the hard
            // registration rejection and the PKI persist/rebuild bail-outs)
            // aborts the process via std::terminate. This guard runs on EVERY
            // Run() exit — early returns and exceptions included — so it is the
            // universal backstop. The reconnect-loop final teardown repeats the
            // pump join to order it ahead of plugins_.clear() on the normal path.
            quiesce_run_workers();
            // Stop the trigger engine FIRST — before plugins are torn down —
            // so an in-flight interval/file/service trigger can't dispatch
            // into a plugin that's mid-shutdown. stop() joins the worker
            // threads, so once it returns no further dispatch can occur.
            trigger_engine_.stop();
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

        // Wire trigger dispatch + start the engine. Plugins registered their
        // triggers during init() (above); the engine has been holding them
        // inert until now. The dispatch callback resolves the plugin by name
        // and runs the action in-process via LocalDispatcher — the same
        // mechanism the snapshot pump uses. start() spins up the interval /
        // file-watch / service-watch worker threads and fires any
        // AgentStartup triggers immediately.
        trigger_engine_.set_dispatch([this](const std::string& plugin, const std::string& action,
                                            const std::map<std::string, std::string>& params) {
            const YuzuPluginDescriptor* descriptor = nullptr;
            for (const auto& handle : plugins_) {
                if (std::string_view{handle.descriptor()->name} == plugin) {
                    descriptor = handle.descriptor();
                    break;
                }
            }
            if (!descriptor) {
                spdlog::warn("Trigger dispatch: plugin '{}' not loaded — skipping action '{}'",
                             plugin, action);
                return;
            }
            // Convert the param map into the C-ABI YuzuParam span. The map
            // outlives this synchronous run() call (it's owned by the
            // TriggerConfig snapshot in the engine's worker loop), so the
            // c_str() views stay valid for the duration of the dispatch.
            std::vector<YuzuParam> yparams;
            yparams.reserve(params.size());
            for (const auto& [k, v] : params)
                yparams.push_back(YuzuParam{k.c_str(), v.c_str()});

            LocalDispatcher dispatcher;
            auto result = dispatcher.run(descriptor, action, yparams);
            if (result.rc != 0) {
                spdlog::warn("Trigger dispatch: {}.{} returned rc={}", plugin, action, result.rc);
            }
        });
        trigger_engine_.start();

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

        // PKI PR3: per-agent mTLS provisioning. When TLS is on with a CA but the
        // operator supplied no explicit client cert / OS-store cert, the agent
        // obtains its OWN client leaf from the server — it generates a keypair +
        // CSR, sends the CSR in Register, persists the issued leaf (key 0600), and
        // reconnects presenting it. `pending_csr_pem` rides the next Register; a
        // non-empty `pending_key_pem` is the key awaiting its issued leaf.
        //
        // Renewal is evaluated here at startup (NeedsRenew at 2/3 life). A
        // continuously-running agent that never restarts renews on its next
        // process start / re-provision; a mid-run renewal thread is a follow-up.
        std::string pending_csr_pem;
        std::string pending_key_pem;
        // cpp-safety (#1239): the agent private key lives in `pending_key_pem`
        // from generation until it is persisted (then explicitly zeroed below).
        // A stop/return BETWEEN those points — e.g. shutdown mid-enrollment, or
        // any early return on the connect path — would otherwise leave the key
        // resident in process memory. This guard scrubs it on EVERY exit from
        // run() (the explicit zeroes below clear() too, so the guard then no-ops).
        struct KeyScrub {
            std::string& k;
            ~KeyScrub() { yuzu::secure_zero(k); }
        } pending_key_scrub{pending_key_pem};
        int csr_attempts = 0; // Hermes HIGH-2: bound enrolled-but-no-cert retries.
        const std::filesystem::path cert_dir =
            cfg_.cert_dir.empty() ? (cfg_.data_dir / "certs") : cfg_.cert_dir;
        // HIGH-1 (#1314): resolve the effective CA path BEFORE the provisioning gate.
        // The install-CA auto-discovery used to live only inside build_channel and
        // never wrote back cfg_.tls_ca_cert, so a no-`--ca-cert` agent connected over
        // server-authenticated TLS but `provisioning_eligible` stayed false → it sent
        // no CSR and never got its per-agent client leaf, with no error. Promoting the
        // discovered path into cfg_.tls_ca_cert here makes both the provisioning gate
        // and build_channel see the same effective CA (an explicit --ca-cert is left
        // untouched, so this is a no-op when one was given).
        if (cfg_.tls_enabled && cfg_.tls_ca_cert.empty()) {
            if (auto ca = discover_install_ca_path()) {
                cfg_.tls_ca_cert = *ca;
                spdlog::info("PKI: auto-discovered install CA at {} — using it as the trust "
                             "anchor and enabling per-agent enrollment",
                             cfg_.tls_ca_cert.string());
            }
        }
        const bool provisioning_eligible =
            cfg_.auto_provision_cert && cfg_.tls_enabled && !cfg_.tls_ca_cert.empty() &&
            cfg_.tls_client_cert.empty() && cfg_.cert_store.empty();
        if (provisioning_eligible) {
            const auto state = inspect_provisioned_cert(cert_dir);
            const auto paths = provisioned_cert_paths(cert_dir);
            if (state == CertState::Valid || state == CertState::NeedsRenew) {
                // A usable leaf exists — present it (mTLS from the first connect).
                cfg_.tls_client_cert = paths.cert_path;
                cfg_.tls_client_key = paths.key_path;
                spdlog::info("PKI: using provisioned client cert {} ({})", paths.cert_path.string(),
                             state == CertState::NeedsRenew ? "past 2/3 life — will renew"
                                                            : "valid");
            }
            if (state != CertState::Valid) {
                // Missing / Expired → enroll; NeedsRenew → renew. Either way mint a
                // fresh keypair + CSR to present in Register.
                if (auto kc = generate_key_and_csr(cfg_.agent_id)) {
                    pending_key_pem = std::move(kc->private_key_pem);
                    pending_csr_pem = std::move(kc->csr_pem);
                    spdlog::info("PKI: generated EC P-256 keypair + CSR ({})",
                                 state == CertState::NeedsRenew ? "renewal" : "first enrollment");
                } else {
                    spdlog::error("PKI: failed to generate agent keypair/CSR — continuing without "
                                  "per-agent mTLS");
                }
            }
        }

        CloudIdentity cloud_id; // Populated before registration (step 2b)
        std::shared_ptr<grpc::Channel> channel;
        std::unique_ptr<pb::AgentService::Stub> stub;
        // Build (or rebuild, post-issuance) the credentials + channel + stub from
        // the current cfg_ cert paths. Returns false on an unreadable cert/key.
        auto build_channel = [&]() -> bool {
            std::shared_ptr<grpc::ChannelCredentials> creds;
            if (cfg_.tls_enabled) {
                grpc::SslCredentialsOptions ssl_opts;
                if (!cfg_.tls_ca_cert.empty()) {
                    ssl_opts.pem_root_certs = read_file_contents(cfg_.tls_ca_cert);
                    if (ssl_opts.pem_root_certs.empty()) {
                        spdlog::error("Failed to read CA cert from {}", cfg_.tls_ca_cert.string());
                        return false;
                    }
                } else {
                    // PKI #1303: fail CLOSED. No --ca-cert was given and the install-CA
                    // auto-discovery above run() found nothing usable at the standard
                    // shared-cert-volume path (a found CA is promoted into
                    // cfg_.tls_ca_cert there, so reaching this branch means none existed;
                    // discover_install_ca_path() also rejects an empty/truncated file, so
                    // it never pins nothing). An empty pem_root_certs makes gRPC verify
                    // against the SYSTEM trust store, which does NOT trust a Yuzu
                    // self-signed install CA. With the gateway one-way-TLS edge live that
                    // is a fail-open MITM window (any publicly-trusted impostor cert for
                    // the dial host would be accepted) on the command fan-out plane.
                    // Refuse unless the operator has DELIBERATELY opted into the system
                    // trust store (server leaf signed by a public/corporate CA).
                    if (!cfg_.tls_allow_system_trust) {
                        spdlog::error(
                            "TLS is enabled but no CA could be pinned: --ca-cert was not given "
                            "and no install CA was found at the standard path "
                            "(/etc/yuzu/certs/default-ca.pem). Refusing to connect with the "
                            "SYSTEM trust store, which does NOT trust a Yuzu self-signed install "
                            "CA — that would be a fail-open MITM posture. Fix one of: provide "
                            "--ca-cert; ensure the install CA exists at that path; pass "
                            "--tls-system-roots if the server cert is signed by a public/"
                            "corporate CA already in the system store; or --no-tls for a "
                            "dev/demo stack.");
                        return false;
                    }
                    spdlog::warn("TLS is enabled with no pinned CA — using the SYSTEM trust "
                                 "store by explicit --tls-system-roots. Safe ONLY if the server "
                                 "certificate chains to a CA already trusted by the system "
                                 "(public/corporate root), NOT a Yuzu self-signed install CA.");
                }

                // Client certificate: prefer cert store, fall back to PEM files
                if (!cfg_.cert_store.empty()) {
                    // Read client cert + key from OS certificate store
                    spdlog::info("Reading client certificate from {} store...", cfg_.cert_store);
                    auto store_result = read_cert_from_store(cfg_.cert_store, cfg_.cert_subject,
                                                             cfg_.cert_thumbprint);

                    if (!store_result.ok()) {
                        spdlog::error("Certificate store error: {}", store_result.error);
                        return false;
                    }

                    ssl_opts.pem_cert_chain = std::move(store_result.pem_cert_chain);
                    ssl_opts.pem_private_key = std::move(store_result.pem_private_key);
                    spdlog::info("mTLS enabled: using certificate from {} store", cfg_.cert_store);
                } else {
                    const bool has_client_cert = !cfg_.tls_client_cert.empty();
                    const bool has_client_key = !cfg_.tls_client_key.empty();
                    if (has_client_cert != has_client_key) {
                        spdlog::error("mTLS requires both --client-cert and --client-key");
                        return false;
                    }

                    if (has_client_cert && has_client_key) {
                        ssl_opts.pem_cert_chain = read_file_contents(cfg_.tls_client_cert);
                        ssl_opts.pem_private_key = read_file_contents(cfg_.tls_client_key);
                        if (ssl_opts.pem_cert_chain.empty() || ssl_opts.pem_private_key.empty()) {
                            spdlog::error("Failed to read client cert/key for mTLS");
                            return false;
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
            return true;
        };

        if (!build_channel()) {
            // The initial build_channel() failed closed — most importantly the #1303
            // fail-closed TLS posture (no pinnable CA under secure-by-default), but also
            // an unreadable CA/client cert/key. This is a fatal STARTUP failure, not a
            // normal shutdown: flag it so main() exits non-zero and systemd Restart= /
            // Docker / Windows SCM see the failure instead of a silent EXIT_SUCCESS.
            startup_failed_ = true;
            return;
        }

        // 2b. Detect cloud instance identity (for auto-approve)
        {
            cloud_id = detect_cloud_identity();
            if (cloud_id.valid()) {
                spdlog::info("Cloud identity detected: provider={}, instance={}, region={}",
                             cloud_id.provider, cloud_id.instance_id, cloud_id.region);
            }
        }

        // PR 10 / UAT 2026-05-12 — snapshot pump is spawned ONCE, not
        // per-reconnect. The pump runs through reconnects, keeping the
        // shared `latest_snapshot_` buffer warm; the heartbeat thread
        // (which IS re-spawned per connection) reads from it and ships
        // it on the next heartbeat. This means a brief disconnect does
        // not cost us the next push — the pump kept producing while
        // the link was down, the first reconnected heartbeat carries
        // the latest snapshot.
        //
        // Pump is gated on the TAR plugin being loaded; minimal /
        // embedded agent variants without TAR simply leave the slot
        // empty and the server falls back to dispatch-on-get.
        {
            const YuzuPluginDescriptor* tar_descriptor = nullptr;
            for (const auto& handle : plugins_) {
                if (std::string_view{handle.descriptor()->name} == "tar") {
                    tar_descriptor = handle.descriptor();
                    break;
                }
            }
            if (tar_descriptor) {
                snapshot_pump_thread_ = std::thread([this, tar_descriptor]() {
                    spdlog::info("Snapshot pump started (interval=30s, action=tar.fleet_snapshot)");
                    constexpr auto kFirstDelay = std::chrono::seconds{5};
                    constexpr auto kInterval = std::chrono::seconds{30};
                    auto sleep_for = [this](std::chrono::seconds total) {
                        auto remaining = total;
                        while (remaining.count() > 0 &&
                               !stop_requested_.load(std::memory_order_acquire)) {
                            auto step = std::min(remaining, std::chrono::seconds{2});
                            std::this_thread::sleep_for(step);
                            remaining -= step;
                        }
                    };
                    sleep_for(kFirstDelay);
                    LocalDispatcher dispatcher;
                    while (!stop_requested_.load(std::memory_order_acquire)) {
                        // #1001 / arch-S3 — local-dispatch concerns
                        // (capture buffer, byte cap, truncation sentinel)
                        // live in LocalDispatcher. The pump just decides
                        // what to do with each cycle's result.
                        auto result = dispatcher.run(tar_descriptor, "fleet_snapshot");
                        if (result.truncated) {
                            spdlog::warn("Snapshot pump: capture truncated at {}B; "
                                         "dropping this cycle's snapshot",
                                         result.captured.size());
                        } else if (result.rc == 0 && !result.captured.empty()) {
                            std::lock_guard lock(snapshot_mu_);
                            latest_snapshot_ = std::move(result.captured);
                            latest_snapshot_seq_.fetch_add(1, std::memory_order_acq_rel);
                        } else if (result.rc != 0) {
                            spdlog::warn("Snapshot pump: tar.fleet_snapshot rc={}, captured={}B",
                                         result.rc, result.captured.size());
                        }
                        sleep_for(kInterval);
                    }
                    spdlog::info("Snapshot pump stopped");
                });
            } else {
                spdlog::info("Snapshot pump skipped: TAR plugin not loaded");
            }
        }

        // 3. Register with server — with reconnect loop
        int reconnect_count = 0;
        constexpr int kMaxReconnectDelaySecs = 300; // 5 minutes max backoff
        constexpr int kMaxCsrAttempts = 5; // PKI: bound enrolled-but-no-cert retries

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

                // PKI PR3: present the CSR so the server signs a per-agent client
                // leaf (CN=<agent_id>). Only set when enrolling/renewing — once a
                // leaf is issued and the channel rebuilt, pending_csr_pem is cleared
                // so a steady-state re-Register never triggers a re-issue.
                if (!pending_csr_pem.empty()) {
                    req.set_csr_pem(pending_csr_pem);
                    spdlog::info("Including CSR for per-agent mTLS enrollment");
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

                // PKI PR3: the server signed our CSR. Persist the leaf + key (0600)
                // + issuing chain, point the config at it, and rebuild the channel
                // so the next connection is mutual TLS. We then `continue` to
                // re-Register over mTLS — the FIRST (server-auth) session bound an
                // empty client identity, so the data plane (Subscribe) would reject
                // it; re-registering binds the leaf's CN=<agent_id> to a fresh
                // session. The CSR is cleared first so the re-Register doesn't
                // request a second cert.
                if (!pending_csr_pem.empty()) {
                    if (!resp.issued_certificate().empty()) {
                        const bool persisted = persist_provisioned_cert(
                            cert_dir, pending_key_pem, resp.issued_certificate(),
                            resp.issued_ca_chain());
                        // Zero the in-memory key on every path; clear the CSR once we
                        // no longer need to act on it.
                        yuzu::secure_zero(pending_key_pem);
                        pending_key_pem.clear();
                        pending_csr_pem.clear();
                        if (persisted) {
                            // Pairs with yuzu_agent_cert_provision_failed_total so an
                            // operator can distinguish a provisioned (mutual-TLS) agent
                            // from one that gave up and is running unauthenticated —
                            // the observability half of the silent-downgrade concern
                            // (#1239 should-fix; the enforcement half is the planned
                            // --require-agent-identity flag, see auth-architecture.md).
                            metrics_.counter("yuzu_agent_cert_provisioned_total").increment();
                            const auto paths = provisioned_cert_paths(cert_dir);
                            cfg_.tls_client_cert = paths.cert_path;
                            cfg_.tls_client_key = paths.key_path;
                            spdlog::info("PKI: received per-agent client cert — reconnecting with "
                                         "mutual TLS");
                            if (!build_channel()) {
                                spdlog::error("PKI: failed to rebuild channel with issued cert");
                                return;
                            }
                            continue; // re-Register over mTLS (binds the cert identity)
                        }
                        // Persist failed (disk full / perms). The server recorded the
                        // leaf but we can't use it; falling through would Subscribe
                        // with no client identity and be rejected, then reconnect with
                        // an empty CSR and never recover. Exit so the service manager
                        // restarts us — on restart the pre-step mints a fresh CSR.
                        metrics_.counter("yuzu_agent_cert_provision_failed_total",
                                         {{"reason", "persist_failed"}})
                            .increment();
                        spdlog::error("PKI: failed to persist the issued client cert under {} — "
                                      "exiting for a clean restart-driven retry",
                                      cert_dir.string());
                        return;
                    }
                    // Hermes HIGH-2: enrolled but NO cert returned (server signer
                    // unavailable/rate-limited, or an active MITM stripped the field).
                    // reconnect_count was reset to 0 above, so without a bound the
                    // agent would tight-loop re-minting/dropping certs. Back off and
                    // retry the SAME CSR a bounded number of times; then give up
                    // provisioning (clear the pending CSR) and proceed — if the server
                    // requires client identity Subscribe will be rejected and the
                    // normal reconnect backoff applies (no more cert churn), and if it
                    // does not (one-way TLS) the agent runs without a client cert.
                    if (++csr_attempts >= kMaxCsrAttempts) {
                        metrics_.counter("yuzu_agent_cert_provision_failed_total",
                                         {{"reason", "no_cert_issued"}})
                            .increment();
                        spdlog::error("PKI: enrolled but the server issued no client certificate "
                                      "after {} attempts — giving up auto-provisioning for this "
                                      "run (check the server CA / signer)",
                                      csr_attempts);
                        yuzu::secure_zero(pending_key_pem);
                        pending_key_pem.clear();
                        pending_csr_pem.clear();
                        // fall through unauthenticated
                    } else {
                        spdlog::warn("PKI: enrolled but no client cert issued (attempt {}/{}); "
                                     "backing off and retrying",
                                     csr_attempts, kMaxCsrAttempts);
                        reconnect_count = csr_attempts; // drive exponential backoff
                        continue;                       // retry Register with the same CSR
                    }
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

                // Step 4: publish this stream as the Guardian sink target and wire
                // the event-sink now the stream is up and BEFORE any push arrives, so
                // a guard started by a push has a live sink. Drift events ship as a
                // self-describing CommandResponse{plugin:"__guard__", action:"event",
                // payload}. The sink captures only `this` and writes through
                // guardian_sink_stream_ (H4 / #1209): a guard worker fires
                // asynchronously and outlives any single stream, so capturing a
                // specific `stream` would let it write to a cancelled stream across a
                // reconnect. The holder is reset on read-loop exit, under the same
                // mutex, before the stream is torn down.
                if (guardian_) {
                    {
                        std::lock_guard lock(stream_write_mu_);
                        guardian_sink_stream_ = stream;
                    }
                    guardian_->set_event_sink(
                        [this](const gpb::GuaranteedStateEvent& ev) { emit_guardian_event(ev); });
                }

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
                        // PR 10: per-thread last-shipped snapshot generation.
                        // Stays inside the heartbeat lambda so reconnects
                        // see seq=0 first and re-ship whatever the pump
                        // last produced — important so a flapping link
                        // doesn't leave the server reading a stale slot.
                        uint64_t last_attached_seq = 0;
                        // A4: previous perf-counter reading for the heartbeat's
                        // device-utilization tags (deriving a rate needs two
                        // readings; lambda-local so a reconnect re-baselines and
                        // the first heartbeat of a session ships no stale rate).
#if defined(_WIN32)
                        win::PerfBreachCounters hb_prev_perf;
#elif defined(__linux__)
                        lnx::CpuJiffies hb_prev_cpu_lnx; // A4 Linux heartbeat CPU% delta baseline
#endif
                        // Slice 4a: previous interface byte counters for the
                        // heartbeat network throughput delta (same re-baseline
                        // semantics as hb_prev_perf).
                        netq::NetCounters hb_prev_net;
                        // 4b.3: rolling window of raw cumulative Σretrans/Σsegs
                        // readings — the device retransmit RATE is the interval
                        // delta over this window, not a single sample's absolute
                        // ratio. Lambda-local so a reconnect re-baselines (a new
                        // session ships no rate until it has ≥2 readings again).
                        netq::RetransWindow hb_net_retrans_window;
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
                            // Guardian policy generation (M5 / #1209): lets the
                            // server detect an agent that missed a push (offline at
                            // push time, or reconnected) and re-push it without a
                            // manual operator action. Always emitted — including
                            // generation 0 — so an agent that has never received a
                            // push still converges once rules exist server-side.
                            if (guardian_)
                                tags["yuzu.guardian_generation"] =
                                    std::to_string(guardian_->policy_generation());
#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
                            // DEX signal observer (every platform with a real observer —
                            // Windows / Linux / macOS; no-op platforms have none). Both tags are
                            // omitted when --dex-disable opted the agent out, so the server rollups
                            // reflect genuine state, not opt-outs. The agent has no /metrics
                            // endpoint; these heartbeat tags are the ONLY path that makes a
                            // silently-deaf observer and the fleet signal count observable (see
                            // AgentHealthStore::recompute_metrics).
                            if (!cfg_.dex_disable) {
                                const bool healthy =
                                    dex_health_ &&
                                    dex_health_->load(std::memory_order_relaxed);
                                tags["yuzu.dex_observer_armed"] = healthy ? "1" : "0";
                                tags["yuzu.dex_observed"] =
                                    std::to_string(dex_seq_.load(std::memory_order_relaxed));
                                metrics_.gauge("yuzu_agent_dex_observer_armed")
                                    .set(healthy ? 1.0 : 0.0);
                            }
#endif
                            // A4 fleet perf rollup: ship the device's current
                            // utilization as heartbeat tags — the agent has no
                            // /metrics endpoint, so this is the ONLY channel by
                            // which fleet perf gauges exist (see
                            // AgentHealthStore::recompute_metrics). Derived over
                            // the heartbeat interval from the same raw counter
                            // reads as the A3 breach detector. The first
                            // heartbeat of a session only baselines (invalid
                            // sample -> tags omitted; the server simply doesn't
                            // count this agent that cycle). Gated like the DEX
                            // observer: --dex-disable means no DEX telemetry of
                            // any kind. Windows and Linux each read their own
                            // counters here; macOS / other ship no perf tags yet.
                            if (!cfg_.dex_disable) {
#if defined(_WIN32)
                                const auto cur = win::read_perf_breach_counters();
                                const auto ps = win::derive_breach_sample(hb_prev_perf, cur);
                                hb_prev_perf = cur;
                                if (ps.valid) {
                                    tags["yuzu.perf_cpu_pct"] =
                                        std::format("{:.1f}", ps.cpu_pct);
                                    // Per-domain validity (gov review MEDIUM #1):
                                    // omit a sub-metric whose read failed rather
                                    // than ship a healthy 0% into the fleet gauge.
                                    if (ps.commit_valid)
                                        tags["yuzu.perf_commit_pct"] =
                                            std::format("{:.1f}", ps.commit_pct);
                                    if (ps.disk_valid)
                                        tags["yuzu.perf_disk_lat_ms"] =
                                            std::format("{:.2f}", ps.disk_lat_ms);
                                }
#elif defined(__linux__)
                                // Linux: read /proc here independently (mirrors the Windows
                                // path — the heartbeat does its own read, separate from the A3
                                // breach collector). CPU% needs a delta vs the prior heartbeat;
                                // commit% is instantaneous. The first heartbeat (or an unreadable
                                // /proc) only baselines, so the tag is omitted that cycle. No
                                // disk-latency metric on Linux yet — that perf source is a later
                                // slice.
                                const auto read_proc =
                                    [](const char* p) -> std::optional<std::string> {
                                    std::ifstream f(p);
                                    if (!f.is_open())
                                        return std::nullopt;
                                    const std::istreambuf_iterator<char> begin(f), end;
                                    std::string s(begin, end);
                                    return f.bad() ? std::nullopt : std::optional<std::string>(s);
                                };
                                // A throw here (bad_alloc reading /proc, std::format)
                                // must not unwind out of the heartbeat thread — that
                                // would stop heartbeats and read as the agent going
                                // offline. Swallow; the tag is just omitted this cycle.
                                try {
                                    if (const auto st = read_proc("/proc/stat")) {
                                        const lnx::CpuJiffies cur = lnx::parse_proc_stat(*st);
                                        if (const auto pct =
                                                lnx::cpu_busy_pct(hb_prev_cpu_lnx, cur))
                                            tags["yuzu.perf_cpu_pct"] =
                                                std::format("{:.1f}", *pct);
                                        hb_prev_cpu_lnx = cur;
                                    }
                                    // Gate commit% the SAME way the collector gates
                                    // perf.memory_pressure: under vm.overcommit_memory=1
                                    // ("always") CommitLimit is advisory and commit% reads
                                    // ~100% on healthy overcommit hosts — omit the tag so the
                                    // fleet gauge stays consistent with the breach signal
                                    // (shared lnx::overcommit_is_always, fjarvis review).
                                    const auto oc = read_proc("/proc/sys/vm/overcommit_memory");
                                    if (!(oc && lnx::overcommit_is_always(*oc)))
                                        if (const auto mi = read_proc("/proc/meminfo"))
                                            if (const auto pct = lnx::parse_commit_pct(*mi))
                                                tags["yuzu.perf_commit_pct"] =
                                                    std::format("{:.1f}", *pct);
                                } catch (...) {
                                    // omit perf tags this heartbeat
                                }
#endif
                            }

                            // Slice 4a: device network-quality facts (Linux
                            // netlink TCP_INFO + /proc/net/dev throughput) — the
                            // ONLY channel for the fleet net gauges + /network
                            // Overview, same as the perf tags above. Gated like
                            // perf; this is aggregate device telemetry with NO
                            // per-destination data (that warehouse tier + its
                            // own opt-in are a later slice). Off Linux the sample
                            // is all-invalid, so no tags ship (absent, not zero).
                            if (!cfg_.dex_disable) {
                                const auto net_cur = netq::read_net_counters();
                                const auto ns =
                                    netq::sample_net_quality(hb_prev_net, net_cur);
                                hb_prev_net = net_cur;
                                // TAG-KEY PIN: these literals MUST match
                                // network_perf_rules.hpp kNetTag* (the server
                                // parses by those constants) — a drift = silent
                                // zero-reporting; pinned by static_assert in
                                // tests/unit/server/test_network_perf_model.cpp.
                                if (ns.rtt_valid)
                                    tags["yuzu.net_rtt_p50_ms"] =
                                        std::format("{:.1f}", ns.rtt_p50_ms);
                                // Interval retransmit RATE (ΔΣretr/ΔΣsegs over a
                                // short window), NOT the absolute lifetime ratio
                                // (which is diluted to noise). Push this cycle's
                                // raw device sums, then ship the windowed delta
                                // once there are ≥2 readings (absent on the first
                                // of a session — never a fabricated 0).
                                // MEASUREMENT-FIRST: no `net_degraded` verdict —
                                // a hard threshold needs real-fleet baseline
                                // calibration (a later slice), so it is retired
                                // here rather than shipped loopback-calibrated.
                                if (ns.retrans_valid)
                                    hb_net_retrans_window.push(ns.retrans_total,
                                                               ns.segs_out_total);
                                if (auto rp = hb_net_retrans_window.rate_pct())
                                    tags["yuzu.net_retrans_pct"] =
                                        std::format("{:.2f}", *rp);
                                if (ns.throughput_valid)
                                    tags["yuzu.net_throughput_bps"] =
                                        std::format("{:.0f}", ns.throughput_bps);
                            }

                            // PR 10: attach pushed fleet snapshot if the
                            // pump produced something newer than what
                            // we last shipped. `last_attached_seq` is a
                            // per-heartbeat-thread local; the pump's
                            // monotonic counter is the source of truth.
                            // Empty attach when no new snapshot is
                            // available — keeps quiescent heartbeats at
                            // their pre-PR-10 size.
                            {
                                const auto cur_seq =
                                    latest_snapshot_seq_.load(std::memory_order_acquire);
                                if (cur_seq > last_attached_seq) {
                                    std::lock_guard lock(snapshot_mu_);
                                    if (!latest_snapshot_.empty()) {
                                        req.set_fleet_snapshot_json(latest_snapshot_);
                                        last_attached_seq = cur_seq;
                                    }
                                }
                            }

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
                        // Stamp the response so the server routes it via the Guardian
                        // ingest branch (plugin=="__guard__") and skips the response
                        // store / executions drawer. action mirrors the request.
                        resp.set_plugin("__guard__");
                        resp.set_action(cmd.action());
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

                        // Defence-in-depth: wrap the plugin's execute() so a
                        // thrown C++ exception cannot propagate up into the
                        // command-dispatch thread and terminate() the whole
                        // agent process. Plugins are expected to convert
                        // failures into a non-zero `rc`; this is the safety
                        // net for the cases they miss. Observed 2026-05-12:
                        // agent_logging.get_log threw filesystem_error from
                        // fs::exists on EACCES and brought the agent down
                        // mid-test. The plugin bug is fixed separately;
                        // this catch is so the next plugin's mistake
                        // doesn't have the same blast radius.
                        int rc;
                        try {
                            rc = target->execute(raw_ctx, cmd.action().c_str(), params.data(),
                                                 params.size());
                        } catch (const std::exception& e) {
                            spdlog::error("Plugin {} action {} threw std::exception: {}",
                                          cmd.plugin(), cmd.action(), e.what());
                            std::string msg = "plugin threw exception: ";
                            msg += e.what();
                            ctx_impl.append_output(msg.c_str());
                            rc = 1;
                        } catch (...) {
                            spdlog::error("Plugin {} action {} threw non-std exception",
                                          cmd.plugin(), cmd.action());
                            ctx_impl.append_output("plugin threw non-std exception");
                            rc = 1;
                        }

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

                // Detach the Guardian event-sink from this (now broken) stream BEFORE
                // it is torn down (H4 / #1209). Taking stream_write_mu_ waits for any
                // in-flight sink Write to finish, then nulls the holder so a guard
                // worker firing during teardown drops the event instead of writing to
                // a cancelled stream. Guards keep running across the reconnect; the
                // next iteration republishes the new stream and the heartbeat reconcile
                // (M5) catches up any generation missed while the link was down.
                {
                    std::lock_guard lock(stream_write_mu_);
                    guardian_sink_stream_.reset();
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

                // Signal heartbeat thread to exit and cancel any in-flight RPC
                heartbeat_stop_.store(true, std::memory_order_release);
                if (auto* hctx = heartbeat_ctx_.load(std::memory_order_acquire)) {
                    hctx->TryCancel();
                }
                if (heartbeat_thread_.joinable()) {
                    heartbeat_thread_.join();
                }
                // PR 10: the snapshot pump is intentionally NOT joined on a
                // transient (non-final) disconnect. It is a Run()-lifetime
                // thread that survives reconnects, so the heartbeat thread of
                // the next connection cycle finds a warm latest_snapshot_ and
                // ships it immediately. The pump is joined only on FINAL
                // shutdown — by quiesce_run_workers() in the stop_requested_
                // branch just below (and by the Run()-exit ScopeExit backstop).

                // Only shutdown plugins on final exit — keep them loaded for reconnect
                if (stop_requested_.load(std::memory_order_acquire)) {
                    // #1420 — the snapshot pump borrows a descriptor into
                    // `plugins_`; join it (and the other Run() workers) BEFORE
                    // shutting the plugins down and clearing the vector below,
                    // otherwise an in-flight pump cycle dispatches into freed
                    // plugin state (use-after-free / abort on a clean exit).
                    // This call's SOLE purpose is that ordering relative to
                    // plugins_.clear(); the Run()-exit ScopeExit is the backstop
                    // for every early-return/exception exit, and re-invoking the
                    // helper there is a joinable()-guarded no-op.
                    quiesce_run_workers();
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

        // #1420 / #1434: the snapshot pump, heartbeat, and OTA-updater threads
        // are quiesced and joined by quiesce_run_workers() — invoked from the
        // final-shutdown teardown above (before plugins_.clear(), so a pump
        // cycle can't dispatch into freed plugin state) and, as the universal
        // backstop for every exit path including the early-return rejections,
        // from the Run()-exit ScopeExit `cleanup`. No separate post-loop join
        // is needed here.
    }

    void stop() noexcept override {
        stop_requested_.store(true, std::memory_order_release);
        heartbeat_stop_.store(true, std::memory_order_release);
        // Cancel the Subscribe stream FIRST. The Guardian drift workers and the DEX
        // observer both emit through emit_guardian_event(), whose synchronous gRPC
        // Write() BLOCKS on a stalled-but-not-dead stream (gateway up, not draining).
        // guardian_->stop() / dex_observer_->stop() below DRAIN those emitters with an
        // unbounded wait, so cancelling only after the drain lets an in-flight signal
        // Write during shutdown wedge stop() forever (cpp-safety BLOCKING). TryCancel
        // aborts the blocked Write; it does NOT tear the stream down — the stream holder
        // and stream_write_mu_ are members destroyed AFTER guardian_/dex_observer_, so
        // they stay live through both drains and emit_guardian_event's null-check under
        // the lock remains UAF-safe.
        if (auto* ctx = subscribe_ctx_.load(std::memory_order_acquire)) {
            ctx->TryCancel();
        }
        if (guardian_)
            guardian_->stop();
        if (dex_observer_)
            dex_observer_->stop();
        if (updater_)
            updater_->stop();
        // Cancel any in-flight heartbeat RPC to unblock the heartbeat thread
        if (auto* hctx = heartbeat_ctx_.load(std::memory_order_acquire)) {
            hctx->TryCancel();
        }
    }

    std::string_view agent_id() const noexcept override { return cfg_.agent_id; }

    std::vector<std::string> loaded_plugins() const override { return plugin_names_; }

    [[nodiscard]] bool startup_failed() const noexcept override { return startup_failed_; }

private:
    // Serialize a Guardian event into the __guard__/event CommandResponse and write
    // it through the current Subscribe stream. Shared by the GuardianEngine drift
    // sink and the (ruleless) DEX signal observer. Drops the event if the link is
    // down between reconnects (guardian_sink_stream_ null) — durable buffering is A3.
    void emit_guardian_event(const gpb::GuaranteedStateEvent& ev) {
        pb::CommandResponse resp;
        resp.set_plugin("__guard__");
        resp.set_action("event");
        resp.set_status(pb::CommandResponse::SUCCESS);
        resp.set_payload(ev.SerializeAsString());
        std::lock_guard lock(stream_write_mu_);
        if (guardian_sink_stream_)
            guardian_sink_stream_->Write(resp, grpc::WriteOptions());
    }

    // #1420 / #1434 — single quiesce-and-join chokepoint for the three
    // `this`-capturing worker threads Run() spawns: the Run()-lifetime snapshot
    // pump, the per-connection heartbeat, and the OTA-updater thread. Every one
    // of them must be stopped and joined before the agent's plugins are torn
    // down and before AgentImpl is destroyed:
    //   * the snapshot pump dispatches `tar.fleet_snapshot` into the TAR plugin
    //     through a borrowed descriptor — a cycle that runs after plugin
    //     teardown is a use-after-free (#1420);
    //   * any Run() exit that leaves one of these threads joinable aborts the
    //     process via std::terminate when the std::thread is destroyed (#1434,
    //     e.g. the hard registration-rejection `return`).
    // Invoked from EVERY Run() exit path: the Run()-exit ScopeExit `cleanup`
    // (covers the early returns and exceptions) and the reconnect-loop final
    // teardown (orders the pump join ahead of plugins_.clear()). Idempotent —
    // the joinable() guards make repeat calls and the not-yet-started register
    // loop returns (where heartbeat/updater don't exist yet) no-ops.
    //
    // Unblock-before-join keeps the joins bounded: the pump observes the stop
    // flag on its ≤2 s sleep slices (worst case it finishes one in-flight local
    // `fleet_snapshot` enumerate — no blocking I/O, so the join is bounded by a
    // single capture, not a network wait); the heartbeat may be parked in a
    // Heartbeat RPC and the updater in an OTA RPC, so we TryCancel the heartbeat
    // context and stop() the updater first — `Updater::stop()` now TryCancels
    // its in-flight OTA RPC too (#1434 UP-1), so a stalled download can't hang
    // the join. This is a SUPERSET of what stop() unblocks (stop() additionally
    // cancels the Subscribe stream and drains guardian_/dex_observer_, which are
    // member-owned and joined by their own dtors — deliberately NOT joined here).
    //
    // TERMINAL-ONLY: this sets stop_requested_, so it must be called only on a
    // path that is actually shutting the agent down (the Run()-exit ScopeExit,
    // or the reconnect-loop teardown already gated on stop_requested_). Never
    // call it on a transient-reconnect path — doing so would euthanise a healthy
    // agent and break the across-reconnect warm-snapshot continuity (PR 10).
    void quiesce_run_workers() noexcept {
        stop_requested_.store(true, std::memory_order_release);
        heartbeat_stop_.store(true, std::memory_order_release);
        if (updater_)
            updater_->stop();
        if (auto* hctx = heartbeat_ctx_.load(std::memory_order_acquire))
            hctx->TryCancel();
        if (snapshot_pump_thread_.joinable())
            snapshot_pump_thread_.join();
        if (heartbeat_thread_.joinable())
            heartbeat_thread_.join();
        if (update_thread_.joinable())
            update_thread_.join();
    }

    Config cfg_;
    PluginContextImpl plugin_ctx_;
    // Per-plugin contexts: each plugin gets its own PluginContextImpl with the
    // correct plugin_name for KV storage namespacing. Stored as unique_ptrs so
    // pointers remain stable after map insertions.
    std::unordered_map<std::string, std::unique_ptr<PluginContextImpl>> per_plugin_ctx_;
    std::unique_ptr<KvStore> kv_store_;
    // Drives interval / file-change / service-status triggers that plugins
    // register during init(). Owned here; a non-owning pointer is handed to
    // every per-plugin context so yuzu_register_trigger can reach it.
    // start() is called once plugins are loaded; stop() runs before plugin
    // shutdown so a trigger never fires into a half-torn-down plugin.
    TriggerEngine trigger_engine_;
    yuzu::MetricsRegistry metrics_;
    std::chrono::steady_clock::time_point start_time_;
    std::string session_id_;
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> heartbeat_stop_{false};
    // Set when run() returns due to a fatal STARTUP failure (the #1303 fail-closed
    // TLS posture refused to connect, or an unreadable cert/key) — not a normal
    // stop(). main() maps it to a non-zero exit. Single-threaded: written in run()
    // before the connect loop, read after run() returns; no atomic needed.
    bool startup_failed_{false};
    std::atomic<grpc::ClientContext*> subscribe_ctx_{nullptr};
    std::atomic<grpc::ClientContext*> heartbeat_ctx_{nullptr};
    std::vector<PluginHandle> plugins_;
    std::vector<std::string> plugin_names_;
    std::mutex stream_write_mu_;
    // Current Subscribe stream the Guardian event-sink writes through (H4 / #1209).
    // Guarded by stream_write_mu_. Guard worker threads outlive any single stream
    // and fire asynchronously, so the sink must NOT capture a specific stream: it
    // reads this holder under the lock and drops the event if it is null (link down
    // between reconnects). Set on stream open, reset on read-loop exit BEFORE the
    // stream is torn down, so a guard firing mid-teardown can never write to a
    // cancelled stream.
    std::shared_ptr<SubscribeStream> guardian_sink_stream_;
    // Declared AFTER stream_write_mu_ + guardian_sink_stream_ so it is DESTROYED
    // FIRST (reverse declaration order): ~GuardianEngine joins the guard worker
    // threads, which must happen while the mutex + sink-stream holder those
    // workers write through are still alive (H4 / #1209). Body-initialized in the
    // ctor (after kv_store_), so the later declaration does not affect construction.
    std::unique_ptr<GuardianEngine> guardian_;
    // Fleet-wide DEX signal observer (multi-signal). Declared AFTER stream_write_mu_
    // + guardian_sink_stream_ (same reasoning as guardian_): its OS-callbacks emit
    // through emit_guardian_event(), so its dtor (which stop()s the subscriptions +
    // drains in-flight callbacks) must run while the mutex + sink-stream holder are
    // still alive. dex_seq_ disambiguates the at-least-once event_id for same-agent
    // bursts within one millisecond; agent_id (folded into the id) disambiguates
    // ACROSS agents so a fleet-wide signal wave doesn't collide on the global PK.
    std::atomic<std::uint64_t> dex_seq_{0};
    // Runtime arm/health of the DEX observer — flipped to false by the observer's
    // error callback on a runtime subscription failure on any channel (UP-1). A
    // shared_ptr<atomic> (not `this`) so a late OS-threadpool error callback stays
    // UAF-safe. Read by the heartbeat thread to drive the `yuzu.dex_observer_armed`
    // tag.
    std::shared_ptr<std::atomic<bool>> dex_health_;
    std::unique_ptr<ISignalObserver> dex_observer_;
    std::unique_ptr<ThreadPool> thread_pool_;
    std::unique_ptr<Updater> updater_;
    std::thread update_thread_;
    std::thread heartbeat_thread_;

    // PR 10 / UAT 2026-05-12 — Push-based fleet topology ingestion.
    //
    // `snapshot_pump_thread_` runs `tar.fleet_snapshot` locally on a
    // 30 s interval, captures the JSON, and stashes it under
    // `snapshot_mu_`. The heartbeat thread reads `latest_snapshot_`
    // each iteration; if `latest_snapshot_seq_` advanced since the
    // heartbeat's `last_attached_snapshot_seq_`, the snapshot rides
    // out on the next HeartbeatRequest.fleet_snapshot_json field.
    // Together they replace the previous dispatch-on-get path for
    // /api/v1/viz/fleet/topology, so the renderer reads from
    // per-agent slots that the agents themselves keep current.
    std::thread snapshot_pump_thread_;
    std::mutex snapshot_mu_;
    std::string latest_snapshot_;                  // last JSON produced by pump
    std::atomic<uint64_t> latest_snapshot_seq_{0}; // monotonically increases on each new snapshot

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
