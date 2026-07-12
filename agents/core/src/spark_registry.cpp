/**
 * spark_registry.cpp — the Registry spark mechanism (ADR-0021 Stage 1 PR 1b).
 *
 * Windows: one PRIVATE threadpool wait-group (TP_WAIT, min=2/max=4) servicing
 * RegNotifyChangeKeyValue across every watched key — O(mechanism), never
 * O(rules). This is the #1907-spike mechanism, NOT a port of guard_registry's
 * one-dedicated-thread-per-guard + 64-handle WaitForMultipleObjects model
 * (which is the O(rules)-capped ceiling the SparkEngine removes). Two spike
 * facts are load-bearing:
 *   - REG_NOTIFY_THREAD_AGNOSTIC on every RegNotifyChangeKeyValue: TP_WAIT
 *     recycles pool threads, and a notification registered without the flag is
 *     bound to the (transient) registering thread and dies when the pool
 *     recycles it. Present-in-code; necessity is a documented Win32 property.
 *   - Re-arm BEFORE processing (spike condition 4, rearm_failures=0): the
 *     RegNotify + SetThreadpoolWait are re-issued before the emit, so no change
 *     falls in the arm→process gap.
 *
 * PORTS THE WATCH, NOT THE ASSERTION: no expected-value compare, no write-back,
 * no ResilienceStrategy retry — a fired spark is a raw "this key changed" fact
 * (the old TriggerEngine RegistryChange shape). Compare + enforce are
 * Guardian's, Stage 2. It DOES port guard_registry's nearest-ancestor resilience
 * (survive a deleted+recreated key) and arm-before-check ordering.
 *
 * Off Windows the factory returns nullptr → SparkEngine rejects arm(Registry).
 */

#include "spark_mechanism.hpp"

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "guard_win_handle.hpp" // detail::EventHandle

#include <spdlog/spdlog.h>

#include <windows.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <variant>

#pragma comment(lib, "advapi32.lib")

namespace yuzu::agent {
namespace {

constexpr DWORD kNotifyFilter = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET;
#ifndef REG_NOTIFY_THREAD_AGNOSTIC
#define REG_NOTIFY_THREAD_AGNOSTIC 0x10000000L // Win8+; define for older SDK headers
#endif

/// Hand-rolled HKEY owner (the ScopedWinHandle template is HANDLE-typed;
/// mirrors guard_registry.cpp's RegKeyHandle).
class RegKeyHandle {
public:
    RegKeyHandle() = default;
    ~RegKeyHandle() { reset(); }
    RegKeyHandle(const RegKeyHandle&) = delete;
    RegKeyHandle& operator=(const RegKeyHandle&) = delete;
    void reset(HKEY h = nullptr) {
        if (h_ && h_ != h)
            ::RegCloseKey(h_);
        h_ = h;
    }
    [[nodiscard]] HKEY get() const { return h_; }
    explicit operator bool() const { return h_ != nullptr; }

private:
    HKEY h_ = nullptr;
};

std::wstring to_wide(const std::string& s) {
    if (s.empty())
        return {};
    int n = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

HKEY root_for(const std::string& hive) {
    if (hive == "HKLM")
        return HKEY_LOCAL_MACHINE;
    if (hive == "HKCU")
        return HKEY_CURRENT_USER;
    if (hive == "HKCR")
        return HKEY_CLASSES_ROOT;
    if (hive == "HKU")
        return HKEY_USERS;
    return nullptr;
}

std::string parent_path(const std::string& key) {
    const auto pos = key.find_last_of('\\');
    return pos == std::string::npos ? std::string{} : key.substr(0, pos);
}

/// Walk up from the key's parent until a subkey opens with KEY_NOTIFY (the hive
/// root always opens). Sets `out`; returns false only if even the root fails.
bool open_nearest_ancestor(HKEY root, const std::string& key, RegKeyHandle& out) {
    std::string p = parent_path(key);
    for (;;) {
        HKEY h = nullptr;
        const std::wstring wp = to_wide(p);
        const LONG rc = ::RegOpenKeyExW(root, p.empty() ? nullptr : wp.c_str(), 0, KEY_NOTIFY, &h);
        if (rc == ERROR_SUCCESS) {
            out.reset(h);
            return true;
        }
        if (p.empty())
            return false;
        p = parent_path(p);
    }
}

enum class WatchMode { Target, Ancestor };

class WindowsRegistryMechanism; // OnWait dispatches back through the watch's owner

/// One watched registry key: its notify event, the TP_WAIT that services it, the
/// currently-open key (target or nearest ancestor), and the emit key. `active`
/// (under the mechanism mu_) gates re-arm against teardown. `owner` lets the
/// context-only TP_WAIT callback re-enter the mechanism.
struct RegWatch {
    std::string spark_key;
    HKEY root{nullptr};
    std::string subkey;
    detail::EventHandle event; ///< auto-reset; the TP_WAIT object
    RegKeyHandle open_key;      ///< target in Target mode, ancestor in Ancestor mode
    PTP_WAIT wait{nullptr};
    WatchMode mode{WatchMode::Target};
    bool active{true};
    bool faulted{false}; ///< last-reported health, so fault_ fires only on transitions
    WindowsRegistryMechanism* owner{nullptr};
};

class WindowsRegistryMechanism final : public ISparkMechanism {
public:
    ~WindowsRegistryMechanism() override { stop(); }

    void start(SparkEmitFn emit, SparkFaultFn fault) override {
        std::lock_guard lk(mu_);
        if (pool_)
            return; // idempotent
        emit_ = std::move(emit);
        fault_ = std::move(fault);
        pool_ = ::CreateThreadpool(nullptr);
        if (!pool_) {
            spdlog::error("spark_registry: CreateThreadpool failed (err={}) — registry sparks inert",
                          ::GetLastError());
            return;
        }
        // #1907 condition 2: a pinned PRIVATE pool, bounded min=2/max=4 — the
        // watch count, not the thread count, is what scales.
        ::SetThreadpoolThreadMinimum(pool_, 2);
        ::SetThreadpoolThreadMaximum(pool_, 4);
        ::InitializeThreadpoolEnvironment(&env_);
        ::SetThreadpoolCallbackPool(&env_, pool_);
        started_ = true;
    }

    std::expected<void, std::string> watch(const std::string& key,
                                           const SparkParams& params) override {
        const auto* rp = std::get_if<RegistrySparkParams>(&params);
        if (!rp)
            return std::unexpected("registry mechanism: params are not RegistrySparkParams");
        HKEY root = root_for(rp->hive);
        if (!root)
            return std::unexpected("registry mechanism: unknown hive '" + rp->hive + "'");

        std::lock_guard lk(mu_);
        if (!started_)
            return std::unexpected("registry mechanism not started");
        if (watches_.contains(key))
            return {}; // idempotent (engine dedups, but stay safe)
        auto w = std::make_unique<RegWatch>();
        w->spark_key = key;
        w->root = root;
        w->subkey = rp->key;
        w->owner = this;
        w->event.reset(::CreateEventW(nullptr, FALSE, FALSE, nullptr)); // auto-reset
        if (!w->event)
            return std::unexpected("registry mechanism: CreateEventW failed");
        w->wait = ::CreateThreadpoolWait(&OnWait, w.get(), &env_);
        if (!w->wait)
            return std::unexpected("registry mechanism: CreateThreadpoolWait failed");
        // Arm-before-check: establish the notify + TP_WAIT before returning. A
        // registry change spark fires on a CHANGE, so there is no initial emit.
        if (!reconcile(*w)) {
            // F1: reconcile failed after CreateThreadpoolWait succeeded — release
            // the TP_WAIT before the unique_ptr drops it, or it leaks on every
            // failed arm. SetThreadpoolWait was never called on this path, so
            // teardown()'s CloseThreadpoolWait is the operative cleanup.
            teardown(*w);
            return std::unexpected("registry mechanism: could not arm any watch for the key");
        }
        watches_.emplace(key, std::move(w));
        return {};
    }

    void unwatch(const std::string& key) override {
        std::unique_ptr<RegWatch> victim;
        {
            std::lock_guard lk(mu_);
            auto it = watches_.find(key);
            if (it == watches_.end())
                return;
            it->second->active = false; // no further re-arm from an in-flight callback
            victim = std::move(it->second);
            watches_.erase(it);
        }
        // Disarm + drain OUTSIDE mu_: WaitForThreadpoolWaitCallbacks(TRUE) blocks
        // on a running callback, which itself takes mu_ — holding mu_ here would
        // deadlock. `active=false` (set above) guarantees the drained callback
        // will not re-arm.
        teardown(*victim);
    }

    void stop() override {
        {
            std::lock_guard lk(mu_);
            if (!pool_)
                return;
        }
        // Drop every watch first (each teardown drains its callback), then
        // release the pool. teardown() runs OUTSIDE mu_ — a draining callback
        // takes mu_, so holding it here would deadlock.
        std::unordered_map<std::string, std::unique_ptr<RegWatch>> victims;
        {
            std::lock_guard lk(mu_);
            for (auto& [k, w] : watches_)
                w->active = false;
            victims.swap(watches_);
        }
        for (auto& [k, w] : victims)
            teardown(*w);
        std::lock_guard lk(mu_);
        ::DestroyThreadpoolEnvironment(&env_);
        if (pool_) {
            ::CloseThreadpool(pool_);
            pool_ = nullptr;
        }
        started_ = false;
        emit_ = nullptr;
        fault_ = nullptr;
    }

private:
    /// (Re)establish the notify + TP_WAIT for `w`, preferring the target key and
    /// falling back to the nearest existing ancestor (recreate resilience). Sets
    /// w.mode. Called under mu_. Returns false only if nothing could be armed.
    bool reconcile(RegWatch& w) {
        // Prefer the target key.
        HKEY h = nullptr;
        const std::wstring wsub = to_wide(w.subkey);
        // REG_NOTIFY_THREAD_AGNOSTIC is a dwNotifyFilter bit (3rd arg), NOT the
        // fAsynchronous flag (5th) — it must be OR'd into the filter or it is
        // silently dropped and the notification dies when TP_WAIT recycles the
        // registering thread (the whole reason the flag is here).
        if (::RegOpenKeyExW(w.root, wsub.c_str(), 0, KEY_NOTIFY | KEY_READ, &h) == ERROR_SUCCESS) {
            w.open_key.reset(h);
            if (::RegNotifyChangeKeyValue(w.open_key.get(), FALSE,
                                          kNotifyFilter | REG_NOTIFY_THREAD_AGNOSTIC, w.event.get(),
                                          TRUE /*async*/) == ERROR_SUCCESS) {
                w.mode = WatchMode::Target;
                ::SetThreadpoolWait(w.wait, w.event.get(), nullptr);
                return true;
            }
            w.open_key.reset();
        }
        // Target absent: watch the nearest ancestor for its (re)creation.
        if (open_nearest_ancestor(w.root, w.subkey, w.open_key) &&
            ::RegNotifyChangeKeyValue(w.open_key.get(), FALSE,
                                      REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_THREAD_AGNOSTIC,
                                      w.event.get(), TRUE /*async*/) == ERROR_SUCCESS) {
            w.mode = WatchMode::Ancestor;
            ::SetThreadpoolWait(w.wait, w.event.get(), nullptr);
            return true;
        }
        return false;
    }

    void teardown(RegWatch& w) {
        if (w.wait) {
            ::SetThreadpoolWait(w.wait, nullptr, nullptr);            // disarm
            ::WaitForThreadpoolWaitCallbacks(w.wait, TRUE);          // cancel pending + drain running
            ::CloseThreadpoolWait(w.wait);
            w.wait = nullptr;
        }
        w.open_key.reset();
        w.event.reset();
    }

    static void CALLBACK OnWait(PTP_CALLBACK_INSTANCE, PVOID ctx, PTP_WAIT, TP_WAIT_RESULT) {
        auto* w = static_cast<RegWatch*>(ctx);
        w->owner->on_fire(*w);
    }

    void on_fire(RegWatch& w) {
        SparkEmitFn emit;
        SparkFaultFn fault;
        bool do_emit = false;
        bool fault_changed = false;
        bool now_faulted = false;
        {
            std::lock_guard lk(mu_);
            if (!w.active)
                return; // being torn down — do not re-arm
            const WatchMode old_mode = w.mode;
            // Re-arm BEFORE processing (condition 4): reconcile re-issues the
            // RegNotify + SetThreadpoolWait for the next change. A failure here
            // (neither target nor even the hive root armable) leaves the watch
            // deaf — now reported through the fault channel (B1) instead of only
            // a log, so a deaf watch is observable in SparkEngineStats.
            now_faulted = !reconcile(w);
            if (w.faulted != now_faulted) {
                w.faulted = now_faulted; // report the fault edge only, not every fire
                fault_changed = true;
            }
            if (now_faulted)
                spdlog::warn("spark_registry: re-arm failed for '{}' — watch is now deaf",
                             w.spark_key);
            // Emit when the key existed before this fire (it changed/was deleted)
            // OR exists now (it (re)appeared). Pure-ancestor noise (a sibling key
            // changed while our target stays absent) does not emit.
            do_emit = (old_mode == WatchMode::Target) || (w.mode == WatchMode::Target);
            emit = emit_;
            fault = fault_;
        }
        // Fire emit + fault with mu_ RELEASED: both re-enter the engine under its
        // own lock, and an inline re-arm would take our mu_ → deadlock if held.
        if (do_emit && emit)
            emit(w.spark_key, SparkData{std::monostate{}});
        if (fault_changed && fault)
            fault(w.spark_key, now_faulted, now_faulted ? "registry re-arm failed" : "recovered");
    }

    std::mutex mu_;
    SparkEmitFn emit_;
    SparkFaultFn fault_;
    PTP_POOL pool_{nullptr};
    TP_CALLBACK_ENVIRON env_{};
    bool started_{false};
    std::unordered_map<std::string, std::unique_ptr<RegWatch>> watches_;
};

} // namespace

std::unique_ptr<ISparkMechanism> make_registry_mechanism() {
    return std::make_unique<WindowsRegistryMechanism>();
}

} // namespace yuzu::agent

#else // ── Non-Windows: registry-change spark is Windows-only ─────────────────

namespace yuzu::agent {

std::unique_ptr<ISparkMechanism> make_registry_mechanism() {
    return nullptr; // no mechanism → SparkEngine rejects arm(Registry) off Windows
}

} // namespace yuzu::agent

#endif // _WIN32
