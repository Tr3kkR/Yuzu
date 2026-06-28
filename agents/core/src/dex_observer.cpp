#include <yuzu/agent/dex_observer.hpp>

#include <yuzu/agent/dex_rate_limiter.hpp> // shared per-obs_type hourly cap (Windows + Linux)

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::agent {

// ── Pure, cross-platform helpers ─────────────────────────────────────────────
// Defined unconditionally (no windows.h) so the fiddly parsing is unit-testable
// on every platform, even though real data only flows on Windows.

EventFields extract_named_data(const std::string& xml) {
    EventFields fields;
    std::size_t pos = 0;
    for (;;) {
        const std::size_t open = xml.find("<Data", pos);
        if (open == std::string::npos) break;
        const std::size_t gt = xml.find('>', open);
        if (gt == std::string::npos) break;
        const std::string tag = xml.substr(open, gt - open); // "<Data Name='X'"
        std::string name;
        if (const std::size_t np = tag.find("Name="); np != std::string::npos && np + 5 < tag.size()) {
            const char q = tag[np + 5]; // ' or "
            const std::size_t s = np + 6;
            if (const std::size_t e = tag.find(q, s); e != std::string::npos)
                name = tag.substr(s, e - s);
        }
        if (gt > 0 && xml[gt - 1] == '/') { // <Data .../> self-closing / empty
            fields.emplace_back(std::move(name), std::string{});
            pos = gt + 1;
            continue;
        }
        const std::size_t close = xml.find("</Data>", gt + 1);
        if (close == std::string::npos) break;
        fields.emplace_back(std::move(name), xml.substr(gt + 1, close - (gt + 1)));
        pos = close + 7; // len("</Data>")
    }
    return fields;
}

namespace {

// First attribute value of `attr` inside the first `tag` element ("<Provider
// Name='X'/>" -> "X"). Same tolerant single-pass scan as extract_named_data:
// both quote styles, missing pieces -> "".
std::string first_attr(const std::string& xml, std::string_view tag, std::string_view attr) {
    const std::size_t open = xml.find(std::string("<") + std::string(tag));
    if (open == std::string::npos) return {};
    const std::size_t gt = xml.find('>', open);
    if (gt == std::string::npos) return {};
    const std::string el = xml.substr(open, gt - open);
    const std::string needle = std::string(attr) + "=";
    const std::size_t np = el.find(needle);
    if (np == std::string::npos || np + needle.size() >= el.size()) return {};
    const char q = el[np + needle.size()];
    if (q != '\'' && q != '"') return {};
    const std::size_t s = np + needle.size() + 1;
    const std::size_t e = el.find(q, s);
    if (e == std::string::npos) return {};
    return el.substr(s, e - s);
}

// Text content of the first `tag` element ("<EventID Qualifiers='…'>1000</EventID>"
// -> "1000"). "" when absent / self-closing / unterminated.
std::string first_element_text(const std::string& xml, std::string_view tag) {
    const std::string open_tok = std::string("<") + std::string(tag);
    const std::size_t open = xml.find(open_tok);
    if (open == std::string::npos) return {};
    const std::size_t gt = xml.find('>', open);
    if (gt == std::string::npos || xml[gt - 1] == '/') return {};
    const std::string close_tok = std::string("</") + std::string(tag) + ">";
    const std::size_t close = xml.find(close_tok, gt + 1);
    if (close == std::string::npos) return {};
    return xml.substr(gt + 1, close - (gt + 1));
}

int parse_int_field(const std::string& s) {
    if (s.empty()) return 0;
    try {
        return std::stoi(s);
    } catch (...) {
        return 0; // malformed — default, never throw out of an OS callback
    }
}

} // namespace

EventSystemFields extract_system_fields(const std::string& xml) {
    EventSystemFields f;
    f.provider = first_attr(xml, "Provider", "Name");
    f.event_id = parse_int_field(first_element_text(xml, "EventID"));
    f.level = parse_int_field(first_element_text(xml, "Level"));
    f.channel = first_element_text(xml, "Channel");
    return f;
}

} // namespace yuzu::agent

// ── Platform engine ──────────────────────────────────────────────────────────

#if defined(_WIN32)

#include "guard_win_handle.hpp" // ScopedWinHandle + <windows.h>, EventHandle

#include "dex_win_poll.hpp" // IStatePoller (storage.low / battery state poll)

#include <winevt.h>
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_map>

#include <spdlog/spdlog.h>

#pragma comment(lib, "wevtapi.lib") // EvtSubscribe / EvtRender / EvtClose

namespace yuzu::agent::detail {
// EVT_HANDLE is a HANDLE but must be closed with EvtClose (not CloseHandle), so it
// gets its own ScopedWinHandle specialisation. RAII releases on every exit path.
inline void evt_close_(HANDLE h) { ::EvtClose(h); }
using EvtSubHandle = ScopedWinHandle<&evt_close_>;
} // namespace yuzu::agent::detail

namespace yuzu::agent {
namespace {

// wide_to_utf8 / utf8_to_wide now delegate to the shared agents/shared/win_str.hpp
// helpers (#1681). The removed local copies used the same allocate-(n-1)/pass-n
// idiom (trailing NUL dropped), matching yuzu::win::from_wide / yuzu::win::to_wide
// (both total on null/empty -> {}).
std::string wide_to_utf8(const wchar_t* w) { return yuzu::win::from_wide(w); }
std::wstring utf8_to_wide(const std::string& s) { return yuzu::win::to_wide(s); }

// Render the event to XML once; the pure helpers split out the <System> facts
// and <EventData> fields (both tested off Windows against real records).
std::string render_event_xml(EVT_HANDLE event) {
    DWORD used = 0, props = 0;
    // First call sizes the buffer (used = bytes needed; expected to fail with
    // ERROR_INSUFFICIENT_BUFFER).
    ::EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &used, &props);
    if (used == 0) return {};
    std::wstring buf(used / sizeof(wchar_t) + 1, L'\0');
    if (!::EvtRender(nullptr, event, EvtRenderEventXml, used, buf.data(), &used, &props))
        return {};
    return wide_to_utf8(buf.c_str());
}

std::int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::size_t distinct_obs_types() {
    std::vector<std::string_view> seen;
    for (const auto& s : dex_signal_catalog())
        if (std::find(seen.begin(), seen.end(), s.obs_type) == seen.end())
            seen.emplace_back(s.obs_type);
    return seen.size();
}

/// Windows fleet-wide DEX signal engine. One async push EvtSubscribe PER
/// catalogue channel, each with a kernel-side filtered QueryList — the callback
/// fires only for catalogued events, never a firehose. Per-channel arming gives
/// failure isolation: a channel missing on some SKU (PrintService/Admin on a
/// stripped image) logs a warn and the rest still collect.
///
/// Lifetime (the hard part — inherited verbatim from the governance-hardened
/// slice-1 crash recorder). A threadpool callback can run concurrently with —
/// and, per the API contract, even AFTER — stop()/destruction: EvtClose gives NO
/// documented guarantee that it cancels an already-dispatched callback or blocks
/// until one returns. So the shared state (mutex/cv/sink/flags) lives in a heap
/// `State` owned by a shared_ptr, and each per-channel EvtSubscribe context is a
/// heap `CallbackCtx` holding a strong ref that is intentionally LEAKED on
/// success — a handful of small, bounded leaks per process (the agent arms
/// once). That keeps `State` alive forever, so a late callback always
/// dereferences live memory; it then observes `stopping` / a null `sink` and
/// bails without touching the (possibly destroyed) agent. stop() additionally
/// drains in-flight callbacks so a clean shutdown waits for the common case. The
/// callback body is wrapped in catch(...) so no exception unwinds out of the
/// C-ABI trampoline (→ std::terminate), and an RAII guard guarantees the
/// in-flight decrement + notify even if the sink throws.
///
/// Rate caps: each obs_type carries a max_per_hour in the catalogue; the engine
/// counts per fixed hour-bucket under State::mu and drops the overflow (one WARN
/// per type per bucket — a storming provider must not flood the wire OR the log).
class WindowsDexObserver final : public ISignalObserver {
public:
    ~WindowsDexObserver() override { stop(); }

    bool start(SignalSink sink, std::function<void()> on_error) override {
        std::lock_guard lk(state_->mu);
        if (!subs_.empty()) return true; // already armed (idempotent)
        state_->stopping = false;
        state_->sink = std::move(sink);
        state_->on_error = std::move(on_error);

        int armed = 0;
        for (const auto& channel : dex_channels()) {
            const std::wstring wquery = utf8_to_wide(dex_channel_query(channel));
            // Heap strong-ref handed to EvtSubscribe as the callback context; keeps
            // State alive independent of `this`. Leaked on success (see class note);
            // freed here only when no subscription — hence no callback — is created.
            auto* ctx = new CallbackCtx{state_, channel};
            // Structured QueryList → ChannelPath must be null; the Paths inside the
            // XML select the channel.
            EVT_HANDLE h = ::EvtSubscribe(nullptr, nullptr, nullptr, wquery.c_str(), nullptr, ctx,
                                          &WindowsDexObserver::callback,
                                          EvtSubscribeToFutureEvents);
            if (!h) {
                spdlog::warn("dex_observer: EvtSubscribe({}) failed (gle={}) — channel skipped",
                             channel, ::GetLastError());
                delete ctx;
                continue;
            }
            subs_.emplace_back();
            subs_.back().reset(h);
            ++armed;
        }
        armed_ = armed;
        if (armed == 0) {
            state_->sink = nullptr;
            state_->on_error = nullptr;
            spdlog::warn("dex_observer: no channel armed — DEX signal collection disabled");
            return false;
        }
        // State-poll companion (storage.low / battery): event subscriptions are
        // blind to bad *states* the OS never logs. Started only on successful
        // arm so the start()==false ⇒ nothing-running invariant holds.
        poller_ = win::make_win_state_poller();
        poller_->start(state_->sink);
        spdlog::info("dex_observer: armed — {} channel(s), {} signal type(s) catalogued", armed,
                     distinct_obs_types());
        return true;
    }

    void stop() override {
        {
            std::lock_guard lk(state_->mu);
            state_->stopping = true;
        }
        // The poller owns a plain thread + its own sink copy — join it first so
        // no poll emission can race the teardown below.
        if (poller_) {
            poller_->stop();
            poller_.reset();
        }
        // EvtClose stops further delivery. OUTSIDE mu (it may block on an in-flight
        // callback that needs mu). The leaked ctxs are deliberately NOT freed — a
        // callback dispatched-but-not-entered before EvtClose could still deref them.
        subs_.clear();
        std::unique_lock lk(state_->mu);
        state_->cv.wait(lk, [this] { return state_->in_flight == 0; });
        state_->sink = nullptr;
        state_->on_error = nullptr;
        armed_ = 0;
    }

    int armed_channels() const override { return armed_; }

private:
    struct State {
        std::mutex mu;
        std::condition_variable cv;
        int in_flight = 0;
        bool stopping = false;
        SignalSink sink;                // guarded by mu
        std::function<void()> on_error; // runtime-error handler (UP-1), guarded by mu
        // Shared, pure, cross-collector per-obs_type hourly cap. Guarded by mu (the
        // limiter is single-threaded by contract; mu provides that). Replaces the
        // old inline RateBucket map and unifies the Windows observer onto the same
        // limiter the Linux collector uses.
        DexRateLimiter rate; // guarded by mu
    };

    struct CallbackCtx {
        std::shared_ptr<State> state;
        std::string channel; // which subscription this ctx belongs to (error logs)
    };

    static DWORD WINAPI callback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID ctx, EVT_HANDLE event) {
        // Copy the strong ref first so State cannot die under us mid-callback.
        auto* cb = static_cast<CallbackCtx*>(ctx);
        const std::shared_ptr<State> state = cb->state;
        if (action == EvtSubscribeActionError) {
            // For the error action `event` carries the status code, not a handle.
            spdlog::warn("dex_observer: subscription error on channel '{}' (status={}) — "
                         "channel going deaf",
                         cb->channel,
                         static_cast<unsigned long>(reinterpret_cast<std::uintptr_t>(event)));
            // Signal the owner a subscription died at runtime so it marks the recorder
            // unhealthy (UP-1) — start() succeeded but this channel stops receiving.
            // Copy the handler under mu, call it OUTSIDE mu. The handler is
            // owner-independent (a shared atomic), so a late call during teardown is
            // safe; the `stopping` check just avoids redundant work once stop() began.
            std::function<void()> on_err;
            {
                std::lock_guard lk(state->mu);
                if (!state->stopping)
                    on_err = state->on_error;
            }
            if (on_err) {
                try {
                    on_err();
                } catch (...) {
                }
            }
            return ERROR_SUCCESS;
        }
        try {
            on_event(*state, event);
        } catch (...) {
            // Never let an exception cross the C-ABI threadpool trampoline.
        }
        return ERROR_SUCCESS;
    }

    static void on_event(State& st, EVT_HANDLE event) {
        SignalSink s;
        {
            std::lock_guard lk(st.mu);
            if (st.stopping || !st.sink) return; // tearing down — don't touch a dying sink
            s = st.sink;
            ++st.in_flight;
        }
        // Guarantee the in-flight decrement + notify even if the work below throws,
        // so stop()'s drain can never hang.
        struct InFlightGuard {
            State& st;
            ~InFlightGuard() {
                {
                    std::lock_guard lk(st.mu);
                    --st.in_flight;
                }
                st.cv.notify_all();
            }
        } guard{st};
        // Render + parse + extract OUTSIDE the lock (the sink does a network write).
        const std::string xml = render_event_xml(event);
        const EventSystemFields sys = extract_system_fields(xml);
        auto obs = extract_signal(sys.channel, sys.provider, sys.event_id, sys.level,
                                  extract_named_data(xml));
        if (!obs)
            return; // not a catalogued signal (defensive — the kernel filter should match)
        obs->timestamp_unix = now_unix(); // delivery is near-real-time

        // Per-obs_type hourly cap (shared DexRateLimiter — the Windows observer and
        // the Linux collector both use it). One WARN per (type, hour) so a storm
        // floods neither the wire nor the log.
        RateDecision decision = RateDecision::Emit;
        {
            std::lock_guard lk(st.mu);
            decision = st.rate.check(obs->obs_type, obs->timestamp_unix);
        }
        if (decision == RateDecision::DropAndWarn)
            spdlog::warn("dex_observer: rate cap hit for {} — dropping until the next hour bucket",
                         obs->obs_type);
        if (decision != RateDecision::Emit)
            return; // over cap this hour — suppressed

        spdlog::info("dex_observer: observed {} subject='{}'{}", obs->obs_type, obs->subject,
                     obs->reason.empty() ? std::string{} : " reason=" + obs->reason);
        s(*obs);
    }

    std::shared_ptr<State> state_ = std::make_shared<State>();
    std::vector<detail::EvtSubHandle> subs_;
    std::unique_ptr<win::IStatePoller> poller_; // storage.low / battery state poll
    int armed_{0};
};

} // namespace
} // namespace yuzu::agent

#else // !_WIN32 — no-op until the Linux/macOS collector slices land

namespace yuzu::agent {
namespace {
class NoopDexObserver final : public ISignalObserver {
public:
    bool start(SignalSink, std::function<void()>) override { return false; } // never armed off-Windows
    void stop() override {}
    int armed_channels() const override { return 0; }
};
} // namespace
} // namespace yuzu::agent

#endif

namespace yuzu::agent {

#if defined(__APPLE__)
// Defined in dex_macos_collector.cpp — keeps the kqueue/sysctl mechanism out of
// this TU (and the Windows winevt.h engine out of that one).
std::unique_ptr<ISignalObserver> make_macos_dex_observer();
#elif defined(__linux__)
// Defined in dex_linux_collector.cpp — keeps the /proc poll + statvfs mechanism
// out of this TU (same rationale as the macOS fork).
std::unique_ptr<ISignalObserver> make_linux_dex_observer();
#endif

std::unique_ptr<ISignalObserver> make_dex_observer() {
#if defined(_WIN32)
    return std::make_unique<WindowsDexObserver>();
#elif defined(__APPLE__)
    return make_macos_dex_observer();
#elif defined(__linux__)
    return make_linux_dex_observer();
#else
    return std::make_unique<NoopDexObserver>();
#endif
}

} // namespace yuzu::agent
