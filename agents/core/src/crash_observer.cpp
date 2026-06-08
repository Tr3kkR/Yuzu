#include <yuzu/agent/crash_observer.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::agent {

// ── Pure, cross-platform helpers ─────────────────────────────────────────────
// Defined unconditionally (no windows.h) so the fiddly parsing is unit-testable
// on every platform, even though real data only flows on Windows.

std::string symbolic_exception_name(std::uint32_t code) {
    switch (code) {
    case 0x80000003: return "BREAKPOINT";
    case 0xC0000005: return "ACCESS_VIOLATION";
    case 0xC000001D: return "ILLEGAL_INSTRUCTION";
    case 0xC0000025: return "NONCONTINUABLE_EXCEPTION";
    case 0xC0000026: return "INVALID_DISPOSITION";
    case 0xC000008C: return "ARRAY_BOUNDS_EXCEEDED";
    case 0xC000008E: return "FLOAT_DIVIDE_BY_ZERO";
    case 0xC0000094: return "INTEGER_DIVIDE_BY_ZERO";
    case 0xC0000095: return "INTEGER_OVERFLOW";
    case 0xC0000096: return "PRIVILEGED_INSTRUCTION";
    case 0xC00000FD: return "STACK_OVERFLOW";
    case 0xC0000374: return "HEAP_CORRUPTION";
    case 0xC0000409: return "STACK_BUFFER_OVERRUN";
    case 0xC000041D: return "FATAL_USER_CALLBACK_EXCEPTION";
    case 0xC0000602: return "FAIL_FAST_EXCEPTION"; // __fastfail
    // 0xE0434352 is NOT an NTSTATUS CPU fault — it is the software SEH code the CLR
    // raises when a managed (.NET) exception escapes. Mapping it makes a paired .NET
    // crash (logged as a generic native 1000) legible; the rich managed type/stack
    // lives only in the .NET Runtime 1026 event (a deferred follow-up). See memory
    // project-guardian-process-spark-slices.
    case 0xE0434352: return "CLR_EXCEPTION";
    default: return "";
    }
}

namespace {

std::uint32_t parse_hex_u32(const std::string& s) {
    if (s.empty()) return 0;
    try {
        return static_cast<std::uint32_t>(std::stoul(s, nullptr, 16)); // tolerates "0x" prefix
    } catch (...) {
        return 0; // malformed field — leave default rather than throw
    }
}

std::string lookup_field(const std::vector<std::pair<std::string, std::string>>& fields,
                         std::string_view name) {
    for (const auto& [k, v] : fields)
        if (k == name)
            return v;
    return {};
}

} // namespace

CrashObservation
parse_application_error(const std::vector<std::pair<std::string, std::string>>& f) {
    CrashObservation o;
    o.platform = "windows";
    o.process_name = lookup_field(f, "AppName");
    o.faulting_module = lookup_field(f, "ModuleName");
    o.termination.kind = "exception";
    o.termination.code = parse_hex_u32(lookup_field(f, "ExceptionCode"));
    o.termination.symbolic = symbolic_exception_name(o.termination.code);
    o.pid = parse_hex_u32(lookup_field(f, "ProcessId")); // e.g. "0x297c"
    o.image_path = lookup_field(f, "AppPath");
    return o;
}

std::vector<std::pair<std::string, std::string>> extract_named_data(const std::string& xml) {
    std::vector<std::pair<std::string, std::string>> fields;
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

} // namespace yuzu::agent

// ── Platform collector ───────────────────────────────────────────────────────

#if defined(_WIN32)

#include "guard_win_handle.hpp" // ScopedWinHandle + <windows.h>, EventHandle

#include <winevt.h>

#include <condition_variable>
#include <cstdint>
#include <mutex>

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

std::string wide_to_utf8(const wchar_t* w) {
    if (!w) return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {}; // n counts the NUL; <=1 means empty
    std::string out(static_cast<std::size_t>(n - 1), '\0');
    // Pass the full size `n` (content + NUL): out.data()[n-1] is the std::string's
    // own writable NUL slot. The house pattern everywhere else (process_enum,
    // hardware_plugin, …) is allocate len-1, pass len — match it.
    ::WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), n, nullptr, nullptr);
    return out;
}

// Render the event to XML, then split out the named <Data> fields via the pure,
// cross-platform extract_named_data() (tested off Windows against a real record).
std::vector<std::pair<std::string, std::string>> render_event_data(EVT_HANDLE event) {
    DWORD used = 0, props = 0;
    // First call sizes the buffer (used = bytes needed; expected to fail with
    // ERROR_INSUFFICIENT_BUFFER).
    ::EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &used, &props);
    if (used == 0) return {};
    std::wstring buf(used / sizeof(wchar_t) + 1, L'\0');
    if (!::EvtRender(nullptr, event, EvtRenderEventXml, used, buf.data(), &used, &props))
        return {};
    return extract_named_data(wide_to_utf8(buf.c_str()));
}

std::int64_t now_unix() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

/// Windows fleet-wide crash collector. An async push EvtSubscribe to
/// Application/1000 ("Application Error"): Windows invokes our callback on a
/// threadpool thread for each matching event — and for subscription ERRORS, which
/// the signal-event pull model silently swallowed. Idle-until-crash: the XPath
/// query filters kernel-side, so the callback fires only on a real crash report,
/// NOT a process-exit firehose.
///
/// Lifetime (the hard part). A threadpool callback can run concurrently with — and,
/// per the API contract, even AFTER — stop()/destruction: EvtClose gives NO
/// documented guarantee that it cancels an already-dispatched callback or blocks
/// until one returns. So the shared state (mutex/cv/sink/flags) lives in a heap
/// `State` owned by a shared_ptr, and the EvtSubscribe context is a heap
/// `shared_ptr<State>` that is intentionally LEAKED on success — one small, bounded
/// leak per process (the agent arms once). That keeps `State` alive forever, so a
/// late callback always dereferences live memory; it then observes `stopping` / a
/// null `sink` and bails without touching the (possibly destroyed) agent. stop()
/// additionally drains in-flight callbacks so a clean shutdown waits for the common
/// case. The callback body is wrapped in catch(...) so no exception unwinds out of
/// the C-ABI trampoline (→ std::terminate), and an RAII guard guarantees the
/// in-flight decrement + notify even if the sink throws.
class WindowsCrashObserver final : public ICrashObserver {
public:
    ~WindowsCrashObserver() override { stop(); }

    bool start(CrashSink sink) override {
        std::lock_guard lk(state_->mu);
        if (sub_) return true; // already armed (idempotent)
        state_->stopping = false;
        state_->sink = std::move(sink);
        const wchar_t* query =
            L"*[System[Provider[@Name='Application Error'] and (EventID=1000)]]";
        // Heap strong-ref handed to EvtSubscribe as the callback context; keeps State
        // alive independent of `this`. Leaked on success (see class note); freed here
        // only when no subscription — hence no callback — is created.
        auto* ctx = new std::shared_ptr<State>(state_);
        EVT_HANDLE h = ::EvtSubscribe(nullptr, nullptr, L"Application", query, nullptr, ctx,
                                      &WindowsCrashObserver::callback, EvtSubscribeToFutureEvents);
        if (!h) {
            spdlog::warn("crash_observer: EvtSubscribe(Application/1000) failed (gle={})",
                         ::GetLastError());
            delete ctx;
            state_->sink = nullptr;
            return false;
        }
        sub_.reset(h);
        spdlog::info("crash_observer: armed — Application/1000 (Application Error)");
        return true;
    }

    void stop() override {
        {
            std::lock_guard lk(state_->mu);
            state_->stopping = true;
        }
        // EvtClose stops further delivery. OUTSIDE mu (it may block on an in-flight
        // callback that needs mu). The leaked ctx is deliberately NOT freed — a
        // callback dispatched-but-not-entered before EvtClose could still deref it.
        sub_.reset();
        std::unique_lock lk(state_->mu);
        state_->cv.wait(lk, [this] { return state_->in_flight == 0; });
        state_->sink = nullptr;
    }

private:
    struct State {
        std::mutex mu;
        std::condition_variable cv;
        int in_flight = 0;
        bool stopping = false;
        CrashSink sink; // guarded by mu
    };

    static DWORD WINAPI callback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID ctx, EVT_HANDLE event) {
        // Copy the strong ref first so State cannot die under us mid-callback.
        const std::shared_ptr<State> state = *static_cast<std::shared_ptr<State>*>(ctx);
        if (action == EvtSubscribeActionError) {
            // For the error action `event` carries the status code, not a handle.
            spdlog::warn("crash_observer: subscription error (status={})",
                         static_cast<unsigned long>(reinterpret_cast<std::uintptr_t>(event)));
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
        CrashSink s;
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
        // Render + parse + emit OUTSIDE the lock (the sink does a network write).
        CrashObservation obs = parse_application_error(render_event_data(event));
        obs.timestamp_unix = now_unix(); // report is near-real-time
        spdlog::info("crash_observer: observed crash proc='{}' pid={} code=0x{:08X} {}",
                     obs.process_name, obs.pid, obs.termination.code, obs.termination.symbolic);
        s(obs);
    }

    std::shared_ptr<State> state_ = std::make_shared<State>();
    detail::EvtSubHandle sub_;
};

} // namespace
} // namespace yuzu::agent

#else // !_WIN32 — no-op until the Linux/macOS collector slices land

namespace yuzu::agent {
namespace {
class NoopCrashObserver final : public ICrashObserver {
public:
    bool start(CrashSink) override { return false; } // never armed off-Windows
    void stop() override {}
};
} // namespace
} // namespace yuzu::agent

#endif

namespace yuzu::agent {

std::unique_ptr<ICrashObserver> make_crash_observer() {
#if defined(_WIN32)
    return std::make_unique<WindowsCrashObserver>();
#else
    return std::make_unique<NoopCrashObserver>();
#endif
}

} // namespace yuzu::agent
