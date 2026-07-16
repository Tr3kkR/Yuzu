#ifdef _WIN32

#include "service_win.hpp"

#include "hard_exit.hpp" // shared TerminateProcess + F3 orphan-drain poll (rung 7.6)

#include <yuzu/agent/agent.hpp>

#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <mutex>

namespace {

using yuzu::agent::Agent;

// SERVICE_TABLE_ENTRYW's ServiceMain callback takes no user context parameter, so
// the factory and mutable service state are process-global. This is fine: a given
// process hosts exactly one service (SERVICE_WIN32_OWN_PROCESS), so there is only
// ever one ServiceMain/handler pair alive. Plain (not atomic/mutex-guarded)
// because the only write happens in run_service() strictly before it calls
// StartServiceCtrlDispatcherW, and the only read happens in service_main() on the
// thread the SCM spawns as a *result* of that same call -- Windows thread
// creation provides the needed happens-before edge (unlike g_status_handle
// below, which is genuinely read/written from two independently-running,
// concurrently-active threads once the service is up).
std::move_only_function<std::unique_ptr<Agent>()> g_factory;

// atomic, not a plain pointer guarded by g_status_mu below: it's published once
// by RegisterServiceCtrlHandlerExW's return and then only ever READ by
// report_status() -- an unlocked write racing report_status()'s locked read
// under the C++ memory model is a data race even though it's single-writer and
// practically benign (Gate-2 finding, #1822).
std::atomic<SERVICE_STATUS_HANDLE> g_status_handle{nullptr};
// Guards both the SetServiceStatus call and the checkpoint counter: the control
// handler (SCM-invoked, its own thread) and ServiceMain can both report status
// concurrently -- e.g. a STOP arriving while ServiceMain is still transitioning
// out of START_PENDING/RUNNING -- so report_status() is not naturally single-
// threaded despite the state machine looking sequential on paper.
std::mutex g_status_mu;
DWORD g_checkpoint = 0; // guarded by g_status_mu; monotonic within a pending phase

std::mutex g_agent_mu;
Agent* g_agent = nullptr; // guarded by g_agent_mu; non-owning, published by ServiceMain
std::atomic<bool> g_stop_requested{false};

void report_status(DWORD current_state, DWORD win32_exit_code = NO_ERROR,
                    DWORD specific_exit_code = 0, DWORD wait_hint = 0) {
    std::lock_guard<std::mutex> lock(g_status_mu);

    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = current_state;
    status.dwWin32ExitCode = win32_exit_code;
    status.dwServiceSpecificExitCode = specific_exit_code;
    status.dwWaitHint = wait_hint;

    switch (current_state) {
    case SERVICE_START_PENDING:
    case SERVICE_STOP_PENDING:
        // No controls accepted while pending: MSDN requires it for START_PENDING,
        // and clearing it for STOP_PENDING means a duplicate STOP/SHUTDOWN control
        // simply isn't delivered again, instead of hitting the handler mid-teardown.
        status.dwControlsAccepted = 0;
        status.dwCheckPoint = ++g_checkpoint;
        break;
    case SERVICE_RUNNING:
        status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        status.dwCheckPoint = 0;
        g_checkpoint = 0;
        break;
    default: // SERVICE_STOPPED
        status.dwControlsAccepted = 0;
        status.dwCheckPoint = 0;
        break;
    }

    if (auto handle = g_status_handle.load(std::memory_order_acquire))
        SetServiceStatus(handle, &status);
}

// noexcept for the same reason as service_main: a raw WINAPI callback the SCM
// invokes directly must not let an exception (however unlikely -- only source
// here is std::mutex::lock inside report_status()/this function) cross that C
// ABI boundary as UB; noexcept converts it into a defined std::terminate instead.
DWORD WINAPI handler_ex(DWORD control, DWORD /*event_type*/, LPVOID /*event_data*/,
                         LPVOID /*context*/) noexcept {
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        g_stop_requested.store(true, std::memory_order_relaxed);
        // 30s to match the START_PENDING hint; Agent::stop() itself is
        // non-blocking (sets flags, TryCancels in-flight stream writes), so
        // teardown is bounded well under that -- no checkpoint-bumping thread
        // needed for a single-shot pending report.
        report_status(SERVICE_STOP_PENDING, NO_ERROR, 0, 30000);
        {
            std::lock_guard<std::mutex> lock(g_agent_mu);
            if (g_agent)
                g_agent->stop();
        }
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        // The SCM already has our most recent SetServiceStatus report; nothing to
        // resend.
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

// Clears the published g_agent pointer on destruction, under g_agent_mu.
// service_main declares its unique_ptr<Agent>, THEN this guard: C++ destroys
// locals in reverse declaration order, so the guard fires -- unpublishing
// g_agent -- before the unique_ptr's own destructor runs, on EVERY exit path
// (normal return, exception unwind, everything). Without this, a manual
// "clear g_agent" statement placed only after a (fallible) agent->run() call
// only runs on the happy path; a SERVICE_CONTROL_STOP delivered on the SCM
// control-handler thread during exception unwind would see a stale non-null
// g_agent and call stop() on an already-destructing/destructed Agent (Gate-2
// finding, #1822).
struct AgentUnpublisher {
    ~AgentUnpublisher() {
        std::lock_guard<std::mutex> lock(g_agent_mu);
        g_agent = nullptr;
    }
};

void WINAPI service_main(DWORD, LPWSTR*) noexcept {
    // The try opens here, before RegisterServiceCtrlHandlerExW, not just around
    // the agent construction/run() below: spdlog::error/report_status (fmt
    // formatting, std::mutex::lock) are not statically noexcept, and nothing
    // may cross this raw WINAPI callback boundary uncaught (Gate-2 re-review
    // follow-up, #1822) -- even in this narrow pre-Agent window.
    try {
        auto handle =
            RegisterServiceCtrlHandlerExW(yuzu::agent::win::kServiceName, handler_ex, nullptr);
        if (!handle) {
            spdlog::error("RegisterServiceCtrlHandlerExW failed: {}", GetLastError());
            return;
        }
        g_status_handle.store(handle, std::memory_order_release);

        report_status(SERVICE_START_PENDING, NO_ERROR, 0, 30000);

        // No checkpoint-bumping thread runs during this call because it's cheap
        // today (make_agent() in main.cpp: an in-process flag check, one small
        // SQLite open/write, and a trivial in-memory constructor -- the real
        // startup cost, plugin load and KV/TAR store open, is deliberately deferred
        // into agent->run() below, past the RUNNING report). If a future change
        // ever moves real work into the factory ahead of run(), this single
        // 30s-hint START_PENDING report stops being long enough and needs either a
        // periodic checkpoint bump or a longer hint (Gate 6 sre finding, governance
        // re-run).
        auto agent = g_factory ? g_factory() : nullptr;
        if (!agent) {
            spdlog::critical(
                "Agent factory failed under SCM startup -- reporting service failure");
            report_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, /*specific=*/1);
            return;
        }

        // Constructed here, BEFORE g_agent is published below, so the "guard exists"
        // invariant is structural rather than resting on every statement between
        // publish and construction happening to be non-throwing today (it is, but a
        // future edit inserting a throwing statement in that window would otherwise
        // silently reopen the pre-#1822 UAF gap this guard exists to close --
        // Gate 3 cpp-safety hardening, governance re-run). `agent` is still declared
        // first, so reverse-declaration-order destruction still runs this guard
        // before `agent`'s own destructor on every exit path below.
        AgentUnpublisher unpublisher;

        bool stop_already_requested = false;
        {
            std::lock_guard<std::mutex> lock(g_agent_mu);
            g_agent = agent.get();
            // Catch up on a SERVICE_CONTROL_STOP that arrived while g_factory()
            // was still running: handler_ex would have found g_agent==nullptr
            // (not yet published) and silently skipped calling stop(), which --
            // left unhandled -- would let the service unconditionally report
            // RUNNING below and un-stop itself from the SCM's perspective (Gate-4
            // UP-1). Both this check and handler_ex's read of g_agent are under
            // the same g_agent_mu, so the two can't both miss each other: either
            // handler_ex sees the just-published pointer and stops it directly,
            // or it ran first and set g_stop_requested, which we observe here.
            stop_already_requested = g_stop_requested.load(std::memory_order_relaxed);
            if (stop_already_requested)
                g_agent->stop();
        }

        // Report RUNNING now, before run() -- run()'s reconnect loop is unbounded
        // while the server is unreachable (agent.cpp), so waiting for it to return
        // would itself time out the SCM start (parity with the systemd
        // Type=simple unit, which has no readiness protocol either). Skipped if a
        // stop already landed above: the last report the SCM should see before
        // STOPPED is handler_ex's STOP_PENDING, not a RUNNING that immediately
        // reverses it.
        if (!stop_already_requested)
            report_status(SERVICE_RUNNING);

        agent->run(); // blocks until stop() (via handler_ex, or the catch-up above) or a fatal startup error

        spdlog::default_logger()->flush();

        // AN EXPLICIT OPERATOR STOP ALWAYS WINS, AND IT IS TESTED FIRST.
        //
        // A `sc stop` can RACE a fatal failure (a dispatch-pool re-creation that fails on the
        // reconnect path at the same moment). With the failure tested first, we would report a
        // service-specific error -- and because --install-service sets
        // SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, the SCM would then run its recovery actions and
        // RESTART THE SERVICE THE OPERATOR JUST STOPPED. An explicit stop is the one signal that is
        // unambiguously intentional; it must never be overridden by a failure that arrived with it.
        // (governance: unhappy-path B-7.)
        if (g_stop_requested.load(std::memory_order_relaxed)) {
            report_status(SERVICE_STOPPED);
        } else if (agent->startup_failed()) {
            // specific=1 now covers TWO causes: a fatal STARTUP failure (agent construction, or the
            // fail-closed TLS posture with no pinnable CA) AND a fatal MID-LIFE failure (the
            // dispatch pool could not be re-created -- host out of threads). Both mean "could not
            // continue", both should run the SCM's recovery actions, and the log file carries the
            // actual reason. Documented in server-admin.md. (governance: consistency-auditor.)
            report_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, /*specific=*/1);
        } else {
            // run() returned on its own, without a STOP/SHUTDOWN control -- unexpected.
            report_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, /*specific=*/2);
        }

        // F3 orphan-exit obligation (ADR-0021 rung 7.6; guardian_io_executor.hpp's
        // "ORPHAN PROCESS-EXIT CONTRACT"), Windows SCM path. Mirrors main.cpp's
        // console-mode check: a detached Guardian bounded-I/O worker cannot be
        // joined or force-cancelled, so give it a short grace to actually finish
        // before this function returns and the process runs normal C++ teardown.
        //
        // DELIBERATELY AFTER the report_status chain above, not before it: "AN
        // EXPLICIT OPERATOR STOP ALWAYS WINS" (the comment above) must still hold
        // for what the SCM is TOLD, even when an orphan forces a hard exit right
        // after. hard_exit() only sets the process's raw exit code -- it cannot
        // itself call SetServiceStatus -- so the correct status must already be
        // reported before it runs, never after (Sol rung-7.6 review finding 3).
        {
            // Force synchronization against a possibly-still-in-flight handler_ex
            // or the catch-up block above: stop_requested_ is stop()'s FIRST
            // statement, so run()'s reconnect loop can return before stop()'s
            // LATER steps (guardian_->stop(), dex_observer_->stop()) have actually
            // completed. Both call sites hold g_agent_mu across their entire
            // stop() call; re-acquiring it here blocks until any in-flight call
            // has fully returned before the orphan count below is sampled -
            // otherwise a zero count is meaningless (Sol rung-7.6 review finding
            // 1 - mirrors main.cpp's console-path fix).
            std::lock_guard<std::mutex> lock(g_agent_mu);
        }
        if (const auto n = agent->guardian_active_io_workers(); n > 0) {
            constexpr auto kOrphanDrainGrace = std::chrono::seconds(3);
            if (!yuzu::agent::wait_for_workers_to_drain(
                    [&] { return agent->guardian_active_io_workers(); }, kOrphanDrainGrace)) {
                // Firewalled: a logging exception here must never skip hard_exit()
                // below (Sol rung-7.6 review finding 2).
                try {
                    spdlog::critical("{} Guardian I/O worker(s) still active {}s after shutdown - "
                                     "forcing process exit rather than race static/DSO teardown "
                                     "against them",
                                     n, kOrphanDrainGrace.count());
                } catch (...) {
                }
                yuzu::agent::hard_exit(3); // the SCM status above already reported the real outcome
            }
        }
    } catch (const std::exception& e) {
        // service_main is a raw WINAPI callback invoked directly by the SCM
        // dispatcher thread -- an exception must never cross that C ABI boundary
        // (UB / std::terminate). AgentUnpublisher has already run by this point
        // (stack unwind destructs it before this catch runs), so g_agent is safely
        // cleared regardless of where inside the try the throw originated.
        spdlog::critical("Unhandled exception in ServiceMain: {}", e.what());
        report_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, /*specific=*/3);
    } catch (...) {
        spdlog::critical("Unhandled non-standard exception in ServiceMain");
        report_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, /*specific=*/3);
    }
}

} // namespace

namespace yuzu::agent::win {

int run_service(std::move_only_function<std::unique_ptr<Agent>()> factory) {
    g_factory = std::move(factory);

    // const_cast is safe here: SERVICE_TABLE_ENTRYW.lpServiceName is only ever READ
    // by StartServiceCtrlDispatcherW for an OWN_PROCESS service (used to match the
    // ServiceMain callback to a name) -- nothing writes through it, so casting away
    // constness off the constexpr kServiceName array is not UB in practice, just an
    // artifact of the Win32 API predating const-correctness (Gate 3 cpp-safety/
    // cpp-expert finding, governance re-run).
    SERVICE_TABLE_ENTRYW table[] = {
        {const_cast<LPWSTR>(kServiceName), service_main},
        {nullptr, nullptr},
    };

    if (!StartServiceCtrlDispatcherW(table)) {
        auto err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            // This specific error means the process was NOT launched by the SCM --
            // i.e. --service was passed at a real interactive console by mistake --
            // so a console is guaranteed present here. spdlog's stderr sink is
            // suppressed whenever --service is passed (service_mode gates it in
            // main.cpp, since it can't tell "really under the SCM" from "misused at
            // a console" until this exact call fails), so this specific message
            // would otherwise land only in the log file the operator isn't looking
            // at. Print directly so the one case where we KNOW a console exists
            // actually reaches it (Gate 4 unhappy-path finding, governance re-run).
            std::cerr << "--service is for use by the Windows Service Control Manager; "
                         "run without --service for interactive/console mode\n";
            spdlog::error(
                "--service is for use by the Windows Service Control Manager; "
                "run without --service for interactive/console mode");
        } else {
            spdlog::error("StartServiceCtrlDispatcherW failed: {}", err);
        }
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

} // namespace yuzu::agent::win

#endif // _WIN32
