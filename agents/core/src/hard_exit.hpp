#pragma once

/// @file hard_exit.hpp
/// The single shared "leave now, no unwinding" primitive (ADR-0021 rung 7.6,
/// the F3 orphan-exit obligation - see guardian_io_executor.hpp's "ORPHAN
/// PROCESS-EXIT CONTRACT"). main.cpp's signal handlers already needed this
/// exact `#ifdef _WIN32 TerminateProcess #else _exit #endif` pattern twice
/// before this file existed; extracted here so a third call site (the F3
/// orphan-worker check) doesn't duplicate it a third time, and so
/// service_win.cpp's SCM path can share it too.
///
/// WHY TerminateProcess, NOT ::_exit(), ON WINDOWS: ::_exit() routes through
/// ExitProcess, which runs DLL_PROCESS_DETACH for every loaded plugin DLL -
/// taking the loader lock a wedged thread may already hold. TerminateProcess
/// runs no DllMain and takes no loader lock.
///
/// WHY ::_exit(), NOT std::exit(), ON POSIX: exit_group(2) is async-signal-
/// safe - no atexit handlers, no static/DSO destructors, cannot block. That
/// is the entire point: a caller reaching for hard_exit() has already decided
/// normal C++ teardown is not safe to run (a wedged shutdown, or - F3 - a
/// detached Guardian I/O worker that may still be executing library code
/// through it).
#include <chrono>
#include <cstdlib>
#include <functional>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace yuzu::agent {

/// Terminates the process immediately: no unwinding, no atexit handlers, no
/// static/DSO destructors. `code` should be nonzero for every F3/orphan-
/// triggered call so systemd Restart=/Docker/the Windows SCM see a real
/// failure instead of a silently-successful shutdown - a hard_exit() during
/// what would otherwise be a clean run() return must never look like
/// EXIT_SUCCESS. Not marked [[noreturn]]: TerminateProcess's declared return
/// type does not let the compiler prove that on Windows, and main.cpp's
/// existing call sites (predating this header) rely on the same plain-void
/// shape.
inline void hard_exit(int code) noexcept {
#ifdef _WIN32
    ::TerminateProcess(::GetCurrentProcess(), code);
#else
    ::_exit(code);
#endif
}

/// Polls `active_workers()` until it reports zero or `grace` elapses. Returns
/// true iff it reached zero within the grace period - the pure, testable
/// half of the F3 orphan-exit obligation. The caller decides what "still
/// nonzero after grace" means; main()/service_win.cpp call hard_exit() with a
/// nonzero code rather than let normal process exit run C++ teardown
/// concurrently with a still-running detached I/O worker.
inline bool wait_for_workers_to_drain(const std::function<std::size_t()>& active_workers,
                                      std::chrono::milliseconds grace,
                                      std::chrono::milliseconds poll_interval =
                                          std::chrono::milliseconds(20)) {
    const auto deadline = std::chrono::steady_clock::now() + grace;
    while (active_workers() > 0) {
        if (std::chrono::steady_clock::now() >= deadline)
            return false;
        std::this_thread::sleep_for(poll_interval);
    }
    return true;
}

} // namespace yuzu::agent
