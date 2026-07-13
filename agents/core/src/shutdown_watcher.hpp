#pragma once

/// @file shutdown_watcher.hpp
/// The agent's POSIX shutdown self-pipe: a signal handler writes ONE byte; a dedicated
/// watcher thread wakes and runs the real teardown.
///
/// WHY IT IS IN A HEADER, not buried in main.cpp. An earlier version of this lived in
/// main.cpp, so the unit test could only RE-IMPLEMENT the pipe ("build it the same way the
/// watcher does") and pin a COPY. That copy passed while the real code was broken: the real
/// `pipe2()` call carried `O_CLOEXEC | O_NONBLOCK`, which sets O_NONBLOCK on BOTH ends, so
/// the watcher's blocking read() returned EAGAIN, the thread exited within microseconds, and
/// SIGTERM silently stopped triggering a graceful stop. Nothing looked broken — the process
/// still died via the default disposition. Testing a copy is not testing.
/// (governance Gate-8 cpp-safety.)
///
/// ── WHY THE SELF-PIPE EXISTS AT ALL ──────────────────────────────────────────────
/// The handler used to call `Agent::stop()` inline. stop() takes mutexes, joins worker
/// threads, calls sd_bus_unref (malloc/free) and logs through spdlog — none of which may run
/// in a signal handler. And a process-directed signal lands on an ARBITRARY unmasked thread,
/// so if it landed on a thread stop() JOINS, that join was a SELF-JOIN: std::system_error
/// out of a `noexcept` function -> std::terminate, on SIGTERM. Moving the teardown onto an
/// ordinary thread — one stop() never joins — makes the whole class structurally impossible,
/// and is what let SparkEngine delete its entire signal-mitigation layer.
///
/// ── FIVE TRAPS. All hit for real by an earlier attempt. Do not "simplify" past them. ──
///   1. A bare joinable std::thread in main's scope: `agent->run()` is NOT wrapped in a try
///      at its call site, so a throw unwinds past it -> ~std::thread on a joinable thread ->
///      std::terminate. Hence RAII, declared AFTER the Agent so it is destroyed FIRST.
///   2. A throw from the CONSTRUCTOR BODY skips the destructor. std::thread's ctor throws
///      std::system_error under EAGAIN — on exactly the thread-exhausted host this is meant
///      to survive. RAII does not save you; the ctor must clean up by hand.
///   3. `pipe2(fds, O_CLOEXEC | O_NONBLOCK)` sets O_NONBLOCK on BOTH ends, so the watcher's
///      read() returns EAGAIN immediately and it exits at once. O_NONBLOCK belongs on the
///      WRITE end ONLY (so the handler can never block); the READ end must BLOCK.
///   4. Without O_CLOEXEC both fds are inherited by every popen()/fork+exec child — the
///      trigger engine plus the ioc / firewall / services / software_actions / wol /
///      license_scan plugins — handing every subprocess a lever to shut the agent down.
///   5. Closing the read end while the write end lives makes any late write raise SIGPIPE,
///      whose disposition here is SIG_DFL: it KILLS the agent (exit 141). The fds are never
///      closed; two held to process exit is the correct trade.
///
/// AND: if construction fails, `ok()` is false and the caller MUST NOT install the signal
/// handlers — otherwise the handler catches the signal, finds no pipe, returns, and the
/// signal is SWALLOWED with no default disposition left, so SIGTERM stops working entirely.
///
/// ESCALATION IS THE HANDLER'S JOB, NOT THE WATCHER'S. The watcher's callback runs
/// Agent::stop(), which BLOCKS until teardown completes — so the watcher cannot read a second
/// byte while a teardown is wedged, which is precisely when escalation is needed. (stop()
/// drains guardian_/dex_observer_ with an UNBOUNDED wait, so a stuck worker can hang shutdown
/// indefinitely.) The SECOND signal is therefore handled in on_signal itself, which calls
/// _exit() — async-signal-safe, and the only thing that can still act once the watcher is
/// parked inside a stuck stop().

#ifndef _WIN32

#include <spdlog/spdlog.h>

#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <thread>
#include <unistd.h>

namespace yuzu::agent {

class ShutdownWatcher {
public:
    static constexpr char kSignal = 1; ///< written by the signal handler: tear the agent down
    static constexpr char kQuit = 0;   ///< written by the destructor: just retire

    /// `wfd_slot` is the atomic the signal handler reads the write-fd from (it must be
    /// lock-free — assert that at the definition site). `on_shutdown` runs on the watcher
    /// thread, an ORDINARY thread, so it may lock, join, allocate and log freely. It is
    /// called at most once. If it returns false the watcher keeps waiting — used when the
    /// Agent is not published yet, so a signal arriving during boot cannot CONSUME the
    /// watcher and leave every later signal a no-op.
    ShutdownWatcher(std::atomic<int>& wfd_slot, std::function<bool()> on_shutdown)
        : wfd_slot_{wfd_slot} {
        // Trap 4: O_CLOEXEC on both ends. Trap 3: O_NONBLOCK on the WRITE end ONLY.
#ifdef __linux__
        if (::pipe2(fds_, O_CLOEXEC) != 0) {
#else
        if (::pipe(fds_) != 0) {
#endif
            const int err = errno;
            fds_[0] = fds_[1] = -1;
            // Route through degrade() so it really IS the single "we could not build a watcher"
            // exit — a previous comment here CLAIMED it was while this branch quietly did its
            // own thing. (No fd is open on this path, so degrade() only retracts the slot.)
            // (governance Gate-8 round 9 cpp-safety.)
            degrade();
            spdlog::warn("could not create the shutdown pipe ({})", std::strerror(err));
            return;
        }
#ifndef __linux__
        // macOS has no pipe2, so CLOEXEC is set after the fact and a fork/exec racing this
        // window still inherits the fds — precisely why pipe2 exists. Check the results: a
        // silently-failed F_SETFD restores the subprocess-inherit lever it exists to remove.
        if (::fcntl(fds_[0], F_SETFD, FD_CLOEXEC) < 0 ||
            ::fcntl(fds_[1], F_SETFD, FD_CLOEXEC) < 0) {
            spdlog::warn("could not set FD_CLOEXEC on the shutdown pipe ({}) — the fds will be "
                         "inherited by child processes",
                         std::strerror(errno));
        }
#endif
        const int wfl = ::fcntl(fds_[1], F_GETFL);
        if (wfl < 0 || ::fcntl(fds_[1], F_SETFL, wfl | O_NONBLOCK) < 0) {
            spdlog::warn("could not set O_NONBLOCK on the shutdown pipe's write end ({}) — a "
                         "signal handler could block on a full pipe",
                         std::strerror(errno));
        }

        wfd_slot_.store(fds_[1], std::memory_order_release);

        // Trap 2: a throw from HERE (std::thread's ctor, EAGAIN) means the destructor never
        // runs, so RAII cannot save us — clean up by hand and degrade.
        try {
            thread_ = std::thread([rfd = fds_[0], cb = std::move(on_shutdown)] {
                for (;;) {
                    char byte = 0;
                    ssize_t n = 0;
                    do {
                        n = ::read(rfd, &byte, 1); // BLOCKS — trap 3
                    } while (n < 0 && errno == EINTR);
                    if (n != 1 || byte == kQuit)
                        return; // normal exit or EOF — teardown is the main thread's job
                    if (cb && cb())
                        return; // teardown ran (it BLOCKS until complete); nothing more to do
                    // cb() said "not yet" (the Agent is not published): keep waiting rather
                    // than being consumed, or every LATER signal becomes a silent no-op.
                }
            });
        } catch (const std::exception& e) {
            degrade();
            spdlog::warn("could not start the shutdown watcher ({})", e.what());
        } catch (...) {
            // Degrading is this class's whole purpose, and a throw escaping a CONSTRUCTOR BODY
            // skips the destructor (trap 2) — so nothing may escape, not even a non-std throw.
            // std::thread only throws std::system_error today, but a caller-supplied
            // std::function copy could throw anything. (Gate-8 round 7 cpp-expert S-3.)
            degrade();
            spdlog::warn("could not start the shutdown watcher (unknown exception)");
        }
    }

    ~ShutdownWatcher() {
        if (fds_[1] >= 0 && thread_.joinable()) {
            wfd_slot_.store(-1, std::memory_order_release);
            // THE JOIN BELOW DEPENDS ON THIS BYTE LANDING. The watcher is parked in a BLOCKING
            // read(); if the sentinel is lost, join() never returns and the agent hangs at
            // exit — the very failure this class exists to prevent, moved to the last line.
            // The write end is O_NONBLOCK, so retry EINTR/EAGAIN rather than discarding the
            // result as an earlier version did. (Gate-8 round 7 cpp-expert S-2.)
            const char quit = kQuit;
            bool retired = false;
            // Captured at the point of failure. Reading errno AFTER the loop would read it
            // after std::this_thread::yield() (sched_yield) and a loop re-test — and POSIX
            // permits a SUCCESSFUL call to set errno — so the diagnostic could name the wrong
            // error on precisely the path whose only purpose is diagnosis.
            // (governance Gate-8 round 9 cpp-safety.)
            int last_err = 0;
            bool stayed_full = false;
            for (int attempt = 0; attempt < 1000 && !retired; ++attempt) {
                const ssize_t n = ::write(fds_[1], &quit, 1);
                if (n == 1) {
                    retired = true;
                    break;
                }
                last_err = (n < 0) ? errno : 0;
                if (last_err == EINTR)
                    continue; // interrupted before writing — retry immediately
                if (last_err == EAGAIN) {
                    // Pipe full: the watcher has not drained it yet. It is alive and WILL
                    // wake, so yield and retry rather than spin.
                    stayed_full = true;
                    std::this_thread::yield();
                    continue;
                }
                stayed_full = false;
                break; // unrecoverable — fall through to the detach below
            }
            // EVERY WAY OUT OF THAT LOOP THAT DID NOT DELIVER THE BYTE ENDS HERE — the
            // unrecoverable error AND the 1000-attempt exhaustion. An earlier version handled
            // only the error and let exhaustion fall through to the join() below, which is the
            // one exit that cannot complete: the watcher is parked in a BLOCKING read() we can
            // no longer wake, so join() would hang process exit forever — the exact failure
            // this class exists to prevent, at the last line. Exhaustion is unreachable today
            // (64 KiB pipe; the second-signal _exit() caps the queue at one byte) but its
            // safety depended on an invariant in ANOTHER FILE, which is not a safety argument.
            // (governance Gate-8 round 8: cpp-safety + unhappy-path UP8-3, found independently.)
            //
            // DETACH IS SAFE HERE — but not for the reason an earlier comment gave. It claimed
            // "no byte can arrive because wfd_slot_ is already -1". That is wrong: a handler
            // that loaded the fd BEFORE the store(-1) above can still write() afterwards, and
            // the byte lands. The real invariant is that the callback is safe to run late:
            // main's is capture-free and g_agent is already null by then. THE CALLBACK MUST NOT
            // CAPTURE ANYTHING THAT CAN DIE — the tests' `[&]` lambdas would be a use-after-free
            // if this path were ever reachable from them (it is not: we own both fds and never
            // close them, so write() cannot fail with anything but EINTR/EAGAIN).
            // (governance Gate-8 round 8 cpp-safety.)
            if (!retired) {
                // The exhaustion case reports EAGAIN, so a bare `last_err ? strerror : "full"`
                // could never print the full-pipe message it named. Distinguish them properly —
                // another string that asserted a case it did not cover. (Gate-8 round 10.)
                spdlog::warn("could not retire the shutdown watcher ({}) — detaching it rather "
                             "than blocking process exit on a join that cannot complete",
                             stayed_full ? "pipe stayed full after 1000 attempts"
                                         : std::strerror(last_err));
                thread_.detach();
                return;
            }
        }
        if (thread_.joinable())
            thread_.join();
        // THE FDS ARE DELIBERATELY NOT CLOSED. A signal may be in flight: a handler could
        // already have loaded the fd and be about to write(). Closing here would let that
        // write land in a RECYCLED descriptor — an SQLite file, a gRPC socket — belonging to
        // a thread still running during teardown. Two fds held to process exit is the
        // correct trade, and the standard self-pipe answer.
    }

    /// TRUE iff the watcher thread is actually running. If FALSE the caller MUST NOT install
    /// the signal handlers — see the header note (a swallowed signal leaves the agent
    /// unkillable by SIGTERM).
    [[nodiscard]] bool ok() const { return thread_.joinable(); }

    [[nodiscard]] int read_fd_for_test() const { return fds_[0]; }
    [[nodiscard]] int write_fd_for_test() const { return fds_[1]; }

    ShutdownWatcher(const ShutdownWatcher&) = delete;
    ShutdownWatcher& operator=(const ShutdownWatcher&) = delete;

private:
    /// The CONSTRUCTOR'S FAILURE PATH ONLY. Retract the fd from the handler's slot, then close
    /// both ends.
    ///
    /// Closing the fds is safe ONLY here — where the thread never started, so `ok()` is false
    /// and main leaves SIG_DFL standing, meaning no handler exists to write into a recycled
    /// descriptor (trap 5). Call it on a LIVE watcher and it is a guaranteed hang: closing an
    /// fd does not wake a thread already blocked in read(), the destructor then sees
    /// `fds_[1] < 0`, skips the kQuit write entirely, and joins a thread that can never be
    /// woken — the agent never exits. It was briefly public with only a comment to protect it,
    /// which is the shape of nearly every bug on this branch: a method safe on exactly one
    /// path, guarded by prose.
    /// (governance Gate-8 round 8: cpp-safety + unhappy-path UP8-2, found independently.)
    ///
    /// WHAT ACTUALLY ENFORCES THE PRECONDITION is that this is PRIVATE with exactly three call
    /// sites — the pipe()-failure branch and the two ctor catch blocks — in every one of which
    /// `thread_` is provably not joinable. NOT the assert below: that is compiled out under
    /// NDEBUG, i.e. in every release build. It documents the contract and catches a mistake in
    /// debug; it does not enforce anything in production. Do not add a call site on the
    /// strength of it. (governance Gate-8 round 9 cpp-safety.)
    void degrade() noexcept {
        assert(!thread_.joinable() && "degrade() on a live watcher would hang the agent at exit");
        wfd_slot_.store(-1, std::memory_order_release);
        for (int& fd : fds_) {
            if (fd >= 0) {
                ::close(fd);
                fd = -1;
            }
        }
    }

    std::atomic<int>& wfd_slot_;
    int fds_[2]{-1, -1};
    std::thread thread_;
};

} // namespace yuzu::agent

#endif // !_WIN32
