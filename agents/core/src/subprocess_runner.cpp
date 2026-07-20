/**
 * subprocess_runner.cpp -- agent-core bounded, fork-safe POSIX subprocess
 * runner (#2273 foundation).
 *
 * Merges two independently hardened bounded-subprocess implementations that
 * grew up in different plugins for the same underlying problem (no
 * built-in timeout on `log show`, `codesign`, `plutil`, and GNU `timeout`
 * is not available on macOS): the event_logs plugin's line-collecting
 * bounded_run() and the filesystem plugin's exit-code/output-capturing
 * run_macos_tool(). Both forked+execed directly (no shell), killed the
 * child's whole process group on a deadline, and reaped it without leaving
 * a zombie behind -- this file is that logic, once, serving both
 * consumption styles (SubprocessResult carries both `lines` and `output`).
 *
 * Fork-safety notes (why the child branch looks the way it does):
 *   - The C-style argv is built entirely in the PARENT, before fork().
 *     Between fork() and execvp() the child may only call async-signal-safe
 *     functions (POSIX 2.4.3) -- allocating via std::vector/std::string
 *     post-fork is unsafe in a multithreaded process, since another thread
 *     can hold the allocator lock at the moment of fork, which the child
 *     inherits already-locked and then deadlocks on.
 *   - Both the output pipe and the exec-error pipe are FD_CLOEXEC on both
 *     ends, so neither leaks into whatever the child execs into.
 *   - Setting FD_CLOEXEC is NOT atomic with pipe() on this platform (no
 *     pipe2()) -- a concurrent fork() on another thread landing between
 *     THIS invocation's pipe() and its fcntl(F_SETFD, FD_CLOEXEC) would
 *     otherwise inherit a not-yet-CLOEXEC write end into an unrelated
 *     child, starving this invocation's own EOF (a false timeout) for as
 *     long as that other child runs. A file-local mutex serializes
 *     [pipe()..fork()] across every invocation to close that window; the
 *     child inherits it already locked and never touches it (see
 *     g_fork_pipe_mutex's comment below).
 *   - The child calls setsid() so a timeout kill can take out the whole
 *     process group, not just the direct child (a CLI can spawn helpers
 *     that inherit the group).
 *   - A second pipe (also FD_CLOEXEC) distinguishes "the exec itself
 *     failed" from "the program ran and legitimately exited with some
 *     code": on a successful execvp() the write end's CLOEXEC flag closes
 *     it automatically, so the parent sees EOF with nothing ever written;
 *     on failure -- either execvp() itself or a load-bearing setup step
 *     before it, e.g. the stdout dup2 -- the child write()s its errno to
 *     it (async-signal-safe, no allocation) before _exit(127).
 *
 * Pipe EOF alone does not prove the child has exited (a descendant can
 * close its inherited copy of the write end while the direct child keeps
 * running), so the run loop tracks child-reap state independently via
 * non-blocking waitpid() polls and only finishes once the child is
 * confirmed dead (or the post-kill grace period elapses, whichever is
 * first).
 */

#include <yuzu/agent/subprocess_runner.hpp>

#include <atomic>

#ifndef _WIN32
#include <array>
#include <cerrno>
#include <csignal>
#include <ctime>
#include <fcntl.h>
#include <mutex>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <utility>
#endif

namespace yuzu::agent {

namespace {
// Backs request_subprocess_cancel/subprocess_cancel_requested: a single
// process-wide flag (not per-call, not per-connection), set once at agent
// shutdown and never cleared -- see the agent.cpp call sites next to each
// stop_requested_ latch site.
std::atomic<bool> g_subprocess_cancel{false};
} // namespace

void request_subprocess_cancel(bool cancel) {
    g_subprocess_cancel.store(cancel, std::memory_order_release);
}

bool subprocess_cancel_requested() {
    return g_subprocess_cancel.load(std::memory_order_acquire);
}

#ifndef _WIN32

namespace {

// Bound on how long we'll keep waiting, after sending SIGKILL, for the
// pipes to close AND the child to be reaped. Keeps the "drain" phase
// itself from hanging forever in a pathological case (e.g. an unkillable
// descendant holding a pipe open, or a kernel-uninterruptible child).
constexpr auto kDrainGrace = std::chrono::milliseconds(2000);

// Bound on how long the exception-safety backstop (ChildGuard) will poll
// non-blockingly for the child to be reaped before handing the wait off to
// an asynchronous background reaper. Keeps the guard's destructor itself
// from ever performing an unbounded blocking waitpid() -- the one case the
// run loop below cannot cover, since the loop only runs on the normal path
// and the guard exists specifically for early returns.
constexpr auto kGuardReapGrace = std::chrono::milliseconds(200);

void sleep_briefly(long nanos) {
    struct timespec ts{0, nanos};
    nanosleep(&ts, nullptr);
}

// Send SIGKILL to the child's process group; if that fails (e.g. ESRCH
// because the group is already gone, EPERM, or the child never reached its
// setsid() call before being reaped/killed) fall back to killing the
// direct child so a timeout always has a real chance of landing.
void kill_child_or_group(pid_t pid) {
    if (kill(-pid, SIGKILL) != 0)
        kill(pid, SIGKILL);
}

// Poll waitpid(pid, ..., WNOHANG) for up to `grace`, sleeping briefly
// between attempts. Returns true once the child is confirmed reaped (or
// already gone), false if `grace` elapses first. Never performs a blocking
// wait.
bool try_reap_bounded(pid_t pid, std::chrono::milliseconds grace) {
    auto start = std::chrono::steady_clock::now();
    while (true) {
        int status = 0;
        pid_t waited;
        do {
            waited = waitpid(pid, &status, WNOHANG);
        } while (waited < 0 && errno == EINTR);
        if (waited == pid || (waited < 0 && errno == ECHILD))
            return true;
        if (std::chrono::steady_clock::now() - start >= grace)
            return false;
        sleep_briefly(5'000'000L); // 5ms
    }
}

// Reap `pid` on a detached background thread. Used when try_reap_bounded()
// above could not confirm the reap within its grace period -- rather than
// block the calling (worker) thread indefinitely, hand the wait off to a
// thread that is free to block as long as it needs to. The thread owns
// everything it touches: `pid` is captured by value, so nothing here
// references state on a stack that may already have unwound.
void reap_async(pid_t pid) {
    try {
        std::thread([pid]() {
            int status = 0;
            pid_t waited;
            do {
                waited = waitpid(pid, &status, 0);
            } while (waited < 0 && errno == EINTR);
        }).detach();
    } catch (...) {
        // Thread creation failed (e.g. under resource exhaustion, exactly
        // when this path is most likely to be reached). This can be called
        // from ChildGuard's destructor, which is implicitly noexcept -- an
        // exception escaping it would std::terminate() the whole agent. A
        // zombie left until the agent process itself exits (the kernel
        // reclaims it then regardless) is strictly preferable to that.
    }
}

// RAII owner for a POSIX file descriptor in the parent process -- closes on
// destruction unless reset()/released first. Guards against leaking a pipe
// end if an allocating operation (e.g. std::bad_alloc from a string/vector
// op while collecting output) throws past this function.
class UniqueFd {
public:
    UniqueFd() = default;
    explicit UniqueFd(int fd) : fd_(fd) {}
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    UniqueFd(UniqueFd&& other) noexcept : fd_(other.release()) {}
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) {
            reset();
            fd_ = other.release();
        }
        return *this;
    }
    ~UniqueFd() { reset(); }

    int get() const { return fd_; }

    int release() {
        int fd = fd_;
        fd_ = -1;
        return fd;
    }

    void reset(int fd = -1) {
        if (fd_ >= 0)
            close(fd_);
        fd_ = fd;
    }

private:
    int fd_ = -1;
};

// RAII guard over a forked child: unless discharged, the destructor
// SIGKILLs the child (process group, falling back to the direct child) and
// reaps it. This is the exception-safety backstop for run_bounded_subprocess
// -- the normal path already kills-if-needed and reaps the child via the
// poll loop below and discharges the guard once that is confirmed, so the
// destructor only fires on an early return or an exception unwinding out
// of the function.
//
// The reap here is BOUNDED, never a raw blocking waitpid(): a SIGKILLed
// process usually dies promptly, but a child wedged in uninterruptible
// kernel I/O (or a kill that didn't fully land) would otherwise hang this
// destructor -- and therefore the calling thread -- forever. If the short
// foreground poll can't confirm the reap, the wait is hedged off to a
// detached background thread instead, so ChildGuard's destructor always
// returns promptly.
class ChildGuard {
public:
    explicit ChildGuard(pid_t pid) : pid_(pid) {}
    ChildGuard(const ChildGuard&) = delete;
    ChildGuard& operator=(const ChildGuard&) = delete;
    ~ChildGuard() {
        if (pid_ <= 0)
            return;
        if (child_reaped_) {
            // BR-002: the run loop's own try_reap() already confirmed this
            // PID is gone (waitpid returned it, or ECHILD) before an
            // exception unwound into this destructor -- e.g. std::bad_alloc
            // while collecting output after the child exited. The kernel is
            // free to have recycled the PID for an unrelated process by now,
            // so kill_child_or_group()'s direct-PID kill(pid_, SIGKILL)
            // fallback must never fire here (it would SIGKILL a stranger).
            // Only the process GROUP id is still meaningful, and only
            // best-effort -- a still-running descendant may have kept it
            // alive, but the pid itself is not safe to signal directly.
            (void)kill(-pid_, SIGKILL);
            return;
        }
        kill_child_or_group(pid_);
        if (!try_reap_bounded(pid_, kGuardReapGrace))
            reap_async(pid_);
    }
    void discharge() { pid_ = -1; }
    // BR-002: called from the run loop's try_reap() the instant the child is
    // confirmed reaped, so the guard's destructor knows -- if it still fires
    // after that point (an exception thrown before discharge()) -- that
    // pid_ may already have been recycled and must not be signalled
    // directly.
    void mark_child_reaped() noexcept { child_reaped_ = true; }

private:
    pid_t pid_;
    bool child_reaped_ = false;
};

// EINTR-retrying dup2() -- async-signal-safe (no allocation), safe to call
// from the forked child between fork() and execvp(). dup2() is not
// documented to return EINTR on every platform, but where it can, this
// keeps a spurious interrupt from being mistaken for a real setup
// failure.
int dup2_retry(int oldfd, int newfd) {
    int rc;
    do {
        rc = dup2(oldfd, newfd);
    } while (rc == -1 && errno == EINTR);
    return rc;
}

// Async-signal-safe: writes `err` to the exec-error pipe (retried across
// EINTR, no allocation) then terminates the child immediately via
// _exit(127). Shared by a failed execvp() and by a load-bearing setup
// failure caught before execvp() is ever reached (e.g. the child's own
// stdout dup2) -- either way the parent must see a definite failure on
// this pipe rather than an ambiguous EOF, and the child must never
// proceed to execvp() with broken plumbing. A real write failure other
// than EINTR is still best-effort only: the parent's "no byte ever
// arrived" then stays inconclusive (tool_ran stays false) rather than
// assuming success.
[[noreturn]] void report_setup_failure_and_exit(int err_fd, int err) {
    const auto* bytes = reinterpret_cast<const unsigned char*>(&err);
    std::size_t sent = 0;
    while (sent < sizeof(err)) {
        ssize_t w = write(err_fd, bytes + sent, sizeof(err) - sent);
        if (w > 0) {
            sent += static_cast<std::size_t>(w);
        } else if (w < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    _exit(127);
}

// BR-01: serializes pipe-creation-through-fork across every concurrent
// invocation of run_bounded_subprocess. macOS/BSD has no atomic
// O_CLOEXEC pipe creation (no pipe2(); CLOEXEC is set via a separate
// fcntl() call after pipe()), so a fork()+exec() on another thread that
// lands between this invocation's pipe() and its fcntl(F_SETFD,
// FD_CLOEXEC) would inherit this invocation's not-yet-CLOEXEC write
// end(s) -- keeping a copy of the write end open in a second process and
// starving this invocation's read side of EOF (a false timeout).
//
// Held across [pipe()..fork()] in run_bounded_subprocess below so no
// other thread's fork() can land in that window; released in the PARENT
// immediately after fork() returns. The child inherits it already locked
// and must NEVER touch it -- it always _exit()s or execvp()s out without
// running any C++ destructors, so the lock simply stays locked (and
// irrelevant) in the child's own address space; no deadlock results.
std::mutex g_fork_pipe_mutex;

} // namespace

SubprocessResult run_bounded_subprocess(const std::vector<std::string>& argv,
                                         const SubprocessOptions& opts) {
    SubprocessResult result;
    if (argv.empty())
        return result;

    // Build the C-style argv BEFORE fork() -- see the file header comment.
    std::vector<char*> c_argv;
    c_argv.reserve(argv.size() + 1);
    for (const auto& arg : argv)
        c_argv.push_back(const_cast<char*>(arg.c_str()));
    c_argv.push_back(nullptr);

    // BR-01: serialize pipe-creation-through-fork against every other
    // concurrent invocation (see g_fork_pipe_mutex's comment) -- held from
    // here through fork() below; every early return in between releases it
    // via this lock's destructor.
    std::unique_lock<std::mutex> fork_pipe_lock(g_fork_pipe_mutex);

    int raw_pipe[2];
    if (pipe(raw_pipe) != 0)
        return result;
    UniqueFd read_fd(raw_pipe[0]);
    UniqueFd write_fd(raw_pipe[1]);
    // Fail closed: CLOEXEC on both ends is load-bearing (it's what keeps
    // the pipe from leaking into whatever the child execs into), so a
    // failed fcntl here is treated the same as a failed pipe() above rather
    // than silently continuing with a leaky descriptor. RAII closes both
    // ends on this early return.
    if (fcntl(read_fd.get(), F_SETFD, FD_CLOEXEC) == -1 ||
        fcntl(write_fd.get(), F_SETFD, FD_CLOEXEC) == -1)
        return result;

    // PLAN-11: a second, CLOEXEC pipe used only to detect an exec()
    // failure. Its write end auto-closes the instant execvp() succeeds (no
    // child-side code needed for that case), so the parent sees EOF with
    // nothing ever written; on failure the child writes its errno to it
    // before _exit()ing. tool_ran is derived from whether the parent ever
    // saw a byte on this pipe -- never from the child's exit code, so a
    // program that legitimately exits 127 is never confused with a
    // missing binary.
    int err_raw_pipe[2];
    if (pipe(err_raw_pipe) != 0)
        return result; // read_fd/write_fd close themselves
    UniqueFd err_read_fd(err_raw_pipe[0]);
    UniqueFd err_write_fd(err_raw_pipe[1]);
    if (fcntl(err_read_fd.get(), F_SETFD, FD_CLOEXEC) == -1 ||
        fcntl(err_write_fd.get(), F_SETFD, FD_CLOEXEC) == -1)
        return result; // fail closed, same reasoning as the pipe above

    pid_t pid = fork();
    if (pid < 0)
        return result; // all four fds close themselves

    if (pid == 0) {
        // Child: inherits fork_pipe_lock already locked -- NEVER lock,
        // unlock, or otherwise touch it (see g_fork_pipe_mutex's comment
        // above). Safe specifically because this branch never returns
        // through a normal C++ path -- it always _exit()s or execvp()s
        // below -- so the lock's destructor never runs on this side of the
        // fork either.
        //
        // New session/process group so the whole group can be SIGKILLed as
        // a unit on timeout, even if the target CLI spawns helper
        // processes. Only async-signal-safe calls from here on. Result is
        // checked (rather than silently discarded) but treated as
        // non-load-bearing: a failure here only degrades the timeout kill
        // to the direct child (kill_child_or_group()'s existing
        // ESRCH/EPERM fallback), not the captured output/exit code below,
        // so it does not go through report_setup_failure_and_exit.
        if (setsid() == -1) {
            // no-op: intentionally not load-bearing, see comment above.
        }

        // Both dup2s below ARE the plumbing that makes this invocation's
        // captured output/exit-code contract correct, so a failure here is
        // load-bearing: report it over the exec-error pipe and exit rather
        // than exec'ing with the wrong fd wired to stdout/stderr.
        if (dup2_retry(write_fd.get(), STDOUT_FILENO) == -1)
            report_setup_failure_and_exit(err_write_fd.get(), errno);
        if (opts.merge_stderr) {
            if (dup2_retry(write_fd.get(), STDERR_FILENO) == -1)
                report_setup_failure_and_exit(err_write_fd.get(), errno);
        } else {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                // Best-effort: the dup2's result is checked (rather than
                // silently discarded) but, like the open() above, its
                // failure is not load-bearing -- stderr is simply left
                // wherever it was rather than silenced, which cannot
                // corrupt the captured stdout/exit-code result, unlike the
                // dup2s above that ARE checked-and-fatal.
                if (dup2_retry(devnull, STDERR_FILENO) == -1) {
                    // no-op: intentionally not load-bearing, see comment above.
                }
                close(devnull);
            }
            // else: open() itself failed -- also not load-bearing, stderr
            // is simply left wherever it was (checked via the >= 0 guard
            // above, no report_setup_failure_and_exit for the same reason).
        }
        close(read_fd.get());
        close(write_fd.get());
        close(err_read_fd.get());
        // err_write_fd stays open here: its CLOEXEC flag closes it
        // automatically on a successful execvp(); on failure the code
        // below writes to it explicitly before exiting.

        // BR-003: execv(), not execvp() -- execvp() is not on Darwin's
        // async-signal-safe list because it does a PATH search (fopen()
        // internally on some libc implementations); every production
        // caller already passes an absolute tool path (e.g. /bin/sh,
        // /usr/bin/codesign), so no PATH search is ever needed here.
        execv(c_argv[0], c_argv.data());
        // exec failed -- report why and exit; see
        // report_setup_failure_and_exit's comment above for the
        // EINTR-retry and unconditional-_exit(127) reasoning (shared with
        // the load-bearing setup checks above).
        report_setup_failure_and_exit(err_write_fd.get(), errno);
    }

    // Parent: fork() has returned and this is not the child branch --
    // release the pipe-creation lock now (see g_fork_pipe_mutex's comment
    // above).
    fork_pipe_lock.unlock();

    // Parent: guard the child from here on so an exception anywhere below
    // (e.g. std::bad_alloc while collecting output) cannot leave it
    // running/unreaped or leak the pipe fds (RAII on the UniqueFds).
    ChildGuard guard(pid);

    write_fd.reset();     // only needed by the child
    err_write_fd.reset(); // only needed by the child

    int flags = fcntl(read_fd.get(), F_GETFL, 0);
    if (flags == -1 || fcntl(read_fd.get(), F_SETFL, flags | O_NONBLOCK) == -1) {
        // Fail closed: without a confirmed non-blocking pipe fd, the read()
        // below could block indefinitely before any deadline check ever
        // runs. Treat this as an honest timeout with no collected output --
        // the still-armed guard above kills the child when it unwinds.
        result.timed_out = true;
        return result;
    }
    int err_flags = fcntl(err_read_fd.get(), F_GETFL, 0);
    if (err_flags == -1 || fcntl(err_read_fd.get(), F_SETFL, err_flags | O_NONBLOCK) == -1) {
        result.timed_out = true;
        return result;
    }

    auto start = std::chrono::steady_clock::now();
    bool killed = false;
    bool pipe_eof = false;
    bool child_reaped = false;
    bool err_pipe_open = true; // becomes false once exec success/failure is known
    bool exec_failed = false;  // true iff the child reported a failed execvp()
    // True once exec is POSITIVELY confirmed to have happened: either the
    // exec-error pipe cleanly resolved to EOF while `killed` was still
    // false (so the resolution cannot be an artifact of our own kill
    // reaching the child before it got to execvp()), or real output
    // arrived on the main pipe (only possible after a successful exec, no
    // matter when). A child killed in the narrow fork()-to-execvp() window
    // -- reachable in practice when a cancel is already pending the moment
    // this function is called -- closes both its pipes exactly like a
    // successful exec would, so EOF alone cannot be trusted once a kill is
    // already in flight.
    bool exec_confirmed_ok = false;
    std::chrono::steady_clock::time_point kill_time{};
    std::string line_buf;
    std::array<char, 512> buf{};
    constexpr std::size_t kOutputSanityCapBytes = 1'000'000; // real output is tiny
    // Set once opts.stop_after_max_lines is armed and result.lines has just
    // reached opts.max_lines -- triggers a clean early kill+reap below,
    // distinct from a deadline/cancel kill (see the exit_code fixup after
    // the loop).
    bool line_cap_stop = false;

    auto store_line = [&](std::string line) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            return;
        if (opts.max_lines == 0 || result.lines.size() < opts.max_lines) {
            result.lines.push_back(std::move(line));
            if (opts.stop_after_max_lines && opts.max_lines != 0 &&
                result.lines.size() >= opts.max_lines)
                line_cap_stop = true;
        }
    };

    auto try_reap = [&]() {
        if (child_reaped)
            return;
        int status = 0;
        pid_t waited;
        do {
            waited = waitpid(pid, &status, WNOHANG);
        } while (waited < 0 && errno == EINTR);
        if (waited == pid) {
            child_reaped = true;
            // BR-002: tell the guard immediately -- if an exception unwinds
            // into ~ChildGuard anywhere after this point (e.g. std::bad_alloc
            // in the output-collection code below), it must not signal pid_
            // directly since the kernel may have already recycled it.
            guard.mark_child_reaped();
            // Only ever set on a normal exit -- a signal-killed child (the
            // deadline/cancel path below) leaves this at its -1 sentinel;
            // WIFEXITED is false for a SIGKILL death, so there is no path
            // here that fabricates a WEXITSTATUS for one.
            if (WIFEXITED(status))
                result.exit_code = WEXITSTATUS(status);
        } else if (waited < 0 && errno == ECHILD) {
            child_reaped = true;
            guard.mark_child_reaped(); // BR-002: see comment above
        }
    };

    auto poll_err_pipe = [&]() {
        if (!err_pipe_open)
            return;
        std::array<char, sizeof(int)> probe{};
        ssize_t n = read(err_read_fd.get(), probe.data(), probe.size());
        if (n > 0) {
            exec_failed = true;
            err_pipe_open = false; // outcome decided; nothing more to learn
        } else if (n == 0) {
            err_pipe_open = false; // EOF: write end closed (CLOEXEC-on-exec, or child died)
            if (!killed)
                // Resolved before any kill was ever sent -- unambiguously a
                // successful exec, not a side effect of us killing a
                // not-yet-exec'd child (see exec_confirmed_ok's comment).
                exec_confirmed_ok = true;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            // not ready yet -- retry next iteration
        } else {
            err_pipe_open = false; // real read error: outcome stays unknown (tool_ran=false)
        }
    };

    while (true) {
        auto now = std::chrono::steady_clock::now();

        // Reap and poll the exec-error pipe opportunistically and
        // non-blockingly every iteration. Pipe EOF alone does not prove
        // the child exited (only that no one holds the write end open),
        // so the loop must not treat EOF as "done" until the child is
        // independently confirmed dead.
        try_reap();
        poll_err_pipe();

        if (!killed && (now - start >= opts.deadline || subprocess_cancel_requested())) {
            result.timed_out = true;
            killed = true;
            kill_time = now;
            if (child_reaped) {
                // try_reap() just above already confirmed this PID is gone
                // -- the kernel is free to have reused it for an unrelated
                // process, so kill_child_or_group()'s direct-child fallback
                // must never fire once reaped. Only the process GROUP id is
                // still meaningful (and only if it outlived its leader,
                // e.g. a still-running descendant); if that kill fails
                // there is nothing left that is safe to signal.
                (void)kill(-pid, SIGKILL);
            } else {
                // Whole process group, not just the child; falls back to
                // the still-unreaped direct child if the group kill fails.
                kill_child_or_group(pid);
            }
        } else if (!killed && line_cap_stop) {
            // Caller only wants the first opts.max_lines lines and asked
            // for a clean bounded stop rather than draining to the
            // deadline -- kill+reap exactly like a deadline, but this is
            // NOT a timeout: result.timed_out stays false, and exit_code is
            // fixed up to a success sentinel after the loop below.
            killed = true;
            kill_time = now;
            if (child_reaped) {
                (void)kill(-pid, SIGKILL);
            } else {
                kill_child_or_group(pid);
            }
        }

        if (child_reaped && pipe_eof && !err_pipe_open)
            break; // child is gone, stdout is drained, exec outcome known
        if (killed && now - kill_time >= kDrainGrace)
            // Bounded grace after a kill: something is still holding a
            // pipe open or hasn't been reaped yet -- stop waiting rather
            // than block past the deadline indefinitely.
            break;

        if (pipe_eof) {
            // Nothing left to read, but the child isn't confirmed reaped
            // yet (or the exec outcome isn't resolved yet) -- keep polling
            // above without spinning on read().
            sleep_briefly(5'000'000L); // 5ms
            continue;
        }

        ssize_t n = read(read_fd.get(), buf.data(), buf.size());
        if (n > 0) {
            // Real bytes on the main pipe are only possible after a
            // successful execvp() (the child produces nothing before it) --
            // unambiguous regardless of `killed`'s state, unlike the
            // err-pipe EOF check above.
            exec_confirmed_ok = true;

            // Cap capture at kOutputSanityCapBytes total, applied
            // per-append (never overshoots by up to one read's worth) and
            // uniformly to both the blob and the not-yet-newline-terminated
            // line accumulator -- a newline-free or adversarially long
            // stream must not grow either one unboundedly before the
            // deadline fires.
            const auto avail = result.output.size() < kOutputSanityCapBytes
                                    ? kOutputSanityCapBytes - result.output.size()
                                    : std::size_t{0};
            const auto take = static_cast<std::size_t>(n) < avail ? static_cast<std::size_t>(n) : avail;
            if (take > 0)
                result.output.append(buf.data(), take);
            if (take < static_cast<std::size_t>(n))
                result.output_truncated = true;

            // Line materialization only ever sees the `take` prefix admitted
            // above -- once the blob cap is hit (take == 0), no further
            // bytes reach store_line/line_buf even though the read loop
            // keeps draining (and discarding) the rest of the pipe, so
            // result.lines stays bounded by the same cap as result.output.
            for (ssize_t i = 0; i < static_cast<ssize_t>(take); ++i) {
                char ch = buf[static_cast<std::size_t>(i)];
                if (ch == '\n') {
                    store_line(std::move(line_buf));
                    line_buf.clear();
                } else if (line_buf.size() < kOutputSanityCapBytes) {
                    line_buf += ch;
                } else {
                    result.output_truncated = true;
                }
            }
        } else if (n == 0) {
            pipe_eof = true; // EOF: writer(s) closed their end
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            sleep_briefly(killed ? 5'000'000L : 10'000'000L); // 5ms / 10ms
            continue;
        } else if (errno == EINTR) {
            continue;
        } else {
            pipe_eof = true; // real read error: stop trying to read further
        }
    }

    read_fd.reset();
    err_read_fd.reset();

    if (!line_buf.empty())
        store_line(std::move(line_buf));

    // The loop above exits with child_reaped == true except via the
    // kDrainGrace escape hatch -- one last non-blocking check covers that,
    // then the guard is discharged only once reap is confirmed. If the
    // child is somehow still alive, the guard's destructor forcibly kills
    // it and reaps it with its own bounded poll / async-thread fallback --
    // this worker thread is never held up past that bound, regardless of
    // how long the child takes to actually die.
    try_reap();
    if (child_reaped)
        guard.discharge();

    // tool_ran is true iff exec was positively confirmed (exec_confirmed_ok)
    // and the child never reported an execvp() failure -- never inferred
    // from exit_code. exec_confirmed_ok stays false both for a genuinely
    // unresolved outcome (e.g. the loop exited via the kDrainGrace escape
    // hatch on a pathological hang) and for a child killed before it ever
    // reached execvp(): either way, tool_ran stays false, an honest
    // "unknown" rather than a guess.
    result.tool_ran = exec_confirmed_ok && !exec_failed;

    // A clean stop_after_max_lines stop kills the child by our own request
    // once it had already produced everything the caller asked for -- that
    // is a success, not a failure, so it gets a real exit_code rather than
    // the signal-death -1 sentinel (which callers would otherwise read as
    // "log show exited with an error").
    if (line_cap_stop && !result.timed_out)
        result.exit_code = 0;

    return result;
}

#else // _WIN32

SubprocessResult run_bounded_subprocess(const std::vector<std::string>&, const SubprocessOptions&) {
    return {}; // POSIX-only; no Windows caller invokes this today
}

#endif // !_WIN32

} // namespace yuzu::agent
