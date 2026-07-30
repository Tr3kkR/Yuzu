/**
 * subprocess_runner.cpp -- agent-core bounded, fork-safe subprocess runner
 * (#2273 foundation), extended to the full ADR-3002 runner contract
 * (docs/adr/3002-acquisition-ladder.md:537-606) plus the best-practice
 * addendum (A1-A6, B1-B6).
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
 *   - The C-style argv/envp are built entirely in the PARENT, before fork().
 *     Between fork() and execve() the child may only call async-signal-safe
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
 *     long as that other child runs. BR-001: the process-wide
 *     yuzu::agent::global_fork_lock() (fork_lock.hpp) serializes
 *     [pipe()..fork()] across every launcher that PARTICIPATES in it — this
 *     runner plus the sites listed in fork_lock.hpp's coverage ledger — to
 *     close that window; the child inherits it already locked and never
 *     touches it. It is NOT automatic for every fork/popen in the agent: a
 *     raw popen() that doesn't take the lock still races this window until it
 *     is migrated (fork_lock.hpp tracks the residual uncovered sites).
 *   - The child calls setsid() so a timeout kill can take out the whole
 *     process group, not just the direct child (a CLI can spawn helpers
 *     that inherit the group).
 *   - A second pipe (also FD_CLOEXEC) distinguishes "the exec itself
 *     failed" from "the program ran and legitimately exited with some
 *     code": on a successful execve() the write end's CLOEXEC flag closes
 *     it automatically, so the parent sees EOF with nothing ever written;
 *     on failure -- either execve() itself or a load-bearing setup step
 *     before it, e.g. the stdout dup2 -- the child write()s its errno to
 *     it (async-signal-safe, no allocation) before _exit(127).
 *
 * Pipe EOF alone does not prove the child has exited (a descendant can
 * close its inherited copy of the write end while the direct child keeps
 * running), so the run loop tracks child-reap state independently via
 * non-blocking waitpid()/wait4() polls and only finishes once the child is
 * confirmed dead (or the post-kill grace period elapses, whichever is
 * first).
 *
 * ADR-3002 additions on top of the shipped core above (none of which touch
 * the fd sweep, fork_lock, the hard deadline, process-group kill + reap, the
 * line/output caps, the exec-error pipe, or the single-pipe stderr design):
 *   - build_launch_spec() (subprocess_launch_spec.hpp) now does argv/env
 *     validation and assembly; the runtime argv[0]/embedded-NUL rejection
 *     that used to be assert-only now applies in every build type.
 *   - TerminationReason is computed and surfaced on every return path.
 *   - A per-invocation CancellationToken is checked alongside the existing
 *     process-global cancel flag.
 *   - A1-A6/B2-B6 (Windows handle allow-list + quoting, POSIX signal/rlimit/
 *     umask/env hardening, close_range/pidfd fast paths, rusage capture, the
 *     optional TOCTOU-safe exec primitive) are implemented as ADDITIONS
 *     around the shipped mechanisms, per the addendum's "extend around
 *     these; do not rewrite them."
 *   - A real Windows Job-Object backend replaces the previous stub.
 */

#include <yuzu/agent/subprocess_runner.hpp>

#include <yuzu/agent/subprocess_launch_spec.hpp>

#include <atomic>

#ifndef _WIN32
#include <yuzu/agent/fork_lock.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio> // std::fopen/std::fscanf — read Linux fs.nr_open for the fd ceiling
#include <cstdlib> // std::getenv (TZ passthrough)
#include <ctime>
#include <fcntl.h>
#include <mutex>
#include <poll.h>
#include <sys/resource.h>
#include <sys/stat.h> // umask, fstat, S_ISREG/S_IWGRP/S_IWOTH (A6, B6)
#include <sys/wait.h>
#if defined(__APPLE__)
#include <sys/sysctl.h> // sysctlbyname(kern.maxfilesperproc) — per-process fd ceiling
#endif
#if defined(__linux__)
#include <sys/syscall.h> // SYS_close_range / SYS_pidfd_open / SYS_execveat (B2/B5/B6)
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC 4
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#endif
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
//
// CONTRACT (UP-12): this latch is SHUTDOWN-ONLY. Because it is global and
// sticky, setting it kills EVERY in-flight and future subprocess for the
// process lifetime. A future caller MUST NOT repurpose it for a per-operation
// or per-connection cancel -- that would silently abort all concurrent capture
// (TAR, DEX, plugin shell-outs) agent-wide. A narrower per-call cancel is
// SubprocessOptions::cancel_token (CancellationToken) -- both are checked on
// every poll, independently.
std::atomic<bool> g_subprocess_cancel{false};
} // namespace

void request_subprocess_cancel(bool cancel) {
    // See the shutdown-only contract on g_subprocess_cancel above.
    g_subprocess_cancel.store(cancel, std::memory_order_release);
}

bool subprocess_cancel_requested() {
    return g_subprocess_cancel.load(std::memory_order_acquire);
}

#ifndef _WIN32

namespace {

// Bound on how long we'll keep waiting, after sending the hard kill, for the
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

// ADR-3002 soft-terminate grace: SIGTERM (never SIGKILL) to the process
// group first, falling back to the direct child on the same ESRCH/EPERM
// reasoning as kill_child_or_group() above.
void soft_terminate_child_or_group(pid_t pid) {
    if (kill(-pid, SIGTERM) != 0)
        kill(pid, SIGTERM);
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
        //
        // Make the leak observable (UP-6): sustained detached-reaper spawn
        // failures mean accumulating zombies, which an operator should be able
        // to see rather than diagnose blind. spdlog is itself noexcept-ish, but
        // guard it so this destructor-reachable path can never throw.
        try {
            spdlog::warn("subprocess_runner: could not spawn detached reaper for pid {} "
                         "(resource exhaustion?); leaving it for process-exit reclamation",
                         static_cast<long>(pid));
        } catch (...) {
        }
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
// from the forked child between fork() and execve(). dup2() is not
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

// A true upper bound on any live fd NUMBER, computed in the PARENT (getrlimit /
// sysctl / fopen are not async-signal-safe, so they must never run post-fork).
// Used as the exclusive ceiling for the child's [3, ceiling) close-on-exec sweep.
// The HARD RLIMIT_NOFILE is the natural bound (soft <= hard always, so no fd can
// be allocated at or above it); when the hard limit is infinite — the macOS
// default, or a Linux `LimitNOFILE=infinity` unit — fall back to the kernel's
// actual per-process descriptor cap (macOS `kern.maxfilesperproc`, Linux
// `fs.nr_open`), above which the kernel refuses to allocate a descriptor, so the
// bound stays finite AND complete without an unbounded sweep.
long resolve_fd_ceiling() {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_max != RLIM_INFINITY &&
        rl.rlim_max <= static_cast<rlim_t>(1L << 31))
        return static_cast<long>(rl.rlim_max);
#if defined(__APPLE__)
    int maxproc = 0;
    size_t sz = sizeof(maxproc);
    if (sysctlbyname("kern.maxfilesperproc", &maxproc, &sz, nullptr, 0) == 0 && maxproc > 0)
        return maxproc;
#elif defined(__linux__)
    if (FILE* f = std::fopen("/proc/sys/fs/nr_open", "re")) {
        long v = 0;
        const int n = std::fscanf(f, "%ld", &v);
        std::fclose(f);
        if (n == 1 && v > 0)
            return v;
    }
#endif
    return 1L << 20; // last-resort finite bound (Linux default fs.nr_open)
}

// Async-signal-safe: writes `err` to the exec-error pipe (retried across
// EINTR, no allocation) then terminates the child immediately via
// _exit(127). Shared by a failed execve() and by a load-bearing setup
// failure caught before execve() is ever reached (e.g. the child's own
// stdout dup2) -- either way the parent must see a definite failure on
// this pipe rather than an ambiguous EOF, and the child must never
// proceed to execve() with broken plumbing. A real write failure other
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

// B2 (Linux >=5.11 fast path): the manual fcntl(F_GETFD)/F_SETFD loop this
// function contains is the SHIPPED, do-not-disturb fd sweep, unmodified --
// it is now called as an explicit fallback (see the close_range attempt
// beside its child-branch call site) rather than always being the only
// path, but its own body and semantics (mark-not-close, post-fork, complete
// to the parent-computed hard-limit ceiling) are untouched.
void sweep_fd_range_cloexec_fallback(long ceiling) {
    for (long fd = 3; fd < ceiling; ++fd) {
        const int flags = fcntl(static_cast<int>(fd), F_GETFD);
        if (flags != -1 && !(flags & FD_CLOEXEC))
            fcntl(static_cast<int>(fd), F_SETFD, flags | FD_CLOEXEC);
    }
}

// B6 (optional, off by default; runner primitive only -- no in-tree caller
// enables this in this PR). Async-signal-safe: opens argv[0] O_NOFOLLOW so a
// symlink swap between the probe and this open() can't redirect us, fstat()s
// the FD (never the path, closing the classic stat-vs-exec TOCTOU as far as
// an fd-based check can), and on Linux execs THAT SAME FD via a raw
// execveat(fd, "", ..., AT_EMPTY_PATH) syscall -- a direct syscall rather
// than glibc's fexecve() wrapper, which can fall back to an unsafe
// /proc/self/fd string-formatting path on kernels without execveat().
// Bounded ETXTBSY backoff (a binary still being written) — never unbounded.
[[noreturn]] void toctou_verified_exec(char* const* c_argv, char* const* c_envp,
                                        const LaunchSpec::ExecVerification& v, int err_fd) {
    constexpr int kMaxRetries = 5;
    for (int attempt = 0; attempt < kMaxRetries; ++attempt) {
        int fd = open(c_argv[0], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
            report_setup_failure_and_exit(err_fd, errno);
        struct stat st{};
        if (fstat(fd, &st) != 0) {
            int e = errno;
            close(fd);
            report_setup_failure_and_exit(err_fd, e);
        }
        const bool regular = S_ISREG(st.st_mode);
        const bool root_owned = !v.require_root_owned || st.st_uid == 0;
        const bool not_group_other_writable = (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
        const bool size_ok =
            !v.expected_size || static_cast<std::uint64_t>(st.st_size) == *v.expected_size;
        if (!regular || !root_owned || !not_group_other_writable || !size_ok) {
            close(fd);
            report_setup_failure_and_exit(err_fd, EPERM);
        }
#if defined(__linux__) && defined(SYS_execveat)
        syscall(SYS_execveat, fd, "", c_argv, c_envp, AT_EMPTY_PATH);
        if (errno == ETXTBSY && attempt + 1 < kMaxRetries) {
            close(fd);
            struct timespec ts{0, 20'000'000L * (attempt + 1)}; // bounded 20/40/60/80ms backoff
            nanosleep(&ts, nullptr);
            continue;
        }
        {
            int e = errno;
            close(fd);
            report_setup_failure_and_exit(err_fd, e);
        }
#else
        // macOS/BSD: no fd-based exec primitive (no fexecve()/execveat()).
        // The fstat-verify above is the strongest guarantee available on
        // this platform; the exec itself still re-resolves the path -- an
        // honestly-documented residual (see SubprocessOptions::ExecVerification).
        close(fd);
        execve(c_argv[0], c_argv, c_envp);
        if (errno == ETXTBSY && attempt + 1 < kMaxRetries) {
            struct timespec ts{0, 20'000'000L * (attempt + 1)};
            nanosleep(&ts, nullptr);
            continue;
        }
        report_setup_failure_and_exit(err_fd, errno);
#endif
    }
    report_setup_failure_and_exit(err_fd, ETXTBSY);
}

// B5 (Linux, best-effort): pidfd_open() right after fork(), used ONLY to
// shorten the poll loop's wait latency below (see wait_for_activity()) --
// try_reap()'s waitpid()/wait4() remains the sole authority on "is the
// child actually reaped", and kill_child_or_group()'s process-group
// kill()/killpg() remains the sole termination mechanism (BR-002:
// pidfd_send_signal() is deliberately NOT used to signal the child here,
// only pidfd_open()+poll() for readiness). A kernel <5.3 (no pidfd_open()),
// a sandboxed/seccomp environment that blocks the syscall, or any non-Linux
// platform returns -1 here, and wait_for_activity() falls back to the
// historical fixed sleep -- exactly the behaviour before this feature
// existed.
int try_open_pidfd(pid_t pid) {
#if defined(__linux__) && defined(SYS_pidfd_open)
    long fd = syscall(SYS_pidfd_open, pid, 0);
    return fd >= 0 ? static_cast<int>(fd) : -1;
#else
    (void)pid;
    return -1;
#endif
}

// Waits up to `nanos` for read activity on either pipe or (if `pidfd` >= 0)
// the child's pidfd becoming readable -- whichever comes first -- rather
// than unconditionally sleeping the whole interval. Falls back to the
// historical fixed sleep when no pidfd is available. Never blocks longer
// than `nanos`.
void wait_for_activity(int read_fd, int err_read_fd, int pidfd, long nanos) {
    if (pidfd >= 0) {
        pollfd fds[3] = {{read_fd, POLLIN, 0}, {err_read_fd, POLLIN, 0}, {pidfd, POLLIN, 0}};
        poll(fds, 3, static_cast<int>(nanos / 1'000'000L));
        return;
    }
    sleep_briefly(nanos);
}

} // namespace

SubprocessResult run_bounded_subprocess(const std::vector<std::string>& argv,
                                         const SubprocessOptions& opts) {
    SubprocessResult result;
    if (argv.empty())
        return result; // termination_reason stays its default spawn_error

    // B1: validate + assemble through the pure core (subprocess_launch_spec.hpp)
    // rather than hand-rolling the checks here. Runtime-rejects (in EVERY
    // build type, not just debug/assert builds) an empty/relative argv[0]
    // and an embedded NUL in any argv element -- promoting the old
    // assert-only check.
    LaunchOptions launch_opts;
    launch_opts.working_dir = opts.working_dir;
    launch_opts.merge_stderr = opts.merge_stderr;
    if (const char* tz = std::getenv("TZ"))
        launch_opts.tz = std::string(tz);
    launch_opts.rlimits = {opts.rlimits.cpu_seconds, opts.rlimits.address_space_bytes,
                            opts.rlimits.fsize_bytes, opts.rlimits.nofile_count};
    launch_opts.exec_verify = {opts.exec_verify.enabled, opts.exec_verify.require_root_owned,
                               opts.exec_verify.expected_size};

    LaunchSpec spec = build_launch_spec(argv, launch_opts);
    if (spec.error != LaunchSpecError::none)
        return result; // relative/empty argv[0] or an embedded NUL --
                        // termination_reason stays spawn_error, tool_ran stays false

    // ADR-3002: the output sanity cap is now caller-configurable (up to
    // 16 MiB); clamped rather than trusted verbatim so a caller-supplied 0
    // or an oversized value is corrected, never silently treated as
    // "unbounded".
    const std::size_t output_cap = std::clamp<std::size_t>(opts.output_cap_bytes, 1, 16 * 1024 * 1024);

    // Build the C-style argv/envp BEFORE fork() -- see the file header comment.
    std::vector<char*> c_argv;
    c_argv.reserve(spec.argv.size() + 1);
    for (const auto& arg : spec.argv)
        c_argv.push_back(const_cast<char*>(arg.c_str()));
    c_argv.push_back(nullptr);

    // A5: explicit clear-and-allow-list envp, built here from spec.env (which
    // build_launch_spec assembled from nothing -- LD_*/DYLD_*/IFS/BASH_ENV/
    // GCONV_PATH are stripped by construction, never copied from this
    // process' own environment).
    std::vector<std::string> envp_strings;
    envp_strings.reserve(spec.env.size());
    for (const auto& e : spec.env)
        envp_strings.push_back(e.key + "=" + e.value);
    std::vector<char*> c_envp;
    c_envp.reserve(envp_strings.size() + 1);
    for (auto& s : envp_strings)
        c_envp.push_back(const_cast<char*>(s.c_str()));
    c_envp.push_back(nullptr);

    // BR-001: serialize pipe-creation-through-fork against every other
    // fork/popen launcher in the agent, not just this file (see
    // fork_lock.hpp's contract) -- held from here through fork() below;
    // every early return in between releases it via this lock's destructor.
    std::unique_lock<std::mutex> fork_pipe_lock(global_fork_lock());

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
    // failure. Its write end auto-closes the instant execve() succeeds (no
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

    // Ceiling for the child's inherited-fd sweep, computed HERE in the parent
    // (getrlimit() is not async-signal-safe, so it must not run post-fork). The
    // child sweeps the whole [3, child_fd_ceiling) range (via the B2 close_range
    // fast path or the fcntl fallback) AFTER fork(), which is both:
    //   * COMPLETE — the bound is the HARD RLIMIT_NOFILE. soft <= hard always, so
    //     no descriptor can ever be allocated at or above the hard limit; the
    //     sweep therefore covers every possible live fd number (a soft-limit
    //     ceiling would miss a fd opened while the limit was higher, or under an
    //     RLIM_INFINITY soft limit).
    //   * RACE-FREE — running post-fork, it re-derives the live set from the
    //     child's own (frozen-at-fork) fd table, so it catches EVERY fd present
    //     at fork(), including one a different, unrelated thread opened without
    //     O_CLOEXEC in the window before fork(). A parent-side snapshot cannot
    //     make that guarantee (global_fork_lock() serialises launchers, not
    //     arbitrary socket()/open() callers). This is the round-4 fix: the prior
    //     pre-fork enumeration had exactly that TOCTOU gap.
    const long child_fd_ceiling = resolve_fd_ceiling();

    pid_t pid = fork();
    if (pid < 0)
        return result; // all four fds close themselves

    if (pid == 0) {
        // Child: inherits fork_pipe_lock already locked -- NEVER lock,
        // unlock, or otherwise touch it (see fork_lock.hpp's contract).
        // Safe specifically because this branch never returns
        // through a normal C++ path -- it always _exit()s or exec's
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

        // A3: reset signal disposition/mask to the exec'd tool's defaults.
        // SIG_IGN survives exec (POSIX) -- the agent daemon ignores SIGPIPE,
        // which an exec'd child would otherwise silently inherit. SIGXCPU/
        // SIGXFSZ are the two resource-limit-exceeded signals (paired with
        // A4/B3's RLIMIT_CORE/RLIMIT_CPU/RLIMIT_FSIZE below) -- there is no
        // "SIGXFPE" in POSIX (arithmetic exceptions raise plain SIGFPE,
        // which nothing here ignores or need reset). Plain syscalls, no
        // allocation; slotted beside setsid()/the dup2 block like the rest
        // of this async-signal-safe setup.
        {
            sigset_t empty_mask;
            sigemptyset(&empty_mask);
            sigprocmask(SIG_SETMASK, &empty_mask, nullptr);
            struct sigaction sa{};
            sa.sa_handler = SIG_DFL;
            sigemptyset(&sa.sa_mask);
            sa.sa_flags = 0;
            sigaction(SIGPIPE, &sa, nullptr);
            sigaction(SIGXFSZ, &sa, nullptr);
            sigaction(SIGXCPU, &sa, nullptr);
        }

        // A4: always-on core-dump suppression -- one syscall, prevents a
        // tool segfault from dumping a core built from the daemon's
        // COW-shared secret heap.
        {
            struct rlimit core_limit{0, 0};
            setrlimit(RLIMIT_CORE, &core_limit);
        }

        // B3: optional per-invocation resource caps, OFF unless the caller
        // set them on SubprocessOptions::rlimits (surfaced here via `spec`).
        if (spec.rlimits.cpu_seconds) {
            struct rlimit r{*spec.rlimits.cpu_seconds, *spec.rlimits.cpu_seconds};
            setrlimit(RLIMIT_CPU, &r);
        }
        if (spec.rlimits.address_space_bytes) {
#if defined(RLIMIT_AS)
            struct rlimit r{*spec.rlimits.address_space_bytes, *spec.rlimits.address_space_bytes};
            setrlimit(RLIMIT_AS, &r);
#elif defined(RLIMIT_DATA)
            struct rlimit r{*spec.rlimits.address_space_bytes, *spec.rlimits.address_space_bytes};
            setrlimit(RLIMIT_DATA, &r);
#endif
        }
        if (spec.rlimits.fsize_bytes) {
            struct rlimit r{*spec.rlimits.fsize_bytes, *spec.rlimits.fsize_bytes};
            setrlimit(RLIMIT_FSIZE, &r);
        }
        if (spec.rlimits.nofile_count) {
            struct rlimit r{*spec.rlimits.nofile_count, *spec.rlimits.nofile_count};
            setrlimit(RLIMIT_NOFILE, &r);
        }

        // A6: restrictive umask + a known-safe cwd (blunts DLL/`.so`
        // side-loading and world-writable-drop attacks). Best-effort, like
        // setsid() above -- a failed chdir degrades to "whatever cwd we
        // already had", it never aborts a run that could otherwise succeed.
        umask(0077);
        if (chdir(spec.working_dir.c_str()) != 0) {
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

        // ADR-3002 stdio policy: stdin -> /dev/null by default. Best-effort
        // like the stderr open() above -- a spawned CLI reading from a
        // still-open stdin inherited from the agent daemon (its gRPC
        // connection's controlling terminal, if any) is the concern; a
        // failure here degrades to "whatever stdin already was", never a
        // fatal setup error.
        {
            int devnull_in = open("/dev/null", O_RDONLY);
            if (devnull_in >= 0) {
                if (dup2_retry(devnull_in, STDIN_FILENO) == -1) {
                    // no-op: intentionally not load-bearing.
                }
                close(devnull_in);
            }
        }

        close(read_fd.get());
        close(write_fd.get());
        close(err_read_fd.get());
        // err_write_fd stays open here: its CLOEXEC flag closes it
        // automatically on a successful execve(); on failure the code
        // below writes to it explicitly before exiting.

        // Inherited-fd sanitisation (review blocker). A newly exec'd helper --
        // often a privileged tool (security, codesign, launchctl, pkgutil) --
        // must not inherit any descriptor this agent or a linked library opened
        // without O_CLOEXEC: a gRPC connection socket, a SQLite database fd, or
        // anything else would otherwise leak into an external, possibly-root
        // process (information exposure + resource-lifetime hazard). global_fork_lock()
        // closes only the CLOEXEC *race* window between concurrent launchers'
        // own pipe creation; by its own contract it does NOT sanitise
        // already-open inherited fds (fork_lock.hpp, "non-forking pipe creators
        // are exposed too"). Mark every inherited fd >= 3 close-on-exec so exec()
        // drops them all. Deliberately mark rather than close: err_write_fd is
        // already CLOEXEC, so it survives this sweep -- auto-closing only on a
        // *successful* exec (the parent's success signal) while staying writable
        // to report an exec failure just below. The three own pipe fds were closed
        // above (fcntl on them now returns EBADF and is skipped); stdio (0/1/2) is
        // never in the >= 3 set.
        //
        // B2: on Linux >= 5.11, close_range(3, ~0U, CLOSE_RANGE_CLOEXEC) does
        // this whole sweep in ONE syscall instead of the O(ceiling) fcntl loop
        // -- CLOSE_RANGE_CLOEXEC is mark-not-close (identical semantics to the
        // loop) and still runs POST-fork (identically race-free). A pre-5.11
        // kernel, a header set without SYS_close_range, or a sandboxed
        // environment that blocks the syscall falls straight through to the
        // UNMODIFIED fcntl loop (sweep_fd_range_cloexec_fallback), which
        // remains the only path on every other platform.
#if defined(__linux__) && defined(SYS_close_range)
        if (syscall(SYS_close_range, 3u, ~0u, CLOSE_RANGE_CLOEXEC) != 0)
            sweep_fd_range_cloexec_fallback(child_fd_ceiling);
#else
        sweep_fd_range_cloexec_fallback(child_fd_ceiling);
#endif

        // BR-003: execve(), not execvpe()/execvp() -- neither is on Darwin's
        // async-signal-safe list because both do a PATH search (fopen()
        // internally on some libc implementations); every production
        // caller already passes an absolute tool path (e.g. /bin/sh,
        // /usr/bin/codesign), so no PATH search is ever needed here. A5's
        // explicit c_envp replaces the implicit environ execv() used to
        // read -- the child NEVER inherits this process' actual environment.
        if (spec.exec_verify.enabled) {
            toctou_verified_exec(c_argv.data(), c_envp.data(), spec.exec_verify, err_write_fd.get());
        }
        execve(c_argv[0], c_argv.data(), c_envp.data());
        // exec failed -- report why and exit; see
        // report_setup_failure_and_exit's comment above for the
        // EINTR-retry and unconditional-_exit(127) reasoning (shared with
        // the load-bearing setup checks above).
        report_setup_failure_and_exit(err_write_fd.get(), errno);
    }

    // Parent: fork() has returned and this is not the child branch --
    // release the pipe-creation lock now (see fork_lock.hpp's contract).
    fork_pipe_lock.unlock();

    // Parent: guard the child from here on so an exception anywhere below
    // (e.g. std::bad_alloc while collecting output) cannot leave it
    // running/unreaped or leak the pipe fds (RAII on the UniqueFds).
    ChildGuard guard(pid);

    // B5: best-effort readiness fd (see try_open_pidfd's comment) -- -1 on
    // anything but a >=5.3 Linux kernel, in which case the loop below falls
    // back to its historical fixed sleep exactly as before this feature
    // existed.
    UniqueFd pidfd_owner(try_open_pidfd(pid));

    write_fd.reset();     // only needed by the child
    err_write_fd.reset(); // only needed by the child

    int flags = fcntl(read_fd.get(), F_GETFL, 0);
    if (flags == -1 || fcntl(read_fd.get(), F_SETFL, flags | O_NONBLOCK) == -1) {
        // Fail closed: without a confirmed non-blocking pipe fd, the read()
        // below could block indefinitely before any deadline check ever
        // runs. Treat this as an honest timeout with no collected output --
        // the still-armed guard above kills the child when it unwinds.
        result.timed_out = true;
        result.termination_reason = TerminationReason::spawn_error;
        return result;
    }
    int err_flags = fcntl(err_read_fd.get(), F_GETFL, 0);
    if (err_flags == -1 || fcntl(err_read_fd.get(), F_SETFL, err_flags | O_NONBLOCK) == -1) {
        result.timed_out = true;
        result.termination_reason = TerminationReason::spawn_error;
        return result;
    }

    auto start = std::chrono::steady_clock::now();
    bool killed = false;
    bool pipe_eof = false;
    bool child_reaped = false;
    bool err_pipe_open = true; // becomes false once exec success/failure is known
    bool exec_failed = false;  // true iff the child reported a failed execve()
    // True once exec is POSITIVELY confirmed to have happened: either the
    // exec-error pipe cleanly resolved to EOF while `killed` was still
    // false (so the resolution cannot be an artifact of our own kill
    // reaching the child before it got to execve()), or real output
    // arrived on the main pipe (only possible after a successful exec, no
    // matter when). A child killed in the narrow fork()-to-execve() window
    // -- reachable in practice when a cancel is already pending the moment
    // this function is called -- closes both its pipes exactly like a
    // successful exec would, so EOF alone cannot be trusted once a kill is
    // already in flight.
    bool exec_confirmed_ok = false;
    std::chrono::steady_clock::time_point kill_time{};

    // ADR-3002 termination-reason bookkeeping: at most one of these becomes
    // true (all three guarded by `!killed` at the moment they'd be set), and
    // together with exec_confirmed_ok/exec_failed/natural_signaled below
    // they determine the final TerminationReason after the loop.
    bool killed_by_deadline = false;
    bool killed_by_cancel = false;
    bool killed_by_line_cap = false;
    // True iff the child died from a signal it received ITSELF (e.g. a
    // crash) -- never one this runner sent (guarded by `!killed` at the
    // moment try_reap() observes it, mirroring exec_confirmed_ok's own
    // "resolved before any kill was ever sent" reasoning).
    bool natural_signaled = false;

    // ADR-3002 soft-terminate grace (SubprocessOptions::soft_terminate_grace,
    // 0 by default): when set, a deadline/cancel trigger sends SIGTERM to the
    // process group and waits up to the grace period before escalating to
    // the UNMODIFIED hard SIGKILL path below. hard_kill_sent/hard_kill_time
    // (rather than killed/kill_time) drive the kDrainGrace break check, so
    // the grace period itself is never mistaken for the post-kill drain
    // window -- with soft_terminate_grace == 0 (every existing caller),
    // hard_kill_sent is set in the very same branch as killed, at the same
    // `now`, so this is a no-op for all current behaviour.
    bool soft_terminating = false;
    std::chrono::steady_clock::time_point soft_term_deadline{};
    bool hard_kill_sent = false;
    std::chrono::steady_clock::time_point hard_kill_time{};

    std::string line_buf;
    std::array<char, 512> buf{};
    // Set once opts.stop_after_max_lines is armed and result.lines has just
    // reached opts.max_lines -- triggers a clean early kill+reap below,
    // distinct from a deadline/cancel kill.
    bool line_cap_stop = false;

    auto store_line = [&](std::string line) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            return;
        // ADR-3002 streaming primitive: every completed line reaches the
        // caller's callback (if any), uncapped by max_lines -- unlike
        // result.lines, which stays bounded by the collect-at-end contract
        // below.
        if (opts.on_line)
            opts.on_line(line);
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
        // B4: wait4() over waitpid() to capture rusage on the same
        // WNOHANG-confirmed reap -- a strict superset of the shipped
        // waitpid() call (identical semantics on every other axis).
        struct rusage ru{};
        pid_t waited;
        do {
            waited = wait4(pid, &status, WNOHANG, &ru);
        } while (waited < 0 && errno == EINTR);
        if (waited == pid) {
            child_reaped = true;
            // BR-002: tell the guard immediately -- if an exception unwinds
            // into ~ChildGuard anywhere after this point (e.g. std::bad_alloc
            // in the output-collection code below), it must not signal pid_
            // directly since the kernel may have already recycled it.
            guard.mark_child_reaped();
            // Only ever set on a normal exit -- a signal-killed child (the
            // deadline/cancel/line-cap path below) leaves this at its -1
            // sentinel; WIFEXITED is false for a signal death, so there is
            // no path here that fabricates a WEXITSTATUS for one.
            if (WIFEXITED(status)) {
                result.exit_code = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status) && !killed) {
                // A signal death this runner did NOT initiate (killed is
                // still false) -- the child crashed or was signalled by
                // something else entirely, distinct from our own
                // deadline/cancel/line-cap kills below.
                natural_signaled = true;
            }
            result.child_user_time = std::chrono::microseconds(
                static_cast<long long>(ru.ru_utime.tv_sec) * 1'000'000LL + ru.ru_utime.tv_usec);
            result.child_system_time = std::chrono::microseconds(
                static_cast<long long>(ru.ru_stime.tv_sec) * 1'000'000LL + ru.ru_stime.tv_usec);
#if defined(__APPLE__)
            result.child_max_rss_kb = static_cast<std::uint64_t>(ru.ru_maxrss) / 1024;
#else
            result.child_max_rss_kb = static_cast<std::uint64_t>(ru.ru_maxrss);
#endif
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

        const bool deadline_hit = !killed && (now - start >= opts.deadline);
        const bool cancel_hit =
            !killed && (subprocess_cancel_requested() ||
                        (opts.cancel_token && opts.cancel_token->cancelled()));

        if (deadline_hit || cancel_hit) {
            result.timed_out = true;
            killed = true;
            kill_time = now;
            killed_by_deadline = deadline_hit;
            killed_by_cancel = !deadline_hit && cancel_hit;
            if (opts.soft_terminate_grace.count() > 0 && !child_reaped) {
                // ADR-3002 soft-terminate grace: give a mutating tool a
                // chance to finish an in-flight transaction before the hard
                // group kill below. The existing kDrainGrace-bounded poll
                // loop keeps running underneath -- if the child exits on its
                // own within the grace window, the normal child_reaped path
                // picks it up like any other exit.
                soft_terminate_child_or_group(pid);
                soft_terminating = true;
                soft_term_deadline = now + opts.soft_terminate_grace;
            } else if (child_reaped) {
                // try_reap() just above already confirmed this PID is gone
                // -- the kernel is free to have reused it for an unrelated
                // process, so kill_child_or_group()'s direct-child fallback
                // must never fire once reaped. Only the process GROUP id is
                // still meaningful (and only if it outlived its leader,
                // e.g. a still-running descendant); if that kill fails
                // there is nothing left that is safe to signal.
                (void)kill(-pid, SIGKILL);
                hard_kill_sent = true;
                hard_kill_time = now;
            } else {
                // Whole process group, not just the child; falls back to
                // the still-unreaped direct child if the group kill fails.
                kill_child_or_group(pid);
                hard_kill_sent = true;
                hard_kill_time = now;
            }
        } else if (!killed && line_cap_stop) {
            // Caller only wants the first opts.max_lines lines and asked
            // for a clean bounded stop rather than draining to the
            // deadline -- kill+reap exactly like a deadline, but this is
            // NOT a timeout: result.timed_out stays false. killed_by_line_cap
            // is only credited when our kill is actually what ends the
            // child (child_reaped already true here means it exited
            // naturally on its own in the same instant the cap was hit --
            // see the K-5 unit test -- and termination_reason correctly
            // falls through to `exited` with the child's real exit code
            // instead).
            killed = true;
            kill_time = now;
            killed_by_line_cap = !child_reaped;
            if (child_reaped) {
                (void)kill(-pid, SIGKILL);
            } else {
                kill_child_or_group(pid);
            }
            hard_kill_sent = true;
            hard_kill_time = now;
        } else if (soft_terminating && !child_reaped && now >= soft_term_deadline) {
            // Grace elapsed and the child still hasn't exited on its own --
            // escalate to the SAME unmodified hard kill this runner has
            // always sent.
            soft_terminating = false;
            kill_child_or_group(pid);
            hard_kill_sent = true;
            hard_kill_time = now;
        }

        if (child_reaped && pipe_eof && !err_pipe_open)
            break; // child is gone, stdout is drained, exec outcome known
        if (hard_kill_sent && now - hard_kill_time >= kDrainGrace)
            // Bounded grace after the HARD kill (never the soft-terminate
            // grace, which is bounded separately by soft_term_deadline
            // above): something is still holding a pipe open or hasn't been
            // reaped yet -- stop waiting rather than block indefinitely.
            break;

        if (pipe_eof) {
            // Nothing left to read, but the child isn't confirmed reaped
            // yet (or the exec outcome isn't resolved yet) -- keep polling
            // above without spinning on read().
            wait_for_activity(read_fd.get(), err_read_fd.get(), pidfd_owner.get(), 5'000'000L);
            continue;
        }

        ssize_t n = read(read_fd.get(), buf.data(), buf.size());
        if (n > 0) {
            // Real bytes on the main pipe are only possible after a
            // successful execve() (the child produces nothing before it) --
            // unambiguous regardless of `killed`'s state, unlike the
            // err-pipe EOF check above.
            exec_confirmed_ok = true;

            // Cap capture at output_cap total (ADR-3002: caller-configurable,
            // clamped to [1, 16MiB] -- see output_cap's computation above),
            // applied per-append (never overshoots by up to one read's
            // worth) and uniformly to both the blob and the
            // not-yet-newline-terminated line accumulator -- a
            // newline-free or adversarially long stream must not grow
            // either one unboundedly before the deadline fires.
            const auto avail =
                result.output.size() < output_cap ? output_cap - result.output.size() : std::size_t{0};
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
                } else if (line_buf.size() < output_cap) {
                    line_buf += ch;
                } else {
                    result.output_truncated = true;
                }
            }
        } else if (n == 0) {
            pipe_eof = true; // EOF: writer(s) closed their end
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            wait_for_activity(read_fd.get(), err_read_fd.get(), pidfd_owner.get(),
                               killed ? 5'000'000L : 10'000'000L);
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
    // and the child never reported an execve() failure -- never inferred
    // from exit_code. exec_confirmed_ok stays false both for a genuinely
    // unresolved outcome (e.g. the loop exited via the kDrainGrace escape
    // hatch on a pathological hang) and for a child killed before it ever
    // reached execve(): either way, tool_ran stays false, an honest
    // "unknown" rather than a guess.
    result.tool_ran = exec_confirmed_ok && !exec_failed;

    // ADR-3002: the explicit termination reason. Priority mirrors the
    // mutually-exclusive kill branches above (at most one of
    // killed_by_line_cap/killed_by_cancel/killed_by_deadline is ever true);
    // natural_signaled is checked only once none of those killed-by-us
    // reasons apply. Deliberately NOT fabricating an exit_code=0 for the
    // line_cap case (the removed pre-ADR-3002 sentinel fixup) -- callers
    // distinguish "deliberate clean stop" from "failure" via this field,
    // never via a synthesized exit code.
    if (!result.tool_ran) {
        result.termination_reason = TerminationReason::spawn_error;
    } else if (killed_by_line_cap) {
        result.termination_reason = TerminationReason::line_limit;
    } else if (killed_by_cancel) {
        result.termination_reason = TerminationReason::cancelled;
    } else if (killed_by_deadline) {
        result.termination_reason = TerminationReason::deadline;
    } else if (natural_signaled) {
        result.termination_reason = TerminationReason::signaled;
    } else {
        result.termination_reason = TerminationReason::exited;
    }

    return result;
}

std::string probe_tool_path(const std::vector<std::string>& candidates) {
    for (const auto& c : candidates) {
        if (!detail::is_absolute_path(c))
            continue;
        struct stat st{};
        if (::stat(c.c_str(), &st) == 0 && S_ISREG(st.st_mode) && ::access(c.c_str(), X_OK) == 0)
            return c;
    }
    return {};
}

#else // _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <psapi.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cwctype>

namespace {

// RAII HANDLE owner -- the Windows twin of the POSIX UniqueFd above. Also
// stands in for POSIX's ChildGuard: job_h below is created with
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, so simply destroying it (an ordinary
// RAII destructor, fired on any early return OR an exception unwinding
// through this function) terminates the process -- no separate guard class
// is needed on this platform.
class UniqueHandle {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE h) : h_(h) {}
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& other) noexcept : h_(other.release()) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            reset();
            h_ = other.release();
        }
        return *this;
    }
    ~UniqueHandle() { reset(); }

    HANDLE get() const { return h_; }
    HANDLE release() {
        HANDLE h = h_;
        h_ = nullptr;
        return h;
    }
    void reset(HANDLE h = nullptr) {
        if (h_ != nullptr && h_ != INVALID_HANDLE_VALUE)
            CloseHandle(h_);
        h_ = h;
    }

private:
    HANDLE h_ = nullptr;
};

std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty())
        return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (len <= 0)
        return {};
    std::wstring w(static_cast<std::size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), len);
    return w;
}

} // namespace

SubprocessResult run_bounded_subprocess(const std::vector<std::string>& argv,
                                         const SubprocessOptions& opts) {
    SubprocessResult result;
    if (argv.empty())
        return result;

    LaunchOptions launch_opts;
    launch_opts.working_dir = opts.working_dir;
    launch_opts.merge_stderr = opts.merge_stderr;
    {
        wchar_t tz_buf[64];
        DWORD n = GetEnvironmentVariableW(L"TZ", tz_buf, 64);
        if (n > 0 && n < 64) {
            int u8len = WideCharToMultiByte(CP_UTF8, 0, tz_buf, static_cast<int>(n), nullptr, 0,
                                             nullptr, nullptr);
            if (u8len > 0) {
                std::string tz(static_cast<std::size_t>(u8len), '\0');
                WideCharToMultiByte(CP_UTF8, 0, tz_buf, static_cast<int>(n), tz.data(), u8len, nullptr,
                                     nullptr);
                launch_opts.tz = tz;
            }
        }
    }
    launch_opts.rlimits = {opts.rlimits.cpu_seconds, opts.rlimits.address_space_bytes,
                            opts.rlimits.fsize_bytes, opts.rlimits.nofile_count};
    launch_opts.exec_verify = {opts.exec_verify.enabled, opts.exec_verify.require_root_owned,
                               opts.exec_verify.expected_size};

    LaunchSpec spec = build_launch_spec(argv, launch_opts);
    if (spec.error != LaunchSpecError::none)
        return result; // relative argv[0], embedded NUL, or a banned .bat/.cmd/.com
                        // argv[0] (CVE-2024-24576; ADR-3002:537-606)

    const std::size_t output_cap = std::clamp<std::size_t>(opts.output_cap_bytes, 1, 16 * 1024 * 1024);

    const std::wstring app = utf8_to_wide(spec.argv.front());
    std::wstring cmdline = utf8_to_wide(spec.windows_command_line);

    // A5: explicit lpEnvironment built from the SAME allow-list
    // build_launch_spec assembled -- never NULL/never inherited.
    std::wstring env_block;
    for (const auto& e : spec.env) {
        env_block += utf8_to_wide(e.key + "=" + e.value);
        env_block += L'\0';
    }
    env_block += L'\0'; // double-NUL terminator
    std::vector<wchar_t> env_buf(env_block.begin(), env_block.end());

    // A6: safe, non-writable working directory.
    const std::wstring cwd =
        spec.working_dir == "/" ? std::wstring(L"C:\\Windows\\System32") : utf8_to_wide(spec.working_dir);

    // Output pipe: only the WRITE end is inheritable, and only it is named
    // in the handle allow-list below (A1) -- the read end must never be.
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE read_raw = nullptr;
    HANDLE write_raw = nullptr;
    if (!CreatePipe(&read_raw, &write_raw, &sa, 0))
        return result;
    UniqueHandle read_h(read_raw);
    UniqueHandle write_h(write_raw);
    if (!SetHandleInformation(read_h.get(), HANDLE_FLAG_INHERIT, 0))
        return result;

    // A1: STARTUPINFOEXW + PROC_THREAD_ATTRIBUTE_HANDLE_LIST naming ONLY the
    // handle build_launch_spec's WindowsHandlePolicy marks -- never a
    // blanket "everything inheritable" pattern. merge_stderr shares the SAME
    // pipe as stdout (one named handle either way, per spec.windows_handles).
    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
    if (attr_size == 0)
        return result;
    std::vector<unsigned char> attr_buf(attr_size);
    auto* attr_list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_buf.data());
    if (!InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size))
        return result;
    struct AttrListGuard {
        LPPROC_THREAD_ATTRIBUTE_LIST list;
        ~AttrListGuard() { DeleteProcThreadAttributeList(list); }
    } attr_guard{attr_list};

    HANDLE inherit_list[1] = {write_h.get()};
    if (!UpdateProcThreadAttribute(attr_list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit_list,
                                    sizeof(inherit_list), nullptr, nullptr))
        return result;

    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdOutput = write_h.get();
    si.StartupInfo.hStdError = spec.merge_stderr ? write_h.get() : nullptr;
    si.StartupInfo.hStdInput = nullptr; // stdio policy: no stdin inherited -- the nearest
                                         // Windows equivalent of POSIX's stdin -> /dev/null
    si.lpAttributeList = attr_list;

    PROCESS_INFORMATION pi{};
    // CREATE_SUSPENDED: the child is created suspended and assigned to the
    // kill-on-close Job Object below BEFORE it is ever resumed (ADR-3002:
    // avoids the child-before-job race a create-then-assign order allows).
    // CREATE_NEW_PROCESS_GROUP gives the group a CTRL_BREAK target for
    // soft_terminate_grace -- the Windows twin of POSIX's process-group
    // SIGTERM.
    const DWORD create_flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED |
                                CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP;

    std::vector<wchar_t> cmdline_buf(cmdline.begin(), cmdline.end());
    cmdline_buf.push_back(L'\0'); // CreateProcessW requires a MUTABLE lpCommandLine buffer

    BOOL created =
        CreateProcessW(app.c_str(),        // explicit absolute lpApplicationName
                        cmdline_buf.data(), // CRT-compatible (Colascione) quoted command line
                        nullptr, nullptr,
                        TRUE, // required for the handle list above to take effect --
                              // PROC_THREAD_ATTRIBUTE_HANDLE_LIST restricts what
                              // ACTUALLY inherits to exactly the one named handle,
                              // so this is NOT the banned blanket-inherit pattern
                              // (A1 bans inheriting everything WITHOUT a
                              // restricting handle list, which this call always
                              // supplies)
                        create_flags,
                        env_buf.data(), // A5: explicit lpEnvironment, never NULL
                        cwd.c_str(), &si.StartupInfo, &pi);
    write_h.reset(); // the parent's own copy of the write end is no longer needed
    if (!created)
        return result;
    UniqueHandle process_h(pi.hProcess);
    UniqueHandle thread_h(pi.hThread);

    // Kill-on-close Job Object, assigned BEFORE resume.
    HANDLE job_raw = CreateJobObjectW(nullptr, nullptr);
    if (job_raw == nullptr) {
        TerminateProcess(process_h.get(), 1);
        return result;
    }
    UniqueHandle job_h(job_raw);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // B3 (optional, off by default): the nearest Windows equivalent of POSIX
    // RLIMIT_AS, carried on the Job Object.
    if (spec.rlimits.address_space_bytes) {
        jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        jeli.ProcessMemoryLimit = static_cast<SIZE_T>(*spec.rlimits.address_space_bytes);
    }
    SetInformationJobObject(job_h.get(), JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
    if (!AssignProcessToJobObject(job_h.get(), process_h.get())) {
        TerminateProcess(process_h.get(), 1);
        return result;
    }
    ResumeThread(thread_h.get()); // suspended -> assigned -> resumed, in that exact order
    thread_h.reset();

    constexpr auto kDrainGrace = std::chrono::milliseconds(2000);

    auto start = std::chrono::steady_clock::now();
    bool killed = false;
    bool killed_by_deadline = false;
    bool killed_by_cancel = false;
    bool killed_by_line_cap = false;
    bool soft_terminating = false;
    std::chrono::steady_clock::time_point soft_term_deadline{};
    bool hard_kill_sent = false;
    std::chrono::steady_clock::time_point hard_kill_time{};
    bool pipe_eof = false;
    bool process_exited = false;
    bool line_cap_stop = false;
    std::string line_buf;
    std::array<char, 512> buf{};

    auto store_line = [&](std::string line) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            return;
        if (opts.on_line)
            opts.on_line(line);
        if (opts.max_lines == 0 || result.lines.size() < opts.max_lines) {
            result.lines.push_back(std::move(line));
            if (opts.stop_after_max_lines && opts.max_lines != 0 &&
                result.lines.size() >= opts.max_lines)
                line_cap_stop = true;
        }
    };

    while (true) {
        auto now = std::chrono::steady_clock::now();

        if (!process_exited && WaitForSingleObject(process_h.get(), 0) == WAIT_OBJECT_0)
            process_exited = true;

        const bool deadline_hit = !killed && (now - start >= opts.deadline);
        const bool cancel_hit =
            !killed && (subprocess_cancel_requested() ||
                        (opts.cancel_token && opts.cancel_token->cancelled()));

        if (deadline_hit || cancel_hit) {
            result.timed_out = true;
            killed = true;
            killed_by_deadline = deadline_hit;
            killed_by_cancel = !deadline_hit && cancel_hit;
            if (opts.soft_terminate_grace.count() > 0 && !process_exited) {
                // Windows twin of POSIX's SIGTERM soft-terminate: CTRL_BREAK
                // to the whole process group (CREATE_NEW_PROCESS_GROUP
                // above), giving a mutating tool a chance to unwind before
                // the hard job-close kill below.
                GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pi.dwProcessId);
                soft_terminating = true;
                soft_term_deadline = now + opts.soft_terminate_grace;
            } else if (!process_exited) {
                TerminateProcess(process_h.get(), 1);
                hard_kill_sent = true;
                hard_kill_time = now;
            }
        } else if (!killed && line_cap_stop) {
            killed = true;
            killed_by_line_cap = !process_exited;
            if (!process_exited)
                TerminateProcess(process_h.get(), 1);
            hard_kill_sent = true;
            hard_kill_time = now;
        } else if (soft_terminating && !process_exited && now >= soft_term_deadline) {
            soft_terminating = false;
            TerminateProcess(process_h.get(), 1);
            hard_kill_sent = true;
            hard_kill_time = now;
        }

        // Drain whatever is available without blocking.
        DWORD avail_bytes = 0;
        bool have_peek =
            PeekNamedPipe(read_h.get(), nullptr, 0, nullptr, &avail_bytes, nullptr) != 0;
        if (have_peek && avail_bytes > 0) {
            DWORD to_read = static_cast<DWORD>(std::min<std::size_t>(buf.size(), avail_bytes));
            DWORD n = 0;
            if (ReadFile(read_h.get(), buf.data(), to_read, &n, nullptr) && n > 0) {
                const auto avail = result.output.size() < output_cap ? output_cap - result.output.size()
                                                                      : std::size_t{0};
                const auto take = static_cast<std::size_t>(n) < avail ? static_cast<std::size_t>(n) : avail;
                if (take > 0)
                    result.output.append(buf.data(), take);
                if (take < static_cast<std::size_t>(n))
                    result.output_truncated = true;
                for (std::size_t i = 0; i < take; ++i) {
                    char ch = buf[i];
                    if (ch == '\n') {
                        store_line(std::move(line_buf));
                        line_buf.clear();
                    } else if (line_buf.size() < output_cap) {
                        line_buf += ch;
                    } else {
                        result.output_truncated = true;
                    }
                }
            }
        } else if (!have_peek) {
            // The write end has closed (child exited/crashed) --
            // PeekNamedPipe fails once there is no writer left.
            pipe_eof = true;
        }

        if (process_exited && (pipe_eof || !have_peek))
            break;
        if (hard_kill_sent && now - hard_kill_time >= kDrainGrace)
            break;

        Sleep(killed ? 5 : 10);
    }

    if (!line_buf.empty())
        store_line(std::move(line_buf));

    DWORD exit_code_raw = 0;
    if (GetExitCodeProcess(process_h.get(), &exit_code_raw) && exit_code_raw != STILL_ACTIVE) {
        result.tool_ran = true;
        if (!killed)
            result.exit_code = static_cast<int>(exit_code_raw);
        // else: terminated by us (TerminateProcess/job-close) -- exit_code
        // stays the -1 sentinel, never TerminateProcess's own arbitrary exit
        // value, matching the POSIX "never fabricate a status for a death
        // by [our own] signal" contract.
    }

    // B4: rusage-equivalent, best-effort.
    FILETIME creation_time{}, exit_time{}, kernel_time{}, user_time{};
    if (GetProcessTimes(process_h.get(), &creation_time, &exit_time, &kernel_time, &user_time)) {
        auto to_us = [](const FILETIME& ft) {
            ULARGE_INTEGER u{};
            u.LowPart = ft.dwLowDateTime;
            u.HighPart = ft.dwHighDateTime;
            return static_cast<long long>(u.QuadPart / 10); // 100ns ticks -> microseconds
        };
        result.child_user_time = std::chrono::microseconds(to_us(user_time));
        result.child_system_time = std::chrono::microseconds(to_us(kernel_time));
    }
    PROCESS_MEMORY_COUNTERS pmc{};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(process_h.get(), &pmc, sizeof(pmc)))
        result.child_max_rss_kb = static_cast<std::uint64_t>(pmc.PeakWorkingSetSize) / 1024;

    if (!result.tool_ran) {
        result.termination_reason = TerminationReason::spawn_error;
    } else if (killed_by_line_cap) {
        result.termination_reason = TerminationReason::line_limit;
    } else if (killed_by_cancel) {
        result.termination_reason = TerminationReason::cancelled;
    } else if (killed_by_deadline) {
        result.termination_reason = TerminationReason::deadline;
    } else {
        result.termination_reason = TerminationReason::exited;
    }

    return result;
}

std::string probe_tool_path(const std::vector<std::string>& candidates) {
    for (const auto& c : candidates) {
        if (!detail::is_absolute_path(c))
            continue;
        std::wstring wc = utf8_to_wide(c);
        DWORD attrs = GetFileAttributesW(wc.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0)
            return c;
    }
    return {};
}

#endif // !_WIN32

} // namespace yuzu::agent
