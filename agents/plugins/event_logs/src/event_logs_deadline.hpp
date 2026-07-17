/**
 * event_logs_deadline.hpp — bounded subprocess execution with a hard
 * wall-clock deadline (POSIX: macOS/Linux).
 *
 * `log show` (and similar log-inspection CLIs) has no built-in timeout and
 * GNU `timeout` is not available on macOS, so a hung/slow invocation would
 * otherwise block the calling thread indefinitely. bounded_run() forks +
 * execs the given argv directly (no shell), collects stdout line-by-line,
 * and if the deadline elapses before the child exits it SIGKILLs the
 * child's entire process group (not just the direct child — a CLI can
 * spawn helpers that inherit the group), drains the pipe so the dying
 * child cannot block on a full pipe, and reaps the child via waitpid() so
 * no zombie is left behind. On expiry the function returns whatever lines
 * were collected before the deadline plus `timed_out = true` — it never
 * fabricates a result and never blocks past the deadline (plus a short,
 * bounded grace period to observe the pipe close and the child reap after
 * the kill).
 *
 * Pipe EOF alone does NOT prove the child has exited (a descendant can
 * close its inherited copy of stdout while the direct child keeps running),
 * so the run loop tracks child-reap state independently via non-blocking
 * waitpid() polls and only finishes once the child is confirmed dead (or
 * the post-kill grace period elapses, whichever is first).
 *
 * This header is deliberately pure/dependency-free (no yuzu/plugin.hpp) so
 * it can be driven directly from unit tests against a real `sleep` child.
 */
#pragma once

#include <chrono>
#include <cstddef>
#include <string>
#include <vector>

#ifndef _WIN32
#include <array>
#include <cerrno>
#include <csignal>
#include <ctime>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace yuzu::event_logs {

// Result of a bounded subprocess run.
struct BoundedRunResult {
    std::vector<std::string> lines; // stdout, newline-delimited, in order
    bool timed_out = false;         // true if the deadline fired
};

#ifndef _WIN32

namespace detail {

// Bound on how long we'll keep waiting, after sending SIGKILL, for the
// pipe to close AND the child to be reaped. Keeps the "drain" phase itself
// from hanging forever in a pathological case (e.g. an unkillable
// descendant holding the pipe open, or a kernel-uninterruptible child).
constexpr auto kDrainGrace = std::chrono::milliseconds(2000);

inline void sleep_briefly(long nanos) {
    struct timespec ts{0, nanos};
    nanosleep(&ts, nullptr);
}

// RAII owner for a POSIX file descriptor in the parent process — closes on
// destruction unless reset()/released first. Guards against leaking the
// pipe ends if an allocating operation (e.g. std::bad_alloc from a
// string/vector op while collecting output) throws past this function.
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
// SIGKILLs the child's process group and reaps it (blocking). This is the
// exception-safety backstop for bounded_run() — the normal path already
// kills-if-needed and reaps the child via the poll loop below and
// discharges the guard once that is confirmed, so the destructor only
// fires on an early return or an exception unwinding out of the function.
// A SIGKILLed process dies promptly (barring kernel-uninterruptible I/O),
// so this does not itself introduce an unbounded block in practice.
class ChildGuard {
public:
    explicit ChildGuard(pid_t pid) : pid_(pid) {}
    ChildGuard(const ChildGuard&) = delete;
    ChildGuard& operator=(const ChildGuard&) = delete;
    ~ChildGuard() {
        if (pid_ <= 0)
            return;
        kill(-pid_, SIGKILL);
        int status = 0;
        pid_t waited;
        do {
            waited = waitpid(pid_, &status, 0);
        } while (waited < 0 && errno == EINTR);
    }
    void discharge() { pid_ = -1; }

private:
    pid_t pid_;
};

} // namespace detail

// Runs `argv` (argv[0] resolved via PATH, like execvp — no shell involved,
// so no shell-quoting/injection surface) as a child in its own process
// group. Collects newline-delimited stdout lines until the child exits or
// `deadline` elapses, whichever is first. Child stderr is discarded
// (redirected to /dev/null), matching the historical `2>/dev/null`
// behaviour of the shell commands this replaces.
//
// `max_lines`, if nonzero, caps how many collected lines are kept (the
// caller no longer needs a separate `| head -N` stage for that) — output
// beyond the cap is still drained from the pipe, just not stored. Blank
// lines are dropped (matching the historical line-collection behaviour),
// so they never consume the cap or appear as fabricated rows.
inline BoundedRunResult bounded_run(const std::vector<std::string>& argv,
                                     std::chrono::milliseconds deadline,
                                     std::size_t max_lines = 0) {
    BoundedRunResult result;
    if (argv.empty())
        return result;

    // Build the C-style argv BEFORE fork(): between fork() and execvp()
    // the child may only call async-signal-safe functions (POSIX 2.4.3).
    // Allocating via std::vector/std::string post-fork is unsafe in a
    // multithreaded process — another thread can hold an allocator lock
    // at the moment of fork, which the child inherits already-locked and
    // then deadlocks on.
    std::vector<char*> c_argv;
    c_argv.reserve(argv.size() + 1);
    for (const auto& arg : argv)
        c_argv.push_back(const_cast<char*>(arg.c_str()));
    c_argv.push_back(nullptr);

    int raw_pipe[2];
    if (pipe(raw_pipe) != 0)
        return result;

    // Close-on-exec by default on both ends: dup2() below clears
    // FD_CLOEXEC on whichever descriptor it targets (STDOUT_FILENO /
    // STDERR_FILENO), so the child's own use of the pipe is unaffected;
    // this only guards against these two descriptors leaking into any
    // exec elsewhere on an unexpected path.
    fcntl(raw_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(raw_pipe[1], F_SETFD, FD_CLOEXEC);

    detail::UniqueFd read_fd(raw_pipe[0]);
    detail::UniqueFd write_fd(raw_pipe[1]);

    pid_t pid = fork();
    if (pid < 0)
        return result; // read_fd/write_fd close themselves

    if (pid == 0) {
        // Child: new session/process group so the whole group can be
        // SIGKILLed as a unit on timeout, even if the target CLI spawns
        // helper processes. Only async-signal-safe calls from here on.
        setsid();

        dup2(write_fd.get(), STDOUT_FILENO);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        close(read_fd.get());
        close(write_fd.get());

        execvp(c_argv[0], c_argv.data());
        _exit(127); // exec failed
    }

    // Parent: guard the child from here on so an exception anywhere below
    // (e.g. std::bad_alloc while collecting output) cannot leave it
    // running/unreaped or leak the pipe fds (read_fd/write_fd are RAII).
    detail::ChildGuard guard(pid);

    write_fd.reset(); // only needed by the child

    int flags = fcntl(read_fd.get(), F_GETFL, 0);
    fcntl(read_fd.get(), F_SETFL, flags | O_NONBLOCK);

    auto start = std::chrono::steady_clock::now();
    bool killed = false;
    bool pipe_eof = false;
    bool child_reaped = false;
    std::chrono::steady_clock::time_point kill_time{};
    std::string line_buf;
    std::array<char, 512> buf{};

    auto store_line = [&](std::string line) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            return;
        if (max_lines == 0 || result.lines.size() < max_lines)
            result.lines.push_back(std::move(line));
    };

    auto try_reap = [&]() {
        if (child_reaped)
            return;
        int status = 0;
        pid_t waited;
        do {
            waited = waitpid(pid, &status, WNOHANG);
        } while (waited < 0 && errno == EINTR);
        if (waited == pid || (waited < 0 && errno == ECHILD))
            child_reaped = true;
    };

    while (true) {
        auto now = std::chrono::steady_clock::now();

        // Reap opportunistically and non-blockingly every iteration. Pipe
        // EOF alone does not prove the child exited (only that no one
        // holds the write end open), so the loop must not treat EOF as
        // "done" until the child is independently confirmed dead.
        try_reap();

        if (!killed && now - start >= deadline) {
            result.timed_out = true;
            killed = true;
            kill_time = now;
            kill(-pid, SIGKILL); // whole process group, not just the child
        }

        if (child_reaped && pipe_eof)
            break; // child is gone and stdout is fully drained
        if (killed && now - kill_time >= detail::kDrainGrace)
            // Bounded grace after a kill: something is still holding the
            // pipe open or hasn't been reaped yet (e.g. an unkillable
            // descendant, or a kernel-uninterruptible child) — stop
            // waiting rather than block past the deadline indefinitely.
            break;

        if (pipe_eof) {
            // Nothing left to read, but the child isn't confirmed reaped
            // yet — keep polling waitpid() above without spinning on
            // read().
            detail::sleep_briefly(5'000'000L); // 5ms
            continue;
        }

        ssize_t n = read(read_fd.get(), buf.data(), buf.size());
        if (n > 0) {
            for (ssize_t i = 0; i < n; ++i) {
                char ch = buf[static_cast<size_t>(i)];
                if (ch == '\n') {
                    store_line(std::move(line_buf));
                    line_buf.clear();
                } else {
                    line_buf += ch;
                }
            }
        } else if (n == 0) {
            pipe_eof = true; // EOF: writer(s) closed their end
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            detail::sleep_briefly(killed ? 5'000'000L : 10'000'000L); // 5ms / 10ms
            continue;
        } else if (errno == EINTR) {
            continue;
        } else {
            pipe_eof = true; // real read error: stop trying to read further
        }
    }

    read_fd.reset();

    if (!line_buf.empty())
        store_line(std::move(line_buf));

    // The loop above exits with child_reaped == true except via the
    // kDrainGrace escape hatch — one last non-blocking check covers that,
    // then the guard is discharged only once reap is confirmed. If the
    // child is somehow still alive, the guard's destructor forcibly
    // kills+reaps (blocking) it; a SIGKILLed child dies promptly, so this
    // does not itself block past the deadline in practice.
    try_reap();
    if (child_reaped)
        guard.discharge();

    return result;
}

#endif // !_WIN32

} // namespace yuzu::event_logs
