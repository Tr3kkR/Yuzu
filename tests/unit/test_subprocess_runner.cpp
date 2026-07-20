/**
 * test_subprocess_runner.cpp -- real fork/exec vectors for the agent-core
 * bounded subprocess runner (subprocess_runner.hpp, #2273 foundation).
 *
 * Unlike most of the suite this drives REAL child processes (/bin/sleep,
 * /bin/sh, /usr/bin/printf) -- run_bounded_subprocess()'s whole contract is
 * about actual kill/reap and exec-outcome behaviour, which a pure-string
 * fixture can't exercise. Every single-call case here is bounded well under
 * the suite timeout: the longest possible single wait is one deadline (at
 * most a few hundred ms, or one cooperative cancel) plus the runner's own
 * internal drain grace (2s), so a bug that makes the deadline/cancel not
 * fire fails the test loudly instead of hanging CI. The one multi-threaded
 * case (BR-01 below) is bounded differently -- by the aggregate runtime of
 * a handful of sequential real-child iterations per thread run concurrently
 * across threads, a few seconds total -- rather than by a single deadline.
 *
 * POSIX only (subprocess_runner.hpp's implementation is itself
 * `#ifndef _WIN32`-gated) -- this file is still registered unconditionally
 * in the agent test binary, and its body compiles to nothing observable on
 * Windows because every TEST_CASE here is gated on the same macro.
 * macOS/Linux, per the boundary.
 */

#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include "test_helpers.hpp"

#include <yuzu/agent/subprocess_runner.hpp>

#include <algorithm>
#include <barrier>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include <atomic>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace yuzu::agent;
using namespace std::chrono_literals;

namespace {

bool contains_line(const std::vector<std::string>& lines, const std::string& needle) {
    return std::find(lines.begin(), lines.end(), needle) != lines.end();
}

} // namespace

TEST_CASE("run_bounded_subprocess collects output from a fast child that exits well before the deadline",
          "[subprocess][deadline][macos][linux]") {
    // No shell involved in run_bounded_subprocess itself -- printf's
    // repeated-format-against-each-arg behaviour gives deterministic
    // multi-line output with no stdin dependency.
    SubprocessResult result = run_bounded_subprocess(
        {"/usr/bin/printf", "%s\n", "line1", "line2", "line3"}, SubprocessOptions{.deadline = 5000ms});

    CHECK_FALSE(result.timed_out);
    CHECK(result.tool_ran);
    CHECK(result.exit_code == 0);
    REQUIRE(result.lines.size() == 3);
    CHECK(result.lines[0] == "line1");
    CHECK(result.lines[1] == "line2");
    CHECK(result.lines[2] == "line3");
}

TEST_CASE("run_bounded_subprocess caps stored lines at max_lines but still drains the pipe into output",
          "[subprocess][deadline][macos][linux]") {
    SubprocessResult result = run_bounded_subprocess(
        {"/usr/bin/printf", "%s\n", "a", "b", "c", "d"},
        SubprocessOptions{.deadline = 5000ms, .max_lines = 2});

    CHECK_FALSE(result.timed_out);
    REQUIRE(result.lines.size() == 2);
    CHECK(result.lines[0] == "a");
    CHECK(result.lines[1] == "b");
    // max_lines bounds the STORED lines only -- output is the raw captured
    // blob and is not truncated by it (a separate, much larger sanity cap).
    CHECK(result.output == "a\nb\nc\nd\n");
}

TEST_CASE("run_bounded_subprocess kills, reaps, and returns partial output + timed_out on a hung child",
          "[subprocess][deadline][macos][linux]") {
    // A real sleeping child, well past our deadline: exercises the actual
    // SIGKILL-the-process-group + waitpid()-reap path, not a simulation.
    // Emits partial output BEFORE sleeping so the "partial output +
    // timed_out" contract is asserted together. argv[0] here is the
    // /bin/sh INTERPRETER we chose to run -- run_bounded_subprocess itself
    // still never shells out its own argv.
    const auto start = std::chrono::steady_clock::now();

    SubprocessResult result = run_bounded_subprocess(
        {"/bin/sh", "-c", "printf 'first\\nsecond\\n'; sleep 30"}, SubprocessOptions{.deadline = 300ms});

    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(result.timed_out);
    // PLAN-02: a killed child is never given a fabricated exit status --
    // the sentinel stays -1 even though the shell itself ran fine.
    CHECK(result.exit_code == -1);
    CHECK(result.tool_ran); // exec of /bin/sh succeeded before the kill
    CHECK(contains_line(result.lines, "first"));
    CHECK(contains_line(result.lines, "second"));

    // Bounded proof of "killed + reaped within the deadline": the runner's
    // own documented worst case is `deadline` plus one short drain grace
    // (2000ms) before it gives up waiting. If the child were left as an
    // unreaped zombie holding the pipe open, or SIGKILL failed to land,
    // this would run past that bound. 10s is a generous CI-noise margin
    // well below the real hang this guards against (the child's own 30s
    // sleep).
    CHECK(elapsed < 10s);
}

TEST_CASE("run_bounded_subprocess on a child with no output at all still returns timed_out honestly",
          "[subprocess][deadline][macos][linux]") {
    SubprocessResult result =
        run_bounded_subprocess({"/bin/sleep", "30"}, SubprocessOptions{.deadline = 200ms});

    CHECK(result.timed_out);
    CHECK(result.tool_ran);        // exec of /bin/sleep succeeded before the kill
    CHECK(result.exit_code == -1); // signal-killed, never fabricated
    CHECK(result.lines.empty());   // sleep produces no stdout -- never fabricated
    CHECK(result.output.empty());
}

TEST_CASE("run_bounded_subprocess on an empty argv returns a default, never-fabricated result",
          "[subprocess][deadline][macos][linux]") {
    SubprocessResult result = run_bounded_subprocess({}, SubprocessOptions{.deadline = 1000ms});

    CHECK_FALSE(result.timed_out);
    CHECK_FALSE(result.tool_ran);
    CHECK(result.exit_code == -1);
    CHECK(result.lines.empty());
    CHECK(result.output.empty());
}

TEST_CASE("run_bounded_subprocess on a nonexistent binary reports a spawn failure, not a fabricated exit",
          "[subprocess][deadline][macos][linux]") {
    // execvp() fails inside the child, which reports the failure over the
    // exec-error pipe and _exit(127)s almost immediately -- this must
    // resolve well before the deadline, not be mistaken for a hang, and
    // must not be confused with a program that legitimately exits 127 (see
    // the PLAN-11 case below).
    SubprocessResult result = run_bounded_subprocess({"/no/such/binary-xyz-does-not-exist"},
                                                       SubprocessOptions{.deadline = 5000ms});

    CHECK_FALSE(result.timed_out);
    CHECK_FALSE(result.tool_ran);
    CHECK(result.exit_code == 127);
    CHECK(result.lines.empty());
    CHECK(result.output.empty());
}

TEST_CASE("run_bounded_subprocess captures a real exit code from a child that runs to completion",
          "[subprocess][deadline][macos][linux]") {
    SubprocessResult result =
        run_bounded_subprocess({"/bin/sh", "-c", "exit 3"}, SubprocessOptions{.deadline = 5000ms});

    CHECK_FALSE(result.timed_out);
    CHECK(result.tool_ran);
    CHECK(result.exit_code == 3);
}

TEST_CASE("run_bounded_subprocess tells a real exit-127 apart from a spawn failure (PLAN-11)",
          "[subprocess][deadline][macos][linux]") {
    // /bin/sh legitimately exits 127 here -- the exec of /bin/sh itself
    // succeeded, so this must read as tool_ran=true, unlike the spawn
    // failure above which shares the same exit_code by coincidence (both
    // paths reach a child _exit(127)) but is tool_ran=false. tool_ran is
    // decided entirely by whether the exec-error pipe ever saw a byte,
    // never by the exit code.
    SubprocessResult result =
        run_bounded_subprocess({"/bin/sh", "-c", "exit 127"}, SubprocessOptions{.deadline = 5000ms});

    CHECK_FALSE(result.timed_out);
    CHECK(result.tool_ran);
    CHECK(result.exit_code == 127);
}

TEST_CASE("run_bounded_subprocess honors a cooperative cancel request against a genuinely running child",
          "[subprocess][deadline][macos][linux]") {
    // request_subprocess_cancel is a single process-wide flag -- never let
    // a cancel set by this case leak into a later one.
    struct CancelReset {
        ~CancelReset() { request_subprocess_cancel(false); }
    } cancel_reset;

    // A plain "set the flag from a background thread and race the call"
    // can pass even if the flag happened to already be true before
    // run_bounded_subprocess ever forked -- that would exercise "cancel
    // requested before this call started" but not "cancel noticed partway
    // through an already-running child's wait loop". Close that gap with a
    // real cross-process handshake instead of a sleep_for guess: the child
    // writes to a FIFO only after its shell has actually started (i.e.
    // strictly after its own execvp() succeeded), and the canceller thread
    // waits for that write before ever touching the cancel flag.
    //
    // Opened O_RDWR rather than O_RDONLY so this thread's own open() can
    // never block (POSIX: an O_RDONLY open on a FIFO blocks until a writer
    // arrives; O_RDWR is exempt from that, since the fd is itself already
    // a writer). The actual wait is a single bounded poll() -- not a
    // sleep_for+poll loop -- so a pathological spawn failure inside
    // run_bounded_subprocess (fork()/pipe() failing, meaning the child and
    // its FIFO write never happen at all) fails this test loudly via the
    // REQUIRE below instead of hanging the suite forever.
    std::filesystem::path fifo_path = yuzu::test::unique_temp_path("yuzu_test_cancel_fifo_");
    REQUIRE(mkfifo(fifo_path.c_str(), 0600) == 0);
    struct FifoCleanup {
        std::filesystem::path path;
        ~FifoCleanup() { ::unlink(path.c_str()); }
    } fifo_cleanup{fifo_path};

    const auto start = std::chrono::steady_clock::now();

    std::atomic<bool> handshake_ok{false};
    std::thread canceller([&fifo_path, &handshake_ok]() {
        int fd = open(fifo_path.c_str(), O_RDWR); // never blocks (see comment above)
        if (fd >= 0) {
            pollfd pfd{fd, POLLIN, 0};
            if (poll(&pfd, 1, 5000) > 0) { // generous safety-net bound; the
                                            // real handshake resolves in
                                            // low milliseconds
                char c;
                if (read(fd, &c, 1) > 0)
                    handshake_ok = true;
            }
            close(fd);
        }
        request_subprocess_cancel(true);
    });

    // The deadline (60s) is set well beyond both the child's own sleep
    // (30s) and the 10s bound asserted below, so a pass here can only mean
    // the cancel -- not the deadline -- ended the run.
    SubprocessResult result = run_bounded_subprocess(
        {"/bin/sh", "-c", "echo x > " + fifo_path.string() + "; sleep 30"},
        SubprocessOptions{.deadline = 60000ms});
    canceller.join();

    const auto elapsed = std::chrono::steady_clock::now() - start;

    REQUIRE(handshake_ok.load()); // the FIFO handshake itself must have worked
    CHECK(result.timed_out);
    CHECK(result.tool_ran); // exec of /bin/sh succeeded well before the cancel landed
    CHECK(elapsed < 10s);
}

TEST_CASE("run_bounded_subprocess merges stderr into output and lines when merge_stderr is set",
          "[subprocess][deadline][macos][linux]") {
    SubprocessResult result = run_bounded_subprocess(
        {"/bin/sh", "-c", "printf 'diagnostic\\n' 1>&2"},
        SubprocessOptions{.deadline = 5000ms, .merge_stderr = true});

    CHECK_FALSE(result.timed_out);
    CHECK(result.tool_ran);
    CHECK(result.output == "diagnostic\n");
    REQUIRE(result.lines.size() == 1);
    CHECK(result.lines[0] == "diagnostic");
}

TEST_CASE("run_bounded_subprocess discards stderr by default (merge_stderr=false)",
          "[subprocess][deadline][macos][linux]") {
    SubprocessResult result = run_bounded_subprocess(
        {"/bin/sh", "-c", "printf 'diagnostic\\n' 1>&2"},
        SubprocessOptions{.deadline = 5000ms}); // merge_stderr defaults false

    CHECK_FALSE(result.timed_out);
    CHECK(result.tool_ran);
    CHECK(result.output.empty());
    CHECK(result.lines.empty());
}

TEST_CASE("run_bounded_subprocess serializes pipe-creation-through-fork so a concurrent invocation "
          "never leaks a write end into another invocation's child (BR-01)",
          "[subprocess][concurrency][macos][linux]") {
    // BR-01: macOS has no atomic O_CLOEXEC pipe (no pipe2()) -- FD_CLOEXEC is
    // set via a separate fcntl() call that follows pipe(). Linux DOES have
    // pipe2(O_CLOEXEC), but this implementation deliberately uses the same
    // pipe()+fcntl() sequence on both platforms (one code path, not a
    // per-OS branch) -- so the window this test targets is real on Linux
    // too, even though Linux has a pipe2()-based alternative it doesn't
    // take. Without serializing that window, a fork() on ANOTHER thread
    // landing between this invocation's pipe() and its fcntl(F_SETFD,
    // FD_CLOEXEC) inherits this invocation's not-yet-CLOEXEC write end
    // into a totally unrelated child. If that other child execs into a
    // longer-lived program, the extra open copy of the write end keeps
    // THIS invocation's read side from ever seeing EOF -- even though this
    // invocation's own child already exited -- until the other program
    // eventually exits too. Observed from outside, that is a false timeout
    // on a call whose own child finished almost instantly. The mutex fix
    // closes that window on both platforms; it is a no-op in terms of
    // correctness on Linux (pipe2() would also close it), just not the
    // mechanism used there.
    //
    // Rather than relying on uncoordinated scheduler jitter across a large
    // number of threads to get lucky (expensive in CI process/thread
    // budget -- see BR-01 follow-up FP-003), every thread below is
    // released from a shared std::barrier at the start of each round, so
    // every thread's pipe()..fork() sequence for that round starts at
    // essentially the same instant. That turns "some other thread's
    // fork() happens to land inside my few-CPU-cycle window" from a rare
    // coincidence into the common case each round, without needing more
    // than a small, fixed thread count or many iterations to make it
    // likely. "Host" threads fork a real child that outlives every
    // "victim" thread's much shorter deadline; "victim" threads fork a
    // child that exits almost instantly, so a leaked write end from a
    // still-running host can only manifest as an honest timed_out on a
    // victim whose own child already exited. This is not a mathematical
    // guarantee against the pre-fix code -- true simultaneity is still up
    // to the OS scheduler -- but empirically it fails (nonzero
    // false_timeouts below) reliably against the pre-fix code (no mutex)
    // and always passes against the fix. If it were ever to pass
    // spuriously against pre-fix code on some host, false_timeouts == 0 is
    // still the correct invariant to assert: a genuinely fixed runner must
    // never report a false timeout here, regardless of how reliably the
    // race itself reproduces on a given machine.
    constexpr unsigned kNumHostThreads = 4;
    constexpr unsigned kNumVictimThreads = 8;
    constexpr unsigned kNumThreads = kNumHostThreads + kNumVictimThreads; // 12: a small,
                                                                           // CI-safe fixed
                                                                           // ceiling (not
                                                                           // scaled by
                                                                           // hardware_concurrency)
                                                                           // -- see FP-003.
    constexpr int kRounds = 5; // bounded: kNumThreads * kRounds == 60 total child
                                // processes for the whole test, never more.
    constexpr auto kVictimDeadline = 400ms; // comfortably < the host's real 1s runtime
    constexpr auto kHostDeadline = 3000ms;  // generous; the host's own timing isn't under test

    std::atomic<int> false_timeouts{0};
    std::atomic<int> unexpected_no_run{0};
    std::atomic<int> victim_calls{0};

    // Synchronizes every thread's per-round call to run_bounded_subprocess
    // so they start together -- see the rationale above.
    std::barrier sync_point(static_cast<std::ptrdiff_t>(kNumThreads));

    std::vector<std::thread> threads;
    threads.reserve(kNumThreads);

    for (unsigned t = 0; t < kNumHostThreads; ++t) {
        threads.emplace_back([&]() {
            // Leak host: outlives every victim's deadline, so if it ends up
            // holding a victim's write end open (the race), the victim is
            // starved for the host's whole runtime, not just a few
            // microseconds -- long enough to land past its own deadline.
            for (int r = 0; r < kRounds; ++r) {
                sync_point.arrive_and_wait();
                (void)run_bounded_subprocess({"/bin/sleep", "1"},
                                              SubprocessOptions{.deadline = kHostDeadline});
            }
        });
    }
    for (unsigned t = 0; t < kNumVictimThreads; ++t) {
        threads.emplace_back([&]() {
            for (int r = 0; r < kRounds; ++r) {
                sync_point.arrive_and_wait();
                // Victim: exits essentially instantly. A leaked fd from
                // another concurrent invocation keeps its own read side
                // from ever seeing EOF, which can only manifest here as an
                // honest timed_out at kVictimDeadline -- "the child already
                // exited but the pipe never closed" isn't observable any
                // other way from outside this function.
                SubprocessResult r_result = run_bounded_subprocess(
                    {"/usr/bin/printf", "x"}, SubprocessOptions{.deadline = kVictimDeadline});
                victim_calls.fetch_add(1, std::memory_order_relaxed);
                if (r_result.timed_out)
                    false_timeouts.fetch_add(1, std::memory_order_relaxed);
                else if (!r_result.tool_ran)
                    unexpected_no_run.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    for (auto& th : threads)
        th.join();

    CAPTURE(victim_calls.load());
    // The observable invariant BR-01 guards: no invocation whose own child
    // exited promptly ever reports a false timeout because another
    // invocation's leaked write end kept its pipe open.
    CHECK(false_timeouts.load() == 0);
    CHECK(unexpected_no_run.load() == 0);
}

#endif // !_WIN32
