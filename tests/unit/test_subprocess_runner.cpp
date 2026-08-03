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
 * TWO platform blocks, never interleaved. The first (`#ifndef _WIN32`) holds
 * the POSIX fork/execve vectors -- the bulk of this file, and the only place
 * POSIX-only fixtures (FIFOs, /dev/fd, RLIMIT_NOFILE) appear. The second
 * (`#ifdef _WIN32`, after that block's `#endif`) holds the Windows real-child
 * vectors for the CreateProcessW backend (CDX-FV-05): before they existed the
 * MSVC CI leg compiled this file and ran NOTHING against that backend, so a
 * broken suspended-create / Job-Object-assign / ResumeThread / deadline-kill
 * path could ship green. Neither block is even parsed on the other platform.
 */

#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include "test_helpers.hpp"

#include <yuzu/agent/subprocess_launch_spec.hpp>
#include <yuzu/agent/subprocess_runner.hpp>

#include <algorithm>
#include <barrier>
#include <chrono>
#include <cstdint>
#include <cstring> // std::strerror (B6 spawn_errno diagnostic)
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <atomic>
#include <fcntl.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/syscall.h> // SYS_execveat -- gates the sec-8 exec_verify tests below
#endif

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
    CHECK(result.termination_reason == TerminationReason::exited);
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

TEST_CASE("run_bounded_subprocess: the output_cap byte budget bounds result.lines even when max_lines "
          "is armed (sec-7)",
          "[subprocess][output_cap]") {
    // Before the fix, an armed max_lines consulted ONLY the count cap and
    // never checked stored_line_bytes -- so a caller-set max_lines could
    // store up to max_lines lines with NO byte ceiling, independent of
    // output_cap_bytes. Here max_lines (1000) is set far higher than what a
    // tiny output_cap (32 bytes) can ever admit: /usr/bin/yes emits an
    // endless stream of 2-byte lines ("x\n"), so with the byte budget
    // correctly enforced, result.lines must stop growing once ~16 lines'
    // worth of bytes (32 / 2) are stored, never reaching anywhere near 1000.
    SubprocessResult result = run_bounded_subprocess(
        {"/usr/bin/yes", "x"},
        SubprocessOptions{.deadline = 300ms, .max_lines = 1000, .output_cap_bytes = 32});
    CHECK(result.lines.size() <= 16);
    CHECK(result.lines.size() < 1000);
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
    CHECK(result.termination_reason == TerminationReason::deadline);
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
    CHECK(result.termination_reason == TerminationReason::spawn_error);
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
    CHECK(result.termination_reason == TerminationReason::spawn_error);
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

TEST_CASE("run_bounded_subprocess: a natural nonzero exit survives the stop_after_max_lines fixup (K-5)",
          "[subprocess][deadline][macos][linux]") {
    // The child prints exactly max_lines lines and THEN exits nonzero on its
    // own, before any kill. try_reap() records the real WEXITSTATUS; the
    // line-cap completion fixup must NOT overwrite a genuine status with 0
    // (that would report a failed tool as SUCCESS -- the exact honesty
    // violation the runner exists to prevent). Only the -1 signal-death
    // sentinel may be rewritten to 0.
    SubprocessResult result = run_bounded_subprocess(
        {"/bin/sh", "-c", "printf 'a\\nb\\n'; exit 3"},
        SubprocessOptions{.deadline = 5000ms, .max_lines = 2, .stop_after_max_lines = true});

    CHECK_FALSE(result.timed_out);
    CHECK(result.tool_ran);
    CHECK(result.exit_code == 3); // NOT clobbered to 0
    // The child exited on its own (child_reaped was already true when the
    // line-cap kill decision ran) -- termination_reason correctly credits
    // `exited`, not `line_limit`, even though the cap was also hit.
    CHECK(result.termination_reason == TerminationReason::exited);
}

TEST_CASE("run_bounded_subprocess: stop_after_max_lines cap-stop of a genuinely signal-killed child "
          "never fabricates exit_code 0 (ADR-3002 fixes the pre-existing success-sentinel)",
          "[subprocess][deadline][macos][linux]") {
    // The complementary case to K-5: a child that keeps producing lines past
    // the cap and is KILLED by the runner (never exits naturally) keeps the
    // -1 signal-death sentinel -- ADR-3002 removed the previous fixup that
    // rewrote this to a fabricated exit_code=0 "success". The "this was a
    // deliberate, clean stop, not a failure" signal now lives ENTIRELY in
    // termination_reason (line_limit), never in a synthesized exit code.
    SubprocessResult result = run_bounded_subprocess(
        {"/bin/sh", "-c", "while :; do printf 'x\\n'; done"},
        SubprocessOptions{.deadline = 5000ms, .max_lines = 3, .stop_after_max_lines = true});

    CHECK_FALSE(result.timed_out);
    CHECK(result.tool_ran);
    CHECK(result.exit_code == -1); // signal-death sentinel -- NEVER fabricated to 0
    CHECK(result.termination_reason == TerminationReason::line_limit);
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
    CHECK(result.termination_reason == TerminationReason::cancelled);
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

TEST_CASE("run_bounded_subprocess bounds result.lines by the same cap as result.output for a "
          "newline-rich child (BR-001)",
          "[subprocess][deadline][macos][linux]") {
    // A child that emits nothing but short lines used to blow past the 1MB
    // output blob cap on result.lines too: line materialization iterated
    // over the WHOLE read rather than just the `take` prefix admitted into
    // result.output, so lines could accumulate far past what 1MB of source
    // text implies (observed against /usr/bin/yes x: lines=928256 while
    // output=1000000). This drives a real child past the cap and asserts
    // both are bounded together.
    SubprocessResult result = run_bounded_subprocess(
        {"/usr/bin/awk", "BEGIN{for(i=0;i<600000;++i)print \"x\"}"},
        SubprocessOptions{.deadline = 10000ms});

    CHECK_FALSE(result.timed_out);
    CHECK(result.tool_ran);
    CHECK(result.output.size() == 1'000'000);
    CHECK(result.output_truncated);
    // Each stored line is "x\n" (2 bytes admitted per line), so the 1MB cap
    // bounds lines to at most 500'000 -- nowhere near the pre-fix 928256.
    CHECK(result.lines.size() <= 500'000);
}

TEST_CASE("run_bounded_subprocess with stop_after_max_lines cleanly stops at exactly N lines "
          "instead of draining to the deadline (BR-004)",
          "[subprocess][deadline][macos][linux]") {
    // /usr/bin/yes never stops on its own. Without stop_after_max_lines,
    // max_lines only caps what gets STORED while the runner keeps draining
    // the pipe until the deadline -- reported as a partial, timed_out
    // result. With stop_after_max_lines set, reaching max_lines is itself a
    // clean, bounded success: the runner kills+reaps the child immediately
    // and reports it as a normal completion, not a timeout or truncation.
    constexpr std::size_t kLines = 500;
    SubprocessResult result = run_bounded_subprocess(
        {"/usr/bin/yes", "x"}, SubprocessOptions{.deadline = 10000ms,
                                                  .max_lines = kLines,
                                                  .stop_after_max_lines = true});

    CHECK_FALSE(result.timed_out);
    CHECK_FALSE(result.output_truncated);
    REQUIRE(result.lines.size() == kLines);
    CHECK(result.lines[0] == "x");
    // A clean bounded stop is signalled by termination_reason == line_limit,
    // NOT by a fabricated exit_code. The runner SIGKILLs `yes` to stop it, so
    // exit_code stays the honest -1 sentinel (the removed pre-ADR-3002 fixup
    // used to synthesize 0 here -- exactly the dishonesty the sentinel fix
    // eliminates; see subprocess_runner.hpp stop_after_max_lines contract).
    CHECK(result.termination_reason == TerminationReason::line_limit);
    CHECK(result.exit_code == -1);
}

namespace {
// Places a deliberately non-CLOEXEC descriptor at `target` (dup2 always clears
// CLOEXEC on the new fd — exactly the inherited-leak scenario), then asks a
// child whether it can still see it via /dev/fd/<target>. Returns true iff the
// child could NOT see it (i.e. the runner swept it close-on-exec before exec).
bool child_cannot_see_fd(int target) {
    const int devnull = ::open("/dev/null", O_RDONLY);
    REQUIRE(devnull >= 0);
    REQUIRE(::dup2(devnull, target) == target);
    ::close(devnull);
    // Precondition: the placed fd really is inheritable (non-CLOEXEC).
    REQUIRE((::fcntl(target, F_GETFD) & FD_CLOEXEC) == 0);

    const std::string probe = "if [ -e /dev/fd/" + std::to_string(target) +
                              " ]; then printf LEAK; else printf CLEAN; fi";
    SubprocessResult r =
        run_bounded_subprocess({"/bin/sh", "-c", probe}, SubprocessOptions{.deadline = 5000ms});
    ::close(target);
    return r.tool_ran && r.output == "CLEAN";
}
} // namespace

// B3 (review blocker): a subprocess exec'd by the runner must NOT inherit fds
// this process opened without O_CLOEXEC — they would leak into an external,
// possibly-root helper. The runner marks every fd >= 3 close-on-exec first.
TEST_CASE("run_bounded_subprocess does not leak an inherited non-CLOEXEC fd into the child",
          "[subprocess][fd]") {
    // A low-numbered inherited fd (below any historical cap) is swept.
    CHECK(child_cannot_see_fd(21));
}

// An early fix capped its in-child fcntl sweep at 4096, silently leaking any fd
// at or above it under an ordinary large RLIMIT_NOFILE (systemd's 524288, this
// host's 1048576). The sweep now enumerates the real open-fd set, so a fd placed
// at 5000 is caught regardless of any ceiling.
TEST_CASE("run_bounded_subprocess sweeps an inherited fd above the old 4096 cap",
          "[subprocess][fd]") {
    struct rlimit saved{};
    REQUIRE(::getrlimit(RLIMIT_NOFILE, &saved) == 0);
    struct rlimit raised = saved;
    const rlim_t want = 6000;
    raised.rlim_cur =
        (saved.rlim_max == RLIM_INFINITY || saved.rlim_max >= want) ? want : saved.rlim_max;
    const bool bumped = (::setrlimit(RLIMIT_NOFILE, &raised) == 0);
    struct rlimit now{};
    ::getrlimit(RLIMIT_NOFILE, &now);
    if (!bumped || now.rlim_cur <= 4096) {
        SKIP("host RLIMIT_NOFILE cannot be raised above 4096; cap-regression path unexercisable here");
    }
    CHECK(child_cannot_see_fd(5000));
    ::setrlimit(RLIMIT_NOFILE, &saved); // restore
}

// CODEX-1 (adversarial review): a soft-limit ceiling is not a valid upper bound
// on the live fd set — POSIX keeps an already-open fd valid when RLIMIT_NOFILE is
// later LOWERED below it. Placing a fd at 5000, then lowering the soft limit to
// 1024, must still leave the exec'd child unable to see it (the child sweeps to
// the HARD limit, which soft can never exceed; a `rlim_cur` ceiling would miss it).
TEST_CASE("run_bounded_subprocess sweeps an inherited fd retained after the soft limit is lowered",
          "[subprocess][fd]") {
    struct rlimit saved{};
    REQUIRE(::getrlimit(RLIMIT_NOFILE, &saved) == 0);
    struct rlimit raised = saved;
    const rlim_t want = 6000;
    raised.rlim_cur =
        (saved.rlim_max == RLIM_INFINITY || saved.rlim_max >= want) ? want : saved.rlim_max;
    if (::setrlimit(RLIMIT_NOFILE, &raised) != 0 || raised.rlim_cur <= 4096) {
        SKIP("host RLIMIT_NOFILE cannot be raised to place a fd at 5000");
    }
    const int devnull = ::open("/dev/null", O_RDONLY);
    REQUIRE(devnull >= 0);
    REQUIRE(::dup2(devnull, 5000) == 5000);
    ::close(devnull);
    REQUIRE((::fcntl(5000, F_GETFD) & FD_CLOEXEC) == 0); // deliberately inheritable

    // Lower the soft limit BELOW the open fd — the fd stays valid; a ceiling taken
    // from the now-current soft limit (1024) would fail to sweep fd 5000.
    struct rlimit lowered = saved;
    lowered.rlim_cur = 1024;
    ::setrlimit(RLIMIT_NOFILE, &lowered);

    const std::string probe = "if [ -e /dev/fd/5000 ]; then printf LEAK; else printf CLEAN; fi";
    SubprocessResult r =
        run_bounded_subprocess({"/bin/sh", "-c", probe}, SubprocessOptions{.deadline = 5000ms});
    ::close(5000);
    ::setrlimit(RLIMIT_NOFILE, &saved); // restore
    CHECK(r.tool_ran);
    CHECK(r.output == "CLEAN");
}

// Round-4 (adversarial review): a fd an UNRELATED thread opens without O_CLOEXEC
// concurrently with a spawn must never leak into the exec'd child. The sweep runs
// post-fork over the whole range, so it catches every fd present at fork()
// regardless of when/which thread opened it — unlike a pre-fork snapshot, which
// could miss one opened in the enumerate->fork window. This drives that window
// under load: a racer thread continuously places/removes an inheritable fd at a
// fixed number while the main thread spawns; the child must always report CLEAN.
TEST_CASE("run_bounded_subprocess never leaks a fd opened by a racing thread (TOCTOU)",
          "[subprocess][fd]") {
    constexpr int kRaceFd = 25; // a fixed number the racer toggles; well above the runner's pipes
    std::atomic<bool> stop{false};
    std::thread racer([&] {
        while (!stop.load(std::memory_order_relaxed)) {
            const int fd = ::open("/dev/null", O_RDONLY);
            if (fd < 0)
                continue;
            if (::dup2(fd, kRaceFd) == kRaceFd) // dup2 clears CLOEXEC -> deliberately inheritable
                ::close(kRaceFd);
            ::close(fd);
        }
    });

    const std::string probe =
        "if [ -e /dev/fd/" + std::to_string(kRaceFd) + " ]; then printf LEAK; else printf CLEAN; fi";
    bool any_leak = false;
    for (int i = 0; i < 60 && !any_leak; ++i) {
        SubprocessResult r =
            run_bounded_subprocess({"/bin/sh", "-c", probe}, SubprocessOptions{.deadline = 5000ms});
        if (r.tool_ran && r.output == "LEAK")
            any_leak = true;
    }
    stop.store(true, std::memory_order_relaxed);
    racer.join();
    CHECK_FALSE(any_leak);
}

// ---------------------------------------------------------------------------
// ADR-3002 runner-contract gaps + best-practice addendum (A1-A6, B1-B6).
// ---------------------------------------------------------------------------

TEST_CASE("run_bounded_subprocess rejects a relative argv[0] at RUNTIME in every build type (ADR-3002)",
          "[subprocess][validation]") {
    SubprocessResult r = run_bounded_subprocess({"relative/bin/echo"}, SubprocessOptions{.deadline = 1000ms});
    CHECK_FALSE(r.tool_ran);
    CHECK_FALSE(r.timed_out);
    CHECK(r.termination_reason == TerminationReason::spawn_error);
}

TEST_CASE("run_bounded_subprocess rejects an embedded NUL in any argv element at RUNTIME (ADR-3002)",
          "[subprocess][validation]") {
    SubprocessResult r = run_bounded_subprocess({"/bin/echo", std::string("a\0b", 3)},
                                                  SubprocessOptions{.deadline = 1000ms});
    CHECK_FALSE(r.tool_ran);
    CHECK(r.termination_reason == TerminationReason::spawn_error);
}

TEST_CASE("run_bounded_subprocess reports `signaled` for a child that dies from its OWN signal, "
          "never confused with a runner-initiated kill",
          "[subprocess][termination_reason]") {
    // The generous 5s deadline proves this resolves via the child's own
    // self-signal, not our deadline path.
    SubprocessResult r = run_bounded_subprocess({"/bin/sh", "-c", "kill -9 $$"},
                                                  SubprocessOptions{.deadline = 5000ms});
    CHECK_FALSE(r.timed_out);
    CHECK(r.tool_ran); // exec of /bin/sh succeeded before the self-signal
    CHECK(r.exit_code == -1); // signal death -- never a fabricated exit status
    CHECK(r.termination_reason == TerminationReason::signaled);
}

TEST_CASE("a per-invocation CancellationToken cancels only its own call, never a concurrent one "
          "sharing no token (ADR-3002 per-invocation cancel)",
          "[subprocess][cancel_token]") {
    auto token_a = std::make_shared<CancellationToken>();
    auto token_b = std::make_shared<CancellationToken>();
    token_a->cancel(); // pre-armed: token_a's own call must notice this on its very first poll

    SubprocessResult result_b;
    std::thread b_thread([&]() {
        result_b = run_bounded_subprocess({"/bin/sh", "-c", "sleep 0.3; exit 5"},
                                           SubprocessOptions{.deadline = 5000ms, .cancel_token = token_b});
    });

    SubprocessResult result_a = run_bounded_subprocess(
        {"/bin/sleep", "30"}, SubprocessOptions{.deadline = 60000ms, .cancel_token = token_a});
    b_thread.join();

    CHECK(result_a.timed_out);
    CHECK(result_a.termination_reason == TerminationReason::cancelled);

    // token_b was never cancelled -- its call runs to a genuine natural
    // completion, proving token_a's cancellation had no effect on it.
    CHECK_FALSE(result_b.timed_out);
    CHECK(result_b.tool_ran);
    CHECK(result_b.exit_code == 5);
    CHECK(result_b.termination_reason == TerminationReason::exited);
}

TEST_CASE("run_bounded_subprocess honors a caller-configured output_cap_bytes smaller than the "
          "historical ~1MB default (ADR-3002: caller-configurable byte cap)",
          "[subprocess][output_cap]") {
    SubprocessResult r =
        run_bounded_subprocess({"/usr/bin/yes", "x"}, SubprocessOptions{.deadline = 300ms, .output_cap_bytes = 1000});
    CHECK(r.output_truncated);
    CHECK(r.output.size() == 1000);
}

TEST_CASE("run_bounded_subprocess: on_line delivers every produced line, uncapped by max_lines "
          "(ADR-3002 streaming primitive)",
          "[subprocess][streaming]") {
    std::vector<std::string> streamed;
    SubprocessResult r = run_bounded_subprocess(
        {"/usr/bin/printf", "%s\n", "a", "b", "c", "d", "e"},
        SubprocessOptions{.deadline = 5000ms, .max_lines = 2,
                           .on_line = [&](const std::string& line) { streamed.push_back(line); }});
    CHECK_FALSE(r.timed_out);
    REQUIRE(r.lines.size() == 2);   // the collect-at-end contract stays capped
    REQUIRE(streamed.size() == 5);  // every line reaches the streaming callback, uncapped
    CHECK(streamed[0] == "a");
    CHECK(streamed[4] == "e");
}

TEST_CASE("run_bounded_subprocess: A6 chdir's the child into working_dir",
          "[subprocess][working_dir]") {
    std::filesystem::path dir = yuzu::test::unique_temp_path("yuzu_test_cwd_");
    REQUIRE(std::filesystem::create_directory(dir));
    struct Cleanup {
        std::filesystem::path p;
        ~Cleanup() {
            std::error_code ec;
            std::filesystem::remove(p, ec);
        }
    } cleanup{dir};

    SubprocessResult r = run_bounded_subprocess({"/bin/pwd"},
                                                  SubprocessOptions{.deadline = 5000ms, .working_dir = dir.string()});
    CHECK(r.tool_ran);
    REQUIRE(r.lines.size() == 1);
    std::error_code ec;
    CHECK(std::filesystem::path(r.lines[0]) == std::filesystem::canonical(dir, ec));
}

TEST_CASE("run_bounded_subprocess: A4 always suppresses core dumps in the child",
          "[subprocess][rlimits]") {
    SubprocessResult r =
        run_bounded_subprocess({"/bin/sh", "-c", "ulimit -c"}, SubprocessOptions{.deadline = 5000ms});
    CHECK(r.tool_ran);
    REQUIRE(r.lines.size() == 1);
    CHECK(r.lines[0] == "0");
}

TEST_CASE("run_bounded_subprocess: A6 umask(077) leaves the child with a restrictive default umask",
          "[subprocess][rlimits]") {
    SubprocessResult r =
        run_bounded_subprocess({"/bin/sh", "-c", "umask"}, SubprocessOptions{.deadline = 5000ms});
    CHECK(r.tool_ran);
    REQUIRE(r.lines.size() == 1);
    CHECK(r.lines[0].find("077") != std::string::npos);
}

TEST_CASE("run_bounded_subprocess: A5 env is a clear-and-allow-list, not the daemon's own environment",
          "[subprocess][env]") {
    SubprocessResult r = run_bounded_subprocess({"/usr/bin/env"}, SubprocessOptions{.deadline = 5000ms});
    CHECK(r.tool_ran);
    CHECK(contains_line(r.lines, "LC_ALL=C"));
    for (const auto& line : r.lines) {
        CHECK(line.substr(0, 3) != "LD_");
        CHECK(line.substr(0, 5) != "DYLD_");
        CHECK(line.substr(0, 4) != "IFS=");
        CHECK(line.substr(0, 9) != "BASH_ENV=");
        CHECK(line.substr(0, 11) != "GCONV_PATH=");
    }
}

TEST_CASE("run_bounded_subprocess: B3 an opt-in RLIMIT_CPU cap is applied to the child, off by default "
          "on every other test in this file",
          "[subprocess][rlimits]") {
    SubprocessOptions opts{.deadline = 5000ms};
    opts.rlimits.cpu_seconds = 7;
    SubprocessResult r = run_bounded_subprocess({"/bin/sh", "-c", "ulimit -t"}, opts);
    CHECK(r.tool_ran);
    CHECK(contains_line(r.lines, "7"));
}

TEST_CASE("run_bounded_subprocess captures a nonzero child rusage on reap (B4), never fabricated",
          "[subprocess][rusage]") {
    SubprocessResult r =
        run_bounded_subprocess({"/bin/sh", "-c", "exit 0"}, SubprocessOptions{.deadline = 5000ms});
    CHECK(r.tool_ran);
    // A real fork+exec always burns SOME user or system time -- never both
    // zero for a process that actually ran.
    CHECK((r.child_user_time.count() > 0 || r.child_system_time.count() > 0));
}

TEST_CASE("run_bounded_subprocess: soft_terminate_grace lets a trapping child exit cleanly instead of "
          "being SIGKILLed immediately (ADR-3002 mutating-tool grace)",
          "[subprocess][soft_terminate]") {
    SubprocessResult r = run_bounded_subprocess(
        {"/bin/sh", "-c", "trap 'exit 42' TERM; while :; do sleep 0.05; done"},
        SubprocessOptions{.deadline = 300ms, .soft_terminate_grace = 2000ms});
    CHECK(r.timed_out);
    CHECK(r.tool_ran);
    // Proves SIGTERM (not an immediate SIGKILL) was delivered and the trap
    // ran to completion within the grace window -- a hard-killed child could
    // never report this exit code (see the -1 sentinel below).
    CHECK(r.exit_code == 42);
    CHECK(r.termination_reason == TerminationReason::deadline);
}

TEST_CASE("run_bounded_subprocess: soft_terminate_grace escalates to the unmodified hard kill once "
          "the grace elapses without the child responding",
          "[subprocess][soft_terminate]") {
    const auto start = std::chrono::steady_clock::now();
    SubprocessResult r = run_bounded_subprocess(
        {"/bin/sh", "-c", "trap '' TERM; while :; do sleep 0.05; done"},
        SubprocessOptions{.deadline = 200ms, .soft_terminate_grace = 300ms});
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(r.timed_out);
    CHECK(r.exit_code == -1); // never caught the grace -- escalated to the hard SIGKILL
    CHECK(r.termination_reason == TerminationReason::deadline);
    // Bounded: deadline (200ms) + soft grace (300ms) + kDrainGrace (2000ms) +
    // generous CI-noise margin.
    CHECK(elapsed < 10s);
}

TEST_CASE("run_bounded_subprocess: soft_terminate escalates via the process GROUP even after the leader "
          "is reaped, so a descendant holding stdout cannot hang the runner (CDX-002)",
          "[subprocess][soft_terminate]") {
    const auto start = std::chrono::steady_clock::now();
    // The reproduced hang: a leader that traps SIGTERM and exits fast, plus a
    // descendant that IGNORES SIGTERM and keeps the inherited stdout pipe open.
    // The old grace escalation was guarded by `!child_reaped`, so once the leader
    // was reaped no hard kill was ever armed and — with the pipe never reaching
    // EOF — the runner spun past deadline+grace+drain indefinitely. The fix
    // escalates to a process-GROUP SIGKILL regardless of leader reap.
    SubprocessResult r = run_bounded_subprocess(
        {"/bin/sh", "-c",
         "sh -c 'trap \"\" TERM; while :; do sleep 0.05; done' & trap 'exit 0' TERM; "
         "while :; do sleep 0.05; done"},
        SubprocessOptions{.deadline = 200ms, .soft_terminate_grace = 300ms});
    const auto elapsed = std::chrono::steady_clock::now() - start;
    CHECK(r.timed_out);
    CHECK(r.termination_reason == TerminationReason::deadline);
    // Load-bearing: it RETURNS (bounded) rather than hanging on the descendant.
    CHECK(elapsed < 10s);
}

#if defined(__linux__) && defined(SYS_execveat)
TEST_CASE("exec_verify (B6) accepts a correctly-sized target and execs it via the verified path "
          "(Linux execveat -- an atomic fd-based exec primitive exists here)",
          "[subprocess][exec_verify]") {
    // toctou_verified_exec() opens argv[0] with O_NOFOLLOW (by design: a
    // symlink swap between the caller's stat and this open() is exactly the
    // TOCTOU it exists to close), so it fails closed with ELOOP if argv[0]
    // itself is a symlink -- observed for real on a CI runner where
    // /bin/echo IS one (deterministic on that host, not a flake). A system
    // path's symlink-ness varies by distro/runner and isn't this test's
    // concern; make a throwaway REGULAR-file copy so the test exercises the
    // documented happy path (a genuine regular file) regardless of host
    // layout. std::filesystem::copy_file follows symlinks by default, so the
    // copy is a plain file even when the source isn't.
    //
    // The copy keeps argv[0]'s basename ("echo"): on that same runner /bin/echo
    // resolves to a single-binary coreutils build that dispatches its behaviour
    // by looking at basename(argv[0]) -- a copy under an unrelated name execs
    // fine (spawn_errno=0) but the multiplexer doesn't recognise itself and
    // exits 1, which a differently-named copy would misreport as an exec_verify
    // failure when the exec actually succeeded.
    std::filesystem::path tmp_dir = yuzu::test::unique_temp_path("yuzu_test_b6_echo_");
    REQUIRE(std::filesystem::create_directory(tmp_dir));
    struct Cleanup {
        std::filesystem::path p;
        ~Cleanup() {
            std::error_code ec;
            std::filesystem::remove_all(p, ec);
        }
    } cleanup{tmp_dir};

    std::filesystem::path exe_copy = tmp_dir / "echo";
    std::filesystem::copy_file("/bin/echo", exe_copy);
    REQUIRE(::chmod(exe_copy.c_str(), 0755) == 0);
    struct stat st{};
    REQUIRE(::stat(exe_copy.c_str(), &st) == 0);
    SubprocessOptions opts{.deadline = 5000ms};
    opts.exec_verify.enabled = true;
    opts.exec_verify.require_root_owned = false; // test binaries aren't root-owned in CI
    opts.exec_verify.expected_size = static_cast<std::uint64_t>(st.st_size);
    SubprocessResult r = run_bounded_subprocess({exe_copy.string(), "hi"}, opts);
    // Diagnostic only, printed by Catch2 solely on a failing CHECK below:
    // names the exact reason toctou_verified_exec's child branch gave up
    // (report_setup_failure_and_exit's errno), so a CI failure on an
    // unfamiliar runner environment (e.g. a syscall filter blocking
    // execveat) is diagnosable from the log instead of a bare
    // "tool_ran == false".
    INFO("spawn_errno=" << r.spawn_errno << " (" << std::strerror(r.spawn_errno) << ")");
    CHECK(r.tool_ran);
    CHECK(r.exit_code == 0);
}
#else
TEST_CASE("exec_verify (B6) fails CLOSED on this platform even for a fully-matching target -- no "
          "atomic fd-exec primitive exists here to close the TOCTOU gap (sec-8)",
          "[subprocess][exec_verify]") {
    // macOS/BSD (and any Linux build without SYS_execveat): every fstat check
    // this run requests passes -- regular file, size matches exactly,
    // ownership check waived -- so before the sec-8 fix this still exec'd via
    // close(fd); execve(path, ...), which re-resolves argv[0] from the
    // filesystem and reopens the exact TOCTOU window the verify exists to
    // close. It must now fail closed instead, matching Windows' BR-004
    // rather than degrading to an unverified exec.
    struct stat st{};
    REQUIRE(::stat("/bin/echo", &st) == 0);
    SubprocessOptions opts{.deadline = 5000ms};
    opts.exec_verify.enabled = true;
    opts.exec_verify.require_root_owned = false;
    opts.exec_verify.expected_size = static_cast<std::uint64_t>(st.st_size); // matches exactly
    SubprocessResult r = run_bounded_subprocess({"/bin/echo", "hi"}, opts);
    CHECK_FALSE(r.tool_ran);
    CHECK(r.termination_reason == TerminationReason::spawn_error);
}
#endif

TEST_CASE("exec_verify (B6) fails CLOSED on a size mismatch instead of exec'ing anyway",
          "[subprocess][exec_verify]") {
    SubprocessOptions opts{.deadline = 5000ms};
    opts.exec_verify.enabled = true;
    opts.exec_verify.require_root_owned = false;
    opts.exec_verify.expected_size = 1; // /bin/echo is never exactly 1 byte
    SubprocessResult r = run_bounded_subprocess({"/bin/echo", "hi"}, opts);
    CHECK_FALSE(r.tool_ran);
    CHECK(r.termination_reason == TerminationReason::spawn_error);
}

TEST_CASE("probe_tool_path returns the first existing, absolute, executable candidate",
          "[subprocess][probe]") {
    CHECK(probe_tool_path({"/no/such/thing-xyz", "/bin/sh"}) == "/bin/sh");
    CHECK(probe_tool_path({"/no/such/thing-xyz"}).empty());
    CHECK(probe_tool_path({"relative/path", "/bin/sh"}) == "/bin/sh"); // relative candidates skipped
}

// ---------------------------------------------------------------------------
// B1: the pure build_launch_spec()/LaunchSpec core, exercised WITHOUT
// spawning a real process (CLAUDE.md test discipline) -- the bounded
// real-child tests above remain the integration layer this does not
// replace.
// ---------------------------------------------------------------------------

namespace {
class FakeSpawner : public yuzu::agent::Spawner {
public:
    yuzu::agent::SpawnOutcome scripted;
    yuzu::agent::SpawnOutcome spawn(const yuzu::agent::LaunchSpec&) override { return scripted; }
};
} // namespace

// NOTE: the host-agnostic PURE launch-spec tests (build_launch_spec validation,
// the A5 allow-list env, default_launch_env, quote_windows_arg, and the Windows
// handle policy) moved to test_subprocess_launch_spec.cpp so they run on EVERY
// platform including Windows (K-10/CDX-R2-004) rather than being compiled out by
// this file's `#ifndef _WIN32` real-child guard.

TEST_CASE("the Spawner interface is independently injectable/testable without spawning a process (B1)",
          "[subprocess][launch_spec]") {
    using namespace yuzu::agent;
    LaunchSpec spec = build_launch_spec({"/bin/echo", "hi"}, LaunchOptions{});
    REQUIRE(spec.error == LaunchSpecError::none);

    FakeSpawner fake;
    fake.scripted = SpawnOutcome{true, 0, false};
    SpawnOutcome outcome = fake.spawn(spec);
    CHECK(outcome.tool_ran);
    CHECK(outcome.exit_code == 0);
    CHECK_FALSE(outcome.spawn_error);
}

#endif // !_WIN32

#ifdef _WIN32

// ---------------------------------------------------------------------------
// CDX-FV-05: Windows real-child vectors for the CreateProcessW backend.
//
// Everything above compiles to nothing on Windows, which left the MSVC CI leg
// with ZERO real-child coverage of the backend this branch introduces:
// CreateProcessW with CREATE_SUSPENDED, Job Object assignment before resume,
// handle allowlisting via PROC_THREAD_ATTRIBUTE_HANDLE_LIST, ResumeThread
// failure handling, and deadline Job termination (BR-003, H3, L1, M-c, L-d,
// CDX-007). The pure launch-spec tests in test_subprocess_launch_spec.cpp run
// on every platform but cannot detect a broken CreateProcessW or a failed Job
// assignment -- only a real child can.
//
// Deliberately small and conservative, mirroring the assertion shape of the
// POSIX twins above: only the public run_bounded_subprocess /
// SubprocessOptions / SubprocessResult / CancellationToken surface is used (no
// windows.h in a test body), and every command is one guaranteed present on
// any Windows Server / Windows 10+ image. Bounded exactly as the POSIX cases
// are -- one deadline plus the runner's internal 2s drain grace -- so a
// backend that fails to kill its child fails loudly instead of hanging CI.
// ---------------------------------------------------------------------------

#include <yuzu/agent/subprocess_runner.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

using namespace yuzu::agent;
using namespace std::chrono_literals;

namespace {

// argv[0] MUST be absolute -- run_bounded_subprocess never PATH-searches
// (subprocess_runner.hpp) -- and neither of these carries a banned
// .bat/.cmd/.com extension. These are the same canonical system paths the
// runner's own Windows backend already assumes for the child's working
// directory ("C:\\Windows\\System32", subprocess_runner.cpp) and its A5
// environment allow-list (SystemRoot/windir = "C:\\Windows",
// subprocess_launch_spec.hpp default_launch_env).
//
// Every argv token below is passed as its OWN element, so the Colascione
// quoter never has to quote anything: the child sees a bare
// `cmd.exe /d /c <verb> <arg>` command line, keeping cmd.exe's /C
// quote-stripping rules entirely out of play. `/d` disables the registry
// AutoRun hook, so a machine-local `Command Processor\AutoRun` value on a CI
// image can neither inject output into the captured stream nor change the
// child's exit code -- these assertions describe the runner, not the host.
constexpr const char* kCmdExe = "C:\\Windows\\System32\\cmd.exe";

// `ping -n 30 127.0.0.1` is the portable Windows sleep: ~29s of one-second
// intervals, far longer than any deadline asserted below, with no PowerShell
// and no real network dependency (loopback ICMP is serviced locally, and even
// a blocked ICMP path only makes it take LONGER, never shorter).
constexpr const char* kPingExe = "C:\\Windows\\System32\\ping.exe";

} // namespace

TEST_CASE("run_bounded_subprocess (Windows) runs a real child through CreateProcessW to a clean exit",
          "[subprocess][windows]") {
    // The end-to-end proof that the suspended-create -> Job-assign ->
    // ResumeThread sequence actually works: a child that never resumed would
    // sit suspended until the deadline killed the Job and report
    // timed_out/deadline instead of exited/0 (CDX-007).
    SubprocessResult result = run_bounded_subprocess(
        {kCmdExe, "/d", "/c", "exit", "0"}, SubprocessOptions{.deadline = 10000ms});

    CHECK_FALSE(result.timed_out);
    CHECK(result.tool_ran);
    CHECK(result.exit_code == 0);
    CHECK(result.termination_reason == TerminationReason::exited);
}

TEST_CASE("run_bounded_subprocess (Windows) captures a real nonzero exit code from a child that "
          "runs to completion",
          "[subprocess][windows]") {
    SubprocessResult result = run_bounded_subprocess(
        {kCmdExe, "/d", "/c", "exit", "3"}, SubprocessOptions{.deadline = 10000ms});

    CHECK_FALSE(result.timed_out);
    CHECK(result.tool_ran);
    CHECK(result.exit_code == 3);
    CHECK(result.termination_reason == TerminationReason::exited);
}

TEST_CASE("run_bounded_subprocess (Windows) captures child stdout through the allowlisted pipe handle",
          "[subprocess][windows]") {
    // Load-bearing for the A1 handle allowlist (H3/L1): the stdout write end is
    // the one handle named in PROC_THREAD_ATTRIBUTE_HANDLE_LIST, so if the list
    // were wrong -- or the STARTF_USESTDHANDLES wiring broken -- the child would
    // produce no capturable output at all and this would come back empty.
    SubprocessResult result = run_bounded_subprocess(
        {kCmdExe, "/d", "/c", "echo", "hi"}, SubprocessOptions{.deadline = 10000ms});

    CHECK_FALSE(result.timed_out);
    CHECK(result.tool_ran);
    CHECK(result.exit_code == 0);
    CHECK(result.termination_reason == TerminationReason::exited);
    // cmd.exe emits CRLF; the runner strips the trailing '\r' per line, so the
    // stored line is exactly "hi" while the raw blob keeps what was written.
    REQUIRE(result.lines.size() == 1);
    CHECK(result.lines[0] == "hi");
    CHECK(result.output.find("hi") != std::string::npos);
}

TEST_CASE("run_bounded_subprocess (Windows) terminates the Job at the deadline and returns partial, "
          "honest results instead of waiting out the child",
          "[subprocess][windows]") {
    // BR-003: the deadline path terminates the whole Job Object, not just the
    // leader. A child that outran the deadline by ~29s must be dead and the call
    // returned long before its natural end.
    const auto start = std::chrono::steady_clock::now();

    SubprocessResult result = run_bounded_subprocess({kPingExe, "-n", "30", "127.0.0.1"},
                                                       SubprocessOptions{.deadline = 500ms});

    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(result.timed_out);
    CHECK(result.tool_ran); // CreateProcessW succeeded before the kill
    // A killed child is never given a fabricated exit status -- not even
    // TerminateJobObject's own exit value (same contract as the POSIX twin).
    CHECK(result.exit_code == -1);
    CHECK(result.termination_reason == TerminationReason::deadline);
    // Bounded proof: the runner's documented worst case here is deadline (500ms)
    // plus one drain grace (2000ms). 15s is a generous CI-noise margin that is
    // still well under the child's own ~29s natural runtime, so a Job that
    // failed to terminate fails this loudly rather than passing slowly.
    CHECK(elapsed < 15s);
}

TEST_CASE("run_bounded_subprocess (Windows) honours a pre-armed per-invocation CancellationToken",
          "[subprocess][windows]") {
    // Pre-armed, so the very first poll of the wait loop must notice it. The
    // deadline (60s) is set well beyond both the child's own ~29s runtime and
    // the bound asserted below, so a pass can only mean the CANCEL -- never the
    // deadline -- ended the run.
    auto token = std::make_shared<CancellationToken>();
    token->cancel();

    const auto start = std::chrono::steady_clock::now();

    SubprocessResult result =
        run_bounded_subprocess({kPingExe, "-n", "30", "127.0.0.1"},
                                SubprocessOptions{.deadline = 60000ms, .cancel_token = token});

    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(result.timed_out);
    CHECK(result.termination_reason == TerminationReason::cancelled);
    CHECK(elapsed < 15s);
}

#endif // _WIN32
