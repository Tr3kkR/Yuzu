/**
 * test_subprocess_runner.cpp -- real fork/exec vectors for the agent-core
 * bounded subprocess runner (subprocess_runner.hpp, #2273 foundation).
 *
 * Unlike most of the suite this drives REAL child processes (/bin/sleep,
 * /bin/sh, /usr/bin/printf) -- run_bounded_subprocess()'s whole contract is
 * about actual kill/reap and exec-outcome behaviour, which a pure-string
 * fixture can't exercise. Every case here is bounded well under the suite
 * timeout: the longest possible single wait is one deadline (at most a few
 * hundred ms, or one cooperative cancel) plus the runner's own internal
 * drain grace (2s), so a bug that makes the deadline/cancel not fire fails
 * the test loudly instead of hanging CI.
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

#endif // !_WIN32
