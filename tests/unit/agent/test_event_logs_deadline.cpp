/**
 * test_event_logs_deadline.cpp -- real fork/exec vectors for the event_logs
 * plugin's bounded subprocess runner (event_logs_deadline.hpp, C-1.15, P8).
 *
 * Unlike the other P8 packages this drives REAL child processes (/bin/sleep,
 * /bin/sh) -- bounded_run()'s whole contract is about actual kill/reap
 * behaviour, which a pure-string fixture can't exercise. Every case here is
 * bounded well under the suite timeout: the longest possible single wait is
 * one deadline (a few hundred ms) plus bounded_run's own internal
 * kDrainGrace (2s), so a bug that makes the deadline not fire fails the test
 * loudly instead of hanging CI.
 *
 * POSIX only (event_logs_deadline.hpp itself is `#ifndef _WIN32`-gated) --
 * this file is still registered unconditionally in agent_test_exe, and its
 * body compiles to nothing observable on Windows because the tests
 * TEST_CASE-gate on the same macro. macOS/Linux, per the boundary.
 */

#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include <event_logs_deadline.hpp>

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

using namespace yuzu::event_logs;
using namespace std::chrono_literals;

namespace {

bool contains_line(const std::vector<std::string>& lines, const std::string& needle) {
    return std::find(lines.begin(), lines.end(), needle) != lines.end();
}

} // namespace

TEST_CASE("bounded_run collects output from a fast child that exits well before the deadline",
          "[event_logs][deadline][macos][linux]") {
    // No shell involved in bounded_run itself -- printf's repeated-format-
    // against-each-arg behaviour gives deterministic multi-line output with
    // no stdin dependency.
    BoundedRunResult result =
        bounded_run({"/usr/bin/printf", "%s\n", "line1", "line2", "line3"}, 5000ms);

    CHECK_FALSE(result.timed_out);
    REQUIRE(result.lines.size() == 3);
    CHECK(result.lines[0] == "line1");
    CHECK(result.lines[1] == "line2");
    CHECK(result.lines[2] == "line3");
}

TEST_CASE("bounded_run caps stored lines at max_lines but still drains the pipe",
          "[event_logs][deadline][macos][linux]") {
    BoundedRunResult result =
        bounded_run({"/usr/bin/printf", "%s\n", "a", "b", "c", "d"}, 5000ms, /*max_lines=*/2);

    CHECK_FALSE(result.timed_out);
    REQUIRE(result.lines.size() == 2);
    CHECK(result.lines[0] == "a");
    CHECK(result.lines[1] == "b");
}

TEST_CASE("bounded_run kills, reaps, and returns partial output + timed_out on a hung child",
          "[event_logs][deadline][macos][linux]") {
    // A real sleeping child, well past our deadline: exercises the actual
    // SIGKILL-the-process-group + waitpid()-reap path, not a simulation.
    // Emits partial output BEFORE sleeping so the "partial output +
    // timed_out" contract is asserted together, as the acceptance criteria
    // require. argv[0] here is the /bin/sh INTERPRETER we chose to run --
    // bounded_run itself still never shells out its own argv.
    const auto start = std::chrono::steady_clock::now();

    BoundedRunResult result =
        bounded_run({"/bin/sh", "-c", "printf 'first\\nsecond\\n'; sleep 30"}, 300ms);

    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(result.timed_out);
    CHECK(contains_line(result.lines, "first"));
    CHECK(contains_line(result.lines, "second"));

    // Bounded proof of "killed + reaped within the deadline": bounded_run's
    // own documented worst case is `deadline` plus one short kDrainGrace
    // (2000ms) before it gives up waiting. If the child were left as an
    // unreaped zombie holding the pipe open, or SIGKILL failed to land, the
    // function would run past that bound. 10s is a generous CI-noise margin
    // well below the real hang this guards against (the child's own 30s
    // sleep).
    CHECK(elapsed < 10s);
}

TEST_CASE("bounded_run on a child with no output at all still returns timed_out honestly",
          "[event_logs][deadline][macos][linux]") {
    BoundedRunResult result = bounded_run({"/bin/sleep", "30"}, 200ms);

    CHECK(result.timed_out);
    CHECK(result.lines.empty()); // sleep produces no stdout -- never fabricated
}

TEST_CASE("bounded_run on an empty argv returns a default, never-fabricated result",
          "[event_logs][deadline][macos][linux]") {
    BoundedRunResult result = bounded_run({}, 1000ms);

    CHECK_FALSE(result.timed_out);
    CHECK(result.lines.empty());
}

TEST_CASE("bounded_run on a nonexistent binary exits promptly, no timeout needed",
          "[event_logs][deadline][macos][linux]") {
    // execvp() fails inside the child, which _exit(127)s almost immediately
    // -- this must resolve well before the deadline, not be mistaken for a
    // hang.
    BoundedRunResult result = bounded_run({"/no/such/binary-xyz-does-not-exist"}, 5000ms);

    CHECK_FALSE(result.timed_out);
    CHECK(result.lines.empty());
}

#endif // !_WIN32
