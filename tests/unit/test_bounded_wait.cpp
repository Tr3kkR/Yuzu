// bounded_wait.hpp bounds the WAIT on an uncancellable blocking call (Wave 2
// PR2.1c, governance Gate 4 unhappy-path fix: getnameinfo's reverse-DNS
// lookup has no per-call timeout, and a black-holing resolver could
// otherwise pin a worker on the agent's bounded ThreadPool indefinitely).
// These tests use a synthetic slow callable rather than real DNS, so the
// timeout behaviour is deterministic and network-independent.
#include <catch2/catch_test_macros.hpp>

#include "bounded_wait.hpp"

#include <chrono>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using yuzu::discovery::bounded_call;

TEST_CASE("bounded_call: a fast function returns its result well before the timeout",
          "[agent][bounded_wait]") {
    const auto result = bounded_call(500ms, [] { return 42; });
    REQUIRE(result.has_value());
    CHECK(*result == 42);
}

TEST_CASE("bounded_call: a function that never returns in time yields nullopt, not a hang",
          "[agent][bounded_wait]") {
    // Simulates the black-holing-resolver scenario: the callable blocks far
    // longer than the caller is willing to wait.
    const auto start = std::chrono::steady_clock::now();
    const auto result = bounded_call(100ms, [] {
        std::this_thread::sleep_for(3s);
        return 1;
    });
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK_FALSE(result.has_value());
    // The whole point of the fix: the CALLER returns promptly, not after the
    // callable finishes. Generous CI-safe ceiling, still far under the 3s the
    // callable itself sleeps for.
    CHECK(elapsed < 1500ms);
}

TEST_CASE("bounded_call: propagates a std::string result", "[agent][bounded_wait]") {
    const auto result = bounded_call(500ms, [] { return std::string{"resolved.example"}; });
    REQUIRE(result.has_value());
    CHECK(*result == "resolved.example");
}

TEST_CASE("bounded_call: an exception inside fn() does not crash the process",
          "[agent][bounded_wait]") {
    // fn() runs on a raw detached thread, outside ThreadPool's own exception
    // firewall -- an uncaught throw here would std::terminate() the whole
    // process (governance Gate 5 chaos-injector finding). Reaching this
    // CHECK at all is the proof: the process is still running.
    const auto result = bounded_call(
        300ms, []() -> int { throw std::runtime_error("simulated detached-thread failure"); });
    CHECK_FALSE(result.has_value());
}

TEST_CASE("bounded_call: caps concurrently-outstanding detached threads, degrading excess "
          "callers to an immediate nullopt instead of spawning unboundedly",
          "[agent][bounded_wait]") {
    // Governance Gate 5 chaos-injector finding: a sustained black hole across
    // many concurrent callers could otherwise accumulate an unbounded number
    // of detached threads (verified by execution during the review to reach
    // dozens under simulation). kTotal comfortably exceeds bounded_wait.hpp's
    // internal ceiling so some callers MUST be degraded.
    constexpr int kTotal = 100;
    std::vector<std::thread> callers;
    std::vector<std::chrono::steady_clock::duration> elapsed(kTotal);

    for (int i = 0; i < kTotal; ++i) {
        callers.emplace_back([&, i] {
            const auto start = std::chrono::steady_clock::now();
            bounded_call(2000ms, [] {
                std::this_thread::sleep_for(4s);
                return 1;
            });
            elapsed[i] = std::chrono::steady_clock::now() - start;
        });
    }
    for (auto& t : callers)
        t.join();

    // A real (slot-acquiring) attempt waits up to ~2s before its own timeout;
    // a call degraded by the ceiling returns near-instantly. If the ceiling
    // did nothing, every one of the 100 calls would wait out the full ~2s.
    // A generous lower bound (not the exact 100-minus-ceiling count) keeps
    // this robust to scheduling jitter and any stray thread left running
    // from an earlier test case in this same process.
    int fast_returns = 0;
    for (const auto& e : elapsed) {
        if (e < 500ms)
            ++fast_returns;
    }
    CHECK(fast_returns >= 20);

    // Drain: the outstanding-call counter is process-wide, shared with every
    // other test case in this binary. Wait for the slot-acquiring callers'
    // detached threads to finish (they were sleeping 4s) and decrement it,
    // so a later test case doesn't start against a still-saturated ceiling.
    for (int i = 0; i < 100 && yuzu::discovery::detail::g_outstanding_bounded_calls.load() > 0;
        ++i) {
        std::this_thread::sleep_for(100ms);
    }
}
