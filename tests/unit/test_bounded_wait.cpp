// bounded_wait.hpp bounds the WAIT on an uncancellable blocking call (Wave 2
// PR2.1c, governance Gate 4 unhappy-path fix: getnameinfo's reverse-DNS
// lookup has no per-call timeout, and a black-holing resolver could
// otherwise pin a worker on the agent's bounded ThreadPool indefinitely).
// These tests use a synthetic slow callable rather than real DNS, so the
// timeout behaviour is deterministic and network-independent.
#include <catch2/catch_test_macros.hpp>

#include "bounded_wait.hpp"

#include <chrono>
#include <thread>

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
