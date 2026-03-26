/**
 * test_process_health.cpp — Unit tests for ProcessHealthSampler
 *
 * Covers: sample output ranges, finiteness, memory positivity, stability
 *         under repeated calls, and delta-based CPU measurement.
 */

#include "process_health.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cmath>
#include <thread>

using namespace yuzu::server::detail;

// ── Sample Output Ranges ────────────────────────────────────────────────────

TEST_CASE("ProcessHealthSampler: sample returns non-negative cpu",
          "[process_health][sample]") {
    ProcessHealthSampler sampler;
    auto h = sampler.sample();
    CHECK(h.cpu_percent >= 0.0);
}

TEST_CASE("ProcessHealthSampler: memory is positive",
          "[process_health][sample]") {
    ProcessHealthSampler sampler;
    auto h = sampler.sample();
    CHECK(h.memory_rss_bytes > 0);
    CHECK(h.memory_vss_bytes > 0);
}

TEST_CASE("ProcessHealthSampler: cpu is finite",
          "[process_health][sample]") {
    ProcessHealthSampler sampler;
    auto h = sampler.sample();
    CHECK(std::isfinite(h.cpu_percent));
}

// ── Stability ───────────────────────────────────────────────────────────────

TEST_CASE("ProcessHealthSampler: consecutive calls don't crash",
          "[process_health][stability]") {
    ProcessHealthSampler sampler;
    for (int i = 0; i < 10; ++i) {
        auto h = sampler.sample();
        CHECK(h.cpu_percent >= 0.0);
        CHECK(h.memory_rss_bytes >= 0);
        CHECK(h.memory_vss_bytes >= 0);
    }
}

// ── Delta-based CPU ─────────────────────────────────────────────────────────

TEST_CASE("ProcessHealthSampler: second sample has valid cpu",
          "[process_health][sample]") {
    ProcessHealthSampler sampler;

    // First sample may return 0 (no delta yet).
    auto h1 = sampler.sample();
    CHECK(h1.cpu_percent >= 0.0);

    // Brief sleep so wall-clock delta exceeds the 0.01s threshold.
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    auto h2 = sampler.sample();
    CHECK(h2.cpu_percent >= 0.0);
    CHECK(std::isfinite(h2.cpu_percent));
}
