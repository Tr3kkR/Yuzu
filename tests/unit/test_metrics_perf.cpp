/**
 * test_metrics_perf.cpp — Performance tests for MetricsRegistry
 *
 * Validates that the metrics infrastructure can handle high-throughput
 * concurrent updates and serialization without degrading performance.
 * These are benchmarks, not unit tests — they measure wall-clock time.
 */

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <format>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu;

// ── Helpers ──────────────────────────────────────────────────────────────────

static double elapsed_ms(std::chrono::steady_clock::time_point start) {
    auto end = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count();
}

// ── Counter throughput ───────────────────────────────────────────────────────

TEST_CASE("Perf: counter increment throughput (single thread)", "[metrics][perf]") {
    MetricsRegistry registry;
    constexpr int N = 100'000;

    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < N; ++i) {
        registry.counter("yuzu_perf_counter").increment();
    }
    auto ms = elapsed_ms(start);

    REQUIRE(registry.counter("yuzu_perf_counter").value() == N);
    // Should complete in well under 1 second
    CHECK(ms < 1000.0);
}

TEST_CASE("Perf: counter increment throughput (4 threads)", "[metrics][perf]") {
    MetricsRegistry registry;
    constexpr int kPerThread = 25'000;
    constexpr int kThreads = 4;

    auto start = std::chrono::steady_clock::now();
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&registry]() {
            for (int i = 0; i < kPerThread; ++i) {
                registry.counter("yuzu_perf_mt_counter").increment();
            }
        });
    }
    for (auto& t : threads)
        t.join();
    auto ms = elapsed_ms(start);

    REQUIRE(registry.counter("yuzu_perf_mt_counter").value() == kPerThread * kThreads);
    CHECK(ms < 2000.0);
}

// ── Labeled gauge churn ──────────────────────────────────────────────────────

TEST_CASE("Perf: labeled gauge set with many labels", "[metrics][perf]") {
    MetricsRegistry registry;
    constexpr int kLabels = 1000;

    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < kLabels; ++i) {
        registry.gauge("yuzu_perf_gauge", {{"agent", std::to_string(i)}})
            .set(static_cast<double>(i));
    }
    auto ms = elapsed_ms(start);

    // All 1000 labels should be independent
    CHECK(registry.gauge("yuzu_perf_gauge", {{"agent", "0"}}).value() == 0.0);
    CHECK(registry.gauge("yuzu_perf_gauge", {{"agent", "999"}}).value() == 999.0);
    CHECK(ms < 1000.0);
}

TEST_CASE("Perf: clear_gauge_family then rebuild", "[metrics][perf]") {
    MetricsRegistry registry;
    constexpr int kLabels = 500;
    constexpr int kCycles = 10;

    auto start = std::chrono::steady_clock::now();
    for (int cycle = 0; cycle < kCycles; ++cycle) {
        registry.clear_gauge_family("yuzu_perf_cycle_gauge");
        for (int i = 0; i < kLabels; ++i) {
            registry.gauge("yuzu_perf_cycle_gauge", {{"os", std::to_string(i)}}).set(1.0);
        }
    }
    auto ms = elapsed_ms(start);

    // After last cycle, should have exactly kLabels entries
    CHECK(ms < 2000.0);
}

// ── Histogram throughput ─────────────────────────────────────────────────────

TEST_CASE("Perf: histogram observe throughput", "[metrics][perf]") {
    MetricsRegistry registry;
    constexpr int N = 100'000;

    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < N; ++i) {
        registry.histogram("yuzu_perf_hist").observe(static_cast<double>(i % 100) / 100.0);
    }
    auto ms = elapsed_ms(start);

    auto snap = registry.histogram("yuzu_perf_hist").snapshot();
    REQUIRE(snap.count == N);
    CHECK(ms < 2000.0);
}

// ── Serialize throughput ─────────────────────────────────────────────────────

TEST_CASE("Perf: serialize with many metrics", "[metrics][perf]") {
    MetricsRegistry registry;

    // Create a realistic set of metrics
    for (int i = 0; i < 50; ++i) {
        registry.counter("yuzu_perf_c_" + std::to_string(i)).increment(static_cast<double>(i));
    }
    for (int i = 0; i < 50; ++i) {
        registry.gauge("yuzu_perf_g", {{"agent", std::to_string(i)}}).set(static_cast<double>(i));
    }
    registry.describe("yuzu_perf_c_0", "Test counter", "counter");
    registry.describe("yuzu_perf_g", "Test gauge", "gauge");

    constexpr int kSerializations = 100;
    auto start = std::chrono::steady_clock::now();
    std::string last_output;
    for (int i = 0; i < kSerializations; ++i) {
        last_output = registry.serialize();
    }
    auto ms = elapsed_ms(start);

    REQUIRE(!last_output.empty());
    // 100 serializations of ~100 metrics should be fast
    CHECK(ms < 2000.0);
}

// ── Concurrent read/write (simulates recompute + scrape) ─────────────────────

TEST_CASE("Perf: concurrent gauge updates and serialize", "[metrics][perf]") {
    MetricsRegistry registry;
    std::atomic<bool> stop{false};
    constexpr int kWriters = 2;

    // Pre-seed so serialize() is never empty on the first call
    registry.gauge("yuzu_fleet_agents_by_os", {{"os", "linux"}}).set(0.0);
    registry.gauge("yuzu_fleet_agents_by_os", {{"os", "windows"}}).set(0.0);

    // Writer threads: continuously update gauges
    std::vector<std::thread> writers;
    for (int w = 0; w < kWriters; ++w) {
        writers.emplace_back([&registry, &stop, w]() {
            int i = 0;
            while (!stop.load(std::memory_order_acquire)) {
                registry.gauge("yuzu_fleet_agents_by_os", {{"os", w == 0 ? "linux" : "windows"}})
                    .set(static_cast<double>(++i));
            }
        });
    }

    // Reader thread: serialize repeatedly
    auto start = std::chrono::steady_clock::now();
    int serialize_count = 0;
    while (elapsed_ms(start) < 500.0) {
        auto output = registry.serialize();
        REQUIRE(!output.empty());
        ++serialize_count;
    }

    stop.store(true, std::memory_order_release);
    for (auto& t : writers)
        t.join();

    CHECK(serialize_count > 10);
}
