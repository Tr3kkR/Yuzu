/**
 * test_metrics.cpp — Unit tests for MetricsRegistry, Counter, Gauge, Histogram,
 *                    MetricFamily, and the new clear() / clear_gauge_family() methods
 */

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <thread>
#include <vector>

using namespace yuzu;

// ── Counter ─────────────────────────────────────────────────────────────────

TEST_CASE("Counter: increment and value", "[metrics][counter]") {
    Counter c;
    REQUIRE(c.value() == 0.0);

    c.increment();
    REQUIRE(c.value() == 1.0);

    c.increment(4.5);
    REQUIRE(c.value() == 5.5);

    c.increment(0.0);
    REQUIRE(c.value() == 5.5);
}

TEST_CASE("Counter: labeled counters are independent", "[metrics][counter]") {
    MetricFamily<Counter> family;

    auto& a = family.labels({{"method", "GET"}});
    auto& b = family.labels({{"method", "POST"}});

    a.increment(10.0);
    b.increment(3.0);

    REQUIRE(a.value() == 10.0);
    REQUIRE(b.value() == 3.0);
}

// ── Gauge ───────────────────────────────────────────────────────────────────

TEST_CASE("Gauge: set, increment, decrement", "[metrics][gauge]") {
    Gauge g;
    REQUIRE(g.value() == 0.0);

    g.set(42.0);
    REQUIRE(g.value() == 42.0);

    g.increment(8.0);
    REQUIRE(g.value() == 50.0);

    g.decrement(20.0);
    REQUIRE(g.value() == 30.0);

    g.increment();
    REQUIRE(g.value() == 31.0);

    g.decrement();
    REQUIRE(g.value() == 30.0);
}

TEST_CASE("Gauge: labeled gauges are independent", "[metrics][gauge]") {
    MetricFamily<Gauge> family;

    auto& temp = family.labels({{"sensor", "cpu"}});
    auto& fan  = family.labels({{"sensor", "fan"}});

    temp.set(72.5);
    fan.set(3200.0);

    REQUIRE(temp.value() == 72.5);
    REQUIRE(fan.value() == 3200.0);
}

// ── Histogram ───────────────────────────────────────────────────────────────

TEST_CASE("Histogram: observe and snapshot", "[metrics][histogram]") {
    Histogram h(std::vector<double>{1.0, 5.0, 10.0});

    h.observe(0.5);
    h.observe(3.0);
    h.observe(7.0);
    h.observe(15.0);

    auto snap = h.snapshot();
    REQUIRE(snap.count == 4);
    REQUIRE(snap.sum == 25.5);

    // Buckets count all values <= boundary, then snapshot makes them cumulative.
    // observe(0.5): hits buckets 0,1,2  →  raw = [1,1,1,1]
    // observe(3.0): hits buckets 1,2    →  raw = [1,2,2,2]
    // observe(7.0): hits bucket 2       →  raw = [1,2,3,3]
    // observe(15.0): hits none+inf      →  raw = [1,2,3,4]
    // cumulative: [1, 1+2=3, 3+3=6, count=4]
    REQUIRE(snap.cumulative_counts.size() == 4);
    CHECK(snap.cumulative_counts[0] == 1);  // le=1.0
    CHECK(snap.cumulative_counts[1] == 3);  // le=5.0 (cumulative)
    CHECK(snap.cumulative_counts[2] == 6);  // le=10.0 (cumulative)
    CHECK(snap.cumulative_counts[3] == 4);  // +Inf = count
}

TEST_CASE("Histogram: bucket boundaries", "[metrics][histogram]") {
    auto defaults = Histogram::default_buckets();
    REQUIRE(defaults.size() == 11);
    CHECK(defaults.front() == 0.005);
    CHECK(defaults.back() == 10.0);

    Histogram h;
    auto snap = h.snapshot();
    REQUIRE(snap.boundaries == defaults);
    REQUIRE(snap.count == 0);
    REQUIRE(snap.sum == 0.0);
}

// ── MetricFamily ────────────────────────────────────────────────────────────

TEST_CASE("MetricFamily: clear removes all instances", "[metrics][family]") {
    MetricFamily<Gauge> family;

    family.labels({{"env", "prod"}}).set(1.0);
    family.labels({{"env", "staging"}}).set(2.0);
    family.no_labels().set(3.0);

    REQUIRE(family.all().size() == 3);

    family.clear();

    REQUIRE(family.all().empty());

    // Re-adding after clear works and starts fresh
    auto& g = family.labels({{"env", "prod"}});
    REQUIRE(g.value() == 0.0);
    REQUIRE(family.all().size() == 1);
}

// ── MetricsRegistry ────────────────────────────────────────────────────────

TEST_CASE("MetricsRegistry: counter retrieval is idempotent", "[metrics][registry]") {
    MetricsRegistry reg;

    auto& c1 = reg.counter("yuzu_requests_total");
    c1.increment(5.0);

    auto& c2 = reg.counter("yuzu_requests_total");
    REQUIRE(&c1 == &c2);
    REQUIRE(c2.value() == 5.0);
}

TEST_CASE("MetricsRegistry: gauge retrieval is idempotent", "[metrics][registry]") {
    MetricsRegistry reg;

    auto& g1 = reg.gauge("yuzu_active_agents");
    g1.set(10.0);

    auto& g2 = reg.gauge("yuzu_active_agents");
    REQUIRE(&g1 == &g2);
    REQUIRE(g2.value() == 10.0);
}

TEST_CASE("MetricsRegistry: clear_gauge_family removes labeled instances", "[metrics][registry]") {
    MetricsRegistry reg;

    reg.gauge("yuzu_agent_uptime", {{"agent_id", "a1"}}).set(100.0);
    reg.gauge("yuzu_agent_uptime", {{"agent_id", "a2"}}).set(200.0);

    auto output_before = reg.serialize();
    CHECK(output_before.find("yuzu_agent_uptime") != std::string::npos);

    reg.clear_gauge_family("yuzu_agent_uptime");

    auto output_after = reg.serialize();
    CHECK(output_after.find("yuzu_agent_uptime{") == std::string::npos);

    // Gauge family still exists; adding new labels works
    reg.gauge("yuzu_agent_uptime", {{"agent_id", "a3"}}).set(300.0);
    auto output_readded = reg.serialize();
    CHECK(output_readded.find("a3") != std::string::npos);
}

TEST_CASE("MetricsRegistry: clear_gauge_family on unknown name is safe", "[metrics][registry]") {
    MetricsRegistry reg;

    // Must not throw or crash
    reg.clear_gauge_family("nonexistent_gauge");
    reg.clear_gauge_family("");

    auto output = reg.serialize();
    CHECK(output.empty());
}

TEST_CASE("MetricsRegistry: serialize produces Prometheus format", "[metrics][registry]") {
    MetricsRegistry reg;

    reg.counter("yuzu_http_requests_total").increment(42.0);
    reg.gauge("yuzu_cpu_temp").set(65.5);

    auto output = reg.serialize();
    CHECK(output.find("yuzu_http_requests_total") != std::string::npos);
    CHECK(output.find("42") != std::string::npos);
    CHECK(output.find("yuzu_cpu_temp") != std::string::npos);
    CHECK(output.find("65.5") != std::string::npos);
    CHECK(output.find("# TYPE") != std::string::npos);
}

TEST_CASE("MetricsRegistry: describe adds HELP and TYPE lines", "[metrics][registry]") {
    MetricsRegistry reg;

    reg.describe("yuzu_req_total", "Total HTTP requests", "counter");
    reg.counter("yuzu_req_total").increment(1.0);

    auto output = reg.serialize();
    CHECK(output.find("# HELP yuzu_req_total Total HTTP requests") != std::string::npos);
    CHECK(output.find("# TYPE yuzu_req_total counter") != std::string::npos);
}

// ── Thread safety ───────────────────────────────────────────────────────────

TEST_CASE("MetricsRegistry: thread-safe concurrent increments", "[metrics][thread]") {
    MetricsRegistry reg;
    auto& c = reg.counter("yuzu_concurrent_total");

    constexpr int kThreads = 4;
    constexpr int kIncrementsPerThread = 1000;

    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&c]() {
            for (int i = 0; i < kIncrementsPerThread; ++i) {
                c.increment();
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    REQUIRE(c.value() == kThreads * kIncrementsPerThread);
}
