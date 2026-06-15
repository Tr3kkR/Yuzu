/**
 * test_net_quality_sampler.cpp — pure helpers of the network-quality sampler
 * (median, throughput delta, and the 4b.3 interval-retransmit-rate window). The
 * platform netlink INET_DIAG path is verified EMPIRICALLY on the Linux rig
 * (rtt_p50 matches `ss -ti`; the interval rate separates 0%/4%/12% netem loss),
 * not here — these are the cross-platform, deterministic bits.
 */
#include "net_quality_sampler.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <optional>

using namespace yuzu::agent::netq;

TEST_CASE("median: middle element, empty → nullopt", "[netq]") {
    CHECK(median({}) == std::nullopt);
    CHECK(median({5.0}) == 5.0);
    CHECK(median({3.0, 1.0, 2.0}) == 2.0);      // sorted 1,2,3 → 2
    CHECK(median({4.0, 1.0, 3.0, 2.0}) == 3.0); // sorted 1,2,3,4 → index 2 = 3
}

TEST_CASE("throughput_bps: delta over interval, wrap-safe", "[netq]") {
    using namespace std::chrono;
    const auto t0 = steady_clock::now();
    const NetCounters prev{true, 1000, 2000, t0};
    const NetCounters cur{true, 1000 + 3000, 2000 + 1000, t0 + seconds(2)}; // +4000 B / 2 s
    const auto bps = throughput_bps(prev, cur);
    REQUIRE(bps.has_value());
    CHECK(*bps == 2000.0);

    // First heartbeat (invalid prev) baselines — no rate.
    CHECK(throughput_bps(NetCounters{}, cur) == std::nullopt);
    // Counter wrap/reset (cur < prev) → nullopt, never a bogus huge/negative rate.
    const NetCounters wrapped{true, 10, 10, t0 + seconds(2)};
    CHECK(throughput_bps(prev, wrapped) == std::nullopt);
    // Zero/negative interval → nullopt.
    const NetCounters same_t{true, 5000, 5000, t0};
    CHECK(throughput_bps(prev, same_t) == std::nullopt);
}

TEST_CASE("RetransWindow: interval delta, not absolute ratio", "[netq]") {
    RetransWindow w;
    // <2 readings → no rate (a single sample can't yield an interval delta).
    CHECK(w.rate_pct() == std::nullopt);
    w.push(1000, 100000); // huge absolute lifetime ratio (1%) baked into totals
    CHECK(w.rate_pct() == std::nullopt);
    // Next interval added 40 retrans over 1000 segments → 4.0% (the INTERVAL
    // rate), independent of the large pre-existing absolute totals.
    w.push(1040, 101000);
    REQUIRE(w.rate_pct().has_value());
    CHECK(*w.rate_pct() == Catch::Approx(4.0));
}

TEST_CASE("RetransWindow: idle interval (no segments advance) → absent, not 0", "[netq]") {
    RetransWindow w;
    w.push(500, 50000);
    w.push(500, 50000); // nothing sent → Δsegs == 0
    CHECK(w.rate_pct() == std::nullopt); // never a fabricated healthy 0%
}

TEST_CASE("RetransWindow: connection-churn delta is clamped at zero", "[netq]") {
    RetransWindow w;
    w.push(900, 100000);
    // A high-retrans connection closed → Σretrans DROPS, but Σsegs still
    // advanced on the survivors. Δretrans must clamp to 0 (never negative loss).
    w.push(300, 101000); // retrans 900→300 (down), segs +1000
    REQUIRE(w.rate_pct().has_value());
    CHECK(*w.rate_pct() == Catch::Approx(0.0)); // clamped, not negative
}

TEST_CASE("RetransWindow: smooths over the window and evicts oldest", "[netq]") {
    RetransWindow w{3}; // cap 3 readings → 2 intervals
    w.push(0, 0);
    w.push(10, 1000);   // interval A: +10/+1000
    w.push(30, 2000);   // interval B: +20/+1000  → window sum 30/2000 = 1.5%
    REQUIRE(w.rate_pct().has_value());
    CHECK(*w.rate_pct() == Catch::Approx(1.5));
    // 4th push evicts the (0,0) reading; window is now the last 3.
    w.push(130, 2500);  // interval C: +100/+500; window = B+C = 120/1500 = 8.0%
    REQUIRE(w.rate_pct().has_value());
    CHECK(*w.rate_pct() == Catch::Approx(8.0));
}

TEST_CASE("RetransWindow: a clean link reads ~0 across the window", "[netq]") {
    RetransWindow w;
    uint64_t segs = 100000;
    for (int i = 0; i < 6; ++i) {
        segs += 5000;        // steady traffic
        w.push(200, segs);   // retrans never advances → clean
    }
    REQUIRE(w.rate_pct().has_value());
    CHECK(*w.rate_pct() == Catch::Approx(0.0)); // no false positive on a clean link
}

TEST_CASE("RetransWindow: counter decrease (DWORD wrap) clamps, never negative", "[netq]") {
    // Windows feeds 32-bit DWORD GetTcpStatisticsEx counters; on a long-uptime busy
    // host dwOutSegs/dwRetransSegs can wrap, so segs (and retrans) may DECREASE
    // between readings. The interval must contribute zero, never a negative/garbage
    // rate. (Distinct from the churn case above, where retrans drops but segs rises.)
    RetransWindow w;
    w.push(1000, 200000);
    w.push(40, 8000);      // both wrapped DOWN (cur < prev) → Δretr<0 and Δsegs<0, both clamped
    CHECK(w.rate_pct() == std::nullopt); // the only interval contributed no segments → absent
    // A subsequent clean interval after the wrap reads correctly (post-wrap baseline).
    w.push(50, 9000);      // +10 retr / +1000 segs → 1.0%
    REQUIRE(w.rate_pct().has_value());
    CHECK(*w.rate_pct() == Catch::Approx(1.0)); // wrap interval excluded, not poisoning the rate
}

// NOTE: the Windows platform reads (GetIfTable2 throughput + GetTcpStatisticsEx
// retransmit counters) are deliberately NOT unit-tested here — like the Linux
// netlink path, they are non-exported syscall functions. A live rig verifies only
// the COUNTER PLUMBING (the heartbeat ships yuzu.net_throughput_bps +
// net_retrans_pct → yuzu_fleet_net_* gauges); it does NOT validate the Windows
// retransmit signal's separation-under-loss — that netem validation was run on
// Linux only and is tracked for Windows in issue #1465. Only the cross-platform,
// deterministic helpers above (median / throughput_bps / RetransWindow) are
// unit-tested.
