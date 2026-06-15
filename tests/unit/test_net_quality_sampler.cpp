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

// NOTE: the Windows platform reads (GetIfTable2 throughput + GetTcpStatisticsEx
// retransmit counters) are deliberately NOT unit-tested here — like the Linux
// netlink path, they are non-exported syscall functions verified EMPIRICALLY on a
// live rig (the heartbeat ships yuzu.net_throughput_bps + net_retrans_pct →
// yuzu_fleet_net_* gauges). Only the cross-platform, deterministic helpers above
// (median / throughput_bps / RetransWindow) are unit-tested.
