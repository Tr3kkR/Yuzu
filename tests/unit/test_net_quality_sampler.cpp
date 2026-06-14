/**
 * test_net_quality_sampler.cpp — pure helpers of the slice-4a network-quality
 * sampler (median, throughput delta, degraded threshold). The platform netlink
 * INET_DIAG path is verified EMPIRICALLY on the Linux rig (rtt_p50 matches
 * `ss -ti`), not here — these are the cross-platform, deterministic bits.
 */
#include "net_quality_sampler.hpp"

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

TEST_CASE("is_degraded: RTT or retransmit over threshold; invalid metrics ignored", "[netq]") {
    CHECK_FALSE(is_degraded(true, 40.0, true, 0.5));      // healthy
    CHECK(is_degraded(true, 200.0, false, 0.0));          // RTT over 150 ms
    CHECK(is_degraded(false, 0.0, true, 9.0));            // retransmit over 5%
    CHECK_FALSE(is_degraded(false, 999.0, false, 999.0)); // both invalid → not degraded
}
