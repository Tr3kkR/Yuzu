/**
 * test_dex_rate_limiter.cpp — the per-obs_type hourly emit cap (dex_rate_limiter).
 *
 * Pure + platform-agnostic (no journalctl, no Windows event log), so it runs on
 * every CI leg. Pins two things the Linux collector's emit() chokepoint relies on:
 * the cap value resolved from the catalogue per obs_type, and the per-hour gate
 * (exactly `cap` Emit, the rest Drop, the first Drop a DropAndWarn, reset each hour).
 */

#include <yuzu/agent/dex_rate_limiter.hpp>

#include <catch2/catch_test_macros.hpp>

using yuzu::agent::DexRateLimiter;
using yuzu::agent::dex_obs_cap_per_hour;
using yuzu::agent::RateDecision;

namespace {
constexpr std::int64_t kHour = 3600;
} // namespace

TEST_CASE("dex_obs_cap_per_hour: resolves the catalogue cap, 60 for an uncatalogued type",
          "[guardian][dex][ratelimit]") {
    CHECK(dex_obs_cap_per_hour("process.crashed") == 120);
    CHECK(dex_obs_cap_per_hour("memory.exhausted") == 12);
    CHECK(dex_obs_cap_per_hour("os.uptime_report") == 4);
    CHECK(dex_obs_cap_per_hour("service.crashed") == 60);
    // Wave-4 caps pinned so a future obs_type can't gain a second, differently-capped
    // spec without this failing (the cap-collision class cpp-expert flagged). All
    // seven wave-4 types pinned — not a subset (governance QE).
    CHECK(dex_obs_cap_per_hour("hw.battery_error") == 12);
    CHECK(dex_obs_cap_per_hour("service.unresponsive") == 30);
    CHECK(dex_obs_cap_per_hour("network.adapter_reset") == 60);
    CHECK(dex_obs_cap_per_hour("os.modern_standby_exit") == 60);
    CHECK(dex_obs_cap_per_hour("network.adapter_driver_dump") == 60);
    CHECK(dex_obs_cap_per_hour("hw.driver_load_failed") == 30);
    CHECK(dex_obs_cap_per_hour("service.shutdown_failed") == 30);
    // Linux poll-derived types are not in the (Windows-event-log) catalogue → default 60;
    // they are already hysteresis/latch-bounded so the cap never bites.
    CHECK(dex_obs_cap_per_hour("totally.unknown.type") == 60);
    CHECK(dex_obs_cap_per_hour("") == 60);
}

TEST_CASE("DexRateLimiter: exactly `cap` Emit per hour, the (cap+1)th drops",
          "[guardian][dex][ratelimit]") {
    DexRateLimiter rl;
    const int cap = dex_obs_cap_per_hour("memory.exhausted"); // 12
    REQUIRE(cap == 12);
    const std::int64_t base = 100 * kHour; // some hour boundary

    for (int i = 0; i < cap; ++i)
        CHECK(rl.check("memory.exhausted", base + i) == RateDecision::Emit); // ts within the hour

    // The first over-cap emit warns once; the next is a silent drop.
    CHECK(rl.check("memory.exhausted", base + cap) == RateDecision::DropAndWarn);
    CHECK(rl.check("memory.exhausted", base + cap + 1) == RateDecision::Drop);
    CHECK(rl.check("memory.exhausted", base + cap + 2) == RateDecision::Drop);
}

TEST_CASE("DexRateLimiter: a new clock-hour resets the count and re-warns",
          "[guardian][dex][ratelimit]") {
    DexRateLimiter rl;
    const int cap = dex_obs_cap_per_hour("os.uptime_report"); // 4
    REQUIRE(cap == 4);
    const std::int64_t h0 = 50 * kHour;

    for (int i = 0; i < cap; ++i)
        CHECK(rl.check("os.uptime_report", h0 + i) == RateDecision::Emit);
    CHECK(rl.check("os.uptime_report", h0 + cap) == RateDecision::DropAndWarn);
    CHECK(rl.check("os.uptime_report", h0 + cap + 1) == RateDecision::Drop);

    // Cross into the next clock hour → the bucket resets: cap Emit again, then warn again.
    const std::int64_t h1 = h0 + kHour;
    for (int i = 0; i < cap; ++i)
        CHECK(rl.check("os.uptime_report", h1 + i) == RateDecision::Emit);
    CHECK(rl.check("os.uptime_report", h1 + cap) == RateDecision::DropAndWarn); // warned flag reset
}

TEST_CASE("DexRateLimiter: each obs_type has an independent bucket",
          "[guardian][dex][ratelimit]") {
    DexRateLimiter rl;
    const std::int64_t base = 7 * kHour;
    // Exhaust os.uptime_report (cap 4) ...
    for (int i = 0; i < 4; ++i)
        CHECK(rl.check("os.uptime_report", base + i) == RateDecision::Emit);
    CHECK(rl.check("os.uptime_report", base + 4) != RateDecision::Emit);
    // ... memory.exhausted (cap 12) is untouched in the same hour.
    for (int i = 0; i < 12; ++i)
        CHECK(rl.check("memory.exhausted", base + i) == RateDecision::Emit);
    CHECK(rl.check("memory.exhausted", base + 12) != RateDecision::Emit);
}
