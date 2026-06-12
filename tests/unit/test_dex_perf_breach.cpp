/**
 * test_dex_perf_breach.cpp — pure A3 perf-breach functions (dex_perf_breach).
 *
 * The sibling of test_dex_win_poll.cpp: sample derivation, the sustained-breach
 * hysteresis latch, and the observation builders are pure arithmetic, so they
 * run on EVERY host. The Win32 reads (GetSystemTimes, GetPerformanceInfo,
 * IOCTL_DISK_PERFORMANCE) are exercised on a real Windows box via the live
 * pipeline, not here.
 */

#include "dex_perf_breach.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>

using namespace yuzu::agent;
using Catch::Matchers::WithinAbs;

namespace {

// 100 ns units per second of CPU time.
constexpr std::uint64_t kSec = 10'000'000ULL;

// A valid baseline reading at t=0: idle system, healthy commit, quiet disk.
win::PerfBreachCounters base() {
    win::PerfBreachCounters c;
    c.valid = true;
    c.commit_valid = true;
    c.disk_valid = true;
    c.ts_epoch = 1000;
    c.cpu_idle = 100 * kSec;
    c.cpu_kernel = 110 * kSec; // kernel INCLUDES idle
    c.cpu_user = 10 * kSec;
    c.commit_total_bytes = 4ULL << 30;  // 4 GiB
    c.commit_limit_bytes = 16ULL << 30; // of 16 GiB
    return c;
}

// Advance the baseline `secs` with the given busy fraction across one core.
win::PerfBreachCounters advance(const win::PerfBreachCounters& prev, std::int64_t secs,
                                double busy_frac) {
    win::PerfBreachCounters c = prev;
    c.ts_epoch += secs;
    const auto total = static_cast<std::uint64_t>(secs) * kSec;
    const auto busy = static_cast<std::uint64_t>(static_cast<double>(total) * busy_frac);
    c.cpu_idle += total - busy;
    c.cpu_kernel += total - busy; // all busy time accrues to user for simplicity
    c.cpu_user += busy;
    return c;
}

} // namespace

// ── derive_breach_sample ─────────────────────────────────────────────────────

TEST_CASE("derive: invalid readings / zero elapsed never derive", "[dex_perf]") {
    CHECK(!win::derive_breach_sample({}, base()).valid);
    CHECK(!win::derive_breach_sample(base(), {}).valid);
    CHECK(!win::derive_breach_sample(base(), base()).valid); // elapsed == 0
}

TEST_CASE("derive: CPU busy percentage from cumulative times", "[dex_perf]") {
    const auto prev = base();
    const auto s = win::derive_breach_sample(prev, advance(prev, 120, 0.95));
    REQUIRE(s.valid);
    CHECK_THAT(s.cpu_pct, WithinAbs(95.0, 0.1));
    CHECK_THAT(s.commit_pct, WithinAbs(25.0, 0.1)); // 4 of 16 GiB
}

TEST_CASE("derive: CPU counter regression invalidates the sample (reboot)", "[dex_perf]") {
    const auto prev = base();
    auto cur = advance(prev, 120, 0.5);
    cur.cpu_user = prev.cpu_user - 1;
    CHECK(!win::derive_breach_sample(prev, cur).valid);
}

TEST_CASE("derive: commit limit 0 (failed read) derives healthy, never a breach",
          "[dex_perf]") {
    auto prev = base();
    prev.commit_total_bytes = 0;
    prev.commit_limit_bytes = 0;
    auto cur = advance(prev, 120, 0.1);
    const auto s = win::derive_breach_sample(prev, cur);
    REQUIRE(s.valid);
    CHECK(s.commit_pct == 0.0);
}

TEST_CASE("derive: a failed commit read is NOT valid — never feeds the memory latch (review #1)",
          "[dex_perf]") {
    // GetPerformanceInfo failed this tick: commit_valid=false even though CPU
    // (GetSystemTimes) succeeded. The sample is CPU-valid but the memory domain
    // must read INVALID, so the caller (poll_perf, gating on s.valid &&
    // s.commit_valid) does not reset a building breach or clear a reported latch
    // with a bogus healthy 0%.
    const auto prev = base();
    auto cur = advance(prev, 120, 0.1);
    cur.commit_valid = false;
    cur.commit_total_bytes = 0; // a failed GetPerformanceInfo leaves these 0
    cur.commit_limit_bytes = 0;
    const auto s = win::derive_breach_sample(prev, cur);
    REQUIRE(s.valid);          // CPU domain still usable
    CHECK(!s.commit_valid);    // memory domain marked invalid → latch holds
    CHECK(s.commit_pct == 0.0);
    // And a genuinely valid commit reading sets the flag.
    CHECK(win::derive_breach_sample(prev, advance(prev, 120, 0.1)).commit_valid);
}

TEST_CASE("derive: disk latency = combined per-IO service time in ms", "[dex_perf]") {
    const auto prev = base();
    auto cur = advance(prev, 120, 0.1);
    cur.disk_reads = prev.disk_reads + 50;
    cur.disk_writes = prev.disk_writes + 50;
    // 100 IOs × 30 ms = 3 s of service time = 3e7 in 100 ns units.
    cur.disk_read_time_100ns = prev.disk_read_time_100ns + 20'000'000;
    cur.disk_write_time_100ns = prev.disk_write_time_100ns + 10'000'000;
    const auto s = win::derive_breach_sample(prev, cur);
    REQUIRE(s.valid);
    REQUIRE(s.disk_valid);
    CHECK_THAT(s.disk_lat_ms, WithinAbs(30.0, 0.01));
}

TEST_CASE("derive: zero IOs in the interval reads as 0 ms — idle disk is healthy",
          "[dex_perf]") {
    const auto prev = base();
    const auto s = win::derive_breach_sample(prev, advance(prev, 120, 0.1));
    REQUIRE(s.disk_valid);
    CHECK(s.disk_lat_ms == 0.0);
}

TEST_CASE("derive: disk counter regression degrades only the disk domain", "[dex_perf]") {
    const auto prev = base();
    auto cur = advance(prev, 120, 0.1);
    cur.disk_reads = 0; // hotplug/reset — saturating delta records no ops
    cur.disk_valid = true;
    const auto s = win::derive_breach_sample(prev, cur);
    REQUIRE(s.valid); // CPU + commit stay honest
    CHECK(s.disk_lat_ms == 0.0);
}

TEST_CASE("derive: missing disk data on either side clears disk_valid", "[dex_perf]") {
    auto prev = base();
    prev.disk_valid = false;
    const auto s = win::derive_breach_sample(prev, advance(prev, 120, 0.1));
    REQUIRE(s.valid);
    CHECK(!s.disk_valid);
}

// ── breach_update (the sustained-breach hysteresis latch) ───────────────────

namespace {
const win::BreachParams kP{90.0, 70.0, /*sustain=*/3, /*recover=*/2};
}

TEST_CASE("latch: fires once after `sustain` consecutive bad samples, with the avg",
          "[dex_perf][latch]") {
    win::BreachState st;
    CHECK(!win::breach_update(st, 95.0, true, kP));
    CHECK(!win::breach_update(st, 91.0, true, kP));
    const auto avg = win::breach_update(st, 99.0, true, kP);
    REQUIRE(avg);
    CHECK_THAT(*avg, WithinAbs(95.0, 0.001)); // (95+91+99)/3
    CHECK(st.reported);
}

TEST_CASE("latch: a healthy sample mid-streak resets the sustain count", "[dex_perf][latch]") {
    win::BreachState st;
    CHECK(!win::breach_update(st, 95.0, true, kP));
    CHECK(!win::breach_update(st, 50.0, true, kP)); // dip — not sustained
    CHECK(!win::breach_update(st, 95.0, true, kP));
    CHECK(!win::breach_update(st, 95.0, true, kP));
    CHECK(win::breach_update(st, 95.0, true, kP)); // 3 consecutive from the dip
}

TEST_CASE("latch: suppressed while reported; hysteresis blocks boundary flapping",
          "[dex_perf][latch]") {
    win::BreachState st;
    st.reported = true;
    // Value oscillating between exit (70) and enter (90) — neither re-fires
    // nor progresses recovery.
    for (int i = 0; i < 10; ++i) {
        CHECK(!win::breach_update(st, 80.0, true, kP));
        CHECK(st.reported);
        CHECK(st.good_streak == 0);
    }
}

TEST_CASE("latch: re-arms after `recover` consecutive healthy samples, can fire again",
          "[dex_perf][latch]") {
    win::BreachState st;
    st.reported = true;
    CHECK(!win::breach_update(st, 50.0, true, kP));
    CHECK(st.reported); // 1 of 2
    CHECK(!win::breach_update(st, 50.0, true, kP));
    CHECK(!st.reported); // re-armed
    CHECK(!win::breach_update(st, 95.0, true, kP));
    CHECK(!win::breach_update(st, 95.0, true, kP));
    CHECK(win::breach_update(st, 95.0, true, kP)); // second episode fires
}

TEST_CASE("latch: an invalid sample resets streaks but never clears the latch (UP-5)",
          "[dex_perf][latch]") {
    win::BreachState st;
    // Invalid mid-streak: the sustained claim must not span the gap.
    CHECK(!win::breach_update(st, 95.0, true, kP));
    CHECK(!win::breach_update(st, 95.0, true, kP));
    CHECK(!win::breach_update(st, 0.0, false, kP));
    CHECK(!win::breach_update(st, 95.0, true, kP));
    CHECK(!win::breach_update(st, 95.0, true, kP));
    CHECK(win::breach_update(st, 95.0, true, kP)); // 3 consecutive after the gap

    // Invalid during recovery: must not progress re-arm (st is now reported).
    CHECK(!win::breach_update(st, 50.0, true, kP)); // 1 of 2
    CHECK(!win::breach_update(st, 0.0, false, kP)); // gap — recovery resets
    CHECK(st.reported);
    CHECK(!win::breach_update(st, 50.0, true, kP)); // 1 of 2 again
    CHECK(st.reported);
    CHECK(!win::breach_update(st, 50.0, true, kP));
    CHECK(!st.reported);
}

TEST_CASE("latch: emission is bounded — one fire per sustain+recover cycle",
          "[dex_perf][latch]") {
    win::BreachState st;
    int fires = 0;
    // Permanently-bad metric: exactly one observation, ever.
    for (int i = 0; i < 100; ++i)
        if (win::breach_update(st, 99.0, true, kP))
            ++fires;
    CHECK(fires == 1);
}

// ── Observation builders ─────────────────────────────────────────────────────

TEST_CASE("observations: uniform shape and taxonomy keys", "[dex_perf][obs]") {
    const auto cpu = win::cpu_sustained_observation(94.2);
    CHECK(cpu.obs_type == "perf.cpu_sustained");
    CHECK(cpu.subject == "cpu");
    CHECK(cpu.metric == 94.2);
    CHECK(cpu.reason.find("94%") != std::string::npos);
    CHECK(cpu.reason.find("min") != std::string::npos);
    CHECK(cpu.sentence.find("Sustained high CPU") != std::string::npos);

    const auto mem = win::memory_pressure_observation(91.7);
    CHECK(mem.obs_type == "perf.memory_pressure");
    CHECK(mem.subject == "memory");
    CHECK(mem.metric == 91.7);
    CHECK(mem.reason.find("commit charge") != std::string::npos);
    CHECK(mem.sentence.find("Memory pressure") != std::string::npos);

    const auto disk = win::disk_latency_observation(31.5);
    CHECK(disk.obs_type == "perf.disk_latency_high");
    CHECK(disk.subject == "disk");
    CHECK(disk.metric == 31.5);
    CHECK(disk.reason.find("31.5 ms") != std::string::npos);
    CHECK(disk.sentence.find("Slow disk") != std::string::npos);
}

TEST_CASE("observations: window text derives from the tuning constants", "[dex_perf][obs]") {
    // 5 samples × 120 s = 10 min — if either constant changes, the human-
    // readable claim must follow (an observation must not lie about its window).
    const int mins = static_cast<int>(win::kCpuBreach.sustain *
                                      win::kPerfSampleIntervalSeconds / 60);
    const auto o = win::cpu_sustained_observation(95.0);
    CHECK(o.reason.find(std::to_string(mins) + " min") != std::string::npos);
}

TEST_CASE("tuning: hysteresis invariant — exit strictly below enter", "[dex_perf]") {
    CHECK(win::kCpuBreach.exit < win::kCpuBreach.enter);
    CHECK(win::kMemoryBreach.exit < win::kMemoryBreach.enter);
    CHECK(win::kDiskLatBreach.exit < win::kDiskLatBreach.enter);
}
