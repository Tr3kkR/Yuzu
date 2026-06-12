/**
 * test_dex_win_poll.cpp — pure Windows state-poll decision functions (dex_win_poll).
 *
 * The Windows analogue of the macOS IOKit-poll tests in test_dex_macos.cpp: the
 * storage.low / battery thresholds are pure arithmetic over Win32 readings, so
 * they run on EVERY host. The Win32 mechanism (GetDiskFreeSpaceExW, the battery
 * IOCTLs, the poll thread) is exercised on a real Windows box via the live
 * pipeline, not here.
 */

#include "dex_win_poll.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace yuzu::agent;

namespace {

win::DiskLevel disk(std::uint64_t total, std::uint64_t free_bytes) {
    win::DiskLevel d;
    d.valid = true;
    d.total_bytes = total;
    d.free_bytes = free_bytes;
    return d;
}

constexpr std::uint64_t kGiB = 1024ULL * 1024 * 1024;

} // namespace

TEST_CASE("low_disk: healthy volume emits nothing", "[dex_win_poll]") {
    CHECK(!win::low_disk_observation(disk(500 * kGiB, 250 * kGiB), "C:"));
}

TEST_CASE("low_disk: invalid / zero-total readings never emit", "[dex_win_poll]") {
    CHECK(!win::low_disk_observation(win::DiskLevel{}, "C:"));
    win::DiskLevel z;
    z.valid = true; // total stays 0 — a failed read must never read as a full disk
    CHECK(!win::low_disk_observation(z, "C:"));
}

TEST_CASE("low_disk: >= 90% used trips the percent leg", "[dex_win_poll]") {
    // Exactly 90%: 100 GiB total, 10 GiB free.
    auto o = win::low_disk_observation(disk(100 * kGiB, 10 * kGiB), "C:");
    REQUIRE(o);
    CHECK(o->obs_type == "storage.low");
    CHECK(o->subject == "C:");
    CHECK(o->reason == "90% full");
    CHECK(o->metric == 90.0);
    CHECK(o->sentence.find("MB free") != std::string::npos);
    // 89% used with plenty free: healthy.
    CHECK(!win::low_disk_observation(disk(100 * kGiB, 11 * kGiB), "C:"));
}

TEST_CASE("low_disk: < 5 GiB free trips the absolute leg below 90%", "[dex_win_poll]") {
    // 40 GiB total, 4.5 GiB free = 88% used — but under the 5 GiB floor.
    auto o = win::low_disk_observation(disk(40 * kGiB, 4 * kGiB + kGiB / 2), "D:");
    REQUIRE(o);
    CHECK(o->subject == "D:");
    CHECK(o->reason == "88% full");
    // Same volume with exactly 5 GiB free (87% used): healthy — the absolute
    // leg requires *less than* 5 GiB.
    CHECK(!win::low_disk_observation(disk(40 * kGiB, 5 * kGiB), "D:"));
}

TEST_CASE("low_disk: empty volume name falls back to a stable subject", "[dex_win_poll]") {
    auto o = win::low_disk_observation(disk(100 * kGiB, kGiB), "");
    REQUIRE(o);
    CHECK(o->subject == "disk");
}

TEST_CASE("battery: no battery / no design capacity never emit", "[dex_win_poll]") {
    CHECK(!win::battery_observation(win::BatteryHealth{}));
    win::BatteryHealth h;
    h.valid = true; // designed_capacity stays 0 — ratio undefined, never a failure
    h.full_charged_capacity = 50000;
    CHECK(!win::battery_observation(h));
}

TEST_CASE("battery: healthy and brand-new batteries emit nothing", "[dex_win_poll]") {
    win::BatteryHealth h;
    h.valid = true;
    h.designed_capacity = 50000;
    h.full_charged_capacity = 45000; // 90%
    CHECK(!win::battery_observation(h));
    h.full_charged_capacity = 40000; // exactly 80% — boundary stays healthy (< 80 emits)
    CHECK(!win::battery_observation(h));
    h.full_charged_capacity = 52000; // a fresh cell can read above design
    CHECK(!win::battery_observation(h));
}

TEST_CASE("battery: capacity below 80% of design emits hw.error", "[dex_win_poll]") {
    win::BatteryHealth h;
    h.valid = true;
    h.designed_capacity = 50000;
    h.full_charged_capacity = 39500; // 79%
    h.cycle_count = 612;
    auto o = win::battery_observation(h);
    REQUIRE(o);
    CHECK(o->obs_type == "hw.error"); // rides the generic Hardware type, like macOS
    CHECK(o->subject == "battery");
    CHECK(o->reason == "capacity 79%");
    CHECK(o->metric == 79.0);
    CHECK(o->sentence.find("612 cycles") != std::string::npos);
}

TEST_CASE("battery: cycle count omitted from sentence when unknown", "[dex_win_poll]") {
    win::BatteryHealth h;
    h.valid = true;
    h.designed_capacity = 50000;
    h.full_charged_capacity = 30000; // 60%
    auto o = win::battery_observation(h);
    REQUIRE(o);
    CHECK(o->sentence.find("cycles") == std::string::npos);
}
