/**
 * test_dex_linux_sysfs.cpp — pure /sys parsers for the Linux DEX state polls.
 *
 * Parsing a `/sys` counter file is pure text handling, so it runs on every host.
 * The `/sys` globbing + the throttle latch live in dex_linux_collector.cpp (Linux-
 * only) and are exercised on a real box.
 */

#include "dex_linux_sysfs.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::agent::lnx;

TEST_CASE("sysfs: parse_throttle_count reads a bare counter with a trailing newline",
          "[guardian][dex][linux][sysfs]") {
    CHECK(parse_throttle_count("0\n").value() == 0);
    CHECK(parse_throttle_count("42\n").value() == 42);
    CHECK(parse_throttle_count("18446744073709551615\n").value() == 18446744073709551615ULL);
    CHECK(parse_throttle_count("7").value() == 7); // no trailing newline
    CHECK(parse_throttle_count("  13 \n").value() == 13); // leading/trailing whitespace tolerated
}

TEST_CASE("sysfs: parse_throttle_count rejects non-numeric / empty content",
          "[guardian][dex][linux][sysfs]") {
    CHECK_FALSE(parse_throttle_count("").has_value());
    CHECK_FALSE(parse_throttle_count("\n").has_value());
    CHECK_FALSE(parse_throttle_count("N/A\n").has_value());
    CHECK_FALSE(parse_throttle_count("-1\n").has_value()); // a count is unsigned
    CHECK_FALSE(parse_throttle_count("12x").has_value());  // trailing garbage in the token
}

// ── throttle_increased — the hotplug-safe throttling-edge detector (hw.cpu_throttled) ──

TEST_CASE("sysfs: throttle_increased fires only when a COMMON core's count rises",
          "[guardian][dex][linux][sysfs]") {
    // A core present in both snapshots that incremented = a real throttle this interval.
    CHECK(throttle_increased({{"cpu0", 5}, {"cpu1", 2}}, {{"cpu0", 6}, {"cpu1", 2}}));
    // No common core changed → no throttle.
    CHECK_FALSE(throttle_increased({{"cpu0", 5}, {"cpu1", 2}}, {{"cpu0", 5}, {"cpu1", 2}}));
}

TEST_CASE("sysfs: throttle_increased ignores CPU hotplug (the Gate-8 defect)",
          "[guardian][dex][linux][sysfs]") {
    // A CPU OFFLINING (drops out of cur) is not a throttle — even though the summed count
    // fell, no common core rose.
    CHECK_FALSE(throttle_increased({{"cpu0", 5}, {"cpu1", 9}}, {{"cpu0", 5}}));
    // A CPU RE-ONLINING (appears in cur, absent from prev) — even if its count is huge,
    // it is not compared, so it cannot fabricate a throttle. This is the exact spurious
    // re-online edge the summed-counter latch produced.
    CHECK_FALSE(throttle_increased({{"cpu0", 5}}, {{"cpu0", 5}, {"cpu1", 1000}}));
    // The kernel resets core_throttle_count to 0 on re-online: cpu1 reappears at 0 →
    // ignored (absent from prev); a LATER genuine throttle on it then fires.
    CHECK_FALSE(throttle_increased({{"cpu0", 5}}, {{"cpu0", 5}, {"cpu1", 0}}));
    CHECK(throttle_increased({{"cpu0", 5}, {"cpu1", 0}}, {{"cpu0", 5}, {"cpu1", 1}}));
}

TEST_CASE("sysfs: throttle_increased — a decrease on a common core is not a throttle",
          "[guardian][dex][linux][sysfs]") {
    // A counter that went DOWN on a still-present core (a reset that didn't go through an
    // offline) is not an increment — never a throttle.
    CHECK_FALSE(throttle_increased({{"cpu0", 9}}, {{"cpu0", 3}}));
    // An empty prior snapshot (first poll) → nothing to compare → no throttle.
    CHECK_FALSE(throttle_increased({}, {{"cpu0", 5}}));
}
