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
