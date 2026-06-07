/**
 * test_secure_random.cpp — CSPRNG helper (#801).
 *
 * Covers: contract of `fill_random` and `random_hex` (success, empty,
 * uniqueness, hex shape) plus the documented hard-error mode triggered by
 * an oversized request that exceeds the underlying `RAND_bytes` int range.
 * The latter is the only failure path we can exercise portably — we cannot
 * push OpenSSL into entropy exhaustion from a unit test, so the negative
 * coverage relies on the static size guard inside `fill_random` itself.
 */

#include "secure_random.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <set>
#include <span>
#include <string>

using namespace yuzu::server;

TEST_CASE("secure_random: fill_random of empty span is a no-op success", "[csprng]") {
    std::span<std::uint8_t> empty;
    auto rc = fill_random(empty);
    REQUIRE(rc.has_value());
}

TEST_CASE("secure_random: fill_random writes bytes that are not all-zero", "[csprng]") {
    std::array<std::uint8_t, 32> buf{};
    auto rc = fill_random(std::span{buf});
    REQUIRE(rc.has_value());
    // Probability of a uniform 256-bit draw being all-zero is 2^-256; if this
    // ever fires the CSPRNG is broken or stubbed, which is exactly what we
    // are guarding against.
    const bool any_nonzero =
        std::any_of(buf.begin(), buf.end(), [](std::uint8_t b) { return b != 0; });
    CHECK(any_nonzero);
}

TEST_CASE("secure_random: two consecutive fills differ", "[csprng]") {
    std::array<std::uint8_t, 32> a{};
    std::array<std::uint8_t, 32> b{};
    REQUIRE(fill_random(std::span{a}).has_value());
    REQUIRE(fill_random(std::span{b}).has_value());
    CHECK(a != b);
}

TEST_CASE("secure_random: random_hex returns 2*N lowercase hex chars", "[csprng]") {
    auto hex = random_hex(16);
    REQUIRE(hex.has_value());
    CHECK(hex->size() == 32);
    for (char c : *hex)
        CHECK(((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
}

TEST_CASE("secure_random: random_hex(0) returns empty string", "[csprng]") {
    auto hex = random_hex(0);
    REQUIRE(hex.has_value());
    CHECK(hex->empty());
}

TEST_CASE("secure_random: 1000 consecutive 16-byte hex tokens are all unique", "[csprng]") {
    // Birthday-bound on 128 bits with 10^3 samples is ~2^-108. Any duplicate
    // here is a CSPRNG correctness failure, not a statistical fluke.
    std::set<std::string> seen;
    for (int i = 0; i < 1000; ++i) {
        auto hex = random_hex(16);
        REQUIRE(hex.has_value());
        CHECK(seen.insert(*hex).second);
    }
    CHECK(seen.size() == 1000);
}

#ifndef _WIN32
// On POSIX, fill_random rejects buffers larger than INT_MAX because
// RAND_bytes takes int. Windows splits into ULONG-sized chunks instead, so
// this guard does not apply there.
TEST_CASE("secure_random: oversized request returns prng_failure on POSIX", "[csprng][error]") {
    // We cannot actually allocate INT_MAX+1 bytes — synthesise a fake span
    // whose .size() exceeds the cap. The pointer is never dereferenced
    // because fill_random's size check fires first.
    std::uint8_t dummy{};
    const std::size_t huge = static_cast<std::size_t>(std::numeric_limits<int>::max()) + 1u;
    std::span<std::uint8_t> oversized{&dummy, huge};
    auto rc = fill_random(oversized);
    REQUIRE_FALSE(rc.has_value());
    CHECK(rc.error() == SecureRandomError::prng_failure);
}
#endif
