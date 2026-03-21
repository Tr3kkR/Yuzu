#include <catch2/catch_test_macros.hpp>

#include "rate_limiter.hpp"

using yuzu::server::RateLimiter;

TEST_CASE("RateLimiter — first request allowed", "[rate_limiter]") {
    RateLimiter limiter(10);
    REQUIRE(limiter.allow("192.168.1.1"));
}

TEST_CASE("RateLimiter — burst up to rate", "[rate_limiter]") {
    RateLimiter limiter(5);
    // 5 requests should be allowed (bucket starts full)
    int allowed = 0;
    for (int i = 0; i < 5; ++i) {
        if (limiter.allow("10.0.0.1"))
            ++allowed;
    }
    REQUIRE(allowed == 5);

    // 6th should be denied (bucket drained, no time for refill)
    REQUIRE_FALSE(limiter.allow("10.0.0.1"));
}

TEST_CASE("RateLimiter — different keys independent", "[rate_limiter]") {
    RateLimiter limiter(2);
    // Drain key A
    REQUIRE(limiter.allow("A"));
    REQUIRE(limiter.allow("A"));
    REQUIRE_FALSE(limiter.allow("A"));

    // Key B should still have tokens
    REQUIRE(limiter.allow("B"));
    REQUIRE(limiter.allow("B"));
}

TEST_CASE("RateLimiter — bucket count", "[rate_limiter]") {
    RateLimiter limiter(10);
    REQUIRE(limiter.bucket_count() == 0);

    limiter.allow("A");
    limiter.allow("B");
    REQUIRE(limiter.bucket_count() == 2);
}

TEST_CASE("RateLimiter — purge removes stale", "[rate_limiter]") {
    RateLimiter limiter(10);
    limiter.allow("A");
    REQUIRE(limiter.bucket_count() == 1);

    // Purge won't remove recent entries
    limiter.purge_stale();
    REQUIRE(limiter.bucket_count() == 1);
}

TEST_CASE("RateLimiter — minimum rate is 1", "[rate_limiter]") {
    RateLimiter limiter(0); // Should be clamped to 1
    REQUIRE(limiter.allow("X"));
    REQUIRE_FALSE(limiter.allow("X")); // rate=1, so only 1 allowed
}
