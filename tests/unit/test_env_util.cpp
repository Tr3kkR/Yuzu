/**
 * test_env_util.cpp — Unit tests for yuzu::agent::env_truthy (#1303 / #1332).
 *
 * env_truthy is the value-aware parser behind the YUZU_TLS_SYSTEM_ROOTS security
 * flag: only explicit affirmatives enable the (fail-open) system-trust posture;
 * everything else — unset, empty, "0", "false", garbage — must read false so the
 * agent stays fail-closed. The #1332 review flagged this truth table as untested.
 */

#include <yuzu/agent/env_util.hpp>

#include <catch2/catch_test_macros.hpp>

using yuzu::agent::env_truthy;

TEST_CASE("env_truthy: affirmatives enable, everything else is false", "[agent][env][tls]") {
    SECTION("affirmatives (case-insensitive)") {
        for (const char* v : {"1", "true", "TRUE", "True", "yes", "YES", "on", "ON"})
            CHECK(env_truthy(v));
    }

    SECTION("explicit negatives stay false (the security-critical cases)") {
        for (const char* v : {"0", "false", "FALSE", "no", "off", "", "2", "enable", "y", "t"})
            CHECK_FALSE(env_truthy(v));
    }

    SECTION("unset (null) is false — agent fails closed when the var is absent") {
        CHECK_FALSE(env_truthy(nullptr));
    }

    SECTION("surrounding whitespace is trimmed (config-management templating)") {
        CHECK(env_truthy("  true  "));
        CHECK(env_truthy("\t1\n"));
        CHECK(env_truthy(" on "));
        // ...but trimming must not turn a negative into an affirmative.
        CHECK_FALSE(env_truthy("  0  "));
        CHECK_FALSE(env_truthy("  false "));
    }

    SECTION("interior content is not an affirmative (no substring match)") {
        CHECK_FALSE(env_truthy("truthy"));
        CHECK_FALSE(env_truthy("1.0"));
        CHECK_FALSE(env_truthy("yes please"));
    }
}
