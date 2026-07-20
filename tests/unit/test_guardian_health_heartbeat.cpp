/**
 * test_guardian_health_heartbeat.cpp -- the writer side of the Guardian health-stream fleet
 * telemetry (M1): the sparse-emit rule + the exact PINNED key name. A one-character drift here
 * would silently produce a zero fleet gauge at the #2298 server-side rollup, so this test locks
 * the wire key.
 */

#include "guardian_health_heartbeat.hpp"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <string>

using namespace yuzu::agent;

TEST_CASE("health heartbeat: zero suppression emits NO tag (sparse / inert agent)",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags, 0);
    CHECK(tags.empty()); // nothing suppressed → nothing to report (also the prefer_spark=false case)
}

TEST_CASE("health heartbeat: non-zero suppression emits the pinned key + value",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags, 42);
    CHECK(tags.size() == 1);
    // Pinned wire key — the #2298 rollup reader MUST match this exact string.
    CHECK(tags.at("yuzu.guardian_unhealthy_suppressed") == "42");
    CHECK(std::string(kGuardianUnhealthySuppressedTag) == "yuzu.guardian_unhealthy_suppressed");
}
