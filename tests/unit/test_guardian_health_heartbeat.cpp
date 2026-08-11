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

TEST_CASE("health heartbeat: all-zero stats emits NO tags (sparse / inert agent)",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags, GuardianHealthStats{});
    CHECK(tags.empty()); // nothing to report (also the prefer_spark=false case)
}

TEST_CASE("health heartbeat: non-zero suppression emits the pinned key + value",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags, GuardianHealthStats{.unhealthy_suppressed = 42});
    CHECK(tags.size() == 1);
    // Pinned wire key - the #2298 rollup reader MUST match this exact string.
    CHECK(tags.at("yuzu.guardian_unhealthy_suppressed") == "42");
    CHECK(std::string(kGuardianUnhealthySuppressedTag) == "yuzu.guardian_unhealthy_suppressed");
}

TEST_CASE("health heartbeat: non-zero refresh emits the pinned key + value (F5 6b)",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags, GuardianHealthStats{.unhealthy_refreshed = 7});
    CHECK(tags.size() == 1);
    CHECK(tags.at("yuzu.guardian_unhealthy_refreshed") == "7");
    CHECK(std::string(kGuardianUnhealthyRefreshedTag) == "yuzu.guardian_unhealthy_refreshed");
}

TEST_CASE("health heartbeat: non-zero demotion emits the pinned key + value (F5 6c)",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(tags, GuardianHealthStats{.priority_demoted = 3});
    CHECK(tags.size() == 1);
    CHECK(tags.at("yuzu.guardian_priority_demoted") == "3");
    CHECK(std::string(kGuardianPriorityDemotedTag) == "yuzu.guardian_priority_demoted");
}

TEST_CASE("health heartbeat: all three counters independent and additive",
          "[guardian][health][heartbeat]") {
    std::map<std::string, std::string> tags;
    emit_guardian_health_heartbeat_tags(
        tags, GuardianHealthStats{.unhealthy_suppressed = 1, .unhealthy_refreshed = 2,
                                  .priority_demoted = 3});
    CHECK(tags.size() == 3);
    CHECK(tags.at("yuzu.guardian_unhealthy_suppressed") == "1");
    CHECK(tags.at("yuzu.guardian_unhealthy_refreshed") == "2");
    CHECK(tags.at("yuzu.guardian_priority_demoted") == "3");
}
