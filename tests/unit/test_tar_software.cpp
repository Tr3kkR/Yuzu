/**
 * test_tar_software.cpp -- Unit tests for the `software` source's pure
 * orchestration core (tar_software_core) and its numeric version comparator
 * (tar_version). The Windows registry enumeration in tar_software_collector.cpp
 * is platform-gated and exercised by the Windows smoke; everything that decides
 * WHAT gets emitted — cold-start seeding, corrupt-state skip, machine-only vs
 * per-user carry-forward, and version ordering — is pure and tested here so it
 * runs on every platform (#1620).
 */

#include "tar_software_core.hpp"
#include "tar_version.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::tar;

namespace {
SoftwareInfo sw(std::string name, std::string version, std::string scope = "machine",
                std::string user = "") {
    SoftwareInfo s;
    s.name = std::move(name);
    s.version = std::move(version);
    s.publisher = "Acme";
    s.scope = std::move(scope);
    s.user = std::move(user);
    s.install_date = "20260101";
    return s;
}
} // namespace

// =============================================================================
// Numeric version comparator (tar_version.hpp) — the dedup() ordering key
// =============================================================================

TEST_CASE("compare_versions: numeric segments, not lexicographic", "[tar][software][version]") {
    // The exact #1620 bug: a std::string `operator>` makes "9.0" > "10.0".
    CHECK(compare_versions("10.0", "9.0") > 0);
    CHECK(compare_versions("9.0", "10.0") < 0);
    CHECK(compare_versions("1.2.10", "1.2.9") > 0);
    CHECK(compare_versions("23.01", "24.00") < 0);
    CHECK(compare_versions("2.0.0", "2.0.0") == 0);
}

TEST_CASE("compare_versions: differing segment counts treat missing as zero",
          "[tar][software][version]") {
    CHECK(compare_versions("1.0", "1.0.0") == 0);
    CHECK(compare_versions("1.2", "1.2.0.1") < 0);
}

TEST_CASE("compare_versions: non-numeric segment falls back to lexicographic",
          "[tar][software][version]") {
    CHECK(compare_versions("1.9.5p2", "1.9.5p3") < 0);
    CHECK(compare_versions("", "") == 0);
    CHECK(compare_versions("1", "") > 0);
}

// =============================================================================
// State (de)serialisation round-trip
// =============================================================================

TEST_CASE("software_state_to_json round-trips through software_state_from_json",
          "[tar][software][serde]") {
    std::vector<SoftwareInfo> apps = {sw("7-Zip", "23.01"), sw("Slack", "4.0", "user", "carol")};
    auto restored = software_state_from_json(software_state_to_json(apps));
    REQUIRE(restored.size() == 2);
    CHECK(restored[0].name == "7-Zip");
    CHECK(restored[0].scope == "machine");
    CHECK(restored[1].name == "Slack");
    CHECK(restored[1].scope == "user");
    CHECK(restored[1].user == "carol");
    CHECK(restored[1].version == "4.0");
}

TEST_CASE("software_state_from_json tolerates blank / non-array / garbage",
          "[tar][software][serde]") {
    CHECK(software_state_from_json("").empty());
    CHECK(software_state_from_json("not json at all").empty());
    CHECK(software_state_from_json("{}").empty());       // object, not array
    CHECK(software_state_from_json("[1, 2, 3]").empty()); // array of non-objects
}

// =============================================================================
// software_collect_core — cold-start / corrupt / steady classification
// =============================================================================

TEST_CASE("software_collect_core: cold start seeds the baseline and emits no events",
          "[tar][software][orchestration]") {
    std::vector<SoftwareInfo> enumerated = {sw("7-Zip", "23.01"), sw("Chrome", "120")};
    auto r = software_collect_core("", enumerated, {}, /*user_scope=*/false, 1000, 1);

    REQUIRE(r.kind == SoftwareCollectResult::Kind::kColdStartSeed);
    CHECK(r.events.empty());
    // The seeded state is exactly what was enumerated.
    auto restored = software_state_from_json(r.new_state_json);
    REQUIRE(restored.size() == 2);
}

TEST_CASE("software_collect_core: corrupt prior state skips and preserves the baseline",
          "[tar][software][orchestration]") {
    // Non-array JSON and outright garbage both classify as corrupt — NOT cold-start
    // (would lose the baseline) and NOT a diff-against-empty (would storm).
    for (const char* bad : {"{\"oops\":true}", "not json", "42"}) {
        auto r = software_collect_core(bad, {sw("X", "1")}, {}, /*user_scope=*/false, 2000, 2);
        CHECK(r.kind == SoftwareCollectResult::Kind::kCorruptSkip);
        CHECK(r.events.empty());
        CHECK(r.new_state_json.empty()); // caller leaves the on-disk baseline untouched
    }
}

TEST_CASE("software_collect_core: steady machine-only detects install + remove",
          "[tar][software][orchestration]") {
    auto prev_json = software_state_to_json({sw("7-Zip", "23.01")});
    // 7-Zip removed, Chrome installed.
    std::vector<SoftwareInfo> enumerated = {sw("Chrome", "120")};

    auto r = software_collect_core(prev_json, enumerated, {}, /*user_scope=*/false, 3000, 3);

    REQUIRE(r.kind == SoftwareCollectResult::Kind::kSteady);
    REQUIRE(r.events.size() == 2);
    bool saw_install = false, saw_remove = false;
    for (const auto& e : r.events) {
        if (e.action == "installed" && e.name == "Chrome")
            saw_install = true;
        if (e.action == "removed" && e.name == "7-Zip")
            saw_remove = true;
    }
    CHECK(saw_install);
    CHECK(saw_remove);
    // New state is exactly the machine-only enumeration (no carry-forward).
    auto restored = software_state_from_json(r.new_state_json);
    REQUIRE(restored.size() == 1);
    CHECK(restored[0].name == "Chrome");
}

TEST_CASE("software_collect_core: steady upgrade is one event",
          "[tar][software][orchestration]") {
    auto prev_json = software_state_to_json({sw("7-Zip", "23.01")});
    auto r = software_collect_core(prev_json, {sw("7-Zip", "24.00")}, {}, /*user_scope=*/false,
                                   4000, 4);
    REQUIRE(r.kind == SoftwareCollectResult::Kind::kSteady);
    REQUIRE(r.events.size() == 1);
    CHECK(r.events[0].action == "upgraded");
    CHECK(r.events[0].version == "24.00");
    CHECK(r.events[0].prev_version == "23.01");
}

TEST_CASE("software_collect_core: per-user scope carries logged-off user forward, "
          "detects logged-on uninstall",
          "[tar][software][orchestration]") {
    // Baseline: a machine app, bob's app (bob now logged off), alice's app (alice
    // logged on and has since uninstalled it).
    auto prev_json = software_state_to_json({
        sw("7-Zip", "23.01", "machine"),
        sw("OfflineApp", "1.0", "user", "bob"),
        sw("OnlineApp", "2.0", "user", "alice"),
    });
    // This tick (user scope ON): machine app present; alice scanned with zero apps;
    // bob NOT scanned (logged off) so his hive isn't read.
    std::vector<SoftwareInfo> enumerated = {sw("7-Zip", "23.01", "machine")};
    std::vector<std::string> scanned_users = {"alice"};

    auto r = software_collect_core(prev_json, enumerated, scanned_users, /*user_scope=*/true, 5000,
                                   5);

    REQUIRE(r.kind == SoftwareCollectResult::Kind::kSteady);
    // bob's app is carried forward (inert); only alice's uninstall is an event.
    REQUIRE(r.events.size() == 1);
    CHECK(r.events[0].action == "removed");
    CHECK(r.events[0].name == "OnlineApp");
    CHECK(r.events[0].user == "alice");
    // New state keeps the machine app + bob's carried-forward app.
    auto restored = software_state_from_json(r.new_state_json);
    REQUIRE(restored.size() == 2);
}
