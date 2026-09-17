/**
 * test_launchctl_list.cpp -- fixture-fed tests for agents/shared/
 * launchctl_list.hpp's pure `launchctl list` row parser. Same discipline as
 * test_tar_service.cpp: every case feeds a fixed std::vector<std::string>
 * straight to the pure parser, no spawn, no sleep. Fixture rows are the same
 * real macOS host capture test_tar_service.cpp already documents the
 * provenance of (2026-08-25-era; see that file's header comment) -- reused
 * here rather than re-documented, since it's the identical wire shape.
 */
#include <launchctl_list.hpp>

#include <catch2/catch_test_macros.hpp>

using yuzu::shared::LaunchctlRow;
using yuzu::shared::parse_launchctl_list;

TEST_CASE("parse_launchctl_list: empty input yields empty output", "[launchctl_list]") {
    CHECK(parse_launchctl_list({}).empty());
}

TEST_CASE("parse_launchctl_list: header-only input yields empty output", "[launchctl_list]") {
    std::vector<std::string> lines = {"PID\tStatus\tLabel"};
    CHECK(parse_launchctl_list(lines).empty());
}

TEST_CASE("parse_launchctl_list: real macOS host capture -- raw fields preserved",
          "[launchctl_list]") {
    std::vector<std::string> lines = {
        "PID\tStatus\tLabel",
        "-\t0\tcom.apple.SafariHistoryServiceAgent",
        "1190\t0\tcom.apple.progressd",
        "93175\t-9\tcom.apple.knowledgeconstructiond",
    };

    auto rows = parse_launchctl_list(lines);
    REQUIRE(rows.size() == 3);

    CHECK(rows[0].label == "com.apple.SafariHistoryServiceAgent");
    CHECK_FALSE(rows[0].pid.has_value());
    CHECK(rows[0].status == 0);

    CHECK(rows[1].label == "com.apple.progressd");
    REQUIRE(rows[1].pid.has_value());
    CHECK(*rows[1].pid == 1190);
    CHECK(rows[1].status == 0);

    // A negative (signal-killed) status code with a real pid still decodes
    // both fields verbatim -- unlike the historical ServiceInfo-collapsing
    // parser, this one never discards the status code.
    CHECK(rows[2].label == "com.apple.knowledgeconstructiond");
    REQUIRE(rows[2].pid.has_value());
    CHECK(*rows[2].pid == 93175);
    CHECK(rows[2].status == -9);
}

TEST_CASE("parse_launchctl_list: a truncated row with no LABEL field decodes "
          "with an empty label rather than throwing",
          "[launchctl_list]") {
    std::vector<std::string> lines = {
        "PID\tStatus\tLabel",
        "1190\t0", // synthetic: truncated row, LABEL column missing
    };
    auto rows = parse_launchctl_list(lines);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].label.empty());
    REQUIRE(rows[0].pid.has_value());
    CHECK(*rows[0].pid == 1190);
}

TEST_CASE("launchd_state_for: listed with a pid resolves Running",
          "[launchctl_list]") {
    std::vector<LaunchctlRow> rows = {
        {"com.apple.progressd", 1190, 0},
    };
    CHECK(yuzu::shared::launchd_state_for(rows, "com.apple.progressd")
          == yuzu::agent::ServiceRunState::Running);
}

TEST_CASE("launchd_state_for: listed without a pid resolves Stopped",
          "[launchctl_list]") {
    std::vector<LaunchctlRow> rows = {
        {"com.apple.SafariHistoryServiceAgent", std::nullopt, 0},
    };
    CHECK(yuzu::shared::launchd_state_for(rows, "com.apple.SafariHistoryServiceAgent")
          == yuzu::agent::ServiceRunState::Stopped);
}

TEST_CASE("launchd_state_for: a label absent from the snapshot resolves Stopped, "
          "never Paused",
          "[launchctl_list]") {
    std::vector<LaunchctlRow> rows = {
        {"com.apple.progressd", 1190, 0},
    };
    CHECK(yuzu::shared::launchd_state_for(rows, "com.apple.not.installed")
          == yuzu::agent::ServiceRunState::Stopped);
}
