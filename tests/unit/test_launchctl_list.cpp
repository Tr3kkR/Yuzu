/**
 * test_launchctl_list.cpp -- fixture-fed tests for agents/shared/
 * launchctl_list.hpp's pure `launchctl list` row parser. Same discipline as
 * test_tar_service.cpp: every case feeds a fixed std::vector<std::string>
 * straight to the pure parser, no spawn, no sleep. Real-capture fixture rows
 * are the same ones test_tar_service.cpp documents the provenance of
 * (launchctl rows captured 2026-08-24 on a macOS arm64 dev host -- see that
 * file's header comment) -- reused here rather than re-documented, since
 * it's the identical wire shape.
 */
#include <launchctl_list.hpp>

#include <catch2/catch_test_macros.hpp>

using yuzu::shared::decode_launchctl_row;
using yuzu::shared::LaunchctlRow;
using yuzu::shared::parse_launchctl_list;

// ── decode_launchctl_row (CH-2 fixtures, A0 governance fix round) ────────────

TEST_CASE("decode_launchctl_row: a hex-looking PID is rejected, not truncated",
          "[launchctl_list]") {
    auto row = decode_launchctl_row("0x1A\t0\tcom.example.svc");
    CHECK_FALSE(row.pid.has_value()); // from_chars stops at 'x' -- partial match rejected
    CHECK(row.status == 0);
    CHECK(row.label == "com.example.svc");
}

TEST_CASE("decode_launchctl_row: a trailing-garbage PID is rejected, not truncated "
          "to its numeric prefix",
          "[launchctl_list]") {
    auto row = decode_launchctl_row("12abc\t0\tcom.example.svc");
    CHECK_FALSE(row.pid.has_value()); // stoll would have silently accepted "12"
}

TEST_CASE("decode_launchctl_row: a dash status decodes to 0, not a parse attempt",
          "[launchctl_list]") {
    auto row = decode_launchctl_row("1190\t-\tcom.example.svc");
    REQUIRE(row.pid.has_value());
    CHECK(*row.pid == 1190);
    CHECK(row.status == 0);
}

TEST_CASE("decode_launchctl_row: a 1-field row (no tabs) decodes with an empty "
          "label and no pid, never throws",
          "[launchctl_list]") {
    auto row = decode_launchctl_row("1190");
    CHECK(row.label.empty());
    CHECK_FALSE(row.pid.has_value());
    CHECK(row.status == 0);
}

TEST_CASE("decode_launchctl_row: a 4-field row folds the extra field into the "
          "label verbatim, tab included",
          "[launchctl_list]") {
    auto row = decode_launchctl_row("1190\t0\tcom.example.svc\textra");
    REQUIRE(row.pid.has_value());
    CHECK(*row.pid == 1190);
    CHECK(row.label == "com.example.svc\textra");
}

TEST_CASE("decode_launchctl_row: a literal tab inside the label is preserved "
          "verbatim, not treated as a field boundary",
          "[launchctl_list]") {
    auto row = decode_launchctl_row("1190\t0\tcom.example\tweird.label");
    REQUIRE(row.pid.has_value());
    CHECK(*row.pid == 1190);
    CHECK(row.label == "com.example\tweird.label");
}

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
