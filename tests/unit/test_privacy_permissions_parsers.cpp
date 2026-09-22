/**
 * test_privacy_permissions_parsers.cpp -- pure tests for privacy_permissions_parsers.hpp and
 * privacy_permissions_win_parsers.hpp. No OS call, no platform guard.
 */
#include <catch2/catch_test_macros.hpp>

#include "privacy_permissions_parsers.hpp"
#include "privacy_permissions_win_parsers.hpp"

using namespace yuzu::privacy_permissions;

TEST_CASE("state_token: order pinned, matches kStateTokens", "[privacy_permissions][parsers]") {
    CHECK(state_token(PermissionState::allowed) == "allowed");
    CHECK(state_token(PermissionState::denied) == "denied");
    CHECK(state_token(PermissionState::prompt_undetermined) == "prompt_undetermined");
    CHECK(state_token(PermissionState::absent) == "absent");
    CHECK(state_token(PermissionState::unreadable) == "unreadable");
    CHECK(state_token(PermissionState::unsupported) == "unsupported");
}

TEST_CASE("is_known_category: exactly the four charter categories", "[privacy_permissions][parsers]") {
    CHECK(is_known_category("camera"));
    CHECK(is_known_category("microphone"));
    CHECK(is_known_category("location"));
    CHECK(is_known_category("full_disk_access"));
    CHECK_FALSE(is_known_category("contacts"));
    CHECK_FALSE(is_known_category(""));
}

TEST_CASE("format_row: 8 fields, always, Windows fields default to '-'", "[privacy_permissions][parsers]") {
    PermissionRow r{"macos", "com.example.App", "camera", PermissionState::allowed, "2", "-", "-", false};
    const auto row = format_row(r);
    CHECK(row == "permissions|macos|com.example.App|camera|allowed|2|-|-");
    // field count: split on unescaped '|'
    int fields = 1;
    for (char c : row)
        if (c == '|') ++fields;
    CHECK(fields == 8);
}

TEST_CASE("format_row: Windows row carries real last-used fields", "[privacy_permissions][parsers]") {
    // safe_output_field maps '\' -> '/' (it doubles as the pipe-delimited row's separator
    // sanitizer) -- app_id is checked post-sanitization, matching every other row this
    // plugin's siblings emit.
    PermissionRow r{"windows", "C:\\App\\app.exe", "microphone", PermissionState::denied, "Deny",
                    "1700000000000", "1700000100000", false};
    CHECK(format_row(r) ==
         "permissions|windows|C:/App/app.exe|microphone|denied|Deny|1700000000000|1700000100000");
}

TEST_CASE("whole_read_failed_row: denied sets read_denied and accumulates the token",
          "[privacy_permissions][parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    const auto row = whole_read_failed_row("macos", PermissionState::denied, "tcc_db:open_failed",
                                           acc, true);
    CHECK(row.read_denied);
    CHECK(row.category == "-");
    CHECK(acc.any_failure());
    CHECK(acc.reason() == "tcc_db:open_failed");
}

TEST_CASE("whole_read_failed_row: unreadable-but-not-denied still accumulates",
          "[privacy_permissions][parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    const auto row =
        whole_read_failed_row("linux", PermissionState::unreadable, "portal:shape", acc, false);
    CHECK_FALSE(row.read_denied);
    CHECK(acc.any_failure());
}

TEST_CASE("select_status: denied wins over a mere failure token", "[privacy_permissions][parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    acc.add_failure("x:y");
    const auto st = select_status(acc, true, false);
    CHECK(st.status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(st.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
}

TEST_CASE("select_status: a failure token with no denial is CONSTRAINED", "[privacy_permissions][parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    acc.add_failure("x:y");
    const auto st = select_status(acc, false, false);
    CHECK(st.status == YUZU_RESULT_STATUS_CONSTRAINED);
}

TEST_CASE("select_status: no failure, no denial, reachable mechanism is OK/FULL",
          "[privacy_permissions][parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    CHECK(select_status(acc, false, false).status == YUZU_RESULT_STATUS_OK);
}

TEST_CASE("select_status: no failure, no denial, unavailable mechanism is UNAVAILABLE/FULL",
          "[privacy_permissions][parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    const auto st = select_status(acc, false, true);
    CHECK(st.status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(st.completeness == YUZU_RESULT_COMPLETENESS_FULL);
}

TEST_CASE("any_denied: true iff at least one row's read was refused", "[privacy_permissions][parsers]") {
    std::vector<PermissionRow> rows{
        {"macos", "-", "camera", PermissionState::allowed, "-", "-", "-", false},
        {"macos", "-", "microphone", PermissionState::denied, "-", "-", "-", true},
    };
    CHECK(any_denied(rows));
    rows.pop_back();
    CHECK_FALSE(any_denied(rows));
}

// ── Windows-specific pure layer ──────────────────────────────────────────

TEST_CASE("win::capability_to_category: the four mapped capabilities, unknown returns empty",
          "[privacy_permissions][win_parsers]") {
    CHECK(win::capability_to_category("webcam") == "camera");
    CHECK(win::capability_to_category("microphone") == "microphone");
    CHECK(win::capability_to_category("location") == "location");
    CHECK(win::capability_to_category("broadFileSystemAccess") == "full_disk_access");
    CHECK(win::capability_to_category("contacts").empty());
}

TEST_CASE("win::decode_consent_value: Allow/Deny decode, wrong type or empty is unreadable, "
          "an unknown literal is prompt_undetermined (never silently allowed/denied)",
          "[privacy_permissions][win_parsers]") {
    CHECK(win::decode_consent_value("Allow", true) == PermissionState::allowed);
    CHECK(win::decode_consent_value("Deny", true) == PermissionState::denied);
    CHECK(win::decode_consent_value("Allow", false) == PermissionState::unreadable); // wrong type
    CHECK(win::decode_consent_value("", true) == PermissionState::unreadable);       // empty
    CHECK(win::decode_consent_value("Prompt", true) == PermissionState::prompt_undetermined);
}

TEST_CASE("win::unescape_nonpackaged_app_id: '#' maps to a path separator",
          "[privacy_permissions][win_parsers]") {
    CHECK(win::unescape_nonpackaged_app_id("C#3AProgram Files#3AApp.exe") ==
         "C\\3AProgram Files\\3AApp.exe");
}

TEST_CASE("win::filetime_to_epoch_ms_string: zero and pre-epoch are '-', a real value converts",
          "[privacy_permissions][win_parsers]") {
    CHECK(win::filetime_to_epoch_ms_string(0) == "-");
    CHECK(win::filetime_to_epoch_ms_string(1) == "-"); // far before the Unix epoch
    // The 1601->1970 epoch boundary itself: exactly epoch_ms=0, and one more 100ns-tick
    // interval (10000 ticks = 1ms) past it converts to exactly 1ms -- both self-verifying
    // (derived from the function's own documented constant, not a separately hand-computed
    // calendar date, which is the trap the first version of this test fell into).
    constexpr std::uint64_t kEpochDiff100ns = 116444736000000000ULL;
    CHECK(win::filetime_to_epoch_ms_string(kEpochDiff100ns) == "0");
    CHECK(win::filetime_to_epoch_ms_string(kEpochDiff100ns + 10000) == "1");
    CHECK(win::filetime_to_epoch_ms_string(kEpochDiff100ns + 86400ULL * 10000000ULL) == "86400000"); // +1 day
}
