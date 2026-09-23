/**
 * test_privacy_permissions_parsers.cpp -- pure tests for privacy_permissions_parsers.hpp,
 * privacy_permissions_win_parsers.hpp and privacy_permissions_macos_parsers.hpp. No OS call, no
 * platform guard. The one file read is the committed YAML definition (the row_kind/column pin).
 */
#include <catch2/catch_test_macros.hpp>

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "privacy_permissions_macos_parsers.hpp"
#include "privacy_permissions_parsers.hpp"
#include "privacy_permissions_win_parsers.hpp"

using namespace yuzu::privacy_permissions;

namespace {

std::size_t field_count(const std::string& row) {
    std::size_t n = 1;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') ++i;
        else if (row[i] == '|') ++n;
    }
    return n;
}

/// The `- name:` entries under `result:` -> `columns:` in the committed YAML definition, in
/// order. Deliberately naive (this one file has exactly one document and one columns list).
std::vector<std::string> yaml_result_column_names() {
    // YUZU_TEST_FIXTURE_DIR is "<source_root>/tests/unit/fixtures" (tests/meson.build).
    const auto path = std::filesystem::path{YUZU_TEST_FIXTURE_DIR} / ".." / ".." / ".." /
                      "content" / "definitions" / "privacy_permissions.yaml";
    std::ifstream in(path);
    REQUIRE(in.is_open());
    std::vector<std::string> names;
    bool in_result = false, in_columns = false;
    for (std::string line; std::getline(in, line);) {
        if (line.rfind("  result:", 0) == 0) { in_result = true; continue; }
        if (in_result && line.rfind("    columns:", 0) == 0) { in_columns = true; continue; }
        if (!in_columns) continue;
        if (!line.empty() && line.find_first_not_of(' ') < 4 && line.find_first_not_of(' ') != std::string::npos)
            break; // left the columns block
        const auto pos = line.find("- name: ");
        if (pos != std::string::npos) names.push_back(line.substr(pos + 8));
    }
    return names;
}

} // namespace

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
    CHECK(field_count(row) == 8);
}

TEST_CASE("kColumns equals the YAML definition's result.columns, row_kind first, and every "
          "formatted row -- data and internal_error alike -- has exactly that many fields",
          "[privacy_permissions][parsers][columns]") {
    const auto yaml = yaml_result_column_names();
    REQUIRE(yaml.size() == kColumns.size());
    for (std::size_t i = 0; i < kColumns.size(); ++i) {
        INFO("column " << i);
        CHECK(yaml[i] == kColumns[i]);
    }
    CHECK(kColumns.front() == "row_kind");

    const auto data = format_row(
        {"windows", "alice\\C:\\App\\app.exe", "camera", PermissionState::denied, "Deny", "1", "2", false});
    CHECK(field_count(data) == kColumns.size());
    CHECK(data.rfind(std::string{kRowKindPermissions} + "|windows|", 0) == 0);

    for (const char* os : {"windows", "macos", "linux"}) {
        const auto err = format_internal_error_row(os);
        INFO(err);
        CHECK(field_count(err) == kColumns.size());
        CHECK(err == std::string{"constrained|"} + os + "|-|-|unreadable|internal_error|-|-");
    }
}

TEST_CASE("qualify_app_id: <owner>\\<app_id>; an unresolved owner renders '-', never an empty "
          "prefix that would read as an unqualified machine-wide row",
          "[privacy_permissions][parsers]") {
    CHECK(qualify_app_id("alice", "com.example.App") == "alice\\com.example.App");
    CHECK(qualify_app_id("alice", "-") == "alice\\-");
    CHECK(qualify_app_id("", "x") == "-\\x");
    // On the wire the row sanitizer folds the separator to '/', like every path.
    CHECK(format_row({"macos", qualify_app_id("alice", "com.x"), "camera",
                      PermissionState::allowed, "2", "-", "-", false}) ==
          "permissions|macos|alice/com.x|camera|allowed|2|-|-");
}

TEST_CASE("failure_row: denied promotes read_denied, unreadable does not; both carry the token "
          "in raw and in the accumulator, never absent",
          "[privacy_permissions][parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    const auto d = failure_row("linux", "-", "camera", true, "camera:access_denied", acc);
    CHECK(d.state == PermissionState::denied);
    CHECK(d.read_denied);
    CHECK(d.category == "camera");
    CHECK(d.raw == "camera:access_denied");
    const auto u = failure_row("linux", "-", "microphone", false, "microphone:shape", acc);
    CHECK(u.state == PermissionState::unreadable);
    CHECK_FALSE(u.read_denied);
    CHECK(acc.reason() == "camera:access_denied,microphone:shape");
}

TEST_CASE("fill_uncovered_categories: absent only for uncovered categories and only when "
          "nothing failed -- a failure is never backfilled as absent",
          "[privacy_permissions][parsers]") {
    SECTION("clean read: every uncovered category becomes absent") {
        yuzu::shared::ConstraintAccumulator acc;
        std::vector<PermissionRow> rows{
            {"windows", "alice\\-", "camera", PermissionState::allowed, "Allow", "-", "-", false}};
        fill_uncovered_categories("windows", rows, acc);
        REQUIRE(rows.size() == 4);
        for (std::size_t i = 1; i < rows.size(); ++i) {
            CHECK(rows[i].state == PermissionState::absent);
            CHECK(rows[i].category != "camera");
        }
    }
    SECTION("a failure token exists: nothing is filled") {
        yuzu::shared::ConstraintAccumulator acc;
        std::vector<PermissionRow> rows{failure_row("windows", "alice\\-", "-", false,
                                                    "alice:hive_mount_failed", acc)};
        fill_uncovered_categories("windows", rows, acc);
        CHECK(rows.size() == 1);
    }
    SECTION("a refused read with no token of its own: nothing is filled") {
        yuzu::shared::ConstraintAccumulator acc;
        std::vector<PermissionRow> rows{
            {"windows", "-", "-", PermissionState::denied, "-", "-", "-", true}};
        fill_uncovered_categories("windows", rows, acc);
        CHECK(rows.size() == 1);
    }
}

TEST_CASE("classify_session_bus_open: no session is unavailable, a refused socket is denied, "
          "anything else is a failure -- never all folded into 'no session'",
          "[privacy_permissions][parsers][linux]") {
    CHECK(classify_session_bus_open(ENOENT) == BusOpenOutcome::unavailable);
    CHECK(classify_session_bus_open(ECONNREFUSED) == BusOpenOutcome::unavailable);
#if defined(ENOMEDIUM)
    CHECK(classify_session_bus_open(ENOMEDIUM) == BusOpenOutcome::unavailable);
#endif
    CHECK(classify_session_bus_open(EACCES) == BusOpenOutcome::denied);
    CHECK(classify_session_bus_open(EPERM) == BusOpenOutcome::denied);
    CHECK(classify_session_bus_open(ENOMEM) == BusOpenOutcome::failed);
    CHECK(classify_session_bus_open(0) == BusOpenOutcome::failed);
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

TEST_CASE("win::unescape_nonpackaged_app_id: '#3A' is the drive colon, bare '#' the path "
          "separator (KIMI-P1-05: #3A must be checked first or the colon is corrupted)",
          "[privacy_permissions][win_parsers]") {
    // Real ConsentStore NonPackaged shape: C:\Program Files\App.exe ->
    // C#3A#Program Files#App.exe (':'->'#3A', '\'->'#').
    CHECK(win::unescape_nonpackaged_app_id("C#3A#Program Files#App.exe") ==
         "C:\\Program Files\\App.exe");
    // A bare '#' with no following "3A" still falls through to the path separator.
    CHECK(win::unescape_nonpackaged_app_id("C#3AUsers#name#app.exe") == "C:Users\\name\\app.exe");
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

TEST_CASE("win::decode_last_used: only a REG_QWORD of exactly 8 bytes converts; not-found is "
          "'-'; every other outcome is a visible `unreadable` with a cause",
          "[privacy_permissions][win_parsers]") {
    constexpr std::uint64_t kEpochDiff100ns = 116444736000000000ULL;
    const auto ok = win::decode_last_used(win::kErrorSuccess, win::kRegQword, 8, kEpochDiff100ns + 10000);
    CHECK(ok.value == "1");
    CHECK(ok.cause.empty());

    const auto missing = win::decode_last_used(win::kErrorFileNotFound, 0, 0, 0);
    CHECK(missing.value == "-");
    CHECK(missing.cause.empty());

    const auto short_q = win::decode_last_used(win::kErrorSuccess, win::kRegQword, 4, 0);
    CHECK(short_q.value == "unreadable");
    CHECK(short_q.cause == "size_4");

    const auto wrong_t = win::decode_last_used(win::kErrorSuccess, win::kRegSz, 8, 0);
    CHECK(wrong_t.value == "unreadable");
    CHECK(wrong_t.cause == "type_1");

    const auto denied = win::decode_last_used(win::kErrorAccessDenied, 0, 0, 0);
    CHECK(denied.value == "unreadable");
    CHECK(denied.cause == "access_denied");
    CHECK(denied.denied);

    const auto more_data = win::decode_last_used(234, 3 /* REG_BINARY */, 16, 0);
    CHECK(more_data.cause == "win32_234");
    CHECK_FALSE(more_data.denied);
}

TEST_CASE("win::merge_with_hklm: only a SUCCESSFULLY-read HKLM value overrides a profile entry; "
          "an absent/unreadable/refused HKLM value never does, and a failed profile entry is "
          "kept beside the HKLM value, never hidden",
          "[privacy_permissions][win_parsers]") {
    using win::RawGrant;
    const auto grant = [](std::string app, PermissionState st, std::string raw,
                          bool read_denied = false, std::string cause = {}) {
        RawGrant g{std::move(app), "camera", st, std::move(raw)};
        g.read_denied = read_denied;
        g.cause = std::move(cause);
        return g;
    };

    SECTION("an authoritative HKLM value overrides a successfully-read profile grant") {
        const std::vector<RawGrant> profile{grant("app", PermissionState::allowed, "Allow")};
        const std::vector<RawGrant> hklm{grant("app", PermissionState::denied, "Deny")};
        const auto m = win::merge_with_hklm(profile, hklm);
        REQUIRE(m.size() == 1);
        CHECK(m[0].state == PermissionState::denied);
        CHECK(m[0].raw_value == "Deny");
    }
    SECTION("an HKLM entry that is absent, unreadable or refused overrides nothing") {
        const std::vector<RawGrant> profile{grant("app", PermissionState::allowed, "Allow")};
        for (const auto& h : {grant("app", PermissionState::absent, "-"),
                              grant("app", PermissionState::unreadable, "-", false, "value_empty"),
                              grant("app", PermissionState::denied, "-", true, "value_access_denied")}) {
            const std::vector<RawGrant> hklm{h};
            const auto m = win::merge_with_hklm(profile, hklm);
            REQUIRE(m.size() == 1);
            CHECK(m[0].state == PermissionState::allowed);
            CHECK(m[0].raw_value == "Allow");
        }
    }
    SECTION("an authoritative HKLM value fills a key the profile lacks") {
        const std::vector<RawGrant> profile{};
        const std::vector<RawGrant> hklm{grant("app", PermissionState::allowed, "Allow")};
        const auto m = win::merge_with_hklm(profile, hklm);
        REQUIRE(m.size() == 1);
        CHECK(m[0].app_id == "app");
    }
    SECTION("a failed profile entry is kept, and the HKLM value is added beside it") {
        const std::vector<RawGrant> profile{
            grant("app", PermissionState::unreadable, "-", false, "value_empty")};
        const std::vector<RawGrant> hklm{grant("app", PermissionState::allowed, "Allow")};
        const auto m = win::merge_with_hklm(profile, hklm);
        REQUIRE(m.size() == 2);
        CHECK(m[0].state == PermissionState::unreadable);
        CHECK(m[1].state == PermissionState::allowed);
    }
}

// ── macOS-specific pure layer ────────────────────────────────────────────

TEST_CASE("macos::decode_auth_value: 0 denied, 2/3 allowed, other prompt_undetermined, a "
          "NULL/non-integer column unreadable (never a fabricated 0 = denied)",
          "[privacy_permissions][macos_parsers]") {
    CHECK(macos::decode_auth_value(0) == PermissionState::denied);
    CHECK(macos::decode_auth_value(2) == PermissionState::allowed);
    CHECK(macos::decode_auth_value(3) == PermissionState::allowed);
    CHECK(macos::decode_auth_value(1) == PermissionState::prompt_undetermined);
    CHECK(macos::decode_auth_value(std::nullopt) == PermissionState::unreadable);
}

TEST_CASE("macos::classify_tcc_presence: a missing per-user db is absent, a missing system db "
          "is unreadable, a refused lstat is denied, a non-regular file is refused",
          "[privacy_permissions][macos_parsers]") {
    CHECK_FALSE(macos::classify_tcc_presence(0, true, true).has_value());
    const auto user_missing = macos::classify_tcc_presence(ENOENT, false, true);
    REQUIRE(user_missing);
    CHECK(user_missing->outcome == macos::SourceOutcome::absent);
    CHECK(user_missing->cause.empty());
    const auto sys_missing = macos::classify_tcc_presence(ENOENT, false, false);
    REQUIRE(sys_missing);
    CHECK(sys_missing->outcome == macos::SourceOutcome::unreadable);
    CHECK(sys_missing->cause == "missing");
    for (const int e : {EPERM, EACCES}) {
        const auto d = macos::classify_tcc_presence(e, false, true);
        REQUIRE(d);
        CHECK(d->outcome == macos::SourceOutcome::denied);
    }
    const auto link = macos::classify_tcc_presence(0, false, true);
    REQUIRE(link);
    CHECK(link->outcome == macos::SourceOutcome::unreadable);
    CHECK(link->cause == "not_regular_file");
    const auto io = macos::classify_tcc_presence(EIO, false, true);
    REQUIRE(io);
    CHECK(io->cause == "lstat_errno_" + std::to_string(EIO));
}

TEST_CASE("macos::classify_tcc_sqlite_rc: CANTOPEN/AUTH/PERM (incl. extended codes) on a "
          "present file is denied; any other code unreadable",
          "[privacy_permissions][macos_parsers]") {
    CHECK(macos::classify_tcc_sqlite_rc(macos::kSqliteCantOpen) == macos::SourceOutcome::denied);
    CHECK(macos::classify_tcc_sqlite_rc(macos::kSqliteAuth) == macos::SourceOutcome::denied);
    CHECK(macos::classify_tcc_sqlite_rc(macos::kSqlitePerm) == macos::SourceOutcome::denied);
    CHECK(macos::classify_tcc_sqlite_rc(macos::kSqliteCantOpen | (1 << 8)) ==
          macos::SourceOutcome::denied);
    CHECK(macos::classify_tcc_sqlite_rc(1 /* SQLITE_ERROR */) == macos::SourceOutcome::unreadable);
    CHECK(macos::classify_tcc_sqlite_rc(26 /* SQLITE_NOTADB */) == macos::SourceOutcome::unreadable);
}

TEST_CASE("macos::append_tcc_source_rows: per-user rows qualified; every category is a row -- "
          "decoded grants, absent when clean and empty, unreadable when the step failed",
          "[privacy_permissions][macos_parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PermissionRow> rows;
    // Shaped on the real per-user TCC.db rows this Mac returned on 2026-09-23
    // (kTCCServiceMicrophone|com.microsoft.teams2|2).
    const std::vector<macos::TccServiceRead> reads{
        {"camera", {}, false},
        {"microphone", {{"com.microsoft.teams2", 2}, {"com.example.Broken", std::nullopt}}, false},
        {"full_disk_access", {}, true},
    };
    macos::append_tcc_source_rows("alice", reads, rows, acc);
    REQUIRE(rows.size() == 4);
    CHECK(format_row(rows[0]) == "permissions|macos|alice/-|camera|absent|-|-|-");
    CHECK(format_row(rows[1]) == "permissions|macos|alice/com.microsoft.teams2|microphone|allowed|2|-|-");
    CHECK(rows[2].state == PermissionState::unreadable);
    CHECK(rows[2].raw == "alice:tcc_db:microphone:auth_value_unreadable");
    CHECK(rows[3].category == "full_disk_access");
    CHECK(rows[3].state == PermissionState::unreadable);
    CHECK(rows[3].raw == "alice:tcc_db:full_disk_access:query_step_failed");
    CHECK(acc.reason() ==
          "alice:tcc_db:microphone:auth_value_unreadable,alice:tcc_db:full_disk_access:query_step_failed");

    // The system db (empty owner) keeps its unqualified rows.
    std::vector<PermissionRow> sys;
    const std::vector<macos::TccServiceRead> sys_reads{
        {"full_disk_access", {{"com.microsoft.VSCode", 2}}, false}};
    macos::append_tcc_source_rows({}, sys_reads, sys, acc);
    REQUIRE(sys.size() == 1);
    CHECK(format_row(sys[0]) == "permissions|macos|com.microsoft.VSCode|full_disk_access|allowed|2|-|-");
}

TEST_CASE("macos::tcc_source_failed_row: absent carries no token; denied/unreadable carry "
          "`<source>:<cause>` and are never absent",
          "[privacy_permissions][macos_parsers]") {
    yuzu::shared::ConstraintAccumulator acc;
    const auto absent = macos::tcc_source_failed_row("bob", {macos::SourceOutcome::absent, {}}, acc);
    CHECK(format_row(absent) == "permissions|macos|bob/-|-|absent|-|-|-");
    CHECK_FALSE(acc.any_failure());

    const auto denied = macos::tcc_source_failed_row(
        "bob", {macos::SourceOutcome::denied, "access_denied"}, acc);
    CHECK(denied.state == PermissionState::denied);
    CHECK(denied.read_denied);
    CHECK(denied.raw == "bob:tcc_db:access_denied");

    const auto sys = macos::tcc_source_failed_row(
        {}, {macos::SourceOutcome::unreadable, "open_failed:disk I/O error"}, acc);
    CHECK(sys.app_id == "-");
    CHECK(sys.state == PermissionState::unreadable);
    CHECK(sys.raw == "tcc_db:open_failed:disk I/O error");
}
