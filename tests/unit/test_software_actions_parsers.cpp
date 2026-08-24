/**
 * test_software_actions_parsers.cpp — pure software_actions parse helpers
 * (software_actions_parsers.hpp; software_actions' FIRST test coverage,
 * Wave 4 PR4.3b).
 *
 * The bounded-runner acquisition in software_actions_plugin.cpp is the
 * impure shell; the decision-shaped parsing of winget/apt/yum/
 * softwareupdate/dpkg-query output is header-pure and pinned here on every
 * host (the firewall_parsers.hpp pattern).
 *
 * Fixture provenance, stated honestly:
 *   - the `softwareupdate -l` fixture is a REAL capture from this macOS host
 *     (2026-08-24, `/usr/sbin/softwareupdate -l`, rc=0, empty stderr).
 *   - the winget/apt/yum/dpkg-query fixtures are RECONSTRUCTED from each
 *     tool's documented output format — no Windows or Linux host was
 *     available in this sandbox to capture them live.
 */

#include "software_actions_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::software_actions;

// ── Windows: winget upgrade ────────────────────────────────────────────────

TEST_CASE("winget upgrade: fixed-width table with two rows — reconstructed from documented format",
          "[software_actions]") {
    constexpr std::string_view out =
        "Name               Id                        Version      Available    Source\n"
        "-----------------------------------------------------------------------------\n"
        "7-Zip 22.01        7zip.7zip                 22.01        23.01        winget\n"
        "Git                Git.Git                   2.40.0       2.42.0       winget\n"
        "\n"
        "2 upgrades available.\n";
    auto parsed = parse_winget_upgrade(out);
    CHECK(parsed.separator_found);
    REQUIRE(parsed.rows.size() == 2);
    CHECK(parsed.rows[0].name == "7-Zip 22.01");
    CHECK(parsed.rows[0].current_version == "22.01");
    CHECK(parsed.rows[0].available_version == "23.01");
    CHECK(parsed.rows[1].name == "Git");
    CHECK(parsed.rows[1].current_version == "2.40.0");
    CHECK(parsed.rows[1].available_version == "2.42.0");
}

TEST_CASE("winget upgrade: two-column row (no version columns) falls back to name-only",
          "[software_actions]") {
    constexpr std::string_view out = "Name               Id\n"
                                     "-----------------------------------------------------------------------------\n"
                                     "SomeApp             some.vendor.app\n";
    auto parsed = parse_winget_upgrade(out);
    REQUIRE(parsed.rows.size() == 1);
    CHECK(parsed.rows[0].name == "SomeApp");
    CHECK(parsed.rows[0].current_version == "-");
    CHECK(parsed.rows[0].available_version == "-");
}

TEST_CASE("winget upgrade: separator found but zero data rows is the up-to-date shape",
          "[software_actions]") {
    constexpr std::string_view out =
        "Name               Id                        Version      Available    Source\n"
        "-----------------------------------------------------------------------------\n"
        "No installed package found matching input criteria.\n";
    auto parsed = parse_winget_upgrade(out);
    CHECK(parsed.separator_found);
    // The footer/no-match line has fewer than 2 space-delimited columns, so
    // it never becomes a row.
    CHECK(parsed.rows.empty());
}

TEST_CASE("winget upgrade: empty output never finds the separator", "[software_actions]") {
    auto parsed = parse_winget_upgrade("");
    CHECK_FALSE(parsed.separator_found);
    CHECK(parsed.rows.empty());
}

TEST_CASE("winget upgrade: footer 'N upgrades available' line is skipped, not parsed as a row",
          "[software_actions]") {
    constexpr std::string_view out =
        "Name               Id                        Version      Available    Source\n"
        "-----------------------------------------------------------------------------\n"
        "Git                Git.Git                   2.40.0       2.42.0       winget\n"
        "1 upgrades available.\n";
    auto parsed = parse_winget_upgrade(out);
    REQUIRE(parsed.rows.size() == 1);
    CHECK(parsed.rows[0].name == "Git");
}

// ── Linux: apt list --upgradable ───────────────────────────────────────────

TEST_CASE("apt list --upgradable: real-format lines with from-version — reconstructed",
          "[software_actions]") {
    constexpr std::string_view out =
        "Listing...\n"
        "firefox/jammy-updates 118.0+build2-0ubuntu0.22.04.1 amd64 "
        "[upgradable from: 117.0+build1-0ubuntu0.22.04.1]\n"
        "vim/jammy-updates 2:8.2.3995-1ubuntu2.15 amd64 "
        "[upgradable from: 2:8.2.3995-1ubuntu2.14]\n";
    auto rows = parse_apt_list_upgradable(out);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].name == "firefox");
    CHECK(rows[0].new_version == "118.0+build2-0ubuntu0.22.04.1");
    CHECK(rows[0].old_version == "117.0+build1-0ubuntu0.22.04.1");
    CHECK(rows[1].name == "vim");
    CHECK(rows[1].new_version == "2:8.2.3995-1ubuntu2.15");
    CHECK(rows[1].old_version == "2:8.2.3995-1ubuntu2.14");
}

TEST_CASE("apt list --upgradable: 'Listing...' banner and empty output produce zero rows",
          "[software_actions]") {
    CHECK(parse_apt_list_upgradable("Listing...\n").empty());
    CHECK(parse_apt_list_upgradable("").empty());
}

// ── Linux: yum/dnf check-update ────────────────────────────────────────────

TEST_CASE("yum check-update: real-format lines with banner lines skipped — reconstructed",
          "[software_actions]") {
    constexpr std::string_view out = "Loaded plugins: fastestmirror\n"
                                     "Loading mirror speeds from cached hostfile\n"
                                     "Last metadata expiration check: 0:12:34 ago.\n"
                                     "\n"
                                     "bash.x86_64                    4.4.20-4.el8               baseos\n"
                                     "kernel.x86_64                  4.18.0-425.19.2.el8_7       baseos\n";
    auto rows = parse_yum_checkupdate(out);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].name == "bash.x86_64");
    CHECK(rows[0].new_version == "4.4.20-4.el8");
    CHECK(rows[1].name == "kernel.x86_64");
    CHECK(rows[1].new_version == "4.18.0-425.19.2.el8_7");
}

TEST_CASE("yum check-update: exit-code decision — 0 and 100 are BOTH success, others are not",
          "[software_actions]") {
    // 0 = ran, nothing to update; 100 = ran, updates ARE available (a
    // "success with data" exit code the old popen-based code implicitly
    // tolerated by never checking the exit code at all — the migration must
    // not regress into treating 100 as a failure).
    CHECK(yum_checkupdate_is_success(0));
    CHECK(yum_checkupdate_is_success(100));
    CHECK_FALSE(yum_checkupdate_is_success(1));
    CHECK_FALSE(yum_checkupdate_is_success(-1));
    CHECK_FALSE(yum_checkupdate_is_success(127));
}

// ── macOS: softwareupdate -l ────────────────────────────────────────────────

TEST_CASE("softwareupdate -l: one pending update — REAL capture from this host",
          "[software_actions]") {
    // Verbatim `/usr/sbin/softwareupdate -l` stdout, this macOS host,
    // 2026-08-24 (rc=0, stderr empty on this run).
    constexpr std::string_view out =
        "Software Update Tool\n"
        "\n"
        "Finding available software\n"
        "Software Update found the following new or updated software:\n"
        "* Label: macOS Tahoe 26.6.2-25G83\n"
        "\tTitle: macOS Tahoe 26.6.2, Version: 26.6.2, Size: 3833693KiB, Recommended: YES, "
        "Action: restart, \n";
    auto labels = parse_softwareupdate_list(out);
    REQUIRE(labels.size() == 1);
    CHECK(labels[0] == "macOS Tahoe 26.6.2-25G83");
}

TEST_CASE("softwareupdate -l: no updates available — reconstructed from documented format",
          "[software_actions]") {
    constexpr std::string_view out = "Software Update Tool\n"
                                     "\n"
                                     "No new software available.\n";
    CHECK(parse_softwareupdate_list(out).empty());
}

// ── Linux: dpkg-query status-abbrev / generic line counts ─────────────────

TEST_CASE("dpkg status-abbrev count: 2nd char 'i' counts, others (rc/un) don't",
          "[software_actions]") {
    constexpr std::string_view out = "ii\nhi\nrc\nun\nii\n";
    CHECK(count_dpkg_status_abbrev_installed(out) == 3);
}

TEST_CASE("dpkg status-abbrev count: empty output is zero, never fabricated",
          "[software_actions]") {
    CHECK(count_dpkg_status_abbrev_installed("") == 0);
}

TEST_CASE("generic nonempty-line count (rpm -qa / pkgutil --pkgs)", "[software_actions]") {
    CHECK(count_nonempty_lines("pkg.one\npkg.two\npkg.three\n") == 3);
    CHECK(count_nonempty_lines("") == 0);
    // A single trailing blank line must not be counted as a record.
    CHECK(count_nonempty_lines("pkg.one\n\n") == 1);
}
