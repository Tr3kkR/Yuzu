// Pure-parser coverage for the services plugin's systemctl/launchctl
// enumeration output (Wave-2 PR2.2a, ADR-3002 acquisition-ladder migration).
// The functions live in agents/plugins/services/src/services_parsers.hpp and
// are reachable at runtime from services_plugin.cpp's enumerate_services_linux
// / enumerate_services_macos.
//
// Fixtures below are hand-constructed-but-format-accurate: built from the
// documented `systemctl list-units --no-legend` (UNIT LOAD ACTIVE SUB
// DESCRIPTION whitespace-separated columns) and `launchctl list`
// ("PID\tStatus\tLabel" header + tab-separated rows) column layouts, not a
// live capture from a running host.
#include "services_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <format>
#include <string>

using yuzu::services::is_safe_service_name;
using yuzu::services::kMaxServiceRows;
using yuzu::services::LaunchdListResult;
using yuzu::services::parse_launchctl_list;
using yuzu::services::parse_systemctl_list_units;
using yuzu::services::SystemdUnitEntry;

// ── parse_systemctl_list_units ───────────────────────────────────────────────

TEST_CASE("services: parse_systemctl_list_units parses a well-formed multi-row listing",
          "[services][linux]") {
    const std::string out =
        "cron.service                 loaded active   running Regular background program processing daemon\n"
        "ssh.service                  loaded active   running OpenBSD Secure Shell server\n"
        "bluetooth.service            loaded inactive dead    Bluetooth service\n";

    auto entries = parse_systemctl_list_units(out);
    REQUIRE(entries.size() == 3);

    CHECK(entries[0].name == "cron.service");
    CHECK(entries[0].status == "running");
    CHECK(entries[0].description == "Regular background program processing daemon");

    CHECK(entries[1].name == "ssh.service");
    CHECK(entries[1].status == "running");
    CHECK(entries[1].description == "OpenBSD Secure Shell server");

    CHECK(entries[2].name == "bluetooth.service");
    CHECK(entries[2].status == "dead");
    CHECK(entries[2].description == "Bluetooth service");
}

TEST_CASE("services: parse_systemctl_list_units tolerates CRLF line endings",
          "[services][linux]") {
    const std::string out = "cron.service loaded active running Regular cron\r\n"
                             "ssh.service  loaded active running OpenBSD SSH\r\n";
    auto entries = parse_systemctl_list_units(out);
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].name == "cron.service");
    CHECK(entries[1].name == "ssh.service");
}

TEST_CASE("services: parse_systemctl_list_units skips blank lines", "[services][linux]") {
    const std::string out = "\ncron.service loaded active running Regular cron\n\n\n"
                             "ssh.service  loaded active running OpenBSD SSH\n\n";
    auto entries = parse_systemctl_list_units(out);
    REQUIRE(entries.size() == 2);
}

TEST_CASE("services: parse_systemctl_list_units trims the leading failed-unit marker column",
          "[services][linux]") {
    // Pins the parser's existing " *" leading-character trim (inherited
    // unchanged from the pre-migration inline loop, not introduced by this
    // PR) so a leading marker column never gets folded into the UNIT field.
    const std::string out = "* apparmor.service loaded failed failed Load AppArmor profiles\n";
    auto entries = parse_systemctl_list_units(out);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].name == "apparmor.service");
    CHECK(entries[0].status == "failed");
}

TEST_CASE("services: parse_systemctl_list_units on empty input yields no entries",
          "[services][linux]") {
    CHECK(parse_systemctl_list_units("").empty());
}

TEST_CASE("services: parse_systemctl_list_units handles a unit with no trailing description",
          "[services][linux]") {
    const std::string out = "empty.service loaded active running\n";
    auto entries = parse_systemctl_list_units(out);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].name == "empty.service");
    CHECK(entries[0].status == "running");
    CHECK(entries[0].description.empty());
}

// ── parse_launchctl_list ──────────────────────────────────────────────────────

TEST_CASE("services: parse_launchctl_list skips the header row and parses the rest",
          "[services][macos]") {
    const std::string out = "PID\tStatus\tLabel\n"
                             "123\t0\tcom.apple.something\n"
                             "456\t-15\tcom.apple.crashy\n";
    auto result = parse_launchctl_list(out, /*running_only=*/false);
    REQUIRE(result.services.size() == 2);
    CHECK(result.total_seen == 2);

    CHECK(result.services[0].pid == "123");
    CHECK(result.services[0].status == "0");
    CHECK(result.services[0].label == "com.apple.something");

    CHECK(result.services[1].pid == "456");
    CHECK(result.services[1].status == "-15");
    CHECK(result.services[1].label == "com.apple.crashy");
}

TEST_CASE("services: parse_launchctl_list running_only drops pid=='-' rows",
          "[services][macos]") {
    const std::string out = "PID\tStatus\tLabel\n"
                             "123\t0\tcom.apple.running\n"
                             "-\t0\tcom.apple.notrunning\n";
    auto result = parse_launchctl_list(out, /*running_only=*/true);
    REQUIRE(result.services.size() == 1);
    CHECK(result.services[0].label == "com.apple.running");
    // The dropped-for-not-running row still passed the safety filter, so it
    // is honestly counted -- total_seen answers "how many qualifying rows
    // existed", not "how many made it into `services`".
    CHECK(result.total_seen == 1);
}

TEST_CASE("services: parse_launchctl_list drops an unsafe label before it reaches the result",
          "[services][macos]") {
    const std::string out = "PID\tStatus\tLabel\n"
                             "123\t0\tcom.apple.ok\n"
                             "456\t0\tcom.apple|evil\n"; // '|' would corrupt the pipe protocol
    auto result = parse_launchctl_list(out, /*running_only=*/false);
    REQUIRE(result.services.size() == 1);
    CHECK(result.services[0].label == "com.apple.ok");
    CHECK(result.total_seen == 1); // the unsafe row is never counted either
}

TEST_CASE("services: parse_launchctl_list honours a caller-supplied row_cap and still counts "
          "every qualifying row in total_seen",
          "[services][macos]") {
    std::string out = "PID\tStatus\tLabel\n";
    for (int i = 0; i < 5; ++i) {
        out += std::format("{}\t0\tcom.apple.svc{}\n", i + 1, i);
    }
    auto result = parse_launchctl_list(out, /*running_only=*/false, /*row_cap=*/2);
    CHECK(result.services.size() == 2);
    CHECK(result.total_seen == 5);
}

TEST_CASE("services: parse_launchctl_list defaults to kMaxServiceRows when no cap is given",
          "[services][macos]") {
    std::string out = "PID\tStatus\tLabel\n";
    for (std::size_t i = 0; i < kMaxServiceRows + 10; ++i) {
        out += std::format("{}\t0\tcom.apple.svc{}\n", i + 1, i);
    }
    auto result = parse_launchctl_list(out, /*running_only=*/false);
    CHECK(result.services.size() == kMaxServiceRows);
    CHECK(result.total_seen == kMaxServiceRows + 10);
}

TEST_CASE("services: parse_launchctl_list on empty/header-only input yields no entries",
          "[services][macos]") {
    CHECK(parse_launchctl_list("", false).services.empty());
    CHECK(parse_launchctl_list("PID\tStatus\tLabel\n", false).services.empty());
}

// ── is_safe_service_name ─────────────────────────────────────────────────────

TEST_CASE("services: is_safe_service_name accepts the documented character set",
          "[services]") {
    CHECK(is_safe_service_name("cron.service"));
    CHECK(is_safe_service_name("getty@tty1.service"));
    CHECK(is_safe_service_name("com.apple.something"));
    CHECK(is_safe_service_name("Some_Service-2"));
}

TEST_CASE("services: is_safe_service_name rejects the empty/oversized/unsafe-character cases",
          "[services]") {
    CHECK_FALSE(is_safe_service_name(""));
    CHECK_FALSE(is_safe_service_name(std::string(257, 'a'))); // over the 256 cap
    CHECK_FALSE(is_safe_service_name("evil|pipe"));
    CHECK_FALSE(is_safe_service_name("evil;rm -rf"));
    CHECK_FALSE(is_safe_service_name("has space"));
    CHECK_FALSE(is_safe_service_name("evil`backtick"));
}

TEST_CASE("services: is_safe_service_name permits a leading hyphen (argv callers must still "
          "separate it with an explicit \"--\")",
          "[services]") {
    // Documents the load-bearing NOTE in services_parsers.hpp: the allowlist
    // itself does not forbid a leading '-', so services_plugin.cpp's argv
    // construction is responsible for the "--" separator that keeps a name
    // like this from being parsed as a systemctl/launchctl flag.
    CHECK(is_safe_service_name("-foo"));
}
