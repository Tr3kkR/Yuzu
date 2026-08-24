/**
 * test_tar_service.cpp -- fixture-fed tests for tar_service_parsers.hpp
 * (parse_systemctl_list_units / parse_launchctl_list), the pure parsers
 * extracted from tar_service_collector.cpp's runner-migrated Linux/macOS
 * legs. No test here spawns a process or sleeps -- every case feeds a
 * fixed std::vector<std::string> straight to the pure parser, exactly the
 * shape SubprocessResult::lines hands the collector at runtime (blank
 * lines already dropped, a trailing '\r' already stripped).
 *
 * Fixture provenance (binding rule: fixtures must come from real captures,
 * never invented output shapes):
 *
 *   - systemctl rows below were captured 2026-08-24 by running
 *     `systemctl list-units --type=service --all --no-pager --no-legend`
 *     inside a `jrei/systemd-ubuntu:latest` Docker container (booted with
 *     `--platform linux/amd64 --privileged`, QEMU-emulated on this arm64
 *     development host, real systemd PID 1 running under cgroupfs
 *     passthrough). The container's minimal/degraded boot produced real
 *     `not-found` (bullet-marked) and `failed` (bullet-marked) rows
 *     alongside ordinary `loaded`/`inactive`/`dead` ones -- all reproduced
 *     verbatim below, column spacing included.
 *
 *   - launchctl rows below were captured 2026-08-24 by running
 *     `launchctl list` directly on this macOS development host (arm64).
 *     Includes a real stopped ("-" pid) row, a running row, and a
 *     signal-killed row (status -9, com.apple.knowledgeconstructiond) as
 *     observed on this host at capture time.
 */

#include "tar_service_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::tar;

// ── parse_systemctl_list_units ──────────────────────────────────────────────

TEST_CASE("parse_systemctl_list_units: empty input yields empty output", "[tar_service]") {
    CHECK(parse_systemctl_list_units({}).empty());
}

TEST_CASE("parse_systemctl_list_units: real systemd-ubuntu container capture",
          "[tar_service]") {
    // Real capture (see file header) -- ordinary loaded/inactive rows, a
    // bullet-marked not-found row, a bullet-marked failed row, and a
    // systemd @-template unit name.
    std::vector<std::string> lines = {
        "  dbus.service                             loaded    inactive dead   D-Bus System Message Bus",
        "* display-manager.service                  not-found inactive dead   display-manager.service",
        "  modprobe@dm_mod.service                  loaded    inactive dead   Load Kernel Module dm_mod",
        "* systemd-remount-fs.service               loaded    failed   failed Remount Root and Kernel File Systems",
        "  systemd-journald.service                 loaded    inactive dead   Journal Service",
    };

    auto services = parse_systemctl_list_units(lines);
    REQUIRE(services.size() == 5);

    CHECK(services[0].name == "dbus.service");
    CHECK(services[0].status == "dead"); // SUB column
    CHECK(services[0].display_name == "D-Bus System Message Bus");
    CHECK(services[0].startup_type == "unknown");

    // Bullet-marked (systemctl's failed-unit marker) row -- the bullet and
    // its following space are both trimmed before the UNIT column is read,
    // same as an unmarked row.
    CHECK(services[1].name == "display-manager.service");
    CHECK(services[1].status == "dead");
    CHECK(services[1].display_name == "display-manager.service");

    // systemd template-instance unit name (the '@' syntax) survives untouched.
    CHECK(services[2].name == "modprobe@dm_mod.service");

    CHECK(services[3].name == "systemd-remount-fs.service");
    CHECK(services[3].status == "failed");
    CHECK(services[3].display_name == "Remount Root and Kernel File Systems");

    CHECK(services[4].name == "systemd-journald.service");
    CHECK(services[4].display_name == "Journal Service");
}

TEST_CASE("parse_systemctl_list_units: whitespace-only line is skipped, not counted",
          "[tar_service]") {
    std::vector<std::string> lines = {"   ", "  dbus.service  loaded  inactive dead  D-Bus"};
    auto services = parse_systemctl_list_units(lines);
    REQUIRE(services.size() == 1);
    CHECK(services[0].name == "dbus.service");
}

TEST_CASE("parse_systemctl_list_units: short line with no description still parses UNIT/SUB",
          "[tar_service]") {
    std::vector<std::string> lines = {"foo.service loaded active running"};
    auto services = parse_systemctl_list_units(lines);
    REQUIRE(services.size() == 1);
    CHECK(services[0].name == "foo.service");
    CHECK(services[0].status == "running");
    CHECK(services[0].display_name.empty());
}

// ── parse_launchctl_list ─────────────────────────────────────────────────────

TEST_CASE("parse_launchctl_list: empty input yields empty output", "[tar_service]") {
    CHECK(parse_launchctl_list({}).empty());
}

TEST_CASE("parse_launchctl_list: header-only input yields empty output", "[tar_service]") {
    std::vector<std::string> lines = {"PID\tStatus\tLabel"};
    CHECK(parse_launchctl_list(lines).empty());
}

TEST_CASE("parse_launchctl_list: real macOS host capture", "[tar_service]") {
    // Real capture (see file header) -- header row (always skipped), a
    // stopped ("-" pid) row, a running row, and a signal-killed status row.
    std::vector<std::string> lines = {
        "PID\tStatus\tLabel",
        "-\t0\tcom.apple.SafariHistoryServiceAgent",
        "1190\t0\tcom.apple.progressd",
        "93175\t-9\tcom.apple.knowledgeconstructiond",
    };

    auto services = parse_launchctl_list(lines);
    REQUIRE(services.size() == 3);

    CHECK(services[0].name == "com.apple.SafariHistoryServiceAgent");
    CHECK(services[0].status == "stopped");
    CHECK(services[0].startup_type == "unknown");

    CHECK(services[1].name == "com.apple.progressd");
    CHECK(services[1].status == "running");

    // A negative (signal-killed) status code still carries a non-"-" pid,
    // so it counts as running -- matches the original inline check, which
    // only ever tested the pid field, never the status-code field.
    CHECK(services[2].name == "com.apple.knowledgeconstructiond");
    CHECK(services[2].status == "running");
}

TEST_CASE("parse_launchctl_list: short row (missing label field) degrades to an empty name",
          "[tar_service]") {
    std::vector<std::string> lines = {"PID\tStatus\tLabel", "-\t0"};
    auto services = parse_launchctl_list(lines);
    REQUIRE(services.size() == 1);
    CHECK(services[0].name.empty());
    CHECK(services[0].status == "stopped");
}
