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
 *   - the original (pre-`--plain`) systemctl rows below were captured
 *     2026-08-24 by running `systemctl list-units --type=service --all
 *     --no-pager --no-legend` inside a `jrei/systemd-ubuntu:latest` Docker
 *     container (booted with `--platform linux/amd64 --privileged`,
 *     QEMU-emulated on this arm64 development host, real systemd PID 1
 *     running under cgroupfs passthrough). The container's minimal/degraded
 *     boot produced real `not-found` (bullet-marked) and `failed`
 *     (bullet-marked) rows alongside ordinary `loaded`/`inactive`/`dead`
 *     ones -- all reproduced verbatim below, column spacing included. Kept
 *     as a defensive-tolerance fixture (see tar_service_parsers.hpp) even
 *     though the shipped argv no longer produces this ASCII-`*` shape.
 *
 *   - the `--plain` rows below were captured 2026-08-25 (BR-001 remediation)
 *     by running `systemctl list-units --type=service --all --plain
 *     --no-pager --no-legend` in a fresh `jrei/systemd-ubuntu:22.04`
 *     container (`--platform linux/amd64 --privileged --cgroupns=host`,
 *     QEMU-emulated), after installing and starting a deliberately-failing
 *     `yzfail.service` (`ExecStart=/bin/false`) to force a real `failed`
 *     row. This is the exact argv/output shape tar_service_collector.cpp
 *     now invokes -- no marker column at all, confirmed byte-for-byte via
 *     `od -c` under both a UTF-8 locale and the container's real default
 *     (`LC_ALL=C`) -- proving the argv change makes systemctl's row shape
 *     locale-independent rather than merely re-confirming the ASCII case.
 *
 *   - launchctl rows below were captured 2026-08-24 by running
 *     `launchctl list` directly on this macOS development host (arm64).
 *     Includes a real stopped ("-" pid) row, a running row, and a
 *     signal-killed row (status -9, com.apple.knowledgeconstructiond) as
 *     observed on this host at capture time.
 */

#include "tar_capture_status.hpp" // yuzu::tar::IncompleteCaptureError
#include "tar_collectors.hpp"     // yuzu::tar::{enumerate_services,enumerate_services_impl}
#include "tar_service_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>

#include <yuzu/agent/subprocess_runner.hpp>

using namespace yuzu::tar;

// ── parse_systemctl_list_units ──────────────────────────────────────────────

TEST_CASE("parse_systemctl_list_units: empty input yields empty output", "[tar_service]") {
    CHECK(parse_systemctl_list_units({}).entries.empty());
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

    auto services = parse_systemctl_list_units(lines).entries;
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

TEST_CASE("parse_systemctl_list_units: real --plain capture has no marker column, "
          "including on a genuinely failed unit",
          "[tar_service]") {
    // Real capture (see file header, BR-001) -- this is the exact argv shape
    // tar_service_collector.cpp now invokes. yzfail.service is a real
    // ExecStart=/bin/false unit that systemd reports failed; under the old
    // (non-`--plain`) argv on a UTF-8 stdout this row would have started
    // with the `●` glyph (e2 97 8f) instead of the unit name -- `--plain`
    // means there is no marker column to collide on at all, verified live.
    std::vector<std::string> lines = {
        "dbus.service                         loaded    inactive dead    D-Bus System Message Bus",
        "display-manager.service              not-found inactive dead    display-manager.service",
        "yzfail.service                       loaded    failed   failed  yzfail test unit",
    };

    auto services = parse_systemctl_list_units(lines).entries;
    REQUIRE(services.size() == 3);

    CHECK(services[0].name == "dbus.service");
    CHECK(services[0].status == "dead");

    // not-found: no marker column under --plain, unlike the pre-remediation
    // bullet-marked fixture above.
    CHECK(services[1].name == "display-manager.service");
    CHECK(services[1].status == "dead");

    // The real failed unit -- name and status parse correctly with no glyph
    // collision, the defect BR-001 closes.
    CHECK(services[2].name == "yzfail.service");
    CHECK(services[2].status == "failed");
    CHECK(services[2].display_name == "yzfail test unit");
}

// ── parse_launchctl_list ─────────────────────────────────────────────────────

TEST_CASE("parse_launchctl_list: empty input yields empty output", "[tar_service]") {
    CHECK(parse_launchctl_list({}).entries.empty());
}

TEST_CASE("parse_launchctl_list: header-only input yields empty output", "[tar_service]") {
    std::vector<std::string> lines = {"PID\tStatus\tLabel"};
    CHECK(parse_launchctl_list(lines).entries.empty());
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

    auto services = parse_launchctl_list(lines).entries;
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

// ── malformed-row detection (BR-service-001) ────────────────────────────────
//
// A malformed/truncated row must be DROPPED from `entries` and flag
// `malformed = true`, never pushed as a ServiceInfo carrying an
// empty/garbage name -- mirrors tar_arp_parsers.hpp's BR4-005 tests
// (test_tar_arp.cpp). These two rows are SYNTHETIC edge cases (a
// deliberately truncated/blank line no real systemctl/launchctl invocation
// produces under normal conditions) -- labeled here per the branch's
// fixture-provenance discipline, unlike the real-capture rows above.

TEST_CASE("parse_systemctl_list_units: a well-formed real capture is never "
          "flagged malformed",
          "[tar_service]") {
    // Regression guard for a false positive: re-run the real --plain
    // capture from the case above and assert `malformed` stays false so a
    // genuinely complete table is never misreported as incomplete.
    std::vector<std::string> lines = {
        "dbus.service                         loaded    inactive dead    D-Bus System Message Bus",
        "yzfail.service                       loaded    failed   failed  yzfail test unit",
    };
    auto result = parse_systemctl_list_units(lines);
    CHECK_FALSE(result.malformed);
    CHECK(result.entries.size() == 2);
}

TEST_CASE("parse_systemctl_list_units: a truncated row missing ACTIVE/SUB is "
          "dropped and flagged malformed, not silently included with a "
          "garbage empty status",
          "[tar_service]") {
    // Synthetic edge case: a row with only a UNIT token (LOAD/ACTIVE/SUB all
    // missing, e.g. a truncated read mid-row) -- the exact "malformed row
    // produces a ServiceInfo with an empty or garbage name/status" shape BUG
    // 1 describes. si.name comes back non-empty ("bad-row.service") but
    // si.status comes back "" once next_token() runs out of columns, which
    // is what the fix's malformed check catches.
    std::vector<std::string> lines = {
        "dbus.service                         loaded    inactive dead    D-Bus System Message Bus",
        "bad-row.service", // synthetic: truncated row, only the UNIT column present
        "yzfail.service                       loaded    failed   failed  yzfail test unit",
    };
    auto result = parse_systemctl_list_units(lines);
    CHECK(result.malformed);
    // The two well-formed rows around the malformed one still decode --
    // same defensive-tolerance shape as tar_arp_parsers.hpp's BR4-005.
    REQUIRE(result.entries.size() == 2);
    CHECK(result.entries[0].name == "dbus.service");
    CHECK(result.entries[1].name == "yzfail.service");
}

TEST_CASE("parse_launchctl_list: a well-formed real capture is never flagged "
          "malformed",
          "[tar_service]") {
    std::vector<std::string> lines = {
        "PID\tStatus\tLabel",
        "-\t0\tcom.apple.SafariHistoryServiceAgent",
        "1190\t0\tcom.apple.progressd",
    };
    auto result = parse_launchctl_list(lines);
    CHECK_FALSE(result.malformed);
    CHECK(result.entries.size() == 2);
}

TEST_CASE("parse_launchctl_list: a truncated row with an empty LABEL field is "
          "dropped and flagged malformed, not silently included",
          "[tar_service]") {
    // Synthetic edge case: a row with only PID + status code, no LABEL at
    // all (fewer than 3 tab-separated fields) -- next_field() returns "" for
    // the missing LABEL, which previously became a ServiceInfo with an
    // empty name pushed unconditionally.
    std::vector<std::string> lines = {
        "PID\tStatus\tLabel",
        "-\t0\tcom.apple.SafariHistoryServiceAgent",
        "1190\t0", // synthetic: truncated row, LABEL column missing
        "93175\t-9\tcom.apple.knowledgeconstructiond",
    };
    auto result = parse_launchctl_list(lines);
    CHECK(result.malformed);
    REQUIRE(result.entries.size() == 2);
    CHECK(result.entries[0].name == "com.apple.SafariHistoryServiceAgent");
    CHECK(result.entries[1].name == "com.apple.knowledgeconstructiond");
}

// ── enumerate_services_impl: runner-migration call-site coverage (Finding 3) ──
//
// Everything above exercises only the pure parsers. Nothing previously
// called enumerate_services()/enumerate_services_impl() itself, so a
// regression to the old popen body, a dropped --plain flag, or a wrong argv
// would still have passed every test in this file. enumerate_services_impl
// (tar_collectors.hpp/tar_service_collector.cpp) takes the subprocess runner
// as an injectable parameter for exactly this reason: these tests inject a
// fixture double that records the exact argv/options it was called with and
// returns a caller-controlled SubprocessResult, then call the REAL
// enumerate_services_impl (not a hand-simulated stand-in) so probe_tool_path,
// argv construction, classify_subprocess_capture, and the
// IncompleteCaptureError throw are all genuinely exercised. macOS only here
// (launchctl leg) -- this is the platform this test binary actually links
// and runs on (tests/meson.build now compiles tar_service_collector.cpp into
// yuzu_tar_tests). The Linux leg (systemctl, --plain) is compile-checked
// only on macOS via the #elif __linux__ guard in tar_service_collector.cpp
// -- it is not compiled into this binary at all on this host, so a Linux
// leg regression can only be caught on Linux CI; still exercised for real
// there via the same enumerate_services_impl seam.

#ifdef __APPLE__

TEST_CASE("enumerate_services_impl (macOS/launchctl leg): invokes the exact "
          "argv/options and returns the real parsed rows on a successful run",
          "[tar_service][enumerate]") {
    std::vector<std::string> captured_argv;
    yuzu::agent::SubprocessOptions captured_opts;
    auto fake_run = [&](const std::vector<std::string>& argv,
                        const yuzu::agent::SubprocessOptions& opts) {
        captured_argv = argv;
        captured_opts = opts;
        yuzu::agent::SubprocessResult res;
        res.tool_ran = true;
        res.exit_code = 0;
        res.lines = {
            "PID\tStatus\tLabel",
            "-\t0\tcom.apple.SafariHistoryServiceAgent",
            "1190\t0\tcom.apple.progressd",
        };
        return res;
    };

    auto services = enumerate_services_impl(fake_run);

    // Exact argv: launchctl at its one real absolute path, "list", no other
    // args -- a regression that drops/adds an argument, or reintroduces a
    // shell hop (`/bin/sh -c ...`), changes this.
    REQUIRE(captured_argv.size() == 2);
    CHECK(captured_argv[0] == "/bin/launchctl");
    CHECK(captured_argv[1] == "list");
    CHECK(captured_opts.deadline == std::chrono::seconds{10});

    REQUIRE(services.size() == 2);
    CHECK(services[0].name == "com.apple.SafariHistoryServiceAgent");
    CHECK(services[0].status == "stopped");
    CHECK(services[1].name == "com.apple.progressd");
    CHECK(services[1].status == "running");
}

TEST_CASE("enumerate_services_impl (macOS/launchctl leg): a spawn failure "
          "throws IncompleteCaptureError through the real collector entry point",
          "[tar_service][enumerate]") {
    auto fake_run = [](const std::vector<std::string>&, const yuzu::agent::SubprocessOptions&) {
        yuzu::agent::SubprocessResult res;
        res.tool_ran = false; // exec itself failed
        return res;
    };
    REQUIRE_THROWS_AS(enumerate_services_impl(fake_run), yuzu::tar::IncompleteCaptureError);
}

TEST_CASE("enumerate_services_impl (macOS/launchctl leg): a deadline timeout "
          "throws IncompleteCaptureError through the real collector entry point",
          "[tar_service][enumerate]") {
    auto fake_run = [](const std::vector<std::string>&, const yuzu::agent::SubprocessOptions&) {
        yuzu::agent::SubprocessResult res;
        res.tool_ran = true;
        res.timed_out = true;
        res.exit_code = -1;
        return res;
    };
    REQUIRE_THROWS_AS(enumerate_services_impl(fake_run), yuzu::tar::IncompleteCaptureError);
}

TEST_CASE("enumerate_services_impl (macOS/launchctl leg): an output-cap "
          "truncation throws IncompleteCaptureError through the real "
          "collector entry point",
          "[tar_service][enumerate]") {
    auto fake_run = [](const std::vector<std::string>&, const yuzu::agent::SubprocessOptions&) {
        yuzu::agent::SubprocessResult res;
        res.tool_ran = true;
        res.exit_code = 0;
        res.output_truncated = true;
        res.lines = {"PID\tStatus\tLabel", "1190\t0\tcom.apple.progressd"};
        return res;
    };
    REQUIRE_THROWS_AS(enumerate_services_impl(fake_run), yuzu::tar::IncompleteCaptureError);
}

TEST_CASE("enumerate_services_impl (macOS/launchctl leg): a non-zero exit "
          "throws IncompleteCaptureError through the real collector entry point",
          "[tar_service][enumerate]") {
    auto fake_run = [](const std::vector<std::string>&, const yuzu::agent::SubprocessOptions&) {
        yuzu::agent::SubprocessResult res;
        res.tool_ran = true;
        res.exit_code = 1;
        res.lines = {"PID\tStatus\tLabel", "1190\t0\tcom.apple.progressd"};
        return res;
    };
    REQUIRE_THROWS_AS(enumerate_services_impl(fake_run), yuzu::tar::IncompleteCaptureError);
}

TEST_CASE("enumerate_services: the real production entry point runs against "
          "the live host without throwing",
          "[tar_service][enumerate][live]") {
    // The real production wiring (enumerate_services() -> enumerate_services_impl
    // with the real run_bounded_subprocess) actually invoking real launchctl
    // on this host -- proves the seam's default argument is genuinely wired,
    // not just the injectable path.
    REQUIRE_NOTHROW(enumerate_services());
}

#endif // __APPLE__
