/**
 * test_antivirus_parsers.cpp — pure antivirus parse helpers
 * (antivirus_parsers.hpp, macOS parity 1.2).
 *
 * The popen shell-outs are the impure shell; the decision-shaped parsing of
 * PlistBuddy version output and `systemextensionsctl list` is header-pure and
 * pinned here on every host (the firewall_parsers.hpp pattern). Fixture
 * strings marked "real capture" were taken verbatim from a macOS 26 host;
 * older macOS releases are not yet fixture-verified — capture and add when
 * such hardware is available.
 */

#include "antivirus_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::antivirus;

TEST_CASE("plist version: real captures parse verbatim", "[antivirus]") {
    CHECK(parse_plist_version("5351") == "5351");   // XProtect.bundle (real capture)
    CHECK(parse_plist_version("157") == "157");     // XProtect.app Remediator (real capture)
    CHECK(parse_plist_version("1.93") == "1.93");   // MRT.app (real capture)
    CHECK(parse_plist_version("5351\n") == "5351"); // pre-strip newline tolerated
}

TEST_CASE("plist version: error prose and garbage are rejected", "[antivirus]") {
    CHECK(parse_plist_version("").empty());
    CHECK(parse_plist_version(
              R"(Print: Entry, ":CFBundleShortVersionString", Does Not Exist)")
              .empty());
    CHECK(parse_plist_version("File Doesn't Exist, Will Create: /nope").empty());
    CHECK(parse_plist_version("sh: /usr/libexec/PlistBuddy: No such file or directory").empty());
}

// Real capture, this Mac (Tailscale network extension; note the literal tabs).
static constexpr const char* kRealSysextList =
    "1 extension(s)\n"
    "--- com.apple.system_extension.network_extension (Go to 'System Settings > General > "
    "Login Items & Extensions > Network Extensions' to modify these system extension(s))\n"
    "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
    "*\t*\tW5364U7YZB\tio.tailscale.ipn.macsys.network-extension (1.98.5/101.98.5)\tTailscale "
    "Network Extension\t[activated enabled]\n";

TEST_CASE("sysext: real capture parses fully", "[antivirus]") {
    auto exts = parse_sysext_list(kRealSysextList);
    REQUIRE(exts.size() == 1);
    const auto& e = exts[0];
    CHECK(e.category == "network_extension");
    CHECK(e.team_id == "W5364U7YZB");
    CHECK(e.bundle_id == "io.tailscale.ipn.macsys.network-extension");
    CHECK(e.version == "1.98.5/101.98.5");
    CHECK(e.name == "Tailscale Network Extension");
    CHECK(e.state == "activated enabled");
    CHECK(e.enabled);
    CHECK(e.active);
    CHECK_FALSE(is_endpoint_security(e));
}

// Synthetic but format-faithful endpoint-security section (EDR shape).
static constexpr const char* kEdrSysextList =
    "2 extension(s)\n"
    "--- com.apple.system_extension.endpoint_security\n"
    "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
    "*\t*\tX9E956P446\tcom.crowdstrike.falcon.Agent (7.16.0/507.16.0)\tCrowdStrike Falcon\t"
    "[activated enabled]\n"
    "\t\t2107VB2A4L\tcom.sophos.endpoint.scanextension (10.7.8/1)\tSophos Scan Extension\t"
    "[activated waiting for user]\n";

TEST_CASE("sysext: endpoint-security section, enabled and pending rows", "[antivirus]") {
    auto exts = parse_sysext_list(kEdrSysextList);
    REQUIRE(exts.size() == 2);

    CHECK(is_endpoint_security(exts[0]));
    CHECK(exts[0].bundle_id == "com.crowdstrike.falcon.Agent");
    CHECK(exts[0].version == "7.16.0/507.16.0");
    CHECK(exts[0].name == "CrowdStrike Falcon");
    CHECK(sysext_av_state(exts[0]) == "active");

    // Not enabled/active (empty leading cells) → present but not protecting.
    CHECK(is_endpoint_security(exts[1]));
    CHECK_FALSE(exts[1].enabled);
    CHECK_FALSE(exts[1].active);
    CHECK(exts[1].state == "activated waiting for user");
    CHECK(sysext_av_state(exts[1]) == "installed");
}

TEST_CASE("sysext: empty, none, and garbage inputs yield no rows", "[antivirus]") {
    CHECK(parse_sysext_list("").empty());
    CHECK(parse_sysext_list("0 extension(s)\n").empty());
    CHECK(parse_sysext_list("sh: systemextensionsctl: command not found").empty());
}

TEST_CASE("sysext: malformed rows are skipped without throwing", "[antivirus]") {
    // Too few columns, header-only, stray tabs — none may produce a row.
    auto exts = parse_sysext_list("--- com.apple.system_extension.endpoint_security\n"
                                  "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
                                  "*\t*\tonly-three-cols\n"
                                  "\t\n");
    CHECK(exts.empty());
    // A bundle column without a version parenthesis keeps the whole token.
    auto no_ver = parse_sysext_list("--- com.apple.system_extension.endpoint_security\n"
                                    "*\t\tTEAM\tcom.vendor.thing\tVendor Thing\t[activated]\n");
    REQUIRE(no_ver.size() == 1);
    CHECK(no_ver[0].bundle_id == "com.vendor.thing");
    CHECK(no_ver[0].version.empty());
    CHECK(sysext_av_state(no_ver[0]) == "installed"); // enabled but not active
}

TEST_CASE("contains_insensitive: dedupe helper", "[antivirus]") {
    CHECK(contains_insensitive("CrowdStrike Falcon", "falcon"));
    CHECK(contains_insensitive("com.crowdstrike.falcon.Agent", "CROWDSTRIKE"));
    CHECK_FALSE(contains_insensitive("Sophos Scan Extension", "falcon"));
    CHECK(contains_insensitive("anything", ""));
    CHECK_FALSE(contains_insensitive("", "x"));
}
