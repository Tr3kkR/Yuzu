// The Decision-8 canonical sudo argv FORM is what the sudoers grants from
// scripts/install-agent-user.sh match — pinned here by test, not convention
// (ADR-3002 :443-464). sudo_argv.hpp is POSIX-only, so this whole TU is
// compiled out on the MSVC leg.
#ifndef _WIN32

#include <catch2/catch_test_macros.hpp>

#include <sudo_argv.hpp>

#include <string>
#include <vector>

using yuzu::shared::sudo_wrap;

TEST_CASE("sudo_wrap emits the canonical Decision-8 form", "[agent][sudo_argv]") {
    const std::vector<std::string> tool_argv{"/usr/sbin/iptables", "-L", "INPUT", "-n"};
    const auto argv = sudo_wrap(tool_argv, false);
    REQUIRE(argv.size() == tool_argv.size() + 3);
    CHECK(argv[0] == "/usr/bin/sudo");
    CHECK(argv[1] == "-n");
    CHECK(argv[2] == "--");
    CHECK(argv[3] == "/usr/sbin/iptables");
    CHECK(argv[4] == "-L");
    CHECK(argv[5] == "INPUT");
    CHECK(argv[6] == "-n");
}

TEST_CASE("sudo_wrap preserves the root skip-sudo conditional", "[agent][sudo_argv]") {
    const std::vector<std::string> tool_argv{"/sbin/pfctl", "-s", "rules"};
    const auto argv = sudo_wrap(tool_argv, true);
    REQUIRE(argv == tool_argv);
}

TEST_CASE("sudo_wrap wraps a bare tool with no arguments", "[agent][sudo_argv]") {
    const std::vector<std::string> tool_argv{"/usr/bin/dscacheutil", "-flushcache"};
    const auto argv = sudo_wrap(tool_argv, false);
    REQUIRE(argv.size() == tool_argv.size() + 3);
    CHECK(argv[3] == "/usr/bin/dscacheutil");
    CHECK(argv[4] == "-flushcache");
}

#endif // !_WIN32
