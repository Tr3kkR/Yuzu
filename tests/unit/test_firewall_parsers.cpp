/**
 * test_firewall_parsers.cpp — pure firewall parse helpers
 * (firewall_parsers.hpp, macOS parity 1.1).
 *
 * The popen shell-outs are the impure shell; the decision-shaped parsing of
 * `socketfilterfw --getglobalstate` and `pfctl -s info` output is header-pure
 * and pinned here on every host (the netprobe_stats.hpp pattern). Fixture
 * strings marked "real capture" were taken verbatim from a macOS 26 host.
 */

#include "firewall_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::firewall;

TEST_CASE("alf: disabled (State = 0) — real capture", "[firewall]") {
    auto r = parse_alf_global_state("Firewall is disabled. (State = 0)");
    CHECK(r.state == FwState::disabled);
    CHECK_FALSE(r.block_all);
}

TEST_CASE("alf: enabled (State = 1)", "[firewall]") {
    auto r = parse_alf_global_state("Firewall is enabled. (State = 1)");
    CHECK(r.state == FwState::enabled);
    CHECK_FALSE(r.block_all);
}

TEST_CASE("alf: block-all (State = 2)", "[firewall]") {
    auto r = parse_alf_global_state("Firewall is enabled. (State = 2)");
    CHECK(r.state == FwState::enabled);
    CHECK(r.block_all);
}

TEST_CASE("alf: the state number outranks drifted prose", "[firewall]") {
    // If a future macOS rewords the sentence, the "(State = N)" clause must
    // still decide — even when the prose says the opposite.
    auto r = parse_alf_global_state(
        "Firewall is set to block all incoming connections. (State = 2)");
    CHECK(r.state == FwState::enabled);
    CHECK(r.block_all);

    auto contradictory = parse_alf_global_state("Firewall is enabled. (State = 0)");
    CHECK(contradictory.state == FwState::disabled);
}

TEST_CASE("alf: prose fallback when the state clause is absent", "[firewall]") {
    CHECK(parse_alf_global_state("Firewall is enabled.").state == FwState::enabled);
    CHECK(parse_alf_global_state("Firewall is disabled.").state == FwState::disabled);
    // Both words present → "disabled" wins (bias toward the answer that draws
    // an admin's attention, never toward false assurance).
    CHECK(parse_alf_global_state("enabled then disabled").state == FwState::disabled);
}

TEST_CASE("alf: unrecognised state number falls back to prose", "[firewall]") {
    CHECK(parse_alf_global_state("Firewall is enabled. (State = 7)").state ==
          FwState::enabled);
    CHECK(parse_alf_global_state("Mystery text. (State = 7)").state == FwState::unknown);
}

TEST_CASE("alf: truncated clause at end of output is not read past", "[firewall]") {
    CHECK(parse_alf_global_state("Firewall is enabled. (State = ").state ==
          FwState::enabled); // prose fallback, no out-of-range read
}

TEST_CASE("alf: empty and garbage output are unknown, never false-safe", "[firewall]") {
    CHECK(parse_alf_global_state("").state == FwState::unknown);
    CHECK(parse_alf_global_state(
              "sh: /usr/libexec/ApplicationFirewall/socketfilterfw: "
              "No such file or directory")
              .state == FwState::unknown);
}

TEST_CASE("pf: enabled and disabled status lines", "[firewall]") {
    CHECK(parse_pf_status("Status: Enabled for 0 days 00:00:15           Debug: Urgent") ==
          FwState::enabled);
    CHECK(parse_pf_status("Status: Disabled for 0 days 00:01:02          Debug: Urgent") ==
          FwState::disabled);
}

TEST_CASE("pf: empty or error output is unknown — real non-root capture", "[firewall]") {
    // Non-root read: pfctl prints "pfctl: /dev/pf: Permission denied" on
    // stderr and nothing on stdout; the plugin discards stderr, so the parser
    // sees "". If anyone ever flips the shell-out to 2>&1, the error text
    // itself must still parse to unknown.
    CHECK(parse_pf_status("") == FwState::unknown);
    CHECK(parse_pf_status("pfctl: /dev/pf: Permission denied") == FwState::unknown);
}

TEST_CASE("fw state to_string round-trip", "[firewall]") {
    CHECK(to_string(FwState::enabled) == "enabled");
    CHECK(to_string(FwState::disabled) == "disabled");
    CHECK(to_string(FwState::unknown) == "unknown");
}
