/**
 * test_firewall_parsers.cpp — pure firewall parse helpers
 * (firewall_parsers.hpp, macOS parity 1.1).
 *
 * The popen shell-outs are the impure shell; the decision-shaped parsing of
 * `socketfilterfw --getglobalstate` and `pfctl -s info` output is header-pure
 * and pinned here on every host (the netprobe_stats.hpp pattern). Fixture
 * strings marked "real capture" were taken verbatim from a macOS 26 host;
 * older macOS releases are not yet fixture-verified — capture and add when
 * such hardware is available.
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

TEST_CASE("alf: multi-digit or negative state numbers are unrecognised", "[firewall]") {
    // "(State = 10)" must not be misread as State 1 — the clause is
    // unrecognised and the prose decides instead.
    CHECK(parse_alf_global_state("Firewall is enabled. (State = 10)").state ==
          FwState::enabled); // via prose fallback, not the '1'
    auto r = parse_alf_global_state("Mystery text. (State = 10)");
    CHECK(r.state == FwState::unknown);
    CHECK_FALSE(r.block_all);
    CHECK(parse_alf_global_state("Mystery text. (State = -1)").state == FwState::unknown);
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

// ── Linux: ufw ───────────────────────────────────────────────────────────
//
// Synthetic fixtures matching documented `ufw` output (no live-captured ufw
// output was available in this sandbox — flagged here, not silently assumed
// verified).

TEST_CASE("ufw status: enabled/disabled — the real regression this replaces", "[firewall]") {
    // The bug this parser fixes: the old shell-out did
    // `output.find("active") != npos`, which ALSO matches inside "inactive"
    // -- misreporting a disabled ufw as active. A full-prefix check must
    // never let "Status: inactive" satisfy the active branch.
    CHECK(parse_ufw_status("Status: active\n") == FwState::enabled);
    CHECK(parse_ufw_status("Status: inactive\n") == FwState::disabled);
}

TEST_CASE("ufw status: empty or unrecognised output is unknown", "[firewall]") {
    CHECK(parse_ufw_status("") == FwState::unknown);
    CHECK(parse_ufw_status("sh: ufw: command not found") == FwState::unknown);
}

TEST_CASE("ufw rules: numbered status parses To/Action/From columns — synthetic", "[firewall]") {
    constexpr std::string_view out =
        "Status: active\n"
        "\n"
        "     To                         Action      From\n"
        "     --                         ------      ----\n"
        "[ 1] 22/tcp                     ALLOW IN    Anywhere\n"
        "[ 2] 80,443/tcp                 ALLOW IN    192.168.1.0/24\n";
    auto rules = parse_ufw_rules(out);
    REQUIRE(rules.size() == 2);
    CHECK(rules[0].index == "1");
    CHECK(rules[0].to == "22/tcp");
    CHECK(rules[0].action == "ALLOW IN");
    CHECK(rules[0].from == "Anywhere");
    CHECK(rules[1].index == "2");
    CHECK(rules[1].to == "80,443/tcp");
    CHECK(rules[1].action == "ALLOW IN");
    CHECK(rules[1].from == "192.168.1.0/24");
}

TEST_CASE("ufw rules: inactive ufw with zero numbered rows", "[firewall]") {
    CHECK(parse_ufw_rules("Status: inactive\n").empty());
}

TEST_CASE("ufw rules: malformed bracket line is skipped, not crashed on", "[firewall]") {
    CHECK(parse_ufw_rules("[unterminated bracket with no close\n").empty());
}

// ── Linux: iptables ─────────────────────────────────────────────────────
//
// Real capture: `iptables -S` inside a privileged Docker debian:bookworm-slim
// container with seed rules (NET_ADMIN,NET_RAW), 2026-08-14 — see
// ~/.claude/wave2-prestage/fixtures/linux/iptables_capture.out.

TEST_CASE("iptables -S: real capture — policies, new chain, appends", "[firewall]") {
    constexpr std::string_view out = "-P INPUT ACCEPT\n"
                                     "-P FORWARD ACCEPT\n"
                                     "-P OUTPUT ACCEPT\n"
                                     "-N yuzu-quarantine\n"
                                     "-A INPUT -j yuzu-quarantine\n"
                                     "-A yuzu-quarantine -i lo -j ACCEPT\n"
                                     "-A yuzu-quarantine -m state --state RELATED,ESTABLISHED -j ACCEPT\n"
                                     "-A yuzu-quarantine -s 10.0.0.5/32 -j ACCEPT\n"
                                     "-A yuzu-quarantine -j DROP\n";
    auto rules = parse_iptables_save(out);
    REQUIRE(rules.size() == 9);

    CHECK(rules[0].type == IptablesEntryType::policy);
    CHECK(rules[0].chain == "INPUT");
    CHECK(rules[0].spec == "ACCEPT");
    CHECK(rules[2].type == IptablesEntryType::policy);
    CHECK(rules[2].chain == "OUTPUT");
    CHECK(rules[2].spec == "ACCEPT");

    CHECK(rules[3].type == IptablesEntryType::new_chain);
    CHECK(rules[3].chain == "yuzu-quarantine");
    CHECK(rules[3].spec.empty());

    CHECK(rules[4].type == IptablesEntryType::append);
    CHECK(rules[4].chain == "INPUT");
    CHECK(rules[4].spec == "-j yuzu-quarantine");

    CHECK(rules[6].type == IptablesEntryType::append);
    CHECK(rules[6].chain == "yuzu-quarantine");
    CHECK(rules[6].spec == "-m state --state RELATED,ESTABLISHED -j ACCEPT");

    CHECK(rules[8].type == IptablesEntryType::append);
    CHECK(rules[8].chain == "yuzu-quarantine");
    CHECK(rules[8].spec == "-j DROP");
}

TEST_CASE("iptables -S: unrecognised line preserved, not dropped", "[firewall]") {
    auto rules = parse_iptables_save("-X some-chain\n");
    REQUIRE(rules.size() == 1);
    CHECK(rules[0].type == IptablesEntryType::unknown);
    CHECK(rules[0].spec == "-X some-chain");
}

TEST_CASE("iptables -S: empty output yields zero rules, never fabricated", "[firewall]") {
    CHECK(parse_iptables_save("").empty());
}
