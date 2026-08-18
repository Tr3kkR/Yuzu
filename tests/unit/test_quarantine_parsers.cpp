/**
 * test_quarantine_parsers.cpp — netsh/iptables/pfctl status-read parsing
 * (quarantine_parsers.hpp, Wave-2 ADR-3002 migration, quarantine package).
 *
 * Portable and unguarded — all six functions under test are pure text
 * handling (no I/O, no platform dependency), so this TU carries no platform
 * guard and runs on every leg, including a macOS-only CI runner exercising
 * the Windows/Linux parse rules it can never spawn netsh/iptables to
 * produce output for directly.
 *
 * NOT wired into tests/meson.build by this PR — the integrating senior adds
 * the target alongside the other Wave-2 quarantine wiring.
 *
 * Fixtures are hand-constructed (no live Windows/Linux host available this
 * session) but format-accurate to each tool's real captured output, based
 * on the exact strings quarantine_plugin.cpp's pre-migration code wrote and
 * grepped for.
 */
#include "quarantine_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::quarantine;

// ── is_safe_ip ───────────────────────────────────────────────────────────

TEST_CASE("is_safe_ip accepts IPv4 and IPv6 literals, rejects everything else",
         "[agent][quarantine_parsers]") {
    CHECK(is_safe_ip("10.0.0.5"));
    CHECK(is_safe_ip("::1"));
    CHECK(is_safe_ip("fe80::1"));
    CHECK_FALSE(is_safe_ip(""));
    CHECK_FALSE(is_safe_ip("10.0.0.5; rm -rf /"));
    CHECK_FALSE(is_safe_ip(std::string(46, '1'))); // over the 45-char cap
}

// ── netsh ────────────────────────────────────────────────────────────────

TEST_CASE("netsh_rules_present / netsh_matching_rule_names / netsh_whitelist_ips "
         "parse a realistic `netsh advfirewall firewall show rule` capture",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kCapture = R"(
Rule Name:                           YuzuQuarantine_BlockAllInbound
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             Any
Protocol:                             Any
Action:                               Block


Rule Name:                           YuzuQuarantine_AllowLoopbackIn
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             127.0.0.1
Protocol:                             Any
Action:                               Allow


Rule Name:                           YuzuQuarantine_AllowIn_10.0.0.5
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Profiles:                             Domain,Private,Public
Grouping:
LocalIP:                              Any
RemoteIP:                             10.0.0.5/32
Protocol:                             Any
Action:                               Allow


Rule Name:                           SomeOtherRule
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
RemoteIP:                             8.8.8.8
Action:                               Allow

Ok.
)";

    CHECK(netsh_rules_present(kCapture));

    auto names = netsh_matching_rule_names(kCapture);
    REQUIRE(names.size() == 3);
    CHECK(names[0] == "YuzuQuarantine_BlockAllInbound");
    CHECK(names[1] == "YuzuQuarantine_AllowLoopbackIn");
    CHECK(names[2] == "YuzuQuarantine_AllowIn_10.0.0.5");
    // The non-Yuzu rule must never appear in the delete list.
    for (const auto& n : names)
        CHECK(n != "SomeOtherRule");

    auto ips = netsh_whitelist_ips(kCapture);
    // Loopback and the Block rule's "Any" are excluded; the CIDR suffix on
    // the real whitelist entry is stripped; the non-Yuzu rule's RemoteIP
    // never surfaces (its rule name doesn't start with kRulePrefix).
    REQUIRE(ips.size() == 1);
    CHECK(ips[0] == "10.0.0.5");
}

TEST_CASE("netsh_rules_present is false and the other two parsers return empty "
         "when no rule carries the Yuzu prefix",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kNoRules = R"(
Rule Name:                           Some Windows Default Rule
----------------------------------------------------------------------
Enabled:                              Yes
RemoteIP:                             Any
Action:                               Allow

Ok.
)";
    CHECK_FALSE(netsh_rules_present(kNoRules));
    CHECK(netsh_matching_rule_names(kNoRules).empty());
    CHECK(netsh_whitelist_ips(kNoRules).empty());
}

TEST_CASE("netsh_matching_rule_names deduplicates a rule name repeated across "
         "the dir=in and dir=out captures",
         "[agent][quarantine_parsers]") {
    // win_unquarantine concatenates a dir=in and a dir=out capture before
    // parsing -- the same rule name can legitimately appear twice.
    constexpr std::string_view kDuplicated = R"(
Rule Name:                           YuzuQuarantine_BlockAllInbound
----------------------------------------------------------------------
Direction:                            In

Rule Name:                           YuzuQuarantine_BlockAllInbound
----------------------------------------------------------------------
Direction:                            Out
)";
    auto names = netsh_matching_rule_names(kDuplicated);
    REQUIRE(names.size() == 1);
    CHECK(names[0] == "YuzuQuarantine_BlockAllInbound");
}

// ── iptables ─────────────────────────────────────────────────────────────

TEST_CASE("iptables_chain_referenced detects the yuzu-quarantine jump in "
         "`iptables -L INPUT -n` output",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kInputWithJump = R"(Chain INPUT (policy ACCEPT)
target           prot opt source               destination
yuzu-quarantine  all  --  0.0.0.0/0            0.0.0.0/0
)";
    CHECK(iptables_chain_referenced(kInputWithJump));

    constexpr std::string_view kInputWithoutJump = R"(Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
)";
    CHECK_FALSE(iptables_chain_referenced(kInputWithoutJump));
}

TEST_CASE("iptables_whitelist_ips parses a realistic `iptables -L yuzu-quarantine -n` "
         "capture, excluding loopback/state/default-route rows",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kChainCapture = R"(Chain yuzu-quarantine (2 references)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            in lo
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            out lo
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED
ACCEPT     all  --  10.0.0.5             0.0.0.0/0
ACCEPT     all  --  0.0.0.0/0            10.0.0.5
DROP       all  --  0.0.0.0/0            0.0.0.0/0
)";
    auto ips = iptables_whitelist_ips(kChainCapture);
    // Both the source-side and dest-side ACCEPT for the same whitelisted IP
    // collapse to one entry; the loopback/state/DROP/default-route rows
    // contribute nothing.
    REQUIRE(ips.size() == 1);
    CHECK(ips[0] == "10.0.0.5");
}

TEST_CASE("iptables_whitelist_ips returns empty for a freshly-created empty chain",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kEmptyChain = R"(Chain yuzu-quarantine (0 references)
target     prot opt source               destination
)";
    CHECK(iptables_whitelist_ips(kEmptyChain).empty());
}

// ── pfctl ────────────────────────────────────────────────────────────────

TEST_CASE("pfctl_rules_blocked recognizes both the literal and pfctl-canonicalized "
         "default-deny spelling",
         "[agent][quarantine_parsers]") {
    CHECK(pfctl_rules_blocked("set skip on lo0\nblock all\n"));
    CHECK(pfctl_rules_blocked("set skip on lo0\nblock drop all\n"));
    CHECK_FALSE(pfctl_rules_blocked("set skip on lo0\npass all\n"));
}

TEST_CASE("pfctl_rules_blocked is false against a realistic macOS default ruleset "
         "(no Yuzu quarantine active)",
         "[agent][quarantine_parsers]") {
    // Approximates `pfctl -s rules` on a stock macOS box with pf enabled but
    // no quarantine loaded -- Apple's default ruleset is anchor-only, no
    // top-level default-deny.
    constexpr std::string_view kStockRuleset = R"(scrub-anchor "com.apple/*" all fragment reassemble
anchor "com.apple/*" all
)";
    CHECK_FALSE(pfctl_rules_blocked(kStockRuleset));
}

TEST_CASE("pfctl_whitelist_ips parses a realistic `pfctl -s rules` capture of an "
         "active quarantine ruleset",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kActiveRuleset = R"(set skip on lo0
pass quick from 10.0.0.5 to any keep state
pass quick from any to 10.0.0.5 keep state
pass quick from 192.168.1.1 to any keep state
pass quick from any to 192.168.1.1 keep state
block drop all
)";
    auto ips = pfctl_whitelist_ips(kActiveRuleset);
    REQUIRE(ips.size() == 2);
    CHECK(ips[0] == "10.0.0.5");
    CHECK(ips[1] == "192.168.1.1");
}

TEST_CASE("pfctl_whitelist_ips ignores the lo0 skip directive and returns empty "
         "when the ruleset has no pass rules",
         "[agent][quarantine_parsers]") {
    constexpr std::string_view kBlockOnly = "set skip on lo0\nblock drop all\n";
    CHECK(pfctl_whitelist_ips(kBlockOnly).empty());
}
