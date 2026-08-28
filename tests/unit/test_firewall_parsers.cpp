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

// ── Linux: nftables (rung 1, netlink) ───────────────────────────────────
//
// No live kernel is available in this sandbox (see PR notes), so these are
// hand-built fixtures constructed directly from the documented, VERSIONED
// UAPI wire format (linux/netlink.h, linux/netfilter/nfnetlink.h,
// linux/netfilter/nf_tables.h) rather than a captured real reply — flagged
// here, not silently assumed verified, the same discipline the ufw fixtures
// above already follow for a different reason. The builder helpers below
// exist ONLY to make the fixtures reviewable byte-by-byte instead of opaque
// hex literals; they encode the same header-field/attribute-value byte-order
// split documented in firewall_parsers.hpp (nlmsghdr/nlattr headers: host
// order; nftables numeric attribute VALUES: big-endian).

namespace {

void push_u16(std::vector<std::byte>& buf, std::uint16_t v) {
    buf.push_back(static_cast<std::byte>(v & 0xff));
    buf.push_back(static_cast<std::byte>((v >> 8) & 0xff));
}

void push_u32(std::vector<std::byte>& buf, std::uint32_t v) {
    for (int i = 0; i < 4; ++i)
        buf.push_back(static_cast<std::byte>((v >> (8 * i)) & 0xff));
}

void pad_to_align(std::vector<std::byte>& buf) {
    while (buf.size() % 4 != 0)
        buf.push_back(std::byte{0});
}

/// Appends one nlattr (header + raw value + alignment padding).
void push_attr_raw(std::vector<std::byte>& buf, std::uint16_t type,
                   std::span<const std::byte> value) {
    push_u16(buf, static_cast<std::uint16_t>(4 + value.size()));
    push_u16(buf, type);
    buf.insert(buf.end(), value.begin(), value.end());
    pad_to_align(buf);
}

void push_attr_str(std::vector<std::byte>& buf, std::uint16_t type, std::string_view s) {
    std::vector<std::byte> value;
    for (char c : s)
        value.push_back(static_cast<std::byte>(c));
    value.push_back(std::byte{0}); // NUL terminator, matching real NFTA_*_NAME encoding
    push_attr_raw(buf, type, value);
}

void push_attr_be32(std::vector<std::byte>& buf, std::uint16_t type, std::uint32_t v) {
    std::vector<std::byte> value;
    for (int i = 3; i >= 0; --i)
        value.push_back(static_cast<std::byte>((v >> (8 * i)) & 0xff));
    push_attr_raw(buf, type, value);
}

void push_attr_be64(std::vector<std::byte>& buf, std::uint16_t type, std::uint64_t v) {
    std::vector<std::byte> value;
    for (int i = 7; i >= 0; --i)
        value.push_back(static_cast<std::byte>((v >> (8 * i)) & 0xff));
    push_attr_raw(buf, type, value);
}

/// Appends a nested attribute (NLA_F_NESTED set, matching real encoding —
/// though the parser under test masks the flag bits off before comparing,
/// so this is for fixture realism, not something the parser depends on).
void push_attr_nested(std::vector<std::byte>& buf, std::uint16_t type,
                      std::span<const std::byte> nested_body) {
    constexpr std::uint16_t kNlaFNested = 0x8000;
    push_u16(buf, static_cast<std::uint16_t>(4 + nested_body.size()));
    push_u16(buf, static_cast<std::uint16_t>(type | kNlaFNested));
    buf.insert(buf.end(), nested_body.begin(), nested_body.end());
    pad_to_align(buf);
}

/// Wraps `body` (nfgenmsg + attributes, unpadded) in an nlmsghdr of the
/// given message `type` and appends it (with its own alignment padding).
void push_nlmsg(std::vector<std::byte>& out, std::uint16_t type,
                std::span<const std::byte> body, std::uint16_t flags = 0) {
    push_u32(out, static_cast<std::uint32_t>(16 + body.size()));
    push_u16(out, type);
    // flags defaults to 0 -- unread by the parse_nft_* functions under test,
    // but split_nlmsgs() still decodes it verbatim (nft_dump()'s
    // NLM_F_DUMP_INTR check reads it from that same decoded header).
    push_u16(out, flags);
    push_u32(out, 0); // seq
    push_u32(out, 0); // pid
    out.insert(out.end(), body.begin(), body.end());
    pad_to_align(out);
}

void push_done(std::vector<std::byte>& out) {
    push_nlmsg(out, nft_raw::kNlmsgDone, std::span<const std::byte>{});
}

std::vector<std::byte> make_nfgenmsg(std::uint8_t family) {
    return {static_cast<std::byte>(family), std::byte{0}, std::byte{0}, std::byte{0}};
}

} // namespace

TEST_CASE("nft: parse_nft_tables — two tables, hand-built wire shape", "[firewall]") {
    std::vector<std::byte> buf;
    {
        std::vector<std::byte> body = make_nfgenmsg(nft_raw::kNfprotoInet);
        push_attr_str(body, nft_raw::kNftaTableName, "filter");
        push_nlmsg(buf, static_cast<std::uint16_t>((nft_raw::kNfnlSubsysNftables << 8) | 0), body);
    }
    {
        std::vector<std::byte> body = make_nfgenmsg(nft_raw::kNfprotoIpv4);
        push_attr_str(body, nft_raw::kNftaTableName, "nat");
        push_nlmsg(buf, static_cast<std::uint16_t>((nft_raw::kNfnlSubsysNftables << 8) | 0), body);
    }
    push_done(buf);

    auto tables = parse_nft_tables(buf);
    REQUIRE(tables.size() == 2);
    CHECK(tables[0].family == nft_raw::kNfprotoInet);
    CHECK(tables[0].name == "filter");
    CHECK(tables[1].family == nft_raw::kNfprotoIpv4);
    CHECK(tables[1].name == "nat");
}

TEST_CASE("nft: parse_nft_chains — base chain (hook+policy) vs regular chain", "[firewall]") {
    std::vector<std::byte> buf;
    {
        std::vector<std::byte> body = make_nfgenmsg(nft_raw::kNfprotoInet);
        push_attr_str(body, nft_raw::kNftaChainTable, "filter");
        push_attr_str(body, nft_raw::kNftaChainName, "INPUT");
        std::vector<std::byte> hook_body;
        push_attr_be32(hook_body, nft_raw::kNftaHookHooknum, 1); // NF_INET_LOCAL_IN
        push_attr_nested(body, nft_raw::kNftaChainHook, hook_body);
        push_attr_be32(body, nft_raw::kNftaChainPolicy, nft_raw::kNftPolicyDrop);
        push_nlmsg(buf, static_cast<std::uint16_t>((nft_raw::kNfnlSubsysNftables << 8) | 3), body);
    }
    {
        std::vector<std::byte> body = make_nfgenmsg(nft_raw::kNfprotoInet);
        push_attr_str(body, nft_raw::kNftaChainTable, "filter");
        push_attr_str(body, nft_raw::kNftaChainName, "custom-jump");
        push_nlmsg(buf, static_cast<std::uint16_t>((nft_raw::kNfnlSubsysNftables << 8) | 3), body);
    }
    push_done(buf);

    auto chains = parse_nft_chains(buf);
    REQUIRE(chains.size() == 2);

    CHECK(chains[0].table == "filter");
    CHECK(chains[0].name == "INPUT");
    CHECK(chains[0].is_base_chain);
    REQUIRE(chains[0].hooknum.has_value());
    CHECK(*chains[0].hooknum == 1);
    REQUIRE(chains[0].policy.has_value());
    CHECK(*chains[0].policy == nft_raw::kNftPolicyDrop);
    CHECK(nft_hook_name(chains[0].hooknum) == "input");
    CHECK(nft_policy_name(chains[0].policy) == "drop");

    CHECK(chains[1].name == "custom-jump");
    CHECK_FALSE(chains[1].is_base_chain);
    CHECK_FALSE(chains[1].hooknum.has_value());
    CHECK_FALSE(chains[1].policy.has_value());
}

TEST_CASE("nft: parse_nft_rules — handle decoded as big-endian u64", "[firewall]") {
    std::vector<std::byte> body = make_nfgenmsg(nft_raw::kNfprotoInet);
    push_attr_str(body, nft_raw::kNftaRuleTable, "filter");
    push_attr_str(body, nft_raw::kNftaRuleChain, "INPUT");
    push_attr_be64(body, nft_raw::kNftaRuleHandle, 42);
    std::vector<std::byte> buf;
    push_nlmsg(buf, static_cast<std::uint16_t>((nft_raw::kNfnlSubsysNftables << 8) | 6), body);
    push_done(buf);

    auto rules = parse_nft_rules(buf);
    REQUIRE(rules.size() == 1);
    CHECK(rules[0].table == "filter");
    CHECK(rules[0].chain == "INPUT");
    REQUIRE(rules[0].handle.has_value());
    CHECK(*rules[0].handle == 42);
}

TEST_CASE("nft: has_content — accept-policy base chain with no rules is inactive", "[firewall]") {
    NftChainInfo c;
    c.is_base_chain = true;
    c.policy = nft_raw::kNftPolicyAccept;
    CHECK_FALSE(nft_has_content({c}, {}));
}

TEST_CASE("nft: has_content — drop-policy base chain counts as active even with no rules",
         "[firewall]") {
    NftChainInfo c;
    c.is_base_chain = true;
    c.policy = nft_raw::kNftPolicyDrop;
    CHECK(nft_has_content({c}, {}));
}

TEST_CASE("nft: has_content — any rule counts as active regardless of chain policy", "[firewall]") {
    CHECK(nft_has_content({}, std::vector<NftRuleInfo>(1)));
}

TEST_CASE("nft: has_content — empty ruleset is inactive, never fabricated", "[firewall]") {
    CHECK_FALSE(nft_has_content({}, {}));
}

TEST_CASE("nft: truncated buffer (shorter than one nlmsghdr) yields nothing, no crash",
         "[firewall]") {
    std::vector<std::byte> buf(10, std::byte{0});
    CHECK(parse_nft_tables(buf).empty());
}

TEST_CASE("nft: NLMSG_ERROR is skipped, never treated as data", "[firewall]") {
    std::vector<std::byte> buf;
    push_nlmsg(buf, nft_raw::kNlmsgError, std::vector<std::byte>(4, std::byte{0}));
    CHECK(parse_nft_tables(buf).empty());
}

TEST_CASE("nft: an attribute length overrunning the buffer stops the walk safely",
         "[firewall]") {
    std::vector<std::byte> body = make_nfgenmsg(nft_raw::kNfprotoInet);
    // Corrupt attribute: declares 100 bytes of value but the message ends
    // right after this 4-byte attribute header -- must not read out of bounds.
    push_u16(body, 100);
    push_u16(body, nft_raw::kNftaTableName);
    std::vector<std::byte> buf;
    push_nlmsg(buf, 0, body);
    CHECK(parse_nft_tables(buf).empty()); // name never decoded -> table dropped, not crashed
}

TEST_CASE("nft: family/hook/policy names — known values plus fallback for unrecognised ones",
         "[firewall]") {
    CHECK(nft_family_name(nft_raw::kNfprotoInet) == "inet");
    CHECK(nft_family_name(nft_raw::kNfprotoIpv6) == "ip6");
    CHECK(nft_family_name(99) == "family99");

    CHECK(nft_hook_name(std::optional<std::uint32_t>{4}) == "postrouting");
    CHECK(nft_hook_name(std::optional<std::uint32_t>{7}) == "hook7");
    CHECK(nft_hook_name(std::nullopt) == "unknown");

    CHECK(nft_policy_name(std::optional<std::uint32_t>{nft_raw::kNftPolicyAccept}) == "accept");
    CHECK(nft_policy_name(std::optional<std::uint32_t>{5}) == "policy5");
    CHECK(nft_policy_name(std::nullopt) == "unknown");
}

TEST_CASE("nft: format_nft_chain_rule_row — exact field order/shape try_nftables_rules() emits",
         "[firewall]") {
    NftChainInfo c;
    c.family = nft_raw::kNfprotoInet;
    c.table = "filter";
    c.name = "INPUT";
    c.is_base_chain = true;
    c.hooknum = std::optional<std::uint32_t>{1};
    c.policy = std::optional<std::uint32_t>{nft_raw::kNftPolicyDrop};

    CHECK(format_nft_chain_rule_row(c) == "rule|nftables|inet|filter|INPUT|input|drop");
}

TEST_CASE("nft: format_nft_chain_rule_row sanitizes pipe/newline/CR in table and chain names",
         "[firewall]") {
    NftChainInfo c;
    c.family = nft_raw::kNfprotoIpv4;
    c.table = "fil|ter";
    c.name = "IN\nPUT\r";
    c.is_base_chain = true;
    c.hooknum = std::optional<std::uint32_t>{0};
    c.policy = std::optional<std::uint32_t>{nft_raw::kNftPolicyAccept};

    CHECK(format_nft_chain_rule_row(c) == "rule|nftables|ip|fil_ter|IN_PUT_|prerouting|accept");
}

TEST_CASE("nft: format_nft_rule_handle_row — exact field order/shape, handle present and absent",
         "[firewall]") {
    NftRuleInfo r;
    r.family = nft_raw::kNfprotoIpv6;
    r.table = "filter";
    r.chain = "FORWARD";
    r.handle = std::optional<std::uint64_t>{42};
    CHECK(format_nft_rule_handle_row(r) == "rule|nftables|ip6|filter|FORWARD|handle|42");

    r.handle = std::nullopt;
    CHECK(format_nft_rule_handle_row(r) == "rule|nftables|ip6|filter|FORWARD|handle|unknown");
}

TEST_CASE("nft: format_nft_rule_handle_row sanitizes pipe/newline/CR in table and chain names",
         "[firewall]") {
    NftRuleInfo r;
    r.family = nft_raw::kNfprotoInet;
    r.table = "na|t";
    r.chain = "chain\r\n";
    r.handle = std::optional<std::uint64_t>{7};
    CHECK(format_nft_rule_handle_row(r) == "rule|nftables|inet|na_t|chain__|handle|7");
}

TEST_CASE("nft: split_nlmsgs decodes NLM_F_DUMP_INTR on the terminating DONE message",
         "[firewall]") {
    // nft_dump() (firewall_plugin.cpp) treats a DONE message carrying this
    // flag as a torn/inconsistent dump and fails the round-trip rather than
    // trusting the partial buffer -- that branch does real socket I/O and
    // isn't unit-testable directly (no live kernel in the unit suite), but
    // split_nlmsgs() decoding the flag correctly is the testable half of
    // the same defect: an unread/miscomputed flags field would make that
    // check silently inert regardless of how nft_dump() branches on it.
    std::vector<std::byte> torn;
    push_nlmsg(torn, nft_raw::kNlmsgDone, std::span<const std::byte>{}, nft_raw::kNlmFDumpIntr);
    auto torn_msgs = nft_raw::split_nlmsgs(torn);
    REQUIRE(torn_msgs.size() == 1);
    CHECK(torn_msgs[0].hdr.type == nft_raw::kNlmsgDone);
    CHECK((torn_msgs[0].hdr.flags & nft_raw::kNlmFDumpIntr) != 0);

    std::vector<std::byte> clean;
    push_done(clean);
    auto clean_msgs = nft_raw::split_nlmsgs(clean);
    REQUIRE(clean_msgs.size() == 1);
    CHECK((clean_msgs[0].hdr.flags & nft_raw::kNlmFDumpIntr) == 0);
}
