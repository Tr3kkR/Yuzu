#pragma once

/**
 * firewall_parsers.hpp — pure parse helpers for the firewall plugin.
 *
 * macOS state leg: the Application Firewall global state (socketfilterfw)
 * and the pf packet-filter status (pfctl). Linux legs: `ufw status`/`ufw
 * status numbered` and `iptables -S` — both now emit STRUCTURED rows,
 * replacing the old opaque `rule|<raw line>` passthrough.
 *
 * Header-only and OS-free so the parsing is unit-tested on every host
 * (test_firewall_parsers.cpp — the netprobe_stats.hpp pattern); the
 * run_bounded_subprocess/sd-bus acquisition in firewall_plugin.cpp is the
 * impure shell.
 *
 * Honest-status invariant: empty, truncated, or unrecognised output parses
 * to `unknown` (state) or an empty row set (rules) — never a false-safe
 * enabled/disabled or a fabricated rule.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::firewall {

enum class FwState { enabled, disabled, unknown };

[[nodiscard]] constexpr std::string_view to_string(FwState s) {
    switch (s) {
    case FwState::enabled:
        return "enabled";
    case FwState::disabled:
        return "disabled";
    case FwState::unknown:
        return "unknown";
    }
    return "unknown"; // unreachable — cases are exhaustive so -Wswitch flags enum drift
}

/// Global state of the macOS Application Firewall as reported by
/// `socketfilterfw --getglobalstate`.
struct AlfGlobalState {
    FwState state{FwState::unknown};
    bool block_all{false}; // "(State = 2)" — enabled AND blocking all incoming
};

/// Parse `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`.
/// Primary signal is the "(State = N)" clause — 0 = disabled, 1 = enabled,
/// 2 = enabled + block-all — so prose rewording across macOS releases cannot
/// flip the verdict. A multi-digit or non-digit state is unrecognised and
/// falls through, as does a missing clause: the enabled/disabled prose is the
/// fallback, with "disabled" checked first so ambiguous text biases toward
/// the attention-drawing answer rather than false assurance.
[[nodiscard]] constexpr AlfGlobalState parse_alf_global_state(std::string_view out) {
    AlfGlobalState r;
    constexpr std::string_view kClause = "(State = ";
    const auto pos = out.find(kClause);
    if (pos != std::string_view::npos && pos + kClause.size() < out.size()) {
        const auto idx = pos + kClause.size();
        const bool single_digit =
            idx + 1 >= out.size() || out[idx + 1] < '0' || out[idx + 1] > '9';
        if (single_digit) {
            switch (out[idx]) {
            case '0':
                r.state = FwState::disabled;
                return r;
            case '1':
                r.state = FwState::enabled;
                return r;
            case '2':
                r.state = FwState::enabled;
                r.block_all = true;
                return r;
            default:
                break; // unrecognised state number — fall through to prose
            }
        }
    }
    if (out.find("disabled") != std::string_view::npos)
        r.state = FwState::disabled;
    else if (out.find("enabled") != std::string_view::npos)
        r.state = FwState::enabled;
    return r;
}

/// Parse `pfctl -s info`. The first line reads "Status: Enabled for …" or
/// "Status: Disabled for …". Empty output (reading /dev/pf needs root and the
/// caller discards stderr) or anything unrecognised → unknown.
[[nodiscard]] constexpr FwState parse_pf_status(std::string_view out) {
    if (out.find("Status: Enabled") != std::string_view::npos)
        return FwState::enabled;
    if (out.find("Status: Disabled") != std::string_view::npos)
        return FwState::disabled;
    return FwState::unknown;
}

// ── Linux: ufw ───────────────────────────────────────────────────────────

/// One row of `ufw status numbered` — a bracketed rule ordinal plus its
/// fixed-width To/Action/From columns.
struct UfwRule {
    std::string index; // the bracketed ordinal, e.g. "1" (from "[ 1]")
    std::string to;
    std::string action;
    std::string from;
};

namespace detail {

/// Split on runs of 2+ spaces (ufw's fixed-width column layout), preserving
/// single spaces inside a column value (e.g. the two-word action "ALLOW IN").
[[nodiscard]] inline std::vector<std::string_view> split_multi_space(std::string_view line) {
    std::vector<std::string_view> fields;
    std::size_t i = 0;
    const std::size_t n = line.size();
    while (i < n) {
        while (i < n && line[i] == ' ')
            ++i;
        const std::size_t start = i;
        while (i < n && !(line[i] == ' ' && i + 1 < n && line[i + 1] == ' '))
            ++i;
        if (i > start)
            fields.push_back(line.substr(start, i - start));
        while (i < n && line[i] == ' ')
            ++i;
    }
    return fields;
}

} // namespace detail

/// Parse `ufw status` (the unnumbered form) — only the first "Status: …"
/// line matters.
///
/// Fixes a real bug in the shell-out this replaces: the old code did
/// `output.find("active") != npos`, which ALSO matches the substring
/// "active" inside "inactive" — misreporting a disabled ufw as active. This
/// checks a full-prefix match against "Status: active"/"Status: inactive"
/// instead, so "inactive" can never satisfy the "active" branch.
[[nodiscard]] inline FwState parse_ufw_status(std::string_view out) {
    constexpr std::string_view kInactive = "Status: inactive";
    constexpr std::string_view kActive = "Status: active";
    if (out.substr(0, kInactive.size()) == kInactive)
        return FwState::disabled;
    if (out.substr(0, kActive.size()) == kActive)
        return FwState::enabled;
    return FwState::unknown;
}

/// Parse `ufw status numbered` into structured rows. Only bracketed `[ N]`
/// rule lines are emitted — the "Status:" line, the blank separator, and the
/// "To / Action / From" header + its underline are skipped by construction
/// (none of them start with `[`).
[[nodiscard]] inline std::vector<UfwRule> parse_ufw_rules(std::string_view out) {
    std::vector<UfwRule> rules;
    std::string buf(out); // istringstream needs an owned string
    std::istringstream iss(buf);
    std::string line;
    while (std::getline(iss, line)) {
        while (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty() || line.front() != '[')
            continue;
        const auto close = line.find(']');
        if (close == std::string::npos)
            continue;

        UfwRule rule;
        std::string_view idx(line.data() + 1, close - 1);
        while (!idx.empty() && idx.front() == ' ')
            idx.remove_prefix(1);
        while (!idx.empty() && idx.back() == ' ')
            idx.remove_suffix(1);
        rule.index = std::string(idx);

        const auto fields = detail::split_multi_space(std::string_view(line).substr(close + 1));
        if (fields.size() >= 1)
            rule.to = std::string(fields[0]);
        if (fields.size() >= 2)
            rule.action = std::string(fields[1]);
        if (fields.size() >= 3)
            rule.from = std::string(fields[2]);
        rules.push_back(std::move(rule));
    }
    return rules;
}

// ── Linux: iptables ─────────────────────────────────────────────────────

enum class IptablesEntryType { policy, new_chain, append, unknown };

/// One row of `iptables -S` output — the command-form rule-save syntax
/// (`-P`/`-N`/`-A` lines), one row per line.
struct IptablesRule {
    IptablesEntryType type{IptablesEntryType::unknown};
    std::string chain;
    std::string spec; // policy target ("ACCEPT"/"DROP") for `policy`; empty
                       // for `new_chain`; the rule spec after the chain name
                       // for `append`; the raw line for `unknown`.
};

/// Parse `iptables -S` into structured rows, replacing the old opaque
/// `rule|<raw line>` passthrough. An unrecognised line (not `-P`/`-N`/`-A`)
/// parses to `IptablesEntryType::unknown` with the raw line preserved in
/// `spec` rather than being silently dropped.
[[nodiscard]] inline std::vector<IptablesRule> parse_iptables_save(std::string_view out) {
    std::vector<IptablesRule> rules;
    std::string buf(out);
    std::istringstream iss(buf);
    std::string line;
    while (std::getline(iss, line)) {
        while (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;

        std::istringstream ls(line);
        std::string tok;
        ls >> tok;

        IptablesRule r;
        if (tok == "-P") {
            r.type = IptablesEntryType::policy;
            ls >> r.chain;
            std::string target;
            ls >> target;
            r.spec = target;
        } else if (tok == "-N") {
            r.type = IptablesEntryType::new_chain;
            ls >> r.chain;
        } else if (tok == "-A") {
            r.type = IptablesEntryType::append;
            ls >> r.chain;
            std::string rest;
            std::getline(ls, rest);
            while (!rest.empty() && rest.front() == ' ')
                rest.erase(rest.begin());
            r.spec = rest;
        } else {
            r.type = IptablesEntryType::unknown;
            r.spec = line;
        }
        rules.push_back(std::move(r));
    }
    return rules;
}

// ── Linux: nftables (rung 1, netlink) ───────────────────────────────────
//
// Pure decode over NETLINK_NETFILTER/NFNL_SUBSYS_NFTABLES dump-reply bytes —
// zero socket/OS dependency, mirroring tar_netqual_nstat.hpp's split between
// a transcribed wire-format namespace (here: nft_raw) and free decode
// functions, and firewall_plugin.cpp's own header docblock claim that every
// parser in this file is OS-free and unit-tested on every host. Unlike
// tar_netqual_nstat.hpp's private/unversioned Darwin nstat ABI, the structs
// below transcribe STABLE, VERSIONED kernel UAPI headers (linux/netlink.h,
// linux/netfilter/nfnetlink.h, linux/netfilter/nf_tables.h) — confidence is
// correspondingly higher, and this leg HAS since been verified against a
// real kernel (see docs/agent-privilege-model.md's "Verified 2026-08-23"
// note: correct enumeration of ~50 real rules across ip/ip6/inet on a live
// host, 129/129 assertions passing). Every decode function still degrades
// honestly regardless (a malformed/unrecognised byte sequence yields an
// empty result or an "unknown"/`policyN`-shaped fallback string, never a
// crash or a fabricated value) exactly like this header's other parsers —
// that contract is retained for the untested no-CAP_NET_ADMIN denial path
// and any future malformed-reply case, not dropped now that the happy path
// is proven.
//
// Byte-order note (load-bearing, easy to get backwards): `nlmsghdr`/
// `nfgenmsg`/`nlattr` HEADER fields are HOST byte order (every supported
// deployment target is little-endian, so plain memcpy reads them correctly);
// nftables' own numeric ATTRIBUTE VALUES (chain policy, hook number, rule
// handle) are NETWORK byte order (big-endian) by nftables userspace
// convention — this is why load_be32/load_be64 exist as separate, explicit
// big-endian readers rather than reusing a native memcpy like the header
// fields do.
//
// Read-only by design (ADR-3002 Decision 8): only NFT_MSG_GET* dump requests
// are ever sent by the impure shell in firewall_plugin.cpp — a mutating leg
// needs a separately-approved brokered-elevation design and is out of scope
// here. Expression-level rule decoding (individual match/verdict opcodes
// inside NFTA_RULE_EXPRESSIONS) is ALSO out of scope, the same documented-gap
// pattern as this file's own firewalld getPorts() omission above: base-chain
// hook/policy plus per-rule handle enumeration is the high-confidence subset
// (mirrors what `nft list chains` shows), full expression bytecode decoding
// is a distinct, much larger follow-up.

namespace nft_raw {

/// linux/netlink.h `struct nlmsghdr` (16 bytes, host byte order).
struct NlMsgHdr {
    std::uint32_t len{};
    std::uint16_t type{};
    std::uint16_t flags{};
    std::uint32_t seq{};
    std::uint32_t pid{};
};
static_assert(sizeof(NlMsgHdr) == 16);

/// linux/netfilter/nfnetlink.h `struct nfgenmsg` (4 bytes) — immediately
/// follows nlmsghdr in every NFNETLINK-family message, nftables included.
/// `family`/`version` are read like `nlmsghdr`/`nlattr` header fields (host
/// byte order); `res_id` is `__be16` (network byte order) in the real UAPI
/// struct, but this code always sends it as 0 and never reads it back on the
/// decode side, so the byte-order distinction is inert here today.
struct NfGenMsg {
    std::uint8_t family{};
    std::uint8_t version{};
    std::uint16_t res_id{}; // __be16 in the kernel struct; unused/always-zero here
};
static_assert(sizeof(NfGenMsg) == 4);

/// linux/netlink.h `struct nlattr` (4 bytes) — precedes each attribute's
/// value; `len` counts the header itself plus the (unpadded) value.
struct NlAttr {
    std::uint16_t len{};
    std::uint16_t type{};
};
static_assert(sizeof(NlAttr) == 4);

constexpr std::uint16_t kNlaTypeMask = 0x3fff; // NLA_TYPE_MASK
constexpr std::size_t kNlaAlignTo = 4;

constexpr std::uint16_t kNlmsgError = 0x2;
constexpr std::uint16_t kNlmsgDone = 0x3;

constexpr std::uint8_t kNfnlSubsysNftables = 10;
constexpr std::uint16_t kNftMsgGettable = 1;
constexpr std::uint16_t kNftMsgGetchain = 4;
constexpr std::uint16_t kNftMsgGetrule = 7;

constexpr std::uint8_t kNfprotoUnspec = 0;
constexpr std::uint8_t kNfprotoInet = 1;
constexpr std::uint8_t kNfprotoIpv4 = 2;
constexpr std::uint8_t kNfprotoArp = 3;
constexpr std::uint8_t kNfprotoNetdev = 5;
constexpr std::uint8_t kNfprotoBridge = 7;
constexpr std::uint8_t kNfprotoIpv6 = 10;

constexpr std::uint16_t kNftaTableName = 1;

constexpr std::uint16_t kNftaChainTable = 1;
constexpr std::uint16_t kNftaChainName = 3;
constexpr std::uint16_t kNftaChainHook = 4;
constexpr std::uint16_t kNftaChainPolicy = 5;

constexpr std::uint16_t kNftaHookHooknum = 1;

constexpr std::uint16_t kNftaRuleTable = 1;
constexpr std::uint16_t kNftaRuleChain = 2;
constexpr std::uint16_t kNftaRuleHandle = 3;

constexpr std::uint32_t kNftPolicyDrop = 0;
constexpr std::uint32_t kNftPolicyAccept = 1;

/// One decoded netlink message: its header plus the raw payload span
/// (nfgenmsg + attributes for a data message; unexamined for
/// NLMSG_DONE/NLMSG_ERROR).
struct RawNlMsg {
    NlMsgHdr hdr;
    std::span<const std::byte> payload;
};

/// Splits a raw dump-reply buffer into its nlmsghdr-framed messages. A
/// message whose declared `len` is shorter than the header or overruns the
/// buffer stops the walk at that point (truncated input decodes to "as much
/// as could be safely read", never an out-of-bounds read) — same contract as
/// tar_netqual_nstat.hpp's nstat_frame_messages().
[[nodiscard]] inline std::vector<RawNlMsg> split_nlmsgs(std::span<const std::byte> buf) {
    std::vector<RawNlMsg> msgs;
    std::size_t off = 0;
    while (off + sizeof(NlMsgHdr) <= buf.size()) {
        NlMsgHdr hdr{};
        std::memcpy(&hdr, buf.data() + off, sizeof(hdr));
        if (hdr.len < sizeof(NlMsgHdr) || off + hdr.len > buf.size())
            break;
        const std::size_t payload_len = hdr.len - sizeof(NlMsgHdr);
        msgs.push_back({hdr, buf.subspan(off + sizeof(NlMsgHdr), payload_len)});
        const std::size_t aligned = (hdr.len + (kNlaAlignTo - 1)) & ~(kNlaAlignTo - 1);
        if (aligned == 0)
            break; // unreachable given the >= sizeof(NlMsgHdr) check above; defensive
        off += aligned;
    }
    return msgs;
}

struct RawAttr {
    std::uint16_t type; // NLA_TYPE_MASK already applied
    std::span<const std::byte> value;
};

/// Walks one flat (non-nested) attribute stream. Same truncated-input
/// contract as split_nlmsgs. Nested attributes (e.g. NFTA_CHAIN_HOOK's
/// value) are walked by calling this again on that attribute's `value`.
[[nodiscard]] inline std::vector<RawAttr> walk_attrs(std::span<const std::byte> data) {
    std::vector<RawAttr> out;
    std::size_t off = 0;
    while (off + sizeof(NlAttr) <= data.size()) {
        NlAttr hdr{};
        std::memcpy(&hdr, data.data() + off, sizeof(hdr));
        if (hdr.len < sizeof(NlAttr) || off + hdr.len > data.size())
            break;
        const std::uint16_t type = hdr.type & kNlaTypeMask;
        const std::size_t value_len = hdr.len - sizeof(NlAttr);
        out.push_back({type, data.subspan(off + sizeof(NlAttr), value_len)});
        const std::size_t aligned = (hdr.len + (kNlaAlignTo - 1)) & ~(kNlaAlignTo - 1);
        if (aligned == 0)
            break;
        off += aligned;
    }
    return out;
}

/// NUL-terminated string attribute value → std::string (stops at the first
/// NUL or the end of the value span, whichever comes first).
[[nodiscard]] inline std::string nla_string(std::span<const std::byte> v) {
    std::size_t len = 0;
    while (len < v.size() && v[len] != std::byte{0})
        ++len;
    return std::string(reinterpret_cast<const char*>(v.data()), len);
}

/// Big-endian u32 attribute value (nftables numeric-attribute convention —
/// see the byte-order note above). nullopt if the value is too short.
[[nodiscard]] constexpr std::optional<std::uint32_t>
load_be32(std::span<const std::byte> v) noexcept {
    if (v.size() < 4)
        return std::nullopt;
    return (static_cast<std::uint32_t>(std::to_integer<unsigned char>(v[0])) << 24) |
           (static_cast<std::uint32_t>(std::to_integer<unsigned char>(v[1])) << 16) |
           (static_cast<std::uint32_t>(std::to_integer<unsigned char>(v[2])) << 8) |
           static_cast<std::uint32_t>(std::to_integer<unsigned char>(v[3]));
}

/// Big-endian u64 attribute value (NFTA_RULE_HANDLE is `__be64`).
[[nodiscard]] constexpr std::optional<std::uint64_t>
load_be64(std::span<const std::byte> v) noexcept {
    if (v.size() < 8)
        return std::nullopt;
    std::uint64_t r = 0;
    for (int i = 0; i < 8; ++i)
        r = (r << 8) | static_cast<std::uint64_t>(std::to_integer<unsigned char>(v[i]));
    return r;
}

} // namespace nft_raw

struct NftTableInfo {
    std::uint8_t family{};
    std::string name;
};

struct NftChainInfo {
    std::uint8_t family{};
    std::string table;
    std::string name;
    bool is_base_chain{false};             // NFTA_CHAIN_HOOK present
    std::optional<std::uint32_t> hooknum;  // only meaningful when is_base_chain
    std::optional<std::uint32_t> policy;   // only meaningful when is_base_chain
};

struct NftRuleInfo {
    std::uint8_t family{};
    std::string table;
    std::string chain;
    std::optional<std::uint64_t> handle;
};

/// Parses one NFT_MSG_GETTABLE dump-reply buffer. NLMSG_DONE/NLMSG_ERROR
/// messages are skipped (the caller decides reachability from the dump
/// round-trip's own success/failure, not from this function); a message
/// whose table name could not be decoded is dropped rather than emitted with
/// an empty name.
[[nodiscard]] inline std::vector<NftTableInfo> parse_nft_tables(std::span<const std::byte> buf) {
    using namespace nft_raw;
    std::vector<NftTableInfo> out;
    for (const auto& m : split_nlmsgs(buf)) {
        if (m.hdr.type == kNlmsgDone || m.hdr.type == kNlmsgError)
            continue;
        if (m.payload.size() < sizeof(NfGenMsg))
            continue;
        NfGenMsg gen{};
        std::memcpy(&gen, m.payload.data(), sizeof(gen));
        NftTableInfo info;
        info.family = gen.family;
        for (const auto& a : walk_attrs(m.payload.subspan(sizeof(gen)))) {
            if (a.type == kNftaTableName)
                info.name = nla_string(a.value);
        }
        if (!info.name.empty())
            out.push_back(std::move(info));
    }
    return out;
}

/// Parses one NFT_MSG_GETCHAIN dump-reply buffer. A chain is a "base chain"
/// (attached to a netfilter hook, and the only kind with a policy) iff
/// NFTA_CHAIN_HOOK is present — a regular (non-base) chain exists only as a
/// jump target and carries neither hook nor policy.
[[nodiscard]] inline std::vector<NftChainInfo> parse_nft_chains(std::span<const std::byte> buf) {
    using namespace nft_raw;
    std::vector<NftChainInfo> out;
    for (const auto& m : split_nlmsgs(buf)) {
        if (m.hdr.type == kNlmsgDone || m.hdr.type == kNlmsgError)
            continue;
        if (m.payload.size() < sizeof(NfGenMsg))
            continue;
        NfGenMsg gen{};
        std::memcpy(&gen, m.payload.data(), sizeof(gen));
        NftChainInfo info;
        info.family = gen.family;
        for (const auto& a : walk_attrs(m.payload.subspan(sizeof(gen)))) {
            switch (a.type) {
            case kNftaChainTable:
                info.table = nla_string(a.value);
                break;
            case kNftaChainName:
                info.name = nla_string(a.value);
                break;
            case kNftaChainHook:
                info.is_base_chain = true;
                for (const auto& h : walk_attrs(a.value)) {
                    if (h.type == kNftaHookHooknum)
                        info.hooknum = load_be32(h.value);
                }
                break;
            case kNftaChainPolicy:
                info.policy = load_be32(a.value);
                break;
            default:
                break;
            }
        }
        if (!info.name.empty())
            out.push_back(std::move(info));
    }
    return out;
}

/// Parses one NFT_MSG_GETRULE dump-reply buffer into per-rule handle rows
/// (see the header comment above: expression-level decoding is out of
/// scope). A rule row is still emitted even if the table/chain attribute
/// could not be decoded — an incomplete row is still meaningful evidence
/// that a rule exists, unlike a table/chain with no name.
[[nodiscard]] inline std::vector<NftRuleInfo> parse_nft_rules(std::span<const std::byte> buf) {
    using namespace nft_raw;
    std::vector<NftRuleInfo> out;
    for (const auto& m : split_nlmsgs(buf)) {
        if (m.hdr.type == kNlmsgDone || m.hdr.type == kNlmsgError)
            continue;
        if (m.payload.size() < sizeof(NfGenMsg))
            continue;
        NfGenMsg gen{};
        std::memcpy(&gen, m.payload.data(), sizeof(gen));
        NftRuleInfo info;
        info.family = gen.family;
        for (const auto& a : walk_attrs(m.payload.subspan(sizeof(gen)))) {
            switch (a.type) {
            case kNftaRuleTable:
                info.table = nla_string(a.value);
                break;
            case kNftaRuleChain:
                info.chain = nla_string(a.value);
                break;
            case kNftaRuleHandle:
                info.handle = load_be64(a.value);
                break;
            default:
                break;
            }
        }
        out.push_back(std::move(info));
    }
    return out;
}

/// "Active" heuristic mirroring parse_iptables_save's has_content logic in
/// firewall_plugin.cpp's try_iptables_state: any actual rule, or any base
/// chain whose policy is not the default-open "accept", counts as active
/// content. An empty ruleset (no tables at all, or tables with no base
/// chains/rules) is inactive — never fabricated as active.
[[nodiscard]] inline bool nft_has_content(const std::vector<NftChainInfo>& chains,
                                          const std::vector<NftRuleInfo>& rules) {
    if (!rules.empty())
        return true;
    for (const auto& c : chains) {
        if (c.is_base_chain && c.policy.has_value() && *c.policy != nft_raw::kNftPolicyAccept)
            return true;
    }
    return false;
}

[[nodiscard]] inline std::string nft_family_name(std::uint8_t family) {
    using namespace nft_raw;
    switch (family) {
    case kNfprotoUnspec:
        return "unspec";
    case kNfprotoInet:
        return "inet";
    case kNfprotoIpv4:
        return "ip";
    case kNfprotoArp:
        return "arp";
    case kNfprotoNetdev:
        return "netdev";
    case kNfprotoBridge:
        return "bridge";
    case kNfprotoIpv6:
        return "ip6";
    default:
        return "family" + std::to_string(static_cast<int>(family));
    }
}

[[nodiscard]] inline std::string nft_hook_name(std::optional<std::uint32_t> hooknum) {
    if (!hooknum)
        return "unknown";
    switch (*hooknum) {
    case 0:
        return "prerouting";
    case 1:
        return "input";
    case 2:
        return "forward";
    case 3:
        return "output";
    case 4:
        return "postrouting";
    default:
        return "hook" + std::to_string(*hooknum);
    }
}

[[nodiscard]] inline std::string nft_policy_name(std::optional<std::uint32_t> policy) {
    if (!policy)
        return "unknown";
    if (*policy == nft_raw::kNftPolicyAccept)
        return "accept";
    if (*policy == nft_raw::kNftPolicyDrop)
        return "drop";
    return "policy" + std::to_string(*policy);
}

} // namespace yuzu::firewall
