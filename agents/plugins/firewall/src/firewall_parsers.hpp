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

} // namespace yuzu::firewall
