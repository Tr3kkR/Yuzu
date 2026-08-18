/**
 * quarantine_parsers.hpp — pure status-read parsing for the quarantine
 * plugin (Wave-2 ADR-3002 acquisition-ladder migration, quarantine
 * package). Portable and header-only, no platform guard: this file and its
 * test TU (test_quarantine_parsers.cpp) compile and run on every leg, byte-
 * for-byte lifted from the pre-migration parsing logic in
 * quarantine_plugin.cpp (no behaviour change — this PR moves the spawn
 * mechanism, not the parse rules).
 *
 * Three consumers in quarantine_plugin.cpp, one per platform's status reads:
 *   - netsh_rules_present / netsh_matching_rule_names / netsh_whitelist_ips
 *     (win_is_quarantined, win_unquarantine, win_get_whitelist)
 *   - iptables_chain_referenced / iptables_whitelist_ips
 *     (linux_is_quarantined, linux_get_whitelist)
 *   - pfctl_rules_blocked / pfctl_whitelist_ips
 *     (macos_is_quarantined, macos_get_whitelist)
 *
 * None of these functions perform I/O or spawn anything — the plugin
 * captures `netsh advfirewall firewall show rule ...`, `iptables -L ...`
 * and `pfctl -s rules` output via yuzu::agent::run_bounded_subprocess and
 * hands the captured text here.
 */
#pragma once

#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::quarantine {

// Firewall rules created by this plugin are prefixed for identification —
// shared by every platform's status read and by the mutating paths in
// quarantine_plugin.cpp.
inline constexpr std::string_view kRulePrefix = "YuzuQuarantine_";

// ── IP validation ────────────────────────────────────────────────────────
//
// Single source of truth for "does this look like an IPv4/IPv6 literal" —
// used both to validate operator-supplied whitelist IPs (quarantine_plugin.
// cpp) and to filter parsed values here so a malformed/adversarial capture
// (e.g. an attacker-controlled RemoteIP-shaped string embedded in a rule
// name) can't smuggle a non-IP token into a whitelist result.
inline bool is_safe_ip(std::string_view ip) {
    if (ip.empty() || ip.size() > 45)
        return false;
    for (char c : ip) {
        const bool ok = (c >= '0' && c <= '9') || c == '.' || c == ':' ||
                        (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!ok)
            return false;
    }
    return true;
}

// ── Windows: netsh advfirewall firewall show rule ──────────────────────────

/**
 * True iff `show_rule_output` (captured from
 * `netsh advfirewall firewall show rule name=all dir=in`) contains at least
 * one rule whose name starts with kRulePrefix. A pure substring check —
 * matches the pre-migration win_is_quarantined behaviour exactly.
 */
inline bool netsh_rules_present(std::string_view show_rule_output) {
    return show_rule_output.find(kRulePrefix) != std::string_view::npos;
}

/**
 * Every "Rule Name:" value in `show_rule_output` whose value starts with
 * kRulePrefix, deduplicated, in first-seen order. Feeds win_unquarantine's
 * delete list — netsh has no wildcard delete, so every matching name must
 * be named individually.
 */
inline std::vector<std::string> netsh_matching_rule_names(std::string_view show_rule_output) {
    std::vector<std::string> names;
    std::istringstream iss{std::string{show_rule_output}};
    std::string line;
    while (std::getline(iss, line)) {
        auto colon = line.find(':');
        if (colon == std::string::npos)
            continue;
        auto key = line.substr(0, colon);
        while (!key.empty() && key.back() == ' ')
            key.pop_back();
        if (key != "Rule Name")
            continue;
        auto val = line.substr(colon + 1);
        while (!val.empty() && val.front() == ' ')
            val.erase(val.begin());
        if (val.starts_with(kRulePrefix)) {
            bool found = false;
            for (const auto& n : names) {
                if (n == val) {
                    found = true;
                    break;
                }
            }
            if (!found)
                names.push_back(val);
        }
    }
    return names;
}

/**
 * Whitelisted IPs from an "Allow"-named YuzuQuarantine rule's RemoteIP
 * field, deduplicated, excluding loopback ("127.0.0.1") and "Any". A CIDR
 * suffix (e.g. "1.2.3.4/32") is stripped before comparison/storage. Mirrors
 * win_get_whitelist's pre-migration state-machine parse (Rule Name: /
 * RemoteIP: key lines) exactly.
 */
inline std::vector<std::string> netsh_whitelist_ips(std::string_view show_rule_output) {
    std::vector<std::string> ips;
    std::istringstream iss{std::string{show_rule_output}};
    std::string line;
    std::string current_rule;

    while (std::getline(iss, line)) {
        auto colon = line.find(':');
        if (colon == std::string::npos)
            continue;
        auto key = line.substr(0, colon);
        while (!key.empty() && key.back() == ' ')
            key.pop_back();
        auto val = line.substr(colon + 1);
        while (!val.empty() && val.front() == ' ')
            val.erase(val.begin());

        if (key == "Rule Name") {
            current_rule = val;
        } else if (key == "RemoteIP" && current_rule.starts_with(kRulePrefix) &&
                   current_rule.find("Allow") != std::string::npos) {
            if (val != "127.0.0.1" && val != "Any") {
                auto slash = val.find('/');
                if (slash != std::string::npos)
                    val = val.substr(0, slash);
                bool found = false;
                for (const auto& existing : ips) {
                    if (existing == val) {
                        found = true;
                        break;
                    }
                }
                if (!found && is_safe_ip(val))
                    ips.push_back(val);
            }
        }
    }
    return ips;
}

// ── Linux: iptables -L ──────────────────────────────────────────────────────

/**
 * True iff `list_input_output` (captured from `iptables -L INPUT -n`)
 * references the yuzu-quarantine chain — i.e. the INPUT jump rule is
 * present. Mirrors linux_is_quarantined's pre-migration substring check
 * exactly.
 */
inline bool iptables_chain_referenced(std::string_view list_input_output) {
    return list_input_output.find("yuzu-quarantine") != std::string_view::npos;
}

/**
 * Whitelisted IPs from `iptables -L yuzu-quarantine -n` output: ACCEPT
 * lines, excluding the loopback and ESTABLISHED/RELATED state rules,
 * deduplicated. Mirrors linux_get_whitelist's pre-migration column parse
 * exactly, including its known scope: iptables -L without -v does not
 * render -i/-o interface restrictions as visible text, so the "lo"
 * substring exclusion only ever matches if a captured line happens to
 * contain that substring elsewhere (see quarantine_plugin.cpp's migration
 * report for the pre-existing-behaviour note — unchanged here, not this
 * PR's scope to redesign).
 */
inline std::vector<std::string> iptables_whitelist_ips(std::string_view list_chain_output) {
    std::vector<std::string> ips;
    std::istringstream iss{std::string{list_chain_output}};
    std::string line;

    auto add_if_new = [&](const std::string& v) {
        if (v.empty() || v == "0.0.0.0/0" || !is_safe_ip(v))
            return;
        for (const auto& existing : ips) {
            if (existing == v)
                return;
        }
        ips.push_back(v);
    };

    while (std::getline(iss, line)) {
        if (line.find("ACCEPT") == std::string::npos)
            continue;
        if (line.find("lo") != std::string::npos)
            continue;
        if (line.find("state") != std::string::npos)
            continue;

        std::istringstream lss(line);
        std::string target, prot, opt, source, dest;
        lss >> target >> prot >> opt >> source >> dest;

        add_if_new(source);
        add_if_new(dest);
    }
    return ips;
}

// ── macOS: pfctl -s rules ───────────────────────────────────────────────────

/**
 * True iff the active main ruleset (captured from `pfctl -s rules`) carries
 * the load-bearing default-deny ("block all", or pfctl's canonicalized
 * "block drop all"). This is the ONLY thing macos_is_quarantined checks —
 * post-incident design writes quarantine rules directly into the main
 * ruleset (never a pf anchor); see quarantine_plugin.cpp's header comment
 * on the 672896112 production incident this design fixed.
 */
inline bool pfctl_rules_blocked(std::string_view rules_output) {
    return rules_output.find("block drop all") != std::string_view::npos ||
           rules_output.find("block all") != std::string_view::npos;
}

/**
 * Whitelisted IPs from `pfctl -s rules` output: "pass quick from <ip> to
 * any" / "pass quick from any to <ip>" lines, excluding lo0 and "any",
 * deduplicated. Mirrors macos_get_whitelist's pre-migration parse exactly.
 */
inline std::vector<std::string> pfctl_whitelist_ips(std::string_view rules_output) {
    std::vector<std::string> ips;
    std::istringstream iss{std::string{rules_output}};
    std::string line;

    auto add_if_new = [&](const std::string& v) {
        if (v == "any" || !is_safe_ip(v))
            return;
        for (const auto& existing : ips) {
            if (existing == v)
                return;
        }
        ips.push_back(v);
    };

    while (std::getline(iss, line)) {
        if (line.find("pass") == std::string::npos)
            continue;
        if (line.find("lo0") != std::string::npos)
            continue;

        auto from_pos = line.find("from ");
        if (from_pos != std::string::npos) {
            auto start = from_pos + 5;
            auto end = line.find(' ', start);
            add_if_new(line.substr(start, end - start));
        }
        auto to_pos = line.find("to ");
        if (to_pos != std::string::npos) {
            auto start = to_pos + 3;
            auto end = line.find(' ', start);
            if (end == std::string::npos)
                end = line.size();
            add_if_new(line.substr(start, end - start));
        }
    }
    return ips;
}

} // namespace yuzu::quarantine
