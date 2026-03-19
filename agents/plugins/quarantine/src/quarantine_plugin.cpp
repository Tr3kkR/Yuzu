/**
 * quarantine_plugin.cpp — Device Quarantine (Network Isolation) plugin for Yuzu
 *
 * Actions:
 *   "quarantine"   — Isolate the device from the network, whitelisting
 *                     management server and optional IPs.
 *   "unquarantine" — Remove all quarantine firewall rules and restore access.
 *   "status"       — Check whether quarantine rules are currently active.
 *   "whitelist"    — Add or remove IPs from an active quarantine whitelist.
 *
 * Firewall rules are prefixed with "YuzuQuarantine_" for easy identification.
 * Output is pipe-delimited via write_output().
 */

#include <yuzu/plugin.hpp>

#include <array>
#include <cstdio>
#include <format>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

// ── Subprocess helpers ───────────────────────────────────────────────────────

std::string run_command(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
#ifdef _WIN32
    FILE* pipe = _popen(cmd, "r");
#else
    FILE* pipe = popen(cmd, "r");
#endif
    if (!pipe) return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
}

int run_command_rc(const char* cmd) {
#ifdef _WIN32
    FILE* pipe = _popen(cmd, "r");
#else
    FILE* pipe = popen(cmd, "r");
#endif
    if (!pipe) return -1;
    std::array<char, 256> buf{};
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {}
#ifdef _WIN32
    return _pclose(pipe);
#else
    return pclose(pipe);
#endif
}

// ── IP validation ────────────────────────────────────────────────────────────

bool is_valid_ip_char(char c) {
    return (c >= '0' && c <= '9') || c == '.' || c == ':' ||
           (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

bool is_safe_ip(std::string_view ip) {
    if (ip.empty() || ip.size() > 45) return false;
    for (char c : ip) {
        if (!is_valid_ip_char(c)) return false;
    }
    return true;
}

// ── String splitting ─────────────────────────────────────────────────────────

std::vector<std::string> split_ips(std::string_view csv) {
    std::vector<std::string> ips;
    std::istringstream iss{std::string{csv}};
    std::string token;
    while (std::getline(iss, token, ',')) {
        // Trim whitespace
        while (!token.empty() && token.front() == ' ') token.erase(token.begin());
        while (!token.empty() && token.back() == ' ')  token.pop_back();
        if (!token.empty() && is_safe_ip(token)) {
            ips.push_back(std::move(token));
        }
    }
    return ips;
}

std::string join_ips(const std::vector<std::string>& ips) {
    std::string result;
    for (size_t i = 0; i < ips.size(); ++i) {
        if (i > 0) result += ',';
        result += ips[i];
    }
    return result;
}

// ── Rule name prefix ─────────────────────────────────────────────────────────

constexpr const char* kRulePrefix = "YuzuQuarantine_";

// ── Windows implementation ───────────────────────────────────────────────────

#ifdef _WIN32

int win_quarantine(yuzu::CommandContext& ctx,
                   const std::vector<std::string>& whitelist_ips) {
    int rules_applied = 0;

    // Block all inbound traffic
    auto cmd = std::format(
        "netsh advfirewall firewall add rule name=\"{}BlockAllInbound\" "
        "dir=in action=block enable=yes protocol=any", kRulePrefix);
    if (run_command_rc(cmd.c_str()) == 0) ++rules_applied;

    // Block all outbound traffic
    cmd = std::format(
        "netsh advfirewall firewall add rule name=\"{}BlockAllOutbound\" "
        "dir=out action=block enable=yes protocol=any", kRulePrefix);
    if (run_command_rc(cmd.c_str()) == 0) ++rules_applied;

    // Allow loopback inbound
    cmd = std::format(
        "netsh advfirewall firewall add rule name=\"{}AllowLoopbackIn\" "
        "dir=in action=allow enable=yes remoteip=127.0.0.1", kRulePrefix);
    if (run_command_rc(cmd.c_str()) == 0) ++rules_applied;

    // Allow loopback outbound
    cmd = std::format(
        "netsh advfirewall firewall add rule name=\"{}AllowLoopbackOut\" "
        "dir=out action=allow enable=yes remoteip=127.0.0.1", kRulePrefix);
    if (run_command_rc(cmd.c_str()) == 0) ++rules_applied;

    // Allow each whitelisted IP (inbound + outbound)
    for (const auto& ip : whitelist_ips) {
        cmd = std::format(
            "netsh advfirewall firewall add rule name=\"{}AllowIn_{}\" "
            "dir=in action=allow enable=yes remoteip={}", kRulePrefix, ip, ip);
        if (run_command_rc(cmd.c_str()) == 0) ++rules_applied;

        cmd = std::format(
            "netsh advfirewall firewall add rule name=\"{}AllowOut_{}\" "
            "dir=out action=allow enable=yes remoteip={}", kRulePrefix, ip, ip);
        if (run_command_rc(cmd.c_str()) == 0) ++rules_applied;
    }

    ctx.write_output(std::format("status|quarantined|rules_applied|{}", rules_applied));
    return 0;
}

int win_unquarantine(yuzu::CommandContext& ctx) {
    // Delete all rules whose name starts with the prefix
    // netsh does not support wildcards, so we list rules and delete matches.
    auto output = run_command(
        "netsh advfirewall firewall show rule name=all dir=in");
    // Also grab outbound rules
    auto output_out = run_command(
        "netsh advfirewall firewall show rule name=all dir=out");
    output += "\n" + output_out;

    std::istringstream iss(output);
    std::string line;
    std::vector<std::string> rules_to_delete;

    while (std::getline(iss, line)) {
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        auto key = line.substr(0, colon);
        while (!key.empty() && key.back() == ' ') key.pop_back();
        if (key != "Rule Name") continue;
        auto val = line.substr(colon + 1);
        while (!val.empty() && val.front() == ' ') val.erase(val.begin());
        if (val.starts_with(kRulePrefix)) {
            // Avoid duplicates
            bool found = false;
            for (const auto& r : rules_to_delete) {
                if (r == val) { found = true; break; }
            }
            if (!found) rules_to_delete.push_back(val);
        }
    }

    for (const auto& rule : rules_to_delete) {
        auto cmd = std::format(
            "netsh advfirewall firewall delete rule name=\"{}\"", rule);
        run_command_rc(cmd.c_str());
    }

    ctx.write_output("status|released");
    return 0;
}

bool win_is_quarantined() {
    auto output = run_command(
        "netsh advfirewall firewall show rule name=all dir=in");
    return output.find(kRulePrefix) != std::string::npos;
}

std::vector<std::string> win_get_whitelist() {
    std::vector<std::string> ips;
    auto output = run_command(
        "netsh advfirewall firewall show rule name=all dir=in");
    std::istringstream iss(output);
    std::string line;
    std::string current_rule;

    while (std::getline(iss, line)) {
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        auto key = line.substr(0, colon);
        while (!key.empty() && key.back() == ' ') key.pop_back();
        auto val = line.substr(colon + 1);
        while (!val.empty() && val.front() == ' ') val.erase(val.begin());

        if (key == "Rule Name") {
            current_rule = val;
        } else if (key == "RemoteIP" && current_rule.starts_with(kRulePrefix) &&
                   current_rule.find("Allow") != std::string::npos) {
            if (val != "127.0.0.1" && val != "Any") {
                // Remove CIDR suffix if present (e.g., "1.2.3.4/32")
                auto slash = val.find('/');
                if (slash != std::string::npos) val = val.substr(0, slash);
                bool found = false;
                for (const auto& existing : ips) {
                    if (existing == val) { found = true; break; }
                }
                if (!found && is_safe_ip(val)) ips.push_back(val);
            }
        }
    }
    return ips;
}

#endif // _WIN32

// ── Linux implementation ─────────────────────────────────────────────────────

#ifdef __linux__

int linux_quarantine(yuzu::CommandContext& ctx,
                     const std::vector<std::string>& whitelist_ips) {
    int rules_applied = 0;

    // Create the yuzu-quarantine chain (ignore error if it already exists)
    run_command_rc("iptables -N yuzu-quarantine 2>/dev/null");
    // Flush the chain to start fresh
    run_command_rc("iptables -F yuzu-quarantine");

    // Allow loopback
    if (run_command_rc("iptables -A yuzu-quarantine -i lo -j ACCEPT") == 0)
        ++rules_applied;
    if (run_command_rc("iptables -A yuzu-quarantine -o lo -j ACCEPT") == 0)
        ++rules_applied;

    // Allow established/related connections (keeps management connection alive)
    if (run_command_rc(
            "iptables -A yuzu-quarantine -m state --state ESTABLISHED,RELATED -j ACCEPT") == 0)
        ++rules_applied;

    // Allow each whitelisted IP
    for (const auto& ip : whitelist_ips) {
        auto cmd = std::format(
            "iptables -A yuzu-quarantine -s {} -j ACCEPT", ip);
        if (run_command_rc(cmd.c_str()) == 0) ++rules_applied;

        cmd = std::format(
            "iptables -A yuzu-quarantine -d {} -j ACCEPT", ip);
        if (run_command_rc(cmd.c_str()) == 0) ++rules_applied;
    }

    // Drop everything else
    if (run_command_rc("iptables -A yuzu-quarantine -j DROP") == 0)
        ++rules_applied;

    // Insert jump to our chain at the top of INPUT and OUTPUT
    // Remove any existing jumps first to avoid duplicates
    run_command_rc("iptables -D INPUT -j yuzu-quarantine 2>/dev/null");
    run_command_rc("iptables -D OUTPUT -j yuzu-quarantine 2>/dev/null");
    if (run_command_rc("iptables -I INPUT 1 -j yuzu-quarantine") == 0)
        ++rules_applied;
    if (run_command_rc("iptables -I OUTPUT 1 -j yuzu-quarantine") == 0)
        ++rules_applied;

    ctx.write_output(std::format("status|quarantined|rules_applied|{}", rules_applied));
    return 0;
}

int linux_unquarantine(yuzu::CommandContext& ctx) {
    // Remove jumps from INPUT and OUTPUT
    run_command_rc("iptables -D INPUT -j yuzu-quarantine 2>/dev/null");
    run_command_rc("iptables -D OUTPUT -j yuzu-quarantine 2>/dev/null");
    // Flush and delete the chain
    run_command_rc("iptables -F yuzu-quarantine 2>/dev/null");
    run_command_rc("iptables -X yuzu-quarantine 2>/dev/null");

    ctx.write_output("status|released");
    return 0;
}

bool linux_is_quarantined() {
    auto output = run_command("iptables -L INPUT -n 2>/dev/null");
    return output.find("yuzu-quarantine") != std::string::npos;
}

std::vector<std::string> linux_get_whitelist() {
    std::vector<std::string> ips;
    auto output = run_command("iptables -L yuzu-quarantine -n 2>/dev/null");
    std::istringstream iss(output);
    std::string line;

    while (std::getline(iss, line)) {
        // Skip header lines and DROP/loopback rules
        if (line.find("ACCEPT") == std::string::npos) continue;
        if (line.find("lo") != std::string::npos) continue;
        if (line.find("state") != std::string::npos) continue;

        // Parse source/destination from iptables output
        // Typical line: "ACCEPT  all  --  1.2.3.4  0.0.0.0/0"
        std::istringstream lss(line);
        std::string target, prot, opt, source, dest;
        lss >> target >> prot >> opt >> source >> dest;

        if (!source.empty() && source != "0.0.0.0/0" && is_safe_ip(source)) {
            bool found = false;
            for (const auto& existing : ips) {
                if (existing == source) { found = true; break; }
            }
            if (!found) ips.push_back(source);
        }
        if (!dest.empty() && dest != "0.0.0.0/0" && is_safe_ip(dest)) {
            bool found = false;
            for (const auto& existing : ips) {
                if (existing == dest) { found = true; break; }
            }
            if (!found) ips.push_back(dest);
        }
    }
    return ips;
}

#endif // __linux__

// ── macOS implementation ─────────────────────────────────────────────────────

#ifdef __APPLE__

int macos_quarantine(yuzu::CommandContext& ctx,
                     const std::vector<std::string>& whitelist_ips) {
    int rules_applied = 0;

    // Build pf anchor rules
    std::string rules;

    // Allow loopback
    rules += "pass quick on lo0 all\n";
    ++rules_applied;

    // Allow whitelisted IPs
    for (const auto& ip : whitelist_ips) {
        rules += std::format("pass quick from {} to any\n", ip);
        rules += std::format("pass quick from any to {}\n", ip);
        rules_applied += 2;
    }

    // Block everything else
    rules += "block all\n";
    ++rules_applied;

    // Write rules to a temporary file
    auto tmp_path = std::string{"/tmp/yuzu_quarantine_anchor.conf"};
    {
        auto cmd = std::format(
            "printf '%s' '{}' > {}", rules, tmp_path);
        // Use a safer write approach
        FILE* f = fopen(tmp_path.c_str(), "w");
        if (f) {
            fputs(rules.c_str(), f);
            fclose(f);
        } else {
            ctx.write_output("error|failed to write pf anchor rules");
            return 1;
        }
    }

    // Load the anchor
    auto cmd = std::format("pfctl -a yuzu-quarantine -f {} 2>/dev/null", tmp_path);
    run_command_rc(cmd.c_str());

    // Ensure pf is enabled
    run_command_rc("pfctl -e 2>/dev/null");

    // Add anchor reference to the main ruleset if not present
    auto pf_conf = run_command("pfctl -s rules 2>/dev/null");
    if (pf_conf.find("yuzu-quarantine") == std::string::npos) {
        // Append anchor reference
        run_command_rc(
            "echo 'anchor \"yuzu-quarantine\"' | pfctl -f - 2>/dev/null");
    }

    ctx.write_output(std::format("status|quarantined|rules_applied|{}", rules_applied));
    return 0;
}

int macos_unquarantine(yuzu::CommandContext& ctx) {
    // Flush the anchor rules
    run_command_rc("pfctl -a yuzu-quarantine -F all 2>/dev/null");

    ctx.write_output("status|released");
    return 0;
}

bool macos_is_quarantined() {
    auto output = run_command("pfctl -a yuzu-quarantine -s rules 2>/dev/null");
    // If the anchor has rules, quarantine is active
    return !output.empty() && output.find("block") != std::string::npos;
}

std::vector<std::string> macos_get_whitelist() {
    std::vector<std::string> ips;
    auto output = run_command("pfctl -a yuzu-quarantine -s rules 2>/dev/null");
    std::istringstream iss(output);
    std::string line;

    while (std::getline(iss, line)) {
        if (line.find("pass") == std::string::npos) continue;
        if (line.find("lo0") != std::string::npos) continue;

        // Parse IP from "pass quick from <ip> to any" or "pass quick from any to <ip>"
        auto from_pos = line.find("from ");
        auto to_pos   = line.find("to ");
        if (from_pos != std::string::npos) {
            auto start = from_pos + 5;
            auto end   = line.find(' ', start);
            auto ip    = line.substr(start, end - start);
            if (ip != "any" && is_safe_ip(ip)) {
                bool found = false;
                for (const auto& existing : ips) {
                    if (existing == ip) { found = true; break; }
                }
                if (!found) ips.push_back(ip);
            }
        }
        if (to_pos != std::string::npos) {
            auto start = to_pos + 3;
            auto end   = line.find(' ', start);
            if (end == std::string::npos) end = line.size();
            auto ip = line.substr(start, end - start);
            if (ip != "any" && is_safe_ip(ip)) {
                bool found = false;
                for (const auto& existing : ips) {
                    if (existing == ip) { found = true; break; }
                }
                if (!found) ips.push_back(ip);
            }
        }
    }
    return ips;
}

#endif // __APPLE__

} // namespace

// ── Plugin class ─────────────────────────────────────────────────────────────

class QuarantinePlugin final : public yuzu::Plugin {
public:
    std::string_view name()        const noexcept override { return kName; }
    std::string_view version()     const noexcept override { return kVersion; }
    std::string_view description() const noexcept override {
        return "Device network isolation (quarantine) with per-IP whitelisting";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {
            "quarantine", "unquarantine", "status", "whitelist", nullptr
        };
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx,
                std::string_view action,
                yuzu::Params params) override {

        if (action == "quarantine") {
            return do_quarantine(ctx, params);
        }
        if (action == "unquarantine") {
            return do_unquarantine(ctx);
        }
        if (action == "status") {
            return do_status(ctx);
        }
        if (action == "whitelist") {
            return do_whitelist(ctx, params);
        }

        ctx.write_output(std::format("error|unknown action: {}", action));
        return 1;
    }

private:
    static constexpr const char* kName    = "quarantine";
    static constexpr const char* kVersion = "1.0.0";

    // ── quarantine action ────────────────────────────────────────────────────

    int do_quarantine(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto server_ip     = params.get("server_ip");
        auto whitelist_csv = params.get("whitelist_ips");

        // Build the full whitelist: always include loopback + management server
        std::vector<std::string> whitelist;

        if (!server_ip.empty() && is_safe_ip(server_ip)) {
            whitelist.emplace_back(server_ip);
        }

        auto extra = split_ips(whitelist_csv);
        for (auto& ip : extra) {
            // Avoid duplicates with server_ip
            bool dup = false;
            for (const auto& existing : whitelist) {
                if (existing == ip) { dup = true; break; }
            }
            if (!dup) whitelist.push_back(std::move(ip));
        }

#ifdef _WIN32
        return win_quarantine(ctx, whitelist);
#elif defined(__linux__)
        return linux_quarantine(ctx, whitelist);
#elif defined(__APPLE__)
        return macos_quarantine(ctx, whitelist);
#else
        ctx.write_output("error|unsupported platform");
        return 1;
#endif
    }

    // ── unquarantine action ──────────────────────────────────────────────────

    int do_unquarantine(yuzu::CommandContext& ctx) {
#ifdef _WIN32
        return win_unquarantine(ctx);
#elif defined(__linux__)
        return linux_unquarantine(ctx);
#elif defined(__APPLE__)
        return macos_unquarantine(ctx);
#else
        ctx.write_output("error|unsupported platform");
        return 1;
#endif
    }

    // ── status action ────────────────────────────────────────────────────────

    int do_status(yuzu::CommandContext& ctx) {
#ifdef _WIN32
        bool active = win_is_quarantined();
#elif defined(__linux__)
        bool active = linux_is_quarantined();
#elif defined(__APPLE__)
        bool active = macos_is_quarantined();
#else
        ctx.write_output("error|unsupported platform");
        return 1;
#endif
        ctx.write_output(std::format("state|{}", active ? "active" : "inactive"));

        if (active) {
#ifdef _WIN32
            auto ips = win_get_whitelist();
#elif defined(__linux__)
            auto ips = linux_get_whitelist();
#elif defined(__APPLE__)
            auto ips = macos_get_whitelist();
#endif
            ctx.write_output(std::format("whitelist|{}", join_ips(ips)));
        }

        return 0;
    }

    // ── whitelist action ─────────────────────────────────────────────────────

    int do_whitelist(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto action_param = params.get("action");
        auto ips_csv      = params.get("ips");

        if (action_param.empty()) {
            ctx.write_output("error|missing required parameter: action (add/remove)");
            return 1;
        }
        if (ips_csv.empty()) {
            ctx.write_output("error|missing required parameter: ips");
            return 1;
        }

        auto new_ips = split_ips(ips_csv);
        if (new_ips.empty()) {
            ctx.write_output("error|no valid IPs provided");
            return 1;
        }

        if (action_param == "add") {
#ifdef _WIN32
            for (const auto& ip : new_ips) {
                auto cmd = std::format(
                    "netsh advfirewall firewall add rule name=\"{}AllowIn_{}\" "
                    "dir=in action=allow enable=yes remoteip={}", kRulePrefix, ip, ip);
                run_command_rc(cmd.c_str());
                cmd = std::format(
                    "netsh advfirewall firewall add rule name=\"{}AllowOut_{}\" "
                    "dir=out action=allow enable=yes remoteip={}", kRulePrefix, ip, ip);
                run_command_rc(cmd.c_str());
            }
#elif defined(__linux__)
            for (const auto& ip : new_ips) {
                // Insert before the DROP rule (second-to-last position)
                auto cmd = std::format(
                    "iptables -I yuzu-quarantine -s {} -j ACCEPT", ip);
                run_command_rc(cmd.c_str());
                cmd = std::format(
                    "iptables -I yuzu-quarantine -d {} -j ACCEPT", ip);
                run_command_rc(cmd.c_str());
            }
#elif defined(__APPLE__)
            // Re-read current rules and append new ones
            for (const auto& ip : new_ips) {
                auto cmd = std::format(
                    "echo 'pass quick from {} to any\npass quick from any to {}' | "
                    "pfctl -a yuzu-quarantine -f - 2>/dev/null", ip, ip);
                run_command_rc(cmd.c_str());
            }
#else
            ctx.write_output("error|unsupported platform");
            return 1;
#endif
        } else if (action_param == "remove") {
#ifdef _WIN32
            for (const auto& ip : new_ips) {
                auto cmd = std::format(
                    "netsh advfirewall firewall delete rule name=\"{}AllowIn_{}\"",
                    kRulePrefix, ip);
                run_command_rc(cmd.c_str());
                cmd = std::format(
                    "netsh advfirewall firewall delete rule name=\"{}AllowOut_{}\"",
                    kRulePrefix, ip);
                run_command_rc(cmd.c_str());
            }
#elif defined(__linux__)
            for (const auto& ip : new_ips) {
                auto cmd = std::format(
                    "iptables -D yuzu-quarantine -s {} -j ACCEPT 2>/dev/null", ip);
                run_command_rc(cmd.c_str());
                cmd = std::format(
                    "iptables -D yuzu-quarantine -d {} -j ACCEPT 2>/dev/null", ip);
                run_command_rc(cmd.c_str());
            }
#elif defined(__APPLE__)
            // Removing individual pf rules requires rewriting the anchor.
            // Read current rules, filter out the IPs, and reload.
            auto current = run_command(
                "pfctl -a yuzu-quarantine -s rules 2>/dev/null");
            std::string filtered;
            std::istringstream iss(current);
            std::string line;
            while (std::getline(iss, line)) {
                bool skip = false;
                for (const auto& ip : new_ips) {
                    if (line.find(ip) != std::string::npos) {
                        skip = true;
                        break;
                    }
                }
                if (!skip) {
                    filtered += line + "\n";
                }
            }
            FILE* f = fopen("/tmp/yuzu_quarantine_anchor.conf", "w");
            if (f) {
                fputs(filtered.c_str(), f);
                fclose(f);
                run_command_rc(
                    "pfctl -a yuzu-quarantine -f /tmp/yuzu_quarantine_anchor.conf 2>/dev/null");
            }
#else
            ctx.write_output("error|unsupported platform");
            return 1;
#endif
        } else {
            ctx.write_output(
                std::format("error|invalid action '{}', expected 'add' or 'remove'",
                            action_param));
            return 1;
        }

        // Report current whitelist
#ifdef _WIN32
        auto current_ips = win_get_whitelist();
#elif defined(__linux__)
        auto current_ips = linux_get_whitelist();
#elif defined(__APPLE__)
        auto current_ips = macos_get_whitelist();
#else
        std::vector<std::string> current_ips;
#endif
        ctx.write_output(std::format("status|updated|whitelist|{}", join_ips(current_ips)));
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(QuarantinePlugin)
