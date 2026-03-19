/**
 * firewall_plugin.cpp — Firewall status and rules plugin for Yuzu
 *
 * Actions:
 *   "state" — Return firewall state per profile/backend.
 *   "rules" — List firewall rules (summary).
 *
 * Output is pipe-delimited via write_output().
 */

#include <yuzu/plugin.hpp>

#include <array>
#include <cstdio>
#include <format>
#include <sstream>
#include <string>
#include <string_view>

namespace {

std::string run_command(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
#ifdef _WIN32
    FILE* pipe = _popen(cmd, "r");
#else
    FILE* pipe = popen(cmd, "r");
#endif
    if (!pipe)
        return result;
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

#ifdef _WIN32

void parse_firewall_state(yuzu::CommandContext& ctx, const std::string& output) {
    // Parse "netsh advfirewall show allprofiles state" output
    // Lines like: "State                                 ON" under profile headers
    std::istringstream iss(output);
    std::string line;
    std::string current_profile;
    while (std::getline(iss, line)) {
        if (line.find("Domain Profile") != std::string::npos) {
            current_profile = "Domain";
        } else if (line.find("Private Profile") != std::string::npos) {
            current_profile = "Private";
        } else if (line.find("Public Profile") != std::string::npos) {
            current_profile = "Public";
        } else if (!current_profile.empty() && line.find("State") != std::string::npos) {
            std::string state = "unknown";
            if (line.find("ON") != std::string::npos) {
                state = "enabled";
            } else if (line.find("OFF") != std::string::npos) {
                state = "disabled";
            }
            ctx.write_output(std::format("profile|{}|{}", current_profile, state));
            current_profile.clear();
        }
    }
}

void parse_firewall_rules(yuzu::CommandContext& ctx, const std::string& output) {
    std::istringstream iss(output);
    std::string line;
    std::string rule_name, enabled, direction, action_str, profiles;
    int count = 0;

    auto emit_rule = [&]() {
        if (!rule_name.empty() && count < 100) {
            ctx.write_output(std::format("rule|{}|{}|{}|{}|{}", rule_name, enabled, direction,
                                         action_str, profiles));
            ++count;
        }
        rule_name.clear();
        enabled.clear();
        direction.clear();
        action_str.clear();
        profiles.clear();
    };

    while (std::getline(iss, line) && count < 100) {
        if (line.empty() || line[0] == '-')
            continue;

        auto colon = line.find(':');
        if (colon == std::string::npos)
            continue;

        auto key = line.substr(0, colon);
        auto val = line.substr(colon + 1);
        // Trim whitespace
        while (!key.empty() && key.back() == ' ')
            key.pop_back();
        while (!val.empty() && val.front() == ' ')
            val.erase(val.begin());

        if (key == "Rule Name") {
            emit_rule();
            rule_name = val;
        } else if (key == "Enabled") {
            enabled = val;
        } else if (key == "Direction") {
            direction = val;
        } else if (key == "Action") {
            action_str = val;
        } else if (key == "Profiles") {
            profiles = val;
        }
    }
    emit_rule();
}

#endif

} // namespace

class FirewallPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "firewall"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Firewall status and rule listing";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"state", "rules", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {

        if (action == "state") {
#ifdef _WIN32
            auto output = run_command("netsh advfirewall show allprofiles state");
            parse_firewall_state(ctx, output);
#elif defined(__linux__)
            // Try firewalld first
            auto fw_state = run_command("firewall-cmd --state 2>/dev/null");
            if (fw_state.find("running") != std::string::npos) {
                ctx.write_output("backend|firewalld");
                ctx.write_output("state|running");
            } else {
                // Try ufw
                auto ufw_out = run_command("ufw status 2>/dev/null");
                if (ufw_out.find("active") != std::string::npos) {
                    ctx.write_output("backend|ufw");
                    ctx.write_output(
                        std::format("state|{}", ufw_out.find("Status: active") != std::string::npos
                                                    ? "active"
                                                    : "inactive"));
                } else {
                    // Try iptables
                    auto ipt = run_command("iptables -L -n 2>/dev/null");
                    if (!ipt.empty() && ipt.find("Chain") != std::string::npos) {
                        ctx.write_output("backend|iptables");
                        // Count non-header lines to determine if rules exist
                        int rule_count = 0;
                        std::istringstream iss(ipt);
                        std::string line;
                        while (std::getline(iss, line)) {
                            if (!line.empty() && line.find("Chain") == std::string::npos &&
                                line.find("target") == std::string::npos) {
                                ++rule_count;
                            }
                        }
                        ctx.write_output(
                            std::format("state|{}", rule_count > 0 ? "active" : "inactive"));
                    } else {
                        ctx.write_output("backend|none");
                        ctx.write_output("state|inactive");
                    }
                }
            }
#elif defined(__APPLE__)
            auto output = run_command("pfctl -s info 2>/dev/null");
            ctx.write_output("backend|pf");
            if (output.find("Status: Enabled") != std::string::npos) {
                ctx.write_output("state|enabled");
            } else if (output.find("Status: Disabled") != std::string::npos) {
                ctx.write_output("state|disabled");
            } else {
                ctx.write_output("state|unknown");
            }
#endif
            return 0;
        }

        if (action == "rules") {
#ifdef _WIN32
            auto output = run_command("netsh advfirewall firewall show rule name=all dir=in");
            parse_firewall_rules(ctx, output);
#elif defined(__linux__)
            auto output = run_command("firewall-cmd --list-all 2>/dev/null || "
                                      "ufw status numbered 2>/dev/null || "
                                      "iptables -L -n --line-numbers 2>/dev/null");
            std::istringstream iss(output);
            std::string line;
            while (std::getline(iss, line)) {
                if (!line.empty()) {
                    ctx.write_output(std::format("rule|{}", line));
                }
            }
#elif defined(__APPLE__)
            auto output = run_command("pfctl -s rules 2>/dev/null");
            std::istringstream iss(output);
            std::string line;
            while (std::getline(iss, line)) {
                if (!line.empty()) {
                    ctx.write_output(std::format("rule|{}", line));
                }
            }
#endif
            return 0;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(FirewallPlugin)
