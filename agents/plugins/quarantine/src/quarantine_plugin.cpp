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

#ifndef _WIN32
#include <sys/wait.h> // WIFEXITED / WEXITSTATUS — interpret popen()'s return value
#include <unistd.h>   // geteuid() — privilege detection for sudo prefix
#endif

namespace {

// ── Privilege escalation helper (Unix only) ──────────────────────────────────
//
// The agent runs as a dedicated unprivileged account (`_yuzu` on macOS,
// `yuzu` on Linux — see docs/agent-privilege-model.md). Plugins that need
// privileged operations shell out via narrow `sudo NOPASSWD` entries
// installed by scripts/install-agent-user.sh. This helper returns the
// prefix to glue in front of the binary path.
//
//   - When EUID is 0 (test/dev runs that launched the agent as root):
//     returns "" so we don't have a useless sudo round-trip.
//   - Otherwise (production / properly-installed dev): returns "sudo -n ".
//     The `-n` is critical: non-interactive mode makes sudo fail
//     immediately with a useful error if the sudoers grant is missing,
//     rather than blocking the daemon waiting on a password prompt
//     it can't answer.
//
// The result is cached on first call — EUID can't change during the
// agent's lifetime, so this is a const for all practical purposes.
//
// Windows takes a different path entirely: the YuzuAgent service account
// carries SeAssignPrimaryTokenPrivilege + Administrators membership,
// granted at install time via LsaAddAccountRights. The Windows code
// blocks below shell out to `netsh` directly — no sudo equivalent.

#ifndef _WIN32
const char* sudo_prefix() {
    static const char* prefix = (geteuid() == 0) ? "" : "sudo -n ";
    return prefix;
}
#endif

// Absolute paths to firewall binaries. These MUST match the paths in
// the sudoers grants — see scripts/install-agent-user.sh
// generate_sudoers_content(). PATH-injection bypass would be possible
// with bare names: an attacker who got code execution as the agent
// could prepend a directory to $PATH containing a malicious `iptables`,
// and the sudoers entry `/usr/sbin/iptables` would happily run that
// instead. Absolute paths in the shell-out close that gap.
//
// If a future distro ships these binaries somewhere else (`/sbin/iptables`
// on a few older Linuxes, `/opt/homebrew/sbin/pfctl` on a developer's
// custom box), update both sides — the constant here AND the sudoers
// entry generator.

#ifdef __APPLE__
constexpr const char* kPfctl = "/sbin/pfctl";
#endif
#ifdef __linux__
constexpr const char* kIptables = "/usr/sbin/iptables";
#endif

// ── Subprocess helpers ───────────────────────────────────────────────────────

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

int run_command_rc(const char* cmd) {
#ifdef _WIN32
    FILE* pipe = _popen(cmd, "r");
#else
    FILE* pipe = popen(cmd, "r");
#endif
    if (!pipe)
        return -1;
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
    return (c >= '0' && c <= '9') || c == '.' || c == ':' || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

bool is_safe_ip(std::string_view ip) {
    if (ip.empty() || ip.size() > 45)
        return false;
    for (char c : ip) {
        if (!is_valid_ip_char(c))
            return false;
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
        while (!token.empty() && token.front() == ' ')
            token.erase(token.begin());
        while (!token.empty() && token.back() == ' ')
            token.pop_back();
        if (!token.empty() && is_safe_ip(token)) {
            ips.push_back(std::move(token));
        }
    }
    return ips;
}

std::string join_ips(const std::vector<std::string>& ips) {
    std::string result;
    for (size_t i = 0; i < ips.size(); ++i) {
        if (i > 0)
            result += ',';
        result += ips[i];
    }
    return result;
}

// ── Rule name prefix ─────────────────────────────────────────────────────────

constexpr const char* kRulePrefix = "YuzuQuarantine_";

// ── Windows implementation ───────────────────────────────────────────────────

#ifdef _WIN32

int win_quarantine(yuzu::CommandContext& ctx, const std::vector<std::string>& whitelist_ips) {
    int rules_applied = 0;

    // Block all inbound traffic
    auto cmd = std::format("netsh advfirewall firewall add rule name=\"{}BlockAllInbound\" "
                           "dir=in action=block enable=yes protocol=any",
                           kRulePrefix);
    if (run_command_rc(cmd.c_str()) == 0)
        ++rules_applied;

    // Block all outbound traffic
    cmd = std::format("netsh advfirewall firewall add rule name=\"{}BlockAllOutbound\" "
                      "dir=out action=block enable=yes protocol=any",
                      kRulePrefix);
    if (run_command_rc(cmd.c_str()) == 0)
        ++rules_applied;

    // Allow loopback inbound
    cmd = std::format("netsh advfirewall firewall add rule name=\"{}AllowLoopbackIn\" "
                      "dir=in action=allow enable=yes remoteip=127.0.0.1",
                      kRulePrefix);
    if (run_command_rc(cmd.c_str()) == 0)
        ++rules_applied;

    // Allow loopback outbound
    cmd = std::format("netsh advfirewall firewall add rule name=\"{}AllowLoopbackOut\" "
                      "dir=out action=allow enable=yes remoteip=127.0.0.1",
                      kRulePrefix);
    if (run_command_rc(cmd.c_str()) == 0)
        ++rules_applied;

    // Allow each whitelisted IP (inbound + outbound)
    for (const auto& ip : whitelist_ips) {
        cmd = std::format("netsh advfirewall firewall add rule name=\"{}AllowIn_{}\" "
                          "dir=in action=allow enable=yes remoteip={}",
                          kRulePrefix, ip, ip);
        if (run_command_rc(cmd.c_str()) == 0)
            ++rules_applied;

        cmd = std::format("netsh advfirewall firewall add rule name=\"{}AllowOut_{}\" "
                          "dir=out action=allow enable=yes remoteip={}",
                          kRulePrefix, ip, ip);
        if (run_command_rc(cmd.c_str()) == 0)
            ++rules_applied;
    }

    ctx.write_output(std::format("status|quarantined|rules_applied|{}", rules_applied));
    return 0;
}

int win_unquarantine(yuzu::CommandContext& ctx) {
    // Delete all rules whose name starts with the prefix
    // netsh does not support wildcards, so we list rules and delete matches.
    auto output = run_command("netsh advfirewall firewall show rule name=all dir=in");
    // Also grab outbound rules
    auto output_out = run_command("netsh advfirewall firewall show rule name=all dir=out");
    output += "\n" + output_out;

    std::istringstream iss(output);
    std::string line;
    std::vector<std::string> rules_to_delete;

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
            // Avoid duplicates
            bool found = false;
            for (const auto& r : rules_to_delete) {
                if (r == val) {
                    found = true;
                    break;
                }
            }
            if (!found)
                rules_to_delete.push_back(val);
        }
    }

    for (const auto& rule : rules_to_delete) {
        auto cmd = std::format("netsh advfirewall firewall delete rule name=\"{}\"", rule);
        run_command_rc(cmd.c_str());
    }

    ctx.write_output("status|released");
    return 0;
}

bool win_is_quarantined() {
    auto output = run_command("netsh advfirewall firewall show rule name=all dir=in");
    return output.find(kRulePrefix) != std::string::npos;
}

std::vector<std::string> win_get_whitelist() {
    std::vector<std::string> ips;
    auto output = run_command("netsh advfirewall firewall show rule name=all dir=in");
    std::istringstream iss(output);
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
                // Remove CIDR suffix if present (e.g., "1.2.3.4/32")
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

#endif // _WIN32

// ── Linux implementation ─────────────────────────────────────────────────────

#ifdef __linux__

int linux_quarantine(yuzu::CommandContext& ctx, const std::vector<std::string>& whitelist_ips) {
    int rules_applied = 0;
    const auto* pfx = sudo_prefix();

    // Create the yuzu-quarantine chain (ignore error if it already exists)
    auto cmd = std::format("{}{} -N yuzu-quarantine 2>/dev/null", pfx, kIptables);
    run_command_rc(cmd.c_str());
    // Flush the chain to start fresh
    cmd = std::format("{}{} -F yuzu-quarantine", pfx, kIptables);
    run_command_rc(cmd.c_str());

    // Allow loopback
    cmd = std::format("{}{} -A yuzu-quarantine -i lo -j ACCEPT", pfx, kIptables);
    if (run_command_rc(cmd.c_str()) == 0)
        ++rules_applied;
    cmd = std::format("{}{} -A yuzu-quarantine -o lo -j ACCEPT", pfx, kIptables);
    if (run_command_rc(cmd.c_str()) == 0)
        ++rules_applied;

    // Allow established/related connections (keeps management connection alive)
    cmd = std::format("{}{} -A yuzu-quarantine -m state --state ESTABLISHED,RELATED -j ACCEPT", pfx,
                      kIptables);
    if (run_command_rc(cmd.c_str()) == 0)
        ++rules_applied;

    // Allow each whitelisted IP
    for (const auto& ip : whitelist_ips) {
        cmd = std::format("{}{} -A yuzu-quarantine -s {} -j ACCEPT", pfx, kIptables, ip);
        if (run_command_rc(cmd.c_str()) == 0)
            ++rules_applied;

        cmd = std::format("{}{} -A yuzu-quarantine -d {} -j ACCEPT", pfx, kIptables, ip);
        if (run_command_rc(cmd.c_str()) == 0)
            ++rules_applied;
    }

    // Drop everything else
    cmd = std::format("{}{} -A yuzu-quarantine -j DROP", pfx, kIptables);
    if (run_command_rc(cmd.c_str()) == 0)
        ++rules_applied;

    // Insert jump to our chain at the top of INPUT and OUTPUT
    // Remove any existing jumps first to avoid duplicates
    cmd = std::format("{}{} -D INPUT -j yuzu-quarantine 2>/dev/null", pfx, kIptables);
    run_command_rc(cmd.c_str());
    cmd = std::format("{}{} -D OUTPUT -j yuzu-quarantine 2>/dev/null", pfx, kIptables);
    run_command_rc(cmd.c_str());
    cmd = std::format("{}{} -I INPUT 1 -j yuzu-quarantine", pfx, kIptables);
    if (run_command_rc(cmd.c_str()) == 0)
        ++rules_applied;
    cmd = std::format("{}{} -I OUTPUT 1 -j yuzu-quarantine", pfx, kIptables);
    if (run_command_rc(cmd.c_str()) == 0)
        ++rules_applied;

    ctx.write_output(std::format("status|quarantined|rules_applied|{}", rules_applied));
    return 0;
}

int linux_unquarantine(yuzu::CommandContext& ctx) {
    const auto* pfx = sudo_prefix();
    // Remove jumps from INPUT and OUTPUT
    auto cmd = std::format("{}{} -D INPUT -j yuzu-quarantine 2>/dev/null", pfx, kIptables);
    run_command_rc(cmd.c_str());
    cmd = std::format("{}{} -D OUTPUT -j yuzu-quarantine 2>/dev/null", pfx, kIptables);
    run_command_rc(cmd.c_str());
    // Flush and delete the chain
    cmd = std::format("{}{} -F yuzu-quarantine 2>/dev/null", pfx, kIptables);
    run_command_rc(cmd.c_str());
    cmd = std::format("{}{} -X yuzu-quarantine 2>/dev/null", pfx, kIptables);
    run_command_rc(cmd.c_str());

    ctx.write_output("status|released");
    return 0;
}

bool linux_is_quarantined() {
    // -L is a read-only list operation; depending on the distro and kernel
    // build, iptables will refuse the operation without root even for
    // listing because /proc/net/ip_tables_names is root-readable. So we
    // also use sudo for the read path.
    auto cmd = std::format("{}{} -L INPUT -n 2>/dev/null", sudo_prefix(), kIptables);
    auto output = run_command(cmd.c_str());
    return output.find("yuzu-quarantine") != std::string::npos;
}

std::vector<std::string> linux_get_whitelist() {
    std::vector<std::string> ips;
    auto cmd = std::format("{}{} -L yuzu-quarantine -n 2>/dev/null", sudo_prefix(), kIptables);
    auto output = run_command(cmd.c_str());
    std::istringstream iss(output);
    std::string line;

    while (std::getline(iss, line)) {
        // Skip header lines and DROP/loopback rules
        if (line.find("ACCEPT") == std::string::npos)
            continue;
        if (line.find("lo") != std::string::npos)
            continue;
        if (line.find("state") != std::string::npos)
            continue;

        // Parse source/destination from iptables output
        // Typical line: "ACCEPT  all  --  1.2.3.4  0.0.0.0/0"
        std::istringstream lss(line);
        std::string target, prot, opt, source, dest;
        lss >> target >> prot >> opt >> source >> dest;

        if (!source.empty() && source != "0.0.0.0/0" && is_safe_ip(source)) {
            bool found = false;
            for (const auto& existing : ips) {
                if (existing == source) {
                    found = true;
                    break;
                }
            }
            if (!found)
                ips.push_back(source);
        }
        if (!dest.empty() && dest != "0.0.0.0/0" && is_safe_ip(dest)) {
            bool found = false;
            for (const auto& existing : ips) {
                if (existing == dest) {
                    found = true;
                    break;
                }
            }
            if (!found)
                ips.push_back(dest);
        }
    }
    return ips;
}

#endif // __linux__

// ── macOS implementation ─────────────────────────────────────────────────────

#ifdef __APPLE__

int macos_quarantine(yuzu::CommandContext& ctx, const std::vector<std::string>& whitelist_ips) {
    // rules_written counts the lines we hand to pfctl. The actual number
    // of rules installed in pf is reported back to the operator only if
    // pfctl's load succeeds (see the rc check after run_command_rc below).
    // Pre-patch behaviour was to increment this counter unconditionally
    // and report it as `rules_applied`, which lied about success when
    // pfctl was rejected (e.g., agent not in sudoers). Now: any load
    // failure returns `error|...` instead of a falsely-positive count.
    int rules_written = 0;
    const auto* pfx = sudo_prefix();

    // Build pf anchor rules
    std::string rules;

    // Allow loopback
    rules += "pass quick on lo0 all\n";
    ++rules_written;

    // Allow whitelisted IPs
    for (const auto& ip : whitelist_ips) {
        rules += std::format("pass quick from {} to any\n", ip);
        rules += std::format("pass quick from any to {}\n", ip);
        rules_written += 2;
    }

    // Block everything else
    rules += "block all\n";
    ++rules_written;

    // Write rules to a securely-created temp file. We deliberately avoid
    // a predictable path like /tmp/yuzu_quarantine_anchor.conf because:
    //
    //   - Any local user can pre-create that path as a symlink pointing
    //     at /etc/pf.conf (or any other root-owned file), and the agent
    //     would then overwrite it under sudo via `sudo /sbin/pfctl -f`
    //     after we wrote our content. mkstemp()-based TempFile generates
    //     an unpredictable suffix and uses O_CREAT|O_EXCL so we can't
    //     follow a pre-existing symlink.
    //   - When the agent ran as root the attacker had to be root to
    //     win the race; once the agent runs as `_yuzu` (per
    //     docs/agent-privilege-model.md) the bar is just "any local user".
    //
    // The TempFile RAII destructor cleans up when the function returns.
    auto tmp_file_result = yuzu::TempFile::create("yuzu-quarantine-anchor-", ".conf");
    if (!tmp_file_result) {
        ctx.write_output("error|failed to create temp file for pf anchor rules");
        return 1;
    }
    auto tmp_file = std::move(*tmp_file_result);
    {
        FILE* f = fopen(tmp_file.path().c_str(), "w");
        if (f) {
            fputs(rules.c_str(), f);
            fclose(f);
        } else {
            ctx.write_output("error|failed to write pf anchor rules");
            return 1;
        }
    }

    // Load the anchor. We DO NOT swallow stderr here (no `2>/dev/null`)
    // because that's the channel sudo uses for permission errors —
    // diagnostic messages we want surfaced. popen()'s read side is stdout
    // only by default, but `2>&1` would interleave them. We accept the
    // trade-off of stderr going to the agent's terminal: the load_rc
    // below is the load-bearing signal, and the response carries the
    // operator-actionable note.
    auto cmd = std::format("{}{} -a yuzu-quarantine -f {}", pfx, kPfctl, tmp_file.path());
    int load_rc = run_command_rc(cmd.c_str());
    if (load_rc != 0) {
        // popen(3) returns the wait(2) status — extract the exit code if
        // it was a normal exit. Most failures here are sudo refusing
        // (exit 1) or pfctl rejecting the rules file (exit 1 or 255).
        int exit_code = WIFEXITED(load_rc) ? WEXITSTATUS(load_rc) : load_rc;
        ctx.write_output(std::format("error|pfctl load failed (rc={}). Likely the agent account "
                                     "is not in /etc/sudoers.d/yuzu-agent — run "
                                     "`sudo bash scripts/install-agent-user.sh --check` to verify.",
                                     exit_code));
        return 1;
    }

    // Ensure pf is enabled (idempotent — fails harmlessly if already enabled)
    cmd = std::format("{}{} -e 2>/dev/null", pfx, kPfctl);
    run_command_rc(cmd.c_str());

    // Add anchor reference to the main ruleset if not present.
    // The read-side `pfctl -s rules` also needs sudo on a hardened pf
    // config (some macOS releases require root just to enumerate the
    // active ruleset), so we wrap it the same way.
    cmd = std::format("{}{} -s rules 2>/dev/null", pfx, kPfctl);
    auto pf_conf = run_command(cmd.c_str());
    if (pf_conf.find("yuzu-quarantine") == std::string::npos) {
        // Append anchor reference. The pipe sends data to sudo's stdin;
        // by default sudo passes stdin through to the child, so pfctl
        // sees our anchor declaration on stdin via `-f -`.
        cmd = std::format("echo 'anchor \"yuzu-quarantine\"' | {}{} -f - 2>/dev/null", pfx, kPfctl);
        run_command_rc(cmd.c_str());
    }

    ctx.write_output(std::format("status|quarantined|rules_applied|{}", rules_written));
    return 0;
}

int macos_unquarantine(yuzu::CommandContext& ctx) {
    // Flush the anchor rules
    auto cmd = std::format("{}{} -a yuzu-quarantine -F all 2>/dev/null", sudo_prefix(), kPfctl);
    run_command_rc(cmd.c_str());

    ctx.write_output("status|released");
    return 0;
}

bool macos_is_quarantined() {
    auto cmd = std::format("{}{} -a yuzu-quarantine -s rules 2>/dev/null", sudo_prefix(), kPfctl);
    auto output = run_command(cmd.c_str());
    // If the anchor has rules, quarantine is active
    return !output.empty() && output.find("block") != std::string::npos;
}

std::vector<std::string> macos_get_whitelist() {
    std::vector<std::string> ips;
    auto cmd = std::format("{}{} -a yuzu-quarantine -s rules 2>/dev/null", sudo_prefix(), kPfctl);
    auto output = run_command(cmd.c_str());
    std::istringstream iss(output);
    std::string line;

    while (std::getline(iss, line)) {
        if (line.find("pass") == std::string::npos)
            continue;
        if (line.find("lo0") != std::string::npos)
            continue;

        // Parse IP from "pass quick from <ip> to any" or "pass quick from any to <ip>"
        auto from_pos = line.find("from ");
        auto to_pos = line.find("to ");
        if (from_pos != std::string::npos) {
            auto start = from_pos + 5;
            auto end = line.find(' ', start);
            auto ip = line.substr(start, end - start);
            if (ip != "any" && is_safe_ip(ip)) {
                bool found = false;
                for (const auto& existing : ips) {
                    if (existing == ip) {
                        found = true;
                        break;
                    }
                }
                if (!found)
                    ips.push_back(ip);
            }
        }
        if (to_pos != std::string::npos) {
            auto start = to_pos + 3;
            auto end = line.find(' ', start);
            if (end == std::string::npos)
                end = line.size();
            auto ip = line.substr(start, end - start);
            if (ip != "any" && is_safe_ip(ip)) {
                bool found = false;
                for (const auto& existing : ips) {
                    if (existing == ip) {
                        found = true;
                        break;
                    }
                }
                if (!found)
                    ips.push_back(ip);
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
    std::string_view name() const noexcept override { return kName; }
    std::string_view version() const noexcept override { return kVersion; }
    std::string_view description() const noexcept override {
        return "Device network isolation (quarantine) with per-IP whitelisting";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"quarantine", "unquarantine", "status", "whitelist", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {

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
    static constexpr const char* kName = "quarantine";
    static constexpr const char* kVersion = "1.0.0";

    // ── quarantine action ────────────────────────────────────────────────────

    int do_quarantine(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto server_ip = params.get("server_ip");
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
                if (existing == ip) {
                    dup = true;
                    break;
                }
            }
            if (!dup)
                whitelist.push_back(std::move(ip));
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
        auto ips_csv = params.get("ips");

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
                auto cmd = std::format("netsh advfirewall firewall add rule name=\"{}AllowIn_{}\" "
                                       "dir=in action=allow enable=yes remoteip={}",
                                       kRulePrefix, ip, ip);
                run_command_rc(cmd.c_str());
                cmd = std::format("netsh advfirewall firewall add rule name=\"{}AllowOut_{}\" "
                                  "dir=out action=allow enable=yes remoteip={}",
                                  kRulePrefix, ip, ip);
                run_command_rc(cmd.c_str());
            }
#elif defined(__linux__)
            {
                const auto* pfx = sudo_prefix();
                for (const auto& ip : new_ips) {
                    // Insert before the DROP rule (second-to-last position)
                    auto cmd =
                        std::format("{}{} -I yuzu-quarantine -s {} -j ACCEPT", pfx, kIptables, ip);
                    run_command_rc(cmd.c_str());
                    cmd =
                        std::format("{}{} -I yuzu-quarantine -d {} -j ACCEPT", pfx, kIptables, ip);
                    run_command_rc(cmd.c_str());
                }
            }
#elif defined(__APPLE__)
            {
                // Re-read current rules and append new ones
                const auto* pfx = sudo_prefix();
                for (const auto& ip : new_ips) {
                    auto cmd =
                        std::format("echo 'pass quick from {} to any\npass quick from any to {}' | "
                                    "{}{} -a yuzu-quarantine -f - 2>/dev/null",
                                    ip, ip, pfx, kPfctl);
                    run_command_rc(cmd.c_str());
                }
            }
#else
            ctx.write_output("error|unsupported platform");
            return 1;
#endif
        } else if (action_param == "remove") {
#ifdef _WIN32
            for (const auto& ip : new_ips) {
                auto cmd =
                    std::format("netsh advfirewall firewall delete rule name=\"{}AllowIn_{}\"",
                                kRulePrefix, ip);
                run_command_rc(cmd.c_str());
                cmd = std::format("netsh advfirewall firewall delete rule name=\"{}AllowOut_{}\"",
                                  kRulePrefix, ip);
                run_command_rc(cmd.c_str());
            }
#elif defined(__linux__)
            {
                const auto* pfx = sudo_prefix();
                for (const auto& ip : new_ips) {
                    auto cmd = std::format("{}{} -D yuzu-quarantine -s {} -j ACCEPT 2>/dev/null",
                                           pfx, kIptables, ip);
                    run_command_rc(cmd.c_str());
                    cmd = std::format("{}{} -D yuzu-quarantine -d {} -j ACCEPT 2>/dev/null", pfx,
                                      kIptables, ip);
                    run_command_rc(cmd.c_str());
                }
            }
#elif defined(__APPLE__)
            {
                // Removing individual pf rules requires rewriting the anchor.
                // Read current rules, filter out the IPs, and reload from a
                // securely-created temp file (same symlink-attack rationale
                // as in macos_quarantine — see comment there).
                const auto* pfx = sudo_prefix();
                auto cmd = std::format("{}{} -a yuzu-quarantine -s rules 2>/dev/null", pfx, kPfctl);
                auto current = run_command(cmd.c_str());
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
                auto tmp_file_result = yuzu::TempFile::create("yuzu-quarantine-anchor-", ".conf");
                if (tmp_file_result) {
                    auto tmp_file = std::move(*tmp_file_result);
                    FILE* f = fopen(tmp_file.path().c_str(), "w");
                    if (f) {
                        fputs(filtered.c_str(), f);
                        fclose(f);
                        cmd = std::format("{}{} -a yuzu-quarantine -f {} 2>/dev/null", pfx, kPfctl,
                                          tmp_file.path());
                        run_command_rc(cmd.c_str());
                    }
                }
            }
#else
            ctx.write_output("error|unsupported platform");
            return 1;
#endif
        } else {
            ctx.write_output(
                std::format("error|invalid action '{}', expected 'add' or 'remove'", action_param));
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
