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

// Dedicated pf anchor the quarantine plugin loads its rules into, and the
// on-disk anchor file F-pf-provisioning (scripts/install-agent-user.sh)
// installs and hooks into /etc/pf.conf's active main ruleset ahead of time
// (see docs/agent-privilege-model.md, "macOS pf-anchor provisioning"). These
// two constants MUST match that script's PF_ANCHOR_NAME / PF_ANCHOR_FILE
// byte-for-byte — the plugin never writes PF_ANCHOR_FILE itself (that's
// root-owned; the agent has no write access to it), it only loads live rules
// into the anchor via `pfctl -a <name> -f <tempfile>`, but the anchor NAME
// has to line up exactly or the plugin's loads land in an anchor pf's active
// ruleset never invokes — a silent, unenforced false quarantine.
constexpr const char* kAnchorName = "yuzu-quarantine";
constexpr const char* kAnchorFile = "/etc/pf.anchors/yuzu-quarantine";
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

// Backward-compat: fingerprint of the PRE-anchor design. The old
// macos_load_ruleset() (before A-1.18) called plain `pfctl -f <tempfile>`,
// which replaced pf's entire ACTIVE main ruleset wholesale with our
// pass-whitelist + `block all` rules. If a host was quarantined under that
// build and the plugin binary was then upgraded to this anchor-based one
// without an intervening unquarantine, that inline `block all` survives in
// the active ruleset independent of anything we do to the anchor below —
// and would leave the host permanently blocked, since nothing here touches
// it otherwise. A top-level `block all`/`block drop all` in `pfctl -s rules`
// is that fingerprint: our own rules now only ever live inside the
// yuzu-quarantine anchor, never at the top level.
bool macos_has_stale_inline_block() {
    auto cmd = std::format("{}{} -s rules 2>/dev/null", sudo_prefix(), kPfctl);
    auto output = run_command(cmd.c_str());
    bool has_block_all = output.find("block drop all") != std::string::npos ||
                         output.find("block all") != std::string::npos;
    if (!has_block_all)
        return false;

    // A top-level `block all` alone isn't a unique fingerprint of the
    // pre-anchor design — it's also a perfectly ordinary operator-authored
    // default-deny policy. Only treat it as OUR stale leftover when the
    // yuzu-quarantine anchor hook is ALSO absent from the active ruleset:
    // once F-pf-provisioning has hooked the anchor in, this plugin never
    // writes to the main ruleset again, so a top-level block all from that
    // point on is provably not ours. Narrows the false-positive where an
    // operator runs their own default-deny main ruleset alongside an
    // already-provisioned yuzu-quarantine anchor — without this, every
    // quarantine/whitelist/release call on that host would wrongly reload
    // /etc/pf.conf and discard any non-persisted live rule changes.
    bool anchor_hooked = output.find(std::format("anchor \"{}\"", kAnchorName)) != std::string::npos;
    return !anchor_hooked;
}

// Clear a stale pre-anchor inline block by reloading /etc/pf.conf — the one
// place the quarantine path still touches the main ruleset directly, and
// only to undo the OLD design's clobber, never as a substitute for the
// anchor operations below. Once F-pf-provisioning has run, the reloaded
// /etc/pf.conf also carries the `anchor "yuzu-quarantine"` hook, so this
// doubles as picking that hook up if it wasn't active yet.
int macos_clear_stale_inline_block(std::string* error_out) {
    const auto* pfx = sudo_prefix();
    auto cmd = std::format("{}{} -f /etc/pf.conf 2>/dev/null", pfx, kPfctl);
    int rc = run_command_rc(cmd.c_str());
    if (rc != 0) {
        int exit_code = WIFEXITED(rc) ? WEXITSTATUS(rc) : rc;
        *error_out = std::format(
            "detected a pre-anchor inline quarantine block still active, but reloading "
            "/etc/pf.conf to clear it failed (rc={}) — the host may still be blocked; "
            "run `sudo {} -f /etc/pf.conf` by hand.",
            exit_code, kPfctl);
        return 1;
    }
    return 0;
}

// P2 (verified): quarantine rules loaded into the yuzu-quarantine anchor via
// `pfctl -a yuzu-quarantine -f <file>` only take effect if pf's ACTIVE main
// ruleset also invokes that anchor — the `anchor "yuzu-quarantine"` (+
// matching `load anchor ...`) hook that F-pf-provisioning
// (scripts/install-agent-user.sh) installs into /etc/pf.conf and loads. See
// docs/agent-privilege-model.md, "macOS pf-anchor provisioning". Without it,
// anchor loads are a silent no-op: traffic bypasses the rules entirely. This
// checks the ACTIVE ruleset (`pfctl -s rules`), not just the on-disk
// /etc/pf.conf, so a host where the hook was written but never (re)loaded is
// still correctly reported as unhooked.
bool macos_anchor_hooked() {
    auto cmd = std::format("{}{} -s rules 2>/dev/null", sudo_prefix(), kPfctl);
    auto output = run_command(cmd.c_str());
    return output.find(std::format("anchor \"{}\"", kAnchorName)) != std::string::npos;
}

// pf can retain and enforce a loaded ruleset while administratively
// DISABLED — an anchor hook + loaded rules is necessary but not sufficient
// for enforcement; `pfctl -e`/`pfctl -d` toggle a separate on/off switch
// that this checks directly via `pfctl -s info`'s "Status:" line. Used to
// (a) confirm the runtime `pfctl -e` in macos_load_ruleset() actually took
// effect rather than trusting its exit code alone, and (b) fold into
// macos_is_quarantined() so a host with pf disabled is never reported as
// actively quarantined.
enum class MacosPfState { enabled, disabled, unknown };

MacosPfState macos_pf_state() {
    auto cmd = std::format("{}{} -s info 2>/dev/null", sudo_prefix(), kPfctl);
    auto output = run_command(cmd.c_str());
    if (output.find("Status: Enabled") != std::string::npos)
        return MacosPfState::enabled;
    if (output.find("Status: Disabled") != std::string::npos)
        return MacosPfState::disabled;
    return MacosPfState::unknown;
}

// Compose-and-load the complete pf ruleset for a quarantine state into the
// dedicated yuzu-quarantine anchor.
//
// `rules_written_out` is set to the count of rule lines we wrote.
// `error_out` is set to a non-empty operator-actionable string on
// failure; caller writes it to ctx.write_output.
//
// Returns 0 on success, non-zero on failure. Used by both
// macos_quarantine() and the macOS branch of do_whitelist() so the
// "rebuild the ruleset and atomically load it" logic lives in one
// place. See the rationale comment inside about the loopback pass rule.
int macos_load_ruleset(const std::vector<std::string>& whitelist_ips, int* rules_written_out,
                       std::string* error_out) {
    const auto* pfx = sudo_prefix();
    int rules_written = 0;
    std::string rules;

    rules += "# Yuzu agent quarantine — generated by quarantine_plugin.cpp\n";
    rules += "# DO NOT edit by hand; this file is overwritten on every dispatch.\n";
    rules += std::format("# Loaded into the \"{}\" pf anchor (not the main ruleset) via\n",
                         kAnchorName);
    rules += "# `pfctl -a <anchor> -f <this file>`. Release via the unquarantine action,\n";
    rules += "# which flushes the anchor (`pfctl -a <anchor> -F rules`).\n";
    rules += "\n";
    rules += "# Keep loopback open — agent<->gateway<->server TCP rides lo0. `set skip`\n";
    rules += "# is a main-ruleset-only pf OPTION, not a filter rule, and is not valid\n";
    rules += "# inside an anchor body (see pf.conf(5), GRAMMAR: `option` vs `pf-rule`).\n";
    rules += "# Use an anchor-legal quick pass rule instead, ordered before block all.\n";
    rules += "pass quick on lo0 all\n";
    ++rules_written;

    for (const auto& ip : whitelist_ips) {
        rules += std::format("pass quick from {} to any keep state\n", ip);
        rules += std::format("pass quick from any to {} keep state\n", ip);
        rules_written += 2;
    }

    rules += "block all\n";
    ++rules_written;

    // Backward-compat cleanup first (see macos_has_stale_inline_block()) —
    // this may also pick up a not-yet-active F-pf-provisioning hook by
    // reloading /etc/pf.conf, so it runs before the anchor-hooked check.
    // But ONLY when /etc/pf.conf on disk already carries the anchor hook:
    // reloading it is how a stale inline `block all` gets cleared, and if
    // the hook isn't in the on-disk file yet (F-pf-provisioning never ran),
    // that reload would strip the old design's block-all with nothing to
    // replace it — the anchor-hooked check just below then fails the
    // request anyway, leaving a previously isolated host fully open on a
    // quarantine call that reports failure. /etc/pf.conf is world-readable
    // (0644), so checking its on-disk contents needs no sudo.
    auto pf_conf_on_disk = run_command("/bin/cat /etc/pf.conf 2>/dev/null");
    bool hook_on_disk =
        pf_conf_on_disk.find(std::format("anchor \"{}\"", kAnchorName)) != std::string::npos;
    if (hook_on_disk && macos_has_stale_inline_block()) {
        std::string cleanup_err;
        if (macos_clear_stale_inline_block(&cleanup_err) != 0) {
            *error_out = cleanup_err;
            return 1;
        }
    }

    if (!macos_anchor_hooked()) {
        *error_out = std::format(
            "pf anchor \"{}\" is not hooked into the active ruleset — quarantine rules "
            "loaded into it would have no effect on live traffic (false quarantine). "
            "Run `sudo bash scripts/install-agent-user.sh` to provision the "
            "F-pf-provisioning hook (installs {} and hooks it into /etc/pf.conf — see "
            "docs/agent-privilege-model.md, \"macOS pf-anchor provisioning\"), then retry.",
            kAnchorName, kAnchorFile);
        return 1;
    }

    auto tmp_file_result = yuzu::TempFile::create("yuzu-quarantine-", ".conf");
    if (!tmp_file_result) {
        *error_out = "failed to create temp file for pf rules";
        return 1;
    }
    auto tmp_file = std::move(*tmp_file_result);
    {
        FILE* f = fopen(tmp_file.path().c_str(), "w");
        if (!f) {
            *error_out = "failed to write pf rules";
            return 1;
        }
        fputs(rules.c_str(), f);
        fclose(f);
    }

    auto cmd = std::format("{}{} -a {} -f {}", pfx, kPfctl, kAnchorName, tmp_file.path());
    int load_rc = run_command_rc(cmd.c_str());
    if (load_rc != 0) {
        int exit_code = WIFEXITED(load_rc) ? WEXITSTATUS(load_rc) : load_rc;
        *error_out = std::format("pfctl anchor load failed (rc={}). Likely the agent account "
                                 "is not in /etc/sudoers.d/yuzu-agent — run "
                                 "`sudo bash scripts/install-agent-user.sh --check` to verify.",
                                 exit_code);
        return 1;
    }

    // Enable pf if not already enabled. Idempotent — the kernel returns
    // a harmless warning to stderr when called on an already-enabled pf,
    // so a nonzero exit code alone doesn't distinguish "already enabled"
    // from "failed to enable" (e.g. root-owned pf token held elsewhere).
    // Confirm via `pfctl -s info` rather than trusting the exit code —
    // anchor rules loaded above have zero effect while pf is disabled,
    // and that would otherwise be a silent false quarantine.
    cmd = std::format("{}{} -e 2>/dev/null", pfx, kPfctl);
    run_command_rc(cmd.c_str());
    if (macos_pf_state() != MacosPfState::enabled) {
        *error_out = std::format(
            "pf anchor \"{}\" loaded, but pf itself could not be confirmed enabled — "
            "quarantine rules are not enforced while pf is disabled. Run "
            "`sudo {} -e` by hand and retry.",
            kAnchorName, kPfctl);
        return 1;
    }

    *rules_written_out = rules_written;
    return 0;
}

int macos_quarantine(yuzu::CommandContext& ctx, const std::vector<std::string>& whitelist_ips) {
    // rules_written counts the lines we hand to pfctl. The actual number
    // of rules installed in pf is reported back to the operator only if
    // pfctl's load succeeds (see the rc check after run_command_rc below).
    int rules_written = 0;
    std::string error;
    if (macos_load_ruleset(whitelist_ips, &rules_written, &error) != 0) {
        ctx.write_output(std::format("error|{}", error));
        return 1;
    }
    ctx.write_output(std::format("status|quarantined|rules_applied|{}", rules_written));
    return 0;
}

int macos_unquarantine(yuzu::CommandContext& ctx) {
    const auto* pfx = sudo_prefix();

    // Backward-compat cleanup first (see macos_has_stale_inline_block()) —
    // a host mid-migration (quarantined under the pre-anchor plugin, then
    // upgraded to this build) can carry a stale inline `block all` that the
    // anchor flush below never touches.
    if (macos_has_stale_inline_block()) {
        std::string cleanup_err;
        if (macos_clear_stale_inline_block(&cleanup_err) != 0) {
            ctx.write_output(std::format("error|{}", cleanup_err));
            return 1;
        }
    }

    // Flush the anchor's rule table rather than clobbering /etc/pf.conf —
    // the anchor is where quarantine.isolate loads rules
    // (macos_load_ruleset), so this is the correct, minimal "undo". Safe to
    // call even if the anchor was never hooked into the active ruleset (pf
    // tracks a named anchor's rule table independently of whether the main
    // ruleset references it) or was never populated.
    auto cmd = std::format("{}{} -a {} -F rules 2>/dev/null", pfx, kPfctl, kAnchorName);
    int rc = run_command_rc(cmd.c_str());
    if (rc != 0) {
        // Last-resort fallback ONLY — never clobber /etc/pf.conf as the
        // primary path (that was the pre-anchor bug this rework fixes).
        // Disabling pf wholesale is strictly more permissive than desired,
        // but leaves the box reachable for the operator to clean up.
        cmd = std::format("{}{} -d 2>/dev/null", pfx, kPfctl);
        run_command_rc(cmd.c_str());
        // Confirm the fallback actually landed rather than trusting its
        // exit code (which, like `-e`'s, is unreliable on an
        // already-toggled pf) — if pf can't be confirmed disabled, BOTH
        // the anchor flush and the disable fallback have failed, and the
        // device is still quarantined. Reporting "released" here would be
        // a false release: an operator would believe connectivity was
        // restored while the box stays blocked.
        if (macos_pf_state() != MacosPfState::disabled) {
            ctx.write_output(std::format(
                "error|failed to flush anchor \"{}\" and could not confirm pf disabled — "
                "quarantine is likely still enforced. Run `sudo {} -a {} -F rules` or "
                "`sudo {} -d` by hand.",
                kAnchorName, kPfctl, kAnchorName, kPfctl));
            return 1;
        }
        ctx.write_output(std::format(
            "status|released|note|pf disabled (failed to flush anchor \"{}\")", kAnchorName));
        return 0;
    }

    if (!macos_anchor_hooked()) {
        // Honest note, not an error: the flush above still succeeded (pf
        // anchor rule tables are addressable whether or not the main
        // ruleset invokes them), but since the anchor was never hooked in,
        // nothing was actually enforcing quarantine to begin with — this is
        // surfaced so an operator doesn't mistake "released" for evidence
        // the quarantine mechanism itself is provisioned.
        ctx.write_output(std::format(
            "status|released|note|pf anchor \"{}\" is not hooked into the active ruleset "
            "(F-pf-provisioning not run) — nothing was enforcing quarantine", kAnchorName));
        return 0;
    }

    ctx.write_output("status|released");
    return 0;
}

// Takes the pf-state and anchor-hooked checks as inputs rather than
// re-querying pfctl for them, so a caller that already needs those two
// facts for its own reporting (do_status) can compute each exactly once
// instead of pfctl being forked twice more per status call — the two
// results can't drift out from under each other that way either.
bool macos_is_quarantined(MacosPfState pf_state, bool anchor_hooked) {
    // Honest false: pf retains and inspects a loaded anchor's rules even
    // while administratively disabled (`pfctl -d`), so rule presence alone
    // is not proof of enforcement — never report "active" while pf itself
    // is off or its state can't be confirmed.
    if (pf_state != MacosPfState::enabled)
        return false;

    // Honest false (P2, verified): without the F-pf-provisioning hook (see
    // macos_anchor_hooked()), rules loaded into the anchor have zero effect
    // on live traffic — never report "active" for a quarantine that isn't
    // actually enforced.
    if (!anchor_hooked)
        return false;

    // We're quarantined iff the yuzu-quarantine anchor's own rule table has
    // our `block all` rule (the load-bearing default-deny) — query the
    // anchor directly, not the main ruleset, since that's where
    // macos_load_ruleset() writes rules now.
    auto cmd = std::format("{}{} -a {} -s rules 2>/dev/null", sudo_prefix(), kPfctl, kAnchorName);
    auto output = run_command(cmd.c_str());
    return output.find("block drop all") != std::string::npos ||
           output.find("block all") != std::string::npos;
}

bool macos_is_quarantined() {
    return macos_is_quarantined(macos_pf_state(), macos_anchor_hooked());
}

std::vector<std::string> macos_get_whitelist() {
    std::vector<std::string> ips;
    auto cmd = std::format("{}{} -a {} -s rules 2>/dev/null", sudo_prefix(), kPfctl, kAnchorName);
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
        // Compute pf-state and anchor-hooked once and thread them through
        // (rather than each of macos_is_quarantined() and the two note
        // checks below independently re-invoking pfctl for the same two
        // facts) — pf state can otherwise change between the separate
        // forks, letting the state|active line and the following notes
        // disagree about the reason.
        MacosPfState pf_state = macos_pf_state();
        bool anchor_hooked = macos_anchor_hooked();
        bool active = macos_is_quarantined(pf_state, anchor_hooked);
#else
        ctx.write_output("error|unsupported platform");
        return 1;
#endif
        ctx.write_output(std::format("state|{}", active ? "active" : "inactive"));

#ifdef __APPLE__
        // Honest status (P2, verified): surfaced as a separate output line
        // so callers can distinguish "not quarantined" from "quarantine
        // cannot be enforced at all because F-pf-provisioning hasn't run" —
        // see macos_anchor_hooked().
        if (!anchor_hooked) {
            ctx.write_output(std::format(
                "note|pf anchor \"{}\" is not hooked into the active ruleset — run "
                "scripts/install-agent-user.sh to provision it (see "
                "docs/agent-privilege-model.md, \"macOS pf-anchor provisioning\"); "
                "quarantine cannot be enforced until then",
                kAnchorName));
        }
        // Honest status: pf can be administratively disabled (`pfctl -d`)
        // while still holding a hooked anchor and loaded rules — surfaced
        // separately so "inactive" isn't mistaken for "mechanism not
        // provisioned" when the real cause is pf being off.
        if (pf_state != MacosPfState::enabled) {
            ctx.write_output(
                "note|pf is disabled or its state could not be confirmed via "
                "`pfctl -s info` — quarantine cannot be enforced until pf is enabled");
        }
#endif

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
                // The anchor-based design means "add" = "rebuild the
                // anchor's rule set with the union of current whitelist +
                // new IPs". We get the current whitelist via
                // macos_get_whitelist() (queries the anchor) and merge.
                auto current = macos_get_whitelist();
                for (const auto& ip : new_ips) {
                    bool dup = false;
                    for (const auto& existing : current) {
                        if (existing == ip) {
                            dup = true;
                            break;
                        }
                    }
                    if (!dup)
                        current.push_back(ip);
                }
                int rules_written = 0;
                std::string err;
                if (macos_load_ruleset(current, &rules_written, &err) != 0) {
                    ctx.write_output(std::format("error|{}", err));
                    return 1;
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
                // "remove" = rebuild the anchor's rule set with
                // current-whitelist minus new_ips. macos_load_ruleset takes
                // the final desired set; we don't manipulate individual
                // rules in place (string-matching individual pf rules to
                // delete them has a well-known false-match risk).
                auto current = macos_get_whitelist();
                std::vector<std::string> filtered;
                for (const auto& ip : current) {
                    bool removed = false;
                    for (const auto& rm : new_ips) {
                        if (ip == rm) {
                            removed = true;
                            break;
                        }
                    }
                    if (!removed)
                        filtered.push_back(ip);
                }
                int rules_written = 0;
                std::string err;
                if (macos_load_ruleset(filtered, &rules_written, &err) != 0) {
                    ctx.write_output(std::format("error|{}", err));
                    return 1;
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
