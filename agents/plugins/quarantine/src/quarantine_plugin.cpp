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

#ifdef __APPLE__
// rename() comes from <cstdio> (already included above — it's part of ISO
// C's <stdio.h>, which C++ <cstdio> re-exports).
#include <fcntl.h>    // open() — for fsync'ing the anchor directory after rename
#include <sys/stat.h> // chmod()
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
// byte-for-byte, or the plugin's loads land in an anchor pf's active
// ruleset never invokes — a silent, unenforced false quarantine.
//
// BR-002 fix: the plugin now ALSO writes kAnchorFile itself, in addition
// to loading live rules into the anchor via `pfctl -a <name> -f
// <tempfile>` — see macos_write_anchor_file_atomic(). Live-only loads
// vanish on reboot or `pfctl -f /etc/pf.conf` (pf reconstructs the anchor
// from this on-disk file), which used to silently release quarantine.
// This is safe without a new sudoers grant because the macOS agent runs
// as root (docs/agent-privilege-model.md:14), unlike the `_yuzu`
// unprivileged-account model Linux/Windows use — root already owns
// kAnchorFile and kAnchorDir, so the plugin writes them directly rather
// than shelling out through `sudo -n pfctl` like every other mutation in
// this file.
constexpr const char* kAnchorName = "yuzu-quarantine";
constexpr const char* kAnchorFile = "/etc/pf.anchors/yuzu-quarantine";

// Directory containing kAnchorFile. Passed as the `directory` override to
// yuzu::TempFile::create() (see macos_write_anchor_file_atomic() below) so
// the staging temp file lands on the SAME filesystem as kAnchorFile —
// required for the final rename() to be atomic; a cross-filesystem rename
// isn't atomic (some libcs silently fall back to copy+unlink), which would
// reopen the exact torn-write window this exists to close.
constexpr const char* kAnchorDir = "/etc/pf.anchors";
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
//
// BR-03 (HIGH, fixed): this used to be paired with
// macos_clear_stale_inline_block(), which reloaded /etc/pf.conf whenever
// this heuristic fired. That was unsound: absence of the active
// yuzu-quarantine anchor proves only that SOME main ruleset is active with
// no anchor hook — NOT that Yuzu authored its `block all`. An admin / VPN /
// security product can legitimately load its own top-level `block all`
// with no yuzu-quarantine anchor (e.g. before F-pf-provisioning ever ran
// on that host), and the old code would silently discard that unrelated
// live policy on the very next quarantine/whitelist/release call — with no
// restore, not even on release.
//
// There is also no reliable way to fix this by keying on a Yuzu-owned
// marker instead: the legacy pre-anchor design (before commit 18543181,
// "A-1.18-quarantine") loaded its `block all` via a bare
// `pfctl -f <tempfile>` against the live ruleset — it never wrote to
// /etc/pf.conf or any other durable file, and pfctl -s rules does not
// preserve the rule-file comments the tempfile happened to contain (see
// the old macos_load_ruleset() rules-header comment at that revision).
// So the active ruleset carries no durable, uniquely-Yuzu fingerprint to
// gate a migration on.
//
// Given that, this function is now advisory-only: it still reports the
// same heuristic (top-level block-all with no anchor hook), but callers
// must NEVER act on it by touching the main ruleset — only surface an
// honest note asking the operator to check/clear it by hand. See callers
// for where that note is emitted.
bool macos_has_stale_inline_block() {
    auto cmd = std::format("{}{} -s rules 2>/dev/null", sudo_prefix(), kPfctl);
    auto output = run_command(cmd.c_str());
    bool has_block_all = output.find("block drop all") != std::string::npos ||
                         output.find("block all") != std::string::npos;
    if (!has_block_all)
        return false;

    // A top-level `block all` alone isn't a unique fingerprint of the
    // pre-anchor design — it's also a perfectly ordinary operator-authored
    // default-deny policy. Only flag it as POSSIBLY our stale leftover when
    // the yuzu-quarantine anchor hook is ALSO absent from the active
    // ruleset: once F-pf-provisioning has hooked the anchor in, this
    // plugin never writes to the main ruleset again, so a top-level block
    // all from that point on is provably not ours. This still can't prove
    // the block-all IS ours when the anchor is absent (see the function
    // comment above) — it only narrows candidates for the advisory note.
    bool anchor_hooked = output.find(std::format("anchor \"{}\"", kAnchorName)) != std::string::npos;
    return !anchor_hooked;
}

// Advisory note surfaced wherever macos_has_stale_inline_block() fires.
// Intentionally takes NO action on the main ruleset — see the rationale on
// macos_has_stale_inline_block() above (BR-03). This is honest about what
// it does and doesn't know: it never claims to have cleaned anything up.
std::string macos_stale_inline_block_note() {
    return std::format(
        "a top-level `block all`/`block drop all` is present in the active pf ruleset with "
        "no \"{}\" anchor hook. This MAY be a leftover from a pre-A-1.18 Yuzu build (which "
        "wrote block-all directly into the main ruleset instead of a dedicated anchor) — or "
        "it may be an unrelated admin/VPN/security-product policy that happens to look the "
        "same from here. Yuzu can't tell these apart and will not touch the main ruleset to "
        "guess; if you know it's a stale Yuzu leftover, remove it by hand (e.g. review and "
        "reload /etc/pf.conf yourself once you've confirmed it reflects the ruleset you "
        "actually want active). Quarantine/whitelist/release continue to work normally via "
        "the \"{}\" anchor regardless of this note.",
        kAnchorName, kAnchorName);
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

// BR-002: rules loaded live via `pfctl -a <anchor> -f <file>` (below) live
// only in the kernel's in-memory anchor table — they vanish on reboot or
// on ANY `pfctl -f /etc/pf.conf` reload, because pf reconstructs the
// yuzu-quarantine anchor from kAnchorFile on disk (via the `load anchor
// ... from ...` directive F-pf-provisioning hooks into /etc/pf.conf — see
// docs/agent-privilege-model.md, "macOS pf-anchor provisioning"). Until
// this function runs, kAnchorFile is the EMPTY placeholder
// install-agent-user.sh provisions, so a reboot silently reconstructs an
// open anchor — the device is released while the server still believes
// it's isolated. Every live anchor load/flush in this file is therefore
// mirrored here to keep kAnchorFile in sync with what's enforced live.
//
// The macOS agent runs as root (docs/agent-privilege-model.md:14 — the
// shipped LaunchDaemon has no UserName key, so launchd runs it as root),
// so this writes kAnchorFile directly with no privilege escalation; unlike
// every pfctl shell-out in this file, no sudo prefix is used or needed
// here, and no new sudoers grant is required (root already owns the file
// and its containing directory).
//
// TOCTOU-safe atomic replace: yuzu::TempFile::create() creates its file
// via mkstemps() — O_CREAT|O_EXCL semantics, so the staging path can never
// collide with or be raced onto an attacker-predicted name (see
// agents/core/src/temp_file.cpp) — inside kAnchorDir so it shares
// kAnchorFile's filesystem. Contents are fsync()'d before rename() so
// they're durable even against a crash immediately after the call, and
// rename() is atomic within one filesystem: a concurrent reader (or a
// reboot re-sourcing /etc/pf.conf) can only ever observe the fully-old or
// fully-new file, never a partially-written one.
bool macos_write_anchor_file_atomic(const std::string& contents, std::string* error_out) {
    auto tmp_file_result = yuzu::TempFile::create("yuzu-quarantine-", ".conf", kAnchorDir);
    if (!tmp_file_result) {
        *error_out = std::format(
            "failed to create a staging temp file in {} for the persistent pf anchor file "
            "({}) — {}",
            kAnchorDir, kAnchorFile, tmp_file_result.error().message);
        return false;
    }
    auto tmp_file = std::move(*tmp_file_result);

    FILE* f = fopen(tmp_file.path().c_str(), "w");
    if (!f) {
        *error_out = std::format("failed to open staging file {} for the persistent pf anchor",
                                 tmp_file.path());
        return false;
    }
    bool write_ok = fputs(contents.c_str(), f) != EOF;
    if (write_ok && fflush(f) != 0)
        write_ok = false;
    // fsync BEFORE fclose: fclose alone doesn't guarantee the data hit
    // disk, only that the stdio buffer was flushed to the fd (which
    // fflush above already did) — fsync is what forces the kernel to
    // persist it.
    if (write_ok && fsync(fileno(f)) != 0)
        write_ok = false;
    fclose(f);
    if (!write_ok) {
        *error_out = std::format(
            "failed to write/fsync the persistent pf anchor staging file {}", tmp_file.path());
        return false;
    }

    // Match install-agent-user.sh's macos_install_pf_anchor_file()
    // convention for kAnchorFile: mode 0644 (world-readable — e.g. for a
    // non-root operator's `pfctl -nf` validation). Owner is already root
    // since this whole plugin process runs as root on macOS.
    if (chmod(tmp_file.path().c_str(), 0644) != 0) {
        *error_out =
            std::format("failed to chmod staging file {} to 0644", tmp_file.path());
        return false;
    }

    if (rename(tmp_file.path().c_str(), kAnchorFile) != 0) {
        *error_out = std::format("failed to atomically replace {} (rename from {} failed)",
                                 kAnchorFile, tmp_file.path());
        return false;
    }
    // The rename moved the staging path onto kAnchorFile, so the original
    // staging path no longer exists — tell the RAII wrapper not to try to
    // unlink it (harmless no-op either way, but explicit is clearer).
    tmp_file.release();

    // Belt-and-suspenders durability: fsync the containing directory so
    // the rename's directory-entry update itself survives a crash right
    // after this call (the file's own contents were already fsync'd
    // above; a bare rename's directory-entry update is a separate write
    // that also needs an explicit fsync to be crash-durable on most
    // POSIX filesystems). Best-effort — a failure here doesn't invalidate
    // the rename that already completed, so it's intentionally not fatal.
    int dir_fd = open(kAnchorDir, O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    return true;
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

    // BR-03 (fixed): this used to run a "backward-compat cleanup" here that
    // reloaded /etc/pf.conf whenever macos_has_stale_inline_block() fired.
    // That heuristic cannot distinguish a stale pre-anchor Yuzu leftover
    // from an admin/VPN/security product's own legitimate top-level
    // `block all`, so it was capable of silently discarding an unrelated
    // live policy on every quarantine call. Removed outright — see the
    // rationale on macos_has_stale_inline_block() above. This function no
    // longer touches the main ruleset at all; it only ever loads rules
    // into the yuzu-quarantine anchor below, which is unaffected by
    // whatever the main ruleset currently contains.
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

    // BR-002: mirror the rules just loaded LIVE to the persistent anchor
    // file so a reboot / `pfctl -f /etc/pf.conf` reload reconstructs the
    // SAME ruleset instead of the empty install-time placeholder
    // install-agent-user.sh provisions — see
    // macos_write_anchor_file_atomic() above. Deliberately runs AFTER the
    // live load + enable above succeeds, so the host is already isolated
    // live by the time we get here. If the persistent write fails, this
    // still returns an error rather than success: the caller must never
    // report quarantine as durably active when the on-disk anchor file
    // doesn't back it up. The live load is intentionally left in place
    // either way — an operator seeing "error, but the host is isolated"
    // is a safer failure mode than this function silently tearing down
    // live isolation just because the durability leg failed.
    std::string persist_err;
    if (!macos_write_anchor_file_atomic(rules, &persist_err)) {
        *error_out = std::format(
            "pf anchor \"{}\" loaded LIVE — the host is isolated right now — but the "
            "persistent copy at {} could not be updated ({}). Quarantine will NOT survive "
            "a reboot or `pfctl -f /etc/pf.conf` reload until this is fixed; live "
            "isolation remains in effect in the meantime.",
            kAnchorName, kAnchorFile, persist_err);
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

// BR-002: on-disk replacement for kAnchorFile once quarantine is released,
// mirroring the install-time placeholder scripts/install-agent-user.sh
// provisions (empty — no filter rules, matches nothing). Used by
// macos_unquarantine() so a reboot / `pfctl -f /etc/pf.conf` reload
// reconstructs an EMPTY anchor, same as what the live flush just did,
// instead of replaying whatever quarantine ruleset macos_load_ruleset()
// last persisted there.
constexpr const char* kEmptyAnchorContents =
    "# Yuzu agent quarantine anchor — cleared by quarantine_plugin.cpp (unquarantine).\n"
    "# DO NOT edit by hand; overwritten on every quarantine/unquarantine dispatch.\n"
    "#\n"
    "# Empty (no rules) — matches the install-time placeholder\n"
    "# scripts/install-agent-user.sh provisions. An anchor with no filter rules\n"
    "# matches nothing, so a reboot / `pfctl -f /etc/pf.conf` reload that\n"
    "# reconstructs this anchor from this file releases quarantine, not\n"
    "# re-imposes it.\n";

int macos_unquarantine(yuzu::CommandContext& ctx) {
    const auto* pfx = sudo_prefix();

    // BR-03 (fixed): this used to run a "backward-compat cleanup" here —
    // reloading /etc/pf.conf whenever macos_has_stale_inline_block() fired,
    // on the theory that a host mid-migration (quarantined under the
    // pre-anchor plugin, then upgraded to this build) could carry a stale
    // inline `block all` the anchor flush below never touches. But the
    // heuristic can't tell a stale Yuzu leftover apart from an unrelated
    // admin/VPN/security-product default-deny ruleset, and there's no
    // durable Yuzu-owned marker to key a safe migration on instead (see the
    // rationale on macos_has_stale_inline_block() above) — reloading
    // /etc/pf.conf here could silently discard a live non-Yuzu policy, and
    // release never restored it. Replaced with an honest advisory note
    // only; the main ruleset is never touched by this function.
    if (macos_has_stale_inline_block()) {
        ctx.write_output(std::format("note|{}", macos_stale_inline_block_note()));
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
        // The anchor flush itself failed, so pf being administratively
        // disabled here is only a temporary, orthogonal release mechanism —
        // it makes the host reachable right now, but says nothing about the
        // anchor's own rule table, which is still unconfirmed (that's the
        // failure we're in) and whose persisted copy on disk still holds
        // whatever macos_load_ruleset() last wrote. Best-effort clear the
        // persistent anchor file with the same atomic helper the successful
        // path uses below, so a stale `block all` doesn't survive to
        // re-impose quarantine the next time pf is re-enabled, `pfctl -f
        // /etc/pf.conf` reloads, or the box reboots. But never report
        // "released"/rc 0 for this branch regardless of whether the
        // best-effort clear lands: the live anchor's rule table was never
        // confirmed flushed, so durable quarantine state is not confirmed
        // cleared and the controller must keep reconciling rather than
        // treating this host as released.
        std::string persist_err;
        const bool persisted =
            macos_write_anchor_file_atomic(kEmptyAnchorContents, &persist_err);
        if (persisted) {
            ctx.write_output(std::format(
                "status|release_incomplete|note|pf disabled (host reachable) but anchor "
                "\"{}\" rule table flush failed — persistent anchor file at {} was "
                "best-effort cleared, but the live anchor's own state is unconfirmed; "
                "retry `sudo {} -a {} -F rules`",
                kAnchorName, kAnchorFile, kPfctl, kAnchorName));
        } else {
            ctx.write_output(std::format(
                "status|release_incomplete|note|pf disabled (host reachable) but anchor "
                "\"{}\" rule table flush failed AND the persistent anchor file at {} could "
                "not be cleared ({}) — durable quarantine state remains uncleared; retry "
                "`sudo {} -a {} -F rules` or fix the anchor file by hand",
                kAnchorName, kAnchorFile, persist_err, kPfctl, kAnchorName));
        }
        return 1;
    }

    // BR-002: the live anchor flush above succeeded — mirror that to the
    // persistent anchor file so a reboot / `pfctl -f /etc/pf.conf` reload
    // reconstructs the same released (empty) state instead of replaying a
    // stale quarantine ruleset. Never report "released" if this fails:
    // the box IS open right now (the live flush succeeded), but the very
    // next reboot would silently re-quarantine it from the stale on-disk
    // file — an operator told "released" would have no reason to expect
    // that.
    std::string persist_err;
    if (!macos_write_anchor_file_atomic(kEmptyAnchorContents, &persist_err)) {
        ctx.write_output(std::format(
            "error|pf anchor \"{}\" flushed LIVE — the host is reachable right now — but "
            "the persistent copy at {} could not be cleared ({}). A reboot or `pfctl -f "
            "/etc/pf.conf` reload will re-impose the OLD quarantine ruleset until this is "
            "fixed.",
            kAnchorName, kAnchorFile, persist_err));
        return 1;
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
        // BR-03: advisory only — see macos_has_stale_inline_block() and
        // macos_stale_inline_block_note(). Never acted on automatically;
        // surfaced here purely so an operator querying status learns about
        // it without having to run unquarantine first.
        if (macos_has_stale_inline_block()) {
            ctx.write_output(std::format("note|{}", macos_stale_inline_block_note()));
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
