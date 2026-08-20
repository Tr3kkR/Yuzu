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
 *
 * ── Wave-2 ADR-3002 acquisition-ladder migration ─────────────────────────
 *
 * Every spawn site in this file goes through yuzu::agent::run_bounded_subprocess
 * with clean, pre-split argv (no shell, no popen/_popen, no PATH search —
 * argv[0] is always an absolute path). Linux/macOS privilege escalation is
 * yuzu::shared::sudo_wrap's canonical `sudo -n -- <tool> <args>` form;
 * Windows needs none (the YuzuAgent service account's own privilege covers
 * netsh). Every mutating call's real termination reason is forwarded
 * through the ABI4 result-status seam via yuzu::agent::forward_runner_failure
 * — a quarantine/unquarantine/status read never silently reports success
 * when the underlying tool did not genuinely run and exit as expected. This
 * is deliberately careful: an incorrectly-reported quarantine or
 * unquarantine is a containment/availability failure, not a cosmetic one.
 *
 * ── macOS: DO NOT reintroduce a pf anchor ─────────────────────────────────
 *
 * `macos_load_ruleset` writes the ENTIRE main pf ruleset (never an anchor)
 * and loads it with ONE atomic `pfctl -f` call, with `set skip on lo0` as
 * the first line. This is a deliberate fix for a real production incident
 * (commit 672896112, `git log -1 672896112` for the full account): an
 * earlier design used a named anchor (`pfctl -a yuzu-quarantine -f tmp`
 * then a second `pfctl -f -` to attach the anchor to the main ruleset) —
 * that second call REPLACED the whole main ruleset with just the anchor
 * reference, evicting macOS's default rules, and 29 seconds later the
 * agent⇄gateway⇄server loopback TCP connection died mid-flight because the
 * anchor design's rule reload did not preserve pf's loopback connection
 * state. This migration changes ONLY the spawn mechanism (popen → bounded
 * subprocess argv, sudo prefix → yuzu::shared::sudo_wrap) — the ruleset
 * content, the single-atomic-`pfctl -f`-call strategy, and `set skip on
 * lo0` are byte-for-byte unchanged. If you find yourself adding `pfctl -a`
 * anywhere in this file, stop — that is the reverted design.
 */

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp> // yuzu::util::safe_output_field — escape attacker/environment-influenced diagnostic text before it reaches a pipe-delimited output row
#include <yuzu/agent/runner_status.hpp>     // yuzu::agent::forward_runner_failure (ABI4 result seam)
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess (ADR-3002 rung 2)

#ifndef _WIN32
#include <spdlog/spdlog.h>
#include "sudo_argv.hpp" // yuzu::shared::sudo_wrap — canonical sudo -n -- <tool> <args> form (agents/shared)
#endif

#include "quarantine_parsers.hpp" // yuzu::quarantine:: pure netsh/iptables/pfctl output parsers

#include <chrono>
#include <cstdio>
#include <format>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "win_str.hpp" // yuzu::win::from_wide (agents/shared, #1681)
#endif

namespace {

using yuzu::quarantine::is_safe_ip;
using yuzu::quarantine::kRulePrefix;

// ── Bounded-execution deadlines (ADR-3002 runner-idiom ceiling) ────────────
//
// 15s for mutating firewall-rule changes (task-set convention shared with
// the sibling users/certificates Wave-2 packages); 10s for the read-only
// status/whitelist queries, which should return near-instantly. Both are
// generous enough never to fire in normal operation and short enough that a
// wedged netsh/iptables/pfctl invocation cannot pin the instruction worker
// indefinitely (the popen()-based predecessor had NO bound at all).
constexpr std::chrono::milliseconds kQuarantineMutateDeadline{15000};
constexpr std::chrono::milliseconds kQuarantineReadDeadline{10000};

// Absolute paths to firewall binaries. These MUST match the paths in the
// sudoers grants — see scripts/install-agent-user.sh
// generate_sudoers_content(). PATH-injection bypass would be possible with
// bare names: an attacker who got code execution as the agent could prepend
// a directory to $PATH containing a malicious `iptables`, and a sudoers
// entry keyed on `/usr/sbin/iptables` would happily run that instead —
// moot now that run_bounded_subprocess never PATH-searches argv[0] at all,
// but the absolute path is also what the sudoers grant itself matches.
#ifdef __APPLE__
constexpr const char* kPfctl = "/sbin/pfctl";
#endif
#ifdef __linux__
constexpr const char* kIptables = "/usr/sbin/iptables";
#endif

// ── Subprocess helper ────────────────────────────────────────────────────

/// Outcome of run_tool(): the captured output PLUS the raw runner result, so
/// a caller can forward the latter through the ABI4 result seam
/// (report_runner_result / yuzu::agent::forward_runner_failure) itself.
struct ToolOutcome {
    std::string output;
    yuzu::agent::SubprocessResult res;
};

/// Direct-argv replacement for the popen()/_popen() shell-string hop that
/// used to run every command here through a shell (ADR-3002 rung 2): the
/// same bounded runner, but exec'd straight to argv[0] with no shell in
/// between — no shell-quoting/injection surface. `merge_stderr=false`
/// matches this file's old `2>/dev/null` redirections; `merge_stderr=true`
/// matches a call site that used to have no redirection at all (stderr
/// simply wasn't captured) but where capturing it now gives the honest
/// failure message a real diagnostic to quote (the established
/// mutating-action convention — see users_plugin.cpp/certificates_plugin.cpp).
ToolOutcome run_tool(const std::vector<std::string>& argv, std::chrono::milliseconds deadline,
                     bool merge_stderr) {
    auto res = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = deadline, .merge_stderr = merge_stderr});
#ifndef _WIN32
    // A cut-short/failed tool call can parse as "not quarantined" / "0 rules
    // applied" — a silent false-negative for a security-critical action.
    // Warn so an operator can distinguish a degraded run from a genuinely
    // clean one. spdlog isn't linked on the Windows leg of this plugin
    // today (no other call site here needed it); the ABI4 result-status
    // forward below is the cross-platform channel.
    if (res.timed_out || !res.tool_ran || res.output_truncated) {
        spdlog::warn("quarantine: degraded run (timed_out={}, tool_ran={}, truncated={}): {}",
                     res.timed_out, res.tool_ran, res.output_truncated,
                     argv.empty() ? std::string{} : argv.front());
    }
#endif
    std::string output = res.output;
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r'))
        output.pop_back();
    return ToolOutcome{std::move(output), std::move(res)};
}

/// Forwards a genuine runner failure (spawn_error/deadline/cancelled/
/// signaled — see runner_status.hpp) through the ABI4 result seam AT MOST
/// ONCE per action: `status_forwarded` is a local guard threaded through
/// every call in one do_*/leaf-function entry point so a later, less-
/// specific failure never overwrites an earlier one (mirrors
/// users_plugin.cpp's run_tool/status_forwarded convention). Returns true
/// iff the tool positively ran and exited zero — the mutating call sites
/// that need that (the old `run_command_rc(...) == 0` rules_applied
/// counters) use the return value; read-only call sites (status/whitelist
/// parses, which must not gate on a query command's exit code — a
/// nonexistent chain/rule set is a normal "not quarantined" outcome, not a
/// failure) ignore it and rely solely on the forwarding side effect.
bool report_runner_result(yuzu::CommandContext& ctx, bool& status_forwarded,
                          const yuzu::agent::SubprocessResult& res) {
    if (!status_forwarded && yuzu::agent::forward_runner_failure(ctx, res))
        status_forwarded = true;
    return res.tool_ran && res.exit_code == 0;
}

// ── String splitting ─────────────────────────────────────────────────────

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

// ── Windows implementation ───────────────────────────────────────────────────

#ifdef _WIN32

/// Absolute path to netsh.exe, resolved via GetSystemDirectoryW so this
/// never depends on PATH (same PATH-hijack rationale as
/// tar_mapdrive_collector.cpp's system32_path — that helper returns a
/// shell-quoted string for its own popen()-based caller; run_bounded_subprocess
/// execs argv[0] directly with no shell, so this returns UNQUOTED). Cached
/// on first call — the system directory can't change during the agent's
/// lifetime.
const std::string& netsh_path() {
    static const std::string path = [] {
        wchar_t dir[MAX_PATH]{};
        UINT n = GetSystemDirectoryW(dir, MAX_PATH);
        if (n == 0 || n >= MAX_PATH)
            return std::string{}; // honest empty -> run_bounded_subprocess's
                                   // own empty-argv[0] spawn_error reject
        return yuzu::win::from_wide(dir) + "\\netsh.exe";
    }();
    return path;
}

struct StatusReadResult {
    bool active = false;
    yuzu::agent::SubprocessResult res;
};
struct WhitelistRead {
    std::vector<std::string> ips;
    yuzu::agent::SubprocessResult res;
};

int win_quarantine(yuzu::CommandContext& ctx, const std::vector<std::string>& whitelist_ips) {
    int rules_applied = 0;
    bool status_forwarded = false;

    auto apply = [&](std::vector<std::string> argv) {
        auto out = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
        if (report_runner_result(ctx, status_forwarded, out.res))
            ++rules_applied;
    };

    // sink: quarantine/win_quarantine#1 — rung-2 runner argv, MUTATING
    apply({netsh_path(), "advfirewall", "firewall", "add", "rule",
          std::format("name={}BlockAllInbound", kRulePrefix), "dir=in", "action=block",
          "enable=yes", "protocol=any"});

    // sink: quarantine/win_quarantine#2 — rung-2 runner argv, MUTATING
    apply({netsh_path(), "advfirewall", "firewall", "add", "rule",
          std::format("name={}BlockAllOutbound", kRulePrefix), "dir=out", "action=block",
          "enable=yes", "protocol=any"});

    // sink: quarantine/win_quarantine#3 — rung-2 runner argv, MUTATING
    apply({netsh_path(), "advfirewall", "firewall", "add", "rule",
          std::format("name={}AllowLoopbackIn", kRulePrefix), "dir=in", "action=allow",
          "enable=yes", "remoteip=127.0.0.1"});

    // sink: quarantine/win_quarantine#4 — rung-2 runner argv, MUTATING
    apply({netsh_path(), "advfirewall", "firewall", "add", "rule",
          std::format("name={}AllowLoopbackOut", kRulePrefix), "dir=out", "action=allow",
          "enable=yes", "remoteip=127.0.0.1"});

    for (const auto& ip : whitelist_ips) {
        // sink: quarantine/win_quarantine#5 — rung-2 runner argv, MUTATING,
        // operator-supplied IP validated by is_safe_ip before reaching here.
        // Argv construction lives in netsh_allow_in_rule_argv
        // (quarantine_parsers.hpp) — pure and unit-tested (FN-03).
        apply(yuzu::quarantine::netsh_allow_in_rule_argv(netsh_path(), ip));

        // sink: quarantine/win_quarantine#6 — rung-2 runner argv, MUTATING,
        // operator-supplied IP validated by is_safe_ip before reaching here
        apply({netsh_path(), "advfirewall", "firewall", "add", "rule",
              std::format("name={}AllowOut_{}", kRulePrefix, ip), "dir=out", "action=allow",
              "enable=yes", std::format("remoteip={}", ip)});
    }

    if (rules_applied == 0) {
        // Every single netsh call failed to apply — the device is NOT
        // quarantined. Reporting "quarantined" here regardless of
        // rules_applied was the pre-migration behaviour; a security-critical
        // action that silently isolates nothing is exactly the failure mode
        // this migration must close.
        if (!status_forwarded) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "quarantine:win_quarantine all rules failed to apply");
        }
        ctx.write_output("status|failed|rules_applied|0");
        return 1;
    }

    ctx.write_output(std::format("status|quarantined|rules_applied|{}", rules_applied));
    return 0;
}

int win_unquarantine(yuzu::CommandContext& ctx) {
    bool status_forwarded = false;
    // Tracks a CLEAN failure (tool ran, exited nonzero) on one of the rule
    // deletions below — distinct from status_forwarded, which only covers a
    // genuine runner-level failure (spawn/deadline/cancel/signal). Every
    // rule in rules_to_delete was just observed present in the show-rule
    // capture, so a delete that runs and refuses is a real signal the
    // release did not fully complete, not routine idempotency noise —
    // discarding it (the pre-fix behaviour) let a partially-failed release
    // still report "released".
    bool delete_failed = false;

    // netsh does not support wildcards, so we list rules and delete matches.
    // sink: quarantine/win_unquarantine#1 — rung-2 runner argv, read-only
    auto out_in = run_tool({netsh_path(), "advfirewall", "firewall", "show", "rule", "name=all",
                            "dir=in"},
                           kQuarantineReadDeadline, /*merge_stderr=*/false);
    report_runner_result(ctx, status_forwarded, out_in.res);

    // sink: quarantine/win_unquarantine#2 — rung-2 runner argv, read-only
    auto out_out = run_tool({netsh_path(), "advfirewall", "firewall", "show", "rule", "name=all",
                             "dir=out"},
                            kQuarantineReadDeadline, /*merge_stderr=*/false);
    report_runner_result(ctx, status_forwarded, out_out.res);

    std::string combined = out_in.output + "\n" + out_out.output;
    auto rules_to_delete = yuzu::quarantine::netsh_matching_rule_names(combined);

    for (const auto& rule : rules_to_delete) {
        // sink: quarantine/win_unquarantine#3 — rung-2 runner argv, MUTATING
        auto del = run_tool({netsh_path(), "advfirewall", "firewall", "delete", "rule",
                             std::format("name={}", rule)},
                            kQuarantineMutateDeadline, /*merge_stderr=*/true);
        if (!report_runner_result(ctx, status_forwarded, del.res))
            delete_failed = true;
    }

    if (status_forwarded || delete_failed) {
        // A genuine runner failure (spawn/deadline/cancel/signal), OR a
        // clean failure on one of the rule deletions themselves, occurred
        // somewhere in the release sequence — do NOT claim the device is
        // released when the release commands themselves may not have run to
        // completion. This is the unquarantine-side mirror of the invariant
        // the macOS incident this migration must not reintroduce: a
        // firewalled host must never be silently reported as recovered.
        if (!status_forwarded) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "quarantine:win_unquarantine one or more rule deletions failed");
        }
        ctx.write_output("status|release_uncertain");
        return 1;
    }

    ctx.write_output("status|released");
    return 0;
}

StatusReadResult win_is_quarantined() {
    // sink: quarantine/win_is_quarantined#1 — rung-2 runner argv, read-only
    auto out = run_tool({netsh_path(), "advfirewall", "firewall", "show", "rule", "name=all",
                        "dir=in"},
                       kQuarantineReadDeadline, /*merge_stderr=*/false);
    StatusReadResult result;
    result.active = yuzu::quarantine::netsh_rules_present(out.output);
    result.res = std::move(out.res);
    return result;
}

WhitelistRead win_get_whitelist() {
    // sink: quarantine/win_get_whitelist#1 — rung-2 runner argv, read-only
    auto out = run_tool({netsh_path(), "advfirewall", "firewall", "show", "rule", "name=all",
                        "dir=in"},
                       kQuarantineReadDeadline, /*merge_stderr=*/false);
    WhitelistRead result;
    result.ips = yuzu::quarantine::netsh_whitelist_ips(out.output);
    result.res = std::move(out.res);
    return result;
}

#endif // _WIN32

// ── Linux implementation ─────────────────────────────────────────────────────

#ifdef __linux__

struct StatusReadResult {
    bool active = false;
    yuzu::agent::SubprocessResult res;
};
struct WhitelistRead {
    std::vector<std::string> ips;
    yuzu::agent::SubprocessResult res;
};

int linux_quarantine(yuzu::CommandContext& ctx, const std::vector<std::string>& whitelist_ips) {
    int rules_applied = 0;
    bool status_forwarded = false;

    auto apply = [&](std::vector<std::string> tool_argv) {
        auto argv = yuzu::shared::sudo_wrap(std::move(tool_argv));
        auto out = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
        if (report_runner_result(ctx, status_forwarded, out.res))
            ++rules_applied;
    };
    auto apply_ignore_result = [&](std::vector<std::string> tool_argv) {
        auto argv = yuzu::shared::sudo_wrap(std::move(tool_argv));
        auto out = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
        // Best-effort/idempotent step (create-if-absent, remove-stale-jump)
        // — a nonzero exit here is expected on a fresh chain and was never
        // checked pre-migration. A genuine runner failure is still
        // forwarded so a broken sudoers grant surfaces on the FIRST call
        // that hits it, not silently on a later one.
        report_runner_result(ctx, status_forwarded, out.res);
    };

    // Create the yuzu-quarantine chain (ignore error if it already exists)
    // sink: quarantine/linux_quarantine#1 — rung-2 sudo-governed runner argv, MUTATING (idempotent)
    apply_ignore_result({kIptables, "-N", "yuzu-quarantine"});
    // Flush the chain to start fresh. Best-effort/non-counting like `-N`
    // above (pre-migration behaviour, `git show 313031966:...` at the
    // merge-base): a flush that succeeds installs zero containment rules by
    // itself, so it must never contribute to rules_applied — otherwise a
    // flush-only success with every subsequent ACCEPT/DROP/jump rule failing
    // would report `status|quarantined|rules_applied|1`, a false-positive
    // quarantine with zero real rules in place.
    // sink: quarantine/linux_quarantine#2 — rung-2 sudo-governed runner argv, MUTATING (non-counting)
    apply_ignore_result({kIptables, "-F", "yuzu-quarantine"});

    // Allow loopback
    // sink: quarantine/linux_quarantine#3 — rung-2 sudo-governed runner argv, MUTATING
    apply({kIptables, "-A", "yuzu-quarantine", "-i", "lo", "-j", "ACCEPT"});
    // sink: quarantine/linux_quarantine#4 — rung-2 sudo-governed runner argv, MUTATING
    apply({kIptables, "-A", "yuzu-quarantine", "-o", "lo", "-j", "ACCEPT"});

    // Allow established/related connections (keeps management connection alive)
    // sink: quarantine/linux_quarantine#5 — rung-2 sudo-governed runner argv, MUTATING
    apply({kIptables, "-A", "yuzu-quarantine", "-m", "state", "--state", "ESTABLISHED,RELATED",
          "-j", "ACCEPT"});

    // Allow each whitelisted IP
    for (const auto& ip : whitelist_ips) {
        // sink: quarantine/linux_quarantine#6 — rung-2 sudo-governed runner
        // argv, MUTATING, operator-supplied IP validated by is_safe_ip.
        // Argv construction lives in iptables_accept_source_argv
        // (quarantine_parsers.hpp) — pure and unit-tested (FN-03).
        apply(yuzu::quarantine::iptables_accept_source_argv(kIptables, ip));
        // sink: quarantine/linux_quarantine#7 — rung-2 sudo-governed runner
        // argv, MUTATING, operator-supplied IP validated by is_safe_ip
        apply({kIptables, "-A", "yuzu-quarantine", "-d", ip, "-j", "ACCEPT"});
    }

    // Drop everything else
    // sink: quarantine/linux_quarantine#8 — rung-2 sudo-governed runner argv, MUTATING
    apply({kIptables, "-A", "yuzu-quarantine", "-j", "DROP"});

    // Insert jump to our chain at the top of INPUT and OUTPUT
    // Remove any existing jumps first to avoid duplicates
    // sink: quarantine/linux_quarantine#9 — rung-2 sudo-governed runner argv, MUTATING (idempotent)
    apply_ignore_result({kIptables, "-D", "INPUT", "-j", "yuzu-quarantine"});
    // sink: quarantine/linux_quarantine#10 — rung-2 sudo-governed runner argv, MUTATING (idempotent)
    apply_ignore_result({kIptables, "-D", "OUTPUT", "-j", "yuzu-quarantine"});
    // sink: quarantine/linux_quarantine#11 — rung-2 sudo-governed runner argv, MUTATING
    apply({kIptables, "-I", "INPUT", "1", "-j", "yuzu-quarantine"});
    // sink: quarantine/linux_quarantine#12 — rung-2 sudo-governed runner argv, MUTATING
    apply({kIptables, "-I", "OUTPUT", "1", "-j", "yuzu-quarantine"});

    if (rules_applied == 0) {
        if (!status_forwarded) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "quarantine:linux_quarantine all rules failed to apply");
        }
        ctx.write_output("status|failed|rules_applied|0");
        return 1;
    }

    ctx.write_output(std::format("status|quarantined|rules_applied|{}", rules_applied));
    return 0;
}

int linux_unquarantine(yuzu::CommandContext& ctx) {
    bool status_forwarded = false;
    // Clean-failure tracker for the genuine teardown steps (flush + delete
    // chain) — see win_unquarantine's identical-purpose comment. Distinct
    // from the two -D jump removals below, which stay best-effort/ignored:
    // they are idempotent the same way linux_quarantine's own -D calls are
    // (a jump that's already absent, e.g. on a repeat unquarantine, is not a
    // failure). Flushing/deleting the chain is the actual release action,
    // so a clean (tool-ran, nonzero-exit) failure there must surface.
    bool teardown_failed = false;

    auto apply_ignore_result = [&](std::vector<std::string> tool_argv) {
        auto argv = yuzu::shared::sudo_wrap(std::move(tool_argv));
        auto out = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
        report_runner_result(ctx, status_forwarded, out.res);
    };
    auto apply = [&](std::vector<std::string> tool_argv) {
        auto argv = yuzu::shared::sudo_wrap(std::move(tool_argv));
        auto out = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
        if (!report_runner_result(ctx, status_forwarded, out.res))
            teardown_failed = true;
    };

    // Remove jumps from INPUT and OUTPUT — best-effort/idempotent
    // sink: quarantine/linux_unquarantine#1 — rung-2 sudo-governed runner argv, MUTATING (idempotent)
    apply_ignore_result({kIptables, "-D", "INPUT", "-j", "yuzu-quarantine"});
    // sink: quarantine/linux_unquarantine#2 — rung-2 sudo-governed runner argv, MUTATING (idempotent)
    apply_ignore_result({kIptables, "-D", "OUTPUT", "-j", "yuzu-quarantine"});
    // Flush and delete the chain — the genuine release steps
    // sink: quarantine/linux_unquarantine#3 — rung-2 sudo-governed runner argv, MUTATING
    apply({kIptables, "-F", "yuzu-quarantine"});
    // sink: quarantine/linux_unquarantine#4 — rung-2 sudo-governed runner argv, MUTATING
    apply({kIptables, "-X", "yuzu-quarantine"});

    if (status_forwarded || teardown_failed) {
        // See win_unquarantine's identical comment: a genuine runner
        // failure, OR a clean failure to flush/delete the chain, must never
        // be reported as "released".
        if (!status_forwarded) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "quarantine:linux_unquarantine chain flush/delete failed");
        }
        ctx.write_output("status|release_uncertain");
        return 1;
    }

    ctx.write_output("status|released");
    return 0;
}

StatusReadResult linux_is_quarantined() {
    // -L is a read-only list operation; depending on the distro and kernel
    // build, iptables will refuse the operation without root even for
    // listing because /proc/net/ip_tables_names is root-readable. So we
    // also use sudo for the read path.
    // sink: quarantine/linux_is_quarantined#1 — rung-2 sudo-governed runner argv, read-only
    auto argv = yuzu::shared::sudo_wrap({kIptables, "-L", "INPUT", "-n"});
    auto out = run_tool(argv, kQuarantineReadDeadline, /*merge_stderr=*/false);
    StatusReadResult result;
    result.active = yuzu::quarantine::iptables_chain_referenced(out.output);
    result.res = std::move(out.res);
    return result;
}

WhitelistRead linux_get_whitelist() {
    // sink: quarantine/linux_get_whitelist#1 — rung-2 sudo-governed runner argv, read-only
    auto argv = yuzu::shared::sudo_wrap({kIptables, "-L", "yuzu-quarantine", "-n"});
    auto out = run_tool(argv, kQuarantineReadDeadline, /*merge_stderr=*/false);
    WhitelistRead result;
    result.ips = yuzu::quarantine::iptables_whitelist_ips(out.output);
    result.res = std::move(out.res);
    return result;
}

#endif // __linux__

// ── macOS implementation ─────────────────────────────────────────────────────

#ifdef __APPLE__

struct StatusReadResult {
    bool active = false;
    yuzu::agent::SubprocessResult res;
};
struct WhitelistRead {
    std::vector<std::string> ips;
    yuzu::agent::SubprocessResult res;
};

// Compose-and-load the complete pf ruleset for a quarantine state.
//
// `rules_written_out` is set to the count of rule lines we wrote.
// `error_out` is set to a non-empty operator-actionable string on
// failure; caller writes it to ctx.write_output.
//
// Returns 0 on success, non-zero on failure. Used by both
// macos_quarantine() and the macOS branch of do_whitelist() so the
// "rebuild the ruleset and atomically load it" logic lives in one
// place. See the header comment above (and `git log -1 672896112`) for
// why this MUST stay ONE atomic `pfctl -f` call against the main
// ruleset with `set skip on lo0` — never a named anchor.
int macos_load_ruleset(yuzu::CommandContext& ctx, const std::vector<std::string>& whitelist_ips,
                       int* rules_written_out, std::string* error_out,
                       bool* pf_enable_failed_out = nullptr) {
    int rules_written = 0;
    std::string rules;

    rules += "# Yuzu agent quarantine — generated by quarantine_plugin.cpp\n";
    rules += "# DO NOT edit by hand; this file is overwritten on every dispatch.\n";
    rules += "# Restore via `pfctl -f /etc/pf.conf` (macos_unquarantine does this).\n";
    rules += "\n";
    rules += "# Bypass loopback entirely — keeps agent⇄gateway⇄server TCP alive\n";
    rules += "# through the rule reload. See comment in quarantine_plugin.cpp.\n";
    rules += "set skip on lo0\n";
    ++rules_written;

    for (const auto& ip : whitelist_ips) {
        rules += std::format("pass quick from {} to any keep state\n", ip);
        rules += std::format("pass quick from any to {} keep state\n", ip);
        rules_written += 2;
    }

    rules += "block all\n";
    ++rules_written;

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

    // sink: quarantine/macos_load_ruleset#1 — rung-2 sudo-governed runner
    // argv, MUTATING, single atomic full-ruleset reload
    // (`sudo -n -- /sbin/pfctl -f <tmpfile>`). THE call this migration is
    // bound not to change the shape of — see the header comment on the
    // 672896112 incident: never split this into a named-anchor `pfctl -a`
    // plus a second attach call. Argv construction lives in
    // pfctl_load_ruleset_argv (quarantine_parsers.hpp) — pure and
    // unit-tested (FN-03).
    auto argv = yuzu::shared::sudo_wrap(
        yuzu::quarantine::pfctl_load_ruleset_argv(kPfctl, tmp_file.path()));
    auto load_out = run_tool(argv, kQuarantineMutateDeadline, /*merge_stderr=*/true);
    if (!(load_out.res.tool_ran && load_out.res.exit_code == 0)) {
        // A quarantine that silently fails to apply is the single most
        // safety-critical failure mode in this file — always mark the ABI4
        // result seam, whether the failure is a genuine runner-level event
        // (spawn/deadline/etc, forwarded below) or a clean exit with a
        // nonzero rc (e.g. a missing sudoers grant, which exits normally
        // from sudo's own perspective — exit-code semantics are the
        // caller's domain per runner_status.hpp, so classify_runner_failure
        // alone would miss this case).
        if (!yuzu::agent::forward_runner_failure(ctx, load_out.res)) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "quarantine:macos_load_ruleset pfctl exited non-zero");
        }
        int exit_code = load_out.res.tool_ran ? load_out.res.exit_code : -1;
        std::string diag = load_out.output.empty()
                               ? std::string{}
                               : std::format(" pfctl said: {}",
                                             yuzu::util::safe_output_field(load_out.output));
        *error_out = std::format("pfctl load failed (rc={}). Likely the agent account "
                                 "is not in /etc/sudoers.d/yuzu-agent — run "
                                 "`sudo bash scripts/install-agent-user.sh --check` to verify.{}",
                                 exit_code, diag);
        return 1;
    }

    // Enable pf if not already enabled. Idempotent — the kernel returns a
    // harmless warning to stderr when called on an already-enabled pf.
    // Best-effort in the sense that a failure here does not unwind the
    // ruleset load that just succeeded above — but the failure is still
    // forwarded through the ABI4 result-status seam (genuine runner
    // failure via forward_runner_failure, or a clean nonzero exit via
    // set_result_status) so a caller can never mistake "ruleset loaded"
    // for "pf actually enabled". On stock macOS pf ships disabled, so a
    // silently swallowed failure here would mean the quarantine reports
    // success while blocking nothing.
    // sink: quarantine/macos_load_ruleset#2 — rung-2 sudo-governed runner
    // argv, MUTATING (idempotent enable; failure forwarded, not ignored)
    auto enable_argv = yuzu::shared::sudo_wrap({kPfctl, "-e"});
    auto enable_out = run_tool(enable_argv, kQuarantineMutateDeadline, /*merge_stderr=*/false);
    if (!(enable_out.res.tool_ran && enable_out.res.exit_code == 0)) {
        if (!yuzu::agent::forward_runner_failure(ctx, enable_out.res)) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "quarantine:macos_load_ruleset pfctl -e failed to enable pf");
        }
        // The ABI4 result seam above is the durable, server-persisted signal
        // -- but it isn't the channel most customer-facing tooling parses
        // (docs/user-manual/agent-plugins.md documents write_output's
        // pipe-delimited fields as the contract). Surface it there too, via
        // the out-param, so a caller that only reads stdout still learns
        // the ruleset loaded but pf may not be enforcing it.
        if (pf_enable_failed_out)
            *pf_enable_failed_out = true;
    }

    *rules_written_out = rules_written;
    return 0;
}

int macos_quarantine(yuzu::CommandContext& ctx, const std::vector<std::string>& whitelist_ips) {
    // rules_written counts the lines we hand to pfctl. The actual number
    // of rules installed in pf is reported back to the operator only if
    // pfctl's load succeeds (see the rc check inside macos_load_ruleset).
    int rules_written = 0;
    std::string error;
    bool pf_enable_failed = false;
    if (macos_load_ruleset(ctx, whitelist_ips, &rules_written, &error, &pf_enable_failed) != 0) {
        ctx.write_output(std::format("error|{}", error));
        return 1;
    }
    if (pf_enable_failed) {
        ctx.write_output(std::format(
            "status|quarantined|rules_applied|{}|note|ruleset loaded but pf failed to enable "
            "-- traffic may not actually be blocked, check agent logs",
            rules_written));
    } else {
        ctx.write_output(std::format("status|quarantined|rules_applied|{}", rules_written));
    }
    return 0;
}

int macos_unquarantine(yuzu::CommandContext& ctx) {
    bool status_forwarded = false;

    // Restore the system default ruleset by reloading /etc/pf.conf.
    // macOS ships /etc/pf.conf with the platform's default anchors
    // (com.apple/*, etc.). After our quarantine clobbered the main
    // ruleset, this is the cleanest way to get back to "what the OS
    // started with" without trying to remember and replay the prior
    // state ourselves.
    // sink: quarantine/macos_unquarantine#1 — rung-2 sudo-governed runner argv, MUTATING
    auto restore_argv = yuzu::shared::sudo_wrap({kPfctl, "-f", "/etc/pf.conf"});
    auto restore_out = run_tool(restore_argv, kQuarantineMutateDeadline, /*merge_stderr=*/false);
    bool restore_ok = report_runner_result(ctx, status_forwarded, restore_out.res);

    if (!restore_ok) {
        // /etc/pf.conf might not exist or might fail to parse on a
        // non-default OS install. Fall back to disabling pf entirely —
        // strictly more permissive than what the user wants, but at
        // least the box is reachable for the operator to clean up.
        // sink: quarantine/macos_unquarantine#2 — rung-2 sudo-governed runner argv, MUTATING
        auto disable_argv = yuzu::shared::sudo_wrap({kPfctl, "-d"});
        auto disable_out = run_tool(disable_argv, kQuarantineMutateDeadline, /*merge_stderr=*/false);
        bool disable_ok = report_runner_result(ctx, status_forwarded, disable_out.res);

        if (!disable_ok) {
            // Neither restoring /etc/pf.conf NOR disabling pf outright
            // succeeded — the host may still be firewalled. Reporting
            // "released" here unconditionally (the pre-migration behaviour
            // — this fallback call's return value was previously discarded
            // entirely) is exactly the silent-failure class this migration
            // must not reintroduce; see the 672896112 incident note at the
            // top of this file.
            if (!status_forwarded) {
                ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE,
                                      YUZU_RESULT_COMPLETENESS_PARTIAL,
                                      "quarantine:macos_unquarantine restore and disable both failed");
            }
            ctx.write_output(
                "error|failed to restore /etc/pf.conf and failed to disable pf — host may "
                "still be firewalled, manual `pfctl -F all` may be required");
            return 1;
        }

        ctx.write_output("status|released|note|pf disabled (could not restore /etc/pf.conf)");
        return 0;
    }

    ctx.write_output("status|released");
    return 0;
}

StatusReadResult macos_is_quarantined() {
    // We're quarantined iff the active main ruleset has our `block all`
    // rule (the load-bearing default-deny). Pre-patch this looked at the
    // yuzu-quarantine anchor; the new design writes the rules directly into
    // the main ruleset so we check there instead.
    // sink: quarantine/macos_is_quarantined#1 — rung-2 sudo-governed runner argv, read-only
    auto argv = yuzu::shared::sudo_wrap({kPfctl, "-s", "rules"});
    auto out = run_tool(argv, kQuarantineReadDeadline, /*merge_stderr=*/false);
    StatusReadResult result;
    result.active = yuzu::quarantine::pfctl_rules_blocked(out.output);
    result.res = std::move(out.res);
    return result;
}

WhitelistRead macos_get_whitelist() {
    // sink: quarantine/macos_get_whitelist#1 — rung-2 sudo-governed runner argv, read-only
    auto argv = yuzu::shared::sudo_wrap({kPfctl, "-s", "rules"});
    auto out = run_tool(argv, kQuarantineReadDeadline, /*merge_stderr=*/false);
    WhitelistRead result;
    result.ips = yuzu::quarantine::pfctl_whitelist_ips(out.output);
    result.res = std::move(out.res);
    return result;
}

#endif // __APPLE__

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// Wave-2 ADR-3002 migration: every leg on every platform now shells out
// through yuzu::agent::run_bounded_subprocess with clean, pre-split argv —
// never popen()/_popen(), never a shell. Linux (sudo-governed iptables) and
// macOS (sudo-governed pfctl) go through yuzu::shared::sudo_wrap's `sudo -n
// -- <tool> <args>` form; Windows (netsh) needs no sudo-equivalent, since
// the YuzuAgent service account's own privilege already covers it. That is
// rung 2 throughout — a bounded direct-argv tool invocation, whether or not
// sudo-governed, is not rung 1 (no native OS API is used; Windows in
// particular has a native COM firewall-rule API — INetFwPolicy2/
// INetFwRule — that this migration deliberately did not evaluate, since the
// task was mechanism-only). quarantine is the endpoint's most disruptive
// action here — it blocks essentially all traffic except the whitelist —
// so it is classified Destructive AND Irreversible. `unquarantine` restores
// reachability — scripts/test/instructions_quarantine_survivor.py verifies
// end-to-end that the box is NOT left locked out — but that is connectivity
// restoration, not STATE restoration: on macOS `macos_load_ruleset` replaces
// the whole active pf ruleset via `pfctl -f`, and `macos_unquarantine`
// deliberately restores only the OS-default /etc/pf.conf rather than replaying
// the prior state, so any runtime pf rules the endpoint had are permanently
// lost. Only Linux (a Yuzu-owned iptables chain) and Windows have a genuine
// undo, so the catalogue row is Irreversible across all platforms — see
// server/core/src/capability_decls/plugin_action_catalogue_c.hpp.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "quarantine",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "sudo-governed iptables via bounded runner argv", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "sudo-governed pfctl via bounded runner argv", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 2, "netsh via bounded runner argv (service-account privilege, no sudo)", nullptr},
    },
    {
        /* .action      = */ "unquarantine",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "sudo-governed iptables via bounded runner argv", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "sudo-governed pfctl via bounded runner argv", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 2, "netsh via bounded runner argv (service-account privilege, no sudo)", nullptr},
    },
    {
        /* .action      = */ "status",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "sudo-governed iptables via bounded runner argv", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "sudo-governed pfctl via bounded runner argv", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 2, "netsh via bounded runner argv (service-account privilege, no sudo)", nullptr},
    },
    {
        /* .action      = */ "whitelist",
        /* .linux_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "sudo-governed iptables via bounded runner argv", nullptr},
        /* .macos_leg   = */ {YUZU_SUPPORT_SUPPORTED, 2, "sudo-governed pfctl via bounded runner argv", nullptr},
        /* .windows_leg = */ {YUZU_SUPPORT_SUPPORTED, 2, "netsh via bounded runner argv (service-account privilege, no sudo)", nullptr},
    },
};

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

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
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
        bool status_forwarded = false;
#ifdef _WIN32
        auto check = win_is_quarantined();
#elif defined(__linux__)
        auto check = linux_is_quarantined();
#elif defined(__APPLE__)
        auto check = macos_is_quarantined();
#else
        ctx.write_output("error|unsupported platform");
        return 1;
#endif
        // Ignore the return value: a nonzero/failed exit from a status
        // query is not itself an error (an absent chain/rule is a normal
        // "not quarantined" outcome) — only a genuine runner-level failure
        // (forwarded here) should mark the ABI4 result seam degraded.
        report_runner_result(ctx, status_forwarded, check.res);
        ctx.write_output(std::format("state|{}", check.active ? "active" : "inactive"));

        if (check.active) {
#ifdef _WIN32
            auto wl = win_get_whitelist();
#elif defined(__linux__)
            auto wl = linux_get_whitelist();
#elif defined(__APPLE__)
            auto wl = macos_get_whitelist();
#endif
            report_runner_result(ctx, status_forwarded, wl.res);
            ctx.write_output(std::format("whitelist|{}", join_ips(wl.ips)));
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

        bool status_forwarded = false;
        // Tracks a CLEAN failure (tool ran, exited nonzero) on any Windows/
        // Linux add/remove mutation below — distinct from status_forwarded,
        // which only covers a genuine runner-level failure. Discarding this
        // (the pre-fix behaviour) let a whitelist add/remove that the
        // underlying tool refused still report "status|updated". macOS's
        // add/remove branches don't need this: macos_load_ruleset already
        // checks its own pfctl exit code and returns early on failure.
        bool mutation_failed = false;

        if (action_param == "add") {
#ifdef _WIN32
            for (const auto& ip : new_ips) {
                // sink: quarantine/do_whitelist#1 — rung-2 runner argv,
                // MUTATING, operator-supplied IP validated by is_safe_ip.
                // Argv construction lives in netsh_allow_in_rule_argv
                // (quarantine_parsers.hpp) — pure and unit-tested (FN-03).
                auto out1 = run_tool(yuzu::quarantine::netsh_allow_in_rule_argv(netsh_path(), ip),
                                    kQuarantineMutateDeadline, /*merge_stderr=*/true);
                if (!report_runner_result(ctx, status_forwarded, out1.res))
                    mutation_failed = true;
                // sink: quarantine/do_whitelist#2 — rung-2 runner argv,
                // MUTATING, operator-supplied IP validated by is_safe_ip
                auto out2 = run_tool({netsh_path(), "advfirewall", "firewall", "add", "rule",
                                     std::format("name={}AllowOut_{}", kRulePrefix, ip), "dir=out",
                                     "action=allow", "enable=yes", std::format("remoteip={}", ip)},
                                    kQuarantineMutateDeadline, /*merge_stderr=*/true);
                if (!report_runner_result(ctx, status_forwarded, out2.res))
                    mutation_failed = true;
            }
#elif defined(__linux__)
            {
                for (const auto& ip : new_ips) {
                    // Insert before the DROP rule (second-to-last position)
                    // sink: quarantine/do_whitelist#5 — rung-2 sudo-governed
                    // runner argv, MUTATING, operator-supplied IP validated
                    // by is_safe_ip
                    auto argv1 = yuzu::shared::sudo_wrap(
                        {kIptables, "-I", "yuzu-quarantine", "-s", ip, "-j", "ACCEPT"});
                    auto out1 = run_tool(argv1, kQuarantineMutateDeadline, /*merge_stderr=*/true);
                    if (!report_runner_result(ctx, status_forwarded, out1.res))
                        mutation_failed = true;
                    // sink: quarantine/do_whitelist#6 — rung-2 sudo-governed
                    // runner argv, MUTATING, operator-supplied IP validated
                    // by is_safe_ip
                    auto argv2 = yuzu::shared::sudo_wrap(
                        {kIptables, "-I", "yuzu-quarantine", "-d", ip, "-j", "ACCEPT"});
                    auto out2 = run_tool(argv2, kQuarantineMutateDeadline, /*merge_stderr=*/true);
                    if (!report_runner_result(ctx, status_forwarded, out2.res))
                        mutation_failed = true;
                }
            }
#elif defined(__APPLE__)
            {
                // The new design (no anchor, rules in main ruleset) means
                // "add" = "rebuild the entire ruleset with the union of
                // current whitelist + new IPs". We get the current
                // whitelist via macos_get_whitelist() and merge.
                auto current = macos_get_whitelist();
                if (!report_runner_result(ctx, status_forwarded, current.res)) {
                    // The prerequisite whitelist read failed — either a
                    // genuine runner failure (already forwarded above) or a
                    // clean nonzero exit (tool ran, refused). Either way
                    // current.ips cannot be trusted as the whitelist
                    // baseline: rebuilding the entire main pf ruleset from
                    // an empty/wrong set would silently drop any real
                    // whitelisted entries (including a possible
                    // management-server IP) — the same impact class as the
                    // 672896112 incident this migration exists to prevent.
                    // Abort instead of rebuilding from an unproven read.
                    if (!status_forwarded) {
                        ctx.set_result_status(
                            YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                            "quarantine:do_whitelist macOS whitelist read failed before add");
                    }
                    ctx.write_output("error|whitelist read failed, ruleset not rewritten");
                    return 1;
                }
                for (const auto& ip : new_ips) {
                    bool dup = false;
                    for (const auto& existing : current.ips) {
                        if (existing == ip) {
                            dup = true;
                            break;
                        }
                    }
                    if (!dup)
                        current.ips.push_back(ip);
                }
                int rules_written = 0;
                std::string err;
                if (macos_load_ruleset(ctx, current.ips, &rules_written, &err) != 0) {
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
                // sink: quarantine/do_whitelist#3 — rung-2 runner argv, MUTATING
                auto out1 =
                    run_tool({netsh_path(), "advfirewall", "firewall", "delete", "rule",
                             std::format("name={}AllowIn_{}", kRulePrefix, ip)},
                            kQuarantineMutateDeadline, /*merge_stderr=*/true);
                if (!report_runner_result(ctx, status_forwarded, out1.res))
                    mutation_failed = true;
                // sink: quarantine/do_whitelist#4 — rung-2 runner argv, MUTATING
                auto out2 =
                    run_tool({netsh_path(), "advfirewall", "firewall", "delete", "rule",
                             std::format("name={}AllowOut_{}", kRulePrefix, ip)},
                            kQuarantineMutateDeadline, /*merge_stderr=*/true);
                if (!report_runner_result(ctx, status_forwarded, out2.res))
                    mutation_failed = true;
            }
#elif defined(__linux__)
            {
                for (const auto& ip : new_ips) {
                    // sink: quarantine/do_whitelist#7 — rung-2 sudo-governed
                    // runner argv, MUTATING
                    auto argv1 = yuzu::shared::sudo_wrap(
                        {kIptables, "-D", "yuzu-quarantine", "-s", ip, "-j", "ACCEPT"});
                    auto out1 = run_tool(argv1, kQuarantineMutateDeadline, /*merge_stderr=*/true);
                    if (!report_runner_result(ctx, status_forwarded, out1.res))
                        mutation_failed = true;
                    // sink: quarantine/do_whitelist#8 — rung-2 sudo-governed
                    // runner argv, MUTATING
                    auto argv2 = yuzu::shared::sudo_wrap(
                        {kIptables, "-D", "yuzu-quarantine", "-d", ip, "-j", "ACCEPT"});
                    auto out2 = run_tool(argv2, kQuarantineMutateDeadline, /*merge_stderr=*/true);
                    if (!report_runner_result(ctx, status_forwarded, out2.res))
                        mutation_failed = true;
                }
            }
#elif defined(__APPLE__)
            {
                // "remove" = rebuild the ruleset with current-whitelist
                // minus new_ips. macos_load_ruleset takes the final
                // desired set; we don't manipulate individual rules
                // (which the old anchor design tried to do via string
                // matching, with the well-known false-match risk).
                auto current = macos_get_whitelist();
                if (!report_runner_result(ctx, status_forwarded, current.res)) {
                    // Same rationale as the "add" branch above: a failed
                    // prerequisite read (runner failure OR clean nonzero
                    // exit) must not be treated as an empty whitelist —
                    // that would rebuild the ruleset with nothing
                    // whitelisted at all. Abort rather than rebuild.
                    if (!status_forwarded) {
                        ctx.set_result_status(
                            YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                            "quarantine:do_whitelist macOS whitelist read failed before remove");
                    }
                    ctx.write_output("error|whitelist read failed, ruleset not rewritten");
                    return 1;
                }
                std::vector<std::string> filtered;
                for (const auto& ip : current.ips) {
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
                if (macos_load_ruleset(ctx, filtered, &rules_written, &err) != 0) {
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
        auto current_read = win_get_whitelist();
#elif defined(__linux__)
        auto current_read = linux_get_whitelist();
#elif defined(__APPLE__)
        auto current_read = macos_get_whitelist();
#else
        struct { std::vector<std::string> ips; } current_read;
#endif
#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
        report_runner_result(ctx, status_forwarded, current_read.res);
#endif
        if (status_forwarded || mutation_failed) {
            // A genuine runner failure, OR a clean failure on one of the
            // add/remove mutations themselves, occurred — do NOT claim the
            // whitelist is updated when the underlying tool may not have
            // applied every change.
            if (!status_forwarded) {
                ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                      "quarantine:do_whitelist one or more rule mutations failed");
            }
            ctx.write_output(
                std::format("status|update_uncertain|whitelist|{}", join_ips(current_read.ips)));
            return 1;
        }
        ctx.write_output(std::format("status|updated|whitelist|{}", join_ips(current_read.ips)));
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(QuarantinePlugin)
