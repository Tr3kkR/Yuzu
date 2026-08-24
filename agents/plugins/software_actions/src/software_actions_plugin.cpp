/**
 * software_actions_plugin.cpp — Software upgrade info plugin for Yuzu
 *
 * Actions:
 *   "list_upgradable" — List packages/apps that can be upgraded (read-only).
 *   "installed_count" — Quick count of installed packages/apps.
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   upgradable|name|current|available
 *   count|N
 *
 * ADR-3002 acquisition-ladder migration (Wave 4, PR4.3b): every popen/_popen
 * shell-out is replaced — Windows' installed_count by a native Reg*W subkey
 * count (rung 1, zero subprocesses), everything else by the shared
 * agent-core bounded argv runner (rung 2, run_bounded_subprocess /
 * probe_tool_path) — no shell, no PATH search, no string-as-code surface. A
 * runner-level failure (spawn error / deadline / cancelled / signaled) is
 * always forwarded through the ABI4 result-status seam via
 * forward_runner_failure — never silently reported as a clean result.
 */

#include <yuzu/plugin.hpp>

#include <chrono>
#include <cstddef>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include <yuzu/agent/runner_status.hpp>     // yuzu::agent::forward_runner_failure
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess / probe_tool_path

#include "software_actions_parsers.hpp" // yuzu::software_actions::{parse_*, count_*, yum_checkupdate_is_success}

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681) — from_wide for %LOCALAPPDATA%
#pragma comment(lib, "advapi32.lib")
#endif

namespace {

// Read-only enumeration tools (apt/yum/dpkg-query/rpm/pkgutil): quick local
// reads, generous enough never to fire on a healthy endpoint.
constexpr std::chrono::milliseconds kQuickToolDeadline{20'000};
// winget (hits its configured source over the network) and softwareupdate -l
// (observed to take tens of seconds against Apple's catalog) are both
// slower, single-shot, read-only calls — a longer ceiling that still bounds
// a wedged tool rather than pinning the instruction worker indefinitely.
constexpr std::chrono::milliseconds kSlowToolDeadline{60'000};

#ifdef _WIN32

// RAII closer for an HKEY (installed_apps_plugin.cpp's HKeyCloser pattern —
// a tiny local copy rather than pulling in that plugin's headers).
struct HKeyCloser {
    HKEY h;
    explicit HKeyCloser(HKEY k) : h(k) {}
    ~HKeyCloser() {
        if (h)
            RegCloseKey(h);
    }
    HKeyCloser(const HKeyCloser&) = delete;
    HKeyCloser& operator=(const HKeyCloser&) = delete;
};

// software_actions/installed_count_windows — NOT a spawn site (rung 1, no
// subprocess): a native RegOpenKeyExW + RegQueryInfoKeyW subkey count of the
// default (non-redirected) view of the Uninstall key, mirroring the exact
// semantics of the powershell one-liner it replaces (that script also read
// only the default view via Get-ItemProperty against the bare
// HKLM:\...\Uninstall\* path — no WOW6432Node, no HKCU). Returns -1 on any
// registry failure so the caller can report an honest degrade rather than a
// fabricated zero.
int registry_uninstall_subkey_count() {
    HKEY hkey{};
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                       L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ,
                       &hkey) != ERROR_SUCCESS) {
        return -1;
    }
    HKeyCloser guard{hkey};
    DWORD subkey_count = 0;
    if (RegQueryInfoKeyW(hkey, nullptr, nullptr, nullptr, &subkey_count, nullptr, nullptr,
                         nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        return -1;
    }
    return static_cast<int>(subkey_count);
}

// winget ships as a per-user App Execution Alias under
// %LOCALAPPDATA%\Microsoft\WindowsApps\winget.exe — not on the machine-wide
// PATH the runner refuses to search anyway. Resolve the env var natively and
// hand the one candidate to probe_tool_path for the existence+executable
// check; a missing/empty LOCALAPPDATA or a missing winget.exe both resolve
// to "" (the honest "not present in this context" case the service-account
// context can legitimately hit — App Execution Aliases are a per-user-session
// mechanism).
std::string resolve_winget_path() {
    wchar_t buf[MAX_PATH]{};
    const DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
    std::vector<std::string> candidates;
    if (n > 0 && n < MAX_PATH) {
        candidates.push_back(yuzu::win::from_wide(buf, static_cast<int>(n)) +
                             "\\Microsoft\\WindowsApps\\winget.exe");
    }
    return yuzu::agent::probe_tool_path(candidates);
}

#endif // _WIN32

// ── list_upgradable action ─────────────────────────────────────────────────

int do_list_upgradable(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    auto tool = resolve_winget_path();
    if (tool.empty()) {
        // winget's App Execution Alias is unavailable to the agent service
        // context (no interactive user session) — an honest, expected
        // CONSTRAINED result, not a runner failure.
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "software_actions:winget_not_present");
        ctx.write_output("upgradable|unavailable|winget not present in this context|-");
        return 0;
    }
    // software_actions/list_upgradable_windows#1 (docs/agent-spawn-sink-manifest.md)
    auto res = yuzu::agent::run_bounded_subprocess(
        {tool, "upgrade", "--accept-source-agreements"},
        yuzu::agent::SubprocessOptions{.deadline = kSlowToolDeadline});
    bool status_forwarded = yuzu::agent::forward_runner_failure(ctx, res);
    auto parsed = yuzu::software_actions::parse_winget_upgrade(res.output);
    if (parsed.rows.empty()) {
        ctx.write_output(parsed.separator_found ? "upgradable|none|System is up to date|-"
                                                : "upgradable|none|-|-");
    } else {
        for (const auto& r : parsed.rows) {
            ctx.write_output(
                std::format("upgradable|{}|{}|{}", r.name, r.current_version, r.available_version));
        }
    }
    return status_forwarded ? 1 : 0;

#elif defined(__linux__)
    bool found = false;
    bool status_forwarded = false;
    yuzu::agent::SubprocessResult apt_res, yum_res;
    bool apt_tried = false, yum_tried = false, yum_success = false;

    auto apt = yuzu::agent::probe_tool_path({"/usr/bin/apt", "/bin/apt"});
    if (!apt.empty()) {
        apt_tried = true;
        // software_actions/list_upgradable_linux#1 (docs/agent-spawn-sink-manifest.md)
        apt_res = yuzu::agent::run_bounded_subprocess(
            {apt, "list", "--upgradable"},
            yuzu::agent::SubprocessOptions{.deadline = kQuickToolDeadline});
        for (const auto& r : yuzu::software_actions::parse_apt_list_upgradable(apt_res.output)) {
            ctx.write_output(std::format("upgradable|{}|{}|{}", r.name, r.old_version, r.new_version));
            found = true;
        }
    }
    if (!found) {
        auto yum = yuzu::agent::probe_tool_path({"/usr/bin/yum", "/usr/bin/dnf"});
        if (!yum.empty()) {
            yum_tried = true;
            // software_actions/list_upgradable_linux#2 (docs/agent-spawn-sink-manifest.md)
            yum_res = yuzu::agent::run_bounded_subprocess(
                {yum, "check-update"}, yuzu::agent::SubprocessOptions{.deadline = kQuickToolDeadline});
            // yum/dnf check-update exits 100 when updates ARE available — a
            // success-with-data exit code, never a failure (see
            // yum_checkupdate_is_success's doc comment). The old popen-based
            // code never inspected the exit code at all; this must not
            // regress into treating 100 as an error.
            if (yuzu::software_actions::yum_checkupdate_is_success(yum_res.exit_code)) {
                yum_success = true;
                for (const auto& r : yuzu::software_actions::parse_yum_checkupdate(yum_res.output)) {
                    ctx.write_output(std::format("upgradable|{}|-|{}", r.name, r.new_version));
                    found = true;
                }
            }
        }
    }
    if (!found) {
        // Report the runner-level degrade of whichever attempt is
        // authoritative for the empty result — never overwrite an earlier
        // degrade, and never report a degrade for an attempt a successful
        // fallback already rescued.
        if (yum_tried && !yum_success)
            status_forwarded = yuzu::agent::forward_runner_failure(ctx, yum_res);
        if (!status_forwarded && apt_tried)
            status_forwarded = yuzu::agent::forward_runner_failure(ctx, apt_res);
        ctx.write_output("upgradable|none|System is up to date|-");
    }
    return status_forwarded ? 1 : 0;

#elif defined(__APPLE__)
    auto tool = yuzu::agent::probe_tool_path({"/usr/sbin/softwareupdate"});
    std::vector<std::string> argv;
    if (!tool.empty())
        argv = {tool, "-l"};
    // software_actions/list_upgradable_macos#1 (docs/agent-spawn-sink-manifest.md)
    auto res = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = kSlowToolDeadline});
    bool status_forwarded = yuzu::agent::forward_runner_failure(ctx, res);
    auto labels = yuzu::software_actions::parse_softwareupdate_list(res.output);
    if (labels.empty()) {
        ctx.write_output("upgradable|none|System is up to date|-");
    } else {
        for (const auto& label : labels)
            ctx.write_output(std::format("upgradable|{}|-|-", label));
    }
    return status_forwarded ? 1 : 0;

#else
    ctx.write_output("error|platform not supported");
    return 1;
#endif
}

// ── installed_count action ─────────────────────────────────────────────────

int do_installed_count(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    auto count = registry_uninstall_subkey_count();
    if (count < 0) {
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "software_actions:registry_query_failed");
        ctx.write_output("count|0");
        return 1;
    }
    ctx.write_output(std::format("count|{}", count));
    return 0;

#elif defined(__linux__)
    auto dpkg = yuzu::agent::probe_tool_path({"/usr/bin/dpkg-query", "/bin/dpkg-query"});
    if (!dpkg.empty()) {
        // software_actions/installed_count_linux#1 (docs/agent-spawn-sink-manifest.md)
        auto res = yuzu::agent::run_bounded_subprocess(
            {dpkg, "-W", "-f=${db:Status-Abbrev}\\n"},
            yuzu::agent::SubprocessOptions{.deadline = kQuickToolDeadline});
        bool status_forwarded = yuzu::agent::forward_runner_failure(ctx, res);
        ctx.write_output(std::format(
            "count|{}", yuzu::software_actions::count_dpkg_status_abbrev_installed(res.output)));
        return status_forwarded ? 1 : 0;
    }
    auto rpm = yuzu::agent::probe_tool_path({"/usr/bin/rpm", "/bin/rpm"});
    if (!rpm.empty()) {
        // software_actions/installed_count_linux#2 (docs/agent-spawn-sink-manifest.md)
        auto res = yuzu::agent::run_bounded_subprocess(
            {rpm, "-qa"}, yuzu::agent::SubprocessOptions{.deadline = kQuickToolDeadline});
        bool status_forwarded = yuzu::agent::forward_runner_failure(ctx, res);
        ctx.write_output(
            std::format("count|{}", yuzu::software_actions::count_nonempty_lines(res.output)));
        return status_forwarded ? 1 : 0;
    }
    ctx.write_output("count|0");
    return 0;

#elif defined(__APPLE__)
    auto tool = yuzu::agent::probe_tool_path({"/usr/sbin/pkgutil"});
    std::vector<std::string> argv;
    if (!tool.empty())
        argv = {tool, "--pkgs"};
    // software_actions/installed_count_macos#1 (docs/agent-spawn-sink-manifest.md)
    auto res = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = kQuickToolDeadline});
    bool status_forwarded = yuzu::agent::forward_runner_failure(ctx, res);
    ctx.write_output(
        std::format("count|{}", yuzu::software_actions::count_nonempty_lines(res.output)));
    return status_forwarded ? 1 : 0;

#else
    ctx.write_output("error|platform not supported");
    return 1;
#endif
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// Wave 4 PR4.3b: migrated off popen/_popen on every OS.
// list_upgradable: Linux (apt/yum via bounded argv runner) and macOS
// (softwareupdate via bounded argv runner) are SUPPORTED/rung 2. Windows
// (winget via bounded argv runner) is CONSTRAINED/rung 2 — the winget App
// Execution Alias is a per-user-session mechanism that can be unavailable to
// the agent's service context, in which case an honest empty/unavailable
// result is reported rather than a failure.
// installed_count: Linux (dpkg-query/rpm via bounded argv runner) and macOS
// (pkgutil --pkgs via bounded argv runner) are SUPPORTED/rung 2. Windows is
// SUPPORTED/rung 1 — a native Reg*W subkey count of the Uninstall key,
// replacing the prior `powershell -Command` shell-out (ADR-3002 Decision 5
// pins any `powershell -Command` payload at rung 3 forever; this is not a
// tighter rung-3 wrapper of that payload but its outright replacement by a
// zero-subprocess native read).
const YuzuActionDescriptor kActionDescriptors[] = {
    {"list_upgradable",
     /* linux   = */
     {YUZU_SUPPORT_SUPPORTED, 2, "apt/yum check-update via bounded argv runner", nullptr},
     /* macos   = */
     {YUZU_SUPPORT_SUPPORTED, 2, "softwareupdate -l via bounded argv runner", nullptr},
     /* windows = */
     {YUZU_SUPPORT_CONSTRAINED, 2, "winget via bounded argv runner",
      "winget App-Execution-Alias may be unavailable to the agent service context; reports an "
      "honest empty/unavailable result"}},
    {"installed_count",
     /* linux   = */
     {YUZU_SUPPORT_SUPPORTED, 2, "dpkg-query/rpm via bounded argv runner", nullptr},
     /* macos   = */
     {YUZU_SUPPORT_SUPPORTED, 2, "pkgutil --pkgs via bounded argv runner", nullptr},
     /* windows = */
     {YUZU_SUPPORT_SUPPORTED, 1, "native Reg*W subkey count of the Uninstall key", nullptr}},
};

} // namespace

class SoftwareActionsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "software_actions"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Lists upgradable packages and counts installed software";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list_upgradable", "installed_count", nullptr};
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

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "list_upgradable")
            return do_list_upgradable(ctx);
        if (action == "installed_count")
            return do_installed_count(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(SoftwareActionsPlugin)
