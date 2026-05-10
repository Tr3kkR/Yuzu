/**
 * sccm_plugin.cpp — SCCM/ConfigMgr client info plugin for Yuzu (Windows-only)
 *
 * Actions:
 *   "client_version" — Check if SCCM client is installed and report version.
 *   "site"           — Get SCCM site assignment info.
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   installed|true/false
 *   version|X.Y.Z
 *   site_code|ABC
 *   management_point|hostname
 */

#include <yuzu/plugin.hpp>

#include <array>
#include <cstdio>
#include <format>
#include <string>
#include <string_view>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#pragma comment(lib, "advapi32.lib")
#endif

namespace {

// ── subprocess helper ──────────────────────────────────────────────────────

#ifdef _WIN32
std::string run_command(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
    FILE* pipe = _popen(cmd, "r");
    if (!pipe)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
    _pclose(pipe);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
}

std::string read_registry_string(HKEY root, const char* subkey, const char* value) {
    HKEY hkey{};
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hkey) != ERROR_SUCCESS) {
        return {};
    }
    char buf[256]{};
    DWORD size = sizeof(buf);
    DWORD type = 0;
    std::string result;
    if (RegQueryValueExA(hkey, value, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &size) ==
        ERROR_SUCCESS) {
        if (type == REG_SZ && size > 0) {
            result.assign(buf, size - 1);
        }
    }
    RegCloseKey(hkey);
    return result;
}
#endif

// ── client_version action ──────────────────────────────────────────────────

int do_client_version(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    // Check registry for SCCM client version
    auto version = read_registry_string(
        HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\SMS\\Mobile Client", "ProductVersion");

    if (!version.empty()) {
        ctx.write_output("installed|true");
        ctx.write_output(std::format("version|{}", version));
    } else {
        ctx.write_output("installed|false");
        ctx.write_output("version|-");
    }

    // Also check if CcmExec service exists
    auto svc_output = run_command("sc query ccmexec 2>nul");
    if (svc_output.find("RUNNING") != std::string::npos) {
        ctx.write_output("service_status|running");
    } else if (svc_output.find("STOPPED") != std::string::npos) {
        ctx.write_output("service_status|stopped");
    } else if (svc_output.find("ccmexec") != std::string::npos ||
               svc_output.find("CcmExec") != std::string::npos) {
        ctx.write_output("service_status|exists");
    } else {
        ctx.write_output("service_status|not_found");
    }

#else
    ctx.write_output("installed|false");
    ctx.write_output("error|platform not supported");
#endif
    return 0;
}

// ── site action ────────────────────────────────────────────────────────────

int do_site(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    // Try registry first
    auto site_code = read_registry_string(
        HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\SMS\\Mobile Client", "AssignedSiteCode");

    if (site_code.empty()) {
        // Try alternate location
        site_code = read_registry_string(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\CCM",
                                         "AssignedSiteCode");
    }

    if (!site_code.empty()) {
        ctx.write_output(std::format("site_code|{}", site_code));
    } else {
        // Try COM object via PowerShell
        auto ps_site =
            run_command("powershell -NoProfile -Command \""
                        "try { (New-Object -ComObject Microsoft.SMS.Client).GetAssignedSite() } "
                        "catch { 'unavailable' }\"");
        if (!ps_site.empty() && ps_site != "unavailable") {
            ctx.write_output(std::format("site_code|{}", ps_site));
        } else {
            ctx.write_output("site_code|not_configured");
        }
    }

    // Get management point
    auto mp = read_registry_string(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\CCM", "Authority");
    if (mp.empty()) {
        mp = read_registry_string(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\CCM\\Authority\\SMS:{}",
                                  "CurrentManagementPoint");
    }
    if (mp.empty()) {
        // Try PowerShell
        mp = run_command("powershell -NoProfile -Command \""
                         "try { (New-Object -ComObject Microsoft.SMS.Client)"
                         ".GetCurrentManagementPoint() } catch { '' }\"");
    }
    if (!mp.empty()) {
        ctx.write_output(std::format("management_point|{}", mp));
    } else {
        ctx.write_output("management_point|unknown");
    }

#else
    ctx.write_output("error|platform not supported");
#endif
    return 0;
}

} // namespace

class SccmPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "sccm"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports SCCM/ConfigMgr client status, version, and site assignment";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"client_version", "site", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "client_version")
            return do_client_version(ctx);
        if (action == "site")
            return do_site(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(SccmPlugin)
