/**
 * antivirus_plugin.cpp — Antivirus product detection plugin for Yuzu
 *
 * Actions:
 *   "products" — List installed AV products.
 *   "status"   — Windows Defender detailed status.
 *
 * Output is pipe-delimited via write_output().
 */

#include <yuzu/plugin.hpp>

#include "antivirus_parsers.hpp"

#include <array>
#include <cstdio>
#include <format>
#include <sstream>
#include <string>
#include <string_view>

#if defined(__linux__)
#include <cstdlib>
#include <filesystem>
#endif

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

void list_av_products_win(yuzu::CommandContext& ctx) {
    auto output = run_command("powershell -NoProfile -Command \""
                              "Get-CimInstance -Namespace root/SecurityCenter2 "
                              "-ClassName AntiVirusProduct | "
                              "ForEach-Object { $_.displayName + '|' + $_.productState }\"");

    if (output.empty()) {
        ctx.write_output("av_count|0");
        return;
    }

    std::istringstream iss(output);
    std::string line;
    int count = 0;
    while (std::getline(iss, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.empty())
            continue;
        auto sep = line.find('|');
        if (sep != std::string::npos) {
            auto name = line.substr(0, sep);
            auto state = line.substr(sep + 1);
            ctx.write_output(std::format("av|{}|{}", name, state));
        } else {
            ctx.write_output(std::format("av|{}|unknown", line));
        }
        ++count;
    }
    if (count == 0) {
        ctx.write_output("av_count|0");
    }
}

void defender_status_win(yuzu::CommandContext& ctx) {
    auto output = run_command("powershell -NoProfile -Command \""
                              "Get-MpComputerStatus | Select-Object "
                              "RealTimeProtectionEnabled,AntivirusSignatureVersion,"
                              "AntivirusSignatureLastUpdated,QuickScanEndTime | Format-List\"");

    if (output.empty()) {
        ctx.write_output("status|not_available");
        return;
    }

    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.empty())
            continue;

        auto colon = line.find(':');
        if (colon == std::string::npos)
            continue;

        auto key = line.substr(0, colon);
        auto val = line.substr(colon + 1);
        while (!key.empty() && key.back() == ' ')
            key.pop_back();
        while (!val.empty() && val.front() == ' ')
            val.erase(val.begin());

        if (key == "RealTimeProtectionEnabled") {
            ctx.write_output(
                std::format("realtime_protection|{}", val == "True" ? "enabled" : "disabled"));
        } else if (key == "AntivirusSignatureVersion") {
            ctx.write_output(std::format("definition_version|{}", val));
        } else if (key == "AntivirusSignatureLastUpdated") {
            ctx.write_output(std::format("last_update|{}", val));
        } else if (key == "QuickScanEndTime") {
            ctx.write_output(std::format("last_quick_scan|{}", val));
        }
    }
}

#elif defined(__linux__)

void list_av_products_linux(yuzu::CommandContext& ctx) {
    int found = 0;

    // Check ClamAV
    auto clamd = run_command("pgrep -x clamd 2>/dev/null");
    if (!clamd.empty()) {
        ctx.write_output("av|ClamAV|running");
        ++found;
    }

    // Check CrowdStrike Falcon
    auto falcon = run_command("pgrep -x falcon-sensor 2>/dev/null");
    if (!falcon.empty()) {
        ctx.write_output("av|CrowdStrike Falcon|running");
        ++found;
    } else if (std::filesystem::exists("/opt/CrowdStrike")) {
        ctx.write_output("av|CrowdStrike Falcon|installed");
        ++found;
    }

    // Check Sophos
    auto sophos = run_command("pgrep -f sophos 2>/dev/null");
    if (!sophos.empty()) {
        ctx.write_output("av|Sophos|running");
        ++found;
    } else if (std::filesystem::exists("/opt/sophos-av")) {
        ctx.write_output("av|Sophos|installed");
        ++found;
    }

    if (found == 0) {
        ctx.write_output("av_count|0");
    }
}

#elif defined(__APPLE__)

constexpr const char* kXProtectVersionCmd =
    "/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "
    "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist "
    "2>/dev/null";

void list_av_products_macos(yuzu::CommandContext& ctx) {
    // XProtect: probe the definition bundle instead of asserting it — the old
    // hardcoded "active" reported protection without reading anything.
    auto xp_ver = yuzu::antivirus::parse_plist_version(run_command(kXProtectVersionCmd));
    if (!xp_ver.empty()) {
        ctx.write_output("av|XProtect|active");
        ctx.write_output(std::format("xprotect_version|{}", xp_ver));
    } else {
        ctx.write_output("av|XProtect|unknown");
    }

    // Third-party EDR/AV: the authoritative source is the endpoint-security
    // system-extension registry (unprivileged read); modern EDRs must
    // register there. Emits an av row per extension plus a detail row with
    // bundle id and version.
    auto exts = yuzu::antivirus::parse_sysext_list(
        run_command("systemextensionsctl list 2>/dev/null"));
    std::string es_names;
    for (const auto& ext : exts) {
        if (!yuzu::antivirus::is_endpoint_security(ext))
            continue;
        ctx.write_output(
            std::format("av|{}|{}", ext.name, yuzu::antivirus::sysext_av_state(ext)));
        ctx.write_output(std::format("edr|{}|{}", ext.bundle_id, ext.version));
        es_names += ext.name;
        es_names += '|';
        es_names += ext.bundle_id;
        es_names += '\n';
    }

    // Process-detection fallback for agents that predate (or sit outside)
    // the extension registry; skipped when the registry already reported
    // that vendor. The CrowdStrike daemon is falcond, not falcon.
    if (!yuzu::antivirus::contains_insensitive(es_names, "crowdstrike") &&
        !yuzu::antivirus::contains_insensitive(es_names, "falcon")) {
        auto falcon = run_command("pgrep -x falcond 2>/dev/null");
        if (!falcon.empty()) {
            ctx.write_output("av|CrowdStrike Falcon|running");
        }
    }
    if (!yuzu::antivirus::contains_insensitive(es_names, "sophos")) {
        auto sophos = run_command("pgrep -f sophos 2>/dev/null");
        if (!sophos.empty()) {
            ctx.write_output("av|Sophos|running");
        }
    }
}

void xprotect_status_macos(yuzu::CommandContext& ctx) {
    // Defender-status analogue built from what macOS can actually prove:
    // XProtect definition version + bundle freshness, and the Remediator/MRT
    // engine versions. No realtime_protection row — macOS exposes no
    // queryable equivalent, and asserting one would be false confidence.
    auto ver = yuzu::antivirus::parse_plist_version(run_command(kXProtectVersionCmd));
    if (ver.empty()) {
        ctx.write_output("status|unknown");
        return;
    }
    ctx.write_output(std::format("definition_version|{}", ver));

    auto mtime = run_command(
        "stat -f %Sm -t %Y-%m-%dT%H:%M:%S "
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist "
        "2>/dev/null");
    if (!mtime.empty() && mtime.find(' ') == std::string::npos) {
        ctx.write_output(std::format("last_update|{}", mtime));
    }

    auto remediator = yuzu::antivirus::parse_plist_version(run_command(
        "/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "
        "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist "
        "2>/dev/null"));
    if (!remediator.empty()) {
        ctx.write_output(std::format("remediator_version|{}", remediator));
    }

    auto mrt = yuzu::antivirus::parse_plist_version(run_command(
        "/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "
        "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist "
        "2>/dev/null"));
    if (!mrt.empty()) {
        ctx.write_output(std::format("mrt_version|{}", mrt));
    }
}

#endif

} // namespace

class AntivirusPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "antivirus"; }
    std::string_view version() const noexcept override { return "0.2.0"; }
    std::string_view description() const noexcept override {
        return "Antivirus product detection and Defender status";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"products", "status", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {

        if (action == "products") {
#ifdef _WIN32
            list_av_products_win(ctx);
#elif defined(__linux__)
            list_av_products_linux(ctx);
#elif defined(__APPLE__)
            list_av_products_macos(ctx);
#endif
            return 0;
        }

        if (action == "status") {
#ifdef _WIN32
            defender_status_win(ctx);
#elif defined(__APPLE__)
            xprotect_status_macos(ctx);
#else
            ctx.write_output("status|not_available");
#endif
            return 0;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(AntivirusPlugin)
