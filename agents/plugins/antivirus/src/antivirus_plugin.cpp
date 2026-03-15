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

#ifdef _WIN32

void list_av_products_win(yuzu::CommandContext& ctx) {
    auto output = run_command(
        "powershell -NoProfile -Command \""
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
        if (line.empty()) continue;
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
    auto output = run_command(
        "powershell -NoProfile -Command \""
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
        if (line.empty()) continue;

        auto colon = line.find(':');
        if (colon == std::string::npos) continue;

        auto key = line.substr(0, colon);
        auto val = line.substr(colon + 1);
        while (!key.empty() && key.back() == ' ') key.pop_back();
        while (!val.empty() && val.front() == ' ') val.erase(val.begin());

        if (key == "RealTimeProtectionEnabled") {
            ctx.write_output(std::format("realtime_protection|{}",
                val == "True" ? "enabled" : "disabled"));
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

void list_av_products_macos(yuzu::CommandContext& ctx) {
    // XProtect is always present on macOS
    ctx.write_output("av|XProtect|active");

    // Check for common AV processes
    auto falcon = run_command("pgrep -x falcon 2>/dev/null");
    if (!falcon.empty()) {
        ctx.write_output("av|CrowdStrike Falcon|running");
    }

    auto sophos = run_command("pgrep -f sophos 2>/dev/null");
    if (!sophos.empty()) {
        ctx.write_output("av|Sophos|running");
    }
}

#endif

} // namespace

class AntivirusPlugin final : public yuzu::Plugin {
public:
    std::string_view name()        const noexcept override { return "antivirus"; }
    std::string_view version()     const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Antivirus product detection and Defender status";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = { "products", "status", nullptr };
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx,
                std::string_view action,
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
