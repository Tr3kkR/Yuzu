/**
 * os_info_plugin.cpp — OS information plugin for Yuzu
 *
 * Actions:
 *   "os_name"    — Returns the full OS product name.
 *   "os_version" — Returns the OS version string.
 *   "os_build"   — Returns the OS build identifier.
 *   "os_arch"    — Returns the CPU architecture.
 *   "uptime"     — Returns system uptime in seconds and human-readable form.
 *
 * Output is pipe-delimited, one field per line via write_output():
 *   key|value
 */

#include <yuzu/plugin.hpp>

#include <array>
#include <cstdio>
#include <ctime>
#include <format>
#include <string>
#include <string_view>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/utsname.h>
#endif

#if defined(__linux__)
#include <fstream>
#endif

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace {

// ── helpers ─────────────────────────────────────────────────────────────────

#if defined(__APPLE__)
std::string run_command(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
    FILE* pipe = popen(cmd, "r");
    if (!pipe)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        result += buf.data();
    }
    pclose(pipe);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}
#endif

#ifdef _WIN32
// RtlGetVersion signature — avoids manifest-dependent version lies from
// GetVersionEx. Loaded dynamically from ntdll.
using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);

bool get_rtl_version(RTL_OSVERSIONINFOW& vi) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return false;
    auto fn = reinterpret_cast<RtlGetVersionFn>(GetProcAddress(ntdll, "RtlGetVersion"));
    if (!fn)
        return false;
    vi.dwOSVersionInfoSize = sizeof(vi);
    return fn(&vi) == 0; // STATUS_SUCCESS
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
            result.assign(buf, size - 1); // exclude null terminator
        }
    }
    RegCloseKey(hkey);
    return result;
}

DWORD read_registry_dword(HKEY root, const char* subkey, const char* value) {
    HKEY hkey{};
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hkey) != ERROR_SUCCESS) {
        return 0;
    }
    DWORD data = 0;
    DWORD size = sizeof(data);
    DWORD type = 0;
    if (RegQueryValueExA(hkey, value, nullptr, &type, reinterpret_cast<LPBYTE>(&data), &size) !=
        ERROR_SUCCESS) {
        data = 0;
    }
    RegCloseKey(hkey);
    return data;
}
#endif

std::string format_uptime(long long total_seconds) {
    long long days = total_seconds / 86400;
    long long hours = (total_seconds % 86400) / 3600;
    long long minutes = (total_seconds % 3600) / 60;
    return std::format("{}d {}h {}m", days, hours, minutes);
}

#ifdef __linux__
std::string read_os_release_field(const char* field) {
    std::ifstream ifs("/etc/os-release");
    if (!ifs)
        return {};
    std::string prefix = std::string(field) + "=";
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.starts_with(prefix)) {
            auto val = line.substr(prefix.size());
            // Strip surrounding quotes
            if (val.size() >= 2 && val.front() == '"' && val.back() == '"') {
                val = val.substr(1, val.size() - 2);
            }
            return val;
        }
    }
    return {};
}
#endif

constexpr const char* kWinNtCurrentVersion = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

// ── os_name action ──────────────────────────────────────────────────────────

int do_os_name(yuzu::CommandContext& ctx) {
#ifdef __linux__
    auto name = read_os_release_field("PRETTY_NAME");
    if (name.empty())
        name = "Linux";
    ctx.write_output(std::format("os_name|{}", name));

#elif defined(__APPLE__)
    auto product = run_command("sw_vers -productName");
    auto version = run_command("sw_vers -productVersion");
    if (!product.empty() && !version.empty()) {
        ctx.write_output(std::format("os_name|{} {}", product, version));
    } else {
        ctx.write_output("os_name|macOS");
    }

#elif defined(_WIN32)
    auto name = read_registry_string(HKEY_LOCAL_MACHINE, kWinNtCurrentVersion, "ProductName");
    // Windows 11 shipped with build 22000+, but the registry ProductName
    // still says "Windows 10" on many builds. Correct it using the build number.
    if (!name.empty()) {
        auto build_str =
            read_registry_string(HKEY_LOCAL_MACHINE, kWinNtCurrentVersion, "CurrentBuildNumber");
        int build = 0;
        try {
            build = std::stoi(build_str);
        } catch (...) {}
        if (build >= 22000) {
            auto pos = name.find("Windows 10");
            if (pos != std::string::npos) {
                name.replace(pos, 10, "Windows 11");
            }
        }
    }
    ctx.write_output(std::format("os_name|{}", name.empty() ? "Windows" : name));

#else
    ctx.write_output("os_name|unknown");
#endif
    return 0;
}

// ── os_version action ───────────────────────────────────────────────────────

int do_os_version(yuzu::CommandContext& ctx) {
#if defined(__linux__) || defined(__APPLE__)
    struct utsname uts{};
    if (uname(&uts) == 0) {
        ctx.write_output(std::format("os_version|{}", uts.release));
    } else {
        ctx.write_output("os_version|unknown");
    }

#elif defined(_WIN32)
    RTL_OSVERSIONINFOW vi{};
    if (get_rtl_version(vi)) {
        ctx.write_output(std::format("os_version|{}.{}.{}", vi.dwMajorVersion, vi.dwMinorVersion,
                                     vi.dwBuildNumber));
    } else {
        ctx.write_output("os_version|unknown");
    }

#else
    ctx.write_output("os_version|unknown");
#endif

#ifdef __APPLE__
    // Also provide the user-facing product version
    auto product_ver = run_command("sw_vers -productVersion");
    if (!product_ver.empty()) {
        ctx.write_output(std::format("os_product_version|{}", product_ver));
    }
#endif
    return 0;
}

// ── os_build action ─────────────────────────────────────────────────────────

int do_os_build(yuzu::CommandContext& ctx) {
#ifdef __linux__
    std::ifstream proc_ver("/proc/version");
    if (proc_ver) {
        std::string line;
        std::getline(proc_ver, line);
        // First token is typically "Linux"
        // We want the full build string, but extract the version token
        // (third whitespace-delimited field, e.g. "6.5.0-44-generic")
        std::string token;
        int field = 0;
        for (auto ch : line) {
            if (ch == ' ') {
                ++field;
                if (field == 3)
                    break;
                token.clear();
            } else {
                token += ch;
            }
        }
        ctx.write_output(std::format("os_build|{}", token.empty() ? line : token));
    } else {
        ctx.write_output("os_build|unknown");
    }

#elif defined(__APPLE__)
    auto build = run_command("sw_vers -buildVersion");
    ctx.write_output(std::format("os_build|{}", build.empty() ? "unknown" : build));

#elif defined(_WIN32)
    auto build_num =
        read_registry_string(HKEY_LOCAL_MACHINE, kWinNtCurrentVersion, "CurrentBuildNumber");
    auto ubr = read_registry_dword(HKEY_LOCAL_MACHINE, kWinNtCurrentVersion, "UBR");
    if (!build_num.empty()) {
        ctx.write_output(std::format("os_build|{}.{}", build_num, ubr));
    } else {
        ctx.write_output("os_build|unknown");
    }

#else
    ctx.write_output("os_build|unknown");
#endif
    return 0;
}

// ── os_arch action ──────────────────────────────────────────────────────────

int do_os_arch(yuzu::CommandContext& ctx) {
#if defined(__linux__) || defined(__APPLE__)
    struct utsname uts{};
    if (uname(&uts) == 0) {
        ctx.write_output(std::format("os_arch|{}", uts.machine));
    } else {
        ctx.write_output("os_arch|unknown");
    }

#elif defined(_WIN32)
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    const char* arch = "unknown";
    switch (si.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
        arch = "x86_64";
        break;
    case PROCESSOR_ARCHITECTURE_ARM64:
        arch = "aarch64";
        break;
    case PROCESSOR_ARCHITECTURE_INTEL:
        arch = "x86";
        break;
    case PROCESSOR_ARCHITECTURE_ARM:
        arch = "arm";
        break;
    }
    ctx.write_output(std::format("os_arch|{}", arch));

#else
    ctx.write_output("os_arch|unknown");
#endif
    return 0;
}

// ── uptime action ───────────────────────────────────────────────────────────

int do_uptime(yuzu::CommandContext& ctx) {
    long long seconds = -1;

#ifdef __linux__
    std::ifstream proc_uptime("/proc/uptime");
    if (proc_uptime) {
        double up = 0.0;
        proc_uptime >> up;
        seconds = static_cast<long long>(up);
    }

#elif defined(__APPLE__)
    struct timeval boottime{};
    size_t len = sizeof(boottime);
    int mib[2] = {CTL_KERN, KERN_BOOTTIME};
    if (sysctl(mib, 2, &boottime, &len, nullptr, 0) == 0) {
        seconds = static_cast<long long>(std::time(nullptr) - boottime.tv_sec);
    }

#elif defined(_WIN32)
    seconds = static_cast<long long>(GetTickCount64() / 1000);
#endif

    if (seconds >= 0) {
        ctx.write_output(std::format("uptime_seconds|{}", seconds));
        ctx.write_output(std::format("uptime_display|{}", format_uptime(seconds)));
    } else {
        ctx.write_output("uptime_seconds|unknown");
        ctx.write_output("uptime_display|unknown");
    }
    return 0;
}

} // namespace

class OsInfoPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "os_info"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports OS name, version, build, architecture, and system uptime";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"os_name", "os_version", "os_build",
                                     "os_arch", "uptime",     nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        if (action == "os_name")
            return do_os_name(ctx);
        if (action == "os_version")
            return do_os_version(ctx);
        if (action == "os_build")
            return do_os_build(ctx);
        if (action == "os_arch")
            return do_os_arch(ctx);
        if (action == "uptime")
            return do_uptime(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(OsInfoPlugin)
