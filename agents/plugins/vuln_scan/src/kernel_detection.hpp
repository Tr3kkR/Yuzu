#pragma once
#include <cstdint>
#include <string>
#include <string_view>

#if defined(__linux__) || defined(__APPLE__)
#include "proc_exec.hpp"  // yuzu::vuln::capture_command (must precede the namespace)
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace yuzu::vuln {

struct KernelInfo {
    int major{0};
    int minor{0};
    int patch{0};
    std::string full_version;
    std::string platform; // "linux", "windows", "macos"
};

// ── Linux ─────────────────────────────────────────────────────────────────

#ifdef __linux__
#include <sys/utsname.h>

// Parse "MAJOR.MINOR.PATCH..." from a uname release string.
// Stops at the first character that is neither a digit nor a '.'.
inline KernelInfo parse_linux_kernel_version(std::string_view release) {
    KernelInfo k;
    k.full_version = std::string(release);
    k.platform = "linux";
    int* fields[3] = {&k.major, &k.minor, &k.patch};
    int idx = 0, cur = 0;
    bool in_num = false;
    for (char c : release) {
        if (c >= '0' && c <= '9') {
            cur = cur * 10 + (c - '0');
            in_num = true;
        } else if (c == '.' && in_num && idx < 2) {
            *fields[idx++] = cur;
            cur = 0;
            in_num = false;
        } else {
            break;
        }
    }
    if (in_num && idx < 3)
        *fields[idx] = cur;
    return k;
}

inline KernelInfo get_kernel_info() {
    struct utsname u{};
    if (uname(&u) != 0)
        return {};
    return parse_linux_kernel_version(u.release);
}
#endif // __linux__

// ── Windows ────────────────────────────────────────────────────────────────

#ifdef _WIN32
inline std::string synthesize_windows_version(int major, int minor,
                                               int build, int ubr) {
    return std::to_string(major) + "." + std::to_string(minor) + "." +
           std::to_string(build) + "." + std::to_string(ubr);
}

namespace detail_kernel {
inline DWORD read_reg_dword(HKEY root, const char* subkey,
                             const char* value, DWORD def) {
    HKEY h{};
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &h) != ERROR_SUCCESS)
        return def;
    DWORD v = 0, sz = sizeof(v), type = 0;
    DWORD r = def;
    if (RegQueryValueExA(h, value, nullptr, &type,
                         reinterpret_cast<LPBYTE>(&v), &sz) == ERROR_SUCCESS &&
        type == REG_DWORD)
        r = v;
    RegCloseKey(h);
    return r;
}

inline std::string read_reg_string(HKEY root, const char* subkey,
                                    const char* value, const std::string& def) {
    HKEY h{};
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &h) != ERROR_SUCCESS)
        return def;
    char buf[256]{};
    DWORD sz = sizeof(buf) - 1, type = 0;
    std::string r = def;
    if (RegQueryValueExA(h, value, nullptr, &type,
                         reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS &&
        type == REG_SZ)
        r = buf;
    RegCloseKey(h);
    return r;
}
} // namespace detail_kernel

inline KernelInfo get_kernel_info() {
    KernelInfo k;
    k.platform = "windows";
    static const char* kKey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    // CurrentBuildNumber is REG_SZ (string), not REG_DWORD
    auto build_str = detail_kernel::read_reg_string(HKEY_LOCAL_MACHINE, kKey, "CurrentBuildNumber", "0");
    int build = 0;
    try { build = std::stoi(build_str); } catch (...) { build = 0; }
    // UBR is REG_DWORD
    int ubr = static_cast<int>(
        detail_kernel::read_reg_dword(HKEY_LOCAL_MACHINE, kKey, "UBR", 0));
    k.major = 10;
    k.minor = 0;
    k.patch = build;
    k.full_version = synthesize_windows_version(10, 0, build, ubr);
    return k;
}
#endif // _WIN32

// ── macOS ──────────────────────────────────────────────────────────────────

#ifdef __APPLE__
#include <cstdio>

inline KernelInfo get_kernel_info() {
    KernelInfo k;
    k.platform = "macos";
    // RAII pipe capture (proc_exec.hpp) reclaims the FD/child on every path.
    k.full_version = capture_command("sw_vers -productVersion 2>/dev/null");
    if (k.full_version.empty())
        return k;
    // NOLINTNEXTLINE(cert-err34-c) — sscanf is fine for fixed-format OS version
    std::sscanf(k.full_version.c_str(), "%d.%d.%d", &k.major, &k.minor, &k.patch);
    return k;
}
#endif // __APPLE__

} // namespace yuzu::vuln
