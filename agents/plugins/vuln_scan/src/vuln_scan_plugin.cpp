/**
 * vuln_scan_plugin.cpp — Host installed-software identity collector for Yuzu
 *
 * Under ADR-0018 the agent COLLECTS, never decides: it emits a rich installed-
 * software identity record and the server correlates it against NVD/OVAL/VEX.
 * This plugin is therefore a pure identity collector — it holds no CVE rules and
 * does no matching. (Agent-side matching + the config-hardening checks were
 * retired / split out; see git history and docs/vuln-scan-roadmap.md M1a.)
 *
 * Action:
 *   "inventory" — emit one pipe-delimited record per installed package/app, for
 *                 server-side NVD/OVAL/VEX matching. Column order is
 *                 yuzu::vuln::kColumns:
 *     kind|ecosystem|name|epoch|version|release|arch|packager|signature_status|distro_id|distro_version
 *
 *   Fields the OS does not store are left EMPTY — never synthesised (a fake
 *   epoch/arch/signature breaks the server matcher worse than an absent one).
 *
 * Performance invariant (ADR-0018 / VEX design doc Stage 1): read only the
 * signature status the package DB already STORES. Never trigger live signature
 * re-verification (rpm -K / gpg --verify / codesign) on a routine scan — that is
 * per-package public-key crypto and turns a sub-second scan into seconds. The
 * pure parsing/formatting lives in vuln_identity.hpp (unit tested).
 */

#include <yuzu/plugin.hpp>

#include "vuln_identity.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#if defined(__linux__) || defined(__APPLE__)
#include <sstream>
#endif

#ifdef __linux__
#include <fstream>
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <win_str.hpp>  // shared yuzu::win wide<->UTF-8 helpers (#1681)
#endif

namespace {

using yuzu::vuln::PackageRecord;

#if defined(__linux__) || defined(__APPLE__)
// ── Subprocess helper (Linux / macOS) ──────────────────────────────────────

std::string run_command(const char* cmd) {
    std::string result;
    std::array<char, 256> buf{};
    // RAII owner: pclose runs on every exit including the std::bad_alloc throw
    // path from `result +=` below, so the pipe fd never leaks.
    std::unique_ptr<FILE, decltype(&pclose)> pipe{popen(cmd, "r"), &pclose};
    if (!pipe)
        return result;
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe.get())) {
        result += buf.data();
    }
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
        result.pop_back();
    }
    return result;
}

bool command_exists(const char* cmd) {
    auto check = std::string("command -v ") + cmd + " >/dev/null 2>&1";
    return system(check.c_str()) == 0;
}
#endif

// ── Platform enumerators ────────────────────────────────────────────────────

#ifdef _WIN32

// RAII closer for an HKEY -- releases the handle even if a value read throws
// (std::string allocation in reg_sz_to_utf8/to_wide). vuln_scan reads HKLM/HKCU
// directly, so unlike installed_apps it needs no hive load/unload guard.
struct HKeyCloser {
    HKEY h{};
    explicit HKeyCloser(HKEY k) : h(k) {}
    ~HKeyCloser() {
        if (h)
            RegCloseKey(h);
    }
    HKeyCloser(const HKeyCloser&) = delete;
    HKeyCloser& operator=(const HKeyCloser&) = delete;
};

// `arch_hint` records the registry view the key was opened under: the 32-bit
// (WOW6432Node) view holds 32-bit apps, the 64-bit view holds 64-bit apps. That
// is a real bitness signal from the registry, not a synthesised field; the HKCU
// pass has no reliable bitness so it is left empty.
void enumerate_uninstall_key(HKEY root, const char* subkey, REGSAM extra_sam,
                             std::string_view arch_hint, std::vector<PackageRecord>& out) {
    HKEY hkey{};
    // Reg*W + WideCharToMultiByte(CP_UTF8) so non-ASCII names (e.g. "Café")
    // survive intact -- the *A APIs return the system ANSI code page (cp1252),
    // which then fails UTF-8 validation downstream and corrupts the stored /
    // fleet-queryable software-inventory surface (#1662 / #1682).
    if (RegOpenKeyExW(root, yuzu::win::to_wide(subkey).c_str(), 0,
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS | extra_sam, &hkey) != ERROR_SUCCESS) {
        return;
    }
    HKeyCloser hkey_guard{hkey};

    // RegEnumKeyExW's lpcchName is a WCHAR COUNT, not a byte size. Bind the array
    // size and every reset to one constant so the byte-vs-count unit cannot skew --
    // the #1662 A->W conversion missed one reset site (gov Gate 3/4 BLOCKING).
    constexpr DWORD kNameBufLen = 256;
    wchar_t name_buf[kNameBufLen]{};
    DWORD idx = 0;
    DWORD name_len = kNameBufLen;

    while (RegEnumKeyExW(hkey, idx++, name_buf, &name_len, nullptr, nullptr, nullptr, nullptr) ==
           ERROR_SUCCESS) {
        HKEY app_key{};
        if (RegOpenKeyExW(hkey, name_buf, 0, KEY_READ | extra_sam, &app_key) == ERROR_SUCCESS) {
            HKeyCloser app_guard{app_key};
            // Value names are compile-time wide literals -> no per-iteration to_wide
            // allocation in this hot loop, and the only throwing call left is the
            // post-read reg_sz_to_utf8, on which app_guard still releases app_key
            // (#1682 Gate-4 R4). buf is written as bytes and read back through its
            // declared wchar_t lvalue (LPBYTE is alignment-1).
            auto read_str = [&](const wchar_t* value_name) -> std::string {
                wchar_t buf[512]{};
                DWORD size = sizeof(buf); // size in BYTES
                DWORD type = 0;
                if (RegQueryValueExW(app_key, value_name, nullptr, &type,
                                     reinterpret_cast<LPBYTE>(buf), &size) == ERROR_SUCCESS) {
                    if (type == REG_SZ && size >= sizeof(wchar_t)) {
                        return yuzu::win::reg_sz_to_utf8(buf, size);
                    }
                }
                return {};
            };

            auto display_name = read_str(L"DisplayName");
            if (!display_name.empty()) {
                auto sys_component = read_str(L"SystemComponent");
                if (sys_component != "1") {
                    PackageRecord r;
                    r.kind = "app";
                    r.ecosystem = "windows";
                    r.name = std::move(display_name);
                    r.version = read_str(L"DisplayVersion");
                    r.packager = read_str(L"Publisher");
                    r.arch = arch_hint;
                    r.distro_id = "windows";
                    out.push_back(std::move(r));
                }
            }
            // app_guard closes app_key (also on the read_str throw path)
        }
        name_len = kNameBufLen;
    }
    // hkey_guard closes hkey
}

std::vector<PackageRecord> collect_records() {
    std::vector<PackageRecord> out;
    static const char* kUninstallKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    enumerate_uninstall_key(HKEY_LOCAL_MACHINE, kUninstallKey, KEY_WOW64_64KEY, "x64", out);
    enumerate_uninstall_key(HKEY_LOCAL_MACHINE, kUninstallKey, KEY_WOW64_32KEY, "x86", out);
    enumerate_uninstall_key(HKEY_CURRENT_USER, kUninstallKey, 0, "", out);
    return out;
}

#elif defined(__linux__)

// Read ID / VERSION_ID from /etc/os-release once per scan (host-level context
// stamped onto every package record). One tiny file read, negligible cost.
void read_os_release(std::string& id, std::string& version_id) {
    std::ifstream f("/etc/os-release");
    if (!f)
        return;
    std::string line;
    while (std::getline(f, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos)
            continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        if (val.size() >= 2 && (val.front() == '"' || val.front() == '\'') &&
            val.back() == val.front())
            val = val.substr(1, val.size() - 2);
        if (key == "ID")
            id = val;
        else if (key == "VERSION_ID")
            version_id = val;
    }
}

std::vector<PackageRecord> collect_records() {
    std::vector<PackageRecord> out;
    std::string distro_id, distro_version;
    read_os_release(distro_id, distro_version);

    auto scan = [&](const char* cmd,
                    std::optional<PackageRecord> (*parse)(const std::string&)) {
        std::istringstream ss(run_command(cmd));
        std::string line;
        while (std::getline(ss, line)) {
            if (auto r = parse(line))
                out.push_back(std::move(*r));
        }
    };

    // 0x1F queryformat delimiter (kUS): a packager string containing '|' cannot
    // forge a field boundary during parsing.
    if (command_exists("dpkg-query")) {
        scan("dpkg-query -W "
             "-f='${Package}\x1f${Version}\x1f${Architecture}\x1f${Maintainer}\x1f${db:Status-Abbrev}\\n' "
             "2>/dev/null",
             yuzu::vuln::parse_dpkg_line);
    } else if (command_exists("rpm")) {
        scan("rpm -qa --queryformat "
             "'%{NAME}\x1f%{EPOCH}\x1f%{VERSION}\x1f%{RELEASE}\x1f%{ARCH}\x1f%{PACKAGER}\x1f%{SIGPGP}\x1f%{RSAHEADER}\\n' "
             "2>/dev/null",
             yuzu::vuln::parse_rpm_line);
    } else if (command_exists("pacman")) {
        scan("pacman -Q 2>/dev/null", yuzu::vuln::parse_pacman_line);
    } else if (command_exists("apk")) {
        std::string apk_arch;
        {
            std::ifstream af("/etc/apk/arch");
            if (af)
                std::getline(af, apk_arch);
        }
        std::istringstream ss(run_command("apk info -v 2>/dev/null"));
        std::string line;
        while (std::getline(ss, line)) {
            if (auto r = yuzu::vuln::parse_apk_line(line)) {
                r->arch = apk_arch;
                out.push_back(std::move(*r));
            }
        }
    }

    for (auto& r : out) {
        r.distro_id = distro_id;
        r.distro_version = distro_version;
    }
    return out;
}

#elif defined(__APPLE__)

std::vector<PackageRecord> collect_records() {
    std::vector<PackageRecord> out;

    auto add_app = [&](std::string_view ecosystem, std::string name, std::string version) {
        PackageRecord r;
        r.kind = "app";
        r.ecosystem = ecosystem;
        r.name = std::move(name);
        r.version = std::move(version);
        r.distro_id = "macos";
        out.push_back(std::move(r));
    };

    auto sw = run_command("system_profiler SPApplicationsDataType -detailLevel mini 2>/dev/null"
                          " | grep -E '^ {4}\\w|Version:'");
    if (!sw.empty()) {
        std::istringstream ss(sw);
        std::string line;
        std::string current_name;
        std::string current_version;
        while (std::getline(ss, line)) {
            auto start = line.find_first_not_of(" \t");
            if (start == std::string::npos)
                continue;
            line = line.substr(start);
            if (line.find("Version:") == 0) {
                auto colon = line.find(':');
                current_version = (colon != std::string::npos && colon + 2 <= line.size())
                                      ? line.substr(colon + 2)
                                      : "";
            } else if (!line.empty() && line.back() == ':') {
                if (!current_name.empty())
                    add_app("macos", current_name, current_version);
                current_name = line.substr(0, line.size() - 1);
                current_version.clear();
            }
        }
        if (!current_name.empty())
            add_app("macos", current_name, current_version);
    }

    if (command_exists("brew")) {
        std::istringstream ss(run_command("brew list --versions 2>/dev/null"));
        std::string line;
        while (std::getline(ss, line)) {
            auto sp = line.find(' ');
            if (sp != std::string::npos)
                add_app("homebrew", line.substr(0, sp), line.substr(sp + 1));
        }
    }
    return out;
}

#else

std::vector<PackageRecord> collect_records() {
    return {};
}

#endif

// Sort + de-duplicate on the identity key so the output is stable across scans.
std::vector<PackageRecord> collect_sorted() {
    auto recs = collect_records();
    auto key = [](const PackageRecord& r) {
        return std::tie(r.ecosystem, r.name, r.version, r.release, r.arch);
    };
    std::sort(recs.begin(), recs.end(),
              [&](const PackageRecord& a, const PackageRecord& b) { return key(a) < key(b); });
    recs.erase(std::unique(recs.begin(), recs.end(),
                           [&](const PackageRecord& a, const PackageRecord& b) {
                               return key(a) == key(b);
                           }),
               recs.end());
    return recs;
}

} // namespace

class VulnScanPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "vuln_scan"; }
    std::string_view version() const noexcept override { return "2.0.0"; }
    std::string_view description() const noexcept override {
        return "Installed-software identity collector for server-side vulnerability matching";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"inventory", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                [[maybe_unused]] yuzu::Params params) override {
        if (action == "inventory") {
            // Emit the rich installed-software identity record (yuzu::vuln::kColumns)
            // for server-side NVD/OVAL/VEX correlation — one row per package/app.
            auto records = collect_sorted();
            if (records.empty()) {
                // Fail CLOSED, not silent-empty: a host with zero detectable
                // software is almost always a collection failure (no supported
                // package source, or the enumerator errored), not a real empty
                // inventory. Returning success here would let the server read the
                // host as "no packages installed" == CVE-clean (UP-2/UP-3). Frame
                // the response as an error instead so absence never reads as clean.
                ctx.write_output("error|no installed software detected (no supported "
                                 "package source, or the enumerator failed)");
                return 1;
            }
            for (const auto& r : records)
                ctx.write_output(yuzu::vuln::format_record(r));
            return 0;
        }

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(VulnScanPlugin)
