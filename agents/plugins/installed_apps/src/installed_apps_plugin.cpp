/**
 * installed_apps_plugin.cpp — Installed applications plugin for Yuzu
 *
 * Actions:
 *   "list"  — Lists all installed applications.
 *   "query" — Searches for a specific app by name (partial match).
 *             Params: name (required).
 *   "list_inventory" — machine-scope software inventory for the daily sync
 *             (blob contract v2, ADR-0016). Emits the extended 12-field rows;
 *             fields an ecosystem does not store are EMPTY, never synthesised
 *             (no "-" placeholders, no sentinel row on an empty result).
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   app|name|version|publisher|install_date                       (list/query)
 *   inv|name|version|publisher|install_date|kind|ecosystem|epoch|release|arch|
 *       signature_status|distro_id|distro_version                 (list_inventory)
 *
 * `list`/`query`/`list_per_user` output is a stable operator-facing contract
 * (content/definitions/installed_apps.yaml et al.) — extend `list_inventory`,
 * never those.
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <format>
#include <string>
#include <string_view>
#include <vector>

// Pure parse/format helpers for the list_inventory action (v2 rows). In a
// header so the unit test exercises the same code (pattern: #1662).
#include "installed_apps_inventory.hpp"

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

// UTF-16<->UTF-8 registry conversion (#1662). In a header so the #1662
// regression test exercises the same code, not a re-implementation.
// Deliberately NOT replaced by agents/shared/win_str.hpp: this copy strips
// ALL trailing NULs where the shared one stops at the first, so aligning them
// would change output bytes for interior-NUL values. Both headers carry the
// do-not-merge note.
#include "installed_apps_registry_utf8.hpp"

// Shared per-user profile/hive ladder (#2771) — the canonical implementation
// this plugin's private copy was replaced by.
#include <user_profile_model.hpp>
#include <win_profiles.hpp>
#include <win_reg_handle.hpp>
#endif

namespace {

// ── subprocess helper (Linux / macOS) ──────────────────────────────────────

#if defined(__linux__) || defined(__APPLE__)
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

bool command_exists(const char* cmd) {
    auto check = std::string("command -v ") + cmd + " >/dev/null 2>&1";
    return system(check.c_str()) == 0;
}
#endif

// ── App record ────────────────────────────────────────────────────────────

struct AppInfo {
    std::string name;
    std::string version;
    std::string publisher;
    std::string install_date;
};

// Case-insensitive substring match
bool icontains(const std::string& haystack, const std::string& needle) {
    if (needle.empty())
        return true;
    if (haystack.size() < needle.size())
        return false;
    auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                          [](char a, char b) {
                              return std::tolower(static_cast<unsigned char>(a)) ==
                                     std::tolower(static_cast<unsigned char>(b));
                          });
    return it != haystack.end();
}

// Replace invalid UTF-8 bytes with '?' to avoid protobuf serialization errors.
// Windows registry strings are now read via the *W APIs + WideCharToMultiByte(CP_UTF8)
// and are already valid UTF-8, so this is defence-in-depth there (#1662); it remains
// load-bearing for the Linux/macOS subprocess paths, whose output encoding is unknown.
std::string sanitize_utf8(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            // ASCII
            out += s[i];
            ++i;
        } else if ((c >> 5) == 0x06 && i + 1 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02) {
            // Valid 2-byte sequence
            out += s[i];
            out += s[i + 1];
            i += 2;
        } else if ((c >> 4) == 0x0E && i + 2 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02) {
            // Valid 3-byte sequence
            out += s[i];
            out += s[i + 1];
            out += s[i + 2];
            i += 3;
        } else if ((c >> 3) == 0x1E && i + 3 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 3]) >> 6) == 0x02) {
            // Valid 4-byte sequence
            out += s[i];
            out += s[i + 1];
            out += s[i + 2];
            out += s[i + 3];
            i += 4;
        } else {
            out += '?';
            ++i;
        }
    }
    return out;
}

// ── Windows: read apps from a registry uninstall key ──────────────────────

#ifdef _WIN32

// to_wide / from_wide / reg_sz_to_utf8 now live in
// installed_apps_registry_utf8.hpp (included above) so the #1662 regression test
// runs the same conversion the plugin does. Pull them into this anonymous
// namespace so the existing unqualified call sites resolve unchanged.
using namespace yuzu::installed_apps::reg_utf8;

// RAII closer for an HKEY. Closing every handle into a RegLoadKeyW-mounted hive
// BEFORE the unload is load-bearing: RegUnLoadKeyW fails (ERROR_ACCESS_DENIED)
// while any subtree handle is open, so a leaked HKEY on a throw path would defeat
// the HiveUnloadGuard in do_list_per_user. Destruction order guarantees these
// callee handles close as the exception leaves enumerate_uninstall_key, before
// the caller's unload guard runs (#1662 Gate-8).
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

void enumerate_uninstall_key(HKEY root, const char* subkey, REGSAM extra_sam,
                             std::vector<AppInfo>& apps) {
    HKEY hkey{};
    if (RegOpenKeyExW(root, to_wide(subkey).c_str(), 0,
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS | extra_sam, &hkey) != ERROR_SUCCESS) {
        return;
    }
    HKeyCloser hkey_guard{hkey};

    // RegEnumKeyExW's lpcchName is a WCHAR COUNT, not a byte size. Bind the array
    // size and every reset to one constant so the byte-vs-count unit cannot skew —
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
            auto read_str = [&](const char* value_name) -> std::string {
                wchar_t buf[512]{};
                DWORD size = sizeof(buf); // size in BYTES
                DWORD type = 0;
                if (RegQueryValueExW(app_key, to_wide(value_name).c_str(), nullptr, &type,
                                     reinterpret_cast<LPBYTE>(buf), &size) == ERROR_SUCCESS) {
                    if (type == REG_SZ && size >= sizeof(wchar_t)) {
                        return reg_sz_to_utf8(buf, size);
                    }
                }
                return {};
            };

            auto display_name = read_str("DisplayName");
            if (!display_name.empty()) {
                // Skip system components and updates without meaningful names
                auto sys_component = read_str("SystemComponent");
                if (sys_component == "1") {
                    name_len = kNameBufLen;
                    continue; // app_guard closes app_key
                }

                AppInfo app;
                app.name = std::move(display_name);
                app.version = read_str("DisplayVersion");
                app.publisher = read_str("Publisher");
                app.install_date = read_str("InstallDate");
                apps.push_back(std::move(app));
            }
        }
        name_len = kNameBufLen;
    }
}

std::vector<AppInfo> get_installed_apps_windows() {
    std::vector<AppInfo> apps;
    static const char* kUninstallKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

    // 64-bit HKLM
    enumerate_uninstall_key(HKEY_LOCAL_MACHINE, kUninstallKey, KEY_WOW64_64KEY, apps);
    // 32-bit HKLM (WoW6432Node)
    enumerate_uninstall_key(HKEY_LOCAL_MACHINE, kUninstallKey, KEY_WOW64_32KEY, apps);
    // Current user
    enumerate_uninstall_key(HKEY_CURRENT_USER, kUninstallKey, 0, apps);

    // Deduplicate by name+version
    std::sort(apps.begin(), apps.end(), [](const AppInfo& a, const AppInfo& b) {
        return a.name < b.name || (a.name == b.name && a.version < b.version);
    });
    apps.erase(std::unique(apps.begin(), apps.end(),
                           [](const AppInfo& a, const AppInfo& b) {
                               return a.name == b.name && a.version == b.version;
                           }),
               apps.end());

    return apps;
}
#endif

// ── Linux: detect package manager and list packages ───────────────────────

#ifdef __linux__
std::vector<AppInfo> get_installed_apps_linux() {
    std::vector<AppInfo> apps;

    if (command_exists("dpkg-query")) {
        // Debian/Ubuntu
        auto out = run_command(
            "dpkg-query -W -f='${Package}|${Version}|${Maintainer}|${Status}\\n' 2>/dev/null");
        std::istringstream ss(out);
        std::string line;
        while (std::getline(ss, line)) {
            // Only include fully installed packages
            if (line.find("install ok installed") == std::string::npos)
                continue;

            std::istringstream ls(line);
            std::string name, version, publisher;
            std::getline(ls, name, '|');
            std::getline(ls, version, '|');
            std::getline(ls, publisher, '|');

            apps.push_back({name, version, publisher, "-"});
        }
    } else if (command_exists("rpm")) {
        // RHEL/Fedora/SUSE
        auto out = run_command(
            "rpm -qa --queryformat "
            "'%{NAME}|%{VERSION}-%{RELEASE}|%{VENDOR}|%{INSTALLTIME:date}\\n' 2>/dev/null");
        std::istringstream ss(out);
        std::string line;
        while (std::getline(ss, line)) {
            std::istringstream ls(line);
            std::string name, version, publisher, date;
            std::getline(ls, name, '|');
            std::getline(ls, version, '|');
            std::getline(ls, publisher, '|');
            std::getline(ls, date, '|');

            if (publisher == "(none)")
                publisher = "-";
            apps.push_back({name, version, publisher, date});
        }
    } else if (command_exists("pacman")) {
        // Arch Linux
        auto out = run_command("pacman -Q 2>/dev/null");
        std::istringstream ss(out);
        std::string line;
        while (std::getline(ss, line)) {
            // Format: "name version"
            auto sp = line.find(' ');
            if (sp != std::string::npos) {
                apps.push_back({line.substr(0, sp), line.substr(sp + 1), "-", "-"});
            }
        }
    }

    std::sort(apps.begin(), apps.end(),
              [](const AppInfo& a, const AppInfo& b) { return a.name < b.name; });
    return apps;
}
#endif

// ── macOS: list GUI apps and packages ─────────────────────────────────────

#ifdef __APPLE__
std::vector<AppInfo> get_installed_apps_macos() {
    std::vector<AppInfo> apps;

    // GUI applications from system_profiler
    auto out = run_command("system_profiler SPApplicationsDataType -detailLevel mini 2>/dev/null"
                           " | grep -E '^ {4}\\w|Version:|Last Modified:' ");
    if (!out.empty()) {
        std::istringstream ss(out);
        std::string line;
        std::string current_name;
        std::string current_version;
        std::string current_date;
        while (std::getline(ss, line)) {
            // Trim leading whitespace
            auto start = line.find_first_not_of(" \t");
            if (start == std::string::npos)
                continue;
            line = line.substr(start);

            if (line.find("Version:") == 0) {
                current_version = line.substr(line.find(':') + 2);
            } else if (line.find("Last Modified:") == 0) {
                current_date = line.substr(line.find(':') + 2);
            } else if (!line.empty() && line.back() == ':') {
                // Emit previous app
                if (!current_name.empty()) {
                    apps.push_back({current_name, current_version, "-", current_date});
                }
                current_name = line.substr(0, line.size() - 1);
                current_version.clear();
                current_date.clear();
            }
        }
        if (!current_name.empty()) {
            apps.push_back({current_name, current_version, "-", current_date});
        }
    }

    std::sort(apps.begin(), apps.end(),
              [](const AppInfo& a, const AppInfo& b) { return a.name < b.name; });
    return apps;
}
#endif

// ── list_inventory collectors (blob contract v2) ──────────────────────────

namespace inv = yuzu::installed_apps::inventory;

#ifdef _WIN32
std::vector<inv::InvRecord> get_inventory_windows() {
    std::vector<inv::InvRecord> recs;
    for (auto& app : get_installed_apps_windows()) {
        inv::InvRecord r;
        r.name = std::move(app.name);
        r.version = std::move(app.version);
        r.publisher = std::move(app.publisher);
        r.install_date = std::move(app.install_date);
        r.kind = "app";
        r.ecosystem = "windows";
        // epoch/release/signature honest-empty: the Uninstall hive stores no
        // NEVRA and no signature. arch stays empty too — inferring x64/x86
        // from which hive a key sat in would be synthesis, not storage.
        recs.push_back(std::move(r));
    }
    return recs;
}
#endif

#ifdef __linux__
std::vector<inv::InvRecord> get_inventory_linux() {
    std::vector<inv::InvRecord> recs;

    const auto collect = [&recs](const char* cmd, auto parse_line) {
        auto out = run_command(cmd);
        std::istringstream ss(out);
        std::string line;
        while (std::getline(ss, line)) {
            if (auto r = parse_line(line))
                recs.push_back(std::move(*r));
        }
    };

    if (command_exists("dpkg-query")) {
        // ${db:Status-Abbrev} (want+status, 2 chars) keeps installed AND held
        // packages via its 2nd char == 'i' ("ii" want=install, "hi" want=hold)
        // — matches vuln_scan's vuln_identity.hpp (PR #1804) exactly, so the
        // two collectors agree on which packages are present. "rc"
        // (removed, config-files) and "un" (unknown) are correctly excluded;
        // this also supersedes the legacy `list` filter's narrower
        // "install ok installed" substring check, which excludes held.
        collect("dpkg-query -W -f='${Package}\\t${db:Status-Abbrev}\\t${Version}\\t"
                "${Architecture}\\t${Maintainer}\\n' 2>/dev/null",
                inv::parse_dpkg_inv_line);
    } else if (command_exists("rpm")) {
        // Raw SIGPGP (payload) + RSAHEADER (header) signature tags; signed vs
        // unsigned is computed in C++ by parse_rpm_inv_line/rpm_sig_present —
        // matches vuln_scan's vuln_identity.hpp (PR #1804) exactly, so the two
        // collectors agree on this field for the same rpm. Never a live
        // `rpm -K` verification. PACKAGER per the v2 spec (`list` keeps VENDOR
        // for its stable operator contract).
        collect("rpm -qa --queryformat '%{NAME}\\t%{EPOCH}\\t%{VERSION}\\t%{RELEASE}\\t"
                "%{ARCH}\\t%{PACKAGER}\\t%{INSTALLTIME:date}\\t%{SIGPGP}\\t%{RSAHEADER}\\n' "
                "2>/dev/null",
                inv::parse_rpm_inv_line);
    } else if (command_exists("pacman")) {
        collect("pacman -Q 2>/dev/null", inv::parse_pacman_inv_line);
    } else if (command_exists("apk")) {
        // Alpine — first apk enumeration on the sync path (the legacy `list`
        // has no apk branch; precedent is vuln_scan's enumerator).
        collect("apk info -v 2>/dev/null", inv::parse_apk_inv_line);
    }

    // Host-level distro identity, read once and stamped on every row (v2
    // contract). Honest-empty when /etc/os-release is absent (minimal
    // containers) or the keys are missing.
    std::string osrel;
    if (std::ifstream f{"/etc/os-release"}; f) {
        std::ostringstream buf;
        buf << f.rdbuf();
        osrel = buf.str();
    }
    const std::string distro_id = inv::parse_os_release(osrel, "ID");
    const std::string distro_version = inv::parse_os_release(osrel, "VERSION_ID");
    for (auto& r : recs) {
        r.distro_id = distro_id;
        r.distro_version = distro_version;
    }
    return recs;
}
#endif

#ifdef __APPLE__
std::vector<inv::InvRecord> get_inventory_macos() {
    std::vector<inv::InvRecord> recs;
    for (auto& app : get_installed_apps_macos()) {
        inv::InvRecord r;
        r.name = std::move(app.name);
        r.version = std::move(app.version);
        // system_profiler mini exposes no publisher; the legacy collector
        // stores a "-" placeholder which must NOT leak into v2 rows.
        if (app.publisher != "-")
            r.publisher = std::move(app.publisher);
        r.install_date = std::move(app.install_date); // Last Modified
        r.kind = "app";
        r.ecosystem = "macos";
        // "homebrew" stays a reserved ecosystem value: brew is per-user
        // (list_per_user) and out of machine-scope this slice.
        recs.push_back(std::move(r));
    }
    return recs;
}
#endif

int do_list_inventory(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    auto recs = get_inventory_windows();
#elif defined(__linux__)
    auto recs = get_inventory_linux();
#elif defined(__APPLE__)
    auto recs = get_inventory_macos();
#else
    std::vector<inv::InvRecord> recs;
#endif

    // No sentinel row: an empty result is empty output + rc 0. The sync
    // source's empty-parse guard skips the cycle rather than wiping state.
    for (const auto& r : recs) {
        if (r.name.empty())
            continue; // contract: row dropped if name is empty
        ctx.write_output(sanitize_utf8(inv::format_inv_row(r)));
    }
    return 0;
}

// ── list action ───────────────────────────────────────────────────────────

int do_list(yuzu::CommandContext& ctx) {
#ifdef _WIN32
    auto apps = get_installed_apps_windows();
#elif defined(__linux__)
    auto apps = get_installed_apps_linux();
#elif defined(__APPLE__)
    auto apps = get_installed_apps_macos();
#else
    std::vector<AppInfo> apps;
#endif

    if (apps.empty()) {
        ctx.write_output("app|No applications found|-|-|-");
        return 0;
    }

    for (const auto& app : apps) {
        ctx.write_output(sanitize_utf8(
            std::format("app|{}|{}|{}|{}", app.name, app.version.empty() ? "-" : app.version,
                        app.publisher.empty() ? "-" : app.publisher,
                        app.install_date.empty() ? "-" : app.install_date)));
    }
    return 0;
}

// ── query action ──────────────────────────────────────────────────────────

int do_query(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto search = std::string(params.get("name"));
    if (search.empty()) {
        ctx.write_output("error|'name' parameter is required");
        return 1;
    }

#ifdef _WIN32
    auto apps = get_installed_apps_windows();
#elif defined(__linux__)
    auto apps = get_installed_apps_linux();
#elif defined(__APPLE__)
    auto apps = get_installed_apps_macos();
#else
    std::vector<AppInfo> apps;
#endif

    bool found = false;
    for (const auto& app : apps) {
        if (icontains(app.name, search)) {
            if (!found) {
                ctx.write_output("found|true");
                found = true;
            }
            ctx.write_output(sanitize_utf8(
                std::format("app|{}|{}|{}", app.name, app.version.empty() ? "-" : app.version,
                            app.publisher.empty() ? "-" : app.publisher)));
        }
    }

    if (!found) {
        ctx.write_output("found|false");
    }
    return 0;
}

} // namespace

class InstalledAppsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "installed_apps"; }
    std::string_view version() const noexcept override { return "1.1.0"; }
    std::string_view description() const noexcept override {
        return "Inventories installed applications and queries by name";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "query", "list_per_user", "list_inventory", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "list")
            return do_list(ctx);
        if (action == "query")
            return do_query(ctx, params);
        if (action == "list_per_user")
            return do_list_per_user(ctx);
        if (action == "list_inventory")
            return do_list_inventory(ctx);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_list_per_user([[maybe_unused]] yuzu::CommandContext& ctx) {
#ifdef _WIN32
        // #2771: this walk used to be a full private copy of the ProfileList ->
        // HKU -> RegLoadKeyW ladder — one of three in the tree — and was the
        // weakest of them: it swallowed the RegUnLoadKeyW result, expanded
        // ProfileImagePath single-pass into a 512-wchar buffer with the return
        // value ignored (silent truncation), enabled neither SeBackup nor
        // SeRestore, and fell back to the SID as a display name in violation
        // of ADR-0024 D11. It now rides the shared ladder in
        // agents/shared/win_profiles.hpp, which is the canonical one.
        static const char* kUninstallKey =
            "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

        bool profiles_ok = false;
        bool truncated = false;
        auto records = yuzu::win::enumerate_profile_records(profiles_ok, &truncated);
        if (!profiles_ok) {
            ctx.write_output("error|profile_list_unreadable");
            return 1;
        }
        const auto hku_subkeys = yuzu::win::enumerate_hku_subkeys();
        // System SIDs are filtered here, BEFORE any per-profile read, rather
        // than after reading ProfileImagePath as the old walk did.
        const auto profiles = yuzu::profiles::build_profile_list(records, hku_subkeys);

        std::size_t privilege_missing = 0;
        for (const auto& profile : profiles) {
            std::vector<AppInfo> user_apps;
            yuzu::win::HiveAccessReport report;
            const auto status = yuzu::win::with_user_hive(
                profile.sid, profile.profile_path,
                [&](HKEY root) { enumerate_uninstall_key(root, kUninstallKey, 0, user_apps); },
                &report);

            // A leaked mount is the same system-wide fact wherever it happens,
            // so the shared renderer supplies the wording. Passing status=ok
            // deliberately emits ONLY the unload warning: registry's error
            // vocabulary is registry's contract, and not_found/mount_failed are
            // routine here (a logged-out user whose hive is locked) — one line
            // per profile per run would be noise, not signal.
            if (report.unload_failed) {
                for (const auto& line : yuzu::profiles::render_hive_access_lines(
                         yuzu::profiles::HiveAccessStatus::ok, true, report.mount_name,
                         profile.sid))
                    ctx.write_output(sanitize_utf8(line));
            }
            if (status == yuzu::win::HiveAccessStatus::privilege_missing)
                ++privilege_missing;

            // ADR-0024 D11: an unresolvable profile name is rendered "-", never
            // the SID. "-" (not "") matches this row's own convention for
            // version/publisher/install_date below, and is distinguishable from
            // a rendering fault. The SID fallback this replaces was a
            // fabricated display name.
            const std::string username =
                profile.profile_name.empty() ? std::string{"-"} : profile.profile_name;

            for (const auto& app : user_apps) {
                // The leading "user_app|" tag is LOAD-BEARING: installed_apps is
                // in result_parsing.hpp's kKeyValuePlugins, so the dashboard
                // splits these rows into (key, rest) — the opposite of the
                // registry list_profiles case, where a leading tag caused the
                // hp-B1 column shift. Do not strip it.
                ctx.write_output(sanitize_utf8(
                    std::format("user_app|{}|{}|{}|{}|{}", username,
                                app.name, app.version.empty() ? "-" : app.version,
                                app.publisher.empty() ? "-" : app.publisher,
                                app.install_date.empty() ? "-" : app.install_date)));
            }
        }

        // Both caps/failures are reported honestly rather than silently
        // shrinking the result, matching registry.list_profiles' precedent.
        if (truncated) {
            ctx.write_output(yuzu::profiles::render_profile_list_truncated_warning(
                yuzu::win::kMaxProfiles));
        }
        if (privilege_missing > 0) {
            ctx.write_output(std::format(
                "warning|privilege_missing: SeBackupPrivilege/SeRestorePrivilege could not be "
                "enabled for {} logged-out profile(s); their per-user apps are not listed",
                privilege_missing));
        }
        return 0;

#elif defined(__linux__)
        // List packages installed per-user via dpkg or per-user snap/flatpak
        // For dpkg-based systems, packages are system-wide. Report them as system.
        auto apps = get_installed_apps_linux();
        for (const auto& app : apps) {
            ctx.write_output(sanitize_utf8(
                std::format("user_app|system|{}|{}|{}|{}", app.name,
                            app.version.empty() ? "-" : app.version,
                            app.publisher.empty() ? "-" : app.publisher,
                            app.install_date.empty() ? "-" : app.install_date)));
        }
        return 0;

#elif defined(__APPLE__)
        // On macOS, use brew list per user if Homebrew is installed
        // First list system apps
        auto apps = get_installed_apps_macos();
        for (const auto& app : apps) {
            ctx.write_output(sanitize_utf8(
                std::format("user_app|system|{}|{}|{}|{}", app.name,
                            app.version.empty() ? "-" : app.version,
                            app.publisher.empty() ? "-" : app.publisher,
                            app.install_date.empty() ? "-" : app.install_date)));
        }

        // Try Homebrew per-user (runs under current user)
        if (command_exists("brew")) {
            auto brew_out = run_command("brew list --versions 2>/dev/null");
            if (!brew_out.empty()) {
                std::istringstream ss(brew_out);
                std::string line;
                while (std::getline(ss, line)) {
                    auto sp = line.find(' ');
                    std::string name = (sp != std::string::npos) ? line.substr(0, sp) : line;
                    std::string version = (sp != std::string::npos) ? line.substr(sp + 1) : "-";
                    ctx.write_output(sanitize_utf8(
                        std::format("user_app|brew|{}|{}|-|-", name, version)));
                }
            }
        }
        return 0;
#else
        ctx.write_output("error|per-user app inventory not supported on this platform");
        return 1;
#endif
    }
};

YUZU_PLUGIN_EXPORT(InstalledAppsPlugin)
