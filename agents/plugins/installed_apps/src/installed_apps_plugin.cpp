/**
 * installed_apps_plugin.cpp — Installed applications plugin for Yuzu
 *
 * Actions:
 *   "list"  — Lists all installed applications.
 *   "query" — Searches for a specific app by name (partial match).
 *             Params: name (required).
 *
 * Output is pipe-delimited, one record per line via write_output():
 *   app|name|version|publisher|install_date
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#if defined(__linux__) || defined(__APPLE__)
#include <sstream>
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

// Registry strings are UTF-16. Read via the *W APIs and convert to UTF-8 so
// non-ASCII names (e.g. "Café") survive intact — the *A APIs return the system
// ANSI code page (cp1252), which then fails UTF-8 validation downstream and
// corrupts the typed software-inventory store's WHERE name=$1 lookups (#1662).
// to_wide/from_wide are duplicated from registry_plugin.cpp for build isolation
// (each plugin is its own shared object with no shared internal code); reg_sz_to_utf8
// is a local helper for the REG_SZ byte-size convention.
std::wstring to_wide(std::string_view s) {
    if (s.empty())
        return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring ws(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), ws.data(), len);
    return ws;
}

std::string from_wide(const wchar_t* ws, int len = -1) {
    if (!ws)
        return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, ws, len, nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(sz), '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws, len, s.data(), sz, nullptr, nullptr);
    if (!s.empty() && s.back() == '\0')
        s.pop_back();
    return s;
}

// Convert a REG_SZ payload (size is in BYTES, may include trailing NUL(s)) to UTF-8.
std::string reg_sz_to_utf8(const wchar_t* buf, DWORD size_bytes) {
    size_t nch = size_bytes / sizeof(wchar_t);
    while (nch > 0 && buf[nch - 1] == L'\0')
        --nch;
    return from_wide(buf, static_cast<int>(nch));
}

void enumerate_uninstall_key(HKEY root, const char* subkey, REGSAM extra_sam,
                             std::vector<AppInfo>& apps) {
    HKEY hkey{};
    if (RegOpenKeyExW(root, to_wide(subkey).c_str(), 0,
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS | extra_sam, &hkey) != ERROR_SUCCESS) {
        return;
    }

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
                    RegCloseKey(app_key);
                    name_len = kNameBufLen;
                    continue;
                }

                AppInfo app;
                app.name = std::move(display_name);
                app.version = read_str("DisplayVersion");
                app.publisher = read_str("Publisher");
                app.install_date = read_str("InstallDate");
                apps.push_back(std::move(app));
            }
            RegCloseKey(app_key);
        }
        name_len = kNameBufLen;
    }
    RegCloseKey(hkey);
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
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Inventories installed applications and queries by name";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "query", "list_per_user", nullptr};
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

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_list_per_user([[maybe_unused]] yuzu::CommandContext& ctx) {
#ifdef _WIN32
        // Enumerate user profiles from the ProfileList registry key
        static const char* kProfileListKey =
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
        static const char* kUninstallKey =
            "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

        HKEY profiles_key{};
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, to_wide(kProfileListKey).c_str(), 0,
                          KEY_READ | KEY_ENUMERATE_SUB_KEYS, &profiles_key) != ERROR_SUCCESS) {
            ctx.write_output("error|failed to open ProfileList registry key");
            return 1;
        }

        wchar_t sid_buf[256]{};
        DWORD idx = 0;
        DWORD sid_len = 256; // RegEnumKeyExW counts WCHARs, not bytes

        while (RegEnumKeyExW(profiles_key, idx++, sid_buf, &sid_len,
                             nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            std::string sid = from_wide(sid_buf, static_cast<int>(sid_len));
            sid_len = 256;

            // Read ProfileImagePath to get the username
            HKEY sid_key{};
            if (RegOpenKeyExW(profiles_key, to_wide(sid).c_str(), 0, KEY_READ, &sid_key) !=
                ERROR_SUCCESS)
                continue;

            wchar_t path_buf[512]{};
            DWORD path_size = sizeof(path_buf); // size in BYTES
            DWORD type = 0;
            std::string username = sid;  // fallback to SID
            std::wstring profile_path_w; // kept wide for RegLoadKeyW below
            if (RegQueryValueExW(sid_key, L"ProfileImagePath", nullptr, &type,
                                 reinterpret_cast<LPBYTE>(path_buf), &path_size) == ERROR_SUCCESS) {
                size_t nch = path_size / sizeof(wchar_t);
                while (nch > 0 && path_buf[nch - 1] == L'\0')
                    --nch;
                profile_path_w.assign(path_buf, nch);
                std::string profile_path =
                    from_wide(profile_path_w.c_str(), static_cast<int>(profile_path_w.size()));
                auto last_sep = profile_path.find_last_of("\\/");
                if (last_sep != std::string::npos)
                    username = profile_path.substr(last_sep + 1);
            }
            RegCloseKey(sid_key);

            // Skip system SIDs (S-1-5-18, S-1-5-19, S-1-5-20)
            if (sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20")
                continue;

            // Try to read the user's Uninstall key from HKU\<SID>
            std::string user_uninstall = sid + "\\" + kUninstallKey;
            std::vector<AppInfo> user_apps;
            enumerate_uninstall_key(HKEY_USERS, user_uninstall.c_str(), 0, user_apps);

            // The !profile_path_w.empty() guard avoids mounting a hive from a bogus
            // "\NTUSER.DAT" path when ProfileImagePath failed to read (it also
            // blocked an empty-path hive-load the prior *A code permitted).
            if (user_apps.empty() && !profile_path_w.empty()) {
                // User hive may not be loaded — try loading NTUSER.DAT
                std::wstring ntuser_path_w = profile_path_w + L"\\NTUSER.DAT";
                std::string mount_key = "YUZU_APPS_" + sid;

                // Attempt to expand environment variables in the path
                wchar_t expanded[512]{};
                ExpandEnvironmentStringsW(ntuser_path_w.c_str(), expanded, 512);

                const std::wstring mount_w = to_wide(mount_key);
                LONG load_res = RegLoadKeyW(HKEY_USERS, mount_w.c_str(), expanded);
                if (load_res == ERROR_SUCCESS) {
                    // RAII: unload the mounted hive on EVERY exit, including a
                    // std::bad_alloc thrown by enumerate_uninstall_key. A leaked
                    // mount is system-wide, survives process death, and locks the
                    // user's NTUSER.DAT until reboot (gov Gate 6 sre / UP-1).
                    struct HiveUnloadGuard {
                        const std::wstring& mount;
                        ~HiveUnloadGuard() { RegUnLoadKeyW(HKEY_USERS, mount.c_str()); }
                    } unload_guard{mount_w};

                    std::string mounted_uninstall = mount_key + "\\" + kUninstallKey;
                    enumerate_uninstall_key(HKEY_USERS, mounted_uninstall.c_str(), 0, user_apps);
                }
            }

            for (const auto& app : user_apps) {
                ctx.write_output(sanitize_utf8(
                    std::format("user_app|{}|{}|{}|{}|{}", username,
                                app.name, app.version.empty() ? "-" : app.version,
                                app.publisher.empty() ? "-" : app.publisher,
                                app.install_date.empty() ? "-" : app.install_date)));
            }
        }
        RegCloseKey(profiles_key);
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
