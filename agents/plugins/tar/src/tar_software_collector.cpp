/**
 * tar_software_collector.cpp -- Installed-software enumeration for the TAR
 * `software` source (Phase 8 Wave 1).
 *
 * Windows: machine-wide (HKLM Uninstall 64-bit + WOW6432Node 32-bit) plus
 * per-user (HKU\<SID>\...\Uninstall, mounting NTUSER.DAT for logged-off
 * profiles), mirroring the installed_apps plugin's enumeration. SystemComponent
 * entries are skipped. Registry strings are sanitised to valid UTF-8 (legacy
 * system-codepage bytes are replaced) so protobuf serialization downstream
 * cannot choke. The `scope` field distinguishes machine vs per-user rows and
 * `user` carries the profile name for per-user entries.
 *
 * Linux / macOS: returns empty (kPlanned in the schema registry) — a fast-follow
 * will reuse the installed_apps dpkg/rpm/pkgutil enumeration.
 */

#include "tar_collectors.hpp"

#include <algorithm>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace yuzu::tar {

#ifdef _WIN32

namespace {

// Replace invalid UTF-8 bytes with '?'. Windows registry strings read via the
// ANSI API may carry legacy system-codepage bytes that are not valid UTF-8.
// (Intentionally duplicated from installed_apps for build isolation.)
std::string sanitize_utf8(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            out += s[i];
            ++i;
        } else if ((c >> 5) == 0x06 && i + 1 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02) {
            out += s[i];
            out += s[i + 1];
            i += 2;
        } else if ((c >> 4) == 0x0E && i + 2 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02) {
            out += s[i];
            out += s[i + 1];
            out += s[i + 2];
            i += 3;
        } else if ((c >> 3) == 0x1E && i + 3 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 3]) >> 6) == 0x02) {
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

// Enumerate one Uninstall key, appending SoftwareInfo records tagged with the
// supplied scope/user. SystemComponent=1 and nameless entries are skipped.
void enumerate_uninstall_key(HKEY root, const char* subkey, REGSAM extra_sam,
                             const std::string& scope, const std::string& user,
                             std::vector<SoftwareInfo>& apps) {
    HKEY hkey{};
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | extra_sam, &hkey) !=
        ERROR_SUCCESS) {
        return;
    }

    char name_buf[256]{};
    DWORD idx = 0;
    DWORD name_len = sizeof(name_buf);

    while (RegEnumKeyExA(hkey, idx++, name_buf, &name_len, nullptr, nullptr, nullptr, nullptr) ==
           ERROR_SUCCESS) {
        HKEY app_key{};
        if (RegOpenKeyExA(hkey, name_buf, 0, KEY_READ | extra_sam, &app_key) == ERROR_SUCCESS) {
            auto read_str = [&](const char* value_name) -> std::string {
                char buf[512]{};
                DWORD size = sizeof(buf);
                DWORD type = 0;
                if (RegQueryValueExA(app_key, value_name, nullptr, &type,
                                     reinterpret_cast<LPBYTE>(buf), &size) == ERROR_SUCCESS) {
                    if (type == REG_SZ && size > 0) {
                        return std::string(buf, size - 1);
                    }
                }
                return {};
            };

            auto display_name = read_str("DisplayName");
            if (!display_name.empty() && read_str("SystemComponent") != "1") {
                SoftwareInfo app;
                app.name = sanitize_utf8(std::move(display_name));
                app.version = sanitize_utf8(read_str("DisplayVersion"));
                app.publisher = sanitize_utf8(read_str("Publisher"));
                app.install_date = sanitize_utf8(read_str("InstallDate"));
                app.scope = scope;
                app.user = user;
                apps.push_back(std::move(app));
            }
            RegCloseKey(app_key);
        }
        name_len = sizeof(name_buf);
    }
    RegCloseKey(hkey);
}

// Walk ProfileList, enumerating each non-system profile's per-user Uninstall key
// (HKU\<SID> when the hive is loaded; mounting NTUSER.DAT otherwise so logged-off
// users' installs still appear — without this the inventory would lose a user on
// logoff and the diff would emit spurious removed/installed on logoff/logon).
void enumerate_per_user(std::vector<SoftwareInfo>& apps) {
    static const char* kProfileListKey =
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
    static const char* kUserUninstall = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

    HKEY profiles_key{};
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, kProfileListKey, 0,
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS, &profiles_key) != ERROR_SUCCESS) {
        return;
    }

    char sid_buf[256]{};
    DWORD idx = 0;
    DWORD sid_len = sizeof(sid_buf);

    while (RegEnumKeyExA(profiles_key, idx++, sid_buf, &sid_len, nullptr, nullptr, nullptr,
                         nullptr) == ERROR_SUCCESS) {
        std::string sid(sid_buf, sid_len);
        sid_len = sizeof(sid_buf);

        // Skip the system / service profiles — not real users.
        if (sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20")
            continue;

        // Resolve a friendly username from ProfileImagePath; fall back to the SID.
        HKEY sid_key{};
        if (RegOpenKeyExA(profiles_key, sid.c_str(), 0, KEY_READ, &sid_key) != ERROR_SUCCESS)
            continue;

        char path_buf[512]{};
        DWORD path_size = sizeof(path_buf);
        DWORD type = 0;
        std::string username = sid;
        if (RegQueryValueExA(sid_key, "ProfileImagePath", nullptr, &type,
                             reinterpret_cast<LPBYTE>(path_buf), &path_size) == ERROR_SUCCESS) {
            std::string profile_path(path_buf, path_size > 0 ? path_size - 1 : 0);
            auto last_sep = profile_path.find_last_of("\\/");
            if (last_sep != std::string::npos)
                username = profile_path.substr(last_sep + 1);
        }
        RegCloseKey(sid_key);
        username = sanitize_utf8(username);

        // Loaded hive first (logged-on users): HKU\<SID>\...\Uninstall.
        std::string loaded = sid + "\\" + kUserUninstall;
        std::size_t before = apps.size();
        enumerate_uninstall_key(HKEY_USERS, loaded.c_str(), 0, "user", username, apps);

        // Logged-off user: mount NTUSER.DAT, enumerate, unmount. Best-effort — a
        // locked or missing hive (or insufficient privilege) simply yields no
        // per-user rows for that profile rather than failing the whole pass.
        if (apps.size() == before) {
            char expanded[512]{};
            std::string ntuser = std::string(path_buf) + "\\NTUSER.DAT";
            ExpandEnvironmentStringsA(ntuser.c_str(), expanded, sizeof(expanded));
            std::string mount_key = "YUZU_TAR_SW_" + sid;
            if (RegLoadKeyA(HKEY_USERS, mount_key.c_str(), expanded) == ERROR_SUCCESS) {
                std::string mounted = mount_key + "\\" + kUserUninstall;
                enumerate_uninstall_key(HKEY_USERS, mounted.c_str(), 0, "user", username, apps);
                RegUnLoadKeyA(HKEY_USERS, mount_key.c_str());
            }
        }
    }
    RegCloseKey(profiles_key);
}

} // namespace

std::vector<SoftwareInfo> enumerate_software() {
    std::vector<SoftwareInfo> apps;
    static const char* kMachineUninstall =
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

    // Machine scope: 64-bit then 32-bit (WoW6432Node) HKLM.
    enumerate_uninstall_key(HKEY_LOCAL_MACHINE, kMachineUninstall, KEY_WOW64_64KEY, "machine", "",
                            apps);
    enumerate_uninstall_key(HKEY_LOCAL_MACHINE, kMachineUninstall, KEY_WOW64_32KEY, "machine", "",
                            apps);

    // Per-user scope.
    enumerate_per_user(apps);

    // Deterministic one-entry-per-(scope,user,name): sort, then keep the
    // highest-versioned of any same-identity duplicates (e.g. two products that
    // share a DisplayName). Keeps the diff key (scope,user,name) unambiguous.
    std::sort(apps.begin(), apps.end(), [](const SoftwareInfo& a, const SoftwareInfo& b) {
        if (a.scope != b.scope) return a.scope < b.scope;
        if (a.user != b.user) return a.user < b.user;
        if (a.name != b.name) return a.name < b.name;
        return a.version > b.version; // descending → std::unique keeps the highest version
    });
    apps.erase(std::unique(apps.begin(), apps.end(),
                           [](const SoftwareInfo& a, const SoftwareInfo& b) {
                               return a.scope == b.scope && a.user == b.user && a.name == b.name;
                           }),
               apps.end());
    return apps;
}

#else // !_WIN32

// Linux/macOS: kPlanned. The schema is queryable-empty; a fast-follow will reuse
// the installed_apps dpkg/rpm/pkgutil enumeration here.
std::vector<SoftwareInfo> enumerate_software() {
    return {};
}

#endif

} // namespace yuzu::tar
