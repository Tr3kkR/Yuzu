/**
 * tar_software_collector.cpp -- Installed-software enumeration for the TAR
 * `software` source (Phase 8 Wave 1).
 *
 * Windows enumerates the registry Uninstall keys. Two scopes:
 *   - machine: HKLM ...\Uninstall (64-bit + WOW6432Node 32-bit) — cheap, no mounts.
 *   - user:    each profile's HKU\<SID>\...\Uninstall. A LOGGED-ON user's hive is
 *              already loaded under HKU (cheap); a LOGGED-OFF user's hive is on
 *              disk and must be mounted with RegLoadKeyW (NTUSER.DAT) to read.
 *
 * Steady-state TAR ticks call enumerate_machine_software + enumerate_loaded_user_software
 * (loaded hives only — NO mounting) and carry forward logged-off users from the
 * stored baseline; a logged-off user cannot install software, so their inventory
 * is frozen and re-mounting every tick is pure I/O waste (a real cost on
 * many-profile RDS/Citrix hosts). The full enumerate_software(max_hive_mounts) —
 * which mounts logged-off hives, capped — is used ONLY for the one-time cold-start
 * baseline.
 *
 * All registry handles and hive mounts are owned by RAII guards (RegKey /
 * HiveUnmount) so an exception (e.g. std::bad_alloc while building a result
 * string) cannot leak an HKEY or, worse, leave a user's NTUSER.DAT permanently
 * mounted (which would pin the file and break that user's next logon).
 *
 * Registry STRING reads use the wide Reg*W APIs and convert to UTF-8 via the
 * shared win_str.hpp helpers (yuzu::win::reg_sz_to_utf8 / from_wide), per the
 * project-wide wide-only registry-read contract (#1662/#1682). The old ANSI
 * Reg*A path returned system-codepage bytes that silently corrupted non-ASCII
 * application names, publishers, and profile paths before storage. Linux/macOS:
 * every entry point returns empty (kPlanned).
 */

#include "tar_collectors.hpp"
#include "tar_version.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
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

#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681/#1682)
#endif

namespace yuzu::tar {

#ifdef _WIN32

namespace {

constexpr const char* kMachineUninstall = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
constexpr const char* kUserUninstall = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
constexpr const char* kProfileListKey =
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";

// RAII owner for an HKEY. Closes on destruction so an exception between open and
// the (former) manual RegCloseKey cannot leak the handle. Non-copyable and
// non-movable (the user-declared dtor suppresses the implicit move; a defaulted
// move would copy the raw HKEY and double-close — we never need to move one).
class RegKey {
public:
    RegKey() = default;
    RegKey(const RegKey&) = delete;
    RegKey& operator=(const RegKey&) = delete;
    ~RegKey() {
        if (h_)
            RegCloseKey(h_);
    }
    HKEY* put() { return &h_; } // for the &phkResult out-param of RegOpenKeyExW
    HKEY get() const { return h_; }

private:
    HKEY h_{nullptr};
};

// RAII guard that unmounts a hive (RegUnLoadKeyW) loaded with RegLoadKeyW. Armed
// only after a successful load, so the destructor unloads on every exit path —
// including an exception while enumerating the mounted hive.
class HiveUnmount {
public:
    explicit HiveUnmount(std::string mount_key) : key_(std::move(mount_key)) {}
    HiveUnmount(const HiveUnmount&) = delete;
    HiveUnmount& operator=(const HiveUnmount&) = delete;
    ~HiveUnmount() { RegUnLoadKeyW(HKEY_USERS, yuzu::win::to_wide(key_).c_str()); }

private:
    std::string key_; // ASCII ("YUZU_TAR_SW_<SID>")
};

// Warn once (per process) when the per-cycle software entry cap is hit. Unlike
// the ARP/DNS auto-clearing rate-limit, a host that genuinely owns >8192
// installed entries would truncate on EVERY tick, so the flag latches and never
// resets — one warning, not a per-tick spam. The append loop bounds memory + tick
// duration regardless of whether the warn fires (#1620).
void note_software_truncation() {
    static std::atomic<bool> warned{false};
    if (!warned.exchange(true)) {
        spdlog::warn("TAR software: per-cycle entry cap {} reached — truncating installed-software "
                     "inventory (further truncation warnings suppressed)",
                     kSoftwareEntryCap);
    }
}

// One-entry-per-(scope,user,name): sort then keep the highest-versioned of any
// same-identity duplicates (e.g. two products sharing a DisplayName), so the
// diff key (scope,user,name) is unambiguous. Versions compare numerically
// (compare_versions), not lexicographically — "10.0" outranks "9.0" so the diff
// keeps the real-latest build (#1620).
void dedup(std::vector<SoftwareInfo>& apps) {
    std::sort(apps.begin(), apps.end(), [](const SoftwareInfo& a, const SoftwareInfo& b) {
        if (a.scope != b.scope) return a.scope < b.scope;
        if (a.user != b.user) return a.user < b.user;
        if (a.name != b.name) return a.name < b.name;
        return compare_versions(a.version, b.version) > 0; // descending → unique keeps the highest
    });
    apps.erase(std::unique(apps.begin(), apps.end(),
                           [](const SoftwareInfo& a, const SoftwareInfo& b) {
                               return a.scope == b.scope && a.user == b.user && a.name == b.name;
                           }),
               apps.end());
}

// Enumerate one Uninstall key, appending SoftwareInfo records tagged with the
// supplied scope/user. SystemComponent=1 and nameless entries are skipped.
// `subkey` is an ASCII key PATH (compile-time literal or SID-derived); it is
// converted to wide for the open so the whole read path is Reg*W.
void enumerate_uninstall_key(HKEY root, const char* subkey, REGSAM extra_sam,
                             const std::string& scope, const std::string& user,
                             std::vector<SoftwareInfo>& apps) {
    // Per-cycle cap (#1620): `apps` is the shared accumulator across machine +
    // every per-user hive in one tick, so a prior key may already have filled it.
    if (apps.size() >= kSoftwareEntryCap) {
        note_software_truncation();
        return;
    }

    RegKey hkey;
    if (RegOpenKeyExW(root, yuzu::win::to_wide(subkey).c_str(), 0,
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS | extra_sam, hkey.put()) != ERROR_SUCCESS) {
        return;
    }

    // App subkey names can be non-ASCII (some installers key on the DisplayName),
    // so enumerate wide and re-open with the wide name directly — an ANSI round
    // trip could mangle the name and fail the re-open.
    wchar_t name_buf[256]{};
    DWORD idx = 0;
    DWORD name_len = ARRAYSIZE(name_buf); // RegEnumKeyExW length is in CHARACTERS, not bytes

    while (RegEnumKeyExW(hkey.get(), idx++, name_buf, &name_len, nullptr, nullptr, nullptr,
                         nullptr) == ERROR_SUCCESS) {
        if (apps.size() >= kSoftwareEntryCap) {
            note_software_truncation();
            break;
        }
        RegKey app_key;
        if (RegOpenKeyExW(hkey.get(), name_buf, 0, KEY_READ | extra_sam, app_key.put()) ==
            ERROR_SUCCESS) {
            auto read_str = [&](const wchar_t* value_name) -> std::string {
                wchar_t buf[512]{};
                DWORD size = sizeof(buf); // bytes — RegQueryValueExW reports/consumes byte counts
                DWORD type = 0;
                if (RegQueryValueExW(app_key.get(), value_name, nullptr, &type,
                                     reinterpret_cast<LPBYTE>(buf), &size) == ERROR_SUCCESS) {
                    // Accept REG_EXPAND_SZ as well as REG_SZ — some installers store
                    // these values with embedded environment refs. reg_sz_to_utf8
                    // stops at the first NUL (correct for REG_SZ/REG_EXPAND_SZ) and
                    // returns valid UTF-8, so no system-codepage corruption and no
                    // separate sanitisation pass is needed.
                    if ((type == REG_SZ || type == REG_EXPAND_SZ) && size > 0) {
                        DWORD cap = size < sizeof(buf) ? size : sizeof(buf);
                        return yuzu::win::reg_sz_to_utf8(buf, cap);
                    }
                }
                return {};
            };

            // SystemComponent is canonically a REG_DWORD (=1 hides the entry from
            // Add/Remove Programs); a REG_SZ-only read made the filter a permanent
            // no-op so system components/patches were collected despite the manual's
            // contract (#1620). Read the DWORD form, falling back to the rare string
            // form. (A DWORD read carries no encoding; it stays correct under W.)
            auto system_component_set = [&]() -> bool {
                DWORD val = 0;
                DWORD size = sizeof(val);
                DWORD type = 0;
                if (RegQueryValueExW(app_key.get(), L"SystemComponent", nullptr, &type,
                                     reinterpret_cast<LPBYTE>(&val), &size) == ERROR_SUCCESS &&
                    type == REG_DWORD && size == sizeof(DWORD)) {
                    return val == 1;
                }
                return read_str(L"SystemComponent") == "1";
            };

            auto display_name = read_str(L"DisplayName");
            if (!display_name.empty() && !system_component_set()) {
                SoftwareInfo app;
                app.name = std::move(display_name);
                app.version = read_str(L"DisplayVersion");
                app.publisher = read_str(L"Publisher");
                // InstallDate is usually REG_SZ "YYYYMMDD", but some installers
                // store it as a REG_DWORD number — fall back to that so the column
                // is not silently empty.
                auto install_date = read_str(L"InstallDate");
                if (install_date.empty()) {
                    DWORD val = 0;
                    DWORD dsize = sizeof(val);
                    DWORD dtype = 0;
                    if (RegQueryValueExW(app_key.get(), L"InstallDate", nullptr, &dtype,
                                         reinterpret_cast<LPBYTE>(&val), &dsize) == ERROR_SUCCESS &&
                        dtype == REG_DWORD && dsize == sizeof(DWORD) && val != 0) {
                        install_date = std::to_string(val);
                    }
                }
                app.install_date = std::move(install_date);
                app.scope = scope;
                app.user = user;
                apps.push_back(std::move(app));
            }
        }
        name_len = ARRAYSIZE(name_buf);
    }
}

struct ProfileEntry {
    std::string sid;
    std::string username;
    std::string profile_dir;
    bool loaded{false}; // HKU\<SID> currently present (user logged on / hive loaded)
};

// Walk ProfileList → real user profiles (system SIDs skipped). No hive mounting;
// `loaded` records whether HKU\<SID> is already present so the caller can read it
// cheaply vs. having to mount NTUSER.DAT.
std::vector<ProfileEntry> list_profiles() {
    std::vector<ProfileEntry> profiles;
    RegKey profiles_key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, yuzu::win::to_wide(kProfileListKey).c_str(), 0,
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS, profiles_key.put()) != ERROR_SUCCESS) {
        return profiles;
    }

    // SID subkey names are ASCII by construction (S-1-...), but enumerate wide for
    // uniformity and to keep the whole path Reg*W; from_wide round-trips ASCII exactly.
    wchar_t sid_buf[256]{};
    DWORD idx = 0;
    DWORD sid_len = ARRAYSIZE(sid_buf); // characters, not bytes
    while (RegEnumKeyExW(profiles_key.get(), idx++, sid_buf, &sid_len, nullptr, nullptr, nullptr,
                         nullptr) == ERROR_SUCCESS) {
        std::string sid = yuzu::win::from_wide(sid_buf, static_cast<int>(sid_len));
        sid_len = ARRAYSIZE(sid_buf);

        // Skip the system / service profiles — not real users.
        if (sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20")
            continue;

        ProfileEntry p;
        p.sid = sid;

        RegKey sid_key;
        if (RegOpenKeyExW(profiles_key.get(), sid_buf, 0, KEY_READ, sid_key.put()) !=
            ERROR_SUCCESS) {
            continue;
        }
        wchar_t path_buf[512]{};
        DWORD path_size = sizeof(path_buf); // bytes
        DWORD type = 0;
        std::string username = sid; // fall back to the SID
        if (RegQueryValueExW(sid_key.get(), L"ProfileImagePath", nullptr, &type,
                             reinterpret_cast<LPBYTE>(path_buf), &path_size) == ERROR_SUCCESS &&
            path_size > 0) {
            // ProfileImagePath is REG_EXPAND_SZ; reg_sz_to_utf8 stops at the first
            // NUL and yields valid UTF-8 (non-ASCII profile dirs round-trip intact).
            DWORD cap = path_size < sizeof(path_buf) ? path_size : sizeof(path_buf);
            p.profile_dir = yuzu::win::reg_sz_to_utf8(path_buf, cap);
            auto last_sep = p.profile_dir.find_last_of("\\/");
            if (last_sep != std::string::npos)
                username = p.profile_dir.substr(last_sep + 1);
        }
        p.username = std::move(username);

        // HKU\<SID> present ⇒ the hive is already loaded (user logged on or hive
        // otherwise mounted) and can be read without RegLoadKeyW.
        RegKey loaded_probe;
        p.loaded = RegOpenKeyExW(HKEY_USERS, sid_buf, 0, KEY_READ, loaded_probe.put()) ==
                   ERROR_SUCCESS;

        profiles.push_back(std::move(p));
    }
    return profiles;
}

// Read a loaded profile's per-user Uninstall key (HKU\<SID>\...\Uninstall).
void read_loaded_user(const ProfileEntry& p, std::vector<SoftwareInfo>& apps) {
    std::string key = p.sid + "\\" + kUserUninstall;
    enumerate_uninstall_key(HKEY_USERS, key.c_str(), 0, "user", p.username, apps);
}

// Mount a logged-off profile's NTUSER.DAT, read its Uninstall key, unmount.
// Best-effort: a locked/missing hive or insufficient privilege simply yields no
// per-user rows for that profile. Returns true if the mount was attempted-and-loaded.
bool read_offline_user(const ProfileEntry& p, std::vector<SoftwareInfo>& apps) {
    if (p.profile_dir.empty())
        return false;
    std::string ntuser = p.profile_dir + "\\NTUSER.DAT";
    wchar_t expanded[512]{};
    DWORD n = ExpandEnvironmentStringsW(yuzu::win::to_wide(ntuser).c_str(), expanded,
                                        ARRAYSIZE(expanded)); // nSize is in CHARACTERS
    if (n == 0 || n > ARRAYSIZE(expanded))
        return false; // expansion failed or truncated — skip rather than mount a bad path
    std::string mount_key = "YUZU_TAR_SW_" + p.sid;
    if (RegLoadKeyW(HKEY_USERS, yuzu::win::to_wide(mount_key).c_str(), expanded) != ERROR_SUCCESS)
        return false;
    HiveUnmount unmount(mount_key); // unloads on every exit, including an exception below
    std::string key = mount_key + "\\" + kUserUninstall;
    enumerate_uninstall_key(HKEY_USERS, key.c_str(), 0, "user", p.username, apps);
    return true;
}

} // namespace

void enumerate_machine_software(std::vector<SoftwareInfo>& out) {
    // 64-bit then 32-bit (WoW6432Node) HKLM. (Per-user keys below pass extra_sam=0
    // because HKU is not subject to WoW64 registry redirection.)
    enumerate_uninstall_key(HKEY_LOCAL_MACHINE, kMachineUninstall, KEY_WOW64_64KEY, "machine", "",
                            out);
    enumerate_uninstall_key(HKEY_LOCAL_MACHINE, kMachineUninstall, KEY_WOW64_32KEY, "machine", "",
                            out);
    dedup(out);
}

LoadedUserScan enumerate_loaded_user_software() {
    LoadedUserScan scan;
    for (const auto& p : list_profiles()) {
        if (!p.loaded)
            continue;
        read_loaded_user(p, scan.entries);
        scan.scanned_users.push_back(p.username); // record EVERY loaded profile, even if 0 apps
    }
    dedup(scan.entries);
    return scan;
}

std::vector<SoftwareInfo> enumerate_software(int max_hive_mounts) {
    std::vector<SoftwareInfo> apps;
    enumerate_machine_software(apps); // dedups machine; per-user appended below

    int mounts_used = 0;
    for (const auto& p : list_profiles()) {
        // Stop once the per-cycle cap is full so we don't keep mounting (the
        // expensive part) hives whose entries would be dropped anyway (#1620).
        if (apps.size() >= kSoftwareEntryCap) {
            note_software_truncation();
            break;
        }
        if (p.loaded) {
            read_loaded_user(p, apps);
        } else if (mounts_used < max_hive_mounts) {
            if (read_offline_user(p, apps))
                ++mounts_used;
        }
        // Offline profiles beyond the mount cap are not baselined here; they are
        // first captured when their user next logs on (hive becomes loaded → read
        // with no mount), at which point their apps register as 'installed'.
    }
    dedup(apps);
    return apps;
}

#else // !_WIN32

// Linux/macOS: kPlanned. The schema is queryable-empty; a fast-follow will reuse
// the installed_apps dpkg/rpm/pkgutil enumeration here.
std::vector<SoftwareInfo> enumerate_software(int /*max_hive_mounts*/) { return {}; }
void enumerate_machine_software(std::vector<SoftwareInfo>& /*out*/) {}
LoadedUserScan enumerate_loaded_user_software() { return {}; }

#endif

} // namespace yuzu::tar
