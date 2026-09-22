/**
 * privacy_permissions_win.cpp -- Windows leg: HKCU/HKLM
 * ...\CapabilityAccessManager\ConsentStore walk (rung 1, registry only, no spawn).
 *
 * UNKNOWNS pending a real the-rig capture (see the plan): the exact NonPackaged
 * path-escaping scheme (unescape_nonpackaged_app_id is a best-effort `#`->`\` pass), whether
 * the HKLM policy mirror exists un-configured on a non-MDM host (expected: absent), and the
 * real `Value` literal vocabulary (decode_consent_value never assumes only Allow/Deny exist).
 *
 * HKLM takes precedence over HKCU for the same (CapabilityName, app_id) pair when both are
 * present -- an MDM/GPO-locked policy overriding the user's own choice.
 */
#include "privacy_permissions_legs.hpp"
#include "privacy_permissions_win_parsers.hpp"

#if defined(_WIN32)

#include <win_reg_handle.hpp>
#include <win_str.hpp>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

namespace yuzu::privacy_permissions {

namespace {

constexpr wchar_t kConsentStorePath[] =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore";

/// One (app_id, category) grant as read from ONE registry root (HKCU or HKLM).
struct RawGrant {
    std::string app_id; // "-" for the capability-level (no specific app) row
    std::string category;
    PermissionState state;
    std::string raw_value;
    std::string last_used_start;
    std::string last_used_stop;
};

std::vector<std::wstring> enumerate_subkey_names(HKEY parent) {
    std::vector<std::wstring> out;
    constexpr DWORD kNameBufLen = 512;
    wchar_t buf[kNameBufLen]{};
    DWORD idx = 0, len = kNameBufLen;
    while (RegEnumKeyExW(parent, idx++, buf, &len, nullptr, nullptr, nullptr, nullptr) ==
          ERROR_SUCCESS) {
        out.emplace_back(buf, len);
        len = kNameBufLen;
    }
    return out;
}

/// Reads one app-level grant's `Value` (+ LastUsedTime* if present) from `app_key`.
RawGrant read_one_grant(HKEY app_key, std::string app_id, std::string_view category) {
    RawGrant g{std::move(app_id), std::string{category}, PermissionState::unreadable, "-", "-", "-"};

    DWORD type = 0, size = 0;
    if (RegQueryValueExW(app_key, L"Value", nullptr, &type, nullptr, &size) == ERROR_SUCCESS &&
        size > 0) {
        std::vector<wchar_t> buf(size / sizeof(wchar_t) + 1, L'\0');
        DWORD sz = size;
        if (RegQueryValueExW(app_key, L"Value", nullptr, &type,
                             reinterpret_cast<BYTE*>(buf.data()), &sz) == ERROR_SUCCESS) {
            const std::string val = yuzu::win::reg_sz_to_utf8(buf.data(), sz);
            g.state = win::decode_consent_value(val, type == REG_SZ);
            g.raw_value = val.empty() ? "-" : val;
        }
    } else {
        g.state = PermissionState::absent; // no Value under this app's own key
    }

    const auto read_filetime = [&](const wchar_t* name) -> std::string {
        std::uint64_t ft = 0;
        DWORD t = 0, sz = sizeof(ft);
        if (RegQueryValueExW(app_key, name, nullptr, &t, reinterpret_cast<BYTE*>(&ft), &sz) ==
              ERROR_SUCCESS &&
            t == REG_QWORD)
            return win::filetime_to_epoch_ms_string(ft);
        return "-";
    };
    g.last_used_start = read_filetime(L"LastUsedTimeStart");
    g.last_used_stop = read_filetime(L"LastUsedTimeStop");
    return g;
}

/// Walks every mapped CapabilityName under `root`, and under each one the capability-level
/// Value plus every NonPackaged/packaged app child. `root_open_err` (0 = opened fine) lets the
/// caller distinguish ConsentStore-itself-missing from a per-capability miss.
std::vector<RawGrant> walk_consent_store(HKEY hive, LONG* root_open_err) {
    std::vector<RawGrant> out;
    yuzu::win::RegKey store;
    const LONG rc = RegOpenKeyExW(hive, kConsentStorePath, 0, KEY_READ, store.put());
    if (root_open_err) *root_open_err = rc;
    if (rc != ERROR_SUCCESS) return out;

    for (const auto& cap : win::kCapabilities) {
        yuzu::win::RegKey cap_key;
        if (RegOpenKeyExW(store.get(), yuzu::win::to_wide(cap.capability_name).c_str(), 0,
                          KEY_READ, cap_key.put()) != ERROR_SUCCESS)
            continue; // this capability's key is absent on this host -- fine, not every host has every one

        // The capability-level grant itself (no specific app -- "the global default").
        out.push_back(read_one_grant(cap_key.get(), "-", cap.category));

        // Packaged apps: direct children of the capability key OTHER than "NonPackaged".
        for (const auto& child : enumerate_subkey_names(cap_key.get())) {
            if (child == L"NonPackaged") continue;
            yuzu::win::RegKey app_key;
            if (RegOpenKeyExW(cap_key.get(), child.c_str(), 0, KEY_READ, app_key.put()) ==
                ERROR_SUCCESS)
                out.push_back(read_one_grant(app_key.get(), yuzu::win::from_wide(child.c_str()),
                                             cap.category));
        }

        // Win32 (non-packaged) apps, keyed by an escaped executable path.
        yuzu::win::RegKey nonpkg;
        if (RegOpenKeyExW(cap_key.get(), L"NonPackaged", 0, KEY_READ, nonpkg.put()) ==
            ERROR_SUCCESS) {
            for (const auto& child : enumerate_subkey_names(nonpkg.get())) {
                yuzu::win::RegKey app_key;
                if (RegOpenKeyExW(nonpkg.get(), child.c_str(), 0, KEY_READ, app_key.put()) ==
                    ERROR_SUCCESS)
                    out.push_back(read_one_grant(
                        app_key.get(),
                        win::unescape_nonpackaged_app_id(yuzu::win::from_wide(child.c_str())),
                        cap.category));
            }
        }
    }
    return out;
}

} // namespace

int collect_windows_permissions(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;

    LONG hkcu_rc = 0, hklm_rc = 0;
    const auto hkcu = walk_consent_store(HKEY_CURRENT_USER, &hkcu_rc);
    const auto hklm = walk_consent_store(HKEY_LOCAL_MACHINE, &hklm_rc);

    bool denied = false;
    if (hkcu_rc == ERROR_ACCESS_DENIED || hklm_rc == ERROR_ACCESS_DENIED) denied = true;

    // Merge: HKLM wins for the same (app_id, category); everything HKCU-only stays.
    std::map<std::pair<std::string, std::string>, RawGrant> merged;
    for (const auto& g : hkcu) merged[{g.app_id, g.category}] = g;
    for (const auto& g : hklm) merged[{g.app_id, g.category}] = g; // overwrite: HKLM precedence

    std::vector<PermissionRow> rows;
    rows.reserve(merged.size());
    for (const auto& [key, g] : merged) {
        if (g.state == PermissionState::unreadable)
            acc.add_failure(g.app_id + ":" + g.category + ":value_unreadable");
        rows.push_back({"windows", g.app_id, g.category, g.state, g.raw_value, g.last_used_start,
                        g.last_used_stop, false});
    }

    if (rows.empty() && hkcu_rc != ERROR_SUCCESS && hkcu_rc != ERROR_FILE_NOT_FOUND) {
        // ConsentStore itself couldn't be opened for a reason other than "not there".
        const bool this_denied = (hkcu_rc == ERROR_ACCESS_DENIED);
        rows.push_back(whole_read_failed_row(
            "windows", this_denied ? PermissionState::denied : PermissionState::unreadable,
            this_denied ? "consent_store:access_denied"
                        : "consent_store:win32_" + std::to_string(hkcu_rc),
            acc, this_denied));
        denied = denied || this_denied;
    } else if (rows.empty()) {
        // Definitively not there (ERROR_FILE_NOT_FOUND) -- a legitimate, if unusual, host state.
        rows.push_back({"windows", "-", "-", PermissionState::absent, "-", "-", "-", false});
    }

    return emit_rows(ctx, rows, acc, false);
}

} // namespace yuzu::privacy_permissions

#endif // defined(_WIN32)
