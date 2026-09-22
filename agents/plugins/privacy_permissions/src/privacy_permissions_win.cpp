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

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include <win_reg_handle.hpp>
#include <win_str.hpp>

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
    // The READ of this grant's `Value` was refused (ERROR_ACCESS_DENIED) -- NOT the same thing
    // as `state == PermissionState::denied`, which also (correctly) means "the read succeeded
    // and decoded to a stored `Deny` grant". Conflating the two turns an ordinary, successfully
    // read `Deny` value into a whole-action PERMISSION_DENIED/PARTIAL, which is wrong: the read
    // worked and the data is complete.
    bool read_denied = false;
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
    const LONG probe_rc = RegQueryValueExW(app_key, L"Value", nullptr, &type, nullptr, &size);
    if (probe_rc == ERROR_SUCCESS && size > 0) {
        std::vector<wchar_t> buf(size / sizeof(wchar_t) + 1, L'\0');
        DWORD sz = size;
        if (RegQueryValueExW(app_key, L"Value", nullptr, &type,
                             reinterpret_cast<BYTE*>(buf.data()), &sz) == ERROR_SUCCESS) {
            const std::string val = yuzu::win::reg_sz_to_utf8(buf.data(), sz);
            g.state = win::decode_consent_value(val, type == REG_SZ);
            g.raw_value = val.empty() ? "-" : val;
        }
        // else: the second (real) read failed after the first (size-probe) succeeded -- keep
        // the default `unreadable` rather than guess; an unusual TOCTOU-shaped registry race.
    } else if (probe_rc == ERROR_FILE_NOT_FOUND) {
        g.state = PermissionState::absent; // no Value under this app's own key -- genuinely not there
    } else if (probe_rc == ERROR_ACCESS_DENIED) {
        g.state = PermissionState::denied; // the read was refused, never collapsed into absent
        g.read_denied = true;              // -- and it really was the READ that failed here
    }
    // else: any other Win32 error (or a zero-size value) stays `unreadable`, its default --
    // a refusal we can't name more precisely, not "not there".

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

/// Opens `child` under `parent`. A denial anywhere below the ConsentStore root used to be
/// silently swallowed (`continue`/skip) same as a genuine "not there" -- this is the ONE
/// helper every open call below the root now goes through, so a real refusal is never lost
/// again (CDX-P1-003): ERROR_FILE_NOT_FOUND is the sole "fine, skip it" outcome; anything else
/// (ERROR_ACCESS_DENIED foremost) is folded into `acc` as a named token (CONSTRAINED/PARTIAL
/// via `acc.any_failure()` -- the rest of the tree still reads, so this stays one severity
/// below a root-level denial, which escalates all the way to PERMISSION_DENIED below), and the
/// open still fails (the caller still skips that one subtree -- best-effort against a keyed-out
/// branch -- but the incompleteness is now VISIBLE, never silent).
bool try_open_subkey(HKEY parent, const wchar_t* child, yuzu::win::RegKey& out,
                     std::string_view token_prefix, yuzu::shared::ConstraintAccumulator& acc) {
    const LONG rc = RegOpenKeyExW(parent, child, 0, KEY_READ, out.put());
    if (rc == ERROR_SUCCESS) return true;
    if (rc == ERROR_FILE_NOT_FOUND) return false; // genuinely absent on this host -- fine
    acc.add_failure(std::string{token_prefix} +
                    (rc == ERROR_ACCESS_DENIED ? ":access_denied" : (":win32_" + std::to_string(rc))));
    return false;
}

/// Walks every mapped CapabilityName under `root`, and under each one the capability-level
/// Value plus every NonPackaged/packaged app child. `root_open_err` (0 = opened fine) lets the
/// caller distinguish ConsentStore-itself-missing from a per-capability miss. Every open/
/// enumerate below the root threads through `acc` (see try_open_subkey) so a refusal anywhere
/// in the tree surfaces, not just at the root.
std::vector<RawGrant> walk_consent_store(HKEY hive, LONG* root_open_err,
                                         yuzu::shared::ConstraintAccumulator& acc) {
    std::vector<RawGrant> out;
    yuzu::win::RegKey store;
    const LONG rc = RegOpenKeyExW(hive, kConsentStorePath, 0, KEY_READ, store.put());
    if (root_open_err) *root_open_err = rc;
    if (rc != ERROR_SUCCESS) return out;

    for (const auto& cap : win::kCapabilities) {
        yuzu::win::RegKey cap_key;
        if (!try_open_subkey(store.get(), yuzu::win::to_wide(cap.capability_name).c_str(),
                             cap_key, std::string{cap.category} + ":capability", acc))
            continue; // absent, or denied (recorded above) -- either way nothing more to read here

        // The capability-level grant itself (no specific app -- "the global default").
        out.push_back(read_one_grant(cap_key.get(), "-", cap.category));

        // Packaged apps: direct children of the capability key OTHER than "NonPackaged".
        for (const auto& child : enumerate_subkey_names(cap_key.get())) {
            if (child == L"NonPackaged") continue;
            yuzu::win::RegKey app_key;
            if (try_open_subkey(cap_key.get(), child.c_str(), app_key,
                                std::string{cap.category} + ":packaged_app", acc))
                out.push_back(read_one_grant(app_key.get(), yuzu::win::from_wide(child.c_str()),
                                             cap.category));
        }

        // Win32 (non-packaged) apps, keyed by an escaped executable path.
        yuzu::win::RegKey nonpkg;
        if (try_open_subkey(cap_key.get(), L"NonPackaged", nonpkg,
                            std::string{cap.category} + ":nonpackaged_container", acc)) {
            for (const auto& child : enumerate_subkey_names(nonpkg.get())) {
                yuzu::win::RegKey app_key;
                if (try_open_subkey(nonpkg.get(), child.c_str(), app_key,
                                    std::string{cap.category} + ":nonpackaged_app", acc))
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

    // Every capability/app-key/enumeration-level ACCESS_DENIED below either root (via
    // try_open_subkey) already lands in `acc` as a named token, so the action correctly
    // reports CONSTRAINED/PARTIAL rather than silently OK even when the root itself opened
    // fine (CDX-P1-003). A ROOT-level denial is escalated further, below.
    LONG hkcu_rc = 0, hklm_rc = 0;
    const auto hkcu = walk_consent_store(HKEY_CURRENT_USER, &hkcu_rc, acc);
    const auto hklm = walk_consent_store(HKEY_LOCAL_MACHINE, &hklm_rc, acc);

    // Merge: HKLM wins for the same (app_id, category); everything HKCU-only stays.
    std::map<std::pair<std::string, std::string>, RawGrant> merged;
    for (const auto& g : hkcu) merged[{g.app_id, g.category}] = g;
    for (const auto& g : hklm) merged[{g.app_id, g.category}] = g; // overwrite: HKLM precedence

    std::vector<PermissionRow> rows;
    rows.reserve(merged.size());
    for (const auto& [key, g] : merged) {
        if (g.state == PermissionState::unreadable)
            acc.add_failure(g.app_id + ":" + g.category + ":value_unreadable");
        else if (g.read_denied)
            acc.add_failure(g.app_id + ":" + g.category + ":value_access_denied");
        // g.read_denied (NOT g.state == denied) is the row's read_denied -- a successfully
        // read `Deny` grant is complete, correct data, not a read failure (CDX-P1-002).
        rows.push_back({"windows", g.app_id, g.category, g.state, g.raw_value, g.last_used_start,
                        g.last_used_stop, g.read_denied});
    }

    // Root-level: BOTH hives checked, not just HKCU (CDX-P1-003) -- an HKLM-only refusal used
    // to be invisible whenever HKCU produced rows (or was itself merely FILE_NOT_FOUND), which
    // is exactly backwards: HKLM is the MDM/GPO-authoritative half of the advertised
    // HKLM-wins merge, so its denial is the more consequential one to lose silently. Each root
    // denial promotes the action all the way to PERMISSION_DENIED (a whole hive's authoritative
    // view was refused), distinct from a capability/app-key-level denial above (CONSTRAINED via
    // `acc`, since the rest of the tree still read).
    for (const auto& [hive_rc, hive_label] :
        std::initializer_list<std::pair<LONG, std::string_view>>{{hkcu_rc, "hkcu"},
                                                                  {hklm_rc, "hklm"}}) {
        if (hive_rc == ERROR_SUCCESS || hive_rc == ERROR_FILE_NOT_FOUND) continue;
        const bool this_denied = (hive_rc == ERROR_ACCESS_DENIED);
        rows.push_back(whole_read_failed_row(
            "windows", this_denied ? PermissionState::denied : PermissionState::unreadable,
            std::string{hive_label} + (this_denied ? ":access_denied"
                                                   : (":win32_" + std::to_string(hive_rc))),
            acc, this_denied));
    }

    if (rows.empty()) {
        // Both hives definitively not there (ERROR_FILE_NOT_FOUND) -- a legitimate, if
        // unusual, host state.
        rows.push_back({"windows", "-", "-", PermissionState::absent, "-", "-", "-", false});
    }

    return emit_rows(ctx, rows, acc, false);
}

} // namespace yuzu::privacy_permissions

#endif // defined(_WIN32)
