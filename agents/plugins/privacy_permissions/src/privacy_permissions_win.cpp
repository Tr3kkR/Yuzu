/**
 * privacy_permissions_win.cpp -- Windows leg: per-user HKCU (via the shared live-hive-first/
 * offline-NTUSER.DAT-fallback ladder, NOT the process's own HKEY_CURRENT_USER) plus machine-
 * wide HKLM, walking ...\CapabilityAccessManager\ConsentStore (rung 1, registry only, no spawn).
 *
 * CDX-R2-001: the Windows agent service registers and runs as LocalSystem, not a per-user
 * identity (docs/agent-privilege-model.md TL;DR, #1442) -- HKEY_CURRENT_USER therefore
 * resolves to LocalSystem's own (irrelevant, near-always-empty) profile, never an interactive
 * user's real ConsentStore. Every other per-user Windows collector in this repo already
 * accounts for this: license_scan's run_per_user_surfaces and registry's do_get_user_value
 * both enumerate real profiles (agents/shared/win_profiles.hpp's enumerate_profile_records +
 * build_profile_list, which filters the LocalSystem/LocalService/NetworkService system SIDs)
 * and read each one's registry via with_user_hive (loaded HKU\<SID> first, an offline
 * NTUSER.DAT mount as the fallback) -- this file now does the same, once per real profile.
 *
 * UNKNOWNS pending a real the-rig capture (see the plan): the exact NonPackaged
 * path-escaping scheme (unescape_nonpackaged_app_id is a best-effort `#`->`\` pass), whether
 * the HKLM policy mirror exists un-configured on a non-MDM host (expected: absent), and the
 * real `Value` literal vocabulary (decode_consent_value never assumes only Allow/Deny exist).
 *
 * HKLM takes precedence over a user's own HKCU-equivalent entry for the same (CapabilityName,
 * app_id) pair when both are present -- an MDM/GPO-locked policy overriding the user's own
 * choice -- applied per profile now that there can be more than one HKCU-equivalent source.
 * `app_id` is qualified with the owning profile's name (never its SID -- ADR-0024 D11) so the
 * same app across two different users' profiles never collides in the merge or the output.
 */
#include "privacy_permissions_legs.hpp"
#include "privacy_permissions_win_parsers.hpp"

#if defined(_WIN32)

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include <win_profiles.hpp>
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

// COD-P1-03: a ConsentStore subtree is under the OWNING USER's write access (packaged/
// NonPackaged app keys), so an unbounded enumeration lets that same user pin the instruction
// worker -- and, on the offline-hive arm, hold the process-wide offline_hive_mutex() -- for as
// long as they can keep stuffing subkeys. Same shape and same order-of-magnitude as
// win_profiles.hpp's own kMaxEnumeratedValueNames (4096), the precedent this cap copies.
inline constexpr DWORD kMaxEnumeratedSubkeys = 4096;

/// `terminal_rc`, if non-null, receives the RegEnumKeyExW code that ended the walk --
/// ERROR_NO_MORE_ITEMS is the only clean stop (CDX-R2-002: a previous version discarded this
/// entirely, so a mid-enumeration ERROR_ACCESS_DENIED was silently indistinguishable from
/// having enumerated every child). `truncated`, if non-null, is set when the walk stopped
/// because it hit kMaxEnumeratedSubkeys AND a genuine next entry exists -- "cap reached" alone
/// is NOT the same fact as "a record was dropped" (C4-CODEX-005/K2: a key with EXACTLY
/// kMaxEnumeratedSubkeys real children would otherwise report a false truncation, since the
/// cap-reached check alone can't tell "there were exactly this many" from "there were more").
/// One extra, uncounted RegEnumKeyExW probe at the current index disambiguates -- same shape as
/// win_profiles.hpp's own enumerate_profile_records/profile_list_actually_truncated precedent.
std::vector<std::wstring> enumerate_subkey_names(HKEY parent, LONG* terminal_rc = nullptr,
                                                 bool* truncated = nullptr) {
    std::vector<std::wstring> out;
    constexpr DWORD kNameBufLen = 512;
    wchar_t buf[kNameBufLen]{};
    DWORD idx = 0, len = kNameBufLen;
    LONG rc = ERROR_SUCCESS;
    while (idx < kMaxEnumeratedSubkeys &&
          (rc = RegEnumKeyExW(parent, idx++, buf, &len, nullptr, nullptr, nullptr, nullptr)) ==
              ERROR_SUCCESS) {
        out.emplace_back(buf, len);
        len = kNameBufLen;
    }
    if (truncated) {
        if (idx >= kMaxEnumeratedSubkeys) {
            wchar_t probe_buf[kNameBufLen]{};
            DWORD probe_len = kNameBufLen;
            *truncated = (RegEnumKeyExW(parent, idx, probe_buf, &probe_len, nullptr, nullptr,
                                        nullptr, nullptr) == ERROR_SUCCESS);
        } else {
            *truncated = false;
        }
    }
    if (terminal_rc) *terminal_rc = rc;
    return out;
}

/// Reads one app-level grant's `Value` (+ LastUsedTime* if present) from `app_key`.
RawGrant read_one_grant(HKEY app_key, std::string app_id, std::string_view category) {
    RawGrant g{std::move(app_id), std::string{category}, PermissionState::unreadable, "-", "-", "-"};

    DWORD type = 0, size = 0;
    const LONG probe_rc = RegQueryValueExW(app_key, L"Value", nullptr, &type, nullptr, &size);
    if (probe_rc == ERROR_SUCCESS && size > 0 && size > yuzu::win::kMaxRegValueBytes) {
        // C4-CODEX-002: this subtree is under the OWNING USER's write access (the file
        // banner's own words), so an unbounded allocation sized from a provider-reported
        // DWORD lets that user make the privileged agent retain an arbitrarily large buffer
        // per value -- the same class of problem win_profiles.hpp's own kMaxRegValueBytes
        // (1 MiB) exists to cap. Reported honestly (unreadable, via the caller's existing
        // value_unreadable token -- see merge_and_emit), never silently truncated/guessed.
        g.state = PermissionState::unreadable;
    } else if (probe_rc == ERROR_SUCCESS && size > 0) {
        std::vector<wchar_t> buf(size / sizeof(wchar_t) + 1, L'\0');
        DWORD sz = size;
        const LONG real_rc = RegQueryValueExW(app_key, L"Value", nullptr, &type,
                                              reinterpret_cast<BYTE*>(buf.data()), &sz);
        if (real_rc == ERROR_SUCCESS) {
            const std::string val = yuzu::win::reg_sz_to_utf8(buf.data(), sz);
            g.state = win::decode_consent_value(val, type == REG_SZ);
            g.raw_value = val.empty() ? "-" : val;
        } else if (real_rc == ERROR_ACCESS_DENIED) {
            // CDX-R2-002: the second (real) read can itself be denied even though the
            // size-probe just above succeeded (an ACL change between the two calls) --
            // previously silently kept as `unreadable`, indistinguishable from an ordinary
            // read failure.
            g.state = PermissionState::denied;
            g.read_denied = true;
        }
        // else: any other Win32 error on the second read -- keep the default `unreadable`
        // rather than guess; an unusual TOCTOU-shaped registry race.
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
        LONG packaged_enum_rc = ERROR_SUCCESS;
        bool packaged_truncated = false;
        for (const auto& child :
            enumerate_subkey_names(cap_key.get(), &packaged_enum_rc, &packaged_truncated)) {
            if (child == L"NonPackaged") continue;
            yuzu::win::RegKey app_key;
            if (try_open_subkey(cap_key.get(), child.c_str(), app_key,
                                std::string{cap.category} + ":packaged_app", acc))
                out.push_back(read_one_grant(app_key.get(), yuzu::win::from_wide(child.c_str()),
                                             cap.category));
        }
        if (packaged_truncated)
            acc.add_failure(std::string{cap.category} + ":packaged_enum_truncated");
        else if (packaged_enum_rc != ERROR_NO_MORE_ITEMS)
            acc.add_failure(std::string{cap.category} + ":packaged_enum_" +
                            std::to_string(packaged_enum_rc));

        // Win32 (non-packaged) apps, keyed by an escaped executable path.
        yuzu::win::RegKey nonpkg;
        if (try_open_subkey(cap_key.get(), L"NonPackaged", nonpkg,
                            std::string{cap.category} + ":nonpackaged_container", acc)) {
            LONG nonpkg_enum_rc = ERROR_SUCCESS;
            bool nonpkg_truncated = false;
            for (const auto& child :
                enumerate_subkey_names(nonpkg.get(), &nonpkg_enum_rc, &nonpkg_truncated)) {
                yuzu::win::RegKey app_key;
                if (try_open_subkey(nonpkg.get(), child.c_str(), app_key,
                                    std::string{cap.category} + ":nonpackaged_app", acc))
                    out.push_back(read_one_grant(
                        app_key.get(),
                        win::unescape_nonpackaged_app_id(yuzu::win::from_wide(child.c_str())),
                        cap.category));
            }
            if (nonpkg_truncated)
                acc.add_failure(std::string{cap.category} + ":nonpackaged_enum_truncated");
            else if (nonpkg_enum_rc != ERROR_NO_MORE_ITEMS)
                acc.add_failure(std::string{cap.category} + ":nonpackaged_enum_" +
                                std::to_string(nonpkg_enum_rc));
        }
    }
    return out;
}

/// Merges `hklm_by_key` into `base` (HKLM wins for a matching (app_id,category)), emits
/// PermissionRows into `rows`, and records value-level failure tokens into `acc`. `qualify`
/// prefixes an app_id (empty string = no prefix, used for HKLM-only/no-profile-context output).
void merge_and_emit(const std::vector<RawGrant>& base,
                    const std::map<std::pair<std::string, std::string>, RawGrant>& hklm_by_key,
                    const std::string& qualify, std::vector<PermissionRow>& rows,
                    yuzu::shared::ConstraintAccumulator& acc) {
    std::map<std::pair<std::string, std::string>, RawGrant> merged;
    for (const auto& g : base) merged[{g.app_id, g.category}] = g;
    for (const auto& [key, g] : hklm_by_key) merged[key] = g; // overwrite: HKLM precedence
    for (const auto& [key, g] : merged) {
        // C4-CODEX-003/K1: a capability-level "-" row is the owning profile's OWN global
        // default for that category, NOT a machine-wide fact -- exempting it from
        // qualification (as the original round-2 rewrite did) let two different profiles'
        // opposing defaults for the same category collide into indistinguishable rows. Only
        // truly qualify-less output (empty `qualify`, the no-reachable-profile HKLM fallback,
        // where there IS no profile to attribute a default to) keeps the bare "-".
        const std::string app_id =
            qualify.empty() ? g.app_id : (qualify + "\\" + g.app_id);
        if (g.state == PermissionState::unreadable)
            acc.add_failure(app_id + ":" + g.category + ":value_unreadable");
        else if (g.read_denied)
            acc.add_failure(app_id + ":" + g.category + ":value_access_denied");
        // g.read_denied (NOT g.state == denied) is the row's read_denied -- a successfully
        // read `Deny` grant is complete, correct data, not a read failure (CDX-P1-002).
        rows.push_back({"windows", app_id, g.category, g.state, g.raw_value, g.last_used_start,
                        g.last_used_stop, g.read_denied});
    }
}

} // namespace

int collect_windows_permissions(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PermissionRow> rows;

    // HKLM: machine-wide, no per-user dimension -- collected once, then applied as an
    // override into EVERY profile's own merge below (and, if no profile is reachable at all,
    // emitted directly so an MDM/GPO policy is never silently dropped just because nobody is
    // logged in).
    LONG hklm_rc = 0;
    const auto hklm = walk_consent_store(HKEY_LOCAL_MACHINE, &hklm_rc, acc);
    std::map<std::pair<std::string, std::string>, RawGrant> hklm_by_key;
    for (const auto& g : hklm) hklm_by_key[{g.app_id, g.category}] = g;

    // Real interactive users, not the agent process's own (LocalSystem) HKEY_CURRENT_USER --
    // see the file banner (CDX-R2-001). Same enumerate-then-with_user_hive shape as
    // license_scan's run_per_user_surfaces / registry's do_get_user_value.
    bool profiles_ok = false;
    bool truncated = false;
    const auto raw_profiles = yuzu::win::enumerate_profile_records(profiles_ok, &truncated);
    if (truncated) acc.add_failure("profiles:truncated");
    const auto hku_subkeys = yuzu::win::enumerate_hku_subkeys();
    const auto profiles =
        profiles_ok ? yuzu::profiles::build_profile_list(raw_profiles, hku_subkeys)
                    : std::vector<yuzu::profiles::ProfileInfo>{};
    if (!profiles_ok) acc.add_failure("profiles:profile_list_unreadable");

    // Counts profiles whose hive was ACTUALLY reached (status == ok), not merely enumerated --
    // COD-P1-02/K1 (both external reviewers independently): the previous version fell back to
    // direct, unqualified HKLM emission only when `profiles` (the ENUMERATED list) was empty,
    // so a host with real profiles that were ALL unreachable (privilege_missing/not_found/
    // mount_failed) silently dropped HKLM policy data entirely instead of falling back.
    std::size_t reachable_profiles = 0;
    for (const auto& profile : profiles) {
        // C4-CODEX-001: with_user_hive's live-hive check tests only `== ERROR_SUCCESS` --
        // ERROR_ACCESS_DENIED on the LIVE HKU\<SID> root and ERROR_FILE_NOT_FOUND (no such
        // live entry, the ordinary case) are indistinguishable to its caller, and if the
        // offline fallback then ALSO fails (privilege_missing/mount_failed), the original
        // live-root denial is lost entirely -- reported as a generic CONSTRAINED token
        // instead of the contract-required PERMISSION_DENIED a refused root read gets
        // everywhere else in this file. This is a genuine gap in the SHARED with_user_hive
        // primitive (also affects license_scan/registry, out of scope to fix here without a
        // wider, separately-reviewed change), so it is worked around plugin-locally: a cheap
        // peek at the live root BEFORE calling with_user_hive, used only to enrich a
        // subsequent non-ok status with the real reason when it was specifically denied.
        // Benign TOCTOU: ACLs changing between the peek and with_user_hive's own attempt in
        // the few-microsecond window is exactly as safe/unsafe as every other check-then-act
        // registry read in this file, and the peek never gates or replaces the real call.
        LONG peek_rc = ERROR_SUCCESS;
        {
            yuzu::win::RegKey peek;
            peek_rc = RegOpenKeyExW(HKEY_USERS, yuzu::win::to_wide(profile.sid).c_str(), 0,
                                    KEY_READ, peek.put());
        }

        std::vector<RawGrant> user_grants;
        LONG user_rc = ERROR_SUCCESS;
        yuzu::win::HiveAccessReport report;
        const auto status = yuzu::win::with_user_hive(
            profile.sid, profile.profile_path,
            [&](HKEY root) { user_grants = walk_consent_store(root, &user_rc, acc); }, &report);
        if (report.unload_failed) acc.add_failure(profile.profile_name + ":hive_unload_failed");

        // Exhaustive switch over the FOUR HiveAccessStatus outcomes (COD-P1-02/K1): the previous
        // version handled only two, so `mount_failed` fell through and merge_and_emit ran with
        // an EMPTY user_grants (fn was never called) as if the profile had been read cleanly --
        // fabricating an OK/FULL "this profile has no grants" for a hive that was never actually
        // opened (a locked/corrupt NTUSER.DAT, or an orphaned ProfileList record -- routine on a
        // real fleet, not a rare edge case).
        switch (status) {
        case yuzu::win::HiveAccessStatus::ok:
            ++reachable_profiles;
            break;
        case yuzu::win::HiveAccessStatus::privilege_missing:
            if (peek_rc == ERROR_ACCESS_DENIED) {
                rows.push_back(whole_read_failed_row("windows", PermissionState::denied,
                                                      profile.profile_name + ":access_denied",
                                                      acc, true));
            } else {
                acc.add_failure(profile.profile_name + ":privilege_missing");
            }
            continue;
        case yuzu::win::HiveAccessStatus::not_found:
            // Enumerated but genuinely unreachable (no live HKU entry, no offline NTUSER.DAT
            // path). `profile_path_unreadable` (carried from the raw ProfileList record) means
            // even the PATH itself couldn't be resolved -- name that distinctly rather than
            // conflating it with "no path was ever recorded".
            acc.add_failure(profile.profile_name +
                            (profile.profile_path_unreadable ? ":profile_path_unreadable"
                                                             : ":hive_not_found"));
            continue;
        case yuzu::win::HiveAccessStatus::mount_failed:
            if (peek_rc == ERROR_ACCESS_DENIED) {
                rows.push_back(whole_read_failed_row("windows", PermissionState::denied,
                                                      profile.profile_name + ":access_denied",
                                                      acc, true));
            } else {
                acc.add_failure(profile.profile_name + ":hive_mount_failed");
            }
            continue;
        }

        merge_and_emit(user_grants, hklm_by_key, profile.profile_name, rows, acc);

        if (user_rc != ERROR_SUCCESS && user_rc != ERROR_FILE_NOT_FOUND) {
            const bool this_denied = (user_rc == ERROR_ACCESS_DENIED);
            rows.push_back(whole_read_failed_row(
                "windows", this_denied ? PermissionState::denied : PermissionState::unreadable,
                profile.profile_name +
                    (this_denied ? ":access_denied" : (":win32_" + std::to_string(user_rc))),
                acc, this_denied));
        }
    }

    if (reachable_profiles == 0) {
        // No interactive user's hive was actually reached -- no profiles enumerated at all (a
        // server/unattended host), the profile list itself couldn't be read, or every
        // enumerated profile hit privilege_missing/not_found/mount_failed above -- still
        // surface any HKLM machine policy directly, rather than silently dropping it because
        // no per-user row existed to merge it into.
        merge_and_emit({}, hklm_by_key, "", rows, acc);
    }

    // HKLM root-level denial, reported once regardless of the per-profile loop -- an
    // MDM/GPO-authoritative refusal is the more consequential one to lose silently (CDX-P1-003).
    if (hklm_rc != ERROR_SUCCESS && hklm_rc != ERROR_FILE_NOT_FOUND) {
        const bool this_denied = (hklm_rc == ERROR_ACCESS_DENIED);
        rows.push_back(whole_read_failed_row(
            "windows", this_denied ? PermissionState::denied : PermissionState::unreadable,
            std::string{"hklm"} +
                (this_denied ? ":access_denied" : (":win32_" + std::to_string(hklm_rc))),
            acc, this_denied));
    }

    if (rows.empty()) {
        // No profiles, no HKLM data, HKLM itself genuinely not there -- a legitimate, if
        // unusual, host state.
        rows.push_back({"windows", "-", "-", PermissionState::absent, "-", "-", "-", false});
    }

    return emit_rows(ctx, rows, acc, false);
}

} // namespace yuzu::privacy_permissions

#endif // defined(_WIN32)
