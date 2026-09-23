/**
 * privacy_permissions_win_parsers.hpp -- Windows-only PURE layer: the CapabilityName ->
 * category table, the ConsentStore `Value` string -> PermissionState decode, the NonPackaged
 * app-identity unescape, the LastUsedTime* QWORD decode, and the profile-vs-HKLM precedence
 * merge. Separate from privacy_permissions_parsers.hpp (the cross-OS pure layer), same split as
 * platform_security_win_parsers.hpp. windows.h-free: the Win32 codes it branches on are
 * mirrored below and static_asserted against the real macros in privacy_permissions_win.cpp.
 *
 * UNKNOWN, pending a real-hardware probe (see the plan's "genuine unknowns" list): the real
 * literal `Value` vocabulary. `Allow`/`Deny` are what the charter names; this file does NOT
 * assume that is the complete set -- any other value decodes as `prompt_undetermined` when it
 * looks plausible (non-empty, no embedded NUL) and `unreadable` only when the type itself is
 * wrong (not REG_SZ) or genuinely empty, so a real third state discovered by the probe fails
 * SAFE (a named, visible state) rather than silently misclassifying as allowed or denied.
 */
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include "privacy_permissions_parsers.hpp"

namespace yuzu::privacy_permissions::win {

// <profile hive>/HKLM ...\CapabilityAccessManager\ConsentStore\<CapabilityName>. Only the
// capabilities this plugin's charter names are opened; every other CapabilityName Windows
// exposes (contacts, phoneCall, userAccountInformation, ...) is never opened at all -- a scope
// filter, not a decode failure.
struct CapabilityEntry {
    std::string_view capability_name; // the literal registry subkey name
    std::string_view category;        // one of kCategories
};

inline constexpr std::array<CapabilityEntry, 4> kCapabilities{{
    {"webcam", "camera"},
    {"microphone", "microphone"},
    {"location", "location"},
    {"broadFileSystemAccess", "full_disk_access"},
}};

[[nodiscard]] constexpr std::string_view capability_to_category(std::string_view capability_name) noexcept {
    for (const auto& c : kCapabilities)
        if (c.capability_name == capability_name) return c.category;
    return {};
}

/// The ConsentStore `Value` REG_SZ decoded to a PermissionState. `type_ok` = the registry
/// value was actually REG_SZ (a wrong type is unreadable regardless of its bytes).
[[nodiscard]] inline PermissionState decode_consent_value(std::string_view value, bool type_ok) noexcept {
    if (!type_ok || value.empty()) return PermissionState::unreadable;
    if (value == "Allow") return PermissionState::allowed;
    if (value == "Deny") return PermissionState::denied;
    // A real third literal the probe finds (Prompt, AllowedTemporary, ...) is visible and
    // distinct, never silently folded into allowed/denied.
    return PermissionState::prompt_undetermined;
}

/// `NonPackaged` subkey names are the app's executable path with a small set of characters
/// percent/hash-escaped (Windows uses `#` in place of `\` and other reserved registry-path
/// characters in this specific tree). This is a best-effort unescape pending the real-capture
/// probe (unknown #4/#5 in the plan): the publicly documented ConsentStore NonPackaged scheme
/// escapes BOTH `\`->`#` AND `:`->`#3A` (e.g. `C#3AUsers#Admin#app.exe`), so `#3A` is checked
/// FIRST (KIMI-P1-05) -- a single-pass `#`->`\` alone would corrupt the drive separator into
/// `C\3AUsers\...` instead of `C:\Users\...`. An unrecognized `#`-escape (this scheme's only
/// other use) still falls through to `\`, degrading safely rather than corrupting or throwing.
[[nodiscard]] inline std::string unescape_nonpackaged_app_id(std::string_view escaped) {
    std::string out;
    out.reserve(escaped.size());
    for (std::size_t i = 0; i < escaped.size(); ++i) {
        if (escaped[i] == '#' && i + 2 < escaped.size() && escaped[i + 1] == '3' &&
            escaped[i + 2] == 'A') {
            out += ':';
            i += 2;
        } else {
            out += (escaped[i] == '#') ? '\\' : escaped[i];
        }
    }
    return out;
}

/// FILETIME (100ns ticks since 1601-01-01) -> Unix epoch milliseconds. Same conversion shape
/// as execution_artifacts_parsers.hpp's filetime helper (duplicated per this repo's
/// header-only-pure-function convention rather than cross-plugin-shared). 0 -> "-" (never set).
[[nodiscard]] inline std::string filetime_to_epoch_ms_string(std::uint64_t filetime_100ns) {
    if (filetime_100ns == 0) return "-";
    constexpr std::uint64_t kEpochDiff100ns = 116444736000000000ULL; // 1601 -> 1970, in 100ns ticks
    if (filetime_100ns < kEpochDiff100ns) return "-"; // before the Unix epoch: not a real timestamp
    return std::to_string((filetime_100ns - kEpochDiff100ns) / 10000ULL);
}

// ── Win32 codes (mirrored; privacy_permissions_win.cpp static_asserts each) ──

inline constexpr long kErrorSuccess = 0;
inline constexpr long kErrorFileNotFound = 2;
inline constexpr long kErrorAccessDenied = 5;
inline constexpr std::uint32_t kRegSz = 1;
inline constexpr std::uint32_t kRegQword = 11;

/// `access_denied` or `win32_<rc>` -- the cause suffix every failed registry call reports.
[[nodiscard]] inline std::string win32_cause(long rc) {
    return rc == kErrorAccessDenied ? std::string{"access_denied"} : "win32_" + std::to_string(rc);
}

/// One LastUsedTimeStart/LastUsedTimeStop field. `value` is epoch-ms, "-" (the value is not
/// there -- never set), or `unreadable`; `cause` is non-empty exactly when it is `unreadable`
/// (`win32_<rc>`/`access_denied`, `type_<n>` or `size_<n>`); `denied` marks a refused read.
struct LastUsedField {
    std::string value;
    std::string cause;
    bool denied = false;
};

/// Decodes one RegQueryValueExW(LastUsedTime*) into an 8-byte buffer. Only ERROR_FILE_NOT_FOUND
/// is "not there"; success counts only with BOTH type REG_QWORD AND a returned size of exactly
/// 8 bytes (a short REG_QWORD would leave stale buffer bytes read as a timestamp); every other
/// outcome is a visible `unreadable`, never a silent "-".
[[nodiscard]] inline LastUsedField decode_last_used(long rc, std::uint32_t type, std::uint32_t size,
                                                    std::uint64_t filetime_100ns) {
    if (rc == kErrorFileNotFound) return {"-", {}, false};
    if (rc != kErrorSuccess) return {"unreadable", win32_cause(rc), rc == kErrorAccessDenied};
    if (type != kRegQword) return {"unreadable", "type_" + std::to_string(type), false};
    if (size != sizeof(std::uint64_t)) return {"unreadable", "size_" + std::to_string(size), false};
    return {filetime_to_epoch_ms_string(filetime_100ns), {}, false};
}

/// One (app_id, category) grant as read from ONE ConsentStore root (a profile hive or HKLM).
/// `app_id` is UNqualified here ("-" = the capability-level default / coverage entry); the
/// caller qualifies it per profile. `cause` is non-empty exactly when the Value read failed
/// (value_access_denied / value_oversized / value_empty / value_type_<n> / value_win32_<n>).
struct RawGrant {
    std::string app_id;
    std::string_view category; // a kCapabilities literal -- static storage, safe in a row
    PermissionState state;
    std::string raw_value;
    LastUsedField last_used_start{"-", {}, false};
    LastUsedField last_used_stop{"-", {}, false};
    std::string cause;
    // The READ of this grant's `Value` was refused (ERROR_ACCESS_DENIED) -- NOT the same thing
    // as `state == PermissionState::denied` alone, which also (correctly) means "the read
    // succeeded and decoded to a stored `Deny` grant" (CDX-P1-002).
    bool read_denied = false;
};

[[nodiscard]] inline bool grant_failed(const RawGrant& g) noexcept {
    return g.read_denied || g.state == PermissionState::unreadable;
}

/// An HKLM value may override a profile's entry ONLY when it was SUCCESSFULLY read and decoded
/// to a real state -- an absent, unreadable or refused HKLM value says nothing about policy and
/// must never displace what the profile really holds.
[[nodiscard]] inline bool hklm_value_authoritative(const RawGrant& g) noexcept {
    if (grant_failed(g)) return false;
    return g.state == PermissionState::allowed || g.state == PermissionState::denied ||
           g.state == PermissionState::prompt_undetermined;
}

/// The profile's own grants with every AUTHORITATIVE HKLM grant applied: HKLM wins a matching
/// (app_id, category) over a successfully-read profile entry (an MDM/GPO-locked policy over the
/// user's own choice) and fills in a key the profile lacks. A FAILED profile entry is never
/// overwritten -- its failure row is kept and the HKLM value is added beside it, so a read
/// failure is never hidden behind a policy value. Non-authoritative HKLM grants are NOT merged
/// (the caller reports those once, as HKLM's own rows). Output sorted by (app_id, category).
[[nodiscard]] inline std::vector<RawGrant> merge_with_hklm(std::span<const RawGrant> profile,
                                                           std::span<const RawGrant> hklm) {
    std::map<std::pair<std::string, std::string_view>, RawGrant> merged;
    std::vector<RawGrant> extra; // HKLM values applied beside a failed profile entry
    for (const auto& g : profile) merged[{g.app_id, g.category}] = g;
    for (const auto& h : hklm) {
        if (!hklm_value_authoritative(h)) continue;
        const auto it = merged.find({h.app_id, h.category});
        if (it != merged.end() && grant_failed(it->second))
            extra.push_back(h);
        else
            merged[{h.app_id, h.category}] = h;
    }
    std::vector<RawGrant> out;
    out.reserve(merged.size() + extra.size());
    for (auto& [key, g] : merged) out.push_back(std::move(g));
    for (auto& g : extra) out.push_back(std::move(g));
    std::stable_sort(out.begin(), out.end(), [](const RawGrant& a, const RawGrant& b) {
        return std::tie(a.app_id, a.category) < std::tie(b.app_id, b.category);
    });
    return out;
}

} // namespace yuzu::privacy_permissions::win
