/**
 * privacy_permissions_win_parsers.hpp -- Windows-only PURE layer: the CapabilityName ->
 * category table, the ConsentStore `Value` string -> PermissionState decode, and the
 * NonPackaged app-identity unescape. Separate from privacy_permissions_parsers.hpp (the
 * cross-OS pure layer), same split as platform_security_win_parsers.hpp.
 *
 * UNKNOWN, pending a real-hardware probe (see the plan's "genuine unknowns" list): the real
 * literal `Value` vocabulary. `Allow`/`Deny` are what the charter names; this file does NOT
 * assume that is the complete set -- any other value decodes as `prompt_undetermined` when it
 * looks plausible (non-empty, no embedded NUL) and `unreadable` only when the type itself is
 * wrong (not REG_SZ) or genuinely empty, so a real third state discovered by the probe fails
 * SAFE (a named, visible state) rather than silently misclassifying as allowed or denied.
 */
#pragma once

#include "privacy_permissions_parsers.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace yuzu::privacy_permissions::win {

// HKCU/HKLM ...\CapabilityAccessManager\ConsentStore\<CapabilityName>. Only the capabilities
// this plugin's charter names are mapped; every other CapabilityName Windows exposes
// (contacts, phoneCall, userAccountInformation, ...) is enumerated but deliberately skipped --
// a scope filter, not a decode failure.
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
/// probe (unknown #4/#5 in the plan) -- `#` -> `\`, everything else passed through unchanged,
/// which degrades safely: an unrecognized escape leaves a literal `#` in the output rather
/// than corrupting the path or throwing.
[[nodiscard]] inline std::string unescape_nonpackaged_app_id(std::string_view escaped) {
    std::string out;
    out.reserve(escaped.size());
    for (const char c : escaped) out += (c == '#') ? '\\' : c;
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

} // namespace yuzu::privacy_permissions::win
