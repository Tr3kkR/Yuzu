#pragma once

/**
 * user_profile_model.hpp — pure model for Windows user-profile / registry-hive
 * discovery (PR1.7).
 *
 * windows.h-free by design (mirrors tar_module_etw.hpp's EtwImageSample
 * split): the Win32 shell (agents/shared/win_profiles.hpp) gathers raw
 * ProfileList rows and HKEY_USERS subkey names into the plain structs below;
 * every classification and formatting decision here is a pure function over
 * that plain data, so the whole decision layer is unit-tested on every host
 * (test_user_profile_model.cpp) without linking advapi32.
 *
 * ADR-0024 D11 invariant (binds this header, not just license_scan's per-user
 * records): when a profile's display name cannot be resolved,
 * ProfileInfo::profile_name stays EMPTY — it must NEVER fall back to the SID.
 * installed_apps_plugin.cpp's `username = sid` fallback does not follow this
 * rule; this header deliberately does not clone it.
 */

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::profiles {

/// Whether a HKEY_USERS-shaped hive for a SID is reachable right now.
enum class HiveState {
    loaded,              // HKU\<SID> is present (user logged in, or mounted elsewhere)
    loaded_classes_only, // only HKU\<SID>_Classes is present (rare: partial/COM-only load)
    not_loaded,          // neither present — an offline RegLoadKeyW mount is the only path in
};

[[nodiscard]] constexpr std::string_view hive_state_name(HiveState s) {
    switch (s) {
    case HiveState::loaded:
        return "loaded";
    case HiveState::loaded_classes_only:
        return "loaded_classes_only";
    case HiveState::not_loaded:
        return "not_loaded";
    }
    return "not_loaded"; // unreachable — cases are exhaustive so -Wswitch flags enum drift
}

/// One HKLM ProfileList subkey as read by the Win32 shell. profile_image_path
/// is ALREADY environment-expanded by the shell (two-pass
/// ExpandEnvironmentStringsW — see win_profiles.hpp) so this layer never
/// re-expands it; empty means ProfileImagePath was absent or unreadable.
struct RawProfileRecord {
    std::string sid;
    std::string profile_image_path;
};

/// One resolved, classified profile.
struct ProfileInfo {
    std::string sid;
    std::string profile_name; // last path component of profile_image_path;
                              // EMPTY when unresolvable — NEVER the sid (ADR-0024 D11)
    std::string profile_path; // == the raw record's profile_image_path (already expanded)
    HiveState state{HiveState::not_loaded};
};

/// The three well-known local-system profile SIDs ProfileList always carries
/// (LocalSystem / LocalService / NetworkService). Matches the existing
/// convention in tar_mapdrive_collector.cpp's is_system_sid and
/// licensing_win.cpp's enumerate_profiles verbatim — deliberately not a
/// general S-1-5-* classifier, so it stays in lockstep with those call sites.
[[nodiscard]] inline bool is_system_sid(std::string_view sid) {
    return sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20";
}

/// Structural well-formedness check for a domain/local Windows user SID
/// (S-1-5-21-<a>-<b>-<c>-<rid>): the "S-1-5-21-" prefix followed by exactly
/// four non-empty, all-digit, dash-separated components. Purely syntactic —
/// a well-formed SID may still not correspond to a resolvable profile.
[[nodiscard]] inline bool is_user_sid(std::string_view sid) {
    constexpr std::string_view kPrefix = "S-1-5-21-";
    if (!sid.starts_with(kPrefix))
        return false;
    std::string_view rest = sid.substr(kPrefix.size());
    if (rest.empty())
        return false;
    int component_count = 0;
    while (!rest.empty()) {
        auto dash = rest.find('-');
        std::string_view component = (dash == std::string_view::npos) ? rest : rest.substr(0, dash);
        if (component.empty())
            return false;
        for (char c : component) {
            if (c < '0' || c > '9')
                return false;
        }
        ++component_count;
        if (dash == std::string_view::npos)
            break;
        rest = rest.substr(dash + 1);
    }
    return component_count == 4;
}

/// Last '\' or '/' separated component of `profile_image_path`, with any
/// trailing separators stripped first (so "C:\Users\alice\" yields "alice",
/// matching basename-style semantics). Returns "" only when the path is
/// empty or consists entirely of separators — the caller must never
/// substitute the sid for that empty result (ADR-0024 D11).
[[nodiscard]] inline std::string profile_name_from_path(std::string_view profile_image_path) {
    std::string_view p = profile_image_path;
    while (!p.empty() && (p.back() == '\\' || p.back() == '/'))
        p.remove_suffix(1);
    if (p.empty())
        return {};
    auto last_sep = p.find_last_of("\\/");
    std::string_view name = (last_sep == std::string_view::npos) ? p : p.substr(last_sep + 1);
    return std::string{name};
}

/// Classifies a SID's hive reachability from the live HKEY_USERS subkey list
/// (as returned by win_profiles.hpp's enumerate_hku_subkeys). `hku_subkeys`
/// holds exactly the subkey names under HKEY_USERS, e.g. {"S-1-5-21-...-1001",
/// "S-1-5-21-...-1001_Classes", ...}. The real hive outranks a Classes-only
/// sighting of the same SID.
[[nodiscard]] inline HiveState classify_hive_state(std::string_view sid,
                                                    std::span<const std::string> hku_subkeys) {
    bool loaded = false;
    bool classes_only = false;
    const std::string classes_suffix = std::string{sid} + "_Classes";
    for (const auto& subkey : hku_subkeys) {
        if (subkey == sid) {
            loaded = true;
            break;
        }
        if (subkey == classes_suffix)
            classes_only = true;
    }
    if (loaded)
        return HiveState::loaded;
    if (classes_only)
        return HiveState::loaded_classes_only;
    return HiveState::not_loaded;
}

/// Builds the classified profile list from raw ProfileList rows + the live
/// HKEY_USERS subkey snapshot. System SIDs (is_system_sid) are filtered
/// BEFORE any other work — filtering after reading profile data (as
/// installed_apps_plugin.cpp's do_list_per_user does) wastes the read.
/// Duplicate SIDs in `records` keep only the first occurrence.
[[nodiscard]] inline std::vector<ProfileInfo> build_profile_list(
    std::span<const RawProfileRecord> records, std::span<const std::string> hku_subkeys) {
    std::vector<ProfileInfo> out;
    out.reserve(records.size());
    for (const auto& rec : records) {
        if (is_system_sid(rec.sid))
            continue;
        bool already_seen = false;
        for (const auto& seen : out) {
            if (seen.sid == rec.sid) {
                already_seen = true;
                break;
            }
        }
        if (already_seen)
            continue;

        ProfileInfo info;
        info.sid = rec.sid;
        info.profile_path = rec.profile_image_path;
        info.profile_name = profile_name_from_path(rec.profile_image_path);
        info.state = classify_hive_state(rec.sid, hku_subkeys);
        out.push_back(std::move(info));
    }
    return out;
}

/// Finds the SID whose resolved profile_name equals `username` (exact,
/// case-sensitive match) — the pure half of registry.get_user_value's
/// username-to-SID resolution. Returns the FIRST match in `profiles` order
/// when more than one profile resolves to the same name (redirected/renamed
/// profiles can collide); ambiguity is resolved by discovery order, not
/// reported. Never matches an entry whose profile_name is empty — an
/// unresolved name coincidentally equal to a lookup would hide a real
/// ambiguity rather than answer it.
[[nodiscard]] inline std::optional<std::string> find_sid_by_username(
    std::span<const ProfileInfo> profiles, std::string_view username) {
    if (username.empty())
        return std::nullopt;
    for (const auto& p : profiles) {
        if (!p.profile_name.empty() && p.profile_name == username)
            return p.sid;
    }
    return std::nullopt;
}

/// Strips '|', '\r', '\n' from a field before it is written into the
/// pipe-delimited plugin-output protocol, so a value containing one of those
/// cannot forge a column or row boundary. Same behaviour as
/// registry_plugin.cpp's local sanitize_field, which today applies only to
/// the unknown-action error string; every field this header renders goes
/// through this copy instead.
[[nodiscard]] inline std::string sanitize_field(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s)
        out += (c == '|' || c == '\n' || c == '\r') ? '_' : c;
    return out;
}

/// Renders one profile as `profile|<sid>|<name>|<path>|<state>`, with every
/// field sanitised and empty fields rendered as "-".
[[nodiscard]] inline std::string render_profile_row(const ProfileInfo& info) {
    auto field = [](std::string_view v) -> std::string {
        return v.empty() ? std::string{"-"} : sanitize_field(v);
    };
    std::string out = "profile|";
    out += field(info.sid);
    out += '|';
    out += field(info.profile_name);
    out += '|';
    out += field(info.profile_path);
    out += '|';
    out += hive_state_name(info.state);
    return out;
}

} // namespace yuzu::profiles
