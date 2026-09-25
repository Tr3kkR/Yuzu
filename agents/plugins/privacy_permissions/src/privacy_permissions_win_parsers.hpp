/**
 * privacy_permissions_win_parsers.hpp -- Windows-only PURE layer: the CapabilityName ->
 * category table, the ConsentStore `Value` string -> PermissionState decode, the NonPackaged
 * app-identity unescape, the LastUsedTime* QWORD decode, and the profile-vs-HKLM precedence
 * merge. Separate from privacy_permissions_parsers.hpp (the cross-OS pure layer), same split as
 * platform_security_win_parsers.hpp. windows.h-free: the Win32 codes it branches on are
 * mirrored below and static_asserted against the real macros in privacy_permissions_win.cpp.
 *
 * MEASURED on the-rig (Windows 11 Pro 10.0.26200, LocalSystem, read-only reg dumps,
 * 2026-09-23): the `Value` literals seen are `Allow`, `Deny` and `Prompt`; this file does NOT
 * assume that is the complete set -- any other value decodes as `prompt_undetermined` (a named,
 * visible state) and `unreadable` only when the type is wrong (not REG_SZ) or the value empty.
 * The same host showed the ConsentStore's three levels: HKLM `<capability>` `Value` (the device
 * toggle -- `Allow` on all 33 capabilities of this non-MDM host), the per-user `<capability>`
 * `Value`, and the per-user `<capability>\NonPackaged` `Value` (the "let desktop apps access"
 * toggle). A per-app NonPackaged child carries NO `Value` -- only LastUsedTimeStart/Stop -- so it
 * reads `absent` (no per-app decision; the NonPackaged toggle row governs it).
 */
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <optional>
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

/// `<capability>\NonPackaged` is both the container of per-app desktop keys and, through its own
/// `Value`, the "let desktop apps access" toggle. That toggle is reported as its own row under
/// this app_id (qualified `<user>\NonPackaged` per profile, bare on HKLM -- qualify_app_id).
inline constexpr std::string_view kNonPackagedToggleAppId = "NonPackaged";

/// NonPackaged children that are containers, not apps (measured on the-rig:
/// `NonPackaged\Executables\<exe>` holds only a `GlobalPromptShown` DWORD per executable, never
/// a `Value`). Skipped by name; any other child is read as an app key, so an unknown shape stays
/// a visible row rather than vanishing.
[[nodiscard]] constexpr bool is_nonpackaged_container_key(std::string_view name) noexcept {
    return name == "Executables";
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

/// `NonPackaged` subkey names are the app's executable path with `\` written as `#` and the drive
/// colon left literal (measured on the-rig: `C:#Program Files#...`). Nothing else is escaped.
[[nodiscard]] inline std::string unescape_nonpackaged_app_id(std::string_view escaped) {
    std::string out{escaped};
    std::replace(out.begin(), out.end(), '#', '\\');
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
inline constexpr long kErrorNoMoreItems = 259;
inline constexpr std::uint32_t kRegSz = 1;
inline constexpr std::uint32_t kRegQword = 11;

/// `access_denied` or `win32_<rc>` -- the cause suffix every failed registry call reports.
[[nodiscard]] inline std::string win32_cause(long rc) {
    return rc == kErrorAccessDenied ? std::string{"access_denied"} : "win32_" + std::to_string(rc);
}

// ── retention bounds (the ConsentStore is under its owning user's write access) ──

/// Cap on one ConsentStore `Value`, in bytes as the registry reports them (UTF-16 + NUL). The
/// literals measured on the-rig are `Allow`/`Deny`/`Prompt` (at most 14 bytes); 64 bytes (31
/// characters) leaves room for a longer literal Windows may add without letting a profile owner
/// make the agent retain the generic 1 MiB registry cap per value. Over it is `value_oversized`.
inline constexpr std::uint32_t kMaxConsentValueBytes = 64;

/// One run-wide bound on what the Windows walk retains before emitting, across every profile,
/// HKLM, capability and level (the per-list 4096-child caps alone multiply to tens of GiB).
/// 65536 grants = kMaxProfiles (512) x 4 categories x 32 entries; 16 MiB = 65536 x 256 bytes of
/// app_id/value/cause text -- the variable, owner-controlled part of a grant (a NonPackaged path
/// is well under 256 bytes; a hostile 512-character name makes the byte bound bind first).
inline constexpr std::size_t kMaxRetainedGrants = 65536;
inline constexpr std::size_t kMaxRetainedBytes = 16u * 1024u * 1024u;

/// The run-wide budget. charge() is called BEFORE a grant is retained; once either limit would be
/// crossed it refuses, stays refused (sticky), and the collector stops walking, keeps every row
/// already charged and reports `collection:budget_exceeded` (unreadable, CONSTRAINED).
struct RetentionBudget {
    std::size_t max_grants = kMaxRetainedGrants;
    std::size_t max_bytes = kMaxRetainedBytes;
    std::size_t grants = 0;
    std::size_t bytes = 0;
    bool exhausted = false;

    [[nodiscard]] bool charge(std::size_t n_bytes) noexcept {
        if (exhausted || grants + 1 > max_grants || n_bytes > max_bytes - bytes) {
            exhausted = true;
            return false;
        }
        ++grants;
        bytes += n_bytes;
        return true;
    }
};

inline constexpr std::string_view kBudgetExceededToken = "collection:budget_exceeded";

// ── subkey enumeration outcome ─────────────────────────────────────────

enum class EnumOutcome { complete, truncated, failed };

struct EnumVerdict {
    EnumOutcome outcome;
    long rc = kErrorSuccess; // the failing code when `failed`
};

/// How a capped RegEnumKeyExW walk ended. `last_rc` is the code that ended the loop: anything but
/// ERROR_SUCCESS means the walk stopped on its own (ERROR_NO_MORE_ITEMS is the only clean stop,
/// every other code a real failure); ERROR_SUCCESS means the loop stopped only because it hit
/// the cap, and `probe_rc` -- one extra RegEnumKeyExW at the next index -- decides: NO_MORE_ITEMS
/// = there were EXACTLY cap children (complete, never a failure), SUCCESS = a real next child
/// exists (truncated), anything else = the probe itself failed (failed, never read as complete).
[[nodiscard]] constexpr EnumVerdict classify_subkey_enum(long last_rc, long probe_rc) noexcept {
    if (last_rc != kErrorSuccess) {
        if (last_rc == kErrorNoMoreItems) return {EnumOutcome::complete, kErrorSuccess};
        return {EnumOutcome::failed, last_rc};
    }
    if (probe_rc == kErrorNoMoreItems) return {EnumOutcome::complete, kErrorSuccess};
    if (probe_rc == kErrorSuccess) return {EnumOutcome::truncated, kErrorSuccess};
    return {EnumOutcome::failed, probe_rc};
}

struct EnumFailure {
    std::string cause; // `<kind>_enum_truncated` or `<kind>_enum_<win32_cause>`
    bool denied = false;
};

/// The failure an enumeration contributes, or nullopt for a complete one -- a complete walk,
/// including one of exactly the cap, never produces a failure token.
[[nodiscard]] inline std::optional<EnumFailure> enum_failure(std::string_view kind,
                                                             const EnumVerdict& v) {
    switch (v.outcome) {
    case EnumOutcome::complete:
        return std::nullopt;
    case EnumOutcome::truncated:
        return EnumFailure{std::string{kind} + "_enum_truncated", false};
    case EnumOutcome::failed:
        break;
    }
    return EnumFailure{std::string{kind} + "_enum_" + win32_cause(v.rc),
                       v.rc == kErrorAccessDenied};
}

/// How ProfileList discovery ended, as the one whole-source failure it contributes (nullopt: every
/// profile subkey was enumerated). `root_rc` opened ProfileList; `last_rc`/`probe_rc` are the walk's
/// terminating RegEnumKeyExW code and cap probe (classify_subkey_enum). A refused root or a refused
/// mid-walk enumeration is `denied` (PERMISSION_DENIED); any other root failure, terminating error
/// or a cap with more profiles is `unreadable` -- never a prefix read as the complete list.
[[nodiscard]] inline std::optional<EnumFailure> profile_discovery_failure(long root_rc, long last_rc,
                                                                          long probe_rc) {
    if (root_rc == kErrorAccessDenied) return EnumFailure{"profiles:profile_list_access_denied", true};
    if (root_rc != kErrorSuccess) return EnumFailure{"profiles:profile_list_unreadable", false};
    const auto v = classify_subkey_enum(last_rc, probe_rc);
    if (v.outcome == EnumOutcome::complete) return std::nullopt;
    if (v.outcome == EnumOutcome::truncated) return EnumFailure{"profiles:truncated", false};
    return EnumFailure{"profiles:enum_" + win32_cause(v.rc), v.rc == kErrorAccessDenied};
}

/// One ProfileList record whose SID key (`key_open`) or ProfileImagePath value failed to read.
/// A refusal is `denied` even when that profile's hive is still reached through HKU.
[[nodiscard]] inline EnumFailure profile_record_failure(bool key_open, long rc) {
    return {std::string{key_open ? "profiles:profile_key_" : "profiles:profile_image_path_"} +
                win32_cause(rc),
            rc == kErrorAccessDenied};
}

// ── profile SID validation ──────────────────────────────────────────────

/// A SID string of the `S-1-<authority>(-<subauthority>)*` shape, every component decimal
/// digits, within a sane length. Checked BEFORE the SID is appended to HKEY_USERS: an empty or
/// malformed string there would open the HKU root itself (or some other key), never the
/// profile's own hive.
[[nodiscard]] constexpr bool is_valid_sid_string(std::string_view sid) noexcept {
    constexpr std::size_t kMaxSidChars = 256;
    if (sid.size() > kMaxSidChars || !sid.starts_with("S-1-")) return false;
    std::size_t digits = 0;
    for (std::size_t i = 4; i < sid.size(); ++i) {
        const char c = sid[i];
        if (c >= '0' && c <= '9') {
            ++digits;
        } else if (c == '-' && digits > 0) {
            digits = 0;
        } else {
            return false;
        }
    }
    return digits > 0;
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

/// The token a failed grant adds to the run's constraint set: `<source>:<category>:<cause>`, no
/// app. One token per kind of failure however many apps share it, so an owner-stuffed ConsentStore
/// cannot grow the set; the row's own `raw` still names the app.
[[nodiscard]] inline std::string coarse_failure_token(std::string_view source,
                                                      std::string_view category,
                                                      std::string_view cause) {
    return std::string{source} + ":" + std::string{category} + ":" + std::string{cause};
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
    std::string cause{};
    // The READ of this grant's `Value` was refused (ERROR_ACCESS_DENIED) -- NOT the same thing
    // as `state == PermissionState::denied` alone, which also (correctly) means "the read
    // succeeded and decoded to a stored `Deny` grant" (CDX-P1-002).
    bool read_denied = false;
};

[[nodiscard]] inline bool grant_failed(const RawGrant& g) noexcept {
    return g.read_denied || g.state == PermissionState::unreadable;
}

/// A LastUsedTime* field that was never set (RawGrant's default for both).
inline const LastUsedField kLastUsedNotSet{"-", {}, false};

/// Every retained grant's owner-controlled text, charged against RetentionBudget.
[[nodiscard]] inline std::size_t retained_bytes(const RawGrant& g) noexcept {
    return g.app_id.size() + g.raw_value.size() + g.cause.size();
}

/// A category-level failure that is not one Value read (a key that refused/failed to open, an
/// enumeration that failed or hit its cap). Kept apart from the (app_id, category)-keyed grants
/// so the precedence merge can never overwrite or drop it.
[[nodiscard]] inline RawGrant structural_failure(std::string app_id, std::string_view category,
                                                 std::string cause, bool denied) {
    return {std::move(app_id), category,
            denied ? PermissionState::denied : PermissionState::unreadable, "-",
            kLastUsedNotSet, kLastUsedNotSet, std::move(cause), denied};
}

/// A `<capability>\NonPackaged` key that did not open. Genuinely missing is the desktop-apps
/// toggle row reading `absent` -- the toggle is its own row at every level, never omitted; any
/// other code is a `nonpackaged_container:<cause>` structural failure.
[[nodiscard]] inline RawGrant nonpackaged_open_failure(std::string_view category, long rc) {
    if (rc == kErrorFileNotFound)
        return {std::string{kNonPackagedToggleAppId}, category, PermissionState::absent, "-",
                kLastUsedNotSet, kLastUsedNotSet, {}, false};
    return structural_failure("-", category, "nonpackaged_container:" + win32_cause(rc),
                              rc == kErrorAccessDenied);
}

/// PRECEDENCE -- Microsoft's documented Settings model for the ConsentStore, confirmed on the-rig
/// (a non-MDM host carries HKLM `<capability>` `Value Allow` on every capability): the
/// machine-wide HKLM `Value` is the DEVICE toggle ("allow access on this device"). An HKLM `Deny`
/// blocks every user whatever their own value; an HKLM `Allow` blocks nothing and defers to each
/// user's own choice. So only a SUCCESSFULLY read and decoded HKLM `Deny` overrides a profile:
/// most restrictive wins, key by key -- the capability toggle (`-`) against the user's
/// capability toggle, the NonPackaged toggle against the user's NonPackaged toggle, an app
/// against the same app. An HKLM `Allow` or unmodelled value never overrides a user's Deny or
/// prompt (nor fills a key the user lacks -- that would invent a per-user grant); an absent,
/// unreadable or refused HKLM value says nothing. Rows below a toggle are reported as stored:
/// the toggle rows are what govern them, and the plugin does not compute an effective state.
[[nodiscard]] inline bool hklm_overrides_profile(const RawGrant& g) noexcept {
    return !grant_failed(g) && g.state == PermissionState::denied;
}

/// Whether an HKLM entry is emitted ONCE as HKLM's own unqualified row. An overriding `Deny` is
/// applied into each reachable profile's merge instead, so it is its own row only when no
/// profile was reachable to carry it. Everything else HKLM holds is its own row -- a
/// capability-level `absent` included: HKLM was read and definitively holds nothing there, and
/// that row must survive a profile-side whole-source failure (which suppresses
/// fill_uncovered_categories' backstop for every source).
[[nodiscard]] inline bool hklm_emitted_once(const RawGrant& g, bool any_profile_reachable) noexcept {
    return !hklm_overrides_profile(g) || !any_profile_reachable;
}

/// The profile's own grants with every overriding HKLM `Deny` applied (hklm_overrides_profile):
/// it replaces a successfully-read profile entry for the same (app_id, category) and fills a key
/// the profile lacks. A FAILED profile entry is never overwritten -- its failure row is kept and
/// the HKLM value is added beside it, so a read failure is never hidden behind a policy value.
/// Every other HKLM entry is skipped here (the caller reports those once, hklm_emitted_once).
/// Two profile entries with the same (app_id, category) -- distinct registry keys that decode to
/// one id, e.g. a packaged key `X` and a NonPackaged key `X` -- are both kept as stored, plus one
/// `duplicate_app_id` unreadable row naming the collision; neither silently replaces the other.
/// Output sorted by (app_id, category).
[[nodiscard]] inline std::vector<RawGrant> merge_with_hklm(std::span<const RawGrant> profile,
                                                           std::span<const RawGrant> hklm) {
    std::map<std::pair<std::string, std::string_view>, RawGrant> merged;
    std::vector<RawGrant> extra; // duplicates, their collision rows, HKLM beside a failed entry
    for (const auto& g : profile) {
        if (merged.try_emplace({g.app_id, g.category}, g).second) continue;
        extra.push_back(g);
        extra.push_back(structural_failure(g.app_id, g.category, "duplicate_app_id", false));
    }
    for (const auto& h : hklm) {
        if (!hklm_overrides_profile(h)) continue;
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
