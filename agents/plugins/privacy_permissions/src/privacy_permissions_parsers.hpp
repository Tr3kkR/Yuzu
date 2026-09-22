/**
 * privacy_permissions_parsers.hpp -- the PURE layer for privacy_permissions: the state
 * vocabulary, the fixed cross-OS category table, the row formatter and the shared status
 * selector. No OS call, no I/O, no platform header: the leg TUs supply the real
 * SQLite/registry/D-Bus read, this file only decides what a result MEANS.
 *
 * ROW (always 8 fields): permissions|<os>|<app_id>|<category>|<state>|<raw>|<last_used_start>
 * |<last_used_stop>. The two `last_used_*` fields are Windows-only (epoch-ms, "-" elsewhere) --
 * always present so every row from this plugin has the same field count, never omitted.
 *
 * <category> is a FIXED, cross-OS vocabulary: camera | microphone | location |
 * full_disk_access. Each leg owns its own native-identifier -> category table and silently
 * SKIPS any native capability outside it (Windows' `contacts`/`phoneCall`/etc, a macOS TCC
 * service this plugin doesn't model) -- that is a deliberate charter-scoped filter, not a
 * decode failure, and must never consume a `constrained` token or emit a row.
 *
 * <state> = allowed | denied | prompt_undetermined | absent | unreadable | unsupported.
 * BINDING CONTRACT (same discipline as every sibling Wave 8 plugin): absent (the mechanism
 * definitively says there is no record for this app+category -- the app never asked) adds no
 * failure token and never downgrades the status; unreadable (the read itself failed for a
 * reason OTHER than "not there") always carries a `<key>:<cause>` token; denied (a
 * PERMISSION_DENIED-class refusal -- EACCES/EPERM opening TCC.db, ERROR_ACCESS_DENIED on the
 * registry, an AccessDenied-shaped D-Bus error) is a THIRD, separate bucket from both -- a
 * refused read must NEVER collapse into absent. This is the single most important
 * correctness property here: the macOS acceptance criterion is explicitly about recording a
 * real SIP/TCC denial honestly, not silently reporting "no camera access requested".
 */
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <constraint_accumulator.hpp>

#include <yuzu/plugin.h> // YuzuResultStatus / Completeness (C ABI: no OS types)
#include <yuzu/string_utils.hpp>

namespace yuzu::privacy_permissions {

inline constexpr std::string_view kPermissionsAction = "permissions";

enum class PermissionState { allowed, denied, prompt_undetermined, absent, unreadable, unsupported };

// Indexed by PermissionState: order is part of the contract (pinned by the unit test).
inline constexpr std::array<std::string_view, 6> kStateTokens{
    "allowed", "denied", "prompt_undetermined", "absent", "unreadable", "unsupported"};

[[nodiscard]] constexpr std::string_view state_token(PermissionState s) noexcept {
    return kStateTokens[static_cast<std::size_t>(s)];
}

// ── the fixed cross-OS category vocabulary ───────────────────────────────

inline constexpr std::array<std::string_view, 4> kCategories{"camera", "microphone", "location",
                                                              "full_disk_access"};

[[nodiscard]] constexpr bool is_known_category(std::string_view c) noexcept {
    for (const auto k : kCategories)
        if (k == c) return true;
    return false;
}

// ── rows ───────────────────────────────────────────────────────────────

/// `app_id` is owned (a per-app identifier -- an exe path, a bundle id, a PFN); `category` and
/// `os` borrow literals. `denied` = the read was refused (distinct from PermissionState::denied,
/// which means "this app's grant for this category is denied" -- a normal, non-failure result).
/// On Windows, `app_id` is qualified with the owning profile's name (`<profile>\<app_id>`,
/// never a SID -- ADR-0024 D11) since the agent runs as LocalSystem and reads MULTIPLE real
/// users' ConsentStore hives, so the same app across two profiles must not collide.
struct PermissionRow {
    std::string_view os;
    std::string app_id;
    std::string_view category; // must be one of kCategories
    PermissionState state;
    std::string raw;              // "-" when nothing meaningful beyond the state itself
    std::string last_used_start;  // "-" except Windows (epoch-ms)
    std::string last_used_stop;   // "-" except Windows (epoch-ms)
    bool read_denied = false;     // the READ was refused, not "this grant is denied"
};

[[nodiscard]] inline std::string format_row(const PermissionRow& r) {
    std::string out{kPermissionsAction};
    (out += '|').append(r.os) += '|';
    (out += yuzu::util::safe_output_field(r.app_id)) += '|';
    (out += r.category) += '|';
    (out += state_token(r.state)) += '|';
    (out += yuzu::util::safe_output_field(r.raw)) += '|';
    (out += r.last_used_start) += '|';
    return out.append(r.last_used_stop);
}

/// One row naming the whole read as failed (no per-app rows could be produced at all --
/// e.g. TCC.db itself couldn't be opened, ConsentStore root key is missing, the portal bus
/// call failed outright). `category` is "-" since no specific category is implicated.
[[nodiscard]] inline PermissionRow whole_read_failed_row(std::string_view os, PermissionState state,
                                                         std::string_view cause,
                                                         yuzu::shared::ConstraintAccumulator& acc,
                                                         bool denied) {
    if (state == PermissionState::unreadable || denied) acc.add_failure(std::string{cause});
    return {os, "-", "-", state, std::string{cause}, "-", "-", denied};
}

// ── status selection (pure; the one decision every leg shares) ──────────

[[nodiscard]] inline bool any_denied(std::span<const PermissionRow> rows) noexcept {
    for (const auto& r : rows)
        if (r.read_denied) return true;
    return false;
}

struct PermissionStatus {
    YuzuResultStatus status;
    YuzuResultCompleteness completeness;
    std::string provenance;
};

/// PERMISSION_DENIED/PARTIAL if any read was refused, else CONSTRAINED/PARTIAL if a failure
/// token exists, else UNAVAILABLE/FULL if the whole mechanism is honestly not reachable on
/// this host (no daemon/no session -- the Linux common case), else OK/FULL.
[[nodiscard]] inline PermissionStatus select_status(const yuzu::shared::ConstraintAccumulator& acc,
                                                    bool denied, bool unavailable) {
    if (denied)
        return {YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                acc.reason()};
    if (acc.any_failure())
        return {YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL, acc.reason()};
    if (unavailable)
        return {YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_FULL, {}};
    return {YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, {}};
}

} // namespace yuzu::privacy_permissions
