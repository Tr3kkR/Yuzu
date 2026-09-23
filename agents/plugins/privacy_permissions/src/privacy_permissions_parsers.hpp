/**
 * privacy_permissions_parsers.hpp -- the PURE layer for privacy_permissions: the state
 * vocabulary, the fixed cross-OS category table, the row formatter and the shared status
 * selector. No OS call, no I/O, no platform header: the leg TUs supply the real
 * SQLite/registry/D-Bus read, this file only decides what a result MEANS.
 *
 * ROW (always 8 fields, pinned to content/definitions/privacy_permissions.yaml's `result.columns`
 * by kColumns + the unit test): <row_kind>|<os>|<app_id>|<category>|<state>|<raw>
 * |<last_used_start>|<last_used_stop>. `row_kind` is `permissions` on every data row and
 * `constrained` only on the one internal_error row the plugin's catch-all writes (same field
 * count, so the YAML columns never shift). The two `last_used_*` fields are Windows-only
 * (epoch-ms, "-" elsewhere) -- always present so every row has the same field count.
 *
 * FAILURE ROWS: a row whose state is `unreadable` or `denied` because a READ failed carries its
 * own `<subject>:<cause>` failure token in `raw` (the same token lands in the result
 * provenance), so a failure row is never mistaken for a decoded grant. `category` is "-" only
 * on a whole-SOURCE row (a whole TCC.db, profile hive, HKLM root, the portal/session bus) --
 * that one row stands for every category of that source, so no category is ever silently
 * omitted: each category either gets its own row or is covered by a whole-source row.
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
#include <cerrno>
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

// Row families (the leading `row_kind` field). Every data row is `permissions`; `constrained`
// is written only by the plugin's catch-all (format_internal_error_row).
inline constexpr std::string_view kRowKindPermissions = kPermissionsAction;
inline constexpr std::string_view kRowKindConstrained = "constrained";

// The wire row's fields, in order -- MUST equal the YAML definition's `result.columns` names
// (pinned by test_privacy_permissions_parsers.cpp, which reads the YAML itself).
inline constexpr std::array<std::string_view, 8> kColumns{
    "row_kind", "os", "app_id", "category", "state", "raw", "last_used_start", "last_used_stop"};

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

/// `app_id` is owned (a per-app identifier -- an exe path, a bundle id, a PFN, or "-" for "no
/// specific app"); `category` and `os` borrow literals. `read_denied` = the read was refused
/// (distinct from PermissionState::denied alone, which on a decoded row means "this app's grant
/// for this category is denied" -- a normal, non-failure result). A row read from a PER-USER
/// source (a Windows profile hive, a macOS per-user TCC.db) has its app_id qualified with that
/// user's name via qualify_app_id (never a SID -- ADR-0024 D11), so the same app across two
/// users never collides.
struct PermissionRow {
    std::string_view os;
    std::string app_id;
    std::string_view category; // one of kCategories, or "-" on a whole-source row only
    PermissionState state;
    std::string raw;              // "-" when nothing meaningful; the failure token on a failure row
    std::string last_used_start;  // "-" except Windows (epoch-ms, or `unreadable`)
    std::string last_used_stop;   // "-" except Windows (epoch-ms, or `unreadable`)
    bool read_denied = false;     // the READ was refused, not "this grant is denied"
};

/// `<owner>\<app_id>` -- the one per-user qualification shape every leg uses. An owner name
/// that could not be resolved renders as "-" (user_profile_model.hpp's display convention),
/// never an empty prefix that would read as an unqualified machine-wide row. On the wire the
/// row sanitizer (safe_output_field) folds the `\` to `/`, as it does for every path.
[[nodiscard]] inline std::string qualify_app_id(std::string_view owner, std::string_view app_id) {
    std::string out = owner.empty() ? std::string{"-"} : std::string{owner};
    out += '\\';
    return out.append(app_id);
}

[[nodiscard]] inline std::string format_row(const PermissionRow& r) {
    std::string out{kRowKindPermissions};
    (out += '|').append(r.os) += '|';
    (out += yuzu::util::safe_output_field(r.app_id)) += '|';
    (out += r.category) += '|';
    (out += state_token(r.state)) += '|';
    (out += yuzu::util::safe_output_field(r.raw)) += '|';
    (out += r.last_used_start) += '|';
    return out.append(r.last_used_stop);
}

/// The internal_error row the plugin's catch-all writes: the SAME 8-field shape as a data row
/// (row_kind `constrained`), so a consumer binding the YAML columns positionally never shifts.
[[nodiscard]] inline std::string format_internal_error_row(std::string_view os) {
    std::string out{kRowKindConstrained};
    (out += '|').append(os);
    out += "|-|-|";
    out += state_token(PermissionState::unreadable);
    return out += "|internal_error|-|-";
}

/// A row whose READ failed: `denied` (the read was refused -- promotes PERMISSION_DENIED) or
/// `unreadable` (any other failure -- CONSTRAINED). Never `absent`. The failure token is both
/// accumulated and carried in `raw`, so the row names its own cause.
[[nodiscard]] inline PermissionRow failure_row(std::string_view os, std::string app_id,
                                               std::string_view category, bool denied,
                                               std::string token,
                                               yuzu::shared::ConstraintAccumulator& acc) {
    acc.add_failure(token);
    return {os,
            std::move(app_id),
            category,
            denied ? PermissionState::denied : PermissionState::unreadable,
            std::move(token),
            "-",
            "-",
            denied};
}

/// One row naming a whole SOURCE's read as failed (TCC.db wouldn't open, a profile hive or the
/// HKLM ConsentStore root refused, the portal bus call failed outright). `category` is "-"
/// since the row stands for every category of that source.
[[nodiscard]] inline PermissionRow whole_read_failed_row(std::string_view os, PermissionState state,
                                                         std::string_view cause,
                                                         yuzu::shared::ConstraintAccumulator& acc,
                                                         bool denied) {
    if (state == PermissionState::unreadable || denied) acc.add_failure(std::string{cause});
    return {os, "-", "-", state, std::string{cause}, "-", "-", denied};
}

/// Coverage backstop: appends an `absent` row for every category no row mentions -- but ONLY
/// when nothing failed. If any read failed or was refused, the failure rows (a whole-source
/// row covers every category of its source) already account for the gap, and an `absent` here
/// would be exactly the failure-reads-as-absent collapse this plugin must never make.
inline void fill_uncovered_categories(std::string_view os, std::vector<PermissionRow>& rows,
                                      const yuzu::shared::ConstraintAccumulator& acc) {
    if (acc.any_failure()) return;
    for (const auto& r : rows)
        if (r.read_denied) return;
    for (const auto cat : kCategories) {
        bool covered = false;
        for (const auto& r : rows)
            if (r.category == cat) covered = true;
        if (!covered) rows.push_back({os, "-", cat, PermissionState::absent, "-", "-", "-", false});
    }
}

// ── Linux session-bus open (pure; errno values are portable <cerrno> constants) ──

enum class BusOpenOutcome { unavailable, denied, failed };

/// Classifies sd_bus_open_user's NEGATED return (pass the positive errno). No session bus to
/// reach (no XDG_RUNTIME_DIR/DBUS_SESSION_BUS_ADDRESS, no socket, nobody listening) is the
/// honest UNAVAILABLE case; a refused socket is `denied`, never folded into "no session";
/// anything else is a real failure.
[[nodiscard]] constexpr BusOpenOutcome classify_session_bus_open(int err) noexcept {
    switch (err) {
    case ENOENT:
    case ENOTDIR:
    case ECONNREFUSED:
    case ENXIO:
#if defined(ENOMEDIUM)
    case ENOMEDIUM: // systemd's "no XDG_RUNTIME_DIR" answer (Linux-only errno)
#endif
        return BusOpenOutcome::unavailable;
    case EACCES:
    case EPERM:
        return BusOpenOutcome::denied;
    default:
        return BusOpenOutcome::failed;
    }
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
