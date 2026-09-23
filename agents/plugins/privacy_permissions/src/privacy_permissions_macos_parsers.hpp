/**
 * privacy_permissions_macos_parsers.hpp -- macOS-only PURE layer: the TCC service -> category
 * table, the `auth_value` decode, the open/prepare outcome classifiers and the per-source row
 * builder. No sqlite3.h, no syscall: privacy_permissions_macos.cpp supplies the real
 * lstat/sqlite3 results (and static_asserts the mirrored SQLite codes below), this file only
 * decides what they MEAN. Separate from privacy_permissions_parsers.hpp (the cross-OS layer),
 * same split as privacy_permissions_win_parsers.hpp.
 *
 * SOURCES: the system TCC.db (rows unqualified -- machine-wide services such as
 * full_disk_access) plus one per-user TCC.db per real home under /Users (rows qualified
 * `<user>\<client>` via qualify_app_id -- camera/microphone grants live there). Each source
 * reports every mapped category: its decoded rows, or an `absent` row when it genuinely holds
 * none, or an `unreadable` row when that category's query step failed.
 */
#pragma once

#include <array>
#include <cerrno>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "privacy_permissions_parsers.hpp"

namespace yuzu::privacy_permissions::macos {

struct TccService {
    std::string_view service; // literal TCC service identifier
    std::string_view category;
};

// Only three of the four charter categories are TCC services; every other TCC service
// (kTCCServiceContacts, kTCCServiceAppleEvents, kTCCServiceScreenCapture, ...) is out of scope
// by deliberate filter, not a decode failure -- the query never asks for them. `location` is
// NOT here (CDX-R2-005): ADR-3003's platform investigation established macOS Location Services
// is administered by `locationd`, OUTSIDE TCC entirely -- there is no kTCCServiceLocation row
// to query. It ships as its own explicit `unsupported` row instead.
inline constexpr std::array<TccService, 3> kTccServices{{
    {"kTCCServiceCamera", "camera"},
    {"kTCCServiceMicrophone", "microphone"},
    {"kTCCServiceSystemPolicyAllFiles", "full_disk_access"},
}};

/// Commonly-documented `auth_value` mapping across recent macOS releases (0=denied, 2=allowed,
/// 3=limited); any other value is a visible prompt_undetermined rather than a guess. A NULL or
/// non-integer column (nullopt) is `unreadable` -- sqlite3_column_int would silently read it as
/// 0, i.e. a fabricated `denied`.
[[nodiscard]] constexpr PermissionState decode_auth_value(std::optional<int> v) noexcept {
    if (!v) return PermissionState::unreadable;
    switch (*v) {
    case 0: return PermissionState::denied;
    case 2: return PermissionState::allowed;
    case 3: return PermissionState::allowed; // "limited" -- still a grant, just scoped
    default: return PermissionState::prompt_undetermined;
    }
}

// SQLite primary result codes, mirrored so this header stays sqlite3.h-free;
// privacy_permissions_macos.cpp static_asserts each against the real macro.
inline constexpr int kSqlitePerm = 3;
inline constexpr int kSqliteCantOpen = 14;
inline constexpr int kSqliteAuth = 23;

enum class SourceOutcome { absent, denied, unreadable };

struct SourceFailure {
    SourceOutcome outcome;
    std::string cause; // empty for `absent` (no token -- not a failure)
};

/// The lstat() pre-check on a TCC.db path, run BEFORE sqlite3_open_v2 so a missing file is
/// told apart from a refused one (sqlite reports both as SQLITE_CANTOPEN). `lstat_errno` is 0
/// on success. nullopt = a regular file is there, go ahead and open it.
/// `missing_is_absent`: a per-user TCC.db that does not exist is an honest "this user has no
/// TCC records" (absent); the SYSTEM TCC.db is always present on a supported macOS, so its
/// absence is `unreadable`, never absent. A symlink or other non-regular final component is
/// refused as `unreadable` (the open itself also passes SQLITE_OPEN_NOFOLLOW).
[[nodiscard]] inline std::optional<SourceFailure>
classify_tcc_presence(int lstat_errno, bool is_regular_file, bool missing_is_absent) {
    if (lstat_errno == 0) {
        if (is_regular_file) return std::nullopt;
        return SourceFailure{SourceOutcome::unreadable, "not_regular_file"};
    }
    if (lstat_errno == ENOENT || lstat_errno == ENOTDIR) {
        if (missing_is_absent) return SourceFailure{SourceOutcome::absent, {}};
        return SourceFailure{SourceOutcome::unreadable, "missing"};
    }
    if (lstat_errno == EPERM || lstat_errno == EACCES)
        return SourceFailure{SourceOutcome::denied, "access_denied"};
    return SourceFailure{SourceOutcome::unreadable, "lstat_errno_" + std::to_string(lstat_errno)};
}

/// A sqlite3_open_v2 / sqlite3_prepare_v2 failure on a file the lstat pre-check already saw
/// as present: SQLITE_CANTOPEN/SQLITE_AUTH/SQLITE_PERM is the SIP/TCC refusal shape (the
/// charter's expected outcome for a process without Full Disk Access) -> denied; any other code
/// (SQLITE_NOMEM, SQLITE_IOERR, SQLITE_NOTADB, a schema error) is a real fault that gaining FDA
/// would not fix -> unreadable (C4-CODEX-004). `rc` may be an extended code; only the primary
/// byte is compared.
[[nodiscard]] constexpr SourceOutcome classify_tcc_sqlite_rc(int rc) noexcept {
    const int primary = rc & 0xff;
    if (primary == kSqliteCantOpen || primary == kSqliteAuth || primary == kSqlitePerm)
        return SourceOutcome::denied;
    return SourceOutcome::unreadable;
}

/// `tcc_db` for the system database, `<user>:tcc_db` for a per-user one -- the subject every
/// whole-source failure token from this leg starts with.
[[nodiscard]] inline std::string tcc_source_key(std::string_view owner) {
    return owner.empty() ? std::string{"tcc_db"} : std::string{owner} + ":tcc_db";
}

[[nodiscard]] inline std::string tcc_row_app_id(std::string_view owner, std::string_view client) {
    return owner.empty() ? std::string{client} : qualify_app_id(owner, client);
}

/// The one row a whole TCC.db source contributes when it could not be read at all: `absent`
/// (per-user file genuinely missing -- no token), or a denied/unreadable failure row whose
/// token is `<source_key>:<cause>`. Category "-": the row stands for every TCC category of
/// that source.
[[nodiscard]] inline PermissionRow tcc_source_failed_row(std::string_view owner,
                                                         const SourceFailure& f,
                                                         yuzu::shared::ConstraintAccumulator& acc) {
    const std::string app_id = tcc_row_app_id(owner, "-");
    if (f.outcome == SourceOutcome::absent)
        return {"macos", app_id, "-", PermissionState::absent, "-", "-", "-", false};
    return failure_row("macos", app_id, "-", f.outcome == SourceOutcome::denied,
                       tcc_source_key(owner) + ":" + f.cause, acc);
}

struct TccGrant {
    std::string client;
    std::optional<int> auth_value; // nullopt = NULL / non-integer column
};

/// One mapped TCC service's query result from one source.
struct TccServiceRead {
    std::string_view category;
    std::vector<TccGrant> grants;
    bool step_failed = false; // sqlite3_step returned something other than ROW/DONE
};

/// Appends one successfully-opened source's rows: every decoded grant; an `unreadable` row
/// (token `<source_key>:<category>:query_step_failed`) for a category whose step failed --
/// even when some of its rows were already read, since the set is incomplete; and an `absent`
/// row for a category the source cleanly holds nothing for. A grant whose auth_value could not
/// be read is an `unreadable` row with token `<source_key>:<category>:auth_value_unreadable`.
inline void append_tcc_source_rows(std::string_view owner, std::span<const TccServiceRead> reads,
                                   std::vector<PermissionRow>& rows,
                                   yuzu::shared::ConstraintAccumulator& acc) {
    const std::string key = tcc_source_key(owner);
    for (const auto& read : reads) {
        for (const auto& g : read.grants) {
            if (!g.auth_value) {
                rows.push_back(failure_row("macos", tcc_row_app_id(owner, g.client), read.category,
                                           false,
                                           key + ":" + std::string{read.category} +
                                               ":auth_value_unreadable",
                                           acc));
                continue;
            }
            rows.push_back({"macos", tcc_row_app_id(owner, g.client), read.category,
                            decode_auth_value(g.auth_value), std::to_string(*g.auth_value), "-", "-",
                            false});
        }
        if (read.step_failed) {
            rows.push_back(failure_row("macos", tcc_row_app_id(owner, "-"), read.category, false,
                                       key + ":" + std::string{read.category} +
                                           ":query_step_failed",
                                       acc));
        } else if (read.grants.empty()) {
            rows.push_back({"macos", tcc_row_app_id(owner, "-"), read.category,
                            PermissionState::absent, "-", "-", "-", false});
        }
    }
}

} // namespace yuzu::privacy_permissions::macos
