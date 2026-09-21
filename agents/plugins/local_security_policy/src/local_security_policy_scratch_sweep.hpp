#pragma once

/**
 * local_security_policy_scratch_sweep.hpp -- the PURE decisions behind the
 * Windows leg's secedit export: which leftover directories under
 * agent.data_dir the pre-dispatch sweep may reclaim, how the secedit run and
 * the read of its output are classified. No OS calls -- only the standard
 * library -- so every decision is unit-tested on every OS. The shell in
 * local_security_policy_win.cpp only performs what these functions return. The
 * exported-INI -> rows mapping is NOT here: it is the parsers header's.
 *
 * Why a sweep: the CHILD (secedit) writes the export, so a crash or service
 * stop between export and the agent's RAII delete orphans a copy of the
 * machine's policy under agent.data_dir. Every dispatch sweeps stale
 * `local_security_policy-<32 hex>` directories BEFORE spawning.
 *
 * The selection policy is a PLUGIN-LOCAL COPY of execution_artifacts'
 * (prefix + 32 hex + strict age, same unconditional caps); not lifted into
 * agents/shared until a second consumer exists. The one-hour floor is not a
 * data-safety guard: a live directory is protected by the dispatch holding it
 * open without FILE_SHARE_DELETE; the floor only covers the create-to-open
 * window of a concurrent dispatch.
 */

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::local_security_policy {

// -- Scratch directory naming -------------------------------------------------

/// MUST equal the literal prefix passed to yuzu_create_temp_dir() in
/// local_security_policy_win.cpp.
inline constexpr std::string_view kScratchDirPrefix = "local_security_policy-";

/// yuzu_create_temp_dir appends exactly this many hex characters (128 bits).
inline constexpr std::size_t kScratchDirRandomHexLen = 32;

/// One hour; strictly-greater comparison (see is_stale).
inline constexpr std::int64_t kScratchDirStaleAfterSecs = 3600;

// -- Unconditional per-pass caps ----------------------------------------------

inline constexpr std::size_t kScratchSweepMaxRootEntries = 4096;
inline constexpr std::size_t kScratchSweepMaxRemovals = 64;
/// Counted separately from removals: failures delete nothing, so a run of
/// persistent failures must not starve a later removable orphan.
inline constexpr std::size_t kScratchSweepMaxFailures = 256;
inline constexpr std::int64_t kScratchSweepMaxWallMs = 2000;
/// A real export directory holds one file (policy.inf).
inline constexpr std::size_t kScratchSweepMaxDirEntries = 64;

struct ScratchSweepResult {
    std::size_t removed{0};
    std::size_t failed{0};
    std::size_t skipped_fresh{0};
    std::size_t skipped_not_ours{0};
    std::size_t deferred{0};
    bool enumerate_error{false};
    int os_error{0};
};

/// True only for the exact prefix followed by exactly 32 hex digits (either
/// case) and nothing else.
[[nodiscard]] inline bool is_scratch_dir_name(std::string_view name) noexcept {
    if (!name.starts_with(kScratchDirPrefix))
        return false;
    const std::string_view rest = name.substr(kScratchDirPrefix.size());
    if (rest.size() != kScratchDirRandomHexLen)
        return false;
    for (const char c : rest) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                         (c >= 'A' && c <= 'F');
        if (!hex)
            return false;
    }
    return true;
}

/// True only when `now - mtime` is STRICTLY GREATER than `stale_after`: exact
/// equality and a future-dated mtime (clock skew) are both FRESH.
[[nodiscard]] inline bool is_stale(std::int64_t mtime_unix_s, std::int64_t now_unix_s,
                                   std::int64_t stale_after_s) noexcept {
    return (now_unix_s - mtime_unix_s) > stale_after_s;
}

enum class SweepCandidate {
    NotCandidate, // wrong name shape or not a directory -- never opened
    NoMtime,      // absence of an mtime is never treated as "old"
    Fresh,        // younger than the threshold -- left for a later pass
    Stale,        // eligible for the ownership check and removal
};

[[nodiscard]] inline SweepCandidate
classify_sweep_candidate(std::string_view name, bool is_directory,
                         std::optional<std::int64_t> mtime_unix_s, std::int64_t now_unix_s,
                         std::int64_t stale_after_s) noexcept {
    if (!is_scratch_dir_name(name) || !is_directory)
        return SweepCandidate::NotCandidate;
    if (!mtime_unix_s)
        return SweepCandidate::NoMtime;
    return is_stale(*mtime_unix_s, now_unix_s, stale_after_s) ? SweepCandidate::Stale
                                                              : SweepCandidate::Fresh;
}

/// A stale candidate is removed only when this process's token owner owns it;
/// a same-named directory owned by any other SID is skipped, never touched.
[[nodiscard]] inline bool sweep_may_remove(bool owned_by_current_token_owner) noexcept {
    return owned_by_current_token_owner;
}

/// `scratch_sweep:<removed>/<skipped>` -- banner-level log only, never a row
/// or a constraint token. skipped = every examined-but-not-removed outcome.
[[nodiscard]] inline std::string format_sweep_summary(const ScratchSweepResult& r) {
    const std::size_t skipped = r.skipped_fresh + r.skipped_not_ours + r.failed + r.deferred;
    return "scratch_sweep:" + std::to_string(r.removed) + "/" + std::to_string(skipped);
}

// -- secedit run / read classification ----------------------------------------

inline constexpr std::int64_t kExportDeadlineMs = 30'000;
inline constexpr std::size_t kExportMaxBytes = 1024 * 1024; // 1 MiB

/// Win32 error numbers, plain integers here and static_asserted against
/// winerror.h in the Windows TU.
inline constexpr unsigned long kWin32FileNotFound = 2;
inline constexpr unsigned long kWin32PathNotFound = 3;
inline constexpr unsigned long kWin32AccessDenied = 5;

/// How the runner reported the child ending, mirrored so this header stays
/// free of agent-core types.
enum class RunEnd { Exited, Deadline, Cancelled, Signaled, SpawnError, Other };

/// Empty string = the run succeeded; otherwise the CONSTRAINED token.
[[nodiscard]] inline std::string classify_export_run(RunEnd end, int exit_code) {
    switch (end) {
    case RunEnd::SpawnError:
        return "secedit:spawn_error";
    case RunEnd::Deadline:
        return "secedit:timeout";
    case RunEnd::Cancelled:
        return "secedit:cancelled";
    case RunEnd::Signaled:
        return "secedit:signaled";
    case RunEnd::Other:
        return "secedit:unexpected_termination";
    case RunEnd::Exited:
        break;
    }
    return exit_code == 0 ? std::string{} : "secedit:exit_" + std::to_string(exit_code);
}

struct ExportReadFailure {
    bool permission_denied{false}; // -> PERMISSION_DENIED, else CONSTRAINED
    std::string token;
};

/// Classifies a failed open/read of the exported file. A refused read is
/// PERMISSION_DENIED; a file that is not there after a zero exit is its own
/// token; anything else keeps its Win32 number. Never reads as "absent".
[[nodiscard]] inline ExportReadFailure classify_export_read_error(unsigned long win32_error) {
    if (win32_error == kWin32AccessDenied)
        return {true, "secedit:access_denied"};
    if (win32_error == kWin32FileNotFound || win32_error == kWin32PathNotFound)
        return {false, "secedit:output_missing"};
    return {false, "secedit:read_" + std::to_string(win32_error)};
}

} // namespace yuzu::local_security_policy
