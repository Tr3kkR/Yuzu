#pragma once

/**
 * confined_fs_walk.hpp -- PURE, header-only, Ops-parameterised iterative
 * walker for confined recursive delete (PLAN-010: centralises the semantics
 * PLAN-001/002/014 bind, so both platform legs -- and their sight-unseen
 * authors -- share ONE walk implementation instead of two hand-copies that
 * drift). No OS headers: only confined_fs_rules.hpp plus <optional>,
 * <utility>, <vector>, <string>.
 *
 * `Ops` is a compile-time interface (duck-typed template parameter, no
 * virtual dispatch) a platform shell provides:
 *
 *   using DirHandle = /-- move-only handle type (fd, HANDLE, whatever) --/;
 *   OpenDirRes<DirHandle> open_dir(DirHandle& parent, const std::string& name);
 *   EnumerateResult enumerate(DirHandle& dir, const EnumBudget&);
 *   UnlinkOutcome unlink(DirHandle& parent, const std::string& name, UnlinkKind);
 *   std::chrono::steady_clock::time_point now();
 *
 * `walk_delete` itself never opens a path, never resolves a symlink, and
 * never allocates OS resources -- it only calls the four `Ops` members above
 * and asks `decide_entry` what to do with what they return. A test TU can
 * therefore drive it end-to-end with a fake in-memory `Ops` and zero
 * disk access (test_confined_fs_walk.cpp).
 *
 * ── Binding walker semantics ─────────────────────────────────────────────
 *
 *  1. `deadline = ops.now() + limits.max_wall` is computed EXACTLY ONCE, at
 *     the start of the walk -- never re-derived per directory or per entry
 *     (a re-derived deadline would let the wall-time cap creep forward
 *     indefinitely on a slow walk).
 *  2. Traversal is an EXPLICIT ITERATIVE STACK of `{DirHandle, rel_prefix,
 *     depth}` frames -- no recursion, so a deep/adversarial directory tree
 *     cannot blow the call stack. The root frame is depth 0.
 *  3. Each directory is enumerated with
 *     `EnumBudget{max_entries - tally.entries_seen (0 if already exhausted),
 *     deadline}`.
 *       - Enumeration truncated with `WallTimeCap`: stop IMMEDIATELY --
 *         the entries collected before truncation are NOT processed --
 *         `stop_reason = WallTimeCap`.
 *       - Enumeration truncated with `EntryCap` and zero entries were
 *         collected: `stop_reason = EntryCap`.
 *       - `EnumerateResult::reason == OsError`: append
 *         `EntryOutcome{<this dir's rel_path>, Failed, OsError, os_error}`
 *         and continue on to the NEXT sibling on the stack (the walk is
 *         not stopped by one unreadable directory).
 *  4. Per collected entry, in order:
 *       - `stat_error != 0` -> append `Failed(OsError, stat_error)`,
 *         `entries_seen++`, continue to the next entry.
 *       - `name_invalid` -> append `Skipped(InvalidName)`, `entries_seen++`,
 *         continue (never reaches match or deletion).
 *       - Otherwise, the LAZY MATCH protocol (PLAN-001): call
 *         `decide_entry` first with `name_matched = true`. `MatchFn` is
 *         called ONLY if that decision's rule sits AT OR AFTER the
 *         name-match rule in the binding order -- i.e. the resulting
 *         action is `Unlink`, or `SkipEntry` with `reason == ByteCap`
 *         (both rules that fire strictly after the name-match check). Any
 *         other outcome (a structural rejection, a cap stop) means
 *         `decide_entry` never needed `name_matched` at all, so `MatchFn`
 *         is never invoked for it. When the real match is needed, it is
 *         evaluated inside a try/catch: a throw sets
 *         `stop_reason = MatchError` and returns the PARTIAL result built
 *         so far. Otherwise `decide_entry` is re-invoked with the real
 *         `name_matched` value and the walker acts on THAT decision.
 *  5. Acting on the (possibly re-evaluated) decision:
 *       - `Unlink`: call `ops.unlink(parent, name, File)`; append
 *         `Deleted` or `Failed(reason, os_error)` per the outcome;
 *         `entries_seen++` always; `bytes_deleted += size_bytes` ONLY on a
 *         successful delete.
 *       - `RecurseIntoDir`: call `ops.open_dir`. A POLICY refusal
 *         (`SymlinkRejected`/`ReparseRejected`/`DeviceBoundary`/
 *         `NotRegularFile`/`InvalidName`) appends `Skipped(reason)`; an
 *         `OsError` refusal appends `Failed(OsError, os_error)`
 *         (PLAN-002); success pushes a new stack frame. `entries_seen++`
 *         either way.
 *       - `SkipEntry`: `entries_seen++`; append an outcome UNLESS
 *         `reason == NameFilteredOut`, which is intentionally left
 *         UNRECORDED (bounded-output rule -- a filtered-out tree must not
 *         blow up `DeleteResult::entries` to the size of the whole subtree)
 *         but IS still counted in `entries_seen`.
 *       - `StopWalk`: `stop_reason = reason`; return immediately.
 *  6. Directories are TRAVERSED, never deleted -- `RecurseIntoDir` never
 *     reaches `ops.unlink`. `rel_path` components are joined with `/`.
 *  7. EXCEPTION FIREWALL (PLAN-014): the entire walk body runs inside one
 *     outer try/catch(...). Any exception that is not the deliberately
 *     caught `MatchFn` throw (rule 4) is caught here, `stop_reason` is set
 *     to `Internal`, and the best-effort partial result built so far is
 *     returned. `walk_delete` lets NO exception escape to its caller.
 */

#include <yuzu/agent/confined_fs_rules.hpp>

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::agent::confined_fs {

/// Result of an `Ops::open_dir` call: either a handle to the newly opened
/// directory, or a refusal reason (`Reason::None` + a present `handle` is
/// success; any other `reason` is a refusal and `handle` is empty).
template <class H>
struct OpenDirRes {
    std::optional<H> handle;
    Reason reason{Reason::None};
    int os_error{0};
};

namespace detail {

/// One frame of the explicit traversal stack.
template <class DirHandle>
struct WalkFrame {
    DirHandle handle;
    std::string rel_prefix; // "" for the root, else "a/b" with a trailing entry name to append
    std::uint32_t depth;
};

inline std::string join_rel(const std::string& prefix, const std::string& name) {
    if (prefix.empty())
        return name;
    return prefix + "/" + name;
}

} // namespace detail

/**
 * Walk `root` (already-open, caller-owned) deleting every entry `match`
 * accepts, subject to `limits`. See the header banner for the full binding
 * semantics. Never throws -- see rule 7 above.
 */
template <class Ops>
DeleteResult walk_delete(typename Ops::DirHandle root, Ops& ops, const MatchFn& match,
                          const DeleteLimits& limits) {
    using DirHandle = typename Ops::DirHandle;

    DeleteResult result{};
    result.stop_reason = Reason::None;

    try {
        const auto deadline = ops.now() + limits.max_wall;

        std::vector<detail::WalkFrame<DirHandle>> stack;
        stack.push_back(detail::WalkFrame<DirHandle>{std::move(root), std::string{}, 0});

        while (!stack.empty()) {
            detail::WalkFrame<DirHandle> frame = std::move(stack.back());
            stack.pop_back();

            const std::uint64_t remaining = result.tally.entries_seen >= limits.max_entries
                                                 ? 0
                                                 : limits.max_entries - result.tally.entries_seen;
            EnumBudget budget{remaining, deadline};

            EnumerateResult enum_result = ops.enumerate(frame.handle, budget);

            if (enum_result.reason == Reason::WallTimeCap) {
                result.stop_reason = Reason::WallTimeCap;
                return result;
            }
            if (enum_result.reason == Reason::EntryCap && enum_result.entries.empty()) {
                result.stop_reason = Reason::EntryCap;
                return result;
            }
            if (enum_result.reason == Reason::OsError) {
                result.entries.push_back(EntryOutcome{frame.rel_prefix, EntryStatus::Failed,
                                                        Reason::OsError, enum_result.os_error});
                continue; // move on to sibling directories still on the stack
            }

            bool stopped = false;
            for (auto& dir_entry : enum_result.entries) {
                const std::string rel_path = detail::join_rel(frame.rel_prefix, dir_entry.name);

                if (dir_entry.stat_error != 0) {
                    result.entries.push_back(EntryOutcome{
                        rel_path, EntryStatus::Failed, Reason::OsError, dir_entry.stat_error});
                    ++result.tally.entries_seen;
                    continue;
                }
                if (dir_entry.name_invalid) {
                    result.entries.push_back(
                        EntryOutcome{rel_path, EntryStatus::Skipped, Reason::InvalidName, 0});
                    ++result.tally.entries_seen;
                    continue;
                }

                const bool deadline_exceeded = ops.now() >= deadline;
                const bool depth_exceeded = frame.depth >= limits.max_depth;

                // Lazy-match protocol (PLAN-001): probe with name_matched=true
                // first; only call the real MatchFn if the probe decision's
                // rule sits at or after the name-match rule.
                Decision decision = decide_entry(dir_entry.meta, limits, result.tally,
                                                  deadline_exceeded, depth_exceeded,
                                                  /*name_matched=*/true);
                const bool needs_real_match =
                    decision.action == Action::Unlink ||
                    (decision.action == Action::SkipEntry && decision.reason == Reason::ByteCap);
                if (needs_real_match) {
                    bool matched = false;
                    try {
                        matched = match(rel_path);
                    } catch (...) {
                        result.stop_reason = Reason::MatchError;
                        stopped = true;
                        break;
                    }
                    decision = decide_entry(dir_entry.meta, limits, result.tally,
                                             deadline_exceeded, depth_exceeded, matched);
                }

                switch (decision.action) {
                case Action::Unlink: {
                    UnlinkOutcome outcome =
                        ops.unlink(frame.handle, dir_entry.name, UnlinkKind::File);
                    if (outcome.status == EntryStatus::Deleted)
                        result.tally.bytes_deleted += dir_entry.meta.size_bytes;
                    result.entries.push_back(
                        EntryOutcome{rel_path, outcome.status, outcome.reason, outcome.os_error});
                    ++result.tally.entries_seen;
                    break;
                }
                case Action::RecurseIntoDir: {
                    OpenDirRes<DirHandle> opened = ops.open_dir(frame.handle, dir_entry.name);
                    ++result.tally.entries_seen;
                    if (opened.handle.has_value()) {
                        stack.push_back(detail::WalkFrame<DirHandle>{
                            std::move(*opened.handle), rel_path,
                            frame.depth + 1});
                    } else if (opened.reason == Reason::OsError) {
                        result.entries.push_back(EntryOutcome{
                            rel_path, EntryStatus::Failed, Reason::OsError, opened.os_error});
                    } else {
                        result.entries.push_back(
                            EntryOutcome{rel_path, EntryStatus::Skipped, opened.reason, 0});
                    }
                    break;
                }
                case Action::SkipEntry:
                    ++result.tally.entries_seen;
                    if (decision.reason != Reason::NameFilteredOut) {
                        result.entries.push_back(
                            EntryOutcome{rel_path, EntryStatus::Skipped, decision.reason, 0});
                    }
                    break;
                case Action::StopWalk:
                    result.stop_reason = decision.reason;
                    stopped = true;
                    break;
                }

                if (stopped)
                    break;
            }

            if (stopped)
                return result;
        }

        return result;
    } catch (...) {
        result.stop_reason = Reason::Internal;
        return result;
    }
}

} // namespace yuzu::agent::confined_fs
