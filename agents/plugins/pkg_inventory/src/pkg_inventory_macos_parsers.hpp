/**
 * pkg_inventory_macos_parsers.hpp — the macOS Homebrew walks, over an INJECTED
 * ROOT. Production passes "/"; the unit suite passes a materialized tree.
 *
 * NOVEL DESIGN. The peripherals injected-root precedent is Linux-only
 * (peripherals_macos.cpp has no `_at` seam), so these seams have no template.
 *
 * TWO PREFIXES. Homebrew lives at /opt/homebrew on Apple silicon and at
 * /usr/local on Intel; a Mac migrated between architectures (or running both
 * under Rosetta) can have both. Every walk probes BOTH, in that order, and
 * reports each detected prefix as its own manager row (root_path names the
 * logical prefix). A package installed in both prefixes yields one row per
 * prefix; the package row has no prefix column by design (the manager row
 * says which prefixes exist).
 *
 * WHAT COUNTS AS HOMEBREW. A prefix is Homebrew iff at least one of
 * `Library/Taps`, `Cellar`, `Caskroom` exists under it (/usr/local exists on
 * every Mac, so the bare prefix proves nothing). An absent marker counts 0
 * (taps/formulae/casks facts); an unreadable marker is a constrained token and
 * its fact is omitted (never a false 0). No process is spawned (no `brew`
 * invocation, no version string is read: the version field is always "-").
 *
 * Filesystem layout read (formula and cask names/versions are directory names):
 *   <prefix>/Library/Taps/<org>/<repo>      -> taps
 *   <prefix>/Cellar/<formula>/<version>     -> formulae / package|...|formula
 *   <prefix>/Caskroom/<cask>/<version>      -> casks    / package|...|cask
 * Entries that are not real directories (files, symlinks) and names that fail
 * version_dir_name_ok (dot-prefixed `.metadata`/`.keepme`, separators, control
 * characters) are skipped by design: Homebrew creates real directories.
 *
 * SYMLINKS ARE NEVER FOLLOWED. Every marker is reached the same way: the prefix
 * root is opened with O_NOFOLLOW (its own parents, /opt and /usr, are owned by
 * the OS), then each marker component is one openat + O_NOFOLLOW hop. A
 * symlinked prefix, Library, Taps, Cellar or Caskroom is therefore refused and
 * reported as a constraint (`symlink_refused` / `not_a_directory`), never read.
 *
 * BOUNDED. Both actions share one whole-ACTION budget (entries read and wall
 * clock) on top of the per-directory cap; exhausting it is a `walk_budget`
 * constraint, never a silently shorter result.
 *
 * Per-user Homebrew stores are out of scope (machine scope only).
 *
 * Compiled on POSIX only; the portable row/text layer is
 * pkg_inventory_parsers.hpp, the guarded walk primitives (`posix::`) are in
 * pkg_inventory_legs.hpp.
 */
#pragma once

#if !defined(_WIN32)

#include "pkg_inventory_legs.hpp"
#include "pkg_inventory_parsers.hpp"

#include <constraint_accumulator.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::pkg_inventory::mac {

namespace detail {

inline constexpr std::string_view kOs = "macos";

/// Apple silicon first, then Intel. Logical (un-rooted) paths without the
/// leading slash, so `root / prefix` composes with any injected root.
inline constexpr std::array<std::string_view, 2> kPrefixes{"opt/homebrew", "usr/local"};

/// The two package containers under a prefix, in walk order.
struct Container {
    std::string_view rel;
    std::string_view source;
    PackageKind kind;
};
inline constexpr std::array<Container, 2> kContainers{{
    {"Cellar", "homebrew_cellar", PackageKind::formula},
    {"Caskroom", "homebrew_caskroom", PackageKind::cask},
}};

[[nodiscard]] inline std::string under(const std::filesystem::path& root, std::string_view rel) {
    std::error_code ec;
    auto base = std::filesystem::absolute(root, ec);
    if (ec) base = root;
    return (base / std::string{rel}).string();
}

[[nodiscard]] inline std::string logical(std::string_view prefix) {
    return "/" + std::string{prefix};
}

/// Whole-ACTION entries + wall-clock budget, one per action (constructed once,
/// before the prefix loop) and threaded by reference through every listing that
/// action performs. Each directory listing is bounded on its own by
/// lim.max_entries_per_dir, but nothing else bounds how many such listings a
/// whole action performs: a tree of max_entries_per_dir id/org directories x
/// max_entries_per_dir entries each (or a Cellar full of plain files that never
/// classify as a version directory, so row_cap never trips) would otherwise be
/// read in full on every call. Not agents/core/include/yuzu/agent/
/// confined_fs_rules.hpp's `EnumBudget`: that type is scoped, by its own banner,
/// to confined recursive DELETE (a different subsystem) -- this is a small
/// pkg_inventory-local equivalent of the same shape, not a shared import.
struct WalkBudget {
    std::size_t remaining_entries;
    std::chrono::steady_clock::time_point deadline;

    [[nodiscard]] static WalkBudget from(const Limits& lim) {
        return {lim.max_walk_entries,
                std::chrono::steady_clock::now() + std::chrono::seconds(lim.max_walk_seconds)};
    }
    [[nodiscard]] bool exhausted() const noexcept {
        return remaining_entries == 0 || std::chrono::steady_clock::now() >= deadline;
    }
    void charge(std::size_t n) noexcept { remaining_entries -= std::min(n, remaining_entries); }
};

/// Opens <root>/<prefix>/<components...> one hop at a time: the prefix root with
/// an O_NOFOLLOW open, then each component with openat + O_NOFOLLOW. Opening the
/// joined string in one call would guard only its FINAL component -- the kernel
/// still resolves every intermediate one through symlink-following path
/// resolution -- so a swapped-in prefix or Library link would be read as the
/// real thing (mirrors autoruns_macos.cpp's open_dir_no_follow_at_checked chain
/// for the identical reason). The prefix root's own parents (/opt, /usr) are
/// owned by the OS, so the one-string open of it is the trusted injected root
/// plus a fixed literal. `absent` means some hop is ENOENT; `detail` names any
/// other failure (a symlink is `symlink_refused` / `not_a_directory`).
[[nodiscard]] inline posix::OpenDirResult
open_under_prefix(const std::filesystem::path& root, std::string_view prefix,
                  std::initializer_list<std::string_view> components) {
    auto cur = posix::open_dir_no_follow(under(root, prefix));
    for (const auto component : components) {
        if (!cur.dir.valid()) return cur; // absent, or a real failure: stop at this hop
        const std::string name{component};
        cur = posix::open_dir_no_follow_at(cur.dir, name.c_str());
    }
    return cur;
}

/// Result of counting the real, well-named subdirectories of an open directory.
struct SubdirCount {
    std::size_t count = 0;
    bool ok = true; ///< false when a per-entry stat failed (token already in acc)
};

/// Counts the subdirectories of `dir` that pass version_dir_name_ok, recording
/// listing truncation and per-entry stat failures under `source`. The listing
/// is charged to `budget`; the caller decides when to check it.
[[nodiscard]] inline SubdirCount count_subdirs(const posix::Dir& dir, std::string_view source,
                                               const Limits& lim,
                                               yuzu::shared::ConstraintAccumulator& acc,
                                               WalkBudget& budget) {
    SubdirCount out;
    const auto listing = posix::list_names(dir, lim.max_entries_per_dir);
    posix::note_listing(acc, kOs, source, listing);
    budget.charge(listing.names.size());
    for (const auto& name : listing.names) {
        if (!version_dir_name_ok(name)) continue;
        const auto cls = posix::classify_entry(dir, name.c_str());
        if (cls.kind == posix::EntryKind::error) {
            acc.add_failure(make_token(kOs, source, cls.detail));
            out.ok = false;
            continue;
        }
        if (cls.kind == posix::EntryKind::directory) ++out.count;
    }
    return out;
}

/// What one marker directory looked like.
struct MarkerState {
    bool exists = false;   ///< opened, or failed for a reason other than absence
    bool readable = false; ///< opened
};

/// Counts <prefix>/<rel> subdirectories. Absent -> count 0 (marker not
/// existing); a failed open -> nullopt and a token. `state` reports whether the
/// marker exists/was readable so the caller can decide Homebrew presence.
[[nodiscard]] inline std::optional<std::size_t>
count_marker(const std::filesystem::path& root, std::string_view prefix, std::string_view rel,
             std::string_view source, MarkerState& state, const Limits& lim,
             yuzu::shared::ConstraintAccumulator& acc, WalkBudget& budget) {
    auto opened = open_under_prefix(root, prefix, {rel});
    if (opened.absent) return std::size_t{0};
    state.exists = true;
    if (!opened.detail.empty()) {
        acc.add_failure(make_token(kOs, source, opened.detail));
        return std::nullopt;
    }
    state.readable = true;
    const auto c = count_subdirs(opened.dir, source, lim, acc, budget);
    // A per-entry stat failure makes the count a lower bound: omit it.
    if (!c.ok) return std::nullopt;
    return c.count;
}

/// Counts Library/Taps/<org>/<repo>: the well-named directories one level down
/// inside each org directory. This is the one NESTED walk in `managers` (up to
/// max_entries_per_dir orgs x max_entries_per_dir repos), so the whole-action
/// budget is checked before every org: tripping it records `walk_budget` and
/// omits the count (a lower bound is not a fact), like a per-entry stat failure.
[[nodiscard]] inline std::optional<std::size_t>
count_taps(const std::filesystem::path& root, std::string_view prefix, MarkerState& state,
           const Limits& lim, yuzu::shared::ConstraintAccumulator& acc, WalkBudget& budget) {
    constexpr std::string_view source = "homebrew_taps";
    auto opened = open_under_prefix(root, prefix, {"Library", "Taps"});
    if (opened.absent) return std::size_t{0};
    state.exists = true;
    if (!opened.detail.empty()) {
        acc.add_failure(make_token(kOs, source, opened.detail));
        return std::nullopt;
    }
    state.readable = true;
    const auto orgs = posix::list_names(opened.dir, lim.max_entries_per_dir);
    posix::note_listing(acc, kOs, source, orgs);
    budget.charge(orgs.names.size());
    std::size_t taps = 0;
    bool ok = true;
    for (const auto& org : orgs.names) {
        if (!version_dir_name_ok(org)) continue;
        const auto cls = posix::classify_entry(opened.dir, org.c_str());
        if (cls.kind == posix::EntryKind::error) {
            acc.add_failure(make_token(kOs, source, cls.detail));
            ok = false;
            continue;
        }
        if (cls.kind != posix::EntryKind::directory) continue;
        if (budget.exhausted()) {
            acc.add_failure(make_token(kOs, source, "walk_budget"));
            acc.mark_incomplete();
            ok = false;
            break;
        }
        auto org_dir = posix::open_dir_no_follow_at(opened.dir, org.c_str());
        if (!org_dir.dir.valid()) {
            if (!org_dir.absent) {
                acc.add_failure(make_token(kOs, source, org_dir.detail));
                ok = false;
            }
            continue;
        }
        const auto c = count_subdirs(org_dir.dir, source, lim, acc, budget);
        taps += c.count;
        if (!c.ok) ok = false;
    }
    if (!ok) return std::nullopt;
    return taps;
}

/// Appends one package row per <container>/<name>/<version> directory under
/// <prefix>/<rel> (rel = "Cellar" or "Caskroom"). Stops at lim.max_package_rows
/// (`row_cap`) or, first, at `budget` (`walk_budget`); see WalkBudget for why
/// the per-directory cap alone does not bound the action. Returns true when it
/// stopped on the budget and recorded `walk_budget` itself, so the caller does
/// not also have to. Exhaustion that leaves NOTHING of this container unread
/// (the last id was already walked, or only non-directory entries remained)
/// records nothing here: the caller records it iff a later container is skipped.
[[nodiscard]] inline bool
append_package_rows(const std::filesystem::path& root, std::string_view prefix,
                    std::string_view rel, std::string_view source, PackageKind kind,
                    const Limits& lim, std::vector<std::string>& rows,
                    yuzu::shared::ConstraintAccumulator& acc, WalkBudget& budget) {
    auto top = open_under_prefix(root, prefix, {rel});
    if (top.absent) return false;
    if (!top.detail.empty()) {
        acc.add_failure(make_token(kOs, source, top.detail));
        return false;
    }
    const auto names = posix::list_names(top.dir, lim.max_entries_per_dir);
    posix::note_listing(acc, kOs, source, names);
    budget.charge(names.names.size());
    for (const auto& id : names.names) {
        if (!version_dir_name_ok(id)) continue;
        const auto cls = posix::classify_entry(top.dir, id.c_str());
        if (cls.kind == posix::EntryKind::error) {
            acc.add_failure(make_token(kOs, source, cls.detail));
            continue;
        }
        if (cls.kind != posix::EntryKind::directory) continue;
        if (budget.exhausted()) {
            // Stop before starting the next id-directory's version listing --
            // rows already appended below (from ids already fully walked)
            // stay: this is a constraint, not a discard.
            acc.add_failure(make_token(kOs, source, "walk_budget"));
            acc.mark_incomplete();
            return true;
        }
        auto id_dir = posix::open_dir_no_follow_at(top.dir, id.c_str());
        if (!id_dir.dir.valid()) {
            if (!id_dir.absent) acc.add_failure(make_token(kOs, source, id_dir.detail));
            continue;
        }
        const auto versions = posix::list_names(id_dir.dir, lim.max_entries_per_dir);
        posix::note_listing(acc, kOs, source, versions);
        budget.charge(versions.names.size());
        for (const auto& version : versions.names) {
            if (!version_dir_name_ok(version)) continue;
            const auto vcls = posix::classify_entry(id_dir.dir, version.c_str());
            if (vcls.kind == posix::EntryKind::error) {
                acc.add_failure(make_token(kOs, source, vcls.detail));
                continue;
            }
            if (vcls.kind != posix::EntryKind::directory) continue;
            if (rows.size() >= lim.max_package_rows) {
                acc.add_failure(make_token(kOs, source, "row_cap"));
                acc.mark_incomplete();
                return false;
            }
            rows.push_back(format_package_row(id, version, kind));
        }
    }
    return false;
}

/// Folds `from`'s comma-joined tokens into `into` (ConstraintAccumulator has no
/// merge; tokens never contain a comma, so the split is lossless).
inline void merge_tokens(yuzu::shared::ConstraintAccumulator& into,
                         const yuzu::shared::ConstraintAccumulator& from) {
    const std::string joined = from.reason();
    std::size_t pos = 0;
    while (pos < joined.size()) {
        const auto comma = joined.find(',', pos);
        const auto end = comma == std::string::npos ? joined.size() : comma;
        into.add_failure(std::string_view{joined}.substr(pos, end - pos));
        pos = end + 1;
    }
    if (from.incomplete()) into.mark_incomplete();
}

} // namespace detail

/// One `manager|homebrew|...` row per Homebrew prefix detected under `root`
/// (see the header banner for the two-prefix and marker rules). Facts:
/// `taps=N;formulae=N;casks=N` (a fact is omitted when its directory could not
/// be read). No Homebrew anywhere -> zero rows and no constraint. `token` is
/// set (comma-joined failure tokens) iff any read failed. `lim` is the
/// resource-bound set (production: the defaults); the whole-action
/// entries/wall-clock budget covers every prefix and marker.
[[nodiscard]] inline std::vector<std::string>
macos_manager_rows_at(const std::filesystem::path& root, std::optional<std::string>& token,
                      const Limits& lim = Limits{}) {
    token.reset();
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<std::string> rows;
    auto budget = detail::WalkBudget::from(lim);
    for (const auto prefix : detail::kPrefixes) {
        // Per-prefix accumulator: an `unavailable` row's reason must name only
        // this prefix's failures, while the status row sees every prefix's.
        yuzu::shared::ConstraintAccumulator pacc;
        detail::MarkerState state;
        const auto taps = detail::count_taps(root, prefix, state, lim, pacc, budget);
        const auto formulae = detail::count_marker(root, prefix, "Cellar", "homebrew_cellar", state,
                                                   lim, pacc, budget);
        const auto casks = detail::count_marker(root, prefix, "Caskroom", "homebrew_caskroom", state,
                                                lim, pacc, budget);
        detail::merge_tokens(acc, pacc);
        if (!state.exists) continue; // no Homebrew marker under this prefix
        Facts f;
        if (taps) f.add("taps", *taps);
        if (formulae) f.add("formulae", *formulae);
        if (casks) f.add("casks", *casks);
        if (state.readable) {
            rows.push_back(format_manager_row(Manager::homebrew, Presence::present, "",
                                              detail::logical(prefix), f.str(), ""));
        } else {
            // Something is there but nothing could be read: the reason field
            // carries this prefix's tokens.
            rows.push_back(format_manager_row(Manager::homebrew, Presence::unavailable, "",
                                              detail::logical(prefix), "-", pacc.reason()));
        }
    }
    if (acc.any_failure()) token = acc.reason();
    return rows;
}

/// One `package|homebrew|<id>|<version>|<formula|cask>` row per
/// Cellar/<formula>/<version> and Caskroom/<cask>/<version> directory, over
/// both prefixes, capped at lim.max_package_rows (`row_cap`) and, whole-action,
/// at lim.max_walk_entries/max_walk_seconds (`walk_budget`). Sorted within
/// each (prefix, kind) block, so output is deterministic.
[[nodiscard]] inline std::vector<std::string>
macos_package_rows_at(const std::filesystem::path& root, std::optional<std::string>& token,
                      const Limits& lim = Limits{}) {
    token.reset();
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<std::string> rows;
    auto budget = detail::WalkBudget::from(lim);
    // `walk_budget` is recorded once: by append_package_rows when it trips inside a
    // container, otherwise here, at the first container the exhausted budget makes
    // us skip (a budget that dies exactly at a container boundary, or on a listing
    // of only non-directory entries, would otherwise skip the rest silently).
    bool budget_recorded = false;
    [&] {
        for (const auto prefix : detail::kPrefixes) {
            for (const auto& c : detail::kContainers) {
                if (budget.exhausted()) {
                    if (!budget_recorded) {
                        acc.add_failure(make_token(detail::kOs, c.source, "walk_budget"));
                        acc.mark_incomplete();
                    }
                    return;
                }
                if (detail::append_package_rows(root, prefix, c.rel, c.source, c.kind, lim, rows,
                                                acc, budget))
                    budget_recorded = true;
            }
        }
    }();
    if (acc.any_failure()) token = acc.reason();
    return rows;
}

/// The production macOS leg body over an INJECTED root: runs the action's walk
/// and hands rows + constraint to the one emission seam (emit_result), so the
/// wire status row and the CC-07 typed status are produced here. run_macos
/// (pkg_inventory_macos.cpp) calls it with "/"; the unit suite drives it over a
/// fixture tree through a real CommandContext. MUTATION: passing std::nullopt
/// instead of `constraint` below fails the forced-constraint seam case in
/// test_pkg_inventory_macos_parsers.cpp.
inline int run_macos_at(yuzu::CommandContext& ctx, Action a, const std::filesystem::path& root) {
    std::optional<std::string> constraint;
    std::vector<std::string> rows;
    switch (a) {
    case Action::managers: rows = macos_manager_rows_at(root, constraint); break;
    case Action::packages: rows = macos_package_rows_at(root, constraint); break;
    }
    emit_result(ctx, a, rows, constraint);
    return 0;
}

} // namespace yuzu::pkg_inventory::mac

#endif // !defined(_WIN32)
