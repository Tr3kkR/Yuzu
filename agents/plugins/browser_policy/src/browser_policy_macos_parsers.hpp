/**
 * browser_policy_macos_parsers.hpp — INJECTED-ROOT macOS Managed Preferences
 * walk.
 *
 * NOVEL SEAM. peripherals' injected-root precedent is Linux-only
 * (peripherals_macos.cpp has no `_at` variant), so `macos_policy_rows_at` has
 * no template: it takes a `root` path exactly like lnx::linux_policy_rows_at,
 * production (browser_policy_macos.cpp) passes "/", and the unit suite passes
 * a temp tree materialized from tests/unit/fixtures/wave10/browser_policy/
 * macos/tree.manifest.
 *
 * WALK (all below <root>/Library/Managed Preferences, every component opened
 * with openat(O_NOFOLLOW|O_DIRECTORY) chained from the previous fd — the
 * hop-by-hop shape of autoruns_macos.cpp's collect_user_launchagents, whose
 * per-user directory walk this follows; the secure-read kit is the plugin's
 * own copy in browser_policy_linux_parsers.hpp `posix::`):
 *   1. machine scope: {com.google.Chrome,com.microsoft.Edge}.plist directly
 *      in the directory;
 *   2. user scope: every immediate SUBDIRECTORY (fstatat AT_SYMLINK_NOFOLLOW
 *      + S_ISDIR; a symlinked "user" entry is refused and reported as
 *      `macos:symlink_refused`) holds the same two
 *      plists, reported as scope `user:<directory name>` (the directory's own
 *      name, no Open Directory lookup — the autoruns mac_user_launchagents
 *      convention).
 * Users are visited in sorted order so output never depends on readdir order.
 *
 * ABSENT vs FAILED is the same contract as the Linux walk: ENOENT at any hop
 * or for any plist is genuine absence (a Mac with no managed Chrome/Edge
 * reports zero rows, OK); everything else — permission denied, a refused
 * symlink, oversized/unreadable file, undecodable plist, a truncated
 * directory listing — lands on the ConstraintAccumulator as a
 * `macos:<detail>` token and surfaces as CONSTRAINED. Rows that did read are
 * kept.
 *
 * Apple-only (CoreFoundation): the tree test that exercises this is
 * `#ifdef __APPLE__`; the pure row model is tested on every OS.
 */
#pragma once

#if defined(__APPLE__)

#include "browser_policy_legs.hpp"
#include "browser_policy_linux_parsers.hpp" // posix:: secure-read kit
#include "browser_policy_macos.hpp"

#include <constraint_accumulator.hpp>
#include <posix_dir_walk.hpp>

#include <sys/stat.h>

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::browser_policy::mac {

struct PlistName {
    Browser browser;
    const char* file;
};

inline constexpr PlistName kPlistNames[] = {
    {Browser::chrome, "com.google.Chrome.plist"},
    {Browser::edge, "com.microsoft.Edge.plist"},
};

/// Returns one formatted `policy|` row per managed policy key. `failure_reason`
/// is set (comma-joined `macos:<detail>` tokens) iff anything could not be
/// read or decoded; empty means a complete read (possibly zero rows).
[[nodiscard]] inline std::vector<std::string>
macos_policy_rows_at(const std::filesystem::path& root, std::string& failure_reason,
                     const WalkLimits& limits = {}) {
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<std::string> rows;
    failure_reason.clear();
    bool capped = false;

    auto finish = [&]() {
        failure_reason = acc.reason();
        return rows;
    };
    auto fail = [&](std::string_view detail) {
        acc.add_failure(std::string{"macos:"} + std::string{detail});
    };

    // Reads the two plists directly inside `dir_fd` under `scope`;
    // `dir_label` is the root-relative directory, for the row's source field.
    auto read_dir_plists = [&](int dir_fd, const std::string& scope, const std::string& dir_label) {
        for (const auto& spec : kPlistNames) {
            if (capped)
                return;
            auto file = posix::read_file_at(dir_fd, spec.file, limits.max_file_bytes);
            if (file.status == posix::OpenStatus::absent)
                continue;
            if (file.status == posix::OpenStatus::failed) {
                fail(file.detail);
                continue;
            }
            const std::string source = dir_label + "/" + spec.file;
            auto parsed = rows_from_plist_bytes(file.bytes, spec.browser, scope, source);
            if (parsed.failure)
                acc.add_failure(*parsed.failure);
            for (const auto& row : parsed.rows) {
                if (rows.size() >= limits.max_rows) {
                    acc.add_failure("macos:row_cap");
                    capped = true;
                    return;
                }
                rows.push_back(format_policy_row(row));
            }
        }
    };

    posix::DirOpen root_open = posix::open_root_dir(root);
    if (root_open.status == posix::OpenStatus::absent)
        return finish();
    if (root_open.status == posix::OpenStatus::failed) {
        fail(root_open.detail);
        return finish();
    }

    const char* const mp_chain[] = {"Library", "Managed Preferences"};
    posix::DirOpen mp = posix::open_dir_chain(root_open.dir.fd(), mp_chain);
    if (mp.status == posix::OpenStatus::failed)
        fail(mp.detail);
    if (mp.status != posix::OpenStatus::ok)
        return finish();

    const std::string mp_label = "/Library/Managed Preferences";
    const int mp_fd = mp.dir.fd();

    read_dir_plists(mp_fd, machine_scope(), mp_label);

    // Users: immediate real subdirectories (a plist file or a symlink is not one).
    bool stat_failed = false;
    bool symlink_refused = false;
    const auto users = posix::list_names(
        mp.dir,
        [&](const struct dirent* e) {
            struct stat st{};
            if (::fstatat(mp_fd, e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
                if (errno != ENOENT)
                    stat_failed = true; // a raced deletion is benign, anything else is not
                return false;
            }
            // A symlinked "user" entry is refused (never followed) — and reported: a
            // refusal must not read as "no such user". A symlinked *.plist is not a
            // user entry at all (read_file_at reports it if it is one we look for).
            if (S_ISLNK(st.st_mode) && !posix::ends_with(e->d_name, ".plist"))
                symlink_refused = true;
            return S_ISDIR(st.st_mode);
        },
        acc, "macos", limits.max_entries_per_dir);
    if (stat_failed)
        fail("stat_failed");
    if (symlink_refused)
        fail("symlink_refused");

    for (const auto& user : users) {
        if (capped)
            break;
        posix::DirOpen user_dir = posix::open_dir_at(mp_fd, user.c_str());
        if (user_dir.status == posix::OpenStatus::failed)
            fail(user_dir.detail);
        if (user_dir.status != posix::OpenStatus::ok)
            continue;
        read_dir_plists(user_dir.dir.fd(), user_scope(user), mp_label + "/" + user);
    }
    return finish();
}

} // namespace yuzu::browser_policy::mac

namespace yuzu::browser_policy {

/// The macOS leg body with the filesystem root injected (see run_linux_at):
/// run_macos passes "/", the unit suite passes a temp tree through a real
/// CommandContext so the status wiring is tested as production runs it.
inline int run_macos_at(yuzu::CommandContext& ctx, const std::filesystem::path& root,
                        const WalkLimits& limits = {}) {
    std::string failure_reason;
    const auto rows = mac::macos_policy_rows_at(root, failure_reason, limits);
    write_rows(ctx, rows);
    mark_result_read(ctx, failure_reason);
    return 0;
}

} // namespace yuzu::browser_policy

#endif // defined(__APPLE__)
