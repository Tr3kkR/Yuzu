/**
 * pkg_inventory_linux_parsers.hpp — the Linux `managers` walk, over an INJECTED
 * ROOT (the peripherals_linux_parsers.hpp precedent: production passes "/",
 * the unit suite passes a materialized fixture tree).
 *
 * Linux reports package-manager IDENTITY/PRESENCE and manager-level CONFIG
 * FACTS only (Alex, 2026-09-19, "shrink"). It never enumerates individual
 * packages in any form: installed_apps.get_inventory_linux owns the roster.
 * There is deliberately no `linux_package_rows_at` -- the Linux `packages`
 * action is UNSUPPORTED by construction (see pkg_inventory_linux.cpp).
 *
 * Never spawns a process (no dpkg-query / rpm / pacman / apk), and never opens
 * /var/lib/dpkg/status. Presence is a stat + X_OK probe of the tool path
 * resolved under `root` (yuzu::agent::probe_tool_path takes absolute
 * candidates only and has no root parameter, so injection is by passing
 * `<root>/usr/bin/dpkg` -- the tree must give the file mode 0755). When the
 * probe finds nothing, each candidate is stat()ed once more so a lookup FAILURE
 * (EACCES on a parent directory, ELOOP, EIO) is recorded as a constraint token
 * instead of reading as an uninstalled manager; only ENOENT/ENOTDIR are absence.
 *
 * Compiled on POSIX only (posix_dir_walk.hpp does not exist on Windows); the
 * portable row/text layer is pkg_inventory_parsers.hpp, the guarded walk
 * primitives (`posix::`) are in pkg_inventory_legs.hpp.
 */
#pragma once

#if !defined(_WIN32)

#include "pkg_inventory_legs.hpp"
#include "pkg_inventory_parsers.hpp"

#include <yuzu/agent/subprocess_runner.hpp>

#include <constraint_accumulator.hpp>

#include <sys/stat.h>

#include <cerrno>
#include <filesystem>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::pkg_inventory::lnx {

namespace detail {

inline constexpr std::string_view kOs = "linux";

/// `root / rel` as an absolute path string (probe_tool_path and the open()
/// calls need one; a relative test root is resolved against the cwd).
[[nodiscard]] inline std::string under(const std::filesystem::path& root, std::string_view rel) {
    std::error_code ec;
    auto base = std::filesystem::absolute(root, ec);
    if (ec) base = root;
    return (base / std::string{rel}).string();
}

/// True when any `rels` entry resolves under `root` to an executable regular
/// file. No process is spawned. `false` is "absent" ONLY when every candidate
/// failed with ENOENT/ENOTDIR (or exists but is not an executable regular
/// file); any other lookup errno is a real constraint recorded in `acc` under
/// `source` -- an inaccessible manager must not read as an uninstalled one.
[[nodiscard]] inline bool tool_present_at(const std::filesystem::path& root,
                                          std::initializer_list<std::string_view> rels,
                                          std::string_view source,
                                          yuzu::shared::ConstraintAccumulator& acc) {
    std::vector<std::string> candidates;
    for (const auto rel : rels)
        candidates.push_back(under(root, rel));
    if (!yuzu::agent::probe_tool_path(candidates).empty()) return true;
    for (const auto& candidate : candidates) {
        struct stat st{};
        if (::stat(candidate.c_str(), &st) == 0) continue; // exists, not an executable file
        const int err = errno;
        if (err == ENOENT || err == ENOTDIR) continue;
        acc.add_failure(make_token(kOs, source, open_failure_token(err)));
    }
    return false;
}

/// Reads `<root>/<rel>` (bounded, O_NOFOLLOW). Absent -> nullopt and NO
/// failure (a manager may legitimately lack the file); a real failure -> a
/// token in `acc` and nullopt; oversized -> a token in `acc` and the capped
/// prefix (any count derived from it is a lower bound, flagged constrained).
[[nodiscard]] inline std::optional<std::string>
read_text(const std::filesystem::path& root, std::string_view rel, std::string_view source,
          const Limits& lim, yuzu::shared::ConstraintAccumulator& acc) {
    auto r = posix::read_file_bounded(under(root, rel), lim.max_config_bytes);
    if (r.absent) return std::nullopt;
    if (!r.detail.empty()) {
        acc.add_failure(make_token(kOs, source, r.detail));
        return std::nullopt;
    }
    if (r.oversized) {
        acc.add_failure(make_token(kOs, source, "oversized"));
        acc.mark_incomplete();
    }
    return std::move(r.text);
}

/// Number of FILES in `<root>/<rel>` whose name ends in one of `suffixes`. A
/// directory (or fifo/socket/device) that merely has a matching name is not a
/// source file; symlinks count (apt and dnf accept a linked source file; the
/// link target is not resolved). An absent directory counts 0 (a manager with
/// no source files has zero); a failed open / a truncated or errored listing /
/// a failed per-entry stat is recorded in `acc`, and an open failure or stat
/// failure returns nullopt so the caller omits the fact rather than reporting a
/// false (lower-bound) count.
[[nodiscard]] inline std::optional<std::size_t>
count_entries_with_suffix(const std::filesystem::path& root, std::string_view rel,
                          std::initializer_list<std::string_view> suffixes,
                          std::string_view source, const Limits& lim,
                          yuzu::shared::ConstraintAccumulator& acc) {
    auto opened = posix::open_dir_no_follow(under(root, rel));
    if (opened.absent) return std::size_t{0};
    if (!opened.detail.empty()) {
        acc.add_failure(make_token(kOs, source, opened.detail));
        return std::nullopt;
    }
    const auto listing = posix::list_names(opened.dir, lim.max_entries_per_dir);
    posix::note_listing(acc, kOs, source, listing);
    std::size_t n = 0;
    bool ok = true;
    for (const auto& name : listing.names) {
        const bool named = std::any_of(suffixes.begin(), suffixes.end(), [&](std::string_view suffix) {
            return has_suffix(name, suffix);
        });
        if (!named) continue;
        const auto cls = posix::classify_entry(opened.dir, name.c_str());
        if (cls.kind == posix::EntryKind::error) {
            acc.add_failure(make_token(kOs, source, cls.detail));
            ok = false;
            continue;
        }
        if (cls.kind == posix::EntryKind::regular || cls.kind == posix::EntryKind::symlink) ++n;
    }
    if (!ok) return std::nullopt;
    return n;
}

/// Line count of `<root>/<rel>` via count_nonblank_noncomment_lines. Absent
/// file -> 0; failure -> nullopt (fact omitted) with the token in `acc`.
[[nodiscard]] inline std::optional<std::size_t>
count_lines(const std::filesystem::path& root, std::string_view rel, std::string_view source,
            const Limits& lim, yuzu::shared::ConstraintAccumulator& acc) {
    auto r = posix::read_file_bounded(under(root, rel), lim.max_config_bytes);
    if (r.absent) return std::size_t{0};
    if (!r.detail.empty()) {
        acc.add_failure(make_token(kOs, source, r.detail));
        return std::nullopt;
    }
    if (r.oversized) {
        acc.add_failure(make_token(kOs, source, "oversized"));
        acc.mark_incomplete();
    }
    return count_nonblank_noncomment_lines(r.text);
}

inline void add_count(Facts& f, std::string_view key, const std::optional<std::size_t>& v) {
    if (v) f.add(key, *v);
}

/// Adds `<key>=<a,b,...>` from an architecture-list file (dpkg/arch,
/// apk/arch). A malformed line is a constrained token, never dropped silently.
inline void add_arch_fact(Facts& f, std::string_view key, const std::filesystem::path& root,
                          std::string_view rel, std::string_view source, const Limits& lim,
                          yuzu::shared::ConstraintAccumulator& acc) {
    const auto text = read_text(root, rel, source, lim, acc);
    if (!text) return;
    const auto parsed = parse_dpkg_arch_file(*text);
    if (parsed.rejected > 0) acc.add_failure(make_token(kOs, source, "malformed"));
    if (!parsed.arches.empty()) f.add(key, join_arches(parsed.arches));
}

} // namespace detail

/// One `manager|...` row per package manager whose tool is present under
/// `root`, in a fixed order (dpkg, apt, rpm, dnf, pacman, apk). An absent
/// manager produces NO row and no constraint. `token` is set (comma-joined
/// failure tokens) iff any read failed; the caller renders the status row from
/// it. `root_path` in a row is the LOGICAL path ("/etc/apt"), never the
/// injected root. `lim` is the resource-bound set (production: the defaults).
[[nodiscard]] inline std::vector<std::string>
linux_manager_rows_at(const std::filesystem::path& root, std::optional<std::string>& token,
                      const Limits& lim = Limits{}) {
    token.reset();
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<std::string> rows;
    using detail::add_arch_fact;
    using detail::add_count;
    using detail::count_entries_with_suffix;
    using detail::count_lines;
    using detail::tool_present_at;

    if (tool_present_at(root, {"usr/bin/dpkg", "bin/dpkg"}, "dpkg_tool", acc)) {
        Facts f;
        add_arch_fact(f, "architectures", root, "var/lib/dpkg/arch", "dpkg_arch", lim, acc);
        rows.push_back(
            format_manager_row(Manager::dpkg, Presence::present, "", "/var/lib/dpkg", f.str(), ""));
    }
    if (tool_present_at(root, {"usr/bin/apt-get", "bin/apt-get"}, "apt_tool", acc)) {
        Facts f;
        add_count(f, "sources_list_lines",
                  count_lines(root, "etc/apt/sources.list", "apt_sources_list", lim, acc));
        add_count(f, "sources_d_files",
                  count_entries_with_suffix(root, "etc/apt/sources.list.d", {".list", ".sources"},
                                            "apt_sources_d", lim, acc));
        rows.push_back(
            format_manager_row(Manager::apt, Presence::present, "", "/etc/apt", f.str(), ""));
    }
    if (tool_present_at(root, {"usr/bin/rpm", "bin/rpm"}, "rpm_tool", acc)) {
        // Presence only: the rpm database location differs across distros
        // (/var/lib/rpm vs /usr/lib/sysimage/rpm) and is not read here.
        rows.push_back(format_manager_row(Manager::rpm, Presence::present, "", "", "-", ""));
    }
    if (tool_present_at(root, {"usr/bin/dnf", "usr/bin/dnf5", "bin/dnf"}, "dnf_tool", acc)) {
        Facts f;
        add_count(f, "repo_files",
                  count_entries_with_suffix(root, "etc/yum.repos.d", {".repo"}, "dnf_repos_d", lim, acc));
        add_count(f, "dnf_conf_lines", count_lines(root, "etc/dnf/dnf.conf", "dnf_conf", lim, acc));
        rows.push_back(
            format_manager_row(Manager::dnf, Presence::present, "", "/etc/dnf", f.str(), ""));
    }
    if (tool_present_at(root, {"usr/bin/pacman", "bin/pacman"}, "pacman_tool", acc)) {
        Facts f;
        add_count(f, "pacman_conf_lines", count_lines(root, "etc/pacman.conf", "pacman_conf", lim, acc));
        add_count(f, "mirrors", count_lines(root, "etc/pacman.d/mirrorlist", "pacman_mirrorlist", lim, acc));
        rows.push_back(format_manager_row(Manager::pacman, Presence::present, "", "/etc/pacman.d",
                                          f.str(), ""));
    }
    if (tool_present_at(root, {"sbin/apk", "usr/sbin/apk", "usr/bin/apk"}, "apk_tool", acc)) {
        Facts f;
        if (const auto text = detail::read_text(root, "etc/apk/repositories", "apk_repositories", lim, acc)) {
            const auto repos = parse_apk_repositories(*text);
            f.add("repositories", repos.count);
            f.add("tagged", repos.tagged);
        }
        add_arch_fact(f, "arch", root, "etc/apk/arch", "apk_arch", lim, acc);
        rows.push_back(
            format_manager_row(Manager::apk, Presence::present, "", "/etc/apk", f.str(), ""));
    }

    if (acc.any_failure()) token = acc.reason();
    return rows;
}

} // namespace yuzu::pkg_inventory::lnx

#endif // !defined(_WIN32)
