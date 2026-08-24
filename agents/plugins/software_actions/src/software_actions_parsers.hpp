#pragma once

/**
 * software_actions_parsers.hpp — pure parse helpers for the software_actions
 * plugin (winget/apt/yum/softwareupdate/dpkg-query output).
 *
 * Header-only and OS-free (no windows.h, no POSIX, no subprocesses) so the
 * parsing is unit-tested on every host (the firewall_parsers.hpp /
 * services_parsers.hpp pattern); the run_bounded_subprocess acquisition in
 * software_actions_plugin.cpp is the impure shell.
 *
 * Every emit string these feed stays byte-compatible with the plugin's
 * pre-migration `upgradable|...`/`count|N` output contract — only the
 * acquisition mechanism (popen -> bounded argv runner) changed.
 */

#include <cstddef>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::software_actions {

namespace detail {

/// Split `out` on '\n', stripping a trailing '\r' from each physical line
/// and dropping lines that are empty after that strip — matches the old
/// run_command_lines() popen helper's line contract exactly, so lifting the
/// parsing logic below out of the plugin changes nothing about what it sees.
[[nodiscard]] inline std::vector<std::string> split_nonblank_lines(std::string_view out) {
    std::vector<std::string> lines;
    std::string buf(out); // istringstream needs an owned string
    std::istringstream iss(buf);
    std::string line;
    while (std::getline(iss, line)) {
        while (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            lines.push_back(std::move(line));
    }
    return lines;
}

} // namespace detail

// ── Windows: winget upgrade ────────────────────────────────────────────────

struct WingetUpgradeRow {
    std::string name;
    std::string current_version;
    std::string available_version;
};

struct WingetUpgradeParse {
    std::vector<WingetUpgradeRow> rows;
    // True once the fixed-width header's dashed separator line was found —
    // distinguishes "winget ran but produced no recognisable table at all"
    // (separator_found stays false; the caller emits `upgradable|none|-|-`)
    // from "winget ran, found the table, and it has zero data rows" (a
    // genuine up-to-date system; the caller emits the "System is up to
    // date" line) — the same two-shape distinction the original popen-based
    // code made via `lines.empty()` vs `!found_any`.
    bool separator_found = false;
};

/// Parse `winget upgrade --accept-source-agreements` output. winget uses
/// fixed-width columns (Name / Id / Version / Available / Source); columns
/// are split on runs of 2+ spaces, single spaces inside a column value are
/// preserved. Footer lines ("N upgrades available") are skipped by their own
/// "upgrade"+"available" substring pair, matching the pre-migration parser.
[[nodiscard]] inline WingetUpgradeParse parse_winget_upgrade(std::string_view output) {
    WingetUpgradeParse result;
    bool in_data = false;
    for (const auto& line : detail::split_nonblank_lines(output)) {
        if (!in_data) {
            // Look for the separator line (all dashes/spaces).
            bool is_sep = !line.empty();
            for (char ch : line) {
                if (ch != '-' && ch != ' ') {
                    is_sep = false;
                    break;
                }
            }
            if (is_sep && line.size() > 10) {
                in_data = true;
                result.separator_found = true;
            }
            continue;
        }
        // Skip footer lines (e.g. "N upgrades available").
        if (line.find("upgrade") != std::string::npos &&
            line.find("available") != std::string::npos) {
            continue;
        }

        // Typical format: "Name            Id              Version  Available"
        // Split on multiple spaces.
        std::vector<std::string> parts;
        std::string current;
        int spaces = 0;
        for (char ch : line) {
            if (ch == ' ') {
                spaces++;
                if (spaces >= 2 && !current.empty()) {
                    parts.push_back(current);
                    current.clear();
                    spaces = 0;
                }
            } else {
                if (spaces > 0 && spaces < 2) {
                    current += std::string(static_cast<std::size_t>(spaces), ' ');
                }
                spaces = 0;
                current += ch;
            }
        }
        if (!current.empty())
            parts.push_back(current);

        if (parts.size() >= 4) {
            result.rows.push_back({parts[0], parts[2], parts[3]});
        } else if (parts.size() >= 2) {
            result.rows.push_back({parts[0], "-", "-"});
        }
    }
    return result;
}

// ── Linux: apt list --upgradable ───────────────────────────────────────────

struct AptUpgradeRow {
    std::string name;
    std::string old_version;
    std::string new_version;
};

/// Parse `apt list --upgradable` output: "name/repo new_ver arch [upgradable
/// from: old_ver]" per line, "Listing..." banner skipped.
[[nodiscard]] inline std::vector<AptUpgradeRow> parse_apt_list_upgradable(std::string_view output) {
    std::vector<AptUpgradeRow> rows;
    for (const auto& line : detail::split_nonblank_lines(output)) {
        if (line.starts_with("Listing"))
            continue;
        auto slash = line.find('/');
        auto space = line.find(' ');
        if (slash != std::string::npos && space != std::string::npos) {
            auto name = line.substr(0, slash);
            auto rest = line.substr(space + 1);
            auto ver_end = rest.find(' ');
            auto new_ver = (ver_end != std::string::npos) ? rest.substr(0, ver_end) : rest;
            std::string old_ver = "-";
            auto from_pos = rest.find("from: ");
            if (from_pos != std::string::npos) {
                old_ver = rest.substr(from_pos + 6);
                auto bracket = old_ver.find(']');
                if (bracket != std::string::npos)
                    old_ver = old_ver.substr(0, bracket);
            }
            rows.push_back({std::move(name), std::move(old_ver), std::move(new_ver)});
        }
    }
    return rows;
}

// ── Linux: yum/dnf check-update ────────────────────────────────────────────

struct YumUpgradeRow {
    std::string name;
    std::string new_version;
};

/// yum/dnf `check-update` exit-code contract: 0 = ran, nothing to update
/// (success); 100 = ran, updates ARE available (ALSO success — "success with
/// data", not a failure); any other code is a genuine tool failure. The old
/// popen-based code never inspected the exit code at all (popen only exposes
/// stdout), so this is a strictly more honest decision than what it replaces
/// — the new runner-based call site must NOT regress by treating 100 as an
/// error.
[[nodiscard]] constexpr bool yum_checkupdate_is_success(int exit_code) {
    return exit_code == 0 || exit_code == 100;
}

/// Parse `yum check-update` / `dnf check-update` output: "package.arch
/// new_version repo" per line, "Loaded"/"Loading"/"Last metadata" banner
/// lines skipped.
[[nodiscard]] inline std::vector<YumUpgradeRow> parse_yum_checkupdate(std::string_view output) {
    std::vector<YumUpgradeRow> rows;
    for (const auto& line : detail::split_nonblank_lines(output)) {
        if (line.starts_with("Loaded") || line.starts_with("Loading"))
            continue;
        if (line.starts_with("Last metadata"))
            continue;
        std::string name, version;
        std::size_t pos = 0;
        while (pos < line.size() && line[pos] != ' ' && line[pos] != '\t')
            pos++;
        name = line.substr(0, pos);
        while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t'))
            pos++;
        auto ver_start = pos;
        while (pos < line.size() && line[pos] != ' ' && line[pos] != '\t')
            pos++;
        version = line.substr(ver_start, pos - ver_start);
        if (!name.empty())
            rows.push_back({std::move(name), std::move(version)});
    }
    return rows;
}

// ── macOS: softwareupdate -l ───────────────────────────────────────────────

/// Parse `softwareupdate -l` output into a list of upgradable labels/titles.
/// Boilerplate lines ("Software Update Tool", "Finding available software",
/// "No new software available.") are skipped; "* Label: X" lines yield X;
/// any other non-Title/Size/Recommended/Action line under a "*"-prefixed
/// entry is emitted verbatim, matching the pre-migration parser exactly.
[[nodiscard]] inline std::vector<std::string> parse_softwareupdate_list(std::string_view output) {
    std::vector<std::string> labels;
    for (const auto& line : detail::split_nonblank_lines(output)) {
        auto trimmed = line;
        auto start = trimmed.find_first_not_of(" \t*");
        if (start == std::string::npos)
            continue;
        trimmed = trimmed.substr(start);
        if (trimmed.empty())
            continue;
        if (trimmed.starts_with("Software Update") || trimmed.starts_with("Finding") ||
            trimmed.starts_with("No new"))
            continue;
        if (trimmed.find("Label:") != std::string::npos) {
            labels.push_back(trimmed.substr(trimmed.find(':') + 2));
        } else if (!trimmed.starts_with("Title:") && !trimmed.starts_with("Size:") &&
                   !trimmed.starts_with("Recommended:") && !trimmed.starts_with("Action:")) {
            labels.push_back(trimmed);
        }
    }
    return labels;
}

// ── Linux: dpkg-query status-abbrev count ──────────────────────────────────

/// Count lines from `dpkg-query -W -f='${db:Status-Abbrev}\n'` output whose
/// 2nd character is 'i' — matches the repo's installed-and-held filter
/// convention (installed_apps_inventory.hpp's parse_dpkg_inv_line / vuln_scan's
/// vuln_identity.hpp): "ii" (want=install) and "hi" (want=hold) count, "rc"
/// (removed) and "un" (unknown) do not.
[[nodiscard]] inline std::size_t count_dpkg_status_abbrev_installed(std::string_view output) {
    std::size_t count = 0;
    for (const auto& line : detail::split_nonblank_lines(output)) {
        if (line.size() >= 2 && line[1] == 'i')
            ++count;
    }
    return count;
}

/// Generic "one record per non-empty line" count (`rpm -qa`, `pkgutil --pkgs`).
[[nodiscard]] inline std::size_t count_nonempty_lines(std::string_view output) {
    return detail::split_nonblank_lines(output).size();
}

} // namespace yuzu::software_actions
