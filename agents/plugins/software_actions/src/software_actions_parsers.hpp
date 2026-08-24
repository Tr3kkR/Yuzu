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
#include <optional>
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

/// Offsets at which each whitespace-separated token of `header` begins.
/// winget renders a fixed-width table whose header names sit at the exact
/// column origins of the data beneath them, so the token starts ARE the
/// column boundaries. Only the positions are used, never the header text —
/// winget localises the column names, so reading the text would break on
/// every non-English Windows.
[[nodiscard]] inline std::vector<std::size_t> column_origins(std::string_view header) {
    std::vector<std::size_t> origins;
    bool in_token = false;
    for (std::size_t i = 0; i < header.size(); ++i) {
        const bool is_space = header[i] == ' ' || header[i] == '\t';
        if (!is_space && !in_token) {
            origins.push_back(i);
            in_token = true;
        } else if (is_space) {
            in_token = false;
        }
    }
    return origins;
}

/// `line[begin, end)` with surrounding blanks trimmed; empty when the slice
/// starts past the end of the line (a short row simply has empty tail columns).
[[nodiscard]] inline std::string slice_trimmed(const std::string& line, std::size_t begin,
                                               std::size_t end) {
    if (begin >= line.size())
        return {};
    end = end < line.size() ? end : line.size();
    const auto width = end - begin;
    const auto first = line.find_first_not_of(" \t", begin);
    if (first == std::string::npos || first >= begin + width)
        return {};
    const auto last = line.find_last_not_of(" \t", begin + width - 1);
    return line.substr(first, last - first + 1);
}

} // namespace detail

// ── Windows: winget upgrade ────────────────────────────────────────────────

/// winget upgrade renders five columns: Name / Id / Version / Available /
/// Source.
///
/// Positional slicing removes the dependency on the header TEXT, so a
/// translated header still parses -- but it assumes each localised column name
/// is a SINGLE token. A translation using a two-word column name yields more
/// than five origins and drops the table into the name-only degrade path. That
/// is an honest degrade, not a mis-parse, but it is not "localisation solved".
inline constexpr std::size_t kWingetColumnCount = 5;

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
    // Post-separator lines that looked like data but could not be mapped onto
    // the header's columns. Trailer prose lands here too, so a nonzero value is
    // not by itself an error -- but a row silently vanishing from an upgrade
    // report IS, so the caller reports PARTIAL completeness once any line is
    // dropped beyond the trailers it recognises.
    std::size_t unmapped_lines = 0;
    // True when the header line above the separator did NOT yield exactly
    // kWingetColumnCount column origins, so positional slicing was not
    // possible and rows were emitted name-only (`name|-|-`). Never means a
    // version was guessed: a version is either read from its own column or
    // reported as "-". The caller surfaces this as a CONSTRAINED/partial
    // result so an operator can tell "no upgrades" from "could not read the
    // version columns".
    bool header_unrecognized = false;
};

/// winget's post-table trailer lines ("23 upgrades available.", "N package(s)
/// have version numbers that cannot be determined. …"). Recognised so they are
/// never counted as dropped data rows, and never emitted as a phantom package
/// in the degraded name-only path. English-only by nature -- winget localises
/// these too -- so it is used ONLY to classify lines already rejected as data,
/// never to admit one.
[[nodiscard]] inline bool is_winget_trailer(const std::string& line) {
    const bool upgrades_available =
        line.find("upgrade") != std::string::npos && line.find("available") != std::string::npos;
    const bool undetermined_versions = line.find("package(s)") != std::string::npos &&
                                       line.find("version") != std::string::npos;
    return upgrades_available || undetermined_versions;
}

/// Parse `winget upgrade --accept-source-agreements` output.
///
/// winget renders a FIXED-WIDTH table (Name / Id / Version / Available /
/// Source), so columns are sliced by the byte offsets of the header's tokens
/// rather than guessed from runs of 2+ spaces. The old split-on-2+-spaces
/// heuristic silently mis-mapped every row whose content filled a column to
/// its full width and so was followed by a SINGLE space: those rows yielded
/// four fields instead of five, and reading `parts[3]` as the available
/// version handed back the *Source* column, emitting a literal
/// `available_version == "winget"`. Against a real 23-row capture from a
/// live Windows host, 4 rows reported "winget" as the available version and
/// a 5th collapsed to name-only — fabricated data of the same class as the
/// Wave-3 BitLocker/firewall false-state bugs. Positional slicing parses all
/// 23 of those rows exactly, including `Version == "< 17.14.35"` (a value
/// containing a space, which no space-delimited split can recover).
///
/// Only header token POSITIONS are used, never the header text: winget
/// localises the column names, so matching on "Name"/"Version" would break
/// on every non-English Windows.
///
/// Honesty contract: a line that does not map cleanly onto the header's
/// columns NEVER contributes a value borrowed from a neighbouring column. It
/// is either skipped (trailer lines such as "23 upgrades available." and the
/// "N package(s) have version numbers that cannot be determined" footer,
/// neither of which aligns to the Id column) or, when the header itself is
/// unreadable, emitted name-only as `name|-|-` with header_unrecognized set.
[[nodiscard]] inline WingetUpgradeParse parse_winget_upgrade(std::string_view output) {
    WingetUpgradeParse result;
    const auto lines = detail::split_nonblank_lines(output);

    std::size_t separator_index = lines.size();
    for (std::size_t i = 0; i < lines.size(); ++i) {
        bool is_sep = !lines[i].empty();
        for (char ch : lines[i]) {
            if (ch != '-' && ch != ' ') {
                is_sep = false;
                break;
            }
        }
        if (is_sep && lines[i].size() > 10) {
            separator_index = i;
            result.separator_found = true;
            break;
        }
    }
    if (!result.separator_found)
        return result;

    std::vector<std::size_t> origins;
    if (separator_index > 0)
        origins = detail::column_origins(lines[separator_index - 1]);
    const bool positional = origins.size() == kWingetColumnCount;
    result.header_unrecognized = !positional;

    for (std::size_t i = separator_index + 1; i < lines.size(); ++i) {
        const auto& line = lines[i];

        if (!positional) {
            // Header unreadable — emit the Name column only. The Name column
            // always begins at offset 0, so the text before the first run of
            // 2+ spaces is genuinely the name; the version columns are
            // reported as "-" rather than guessed.
            if (is_winget_trailer(line))
                continue;
            const auto gap = line.find("  ");
            auto name = detail::slice_trimmed(line, 0, gap == std::string::npos ? line.size() : gap);
            if (!name.empty())
                result.rows.push_back({std::move(name), "-", "-"});
            continue;
        }

        // A data row must respect every column boundary: the character
        // immediately before each column origin is a space (or the row ends
        // before that column). Trailer prose overflows its columns and fails
        // this check, so it can never become a phantom row.
        bool aligned = true;
        for (std::size_t c = 1; c < origins.size(); ++c) {
            const std::size_t origin = origins[c];
            if (origin < line.size() && line[origin - 1] != ' ') {
                aligned = false;
                break;
            }
        }
        if (!aligned) {
            // Either trailer prose (which overflows its columns) or a genuine
            // row whose padding this parser could not follow. It is NOT emitted
            // with borrowed values -- but it is counted, so a dropped package
            // cannot vanish silently.
            if (!is_winget_trailer(line))
                ++result.unmapped_lines;
            continue;
        }

        auto name = detail::slice_trimmed(line, origins[0], origins[1]);
        const auto id = detail::slice_trimmed(line, origins[1], origins[2]);
        auto current = detail::slice_trimmed(line, origins[2], origins[3]);
        auto available = detail::slice_trimmed(line, origins[3], origins[4]);
        // Id and Version are always populated on a genuine winget row; a
        // short trailer line ("23 upgrades available.") aligns trivially but
        // leaves them empty, which is what distinguishes it from data.
        if (name.empty() || id.empty() || current.empty())
            continue;
        if (available.empty())
            available = "-";
        result.rows.push_back({std::move(name), std::move(current), std::move(available)});
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
        if (const auto label_pos = trimmed.find("Label:"); label_pos != std::string::npos) {
            // Take the text after THIS "Label:" -- not after the first colon in
            // the line, which need not be the same one. An unguarded
            // substr(find(':') + 2) also throws std::out_of_range on a bare
            // "Label:" line, and that exception would cross the plugin's C ABI
            // boundary out of execute(), which has no catch.
            const auto value = trimmed.find_first_not_of(" \t", label_pos + 6);
            if (value != std::string::npos)
                labels.push_back(trimmed.substr(value));
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

/// Whether one tool invocation produced a COMPLETE, trustworthy capture that
/// a count or a row list may honestly be derived from. `exit_ok` is the
/// caller's own verdict on the exit code (runner_status.hpp leaves exit-code
/// semantics to the caller: yum/dnf's 100 is a success, most tools' nonzero is
/// not). Pure so every combination is unit-testable without a spawn.
[[nodiscard]] constexpr bool capture_is_complete(bool tool_ran, bool timed_out,
                                                 bool output_truncated, bool exit_ok) {
    return tool_ran && !timed_out && !output_truncated && exit_ok;
}

// ── installed_count emit decision (pure seam) ──────────────────────────────

/// The `count|N` line for a subkey/record count, or std::nullopt when the
/// count is unavailable (a negative sentinel — Windows'
/// registry_uninstall_subkey_count() returns -1 when the registry read
/// fails).
///
/// Pure so the FAILURE path is unit-testable on every host: the Windows
/// registry read it guards essentially never fails on a real machine, so
/// the honest-degrade branch would otherwise ship unexercised. A degraded
/// read must emit NO count line — `count|0` would assert "zero programs are
/// installed", the same false-clean shape the antivirus plugin's
/// `exclusion_count|0` invariant forbids.
[[nodiscard]] inline std::optional<std::string> installed_count_line(int count) {
    if (count < 0)
        return std::nullopt;
    return "count|" + std::to_string(count);
}

} // namespace yuzu::software_actions
