#pragma once

// installed_apps_parsers.hpp -- pure parse helpers for the `list`/`query`/
// `list_per_user` acquisition legs of installed_apps_plugin.cpp (the
// `list_inventory` v2-row parsers already live in installed_apps_inventory.hpp
// and are unchanged by this header).
//
// Header-only and OS-free so every parser here is fixture-tested on any host
// (the firewall_parsers.hpp / netprobe_stats.hpp pattern) -- the plugin's own
// run_bounded_subprocess acquisition is the impure shell; this header only
// ever sees an already-captured output blob.
//
// Wave 4 PR4.3a de-shells the Linux dpkg/rpm/pacman '|'-format line parsers
// (previously inline istringstream loops in installed_apps_plugin.cpp), the
// macOS `system_profiler SPApplicationsDataType -detailLevel mini` text
// parse (previously piped through `| grep` before reaching C++), the macOS
// `brew list --versions` line parse, and adds the #2273 macOS enrichment
// acquisition's own pure parsers (`pkgutil --pkgs` id list, `pkgutil
// --pkg-info <id>` version/install-time extraction).

#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::installed_apps::parsers {

// Mirrors installed_apps_plugin.cpp's (still plugin-local) AppInfo shape,
// plus one INTERNAL-only field: `location`. `location` (macOS
// system_profiler's "Location:" line -- the app bundle's absolute path) is
// never emitted through the stable `app|name|version|publisher|install_date`
// list/query wire format; it exists solely so get_inventory_macos() can hand
// the bundle path to the #2273 native CFBundle/SecStaticCode enrichment in
// installed_apps_macos_enrich.hpp. Honest-empty when the source format
// doesn't carry a given field (matches installed_apps_inventory.hpp's own
// convention) -- never synthesised, never a "-" placeholder (the plugin
// applies that display convention itself, at format time).
struct AppRecord {
    std::string name;
    std::string version;
    std::string publisher;
    std::string install_date;
    std::string location;
};

namespace detail {

inline void strip_trailing_cr(std::string& line) {
    if (!line.empty() && line.back() == '\r')
        line.pop_back();
}

} // namespace detail

// ── Linux: dpkg-query ───────────────────────────────────────────────────────

// One line of `dpkg-query -W -f='${Package}|${Version}|${Maintainer}|${Status}\n'`
// (the `\n` here is the LITERAL two-byte escape dpkg-query's own format-string
// interpreter expands -- see the plugin's argv construction comment). Only
// fully-installed packages are kept ("install ok installed"), matching the
// legacy shell-out this replaces exactly.
[[nodiscard]] inline std::vector<AppRecord> parse_dpkg_list(std::string_view output) {
    std::vector<AppRecord> apps;
    std::string buf(output);
    std::istringstream ss(buf);
    std::string line;
    while (std::getline(ss, line)) {
        detail::strip_trailing_cr(line);
        if (line.find("install ok installed") == std::string::npos)
            continue;
        std::istringstream ls(line);
        std::string name, version, publisher;
        std::getline(ls, name, '|');
        std::getline(ls, version, '|');
        std::getline(ls, publisher, '|');
        apps.push_back(AppRecord{std::move(name), std::move(version), std::move(publisher),
                                 "-", {}});
    }
    return apps;
}

// ── Linux: rpm ───────────────────────────────────────────────────────────

// One line of `rpm -qa --queryformat '%{NAME}|%{VERSION}-%{RELEASE}|%{VENDOR}|%{INSTALLTIME:date}\n'`.
[[nodiscard]] inline std::vector<AppRecord> parse_rpm_list(std::string_view output) {
    std::vector<AppRecord> apps;
    std::string buf(output);
    std::istringstream ss(buf);
    std::string line;
    while (std::getline(ss, line)) {
        detail::strip_trailing_cr(line);
        std::istringstream ls(line);
        std::string name, version, publisher, date;
        std::getline(ls, name, '|');
        std::getline(ls, version, '|');
        std::getline(ls, publisher, '|');
        std::getline(ls, date, '|');
        if (publisher == "(none)")
            publisher = "-";
        apps.push_back(AppRecord{std::move(name), std::move(version), std::move(publisher),
                                 std::move(date), {}});
    }
    return apps;
}

// ── Linux: pacman ───────────────────────────────────────────────────────

// One line of `pacman -Q` output: "name version".
[[nodiscard]] inline std::vector<AppRecord> parse_pacman_list(std::string_view output) {
    std::vector<AppRecord> apps;
    std::string buf(output);
    std::istringstream ss(buf);
    std::string line;
    while (std::getline(ss, line)) {
        detail::strip_trailing_cr(line);
        const auto sp = line.find(' ');
        if (sp != std::string::npos) {
            apps.push_back(
                AppRecord{line.substr(0, sp), line.substr(sp + 1), {}, {}, {}});
        }
    }
    return apps;
}

// ── macOS: system_profiler SPApplicationsDataType -detailLevel mini ──────

// Parses the RAW (un-grepped) mini-detail text block. The legacy shell-out
// piped this through
// `grep -E '^ {4}\w|Version:|Last Modified:'` before any C++ ever saw it;
// with that shell stage gone (rung 2: clean argv, no pipe), this function
// replicates the SAME three-way selection in-process so `list`/`query`'s
// emitted rows are byte-identical to before:
//   - a line with EXACTLY 4 leading spaces then a non-space character is an
//     app-name header (e.g. "    Keynote:") -- ANY other indent (0, the
//     top-level "Applications:" line; 6, an attribute line) is not a header;
//   - a line containing the substring "Version:" carries the version;
//   - a line containing the substring "Last Modified:" carries the install
//     date;
//   - everything else (Obtained from/Kind/Signed by/Location, in the mini
//     detail's normal case) was never visible to the old grep and is
//     likewise skipped here for those three fields.
// "Location:" is the one deliberate ADDITION (Wave 4 PR4.3a, #2273): it was
// never part of the old grep/parse and is not emitted via list/query's wire
// format, but the app's absolute bundle path is exactly what the new macOS
// list_inventory enrichment (installed_apps_macos_enrich.hpp) needs to call
// CFBundleCreate/SecStaticCodeCreateWithPath against -- capturing it here
// only ever adds an internal field, never changes list/query's emitted shape.
[[nodiscard]] inline std::vector<AppRecord> parse_system_profiler_apps(std::string_view output) {
    std::vector<AppRecord> apps;
    std::string buf(output);
    std::istringstream ss(buf);
    std::string line;

    std::string current_name, current_version, current_date, current_location;
    bool have_current = false;

    auto flush = [&]() {
        if (have_current && !current_name.empty()) {
            apps.push_back(AppRecord{current_name, current_version, {}, current_date,
                                     current_location});
        }
        current_name.clear();
        current_version.clear();
        current_date.clear();
        current_location.clear();
        have_current = false;
    };

    while (std::getline(ss, line)) {
        detail::strip_trailing_cr(line);

        const bool four_space_header = line.size() > 4 && line.compare(0, 4, "    ") == 0 &&
                                       line[4] != ' ' && line[4] != '\t';
        const bool has_version = line.find("Version:") != std::string::npos;
        const bool has_last_modified = line.find("Last Modified:") != std::string::npos;
        const bool has_location = line.find("Location:") != std::string::npos;
        if (!four_space_header && !has_version && !has_last_modified && !has_location)
            continue;

        const auto start = line.find_first_not_of(" \t");
        if (start == std::string::npos)
            continue;
        const std::string_view trimmed = std::string_view(line).substr(start);

        if (trimmed.starts_with("Version:")) {
            const auto colon = trimmed.find(':');
            current_version = std::string(trimmed.substr(colon + 2));
        } else if (trimmed.starts_with("Last Modified:")) {
            const auto colon = trimmed.find(':');
            current_date = std::string(trimmed.substr(colon + 2));
        } else if (trimmed.starts_with("Location:")) {
            const auto colon = trimmed.find(':');
            current_location = std::string(trimmed.substr(colon + 2));
        } else if (!trimmed.empty() && trimmed.back() == ':') {
            flush();
            current_name = std::string(trimmed.substr(0, trimmed.size() - 1));
            have_current = true;
        }
    }
    flush();
    return apps;
}

// ── macOS: brew list --versions ─────────────────────────────────────────

// One line of `brew list --versions`: "name version[ version...]". Only the
// first version token is kept (matches the legacy shell-out's own
// `line.substr(sp + 1)`, which keeps everything after the first space --
// a multi-version brew formula line's later tokens ride along as part of
// `version`, unchanged from the prior behaviour).
[[nodiscard]] inline std::vector<AppRecord> parse_brew_list(std::string_view output) {
    std::vector<AppRecord> apps;
    std::string buf(output);
    std::istringstream ss(buf);
    std::string line;
    while (std::getline(ss, line)) {
        detail::strip_trailing_cr(line);
        if (line.empty())
            continue;
        const auto sp = line.find(' ');
        AppRecord r;
        if (sp != std::string::npos) {
            r.name = line.substr(0, sp);
            r.version = line.substr(sp + 1);
        } else {
            r.name = line;
        }
        apps.push_back(std::move(r));
    }
    return apps;
}

// ── macOS: pkgutil (#2273 enrichment) ───────────────────────────────────

// `pkgutil --pkgs` -- one reverse-domain package identifier per line.
// Byte-for-byte the same split/trim shape as
// msi_packages_macos.hpp::parse_pkg_ids (duplicated rather than shared
// across the plugin boundary -- each plugin's pure-parser header is
// self-contained, matching every other plugin pair in this tree).
[[nodiscard]] inline std::vector<std::string> parse_pkgutil_pkgs(std::string_view output) {
    std::vector<std::string> ids;
    std::string buf(output);
    std::istringstream ss(buf);
    std::string line;
    while (std::getline(ss, line)) {
        detail::strip_trailing_cr(line);
        if (!line.empty())
            ids.push_back(line);
    }
    return ids;
}

// One `pkgutil --pkg-info <id>` receipt's version + install-time fields
// (`key: value` lines). `install_time` is pkgutil's raw UNIX-epoch-seconds
// string (its only time representation for a receipt -- no strftime here to
// avoid inventing a format the other ecosystems don't share; honest raw data,
// not synthesised). Malformed/empty input yields an all-empty result, never a
// crash or a fabricated value -- same discipline as
// msi_packages_macos.hpp::parse_pkg_info.
struct PkgutilInfo {
    std::string version;
    std::string install_time;
};

[[nodiscard]] inline PkgutilInfo parse_pkgutil_pkg_info(std::string_view output) {
    PkgutilInfo info;
    std::string buf(output);
    std::istringstream ss(buf);
    std::string line;
    while (std::getline(ss, line)) {
        detail::strip_trailing_cr(line);
        const auto sep = line.find(": ");
        if (sep == std::string::npos)
            continue;
        const std::string_view key = std::string_view(line).substr(0, sep);
        const std::string_view value = std::string_view(line).substr(sep + 2);
        if (key == "version")
            info.version = std::string(value);
        else if (key == "install-time")
            info.install_time = std::string(value);
    }
    return info;
}

} // namespace yuzu::installed_apps::parsers
