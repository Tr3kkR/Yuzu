#pragma once

/**
 * antivirus_parsers.hpp — pure parse helpers for the antivirus plugin's macOS
 * legs: the XProtect definition-bundle version (PlistBuddy output) and the
 * system-extension registry (`systemextensionsctl list`), which is where
 * modern EDR/AV products register their endpoint-security extensions.
 *
 * Header-only and OS-free so the parsing is unit-tested on every host
 * (test_antivirus_parsers.cpp — the firewall_parsers.hpp pattern); the popen
 * shell-outs in antivirus_plugin.cpp are the impure shell.
 *
 * Honest-status invariant: empty, truncated, or unrecognised output parses
 * to empty/absent results — the caller reports `unknown`, never a false-safe
 * "active".
 */

#include <string>
#include <string_view>
#include <vector>

namespace yuzu::antivirus {

/// Parse PlistBuddy's `Print :CFBundleShortVersionString` output: on success
/// it is exactly the version token (e.g. "5351", "1.93"). Anything containing
/// whitespace, quotes, or colons is error text, not a version — returns an
/// empty view (the caller maps that to unknown). The returned view aliases
/// `out` and must not outlive it.
[[nodiscard]] constexpr std::string_view parse_plist_version(std::string_view out) {
    // Trim surrounding whitespace/newlines.
    while (!out.empty() && (out.front() == ' ' || out.front() == '\t' || out.front() == '\n' ||
                            out.front() == '\r'))
        out.remove_prefix(1);
    while (!out.empty() && (out.back() == ' ' || out.back() == '\t' || out.back() == '\n' ||
                            out.back() == '\r'))
        out.remove_suffix(1);
    if (out.empty() || out.size() > 64)
        return {};
    for (char c : out) {
        if (c == ' ' || c == '\t' || c == ':' || c == '"' || c == ',')
            return {}; // error prose, not a version token
    }
    return out;
}

/// One row of `systemextensionsctl list`.
struct SysExtension {
    std::string category;  // section, e.g. "endpoint_security", "network_extension"
    std::string team_id;   // signing team identifier column
    std::string bundle_id; // e.g. "com.crowdstrike.falcon.Agent"
    std::string version;   // as printed, e.g. "7.16.0/101.98.5"
    std::string name;      // display-name column
    std::string state;     // bracket contents, e.g. "activated enabled"
    bool enabled{false};   // leading '*' in the enabled column
    bool active{false};    // '*' in the active column
};

/// Parse `systemextensionsctl list`. Format (verified live, macOS 26):
///   N extension(s)
///   --- com.apple.system_extension.<category> (Go to 'System Settings…')
///   enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
///   *\t*\tTEAMID\tcom.vendor.product (1.2.3/4.5)\tProduct Name\t[activated enabled]
/// Rows are tab-separated; the enabled/active cells hold '*' or are empty.
/// Malformed rows are skipped; empty/garbage input yields an empty vector.
[[nodiscard]] inline std::vector<SysExtension> parse_sysext_list(std::string_view out) {
    std::vector<SysExtension> exts;
    std::string category;
    size_t start = 0;
    while (start <= out.size()) {
        const auto nl = out.find('\n', start);
        std::string_view line =
            out.substr(start, nl == std::string_view::npos ? out.size() - start : nl - start);
        start = nl == std::string_view::npos ? out.size() + 1 : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);

        if (line.rfind("--- ", 0) == 0) {
            // "--- com.apple.system_extension.<category> (…)" — take the token
            // after "--- " up to the first space, then the part after its
            // last dot.
            auto token = line.substr(4);
            if (auto sp = token.find(' '); sp != std::string_view::npos)
                token = token.substr(0, sp);
            if (auto dot = token.rfind('.'); dot != std::string_view::npos)
                token = token.substr(dot + 1);
            category.assign(token);
            continue;
        }
        if (line.find('\t') == std::string_view::npos)
            continue; // count line, blank line, or prose
        if (line.rfind("enabled\t", 0) == 0)
            continue; // column-header line

        // Tab-split, keeping empty fields (a disabled row starts "\t\t…").
        std::vector<std::string_view> cols;
        size_t cstart = 0;
        while (true) {
            const auto tab = line.find('\t', cstart);
            cols.push_back(line.substr(
                cstart, tab == std::string_view::npos ? line.size() - cstart : tab - cstart));
            if (tab == std::string_view::npos)
                break;
            cstart = tab + 1;
        }
        if (cols.size() < 6)
            continue; // not a data row

        SysExtension ext;
        ext.category = category;
        ext.enabled = cols[0] == "*";
        ext.active = cols[1] == "*";
        ext.team_id.assign(cols[2]);
        std::string_view bundle = cols[3];
        if (auto paren = bundle.find(" ("); paren != std::string_view::npos) {
            ext.bundle_id.assign(bundle.substr(0, paren));
            auto ver = bundle.substr(paren + 2);
            if (!ver.empty() && ver.back() == ')')
                ver.remove_suffix(1);
            ext.version.assign(ver);
        } else {
            ext.bundle_id.assign(bundle);
        }
        ext.name.assign(cols[4]);
        std::string_view state = cols[5];
        if (!state.empty() && state.front() == '[')
            state.remove_prefix(1);
        if (!state.empty() && state.back() == ']')
            state.remove_suffix(1);
        ext.state.assign(state);
        exts.push_back(std::move(ext));
    }
    return exts;
}

/// EDR/AV products register endpoint-security system extensions.
[[nodiscard]] inline bool is_endpoint_security(const SysExtension& ext) {
    return ext.category == "endpoint_security";
}

/// Map an extension's registry state onto the products row vocabulary:
/// activated+enabled is running protection ("active"); anything else is
/// present but not protecting ("installed").
[[nodiscard]] inline std::string_view sysext_av_state(const SysExtension& ext) {
    return ext.enabled && ext.active ? "active" : "installed";
}

/// Case-insensitive substring test (ASCII), for de-duplicating the pgrep
/// fallback against products already reported via the extension registry.
[[nodiscard]] constexpr bool contains_insensitive(std::string_view hay, std::string_view needle) {
    if (needle.empty() || hay.size() < needle.size())
        return needle.empty();
    auto lower = [](char c) constexpr {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    };
    for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        size_t j = 0;
        while (j < needle.size() && lower(hay[i + j]) == lower(needle[j]))
            ++j;
        if (j == needle.size())
            return true;
    }
    return false;
}

} // namespace yuzu::antivirus
