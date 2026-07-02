/**
 * vuln_identity.hpp — pure, testable installed-software identity helpers.
 *
 * The vuln_scan plugin (ADR-0018 collect-thin) enumerates installed software and
 * emits a rich identity record; the server correlates it against NVD/OVAL/VEX.
 * This header holds the OS-independent parsing/formatting logic so it can be unit
 * tested with captured package-manager output (see tests/unit/test_vuln_identity.cpp),
 * mirroring the netprobe_stats.hpp / installed_apps_registry_utf8.hpp precedent.
 *
 * Contract: fields the ecosystem does not store are left EMPTY — never
 * synthesised. The line parsers take a 0x1F-delimited record (the collector uses
 * 0x1F as the package-manager queryformat delimiter so a packager string
 * containing '|' cannot forge a field boundary).
 */
#pragma once

#include <cctype>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::vuln {

// One row per installed package/app. Empty string = field unavailable on this OS.
struct PackageRecord {
    std::string kind;             // "package" | "app"
    std::string ecosystem;        // rpm|deb|apk|pacman|windows|macos|homebrew
    std::string name;
    std::string epoch;            // rpm %{EPOCH} / deb version epoch; else empty
    std::string version;          // upstream version (release/revision stripped)
    std::string release;          // rpm %{RELEASE} / deb revision / apk pkgrel
    std::string arch;
    std::string packager;         // rpm packager / deb Maintainer / win Publisher
    std::string signature_status; // "signed"/"unsigned" (rpm, stored); else empty
    std::string distro_id;        // /etc/os-release ID (host-level, stamped)
    std::string distro_version;   // /etc/os-release VERSION_ID
};

inline constexpr char kUS = '\x1f'; // unit separator: collector queryformat delimiter

// Map a package-DB "no value" sentinel to empty. rpm prints the literal "(none)"
// for unset tags (EPOCH, PACKAGER, …); dpkg leaves such fields empty already.
inline std::string none_to_empty(std::string s) {
    if (s == "(none)")
        s.clear();
    return s;
}

// Replace invalid UTF-8 byte sequences with '?'.
inline std::string sanitize_utf8(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            // Neutralise ASCII control bytes (newline, CR, tab, 0x1F, …) to a
            // space: a raw '\n' in a field would forge a new server row at
            // split-on-'\n' framing, and control bytes must never break the
            // pipe-delimited row structure (UP-1/UP-9).
            out += (c < 0x20) ? ' ' : s[i];
            ++i;
        } else if ((c >> 5) == 0x06 && i + 1 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02) {
            out += s[i];
            out += s[i + 1];
            i += 2;
        } else if ((c >> 4) == 0x0E && i + 2 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02) {
            out += s[i];
            out += s[i + 1];
            out += s[i + 2];
            i += 3;
        } else if ((c >> 3) == 0x1E && i + 3 < s.size() &&
                   (static_cast<unsigned char>(s[i + 1]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 2]) >> 6) == 0x02 &&
                   (static_cast<unsigned char>(s[i + 3]) >> 6) == 0x02) {
            out += s[i];
            out += s[i + 1];
            out += s[i + 2];
            out += s[i + 3];
            i += 4;
        } else {
            out += '?';
            ++i;
        }
    }
    return out;
}

// Escape pipe characters so a '|' inside a value can't forge a column boundary
// in the output row. NOTE: this mirrors the shared server decode
// (result_parsing.hpp find_unescaped_pipe/unescape_pipes), which treats any '|'
// preceded by '\' as escaped. A value ending in a literal backslash is therefore
// still ambiguous at the column boundary — a known limitation of the shared
// pipe-escaping scheme (affects every plugin that uses it), tracked as a
// cross-cutting follow-up rather than fixed one-sided here.
inline std::string escape_pipes(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '|')
            out += "\\|";
        else
            out += c;
    }
    return out;
}

// Split a 0x1F-delimited record into fields (always yields count-of-delims + 1).
inline std::vector<std::string> split_us(const std::string& line) {
    std::vector<std::string> f;
    std::string cur;
    for (char c : line) {
        if (c == kUS) {
            f.push_back(cur);
            cur.clear();
        } else {
            cur += c;
        }
    }
    f.push_back(cur);
    return f;
}

// Split a Debian/pacman-style version "[epoch:]upstream[-revision]" into parts.
// A leading all-digit "N:" is the epoch; the substring after the last '-' is the
// revision/release; a native package (no '-') has no release.
inline void split_evr(const std::string& full, std::string& epoch, std::string& version,
                      std::string& release) {
    epoch.clear();
    version.clear();
    release.clear();
    std::string rest = full;
    auto colon = rest.find(':');
    if (colon != std::string::npos && colon > 0) {
        bool all_digits = true;
        for (size_t i = 0; i < colon; ++i)
            if (!std::isdigit(static_cast<unsigned char>(rest[i])))
                all_digits = false;
        if (all_digits) {
            epoch = rest.substr(0, colon);
            rest = rest.substr(colon + 1);
        }
    }
    auto dash = rest.rfind('-');
    if (dash != std::string::npos && dash > 0 && dash + 1 < rest.size()) {
        version = rest.substr(0, dash);
        release = rest.substr(dash + 1);
    } else {
        version = rest;
    }
}

// ── Per-ecosystem line parsers (pure) ───────────────────────────────────────

// dpkg-query -W -f='${Package}<US>${Version}<US>${Architecture}<US>${Maintainer}<US>${db:Status-Abbrev}'
inline std::optional<PackageRecord> parse_dpkg_line(const std::string& line) {
    auto f = split_us(line);
    // Exact field count: the queryformat emits exactly 4 delimiters (5 fields);
    // a value carrying a stray 0x1F would over-split and shift columns, so a
    // wrong count means a corrupt record — drop it rather than mis-attribute.
    if (f.size() != 5)
        return std::nullopt;
    // db:Status-Abbrev is <want><status>; the 2nd char 'i' == installed. This
    // covers "ii" (want=install) AND "hi" (want=hold) — a held-but-installed
    // package (apt-mark hold / kernel pin) is present and scannable. "rc"
    // (removed, config-files) and "un" (unknown) are correctly skipped.
    if (f[4].size() < 2 || f[4][1] != 'i')
        return std::nullopt;
    if (f[0].empty())
        return std::nullopt;
    PackageRecord r;
    r.kind = "package";
    r.ecosystem = "deb";
    r.name = f[0];
    split_evr(f[1], r.epoch, r.version, r.release);
    r.arch = f[2];
    r.packager = f[3];
    return r;
}

// rpm -qa --queryformat
//   '%{NAME}<US>%{EPOCH}<US>%{VERSION}<US>%{RELEASE}<US>%{ARCH}<US>%{PACKAGER}<US>%{SIGPGP}<US>%{RSAHEADER}'
// Signature is read from STORED tags only — never a live rpm -K verification.
// Both the payload signature (SIGPGP, v3 OpenPGP) AND the header signature
// (RSAHEADER) are checked: modern RHEL/Fedora packages are frequently
// header-signed only, with %{SIGPGP} == (none), so checking SIGPGP alone would
// mislabel a validly-signed package as "unsigned".
// A signature tag counts as present only if it holds a real value — not empty,
// not "(none)", and not an unexpanded literal "%{...}" (an rpm too old to know
// the tag echoes the format string, which must NOT read as "signed").
inline bool rpm_sig_present(const std::string& raw) {
    std::string v = none_to_empty(raw);
    return !v.empty() && v.rfind("%{", 0) != 0;
}

inline std::optional<PackageRecord> parse_rpm_line(const std::string& line) {
    auto f = split_us(line);
    // Exact field count: the queryformat emits exactly 7 delimiters (8 fields);
    // a wrong count means a stray 0x1F shifted the columns — drop the record.
    if (f.size() != 8)
        return std::nullopt;
    if (f[0].empty())
        return std::nullopt;
    PackageRecord r;
    r.kind = "package";
    r.ecosystem = "rpm";
    r.name = f[0];
    r.epoch = none_to_empty(f[1]);
    r.version = f[2];
    r.release = f[3];
    r.arch = f[4];
    r.packager = none_to_empty(f[5]);
    r.signature_status = (rpm_sig_present(f[6]) || rpm_sig_present(f[7])) ? "signed" : "unsigned";
    return r;
}

// `apk info -v` line: "<name>-<pkgver>-r<pkgrel>". pkgver/pkgrel never contain
// '-', so the last two '-'-delimited fields are pkgver and the rN pkgrel.
inline std::optional<PackageRecord> parse_apk_line(std::string line) {
    while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
        line.pop_back();
    auto rel_sep = line.rfind('-');
    if (rel_sep == std::string::npos || rel_sep == 0)
        return std::nullopt;
    auto ver_sep = line.rfind('-', rel_sep - 1);
    if (ver_sep == std::string::npos || ver_sep == 0)
        return std::nullopt;
    PackageRecord r;
    r.kind = "package";
    r.ecosystem = "apk";
    r.name = line.substr(0, ver_sep);
    r.version = line.substr(ver_sep + 1, rel_sep - ver_sep - 1);
    r.release = line.substr(rel_sep + 1);
    return r;
}

// `pacman -Q` line: "<name> <version>" (version is "[epoch:]pkgver-pkgrel").
inline std::optional<PackageRecord> parse_pacman_line(const std::string& line) {
    auto sp = line.find(' ');
    if (sp == std::string::npos || sp == 0)
        return std::nullopt;
    PackageRecord r;
    r.kind = "package";
    r.ecosystem = "pacman";
    r.name = line.substr(0, sp);
    split_evr(line.substr(sp + 1), r.epoch, r.version, r.release);
    return r;
}

// Format one record as the plugin's pipe-delimited output row.
inline std::string format_record(const PackageRecord& r) {
    auto e = [](const std::string& s) { return escape_pipes(sanitize_utf8(s)); };
    std::string out;
    out.reserve(96);
    out += e(r.kind);
    for (const std::string* p :
         {&r.ecosystem, &r.name, &r.epoch, &r.version, &r.release, &r.arch, &r.packager,
          &r.signature_status, &r.distro_id, &r.distro_version}) {
        out += '|';
        out += e(*p);
    }
    return out;
}

// The output column header order (for docs / result-schema parity).
inline constexpr std::string_view kColumns =
    "kind|ecosystem|name|epoch|version|release|arch|packager|signature_status|distro_id|distro_version";

} // namespace yuzu::vuln
