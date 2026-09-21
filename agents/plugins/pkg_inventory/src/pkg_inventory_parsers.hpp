/**
 * pkg_inventory_parsers.hpp — the PURE text/row layer for pkg_inventory.
 *
 * Every function here is over plain data: no OS call, no I/O, no POSIX header.
 * It compiles and is unit-tested on EVERY OS (Windows included) by an unguarded
 * test TU -- the repo's pure-core/thin-shell discipline, same shape as
 * peripherals_parsers.hpp. The O_NOFOLLOW / walk_dir_capped file and directory
 * primitives live in the guarded walk layer (pkg_inventory_legs.hpp, `posix::`).
 *
 * SCOPE (row PR10.1-c; charter and the Linux "shrink" ruling of 2026-09-19 are
 * quoted in the roadmap). MACHINE-SCOPE package-manager state only: per-user
 * package stores (npm/pip/cargo/per-user Homebrew) are out of scope and
 * deferred to the user-context-bridge session helper. The Linux leg reports
 * manager identity/presence and manager-level config facts and NEVER a package
 * roster (installed_apps.get_inventory_linux owns that).
 *
 * WIRE GRAMMAR. Every action writes the status row FIRST, then data rows:
 *
 *   status|<action>|<supported|constrained|unsupported>|<tokens or ->
 *   manager|<dpkg|apt|rpm|dnf|pacman|apk|homebrew>|<present|unavailable>|<version or ->|<root_path or ->|<facts k=v;... or ->|<reason or ->
 *   package|homebrew|<id>|<version>|<formula|cask>
 *
 * Every free-text field goes through yuzu::util::safe_output_field (a trailing
 * backslash or a pipe in an OS-supplied value can never shift a column).
 * `status` tokens follow the repo convention ^(windows|macos|linux):[a-z0-9_]+(:[a-z0-9_]+)*$
 * and are composed by make_token so that shape is enforced in one place.
 *
 * "FAILURE NEVER READS AS ABSENT". A genuinely absent manager/prefix yields
 * `supported` + zero data rows. A failed or unreadable read yields
 * `constrained` + a token (accumulated with yuzu::shared::ConstraintAccumulator),
 * never an empty success.
 *
 * NOT IN kKeyValuePlugins: this plugin is not decoded by the server as a
 * two-cell key|rest plugin (the README states this; checked at wiring time).
 */
#pragma once

#include <yuzu/string_utils.hpp>

#include <constraint_accumulator.hpp>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::pkg_inventory {

// ── limits ───────────────────────────────────────────────────────────────

/// Per-file read cap. This package's own choice (config files here are a few
/// hundred bytes; autoruns' kMaxPlistBytes is 1 MiB because plists can be
/// large). A file over the cap is read up to the cap and reported `oversized`.
inline constexpr std::size_t kMaxConfigBytes = 256 * 1024;
/// Per-directory entry cap handed to walk_dir_capped.
inline constexpr std::size_t kMaxEntriesPerDir = 4096;
/// Whole-action package row cap (Homebrew): beyond it the walk stops and the
/// status carries `row_cap`.
inline constexpr std::size_t kMaxPackageRows = 20000;

/// The three resource bounds as ONE injectable value. Production always uses
/// the defaults above; the unit suite passes small values so each bound (and its
/// failure token) is exercised at cap and cap+1 without building 4096 entries
/// or a 256 KiB file.
struct Limits {
    std::size_t max_config_bytes = kMaxConfigBytes;
    std::size_t max_entries_per_dir = kMaxEntriesPerDir;
    std::size_t max_package_rows = kMaxPackageRows;
};

// ── fixed vocabularies (emitted verbatim, never through safe_output_field) ──

enum class Manager { dpkg, apt, rpm, dnf, pacman, apk, homebrew };

[[nodiscard]] constexpr std::string_view manager_name(Manager m) noexcept {
    switch (m) {
    case Manager::dpkg:     return "dpkg";
    case Manager::apt:      return "apt";
    case Manager::rpm:      return "rpm";
    case Manager::dnf:      return "dnf";
    case Manager::pacman:   return "pacman";
    case Manager::apk:      return "apk";
    case Manager::homebrew: return "homebrew";
    }
    return "dpkg";
}

/// `present`: the manager was detected and at least part of it was readable.
/// `unavailable`: detected (something exists) but nothing could be read; the
/// row's reason field carries the token. A manager that is simply not there
/// produces NO row at all.
enum class Presence { present, unavailable };

[[nodiscard]] constexpr std::string_view presence_token(Presence p) noexcept {
    switch (p) {
    case Presence::present:     return "present";
    case Presence::unavailable: return "unavailable";
    }
    return "unavailable";
}

enum class PackageKind { formula, cask };

[[nodiscard]] constexpr std::string_view package_kind_token(PackageKind k) noexcept {
    switch (k) {
    case PackageKind::formula: return "formula";
    case PackageKind::cask:    return "cask";
    }
    return "formula";
}

enum class StatusLevel { supported, constrained, unsupported };

[[nodiscard]] constexpr std::string_view status_level_token(StatusLevel l) noexcept {
    switch (l) {
    case StatusLevel::supported:   return "supported";
    case StatusLevel::constrained: return "constrained";
    case StatusLevel::unsupported: return "unsupported";
    }
    return "constrained";
}

// ── tokens ───────────────────────────────────────────────────────────────

/// Fixed tokens for the two by-design unsupported outcomes.
inline constexpr std::string_view kTokenLinuxPackagesOwned = "linux:owned_by_installed_apps";
inline constexpr std::string_view kTokenWindowsPlanned = "windows:planned";

/// True when `t` matches ^(windows|macos|linux):[a-z0-9_]+(:[a-z0-9_]+)*$.
[[nodiscard]] inline bool is_wellformed_token(std::string_view t) noexcept {
    const auto colon = t.find(':');
    if (colon == std::string_view::npos) return false;
    const auto os = t.substr(0, colon);
    if (os != "windows" && os != "macos" && os != "linux") return false;
    std::size_t seg_len = 0;
    std::size_t segments = 0;
    for (std::size_t i = colon + 1; i <= t.size(); ++i) {
        if (i == t.size() || t[i] == ':') {
            if (seg_len == 0) return false;
            ++segments;
            seg_len = 0;
            continue;
        }
        const char c = t[i];
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        if (!ok) return false;
        ++seg_len;
    }
    return segments >= 1;
}

/// `<os>:<source>:<detail>` -- the per-location failure token. `source` names
/// the location (e.g. "apt_sources_d", "homebrew_cellar"), `detail` the
/// failure class (an open_failure_token value, "entry_cap", ...). All three
/// parts are compile-time literals at every call site.
[[nodiscard]] inline std::string make_token(std::string_view os, std::string_view source,
                                            std::string_view detail) {
    std::string t{os};
    t += ':';
    t += source;
    t += ':';
    t += detail;
    return t;
}

/// True when `err` (errno from an open/openat on a path this plugin reads)
/// means "the thing is not there". Only ENOENT is benign: every other errno is
/// a real constraint the caller must surface, never fold into zero rows.
[[nodiscard]] inline bool is_benign_absent_errno(int err) noexcept { return err == ENOENT; }

/// errno from a failed open/openat -> a stable detail token. `io_error` is the
/// named unmodelled bucket (distinct from "absent" and from every named class).
[[nodiscard]] inline std::string_view open_failure_token(int err) noexcept {
    switch (err) {
    case EACCES:
    case EPERM:   return "permission_denied";
    case ELOOP:   return "symlink_refused";
    case ENOTDIR: return "not_a_directory";
    default:      return "io_error";
    }
}

// ── status + row formatters ──────────────────────────────────────────────
//
// Formatters take already-computed values, make no decisions and return the
// row WITHOUT a trailing newline (append_output() inserts the separator).

/// status|<action>|<level>|<tokens or ->
[[nodiscard]] inline std::string format_status_row(std::string_view action, StatusLevel level,
                                                   std::string_view tokens) {
    std::string out = "status|";
    out += yuzu::util::safe_output_field(action);
    out += '|';
    out += status_level_token(level);
    out += '|';
    out += tokens.empty() ? std::string{"-"} : yuzu::util::safe_output_field(tokens);
    return out;
}

/// The status row for a completed read: constrained + the accumulated tokens
/// if ANY acquisition step failed, otherwise supported (an absent manager or
/// prefix is supported with zero data rows).
[[nodiscard]] inline std::string
status_row(std::string_view action, const yuzu::shared::ConstraintAccumulator& acc) {
    return format_status_row(action,
                             acc.any_failure() ? StatusLevel::constrained : StatusLevel::supported,
                             acc.reason());
}

/// status|<action>|unsupported|<token>
[[nodiscard]] inline std::string unsupported_status_row(std::string_view action,
                                                        std::string_view token) {
    return format_status_row(action, StatusLevel::unsupported, token);
}

/// Builder for the `facts` field: `k=v;k=v`, or "-" when empty. Keys and
/// values here are validated tokens and counts by construction (arch tokens
/// pass arch_token_ok, counts are integers); the whole field still goes
/// through safe_output_field in format_manager_row.
class Facts {
public:
    void add(std::string_view key, std::string_view value) {
        if (!text_.empty()) text_ += ';';
        text_ += key;
        text_ += '=';
        text_ += value;
    }
    void add(std::string_view key, std::size_t value) { add(key, std::to_string(value)); }
    [[nodiscard]] std::string str() const { return text_.empty() ? std::string{"-"} : text_; }

private:
    std::string text_;
};

/// manager|<name>|<present|unavailable>|<version or ->|<root_path or ->|<facts or ->|<reason or ->
/// Empty `version` / `root_path` / `reason` are written as "-". `facts` is the
/// Facts::str() value ("-" when empty).
[[nodiscard]] inline std::string format_manager_row(Manager m, Presence p, std::string_view version,
                                                    std::string_view root_path,
                                                    std::string_view facts,
                                                    std::string_view reason) {
    auto field = [](std::string_view v) {
        return v.empty() ? std::string{"-"} : yuzu::util::safe_output_field(v);
    };
    std::string out = "manager|";
    out += manager_name(m);
    out += '|';
    out += presence_token(p);
    out += '|';
    out += field(version);
    out += '|';
    out += field(root_path);
    out += '|';
    out += field(facts);
    out += '|';
    out += field(reason);
    return out;
}

/// package|homebrew|<id>|<version>|<formula|cask>
[[nodiscard]] inline std::string format_package_row(std::string_view id, std::string_view version,
                                                    PackageKind kind) {
    std::string out = "package|homebrew|";
    out += yuzu::util::safe_output_field(id);
    out += '|';
    out += yuzu::util::safe_output_field(version);
    out += '|';
    out += package_kind_token(kind);
    return out;
}

// ── pure text parsers ────────────────────────────────────────────────────

namespace detail {

[[nodiscard]] inline std::string_view trim(std::string_view s) noexcept {
    const auto is_ws = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    while (!s.empty() && is_ws(s.front())) s.remove_prefix(1);
    while (!s.empty() && is_ws(s.back())) s.remove_suffix(1);
    return s;
}

/// Calls fn(trimmed_line) for every nonblank, non-`#`-comment line.
template <typename Fn>
void for_each_content_line(std::string_view text, Fn&& fn) {
    std::size_t pos = 0;
    while (pos <= text.size()) {
        const auto nl = text.find('\n', pos);
        const auto line =
            trim(text.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos));
        if (!line.empty() && line.front() != '#') fn(line);
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
}

} // namespace detail

/// Number of nonblank, non-`#`-comment lines (pacman.conf, dnf.conf,
/// pacman mirrorlist `Server =` lines, apt one-line sources.list entries).
[[nodiscard]] inline std::size_t count_nonblank_noncomment_lines(std::string_view text) {
    std::size_t n = 0;
    detail::for_each_content_line(text, [&](std::string_view) { ++n; });
    return n;
}

/// A dpkg/apk architecture token: 1..32 chars of [a-z0-9_-] (amd64, arm64,
/// i386, armhf, x86_64, aarch64, ...). The underscore is required: apk's
/// /etc/apk/arch carries `x86_64`.
[[nodiscard]] inline bool arch_token_ok(std::string_view t) noexcept {
    if (t.empty() || t.size() > 32) return false;
    return std::all_of(t.begin(), t.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
    });
}

struct ArchParse {
    std::vector<std::string> arches; ///< valid tokens, first-seen order, de-duplicated
    std::size_t rejected = 0;        ///< content lines that were not a valid token
};

/// /var/lib/dpkg/arch: one architecture per line (native first, then foreign;
/// the file is created by the first `dpkg --add-architecture` and is absent on
/// a stock image). The same one-token-per-line grammar covers /etc/apk/arch.
/// A malformed line is counted in `rejected` (the caller turns that into a
/// constrained token), never silently dropped.
[[nodiscard]] inline ArchParse parse_dpkg_arch_file(std::string_view text) {
    ArchParse out;
    detail::for_each_content_line(text, [&](std::string_view line) {
        if (!arch_token_ok(line)) {
            ++out.rejected;
            return;
        }
        std::string s{line};
        if (std::find(out.arches.begin(), out.arches.end(), s) == out.arches.end())
            out.arches.push_back(std::move(s));
    });
    return out;
}

[[nodiscard]] inline std::string join_arches(const std::vector<std::string>& arches) {
    std::string out;
    for (const auto& a : arches) {
        if (!out.empty()) out += ',';
        out += a;
    }
    return out;
}

struct ApkRepositories {
    std::size_t count = 0;  ///< repository lines
    std::size_t tagged = 0; ///< lines pinned with a leading `@tag`
};

/// /etc/apk/repositories: one repository per line, optionally `@tag URL`.
/// Only COUNTS are returned -- repository URLs may embed credentials and are
/// never surfaced.
[[nodiscard]] inline ApkRepositories parse_apk_repositories(std::string_view text) {
    ApkRepositories out;
    detail::for_each_content_line(text, [&](std::string_view line) {
        ++out.count;
        if (line.front() == '@') ++out.tagged;
    });
    return out;
}

/// True when `name` is an acceptable Homebrew directory name at the formula /
/// cask / version level (Cellar/<formula>/<version>, Caskroom/<cask>/<version>,
/// Library/Taps/<org>/<repo>): non-empty, at most 255 bytes, no leading `.`
/// (excludes `.metadata`, `.brew`, `.keepme`), and only printable ASCII other
/// than the path separator, the pipe and the wire-unsafe backslash. Cask
/// versions legitimately carry `,` and `:` (e.g. "1.2.3,456"); formulae carry
/// `@` and `+` (openssl@3, gtk+).
[[nodiscard]] inline bool version_dir_name_ok(std::string_view name) noexcept {
    if (name.empty() || name.size() > 255 || name.front() == '.') return false;
    return std::all_of(name.begin(), name.end(), [](char c) {
        const auto u = static_cast<unsigned char>(c);
        return u >= 0x20 && u < 0x7f && c != '/' && c != '\\' && c != '|';
    });
}

/// File-name suffix test used for the apt/dnf source counts.
[[nodiscard]] inline bool has_suffix(std::string_view name, std::string_view suffix) noexcept {
    return name.size() > suffix.size() && name.substr(name.size() - suffix.size()) == suffix;
}

} // namespace yuzu::pkg_inventory
