#pragma once

/// @file preflight_parse.hpp
/// PURE, dependency-free parse + verdict layer for the `/auto` Pre-flight page.
///
/// TWO concerns, both pure (the server applies them as raw facts land; the
/// orchestrator applies the same later when headless):
///   1. PARSE — read RAW pipe-delimited plugin output by field index (the bundle /
///      live dispatch bypasses the Instruction Engine, so `result.columns` is not a
///      runtime parser). Verified emit sites (2026-06-28):
///        installed_apps/query → `found|<bool>` then `app|<name>|<version>|<pub>`
///                               (version at field[2]); `found|false` if absent.
///        os_info/os_version   → `os_version|<rel>` (POSIX) / `os_version|<maj.min.build>`
///                               (Windows; a sibling `os_product_version|` row is ignored).
///        os_info/os_arch      → `os_arch|<machine>`.
///        windows_updates/pending_reboot → multi-row; UNCONDITIONAL summary
///                               `reboot_required|<bool>|<reasons>` (bool at field[1]).
///        disk_space/free      → `disk|<path>|<total>|<free>|<percent_used>`
///                               (free at field[3]; leading `disk` is NOT the path).
///   2. VERDICT — apply the operator's per-check THRESHOLD (PreflightConfig) to the
///      parsed fact → {Pass, Fail, Warn, Unknown}. Unknown = no terminal response /
///      unparseable (renders as "incomplete", never a false Pass).
/// Header-only so the unit test links it without the server.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::preflight {

/// One Slice-1 check: the column + the plugin action that feeds it. `blocking` =
/// a Fail makes the device no-go (reboot is block-or-warn per PreflightConfig, so
/// its blocking-ness is resolved at evaluate time, not here).
struct PreflightCheck {
    const char* key;
    const char* label;
    const char* plugin;
    const char* action;
    bool blocking;
};

/// Slice 1 live checks (params come from the config; staged-artifact checks
/// installer/rollback/backup arrive in a later slice).
inline constexpr std::array<PreflightCheck, 5> kPreflightChecks = {{
    {"app", "Target application", "installed_apps", "query", true},
    {"osver", "OS version", "os_info", "os_version", true},
    {"osarch", "Arch", "os_info", "os_arch", true},
    {"disk", "Free disk", "disk_space", "free", true},
    {"reboot", "Pending reboot", "windows_updates", "pending_reboot", true},
}};

/// Operator-set parameters + thresholds (entered in the /auto config section).
struct PreflightConfig {
    std::string app_name;        ///< installed_apps/query `name` param (substring)
    std::string app_min_version; ///< threshold: installed version must be >= this
    std::string app_max_version; ///< threshold (optional): installed version must be <= this
    std::string os_min_version;  ///< threshold: os_version must be >= this
    std::string req_arch;        ///< threshold: "x86_64" | "arm64" | "any"
    std::int64_t min_free_gib = 0; ///< threshold: free disk must be >= this (GiB)
    std::string volume;          ///< disk_space/free `path` param (e.g. "C:\\", "/")
    bool reboot_block = true;    ///< pending reboot: true=Fail (block), false=Warn
};

enum class Verdict { kPass, kFail, kWarn, kUnknown };

/// A device's overall bucket, rolled up from its per-check verdicts. Precedence:
/// Failed > Incomplete > Warn-only > Pass. INVARIANT: evaluate() only returns
/// kFail for a check that is blocking under the active config (reboot returns
/// kWarn, not kFail, in warn-only mode), so a single kFail always means no-go —
/// the roll-up needs the verdicts alone, not a separate blocking flag.
enum class Bucket { kPass, kFailed, kWarnOnly, kIncomplete };

inline Bucket classify_device(const std::vector<Verdict>& verdicts) {
    bool any_unknown = false, any_warn = false;
    for (Verdict v : verdicts) {
        if (v == Verdict::kFail)
            return Bucket::kFailed;
        if (v == Verdict::kUnknown)
            any_unknown = true;
        else if (v == Verdict::kWarn)
            any_warn = true;
    }
    if (any_unknown)
        return Bucket::kIncomplete;
    if (any_warn)
        return Bucket::kWarnOnly;
    return Bucket::kPass;
}

// ── Low-level pipe parsing ───────────────────────────────────────────────────

/// Split one pipe-delimited line into fields (empties preserved).
inline std::vector<std::string> split_pipe(std::string_view row) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (true) {
        auto p = row.find('|', start);
        if (p == std::string_view::npos) {
            out.emplace_back(row.substr(start));
            break;
        }
        out.emplace_back(row.substr(start, p - start));
        start = p + 1;
    }
    return out;
}

/// First line whose field[0] == `discriminator`, split into fields. Tolerates
/// `\n` / `\r\n`; skips blanks. nullopt when absent.
inline std::optional<std::vector<std::string>> find_row(std::string_view output,
                                                        std::string_view discriminator) {
    std::size_t start = 0;
    while (start <= output.size()) {
        auto nl = output.find('\n', start);
        std::string_view line =
            (nl == std::string_view::npos) ? output.substr(start) : output.substr(start, nl - start);
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (!line.empty()) {
            auto fields = split_pipe(line);
            if (!fields.empty() && fields[0] == discriminator)
                return fields;
        }
        if (nl == std::string_view::npos)
            break;
        start = nl + 1;
    }
    return std::nullopt;
}

/// Best-effort signed-int parse (0 on garbage — agent-emitted, never operator input).
inline std::int64_t parse_i64(std::string_view s) {
    std::int64_t v = 0;
    bool neg = false, any = false;
    std::size_t i = 0;
    if (i < s.size() && (s[i] == '-' || s[i] == '+')) {
        neg = s[i] == '-';
        ++i;
    }
    for (; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9')
            break;
        v = v * 10 + (s[i] - '0');
        any = true;
    }
    if (!any)
        return 0;
    return neg ? -v : v;
}

/// Format a byte count as 1-decimal GiB ("123.4 GiB"); negative → "?".
inline std::string format_gib(std::int64_t bytes) {
    if (bytes < 0)
        return "?";
    constexpr std::int64_t kGiB = 1024LL * 1024 * 1024;
    std::int64_t tenths = (bytes * 10) / kGiB;
    std::string out = std::to_string(tenths / 10);
    out += '.';
    out += std::to_string(tenths % 10);
    out += " GiB";
    return out;
}

/// Dotted-numeric version compare: -1 (a<b) / 0 (a==b) / 1 (a>b). Per component
/// numeric (leading digits; non-numeric suffix ignored), missing components = 0,
/// so "10.0.22631" > "10.0.19045" and "4.2" == "4.2.0".
inline int cmp_version(std::string_view a, std::string_view b) {
    auto next = [](std::string_view& s) -> std::int64_t {
        if (s.empty())
            return 0;
        std::size_t dot = s.find('.');
        std::string_view comp = (dot == std::string_view::npos) ? s : s.substr(0, dot);
        std::int64_t v = parse_i64(comp);
        s = (dot == std::string_view::npos) ? std::string_view{} : s.substr(dot + 1);
        return v;
    };
    while (!a.empty() || !b.empty()) {
        std::int64_t x = next(a);
        std::int64_t y = next(b);
        if (x < y)
            return -1;
        if (x > y)
            return 1;
    }
    return 0;
}

// ── Display extraction (drill-down: the device's actual value) ────────────────

/// The raw display value for `key` (shown in the failing-device drill), or nullopt
/// when the expected row is absent/malformed (rendered as "—").
inline std::optional<std::string> extract_cell(std::string_view key, std::string_view output) {
    if (key == "app") {
        auto found = find_row(output, "found");
        if (found && found->size() >= 2 && (*found)[1] == "false")
            return std::string("(not installed)");
        auto app = find_row(output, "app");
        if (app && app->size() >= 3 && !(*app)[2].empty())
            return (*app)[2]; // version
        return std::nullopt;
    }
    if (key == "osver") {
        auto r = find_row(output, "os_version");
        if (r && r->size() >= 2 && !(*r)[1].empty())
            return (*r)[1];
        return std::nullopt;
    }
    if (key == "osarch") {
        auto r = find_row(output, "os_arch");
        if (r && r->size() >= 2 && !(*r)[1].empty())
            return (*r)[1];
        return std::nullopt;
    }
    if (key == "reboot") {
        auto r = find_row(output, "reboot_required");
        if (r && r->size() >= 2)
            return (*r)[1] == "true" ? std::string("Pending") : std::string("Clear");
        return std::nullopt;
    }
    if (key == "disk") {
        auto r = find_row(output, "disk");
        if (r && r->size() >= 5)
            return format_gib(parse_i64((*r)[3])) + " free (" + (*r)[4] + "% used)";
        return std::nullopt;
    }
    return std::nullopt;
}

// ── Verdict (threshold applied to the parsed fact) ───────────────────────────

/// Evaluate one check's raw output against the config threshold. kUnknown when the
/// expected row is absent (no terminal response yet / unparseable).
inline Verdict evaluate(std::string_view key, std::string_view output, const PreflightConfig& cfg) {
    if (key == "app") {
        auto found = find_row(output, "found");
        if (found && found->size() >= 2 && (*found)[1] == "false")
            return Verdict::kFail; // target app not installed
        auto app = find_row(output, "app");
        if (!app || app->size() < 3 || (*app)[2].empty())
            return Verdict::kUnknown;
        const std::string& ver = (*app)[2];
        // Below the floor → Fail; above the (optional) ceiling → Fail (out of the
        // tested range). Neither set → presence-only Pass.
        if (!cfg.app_min_version.empty() && cmp_version(ver, cfg.app_min_version) < 0)
            return Verdict::kFail;
        if (!cfg.app_max_version.empty() && cmp_version(ver, cfg.app_max_version) > 0)
            return Verdict::kFail;
        return Verdict::kPass;
    }
    if (key == "osver") {
        auto r = find_row(output, "os_version");
        if (!r || r->size() < 2 || (*r)[1].empty())
            return Verdict::kUnknown;
        if (cfg.os_min_version.empty())
            return Verdict::kPass;
        return cmp_version((*r)[1], cfg.os_min_version) >= 0 ? Verdict::kPass : Verdict::kFail;
    }
    if (key == "osarch") {
        auto r = find_row(output, "os_arch");
        if (!r || r->size() < 2 || (*r)[1].empty())
            return Verdict::kUnknown;
        if (cfg.req_arch.empty() || cfg.req_arch == "any")
            return Verdict::kPass;
        return (*r)[1] == cfg.req_arch ? Verdict::kPass : Verdict::kFail;
    }
    if (key == "disk") {
        auto r = find_row(output, "disk");
        if (!r || r->size() < 5)
            return Verdict::kUnknown;
        constexpr std::int64_t kGiB = 1024LL * 1024 * 1024;
        std::int64_t free_gib = parse_i64((*r)[3]) / kGiB;
        return free_gib >= cfg.min_free_gib ? Verdict::kPass : Verdict::kFail;
    }
    if (key == "reboot") {
        auto r = find_row(output, "reboot_required");
        if (!r || r->size() < 2)
            return Verdict::kUnknown;
        if ((*r)[1] != "true")
            return Verdict::kPass; // clear
        return cfg.reboot_block ? Verdict::kFail : Verdict::kWarn;
    }
    return Verdict::kUnknown;
}

} // namespace yuzu::server::preflight
