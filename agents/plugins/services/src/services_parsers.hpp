/**
 * services_parsers.hpp — pure output parsers for the services plugin's
 * Linux (`systemctl list-units`) and macOS (`launchctl list`) enumeration
 * paths (Wave-2 PR2.2a, ADR-3002 acquisition-ladder migration, rung 2/3).
 *
 * Header-only, no I/O: services_plugin.cpp owns running systemctl/launchctl
 * through the bounded, shell-free runner (yuzu::agent::run_bounded_subprocess)
 * and hands this header the captured stdout, so every parser here is
 * unit-testable directly against fixture text with no live systemctl/
 * launchctl dependency (see tests/unit/test_services_parsers.cpp).
 *
 * The fixtures in that test file are hand-constructed-but-format-accurate —
 * built from the documented `systemctl list-units --no-legend` and
 * `launchctl list` column layouts, not a live capture from a running host.
 *
 * Mirrors the split services_macos_launchd.hpp already established in this
 * package (parse_print_disabled / startup_type_for): a pure parser header
 * the plugin .cpp includes and feeds captured text, kept independent of the
 * .cpp's anonymous namespace so it stays separately includable/testable.
 */
#pragma once

#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::services {

/// Validate a service name / launchd label before trusting it into the
/// pipe-delimited plugin protocol, into a shell-free argv element, or as a
/// startup_type_for() join key. Allows alphanumeric, hyphens, underscores,
/// dots, and '@' (systemd template instances like getty@tty1.service).
///
/// Own copy, independent of services_macos_launchd.hpp's
/// is_safe_launchd_label (identical character class) — same rationale as
/// that header's own comment: each header stays self-contained and
/// independently testable rather than depending on the other.
///
/// NOTE: this allowlist permits a LEADING '-' (e.g. "-foo"), which is safe
/// for the pipe-delimited protocol but NOT safe as a bare argv element to a
/// tool that parses leading-hyphen arguments as flags — callers passing a
/// validated name into systemctl/launchctl argv must still separate it with
/// an explicit "--" argv element (see services_plugin.cpp's set_start_mode
/// argv construction).
inline bool is_safe_service_name(std::string_view name) {
    if (name.empty() || name.size() > 256)
        return false;
    for (char c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_' && c != '.' &&
            c != '@') {
            return false;
        }
    }
    return true;
}

/// One row of `systemctl list-units --type=service [--all|--state=running]
/// --no-pager --no-legend` output: "UNIT LOAD ACTIVE SUB DESCRIPTION...".
struct SystemdUnitEntry {
    std::string name;        // UNIT
    std::string status;      // SUB (e.g. "running", "dead", "exited")
    std::string description; // remainder of the line
};

/// Parse the captured stdout of `systemctl list-units`. Tolerant of CRLF
/// line endings, a leading whitespace/bullet column (systemctl marks a
/// failed unit with "*"), and short/blank lines (skipped, never thrown).
/// `--no-legend` means there is no header row to skip.
inline std::vector<SystemdUnitEntry> parse_systemctl_list_units(std::string_view output) {
    std::vector<SystemdUnitEntry> services;

    for (std::size_t scan = 0; scan < output.size();) {
        const std::size_t nl = output.find('\n', scan);
        const std::size_t end = (nl == std::string_view::npos) ? output.size() : nl;
        std::string line{output.substr(scan, end - scan)};
        scan = (nl == std::string_view::npos) ? output.size() : nl + 1;
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.pop_back();
        }
        if (line.empty())
            continue;

        // Trim leading whitespace and the bullet systemctl marks a failed
        // unit with.
        auto start = line.find_first_not_of(" *");
        if (start == std::string::npos)
            continue;
        line = line.substr(start);

        SystemdUnitEntry entry;
        std::size_t pos = 0;
        auto next_token = [&]() -> std::string {
            auto s = line.find_first_not_of(' ', pos);
            if (s == std::string::npos)
                return {};
            auto e = line.find(' ', s);
            if (e == std::string::npos)
                e = line.size();
            pos = e;
            return line.substr(s, e - s);
        };

        entry.name = next_token();   // UNIT
        next_token();                // LOAD
        next_token();                // ACTIVE
        entry.status = next_token(); // SUB
        auto desc_start = line.find_first_not_of(' ', pos);
        if (desc_start != std::string::npos) {
            entry.description = line.substr(desc_start);
        }

        services.push_back(std::move(entry));
    }

    return services;
}

/// One row of `launchctl list` output: "PID\tStatus\tLabel".
struct LaunchdEntry {
    std::string label;
    std::string pid;
    std::string status;
};

/// Defensive row cap mirroring the C-8 row_cap precedent (licensing_wmi.hpp):
/// real macOS systems run in the low hundreds of launchd services, so this
/// bounds worst-case memory/output size without affecting normal
/// enumeration. Rows beyond the cap are still counted in total_seen below.
inline constexpr std::size_t kMaxServiceRows = 512;

struct LaunchdListResult {
    std::vector<LaunchdEntry> services;
    // Count of every entry that passed the label-safety + running_only
    // filters BEFORE the row_cap, so the caller can emit an honest
    // truncation sentinel when rows were dropped.
    std::size_t total_seen = 0;
};

/// Parse the captured stdout of `launchctl list` (the first line -- the
/// "PID\tStatus\tLabel" header -- is skipped automatically). `running_only`
/// drops rows whose pid is "-" (not currently running); launchctl has no
/// CLI flag for this, so the filter happens here, mirroring the original
/// inline check. Every label is validated via is_safe_service_name before
/// being trusted into the result -- an unsafe label (e.g. containing '|')
/// would otherwise corrupt the pipe-delimited protocol the caller emits it
/// into, or a startup_type_for() join key.
inline LaunchdListResult parse_launchctl_list(std::string_view output, bool running_only,
                                              std::size_t row_cap = kMaxServiceRows) {
    LaunchdListResult result;

    std::size_t line_pos = 0;
    bool header_skipped = false;
    auto next_line = [&](std::string& out) -> bool {
        if (line_pos >= output.size())
            return false;
        auto nl = output.find('\n', line_pos);
        if (nl == std::string_view::npos) {
            out = std::string(output.substr(line_pos));
            line_pos = output.size();
        } else {
            out = std::string(output.substr(line_pos, nl - line_pos));
            line_pos = nl + 1;
        }
        while (!out.empty() && (out.back() == '\n' || out.back() == '\r'))
            out.pop_back();
        return true;
    };

    std::string line;
    while (next_line(line)) {
        if (!header_skipped) { // first line is the "PID\tStatus\tLabel" header
            header_skipped = true;
            continue;
        }
        if (line.empty())
            continue;

        // Format: PID\tStatus\tLabel
        LaunchdEntry entry;
        std::size_t pos = 0;
        auto next_field = [&]() -> std::string {
            auto tab = line.find('\t', pos);
            std::string field;
            if (tab == std::string::npos) {
                field = line.substr(pos);
                pos = line.size();
            } else {
                field = line.substr(pos, tab - pos);
                pos = tab + 1;
            }
            return field;
        };

        entry.pid = next_field();
        entry.status = next_field();
        entry.label = next_field();

        // Guard the label before it is ever trusted into the pipe-delimited
        // protocol or used as a startup_type_for() join key.
        if (!is_safe_service_name(entry.label))
            continue;

        if (running_only && entry.pid == "-")
            continue;

        // Count every qualifying service BEFORE the cap so the caller can
        // tell a truncated inventory from a complete one.
        ++result.total_seen;

        if (result.services.size() < row_cap) {
            result.services.push_back(std::move(entry));
        }
    }

    return result;
}

} // namespace yuzu::services
