#pragma once

/**
 * launchctl_list.hpp -- shared, pure parser for `launchctl list` output.
 *
 * Decodes the "PID\tStatus\tLabel" rows `launchctl list` emits into raw,
 * per-row facts (label, whether a pid was present, the raw status code) with
 * NO downstream interpretation baked in -- unlike the historical
 * tar_service_parsers.hpp copy this is lifted from (A0, macOS Spark/Reflex/
 * DEX programme), which additionally collapsed pid presence into a
 * "running"/"stopped" ServiceInfo status string and dropped the status-code
 * field entirely. Two independent consumers need the raw shape: TAR's
 * tar_service_collector.cpp (which still wants the collapsed ServiceInfo
 * view -- see tar_service_parsers.hpp's launchctl_rows_to_services(), a thin
 * mapper now built on top of this header) and the macOS Spark launchd
 * service mechanism (a later slice), which needs a per-label state lookup
 * driven by raw pid presence, not a pre-baked string.
 *
 * Header-only, pure decision code (no I/O, no platform API) -- compiled and
 * unit-tested on every host, exactly like tar_service_parsers.hpp's sibling
 * parse_systemctl_list_units(), even though only a macOS collector/mechanism
 * ever calls it at runtime.
 *
 * pid is `std::int64_t`, not `pid_t` -- `pid_t` is POSIX-only and this header
 * must compile on Windows too (the standing "pure decision code compiles on
 * every host" rule), even though no Windows caller exists today.
 */

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::shared {

/// One decoded `launchctl list` row. `pid`: nullopt when the PID column is
/// "-" or empty (not running); `status`: the raw exit/last-status column,
/// parsed as an integer where numeric, 0 where it is "-"/empty/unparsable
/// (no prior behaviour to preserve here -- the historical TAR parser never
/// read this field at all). `label` empty means a malformed/truncated row
/// (fewer than 3 tab-separated fields) -- this parser never drops or throws
/// on that; malformed-row *policy* (BR-service-001) is the caller's job.
struct LaunchctlRow {
    std::string label;
    std::optional<std::int64_t> pid;
    int status{0};
};

/// Parse the line-split stdout of `launchctl list` (blank lines already
/// dropped, a trailing '\r' already stripped by the caller -- matches
/// SubprocessResult::lines' contract). The first line is always the
/// "PID\tStatus\tLabel" header and is skipped unconditionally; an empty
/// `lines` yields an empty result. A total, non-throwing decode: a row with
/// fewer than 3 tab-separated fields still produces a LaunchctlRow (with
/// whatever fields it had; a missing label reads back as "").
[[nodiscard]] inline std::vector<LaunchctlRow>
parse_launchctl_list(std::span<const std::string> lines) {
    std::vector<LaunchctlRow> out;
    if (lines.empty())
        return out;
    out.reserve(lines.size() - 1);

    for (std::size_t i = 1; i < lines.size(); ++i) {
        const std::string& line = lines[i];
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

        LaunchctlRow row;
        auto pid_str = next_field();
        auto status_str = next_field();
        row.label = next_field();

        if (pid_str == "-" || pid_str.empty()) {
            row.pid = std::nullopt;
        } else {
            try {
                row.pid = std::stoll(pid_str);
            } catch (...) {
                row.pid = std::nullopt; // unparsable PID column -- treat as absent
            }
        }
        try {
            row.status = status_str.empty() ? 0 : std::stoi(status_str);
        } catch (...) {
            row.status = 0; // "-" or any other non-numeric status column
        }
        out.push_back(std::move(row));
    }
    return out;
}

} // namespace yuzu::shared

// launchd_state_for() moved to agents/core/include/yuzu/agent/launchd_state.hpp
// (A0 governance fix round: agents/shared/ is a deliberate zero-dependency
// leaf, and that function needs yuzu::agent::ServiceRunState from spark.hpp).
