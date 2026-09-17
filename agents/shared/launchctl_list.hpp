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

#include <charconv>
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

/// Decode one `launchctl list` data row: "PID\tStatus\tLabel". Splits on the
/// FIRST two tabs only -- the label field is everything after the second tab
/// verbatim, including any further literal tabs (a genuine label never
/// contains one, but a malformed/4+-field row is decoded rather than
/// mis-split). Fewer than 2 tabs in the line -- 1-field row (no tabs at all)
/// or 2-field row (one tab) -- yields whichever fields were present and an
/// empty label for the rest; never throws. `std::from_chars` on the raw
/// field, not `std::stoll`/`std::stoi`: a PARTIAL numeric match (e.g.
/// "12abc", or "0x1A" -- from_chars stops at the "x", not a hex parse) is
/// rejected as unparsable (pid -> nullopt, status -> 0), never silently
/// truncated to the numeric prefix the way stoll/stoi would.
[[nodiscard]] inline LaunchctlRow decode_launchctl_row(std::string_view line) {
    LaunchctlRow row;
    auto tab1 = line.find('\t');
    if (tab1 == std::string_view::npos)
        return row; // 1-field row: nothing past PID to decode
    std::string_view pid_sv = line.substr(0, tab1);
    std::string_view rest = line.substr(tab1 + 1);

    auto tab2 = rest.find('\t');
    if (tab2 == std::string_view::npos)
        return row; // 2-field row: PID+status present, no label at all
    std::string_view status_sv = rest.substr(0, tab2);
    row.label = std::string(rest.substr(tab2 + 1));

    if (pid_sv != "-" && !pid_sv.empty()) {
        std::int64_t v{};
        auto res = std::from_chars(pid_sv.data(), pid_sv.data() + pid_sv.size(), v);
        if (res.ec == std::errc{} && res.ptr == pid_sv.data() + pid_sv.size())
            row.pid = v;
    }
    if (status_sv != "-" && !status_sv.empty()) {
        int v{};
        auto res = std::from_chars(status_sv.data(), status_sv.data() + status_sv.size(), v);
        if (res.ec == std::errc{} && res.ptr == status_sv.data() + status_sv.size())
            row.status = v;
    }
    return row;
}

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
