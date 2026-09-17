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

/// Result of parse_launchctl_list(): the decoded rows plus whether the input
/// was structurally trustworthy at all. `malformed` is a STRUCTURAL check
/// only -- line 0 must be exactly "PID\tStatus\tLabel" (a preamble line
/// before the real header, or a header-less capture where the first line is
/// already data, both fail this) -- distinct from a per-row policy decision
/// like BR-service-001 (an individual row with an empty label), which stays
/// the caller's job. `rows` is empty whenever `malformed` is true -- nothing
/// past an unrecognised header is trustworthy enough to decode.
struct LaunchctlParseResult {
    std::vector<LaunchctlRow> rows;
    bool malformed{false};
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
        return row; // 1-field row: nothing to decode at all
    std::string_view pid_sv = line.substr(0, tab1);
    std::string_view rest = line.substr(tab1 + 1);

    // 2-field row (no second tab): PID+status are still both present and
    // decoded below -- only the label is genuinely absent. status_sv is
    // `rest` in full; row.label stays "" (its default).
    auto tab2 = rest.find('\t');
    std::string_view status_sv = (tab2 == std::string_view::npos) ? rest : rest.substr(0, tab2);
    if (tab2 != std::string_view::npos)
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
/// SubprocessResult::lines' contract). An empty `lines` yields an empty,
/// non-malformed result (no output at all is not the same as garbage
/// output). Otherwise line 0 MUST be exactly "PID\tStatus\tLabel" -- a
/// preamble line before the real header, or a header-less capture, is
/// rejected wholesale (`malformed = true`, `rows` empty) rather than
/// decoded starting from the wrong line (UP-6, governance A0 fix round:
/// silently decoding from a wrong offset would misattribute every
/// subsequent field). Every row after a valid header decodes via
/// decode_launchctl_row(), which never throws.
[[nodiscard]] inline LaunchctlParseResult
parse_launchctl_list(std::span<const std::string> lines) {
    LaunchctlParseResult out;
    if (lines.empty())
        return out;
    if (lines[0] != "PID\tStatus\tLabel") {
        out.malformed = true;
        return out;
    }
    out.rows.reserve(lines.size() - 1);
    for (std::size_t i = 1; i < lines.size(); ++i)
        out.rows.push_back(decode_launchctl_row(lines[i]));
    return out;
}

} // namespace yuzu::shared

// launchd_state_for() moved to agents/core/include/yuzu/agent/launchd_state.hpp
// (A0 governance fix round: agents/shared/ is a deliberate zero-dependency
// leaf, and that function needs yuzu::agent::ServiceRunState from spark.hpp).
