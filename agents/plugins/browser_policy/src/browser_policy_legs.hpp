/**
 * browser_policy_legs.hpp — shared seam between the browser_policy plugin TU
 * and its three per-OS leg TUs (peripherals_legs.hpp / disk_actions_legs.hpp
 * are the sibling shape).
 *
 * Each `run_<os>` is a READ and returns 0 unconditionally: a degraded read
 * is not a failed command, and the degradation is reported through the CC-07
 * typed status (`mark_result_read`) instead. Declared unconditionally so the
 * plugin TU and every leg TU see one signature on every OS; only the
 * DEFINITION is self-gated (each leg .cpp wraps its body in
 * `#if defined(_WIN32|__linux__|__APPLE__)`), and the plugin TU calls only
 * the host leg — a single-OS build never links the other two.
 */
#pragma once

#include <yuzu/plugin.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace yuzu::browser_policy {

int run_windows(yuzu::CommandContext& ctx);
int run_linux(yuzu::CommandContext& ctx);
int run_macos(yuzu::CommandContext& ctx);

/// Reason literal for an exception that escaped a leg (never crosses the
/// plugin ABI: plugin.cpp catches it and reports it through this token).
#if defined(_WIN32)
inline constexpr std::string_view kExceptionToken = "windows:leg:exception";
#elif defined(__APPLE__)
inline constexpr std::string_view kExceptionToken = "macos:leg:exception";
#else
inline constexpr std::string_view kExceptionToken = "linux:leg:exception";
#endif

/// Emits every row, one write_output each.
inline void write_rows(yuzu::CommandContext& ctx, const std::vector<std::string>& rows) {
    for (const auto& row : rows)
        ctx.write_output(row);
}

/// The ONE seam every leg reports its outcome through (CC-07). Rows already
/// written stand either way.
///   failure_reason empty  -> OK/FULL. Zero rows here is a genuinely absent
///                            policy set (browser not installed, nothing
///                            managed) — no placeholder row is written.
///   failure_reason set    -> CONSTRAINED/PARTIAL with the (comma-joined,
///                            `<os>:<detail>`) reason: some root, directory,
///                            file or value could not be read or decoded, so
///                            the rows are a lower bound, never proof of
///                            absence.
inline void mark_result_read(yuzu::CommandContext& ctx, std::string_view failure_reason) {
    if (!failure_reason.empty()) {
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              failure_reason);
        return;
    }
    ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
}

} // namespace yuzu::browser_policy
