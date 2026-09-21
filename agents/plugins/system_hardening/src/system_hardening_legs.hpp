/**
 * system_hardening_legs.hpp -- the seam between the portable plugin TU and
 * the three per-OS leg TUs (modelled on peripherals_legs.hpp /
 * disk_actions_legs.hpp). Each entry point is a READ that returns 0
 * unconditionally: a missing or unreadable key is a degraded read reported
 * through set_result_status, never a failed command.
 *
 * Declared unconditionally so every TU sees one signature on every OS; only
 * the DEFINITION is self-gated (each leg TU wraps its whole body in
 * `#if defined(_WIN32|__linux__|__APPLE__)`), and the plugin TU calls only
 * the host leg. collect_posture_win is defined by system_hardening_win.cpp.
 */
#pragma once

#include "system_hardening_parsers.hpp"

#include <yuzu/plugin.hpp>

#include <vector>

namespace yuzu::system_hardening {

int collect_posture_linux(yuzu::CommandContext& ctx);
int collect_posture_macos(yuzu::CommandContext& ctx);
int collect_posture_win(yuzu::CommandContext& ctx);

/// Writes every row, then the CC-07 status: OK/FULL only when every
/// allowlisted key was read (acc holds no failure token); otherwise
/// CONSTRAINED/PARTIAL with the accumulated `<key>:<cause>` tokens as the
/// reason. An absent optional key downgrades the run by design.
inline void emit_posture(yuzu::CommandContext& ctx, const std::vector<PostureRow>& rows,
                         const yuzu::shared::ConstraintAccumulator& acc) {
    for (const auto& r : rows)
        ctx.write_output(format_posture_row(r));
    if (acc.any_failure())
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              acc.reason());
    else
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
}

} // namespace yuzu::system_hardening
