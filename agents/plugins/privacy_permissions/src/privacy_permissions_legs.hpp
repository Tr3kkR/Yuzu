/**
 * privacy_permissions_legs.hpp -- the seam between the portable plugin TU and the per-OS
 * leg TUs. Each collect_* is defined by exactly one leg TU (self-#if-gated internally, same
 * shape as platform_security_legs.hpp / firmware_posture); the portable TU declares and calls
 * all three unconditionally.
 */
#pragma once

#include "privacy_permissions_parsers.hpp"

#include <yuzu/plugin.hpp>

namespace yuzu::privacy_permissions {

int collect_linux_permissions(yuzu::CommandContext& ctx);
int collect_macos_permissions(yuzu::CommandContext& ctx);
int collect_windows_permissions(yuzu::CommandContext& ctx);

/// Writes every row then the one status the rows collectively imply. Shared by all three legs
/// so the status-selection decision lives in exactly one place.
inline int emit_rows(yuzu::CommandContext& ctx, const std::vector<PermissionRow>& rows,
                     const yuzu::shared::ConstraintAccumulator& acc, bool unavailable) {
    for (const auto& r : rows) ctx.write_output(format_row(r));
    const auto st = select_status(acc, any_denied(rows), unavailable);
    ctx.set_result_status(st.status, st.completeness, st.provenance);
    return 0;
}

} // namespace yuzu::privacy_permissions
