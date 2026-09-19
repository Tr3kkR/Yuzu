/**
 * peripherals_win.cpp — Windows leg entry point.
 *
 * PLANNED, not yet implemented. This PR ships the macOS and Linux legs plus
 * the shared scaffold; the Windows leg (SetupAPI-based, see the PLANNED
 * mechanism names on each action's `.windows_leg` descriptor in
 * peripherals_plugin.cpp) lands in a focused follow-up PR on top of this
 * one, matching this plugin's own historical Wave-1-placeholder convention
 * (see peripherals_legs.hpp's header banner) rather than a bare stub with no
 * precedent.
 */
#include "peripherals_legs.hpp"

#if defined(_WIN32)

namespace yuzu::peripherals {

int run_windows(yuzu::CommandContext& ctx, Kind k) {
    mark_result_read(ctx, k, 0, "windows:leg:not_implemented");
    return 0;
}

} // namespace yuzu::peripherals

#endif // defined(_WIN32)
