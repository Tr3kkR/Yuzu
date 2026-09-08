/**
 * peripherals_macos.cpp — macOS leg entry point.
 *
 * WAVE 1 PLACEHOLDER. No IOKit call is made yet; every action reports the
 * honest `macos:leg:not_implemented` unavailable row through
 * mark_result_read. Wave 2 (P91-6+) replaces this body with the real
 * IOServiceMatching(IOUSBHostDevice / IOPCIDevice / IOThunderboltSwitch)
 * walks the descriptor in peripherals_plugin.cpp already commits to.
 */
#include "peripherals_legs.hpp"

#if defined(__APPLE__)

namespace yuzu::peripherals {

int run_macos(yuzu::CommandContext& ctx, Kind k) {
    mark_result_read(ctx, k, 0, "macos:leg:not_implemented");
    return 0;
}

} // namespace yuzu::peripherals

#endif // defined(__APPLE__)
