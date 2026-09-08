/**
 * peripherals_linux.cpp — Linux leg entry point.
 *
 * WAVE 1 PLACEHOLDER. No sysfs read is made yet; every action reports the
 * honest `linux:leg:not_implemented` unavailable row through
 * mark_result_read. Wave 2 (P91-6+) replaces this body with the real
 * /sys/bus/{usb,pci,thunderbolt}/devices walks the descriptor in
 * peripherals_plugin.cpp already commits to.
 */
#include "peripherals_legs.hpp"

#if defined(__linux__)

namespace yuzu::peripherals {

int run_linux(yuzu::CommandContext& ctx, Kind k) {
    mark_result_read(ctx, k, 0, "linux:leg:not_implemented");
    return 0;
}

} // namespace yuzu::peripherals

#endif // defined(__linux__)
