/**
 * browser_inventory_linux.cpp — Linux leg, COMPILING STUB.
 *
 * This package (P2a-1) ships only the pure parsers
 * (browser_inventory_parsers.hpp) and this placeholder body so the plugin
 * links and dispatches for every action before the real leg lands. P2a-2
 * (wave 2) replaces run_linux() below with the real
 * ~/.config/{google-chrome,microsoft-edge}/{Local State,Default/
 * Preferences,Default/Secure Preferences} reads, wired through the parsers
 * this package already ships.
 *
 * Reports CONSTRAINED (not UNAVAILABLE): unlike the macOS/Windows legs,
 * which are genuinely PLANNED work with no implementation date in this
 * descriptor, the Linux leg's descriptor rung in browser_inventory_plugin.
 * cpp is CONSTRAINED/SUPPORTED -- this stub is a known, temporary gap
 * inside this package's own wave, not a cross-PR placeholder.
 */
#include "browser_inventory_legs.hpp"

#if defined(__linux__)

namespace yuzu::browser_inventory {

int run_linux(yuzu::CommandContext& ctx, Action a) {
    mark_stub_linux(ctx, a);
    return 0;
}

} // namespace yuzu::browser_inventory

#endif // __linux__
