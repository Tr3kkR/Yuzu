/**
 * browser_policy_macos.cpp — macOS leg entry point.
 *
 * `run_macos` is a one-line wrapper over `run_macos_at` (defined in
 * browser_policy_macos_parsers.hpp), which takes the filesystem root as a
 * parameter. NOVEL SEAM: peripherals' `_at` precedent is Linux-only, so there
 * is no macOS template — production passes "/", the unit suite
 * (test_browser_policy_macos_plist.cpp) drives run_macos_at against a
 * materialized temp tree through a real CommandContext.
 */
#include "browser_policy_legs.hpp"

#if defined(__APPLE__)

#include "browser_policy_macos_parsers.hpp"

namespace yuzu::browser_policy {

int run_macos(yuzu::CommandContext& ctx) {
    return run_macos_at(ctx, "/");
}

} // namespace yuzu::browser_policy

#endif // defined(__APPLE__)
