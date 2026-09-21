/**
 * browser_policy_linux.cpp — Linux leg entry point.
 *
 * `run_linux` is a one-line wrapper over `run_linux_at` (defined in
 * browser_policy_linux_parsers.hpp), which takes the filesystem root as a
 * parameter (peripherals_linux.cpp is the precedent): production passes "/",
 * the unit suite drives run_linux_at against a temp tree through a real
 * CommandContext and never links this TU (it only builds on __linux__).
 */
#include "browser_policy_legs.hpp"
#include "browser_policy_linux_parsers.hpp"

#if defined(__linux__)

namespace yuzu::browser_policy {

int run_linux(yuzu::CommandContext& ctx) {
    return run_linux_at(ctx, "/");
}

} // namespace yuzu::browser_policy

#endif // defined(__linux__)
