/**
 * runtimes_linux.cpp -- Linux leg entry point.
 *
 * `run_linux` is a one-line wrapper over `lnx::run_linux_at`
 * (runtimes_linux_parsers.hpp), which takes the filesystem root as a parameter
 * (peripherals_linux.cpp shape): production calls it with "/", the unit suite
 * drives the action -> walk -> emit wiring (`lnx::run_linux_at`,
 * `lnx::action_rows_at`) and the walks directly against a materialized fixture
 * tree, so it never links or runs this TU (it only builds on __linux__).
 *
 * Every action is a READ that returns 0: a degraded read is reported through
 * the status row and set_result_status (emit_read), never as a failed command.
 */
#include "runtimes_legs.hpp"
#include "runtimes_linux_parsers.hpp"

#if defined(__linux__)

namespace yuzu::runtimes {

int run_linux(yuzu::CommandContext& ctx, Action a) {
    return lnx::run_linux_at(ctx, a, "/");
}

} // namespace yuzu::runtimes

#endif // defined(__linux__)
