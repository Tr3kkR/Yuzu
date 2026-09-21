/**
 * runtimes_linux.cpp -- Linux leg entry point.
 *
 * `run_linux` is a one-line wrapper over `run_linux_at`, which takes the
 * filesystem root as a parameter (peripherals_linux.cpp shape): production
 * calls it with "/", the unit suite exercises the action -> walk dispatch
 * (`lnx::action_rows_at`) and the walks in runtimes_linux_parsers.hpp
 * directly against a materialized fixture tree and never links or runs this TU
 * (it only builds on __linux__).
 *
 * Every action is a READ that returns 0: a degraded read is reported through
 * the status row and set_result_status (emit_read), never as a failed command.
 */
#include "runtimes_legs.hpp"
#include "runtimes_linux_parsers.hpp"

#if defined(__linux__)

#include <filesystem>
#include <string>
#include <vector>

namespace yuzu::runtimes {

namespace {

int run_linux_at(yuzu::CommandContext& ctx, Action a, const std::filesystem::path& root) {
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = lnx::action_rows_at(a, root, acc);
    emit_read(ctx, a, rows, acc);
    return 0;
}

} // namespace

int run_linux(yuzu::CommandContext& ctx, Action a) {
    return run_linux_at(ctx, a, "/");
}

} // namespace yuzu::runtimes

#endif // defined(__linux__)
