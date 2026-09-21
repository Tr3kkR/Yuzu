/**
 * pkg_inventory_linux.cpp — Linux leg entry point.
 *
 * `run_linux` is a one-line wrapper over `run_linux_at`, which takes the
 * filesystem root as a parameter: production calls it with "/", the unit suite
 * exercises the walk in pkg_inventory_linux_parsers.hpp directly against a
 * fixture tree and never links or runs this TU (it only builds on __linux__).
 *
 * `managers`: manager identity/presence + config facts (linux_manager_rows_at).
 * `packages`: UNSUPPORTED by construction -- installed_apps.get_inventory_linux
 * owns the Linux package roster, and this leg never enumerates a package in any
 * form (Alex, 2026-09-19, "shrink").
 */
#include "pkg_inventory_legs.hpp"
#include "pkg_inventory_linux_parsers.hpp"

#if defined(__linux__)

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::pkg_inventory {

namespace {

int run_linux_at(yuzu::CommandContext& ctx, Action a, const std::filesystem::path& root) {
    switch (a) {
    case Action::managers: {
        std::optional<std::string> constraint;
        const auto rows = lnx::linux_manager_rows_at(root, constraint);
        emit_result(ctx, a, rows, constraint);
        break;
    }
    case Action::packages:
        emit_unsupported(ctx, a, kTokenLinuxPackagesOwned);
        break;
    }
    return 0;
}

} // namespace

int run_linux(yuzu::CommandContext& ctx, Action a) {
    return run_linux_at(ctx, a, "/");
}

} // namespace yuzu::pkg_inventory

#endif // defined(__linux__)
