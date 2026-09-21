/**
 * pkg_inventory_macos.cpp — macOS leg entry point (Homebrew).
 *
 * `run_macos` is a one-line wrapper over `run_macos_at`, which takes the
 * filesystem root as a parameter: production calls it with "/", the unit suite
 * exercises the walks in pkg_inventory_macos_parsers.hpp directly against a
 * fixture tree. Pure filesystem reads: no process is spawned and no `brew`
 * binary is invoked.
 */
#include "pkg_inventory_legs.hpp"
#include "pkg_inventory_macos_parsers.hpp"

#if defined(__APPLE__)

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::pkg_inventory {

namespace {

int run_macos_at(yuzu::CommandContext& ctx, Action a, const std::filesystem::path& root) {
    std::optional<std::string> constraint;
    std::vector<std::string> rows;
    switch (a) {
    case Action::managers: rows = mac::macos_manager_rows_at(root, constraint); break;
    case Action::packages: rows = mac::macos_package_rows_at(root, constraint); break;
    }
    emit_result(ctx, a, rows, constraint);
    return 0;
}

} // namespace

int run_macos(yuzu::CommandContext& ctx, Action a) {
    return run_macos_at(ctx, a, "/");
}

} // namespace yuzu::pkg_inventory

#endif // defined(__APPLE__)
