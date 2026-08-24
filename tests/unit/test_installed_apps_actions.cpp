/**
 * test_installed_apps_actions.cpp -- Wave 4 PR4.3a dispatch remediation:
 * loads the ACTUAL built installed_apps plugin (installed_apps.dylib/.so, the
 * same artifact the agent daemon loads in production) via PluginHandle::load
 * and drives it through yuzu::agent::LocalDispatcher, same pattern as
 * test_users_posix_actions.cpp -- this proves the migrated argv (probe_tool_path
 * + run_bounded_subprocess, replacing popen()/command_exists()) actually
 * reaches a real dpkg-query/rpm/pacman/system_profiler binary on the test
 * host, end to end, not just that the pure parsers in
 * installed_apps_parsers.hpp accept a fixture string.
 *
 * `list` is the fast, local, always-available action (no params, no
 * per-app enrichment loop) -- assertions are on rc and output SHAPE
 * (every emitted line matches the `app|` wire prefix), never on specific
 * app names/counts, which are entirely host-dependent.
 */
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <sstream>
#include <string>

namespace fs = std::filesystem;

namespace {

#if defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

// Mirrors test_users_posix_actions.cpp's find_users_plugin(), pointed at the
// installed_apps plugin's own build output.
fs::path find_installed_apps_plugin() {
    const std::string lib_name = std::string{"installed_apps"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "installed_apps" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "installed_apps" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "installed_apps" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "installed_apps" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "installed_apps" /
                            lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

std::optional<LoadedPlugin> load_installed_apps_plugin() {
    auto plugin_path = find_installed_apps_plugin();
    if (plugin_path.empty())
        return std::nullopt;
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value())
        return std::nullopt;
    const auto* descriptor = handle->descriptor();
    if (!descriptor)
        return std::nullopt;
    return LoadedPlugin{std::move(*handle), descriptor};
}

// Every line of `list`'s output is either a real `app|name|version|publisher|
// install_date` row or the plugin's own honest-empty sentinel
// ("app|No applications found|-|-|-") -- both share the `app|` prefix, so a
// single prefix check covers both shapes.
std::size_t count_non_matching_lines(const std::string& captured, std::string_view prefix) {
    std::istringstream iss(captured);
    std::string line;
    std::size_t bad = 0;
    while (std::getline(iss, line)) {
        if (line.empty())
            continue;
        if (line.compare(0, prefix.size(), prefix) != 0)
            ++bad;
    }
    return bad;
}

} // namespace

TEST_CASE("installed_apps plugin: list executes real dpkg-query/rpm/pacman/system_profiler argv",
          "[installed_apps][posix_actions]") {
    auto plugin = load_installed_apps_plugin();
    if (!plugin) {
        WARN("installed_apps plugin library not found -- skipping LocalDispatcher round-trip test");
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");

    // rc==0 is the real signal here: a wrong/reverted argv (a stale
    // popen()/command_exists() call, a wrong tool path, or a malformed
    // format string the real tool rejects) would surface as a non-zero rc
    // or garbage output -- this call proves the migrated argv actually
    // reached a real tool on this host, not just that it compiles.
    CHECK(result.rc == 0);
    CHECK_FALSE(result.captured.empty());

    // Shape invariant: every emitted line is an `app|...` row, whether a
    // real app/package or the plugin's own "No applications found" sentinel
    // -- never a stray error string or fragment from a reverted parser.
    CHECK(count_non_matching_lines(result.captured, "app|") == 0);
}

#endif // !_WIN32
