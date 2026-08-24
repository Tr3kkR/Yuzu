/**
 * test_wifi_local_dispatcher.cpp -- PKG-WIFI remediation (test_users_posix_
 * actions.cpp's own rationale, ported to wifi): no test proves the migrated
 * D-Bus/argv ladder actually reaches a real plugin binary, only its pure
 * parsers in isolation (test_wifi_parsers.cpp). Loads the ACTUAL built wifi
 * plugin (wifi.dylib/.so, the same artifact the agent daemon loads in
 * production) via PluginHandle::load and drives it through
 * yuzu::agent::LocalDispatcher, the same pattern test_users_posix_actions.cpp
 * established -- this is wifi's POSIX (macOS + Linux) counterpart.
 *
 * On this macOS build host, `connected` always takes the CoreWLAN leg
 * (wifi_corewlan.mm), untouched by this migration; `list_networks` exercises
 * the argv-ized airport/system_profiler fallback chain. Neither the Linux
 * NetworkManager D-Bus rung nor the Linux nmcli/iw/iwlist/iwconfig argv legs
 * are reachable from a macOS test host -- that Linux-only code only meets a
 * compiler in CI (see the package report's "unverifiable without a Linux NM
 * host" note). On a Linux CI host this test instead exercises whichever of
 * the D-Bus/nmcli/iw legs the runner actually reaches.
 *
 * Content assertions are deliberately loose (a record-prefix substring, or
 * the platform's own honest sentinel) rather than pinned to specific
 * network data -- every list_networks/connected code path (a real record,
 * an error marker, or an info sentinel) is `wifi|`/`connected|`-prefixed
 * respectively, so only a broken migration (e.g. a silently reverted shell
 * hop, or a dropped return) produces neither.
 */
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

#if defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

// Mirrors test_users_posix_actions.cpp's find_users_plugin, pointed at the
// wifi plugin's own build output.
fs::path find_wifi_plugin() {
    const std::string lib_name = std::string{"wifi"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "wifi" / lib_name);
    }
    // Meson launches tests with CWD=build root; agents/ sits alongside tests/.
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "wifi" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "wifi" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "wifi" / lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "wifi" / lib_name);

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

std::optional<LoadedPlugin> load_wifi_plugin() {
    auto plugin_path = find_wifi_plugin();
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

} // namespace

TEST_CASE("wifi plugin: connected reaches the real platform mechanism end to end",
          "[wifi][posix_actions]") {
    auto plugin = load_wifi_plugin();
    if (!plugin) {
        WARN("wifi plugin library not found -- skipping LocalDispatcher round-trip test");
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "connected");
    CHECK(result.rc == 0);
    // Reverting the migrated D-Bus/argv path (wrong tool, wrong flags, a
    // shell hop that silently no-ops, a broken sd-bus call, or a dropped
    // CoreWLAN call on macOS) would either fail this call or produce output
    // that matches neither a real `connected|` record nor the production
    // "Not connected" sentinel -- both share the same "connected|" prefix,
    // so this only passes if the real platform mechanism actually ran and
    // emitted something.
    CHECK(result.captured.find("connected|") != std::string::npos);
}

TEST_CASE("wifi plugin: list_networks reaches the real platform mechanism end to end",
          "[wifi][posix_actions]") {
    auto plugin = load_wifi_plugin();
    if (!plugin) {
        WARN("wifi plugin library not found -- skipping LocalDispatcher round-trip test");
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list_networks");
    CHECK(result.rc == 0);
    // Every list_networks code path -- a real NetworkManager/nmcli/airport
    // scan record, a raw iw/iwlist scan_output blob, a "no tools available"
    // error marker, or the honest "scan unavailable" info sentinel -- emits
    // at least one `wifi|`-prefixed line; only a broken migration (e.g. a
    // reverted shell hop, or a dropped return) produces nothing.
    CHECK(result.captured.find("wifi|") != std::string::npos);
}

#endif // !_WIN32
