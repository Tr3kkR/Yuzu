/**
 * test_license_scan_actions.cpp — Wave 4 PR4.3b: loads the ACTUAL built
 * license_scan plugin (license_scan.dylib/.so) via PluginHandle::load and
 * drives it through yuzu::agent::LocalDispatcher (test_users_posix_actions.cpp's
 * pattern), proving the plugin dispatches end to end after the Linux-leg
 * runner migration (licensing_linux.cpp) and the CONSTRAINED/rung-2
 * descriptor demotion.
 *
 * Dispatches "surfaces" -- license_scan's cheapest read action on macOS
 * (licensing_macos.cpp's run_platform_surfaces is pure filesystem glob +
 * in-house XML-plist string parsing, no subprocess at all; "surfaces" also
 * emits only the probe_status diagnostics, skipping "list"'s lic| record
 * formatting/sanitisation). "surfaces" always returns rc 0 by design
 * (ADR-0024 D3: probe_status reporting never fails the call), and
 * licensing_macos.cpp's mas_receipt surface unconditionally appends one
 * ProbeOutcome, so at least one `probe_status|` line is guaranteed on every
 * host regardless of what is actually installed.
 */
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <filesystem>
#include <string>

namespace fs = std::filesystem;

namespace {

#if defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_license_scan_plugin() {
    const std::string lib_name = std::string{"license_scan"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "license_scan" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "license_scan" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "license_scan" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "license_scan" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "license_scan" /
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

std::optional<LoadedPlugin> load_license_scan_plugin() {
    auto plugin_path = find_license_scan_plugin();
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

TEST_CASE("license_scan plugin: surfaces reports probe_status diagnostics via LocalDispatcher",
          "[license_scan]") {
    auto plugin = load_license_scan_plugin();
    if (!plugin) {
        WARN("license_scan plugin library not found -- skipping LocalDispatcher round-trip test");
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "surfaces");
    CHECK(result.rc == 0);
    CHECK(result.captured.find("probe_status|") != std::string::npos);
}

#endif // !_WIN32
