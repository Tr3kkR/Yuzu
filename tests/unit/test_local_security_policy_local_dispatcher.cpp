/**
 * test_local_security_policy_local_dispatcher.cpp -- loads the ACTUAL built
 * local_security_policy plugin via PluginHandle::load and drives it through
 * yuzu::agent::LocalDispatcher.
 *
 * RUNS ON ALL THREE PLATFORMS, unconditionally -- no platform guard on any TEST_CASE
 * (a guarded dispatcher TU hid a never-loaded plugin on PR6.1-b). The plugin reads real
 * host files (/etc/sudoers, a live secedit export, a live pwpolicy plist), so the CI
 * runner's actual permissions decide OK vs CONSTRAINED vs PERMISSION_DENIED -- this file
 * asserts the WIRE SHAPE and status coherence the plugin promises for every outcome, not
 * one specific host's content.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

namespace {

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

std::vector<std::string> captured_rows(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    for (std::string line; std::getline(ss, line);) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            out.push_back(line);
    }
    return out;
}

void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr)
        FAIL("local_security_policy plugin library not found under meson test -- the plugin "
             "did not build, or link_depends is not forcing it to build before this test runs");
    WARN("local_security_policy plugin library not found -- skipping (run from the build root, "
         "or via `meson test`, to exercise it)");
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

std::optional<LoadedPlugin> load_plugin() {
    const fs::path rel = fs::path{"agents"} / "plugins" / "local_security_policy" /
                         (std::string{"local_security_policy"} + kPluginExt);
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_BUILD_ROOT"))
        candidates.push_back(fs::path{root} / rel);
    for (const char* dir : {".", "..", "build-macos", "build-windows", "build-linux"})
        candidates.push_back(fs::path{dir} / rel);
    for (const auto& p : candidates) {
        std::error_code ec;
        if (!fs::exists(p, ec) || ec)
            continue;
        auto handle = yuzu::agent::PluginHandle::load(fs::absolute(p, ec));
        if (!handle.has_value() || !handle->descriptor())
            return std::nullopt;
        const auto* descriptor = handle->descriptor();
        return LoadedPlugin{std::move(*handle), descriptor};
    }
    return std::nullopt;
}

} // namespace

TEST_CASE("local_security_policy plugin: all four actions declared; sudoers is the only "
          "Windows-unsupported leg",
          "[local_security_policy][descriptors]") {
    auto plugin = load_plugin();
    if (!plugin)
        return require_plugin_or_skip();

    REQUIRE(plugin->descriptor->action_descriptor_count == 4);
    REQUIRE(plugin->descriptor->action_descriptors != nullptr);
    std::unordered_set<std::string> seen;
    for (std::size_t i = 0; i < plugin->descriptor->action_descriptor_count; ++i) {
        const auto& d = plugin->descriptor->action_descriptors[i];
        REQUIRE(d.action != nullptr);
        const std::string_view action{d.action};
        INFO("action: " << action);
        seen.insert(std::string{action});

        // Every leg is declared for every action -- never left undeclared, even on a
        // single-OS build (the capability-matrix generator needs a complete, stable shape).
        CHECK(d.linux_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(d.macos_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(d.windows_leg.support != YUZU_SUPPORT_UNDECLARED);

        if (action == "sudoers") {
            CHECK(d.linux_leg.support == YUZU_SUPPORT_CONSTRAINED);
            CHECK(d.linux_leg.rung == 1);
            CHECK(d.macos_leg.support == YUZU_SUPPORT_CONSTRAINED);
            CHECK(d.macos_leg.rung == 1);
            CHECK(d.windows_leg.support == YUZU_SUPPORT_UNSUPPORTED); // no sudoers on Windows
            CHECK(d.windows_leg.rung == 0);
            CHECK(d.windows_leg.fallback == nullptr);
        } else {
            CHECK(d.linux_leg.support == YUZU_SUPPORT_CONSTRAINED);
            CHECK(d.linux_leg.rung == 1);
            CHECK(d.windows_leg.support == YUZU_SUPPORT_CONSTRAINED);
            CHECK(d.windows_leg.rung == 2); // secedit /export, an argv leaf
            CHECK(d.windows_leg.fallback != nullptr);
            // macOS: password/lockout come from pwpolicy (rung 2); audit_policy reads a
            // plain file (rung 1).
            CHECK(d.macos_leg.support == YUZU_SUPPORT_CONSTRAINED);
            CHECK(d.macos_leg.rung == (action == "audit_policy" ? 1 : 2));
        }
        CHECK(d.linux_leg.fallback != nullptr);
        CHECK(d.macos_leg.fallback != nullptr);
    }
    CHECK(seen == std::unordered_set<std::string>{"password_policy", "lockout_policy",
                                                   "audit_policy", "sudoers"});
}

TEST_CASE("local_security_policy plugin: sudoers refuses cleanly with a fixed row on Windows",
          "[local_security_policy][actions]") {
    auto plugin = load_plugin();
    if (!plugin)
        return require_plugin_or_skip();
    if (std::string{kPluginExt} != ".dll")
        return; // this exact fixed shape is the Windows leg's own short-circuit

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "sudoers");
    const auto rows = captured_rows(result.captured);
    CHECK(result.rc == 1);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "sudoers|-|unsupported|-|-|-|windows_has_no_sudoers");
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == "windows_has_no_sudoers");
}

TEST_CASE("local_security_policy plugin: each action reports a coherent status, never an "
          "empty success",
          "[local_security_policy][actions]") {
    auto plugin = load_plugin();
    if (!plugin)
        return require_plugin_or_skip();

    for (const std::string action : {"password_policy", "lockout_policy", "audit_policy", "sudoers"}) {
        if (action == "sudoers" && std::string{kPluginExt} == ".dll")
            continue; // covered by the dedicated fixed-row test above

        INFO("action: " << action);
        yuzu::agent::LocalDispatcher dispatcher;
        auto result = dispatcher.run(plugin->descriptor, action);
        const auto rows = captured_rows(result.captured);

        REQUIRE_FALSE(rows.empty()); // never an empty success or an empty failure
        // Unlike several sibling plugins, this one's apply_collected() always returns 0
        // -- "a read returns 0, degradation is the status" (local_security_policy_legs.hpp) --
        // so rc is not a proxy for OK-vs-degraded here; result_status/completeness carry that.
        CHECK(result.rc == 0);

        for (const auto& r : rows) {
            INFO("row: " << r);
            const bool known = r.rfind(action + "|", 0) == 0 || r.rfind("constrained|", 0) == 0;
            CHECK(known);
            if (r.rfind("constrained|", 0) == 0)
                CHECK((result.result_status == YUZU_RESULT_STATUS_CONSTRAINED ||
                       result.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED ||
                       result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE));
        }
    }
}

TEST_CASE("local_security_policy plugin: an unknown action is refused, no typed status set",
          "[local_security_policy][actions]") {
    auto plugin = load_plugin();
    if (!plugin)
        return require_plugin_or_skip();

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "no|such\naction");
    const auto rows = captured_rows(result.captured);
    CHECK(result.rc == 1);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "unknown action: no\\|such action");
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNDECLARED); // the plugin never calls
                                                                   // set_result_status on this path
}
