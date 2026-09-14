/**
 * test_execution_artifacts_win_local.cpp — P32's per-artifact shape
 * assertions, on top of test_execution_artifacts_local_dispatcher.cpp's
 * generic "real row or named constrained token" check (P31, this package's
 * dependency): each of the three Windows-leg actions gets its own targeted
 * assertion here, one TEST_CASE per artifact.
 *
 * Same loading harness as test_execution_artifacts_local_dispatcher.cpp --
 * LocalDispatcher over the ACTUAL built execution_artifacts.dylib/.so/.dll
 * -- so this exercises the real compiled leg, never a mock. UNGUARDED TU
 * (compiles and runs on every OS, test_filesystem_posture_local_dispatcher
 * .cpp's precedent for why a platform-guarded test TU hides a dead leg):
 * non-Windows hosts assert the fixed unsupported|windows_only_artefact
 * outcome (P31's contract, this package's own copy of that assertion so the
 * check lives with the rest of this file's per-artifact coverage); Windows
 * hosts get this package's (P32) per-artifact assertions below.
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
#include <vector>

namespace fs = std::filesystem;

namespace {

std::vector<std::string> captured_rows(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            out.push_back(line);
    }
    return out;
}

[[maybe_unused]] bool any_row_starts_with(const std::vector<std::string>& rows,
                                          std::string_view prefix) {
    return std::any_of(rows.begin(), rows.end(),
                       [&](const std::string& r) { return r.rfind(prefix, 0) == 0; });
}

void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("execution_artifacts plugin library not found under meson test — the plugin did "
             "not build, or link_depends is not forcing it to build before this test runs");
    }
    WARN("execution_artifacts plugin library not found -- skipping the win-local shape checks "
         "(run from the build root, or via `meson test`, to exercise it)");
}

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_execution_artifacts_plugin() {
    const std::string lib_name = std::string{"execution_artifacts"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" /
                                "execution_artifacts" / lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "execution_artifacts" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "execution_artifacts" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" /
                            "execution_artifacts" / lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" /
                            "execution_artifacts" / lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" /
                            "execution_artifacts" / lib_name);

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

std::optional<LoadedPlugin> load_execution_artifacts_plugin() {
    auto plugin_path = find_execution_artifacts_plugin();
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

#if !defined(_WIN32)

TEST_CASE("execution_artifacts win-local: non-Windows still reports "
          "unsupported|windows_only_artefact for all three actions",
          "[execution_artifacts][win_local]") {
    auto plugin = load_execution_artifacts_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    for (const char* action : {"shimcache", "amcache", "prefetch"}) {
        INFO("action: " << action);
        auto result = dispatcher.run(plugin->descriptor, action);
        CHECK(result.rc == 1);
        const auto rows = captured_rows(result.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows.front() == "unsupported|windows_only_artefact");
    }
}

#else // defined(_WIN32)

TEST_CASE("execution_artifacts win-local: shimcache returns real rows or a named constrained "
          "token, never an empty success",
          "[execution_artifacts][win_local]") {
    auto plugin = load_execution_artifacts_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "shimcache");
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());

    const bool has_success_row = any_row_starts_with(rows, "shimcache|");
    const bool has_constrained_row = any_row_starts_with(rows, "constrained|");
    CHECK((has_success_row || has_constrained_row));
    if (has_success_row)
        CHECK(result.rc == 0);
    else
        CHECK(result.rc == 1);
}

TEST_CASE("execution_artifacts win-local: prefetch returns real rows when Prefetch is enabled, "
          "else a named constrained/prefetch_error token -- never silent-empty",
          "[execution_artifacts][win_local]") {
    auto plugin = load_execution_artifacts_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "prefetch");
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());

    const bool has_success_row = any_row_starts_with(rows, "prefetch|");
    const bool has_named_reason =
        any_row_starts_with(rows, "constrained|") || any_row_starts_with(rows, "prefetch_error|");
    CHECK((has_success_row || has_named_reason));
    if (has_success_row && !has_named_reason)
        CHECK(result.rc == 0);
}

TEST_CASE("execution_artifacts win-local: amcache returns real rows or a named token "
          "(hive_locked/hive_missing/hive_oversized/regload_*/amcache_root_missing/"
          "amcache_empty) -- never an empty success",
          "[execution_artifacts][win_local]") {
    auto plugin = load_execution_artifacts_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "amcache");
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());

    const bool has_success_row = any_row_starts_with(rows, "amcache|");
    const bool has_constrained_row = any_row_starts_with(rows, "constrained|");
    CHECK((has_success_row || has_constrained_row));
    if (has_success_row && !has_constrained_row)
        CHECK(result.rc == 0);
}

#endif
