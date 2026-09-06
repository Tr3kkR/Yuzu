/**
 * test_app_usage_local_dispatcher.cpp — loads the ACTUAL built app_usage
 * plugin (app_usage.dylib/.so/.dll) via PluginHandle::load and drives it
 * through yuzu::agent::LocalDispatcher (test_power_health_local_dispatcher
 * .cpp's pattern), UNGUARDED — init() is never called, which is exactly
 * the seam this package's spec calls out (CommandContext has no
 * get_config; only PluginContext, init()'s argument, does). This is the
 * test that proves execute() alone still resolves a sane tar.db path.
 *
 * RUNS ON ALL THREE PLATFORMS unconditionally, per
 * test_filesystem_posture_local_dispatcher.cpp's precedent for why a
 * platform-guarded dispatcher TU hides a dead leg.
 *
 * On a build host with no real tar.db under the platform default data
 * dir (every CI runner, and most dev hosts), `summary` is expected to
 * report `constrained|tar_db_unavailable|<path>|...` whose <path> ends in
 * "tar.db" under the platform default dir — never an empty success. A
 * host that DOES have a live tar.db (e.g. one running the real tar plugin
 * against the platform default data dir) instead gets a real `meta|` +
 * `usage|*` result — both are accepted; only silent-empty is not.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

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

std::vector<std::string> split_fields(const std::string& row) {
    std::vector<std::string> f;
    std::string cur;
    for (char c : row) {
        if (c == '|') {
            f.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    f.push_back(cur);
    return f;
}

void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("app_usage plugin library not found under meson test — the plugin did not build, "
             "or link_depends is not forcing it to build before this test runs");
    }
    WARN("app_usage plugin library not found -- skipping LocalDispatcher round-trip test (run "
         "from the build root, or via `meson test`, to exercise it)");
}

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
constexpr const char* kPlatformDefaultDbDir = "C:\\ProgramData\\yuzu\\agent";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
constexpr const char* kPlatformDefaultDbDir = "/var/lib/yuzu/agent";
#else
constexpr const char* kPluginExt = ".so";
constexpr const char* kPlatformDefaultDbDir = "/var/lib/yuzu/agent";
#endif

fs::path find_app_usage_plugin() {
    const std::string lib_name = std::string{"app_usage"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "app_usage" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "app_usage" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "app_usage" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "app_usage" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" / "app_usage" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "app_usage" /
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

std::optional<LoadedPlugin> load_app_usage_plugin() {
    auto plugin_path = find_app_usage_plugin();
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

TEST_CASE("app_usage plugin: ABI4 descriptors declare all three OS legs for every action, "
          "never #ifdef'd out (plugin.h:115-136)",
          "[app_usage][descriptors]") {
    auto plugin = load_app_usage_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    REQUIRE(plugin->descriptor->action_descriptor_count == 3);
    REQUIRE(plugin->descriptor->action_descriptors != nullptr);

    for (std::size_t i = 0; i < plugin->descriptor->action_descriptor_count; ++i) {
        const auto& d = plugin->descriptor->action_descriptors[i];
        INFO("action: " << (d.action ? d.action : "<null>"));
        CHECK(d.linux_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(d.macos_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(d.windows_leg.support != YUZU_SUPPORT_UNDECLARED);
    }
}

TEST_CASE("app_usage plugin: summary — real tar.db if present, else an explicit "
          "constrained|tar_db_unavailable|<path under the platform default dir>, never empty",
          "[app_usage][actions]") {
    auto plugin = load_app_usage_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    // UNGUARDED — no init() call, exactly this package's seam decision:
    // execute() must resolve a sane db path on its own.
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "summary");

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty()); // never an empty success

    const auto first = split_fields(rows.front());
    if (first[0] == "constrained" && rows.size() >= 1 &&
        rows.front().rfind("constrained|tar_db_unavailable|", 0) == 0) {
        // "no db at path" distinguished from "no path": the resolved path
        // must be non-empty and end in tar.db under the platform default
        // dir -- proving execute() actually resolved a real path rather
        // than looking nowhere.
        CHECK(result.rc == 1);
        const auto fields = split_fields(rows.front());
        REQUIRE(fields.size() >= 3);
        const std::string& resolved_path = fields[2];
        CHECK_FALSE(resolved_path.empty());
        CHECK(resolved_path.size() >= 6);
        CHECK(resolved_path.compare(resolved_path.size() - 6, 6, "tar.db") == 0);
        CHECK(resolved_path.find(kPlatformDefaultDbDir) == 0);
        return;
    }

    // A real tar.db was found on this host — meta + (zero or more) usage rows.
    CHECK(result.rc == 0);
    if (rows.front().rfind("constrained|usage_source_disabled|", 0) == 0 ||
        rows.front().rfind("constrained|usage_schema_missing|", 0) == 0) {
        // A real, openable tar.db whose TAR predates usage_daily or has usage_enabled=false
        // legitimately answers constrained (rc 0) — not the meta| success shape (review M2).
        SUCCEED("openable tar.db without a usage source: constrained token accepted");
        return;
    }
    CHECK(rows.front().rfind("meta|", 0) == 0);
    for (std::size_t i = 1; i < rows.size(); ++i)
        CHECK(rows[i].rfind("usage|", 0) == 0);
}

TEST_CASE("app_usage plugin: foreground is always constrained, exit code agrees with typed "
          "status",
          "[app_usage][actions]") {
    auto plugin = load_app_usage_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "foreground");

    CHECK(result.rc == 1);
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);  // spec: foreground -> UNAVAILABLE (review M1)

    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows.front().rfind("constrained|foreground_not_captured|", 0) == 0);
}
