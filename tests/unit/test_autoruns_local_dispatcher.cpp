/**
 * test_autoruns_local_dispatcher.cpp — loads the ACTUAL built autoruns
 * plugin (autoruns.dylib / .so / .dll) via PluginHandle::load and drives it
 * through yuzu::agent::LocalDispatcher, exercising the real per-OS leg on
 * the build host.
 *
 * UNGUARDED, deliberately, on all three platforms -- the precedent
 * test_disk_actions_local_dispatcher.cpp's banner documents why a
 * `#ifndef _WIN32` exclusion on a dispatcher TU is exactly how a compiled-out
 * leg ships green with no test ever loading it.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include "autoruns_catalog.hpp"

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <set>
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
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

/// Escape-aware field split (autoruns folds '|' to U+2502, not a backslash
/// escape, so a naive split('|') is already safe here -- no field can
/// contain a raw '|'. Kept as a named helper anyway so a future row shape
/// change to this file needs one edit, not several call sites hand-splitting).
std::vector<std::string> fields_of(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : row) {
        if (c == '|') { out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    out.push_back(cur);
    return out;
}

void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("autoruns plugin library not found under meson test -- the plugin did not build, "
             "or link_depends is not forcing it to build before this test runs");
    }
    WARN("autoruns plugin library not found -- skipping the LocalDispatcher round-trip");
}

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_autoruns_plugin() {
    const std::string lib_name = std::string{"autoruns"} + kPluginExt;
    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "autoruns" / lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "autoruns" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "autoruns" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "autoruns" / lib_name);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec)) return c;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
    explicit operator bool() const { return descriptor != nullptr; }
};

std::optional<LoadedPlugin> load_autoruns_plugin() {
    auto path = find_autoruns_plugin();
    if (path.empty()) return std::nullopt;
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded) return std::nullopt;
    const auto* d = loaded->descriptor();
    if (!d) return std::nullopt;
    return LoadedPlugin{std::move(*loaded), d};
}

} // namespace

TEST_CASE("autoruns plugin: catalog emits exactly one source line per SourceDecl",
          "[autoruns][actions]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "catalog");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    CHECK(rows.front().rfind("catalog|", 0) == 0);

    std::set<std::string> seen_ids;
    for (std::size_t i = 1; i < rows.size(); ++i) {
        const auto f = fields_of(rows[i]);
        REQUIRE(f.size() == 5);
        CHECK(f[0] == "source");
        seen_ids.insert(f[1]);
    }
    // Exactly one line per SourceDecl -- no source missing, none duplicated.
    CHECK(seen_ids.size() == yuzu::autoruns::kSourceCatalog.size());
    CHECK(rows.size() - 1 == yuzu::autoruns::kSourceCatalog.size());
}

TEST_CASE("autoruns plugin: list emits a source status per catalog source, every row's "
          "source_id known, and at least one host-native source is supported with rows",
          "[autoruns][actions]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());

    std::set<std::string> known_ids;
    for (const auto& decl : yuzu::autoruns::kSourceCatalog)
        known_ids.insert(std::string{yuzu::autoruns::source_id_string(decl.id)});

    std::set<std::string> seen_status_ids;
    std::size_t autorun_row_count = 0;
    for (const auto& r : rows) {
        const auto f = fields_of(r);
        if (f[0] == "source") {
            REQUIRE(f.size() == 5);
            CHECK(known_ids.count(f[1]) == 1);
            seen_status_ids.insert(f[1]);
        } else if (f[0] == "autorun") {
            REQUIRE(f.size() == 12);
            CHECK(known_ids.count(f[1]) == 1);
            ++autorun_row_count;
        }
    }
    // One status line per catalog source.
    CHECK(seen_status_ids.size() == known_ids.size());

#if defined(_WIN32)
    const std::string native_id = "win_run_hklm";
#elif defined(__APPLE__)
    const std::string native_id = "mac_system_launchdaemons";
#else
    const std::string native_id = "lnx_systemd_timers_system";
#endif
    bool native_supported_with_rows = false;
    for (const auto& r : rows) {
        const auto f = fields_of(r);
        if (f[0] == "source" && f[1] == native_id &&
            (f[2] == "supported" || f[2] == "constrained") && f[3] != "-" && f[3] != "0") {
            native_supported_with_rows = true;
        }
    }
    CHECK(native_supported_with_rows);
    CHECK(autorun_row_count > 0);
}

TEST_CASE("autoruns plugin: an unknown action is refused, not silently ignored",
          "[autoruns][actions]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "no_such_action");
    CHECK(result.rc != 0);
}
