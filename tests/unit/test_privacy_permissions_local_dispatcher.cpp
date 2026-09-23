/**
 * test_privacy_permissions_local_dispatcher.cpp -- loads the ACTUAL built plugin and drives
 * the `permissions` action through yuzu::agent::LocalDispatcher. Unguarded (runs on all three
 * OSes). Assertions are row-shape and status invariants, never host-specific grant values: a
 * host may or may not have any camera/microphone/location/full-disk-access grant recorded.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

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

#if defined(_WIN32)
constexpr const char* kExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kExt = ".dylib";
#else
constexpr const char* kExt = ".so";
#endif

std::optional<yuzu::agent::PluginHandle> load_plugin() {
    const std::string lib = std::string{"privacy_permissions"} + kExt;
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{root} / "agents" / "plugins" / "privacy_permissions" / lib);
    for (const char* b : {"", "..", "build-macos", "build-windows", "build-linux"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "privacy_permissions" / lib);
    for (const auto& c : candidates) {
        std::error_code ec;
        if (!fs::exists(c, ec)) continue;
        auto h = yuzu::agent::PluginHandle::load(fs::absolute(c, ec));
        if (h.has_value() && h->descriptor() != nullptr) return std::move(*h);
    }
    if (std::getenv("MESON_BUILD_ROOT") != nullptr)
        FAIL("privacy_permissions plugin library not found under meson test");
    WARN("privacy_permissions plugin library not found -- skipping (run via `meson test`)");
    return std::nullopt;
}

std::vector<std::string> rows_of(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    for (std::string l; std::getline(ss, l);) {
        if (!l.empty() && l.back() == '\r') l.pop_back();
        if (!l.empty()) out.push_back(l);
    }
    return out;
}

std::size_t field_count(const std::string& row) {
    std::size_t n = 1;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') ++i;
        else if (row[i] == '|') ++n;
    }
    return n;
}

} // namespace

TEST_CASE("privacy_permissions: descriptor pins the single action per OS",
          "[privacy_permissions][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    const auto* d = plugin->descriptor();
    REQUIRE(d->action_descriptor_count == 1);
    CHECK(std::string_view{d->action_descriptors[0].action} == "permissions");
}

TEST_CASE("privacy_permissions: unknown action reports rc=1 and a named row",
          "[privacy_permissions][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor(), "not_a_real_action");
    CHECK(result.rc == 1);
    const auto rows = rows_of(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows.front().rfind("unknown action:", 0) == 0);
}

TEST_CASE("privacy_permissions: permissions always returns at least one 8-field row",
          "[privacy_permissions][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor(), "permissions");
    const auto rows = rows_of(result.captured);
    REQUIRE_FALSE(rows.empty()); // never a genuinely empty result -- see the binding contract
    for (const auto& row : rows) {
        INFO(row);
        CHECK(row.rfind("permissions|", 0) == 0);
        CHECK(field_count(row) == 8);
    }
}

TEST_CASE("privacy_permissions: no category is silently omitted -- each of the four has its "
          "own row, or a whole-source row (category '-') stands for it",
          "[privacy_permissions][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) return;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor(), "permissions");
    std::vector<std::string> categories;
    for (const auto& row : rows_of(result.captured)) {
        // field 3 (0-based) is `category`; app_id (field 2) never contains an unescaped '|'.
        std::size_t start = 0;
        for (int i = 0; i < 3; ++i) start = row.find('|', start) + 1;
        categories.push_back(row.substr(start, row.find('|', start) - start));
    }
    const auto has = [&](std::string_view c) {
        return std::find(categories.begin(), categories.end(), c) != categories.end();
    };
    const bool whole_source_row = has("-");
    for (const char* cat : {"camera", "microphone", "location", "full_disk_access"}) {
        INFO(cat);
        CHECK((has(cat) || whole_source_row));
    }
#if defined(__APPLE__)
    CHECK(has("location")); // macOS: location is its own `unsupported` row on every collection
#endif
}
