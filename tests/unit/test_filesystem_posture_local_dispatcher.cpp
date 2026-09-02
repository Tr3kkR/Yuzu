/**
 * test_filesystem_posture_local_dispatcher.cpp — PKG-CORE (Wave-1): loads
 * the ACTUAL built filesystem_posture plugin (filesystem_posture.dylib/.so)
 * via PluginHandle::load and drives it through yuzu::agent::LocalDispatcher
 * (test_network_config_local_dispatcher.cpp's pattern), exercising all three
 * actions' real per-OS legs end to end on the build host.
 *
 * Assertions are OUTCOME-specific rather than only `rc == 0` (every action
 * returns 0 on every path by design -- see filesystem_posture_legs.hpp):
 * field count and enumerated-token shape per row. The field split is
 * escape-aware (peer L3): yuzu::util::safe_output_field escapes a literal
 * '|' as '\|', so a naive split('|') would overcount fields on any row
 * whose escaped text happens to contain a pipe.
 *
 * POSIX-only (macOS + Linux) -- Windows legs are compile-verified only, not
 * exercised against a live host in this change (see the plugin's own
 * descriptor fallback prose).
 */
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include "filesystem_posture_legs.hpp"

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

// Escape-aware split: a backslash-preceded '|' is DATA (safe_output_field's
// own escape for a literal pipe), never a field separator. safe_output_field
// folds every literal backslash in the source value to '/' before escaping,
// so an observed "\|" in plugin output is unambiguous.
std::vector<std::string> split_fields_escape_aware(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            cur += '|';
            ++i;
        } else if (row[i] == '|') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    out.push_back(cur);
    return out;
}

// Returns every non-empty captured row (peer PKG-008): filtering by prefix
// let a wrong-prefix row disappear silently instead of failing the shape
// assertions below, so every row -- not just the ones matching the expected
// prefix -- must be checked.
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

// Mirrors test_network_config_local_dispatcher.cpp's require_plugin_or_skip:
// under `meson test` (MESON_BUILD_ROOT always set), a missing plugin means
// the build is genuinely broken and must NOT report "All tests passed".
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("filesystem_posture plugin library not found under meson test — the plugin did not "
             "build, or link_depends is not forcing it to build before this test runs");
    }
    WARN("filesystem_posture plugin library not found -- skipping LocalDispatcher round-trip "
         "test (run from the build root, or via `meson test`, to exercise it)");
}

#if defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

// Candidate-path ladder: mirrors test_license_scan_actions.cpp:46-60 (5
// candidates -- an optional MESON_BUILD_ROOT-relative path plus 4 fixed
// relative-to-cwd fallbacks).
fs::path find_filesystem_posture_plugin() {
    const std::string lib_name = std::string{"filesystem_posture"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" /
                                "filesystem_posture" / lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "filesystem_posture" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "filesystem_posture" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" /
                            "filesystem_posture" / lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" /
                            "filesystem_posture" / lib_name);

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

std::optional<LoadedPlugin> load_filesystem_posture_plugin() {
    auto plugin_path = find_filesystem_posture_plugin();
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

const char* kQuotaTokens[] = {"configured",       "none",     "not_enabled",       "unsupported_fs",
                              "no_block_device", "permission_denied", "unavailable"};

const char* kSnapshotKinds[] = {"apfs", "btrfs_subvolume", "device_mapper", "vss", "none"};

bool one_of(const std::string& v, const char* const* set, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        if (v == set[i])
            return true;
    }
    return false;
}

// Callback that exercises mark_result_partial twice (peer PKG-002): the only
// deterministic way to prove the degraded-result seam -- constrained/partial
// status plus last-writer-wins provenance -- actually reaches LocalDispatcher
// rather than merely being called somewhere the compiler accepts.
int exercise_mark_result_partial(YuzuCommandContext* raw, const char* /*action*/,
                                 const YuzuParam* /*params*/, std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    yuzu::filesystem_posture::mark_result_partial(ctx, "first", "first failure");
    yuzu::filesystem_posture::mark_result_partial(ctx, "second", "second failure");
    return 0;
}

} // namespace

TEST_CASE("filesystem_posture: mark_result_partial's degraded status and last-writer provenance "
         "reach LocalDispatcher (peer PKG-002)",
         "[filesystem_posture][status]") {
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &exercise_mark_result_partial;

    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(&descriptor, "probe");

    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == "second");
}

TEST_CASE("filesystem_posture plugin: mounts action shape", "[filesystem_posture][posix_actions]") {
    auto plugin = load_filesystem_posture_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "mounts");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    // Every host has at least a root mount.
    REQUIRE_FALSE(rows.empty());

    for (const auto& r : rows) {
        const auto f = split_fields_escape_aware(r);
        REQUIRE(f.size() == 9);
        CHECK(f[0] == "mount");
    }
}

TEST_CASE("filesystem_posture plugin: quotas action shape", "[filesystem_posture][posix_actions]") {
    auto plugin = load_filesystem_posture_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "quotas");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    // Every host has at least a root mount, so at least one quota row.
    REQUIRE_FALSE(rows.empty());
    for (const auto& r : rows) {
        const auto f = split_fields_escape_aware(r);
        REQUIRE(f.size() == 7);
        CHECK(f[0] == "quota");
        CHECK(f[2] == "volume");
        CHECK(one_of(f[3], kQuotaTokens, std::size(kQuotaTokens)));
    }
}

TEST_CASE("filesystem_posture plugin: snapshots action shape",
         "[filesystem_posture][posix_actions]") {
    auto plugin = load_filesystem_posture_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "snapshots");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    // Every host has at least a root mount, so at least one snapshot row.
    REQUIRE_FALSE(rows.empty());
    for (const auto& r : rows) {
        const auto f = split_fields_escape_aware(r);
        REQUIRE(f.size() == 5);
        CHECK(f[0] == "snapshot");
        CHECK(one_of(f[3], kSnapshotKinds, std::size(kSnapshotKinds)));
    }
}

#endif // !_WIN32
