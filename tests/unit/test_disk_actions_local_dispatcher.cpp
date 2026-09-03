/**
 * test_disk_actions_local_dispatcher.cpp — loads the ACTUAL built disk_actions
 * plugin (disk_actions.dylib / .so / .dll) via PluginHandle::load and drives it
 * through yuzu::agent::LocalDispatcher, exercising the real per-OS legs on the
 * build host.
 *
 * RUNS ON ALL THREE PLATFORMS, deliberately and from the outset. The sibling
 * plugin's dispatcher TU shipped as `#ifndef _WIN32`, justified only by a
 * "Windows legs are compile-verified only" stance — and that exclusion is
 * precisely why a Windows leg whose implementation had been compiled out
 * entirely passed CI: no test ever loaded the Windows plugin. LocalDispatcher
 * and PluginHandle are both platform-neutral, so nothing technical requires the
 * exclusion, and the assertions below are scoped individually where their
 * SEMANTICS are platform-specific rather than excluding a whole platform.
 *
 * Note what a row-shape assertion can and cannot catch: a leg that is compiled
 * out can still emit a perfectly well-formed row. The BUILD-COMPLETENESS
 * assertions below are the ones that fail on a leg whose own guard excluded it.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include "disk_actions_legs.hpp"

#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

/// Escape-aware field split. yuzu::util::safe_output_field escapes a literal
/// '|' as '\|', so a naive split('|') overcounts fields on any row whose text
/// happens to contain a pipe.
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

bool one_of(const std::string& v, const char* const* set, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i)
        if (v == set[i]) return true;
    return false;
}

/// Under `meson test` (MESON_BUILD_ROOT is always set) a missing plugin means
/// the build is genuinely broken and must NOT report "All tests passed".
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("disk_actions plugin library not found under meson test — the plugin did not build, "
             "or link_depends is not forcing it to build before this test runs");
    }
    WARN("disk_actions plugin library not found -- skipping the LocalDispatcher round-trip");
}

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_disk_actions_plugin() {
    const std::string lib_name = std::string{"disk_actions"} + kPluginExt;
    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "disk_actions" /
                                lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "disk_actions" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "disk_actions" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "disk_actions" / lib_name);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec)) return c;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
    explicit operator bool() const { return descriptor != nullptr; }
};

std::optional<LoadedPlugin> load_disk_actions_plugin() {
    auto path = find_disk_actions_plugin();
    if (path.empty()) return std::nullopt;
    // PluginHandle::load returns std::expected<PluginHandle, LoadError>.
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded) return std::nullopt;
    const auto* d = loaded->descriptor();
    if (!d) return std::nullopt;
    return LoadedPlugin{std::move(*loaded), d};
}

// Fixed vocabularies, mirrored from disk_actions_legs.hpp. Deliberately spelled
// out rather than derived, so a silent change to the emitted token set fails
// here instead of passing by construction.
const char* kHealth[] = {"ok", "warning", "failing", "unknown", "unsupported"};
const char* kBus[] = {"nvme", "sata", "usb", "sas", "virtual", "unknown"};
const char* kMedia[] = {"ssd", "hdd", "unknown"};

} // namespace

TEST_CASE("disk_actions plugin: smart action row shape", "[disk_actions][actions]") {
    auto plugin = load_disk_actions_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "smart");
    CHECK(result.rc == 0); // a degraded read is never a failed command

    const auto rows = captured_rows(result.captured);
    // Every leg emits at least one row, including the honest unsupported one:
    // a consumer reading rows must never see silence and infer "no drives".
    REQUIRE_FALSE(rows.empty());

    for (const auto& r : rows) {
        const auto f = split_fields_escape_aware(r);
        REQUIRE(f.size() == 9);
        CHECK(f[0] == "smart");
        CHECK(one_of(f[3], kBus, std::size(kBus)));
        CHECK(one_of(f[4], kMedia, std::size(kMedia)));
        CHECK(one_of(f[5], kHealth, std::size(kHealth)));
    }
}

TEST_CASE("disk_actions plugin: volumes action row shape", "[disk_actions][actions]") {
    auto plugin = load_disk_actions_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "volumes");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());

    for (const auto& r : rows) {
        const auto f = split_fields_escape_aware(r);
        REQUIRE(f.size() == 7);
        CHECK(f[0] == "volume");
    }
}

TEST_CASE("disk_actions plugin: an unknown action is refused, not silently ignored",
          "[disk_actions][actions]") {
    auto plugin = load_disk_actions_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "no_such_action");
    CHECK(result.rc != 0);
}

// ── pure formatter tests: no plugin load, no OS call ─────────────────────

TEST_CASE("disk_actions: an absent percentage renders as '-', never as 0",
          "[disk_actions][format]") {
    using namespace yuzu::disk_actions;
    // "we did not read this" and "this is zero" are different facts, and a
    // consumer keying on the column must be able to tell them apart.
    const auto absent = format_smart_row("d", "m", Bus::Nvme, Media::Ssd, Health::Unknown,
                                         std::nullopt, std::nullopt, "-");
    CHECK(absent == "smart|d|m|nvme|ssd|unknown|-|-|-");

    const auto zero = format_smart_row("d", "m", Bus::Nvme, Media::Ssd, Health::Ok,
                                       std::optional<std::uint8_t>{0},
                                       std::optional<std::uint8_t>{0}, "-");
    CHECK(zero == "smart|d|m|nvme|ssd|ok|0|0|-");
}

TEST_CASE("disk_actions: an out-of-range percentage is clamped, not dropped",
          "[disk_actions][format]") {
    using namespace yuzu::disk_actions;
    // A device reporting 255% used is malformed, but discarding the row would
    // hide a drive that is plausibly in trouble.
    const auto r = format_smart_row("d", "m", Bus::Nvme, Media::Ssd, Health::Warning,
                                    std::optional<std::uint8_t>{255},
                                    std::optional<std::uint8_t>{200}, "-");
    CHECK(r == "smart|d|m|nvme|ssd|warning|100|100|-");
}

TEST_CASE("disk_actions: untrusted fields cannot forge a column separator",
          "[disk_actions][format]") {
    using namespace yuzu::disk_actions;
    // A drive model is OS-supplied text. If it could inject a bare '|' it would
    // shift every later column for a positional consumer.
    const auto r = format_smart_row("dev", "EVIL|MODEL", Bus::Unknown, Media::Unknown,
                                    Health::Unknown, std::nullopt, std::nullopt, "-");
    const auto f = split_fields_escape_aware(r);
    REQUIRE(f.size() == 9);
    CHECK(f[2] == "EVIL|MODEL"); // round-trips through the escape, one field
}

TEST_CASE("disk_actions: the volume row carries the physical-to-logical join",
          "[disk_actions][format]") {
    using namespace yuzu::disk_actions;
    // The reason this action exists: which physical device backs which mount
    // points. Neither hardware.disks nor filesystem_posture.mounts answers it.
    const auto r = format_volume_row("disk0s2", "/,/System/Volumes/Data", "disk0", "apfs",
                                     std::optional<std::uint64_t>{494384795648}, "-");
    CHECK(r == "volume|disk0s2|/,/System/Volumes/Data|disk0|apfs|494384795648|-");
}
