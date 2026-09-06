/**
 * test_autoruns_macos_local.cpp — macOS leg (P14) tests.
 *
 * UNGUARDED, deliberately, on every platform (precedent:
 * test_autoruns_local_dispatcher.cpp's own banner on why a compiled-out leg
 * must still have a test TU that loads it). Two halves:
 *
 *   1. `plist_to_launchd_fields` (autoruns_macos.hpp, header-only, Apple-only
 *      body) exercised directly against A2's REAL CAPTURE XML and binary
 *      plist fixtures — this is the ONE function real captures must drive
 *      through, since a symbol inside the dlopen'd autoruns plugin is not
 *      reachable from this test binary. Compiled only inside `#ifdef
 *      __APPLE__`: the header's non-Apple branch is a fixed, argument-
 *      independent stub with nothing fixture-shaped to assert against.
 *
 *   2. The actual autoruns plugin loaded via PluginHandle::load and driven
 *      through LocalDispatcher's "list" action (same technique as
 *      test_autoruns_local_dispatcher.cpp, scoped here to the macOS-specific
 *      assertions that dispatcher test does not make): on Apple,
 *      mac_system_launchdaemons reports supported with >= 50 rows; on every
 *      other OS, every macOS SourceId reports unsupported|foreign_os.
 */
#include <catch2/catch_test_macros.hpp>

#include "autoruns_catalog.hpp"
#include "autoruns_macos.hpp"
#include "autoruns_parsers.hpp"

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::autoruns;

namespace {

fs::path fixture_path(const std::string& rel) {
    return fs::path{YUZU_TEST_FIXTURE_DIR} / "wave7" / "autoruns" / "macos" / rel;
}

std::vector<std::uint8_t> read_fixture(const std::string& rel) {
    const fs::path p = fixture_path(rel);
    REQUIRE(fs::exists(p));
    std::ifstream f(p, std::ios::binary);
    std::vector<std::uint8_t> out((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    REQUIRE_FALSE(out.empty());
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

void skip_if_plugin_missing() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr)
        FAIL("autoruns plugin library not found under meson test -- it did not build, or "
             "link_depends is not forcing it to build before this test runs");
    WARN("autoruns plugin library not found -- skipping the LocalDispatcher round-trip");
}

} // namespace

// ── plist_to_launchd_fields over REAL CAPTURE fixtures (Apple-only) ───────

#if defined(__APPLE__)

TEST_CASE("autoruns macOS: plist_to_launchd_fields on a real XML LaunchAgent plist "
          "(homebrew.mxcl.postgresql@18.plist, real capture)",
          "[autoruns][macos]") {
    const auto bytes = read_fixture("homebrew.mxcl.postgresql@18.plist");
    const auto result = plist_to_launchd_fields(std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    REQUIRE(result.has_value());
    CHECK(result->label == "homebrew.mxcl.postgresql@18");
    CHECK(result->program.empty()); // no `Program` key in this real capture
    REQUIRE_FALSE(result->program_arguments.empty());
    CHECK(result->program_arguments.front() == "/opt/homebrew/opt/postgresql@18/bin/postgres");
    CHECK_FALSE(result->disabled_present); // no `Disabled` key in this real capture
}

TEST_CASE("autoruns macOS: plist_to_launchd_fields on a real XML LaunchDaemon plist with "
          "an explicit Program key (com.docker.socket.plist, real capture)",
          "[autoruns][macos]") {
    const auto bytes = read_fixture("com.docker.socket.plist");
    const auto result = plist_to_launchd_fields(std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    REQUIRE(result.has_value());
    CHECK(result->label == "com.docker.socket");
    CHECK(result->program == "/Library/PrivilegedHelperTools/com.docker.socket");
}

TEST_CASE("autoruns macOS: plist_to_launchd_fields on a real BINARY plist "
          "(com.apple.AppleCredentialManagerDaemon.plist, real capture, bplist00 magic)",
          "[autoruns][macos]") {
    const auto bytes = read_fixture("com.apple.AppleCredentialManagerDaemon.plist");
    REQUIRE(bytes.size() >= 8);
    CHECK(std::string(bytes.begin(), bytes.begin() + 6) == "bplist"); // confirms the fixture IS binary
    const auto result = plist_to_launchd_fields(std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    REQUIRE(result.has_value());
    CHECK(result->label == "com.apple.AppleCredentialManagerDaemon");
    CHECK(result->program.empty());
    REQUIRE_FALSE(result->program_arguments.empty());
    CHECK(result->program_arguments.front() ==
         "/System/Library/PrivateFrameworks/AppleCredentialManager.framework/AppleCredentialManagerDaemon");
    CHECK_FALSE(result->disabled_present);
}

TEST_CASE("autoruns macOS: plist_to_launchd_fields on a second real BINARY plist "
          "(com.apple.AssetCacheLocatorService.plist, real capture)",
          "[autoruns][macos]") {
    const auto bytes = read_fixture("com.apple.AssetCacheLocatorService.plist");
    const auto result = plist_to_launchd_fields(std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    REQUIRE(result.has_value());
    CHECK(result->label == "com.apple.AssetCacheLocatorService");
    REQUIRE(result->program_arguments.size() >= 2);
    CHECK(result->program_arguments[1] == "-d");
}

TEST_CASE("autoruns macOS: launchd_row_from_fields over a real XML capture's parsed fields "
          "produces the expected autorun row shape",
          "[autoruns][macos]") {
    const auto bytes = read_fixture("com.docker.vmnetd.plist");
    const auto result = plist_to_launchd_fields(std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    REQUIRE(result.has_value());
    const Row row = launchd_row_from_fields(SourceId::mac_launchdaemons, *result,
                                            "/Library/LaunchDaemons/com.docker.vmnetd.plist",
                                            Scope::system, 0);
    CHECK(row.source_id == SourceId::mac_launchdaemons);
    CHECK(row.entry == result->label);
    CHECK(row.signed_state == Signed::not_checked); // not under /System/Library
    CHECK(row.enabled == Enabled::enabled); // no Disabled key in this real capture
}

TEST_CASE("autoruns macOS: a plist with none of Disabled/RunAtLoad/KeepAlive/Start* "
          "still reports enabled, not unmodelled (RECONSTRUCTION: pins the documented "
          "divergence from the objective's literal key list -- see "
          "docs/wave7/integration-autoruns-macos.md #4 and autoruns_macos.hpp's SCOPE "
          "NOTE: LaunchdFields, P11, carries no members for those four keys, so this "
          "leg cannot reach the `unmodelled` branch the objective describes)",
          "[autoruns][macos]") {
    static constexpr std::string_view kBarePlist =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
        "<plist version=\"1.0\"><dict>"
        "<key>Label</key><string>com.example.bare</string>"
        "</dict></plist>";
    const std::vector<std::uint8_t> bytes(kBarePlist.begin(), kBarePlist.end());
    const auto result = plist_to_launchd_fields(std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    REQUIRE(result.has_value());
    CHECK_FALSE(result->disabled_present);
    const Row row = launchd_row_from_fields(SourceId::mac_launchagents, *result,
                                            "/Library/LaunchAgents/com.example.bare.plist",
                                            Scope::system, 0);
    CHECK(row.enabled == Enabled::enabled);
}

TEST_CASE("autoruns macOS: a truncated plist yields a typed error, never a crash or an "
          "empty success (RECONSTRUCTION: a real capture cut to its first 16 bytes)",
          "[autoruns][macos]") {
    auto bytes = read_fixture("homebrew.mxcl.postgresql@18.plist");
    REQUIRE(bytes.size() > 16);
    bytes.resize(16); // "<?xml version=\"1" -- an unterminated document
    const auto result = plist_to_launchd_fields(std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == PlistError::unparseable);
}

TEST_CASE("autoruns macOS: an empty byte span yields a typed error, never a crash",
          "[autoruns][macos]") {
    const auto result = plist_to_launchd_fields(std::span<const std::uint8_t>{});
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == PlistError::unparseable);
}

TEST_CASE("autoruns macOS: a well-formed plist whose root is not a dictionary "
          "(RECONSTRUCTION: a bare XML array) is unparseable for launchd purposes",
          "[autoruns][macos]") {
    static constexpr std::string_view kArrayPlist =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
        "<plist version=\"1.0\"><array><string>not a dict</string></array></plist>";
    const std::vector<std::uint8_t> bytes(kArrayPlist.begin(), kArrayPlist.end());
    const auto result = plist_to_launchd_fields(std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == PlistError::unparseable);
}

#endif // __APPLE__

// ── the real plugin, via LocalDispatcher (every OS) ────────────────────────

TEST_CASE("autoruns plugin: macOS SourceIds report correctly for this build's own OS",
          "[autoruns][macos][actions]") {
    auto plugin = load_autoruns_plugin();
    if (!plugin) {
        skip_if_plugin_missing();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());

    std::set<std::string> macos_ids;
    for (const auto& decl : kSourceCatalog)
        if (decl.macos != YUZU_SUPPORT_UNSUPPORTED) macos_ids.insert(std::string{source_id_string(decl.id)});
    REQUIRE(macos_ids.size() == 8);

    std::set<std::string> seen_macos_status;
    std::size_t system_launchdaemon_rows = 0;

#if defined(__APPLE__)
    for (const auto& r : rows) {
        const auto f = fields_of(r);
        if (f[0] != "source") continue;
        if (macos_ids.count(f[1]) == 0) continue;
        seen_macos_status.insert(f[1]);
        if (f[1] == "mac_system_launchdaemons") {
            CHECK(f[2] == "supported");
            system_launchdaemon_rows = f[3] == "-" ? 0 : static_cast<std::size_t>(std::stoul(f[3]));
        }
        if (f[1] == "mac_login_items") {
            CHECK(f[2] == "constrained");
            CHECK(f[3] == "0");
            CHECK(f[4] == "btm_private_database_no_public_api");
        }
    }
    // Every macOS SourceId emits one source| line.
    CHECK(seen_macos_status.size() == macos_ids.size());
    CHECK(system_launchdaemon_rows >= 50);
#else
    for (const auto& r : rows) {
        const auto f = fields_of(r);
        if (f[0] != "source") continue;
        if (macos_ids.count(f[1]) == 0) continue;
        seen_macos_status.insert(f[1]);
        CHECK(f[2] == "unsupported");
        CHECK(f[4] == "foreign_os");
    }
    CHECK(seen_macos_status.size() == macos_ids.size());
#endif
}
