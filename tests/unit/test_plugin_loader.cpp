#include <yuzu/agent/plugin_loader.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <random>
#include <string>
#include <system_error>

namespace fs = std::filesystem;

namespace {

#ifdef _WIN32
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

// Locate the reserved-name fixture plugin built by tests/meson.build
// (`reserved_name_fixture_plugin`). Returns empty path if not found —
// tests that require the fixture should SKIP rather than FAIL to keep
// cross-compile / restricted-CI scenarios quiet.
fs::path find_reserved_fixture_plugin() {
    const std::string lib_name = std::string{"reserved_name_fixture_plugin"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "tests" / lib_name);
    }
    // Meson launches tests with CWD=build root; tests/ sits alongside the exe.
    candidates.emplace_back(fs::path{"tests"} / lib_name);
    candidates.emplace_back(fs::path{"."} / lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec) return fs::absolute(p, ec);
    }
    return {};
}

} // namespace

TEST_CASE("PluginLoader returns empty result for nonexistent directory", "[plugin_loader]") {
    auto result = yuzu::agent::PluginLoader::scan("/nonexistent/path");
    REQUIRE(result.loaded.empty());
    REQUIRE(result.errors.empty());
}

TEST_CASE("PluginLoader returns empty result for empty directory", "[plugin_loader]") {
    auto tmp = fs::temp_directory_path() / "yuzu_test_empty_plugins";
    fs::create_directories(tmp);

    auto result = yuzu::agent::PluginLoader::scan(tmp);
    REQUIRE(result.loaded.empty());
    REQUIRE(result.errors.empty());

    fs::remove(tmp);
}

// ── #453 reserved-name namespace ─────────────────────────────────────────────

TEST_CASE("is_reserved_plugin_name matches the reserved set", "[plugin_loader][reserved_name]") {
    using yuzu::agent::is_reserved_plugin_name;

    REQUIRE(is_reserved_plugin_name("__guard__"));
    REQUIRE(is_reserved_plugin_name("__system__"));
    REQUIRE(is_reserved_plugin_name("__update__"));

    // Match must be exact (case-sensitive, no substring / prefix relaxation).
    REQUIRE_FALSE(is_reserved_plugin_name(""));
    REQUIRE_FALSE(is_reserved_plugin_name("example"));
    REQUIRE_FALSE(is_reserved_plugin_name("__GUARD__"));
    REQUIRE_FALSE(is_reserved_plugin_name("__guard"));
    REQUIRE_FALSE(is_reserved_plugin_name("_guard_"));
    REQUIRE_FALSE(is_reserved_plugin_name("x__guard__"));
    REQUIRE_FALSE(is_reserved_plugin_name("__guard__ "));
}

TEST_CASE("kReservedPluginNames covers guardian, system, update",
          "[plugin_loader][reserved_name]") {
    // Sanity-check the exact namespace. If a new reserved name is added,
    // this test is the deliberate trip-wire reminding authors to update
    // docs/cpp-conventions.md and the plugin ABI reference.
    REQUIRE(yuzu::agent::kReservedPluginNames.size() == 3);
    REQUIRE(yuzu::agent::kReservedPluginNames[0] == "__guard__");
    REQUIRE(yuzu::agent::kReservedPluginNames[1] == "__system__");
    REQUIRE(yuzu::agent::kReservedPluginNames[2] == "__update__");
}

TEST_CASE("PluginLoader rejects a plugin declaring a reserved name",
          "[plugin_loader][reserved_name]") {
    auto fixture = find_reserved_fixture_plugin();
    if (fixture.empty()) {
        WARN("reserved_name_fixture_plugin not found — skipping behavioral scan test");
        SUCCEED();
        return;
    }

    // Copy the fixture into an isolated directory so we scan only it —
    // avoids false positives from stray built plugins that may live in a
    // shared tree when run from the build root. Unique per-invocation name
    // is generated from mt19937_64 rather than ::getpid() so the code
    // compiles on MSVC (`_getpid` in <process.h>) and Apple Clang
    // (`<unistd.h>` not transitively available) without per-platform
    // guards. Same pattern sibling store tests use.
    std::random_device rd;
    std::mt19937_64 gen(rd());
    auto tmp = fs::temp_directory_path() /
               ("yuzu_test_reserved_plugin_" + std::to_string(gen()));
    fs::create_directories(tmp);
    auto staged = tmp / fixture.filename();
    std::error_code ec;
    fs::copy_file(fixture, staged, fs::copy_options::overwrite_existing, ec);
    REQUIRE_FALSE(ec);

    auto result = yuzu::agent::PluginLoader::scan(tmp);

    // Must not appear in loaded — nothing under __guard__ may be handed
    // to the dispatcher.
    REQUIRE(result.loaded.empty());

    // Must appear in errors with the stable reason prefix so the agent
    // metric can categorise it.
    REQUIRE(result.errors.size() == 1);
    const auto& err = result.errors.front();
    REQUIRE(err.path == staged.string());
    REQUIRE(err.reason.starts_with(yuzu::agent::kReservedNameReason));
    REQUIRE(err.reason.find("__guard__") != std::string::npos);

    fs::remove_all(tmp);
}
