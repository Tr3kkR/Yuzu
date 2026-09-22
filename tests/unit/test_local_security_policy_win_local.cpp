/**
 * test_local_security_policy_win_local.cpp -- drives the Windows leg's LIVE `secedit /export`
 * spawn + scratch-dir lifecycle, on top of test_local_security_policy_local_dispatcher.cpp's
 * generic dispatcher coverage. That file's bare `LocalDispatcher` run never configures
 * `agent.data_dir`, so collect_windows_policy's very first check (local_security_policy_win.cpp:
 * "if (data_dir.empty()) return emit_constrained(ctx, "data_dir_unset");") short-circuits before
 * the real `secedit` spawn is ever reached -- so until this file the live path had exactly one
 * manual the-rig verification (the `RIG PROBE` banner in local_security_policy_win.cpp) and no
 * repeatable CI regression. This file IS that regression. Same shape as execution_artifacts's own win-local split
 * (test_execution_artifacts_win_local.cpp), which solved the identical gap for `amcache`.
 *
 * Same loading harness as test_local_security_policy_local_dispatcher.cpp -- LocalDispatcher over
 * the ACTUAL built local_security_policy.dylib/.so/.dll, never a mock. UNGUARDED TU: it is listed
 * unconditionally in tests/meson.build and compiles on every OS, so it can never become a file
 * nobody builds (the platform-guarded-TU-hides-a-dead-leg lesson). Be precise about what that
 * buys off Windows, though: the entire body is `#if defined(_WIN32)`, so a non-Windows run
 * registers NO test case from this file at all -- it is compiled, not exercised. The pure
 * decisions behind this leg are covered on every OS by
 * test_local_security_policy_scratch_sweep.cpp; what is Windows-only here is the live spawn and
 * the scratch-dir lifecycle, which no other host can run.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

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

[[maybe_unused]] std::optional<yuzu::agent::PluginHandle> load_plugin() {
    const std::string lib = std::string{"local_security_policy"} + kExt;
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{root} / "agents" / "plugins" / "local_security_policy" / lib);
    for (const char* b : {"", "..", "build-macos", "build-windows", "build-linux"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "local_security_policy" / lib);
    for (const auto& c : candidates) {
        std::error_code ec;
        if (!fs::exists(c, ec)) continue;
        auto h = yuzu::agent::PluginHandle::load(fs::absolute(c, ec));
        if (h.has_value() && h->descriptor() != nullptr) return std::move(*h);
    }
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) // under meson a missing plugin is a broken build
        FAIL("local_security_policy plugin library not found under meson test");
    WARN("local_security_policy plugin library not found -- skipping (run via `meson test`)");
    return std::nullopt;
}

[[maybe_unused]] std::vector<std::string> rows_of(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    for (std::string l; std::getline(ss, l);) {
        if (!l.empty() && l.back() == '\r') l.pop_back();
        if (!l.empty()) out.push_back(l);
    }
    return out;
}

[[maybe_unused]] bool any_row_starts_with(const std::vector<std::string>& rows, std::string_view prefix) {
    return std::any_of(rows.begin(), rows.end(),
                       [&](const std::string& r) { return r.rfind(prefix, 0) == 0; });
}

} // namespace

#if defined(_WIN32)

TEST_CASE("local_security_policy win-local: password_policy without init() (so agent.data_dir "
          "was never configured) reports the named data_dir_unset token, never an empty result",
          "[local_security_policy][win_local]") {
    auto plugin = load_plugin();
    if (!plugin) return;

    // Deliberately skip init() -- the "test/tool didn't configure agent.data_dir" case
    // collect_windows_policy's first check exists for; must never fall back to guessing
    // a scratch location.
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor(), "password_policy");
    const auto rows = rows_of(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows.front() == "constrained|data_dir_unset");
    CHECK(result.rc == 1);
}

TEST_CASE("local_security_policy win-local: password_policy, with agent.data_dir pointed at a "
          "real scratch dir, reaches the real secedit /export spawn and returns real rows or a "
          "named constrained token -- never an empty success -- and leaves the scratch dir "
          "empty afterward either way",
          "[local_security_policy][win_local]") {
    auto plugin = load_plugin();
    if (!plugin) return;

    yuzu::test::TempDir data_dir("yuzu_test_local_security_policy_data_dir_");
    std::error_code ec;
    fs::create_directories(data_dir.path, ec);
    REQUIRE_FALSE(ec);

    // Declared AFTER `plugin` -- the library must outlive the context.
    yuzu::agent::StandalonePluginContext ctx(
        "local_security_policy",
        std::unordered_map<std::string, std::string>{{"agent.data_dir", data_dir.path.string()}});
    if (plugin->descriptor()->init)
        REQUIRE(plugin->descriptor()->init(ctx.get()) == 0);

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor(), "password_policy");
    const auto rows = rows_of(result.captured);
    REQUIRE_FALSE(rows.empty());

    // Split three ways rather than one permissive OR, same reasoning as
    // execution_artifacts's win-local test: a leg that can NEVER pass past
    // scratch-dir setup would still show a green "row or constrained" test if
    // dest_dir_acl/dest_dir_create/dest_dir_open counted as an acceptable
    // constrained outcome -- those are this test HARNESS's own setup failing,
    // not a real secedit result, and must fail loud rather than pass quiet.
    // Also excluded: data_dir_unset and secedit:spawn_error both fire BEFORE
    // the real secedit child process ever runs (the former is the init()-not-
    // called guard this test deliberately bypasses above; the latter is a
    // runner-level spawn failure) -- accepting either here would let a future
    // regression (e.g. a typo'd config key breaking init()) keep this test
    // green while silently losing the live-spawn coverage it exists to prove.
    const bool has_success_row = any_row_starts_with(rows, "password_policy|");
    const bool has_dest_dir_token = any_row_starts_with(rows, "constrained|dest_dir_");
    const bool has_pre_spawn_token = any_row_starts_with(rows, "constrained|data_dir_unset") ||
                                     any_row_starts_with(rows, "constrained|secedit:spawn_error");
    const bool has_other_constrained_row =
        any_row_starts_with(rows, "constrained|") && !has_dest_dir_token && !has_pre_spawn_token;
    CAPTURE(result.captured);
    CHECK_FALSE(has_dest_dir_token);
    CHECK_FALSE(has_pre_spawn_token);
    CHECK((has_success_row || has_other_constrained_row));
    if (has_success_row)
        CHECK(result.rc == 0);
    else if (has_other_constrained_row)
        CHECK(result.rc == 1);

    if (plugin->descriptor()->shutdown)
        plugin->descriptor()->shutdown(ctx.get());

    // ScratchDirGuard creates and removes its export directory entirely within
    // collect_windows_policy's own scope -- nothing under data_dir should
    // survive the dispatch above, success or failure.
    bool data_dir_empty = true;
    for (const auto& entry : fs::directory_iterator(data_dir.path, ec))
        (void)entry, data_dir_empty = false;
    CHECK_FALSE(ec);
    CHECK(data_dir_empty);
}

#endif // defined(_WIN32)
