/**
 * test_script_exec_actions.cpp -- script_exec's FIRST end-to-end test.
 * Loads the ACTUAL built script_exec plugin (script_exec.dylib/.so, the
 * same artifact the agent daemon loads in production) via
 * PluginHandle::load and drives it through yuzu::agent::LocalDispatcher --
 * the same pattern test_users_posix_actions.cpp established, this plugin's
 * POSIX counterpart. Unlike test_script_exec_parsers.cpp (pure, no OS
 * calls), this exercises the real
 * yuzu::agent::run_bounded_subprocess round trip against the real
 * `/bin/echo`/`/bin/bash` binaries on the test host -- every assertion
 * below would fail if the migration's argv, mode dispatch, or wire mapping
 * were wrong.
 *
 * script_exec needs no plugin init to exercise its exec/bash actions (its
 * init() is a no-op -- no storage/g_ctx use anywhere in the migrated
 * paths), so, unlike some other LocalDispatcher suites, there is no
 * init-call step here at all.
 */
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include <sys/stat.h>

namespace fs = std::filesystem;

namespace {

#if defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

// Mirrors test_users_posix_actions.cpp's find_users_plugin, pointed at
// script_exec's own build output.
fs::path find_script_exec_plugin() {
    const std::string lib_name = std::string{"script_exec"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "script_exec" /
                                lib_name);
    }
    // Meson launches tests with CWD=build root; agents/ sits alongside tests/.
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "script_exec" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "script_exec" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "script_exec" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "script_exec" /
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

std::optional<LoadedPlugin> load_script_exec_plugin() {
    auto plugin_path = find_script_exec_plugin();
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

TEST_CASE("script_exec plugin: exec streams real /bin/echo output through the runner",
          "[script_exec][actions]") {
    auto plugin = load_script_exec_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch, not a
    // benign "plugin not built this configuration" case (BR-005).
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"command", "/bin/echo"}, {"args", "happy path"}};
    auto result = dispatcher.run(plugin->descriptor, "exec", params);

    // Reverting the migration (wrong argv, a mode that never calls the
    // runner, or a broken wire mapping) would either fail this call or
    // produce a captured buffer missing one of these three lines -- this
    // only passes if the real runner-mediated argv actually ran.
    CHECK(result.rc == 0);
    auto stdout_pos = result.captured.find("stdout|happy path");
    auto exit_pos = result.captured.find("exit_code|0");
    auto status_pos = result.captured.find("status|ok");
    REQUIRE(stdout_pos != std::string::npos);
    REQUIRE(exit_pos != std::string::npos);
    REQUIRE(status_pos != std::string::npos);
    // Wire ordering contract: streamed output first, then exit_code, then
    // status — a future change reordering these should fail this test, not
    // just prove the three tokens exist somewhere in the buffer.
    CHECK(stdout_pos < exit_pos);
    CHECK(exit_pos < status_pos);
}

TEST_CASE("script_exec plugin: bash runs the script as a single argv element through the runner",
          "[script_exec][actions]") {
    auto plugin = load_script_exec_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch, not a
    // benign "plugin not built this configuration" case (BR-005).
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"script", "echo hi"}};
    auto result = dispatcher.run(plugin->descriptor, "bash", params);

    CHECK(result.rc == 0);
    auto stdout_pos = result.captured.find("stdout|hi");
    auto exit_pos = result.captured.find("exit_code|0");
    auto status_pos = result.captured.find("status|ok");
    REQUIRE(stdout_pos != std::string::npos);
    REQUIRE(exit_pos != std::string::npos);
    REQUIRE(status_pos != std::string::npos);
    CHECK(stdout_pos < exit_pos);
    CHECK(exit_pos < status_pos);
}

TEST_CASE("script_exec plugin: exec with an unresolvable bare command reports status|error "
          "without ever calling the runner",
          "[script_exec][actions]") {
    auto plugin = load_script_exec_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch, not a
    // benign "plugin not built this configuration" case (BR-005).
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    // A bare name with no separator that resolve_executable's real PATH
    // search will not find on any normal test host -- exercises the
    // early-return path (no subprocess spawn attempted at all).
    std::vector<YuzuParam> params{{"command", "yuzu-test-definitely-missing-binary-xyz"}};
    auto result = dispatcher.run(plugin->descriptor, "exec", params);

    CHECK(result.rc == 1);
    auto status_pos = result.captured.find("status|error");
    auto exit_pos = result.captured.find("exit_code|-1");
    REQUIRE(status_pos != std::string::npos);
    REQUIRE(exit_pos != std::string::npos);
    // The early-setup-failure shape is the REVERSE of the post-runner-return
    // order above: status before exit_code (see do_exec's own comment).
    CHECK(status_pos < exit_pos);
}

TEST_CASE("script_exec plugin: a blank stdout line still streams its own stdout| wire record "
          "(A2-002 escalation, A2-006)",
          "[script_exec][actions][streaming]") {
    auto plugin = load_script_exec_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch, not a
    // benign "plugin not built this configuration" case (BR-005).
    REQUIRE(plugin.has_value());

    yuzu::agent::LocalDispatcher dispatcher;
    // printf interprets the \n escapes; the middle one produces a completed,
    // BLANK stdout line between "a" and "b". Before the runner-level A2-006
    // fix, store_line() dropped a blank line before ever invoking on_line,
    // so the middle "stdout|" record below would be missing entirely.
    std::vector<YuzuParam> params{{"script", "printf 'a\\n\\nb\\n'"}};
    auto result = dispatcher.run(plugin->descriptor, "bash", params);

    CHECK(result.rc == 0);
    // Substring match on the exact three-line block (not just each token
    // independently) so a bare "stdout|" existing only as a PREFIX of
    // "stdout|a" can't false-positive this assertion.
    CHECK(result.captured.find("stdout|a\nstdout|\nstdout|b") != std::string::npos);
    CHECK(result.captured.find("exit_code|0") != std::string::npos);
    CHECK(result.captured.find("status|ok") != std::string::npos);
}

TEST_CASE("script_exec plugin: a runner-level spawn_error reaches the ABI4 result-status seam "
          "(BR-001: forward_runner_failure must not be flattened away)",
          "[script_exec][actions]") {
    auto plugin = load_script_exec_plugin();
    // Hard failure, not WARN-and-skip: the plugin build is guaranteed
    // ordered ahead of this test (tests/meson.build link_depends), so its
    // absence is a real regression this test exists to catch, not a
    // benign "plugin not built this configuration" case (BR-005).
    REQUIRE(plugin.has_value());

    // A regular, executable, absolute file that resolve_executable's own
    // is_executable_probe (regular file + access(X_OK)) happily accepts --
    // so do_exec reaches run_bounded_subprocess -- but whose shebang names
    // an interpreter that cannot possibly exist. execve() itself then
    // fails (ENOENT resolving the interpreter), which the runner reports
    // as termination_reason::spawn_error / tool_ran=false, never as an
    // ordinary nonzero exit. Deterministic and immediate: no timing/sleep
    // dependency, matching this suite's no-wall-clock discipline.
    yuzu::test::TempDir dir("yuzu_test_script_exec_spawn_error_");
    // TempDir only reserves a unique path -- it does not create the
    // directory itself (test_helpers.hpp), so create it before writing
    // into it.
    REQUIRE(fs::create_directories(dir.path));
    auto script_path = dir.path / "bad-shebang.sh";
    {
        std::ofstream f(script_path);
        f << "#!/yuzu-test-definitely-nonexistent-interpreter-xyz\necho hi\n";
    }
    REQUIRE(::chmod(script_path.c_str(), 0700) == 0);

    yuzu::agent::LocalDispatcher dispatcher;
    // YuzuParam holds raw const char*, not std::string -- keep the backing
    // string alive across the dispatcher.run() call below rather than
    // binding a temporary's .c_str() into the params vector.
    const std::string script_path_str = script_path.string();
    std::vector<YuzuParam> params{{"command", script_path_str.c_str()}};
    auto result = dispatcher.run(plugin->descriptor, "exec", params);

    CHECK(result.rc != 0);
    CHECK(result.captured.find("status|error") != std::string::npos);
    // The actual assertion this test exists for: forward_runner_failure's
    // ctx.set_result_status() call reached the SAME CommandContextImpl the
    // wire lines above came from -- not just that do_exec/run_via_runner
    // called it, which a grep could already confirm.
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == "subprocess_runner:spawn_error");
}

#endif // !_WIN32
