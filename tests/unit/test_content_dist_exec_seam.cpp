/**
 * test_content_dist_exec_seam.cpp -- BR-006 (whole-branch review round 2):
 * real end-to-end coverage of content_dist_exec_seam.hpp's
 * execute_verified_payload(), the extracted post-hash-verification logic
 * `do_execute` (content_dist_plugin.cpp) runs for `execute_staged`.
 *
 * WHY THIS FILE EXISTS: test_content_dist_actions.cpp's header comment
 * documents a real testability wall -- content_dist_plugin.cpp's `g_ctx`
 * (agent KV) is set only by the plugin's real `init()`, which the
 * LocalDispatcher test harness never calls, so no existing test could drive
 * a real, hash-verified `execute_staged` through the actual runner call.
 * That gap meant a defect in the call-site WIRING between
 * build_execution_options/run_bounded_subprocess/map_execution_result --
 * exactly the shape BR-001 (POSIX inherit_parent_env silently narrowing the
 * child's environment) turned out to be -- could ship with every existing
 * content_dist test green. execute_verified_payload() (content_dist_exec_
 * seam.hpp) is do_execute's logic minus the KV/plugin-ABI dependency, so
 * this file drives it directly against a REAL staged file: a real chmod, a
 * real fork/exec through yuzu::agent::run_bounded_subprocess, real result
 * mapping -- no plugin load, no LocalDispatcher, no g_ctx anywhere in the
 * call path.
 *
 * POSIX-only (a no-op TU on Windows via the #ifndef _WIN32 guard below),
 * same shape as test_content_dist_actions.cpp and test_users_posix_actions.cpp.
 */
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include "content_dist_exec_seam.hpp"
#include "test_helpers.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::content_dist::exec;

namespace {

#ifdef __linux__
constexpr bool kIsLinux = true;
#else
constexpr bool kIsLinux = false;
#endif

bool contains_line(const std::vector<std::string>& lines, std::string_view needle) {
    return std::any_of(lines.begin(), lines.end(),
                       [&](const std::string& l) { return l.find(needle) != std::string::npos; });
}

} // namespace

TEST_CASE("execute_verified_payload runs a REAL staged native executable through the actual "
          "runner call, end to end (BR-006)",
          "[agent][content_dist][exec_seam]") {
    yuzu::test::TempDir dir("yuzu_test_content_dist_exec_seam_");
    fs::create_directories(dir.path);
    fs::path payload = dir.path / "staged-echo";
#ifdef __linux__
    // Linux: is_linux=true below means CDX-002 would reject a shebang
    // script AND B6 exec_verify (fd-exec) is live, so the payload must be a
    // genuine native ELF -- copy one from the system.
    std::error_code copy_ec;
    fs::copy_file("/bin/echo", payload, fs::copy_options::overwrite_existing, copy_ec);
    REQUIRE_FALSE(copy_ec);
#else
    // macOS: copying a system binary like /bin/echo is NOT a valid fixture
    // here -- Apple's platform-binary code-signing protection SIGKILLs a
    // byte-copy at exec (verified independently of this test: `codesign -dv`
    // on the copy shows the same embedded "Platform identifier" as the
    // original, and Apple Silicon's AMFI refuses to run a platform binary's
    // signature from an unsealed path). is_linux=false on this leg anyway,
    // so CDX-002 never fires and B6 exec_verify is disabled -- a shebang
    // script is a perfectly genuine fixture here: the KERNEL handles "#!"
    // translation directly inside execve() (no shell re-exec, no PATH
    // search), so this still exercises the real argv[0]-is-the-payload
    // spawn path exactly as a native binary would.
    { std::ofstream out(payload, std::ios::binary); out << "#!/bin/sh\necho \"$@\"\n"; }
#endif

    // is_linux mirrors the ACTUAL compile target here (unlike the shebang-
    // gate test below) -- this exercises the real B6 exec_verify path on a
    // real Linux CI leg, and the real "exec_verify never enabled" path
    // everywhere else, exactly as do_execute does at its own call site.
    ExecutionOutcome outcome =
        execute_verified_payload(payload, "hello-from-test", kIsLinux, /*is_windows=*/false);

    CHECK(outcome.rc == 0);
    REQUIRE(outcome.run.has_value());
    CHECK(outcome.run->tool_ran);
    CHECK(contains_line(outcome.lines, "status|ok"));
    CHECK(contains_line(outcome.lines, "exit_code|0"));
    // /bin/echo writes its argv back out -- proves argv assembly (payload
    // path as argv[0], split_args(args) appended) actually wired through to
    // the real spawned child, not just that SOME child ran.
    CHECK(contains_line(outcome.lines, "hello-from-test"));
}

TEST_CASE("execute_verified_payload reports a real spawn failure for a nonexistent staged path "
          "(BR-006)",
          "[agent][content_dist][exec_seam]") {
    yuzu::test::TempDir dir("yuzu_test_content_dist_exec_seam_");
    fs::path payload = dir.path / "never-staged"; // deliberately never created

    ExecutionOutcome outcome =
        execute_verified_payload(payload, "", kIsLinux, /*is_windows=*/false);

    CHECK(outcome.rc == -1); // map_execution_result's spawn_error sentinel
    REQUIRE(outcome.run.has_value());
    CHECK_FALSE(outcome.run->tool_ran);
    CHECK(contains_line(outcome.lines, "status|error"));
    CHECK(contains_line(outcome.lines, "exit_code|-1"));
}

TEST_CASE("execute_verified_payload rejects a shebang-interpreted payload before ever reaching "
          "the runner (CDX-002, BR-006)",
          "[agent][content_dist][exec_seam]") {
    // The shebang gate is pure file-content logic (reads two bytes, no
    // exec_verify/runner call happens before it can reject) -- forcing
    // is_linux=true here exercises it on every host this suite runs on,
    // not just an actual Linux leg, exactly like
    // test_content_dist_exec_parsers.cpp's is_shebang_payload fixtures do
    // for the pure predicate this call-site gate wraps.
    yuzu::test::TempDir dir("yuzu_test_content_dist_exec_seam_");
    fs::create_directories(dir.path);
    fs::path payload = dir.path / "staged-script.sh";
    {
        std::ofstream out(payload, std::ios::binary);
        out << "#!/bin/sh\necho hi\n";
    }

    ExecutionOutcome outcome =
        execute_verified_payload(payload, "", /*is_linux=*/true, /*is_windows=*/false);

    CHECK(outcome.rc == 1);
    // Rejected before the runner was ever invoked -- no SubprocessResult to
    // forward through the ABI4 result-status seam.
    CHECK_FALSE(outcome.run.has_value());
    REQUIRE(outcome.lines.size() == 1);
    CHECK(outcome.lines[0].find("script payloads (shebang) are not supported") != std::string::npos);
}

TEST_CASE("execute_verified_payload rejects args containing shell metacharacters before ever "
          "reaching the runner (BR-006)",
          "[agent][content_dist][exec_seam]") {
    yuzu::test::TempDir dir("yuzu_test_content_dist_exec_seam_");
    fs::create_directories(dir.path);
    fs::path payload = dir.path / "staged-echo";
    std::error_code copy_ec;
    fs::copy_file("/bin/echo", payload, fs::copy_options::overwrite_existing, copy_ec);
    REQUIRE_FALSE(copy_ec);

    ExecutionOutcome outcome =
        execute_verified_payload(payload, "hi; rm -rf /", kIsLinux, /*is_windows=*/false);

    CHECK(outcome.rc == 1);
    CHECK_FALSE(outcome.run.has_value()); // never reached the runner
    REQUIRE(outcome.lines.size() == 1);
    CHECK(outcome.lines[0].find("forbidden characters") != std::string::npos);
}

#endif // !_WIN32
