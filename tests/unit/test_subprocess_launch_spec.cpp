/**
 * test_subprocess_launch_spec.cpp -- host-agnostic tests for the PURE launch-
 * spec core (subprocess_launch_spec.hpp): argv/extension validation, the A5
 * clear-and-allow-list environment (POSIX and Windows shapes), the Colascione
 * Windows argument quoter, and the precomputed Windows handle policy.
 *
 * These exercise pure functions with NO process spawning, so -- unlike the
 * real-child vectors in test_subprocess_runner.cpp, which are `#ifndef _WIN32`
 * -- they compile and run on EVERY platform, INCLUDING Windows (K-10 / CDX-R2-
 * 004: the Windows-relevant quoting/NUL/env logic must actually run on the OS
 * it governs, not be compiled out of the Windows test binary).
 */

#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/subprocess_launch_spec.hpp>

#include <optional>
#include <string>
#include <vector>

TEST_CASE("build_launch_spec rejects the same things run_bounded_subprocess rejects at runtime (B1)",
          "[subprocess][launch_spec]") {
    using yuzu::agent::build_launch_spec;
    using yuzu::agent::LaunchOptions;
    using yuzu::agent::LaunchSpecError;

    CHECK(build_launch_spec({}, LaunchOptions{}).error == LaunchSpecError::empty_argv);
    CHECK(build_launch_spec({"relative/bin"}, LaunchOptions{}).error == LaunchSpecError::relative_argv0);
    CHECK(build_launch_spec({"/bin/echo", std::string("a\0b", 3)}, LaunchOptions{}).error ==
          LaunchSpecError::embedded_nul);
    CHECK(build_launch_spec({"/path/tool.bat"}, LaunchOptions{}).error ==
          LaunchSpecError::banned_windows_extension);
    CHECK(build_launch_spec({"/path/TOOL.CMD"}, LaunchOptions{}).error ==
          LaunchSpecError::banned_windows_extension); // case-insensitive
    CHECK(build_launch_spec({"/path/tool.com"}, LaunchOptions{}).error ==
          LaunchSpecError::banned_windows_extension);
    CHECK(build_launch_spec({"C:\\tools\\thing.exe"}, LaunchOptions{}).error ==
          LaunchSpecError::none); // a valid Windows-absolute argv[0]
}

TEST_CASE("build_launch_spec assembles the A5 clear-and-allow-list env with no LD_/DYLD_ leakage (B1)",
          "[subprocess][launch_spec]") {
    using namespace yuzu::agent;
    LaunchOptions opts;
    opts.tz = std::string("UTC");
    LaunchSpec spec = build_launch_spec({"/bin/echo", "hi"}, opts);
    REQUIRE(spec.error == LaunchSpecError::none);

    bool has_path = false;
    bool has_lc_all = false;
    bool has_tz = false;
    for (const auto& e : spec.env) {
        CHECK(e.key.substr(0, 3) != "LD_");
        CHECK(e.key.substr(0, 5) != "DYLD_");
        CHECK(e.key != "IFS");
        CHECK(e.key != "BASH_ENV");
        CHECK(e.key != "GCONV_PATH");
        if (e.key == "PATH")
            has_path = true;
        if (e.key == "LC_ALL") {
            has_lc_all = true;
            CHECK(e.value == "C");
        }
        if (e.key == "TZ") {
            has_tz = true;
            CHECK(e.value == "UTC");
        }
    }
    CHECK(has_path);
    CHECK(has_tz);
    // CDX-P2-008: LC_ALL is a POSIX-only allow-list entry; the Windows leg gets
    // a Windows env with no LC_ALL. build_launch_spec targets the compile OS.
#ifdef _WIN32
    CHECK(!has_lc_all);
#else
    CHECK(has_lc_all);
#endif
}

TEST_CASE("default_launch_env gives Windows children a Windows allow-list, not the POSIX shape "
          "(CDX-P2-008)",
          "[subprocess][launch_spec]") {
    using namespace yuzu::agent;

    // POSIX branch: PATH + LC_ALL=C, no Windows system vars.
    auto posix_env = default_launch_env(/*windows=*/false, std::optional<std::string>{});
    auto find = [](const std::vector<EnvVar>& env, const std::string& k) -> const EnvVar* {
        for (const auto& e : env)
            if (e.key == k)
                return &e;
        return nullptr;
    };
    REQUIRE(find(posix_env, "PATH"));
    CHECK(find(posix_env, "PATH")->value == "/usr/bin:/bin:/usr/sbin:/sbin");
    CHECK(find(posix_env, "LC_ALL"));
    CHECK(find(posix_env, "SystemRoot") == nullptr);

    // Windows branch: system PATH + SystemRoot/windir/TEMP/TMP, no POSIX PATH,
    // no LC_ALL (locale left to the system default).
    auto win_env = default_launch_env(/*windows=*/true, std::optional<std::string>{});
    REQUIRE(find(win_env, "PATH"));
    CHECK(find(win_env, "PATH")->value.find("System32") != std::string::npos);
    CHECK(find(win_env, "PATH")->value.find("/usr/bin") == std::string::npos);
    CHECK(find(win_env, "SystemRoot"));
    CHECK(find(win_env, "windir"));
    CHECK(find(win_env, "TEMP"));
    CHECK(find(win_env, "TMP"));
    CHECK(find(win_env, "LC_ALL") == nullptr);

    // TZ is threaded into either branch when supplied.
    auto tz_env = default_launch_env(/*windows=*/true, std::optional<std::string>("UTC"));
    REQUIRE(find(tz_env, "TZ"));
    CHECK(find(tz_env, "TZ")->value == "UTC");
}

TEST_CASE("quote_windows_arg follows the Colascione backslash-before-quote algorithm (A2)",
          "[subprocess][launch_spec]") {
    using yuzu::agent::quote_windows_arg;
    CHECK(quote_windows_arg("") == "\"\"");
    CHECK(quote_windows_arg("simple") == "simple");
    CHECK(quote_windows_arg("a b c") == "\"a b c\"");
    CHECK(quote_windows_arg("ab\"c") == "\"ab\\\"c\"");
    CHECK(quote_windows_arg("a\\b") == "a\\b"); // no space/quote -> unquoted, backslash untouched
    CHECK(quote_windows_arg("a\\b c") == "\"a\\b c\""); // quoted for the space; a lone backslash
                                                          // not preceding a quote/end is NOT doubled
    CHECK(quote_windows_arg("a b\\") == "\"a b\\\\\""); // trailing backslash IS doubled before the
                                                          // closing quote we add
}

TEST_CASE("build_launch_spec precomputes the Windows handle policy from merge_stderr (A1/B1)",
          "[subprocess][launch_spec]") {
    using namespace yuzu::agent;
    LaunchOptions merged_opts;
    merged_opts.merge_stderr = true;
    LaunchSpec merged_spec = build_launch_spec({"/bin/echo"}, merged_opts);
    REQUIRE(merged_spec.error == LaunchSpecError::none);
    CHECK(merged_spec.windows_handles.inherit_stdout_write);
    CHECK(merged_spec.windows_handles.inherit_stderr_write);

    LaunchSpec default_spec = build_launch_spec({"/bin/echo"}, LaunchOptions{});
    REQUIRE(default_spec.error == LaunchSpecError::none);
    CHECK(default_spec.windows_handles.inherit_stdout_write);
    CHECK_FALSE(default_spec.windows_handles.inherit_stderr_write);
}
