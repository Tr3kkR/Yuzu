/**
 * test_posix_dir_walk.cpp — real-filesystem tests for the shared capped
 * directory-walk primitive (agents/shared/posix_dir_walk.hpp), extracted
 * during PR #4154's round-8 remediation so the correct cap/error-detection
 * logic exists in exactly one place instead of five hand-rolled copies
 * across autoruns_linux.cpp/autoruns_macos.cpp.
 *
 * All real `opendir`/`readdir` against real temp directories -- no fakes.
 * A genuine mid-scan `readdir()` I/O error isn't reliably reproducible from
 * userspace without a filesystem-specific or libc-buffering-dependent
 * trick (closing the underlying fd or removing the directory mid-scan both
 * have unpredictable, implementation-dependent effects on whether the NEXT
 * `readdir()` call actually fails or just serves already-buffered entries)
 * -- so that specific path is covered by direct code review plus the
 * integration-level verification of this primitive's real callers, not a
 * fault-injection unit test here.
 */
#if !defined(_WIN32)

#include <catch2/catch_test_macros.hpp>

#include "test_helpers.hpp"

#include <posix_dir_walk.hpp>

#include <dirent.h>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

namespace {

/// RAII owner for a POSIX DIR* opened against a real directory -- this test
/// file's own small helper, not a claim on any production ownership type.
struct TestDirHandle {
    DIR* d;
    explicit TestDirHandle(const fs::path& path) : d(::opendir(path.c_str())) {}
    ~TestDirHandle() {
        if (d) ::closedir(d);
    }
    TestDirHandle(const TestDirHandle&) = delete;
    TestDirHandle& operator=(const TestDirHandle&) = delete;
};

void touch(const fs::path& p) {
    std::ofstream f(p);
    f << "x";
}

} // namespace

TEST_CASE("posix_dir_walk: walk_dir_capped on a genuinely empty directory reports "
          "clean, not truncated, no error",
          "[posix_dir_walk]") {
    yuzu::test::TempDir dir("yuzu_test_posix_dir_walk_empty_");
    fs::create_directories(dir.path);
    TestDirHandle handle(dir.path);
    REQUIRE(handle.d != nullptr);

    int count = 0;
    const auto result = yuzu::shared::walk_dir_capped(
        handle.d, 10, [&](const struct dirent*) {
            ++count;
            return true;
        });

    CHECK(count == 0);
    CHECK_FALSE(result.truncated);
    CHECK_FALSE(result.enumeration_error);
}

TEST_CASE("posix_dir_walk: walk_dir_capped with fewer real entries than the cap reports "
          "clean, not truncated",
          "[posix_dir_walk]") {
    yuzu::test::TempDir dir("yuzu_test_posix_dir_walk_under_cap_");
    fs::create_directories(dir.path);
    touch(dir.path / "a");
    touch(dir.path / "b");
    TestDirHandle handle(dir.path);
    REQUIRE(handle.d != nullptr);

    int count = 0;
    const auto result = yuzu::shared::walk_dir_capped(
        handle.d, 10, [&](const struct dirent*) {
            ++count;
            return true;
        });

    CHECK(count == 2);
    CHECK_FALSE(result.truncated);
    CHECK_FALSE(result.enumeration_error);
}

TEST_CASE("posix_dir_walk: walk_dir_capped with more real entries than the cap reports "
          "truncated, never an error "
          "(RECONSTRUCTION: pins PR #4154 round 8's blocker -- the cap-boundary "
          "lookahead call itself is now checked, not just the main loop's own "
          "readdir() calls)",
          "[posix_dir_walk]") {
    yuzu::test::TempDir dir("yuzu_test_posix_dir_walk_over_cap_");
    fs::create_directories(dir.path);
    for (int i = 0; i < 5; ++i) touch(dir.path / ("f" + std::to_string(i)));
    TestDirHandle handle(dir.path);
    REQUIRE(handle.d != nullptr);

    int count = 0;
    const auto result = yuzu::shared::walk_dir_capped(
        handle.d, 3, [&](const struct dirent*) {
            ++count;
            return true;
        });

    CHECK(count == 3);
    CHECK(result.truncated);
    CHECK_FALSE(result.enumeration_error);
}

TEST_CASE("posix_dir_walk: a directory with EXACTLY the cap's worth of entries is not "
          "reported truncated",
          "[posix_dir_walk]") {
    yuzu::test::TempDir dir("yuzu_test_posix_dir_walk_exact_cap_");
    fs::create_directories(dir.path);
    for (int i = 0; i < 4; ++i) touch(dir.path / ("f" + std::to_string(i)));
    TestDirHandle handle(dir.path);
    REQUIRE(handle.d != nullptr);

    int count = 0;
    const auto result = yuzu::shared::walk_dir_capped(
        handle.d, 4, [&](const struct dirent*) {
            ++count;
            return true;
        });

    CHECK(count == 4);
    CHECK_FALSE(result.truncated);
    CHECK_FALSE(result.enumeration_error);
}

TEST_CASE("posix_dir_walk: on_entry returning false stops the walk early without it "
          "counting as truncation -- the caller decided it has enough, not that data "
          "was missed",
          "[posix_dir_walk]") {
    yuzu::test::TempDir dir("yuzu_test_posix_dir_walk_early_stop_");
    fs::create_directories(dir.path);
    for (int i = 0; i < 5; ++i) touch(dir.path / ("f" + std::to_string(i)));
    TestDirHandle handle(dir.path);
    REQUIRE(handle.d != nullptr);

    int count = 0;
    const auto result = yuzu::shared::walk_dir_capped(
        handle.d, 10, [&](const struct dirent*) {
            ++count;
            return count < 2; // stop right after the 2nd real entry
        });

    CHECK(count == 2);
    CHECK_FALSE(result.truncated);
    CHECK_FALSE(result.enumeration_error);
}

#endif // !defined(_WIN32)
