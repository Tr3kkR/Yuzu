/**
 * test_pii_scan_collect.cpp — unit tests for pii_scan_collect.hpp's real
 * filesystem behaviour: directory-exclusion list, the wall-clock walk
 * deadline, and single-file-path roots. Previously untested entirely —
 * enumerate_files() had zero test coverage of any kind before this file.
 */

#include <catch2/catch_test_macros.hpp>

#include <pii_scan_collect.hpp>

#include "test_helpers.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>

using namespace yuzu::pii;

namespace {

void write_file(const std::filesystem::path& p, std::string_view content) {
    std::filesystem::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary);
    f << content;
}

} // namespace

TEST_CASE("enumerate_files: a root that is itself a regular file is scanned directly",
         "[pii][collect]") {
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    auto file = dir.path / "notes.exotic-extension";
    write_file(file, "some content");

    ScanConfig cfg;
    cfg.roots = {file.string()};
    auto result = enumerate_files(cfg);

    // The extension allowlist would normally reject ".exotic-extension",
    // but an operator naming an exact file path is an explicit choice the
    // allowlist must not silently veto -- recursive_directory_iterator on
    // a non-directory root would otherwise fail outright (ENOTDIR) and
    // this whole root would be silently skipped.
    REQUIRE(result.files.size() == 1);
    CHECK(result.files[0].path == file.string());
    CHECK_FALSE(result.truncated_by_deadline);
}

TEST_CASE("enumerate_files: excluded directory names are never descended into",
         "[pii][collect]") {
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    write_file(dir.path / "real.txt", "findable content");
    write_file(dir.path / ".git" / "config.txt", "should never be scanned");
    write_file(dir.path / "node_modules" / "pkg" / "index.txt", "should never be scanned either");

    ScanConfig cfg;
    cfg.roots = {dir.path.string()};
    auto result = enumerate_files(cfg);

    std::vector<std::string> found_names;
    for (const auto& f : result.files)
        found_names.push_back(std::filesystem::path(f.path).filename().string());

    CHECK(std::find(found_names.begin(), found_names.end(), "real.txt") != found_names.end());
    CHECK(std::find(found_names.begin(), found_names.end(), "config.txt") == found_names.end());
    CHECK(std::find(found_names.begin(), found_names.end(), "index.txt") == found_names.end());
}

TEST_CASE("enumerate_files: an already-expired deadline truncates the walk honestly",
         "[pii][collect]") {
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    write_file(dir.path / "a.txt", "content");

    ScanConfig cfg;
    cfg.roots = {dir.path.string()};
    cfg.max_walk_duration = std::chrono::milliseconds(0); // already expired by the time we check
    auto result = enumerate_files(cfg);

    CHECK(result.truncated_by_deadline);
}

TEST_CASE("enumerate_files: a generous deadline does not truncate a small tree",
         "[pii][collect]") {
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    write_file(dir.path / "a.txt", "content");
    write_file(dir.path / "b.txt", "content");

    ScanConfig cfg;
    cfg.roots = {dir.path.string()};
    cfg.max_walk_duration = std::chrono::minutes(5);
    auto result = enumerate_files(cfg);

    CHECK_FALSE(result.truncated_by_deadline);
    CHECK(result.files.size() == 2);
}

TEST_CASE("enumerate_files: default extension allowlist still applies under a directory root",
         "[pii][collect]") {
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    write_file(dir.path / "notes.txt", "content");
    write_file(dir.path / "image.png", "binary-ish content");

    ScanConfig cfg;
    cfg.roots = {dir.path.string()};
    auto result = enumerate_files(cfg);

    REQUIRE(result.files.size() == 1);
    CHECK(std::filesystem::path(result.files[0].path).filename() == "notes.txt");
}
