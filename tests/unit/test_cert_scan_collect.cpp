/**
 * test_cert_scan_collect.cpp -- unit tests for cert_scan_collect.hpp.
 * discover_home_directories() itself is NOT tested here -- it is a thin,
 * per-OS enumeration shell (mirrors win_profiles.hpp's own "Win32 shell,
 * not unit-tested directly" precedent) with no decision logic to isolate;
 * is_candidate_file() is the actual decision this header makes, and
 * std::filesystem::path parsing is portable, so it is tested directly here
 * on every host. enumerate_files()/read_file_bytes() are exercised against
 * a real temp directory tree -- previously zero test coverage of any kind.
 */

#include <catch2/catch_test_macros.hpp>

#include <cert_scan_collect.hpp>

#include "test_helpers.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>

using namespace yuzu::cert_scan;

namespace {

void write_file(const std::filesystem::path& p, std::string_view content) {
    std::filesystem::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary);
    f << content;
}

} // namespace

TEST_CASE("is_candidate_file: recognized certificate/key extensions", "[cert_scan]") {
    CHECK(is_candidate_file(std::filesystem::path("/home/alice/site.pem")));
    CHECK(is_candidate_file(std::filesystem::path("/home/alice/site.crt")));
    CHECK(is_candidate_file(std::filesystem::path("/home/alice/site.cer")));
    CHECK(is_candidate_file(std::filesystem::path("/home/alice/site.der")));
    CHECK(is_candidate_file(std::filesystem::path("/home/alice/site.key")));
    CHECK(is_candidate_file(std::filesystem::path("/home/alice/bundle.p12")));
    CHECK(is_candidate_file(std::filesystem::path("/home/alice/bundle.pfx")));
    CHECK(is_candidate_file(std::filesystem::path("/home/alice/store.jks")));
    CHECK(is_candidate_file(std::filesystem::path("/home/alice/store.keystore")));
    CHECK(is_candidate_file(std::filesystem::path("/home/alice/request.csr")));
}

TEST_CASE("is_candidate_file: extension match is case-insensitive", "[cert_scan]") {
    CHECK(is_candidate_file(std::filesystem::path("/home/alice/SITE.PEM")));
    CHECK(is_candidate_file(std::filesystem::path("/home/alice/Bundle.P12")));
}

TEST_CASE("is_candidate_file: unrelated extension is not a candidate", "[cert_scan]") {
    CHECK_FALSE(is_candidate_file(std::filesystem::path("/home/alice/notes.txt")));
    CHECK_FALSE(is_candidate_file(std::filesystem::path("/home/alice/photo.jpg")));
}

TEST_CASE("is_candidate_file: any file directly under a .ssh directory is a candidate",
         "[cert_scan]") {
    CHECK(is_candidate_file(std::filesystem::path("/home/alice/.ssh/id_rsa")));
    CHECK(is_candidate_file(std::filesystem::path("/home/alice/.ssh/id_ed25519")));
    CHECK(is_candidate_file(std::filesystem::path("/home/alice/.ssh/config")));
}

TEST_CASE("is_candidate_file: extensionless file outside .ssh is not a candidate",
         "[cert_scan]") {
    CHECK_FALSE(is_candidate_file(std::filesystem::path("/home/alice/id_rsa")));
    CHECK_FALSE(is_candidate_file(std::filesystem::path("/home/alice/projects/deploy_key")));
}

TEST_CASE("is_candidate_file: .ssh must be the IMMEDIATE parent, not an ancestor",
         "[cert_scan]") {
    CHECK_FALSE(is_candidate_file(std::filesystem::path("/home/alice/.ssh/backup/id_rsa")));
}

// ── enumerate_files: real filesystem behaviour ──────────────────────────────

TEST_CASE("enumerate_files: a .der file is actually reachable, not just extension-recognized",
         "[cert_scan]") {
    // is_candidate_file() recognizing ".der" (tested above) is necessary
    // but not sufficient -- a real .der file alone in a scanned root used
    // to produce "0 files scanned, 0 findings" because the extension was
    // never in candidate_extensions() in the first place, so the file was
    // never SELECTED for reading despite classify_binary_content() having
    // a real DER-parsing branch for it.
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    write_file(dir.path / "cert.der", "not-real-der-bytes-but-present-on-disk");

    ScanConfig cfg;
    cfg.roots = {dir.path.string()};
    auto result = enumerate_files(cfg);

    REQUIRE(result.files.size() == 1);
    CHECK(std::filesystem::path(result.files[0].path).filename() == "cert.der");
}

TEST_CASE("enumerate_files: excluded directory names are never descended into",
         "[cert_scan]") {
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    write_file(dir.path / "real.pem", "findable");
    write_file(dir.path / ".git" / "hooks.pem", "should never be scanned");
    write_file(dir.path / "node_modules" / "pkg" / "cert.pem", "should never be scanned either");

    ScanConfig cfg;
    cfg.roots = {dir.path.string()};
    auto result = enumerate_files(cfg);

    std::vector<std::string> found_names;
    for (const auto& f : result.files)
        found_names.push_back(std::filesystem::path(f.path).filename().string());

    CHECK(std::find(found_names.begin(), found_names.end(), "real.pem") != found_names.end());
    CHECK(std::find(found_names.begin(), found_names.end(), "hooks.pem") == found_names.end());
    CHECK(std::find(found_names.begin(), found_names.end(), "cert.pem") == found_names.end());
}

TEST_CASE("enumerate_files: an inaccessible root is recorded, not silently skipped",
         "[cert_scan]") {
    // The default-scan-on-a-shared-box shape: a root that cannot be
    // opened at all. This used to leave no trace anywhere -- the caller
    // could not tell "found nothing because nothing was there" apart from
    // "found nothing because we couldn't read anything".
    yuzu::test::TempDir dir; // deliberately never created on disk

    ScanConfig cfg;
    cfg.roots = {(dir.path / "does_not_exist").string()};
    auto result = enumerate_files(cfg);

    CHECK(result.files.empty());
    REQUIRE(result.root_outcomes.size() == 1);
    CHECK_FALSE(result.root_outcomes[0].accessible);
}

TEST_CASE("enumerate_files: an accessible root is recorded as such", "[cert_scan]") {
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    write_file(dir.path / "a.pem", "content");

    ScanConfig cfg;
    cfg.roots = {dir.path.string()};
    auto result = enumerate_files(cfg);

    REQUIRE(result.root_outcomes.size() == 1);
    CHECK(result.root_outcomes[0].accessible);
}

TEST_CASE("enumerate_files: max_files_per_scan bounds the result and sets truncation",
         "[cert_scan]") {
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    write_file(dir.path / "a.pem", "content");
    write_file(dir.path / "b.pem", "content");
    write_file(dir.path / "c.pem", "content");

    ScanConfig cfg;
    cfg.roots = {dir.path.string()};
    cfg.max_files_per_scan = 2;
    auto result = enumerate_files(cfg);

    CHECK(result.files.size() == 2);
    CHECK(result.truncated_by_file_cap);
}

TEST_CASE("enumerate_files: max_file_size_bytes excludes an oversized file", "[cert_scan]") {
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    write_file(dir.path / "big.pem", std::string(100, 'x'));

    ScanConfig cfg;
    cfg.roots = {dir.path.string()};
    cfg.max_file_size_bytes = 10;
    auto result = enumerate_files(cfg);

    CHECK(result.files.empty());
}

TEST_CASE("enumerate_files: max_depth stops descending beyond the cap", "[cert_scan]") {
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    write_file(dir.path / "shallow.pem", "content");
    write_file(dir.path / "a" / "b" / "c" / "deep.pem", "content");

    ScanConfig cfg;
    cfg.roots = {dir.path.string()};
    cfg.max_depth = 1; // shallow.pem is at depth 0; a/b/c/deep.pem is at depth 3
    auto result = enumerate_files(cfg);

    std::vector<std::string> found_names;
    for (const auto& f : result.files)
        found_names.push_back(std::filesystem::path(f.path).filename().string());

    CHECK(std::find(found_names.begin(), found_names.end(), "shallow.pem") != found_names.end());
    CHECK(std::find(found_names.begin(), found_names.end(), "deep.pem") == found_names.end());
}

TEST_CASE("enumerate_files: a symlinked file is never returned as a candidate", "[cert_scan]") {
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    auto real_file = dir.path / "real.pem";
    write_file(real_file, "content");
    auto link = dir.path / "link.pem";

    std::error_code ec;
    std::filesystem::create_symlink(real_file, link, ec);
    if (ec) {
        // Symlink creation can fail on Windows without Developer Mode /
        // SeCreateSymbolicLinkPrivilege -- skip rather than false-fail an
        // environment limitation unrelated to this plugin's own logic.
        SUCCEED("symlink creation unavailable in this environment, skipping");
        return;
    }

    ScanConfig cfg;
    cfg.roots = {dir.path.string()};
    auto result = enumerate_files(cfg);

    std::vector<std::string> found_names;
    for (const auto& f : result.files)
        found_names.push_back(std::filesystem::path(f.path).filename().string());

    CHECK(std::find(found_names.begin(), found_names.end(), "real.pem") != found_names.end());
    CHECK(std::find(found_names.begin(), found_names.end(), "link.pem") == found_names.end());
}

// ── read_file_bytes: bounded read ────────────────────────────────────────

TEST_CASE("read_file_bytes: reads content within the cap", "[cert_scan]") {
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    auto file = dir.path / "small.pem";
    write_file(file, "hello world");

    auto content = read_file_bytes(file.string(), 100);
    REQUIRE(content.has_value());
    CHECK(*content == "hello world");
}

TEST_CASE("read_file_bytes: rejects a file over the cap rather than truncating it",
         "[cert_scan]") {
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    auto file = dir.path / "big.pem";
    write_file(file, std::string(200, 'x'));

    auto content = read_file_bytes(file.string(), 100);
    CHECK_FALSE(content.has_value());
}

TEST_CASE("read_file_bytes: nullopt for a nonexistent file", "[cert_scan]") {
    yuzu::test::TempDir dir; // never created
    auto content = read_file_bytes((dir.path / "missing.pem").string(), 100);
    CHECK_FALSE(content.has_value());
}
