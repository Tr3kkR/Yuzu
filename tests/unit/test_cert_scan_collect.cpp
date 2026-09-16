/**
 * test_cert_scan_collect.cpp -- unit tests for the portable, pure-path
 * parts of cert_scan_collect.hpp. discover_home_directories() itself is
 * NOT tested here -- it is a thin, per-OS enumeration shell (mirrors
 * win_profiles.hpp's own "Win32 shell, not unit-tested directly"
 * precedent) with no decision logic to isolate; is_candidate_file() is the
 * actual decision this header makes, and std::filesystem::path parsing is
 * portable, so it is tested directly here on every host.
 */

#include <catch2/catch_test_macros.hpp>

#include <cert_scan_collect.hpp>

#include <filesystem>

using namespace yuzu::cert_scan;

TEST_CASE("is_candidate_file: recognized certificate/key extensions", "[cert_scan]") {
    CHECK(is_candidate_file(std::filesystem::path("/home/alice/site.pem")));
    CHECK(is_candidate_file(std::filesystem::path("/home/alice/site.crt")));
    CHECK(is_candidate_file(std::filesystem::path("/home/alice/site.cer")));
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
