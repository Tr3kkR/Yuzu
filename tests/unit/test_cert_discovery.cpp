/**
 * test_cert_discovery.cpp — Unit tests for agent-side install-CA auto-discovery
 * (PKI #1289 / HIGH-1 #1314).
 *
 * The bug HIGH-1 closes: the install-CA discovery used to live only inside
 * agent.cpp's build_channel and never wrote the discovered path back into
 * cfg_.tls_ca_cert, so a no-`--ca-cert` agent connected over server-authenticated
 * TLS but `provisioning_eligible` (which requires a non-empty CA) stayed false —
 * it sent no CSR and never enrolled. The fix promotes the discovered path into
 * cfg_.tls_ca_cert BEFORE the provisioning gate. `discover_install_ca_path()` is
 * that single source of truth; these tests pin its contract via the injectable
 * candidate-list overload (the standard system paths are not writable in a test).
 */

#include <yuzu/agent/cert_discovery.hpp>

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <filesystem>
#include <fstream>

#if defined(__APPLE__)
#include <cstdlib>
#include <unistd.h> // geteuid()
#endif

namespace fs = std::filesystem;
using namespace yuzu::agent;

namespace {

// Writes `contents` to a fresh temp file and returns its path. Empty contents
// produces a zero-byte file (used to prove the non-empty-file guard).
fs::path write_temp(std::string_view prefix, std::string_view contents) {
    auto p = yuzu::test::unique_temp_path(prefix);
    std::ofstream f(p, std::ios::binary);
    f << contents;
    f.close();
    return p;
}

} // namespace

TEST_CASE("discover_install_ca_path returns first existing non-empty candidate",
          "[agent][pki][cert-discovery]") {
    auto ca = write_temp("yuzu-ca-", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
    fs::path missing = yuzu::test::unique_temp_path("yuzu-missing-"); // never created

    SECTION("a single readable CA is found") {
        std::array<fs::path, 1> candidates{ca};
        auto found = discover_install_ca_path(candidates);
        REQUIRE(found.has_value());
        REQUIRE(*found == ca);
    }

    SECTION("first match wins; earlier missing candidate is skipped") {
        auto ca2 = write_temp("yuzu-ca2-", "second");
        std::array<fs::path, 3> candidates{missing, ca, ca2};
        auto found = discover_install_ca_path(candidates);
        REQUIRE(found.has_value());
        REQUIRE(*found == ca); // ca precedes ca2 in scan order
        fs::remove(ca2);
    }

    fs::remove(ca);
}

TEST_CASE("discover_install_ca_path rejects empty and absent files",
          "[agent][pki][cert-discovery]") {
    SECTION("no candidates → nullopt") {
        REQUIRE_FALSE(discover_install_ca_path(std::span<const fs::path>{}).has_value());
    }

    SECTION("a zero-byte CA file is treated as absent (not a usable trust anchor)") {
        auto empty_ca = write_temp("yuzu-empty-ca-", "");
        std::array<fs::path, 1> candidates{empty_ca};
        REQUIRE_FALSE(discover_install_ca_path(candidates).has_value());
        fs::remove(empty_ca);
    }

    SECTION("a non-existent path → nullopt") {
        std::array<fs::path, 1> candidates{yuzu::test::unique_temp_path("yuzu-nope-")};
        REQUIRE_FALSE(discover_install_ca_path(candidates).has_value());
    }

    SECTION("a directory is not a regular file → skipped") {
        auto dir = yuzu::test::unique_temp_path("yuzu-dir-");
        fs::create_directory(dir);
        std::array<fs::path, 1> candidates{dir};
        REQUIRE_FALSE(discover_install_ca_path(candidates).has_value());
        fs::remove(dir);
    }

    SECTION("a symlink to a real CA is rejected (#1314 M-2 — no planted trust anchor)") {
        auto real_ca = write_temp("yuzu-real-ca-", "ca-bytes");
        auto link = yuzu::test::unique_temp_path("yuzu-link-ca-");
        std::error_code ec;
        fs::create_symlink(real_ca, link, ec);
        if (ec) {
            SUCCEED("symlinks unsupported on this platform — skip");
        } else {
            std::array<fs::path, 1> candidates{link};
            REQUIRE_FALSE(discover_install_ca_path(candidates).has_value());
            fs::remove(link);
        }
        fs::remove(real_ca);
    }
}

TEST_CASE("discover_install_ca_path() default overload scans the standard install path",
          "[agent][pki][cert-discovery]") {
    // The no-arg overload reads the platform's fixed shared-cert-volume path
    // (/etc/yuzu/certs/default-ca.pem on POSIX). In the test sandbox that path is
    // absent, so the contract we can assert here is that it does not throw and
    // returns a well-formed optional — the populated-path behaviour is covered by
    // the injectable overload above and by the reference-stack boot smoke.
    auto found = discover_install_ca_path();
    if (found.has_value()) {
        // If a real install CA happens to exist on the build host, it must be a
        // non-empty regular file (the same guarantee the overload enforces).
        REQUIRE(fs::is_regular_file(*found));
        REQUIRE(fs::file_size(*found) > 0);
    } else {
        SUCCEED("no install CA on this host — expected in the test sandbox");
    }
}

#if defined(__APPLE__)
namespace {
struct ScopedEnv {
    std::string name;
    bool had_prev = false;
    std::string prev;
    ScopedEnv(std::string n, const std::string& v) : name(std::move(n)) {
        if (const char* cur = std::getenv(name.c_str())) {
            had_prev = true;
            prev = cur;
        }
        ::setenv(name.c_str(), v.c_str(), 1);
    }
    ~ScopedEnv() {
        if (had_prev)
            ::setenv(name.c_str(), prev.c_str(), 1);
        else
            ::unsetenv(name.c_str());
    }
};
} // namespace

// A root agent must never fall back to a per-user path: macOS `sudo` preserves
// $HOME by default, so an unqualified fallback would let a root process adopt
// a CA planted in an unprivileged user's home as its pinned trust anchor.
TEST_CASE("discover_install_ca_path(): root ignores the per-user HOME candidate",
          "[agent][pki][cert-discovery][macos]") {
    if (::geteuid() != 0) {
        SUCCEED("test process is not root — covered by the non-root case below");
        return;
    }
    yuzu::test::TempDir home;
    fs::create_directories(home.path / "Library/Application Support/Yuzu/certs");
    std::ofstream f(home.path / "Library/Application Support/Yuzu/certs/default-ca.pem");
    f << "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    f.close();
    ScopedEnv env{"HOME", home.path.string()};

    auto found = discover_install_ca_path();
    // /etc/yuzu/certs/default-ca.pem is the only candidate considered as root;
    // it is expected absent in the test sandbox, so this must NOT resolve to
    // the planted per-user file.
    if (found.has_value())
        REQUIRE(*found != home.path / "Library/Application Support/Yuzu/certs/default-ca.pem");
}

// A non-root agent falls back to the per-user Application Support path when
// the shared /etc/yuzu/certs convention has nothing (dev/UAT rig — this is
// where server::auth::default_cert_dir() writes for a non-root native macOS
// server run).
TEST_CASE("discover_install_ca_path(): non-root finds the per-user HOME candidate",
          "[agent][pki][cert-discovery][macos]") {
    if (::geteuid() == 0) {
        SUCCEED("test process is root — covered by the root case above");
        return;
    }
    yuzu::test::TempDir home;
    auto ca_dir = home.path / "Library/Application Support/Yuzu/certs";
    fs::create_directories(ca_dir);
    auto ca_path = ca_dir / "default-ca.pem";
    std::ofstream f(ca_path);
    f << "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    f.close();
    ScopedEnv env{"HOME", home.path.string()};

    auto found = discover_install_ca_path();
    // /etc/yuzu/certs/default-ca.pem is expected absent in the test sandbox
    // (and takes precedence if present), so a found result must be the
    // planted per-user file.
    REQUIRE(found.has_value());
    REQUIRE(*found == ca_path);
}
#endif // __APPLE__
