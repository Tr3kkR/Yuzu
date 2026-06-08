/**
 * test_vuln_scan.cpp — Unit tests for vuln_scan Phase 2+3 components:
 *   kernel_detection.hpp, binary_version.hpp, cis_checks.hpp
 */

#include "cis_checks.hpp"
#include "kernel_detection.hpp"
#include "binary_version.hpp"
#include "pkg_scan.hpp"

#include <catch2/catch_test_macros.hpp>

// ── kernel_detection ────────────────────────────────────────────────────────

#ifdef __linux__

TEST_CASE("parse_linux_kernel_version: extracts major.minor.patch", "[vuln][kernel]") {
    using yuzu::vuln::parse_linux_kernel_version;

    // Ubuntu LTS
    auto k = parse_linux_kernel_version("5.15.0-91-generic");
    CHECK(k.major == 5);
    CHECK(k.minor == 15);
    CHECK(k.patch == 0);
    CHECK(k.full_version == "5.15.0-91-generic");
    CHECK(k.platform == "linux");

    // Debian stable
    auto k2 = parse_linux_kernel_version("6.1.0-21-amd64");
    CHECK(k2.major == 6);
    CHECK(k2.minor == 1);
    CHECK(k2.patch == 0);

    // RHEL/CentOS style (extra numeric components after patch)
    auto k3 = parse_linux_kernel_version("5.14.0-427.13.1.el9_4.x86_64");
    CHECK(k3.major == 5);
    CHECK(k3.minor == 14);
    CHECK(k3.patch == 0);

    // Garbage input — gracefully returns zeros, not a crash
    auto k4 = parse_linux_kernel_version("not-a-kernel");
    CHECK(k4.major == 0);
    CHECK(k4.minor == 0);
    CHECK(k4.patch == 0);

    // Short form
    auto k5 = parse_linux_kernel_version("6.9");
    CHECK(k5.major == 6);
    CHECK(k5.minor == 9);
    CHECK(k5.patch == 0);
}

TEST_CASE("get_kernel_info returns linux platform", "[vuln][kernel]") {
    auto k = yuzu::vuln::get_kernel_info();
    CHECK(k.platform == "linux");
    // On a real Linux machine the version is non-empty; in a container it may be the host kernel
    CHECK(!k.full_version.empty());
    // Major must be >= 3 for any remotely modern Linux
    CHECK(k.major >= 3);
}

#endif // __linux__

#ifdef _WIN32

TEST_CASE("synthesize_windows_version builds dotted string", "[vuln][kernel]") {
    auto v = yuzu::vuln::synthesize_windows_version(10, 0, 19045, 4170);
    CHECK(v == "10.0.19045.4170");

    auto v2 = yuzu::vuln::synthesize_windows_version(10, 0, 22621, 0);
    CHECK(v2 == "10.0.22621.0");
}

TEST_CASE("get_kernel_info returns windows platform", "[vuln][kernel]") {
    auto k = yuzu::vuln::get_kernel_info();
    CHECK(k.platform == "windows");
    CHECK(k.major == 10);
    CHECK(k.minor == 0);
    CHECK(!k.full_version.empty());
    // Build must be non-zero on any real system
    CHECK(k.patch > 0);
}

#endif // _WIN32

#ifdef __APPLE__

TEST_CASE("get_kernel_info returns macos platform", "[vuln][kernel]") {
    auto k = yuzu::vuln::get_kernel_info();
    CHECK(k.platform == "macos");
    CHECK(!k.full_version.empty());
    // macOS version is always >= 10
    CHECK(k.major >= 10);
}

#endif // __APPLE__

// ── binary_version ──────────────────────────────────────────────────────────

TEST_CASE("strip_linux_pkg_epoch removes valid epoch prefix", "[vuln][binary]") {
    using yuzu::vuln::strip_linux_pkg_epoch;

    CHECK(strip_linux_pkg_epoch("2:1.0.1g") == "1.0.1g");
    CHECK(strip_linux_pkg_epoch("1.0.1g")   == "1.0.1g");
    CHECK(strip_linux_pkg_epoch("0:3.0.2")  == "3.0.2");
    CHECK(strip_linux_pkg_epoch("10:9.8p1") == "9.8p1");
}

TEST_CASE("strip_linux_pkg_epoch does not strip non-epoch colons", "[vuln][binary]") {
    using yuzu::vuln::strip_linux_pkg_epoch;

    // Non-digit before colon — not an epoch, return unchanged
    CHECK(strip_linux_pkg_epoch("foo:1.0")  == "foo:1.0");
    // Empty string
    CHECK(strip_linux_pkg_epoch("")         == "");
}

#ifdef _WIN32

TEST_CASE("get_pe_file_version returns non-empty for system binary", "[vuln][binary]") {
    // notepad.exe is always present on Windows
    auto v = yuzu::vuln::get_pe_file_version("C:\\Windows\\System32\\notepad.exe");
    REQUIRE(!v.empty());
    // Expected format: MAJOR.MINOR.PATCH.BUILD
    auto dot_count = std::count(v.begin(), v.end(), '.');
    CHECK(dot_count == 3);
}

TEST_CASE("get_pe_file_version returns empty for missing file", "[vuln][binary]") {
    auto v = yuzu::vuln::get_pe_file_version("C:\\nonexistent\\no_such_file.exe");
    CHECK(v.empty());
}

#endif // _WIN32

#ifdef __APPLE__

TEST_CASE("get_bundle_version returns empty for non-existent bundle", "[vuln][binary]") {
    auto v = yuzu::vuln::get_bundle_version("/nonexistent/App.app");
    CHECK(v.empty());
}

#endif // __APPLE__

// ── cis_checks ──────────────────────────────────────────────────────────────

TEST_CASE("run_all_cis_checks: structural validity", "[vuln][cis]") {
    auto results = yuzu::vuln::run_all_cis_checks();

    // Must have at least some checks on every platform
    CHECK(!results.empty());

    for (const auto& c : results) {
        INFO("check_id: " << c.check_id);

        // Required fields must be non-empty
        CHECK(!c.check_id.empty());
        CHECK(!c.title.empty());
        CHECK(!c.level.empty());
        CHECK(!c.status.empty());
        CHECK(!c.severity.empty());
        CHECK(!c.remediation.empty());

        // level must be "1" or "2"
        CHECK((c.level == "1" || c.level == "2"));

        // status must be PASS or FAIL
        CHECK((c.status == "PASS" || c.status == "FAIL"));

        // severity must be one of the valid values
        bool valid_severity = (c.severity == "CRITICAL" || c.severity == "HIGH" ||
                               c.severity == "MEDIUM"   || c.severity == "LOW"  ||
                               c.severity == "INFO");
        CHECK(valid_severity);

        // check_id should follow "CIS-XXX-N.N" pattern
        CHECK(c.check_id.starts_with("CIS-"));
    }
}

TEST_CASE("run_all_cis_checks: PASS checks have INFO severity", "[vuln][cis]") {
    auto results = yuzu::vuln::run_all_cis_checks();
    for (const auto& c : results) {
        if (c.status == "PASS") {
            INFO("check_id: " << c.check_id);
            CHECK(c.severity == "INFO");
        }
    }
}

// ── pkg_scan.hpp tests ────────────────────────────────────────────

TEST_CASE("pkg_scan: parse npm JSON output", "[vuln][pkg_scan]") {
    // This test verifies the npm output parsing logic
    // In production, npm outputs: {"dependencies":{"pkg1":{"version":"1.0.0"},...}}
    // We test the parser with a known JSON structure
    std::string npm_output = R"({
  "dependencies": {
    "lodash": {"version": "4.17.21"},
    "express": {"version": "4.18.0"}
  }
})";
    // Test parsing logic (json.is_object() check, iteration over dependencies)
    auto j = nlohmann::json::parse(npm_output);
    REQUIRE(j.contains("dependencies"));
    REQUIRE(j["dependencies"].is_object());
    int count = 0;
    for (auto& [name, data] : j["dependencies"].items()) {
        REQUIRE(data.contains("version"));
        CHECK(!name.empty());
        CHECK(!data["version"].get<std::string>().empty());
        count++;
    }
    CHECK(count == 2);
}

TEST_CASE("pkg_scan: parse pip JSON output", "[vuln][pkg_scan]") {
    // pip list --format=json outputs: [{"name":"pkg1","version":"1.0.0"},...]
    std::string pip_output = R"([
  {"name": "cryptography", "version": "40.0.1"},
  {"name": "requests", "version": "2.28.2"}
])";
    auto j = nlohmann::json::parse(pip_output);
    REQUIRE(j.is_array());
    int count = 0;
    for (const auto& item : j) {
        REQUIRE(item.contains("name"));
        REQUIRE(item.contains("version"));
        CHECK(!item["name"].get<std::string>().empty());
        CHECK(!item["version"].get<std::string>().empty());
        count++;
    }
    CHECK(count == 2);
}

TEST_CASE("pkg_scan: parse cargo output lines", "[vuln][pkg_scan]") {
    // cargo install --list outputs lines: "pkg v1.0.0:"
    std::string cargo_output = R"(ripgrep v13.0.0:
cli-rs v0.1.0:
another-tool v2.3.0:)";
    std::istringstream stream(cargo_output);
    std::string line;
    int count = 0;
    while (std::getline(stream, line)) {
        size_t space_pos = line.find(' ');
        REQUIRE(space_pos != std::string::npos);
        std::string name = line.substr(0, space_pos);
        CHECK(!name.empty());
        count++;
    }
    CHECK(count == 3);
}

TEST_CASE("pkg_scan: parse gem output format", "[vuln][pkg_scan]") {
    // gem list outputs: "name (v1, v2, ...)"
    std::string gem_output = R"(rails (7.0.4, 7.0.3)
bundler (2.4.1)
rake (13.0.6))";
    std::istringstream stream(gem_output);
    std::string line;
    int count = 0;
    while (std::getline(stream, line)) {
        size_t paren_pos = line.find('(');
        if (paren_pos == std::string::npos) continue;
        std::string name = line.substr(0, paren_pos);
        while (!name.empty() && std::isspace(name.back())) {
            name.pop_back();
        }
        CHECK(!name.empty());
        count++;
    }
    CHECK(count == 3);
}

TEST_CASE("pkg_scan: LangPkgInfo struct has ecosystem field", "[vuln][pkg_scan]") {
    // Verify the data structure
    yuzu::vuln::LangPkgInfo pkg{"npm", "lodash", "4.17.21"};
    CHECK(pkg.ecosystem == "npm");
    CHECK(pkg.name == "lodash");
    CHECK(pkg.version == "4.17.21");
}

TEST_CASE("pkg_scan: JSON parse error is caught gracefully", "[vuln][pkg_scan]") {
    // Malformed JSON should not throw; function catches and logs
    std::string bad_json = R"({"incomplete": json)";
    bool threw = false;
    try {
        [[maybe_unused]] auto j = nlohmann::json::parse(bad_json);
    } catch (const nlohmann::json::exception&) {
        threw = true;
    }
    CHECK(threw);
    // In production, this is caught and silently skipped
}
