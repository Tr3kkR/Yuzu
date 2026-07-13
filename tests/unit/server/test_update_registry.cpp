/**
 * test_update_registry.cpp — Unit tests for the OTA update registry
 *
 * Covers: UpdateRegistry CRUD, latest_for version selection,
 *         is_eligible rollout logic, binary_path, upsert-replace.
 */

#include "update_registry.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <string>

using namespace yuzu::server;
namespace fs = std::filesystem;

namespace {

/// RAII per-test update_dir. Process-salted: a fixed dir name is a cross-JOB
/// shared resource on the shared-identity CI pools — one job's cleanup
/// remove_all would yank the dir out from under another job's live
/// UpdateRegistry (#1883). RAII (vs the old trailing cleanup call) also
/// removes the dir when a REQUIRE fails — with salted never-reused names a
/// leaked dir is pure litter, not self-overwriting. Creation is asserted so
/// a full temp volume can't silently hollow out the tests (gov safe-1/-2).
struct TempUpdateDir {
    yuzu::test::TempDir guard{"yuzu_test_update_registry-"};
    TempUpdateDir() {
        std::error_code ec;
        fs::create_directories(guard.path, ec);
        REQUIRE(fs::exists(guard.path));
    }
    const fs::path& path() const { return guard.path; }
};

/// Helper: build an UpdatePackage with sensible defaults.
UpdatePackage make_pkg(const std::string& platform = "windows", const std::string& arch = "x86_64",
                       const std::string& version = "0.1.0",
                       const std::string& filename = "yuzu-agent-0.1.0-x64-windows.exe") {
    UpdatePackage pkg;
    pkg.platform = platform;
    pkg.arch = arch;
    pkg.version = version;
    pkg.sha256 = "aabbccdd";
    pkg.filename = filename;
    pkg.mandatory = false;
    pkg.rollout_pct = 100;
    pkg.uploaded_at = "2025-01-01T00:00:00Z";
    pkg.file_size = 1024;
    return pkg;
}

} // anonymous namespace

// ── Database Lifecycle ──────────────────────────────────────────────────────

TEST_CASE("UpdateRegistry: open in-memory", "[update_registry][db]") {
    TempUpdateDir tmp;
    const auto& dir = tmp.path();
    UpdateRegistry reg(":memory:", dir);
    REQUIRE(reg.is_open());
}

// ── Upsert & List ───────────────────────────────────────────────────────────

TEST_CASE("UpdateRegistry: upsert_package + list_packages returns it",
          "[update_registry][upsert]") {
    TempUpdateDir tmp;
    const auto& dir = tmp.path();
    UpdateRegistry reg(":memory:", dir);

    auto pkg = make_pkg();
    reg.upsert_package(pkg);

    auto packages = reg.list_packages();
    REQUIRE(packages.size() == 1);
    REQUIRE(packages[0].platform == "windows");
    REQUIRE(packages[0].arch == "x86_64");
    REQUIRE(packages[0].version == "0.1.0");
    REQUIRE(packages[0].filename == "yuzu-agent-0.1.0-x64-windows.exe");

}

// ── latest_for ──────────────────────────────────────────────────────────────

TEST_CASE("UpdateRegistry: latest_for returns package for matching platform/arch",
          "[update_registry][latest]") {
    TempUpdateDir tmp;
    const auto& dir = tmp.path();
    UpdateRegistry reg(":memory:", dir);

    reg.upsert_package(make_pkg("linux", "x86_64", "0.1.0", "yuzu-agent-0.1.0-linux"));

    auto result = reg.latest_for("linux", "x86_64");
    REQUIRE(result.has_value());
    REQUIRE(result->version == "0.1.0");
    REQUIRE(result->platform == "linux");

}

TEST_CASE("UpdateRegistry: latest_for returns nullopt for unknown platform",
          "[update_registry][latest]") {
    TempUpdateDir tmp;
    const auto& dir = tmp.path();
    UpdateRegistry reg(":memory:", dir);

    reg.upsert_package(make_pkg("windows", "x86_64", "0.1.0"));

    auto result = reg.latest_for("freebsd", "x86_64");
    REQUIRE_FALSE(result.has_value());

}

TEST_CASE("UpdateRegistry: latest_for returns newest version when multiple exist",
          "[update_registry][latest]") {
    TempUpdateDir tmp;
    const auto& dir = tmp.path();
    UpdateRegistry reg(":memory:", dir);

    reg.upsert_package(make_pkg("windows", "x86_64", "0.1.0", "agent-0.1.0.exe"));
    reg.upsert_package(make_pkg("windows", "x86_64", "0.2.0", "agent-0.2.0.exe"));

    auto result = reg.latest_for("windows", "x86_64");
    REQUIRE(result.has_value());
    REQUIRE(result->version == "0.2.0");

}

TEST_CASE("UpdateRegistry: latest_for handles numeric version comparison (0.10.0 > 0.9.0)",
          "[update_registry][latest]") {
    TempUpdateDir tmp;
    const auto& dir = tmp.path();
    UpdateRegistry reg(":memory:", dir);

    reg.upsert_package(make_pkg("linux", "aarch64", "0.9.0", "agent-0.9.0"));
    reg.upsert_package(make_pkg("linux", "aarch64", "0.10.0", "agent-0.10.0"));

    auto result = reg.latest_for("linux", "aarch64");
    REQUIRE(result.has_value());
    REQUIRE(result->version == "0.10.0");

}

// ── Remove ──────────────────────────────────────────────────────────────────

TEST_CASE("UpdateRegistry: remove_package makes latest_for return nullopt",
          "[update_registry][remove]") {
    TempUpdateDir tmp;
    const auto& dir = tmp.path();
    UpdateRegistry reg(":memory:", dir);

    reg.upsert_package(make_pkg("windows", "x86_64", "0.1.0"));
    reg.remove_package("windows", "x86_64", "0.1.0");

    auto result = reg.latest_for("windows", "x86_64");
    REQUIRE_FALSE(result.has_value());

}

TEST_CASE("UpdateRegistry: remove_package for nonexistent does not crash",
          "[update_registry][remove]") {
    TempUpdateDir tmp;
    const auto& dir = tmp.path();
    UpdateRegistry reg(":memory:", dir);

    // Should not throw or crash
    reg.remove_package("darwin", "aarch64", "9.9.9");

    auto packages = reg.list_packages();
    REQUIRE(packages.empty());

}

// ── Rollout Eligibility ─────────────────────────────────────────────────────

TEST_CASE("UpdateRegistry: is_eligible at 100% always returns true", "[update_registry][rollout]") {
    for (int i = 0; i < 50; ++i) {
        REQUIRE(UpdateRegistry::is_eligible("agent-" + std::to_string(i), 100));
    }
}

TEST_CASE("UpdateRegistry: is_eligible at 0% always returns false", "[update_registry][rollout]") {
    for (int i = 0; i < 50; ++i) {
        REQUIRE_FALSE(UpdateRegistry::is_eligible("agent-" + std::to_string(i), 0));
    }
}

TEST_CASE("UpdateRegistry: is_eligible is deterministic", "[update_registry][rollout]") {
    const std::string agent_id = "test-agent-42";
    bool first_result = UpdateRegistry::is_eligible(agent_id, 50);

    // Same agent_id and rollout_pct should always produce the same result
    for (int i = 0; i < 20; ++i) {
        REQUIRE(UpdateRegistry::is_eligible(agent_id, 50) == first_result);
    }
}

TEST_CASE("UpdateRegistry: is_eligible distributes roughly 50% at rollout_pct=50",
          "[update_registry][rollout]") {
    int eligible_count = 0;
    constexpr int kTotal = 100;

    for (int i = 0; i < kTotal; ++i) {
        if (UpdateRegistry::is_eligible("agent-distribution-" + std::to_string(i), 50)) {
            ++eligible_count;
        }
    }

    // Expect roughly half — allow wide margin (30-70) to avoid flaky tests
    REQUIRE(eligible_count >= 30);
    REQUIRE(eligible_count <= 70);
}

// ── binary_path ─────────────────────────────────────────────────────────────

TEST_CASE("UpdateRegistry: binary_path returns update_dir / filename", "[update_registry][path]") {
    TempUpdateDir tmp;
    const auto& dir = tmp.path();
    UpdateRegistry reg(":memory:", dir);

    auto pkg = make_pkg("windows", "x86_64", "0.1.0", "yuzu-agent.exe");
    auto path = reg.binary_path(pkg);
    REQUIRE(path == dir / "yuzu-agent.exe");

}

// ── list_packages ───────────────────────────────────────────────────────────

TEST_CASE("UpdateRegistry: list_packages returns all upserted packages",
          "[update_registry][list]") {
    TempUpdateDir tmp;
    const auto& dir = tmp.path();
    UpdateRegistry reg(":memory:", dir);

    reg.upsert_package(make_pkg("windows", "x86_64", "0.1.0", "agent-win-0.1.0.exe"));
    reg.upsert_package(make_pkg("linux", "x86_64", "0.1.0", "agent-linux-0.1.0"));
    reg.upsert_package(make_pkg("darwin", "aarch64", "0.1.0", "agent-darwin-0.1.0"));

    auto packages = reg.list_packages();
    REQUIRE(packages.size() == 3);

}

// ── Upsert Replace ─────────────────────────────────────────────────────────

TEST_CASE("UpdateRegistry: upsert same platform/arch/version replaces existing",
          "[update_registry][upsert]") {
    TempUpdateDir tmp;
    const auto& dir = tmp.path();
    UpdateRegistry reg(":memory:", dir);

    auto pkg = make_pkg("windows", "x86_64", "0.1.0", "agent-v1.exe");
    pkg.sha256 = "original_hash";
    reg.upsert_package(pkg);

    // Upsert with same primary key but different fields
    pkg.sha256 = "updated_hash";
    pkg.filename = "agent-v1-rebuilt.exe";
    pkg.file_size = 2048;
    reg.upsert_package(pkg);

    auto packages = reg.list_packages();
    REQUIRE(packages.size() == 1);
    REQUIRE(packages[0].sha256 == "updated_hash");
    REQUIRE(packages[0].filename == "agent-v1-rebuilt.exe");
    REQUIRE(packages[0].file_size == 2048);

}
