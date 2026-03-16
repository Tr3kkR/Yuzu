/**
 * test_updater.cpp — Unit tests for the agent-side OTA updater utilities
 *
 * Covers: current_executable_path(), cleanup_old_binary(),
 *         rollback_if_needed(), Updater construction.
 */

#include <yuzu/agent/updater.hpp>

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>

using namespace yuzu::agent;
namespace fs = std::filesystem;

namespace {

/// Helper: create a temporary directory for test files.
fs::path make_temp_dir(const std::string& suffix) {
    auto dir = fs::temp_directory_path() / ("yuzu_test_updater_" + suffix);
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir;
}

/// Helper: clean up a temporary directory.
void cleanup_dir(const fs::path& dir) {
    std::error_code ec;
    fs::remove_all(dir, ec);
}

/// Helper: write a small file to simulate a binary.
void write_fake_binary(const fs::path& path) {
    std::ofstream out(path, std::ios::binary);
    out << "fake-binary-content";
}

}  // anonymous namespace

// ── current_executable_path ─────────────────────────────────────────────────

TEST_CASE("current_executable_path returns non-empty path",
          "[updater][exe_path]") {
    auto path = current_executable_path();
    REQUIRE_FALSE(path.empty());
}

TEST_CASE("current_executable_path points to existing file",
          "[updater][exe_path]") {
    auto path = current_executable_path();
    REQUIRE(fs::exists(path));
}

// ── cleanup_old_binary ──────────────────────────────────────────────────────

TEST_CASE("cleanup_old_binary deletes .old file if present",
          "[updater][cleanup]") {
    auto dir = make_temp_dir("cleanup_present");

#ifdef _WIN32
    auto exe_path = dir / "yuzu-agent.exe";
    auto old_path = dir / "yuzu-agent.old.exe";
#else
    auto exe_path = dir / "yuzu-agent";
    auto old_path = dir / "yuzu-agent.old";
#endif

    write_fake_binary(exe_path);
    write_fake_binary(old_path);

    REQUIRE(fs::exists(old_path));

    UpdateConfig config;
    Updater updater(config, "test-agent", "0.1.0", "windows", "x86_64", exe_path);
    updater.cleanup_old_binary();

    REQUIRE_FALSE(fs::exists(old_path));
    REQUIRE(fs::exists(exe_path));  // Current exe must still exist

    cleanup_dir(dir);
}

TEST_CASE("cleanup_old_binary does nothing if no .old exists",
          "[updater][cleanup]") {
    auto dir = make_temp_dir("cleanup_absent");

#ifdef _WIN32
    auto exe_path = dir / "yuzu-agent.exe";
#else
    auto exe_path = dir / "yuzu-agent";
#endif

    write_fake_binary(exe_path);

    UpdateConfig config;
    Updater updater(config, "test-agent", "0.1.0", "windows", "x86_64", exe_path);

    // Should not throw or crash
    updater.cleanup_old_binary();

    REQUIRE(fs::exists(exe_path));

    cleanup_dir(dir);
}

// ── rollback_if_needed ──────────────────────────────────────────────────────

TEST_CASE("rollback_if_needed returns false when no .old exists",
          "[updater][rollback]") {
    auto dir = make_temp_dir("rollback_no_old");

#ifdef _WIN32
    auto exe_path = dir / "yuzu-agent.exe";
#else
    auto exe_path = dir / "yuzu-agent";
#endif

    write_fake_binary(exe_path);

    UpdateConfig config;
    Updater updater(config, "test-agent", "0.1.0", "windows", "x86_64", exe_path);

    REQUIRE_FALSE(updater.rollback_if_needed());

    cleanup_dir(dir);
}

TEST_CASE("rollback_if_needed returns false when .old exists AND verified marker exists",
          "[updater][rollback]") {
    auto dir = make_temp_dir("rollback_verified");

#ifdef _WIN32
    auto exe_path = dir / "yuzu-agent.exe";
    auto old_path = dir / "yuzu-agent.old.exe";
#else
    auto exe_path = dir / "yuzu-agent";
    auto old_path = dir / "yuzu-agent.old";
#endif

    auto marker_path = dir / ".yuzu-update-verified";

    write_fake_binary(exe_path);
    write_fake_binary(old_path);
    write_fake_binary(marker_path);  // Verification marker exists

    UpdateConfig config;
    Updater updater(config, "test-agent", "0.1.0", "windows", "x86_64", exe_path);

    // Should return false (no rollback needed) and clean up old + marker
    REQUIRE_FALSE(updater.rollback_if_needed());
    REQUIRE_FALSE(fs::exists(old_path));
    REQUIRE_FALSE(fs::exists(marker_path));

    cleanup_dir(dir);
}

TEST_CASE("rollback_if_needed returns true when .old exists but NO verified marker",
          "[updater][rollback]") {
    auto dir = make_temp_dir("rollback_needed");

#ifdef _WIN32
    auto exe_path = dir / "yuzu-agent.exe";
    auto old_path = dir / "yuzu-agent.old.exe";
#else
    auto exe_path = dir / "yuzu-agent";
    auto old_path = dir / "yuzu-agent.old";
#endif

    write_fake_binary(exe_path);
    write_fake_binary(old_path);

    // No .yuzu-update-verified marker — should trigger rollback

    UpdateConfig config;
    Updater updater(config, "test-agent", "0.1.0", "windows", "x86_64", exe_path);

    REQUIRE(updater.rollback_if_needed());

    // After rollback, the old binary should have been moved back to exe_path
    REQUIRE(fs::exists(exe_path));
    REQUIRE_FALSE(fs::exists(old_path));

    cleanup_dir(dir);
}

// ── Construction ────────────────────────────────────────────────────────────

TEST_CASE("Updater constructs without error", "[updater][construct]") {
    UpdateConfig config;
    config.enabled = true;
    config.check_interval = std::chrono::seconds{3600};

    auto exe = current_executable_path();

    // Should not throw
    Updater updater(config, "agent-123", "0.1.0", "windows", "x86_64", exe);

    // Verify stop works without prior start
    updater.stop();
}
