// test_guardian_state_reader.cpp - the production IStateReader (ADR-0021 spark
// rung 5). The file reader is fully exercised against a real filesystem on every
// platform; the systemd service reader runs on Linux (skipped cleanly when no
// system bus is reachable); the registry reader and the Windows SCM service
// reader are behind _WIN32 and are validated on the Windows rig (DGRHP). The
// non-Windows registry branch (Unknown-per-value) IS asserted here.

#include "guardian_state_reader.hpp"

#include "test_helpers.hpp" // yuzu::test::TempDir

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>

using namespace yuzu::agent;

namespace {

// NIST SHA-256("abc"); the file reader must reproduce this from the pinned fd.
constexpr const char* kSha256Abc =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

std::filesystem::path write_file(const std::filesystem::path& dir, const std::string& name,
                                 const std::string& content) {
    std::filesystem::create_directories(dir);
    const auto fp = dir / name;
    std::ofstream o(fp, std::ios::binary);
    o.write(content.data(), static_cast<std::streamsize>(content.size()));
    o.close();
    return fp;
}

} // namespace

TEST_CASE("read_file: an absent path is a Known non-existent snapshot", "[spark][statereader]") {
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    GuardianStateReader reader;
    const auto r = reader.read_file(FileSparkParams{.path = (dir.path / "nope").string()},
                                    FileReadPlan{.hash_cap = 0});
    REQUIRE(r.known);
    REQUIRE_FALSE(r.snapshot.exists);
}

TEST_CASE("read_file: exists-only (hash_cap 0) resolves metadata without hashing",
          "[spark][statereader]") {
    yuzu::test::TempDir dir;
    const auto fp = write_file(dir.path, "f.txt", "abc");
    GuardianStateReader reader;
    const auto r = reader.read_file(FileSparkParams{.path = fp.string()}, FileReadPlan{.hash_cap = 0});
    REQUIRE(r.known);
    REQUIRE(r.snapshot.exists);
    REQUIRE(r.snapshot.readable);
    REQUIRE(r.snapshot.size == 3);
    REQUIRE(r.snapshot.hash.empty());        // hash_cap 0 -> not hashed
    REQUIRE_FALSE(r.snapshot.identity.empty());
    REQUIRE(r.snapshot.mtime_ns != 0);
}

TEST_CASE("read_file: hashes at the cap and reproduces the known SHA-256", "[spark][statereader]") {
    yuzu::test::TempDir dir;
    const auto fp = write_file(dir.path, "f.txt", "abc");
    GuardianStateReader reader;
    const auto r =
        reader.read_file(FileSparkParams{.path = fp.string()}, FileReadPlan{.hash_cap = 1u << 20});
    REQUIRE(r.known);
    REQUIRE(r.snapshot.exists);
    REQUIRE(r.snapshot.readable);
    REQUIRE(r.snapshot.size == 3);
    REQUIRE(r.snapshot.hash == kSha256Abc);
}

TEST_CASE("read_file: a file larger than the cap is Known oversize with no hash",
          "[spark][statereader]") {
    yuzu::test::TempDir dir;
    const auto fp = write_file(dir.path, "f.txt", "abc"); // 3 bytes
    GuardianStateReader reader;
    const auto r =
        reader.read_file(FileSparkParams{.path = fp.string()}, FileReadPlan{.hash_cap = 2});
    REQUIRE(r.known);
    REQUIRE(r.snapshot.exists);
    REQUIRE(r.snapshot.readable); // readable + empty hash + size>cap -> evaluator projects <oversize>
    REQUIRE(r.snapshot.size == 3);
    REQUIRE(r.snapshot.hash.empty());
}

TEST_CASE("read_file: a directory at the path exists but is unreadable", "[spark][statereader]") {
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    GuardianStateReader reader;
    const auto r =
        reader.read_file(FileSparkParams{.path = dir.path.string()}, FileReadPlan{.hash_cap = 64});
    REQUIRE(r.known);
    REQUIRE(r.snapshot.exists);
    REQUIRE_FALSE(r.snapshot.readable); // a directory is not a verifiable regular file
}

TEST_CASE("read_file: a changed file changes the identity/hash across reads", "[spark][statereader]") {
    yuzu::test::TempDir dir;
    const auto fp = write_file(dir.path, "f.txt", "abc");
    GuardianStateReader reader;
    const auto r1 =
        reader.read_file(FileSparkParams{.path = fp.string()}, FileReadPlan{.hash_cap = 1u << 20});
    write_file(dir.path, "f.txt", "abcd"); // rewrite content
    const auto r2 =
        reader.read_file(FileSparkParams{.path = fp.string()}, FileReadPlan{.hash_cap = 1u << 20});
    REQUIRE(r1.known);
    REQUIRE(r2.known);
    REQUIRE(r2.snapshot.size == 4);
    REQUIRE(r1.snapshot.hash != r2.snapshot.hash); // content changed -> digest changed
}

#ifndef _WIN32
TEST_CASE("read_registry off Windows yields Unknown per requested value", "[spark][statereader]") {
    GuardianStateReader reader;
    const auto r = reader.read_registry(
        RegistrySparkParams{.hive = "HKLM", .key = "Software\\Yuzu"},
        RegistryReadPlan{.value_names = {"Alpha", "Beta"}});
    REQUIRE(r.values.size() == 2);
    for (const auto& [name, res] : r.values) {
        INFO("value_name=" << name);
        REQUIRE_FALSE(res.known); // registry cannot be read off Windows -> Unknown, never absent
    }
}
#endif

#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)
TEST_CASE("read_service rejects an invalid unit name as Unknown (no bus touched)",
          "[spark][statereader]") {
    GuardianStateReader reader;
    const auto r = reader.read_service(ServiceSparkParams{.service_name = "bad name!"});
    REQUIRE_FALSE(r.known); // charset-invalid name is refused before any sd_bus work
    REQUIRE(r.error.find("invalid unit name") != std::string::npos);
}

TEST_CASE("read_service maps a truly absent unit to Stopped (R5)", "[spark][statereader]") {
    GuardianStateReader reader;
    const auto r =
        reader.read_service(ServiceSparkParams{.service_name = "yuzu-nonexistent-unit-xyz.service"});
    if (!r.known && r.error.find("sd_bus_open_system") != std::string::npos) {
        SKIP("no reachable system bus in this environment");
    }
    REQUIRE(r.known);                                       // absence is a KNOWN terminal state...
    REQUIRE(r.snapshot == ServiceRunState::Stopped);        // ...that folds to Stopped (R5)
}
#endif
