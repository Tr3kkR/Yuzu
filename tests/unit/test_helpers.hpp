#pragma once

/**
 * test_helpers.hpp — shared test utilities for agent + server unit suites.
 *
 * Header-only inline implementations so every test executable that includes
 * this file owns its own salt and counter. There is no shared-state hazard
 * across the two test binaries — each process gets its own static locals at
 * first use.
 *
 * Layout: `tests/unit/test_helpers.hpp`. Agent-side tests include with
 * `"test_helpers.hpp"`; server-side tests with `"../test_helpers.hpp"`.
 * Intentionally not promoted to a separate include directory in meson —
 * `#include` paths alone are enough, and keeping the header next to the
 * consumers makes grep-discoverable what tests rely on it.
 *
 * History: commit a90a21e hardened `test_guardian_engine.cpp`'s
 * `unique_kv_path()` after Windows MSVC flake #473 traced the fixture
 * collision to `std::hash<std::thread::id>{}` + `steady_clock::now()` —
 * single-threaded Catch2 runs left the clock as the only uniqueness source,
 * and MSVC's steady_clock resolution on some Windows builds was coarse
 * enough that two back-to-back fixtures produced identical paths under
 * Defender-induced I/O serialisation. See #482 for the follow-up that
 * ported the same fix across `test_rest_guaranteed_state.cpp`,
 * `test_rest_api_tokens.cpp`, `test_rest_api_t2.cpp`, and
 * `test_kv_store.cpp`.
 */

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <random>
#include <string>
#include <string_view>

namespace yuzu::test {

/// Generate a unique filesystem path under the system temp directory.
///
/// Uniqueness is guaranteed within a process by a monotonic atomic counter;
/// the counter's initial value is seeded from a process-local 64-bit random
/// salt so two concurrently-running test binaries (if meson ever runs `-j2`
/// on a single suite) cannot collide with each other either. Clock-based
/// uniqueness is explicitly NOT part of the scheme — MSVC's steady_clock on
/// some Windows builds has coarse-enough resolution under Defender-induced
/// I/O serialisation that two back-to-back fixture constructions produced
/// identical paths, causing flake #473.
///
/// The returned path does NOT exist on disk and has no parent directory
/// created. Callers are responsible for creating parent directories and
/// cleaning up (prefer `TempDbFile` RAII below for SQLite stores).
inline std::filesystem::path unique_temp_path(std::string_view prefix = "yuzu-test-") {
    static const std::uint64_t salt = []{
        std::mt19937_64 rng{std::random_device{}()};
        return rng();
    }();
    static std::atomic<std::uint64_t> counter{0};
    const auto n = counter.fetch_add(1, std::memory_order_relaxed);

    std::string name;
    name.reserve(prefix.size() + 40);
    name.append(prefix);
    name.append(std::to_string(salt));
    name.push_back('_');
    name.append(std::to_string(n));
    return std::filesystem::temp_directory_path() / name;
}

/// RAII guard for a per-test SQLite database file. Cleans up the base
/// `.db` plus the `-wal` and `-shm` companion files on destruction. Declare
/// this as the FIRST member of any test harness that opens SQLite so the
/// destructor fires even if downstream construction throws — partial-
/// construction leak pattern documented in `feedback_governance_run.md`
/// (finding qe-B1 from Run 3).
///
/// This is the preferred pattern for new tests. `unique_temp_path()` alone
/// is a lower-level primitive exposed for tests that do not own a SQLite
/// file (e.g. KV-store tests which open via `KvStore::open(path)` and do
/// not generate WAL/SHM directly).
struct TempDbFile {
    std::filesystem::path path;

    explicit TempDbFile(std::string_view prefix = "yuzu-test-") : path(unique_temp_path(prefix)) {}

    ~TempDbFile() noexcept {
        std::error_code ec;
        std::filesystem::remove(path, ec);
        std::filesystem::remove(
            std::filesystem::path(path.string() + "-wal"), ec);
        std::filesystem::remove(
            std::filesystem::path(path.string() + "-shm"), ec);
    }

    TempDbFile(const TempDbFile&) = delete;
    TempDbFile& operator=(const TempDbFile&) = delete;
    TempDbFile(TempDbFile&&) = delete;
    TempDbFile& operator=(TempDbFile&&) = delete;
};

} // namespace yuzu::test
