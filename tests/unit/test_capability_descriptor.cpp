/**
 * test_capability_descriptor.cpp — PR1.1 / #2204 ABI 3→4 descriptor tests.
 *
 * Covers:
 *   - The ABI version macros widen to [1,4] (never narrow, never reorder).
 *   - YuzuActionDescriptor / YuzuOsLeg / YuzuSupportLevel shape and the
 *     append-only ordering of the support enum.
 *   - The CC-07 result-status enums' zero values really are the honest
 *     "undeclared / unknown" defaults, and the real exported
 *     yuzu_ctx_set_result_status() null-context guard behaves safely.
 *   - REAL ABI3 backward compatibility: dlopens the frozen-layout fixture
 *     plugin (tests/fixtures/abi3/) built from tests/fixtures/abi3/plugin_abi3.h
 *     — NOT a plugin merely recompiled against today's header with
 *     abi_version hand-set to 3 — and exercises its int-only execute() path.
 *     This test FAILS (does not skip) if the fixture module is missing: an
 *     absent fixture is exactly the silent regression this test exists to
 *     catch, never a quiet green.
 *   - Declared-vs-observable honesty: a descriptor with no action_descriptors
 *     (the overwhelming common case today — every existing plugin, since none
 *     has adopted the array yet) must read as "undeclared" for every
 *     capability query, never as a fabricated "supported"/"unsupported".
 */

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace fs = std::filesystem;

// yuzu_ctx_set_result_status() itself is declared (with the correct
// export/import decoration for every platform) in <yuzu/plugin.h>, already
// included above; the real implementation is agents/core/src/agent.cpp,
// built into yuzu_agent_core_lib and linked here via yuzu_agent_core_dep.

namespace yuzu::agent {
// Defined (externally linked, no public header — same convention
// local_dispatcher.cpp uses for dispatch_with_capture) in agent.cpp: the
// CC-07 declared-vs-observable fallback pulled out of execute_command_task
// specifically so this suite can pin its behavior without a live gRPC stream.
YuzuResultStatus derive_effective_result_status(YuzuResultStatus reported, int rc);
} // namespace yuzu::agent

namespace {

#ifdef _WIN32
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

/**
 * Locate the ABI3 fixture plugin built from tests/fixtures/abi3/
 * abi3_fixture_plugin.cpp. Mirrors test_plugin_loader.cpp's
 * find_fixture_plugin() search paths exactly (same build-output convention:
 * a tests/meson.build shared_module/shared_library named
 * "abi3_fixture_plugin" with name_prefix: '' lands at
 * <builddir>/tests/abi3_fixture_plugin<ext>), but — unlike that helper —
 * this one is for a fixture whose ABSENCE must FAIL the test, not skip it:
 * the whole point of this fixture is proving ABI3 backward compatibility
 * against a real old-layout binary, and a "not found -> skip" result would
 * silently stop proving anything.
 */
fs::path find_abi3_fixture() {
    const std::string lib_name = std::string{"abi3_fixture_plugin"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "tests" / lib_name);
    }
    // Meson launches tests with CWD=build root; tests/ sits alongside the exe.
    candidates.emplace_back(fs::path{"tests"} / lib_name);
    candidates.emplace_back(fs::path{"."} / lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

struct RawHandle {
    void* handle{nullptr};
    ~RawHandle() {
        if (handle) {
#ifdef _WIN32
            FreeLibrary(static_cast<HMODULE>(handle));
#else
            dlclose(handle);
#endif
        }
    }
};

} // namespace

// ── ABI version widening (append-only, never narrow) ────────────────────────

TEST_CASE("ABI version widens to [1,4], MIN unchanged", "[capability][abi4]") {
    STATIC_REQUIRE(YUZU_PLUGIN_ABI_VERSION == 4);
    STATIC_REQUIRE(YUZU_PLUGIN_ABI_VERSION_MIN == 1);
}

// ── ActionDescriptor / OsLeg / support-level shape ───────────────────────────

TEST_CASE("YuzuSupportLevel: undeclared is the zero value", "[capability][abi4]") {
    // Zero-init POD must read as "no data", never a fabricated support claim.
    YuzuOsLeg leg{};
    CHECK(leg.support == YUZU_SUPPORT_UNDECLARED);
    CHECK(leg.rung == 0);
    CHECK(leg.mechanism == nullptr);
    CHECK(leg.fallback == nullptr);
}

TEST_CASE("YuzuActionDescriptor carries all three OS legs independently",
         "[capability][abi4]") {
    YuzuActionDescriptor ad{};
    ad.action = "list";
    ad.linux_leg = YuzuOsLeg{YUZU_SUPPORT_SUPPORTED, 3, "procfs", nullptr};
    ad.macos_leg = YuzuOsLeg{YUZU_SUPPORT_CONSTRAINED, 2, "endpoint_security", "no cmdline"};
    ad.windows_leg = YuzuOsLeg{YUZU_SUPPORT_PLANNED, 0, "etw", nullptr};

    CHECK(std::string_view{ad.action} == "list");
    CHECK(ad.linux_leg.support == YUZU_SUPPORT_SUPPORTED);
    CHECK(ad.macos_leg.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(std::string_view{ad.macos_leg.fallback} == "no cmdline");
    CHECK(ad.windows_leg.support == YUZU_SUPPORT_PLANNED);
    // Never #ifdef the leg away — all three are always present in the type,
    // regardless of which OS built this translation unit.
}

TEST_CASE("YuzuPluginDescriptor defaults to zero/undeclared capability data",
         "[capability][abi4]") {
    // An ABI4 descriptor that simply never populates the trailing fields
    // (every plugin in-tree today, since none has adopted them yet) must
    // read as "no capability data", not as a crash or a false claim.
    YuzuPluginDescriptor d{};
    d.abi_version = YUZU_PLUGIN_ABI_VERSION;
    CHECK(d.action_descriptors == nullptr);
    CHECK(d.action_descriptor_count == 0);
}

// ── CC-07 result-status seam: honest defaults + real null-guard ─────────────

TEST_CASE("YuzuResultStatus/Completeness: undeclared/unknown are the zero values",
         "[capability][cc07]") {
    STATIC_REQUIRE(static_cast<int>(YUZU_RESULT_STATUS_UNDECLARED) == 0);
    STATIC_REQUIRE(static_cast<int>(YUZU_RESULT_COMPLETENESS_UNKNOWN) == 0);
}

TEST_CASE("derive_effective_result_status: declared-vs-observable honesty",
         "[capability][cc07]") {
    // A plugin that DID report a typed status always wins, regardless of
    // the int return code — an explicit CONSTRAINED report must not be
    // second-guessed just because execute() happened to return 0.
    CHECK(yuzu::agent::derive_effective_result_status(YUZU_RESULT_STATUS_CONSTRAINED, 0) ==
          YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(yuzu::agent::derive_effective_result_status(YUZU_RESULT_STATUS_PERMISSION_DENIED, 0) ==
          YUZU_RESULT_STATUS_PERMISSION_DENIED);

    // UNDECLARED (no call at all — every ABI<4 plugin, or an ABI4 plugin
    // that just didn't report) falls back to a coarse rc-derived guess.
    CHECK(yuzu::agent::derive_effective_result_status(YUZU_RESULT_STATUS_UNDECLARED, 0) ==
          YUZU_RESULT_STATUS_OK);
    CHECK(yuzu::agent::derive_effective_result_status(YUZU_RESULT_STATUS_UNDECLARED, 1) ==
          YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(yuzu::agent::derive_effective_result_status(YUZU_RESULT_STATUS_UNDECLARED, -1) ==
          YUZU_RESULT_STATUS_UNAVAILABLE);
}

TEST_CASE("yuzu_ctx_set_result_status: null context is a safe no-op",
         "[capability][cc07]") {
    // Calls the REAL exported agent-host symbol (not a test re-implementation).
    // A plugin author who calls this before the agent hands out a live
    // context (or a buggy test) must not crash the host.
    yuzu_ctx_set_result_status(nullptr, YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL,
                              "unit-test");
    SUCCEED("no crash");
}

// ── REAL ABI3 backward compatibility (frozen old-layout fixture) ───────────

TEST_CASE("ABI3 fixture: real old-layout plugin loads and its int-only execute() works",
         "[capability][abi3][loader]") {
    auto fixture_path = find_abi3_fixture();
    // MUST FAIL, not skip — see find_abi3_fixture()'s comment. An absent
    // fixture is exactly the silent-regression case this test exists to
    // catch (a future ABI append that isn't actually backward compatible,
    // or a broken fixture build), so it must turn the suite red.
    if (fixture_path.empty()) {
        FAIL("abi3_fixture_plugin" << kPluginExt
                                   << " not found under tests/ (or $MESON_BUILD_ROOT/tests/) — "
                                      "the standalone shared_module target "
                                      "(tests/fixtures/abi3/abi3_fixture_plugin.cpp) must be "
                                      "built before this test runs.");
    }

    RawHandle rh;
#ifdef _WIN32
    HMODULE hmod = LoadLibraryW(fs::absolute(fixture_path).wstring().c_str());
    REQUIRE(hmod != nullptr);
    rh.handle = static_cast<void*>(hmod);
    auto fn = reinterpret_cast<yuzu_plugin_descriptor_fn>(
        GetProcAddress(hmod, "yuzu_plugin_descriptor"));
#else
    void* h = dlopen(fixture_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    REQUIRE(h != nullptr);
    rh.handle = h;
    auto fn = reinterpret_cast<yuzu_plugin_descriptor_fn>(dlsym(h, "yuzu_plugin_descriptor"));
#endif
    REQUIRE(fn != nullptr);

    const YuzuPluginDescriptor* d = fn();
    REQUIRE(d != nullptr);

    SECTION("ABI3 descriptor is honest about its own version") { CHECK(d->abi_version == 3); }

    SECTION("loader's widened [1,4] range still accepts it") {
        CHECK(d->abi_version >= YUZU_PLUGIN_ABI_VERSION_MIN);
        CHECK(d->abi_version <= YUZU_PLUGIN_ABI_VERSION);
    }

    SECTION("int-only execute() path works end to end") {
        REQUIRE(d->execute != nullptr);
        int rc_ok = d->execute(nullptr, "ping", nullptr, 0);
        CHECK(rc_ok == 0);
        int rc_fail = d->execute(nullptr, "unknown-action", nullptr, 0);
        CHECK(rc_fail != 0);
    }

    SECTION("actions array is null-terminated and non-empty") {
        REQUIRE(d->actions != nullptr);
        REQUIRE(d->actions[0] != nullptr);
        CHECK(std::string_view{d->actions[0]} == "ping");
    }
}

// The section above dlopens the fixture directly and re-derives the
// [MIN,VERSION] comparison inline — proving the fixture itself is a real
// old-layout binary. This test instead drives the SAME fixture through the
// actual production entry point (PluginHandle::load(), plugin_loader.cpp:401)
// so a regression in the production loader's validation/descriptor-access
// path (as opposed to the comparison logic alone) also turns this suite red.
TEST_CASE("ABI3 fixture: PluginHandle::load() (production loader) accepts it",
         "[capability][abi3][loader]") {
    auto fixture_path = find_abi3_fixture();
    if (fixture_path.empty()) {
        FAIL("abi3_fixture_plugin" << kPluginExt
                                   << " not found under tests/ (or $MESON_BUILD_ROOT/tests/) — "
                                      "see the previous test case's message.");
    }

    auto result = yuzu::agent::PluginHandle::load(fixture_path);
    REQUIRE(result.has_value());

    const YuzuPluginDescriptor* d = result->descriptor();
    REQUIRE(d != nullptr);
    CHECK(d->abi_version == 3);

    REQUIRE(d->execute != nullptr);
    CHECK(d->execute(nullptr, "ping", nullptr, 0) == 0);
}
