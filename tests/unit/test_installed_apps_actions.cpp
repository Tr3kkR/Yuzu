/**
 * test_installed_apps_actions.cpp -- Wave 4 PR4.3a dispatch remediation:
 * loads the ACTUAL built installed_apps plugin (installed_apps.dylib/.so, the
 * same artifact the agent daemon loads in production) via PluginHandle::load
 * and drives it through yuzu::agent::LocalDispatcher, same pattern as
 * test_users_posix_actions.cpp -- this proves the migrated argv (probe_tool_path
 * + run_bounded_subprocess, replacing popen()/command_exists()) actually
 * reaches a real dpkg-query/rpm/pacman/system_profiler binary on the test
 * host, end to end, not just that the pure parsers in
 * installed_apps_parsers.hpp accept a fixture string.
 *
 * `list` is the fast, local, always-available action (no params, no
 * per-app enrichment loop) -- assertions are on rc and output SHAPE
 * (every emitted line matches the `app|` wire prefix), never on specific
 * app names/counts, which are entirely host-dependent.
 *
 * TEST-EFFICIENCY JUSTIFICATION (CLAUDE.md unit-suite discipline requires one
 * whenever a test's runtime depends on process creation):
 *   - What it costs, measured on this host (macOS 26, arm64, 2026-08-24):
 *     `list` 4.5 s wall, `list_inventory` a few seconds more. Both are
 *     dominated by one `system_profiler` call, not by fan-out; the pkgutil
 *     receipt leg is a bounded per-id loop under kMaxPkgutilPackages.
 *   - Why a pure-function test cannot replace it: the pure parsers in
 *     installed_apps_parsers.hpp are already exhaustively covered by
 *     test_installed_apps_parsers.cpp. What is NOT reachable that way is the
 *     thing this PR actually changes -- that the migrated argv reaches a real
 *     binary, and that the collector wires enrichment and receipts into
 *     emitted rows. A fixture string re-asserts the parser and proves nothing
 *     about the migration; external functional review specifically found that
 *     the parser-only tests survive reverting every changed call site.
 *   - Bound: these two cases are the ONLY process-spawning tests added here,
 *     and both are macOS/POSIX-gated. Everything else added by this PR is a
 *     pure-function case. If the cost ever becomes a problem, the right move
 *     is an integration tag, not weaker assertions.
 */
#include <catch2/catch_test_macros.hpp>

#ifndef _WIN32

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <sstream>
#include <string>

namespace fs = std::filesystem;

namespace {

#if defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

// Mirrors test_users_posix_actions.cpp's find_users_plugin(), pointed at the
// installed_apps plugin's own build output.
fs::path find_installed_apps_plugin() {
    const std::string lib_name = std::string{"installed_apps"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "installed_apps" /
                                lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "installed_apps" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "installed_apps" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "installed_apps" /
                            lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "installed_apps" /
                            lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

std::optional<LoadedPlugin> load_installed_apps_plugin() {
    auto plugin_path = find_installed_apps_plugin();
    if (plugin_path.empty())
        return std::nullopt;
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value())
        return std::nullopt;
    const auto* descriptor = handle->descriptor();
    if (!descriptor)
        return std::nullopt;
    return LoadedPlugin{std::move(*handle), descriptor};
}

// Every line of `list`'s output is either a real `app|name|version|publisher|
// install_date` row or the plugin's own honest-empty sentinel
// ("app|No applications found|-|-|-") -- both share the `app|` prefix, so a
// single prefix check covers both shapes.
std::size_t count_non_matching_lines(const std::string& captured, std::string_view prefix) {
    std::istringstream iss(captured);
    std::string line;
    std::size_t bad = 0;
    while (std::getline(iss, line)) {
        if (line.empty())
            continue;
        if (line.compare(0, prefix.size(), prefix) != 0)
            ++bad;
    }
    return bad;
}

} // namespace

TEST_CASE("installed_apps plugin: list executes real dpkg-query/rpm/pacman/system_profiler argv",
          "[installed_apps][posix_actions]") {
    auto plugin = load_installed_apps_plugin();
    if (!plugin) {
        // SKIP, not WARN-and-return: a bare `return` retires the case with ZERO
        // assertions and Catch2 reports it as PASSED, so a plugin that stopped
        // loading would read as a green test. SKIP reports it as skipped
        // instead. (Named false-green policy floor; tests/meson.build's
        // link_depends means the artifact is built whenever this runs.)
        SKIP("installed_apps plugin library not found -- cannot drive LocalDispatcher");
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list");

    // rc==0 is the real signal here: a wrong/reverted argv (a stale
    // popen()/command_exists() call, a wrong tool path, or a malformed
    // format string the real tool rejects) would surface as a non-zero rc
    // or garbage output -- this call proves the migrated argv actually
    // reached a real tool on this host, not just that it compiles.
    CHECK(result.rc == 0);
    CHECK_FALSE(result.captured.empty());

    // Shape invariant: every emitted line is an `app|...` row, whether a
    // real app/package or the plugin's own "No applications found" sentinel
    // -- never a stray error string or fragment from a reverted parser.
    CHECK(count_non_matching_lines(result.captured, "app|") == 0);
}

#if defined(__APPLE__)

// Gate-1 remediation (external functional review): NOTHING dispatched
// `list_inventory`, so the whole point of this PR on macOS -- the #2273
// enrichment fields and the new pkgutil receipt rows -- could regress with
// every other assertion still green. The pure parsers prove they can PARSE
// their inputs; only a dispatch proves the collector actually WIRES them into
// emitted rows.
//
// Assertions are on the row CONTRACT (field count, allowed enum values,
// cross-field consistency), never on host-specific names or counts -- except
// the two macOS invariants that hold on any Mac: /System/Applications is
// populated with Apple-signed apps, and pkgutil always holds receipts.
TEST_CASE("installed_apps plugin: list_inventory emits enriched macOS app rows and pkgutil receipts",
          "[installed_apps][posix_actions][macos_inventory]") {
    auto plugin = load_installed_apps_plugin();
    if (!plugin)
        SKIP("installed_apps plugin library not found -- cannot drive LocalDispatcher");

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "list_inventory");

    // Two legal outcomes, and the test asserts the CONTRACT of whichever
    // occurred rather than assuming a healthy host. Adversarial review
    // reproduced `system_profiler` exiting 0 having written nothing, which made
    // an unconditional "there are apps" assertion flaky in exactly the way a
    // shared CI runner would hit. That degraded case is now a first-class
    // outcome (rc=1, publish nothing), so assert THAT here instead of skipping:
    // a partial inventory must never be emitted alongside a degraded result.
    if (result.rc != 0) {
        CHECK(result.rc == 1);
        // The whole point of the degraded path: nothing is published, so the
        // daily sync skips the cycle rather than committing a partial set.
        CHECK(result.captured.empty());
        // SKIP, not return. This is the ONLY test of the enrichment + receipt
        // integration, so a degraded run leaves that integration UNVERIFIED --
        // and a `return` here would report the case as PASSED, which is the
        // vacuous green this suite's policy floor forbids (phase-2 review).
        // Reporting skipped keeps the degraded-contract assertions above while
        // telling the truth about what was not covered.
        SKIP("system_profiler degraded on this host -- degraded contract verified, but the "
             "enrichment/receipt integration was NOT exercised");
    }

    REQUIRE_FALSE(result.captured.empty());

    std::size_t app_rows = 0, pkg_rows = 0;
    std::size_t signed_apps = 0, unsigned_apps = 0, apps_with_publisher = 0;
    std::size_t bad_prefix = 0, bad_field_count = 0, bad_sig_value = 0;
    std::size_t pkg_bad_ecosystem = 0, pkg_non_numeric_date = 0;
    std::size_t publisher_without_signature = 0;

    std::istringstream iss(result.captured);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty())
            continue;
        if (line.rfind("inv|", 0) != 0) {
            ++bad_prefix;
            continue;
        }
        // ADR-0016 blob v2: "inv" + exactly 12 fields. Splitting manually
        // (not on a parser helper) keeps this a genuine wire-shape check.
        std::vector<std::string> f;
        std::size_t start = 0;
        while (true) {
            const auto bar = line.find('|', start);
            if (bar == std::string::npos) {
                f.push_back(line.substr(start));
                break;
            }
            f.push_back(line.substr(start, bar - start));
            start = bar + 1;
        }
        if (f.size() != 13) { // "inv" + 12 fields
            ++bad_field_count;
            continue;
        }
        const std::string& kind = f[5];
        const std::string& ecosystem = f[6];
        const std::string& publisher = f[3];
        const std::string& install_date = f[4];
        const std::string& signature = f[10];

        if (signature != "" && signature != "signed" && signature != "unsigned")
            ++bad_sig_value;

        if (kind == "app") {
            ++app_rows;
            if (signature == "signed")
                ++signed_apps;
            else if (signature == "unsigned")
                ++unsigned_apps;
            if (!publisher.empty()) {
                ++apps_with_publisher;
                // A publisher is read off the signing leaf certificate, so it
                // can never be present on a row we called unsigned.
                if (signature != "signed")
                    ++publisher_without_signature;
            }
        } else if (kind == "pkg") {
            ++pkg_rows;
            if (ecosystem != "macos_pkgutil")
                ++pkg_bad_ecosystem;
            // pkgutil receipts carry raw epoch seconds, never a formatted date.
            if (!install_date.empty() &&
                install_date.find_first_not_of("0123456789") != std::string::npos)
                ++pkg_non_numeric_date;
        }
    }

    CHECK(bad_prefix == 0);
    CHECK(bad_field_count == 0);
    CHECK(bad_sig_value == 0);
    CHECK(publisher_without_signature == 0);

    // The #2273 enrichment actually ran and populated the previously
    // always-empty fields.
    CHECK(app_rows > 0);
    CHECK(signed_apps > 0);          // /System/Applications is Apple-signed
    CHECK(apps_with_publisher > 0);  // leaf-certificate CN extraction works

    // The new pkgutil receipt leg actually emitted rows.
    CHECK(pkg_rows > 0);
    CHECK(pkg_bad_ecosystem == 0);
    CHECK(pkg_non_numeric_date == 0);

    // Caps hold (kMaxEnrichApps / kMaxPkgutilPackages are both 500).
    CHECK(pkg_rows <= 500);
    CHECK(signed_apps + unsigned_apps <= 500);
}

#endif // __APPLE__

#endif // !_WIN32
