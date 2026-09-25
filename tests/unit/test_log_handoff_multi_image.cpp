// test_log_handoff_multi_image.cpp - #4666 PR-2 W3a: the macOS multi-image open
// question. log_handoff.hpp's own MULTI-IMAGE note records that Linux and Windows are
// ALREADY CONFIRMED to share one spdlog registry across the exe, libyuzu_agent_core, and
// every plugin image - macOS is the one platform that note calls "LIKELY two registries
// ... unproved, characterised by PR-2's own fixture." This file IS that fixture: it runs
// the identical measurement on every platform the suite executes on, so the macOS run is
// a genuine empirical observation rather than an inference from the other two legs.
//
// MI-1: correctness of install_log_handoff_in_this_image()/
// release_log_handoff_from_this_image() across this test binary's own image, PLUS the
// topology measurement itself - does a call compiled into THIS test binary's image and a
// call compiled into libyuzu_agent_core.so's image (log_handoff_emit_probe_for_test(),
// log_handoff.hpp) both land in the same capture sink once install_log_handoff_in_this_image()
// has run? If both reach it, the two images route through the same default-logger slot
// (whether that means one shared registry, or two registries whose "" default-logger
// entries happen to alias the same object, is not distinguished by this measurement -
// only that a caller in either image observes the same effective logger).
//
// MI-3: a REAL agent_actions plugin dispatch measures the same question from a THIRD
// image (a loaded plugin .so/.dylib/.dll) via a production code path: its real
// set_log_level action calls the raw, registry-wide spdlog::set_level() API
// (agent_actions_plugin.cpp's do_set_log_level()).
//
// Neither REQUIREs the "shared" outcome for the topology question itself - the whole
// point of this file is to OBSERVE a property it cannot know in advance for every
// platform it runs on. Only HELPER correctness (a same-image call reaching the sink,
// teardown destroying the sink, level filtering working) is REQUIRE'd; the topology
// verdict is recorded via INFO/WARN and written to a report file (see
// write_topology_report() below) so it survives the test run for later inspection.

#include "agent_log_wiring.hpp"
#include "local_dispatcher.hpp"
#include "log_handoff.hpp"

#include "log_handoff_test_sinks.hpp"
#include "test_helpers.hpp"

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>

#include <spdlog/spdlog.h>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

using namespace std::chrono_literals;
using yuzu::agent::install_log_handoff_in_this_image;
using yuzu::agent::LogHandoff;
using yuzu::agent::log_handoff_emit_probe_for_test;
using yuzu::agent::release_log_handoff_from_this_image;
using yuzu::test::GatedCaptureSink;

namespace fs = std::filesystem;

namespace {

// Writes `text` to <build-root>/log_handoff_multi_image_topology.txt so MI-1's
// measurement survives past this test run. MESON_BUILD_ROOT is a real env var meson's
// own test runner sets (not a project convention invented here) - already relied on by
// this directory's find_users_plugin()-style helpers (see test_users_posix_actions.cpp).
// Falls back to the current working directory when unset (e.g. a direct, non-`meson
// test` invocation of this binary) - verified empirically that `meson test` itself runs
// with CWD == build root, so the fallback lands in the same place MESON_BUILD_ROOT
// would point to anyway.
void write_topology_report(const std::string& text) {
    fs::path out_dir;
    if (const auto* build_root = std::getenv("MESON_BUILD_ROOT"))
        out_dir = fs::path{build_root};
    else
        out_dir = fs::current_path();

    std::error_code ec;
    fs::create_directories(out_dir, ec); // no-op if it already exists; ignore failure -
                                          // the ofstream open below is the real check.

    std::ofstream out{out_dir / "log_handoff_multi_image_topology.txt", std::ios::trunc};
    if (out)
        out << text;
}

#if defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#elif defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#else
constexpr const char* kPluginExt = ".so";
#endif

// Mirrors test_users_posix_actions.cpp's find_users_plugin() - same candidate-path
// fallback list, pointed at the agent_actions plugin's own build output. Empty path
// (never a hard failure) when not found, so a build without agent plugins skips MI-3
// rather than failing.
fs::path find_agent_actions_plugin() {
    const std::string lib_name = std::string{"agent_actions"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (const auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "agent_actions" /
                                lib_name);
    }
    // Meson launches tests with CWD=build root; agents/ sits alongside tests/.
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "agent_actions" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "agent_actions" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "agent_actions" / lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "agent_actions" / lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

} // namespace

// ---------------------------------------------------------------------------
// MI-1
// ---------------------------------------------------------------------------

TEST_CASE("MI-1: install_log_handoff_in_this_image/release_log_handoff_from_this_image "
          "round-trip in this image, and the cross-image topology measurement itself",
          "[log_handoff][multi_image]") {
    auto sink = std::make_shared<GatedCaptureSink>(/*initially_paused=*/false);
    auto closed = sink->closed_flag();

    auto result = LogHandoff::create_with_sinks({sink});
    REQUIRE(result.has_value());
    auto h = std::move(*result);

    REQUIRE(install_log_handoff_in_this_image(*h, spdlog::level::info, /*json_format=*/false));

    // ---- Topology measurement --------------------------------------------------
    // "from library image" executes INSIDE libyuzu_agent_core's own compiled image -
    // log_handoff_emit_probe_for_test() is defined in log_handoff.cpp (spdlog::info()
    // called from THAT translation unit). "from test image" executes inside THIS test
    // binary's own image - a plain spdlog::info() call compiled directly into this TU.
    log_handoff_emit_probe_for_test("from library image");
    spdlog::info("from test image");

    REQUIRE(yuzu::test::spin_until([&] { return h->queue_depth() == 0; }, 2s));

    const auto snap = sink->snapshot();
    bool saw_library_line = false;
    bool saw_test_line = false;
    for (const auto& c : snap) {
        if (c.payload == "from library image")
            saw_library_line = true;
        if (c.payload == "from test image")
            saw_test_line = true;
    }

    // The test-image line MUST reach the sink: install_log_handoff_in_this_image() just
    // set THIS image's default logger to h's logger, and the spdlog::info() call above
    // ran in this same image/TU. A failure here means the HELPER is broken, not that the
    // topology answer is "separate" - fail loudly rather than fold it into the
    // observational verdict below.
    REQUIRE(saw_test_line);

    std::string topology;
    if (saw_library_line && saw_test_line) {
        topology = "SHARED (or at least routed to the same effective default-logger slot): "
                   "both the library-image probe and the test-image call reached the same "
                   "capture sink";
    } else if (saw_test_line && !saw_library_line) {
        topology = "SEPARATE: the test-image call reached the capture sink but the "
                   "library-image probe did not - libyuzu_agent_core's image appears to "
                   "have its own spdlog registry/default-logger slot, distinct from this "
                   "test binary's";
    } else {
        topology = "AMBIGUOUS: neither line landed as expected - see the raw capture below";
    }

    INFO("MI-1 topology: " << topology);
    WARN("MI-1 topology: " << topology);

    std::string report = "#4666 PR-2 W3a MI-1 topology measurement\n";
    report += "saw_library_line=" + std::string(saw_library_line ? "true" : "false") + "\n";
    report += "saw_test_line=" + std::string(saw_test_line ? "true" : "false") + "\n";
    report += "conclusion: " + topology + "\n";
    report += "raw capture (" + std::to_string(snap.size()) + " line(s)):\n";
    for (const auto& c : snap)
        report += "  - " + c.payload + "\n";
    write_topology_report(report);

    // ---- Teardown / R-LOGGER regression tripwire --------------------------------
    sink.reset(); // drop OUR reference - the only remaining owner is h's own
                  // wrapped_sinks_, so release_log_handoff_from_this_image()'s
                  // teardown() (T3) is what actually destroys the GatedCaptureSink.
    release_log_handoff_from_this_image(*h);
    REQUIRE(closed->load(std::memory_order_acquire));
}

TEST_CASE("MI-1: install_log_handoff_in_this_image applies the level - a below-level "
          "line never reaches the sink, an at-level line does",
          "[log_handoff][multi_image]") {
    auto sink = std::make_shared<GatedCaptureSink>(/*initially_paused=*/false);
    auto result = LogHandoff::create_with_sinks({sink});
    REQUIRE(result.has_value());
    auto h = std::move(*result);
    yuzu::test::ScopeExit release_on_exit{[&] { release_log_handoff_from_this_image(*h); }};

    REQUIRE(install_log_handoff_in_this_image(*h, spdlog::level::warn, /*json_format=*/false));

    spdlog::info("below-the-installed-level");
    REQUIRE(yuzu::test::spin_until([&] { return h->queue_depth() == 0; }, 2s));
    CHECK(sink->count() == 0);

    spdlog::warn("at-the-installed-level");
    REQUIRE(yuzu::test::spin_until([&] { return sink->count() == 1; }, 2s));
    const auto snap = sink->snapshot();
    REQUIRE(snap.size() == 1);
    CHECK(snap[0].payload == "at-the-installed-level");
}

// ---------------------------------------------------------------------------
// MI-3
// ---------------------------------------------------------------------------
//
// do_set_log_level() (agent_actions_plugin.cpp) calls the raw, registry-wide
// spdlog::set_level() API, which (per spdlog::details::registry::set_level()) walks
// registry::loggers_ and changes every ALREADY-REGISTERED logger's level - it only has
// any effect on this test's installed LogHandoff logger if the plugin's own
// spdlog::set_level() call resolves against the SAME registry this test installed into.

TEST_CASE("MI-3: dispatching agent_actions's real set_log_level action against a loaded "
          "plugin image measures whether it reaches this image's installed LogHandoff",
          "[log_handoff][multi_image]") {
    auto plugin_path = find_agent_actions_plugin();
    if (plugin_path.empty()) {
        WARN("agent_actions plugin library not found -- skipping MI-3");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value()) {
        WARN("agent_actions plugin failed to load -- skipping MI-3");
        return;
    }
    const auto* descriptor = handle->descriptor();
    REQUIRE(descriptor != nullptr);

    auto sink = std::make_shared<GatedCaptureSink>(/*initially_paused=*/false);
    auto result = LogHandoff::create_with_sinks({sink});
    REQUIRE(result.has_value());
    auto h = std::move(*result);
    yuzu::test::ScopeExit release_on_exit{[&] { release_log_handoff_from_this_image(*h); }};

    REQUIRE(install_log_handoff_in_this_image(*h, spdlog::level::info, /*json_format=*/false));

    // Baseline: a debug line does NOT reach the sink at the installed 'info' level.
    spdlog::debug("before-dispatch-debug-line");
    REQUIRE(yuzu::test::spin_until([&] { return h->queue_depth() == 0; }, 2s));
    CHECK(sink->count() == 0);

    yuzu::agent::LocalDispatcher dispatcher;
    std::vector<YuzuParam> params{{"level", "debug"}};
    auto dispatch_result = dispatcher.run(descriptor, "set_log_level", params);
    CHECK(dispatch_result.rc == 0);

    // The actual measurement: did the plugin's own spdlog::set_level(debug) call reach
    // this image's installed logger? Recorded, not asserted either way - see the file
    // banner.
    spdlog::debug("after-dispatch-debug-line");
    const bool debug_reached = yuzu::test::spin_until([&] { return sink->count() >= 1; }, 2s);

    if (debug_reached) {
        WARN("MI-3: agent_actions's set_log_level(debug) DID change this image's "
             "installed LogHandoff level -- the plugin's spdlog::set_level() call "
             "reached this image's registered logger");
    } else {
        WARN("MI-3: agent_actions's set_log_level(debug) did NOT change this image's "
             "installed LogHandoff level -- a known possible/historical outcome (#3355): "
             "the plugin image may hold its own separate registry");
    }
}
