/**
 * test_dex_app_perf_ui.cpp — slice-2 DEX app-perf-over-time dashboard renderers.
 *
 * Pure, DB-free coverage of the two HTMX fragment renderers (picker + per-version
 * trend). They render from the SAME reduced model the REST/MCP twins use, so these
 * assert only the presentation invariants the other surfaces can't: the honest
 * empty states, the open-top-bucket "≥" floor, the named-group sub-floor
 * suppression cell + works-council caption, and the CSP-safe scope selector.
 */
#include "app_perf_fleet_store.hpp" // AppPerfAppSummary
#include "dex_app_perf_model.hpp"   // AppPerfVersionSummary, HistPctile
#include "dex_app_perf_ui.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::server;

namespace {
bool has(const std::string& h, const std::string& needle) {
    return h.find(needle) != std::string::npos;
}
} // namespace

TEST_CASE("render_dex_app_perf_picker: empty state + populated rows + cap note",
          "[dex][app_perf][ui]") {
    CHECK(has(render_dex_app_perf_picker({}, false, 30), "No application performance history"));

    std::vector<AppPerfAppSummary> apps = {
        {.app_name = "chrome.exe", .versions = 3, .last_day = 1'700'000'000}};
    const auto h = render_dex_app_perf_picker(apps, /*truncated=*/true, 30);
    CHECK(has(h, "chrome.exe"));
    CHECK(has(h, "/fragments/dex/perf/app?app=chrome.exe")); // drill into the trend
    CHECK(has(h, "/api/v1/dex/perf/apps"));                  // truncation points at the REST API
}

TEST_CASE("render_dex_app_perf_trend: floor pctile, suppression, scope selector",
          "[dex][app_perf][ui]") {
    AppPerfVersionSummary v1;
    v1.version = "124.0";
    v1.latest_day = 200;
    v1.device_count = 12;
    v1.day_count = 2;
    v1.cpu_mean = 6.0;
    v1.cpu_p95 = HistPctile{75.0, true}; // open top bucket → a floor
    v1.ws_mean = 1024LL * 1024 * 1024;   // 1 GB
    v1.cpu_series = {4.0, 6.0};

    AppPerfVersionSummary v2; // a sub-floor group slice → suppressed
    v2.version = "125.0";
    v2.latest_day = 200;
    v2.device_count = 3;
    v2.suppressed = true;

    std::vector<DexGroupOption> groups = {{.id = "g1", .name = "Eng"}};

    // Fleet scope (group empty): selector present with "Whole fleet" selected.
    const auto fleet = render_dex_app_perf_trend("chrome.exe", {v1, v2}, "", groups, 10, 30);
    CHECK(has(fleet, "chrome.exe"));
    CHECK(has(fleet, "124.0"));
    CHECK(has(fleet, "&ge;"));        // open-top p95 rendered as "≥ value", never exact
    CHECK(has(fleet, "<svg"));        // server-rendered CSP-safe sparkline
    CHECK(has(fleet, "1.0 GB"));      // working-set mean formatted
    CHECK(has(fleet, "n too small")); // v2 suppressed → count only
    CHECK(has(fleet, "name=\"group\""));
    CHECK(has(fleet, ">Whole fleet</option>"));
    CHECK(has(fleet, ">Eng</option>")); // group option (names only — no N+1 count)
    CHECK_FALSE(has(fleet, "hx-on"));   // CSP: no eval-compiled handlers

    // Group scope: subtitle names the group, the works-council floor + the shorter
    // (B1, 31-day) window are both captioned.
    const auto grp = render_dex_app_perf_trend("chrome.exe", {v1}, "g1", groups, 10, 30);
    CHECK(has(grp, "Eng"));
    CHECK(has(grp, "works-council"));
    CHECK(has(grp, "31 days")); // window-divergence disambiguator

    // No versions → honest placeholder, never an empty table.
    CHECK(has(render_dex_app_perf_trend("x", {}, "", groups, 10, 30), "No performance history"));
}

TEST_CASE("render_dex_device_app_perf: empty state", "[dex][app_perf][ui]") {
    const auto h = render_dex_device_app_perf({});
    CHECK(has(h, "No application performance history for this device"));
    CHECK(has(h, "procperf_enabled")); // names the opt-in so the empty state isn't read as a bug
}

TEST_CASE("render_dex_device_app_perf: single-version app collapses to one row",
          "[dex][app_perf][ui]") {
    AppPerfDeviceVersion v;
    v.version = "3.2.1";
    v.latest_day = 300;
    v.day_count = 5;
    v.instances_max = 2;
    v.cpu_avg = 2.1;
    v.cpu_max = 7.0;
    v.ws_avg = 1024LL * 1024 * 1024; // 1 GB
    v.ws_max = 2LL * 1024 * 1024 * 1024;
    v.cpu_series = {2.0, 2.2, 2.1};
    AppPerfDeviceApp app;
    app.app_name = "AcmeCRM.exe";
    app.latest_day = 300;
    app.peak_cpu_avg = 2.1;
    app.versions = {v};

    const auto h = render_dex_device_app_perf({app});
    CHECK(has(h, "AcmeCRM.exe"));
    CHECK(has(h, "3.2.1"));      // version inline on the combined row
    CHECK(has(h, "2.1%"));       // avg CPU
    CHECK(has(h, "1.0 GB"));     // avg working set formatted
    CHECK(has(h, "<svg"));       // CSP-safe server-rendered sparkline
    CHECK(has(h, "central store")); // foot explains the retained-daily source
    CHECK(has(h, "crashes/hangs are deferred")); // deferred join is noted, not greyed
    CHECK_FALSE(has(h, "per-version below")); // single version → no app header row
    CHECK_FALSE(has(h, "hx-on"));             // CSP: no eval-compiled handlers
}

TEST_CASE("render_dex_device_app_perf: multi-version app shows header + latest tag",
          "[dex][app_perf][ui]") {
    AppPerfDeviceVersion newer;
    newer.version = "125.0";
    newer.latest_day = 300;
    newer.cpu_avg = 12.4;
    newer.cpu_series = {9.0, 12.4};
    AppPerfDeviceVersion older;
    older.version = "124.0";
    older.latest_day = 200;
    older.cpu_avg = 4.1;
    older.cpu_series = {4.0, 4.1};
    AppPerfDeviceApp app;
    app.app_name = "chrome.exe";
    app.latest_day = 300;
    app.peak_cpu_avg = 12.4;
    app.versions = {newer, older}; // already newest-first (as the reducer emits)

    const auto h = render_dex_device_app_perf({app});
    CHECK(has(h, "2 versions"));   // app header row for a multi-version app
    CHECK(has(h, "per-version below"));
    CHECK(has(h, "125.0"));
    CHECK(has(h, "124.0"));
    CHECK(has(h, "latest")); // newest version (versions[0]) tagged
    CHECK(has(h, "12.4%"));
    CHECK(has(h, "4.1%"));
}
