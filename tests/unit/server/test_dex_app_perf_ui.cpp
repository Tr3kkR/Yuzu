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

    std::vector<DexGroupOption> groups = {{.id = "g1", .name = "Eng", .members = 42}};

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
    CHECK(has(fleet, "Eng (42)"));
    CHECK_FALSE(has(fleet, "hx-on")); // CSP: no eval-compiled handlers

    // Group scope: subtitle names the group, the works-council floor is captioned.
    const auto grp = render_dex_app_perf_trend("chrome.exe", {v1}, "g1", groups, 10, 30);
    CHECK(has(grp, "Eng"));
    CHECK(has(grp, "works-council"));

    // No versions → honest placeholder, never an empty table.
    CHECK(has(render_dex_app_perf_trend("x", {}, "", groups, 10, 30), "No performance history"));
}
