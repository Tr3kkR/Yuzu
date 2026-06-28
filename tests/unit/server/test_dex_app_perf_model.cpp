/**
 * test_dex_app_perf_model.cpp — slice-2 DEX app-perf-over-time READ model.
 *
 * Pure, DB-free coverage of the ONE shared transform the REST endpoint, the MCP
 * tool, and the dashboard all render through (so they cannot disagree):
 *
 *  - percentile_from_hist: nearest-rank DIRECTION over fixed buckets; lower-edge
 *    representative; the OPEN top bucket flagged as a floor (lower_bound); nullopt
 *    on an empty population or a size/scheme mismatch (defence beneath the
 *    caller's hist_version gate).
 *  - app_perf_fleet_trend: EXACT fleet mean = sum/device_count (no divide at
 *    device_count==0); percentiles withheld + hist_stale on a wrong-scheme row;
 *    populated on a current-scheme row.
 */
#include "app_perf_fleet_store.hpp"
#include "app_perf_hist.hpp"
#include "dex_app_perf_model.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <vector>

using namespace yuzu::server;

namespace {

// A valid CPU hist is 12 buckets (11 boundaries → 12). Helper builds one with the
// given per-bucket counts (zero-padded / truncated to the right length).
std::vector<std::int64_t> cpu_hist(std::vector<std::int64_t> counts) {
    counts.resize(app_perf_cpu_buckets().size() + 1, 0);
    return counts;
}

} // namespace

TEST_CASE("percentile_from_hist: size mismatch and empty population degrade", "[dex][app_perf]") {
    const auto& b = app_perf_cpu_buckets(); // 11 boundaries

    // Wrong length (a corrupt / wrong-scheme row) → nullopt, never a wrong read.
    CHECK_FALSE(percentile_from_hist(std::vector<std::int64_t>(5, 0), b, 0.5).has_value());

    // Right length but zero population → nullopt (absent, never a fabricated 0).
    CHECK_FALSE(percentile_from_hist(cpu_hist({}), b, 0.5).has_value());
}

TEST_CASE("percentile_from_hist: nearest-rank lands in the right bucket", "[dex][app_perf]") {
    const auto& b = app_perf_cpu_buckets();
    // 5 devices in bucket 1 = [0.5,1) (lower edge b[0]=0.5);
    // 5 devices in bucket 9 = [30,50) (lower edge b[8]=30). total = 10.
    auto h = cpu_hist({0, 5, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0});

    auto p50 = percentile_from_hist(h, b, 0.50);
    REQUIRE(p50.has_value());
    CHECK(p50->value == 0.5); // rank ceil(.5*10)=5 → still bucket 1
    CHECK_FALSE(p50->lower_bound);

    auto p95 = percentile_from_hist(h, b, 0.95);
    REQUIRE(p95.has_value());
    CHECK(p95->value == 30.0); // rank ceil(.95*10)=10 → bucket 9
    CHECK_FALSE(p95->lower_bound);

    // p0 floors at rank 1 → the lowest populated bucket; p100 → the highest.
    CHECK(percentile_from_hist(h, b, 0.0)->value == 0.5);
    CHECK(percentile_from_hist(h, b, 1.0)->value == 30.0);
}

TEST_CASE("percentile_from_hist: open top bucket is a floor, bottom is the metric floor",
          "[dex][app_perf]") {
    const auto& b = app_perf_cpu_buckets();
    const std::size_t top = b.size(); // bucket index 11 = [75, +inf)

    // All mass in the open top bucket → value is the last boundary, flagged floor.
    std::vector<std::int64_t> hi(b.size() + 1, 0);
    hi[top] = 7;
    auto p = percentile_from_hist(hi, b, 0.95);
    REQUIRE(p.has_value());
    CHECK(p->value == b.back()); // 75
    CHECK(p->lower_bound);       // render "≥ 75", never as an exact value

    // All mass in bucket 0 = [0, b[0]) → the metric floor 0, NOT flagged.
    std::vector<std::int64_t> lo(b.size() + 1, 0);
    lo[0] = 7;
    auto q = percentile_from_hist(lo, b, 0.5);
    REQUIRE(q.has_value());
    CHECK(q->value == 0.0);
    CHECK_FALSE(q->lower_bound);
}

TEST_CASE("app_perf_fleet_trend: exact mean, no divide-by-zero", "[dex][app_perf]") {
    AppPerfFleetRow row;
    row.app_name = "chrome.exe";
    row.version = "124.0.0.1";
    row.day = 1'700'000'000;
    row.device_count = 4;
    row.cpu_sum = 20.0; // mean 5.0
    row.cpu_max = 9.0;
    row.ws_sum = 400;   // mean 100
    row.ws_max = 250;
    row.hist_version = kAppPerfHistVersion;
    row.cpu_hist = cpu_hist({0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0}); // bucket 4
    row.ws_hist.assign(app_perf_ws_buckets().size() + 1, 0);
    row.ws_hist[3] = 4;

    auto trend = app_perf_fleet_trend({row});
    REQUIRE(trend.size() == 1);
    const auto& pt = trend[0];
    CHECK(pt.version == "124.0.0.1");
    CHECK(pt.cpu_mean == 5.0);
    CHECK(pt.ws_mean == 100);
    CHECK_FALSE(pt.hist_stale);
    REQUIRE(pt.cpu_p50.has_value());
    CHECK(pt.cpu_p50->value == app_perf_cpu_buckets()[3]); // bucket 4 lower edge = b[3]=3
    REQUIRE(pt.ws_p50.has_value());

    // device_count == 0 → zero means, no UB.
    AppPerfFleetRow empty;
    empty.device_count = 0;
    empty.cpu_sum = 99.0;
    empty.hist_version = kAppPerfHistVersion;
    empty.cpu_hist = cpu_hist({});
    empty.ws_hist.assign(app_perf_ws_buckets().size() + 1, 0);
    auto t2 = app_perf_fleet_trend({empty});
    REQUIRE(t2.size() == 1);
    CHECK(t2[0].cpu_mean == 0.0);
    CHECK(t2[0].ws_mean == 0);
    CHECK_FALSE(t2[0].cpu_p50.has_value()); // empty population → nullopt
}

TEST_CASE("app_perf_fleet_trend: a wrong-scheme row withholds percentiles", "[dex][app_perf]") {
    AppPerfFleetRow row;
    row.device_count = 2;
    row.cpu_sum = 10.0; // mean still exact
    row.hist_version = kAppPerfHistVersion + 1; // a DIFFERENT scheme
    row.cpu_hist = cpu_hist({0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    row.ws_hist.assign(app_perf_ws_buckets().size() + 1, 0);

    auto trend = app_perf_fleet_trend({row});
    REQUIRE(trend.size() == 1);
    CHECK(trend[0].hist_stale);
    CHECK(trend[0].cpu_mean == 5.0);          // exact stats survive
    CHECK_FALSE(trend[0].cpu_p50.has_value()); // percentiles withheld, not reinterpreted
    CHECK_FALSE(trend[0].cpu_p95.has_value());
    CHECK_FALSE(trend[0].ws_p50.has_value());
}
