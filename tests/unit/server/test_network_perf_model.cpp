/**
 * test_network_perf_model.cpp — /network fleet read model (N1 slice 1).
 *
 *  - network_perf_rules: forged-value posture (reject inf/nan/negative/garbage,
 *    clamp retransmit %, reject absurd-but-finite RTT/throughput); net_degraded
 *    bool parse; the MEASURED perf-pressure co-occurrence threshold.
 *  - fleet_now: absent-not-zero; reporting vs rtt_reporting denominators (RTT
 *    carries its own smaller denominator by design); co-occurrence counts.
 *  - device_list: cross-platform not-reporting complement, co-occurrence band
 *    filter, worst-first metric sort, cohort filter, limit cap.
 *
 * The model COUNTS co-occurrence; it never asserts a cause (no verdict).
 */
#include "network_perf_model.hpp"
#include "network_perf_rules.hpp"
#include "network_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;
namespace rules = yuzu::server::detail;

namespace {

NetPerfDevice dev(const std::string& id, std::optional<double> rtt, std::optional<double> retx,
                  std::optional<double> tput, bool degraded = false,
                  const std::string& platform = "linux", const std::string& cohort = "") {
    NetPerfDevice d;
    d.agent_id = id;
    d.platform = platform;
    d.rtt_ms = rtt;
    d.retrans_pct = retx;
    d.throughput_bps = tput;
    d.net_degraded = degraded;
    d.cohort = cohort;
    return d;
}

/// A degraded device with a known perf/app co-occurrence shape (always reports
/// a metric so it counts as reporting).
NetPerfDevice degraded(const std::string& id, std::optional<double> cpu, bool app) {
    NetPerfDevice d;
    d.agent_id = id;
    d.platform = "linux";
    d.rtt_ms = 300.0;
    d.net_degraded = true;
    d.cpu_pct = cpu;
    d.app_unstable = app;
    return d;
}

} // namespace

// ── network_perf_rules ───────────────────────────────────────────────────────

TEST_CASE("network tag parsing: forged-value posture", "[network][rules]") {
    // Normal values pass.
    CHECK(rules::parse_net_rtt_ms("38.5") == 38.5);
    CHECK(rules::parse_net_retrans_pct("0.4") == 0.4);
    CHECK(rules::parse_net_throughput_bps("3100000") == 3100000.0);
    // Percentage lie clamps to 100 (not an outlier — a lie).
    CHECK(rules::parse_net_retrans_pct("250") == 100.0);
    // Absurd-but-finite rejected above the sanity ceiling.
    CHECK(rules::parse_net_rtt_ms("1e9") == std::nullopt);
    CHECK(rules::parse_net_throughput_bps("1e15") == std::nullopt);
    // Non-finite / negative / garbage / empty → nullopt (never 0).
    CHECK(rules::parse_net_rtt_ms("inf") == std::nullopt);
    CHECK(rules::parse_net_rtt_ms("nan") == std::nullopt);
    CHECK(rules::parse_net_rtt_ms("-5") == std::nullopt);
    CHECK(rules::parse_net_rtt_ms("38xyz") == std::nullopt);
    CHECK(rules::parse_net_rtt_ms("") == std::nullopt);
}

TEST_CASE("net_degraded bool parse", "[network][rules]") {
    CHECK(rules::parse_net_degraded("1") == true);
    CHECK(rules::parse_net_degraded("true") == true);
    CHECK(rules::parse_net_degraded("0") == false);
    CHECK(rules::parse_net_degraded("false") == false);
    CHECK(rules::parse_net_degraded("yes") == std::nullopt); // unknown, not false
}

TEST_CASE("perf-pressure co-occurrence threshold", "[network][rules]") {
    using rules::net_device_under_pressure;
    CHECK(net_device_under_pressure(90.0, std::nullopt, std::nullopt));  // cpu arm
    CHECK(net_device_under_pressure(std::nullopt, 95.0, std::nullopt));  // commit arm
    CHECK(net_device_under_pressure(std::nullopt, std::nullopt, 30.0));  // disk arm
    CHECK_FALSE(net_device_under_pressure(10.0, 40.0, 1.0));
    CHECK_FALSE(net_device_under_pressure(std::nullopt, std::nullopt, std::nullopt)); // absent != strain
}

// ── fleet_now ────────────────────────────────────────────────────────────────

TEST_CASE("fleet_now: absent-not-zero + honest denominators", "[network][model]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(dev("a", 40.0, 0.5, 3.0e6));
    snap.devices.push_back(dev("b", 80.0, 1.0, 5.0e6));
    snap.devices.push_back(dev("c", std::nullopt, 2.0, std::nullopt)); // windows-coarse: retrans only
    snap.devices.push_back(dev("d", std::nullopt, std::nullopt, std::nullopt)); // silent

    const auto f = net_perf_fleet_now(snap);
    CHECK(f.online == 4);
    CHECK(f.reporting == 3);     // a, b, c
    CHECK(f.rtt_reporting == 2); // a, b only — the honest RTT denominator
    REQUIRE(f.rtt.has_value());
    CHECK(f.rtt->n == 2);
    CHECK(f.rtt->max == 80.0);
    REQUIRE(f.retrans.has_value());
    CHECK(f.retrans->n == 3);
}

TEST_CASE("fleet_now: empty population → all stats absent", "[network][model]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(dev("d", std::nullopt, std::nullopt, std::nullopt));
    const auto f = net_perf_fleet_now(snap);
    CHECK(f.online == 1);
    CHECK(f.reporting == 0);
    CHECK_FALSE(f.rtt.has_value());
    CHECK_FALSE(f.retrans.has_value());
    CHECK_FALSE(f.throughput.has_value());
}

TEST_CASE("co-occurrence: counts over degraded devices, overlap allowed", "[network][model]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(degraded("net-only", 10.0, false)); // degraded, no pressure, no app
    snap.devices.push_back(degraded("dev", 95.0, false));      // degraded + pressure
    snap.devices.push_back(degraded("app", 10.0, true));       // degraded + app
    snap.devices.push_back(degraded("both", 95.0, true));      // degraded + pressure + app (overlap)
    snap.devices.push_back(degraded("healthy", 95.0, true));   // ... but flip net_degraded off:
    snap.devices.back().net_degraded = false;                  //   NOT degraded → excluded entirely

    const auto f = net_perf_fleet_now(snap);
    CHECK(f.cooc.degraded == 4);
    CHECK(f.cooc.also_device == 2);  // dev, both
    CHECK(f.cooc.also_app == 2);     // app, both
    CHECK(f.cooc.network_only == 1); // net-only
}

// ── device_list ──────────────────────────────────────────────────────────────

TEST_CASE("device_list: not-reporting complement is cross-platform", "[network][model]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(dev("rep", 40.0, std::nullopt, std::nullopt, false, "windows"));
    snap.devices.push_back(dev("silent-win", std::nullopt, std::nullopt, std::nullopt, false, "windows"));
    snap.devices.push_back(dev("silent-lnx", std::nullopt, std::nullopt, std::nullopt, false, "linux"));
    const auto rows = net_perf_device_list(snap, NetPerfMetric::kRtt, /*not_reporting=*/true,
                                           NetCoocFilter::kNone, std::nullopt, 50);
    REQUIRE(rows.size() == 2); // both silent, regardless of OS (unlike Windows-only perf)
    CHECK(rows[0].agent_id == "silent-lnx"); // sorted by agent_id
    CHECK(rows[1].agent_id == "silent-win");
}

TEST_CASE("device_list: worst-first by metric, percentile ranked", "[network][model]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(dev("low", 40.0, std::nullopt, std::nullopt));
    snap.devices.push_back(dev("high", 600.0, std::nullopt, std::nullopt));
    snap.devices.push_back(dev("mid", 200.0, std::nullopt, std::nullopt));
    const auto rows = net_perf_device_list(snap, NetPerfMetric::kRtt, false, NetCoocFilter::kNone,
                                           std::nullopt, 50);
    REQUIRE(rows.size() == 3);
    CHECK(rows[0].agent_id == "high");
    CHECK(rows[1].agent_id == "mid");
    CHECK(rows[2].agent_id == "low");
    CHECK(rows[0].fleet_pctile >= rows[2].fleet_pctile);
}

TEST_CASE("device_list: co-occurrence band filter flags the facts", "[network][model]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(degraded("net-only", 10.0, false));
    snap.devices.push_back(degraded("dev", 95.0, false));
    snap.devices.push_back(degraded("healthy", 10.0, false));
    snap.devices.back().net_degraded = false;

    const auto dev_rows = net_perf_device_list(snap, NetPerfMetric::kRtt, false,
                                               NetCoocFilter::kAlsoDevice, std::nullopt, 50);
    REQUIRE(dev_rows.size() == 1);
    CHECK(dev_rows[0].agent_id == "dev");
    CHECK(dev_rows[0].under_pressure);

    const auto only = net_perf_device_list(snap, NetPerfMetric::kRtt, false,
                                           NetCoocFilter::kNetworkOnly, std::nullopt, 50);
    REQUIRE(only.size() == 1);
    CHECK(only[0].agent_id == "net-only");
    CHECK_FALSE(only[0].under_pressure);
}

TEST_CASE("device_list: cohort filter + limit cap", "[network][model]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(dev("a1", 40.0, std::nullopt, std::nullopt, false, "linux", "site-a"));
    snap.devices.push_back(dev("a2", 50.0, std::nullopt, std::nullopt, false, "linux", "site-a"));
    snap.devices.push_back(dev("b1", 60.0, std::nullopt, std::nullopt, false, "linux", "site-b"));
    const auto rows = net_perf_device_list(snap, NetPerfMetric::kRtt, false, NetCoocFilter::kNone,
                                           std::optional<std::string>("site-a"), 1);
    REQUIRE(rows.size() == 1);       // limit cap honoured
    CHECK(rows[0].cohort == "site-a");
    CHECK(rows[0].agent_id == "a2"); // worst-first within cohort (50 > 40 ms)
}

TEST_CASE("metric token round-trips", "[network][model]") {
    CHECK(net_perf_metric_from_token("retrans") == NetPerfMetric::kRetrans);
    CHECK(net_perf_metric_from_token("throughput") == NetPerfMetric::kThroughput);
    CHECK(net_perf_metric_from_token("rtt") == NetPerfMetric::kRtt);
    CHECK(net_perf_metric_from_token("garbage") == NetPerfMetric::kRtt); // default
    CHECK(std::string(net_perf_metric_token(NetPerfMetric::kRetrans)) == "retrans");
}

// ── renderers ────────────────────────────────────────────────────────────────

TEST_CASE("overview render: cards, co-occurrence, honesty", "[network][ui]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(dev("lnx-1", 40.0, 0.4, 3.0e6));
    snap.devices.push_back(dev("lnx-2", 600.0, 9.0, 2.0e5));
    snap.devices.push_back(degraded("deg-dev", 95.0, false)); // degraded + device pressure
    snap.devices.push_back(degraded("deg-app", 10.0, true));  // degraded + app instability

    const auto html = render_network_overview_fragment(snap);
    CHECK(html.find("Network quality") != std::string::npos);
    CHECK(html.find("Round-trip time") != std::string::npos);
    CHECK(html.find("co-occurrence") != std::string::npos);
    CHECK(html.find("counting, not blaming") != std::string::npos); // never a verdict
    CHECK(html.find("TCP_INFO") != std::string::npos);              // Linux/Windows honesty note
    CHECK(html.find("cooc=device") != std::string::npos);           // band drills
    CHECK(html.find("cooc=app") != std::string::npos);
}

TEST_CASE("overview render: empty population is honest", "[network][ui]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(dev("silent", std::nullopt, std::nullopt, std::nullopt));
    const auto html = render_network_overview_fragment(snap);
    CHECK(html.find("No network telemetry yet") != std::string::npos);
}

TEST_CASE("devices render: worst-first + co-occurrence flags inline", "[network][ui]") {
    NetPerfSnapshot snap;
    snap.devices.push_back(dev("lnx-low", 40.0, std::nullopt, std::nullopt));
    snap.devices.push_back(dev("lnx-high", 600.0, std::nullopt, std::nullopt));
    snap.devices.push_back(degraded("deg-dev", 95.0, false));

    const auto html = render_network_devices_fragment(snap, NetPerfMetric::kRtt, false,
                                                      NetCoocFilter::kNone, std::nullopt, 50);
    CHECK(html.find("lnx-high") != std::string::npos);
    CHECK(html.find("Worst devices by RTT") != std::string::npos);
    CHECK(html.find("device &#9679;") != std::string::npos); // deg-dev pressure flag inline
    CHECK(html.find("&mdash;") != std::string::npos);        // absent metric cell, never 0
}

// ── routes ───────────────────────────────────────────────────────────────────

TEST_CASE("network routes: perm gating + provider degradation", "[network][routes][rbac]") {
    auto okAuth = [](const httplib::Request&, httplib::Response&) {
        return std::optional<auth::Session>(auth::Session{});
    };
    auto okPerm = [](const httplib::Request&, httplib::Response&, const std::string&,
                     const std::string&) { return true; };
    auto noPerm = [](const httplib::Request&, httplib::Response& res, const std::string&,
                     const std::string&) {
        res.status = 403;
        return false;
    };
    NetworkRoutes::PerfFn perf = [](const std::string&) {
        NetPerfSnapshot snap;
        snap.devices.push_back(degraded("deg-dev", 95.0, false)); // degraded + pressure
        snap.devices.push_back(degraded("deg-app", 10.0, true));  // degraded + app
        return snap;
    };

    SECTION("permitted: overview + devices render through the provider") {
        yuzu::server::test::TestRouteSink sink;
        NetworkRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, perf);
        auto ov = sink.Get("/fragments/network/overview");
        REQUIRE(ov);
        CHECK(ov->status == 200);
        CHECK(ov->body.find("Network quality") != std::string::npos);

        // The device co-occurrence band shows only degraded+pressure devices.
        auto drill = sink.Get("/fragments/network/devices?cooc=device");
        REQUIRE(drill);
        CHECK(drill->status == 200);
        CHECK(drill->body.find("deg-dev") != std::string::npos);
        CHECK(drill->body.find("deg-app") == std::string::npos);
    }

    SECTION("denied without GuaranteedState:Read") {
        yuzu::server::test::TestRouteSink sink;
        NetworkRoutes routes;
        routes.register_routes(sink, okAuth, noPerm, perf);
        auto ov = sink.Get("/fragments/network/overview");
        REQUIRE(ov);
        CHECK(ov->status == 403);
    }

    SECTION("no provider wired → honest unavailable placeholder") {
        yuzu::server::test::TestRouteSink sink;
        NetworkRoutes routes;
        routes.register_routes(sink, okAuth, okPerm);
        auto ov = sink.Get("/fragments/network/overview");
        REQUIRE(ov);
        CHECK(ov->status == 200);
        CHECK(ov->body.find("unavailable") != std::string::npos);
    }

    SECTION("page shell loads the overview fragment") {
        yuzu::server::test::TestRouteSink sink;
        NetworkRoutes routes;
        routes.register_routes(sink, okAuth, okPerm, perf);
        auto page = sink.Get("/network");
        REQUIRE(page);
        CHECK(page->status == 200);
        CHECK(page->body.find("/fragments/network/overview") != std::string::npos);
    }
}
