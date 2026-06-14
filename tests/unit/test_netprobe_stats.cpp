/**
 * test_netprobe_stats.cpp — pure netprobe helpers (netprobe_stats.hpp, E1).
 *
 * The socket work is the impure shell; everything decision-shaped — the
 * min/avg/max/jitter/loss arithmetic, parameter clamping, the probe-target
 * charset gate, and CSV splitting — is header-pure and pinned here on every
 * host (the cve_rules.hpp testing pattern).
 */

#include "netprobe_stats.hpp"

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::netprobe;
using Catch::Approx;

TEST_CASE("stats: all samples lost", "[netprobe]") {
    auto s = compute_stats(5, {});
    CHECK(s.sent == 5);
    CHECK(s.ok == 0);
    CHECK(s.loss_pct == 100.0);
    CHECK(s.min_ms == 0.0);
    CHECK(s.jitter_ms == 0.0);
}

TEST_CASE("stats: single sample has zero jitter", "[netprobe]") {
    auto s = compute_stats(1, {12.5});
    CHECK(s.ok == 1);
    CHECK(s.min_ms == 12.5);
    CHECK(s.avg_ms == 12.5);
    CHECK(s.max_ms == 12.5);
    CHECK(s.jitter_ms == 0.0);
    CHECK(s.loss_pct == 0.0);
}

TEST_CASE("stats: known population stddev", "[netprobe]") {
    // {10, 20, 30}: mean 20, population variance (100+0+100)/3, stddev ≈ 8.165
    auto s = compute_stats(5, {10.0, 20.0, 30.0});
    CHECK(s.sent == 5);
    CHECK(s.ok == 3);
    CHECK(s.min_ms == 10.0);
    CHECK(s.avg_ms == Approx(20.0));
    CHECK(s.max_ms == 30.0);
    CHECK(s.jitter_ms == Approx(8.1650).margin(0.001));
    CHECK(s.loss_pct == Approx(40.0));
}

TEST_CASE("stats: zero sent is defensive, never divides", "[netprobe]") {
    auto s = compute_stats(0, {});
    CHECK(s.sent == 0);
    CHECK(s.loss_pct == 100.0);
}

TEST_CASE("clamp_param: junk falls back, range clamps", "[netprobe]") {
    CHECK(clamp_param("", 5, 1, 10) == 5);
    CHECK(clamp_param("notanumber", 5, 1, 10) == 5);
    CHECK(clamp_param("99999999999999999999", 5, 1, 10) == 5); // out_of_range
    CHECK(clamp_param("7", 5, 1, 10) == 7);
    CHECK(clamp_param("0", 5, 1, 10) == 1);
    CHECK(clamp_param("400", 5, 1, 10) == 10);
    CHECK(clamp_param("-3", 5, 1, 10) == 1);
}

TEST_CASE("valid_probe_target: hostnames and v4 literals pass", "[netprobe]") {
    CHECK(valid_probe_target("gateway.corp.example.com"));
    CHECK(valid_probe_target("10.0.0.1"));
    CHECK(valid_probe_target("host-with-dash"));
    CHECK(valid_probe_target("a"));
    CHECK(valid_probe_target("under_score.host"));
}

TEST_CASE("valid_probe_target: junk is rejected", "[netprobe]") {
    CHECK(!valid_probe_target(""));
    CHECK(!valid_probe_target("host with space"));
    CHECK(!valid_probe_target("host;rm -rf"));
    CHECK(!valid_probe_target("-leading-dash"));
    CHECK(!valid_probe_target("trailing-dash-"));
    CHECK(!valid_probe_target(".leading.dot"));
    CHECK(!valid_probe_target("fe80::1")); // IPv6 literal — tracked follow-up, rejected today
    CHECK(!valid_probe_target(std::string(254, 'a')));
    CHECK(valid_probe_target(std::string(253, 'a'))); // boundary
}

TEST_CASE("sanitize_for_output: strips pipe/newline injection from invalid targets", "[netprobe]") {
    // The pipe-injection vector (gov sec/plugin-dev/qe): an invalid target is
    // echoed into the pipe-delimited output row; '|' and CR/LF would forge
    // fields / rows / log lines. sanitize keeps only the probe charset.
    CHECK(sanitize_for_output("a|injected|field") == "ainjectedfield");
    CHECK(sanitize_for_output("a\nrtt|fake|0|0|0|0|0|0|0|ok") == "arttfake0000000ok");
    CHECK(sanitize_for_output("host\r\nX") == "hostX");
    // Legitimate charset survives unchanged.
    CHECK(sanitize_for_output("gateway.corp-1.example.com") == "gateway.corp-1.example.com");
    // Nothing survivable → a fixed placeholder, never an empty field.
    CHECK(sanitize_for_output("|||") == "<invalid>");
    CHECK(sanitize_for_output("") == "<invalid>");
    // Bounded length.
    CHECK(sanitize_for_output(std::string(200, 'a')).size() == 64);
}

TEST_CASE("split_targets: trims, drops empties, caps fan-out", "[netprobe]") {
    auto t = split_targets(" a.example , b.example ,, c.example ", 4);
    REQUIRE(t.size() == 3);
    CHECK(t[0] == "a.example");
    CHECK(t[1] == "b.example");
    CHECK(t[2] == "c.example");

    auto capped = split_targets("a,b,c,d,e,f", 4);
    CHECK(capped.size() == 4); // silent fan-out bound

    CHECK(split_targets("", 4).empty());
    CHECK(split_targets(" , , ", 4).empty());
}
