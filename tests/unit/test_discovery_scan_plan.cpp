/**
 * test_discovery_scan_plan.cpp — the pure scan_subnet decisions
 * (discovery_scan_plan.hpp, Wave-2 PR2.1c WP-C).
 *
 * These are the decisions /code-review found unproven: both external reviewers
 * (Kimi KIMI-1/KIMI-2, Codex CDX-FV-003/CDX-FV-004) independently blocked on
 * the sweep bound and the honest-degrade branch having no discriminating test,
 * because both lived inside a shell needing a live ICMP socket and a real ARP
 * table. Extracted as pure functions, each assertion below fails against a
 * plausible wrong implementation — the mapping is not merely re-stated.
 *
 * Portable: no platform guard, runs on every leg.
 */
#include "discovery_scan_plan.hpp"

#include <catch2/catch_test_macros.hpp>

#include <set>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::discovery;

// ── classify_icmp_session ─────────────────────────────────────────────────

TEST_CASE("classify_icmp_session: a usable socket is Usable regardless of permitted",
          "[agent][discovery_scan_plan]") {
    CHECK(classify_icmp_session(/*ok=*/true, /*permitted=*/true) == IcmpAvailability::Usable);
    // ok() is authoritative: a usable socket is never reported as a denial even
    // if `permitted` were somehow stale. Pins the precedence, not just the
    // happy path.
    CHECK(classify_icmp_session(/*ok=*/true, /*permitted=*/false) == IcmpAvailability::Usable);
}

TEST_CASE("classify_icmp_session: separates a policy denial from a resource failure",
          "[agent][discovery_scan_plan]") {
    // !ok && !permitted == EACCES/EPERM/EPROTONOSUPPORT -> a policy denial.
    CHECK(classify_icmp_session(false, false) == IcmpAvailability::Denied);
    // !ok && permitted == EMFILE/ENOMEM/... -> an ordinary resource failure.
    // An implementation collapsing both into one state fails here, and that
    // collapse is exactly what makes a scan report the wrong cause.
    CHECK(classify_icmp_session(false, true) == IcmpAvailability::Unavailable);
}

// ── degrade_for ───────────────────────────────────────────────────────────

TEST_CASE("degrade_for: a normal sweep declares no degradation",
          "[agent][discovery_scan_plan]") {
    // The discriminating half of the honesty contract's other side: a healthy
    // scan must NOT stamp itself PARTIAL, or every scan looks degraded and the
    // signal is worthless.
    CHECK_FALSE(degrade_for(IcmpAvailability::Usable).has_report);
}

TEST_CASE("degrade_for: a denied socket reports CONSTRAINED/PARTIAL, never success",
          "[agent][discovery_scan_plan]") {
    const auto d = degrade_for(IcmpAvailability::Denied);
    REQUIRE(d.has_report);
    CHECK(d.report.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(d.report.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(std::string_view{d.report.reason} == "icmp:ping_group_range");
    // Never OK/FULL — that is the "silent success on a dead network" failure.
    CHECK(d.report.status != YUZU_RESULT_STATUS_OK);
    CHECK(d.report.completeness != YUZU_RESULT_COMPLETENESS_FULL);
    // The operator-facing line must name the actual gate, not a generic error.
    CHECK(std::string_view{d.report.message}.find("ping_group_range") !=
          std::string_view::npos);
}

TEST_CASE("degrade_for: a resource failure reports UNAVAILABLE, not a permissions story",
          "[agent][discovery_scan_plan]") {
    const auto d = degrade_for(IcmpAvailability::Unavailable);
    REQUIRE(d.has_report);
    CHECK(d.report.status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(d.report.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(std::string_view{d.report.reason} == "icmp:socket_error");
    // Must not blame ping_group_range for an EMFILE — the two reasons are
    // distinct provenance tags and an operator acts on them differently.
    CHECK(std::string_view{d.report.reason} != "icmp:ping_group_range");
    CHECK(std::string_view{d.report.message}.find("ping_group_range") ==
          std::string_view::npos);
}

TEST_CASE("degrade_for: the two failure states never share a reason tag",
          "[agent][discovery_scan_plan]") {
    const auto denied = degrade_for(IcmpAvailability::Denied);
    const auto unavailable = degrade_for(IcmpAvailability::Unavailable);
    REQUIRE(denied.has_report);
    REQUIRE(unavailable.has_report);
    CHECK(std::string_view{denied.report.reason} !=
          std::string_view{unavailable.report.reason});
    CHECK(denied.report.status != unavailable.report.status);
}

TEST_CASE("timeout_degrade: a deadline-truncated sweep is PARTIAL with its own reason",
          "[agent][discovery_scan_plan]") {
    const auto t = timeout_degrade();
    CHECK(t.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(t.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(std::string_view{t.reason} == "scan:timeout");
    // Distinct from both ICMP reasons: a truncated scan is not a denied socket.
    CHECK(std::string_view{t.reason} !=
          std::string_view{degrade_for(IcmpAvailability::Denied).report.reason});
    CHECK(std::string_view{t.reason} !=
          std::string_view{degrade_for(IcmpAvailability::Unavailable).report.reason});
}

// ── probe_budget_ms ───────────────────────────────────────────────────────

TEST_CASE("probe_budget_ms: the per-host budget is capped so a /24 sweep stays finite",
          "[agent][discovery_scan_plan]") {
    // The bound the plan's risk register called MED-HIGH. A caller asking for
    // more than the ceiling is capped: without this, timeout_ms=10000 (the
    // action's documented maximum) would put a 254-host worst case at ~42
    // minutes and blow straight past any overall deadline.
    CHECK(probe_budget_ms(10000) == kMaxProbeBudgetMs);
    CHECK(probe_budget_ms(1000) == kMaxProbeBudgetMs);
    CHECK(probe_budget_ms(kMaxProbeBudgetMs + 1) == kMaxProbeBudgetMs);

    // Worst-case arithmetic stated as an assertion, so a future ceiling bump
    // cannot silently make a /24 sweep unbounded.
    constexpr int kMaxHostsInA24 = 254;
    CHECK(kMaxHostsInA24 * kMaxProbeBudgetMs <= 120'000);
}

TEST_CASE("probe_budget_ms: a narrower request is honoured, an absurd one floored",
          "[agent][discovery_scan_plan]") {
    // Below the ceiling the caller's value passes through — the cap must be a
    // ceiling, not a constant (an implementation returning kMaxProbeBudgetMs
    // unconditionally passes the test above and fails here).
    CHECK(probe_budget_ms(150) == 150);
    CHECK(probe_budget_ms(kMinProbeBudgetMs) == kMinProbeBudgetMs);

    // Floored: a 1ms budget would report every live host as dead.
    CHECK(probe_budget_ms(1) == kMinProbeBudgetMs);
    CHECK(probe_budget_ms(0) == kMinProbeBudgetMs);
    CHECK(probe_budget_ms(-5) == kMinProbeBudgetMs);
}

// ── arp_hosts_in_subnet ───────────────────────────────────────────────────

TEST_CASE("arp_hosts_in_subnet: a degraded scan reports only in-subnet ARP hosts",
          "[agent][discovery_scan_plan]") {
    const std::vector<std::string> subnet_hosts{"192.168.1.1", "192.168.1.2", "192.168.1.3"};
    const std::set<std::string> arp_ips{
        "192.168.1.1",     // in subnet, present -> keep
        "192.168.1.3",     // in subnet, present -> keep
        "10.0.0.5",        // DIFFERENT subnet   -> must not leak
        "192.168.1.255",   // link-layer broadcast, not an enumerated host
        "224.0.0.251",     // mDNS multicast group
        "239.255.255.250", // SSDP multicast group
    };

    const auto out = arp_hosts_in_subnet(subnet_hosts, arp_ips);
    REQUIRE(out.size() == 2);
    CHECK(out[0] == "192.168.1.1");
    CHECK(out[1] == "192.168.1.3");

    // Stated as explicit exclusions: an implementation returning the raw ARP
    // set (the false-finding bug this intersection exists to prevent) fails
    // each of these, not just the size check.
    for (const auto& ip : out) {
        CHECK(ip != "10.0.0.5");
        CHECK(ip != "192.168.1.255");
        CHECK(ip != "224.0.0.251");
        CHECK(ip != "239.255.255.250");
    }
}

TEST_CASE("arp_hosts_in_subnet: an empty ARP table degrades to no hosts, not all hosts",
          "[agent][discovery_scan_plan]") {
    const std::vector<std::string> subnet_hosts{"192.168.1.1", "192.168.1.2"};
    CHECK(arp_hosts_in_subnet(subnet_hosts, {}).empty());
    // And an ARP table that intersects nothing is equally empty — never a
    // fallthrough to "assume everything is alive".
    CHECK(arp_hosts_in_subnet(subnet_hosts, {"10.0.0.1", "172.16.0.1"}).empty());
}

TEST_CASE("arp_hosts_in_subnet: output follows subnet order, not ARP-set order",
          "[agent][discovery_scan_plan]") {
    // The enumerated subnet is ascending; the returned findings must be too,
    // so operator output is stable regardless of neighbour-table ordering.
    const std::vector<std::string> subnet_hosts{"192.168.1.8", "192.168.1.9", "192.168.1.10"};
    const std::set<std::string> arp_ips{"192.168.1.10", "192.168.1.8"};
    const auto out = arp_hosts_in_subnet(subnet_hosts, arp_ips);
    REQUIRE(out.size() == 2);
    CHECK(out[0] == "192.168.1.8");
    CHECK(out[1] == "192.168.1.10");
}
