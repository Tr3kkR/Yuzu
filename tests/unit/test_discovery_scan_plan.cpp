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

TEST_CASE("hostname_lookup_degraded: CONSTRAINED/PARTIAL with its own distinct reason",
          "[agent][discovery_scan_plan]") {
    const auto h = hostname_lookup_degraded();
    CHECK(h.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(h.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(std::string_view{h.reason} == "dns:hostname_lookup_degraded");
    for (const auto& other : {timeout_degrade().reason,
                              degrade_for(IcmpAvailability::Denied).report.reason,
                              degrade_for(IcmpAvailability::Unavailable).report.reason,
                              degrade_for_arp(false, true).report.reason,
                              degrade_for_sweep(SweepTally{2, 2, 0}).report.reason}) {
        CHECK(std::string_view{h.reason} != std::string_view{other});
    }
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

// ── degrade_for_sweep (runtime transmit-blocked degrade) ─────────────────────
// /adversarial-review (Codex CDX-1, Kimi F4, confirmed independently) found
// that a session which CONSTRUCTS but cannot transmit produced a confidently
// empty network with an OK status — the agent maps rc==0 plus an undeclared
// status straight to OK, so no later layer caught it either.

TEST_CASE("degrade_for_sweep: a healthy sweep declares nothing",
          "[agent][discovery_scan_plan]") {
    CHECK_FALSE(degrade_for_sweep(SweepTally{/*probed=*/254, /*blocked=*/0, /*replied=*/12})
                    .has_report);
    // Zero replies is a legitimate result when the packets genuinely went out:
    // an empty subnet must not masquerade as a degraded scan.
    CHECK_FALSE(degrade_for_sweep(SweepTally{254, 0, 0}).has_report);
}

TEST_CASE("degrade_for_sweep: a fully blocked sweep reports CONSTRAINED/PARTIAL",
          "[agent][discovery_scan_plan]") {
    const auto d = degrade_for_sweep(SweepTally{254, 254, 0});
    REQUIRE(d.has_report);
    CHECK(d.report.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(d.report.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(std::string_view{d.report.reason} == "icmp:transmit_blocked");
    // Never OK/FULL — that is the false-clean-scan failure mode itself.
    CHECK(d.report.status != YUZU_RESULT_STATUS_OK);
    CHECK(d.report.completeness != YUZU_RESULT_COMPLETENESS_FULL);
    // A reason distinct from the construction-time ones, so an operator can
    // tell "socket refused" from "socket fine, send refused".
    CHECK(std::string_view{d.report.reason} !=
          std::string_view{degrade_for(IcmpAvailability::Denied).report.reason});
    CHECK(std::string_view{d.report.reason} !=
          std::string_view{degrade_for(IcmpAvailability::Unavailable).report.reason});
}

TEST_CASE("degrade_for_sweep: a partially blocked sweep still yields real results",
          "[agent][discovery_scan_plan]") {
    // One blocked probe among many must not condemn the whole scan — the
    // replies that did land are real findings.
    CHECK_FALSE(degrade_for_sweep(SweepTally{254, 1, 30}).has_report);
    CHECK_FALSE(degrade_for_sweep(SweepTally{254, 253, 1}).has_report);
}

TEST_CASE("degrade_for_sweep: a sweep that never probed declares nothing",
          "[agent][discovery_scan_plan]") {
    // Every host already in the ARP table, or the degrade path taken before
    // probing: 0/0 must not divide-by-zero into a false degrade.
    CHECK_FALSE(degrade_for_sweep(SweepTally{0, 0, 0}).has_report);
}

// ── degrade_for_arp (ARP acquisition honesty) ───────────────────────────────
// /adversarial-review Codex CDX-3 / Kimi F6: every leg returned a bare empty
// vector for "no neighbours", "the API failed" and "the parse stopped early"
// alike, so a scan whose ARP half never ran reported a clean result.

TEST_CASE("degrade_for_arp: a healthy complete read declares nothing",
          "[agent][discovery_scan_plan]") {
    CHECK_FALSE(degrade_for_arp(/*ok=*/true, /*complete=*/true).has_report);
}

TEST_CASE("degrade_for_arp: a FAILED read is UNAVAILABLE, not an empty table",
          "[agent][discovery_scan_plan]") {
    const auto d = degrade_for_arp(/*ok=*/false, /*complete=*/true);
    REQUIRE(d.has_report);
    CHECK(d.report.status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(d.report.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(std::string_view{d.report.reason} == "arp:read_failed");
    CHECK(d.report.status != YUZU_RESULT_STATUS_OK);
}

TEST_CASE("degrade_for_arp: a TRUNCATED read is CONSTRAINED and distinctly labelled",
          "[agent][discovery_scan_plan]") {
    const auto d = degrade_for_arp(/*ok=*/true, /*complete=*/false);
    REQUIRE(d.has_report);
    CHECK(d.report.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(d.report.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(std::string_view{d.report.reason} == "arp:table_truncated");
    // Distinct from a failed read: partially decoding a table and not being
    // able to read one at all are different operator problems.
    CHECK(std::string_view{d.report.reason} !=
          std::string_view{degrade_for_arp(false, true).report.reason});
}

TEST_CASE("degrade_for_arp: a failed read outranks truncation", "[agent][discovery_scan_plan]") {
    // Both bad: report the stronger, more specific failure.
    const auto d = degrade_for_arp(/*ok=*/false, /*complete=*/false);
    REQUIRE(d.has_report);
    CHECK(d.report.status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(std::string_view{d.report.reason} == "arp:read_failed");
}

TEST_CASE("degrade_for_arp: ARP reasons never collide with the ICMP ones",
          "[agent][discovery_scan_plan]") {
    // An operator reading the reason tag must be able to tell which half of
    // the scan degraded.
    const std::string_view arp_failed{degrade_for_arp(false, true).report.reason};
    const std::string_view arp_trunc{degrade_for_arp(true, false).report.reason};
    for (const auto& icmp : {degrade_for(IcmpAvailability::Denied).report.reason,
                             degrade_for(IcmpAvailability::Unavailable).report.reason,
                             degrade_for_sweep(SweepTally{2, 2, 0}).report.reason,
                             timeout_degrade().reason}) {
        CHECK(arp_failed != std::string_view{icmp});
        CHECK(arp_trunc != std::string_view{icmp});
    }
}

// ── worst_of (multi-degrade severity merge) ─────────────────────────────────

TEST_CASE("worst_of: no report on either side stays no report",
          "[agent][discovery_scan_plan]") {
    CHECK_FALSE(worst_of(MaybeDegrade{}, MaybeDegrade{}).has_report);
}

TEST_CASE("worst_of: a report on one side alone survives regardless of order",
          "[agent][discovery_scan_plan]") {
    const auto report = degrade_for_arp(/*ok=*/false, /*complete=*/true);
    REQUIRE(worst_of(MaybeDegrade{}, report).has_report);
    CHECK(worst_of(MaybeDegrade{}, report).report.status == YUZU_RESULT_STATUS_UNAVAILABLE);
    REQUIRE(worst_of(report, MaybeDegrade{}).has_report);
    CHECK(worst_of(report, MaybeDegrade{}).report.status == YUZU_RESULT_STATUS_UNAVAILABLE);
}

TEST_CASE("worst_of: UNAVAILABLE outranks CONSTRAINED regardless of arrival order",
          "[agent][discovery_scan_plan]") {
    // This is the exact scenario the governance Gate 4 consistency-auditor
    // finding named: an ARP read failure (UNAVAILABLE) and a scan timeout
    // (CONSTRAINED) firing in the same call. The more severe, more actionable
    // reason must survive regardless of which condition is discovered first.
    const auto arp_failed = degrade_for_arp(/*ok=*/false, /*complete=*/true);
    const auto timeout = MaybeDegrade{true, timeout_degrade()};

    const auto arp_then_timeout = worst_of(worst_of(MaybeDegrade{}, arp_failed), timeout);
    REQUIRE(arp_then_timeout.has_report);
    CHECK(arp_then_timeout.report.status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(std::string_view{arp_then_timeout.report.reason} == "arp:read_failed");

    const auto timeout_then_arp = worst_of(worst_of(MaybeDegrade{}, timeout), arp_failed);
    REQUIRE(timeout_then_arp.has_report);
    CHECK(timeout_then_arp.report.status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(std::string_view{timeout_then_arp.report.reason} == "arp:read_failed");
}

TEST_CASE("worst_of: a tie keeps the earlier (first-accumulated) report",
          "[agent][discovery_scan_plan]") {
    // Two equally-severe CONSTRAINED conditions (sweep-blocked, then timeout)
    // must surface the more upstream cause, not whichever was merged last.
    const auto blocked = degrade_for_sweep(SweepTally{2, 2, 0});
    const auto timeout = MaybeDegrade{true, timeout_degrade()};
    REQUIRE(blocked.has_report);
    CHECK(degrade_severity(blocked.report.status) == degrade_severity(timeout.report.status));

    const auto merged = worst_of(worst_of(MaybeDegrade{}, blocked), timeout);
    REQUIRE(merged.has_report);
    CHECK(std::string_view{merged.report.reason} == "icmp:transmit_blocked");
}

TEST_CASE("degrade_severity: exhaustive ranking, UNAVAILABLE worst, OK/UNDECLARED least",
          "[agent][discovery_scan_plan]") {
    CHECK(degrade_severity(YUZU_RESULT_STATUS_UNAVAILABLE) >
          degrade_severity(YUZU_RESULT_STATUS_CONSTRAINED));
    CHECK(degrade_severity(YUZU_RESULT_STATUS_CONSTRAINED) >
          degrade_severity(YUZU_RESULT_STATUS_OK));
    CHECK(degrade_severity(YUZU_RESULT_STATUS_PERMISSION_DENIED) ==
          degrade_severity(YUZU_RESULT_STATUS_CONSTRAINED));
    CHECK(degrade_severity(YUZU_RESULT_STATUS_OK) ==
          degrade_severity(YUZU_RESULT_STATUS_UNDECLARED));
}
