#pragma once

/// @file guardian_health_fleet_tags.hpp
/// Reader side of the Guardian M1 health-stream fleet telemetry (#2298 gate 3, item
/// 6d). Single source of truth for the three `yuzu.guardian_*` heartbeat tag keys this
/// rollup consumes, the `yuzu_fleet_guardian_*` gauge names they roll up into, their
/// HELP text, and the forged-value-safe parse of the agent-supplied values.
///
/// The writer is agents/core/src/guardian_health_heartbeat.hpp
/// (`emit_guardian_health_heartbeat_tags`, `GuardianHealthStats`). Both sides are
/// bound by tests/unit/server/test_guardian_health_fleet_tags.cpp, which emits through
/// the agent's REAL emitter and asserts every key produced is one a table here
/// recognises. That test is the drift guard: a rename on either side without the
/// other is a red test, not a silently-dead gauge.
///
/// The keys are duplicated here rather than `#include`d from the agent header ON
/// PURPOSE - same rationale as the guardian-journal sibling this file mirrors: server
/// production code including an agent private header would add an upward server ->
/// agent dependency edge that the build graph does not have and must not gain (the
/// constraint is recorded verbatim in tests/meson.build). Only the TEST target carries
/// the agent include path, which is exactly where the bind belongs. tests/meson.build's
/// hoist comment names THIS file as a third family that must move together with the
/// spark and journal pins when that hoist lands - do not let a future two-family sweep
/// leave this one behind.
///
/// SHAPE: flat and unlabelled, 3 counters, no age/MAX family (unlike the journal
/// sibling - these three are all plain sparse cumulative counters, none of them a
/// staleness clock). Name rule, asserted by the pin test: `gauge` == "yuzu_fleet_" +
/// `tag` with its "yuzu." heartbeat-namespace prefix stripped.
///
/// WHAT ABSENCE MEANS, MECHANICALLY (same posture as the journal family - stated once
/// there, not re-derived here beyond the mechanics): the writer is SPARSE, a counter
/// that is 0 ships no tag. `AgentHealthStore::recompute_metrics` clears all 3 gauge
/// families at the top of every sweep and re-publishes only those at least one
/// retained agent reported this cycle. An absent family means: no retained agent's
/// latest heartbeat carried a value for it that PASSED the forged-value parse.

#include <charconv>
#include <cstddef>
#include <iterator> // std::size
#include <optional>
#include <string_view>

namespace yuzu::server::detail {

/// Max accepted value of any health tag. Above it the value is treated as "did not
/// report", NOT clamped-and-counted - same rejecting-not-clamping rationale as
/// kMaxPlausibleGuardianJournalCount (guardian_journal_fleet_tags.hpp): these are a
/// fleet SUM accumulated into a double, so a single agent reporting near-UINT64_MAX
/// would make every honest agent's contribution a no-op in IEEE-754.
inline constexpr unsigned long long kMaxPlausibleGuardianHealthCount = 1'000'000'000ULL;

/// One health telemetry signal: the agent's heartbeat tag key, the fleet gauge it sums
/// into, and the gauge's Prometheus HELP text. Same row shape as
/// guardian_journal_fleet_tags.hpp's GuardianJournalMetric.
struct GuardianHealthMetric {
    const char* tag;
    const char* gauge;
    const char* help;
};

/// The full published set. Order matches GuardianHealthStats / the emit order in
/// agents/core/src/guardian_health_heartbeat.hpp for reviewability; nothing depends on
/// it. All 3 are exported as `gauge` - a per-sweep recomputed fleet sum, cleared and
/// rebuilt, never monotonic.
///
/// ALERTING: THESE ARE MONITOR-ONLY, same posture and same reasons as the guardian
/// journal family - no churn-robust new-increment alert exists over an unlabelled
/// fleet sum of per-agent cumulative counters. See the `yuzu-guardian-journal`
/// preamble in docs/prometheus/yuzu-alerts.yml for the full analysis; not restated
/// here.
///
/// ADR-1005 exception ledger, 2026-07-14 class-level entry: a `/metrics`-only fleet
/// gauge family is observability, not capability, so it carries no REST/MCP twin
/// obligation.
inline constexpr GuardianHealthMetric kGuardianHealthMetrics[] = {
    {"yuzu.guardian_unhealthy_suppressed", "yuzu_fleet_guardian_unhealthy_suppressed",
     "Fleet sum of convergence re-evals of a still-errored Guardian rule whose repeat "
     "guard.unhealthy was NOT re-emitted (M1 edge-suppression flood guard). MONITOR-ONLY: "
     "no sound alert form exists over an unlabelled fleet sum of per-agent cumulative "
     "counters - increase() fakes increments on agent churn and bare > 0 never clears at "
     "fleet scale. Graph it; do not page on it"},
    {"yuzu.guardian_unhealthy_refreshed", "yuzu_fleet_guardian_unhealthy_refreshed",
     "Fleet sum of guard.unhealthy re-emissions for a rule still stuck errored, sent at "
     "errored_refresh_ms cadence (M1 item (a)) so a lost/coalesced edge cannot leave the "
     "server's errored view stale forever. Sibling to unhealthy_suppressed - together "
     "they partition every committed repeat-errored eval into \"put on the wire\" vs "
     "\"not this tick\". MONITOR-ONLY, same posture as the rest of this family"},
    {"yuzu.guardian_priority_demoted", "yuzu_fleet_guardian_priority_demoted",
     "Fleet sum of rule_ids demoted off the 5s convergence priority lane to their normal "
     "type-lane cadence after K consecutive Unknown sweeps or T elapsed (M1 item (b), the "
     "read-flood guard for a rule stuck pending-initial). MONITOR-ONLY, same posture as "
     "the rest of this family"},
};

/// Derived with std::size, never a literal - see the sibling table's comment in
/// guardian_journal_fleet_tags.hpp for why a hardcoded count is a governance finding
/// waiting to happen.
inline constexpr std::size_t kNGuardianHealthMetrics = std::size(kGuardianHealthMetrics);

// Meta-signals: about the ROLLUP, not part of the 3-row table. Same rationale as the
// guardian-journal pair - published on EVERY sweep including at 0, because they are
// server-owned counts that always have a true value, so a 0 is a measurement, not a
// fabrication.
//
// READ 0 CAREFULLY, same caveat as the journal reporting gauge: because the writer is
// SPARSE (a 0 counter emits no tag), `reporting` counts agents with at least one
// NON-ZERO health counter, not agents whose Guardian health pipeline is working. A live
// fleet with nothing currently errored/refreshed/demoted reads 0 legitimately.

/// Agents whose latest heartbeat carried at least one parseable
/// yuzu.guardian_unhealthy_*/guardian_priority_demoted tag.
inline constexpr const char* kGuardianHealthReportingGauge = "yuzu_fleet_guardian_health_reporting";
inline constexpr const char* kGuardianHealthReportingHelp =
    "Agents whose latest heartbeat carried at least one parseable "
    "yuzu.guardian_unhealthy_suppressed/refreshed or yuzu.guardian_priority_demoted tag "
    "- the coverage denominator for the 3-counter family. Published every sweep "
    "INCLUDING 0, unlike the 3 counters. READ 0 CAREFULLY: because the writer is SPARSE "
    "(a 0 counter emits no tag), this counts agents with at least one NON-ZERO counter, "
    "not agents whose Guardian health pipeline is working - a live fleet with nothing "
    "currently errored/refreshed/demoted reads 0 legitimately";

/// Health tags that were PRESENT on a heartbeat but failed the forged-value parse.
inline constexpr const char* kGuardianHealthTagRejectedGauge =
    "yuzu_fleet_guardian_health_tag_rejected";
inline constexpr const char* kGuardianHealthTagRejectedHelp =
    "Guardian health tags PRESENT on a heartbeat this sweep but rejected by the "
    "forged-value parse (non-numeric, negative, over 10 digits, or above the "
    "plausibility ceiling). Published every sweep INCLUDING 0. Without it a rejected "
    "value is a SILENT drop: if the rejected agent were the only reporter, its family "
    "goes absent and absent reads as clean. > 0 means some agent is shipping malformed "
    "Guardian health telemetry - investigate that agent, and re-check the ceiling "
    "before raising it";

/// Max digits accepted before the value is rejected unread. Checked FIRST in the parse
/// so an implausible token is refused in O(1) without being scanned - runs under
/// AgentHealthStore::mu_, the same lock heartbeat ingest and every dashboard/REST fleet
/// read take, 3 times per agent per ~15s sweep.
inline constexpr std::size_t kMaxHealthTokenDigits = 10;

namespace detail_pow10_health {
inline constexpr unsigned long long pow10(std::size_t n) {
    unsigned long long v = 1;
    for (std::size_t i = 0; i < n; ++i)
        v *= 10ULL;
    return v;
}
} // namespace detail_pow10_health

// Bind the digit gate to the plausibility ceiling in BOTH directions - same rationale
// as the journal family's identical assert.
static_assert(kMaxPlausibleGuardianHealthCount <
                  detail_pow10_health::pow10(kMaxHealthTokenDigits),
              "kMaxPlausibleGuardianHealthCount no longer fits in kMaxHealthTokenDigits "
              "digits - the length gate in parse_guardian_health_count would reject "
              "legitimate values before the ceiling ever applies. Adjust both together.");

/// Forged-value-safe parse of an agent-supplied Guardian health tag value. Full-token,
/// non-negative integer parse only; empty / garbage / signed / overflow / implausible
/// -> nullopt, which the caller MUST treat as "did not report", never as 0.
inline std::optional<double> parse_guardian_health_count(std::string_view s) {
    if (s.empty() || s.size() > kMaxHealthTokenDigits)
        return std::nullopt;
    unsigned long long v = 0;
    const char* begin = s.data();
    const char* end = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(begin, end, v);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    if (v > kMaxPlausibleGuardianHealthCount)
        return std::nullopt; // implausible -> "did not report", never poison the sum
    return static_cast<double>(v);
}

} // namespace yuzu::server::detail
