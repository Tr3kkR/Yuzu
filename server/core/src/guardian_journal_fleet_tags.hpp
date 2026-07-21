#pragma once

/// @file guardian_journal_fleet_tags.hpp
/// Reader side of the Guardian durable lifecycle-audit journal's fleet telemetry
/// (#2298 gate 3). Single source of truth for the `yuzu.guardian_journal_*` heartbeat
/// tag keys, the `yuzu_fleet_guardian_journal_*` gauge names they roll up into, their
/// HELP text, and the forged-value-safe parse of the agent-supplied values.
///
/// The writer is agents/core/src/guardian_journal_heartbeat.hpp
/// (`emit_guardian_journal_heartbeat_tags`). The two sides are bound by
/// tests/unit/server/test_guardian_journal_fleet_tags.cpp, which emits through the
/// agent's REAL emitter and asserts every key it produces is one this table
/// recognises. That test is the drift guard: a rename on either side without the
/// other is a red test, not a silently-dead gauge.
///
/// The keys are duplicated here rather than `#include`d from the agent header ON
/// PURPOSE. Server production code including an agent private header would add an
/// upward server -> agent dependency edge that the build graph does not have and must
/// not gain (the constraint is recorded verbatim in tests/meson.build, governance
/// Gate-3 architect, on the sibling spark pin). Only the TEST target carries the
/// agent include path, which is exactly where the bind belongs.
///
/// ── SHAPE: FLAT AND UNLABELLED ───────────────────────────────────────────────────
/// One gauge per counter, NO labels - deliberately not the `{stat,os}` distribution
/// shape `yuzu_fleet_net_*` / `yuzu_fleet_perf_*` use (design item 9,
/// "unlabeled/low-cardinality"). These are integrity and loss signals, not
/// distributions: the fleet question is "did ANY endpoint lose a lifecycle record",
/// which a sum answers and a percentile obscures. 22 families, 22 series, no
/// agent-controlled label anywhere - so no cardinality exposure at all (contrast the
/// `os`-labelled families, which need an allowlist).
///
/// ── ABSENT, NEVER A FABRICATED ZERO ──────────────────────────────────────────────
/// The writer is SPARSE: a 0 counter ships no tag. So a healthy, quiescent, or inert
/// (`prefer_spark=false`) fleet emits NO journal tags, and every family here is
/// correctly ABSENT rather than a flatline 0 - a flatline 0 would read as "checked,
/// nothing lost" on a fleet where the journal is not even running
/// (docs/observability-conventions.md, the fleet-rollup absent-not-zero rule).
/// `AgentHealthStore::recompute_metrics` therefore `clear_gauge_family()`s all 22 at
/// the top of every sweep and re-emits only those some agent reported this cycle.
/// That leaves absence overloaded, which is why the two META-SIGNALS below are NOT in
/// the table and are published UNCONDITIONALLY, including at 0: without them, "the
/// journal is quiet", "no agent has been upgraded yet", "every agent aged out", "the
/// sweep thread stalled" and "the heartbeat path broke" all render identically as 22
/// absent families - maximally reassuring exactly when nothing is being observed
/// (governance Gate-4 UP-9). `..._reporting` is the coverage denominator, and
/// `..._reporting == 0 while yuzu_fleet_agents_healthy > 0` is the blackout check -
/// but ONLY once Guardian is actually deployed fleet-wide, because the sparse writer
/// means 0 also reads as "nothing journalled yet" (see its HELP). `..._tag_rejected`
/// carries no such condition. An
/// earlier revision of this header argued no denominator was needed because it would
/// itself be absent on a healthy fleet; that reasoning only held while the journal was
/// inert, and it is wrong post-cutover.
///
/// ── NOT HERE YET ─────────────────────────────────────────────────────────────────
/// `gauge_underflow` (GuardianLifecycleJournal::gauge_underflow()) is deliberately
/// absent: it is not in GuardianJournalStats or the heartbeat emit yet, and wiring it
/// there is cutover-gated on `prefer_spark` (commit 1ffa4299). When it lands, adding
/// it here is ONE table row - the clear, accumulate, publish and describe loops are
/// all driven off this table.

#include <charconv>
#include <cstddef>
#include <iterator> // std::size
#include <optional>
#include <string_view>

namespace yuzu::server::detail {

/// Max accepted value of any journal tag. Above it the value is treated as "did not
/// report", NOT clamped-and-counted.
///
/// Every honest value is far below this. The two size gauges are bounded by the
/// journal's own hard ceilings (64 MiB of bytes, 2000 batches - `hard_max_bytes_` /
/// `hard_max_batches_`); the rest count staging rejections, batch writes, prunes and
/// replay pages on ONE endpoint over its uptime.
///
/// Rejecting rather than clamping matters more than it looks: these gauges are a
/// fleet SUM accumulated into a `double`, so a single agent reporting near-UINT64_MAX
/// (~1.8e19) does not merely dominate the sum, it makes every honest agent's
/// contribution a NO-OP - 1.8e19 + 1 == 1.8e19 in IEEE-754. One compromised or buggy
/// endpoint could otherwise permanently destroy the fleet integrity signal for every
/// operator. At 1e9 x 10k agents the sum is ~1e13, still exact in a double (< 2^53).
inline constexpr unsigned long long kMaxPlausibleGuardianJournalCount = 1'000'000'000ULL;

/// One journal telemetry signal: the agent's heartbeat tag key, the fleet gauge it
/// sums into, and the gauge's Prometheus HELP text.
///
/// Name rule, asserted by the pin test: `gauge` == "yuzu_fleet_" + `tag` with its
/// "yuzu." heartbeat-namespace prefix stripped. Mechanical in both directions, so an
/// operator reading an alert can derive the wire key and vice versa. Keeping the three
/// strings adjacent is what makes adding a signal a one-row change that cannot forget
/// the clear, the publish, or the HELP.
struct GuardianJournalMetric {
    const char* tag;
    const char* gauge;
    const char* help;
};

/// The full published set. Order matches GuardianJournalStats / the emit order in
/// agents/core/src/guardian_journal_heartbeat.hpp for reviewability; nothing depends
/// on it.
///
/// TYPE-HONESTY AND ALERTING, READ BEFORE WRITING A RULE. All 22 are exported as
/// `gauge` because that is what they are server-side - a per-sweep recomputed fleet
/// sum, cleared and rebuilt, never monotonic: it drops when an agent ages out or
/// restarts, and a family nobody reports goes absent.
///
/// NO SOUND ALERTING FORM EXISTS OVER THIS SHAPE YET. Three were evaluated; all three
/// fail, each for a different reason (governance Gate-4 unhappy-path + Gate-6 sre):
///   - increase()/rate(): a fleet sum over a CHURNING population is not a valid
///     counter. An agent ageing out or restarting reads as a counter reset and
///     manufactures a phantom increment; and a series that first APPEARS at a
///     non-zero value contributes no increase at all, missing the one-off loss these
///     counters exist to surface. (Same analysis the spark preamble records in
///     docs/prometheus/yuzu-alerts.yml.)
///   - delta(): needs two samples inside the window, so an absent -> non-zero series
///     has no earlier 0 to diff against. Identical first-loss blind spot, different
///     cause.
///   - bare `> 0`: sound PER AGENT (a should-stay-0 monotonic that self-clears when
///     that agent restarts) but NOT over the unlabelled fleet SUM. The set "some
///     agent, ever, tripped this since its last restart" only grows as fleet-days
///     accumulate and only shrinks when that SPECIFIC agent restarts, so at 10k
///     agents with weeks-long uptimes P(sum > 0) -> 1: the rule would fire within
///     hours of cutover and never clear, and the operator would silence the group.
///
/// So the alert group in docs/prometheus/yuzu-alerts.yml stays COMMENTED OUT - and not
/// only because the journal is inert until the prefer_spark cutover. The interim form
/// closest to correct is a rising edge, `(X > 0) unless (X offset 15m > 0)`, which
/// notifies once per absent->present transition instead of continuously; it still
/// cannot tell "a second agent also broke" from "same agent, still broken", because
/// there is no per-agent axis to separate on. That needs a per-agent delta plus a
/// server-owned monotonic counter (#2083 is the spark-scoped tracker; the journal side
/// belongs on #2298's cutover-gate list, and is not yet filed there). Until then these
/// are MONITOR-ONLY: graph them,
/// review them, do not page on them.
///
/// None of the three live-depth gauges is alertable either. `_pending` drains on a
/// healthy AGENT, but the published series is the fleet SUM, which at scale is non-zero
/// essentially always - so it fails for the same reason as the loss counters, not a
/// different one. `_bytes` and `_batch_count` sit non-zero on any working journal
/// between retention passes. All three are capacity/backlog watch signals, never alert
/// conditions.
///
/// ADR-1005 exception ledger, 2026-07-14 class-level entry: a `/metrics`-only fleet
/// gauge family is observability, not capability, so it carries no REST/MCP twin
/// obligation. Cited here so a future rollup does not relitigate it.
inline constexpr GuardianJournalMetric kGuardianJournalMetrics[] = {
    // ── Staging loss channels (agent runtime, pre-persist) ───────────────────────
    {"yuzu.guardian_journal_stage_dropped", "yuzu_fleet_guardian_journal_stage_dropped",
     "Fleet sum of lifecycle records dropped at staging - the pending reserve overflowed "
     "under sustained write failure. A LOSS channel: these records never reached the "
     "journal, so the audit trail has a hole. MONITOR-ONLY: no sound alert form exists "
     "over an unlabelled fleet sum of per-agent cumulative counters - increase() fakes "
     "increments on agent churn and misses a first report, and bare > 0 never clears at "
     "fleet scale. Graph it; do not page on it"},
    {"yuzu.guardian_journal_stage_failures", "yuzu_fleet_guardian_journal_stage_failures",
     "Fleet sum of disarm records that could not be built post-teardown. A LOSS channel: "
     "the lifecycle end of a rule is unrecorded. MONITOR-ONLY - see the alerting note on "
     "this family; neither increase() nor bare > 0 is sound over a fleet sum"},
    {"yuzu.guardian_journal_field_rejected", "yuzu_fleet_guardian_journal_field_rejected",
     "Fleet sum of records kept out of the journal by a field that failed validation "
     "(embedded NUL, oversized, or non-UTF-8). A LOSS channel, and a malformed-input "
     "signal - a sustained climb means something upstream is producing garbage"},
    {"yuzu.guardian_journal_clock_rejected", "yuzu_fleet_guardian_journal_clock_rejected",
     "Fleet sum of records kept out of the journal by a skewed clock (timestamp <= 0). A "
     "LOSS channel; also the fleet's clock-health canary, since a journal timestamp that "
     "cannot be trusted is not admissible evidence"},
    {"yuzu.guardian_journal_pending", "yuzu_fleet_guardian_journal_pending",
     "Fleet sum of records staged but not yet persisted. A LIVE DEPTH gauge per agent - "
     "it drains as the backlog clears - but what is PUBLISHED is the fleet SUM, which at "
     "10k agents is non-zero essentially always, so `> 0` fires permanently on a healthy "
     "fleet and is NOT a valid alert. MONITOR-ONLY like the rest of this family. "
     "Sustained depth is the leading indicator of the stage_dropped loss that follows "
     "when the reserve overflows"},
    // ── Persist ──────────────────────────────────────────────────────────────────
    {"yuzu.guardian_journal_batches_written", "yuzu_fleet_guardian_journal_batches_written",
     "Fleet sum of journal batches successfully persisted, in BATCHES of up to 256 "
     "records. A cumulative "
     "process-lifetime count, so its presence means some agent's journal HAS WRITTEN since "
     "that agent last restarted - not that it is writing now. It is a WEAK liveness "
     "discriminator and fails in BOTH directions: a rolling reboot resets it to 0 so a "
     "healthy journal reads absent, and a journal running with every write failing also "
     "reads absent. Use ..._reporting for coverage instead"},
    {"yuzu.guardian_journal_write_failures", "yuzu_fleet_guardian_journal_write_failures",
     "Fleet sum of failed journal batch writes. Records stay staged and retry, so this is "
     "not itself loss - but sustained failure fills the pending reserve and becomes "
     "stage_dropped, so it is the earliest warning in this family. MONITOR-ONLY - see "
     "the alerting note; neither increase() nor bare > 0 is sound over a fleet sum"},
    {"yuzu.guardian_journal_key_collisions", "yuzu_fleet_guardian_journal_key_collisions",
     "Fleet sum of journal batch key collisions. Should stay 0 in correct operation; any "
     "value is an accounting or id-generation bug surfacing, so investigate rather than "
     "threshold it"},
    // ── Retention / quarantine ───────────────────────────────────────────────────
    {"yuzu.guardian_journal_quarantined", "yuzu_fleet_guardian_journal_quarantined",
     "Fleet sum of journal batches moved aside as unreadable/corrupt. Degrade-don't-"
     "destroy: the batch is preserved for forensics but its records are NOT replayed, so "
     "> 0 means the server is missing lifecycle evidence that still exists on the "
     "endpoint. NOTE the unit is BATCHES, each holding up to 256 records"},
    {"yuzu.guardian_journal_quarantine_failures",
     "yuzu_fleet_guardian_journal_quarantine_failures",
     "Fleet sum of quarantine attempts that themselves failed. Strictly worse than "
     "quarantined: the corrupt batch could not even be set aside, so it may be re-hit "
     "every maintenance tick"},
    {"yuzu.guardian_journal_quarantine_capacity_evicted",
     "yuzu_fleet_guardian_journal_quarantine_capacity_evicted",
     "Fleet sum of quarantined batches shed because the quarantine area hit its cap "
     "(UP-7). Terminal loss - forensic evidence that had been preserved is now gone. NOTE "
     "the unit is BATCHES, each holding up to 256 records"},
    {"yuzu.guardian_journal_pruned", "yuzu_fleet_guardian_journal_pruned",
     "Fleet sum of journal batches deleted by retention, in BATCHES of up to 256 records "
     "(routine disposal evidence). Expected non-zero on a working fleet; read it as "
     "activity context for the failure counters beside it, not as an alert"},
    {"yuzu.guardian_journal_prune_failures", "yuzu_fleet_guardian_journal_prune_failures",
     "Fleet sum of retention prune failures. Retention not running means the journal "
     "grows toward its byte/count cap, where new writes start being refused - see "
     "write_capacity_rejected"},
    {"yuzu.guardian_journal_write_capacity_rejected",
     "yuzu_fleet_guardian_journal_write_capacity_rejected",
     "Fleet sum of new batches REFUSED because the journal is at its byte/count cap "
     "(UP-1). A LOSS channel and the terminal state of a prune/retention failure: the "
     "endpoint is producing lifecycle records it cannot store. MONITOR-ONLY - see the "
     "alerting note; neither increase() nor bare > 0 is sound over a fleet sum. NOTE the "
     "unit is BATCHES, each holding up to 256 records"},
    {"yuzu.guardian_journal_bytes", "yuzu_fleet_guardian_journal_bytes",
     "Fleet sum of live on-disk journal size in bytes. A LIVE gauge, not cumulative. "
     "Capacity signal: per-endpoint it is bounded by the journal's own cap, so a fleet "
     "value climbing toward (agents x cap) predicts write_capacity_rejected"},
    {"yuzu.guardian_journal_batch_count", "yuzu_fleet_guardian_journal_batch_count",
     "Fleet sum of live journal batch count. A LIVE gauge, not cumulative. The count-cap "
     "twin of _bytes - either ceiling alone can start refusing writes"},
    // ── Replay (agent -> server delivery of journalled records) ───────────────────
    {"yuzu.guardian_journal_pages", "yuzu_fleet_guardian_journal_pages",
     "Fleet sum of replay paging passes (page_into_window). Activity, not health - it is "
     "the denominator that tells you replay is running at all"},
    {"yuzu.guardian_journal_records_paged", "yuzu_fleet_guardian_journal_records_paged",
     "Fleet sum of journalled records newly enqueued into the replay window. Activity "
     "signal for how much backlog is being re-delivered"},
    {"yuzu.guardian_journal_sent_labels", "yuzu_fleet_guardian_journal_sent_labels",
     "Fleet sum of sent-labels written, in BATCHES of up to 256 records (best-effort "
     "delivery evidence). NOT a "
     "valid denominator for the eviction counters despite the matching unit: labels are "
     "counted in the CURRENT agent process, while evictions cover batches written up to "
     "the 7-day retention window earlier across a churning fleet, so after a restart the "
     "eviction numerator can exceed it. Read it as activity, never as a rate base"},
    {"yuzu.guardian_journal_evicted_sent_unacked",
     "yuzu_fleet_guardian_journal_evicted_sent_unacked",
     "Fleet sum of batches aged out of the journal WITH a sent-label but no ack. "
     "MONITOR, do not page: their records were sent and are very likely stored "
     "server-side; the ack simply did not come back. Compare against its no-evidence "
     "sibling. NOTE the unit is BATCHES, each holding up to 256 records"},
    {"yuzu.guardian_journal_evicted_no_send_evidence",
     "yuzu_fleet_guardian_journal_evicted_no_send_evidence",
     "Fleet sum of batches aged out of the journal with NO sent-label - no evidence their "
     "records were ever transmitted. The INTEGRITY GAP counter (CC7.3-relevant evidence): "
     "> 0 suggests lifecycle audit records were lost between endpoint and server. Treat a "
     "rise as a TICKET TO INVESTIGATE, not an incident-register entry - classification is "
     "BEST-EFFORT (a crash between the send and the sent-label write counts a sent batch "
     "as no-evidence), so a mass reboot or OTA manufactures a large benign step. Do not "
     "escalate until agent-side corroboration or magnitude analysis rules out that "
     "crash-timing artifact class. MONITOR-ONLY - see the alerting note; neither "
     "increase() nor bare > 0 is sound over a fleet sum. NOTE the unit is BATCHES, each "
     "holding up to 256 records, so this UNDERSTATES the record count"},
    {"yuzu.guardian_journal_maint_exceptions", "yuzu_fleet_guardian_journal_maint_exceptions",
     "Fleet sum of exceptions swallowed by the journal maintenance tick (page/flush). "
     "Swallowed on purpose so maintenance cannot kill the agent, which is exactly why "
     "they must be visible here - a climbing value means maintenance is failing silently "
     "and the counters beside it are understating reality"},
};

/// Derived with std::size, never a literal and never sizeof-arithmetic: the sibling
/// spark table hardcoded its count, a new token was added, and it compiled clean while
/// being silently never read (prior governance finding). std::size also hard-rejects a
/// future refactor to a pointer, which the sizeof form would mis-size to 1.
inline constexpr std::size_t kNGuardianJournalMetrics = std::size(kGuardianJournalMetrics);

// ── Meta-signals: about the ROLLUP, not part of the 22-row table ──────────────
// Deliberately outside kGuardianJournalMetrics. That table is pinned 1:1 to
// GuardianJournalStats by a static_assert on the struct's size, so anything added to
// it that is not an agent counter breaks the pin. These two are computed server-side.
//
// Both are published on EVERY sweep including at 0 - the opposite of the 22, and
// deliberately so. The 22 are agent-population rollups where absent means "nobody
// reported"; these are server-owned counts that always have a true value, so a 0 is a
// measurement ("nothing is reporting") rather than a fabrication. Same split
// docs/observability-conventions.md draws between pre-seeded server-owned series and
// absent-not-zero agent rollups, and the same posture as yuzu_fleet_perf_reporting.

/// Agents whose latest heartbeat carried at least one parseable journal tag. The
/// coverage denominator the 22 lack: without it, 5 reporting agents and 10,000 produce
/// identical output and "absent = clean" is asserted at unknown coverage.
inline constexpr const char* kGuardianJournalReportingGauge =
    "yuzu_fleet_guardian_journal_reporting";
inline constexpr const char* kGuardianJournalReportingHelp =
    "Agents whose latest heartbeat carried at least one parseable "
    "yuzu.guardian_journal_* tag - the coverage denominator for the whole family. "
    "Published every sweep INCLUDING 0, unlike the 22 counters. READ 0 CAREFULLY: "
    "because the writer is SPARSE (a 0 counter emits no tag), this counts agents with "
    "at least one NON-ZERO counter, not agents whose journal pipeline is working. So 0 "
    "means EITHER the telemetry path is dark (pre-cutover, all aged out, reporting "
    "broke) OR nothing has been journalled anywhere since restart - a live journal on "
    "a fleet with no deployed Guardian rules reads 0 legitimately. It narrows the "
    "overloaded absence of the 22 counters; it does not resolve it";

/// Journal tags that were PRESENT on a heartbeat but failed the forged-value parse.
inline constexpr const char* kGuardianJournalTagRejectedGauge =
    "yuzu_fleet_guardian_journal_tag_rejected";
inline constexpr const char* kGuardianJournalTagRejectedHelp =
    "Journal tags PRESENT on a heartbeat this sweep but rejected by the forged-value "
    "parse (non-numeric, negative, over 10 digits, or above the plausibility ceiling). "
    "Published every sweep INCLUDING 0. Without it a rejected value is a SILENT drop: "
    "if the rejected agent were the only reporter, its family goes absent and absent "
    "reads as clean. > 0 means some agent is shipping malformed journal telemetry - "
    "investigate that agent, and re-check the ceiling before raising it";

/// Forged-value-safe parse of an agent-supplied journal tag value. Full-token,
/// non-negative integer parse only; empty / garbage / signed / overflow / implausible
/// -> nullopt, which the caller MUST treat as "did not report", never as 0.
///
/// The length cap is checked BEFORE from_chars so an implausible value is rejected in
/// O(1) without being scanned. kMaxPlausibleGuardianJournalCount is 10 digits, so any
/// longer token is implausible by construction. This matters because the parse runs
/// under AgentHealthStore::mu_ - the same lock heartbeat ingest and every
/// dashboard/REST fleet read take - 22 times per agent per ~15 s sweep. Without it, an
/// agent parking a multi-megabyte all-digit value in each tag gets it O(n)-scanned
/// inside that critical section forever.
///
/// The value BYTES still sit in the tag map until the store-level ingest bound lands
/// (AgentHealthStore::upsert deep-copies the whole agent-controlled tag map with no
/// key-count or value-length cap; tracked as the heartbeat-tag ingest-bound
/// follow-up). This cap keeps the scan out of the sweep, and is not a claim that the
/// ingest DoS is closed.
// The length gate below is 10 because kMaxPlausibleGuardianJournalCount is 10 digits.
// Raising the ceiling without widening the gate would silently truncate legitimate
// values at the gate instead of at the documented ceiling, so bind the two.
static_assert(kMaxPlausibleGuardianJournalCount < 10'000'000'000ULL,
              "the length gate in parse_guardian_journal_count is 10 digits - widen it "
              "if the plausibility ceiling grows past 10 digits");

inline std::optional<double> parse_guardian_journal_count(std::string_view s) {
    if (s.empty() || s.size() > 10)
        return std::nullopt;
    unsigned long long v = 0;
    const char* begin = s.data();
    const char* end = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(begin, end, v);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    if (v > kMaxPlausibleGuardianJournalCount)
        return std::nullopt; // implausible -> "did not report", never poison the sum
    return static_cast<double>(v);
}

} // namespace yuzu::server::detail
