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
/// There is no separate `_reporting` denominator: `..._batches_written` is the
/// inert-vs-live discriminator (any agent whose journal has persisted anything since
/// its last restart reports it), and a denominator that is itself absent on a healthy
/// fleet would carry no information.
///
/// ── NOT HERE YET ─────────────────────────────────────────────────────────────────
/// `gauge_underflow` (GuardianLifecycleJournal::gauge_underflow()) is deliberately
/// absent: it is not in GuardianJournalStats or the heartbeat emit yet, and wiring it
/// there is cutover-gated on `prefer_spark` (commit 1ffa4299). When it lands, adding
/// it here is ONE table row - the clear, accumulate, publish and describe loops are
/// all driven off this table.

#include <charconv>
#include <cstddef>
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
/// TYPE-HONESTY, READ THIS BEFORE ALERTING. All 22 are exported as `gauge` because
/// that is what they are server-side - a per-sweep recomputed fleet sum, cleared and
/// rebuilt, never monotonic: it drops when an agent ages out or restarts, and a
/// family nobody reports goes absent. Do NOT alert with increase()/rate(): a fleet
/// sum over a churning agent population is not a valid counter. Prometheus reads any
/// decrease (an agent ageing out, a restart resetting its counters) as a counter
/// reset and manufactures a phantom increase, and a series that first APPEARS at a
/// non-zero value - the first loss on a quiet fleet - contributes no increase at
/// all, so increase() misses exactly the one-off event these counters exist to
/// surface. This is the same analysis the spark preamble records in
/// docs/prometheus/yuzu-alerts.yml.
///
/// The sound interim form for the should-stay-0 loss/fault counters is bare `> 0`
/// at severity warning. Sparse emission means a series is present only while some
/// agent holds a non-zero counter, so `> 0` cannot be tripped by population churn.
/// It LATCHES, both ways: it keeps firing until every contributing agent restarts,
/// and while firing it does not re-notify on FURTHER losses (the value grows, the
/// alert state does not - watch the value too). Deliberate for an integrity signal:
/// an occurrence is an incident to investigate, not a rate to tune. The reviewed
/// alert group is in docs/prometheus/yuzu-alerts.yml, commented out until the
/// prefer_spark cutover makes the journal live - until then a firing alert could
/// only come from a forged heartbeat. Of the live-depth gauges only `_pending` is
/// alertable (`> 0 for: 15m`; it drains on a healthy agent); `_bytes` and
/// `_batch_count` sit non-zero on any working journal between retention passes -
/// capacity watch signals, not alert conditions. Increment-grade alerting (notify
/// per new loss) would need per-agent deltas and a server-owned monotonic counter;
/// that is #2083 and is not built yet.
inline constexpr GuardianJournalMetric kGuardianJournalMetrics[] = {
    // ── Staging loss channels (agent runtime, pre-persist) ───────────────────────
    {"yuzu.guardian_journal_stage_dropped", "yuzu_fleet_guardian_journal_stage_dropped",
     "Fleet sum of lifecycle records dropped at staging - the pending reserve overflowed "
     "under sustained write failure. A LOSS channel: these records never reached the "
     "journal, so the audit trail has a hole. Alert on > 0 at warning; the value latches "
     "until the contributing agents restart and does not re-notify on further losses. Do "
     "not use increase() - agent churn fakes increments and a first report registers none"},
    {"yuzu.guardian_journal_stage_failures", "yuzu_fleet_guardian_journal_stage_failures",
     "Fleet sum of disarm records that could not be built post-teardown. A LOSS channel: "
     "the lifecycle end of a rule is unrecorded. Alert on > 0 at warning; latches until "
     "the contributing agents restart. Do not use increase() - agent churn fakes "
     "increments and a first report registers none"},
    {"yuzu.guardian_journal_field_rejected", "yuzu_fleet_guardian_journal_field_rejected",
     "Fleet sum of records kept out of the journal by a field that failed validation "
     "(embedded NUL, oversized, or non-UTF-8). A LOSS channel, and a malformed-input "
     "signal - a sustained climb means something upstream is producing garbage"},
    {"yuzu.guardian_journal_clock_rejected", "yuzu_fleet_guardian_journal_clock_rejected",
     "Fleet sum of records kept out of the journal by a skewed clock (timestamp <= 0). A "
     "LOSS channel; also the fleet's clock-health canary, since a journal timestamp that "
     "cannot be trusted is not admissible evidence"},
    {"yuzu.guardian_journal_pending", "yuzu_fleet_guardian_journal_pending",
     "Fleet sum of records staged but not yet persisted. A LIVE DEPTH gauge, not "
     "cumulative - it falls when the backlog drains, so a bare `> 0 for: 15m` is a valid "
     "alert. Sustained depth is the leading indicator of the stage_dropped loss that "
     "follows when the reserve overflows"},
    // ── Persist ──────────────────────────────────────────────────────────────────
    {"yuzu.guardian_journal_batches_written", "yuzu_fleet_guardian_journal_batches_written",
     "Fleet sum of journal batches successfully persisted. A cumulative process-lifetime "
     "count, so its presence means some agent's journal HAS WRITTEN since that agent last "
     "restarted - not that it is writing now. Still the inert-vs-live discriminator for "
     "this family: absent across the fleet means the journal is inert everywhere "
     "(expected while prefer_spark is off), NOT that it is healthy"},
    {"yuzu.guardian_journal_write_failures", "yuzu_fleet_guardian_journal_write_failures",
     "Fleet sum of failed journal batch writes. Records stay staged and retry, so this is "
     "not itself loss - but sustained failure fills the pending reserve and becomes "
     "stage_dropped. Alert on > 0 at warning to catch it before the loss counter moves; "
     "latches until the contributing agents restart. Do not use increase() - agent churn "
     "fakes increments"},
    {"yuzu.guardian_journal_key_collisions", "yuzu_fleet_guardian_journal_key_collisions",
     "Fleet sum of journal batch key collisions. Should stay 0 in correct operation; any "
     "value is an accounting or id-generation bug surfacing, so investigate rather than "
     "threshold it"},
    // ── Retention / quarantine ───────────────────────────────────────────────────
    {"yuzu.guardian_journal_quarantined", "yuzu_fleet_guardian_journal_quarantined",
     "Fleet sum of journal batches moved aside as unreadable/corrupt. Degrade-don't-"
     "destroy: the batch is preserved for forensics but its records are NOT replayed, so "
     "> 0 means the server is missing lifecycle evidence that still exists on the endpoint"},
    {"yuzu.guardian_journal_quarantine_failures",
     "yuzu_fleet_guardian_journal_quarantine_failures",
     "Fleet sum of quarantine attempts that themselves failed. Strictly worse than "
     "quarantined: the corrupt batch could not even be set aside, so it may be re-hit "
     "every maintenance tick"},
    {"yuzu.guardian_journal_quarantine_capacity_evicted",
     "yuzu_fleet_guardian_journal_quarantine_capacity_evicted",
     "Fleet sum of quarantined batches shed because the quarantine area hit its cap "
     "(UP-7). Terminal loss - forensic evidence that had been preserved is now gone"},
    {"yuzu.guardian_journal_pruned", "yuzu_fleet_guardian_journal_pruned",
     "Fleet sum of journal batches deleted by retention (routine disposal evidence). "
     "Expected to be non-zero on a working fleet; it is a denominator for the failure "
     "counters beside it, not an alert"},
    {"yuzu.guardian_journal_prune_failures", "yuzu_fleet_guardian_journal_prune_failures",
     "Fleet sum of retention prune failures. Retention not running means the journal "
     "grows toward its byte/count cap, where new writes start being refused - see "
     "write_capacity_rejected"},
    {"yuzu.guardian_journal_write_capacity_rejected",
     "yuzu_fleet_guardian_journal_write_capacity_rejected",
     "Fleet sum of new batches REFUSED because the journal is at its byte/count cap "
     "(UP-1). A LOSS channel and the terminal state of a prune/retention failure: the "
     "endpoint is producing lifecycle records it cannot store. Alert on > 0 at warning; "
     "latches until the contributing agents restart. Do not use increase() - agent churn "
     "fakes increments and a first report registers none"},
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
     "Fleet sum of sent-labels written (best-effort delivery evidence). The denominator "
     "for the two eviction counters: a batch aged out WITH a label was at least sent"},
    {"yuzu.guardian_journal_evicted_sent_unacked",
     "yuzu_fleet_guardian_journal_evicted_sent_unacked",
     "Fleet sum of batches aged out of the journal WITH a sent-label but no ack. "
     "MONITOR, do not page: their records were sent and are very likely stored "
     "server-side; the ack simply did not come back. Compare against its no-evidence "
     "sibling. NOTE the unit is BATCHES, each holding up to 256 records"},
    {"yuzu.guardian_journal_evicted_no_send_evidence",
     "yuzu_fleet_guardian_journal_evicted_no_send_evidence",
     "Fleet sum of batches aged out of the journal with NO sent-label - no evidence their "
     "records were ever transmitted. This is the INTEGRITY GAP counter: > 0 means "
     "lifecycle audit records were silently lost between endpoint and server. Alert on "
     "> 0 at warning and treat any firing as an incident (CC7.3-relevant evidence "
     "signal, not a tuning knob). Classification is BEST-EFFORT: a crash between the send "
     "and the sent-label write counts a sent batch as no-evidence, so corroborate with "
     "agent logs before calling it loss. Latches until the contributing agents restart and "
     "does not re-notify on further losses - watch the value too. Do not use increase() - "
     "it misses a first-and-only loss and fakes increments on agent churn. NOTE the unit "
     "is BATCHES, each holding up to 256 records"},
    {"yuzu.guardian_journal_maint_exceptions", "yuzu_fleet_guardian_journal_maint_exceptions",
     "Fleet sum of exceptions swallowed by the journal maintenance tick (page/flush). "
     "Swallowed on purpose so maintenance cannot kill the agent, which is exactly why "
     "they must be visible here - a climbing value means maintenance is failing silently "
     "and the counters beside it are understating reality"},
};

inline constexpr std::size_t kNGuardianJournalMetrics =
    sizeof(kGuardianJournalMetrics) / sizeof(kGuardianJournalMetrics[0]);

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
