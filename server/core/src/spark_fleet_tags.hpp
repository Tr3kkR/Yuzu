#pragma once

/// @file spark_fleet_tags.hpp
/// Single source of truth for the SparkEngine heartbeat status-tag keys and the
/// forged-value-safe parse of their agent-supplied values. Shared by the
/// Prometheus rollup (AgentHealthStore::recompute_metrics → yuzu_fleet_spark_*)
/// and pinned by tests/unit/server/test_spark_fleet_tags.cpp so the gauge reader
/// and the agent emit site (agents/core/src/agent.cpp, the spark heartbeat block)
/// can never silently disagree about a key.
///
/// THE EDGE SHIPS FACTS, NEVER A VERDICT — counts only, no threshold/classification.
/// The agent (ADR-0021 Stage-2 rung 1) exports these OBSERVE-ONLY: with no
/// consumer armed, every counter reads 0 and only the two always-present keys
/// (`spark_running`, `spark_mechs`) carry signal — the running denominator and the
/// per-agent mechanism capability. The counters become non-zero once rung 2 arms
/// rules against the engine; the plumbing ships now so that cutover reports for
/// free. Emission is SPARSE: a counter tag is omitted when 0 (be-kind-to-network,
/// fleet-scale heartbeat) — an absent counter is 0 at the reader (the server
/// pre-nothing: an absent {os,mechanism} series simply does not contribute).
/// A spark-capable agent reports exactly ONE of four postures, and each is
/// distinguishable on the wire — this is the contract the reader is built on:
///
///   RUNNING   spark_running=1, spark_mechs=<CSV>, sparse counters
///   FAILED    spark_running=0                       (enabled, but boot threw)
///   DISABLED  spark_running=0, spark_disabled=1       (--spark-disable)
///   ABSENT    no yuzu.spark_* key at all (a pre-rung-1 agent, a dead one, or the
///             final beats of a gracefully-stopping one — a clean restart must never
///             be bucketed as FAILED)
///
/// So `--spark-disable` does NOT omit all spark tags — an earlier version of this
/// comment said it did, and that WAS the behaviour, which is exactly why a fleet-wide
/// spark boot FAILURE used to be invisible: it emitted nothing, identical to a
/// deliberate opt-out and to an agent that never had spark. Only RUNNING feeds the
/// reporting denominator; FAILED and DISABLED are counted separately (alert on the
/// former, never the latter).
///
/// Values are agent-supplied strings: accept only a finite, non-negative, full-token
/// integer parse below an implausibility ceiling; empty / garbage / negative / overflow
/// / implausible → nullopt, which the caller MUST treat as "did not report", never 0.

#include <charconv>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::detail {

// ── Hostile-input bounds (every spark tag value is fully agent-controlled) ─────
/// Max accepted length of the `yuzu.spark_mechs` CSV. Honest max is 21 bytes
/// ("file,registry,service"); 64 leaves room for ~2 future tokens. See
/// spark_mechs_from_csv() for why an unbounded value is a fleet-read DoS.
inline constexpr std::size_t kMaxSparkMechsCsvBytes = 64;
/// Max accepted value of any spark COUNT tag. These count per-endpoint watch
/// rejections / quarantines / slow ops — a real agent cannot approach this. Above it,
/// the value is treated as "did not report". See parse_spark_count() for why clamping
/// matters more than it looks (double-precision annihilation of the fleet sum).
inline constexpr unsigned long long kMaxPlausibleSparkCount = 1'000'000'000ULL;

// ── Fixed engine-level keys (at most one of each per reporting agent) ──────────
/// "1" = engine constructed AND running. "0" = NOT running: either it was disabled
/// (kSparkTagDisabled also present) or boot-time instantiation threw (it is not).
/// ABSENT = the agent ships no spark telemetry at all (pre-rung-1, dead, or
/// mid-graceful-shutdown).
/// Those three states must stay distinguishable — see spark_heartbeat.hpp.
inline constexpr const char* kSparkTagRunning = "yuzu.spark_running";
/// Present + "1" ONLY under --spark-disable. Its absence alongside running=="0" is
/// what identifies a boot FAILURE rather than a deliberate opt-out.
inline constexpr const char* kSparkTagDisabled = "yuzu.spark_disabled";
inline constexpr const char* kSparkTagMechs = "yuzu.spark_mechs";
inline constexpr const char* kSparkTagArmedFaulted = "yuzu.spark_armed_faulted";
inline constexpr const char* kSparkTagWatchFaults = "yuzu.spark_watch_faults";
inline constexpr const char* kSparkTagQueuedDropped = "yuzu.spark_queued_dropped";
inline constexpr const char* kSparkTagConsumerErrors = "yuzu.spark_consumer_errors";

// ── Per-mechanism-type key composition ────────────────────────────────────────
// A per-type key is `kSparkTagPrefix + <mechanism-token> + "_" + <metric-suffix>`,
// e.g. "yuzu.spark_file_watch_rejected". The mechanism tokens below MUST equal
// spark_type_token() in agents/core/include/yuzu/agent/spark.hpp — the agent
// composes the identical string from spark_type_token(SparkType) — so a drift here
// (or there) is silent zero-reporting. The pin test asserts the composed literals.
inline constexpr const char* kSparkTagPrefix = "yuzu.spark_";

// Closed set of mechanism tokens the fleet rollup buckets by (the `mechanism`
// gauge label). Windows: file + registry + service; Linux: service; macOS: none.
// INVARIANT: this set must list every SparkType that becomes a REGISTERED mechanism
// (spark_type_token() output). The agent emits per-type keys for every registered
// type; a new registered mechanism whose token is missing here is silently dropped
// server-side (never bucketed) — extend this set in lockstep. (gov ca-N1)
inline constexpr const char* kSparkMechFile = "file";
inline constexpr const char* kSparkMechRegistry = "registry";
inline constexpr const char* kSparkMechService = "service";
inline constexpr const char* kSparkMechTokens[] = {kSparkMechFile, kSparkMechRegistry,
                                                   kSparkMechService};

// Per-type metric suffixes — the SparkMechanismStats health counters surfaced per
// type (the three that back the fleet alerts). `retiring`/`retiring_cap` is a
// Windows-file IOCP teardown-backpressure internal (0 without arming churn) — it is
// summed at engine level in SparkEngineStats but its per-{os,mechanism} fleet
// rollup is deferred to rung 2, when arming makes it non-zero.
inline constexpr const char* kSparkMetricWatchRejected = "watch_rejected";
inline constexpr const char* kSparkMetricQuarantined = "quarantined";
inline constexpr const char* kSparkMetricSlowOp = "slow_op";
inline constexpr const char* kSparkMetricTokens[] = {
    kSparkMetricWatchRejected, kSparkMetricQuarantined, kSparkMetricSlowOp};

/// Compose a per-mechanism-type heartbeat key. MUST match the agent's own
/// composition byte-for-byte (see the header note above).
inline std::string spark_type_metric_tag(std::string_view mech_token, std::string_view metric) {
    std::string key;
    key.reserve(std::string_view(kSparkTagPrefix).size() + mech_token.size() + 1 + metric.size());
    key += kSparkTagPrefix;
    key += mech_token;
    key += '_';
    key += metric;
    return key;
}

/// Parse a `spark_mechs` CSV (the agent's registered mechanism tokens) into the
/// RECOGNISED closed-set tokens, DEDUPED, in encounter order, silently dropping any
/// token not in kSparkMechTokens (forged / future-value safe). Empty input -> empty.
/// De-dup matters because the fleet capability gauge counts one agent once per
/// mechanism: a forged/buggy repeated CSV ("service,service,…") must not inflate it
/// (gov sec-L1 / UP-3). An honest agent never repeats — it composes from a map's
/// unique keys — so the dedup is defence-in-depth, bounded by heartbeat tag size.
inline std::vector<std::string> spark_mechs_from_csv(std::string_view csv) {
    std::vector<std::string> out;
    // LENGTH CAP. The value is fully agent-controlled and re-read on EVERY
    // recompute_metrics sweep (~15s) under AgentHealthStore::mu_ — the lock heartbeat
    // ingest AND every dashboard/REST fleet read also take. Without a cap, an agent that
    // parks a multi-MB value here (bounded only by the 4 MB gRPC frame) is O(n)-scanned
    // forever. The honest maximum is 21 bytes ("file,registry,service"); 64 leaves
    // headroom for ~2 future tokens. Over-cap → "reported nothing", never a partial parse.
    //
    // SCOPE, HONESTLY (governance Gate-2 security): this closes the SCAN, not the whole
    // DoS. Two things sit outside it and are NOT fixed by this cap:
    //   - the caller's tag lookup, which used to COPY the value before this cap could be
    //     tested (fixed separately — recompute_metrics' `get` now returns string_view);
    //   - AgentHealthStore::upsert, which still deep-copies the ENTIRE agent-controlled
    //     tag map on every heartbeat with no key-count or value-length bound. That is a
    //     cross-cutting fix benefiting every tag family (net / DEX / spark alike) and is
    //     tracked as the heartbeat-tag ingest-bound follow-up (drafted at governance) — do not read this cap as "the ingest DoS is closed".
    if (csv.size() > kMaxSparkMechsCsvBytes)
        return out;
    for (std::size_t start = 0; start <= csv.size();) {
        const std::size_t comma = csv.find(',', start);
        const std::string_view tok = csv.substr(
            start, comma == std::string_view::npos ? std::string_view::npos : comma - start);
        for (const char* known : kSparkMechTokens)
            if (tok == known) {
                bool already = false;
                for (const auto& seen : out)
                    if (seen == known) {
                        already = true;
                        break;
                    }
                if (!already)
                    out.emplace_back(known);
                break;
            }
        if (comma == std::string_view::npos)
            break;
        start = comma + 1;
    }
    return out;
}

/// The agent's spark posture, parsed STRICTLY from `yuzu.spark_running`.
enum class SparkRunState {
    NotReported, ///< tag absent, or an unrecognised value — contribute to NOTHING
    Running,     ///< exactly "1"
    NotRunning,  ///< exactly "0" — the caller then splits DISABLED vs FAILED
};

/// Every OTHER agent-supplied spark value goes through a strict validator whose contract is
/// "garbage → did not report, never a value" (see parse_spark_count). `spark_running` was
/// the exception: the rollup bucketed `== "1"` as running and ANY other non-empty string as
/// not-running — so `"true"`, `" 1"`, `"01"`, `"2"` or `"x"` from one buggy or forked agent
/// build all landed in `yuzu_fleet_spark_failed{os}`, the ONE gauge documented "alert on
/// it". A single misbehaving agent could page on-call.
///
/// It is also a FORWARD-COMPAT trap: if a later rung adds a third posture value, an OLD
/// server would read it as FAILED and alarm the fleet during a rolling upgrade.
///
/// Strict now: only the two exact tokens mean anything; everything else is NotReported.
/// (governance Gate-4 UP-6 / consistency C-2.)
inline SparkRunState parse_spark_running(std::string_view s) {
    if (s == "1")
        return SparkRunState::Running;
    if (s == "0")
        return SparkRunState::NotRunning;
    return SparkRunState::NotReported;
}

/// Forged-value-safe parse of an agent-supplied spark COUNT (a non-negative
/// integer tag). Full-token parse only; empty / garbage / negative / overflow →
/// nullopt (the caller treats nullopt as "did not report", never 0).
///
/// IMPLAUSIBILITY CLAMP: a value above kMaxPlausibleSparkCount is REJECTED (nullopt),
/// not clamped-and-counted. These gauges are a fleet SUM accumulated into a `double`,
/// so a single agent reporting near-UINT64_MAX (~1.8e19) does not merely dominate the
/// sum — it makes every honest agent's +1 a NO-OP, because 1.8e19 + 1 == 1.8e19 in
/// IEEE-754 double. One compromised endpoint could permanently destroy the fleet
/// signal for every other agent, and at rung 2 (alerts enabled) page on a single
/// forged tag. No honest agent can reach this: these count watch rejections /
/// quarantines / slow ops on one endpoint. (governance Gate-4 UP-7.)
inline std::optional<double> parse_spark_count(std::string_view s) {
    // LENGTH CAP BEFORE PARSE. kMaxPlausibleSparkCount (1e9) is 10 digits, so any
    // longer token is implausible by construction — reject it in O(1) WITHOUT letting
    // from_chars scan it. Without this, a hostile agent parking a multi-megabyte
    // all-digit value in each of the 13 count tags gets them O(n)-scanned on every
    // 15 s sweep UNDER AgentHealthStore::mu_ — the same unbounded-scan class the
    // 64-byte CSV cap exists for (governance Gate-3 performance S1). The value bytes
    // still sit in the tag map until the store-level ingest bound lands (tracked:
    // heartbeat-tag ingest-bound follow-up); this cap only keeps the scan out of the
    // sweep's critical section.
    if (s.empty() || s.size() > 10)
        return std::nullopt;
    unsigned long long v = 0;
    const char* begin = s.data();
    const char* end = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(begin, end, v);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    if (v > kMaxPlausibleSparkCount)
        return std::nullopt; // implausible → "did not report", never poison the sum
    return static_cast<double>(v);
}

} // namespace yuzu::server::detail
