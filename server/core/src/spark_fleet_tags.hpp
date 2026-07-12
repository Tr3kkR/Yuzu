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
/// When `--spark-disable` is set the agent omits ALL spark tags, so the reporting
/// denominator counts only agents actually running the engine.
///
/// Values are agent-supplied strings: accept only a finite, non-negative,
/// full-token integer parse; empty / garbage / negative / overflow → nullopt,
/// which the caller MUST treat as "did not report", never 0.

#include <charconv>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::detail {

// ── Fixed engine-level keys (at most one of each per reporting agent) ──────────
inline constexpr const char* kSparkTagRunning = "yuzu.spark_running";
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
/// RECOGNISED closed-set tokens, in encounter order, silently dropping any token
/// not in kSparkMechTokens (forged / future-value safe). Empty input -> empty.
inline std::vector<std::string> spark_mechs_from_csv(std::string_view csv) {
    std::vector<std::string> out;
    for (std::size_t start = 0; start <= csv.size();) {
        const std::size_t comma = csv.find(',', start);
        const std::string_view tok = csv.substr(
            start, comma == std::string_view::npos ? std::string_view::npos : comma - start);
        for (const char* known : kSparkMechTokens)
            if (tok == known) {
                out.emplace_back(known);
                break;
            }
        if (comma == std::string_view::npos)
            break;
        start = comma + 1;
    }
    return out;
}

/// Forged-value-safe parse of an agent-supplied spark COUNT (a non-negative
/// integer tag). Full-token parse only; empty / garbage / negative / overflow →
/// nullopt (the caller treats nullopt as "did not report", never 0).
inline std::optional<double> parse_spark_count(std::string_view s) {
    if (s.empty())
        return std::nullopt;
    unsigned long long v = 0;
    const char* begin = s.data();
    const char* end = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(begin, end, v);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    return static_cast<double>(v);
}

} // namespace yuzu::server::detail
