/**
 * test_spark_fleet_tags.cpp — SparkEngine fleet-telemetry heartbeat contract
 * (ADR-0021 Stage-2 rung 1).
 *
 *  - Tag-key PIN: the server constants in spark_fleet_tags.hpp are pinned to the
 *    exact literal strings the agent emits (agents/core/src/agent.cpp, the
 *    yuzu.spark_* heartbeat block). A drift is silent zero-reporting.
 *  - MECHANISM-TOKEN BIND: the `mechanism` label tokens are cross-checked against
 *    spark_type_token() — the agent's canonical token source — so agent and server
 *    cannot disagree on file/registry/service. This is a compile-time bind the
 *    net-tag pin lacks (there the agent literal is only comment-coupled).
 *  - parse_spark_count forged-value posture: full-token non-negative integer only;
 *    empty / garbage / negative / fractional / overflow -> nullopt (never 0).
 *  - spark_type_metric_tag composes "yuzu.spark_<type>_<metric>".
 */
#include "spark_fleet_tags.hpp"

#include "spark_heartbeat.hpp"  // agent emitter — bind its ACTUAL emitted keys to the reader
#include <yuzu/agent/spark.hpp> // spark_type_token — the agent's canonical tokens

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace detail = yuzu::server::detail;
using yuzu::agent::SparkType;
using yuzu::agent::spark_type_token;

// TAG-KEY PIN (fixed keys): these server constants MUST equal the literals the
// agent emits in agents/core/src/agent.cpp. The agent composes the same strings
// inline (it cannot include this header) — change both together.
static_assert(std::string_view(detail::kSparkTagRunning) == "yuzu.spark_running");
static_assert(std::string_view(detail::kSparkTagMechs) == "yuzu.spark_mechs");
static_assert(std::string_view(detail::kSparkTagArmedFaulted) == "yuzu.spark_armed_faulted");
static_assert(std::string_view(detail::kSparkTagWatchFaults) == "yuzu.spark_watch_faults");
static_assert(std::string_view(detail::kSparkTagQueuedDropped) == "yuzu.spark_queued_dropped");
static_assert(std::string_view(detail::kSparkTagConsumerErrors) == "yuzu.spark_consumer_errors");
static_assert(std::string_view(detail::kSparkTagPrefix) == "yuzu.spark_");

// MECHANISM-TOKEN BIND: the fleet `mechanism` label values MUST equal the agent's
// spark_type_token() output — the agent buckets per type with exactly these tokens.
static_assert(std::string_view(detail::kSparkMechFile) ==
              std::string_view(spark_type_token(SparkType::File)));
static_assert(std::string_view(detail::kSparkMechRegistry) ==
              std::string_view(spark_type_token(SparkType::Registry)));
static_assert(std::string_view(detail::kSparkMechService) ==
              std::string_view(spark_type_token(SparkType::Service)));

// Metric suffixes — the SparkMechanismStats health counters surfaced per type.
static_assert(std::string_view(detail::kSparkMetricWatchRejected) == "watch_rejected");
static_assert(std::string_view(detail::kSparkMetricQuarantined) == "quarantined");
static_assert(std::string_view(detail::kSparkMetricSlowOp) == "slow_op");

TEST_CASE("spark_type_metric_tag composes yuzu.spark_<type>_<metric>", "[spark][fleet]") {
    using detail::spark_type_metric_tag;
    CHECK(spark_type_metric_tag("file", "watch_rejected") == "yuzu.spark_file_watch_rejected");
    CHECK(spark_type_metric_tag("registry", "quarantined") == "yuzu.spark_registry_quarantined");
    CHECK(spark_type_metric_tag("service", "slow_op") == "yuzu.spark_service_slow_op");
    // Composed from the token + metric arrays must round-trip identically.
    CHECK(spark_type_metric_tag(detail::kSparkMechFile, detail::kSparkMetricSlowOp) ==
          "yuzu.spark_file_slow_op");
}

TEST_CASE("spark_mechs_from_csv keeps recognised tokens and drops the rest", "[spark][fleet]") {
    using detail::spark_mechs_from_csv;
    CHECK(spark_mechs_from_csv("file,registry,service") ==
          std::vector<std::string>{"file", "registry", "service"});
    CHECK(spark_mechs_from_csv("service") == std::vector<std::string>{"service"});
    CHECK(spark_mechs_from_csv("").empty());                        // no mechanisms (e.g. macOS)
    CHECK(spark_mechs_from_csv("bogus").empty());                   // unknown token dropped
    CHECK(spark_mechs_from_csv("file,bogus,service") ==            // forged token in the middle
          std::vector<std::string>{"file", "service"});
    CHECK(spark_mechs_from_csv(",file,").empty() == false);         // stray commas tolerated
    CHECK(spark_mechs_from_csv(",file,") == std::vector<std::string>{"file"});
    // De-dup: a forged/buggy repeated CSV must not double-count in the capability
    // gauge (gov sec-L1 / UP-3). An honest agent never repeats.
    CHECK(spark_mechs_from_csv("file,file,file") == std::vector<std::string>{"file"});
    CHECK(spark_mechs_from_csv("service,file,service") ==
          std::vector<std::string>{"service", "file"});
}

// FULL WRITER↔READER BIND: emit through the agent's real emit_spark_heartbeat_tags
// and assert every key it produces is one the server reader recognises. This closes
// the gap that the static_asserts above leave open — they pin server-const == literal,
// but the agent composes its own literals; a rename on the agent side that isn't
// mirrored here would ship silent zero-reporting. (gov ca-S1 / qe-S2)
TEST_CASE("agent emit keys bind exactly to the server tag constants", "[spark][fleet]") {
    using yuzu::agent::emit_spark_heartbeat_tags;
    using yuzu::agent::SparkEngineStats;
    using yuzu::agent::SparkMechanismStats;

    // The set of keys the server READER recognises: the six fixed keys + every
    // composed per-{mechanism,metric} key.
    std::set<std::string> reader_keys = {
        detail::kSparkTagRunning,        detail::kSparkTagDisabled,
        detail::kSparkTagMechs,          detail::kSparkTagArmedFaulted,
        detail::kSparkTagWatchFaults,    detail::kSparkTagQueuedDropped,
        detail::kSparkTagConsumerErrors};
    for (const char* mech : detail::kSparkMechTokens)
        for (const char* metric : detail::kSparkMetricTokens)
            reader_keys.insert(detail::spark_type_metric_tag(mech, metric));

    // Emit with EVERY counter non-zero for all three mechanisms, so every key the
    // agent can produce is exercised.
    SparkEngineStats ss;
    ss.armed_faulted = 1;
    ss.watch_faults_total = 2;
    ss.queued_dropped_total = 3;
    ss.consumer_errors_total = 4;
    std::map<SparkType, SparkMechanismStats> by_type;
    for (SparkType t : {SparkType::File, SparkType::Registry, SparkType::Service}) {
        SparkMechanismStats ms;
        ms.watch_rejected_total = 5;
        ms.quarantined_total = 6;
        ms.slow_op_total = 7;
        by_type[t] = ms;
    }
    std::map<std::string, std::string> tags;
    emit_spark_heartbeat_tags(tags, /*running=*/true, ss, by_type);

    // Every emitted key must be recognised by the reader — else silent zero-reporting.
    for (const auto& [key, val] : tags) {
        INFO("emitted key not recognised by the server reader: " << key);
        CHECK(reader_keys.count(key) == 1);
    }
    // And the always-present + all non-zero keys are actually emitted (no over-suppression).
    CHECK(tags.count(detail::kSparkTagRunning) == 1);
    CHECK(tags.count(detail::kSparkTagMechs) == 1);
    CHECK(tags.at(detail::kSparkTagMechs) == "file,service,registry"); // SparkType enum order
    CHECK(tags.count(detail::kSparkTagArmedFaulted) == 1);
    CHECK(tags.count(detail::kSparkTagConsumerErrors) == 1);
    CHECK(tags.count(detail::spark_type_metric_tag("registry", "quarantined")) == 1);
}

TEST_CASE("parse_spark_count enforces the forged-value posture", "[spark][fleet]") {
    using detail::parse_spark_count;
    // Valid full-token non-negative integers.
    CHECK(parse_spark_count("0") == 0.0);
    CHECK(parse_spark_count("42") == 42.0);
    // UINT64_MAX is now REJECTED, not accepted. This assertion previously demanded the
    // opposite — it encoded the pre-hardening contract "anything up to uint64 max is a
    // valid count". Governance Gate-4 UP-7 showed that contract is the bug: these gauges
    // are a fleet SUM in a double, and ~1.8e19 does not merely dominate the sum, it
    // ANNIHILATES it (1.8e19 + 1 == 1.8e19 in IEEE-754), so one compromised endpoint
    // permanently destroys the fleet signal for every honest agent. See the implausible-
    // magnitude test below for the full rationale.
    CHECK_FALSE(parse_spark_count("18446744073709551615").has_value());

    // Absent / garbage / signed / fractional / overflow -> nullopt (never 0).
    CHECK_FALSE(parse_spark_count("").has_value());
    CHECK_FALSE(parse_spark_count("-1").has_value());
    CHECK_FALSE(parse_spark_count("12x").has_value());  // trailing garbage
    CHECK_FALSE(parse_spark_count("x12").has_value());  // leading garbage
    CHECK_FALSE(parse_spark_count("3.5").has_value());  // not an integer
    CHECK_FALSE(parse_spark_count(" 5").has_value());   // leading space is not a full token
    CHECK_FALSE(parse_spark_count("18446744073709551616").has_value()); // overflow
}

// ── Hostile input ─────────────────────────────────────────────────────────────
// Every spark tag value is fully agent-controlled. A single compromised or buggy
// enrolled endpoint must not be able to stall the fleet or poison the gauges.

TEST_CASE("spark_mechs_from_csv: an oversized CSV is rejected, not scanned", "[spark][fleet]") {
    // Governance Gate-2 sec-LOW-1, quantified by Gate-3 performance and extended by
    // Gate-4 UP-15. The value is re-scanned on EVERY ~15s recompute_metrics sweep,
    // under AgentHealthStore::mu_ — the same lock heartbeat ingest and every dashboard
    // /REST fleet read take. Unbounded, a multi-MB value (up to the 4MB gRPC frame) is
    // memcpy'd and scanned forever: ~10k such agents saturate the sweep budget and
    // stall fleet reads. Honest max is 21 bytes ("file,registry,service").
    CHECK(detail::kMaxSparkMechsCsvBytes >= std::string("file,registry,service").size());

    const std::string huge(4 * 1024 * 1024, 'a'); // 4 MB of garbage
    CHECK(detail::spark_mechs_from_csv(huge).empty());

    // Even a CSV of VALID tokens is rejected once it exceeds the cap — an honest agent
    // cannot produce one, so over-cap means "forged", and a partial parse would be a
    // half-trusted result.
    std::string repeated;
    while (repeated.size() <= detail::kMaxSparkMechsCsvBytes)
        repeated += "service,";
    CHECK(detail::spark_mechs_from_csv(repeated).empty());

    // At the cap it still parses normally.
    CHECK(detail::spark_mechs_from_csv("file,registry,service") ==
          std::vector<std::string>{"file", "registry", "service"});
}

TEST_CASE("parse_spark_count: an implausible magnitude is rejected, never summed",
          "[spark][fleet]") {
    // Governance Gate-4 UP-7. These gauges are a fleet SUM accumulated into a double.
    // A single agent reporting near-UINT64_MAX (~1.8e19) does not merely dominate the
    // sum — it ANNIHILATES it: 1.8e19 + 1 == 1.8e19 in IEEE-754 double, so every honest
    // agent's contribution becomes a no-op and the fleet signal is destroyed for
    // everyone. Rejecting (rather than clamping) keeps the value out of the sum
    // entirely, and the caller reads nullopt as "did not report", never as 0.
    CHECK(detail::parse_spark_count("18446744073709551615") == std::nullopt); // UINT64_MAX
    CHECK(detail::parse_spark_count(std::to_string(detail::kMaxPlausibleSparkCount + 1)) ==
          std::nullopt);

    // The cap itself, and ordinary values, still parse.
    CHECK(detail::parse_spark_count(std::to_string(detail::kMaxPlausibleSparkCount)).has_value());
    CHECK(detail::parse_spark_count("0") == 0.0);
    CHECK(detail::parse_spark_count("7") == 7.0);

    // A poisoned value must not survive as a partial/clamped number.
    const auto poisoned = detail::parse_spark_count("99999999999999999999");
    CHECK_FALSE(poisoned.has_value());
}

TEST_CASE("the not-running postures bind to reader constants too", "[spark][fleet]") {
    // FAILED and DISABLED are the postures that make a fleet-wide spark boot failure
    // OBSERVABLE (Gate-4 consistency + UP-10). Their keys must be in the reader's
    // vocabulary, or the server silently ignores exactly the signal that matters.
    std::map<std::string, std::string> failed;
    yuzu::agent::emit_spark_absent_tags(failed, /*disabled=*/false);
    CHECK(failed.at(detail::kSparkTagRunning) == "0");
    CHECK(failed.count(detail::kSparkTagDisabled) == 0);

    std::map<std::string, std::string> disabled;
    yuzu::agent::emit_spark_absent_tags(disabled, /*disabled=*/true);
    CHECK(disabled.at(detail::kSparkTagRunning) == "0");
    CHECK(disabled.at(detail::kSparkTagDisabled) == "1");
}

TEST_CASE("parse_spark_running is STRICT — only the exact tokens mean anything",
          "[spark][fleet]") {
    // Governance Gate-4 UP-6 / consistency C-2. The rollup used to treat ANY non-empty
    // value that was not "1" as not-running, which — with no `spark_disabled` key — dropped
    // it into yuzu_fleet_spark_failed{os}, the ONE gauge documented "alert on it". So a
    // single buggy or forked agent build emitting "true" could page on-call.
    //
    // It is also a forward-compat trap: if a later rung adds a third posture value, an OLD
    // server must NOT read it as FAILED and alarm the fleet mid-rolling-upgrade. Unknown
    // means "did not report" — contribute to nothing.
    using detail::parse_spark_running;
    using detail::SparkRunState;

    CHECK(parse_spark_running("1") == SparkRunState::Running);
    CHECK(parse_spark_running("0") == SparkRunState::NotRunning);

    // Everything else is NotReported — never Running, and never NotRunning (which would
    // bucket as FAILED).
    for (const char* garbage : {"", " ", "01", " 1", "1 ", "2", "true", "TRUE", "yes", "x",
                                "-1", "1.0", "00"}) {
        INFO("value: '" << garbage << "'");
        CHECK(parse_spark_running(garbage) == SparkRunState::NotReported);
    }
}
