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
        detail::kSparkTagRunning,      detail::kSparkTagMechs,         detail::kSparkTagArmedFaulted,
        detail::kSparkTagWatchFaults,  detail::kSparkTagQueuedDropped, detail::kSparkTagConsumerErrors};
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
    emit_spark_heartbeat_tags(tags, ss, by_type);

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
    CHECK(parse_spark_count("18446744073709551615") == 18446744073709551615.0); // uint64 max

    // Absent / garbage / signed / fractional / overflow -> nullopt (never 0).
    CHECK_FALSE(parse_spark_count("").has_value());
    CHECK_FALSE(parse_spark_count("-1").has_value());
    CHECK_FALSE(parse_spark_count("12x").has_value());  // trailing garbage
    CHECK_FALSE(parse_spark_count("x12").has_value());  // leading garbage
    CHECK_FALSE(parse_spark_count("3.5").has_value());  // not an integer
    CHECK_FALSE(parse_spark_count(" 5").has_value());   // leading space is not a full token
    CHECK_FALSE(parse_spark_count("18446744073709551616").has_value()); // overflow
}
