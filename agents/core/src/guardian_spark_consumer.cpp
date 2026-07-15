#include "guardian_spark_consumer.hpp"

#include <optional>

namespace yuzu::agent {

namespace {

/// The Guardian rule spark-type tokens (the server-side Guaranteed-State DSL)
/// mapped to the spark vocabulary. These three are the event-driven Guardian
/// types today, matching the dispatch in start_guard_for_rule_locked()
/// (guardian_engine.cpp). Kept as a local pure map so the classifier carries no
/// proto dependency. A token outside this set is not a platform miss - it is an
/// authored spark type the agent does not implement, i.e. an error.
[[nodiscard]] std::optional<SparkType> spark_type_from_token(std::string_view token) noexcept {
    if (token == "file-change") return SparkType::File;
    if (token == "service-status-change") return SparkType::Service;
    if (token == "registry-change") return SparkType::Registry;
    return std::nullopt;
}

} // namespace

RulePlacement GuardianSparkConsumer::classify(std::string_view spark_type_token,
                                              const std::set<SparkType>& supported) noexcept {
    const std::optional<SparkType> type = spark_type_from_token(spark_type_token);
    if (!type) return RulePlacement::Unrecognized;
    return supported.contains(*type) ? RulePlacement::Arm : RulePlacement::Unsupported;
}

std::size_t GuardianSparkConsumer::on_event(const SparkEvent& ev) {
    const std::vector<std::string> rules = index_.rules_for(ev.key);
    if (on_rule_hit_) {
        for (const std::string& rule_id : rules) {
            // TODO(rung 2b): the migrated meaning layer runs here - evaluate the
            // rule's assertion against the freshly re-read state, apply the
            // debounce / compliant-edge suppression, and emit a
            // GuaranteedStateEvent through the engine's event sink. At slice 2a
            // the sink is evaluation-free and test-only.
            on_rule_hit_(rule_id, ev);
        }
    }
    return rules.size();
}

} // namespace yuzu::agent
