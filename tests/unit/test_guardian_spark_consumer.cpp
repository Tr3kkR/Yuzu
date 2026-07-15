// test_guardian_spark_consumer.cpp - GuardianSparkConsumer skeleton
// (ADR-0021 rung 2 slice 2a). Two behaviours are testable INERT: the pure
// platform-rejection classifier, and the event -> rule-set resolution (fan-out)
// through the index. No assertion evaluation or enforcement exists yet (2b).

#include "guardian_spark_consumer.hpp"

#include <catch2/catch_test_macros.hpp>

#include <set>
#include <string>
#include <utility>
#include <vector>

using yuzu::agent::GuardianSparkConsumer;
using yuzu::agent::RulePlacement;
using yuzu::agent::SparkEvent;
using yuzu::agent::SparkType;

TEST_CASE("classify: a supported event-driven type arms", "[spark][consumer]") {
    const std::set<SparkType> win_caps{SparkType::File, SparkType::Registry, SparkType::Service};
    REQUIRE(GuardianSparkConsumer::classify("file-change", win_caps) == RulePlacement::Arm);
    REQUIRE(GuardianSparkConsumer::classify("registry-change", win_caps) == RulePlacement::Arm);
    REQUIRE(GuardianSparkConsumer::classify("service-status-change", win_caps) == RulePlacement::Arm);
}

TEST_CASE("classify: a known type with no mechanism here is Unsupported, not errored", "[spark][consumer]") {
    // A Linux host: Service only (systemd), no File/Registry mechanism. A
    // cross-platform Baseline's registry/file rules are a ROUTINE miss here.
    const std::set<SparkType> linux_caps{SparkType::Service};
    REQUIRE(GuardianSparkConsumer::classify("registry-change", linux_caps) == RulePlacement::Unsupported);
    REQUIRE(GuardianSparkConsumer::classify("file-change", linux_caps) == RulePlacement::Unsupported);
    REQUIRE(GuardianSparkConsumer::classify("service-status-change", linux_caps) == RulePlacement::Arm);

    // A macOS host: no event-driven Guardian mechanism at all -> everything is
    // Unsupported, still never errored.
    const std::set<SparkType> mac_caps{};
    REQUIRE(GuardianSparkConsumer::classify("service-status-change", mac_caps) == RulePlacement::Unsupported);
    REQUIRE(GuardianSparkConsumer::classify("file-change", mac_caps) == RulePlacement::Unsupported);
}

TEST_CASE("classify: an unknown spark type token is Unrecognized (errored)", "[spark][consumer]") {
    const std::set<SparkType> win_caps{SparkType::File, SparkType::Registry, SparkType::Service};
    // An authoring fault, distinct from a platform miss, regardless of caps.
    REQUIRE(GuardianSparkConsumer::classify("banana", win_caps) == RulePlacement::Unrecognized);
    REQUIRE(GuardianSparkConsumer::classify("", win_caps) == RulePlacement::Unrecognized);
    REQUIRE(GuardianSparkConsumer::classify("banana", {}) == RulePlacement::Unrecognized);
}

TEST_CASE("on_event: resolves a shared-watcher event to every fanned-out rule", "[spark][consumer]") {
    GuardianSparkConsumer consumer;
    consumer.index().add("service|5:sshd", "rule-a");
    consumer.index().add("service|5:sshd", "rule-b");
    consumer.index().add("file|4:/etc", "rule-c");

    std::vector<std::string> hit;
    consumer.set_rule_hit([&](std::string_view rule_id, const SparkEvent&) {
        hit.emplace_back(rule_id);
    });

    SparkEvent ev;
    ev.key = "service|5:sshd";
    ev.type = SparkType::Service;

    // One event on the shared key fans out to both rules (sorted), and the
    // return count matches. The other key's rule is untouched.
    REQUIRE(consumer.on_event(ev) == 2);
    REQUIRE(hit == std::vector<std::string>{"rule-a", "rule-b"});
}

TEST_CASE("on_event: an unmapped key resolves to zero rules and no sink call", "[spark][consumer]") {
    GuardianSparkConsumer consumer;
    consumer.index().add("file|4:/etc", "rule-c");

    int calls = 0;
    consumer.set_rule_hit([&](std::string_view, const SparkEvent&) { ++calls; });

    SparkEvent ev;
    ev.key = "service|5:ghost"; // nothing armed on this key
    ev.type = SparkType::Service;

    REQUIRE(consumer.on_event(ev) == 0);
    REQUIRE(calls == 0);
}

TEST_CASE("on_event: safe with no sink installed", "[spark][consumer]") {
    GuardianSparkConsumer consumer;
    consumer.index().add("file|4:/etc", "rule-c");

    SparkEvent ev;
    ev.key = "file|4:/etc";
    ev.type = SparkType::File;

    // No sink set: still resolves and counts, never dereferences a null handler.
    REQUIRE(consumer.on_event(ev) == 1);
}
