// test_guardian_spark_bridge.cpp - spark_spec_from_rule (ADR-0021 rung 2 slice
// 2b). The converter is inline, so the proto Map populate (here in the test EXE)
// and the lookup (inside the converter, also compiled into the test EXE) stay in
// one image - no #501 abseil-seed cross-DLL hazard.

#include "guardian_spark_bridge.hpp"

#include "guaranteed_state.pb.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <variant>

using yuzu::agent::FileSparkParams;
using yuzu::agent::RegistrySparkParams;
using yuzu::agent::ServiceSparkParams;
using yuzu::agent::spark_key;
using yuzu::agent::spark_spec_from_rule;
using yuzu::agent::SparkType;
using Rule = yuzu::guardian::v1::GuaranteedStateRule;

namespace {
Rule make_rule(const std::string& rule_id, const std::string& spark_type,
               const std::string& atype,
               std::initializer_list<std::pair<const char*, const char*>> aparams) {
    Rule r;
    r.set_rule_id(rule_id);
    r.mutable_spark()->set_type(spark_type);
    r.mutable_assertion()->set_type(atype);
    for (const auto& [k, v] : aparams)
        (*r.mutable_assertion()->mutable_params())[k] = v;
    return r;
}
} // namespace

TEST_CASE("spark_spec_from_rule: file-change reads path from the assertion", "[spark][bridge]") {
    const Rule r = make_rule("r1", "file-change", "file-hash-equals", {{"path", "/etc/hosts"}});
    const auto spec = spark_spec_from_rule(r);
    REQUIRE(spec.has_value());
    REQUIRE(spec->type == SparkType::File);
    REQUIRE(std::get<FileSparkParams>(spec->params).path == "/etc/hosts");
}

TEST_CASE("spark_spec_from_rule: service-status-change reads service_name", "[spark][bridge]") {
    const Rule r = make_rule("r1", "service-status-change", "service-running",
                             {{"service_name", "sshd"}});
    const auto spec = spark_spec_from_rule(r);
    REQUIRE(spec.has_value());
    REQUIRE(spec->type == SparkType::Service);
    REQUIRE(std::get<ServiceSparkParams>(spec->params).service_name == "sshd");
}

TEST_CASE("spark_spec_from_rule: registry-change reads hive + key", "[spark][bridge]") {
    const Rule r = make_rule("r1", "registry-change", "registry-value-equals",
                             {{"hive", "HKLM"}, {"key", "Software\\Yuzu"}});
    const auto spec = spark_spec_from_rule(r);
    REQUIRE(spec.has_value());
    REQUIRE(spec->type == SparkType::Registry);
    const auto& rp = std::get<RegistrySparkParams>(spec->params);
    REQUIRE(rp.hive == "HKLM");
    REQUIRE(rp.key == "Software\\Yuzu");
}

TEST_CASE("spark_spec_from_rule: missing required target param is nullopt", "[spark][bridge]") {
    // file with no path
    REQUIRE_FALSE(spark_spec_from_rule(make_rule("r", "file-change", "file-exists", {})).has_value());
    // service with no name
    REQUIRE_FALSE(
        spark_spec_from_rule(make_rule("r", "service-status-change", "service-running", {}))
            .has_value());
    // registry with hive but no key
    REQUIRE_FALSE(
        spark_spec_from_rule(make_rule("r", "registry-change", "registry-value-equals",
                                       {{"hive", "HKLM"}}))
            .has_value());
}

TEST_CASE("spark_spec_from_rule: an unknown spark type is nullopt", "[spark][bridge]") {
    REQUIRE_FALSE(spark_spec_from_rule(make_rule("r", "banana", "whatever", {{"path", "/x"}}))
                      .has_value());
}

TEST_CASE("spark_spec_from_rule: two rules on the same target dedup to one spark_key", "[spark][bridge]") {
    // The whole point of the shared-watcher model: different rule_ids (even with
    // different assertions) watching the same file resolve to ONE spark_key.
    const Rule a = make_rule("rule-a", "file-change", "file-exists", {{"path", "/etc/passwd"}});
    const Rule b = make_rule("rule-b", "file-change", "file-hash-equals",
                             {{"path", "/etc/passwd"}, {"expected_hash", "deadbeef"}});
    const auto sa = spark_spec_from_rule(a);
    const auto sb = spark_spec_from_rule(b);
    REQUIRE(sa.has_value());
    REQUIRE(sb.has_value());
    REQUIRE(spark_key(*sa) == spark_key(*sb));
}
