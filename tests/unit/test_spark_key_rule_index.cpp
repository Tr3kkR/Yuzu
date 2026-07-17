// test_spark_key_rule_index.cpp - SparkKeyRuleIndex (ADR-0021 rung 2 slice 2a).
//
// The index is the consumer-side register-of-record that (1) resolves a shared
// watcher's event back to every rule that fans out from it and (2) reports the
// 0->1 / ->0 refcount edges a caller turns into a single arm()/disarm(). These
// tests pin both roles plus the redeploy (key-move) path, without arming
// anything - the index is pure state.

#include "spark_key_rule_index.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>
#include <vector>

using yuzu::agent::SparkKeyRuleIndex;

TEST_CASE("SparkKeyRuleIndex: add reports the 0->1 edge exactly once per key", "[spark][index]") {
    SparkKeyRuleIndex idx;
    REQUIRE(idx.empty());

    // First rule for a key is the arm edge.
    REQUIRE(idx.add("service|5:sshd", "rule-a") == true);
    // A second rule sharing the SAME key is NOT an arm edge (the watcher exists).
    REQUIRE(idx.add("service|5:sshd", "rule-b") == false);
    // Re-adding an identical (key, rule) pair is an idempotent no-op.
    REQUIRE(idx.add("service|5:sshd", "rule-a") == false);

    REQUIRE(idx.refcount("service|5:sshd") == 2);
    REQUIRE(idx.key_count() == 1);
    REQUIRE(idx.rule_count() == 2);
    REQUIRE_FALSE(idx.empty());
}

TEST_CASE("SparkKeyRuleIndex: rules_for is the sorted fan-out set", "[spark][index]") {
    SparkKeyRuleIndex idx;
    idx.add("file|4:/etc", "rule-z");
    idx.add("file|4:/etc", "rule-a");
    idx.add("file|4:/etc", "rule-m");

    // One shared watcher -> three rules, deterministic (sorted) order.
    REQUIRE(idx.rules_for("file|4:/etc") == std::vector<std::string>{"rule-a", "rule-m", "rule-z"});
    // An unmapped key resolves to nothing.
    REQUIRE(idx.rules_for("file|9:/nowhere").empty());
    REQUIRE(idx.refcount("file|9:/nowhere") == 0);
}

TEST_CASE("SparkKeyRuleIndex: remove_rule reports ->0 only on the last sibling", "[spark][index]") {
    SparkKeyRuleIndex idx;
    idx.add("registry|4:HKLM", "rule-a");
    idx.add("registry|4:HKLM", "rule-b");

    // Removing a rule that still has a sibling is NOT a disarm edge.
    REQUIRE(idx.remove_rule("rule-a") == std::nullopt);
    REQUIRE(idx.refcount("registry|4:HKLM") == 1);
    REQUIRE(idx.rules_for("registry|4:HKLM") == std::vector<std::string>{"rule-b"});

    // Removing the LAST rule surfaces the key so the caller disarms it.
    REQUIRE(idx.remove_rule("rule-b") == std::optional<std::string>{"registry|4:HKLM"});
    REQUIRE(idx.refcount("registry|4:HKLM") == 0);
    REQUIRE(idx.key_count() == 0);
    REQUIRE(idx.empty());
}

TEST_CASE("SparkKeyRuleIndex: remove_rule is idempotent for an unknown rule", "[spark][index]") {
    SparkKeyRuleIndex idx;
    REQUIRE(idx.remove_rule("never-added") == std::nullopt);
    idx.add("service|5:nginx", "rule-a");
    REQUIRE(idx.remove_rule("some-other-rule") == std::nullopt);
    REQUIRE(idx.refcount("service|5:nginx") == 1);
}

TEST_CASE("SparkKeyRuleIndex: a redeploy that moves a rule to a new key", "[spark][index]") {
    SparkKeyRuleIndex idx;
    REQUIRE(idx.add("service|5:sshd", "rule-a") == true);
    REQUIRE(idx.key_for_rule("rule-a") == std::optional<std::string>{"service|5:sshd"});

    // Re-add the SAME rule under a different key (its spec changed). add() drops
    // the stale association and reports the new key's 0->1 edge; the old key is
    // vacated (refcount 0) so it no longer resolves or holds the rule.
    REQUIRE(idx.add("service|5:nginx", "rule-a") == true);
    REQUIRE(idx.key_for_rule("rule-a") == std::optional<std::string>{"service|5:nginx"});
    REQUIRE(idx.refcount("service|5:sshd") == 0);
    REQUIRE(idx.refcount("service|5:nginx") == 1);
    REQUIRE(idx.rules_for("service|5:sshd").empty());
    // Exactly one rule, one key: no orphaned empty key entry left behind.
    REQUIRE(idx.rule_count() == 1);
    REQUIRE(idx.key_count() == 1);
}

TEST_CASE("SparkKeyRuleIndex: key_for_rule tracks the current mapping", "[spark][index]") {
    SparkKeyRuleIndex idx;
    REQUIRE(idx.key_for_rule("rule-a") == std::nullopt);
    idx.add("disk|1:/", "rule-a");
    REQUIRE(idx.key_for_rule("rule-a") == std::optional<std::string>{"disk|1:/"});
    idx.remove_rule("rule-a");
    REQUIRE(idx.key_for_rule("rule-a") == std::nullopt);
}
