/**
 * test_guaranteed_state_store.cpp — Unit tests for GuaranteedStateStore
 *
 * Covers:
 *   - schema migration applies cleanly against a fresh in-memory DB
 *   - rule CRUD round-trip (create / get / list / update / delete)
 *   - event insert + query with filtering
 *   - UNIQUE(name) rejection and unknown-rule update/delete return false
 *   - signature BLOB round-trip
 */

#include "guaranteed_state_store.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::server;

namespace {

GuaranteedStateRuleRow make_rule(std::string rule_id, std::string name) {
    GuaranteedStateRuleRow r;
    r.rule_id = std::move(rule_id);
    r.name = std::move(name);
    r.yaml_source = "apiVersion: yuzu.io/v1alpha1\nkind: GuaranteedStateRule\n";
    r.version = 1;
    r.enabled = true;
    r.enforcement_mode = "enforce";
    r.severity = "high";
    r.os_target = "windows";
    r.scope_expr = "tag:workstations";
    r.signature = {0xDE, 0xAD, 0xBE, 0xEF};
    r.created_at = "2026-04-19T12:00:00Z";
    r.updated_at = "2026-04-19T12:00:00Z";
    return r;
}

GuaranteedStateEventRow make_event(std::string event_id, std::string rule_id,
                                   std::string agent_id, std::string severity = "high") {
    GuaranteedStateEventRow e;
    e.event_id = std::move(event_id);
    e.rule_id = std::move(rule_id);
    e.agent_id = std::move(agent_id);
    e.event_type = "drift.remediated";
    e.severity = std::move(severity);
    e.guard_type = "registry";
    e.guard_category = "event";
    e.detected_value = "0";
    e.expected_value = "1";
    e.remediation_action = "registry-write";
    e.remediation_success = true;
    e.detection_latency_us = 500;
    e.remediation_latency_us = 1200;
    e.timestamp = "2026-04-19T12:00:00Z";
    return e;
}

} // namespace

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("GuaranteedStateStore: opens in-memory and runs migrations",
          "[guaranteed_state_store][db]") {
    GuaranteedStateStore store(":memory:");
    REQUIRE(store.is_open());
    CHECK(store.rule_count() == 0);
    CHECK(store.event_count() == 0);
}

// ── Rule CRUD ──────────────────────────────────────────────────────────────

TEST_CASE("GuaranteedStateStore: rule round-trip", "[guaranteed_state_store][rules]") {
    GuaranteedStateStore store(":memory:");
    auto rule = make_rule("rule-1", "block-smb-445");

    REQUIRE(store.create_rule(rule));
    REQUIRE(store.rule_count() == 1);

    auto fetched = store.get_rule("rule-1");
    REQUIRE(fetched.has_value());
    CHECK(fetched->name == "block-smb-445");
    CHECK(fetched->enforcement_mode == "enforce");
    CHECK(fetched->os_target == "windows");
    CHECK(fetched->signature == rule.signature);
    CHECK(fetched->scope_expr == "tag:workstations");
}

TEST_CASE("GuaranteedStateStore: list returns all rules ordered by name",
          "[guaranteed_state_store][rules]") {
    GuaranteedStateStore store(":memory:");
    REQUIRE(store.create_rule(make_rule("r-2", "bravo")));
    REQUIRE(store.create_rule(make_rule("r-1", "alpha")));
    REQUIRE(store.create_rule(make_rule("r-3", "charlie")));

    auto rules = store.list_rules();
    REQUIRE(rules.size() == 3);
    CHECK(rules[0].name == "alpha");
    CHECK(rules[1].name == "bravo");
    CHECK(rules[2].name == "charlie");
}

TEST_CASE("GuaranteedStateStore: update mutates row", "[guaranteed_state_store][rules]") {
    GuaranteedStateStore store(":memory:");
    auto rule = make_rule("rule-1", "name-v1");
    REQUIRE(store.create_rule(rule));

    rule.name = "name-v2";
    rule.version = 2;
    rule.enforcement_mode = "audit";
    rule.updated_at = "2026-04-19T13:00:00Z";
    REQUIRE(store.update_rule(rule));

    auto fetched = store.get_rule("rule-1");
    REQUIRE(fetched.has_value());
    CHECK(fetched->name == "name-v2");
    CHECK(fetched->version == 2);
    CHECK(fetched->enforcement_mode == "audit");
}

TEST_CASE("GuaranteedStateStore: update of unknown rule returns false",
          "[guaranteed_state_store][rules]") {
    GuaranteedStateStore store(":memory:");
    auto rule = make_rule("does-not-exist", "ghost");
    CHECK_FALSE(store.update_rule(rule));
}

TEST_CASE("GuaranteedStateStore: delete removes row", "[guaranteed_state_store][rules]") {
    GuaranteedStateStore store(":memory:");
    REQUIRE(store.create_rule(make_rule("rule-1", "to-remove")));
    REQUIRE(store.delete_rule("rule-1"));
    CHECK_FALSE(store.get_rule("rule-1").has_value());
    CHECK_FALSE(store.delete_rule("rule-1")); // second delete is a no-op
}

TEST_CASE("GuaranteedStateStore: duplicate name rejected",
          "[guaranteed_state_store][rules]") {
    GuaranteedStateStore store(":memory:");
    REQUIRE(store.create_rule(make_rule("rule-1", "same-name")));
    CHECK_FALSE(store.create_rule(make_rule("rule-2", "same-name")));
}

// ── Events ─────────────────────────────────────────────────────────────────

TEST_CASE("GuaranteedStateStore: event insert + query", "[guaranteed_state_store][events]") {
    GuaranteedStateStore store(":memory:");

    REQUIRE(store.insert_event(make_event("evt-1", "rule-1", "agent-A")));
    REQUIRE(store.insert_event(make_event("evt-2", "rule-1", "agent-B", "medium")));
    REQUIRE(store.insert_event(make_event("evt-3", "rule-2", "agent-A")));

    CHECK(store.event_count() == 3);

    auto all = store.query_events();
    CHECK(all.size() == 3);

    GuaranteedStateEventQuery q;
    q.rule_id = "rule-1";
    auto by_rule = store.query_events(q);
    CHECK(by_rule.size() == 2);

    GuaranteedStateEventQuery q2;
    q2.agent_id = "agent-A";
    auto by_agent = store.query_events(q2);
    CHECK(by_agent.size() == 2);

    GuaranteedStateEventQuery q3;
    q3.severity = "medium";
    auto by_sev = store.query_events(q3);
    REQUIRE(by_sev.size() == 1);
    CHECK(by_sev[0].event_id == "evt-2");
}

TEST_CASE("GuaranteedStateStore: event query honours limit/offset",
          "[guaranteed_state_store][events]") {
    GuaranteedStateStore store(":memory:");
    for (int i = 0; i < 10; ++i) {
        auto e = make_event("evt-" + std::to_string(i), "rule-1", "agent-A");
        REQUIRE(store.insert_event(e));
    }

    GuaranteedStateEventQuery q;
    q.limit = 3;
    auto page1 = store.query_events(q);
    CHECK(page1.size() == 3);

    q.offset = 3;
    auto page2 = store.query_events(q);
    CHECK(page2.size() == 3);
}

TEST_CASE("GuaranteedStateStore: event round-trip preserves all fields",
          "[guaranteed_state_store][events]") {
    GuaranteedStateStore store(":memory:");
    auto in = make_event("evt-1", "rule-1", "agent-X");
    REQUIRE(store.insert_event(in));

    auto out = store.query_events();
    REQUIRE(out.size() == 1);
    CHECK(out[0].event_id == in.event_id);
    CHECK(out[0].rule_id == in.rule_id);
    CHECK(out[0].agent_id == in.agent_id);
    CHECK(out[0].event_type == in.event_type);
    CHECK(out[0].severity == in.severity);
    CHECK(out[0].guard_type == in.guard_type);
    CHECK(out[0].guard_category == in.guard_category);
    CHECK(out[0].detected_value == in.detected_value);
    CHECK(out[0].expected_value == in.expected_value);
    CHECK(out[0].remediation_action == in.remediation_action);
    CHECK(out[0].remediation_success == in.remediation_success);
    CHECK(out[0].detection_latency_us == in.detection_latency_us);
    CHECK(out[0].remediation_latency_us == in.remediation_latency_us);
    CHECK(out[0].timestamp == in.timestamp);
}
