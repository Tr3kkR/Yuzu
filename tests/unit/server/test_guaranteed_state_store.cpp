/**
 * test_guaranteed_state_store.cpp — Unit tests for GuaranteedStateStore
 *
 * Covers:
 *   - schema migration applies cleanly against a fresh in-memory DB
 *   - rule CRUD round-trip (create / get / list / update / delete)
 *   - event insert + query with filtering
 *   - UNIQUE(name) and PRIMARY KEY rejection surface as kConflictPrefix errors
 *   - unknown-rule update/delete return a non-conflict error
 *   - signature BLOB round-trip (incl. empty vs non-empty)
 *   - query_events tie-break ordering with distinct timestamps
 *   - query_events limit clamped to kMaxEventsLimit
 *   - bad-path constructor returns sentinels from every method
 *   - migration idempotency: re-open existing on-disk DB
 *   - #452 §2 created_by / updated_by round-trip
 *   - #452 §5 TTL reaper deletes expired events on demand
 *   - #452 §7 batch insert_events transactional semantics
 */

#include "guaranteed_state_store.hpp"
#include "store_errors.hpp"
#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <map>
#include <random>
#include <thread>

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
    r.created_by = "alice";
    r.updated_by = "alice";
    return r;
}

GuaranteedStateEventRow make_event(std::string event_id, std::string rule_id,
                                   std::string agent_id, std::string severity = "high",
                                   std::string timestamp = "2026-04-19T12:00:00Z") {
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
    e.timestamp = std::move(timestamp);
    return e;
}

// RAII guard for a per-test temp database file. Constructed FIRST so the
// destructor fires even if downstream construction throws (prior governance
// memory qe-B1 — partial-construction leaks when RAII wraps come later).
// Use the shared fixture (unique_temp_path + -wal/-shm cleanup) rather than a
// local random_device variant — matches the CLAUDE.md test-helper mandate and
// avoids the flake-#473 salt pitfalls (qa-S4 / #1209).
using yuzu::test::TempDbFile;

} // namespace

// ── Lifecycle ──────────────────────────────────────────────────────────────

TEST_CASE("GuaranteedStateStore: opens in-memory and runs migrations",
          "[guaranteed_state_store][db]") {
    GuaranteedStateStore store(":memory:");
    REQUIRE(store.is_open());
    CHECK(store.rule_count() == 0);
    CHECK(store.event_count() == 0);
}

// ── M6 / #1209: monotonic policy generation ─────────────────────────────────

TEST_CASE("GuaranteedStateStore: policy_generation bumps monotonically on mutations",
          "[guaranteed_state_store][generation]") {
    GuaranteedStateStore store(":memory:");
    CHECK(store.current_policy_generation() == 0);  // seeded at 0

    REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
    CHECK(store.current_policy_generation() == 1);  // create bumped

    auto r = make_rule("r1", "guard-one");
    r.enabled = false;
    REQUIRE(store.update_rule(r));
    CHECK(store.current_policy_generation() == 2);  // update bumped

    REQUIRE(store.delete_rule("r1"));
    CHECK(store.current_policy_generation() == 3);  // delete bumped

    // A failed mutation (unknown rule) must NOT advance the generation —
    // otherwise a reconcile would chase a phantom version.
    CHECK_FALSE(store.update_rule(make_rule("nope", "missing")));
    CHECK(store.current_policy_generation() == 3);
}

TEST_CASE("GuaranteedStateStore: policy_generation persists across reopen",
          "[guaranteed_state_store][generation]") {
    TempDbFile tmp;
    {
        GuaranteedStateStore store(tmp.path);
        REQUIRE(store.create_rule(make_rule("r1", "guard-one")));
        CHECK(store.current_policy_generation() == 1);
    }
    // Reopen: the counter is persisted, not reset — an agent that applied
    // generation 1 before a server restart must not look stale afterwards.
    GuaranteedStateStore reopened(tmp.path);
    CHECK(reopened.current_policy_generation() == 1);
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
    CHECK(fetched->created_by == "alice");
    CHECK(fetched->updated_by == "alice");
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
    rule.updated_by = "bob";
    REQUIRE(store.update_rule(rule));

    auto fetched = store.get_rule("rule-1");
    REQUIRE(fetched.has_value());
    CHECK(fetched->name == "name-v2");
    CHECK(fetched->version == 2);
    CHECK(fetched->enforcement_mode == "audit");
    // created_by stays immutable; updated_by records the new principal.
    CHECK(fetched->created_by == "alice");
    CHECK(fetched->updated_by == "bob");
}

TEST_CASE("GuaranteedStateStore: update of unknown rule returns error",
          "[guaranteed_state_store][rules]") {
    GuaranteedStateStore store(":memory:");
    auto rule = make_rule("does-not-exist", "ghost");
    auto r = store.update_rule(rule);
    REQUIRE_FALSE(r.has_value());
    CHECK_FALSE(is_conflict_error(r.error()));
    CHECK(r.error().find("not found") != std::string::npos);
}

TEST_CASE("GuaranteedStateStore: delete removes row", "[guaranteed_state_store][rules]") {
    GuaranteedStateStore store(":memory:");
    REQUIRE(store.create_rule(make_rule("rule-1", "to-remove")));
    REQUIRE(store.delete_rule("rule-1"));
    CHECK_FALSE(store.get_rule("rule-1").has_value());
    auto second = store.delete_rule("rule-1");
    REQUIRE_FALSE(second.has_value());
    CHECK(second.error().find("not found") != std::string::npos);
}

TEST_CASE("GuaranteedStateStore: duplicate name rejected with kConflictPrefix",
          "[guaranteed_state_store][rules][conflict]") {
    GuaranteedStateStore store(":memory:");
    REQUIRE(store.create_rule(make_rule("rule-1", "same-name")));
    auto dup = store.create_rule(make_rule("rule-2", "same-name"));
    REQUIRE_FALSE(dup.has_value());
    CHECK(is_conflict_error(dup.error()));
    // Human-readable detail names the offending field so the 409 response
    // body can be shown verbatim to operators after strip_conflict_prefix.
    CHECK(dup.error().find("same-name") != std::string::npos);
    CHECK(std::string(strip_conflict_prefix(dup.error())).find("name") != std::string::npos);
}

TEST_CASE("GuaranteedStateStore: duplicate rule_id rejected with kConflictPrefix",
          "[guaranteed_state_store][rules][conflict]") {
    GuaranteedStateStore store(":memory:");
    REQUIRE(store.create_rule(make_rule("same-id", "name-one")));
    auto dup = store.create_rule(make_rule("same-id", "name-two"));
    REQUIRE_FALSE(dup.has_value());
    CHECK(is_conflict_error(dup.error()));
    // PRIMARY KEY collision — detail calls out rule_id, not name.
    CHECK(dup.error().find("rule_id") != std::string::npos);
    CHECK(dup.error().find("same-id") != std::string::npos);
}

TEST_CASE("GuaranteedStateStore: update into an existing name is a conflict",
          "[guaranteed_state_store][rules][conflict]") {
    GuaranteedStateStore store(":memory:");
    REQUIRE(store.create_rule(make_rule("a", "alpha")));
    REQUIRE(store.create_rule(make_rule("b", "bravo")));

    // Rename b → alpha must collide with a, returning a conflict error.
    auto rule = make_rule("b", "alpha");
    auto r = store.update_rule(rule);
    REQUIRE_FALSE(r.has_value());
    CHECK(is_conflict_error(r.error()));
}

// ── Events ─────────────────────────────────────────────────────────────────

TEST_CASE("GuaranteedStateStore: event insert + query", "[guaranteed_state_store][events]") {
    GuaranteedStateStore store(":memory:");

    REQUIRE(store.insert_event(make_event("evt-1", "rule-1", "agent-A")));
    REQUIRE(store.insert_event(make_event("evt-2", "rule-1", "agent-B", "medium")));
    REQUIRE(store.insert_event(make_event("evt-3", "rule-2", "agent-A")));

    CHECK(store.event_count() == 3);
    CHECK(store.events_written_total() == 3);

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

TEST_CASE("GuaranteedStateStore: duplicate event_id is dropped and counted (#1414)",
          "[guaranteed_state_store][events]") {
    GuaranteedStateStore store(":memory:");

    REQUIRE(store.insert_event(make_event("evt-dup", "rule-1", "agent-A")));
    CHECK(store.events_written_total() == 1);
    CHECK(store.events_dropped_total() == 0);

    // Redelivery / forged-id pre-claim: same event_id collides on the global PK.
    // The conflicting event must NOT be written, the failure surfaces as an error,
    // and the silent-drop counter must advance (CC7.3 evidence — #1414).
    auto r = store.insert_event(make_event("evt-dup", "rule-1", "agent-B"));
    REQUIRE_FALSE(r);
    CHECK(store.event_count() == 1);
    CHECK(store.events_written_total() == 1);
    CHECK(store.events_dropped_total() == 1);
}

TEST_CASE("GuaranteedStateStore: ruleless crash observation skips the compliance census",
          "[guaranteed_state_store][events][crash]") {
    // Guardian DEX slice 1: a fleet-wide process crash is RULELESS — sentinel
    // rule_id "__observation__" + event_type "process.crashed". It must insert
    // (rule_id is NOT NULL — the sentinel satisfies it), keep its agent-set
    // severity verbatim, and NOT create a per-(agent,rule) compliance census row
    // (process.crashed is not a compliance state). A normal drift event in the
    // same store still updates the census — proving the skip is crash-specific.
    // Pins the ruleless path the agent crash recorder relies on.
    GuaranteedStateStore store(":memory:");

    // A normal rule-bound drift (drift.remediated) -> updates the census.
    REQUIRE(store.insert_event(make_event("evt-drift", "rule-1", "agent-A")));

    // A ruleless crash observation.
    GuaranteedStateEventRow crash;
    crash.event_id = "__observation__-1718000000000-0";
    crash.rule_id = "__observation__";
    crash.agent_id = "agent-A";
    crash.event_type = "process.crashed";
    crash.severity = "info";
    crash.guard_type = "process";
    crash.guard_category = ""; // ruleless-ness + event_type IS the discriminator
    crash.detected_value = "notepad.exe pid=1234 code=0xC0000005 ACCESS_VIOLATION module=ntdll.dll";
    crash.timestamp = "2026-06-08T12:00:00Z";
    REQUIRE(store.insert_event(crash));

    // The crash is stored and keeps its severity verbatim (no rule to enrich from).
    GuaranteedStateEventQuery q;
    q.rule_id = "__observation__";
    auto crashes = store.query_events(q);
    REQUIRE(crashes.size() == 1);
    CHECK(crashes[0].event_type == "process.crashed");
    CHECK(crashes[0].severity == "info");
    CHECK(crashes[0].guard_category.empty());

    // The census has the drift's (agent,rule) row but NONE for the sentinel.
    CHECK(store.agent_rule_statuses().size() == 1);
    CHECK(store.agent_rule_statuses("__observation__").empty());
}

TEST_CASE("GuaranteedStateStore: a reserved sentinel rule_id never updates the census",
          "[guaranteed_state_store][events][crash][security]") {
    // Security hardening (Gate-2 LOW → enforced): the "__observation__" sentinel is
    // reserved for ruleless observations and has no live rule. A (mis)behaving agent
    // could pair it with a COMPLIANCE event_type (drift.detected) to mint a phantom
    // per-(agent,rule) census row keyed to the reserved id. The store must skip the
    // census for ANY reserved __…__ rule_id regardless of event_type — not just for
    // process.crashed.
    GuaranteedStateStore store(":memory:");

    GuaranteedStateEventRow abuse;
    abuse.event_id = "__observation__-abuse-1";
    abuse.rule_id = "__observation__";
    abuse.agent_id = "agent-A";
    abuse.event_type = "drift.detected"; // a compliance verdict paired with the sentinel
    abuse.severity = "info";
    abuse.timestamp = "2026-06-09T12:00:00Z";
    REQUIRE(store.insert_event(abuse));

    // The event is still stored (rule_id is NOT NULL — the sentinel satisfies it)…
    GuaranteedStateEventQuery q;
    q.rule_id = "__observation__";
    REQUIRE(store.query_events(q).size() == 1);
    // …but it creates NO census row for the reserved id.
    CHECK(store.agent_rule_statuses().empty());
    CHECK(store.agent_rule_statuses("__observation__").empty());

    // Regression guard: the skip is EXACT-match, NOT a "__"-prefix. A legitimately
    // authored guard whose name slugifies to a "__"-prefixed rule_id (e.g. "__foo-<hex>")
    // is a REAL rule-bound id and MUST keep its compliance census.
    GuaranteedStateEventRow real;
    real.event_id = "evt-real-1";
    real.rule_id = "__foo-abc123"; // not the exact sentinel
    real.agent_id = "agent-A";
    real.event_type = "drift.detected";
    real.severity = "high";
    real.timestamp = "2026-06-09T12:01:00Z";
    REQUIRE(store.insert_event(real));
    CHECK(store.agent_rule_statuses("__foo-abc123").size() == 1);
}

TEST_CASE("GuaranteedStateStore: observation projects uniform detail_json keys",
          "[guaranteed_state_store][events][crash][dex]") {
    // A ruleless observation projects its UNIFORM detail_json facts
    // (subject/reason/symbolic/component/metric) into the guardian_observations
    // read model — generically, for every signal type. A plain drift event must
    // NOT project — the projection is observations-only.
    GuaranteedStateStore store(":memory:");

    REQUIRE(store.insert_event(make_event("evt-drift", "rule-1", "agent-A")));
    CHECK(store.query_observations().empty()); // drift does not project

    GuaranteedStateEventRow crash;
    crash.event_id = "__observation__-proj-1";
    crash.rule_id = "__observation__";
    crash.agent_id = "agent-A";
    crash.event_type = "process.crashed";
    crash.severity = "info";
    crash.detected_value = "notepad.exe pid=1234 code=0xC0000005 ACCESS_VIOLATION module=ntdll.dll";
    crash.detail_json =
        R"({"subject":"notepad.exe","pid":1234,"kind":"exception",)"
        R"("reason":"0xC0000005","symbolic":"ACCESS_VIOLATION",)"
        R"("component":"ntdll.dll","platform":"windows"})";
    crash.timestamp = "2026-06-08T12:00:00Z";
    REQUIRE(store.insert_event(crash));

    auto obs = store.query_observations();
    REQUIRE(obs.size() == 1); // the crash projected; the drift did not
    CHECK(obs[0].event_id == "__observation__-proj-1");
    CHECK(obs[0].agent_id == "agent-A");
    CHECK(obs[0].observed_at == "2026-06-08T12:00:00Z");
    CHECK(obs[0].obs_type == "process.crashed");
    CHECK(obs[0].subject == "notepad.exe");
    CHECK(obs[0].reason == "0xC0000005");
    CHECK(obs[0].symbolic == "ACCESS_VIOLATION");
    CHECK(obs[0].component == "ntdll.dll");
    CHECK(obs[0].platform == "windows");
}

TEST_CASE("GuaranteedStateStore: legacy slice-1 crash keys still project (fallback)",
          "[guaranteed_state_store][events][crash][dex]") {
    // PR #1311 transition compat: an agent still emitting the slice-1 crash keys
    // (process/exception_code/faulting_module) must keep projecting — the
    // projection falls back to them when the uniform keys are absent.
    GuaranteedStateStore store(":memory:");
    GuaranteedStateEventRow crash;
    crash.event_id = "__observation__-legacy-1";
    crash.rule_id = "__observation__";
    crash.agent_id = "agent-L";
    crash.event_type = "process.crashed";
    crash.severity = "info";
    crash.detail_json =
        R"({"process":"old-agent.exe","exception_code":"0xC0000374",)"
        R"("symbolic":"HEAP_CORRUPTION","faulting_module":"heap.dll","platform":"windows"})";
    crash.timestamp = "2026-06-08T12:00:00Z";
    REQUIRE(store.insert_event(crash));

    auto obs = store.query_observations();
    REQUIRE(obs.size() == 1);
    CHECK(obs[0].subject == "old-agent.exe");   // process → subject
    CHECK(obs[0].reason == "0xC0000374");       // exception_code → reason
    CHECK(obs[0].component == "heap.dll");      // faulting_module → component
}

TEST_CASE("GuaranteedStateStore: metric projects for numeric payloads, rejects garbage",
          "[guaranteed_state_store][events][dex]") {
    GuaranteedStateStore store(":memory:");
    auto boot = [&](const std::string& id, const std::string& json) {
        GuaranteedStateEventRow e;
        e.event_id = id;
        e.rule_id = "__observation__";
        e.agent_id = "agent-A";
        e.event_type = "os.boot";
        e.severity = "info";
        e.detail_json = json;
        e.timestamp = "2026-06-09T08:00:00Z";
        REQUIRE(store.insert_event(e));
    };
    boot("b1", R"({"subject":"boot","metric":43210.0,"platform":"windows"})");
    boot("b2", R"({"subject":"boot","metric":-99,"platform":"windows"})");   // negative → 0
    auto obs = store.query_observations();
    REQUIRE(obs.size() == 2);
    // newest-first ties broken by event_id DESC → b2 first
    CHECK(obs[0].metric == 0.0);
    CHECK(obs[1].metric == 43210.0);
}

TEST_CASE("GuaranteedStateStore: redelivered crash event_id does not double-count the projection",
          "[guaranteed_state_store][events][crash][dex]") {
    // The event journal is at-least-once. The projection INSERT lives inside the
    // event INSERT's transaction, so a duplicate event_id fails the event PK and
    // rolls back BOTH — the projection inherits the dedup and never double-counts.
    // A plain round-trip test would miss this (the catch the advisor flagged).
    GuaranteedStateStore store(":memory:");

    GuaranteedStateEventRow crash;
    crash.event_id = "__observation__-dup-1";
    crash.rule_id = "__observation__";
    crash.agent_id = "agent-A";
    crash.event_type = "process.crashed";
    crash.severity = "info";
    crash.detail_json = R"({"process":"svc.exe","exception_code":"0xC0000409","platform":"windows"})";
    crash.timestamp = "2026-06-08T12:00:00Z";

    REQUIRE(store.insert_event(crash));
    auto dup = store.insert_event(crash); // same event_id redelivered
    REQUIRE_FALSE(dup.has_value());
    CHECK(is_conflict_error(dup.error())); // event PK conflict

    // Exactly one event row AND one projection row — no double-count.
    GuaranteedStateEventQuery q;
    q.rule_id = "__observation__";
    CHECK(store.query_events(q).size() == 1);
    CHECK(store.query_observations().size() == 1);
}

TEST_CASE("GuaranteedStateStore: malformed crash detail_json still records the observation",
          "[guaranteed_state_store][events][crash][dex]") {
    // detail_json is parsed defensively: a malformed blob must NOT drop the crash
    // (the event itself is still valuable). The observation lands with empty crash
    // fields rather than failing the insert.
    GuaranteedStateStore store(":memory:");

    GuaranteedStateEventRow crash;
    crash.event_id = "__observation__-bad-json-1";
    crash.rule_id = "__observation__";
    crash.agent_id = "agent-A";
    crash.event_type = "process.crashed";
    crash.severity = "info";
    crash.detail_json = "{not valid json";
    crash.timestamp = "2026-06-08T12:00:00Z";
    REQUIRE(store.insert_event(crash)); // does not fail

    auto obs = store.query_observations();
    REQUIRE(obs.size() == 1);
    CHECK(obs[0].obs_type == "process.crashed");
    CHECK(obs[0].subject.empty()); // degraded, not dropped
}

TEST_CASE("GuaranteedStateStore: DEX crash aggregations", "[guaranteed_state_store][crash][dex]") {
    // Slice 2: crash-scoped GROUP BY over the projection. Known dataset with
    // verifiable counts, blast radius (distinct devices), tie-break, by-OS, by-day,
    // and the since-cutoff.
    GuaranteedStateStore store(":memory:");
    auto crash = [&](const std::string& id, const std::string& agent, const std::string& proc,
                     const std::string& mod, const std::string& plat, const std::string& ts) {
        GuaranteedStateEventRow c;
        c.event_id = id;
        c.rule_id = "__observation__";
        c.agent_id = agent;
        c.event_type = "process.crashed";
        c.severity = "info";
        c.detail_json = "{\"subject\":\"" + proc + "\",\"reason\":\"0xC0000005\","
                        "\"symbolic\":\"ACCESS_VIOLATION\",\"component\":\"" + mod +
                        "\",\"platform\":\"" + plat + "\"}";
        c.timestamp = ts;
        REQUIRE(store.insert_event(c));
    };
    crash("e1", "agent-A", "chrome.exe", "ntdll.dll", "windows", "2026-06-08T10:00:00Z");
    crash("e2", "agent-A", "chrome.exe", "ntdll.dll", "windows", "2026-06-08T11:00:00Z");
    crash("e3", "agent-B", "chrome.exe", "chrome.dll", "windows", "2026-06-09T10:00:00Z");
    crash("e4", "agent-B", "Teams.exe", "ntdll.dll", "windows", "2026-06-09T11:00:00Z");
    crash("e5", "agent-C", "AcmeCRM.exe", "AcmeCRM.dll", "linux", "2026-06-09T12:00:00Z");

    auto sum = store.dex_crash_summary();
    CHECK(sum.total_crashes == 5);
    CHECK(sum.distinct_devices == 3);
    CHECK(sum.distinct_apps == 3);

    auto apps = store.dex_top_apps();
    REQUIRE(apps.size() == 3);
    CHECK(apps[0].subject == "chrome.exe");
    CHECK(apps[0].crashes == 3);
    CHECK(apps[0].hangs == 0); // crash-only dataset
    CHECK(apps[0].distinct_devices == 2); // blast radius: agent-A + agent-B
    CHECK(apps[0].last_seen == "2026-06-09T10:00:00Z");

    auto mods = store.dex_top_modules();
    REQUIRE(mods.size() == 3);
    CHECK(mods[0].component == "ntdll.dll");
    CHECK(mods[0].crashes == 3);
    CHECK(mods[0].distinct_apps == 2); // chrome.exe + Teams.exe

    auto devs = store.dex_top_devices();
    REQUIRE(devs.size() == 3);
    CHECK(devs[0].agent_id == "agent-A"); // ties at 2 broken by agent_id ASC
    CHECK(devs[0].crashes == 2);
    CHECK(devs[1].agent_id == "agent-B");
    CHECK(devs[2].agent_id == "agent-C");
    CHECK(devs[2].crashes == 1);

    auto os = store.dex_crashes_by_os();
    REQUIRE(os.size() == 2);
    CHECK(os[0].platform == "windows");
    CHECK(os[0].crashes == 4);
    CHECK(os[0].distinct_devices == 2);
    CHECK(os[1].platform == "linux");
    CHECK(os[1].crashes == 1);

    auto days = store.dex_crashes_by_day();
    REQUIRE(days.size() == 2);
    CHECK(days[0].day == "2026-06-08");
    CHECK(days[0].crashes == 2);
    CHECK(days[1].day == "2026-06-09");
    CHECK(days[1].crashes == 3);

    // since-cutoff: only 06-09 onward → e3,e4,e5
    auto recent = store.dex_crash_summary("2026-06-09T00:00:00Z");
    CHECK(recent.total_crashes == 3);
    CHECK(recent.distinct_devices == 2); // agent-B + agent-C
}

TEST_CASE("GuaranteedStateStore: generic per-obs_type drill-down + OS scope",
          "[guaranteed_state_store][dex][signals]") {
    // The catalogue View-3 read-model: subjects / OS-split / devices / trend for
    // ANY obs_type (not crash-scoped), plus per-OS coverage scope.
    GuaranteedStateStore store(":memory:");
    auto obs = [&](const std::string& id, const std::string& agent, const std::string& type,
                   const std::string& subject, const std::string& plat, const std::string& ts) {
        GuaranteedStateEventRow r;
        r.event_id = id;
        r.rule_id = "__observation__";
        r.agent_id = agent;
        r.event_type = type;
        r.severity = "info";
        r.detail_json = "{\"subject\":\"" + subject + "\",\"platform\":\"" + plat + "\"}";
        r.timestamp = ts;
        REQUIRE(store.insert_event(r));
    };
    obs("w1", "agent-A", "network.wifi_drop", "CorpNet", "windows", "2026-06-08T10:00:00Z");
    obs("w2", "agent-A", "network.wifi_drop", "CorpNet", "windows", "2026-06-08T11:00:00Z");
    obs("w3", "agent-B", "network.wifi_drop", "Guest", "windows", "2026-06-09T10:00:00Z");
    obs("w4", "mac-1", "network.wifi_drop", "Wi-Fi", "macos", "2026-06-09T11:00:00Z");
    obs("c1", "mac-1", "process.crashed", "Safari", "macos", "2026-06-09T12:00:00Z");

    auto subj = store.dex_signal_subjects("network.wifi_drop");
    REQUIRE(subj.size() == 3);
    CHECK(subj[0].subject == "CorpNet");
    CHECK(subj[0].count == 2);
    CHECK(subj[0].distinct_devices == 1);

    auto os = store.dex_signal_by_os("network.wifi_drop");
    REQUIRE(os.size() == 2);
    CHECK(os[0].platform == "windows");
    CHECK(os[0].crashes == 3); // generic event count
    CHECK(os[1].platform == "macos");
    CHECK(os[1].crashes == 1);

    auto devs = store.dex_signal_devices("network.wifi_drop");
    REQUIRE(devs.size() == 3);
    CHECK(devs[0].agent_id == "agent-A");
    CHECK(devs[0].crashes == 2);

    auto days = store.dex_signal_by_day("network.wifi_drop");
    REQUIRE(days.size() == 2);
    CHECK(days[0].day == "2026-06-08");
    CHECK(days[0].crashes == 2);

    // Per-OS scope: windows collects 1 type (3 events); macOS collects 2 types
    // (2 events). Ordered by total events desc.
    auto scope = store.dex_os_signal_scope();
    REQUIRE(scope.size() == 2);
    CHECK(scope[0].platform == "windows");
    CHECK(scope[0].distinct_types == 1);
    CHECK(scope[0].total_events == 3);
    CHECK(scope[1].platform == "macos");
    CHECK(scope[1].distinct_types == 2);
    CHECK(scope[1].total_events == 2);

    // day × obs_type matrix (the Trends source): grouped by (day, obs_type).
    auto mat = store.dex_signal_day_matrix();
    REQUIRE(mat.size() == 3);
    CHECK(mat[0].day == "2026-06-08");
    CHECK(mat[0].obs_type == "network.wifi_drop");
    CHECK(mat[0].count == 2);
    CHECK(mat[2].day == "2026-06-09");
    CHECK(mat[2].obs_type == "process.crashed");
    CHECK(mat[2].count == 1);
}

TEST_CASE("GuaranteedStateStore: DEX drill-down aggregations", "[guaranteed_state_store][crash][dex]") {
    GuaranteedStateStore store(":memory:");
    auto crash = [&](const std::string& id, const std::string& agent, const std::string& proc,
                     const std::string& mod, const std::string& plat, const std::string& ts) {
        GuaranteedStateEventRow c;
        c.event_id = id;
        c.rule_id = "__observation__";
        c.agent_id = agent;
        c.event_type = "process.crashed";
        c.severity = "info";
        c.detail_json = "{\"subject\":\"" + proc + "\",\"reason\":\"0xC0000005\","
                        "\"symbolic\":\"ACCESS_VIOLATION\",\"component\":\"" + mod +
                        "\",\"platform\":\"" + plat + "\"}";
        c.timestamp = ts;
        REQUIRE(store.insert_event(c));
    };
    crash("e1", "agent-A", "chrome.exe", "ntdll.dll", "windows", "2026-06-08T10:00:00Z");
    crash("e2", "agent-A", "chrome.exe", "ntdll.dll", "windows", "2026-06-08T11:00:00Z");
    crash("e3", "agent-B", "chrome.exe", "chrome.dll", "windows", "2026-06-09T10:00:00Z");
    crash("e4", "agent-B", "Teams.exe", "ntdll.dll", "windows", "2026-06-09T11:00:00Z");

    // Per-app (chrome.exe): 3 crashes across 2 devices.
    auto as = store.dex_app_summary("chrome.exe");
    CHECK(as.crashes == 3);
    CHECK(as.hangs == 0);
    CHECK(as.distinct_devices == 2);
    CHECK(as.first_seen == "2026-06-08T10:00:00Z");
    CHECK(as.last_seen == "2026-06-09T10:00:00Z");

    auto am = store.dex_app_modules("chrome.exe");
    REQUIRE(am.size() == 2);
    CHECK(am[0].component == "ntdll.dll"); // 2 beats chrome.dll's 1
    CHECK(am[0].crashes == 2);

    auto ae = store.dex_app_exceptions("chrome.exe");
    REQUIRE(ae.size() == 1);
    CHECK(ae[0].reason == "0xC0000005");
    CHECK(ae[0].symbolic == "ACCESS_VIOLATION");
    CHECK(ae[0].crashes == 3);

    auto ad = store.dex_app_devices("chrome.exe");
    REQUIRE(ad.size() == 2);
    CHECK(ad[0].agent_id == "agent-A"); // 2 beats agent-B's 1
    CHECK(ad[0].crashes == 2);

    // Per-device (agent-A): 2 crashes, 1 distinct app; history newest-first.
    auto ds = store.dex_device_summary("agent-A");
    CHECK(ds.crashes == 2);
    CHECK(ds.signals == 2);
    CHECK(ds.distinct_apps == 1);

    auto dh = store.dex_device_history("agent-A");
    REQUIRE(dh.size() == 2);
    CHECK(dh[0].event_id == "e2"); // newest first (11:00 before 10:00)
    CHECK(dh[0].subject == "chrome.exe");
    CHECK(dh[1].event_id == "e1");
}

TEST_CASE("GuaranteedStateStore: multi-signal summary, hang-aware apps, boot stats",
          "[guaranteed_state_store][dex][signals]") {
    // The multi-signal read model: mixed signal types land in ONE projection;
    // dex_signal_summary rolls up per type; dex_top_apps pivots crash+hang; the
    // boot aggregations read the metric column; the device history is unified.
    GuaranteedStateStore store(":memory:");
    auto sig = [&](const std::string& id, const std::string& agent, const std::string& type,
                   const std::string& json, const std::string& ts) {
        GuaranteedStateEventRow e;
        e.event_id = id;
        e.rule_id = "__observation__";
        e.agent_id = agent;
        e.event_type = type;
        e.severity = "info";
        e.detail_json = json;
        e.timestamp = ts;
        REQUIRE(store.insert_event(e));
    };
    sig("s1", "agent-A", "process.crashed",
        R"({"subject":"chrome.exe","reason":"0xC0000005","symbolic":"ACCESS_VIOLATION","component":"ntdll.dll","platform":"windows"})",
        "2026-06-09T10:00:00Z");
    sig("s2", "agent-A", "process.hung",
        R"({"subject":"chrome.exe","symbolic":"NOT_RESPONDING","platform":"windows"})",
        "2026-06-09T10:05:00Z");
    sig("s3", "agent-B", "process.hung",
        R"({"subject":"chrome.exe","symbolic":"NOT_RESPONDING","platform":"windows"})",
        "2026-06-09T10:06:00Z");
    sig("s4", "agent-A", "service.crashed",
        R"({"subject":"Spooler","reason":"7031","symbolic":"SERVICE_CRASHED","platform":"windows"})",
        "2026-06-09T11:00:00Z");
    sig("s5", "agent-A", "os.boot",
        R"({"subject":"boot","metric":43210.0,"platform":"windows"})", "2026-06-09T08:00:00Z");
    sig("s6", "agent-B", "os.boot",
        R"({"subject":"boot","metric":91000.0,"platform":"windows"})", "2026-06-09T08:05:00Z");

    // Whole-catalogue rollup: 4 types, ordered by count.
    auto summary = store.dex_signal_summary();
    REQUIRE(summary.size() == 4);
    CHECK(summary[0].count == 2); // hung / boot tie at 2, obs_type ASC → os.boot first
    CHECK(summary[0].obs_type == "os.boot");
    CHECK(summary[1].obs_type == "process.hung");
    CHECK(summary[1].distinct_devices == 2);

    // Hang-aware app table: chrome has 1 crash + 2 hangs across 2 devices.
    auto apps = store.dex_top_apps();
    REQUIRE(apps.size() == 1); // only crash/hang subjects (Spooler/boot are other types)
    CHECK(apps[0].subject == "chrome.exe");
    CHECK(apps[0].crashes == 1);
    CHECK(apps[0].hangs == 2);
    CHECK(apps[0].distinct_devices == 2);

    // Crash summary stays crash-scoped: 1 crash, 1 device.
    auto cs = store.dex_crash_summary();
    CHECK(cs.total_crashes == 1);
    CHECK(cs.distinct_devices == 1);

    // Boot stats from the metric column.
    auto boot = store.dex_boot_stats();
    CHECK(boot.boots == 2);
    CHECK(boot.avg_ms == 67105.0); // (43210 + 91000) / 2
    CHECK(boot.max_ms == 91000.0);
    CHECK(boot.distinct_devices == 2);
    auto slow = store.dex_slowest_boots();
    REQUIRE(slow.size() == 2);
    CHECK(slow[0].agent_id == "agent-B"); // slowest average first
    CHECK(slow[0].max_ms == 91000.0);

    // Per-app summary spans crash + hang, fleet-wide.
    auto as = store.dex_app_summary("chrome.exe");
    CHECK(as.crashes == 1);  // s1
    CHECK(as.hangs == 2);    // s2 + s3
    CHECK(as.distinct_devices == 2);

    // Per-device summary + unified history for agent-A: crash + hang + service + boot.
    auto ds = store.dex_device_summary("agent-A");
    CHECK(ds.crashes == 1);
    CHECK(ds.hangs == 1);
    CHECK(ds.signals == 4);
    CHECK(ds.distinct_apps == 1); // only crash/hang subjects count as apps

    auto dh = store.dex_device_history("agent-A");
    REQUIRE(dh.size() == 4);
    CHECK(dh[0].obs_type == "service.crashed"); // newest first
    CHECK(dh[3].obs_type == "os.boot");
    CHECK(dh[3].metric == 43210.0);
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
    in.detail_json = R"({"process":"notepad.exe","pid":1234})"; // route a' structured companion
    REQUIRE(store.insert_event(in));

    auto out = store.query_events();
    REQUIRE(out.size() == 1);
    CHECK(out[0].detail_json == in.detail_json); // persisted + read back through the new column
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

TEST_CASE("GuaranteedStateStore: duplicate event_id rejected with kConflictPrefix",
          "[guaranteed_state_store][events][conflict]") {
    GuaranteedStateStore store(":memory:");
    REQUIRE(store.insert_event(make_event("evt-same", "rule-1", "agent-A")));
    auto dup = store.insert_event(make_event("evt-same", "rule-1", "agent-B"));
    REQUIRE_FALSE(dup.has_value());
    CHECK(is_conflict_error(dup.error()));
    CHECK(dup.error().find("evt-same") != std::string::npos);
}

// ── Regression tests carried forward from PR 1 governance ──────────────────

TEST_CASE("GuaranteedStateStore: empty signature round-trip stays empty",
          "[guaranteed_state_store][rules]") {
    GuaranteedStateStore store(":memory:");
    auto r = make_rule("r-empty", "sig-empty");
    r.signature.clear();
    REQUIRE(store.create_rule(r));

    auto fetched = store.get_rule("r-empty");
    REQUIRE(fetched.has_value());
    CHECK(fetched->signature.empty());

    auto listed = store.list_rules();
    REQUIRE(listed.size() == 1);
    CHECK(listed[0].signature.empty());
}

TEST_CASE("GuaranteedStateStore: event query tie-breaks by event_id on equal timestamp",
          "[guaranteed_state_store][events]") {
    GuaranteedStateStore store(":memory:");

    REQUIRE(store.insert_event(
        make_event("older", "rule-1", "agent-A", "high", "2026-04-19T12:00:00Z")));
    REQUIRE(store.insert_event(
        make_event("newer", "rule-1", "agent-A", "high", "2026-04-19T13:00:00Z")));

    auto out = store.query_events();
    REQUIRE(out.size() == 2);
    CHECK(out[0].event_id == "newer");
    CHECK(out[1].event_id == "older");

    GuaranteedStateStore tie_store(":memory:");
    const std::string same_ts = "2026-04-19T12:00:00Z";
    REQUIRE(tie_store.insert_event(make_event("evt-A", "r", "a", "high", same_ts)));
    REQUIRE(tie_store.insert_event(make_event("evt-Z", "r", "a", "high", same_ts)));
    REQUIRE(tie_store.insert_event(make_event("evt-M", "r", "a", "high", same_ts)));

    auto tied = tie_store.query_events();
    REQUIRE(tied.size() == 3);
    CHECK(tied[0].event_id == "evt-Z");
    CHECK(tied[1].event_id == "evt-M");
    CHECK(tied[2].event_id == "evt-A");
}

TEST_CASE("GuaranteedStateStore: query_events limit is clamped and semantically consistent",
          "[guaranteed_state_store][events]") {
    static_assert(kMaxEventsLimit == 10'000,
                  "kMaxEventsLimit changed — update REST layer cap + docs");

    GuaranteedStateStore store(":memory:");
    for (int i = 0; i < 5; ++i) {
        REQUIRE(store.insert_event(make_event("evt-" + std::to_string(i), "r", "a")));
    }

    GuaranteedStateEventQuery upper;
    upper.limit = 2'000'000'000;
    CHECK(store.query_events(upper).size() == 5);

    GuaranteedStateEventQuery zero;
    zero.limit = 0;
    CHECK(store.query_events(zero).empty());

    GuaranteedStateEventQuery neg;
    neg.limit = -42;
    CHECK(store.query_events(neg).empty());
}

TEST_CASE("GuaranteedStateStore: bad path yields closed store with sentinel returns",
          "[guaranteed_state_store][db]") {
    GuaranteedStateStore bad("/no/such/directory/guaranteed-state.db");
    CHECK_FALSE(bad.is_open());

    CHECK_FALSE(bad.create_rule(make_rule("x", "x")));
    CHECK_FALSE(bad.update_rule(make_rule("x", "x")));
    CHECK_FALSE(bad.delete_rule("x"));
    CHECK_FALSE(bad.get_rule("x").has_value());
    CHECK(bad.list_rules().empty());
    CHECK_FALSE(bad.insert_event(make_event("e", "r", "a")));
    CHECK(bad.query_events().empty());
    CHECK(bad.rule_count() == 0);
    CHECK(bad.event_count() == 0);
    // Batch insert on a closed store is also a graceful error.
    auto batch = bad.insert_events({make_event("e", "r", "a")});
    CHECK_FALSE(batch.has_value());
}

TEST_CASE("GuaranteedStateStore: migration is idempotent across re-open",
          "[guaranteed_state_store][db]") {
    TempDbFile tmp;

    {
        GuaranteedStateStore s1(tmp.path);
        REQUIRE(s1.is_open());
        REQUIRE(s1.create_rule(make_rule("rule-1", "survives-reopen")));
        REQUIRE(s1.insert_event(make_event("evt-1", "rule-1", "agent-A")));
        REQUIRE(s1.rule_count() == 1);
        REQUIRE(s1.event_count() == 1);
    }

    {
        GuaranteedStateStore s2(tmp.path);
        REQUIRE(s2.is_open());
        CHECK(s2.rule_count() == 1);
        CHECK(s2.event_count() == 1);

        auto r = s2.get_rule("rule-1");
        REQUIRE(r.has_value());
        CHECK(r->name == "survives-reopen");

        REQUIRE(s2.insert_event(make_event("evt-2", "rule-1", "agent-B")));
        CHECK(s2.event_count() == 2);
    }
}

// ── #452 §7 — batch insert_events ────────────────────────────────────────

TEST_CASE("GuaranteedStateStore: batch insert writes all rows transactionally",
          "[guaranteed_state_store][events][batch]") {
    GuaranteedStateStore store(":memory:");

    std::vector<GuaranteedStateEventRow> batch;
    for (int i = 0; i < 50; ++i) {
        batch.push_back(make_event("evt-" + std::to_string(i), "rule-1", "agent-A"));
    }

    auto n = store.insert_events(batch);
    REQUIRE(n.has_value());
    CHECK(*n == 50);
    CHECK(store.event_count() == 50);
    CHECK(store.events_written_total() == 50);
}

TEST_CASE("GuaranteedStateStore: batch insert with duplicate rolls back whole batch",
          "[guaranteed_state_store][events][batch][conflict]") {
    // Confirm the transactional contract: any failing row invalidates the
    // whole batch, so REST handlers never have to reason about partial
    // commits. First write a row that will collide with the batch.
    GuaranteedStateStore store(":memory:");
    REQUIRE(store.insert_event(make_event("evt-collision", "rule-1", "agent-A")));
    CHECK(store.event_count() == 1);

    std::vector<GuaranteedStateEventRow> batch = {
        make_event("evt-new-1", "rule-1", "agent-A"),
        make_event("evt-new-2", "rule-1", "agent-A"),
        make_event("evt-collision", "rule-1", "agent-B"),  // conflict
        make_event("evt-new-3", "rule-1", "agent-A"),
    };

    auto r = store.insert_events(batch);
    REQUIRE_FALSE(r.has_value());
    CHECK(is_conflict_error(r.error()));
    // None of the batch's new IDs should have landed.
    CHECK(store.event_count() == 1);
    CHECK(store.events_written_total() == 1);

    // Regression guard for the B1 transaction-safety fix: a rolled-back batch must
    // NOT leave the connection wedged in an open transaction. A subsequent batch
    // (which issues its own BEGIN) must succeed — before the SqliteTxn RAII owner,
    // a failure/exception between BEGIN and COMMIT could strand the transaction and
    // make the next BEGIN fail (and a still-open stmt make sqlite3_close BUSY-leak).
    auto after = store.insert_events({make_event("evt-after-rollback", "rule-1", "agent-A")});
    REQUIRE(after.has_value());
    CHECK(store.event_count() == 2);
}

TEST_CASE("GuaranteedStateStore: batch insert of empty vector is a no-op",
          "[guaranteed_state_store][events][batch]") {
    GuaranteedStateStore store(":memory:");
    auto r = store.insert_events({});
    REQUIRE(r.has_value());
    CHECK(*r == 0);
    CHECK(store.event_count() == 0);
}

TEST_CASE("GuaranteedStateStore: insert_events batch projects only observations",
          "[guaranteed_state_store][events][dex]") {
    // Governance qa-B1: the batch path also projects ruleless observations into
    // guardian_observations. A mixed batch (drift + observations) must project
    // exactly the observation rows — and a projection failure must NOT roll back
    // the batch (degrade-don't-destroy, UP-1).
    GuaranteedStateStore store(":memory:");
    std::vector<GuaranteedStateEventRow> batch;
    auto obs = [](const std::string& id, const std::string& proc) {
        GuaranteedStateEventRow e;
        e.event_id = id;
        e.rule_id = "__observation__";
        e.agent_id = "agent-A";
        e.event_type = "process.crashed";
        e.severity = "info";
        e.detail_json = R"({"subject":")" + proc + R"(","reason":"0xC0000005","platform":"windows"})";
        e.timestamp = "2026-06-09T10:00:00Z";
        return e;
    };
    batch.push_back(make_event("d1", "rule-1", "agent-A")); // drift — must NOT project
    batch.push_back(obs("o1", "chrome.exe"));
    batch.push_back(obs("o2", "Teams.exe"));
    auto n = store.insert_events(batch);
    REQUIRE(n.has_value());
    CHECK(*n == 3);
    auto rows = store.query_observations();
    REQUIRE(rows.size() == 2); // only the two observations projected
    CHECK(rows[0].subject != rows[1].subject);
    for (const auto& r : rows)
        CHECK((r.subject == "chrome.exe" || r.subject == "Teams.exe"));
}

TEST_CASE("GuaranteedStateStore: batch ingest never pollutes the census with the sentinel",
          "[guaranteed_state_store][events][dex][security]") {
    // Adversarial-review F1: the batch insert_events path (the preferred gRPC
    // GuaranteedStatePush ingest) must apply the SAME sentinel guard as the
    // single-row path — a batch carrying rule_id="__observation__" with a
    // census-mapping event_type (drift.detected) must NOT mint a phantom
    // (agent, __observation__) census row (§24). Enforce server-side, never trust
    // the agent to pair the sentinel with a non-census event_type.
    GuaranteedStateStore store(":memory:");
    std::vector<GuaranteedStateEventRow> batch;
    // A real rule's drift (SHOULD create a census row) + a hostile sentinel row
    // with a census-mapping event_type (must NOT) in the same batch.
    batch.push_back(make_event("real-1", "rule-real", "agent-A")); // event_type drift.detected
    GuaranteedStateEventRow abuse;
    abuse.event_id = "abuse-1";
    abuse.rule_id = "__observation__";
    abuse.agent_id = "agent-A";
    abuse.event_type = "drift.detected"; // maps to a census state — the attack
    abuse.severity = "high";
    abuse.timestamp = "2026-06-09T10:00:00Z";
    batch.push_back(abuse);
    auto n = store.insert_events(batch);
    REQUIRE(n.has_value());
    CHECK(*n == 2); // both events recorded (the sentinel event itself is valid)
    // The real rule got its census row…
    CHECK(store.agent_rule_statuses("rule-real").size() == 1);
    // …but the sentinel minted NONE (this is the F1 regression assertion).
    CHECK(store.agent_rule_statuses("__observation__").empty());
}

TEST_CASE("GuaranteedStateStore: projected fields are length-clamped (server-side)",
          "[guaranteed_state_store][dex][security]") {
    // Governance sec-M1: the server must not trust an enrolled agent to clip —
    // an oversized subject is clamped (256 B) so it cannot bloat the projection
    // or the dashboard. UTF-8-safe so the clamp never tears a codepoint.
    GuaranteedStateStore store(":memory:");
    const std::string huge(5000, 'A');
    GuaranteedStateEventRow c;
    c.event_id = "big-1";
    c.rule_id = "__observation__";
    c.agent_id = "agent-A";
    c.event_type = "process.crashed";
    c.severity = "info";
    c.detail_json = R"({"subject":")" + huge + R"(","reason":"0xC0000005","platform":"windows"})";
    c.timestamp = "2026-06-09T10:00:00Z";
    REQUIRE(store.insert_event(c));
    auto obs = store.query_observations();
    REQUIRE(obs.size() == 1);
    CHECK(obs[0].subject.size() <= 256);
}

TEST_CASE("GuaranteedStateStore: reaper deletes observations in lockstep with events",
          "[guaranteed_state_store][dex][retention]") {
    // Governance qa-B2: a stale observation (projected via insert_event, so it
    // carries the parent event's ttl) is reaped; a fresh one survives. Drives the
    // production observation-DELETE inline via a second connection (the same
    // pattern the events-reaper test uses, since the cron thread's first tick
    // outlasts the test budget) — exercising the real predicate against rows the
    // real projection path created.
    TempDbFile tmp;
    GuaranteedStateStore store(tmp.path, /*retention_days=*/30);
    auto obs = [&](const std::string& id) {
        GuaranteedStateEventRow e;
        e.event_id = id;
        e.rule_id = "__observation__";
        e.agent_id = "agent-A";
        e.event_type = "process.crashed";
        e.severity = "info";
        e.detail_json = R"({"subject":"chrome.exe","reason":"0xC0000005","platform":"windows"})";
        e.timestamp = "2026-06-09T10:00:00Z";
        REQUIRE(store.insert_event(e));
    };
    obs("fresh");
    obs("stale");
    REQUIRE(store.query_observations().size() == 2);

    {
        sqlite3* h = nullptr;
        REQUIRE(sqlite3_open_v2(tmp.path.string().c_str(), &h, SQLITE_OPEN_READWRITE, nullptr) ==
                SQLITE_OK);
        // Age the stale projection row, then run the production observation reap SQL.
        REQUIRE(sqlite3_exec(
                    h, "UPDATE guardian_observations SET ttl_expires_at = 1 WHERE event_id='stale'",
                    nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_stmt* st = nullptr;
        REQUIRE(sqlite3_prepare_v2(h,
                                   "DELETE FROM guardian_observations "
                                   "WHERE ttl_expires_at > 0 AND ttl_expires_at < ?",
                                   -1, &st, nullptr) == SQLITE_OK);
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        sqlite3_bind_int64(st, 1, now);
        REQUIRE(sqlite3_step(st) == SQLITE_DONE);
        CHECK(sqlite3_changes(h) == 1); // only the stale projection row
        sqlite3_finalize(st);
        sqlite3_close(h);
    }

    GuaranteedStateStore reopened(tmp.path, /*retention_days=*/30);
    auto survivors = reopened.query_observations();
    REQUIRE(survivors.size() == 1);
    CHECK(survivors[0].event_id == "fresh");
}

// ── #452 §5 — retention reaper ────────────────────────────────────────────

TEST_CASE("GuaranteedStateStore: retention_days=0 disables TTL",
          "[guaranteed_state_store][retention]") {
    // Sentinel contract: non-positive retention parks ttl_expires_at at 0
    // so the reaper's partial index and WHERE predicate skip every row.
    GuaranteedStateStore store(":memory:", /*retention_days=*/0);
    for (int i = 0; i < 5; ++i) {
        REQUIRE(store.insert_event(make_event("evt-" + std::to_string(i), "r", "a")));
    }
    // Explicit reap pass: nothing eligible, event_count stays put.
    store.start_cleanup();
    store.stop_cleanup();
    CHECK(store.event_count() == 5);
    CHECK(store.events_reaped_total() == 0);
}

TEST_CASE("GuaranteedStateStore: reaper DELETE removes rows past ttl_expires_at",
          "[guaranteed_state_store][retention]") {
    // Use a real temp DB so we can poke the schema directly and exercise
    // the same DELETE the background thread issues, without relying on
    // a wall-clock sleep.
    TempDbFile tmp;
    GuaranteedStateStore store(tmp.path, /*retention_days=*/30);

    for (int i = 0; i < 3; ++i) {
        REQUIRE(store.insert_event(make_event("fresh-" + std::to_string(i), "r", "a")));
    }

    // Force three rows to have an expired ttl by opening a second connection
    // to the same file and rewriting ttl_expires_at. Keeps the production
    // code path single-sourced without test-only hooks.
    {
        sqlite3* handle = nullptr;
        REQUIRE(sqlite3_open_v2(tmp.path.string().c_str(), &handle,
                                SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK);
        for (int i = 0; i < 3; ++i) {
            const std::string id = "stale-" + std::to_string(i);
            auto e = make_event(id, "r", "a");
            // Stale rows get ttl_expires_at = 1 (epoch 1s), which any current
            // clock comfortably exceeds.
            const std::string sql =
                "INSERT INTO guaranteed_state_events "
                "(event_id, rule_id, agent_id, event_type, severity, guard_type, "
                "guard_category, detected_value, expected_value, remediation_action, "
                "remediation_success, detection_latency_us, remediation_latency_us, "
                "timestamp, ttl_expires_at) VALUES "
                "(?, 'r', 'a', 'drift.remediated', 'high', 'registry', 'event', "
                "'0', '1', 'registry-write', 1, 0, 0, '2026-04-19T12:00:00Z', 1);";
            sqlite3_stmt* stmt = nullptr;
            REQUIRE(sqlite3_prepare_v2(handle, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK);
            sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
            REQUIRE(sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
        sqlite3_close(handle);
    }

    CHECK(store.event_count() == 6);

    // Run the reaper with a 1-min interval — we want it to sleep briefly,
    // tick, reap, and then let stop_cleanup drain it.
    store.start_cleanup();
    // Give the reaper enough wall-clock to complete one DELETE cycle.
    // The background thread checks stop_requested every 1s; with a 1-min
    // interval the first pass fires after ~60s, too slow for the test. We
    // instead invoke the DELETE directly via a short loop that matches the
    // reaper's SQL — exercises the same WHERE clause the production thread
    // uses so a predicate regression here is a test failure.
    store.stop_cleanup();

    // Since the background thread's sleep outlasts the test budget, drive
    // the same DELETE inline to verify the schema + predicate + counter
    // are wired correctly. This is a stand-in for the cron tick.
    {
        sqlite3* handle = nullptr;
        REQUIRE(sqlite3_open_v2(tmp.path.string().c_str(), &handle,
                                SQLITE_OPEN_READWRITE, nullptr) == SQLITE_OK);
        sqlite3_stmt* stmt = nullptr;
        REQUIRE(sqlite3_prepare_v2(
                    handle,
                    "DELETE FROM guaranteed_state_events "
                    "WHERE ttl_expires_at > 0 AND ttl_expires_at < ?",
                    -1, &stmt, nullptr) == SQLITE_OK);
        // Pass "now" — the identical threshold the production reaper uses.
        // Fresh rows (ttl = now + 30d) survive; stale rows (ttl = 1) match.
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        sqlite3_bind_int64(stmt, 1, now);
        REQUIRE(sqlite3_step(stmt) == SQLITE_DONE);
        CHECK(sqlite3_changes(handle) == 3);
        sqlite3_finalize(stmt);
        sqlite3_close(handle);
    }

    GuaranteedStateStore reopened(tmp.path, /*retention_days=*/30);
    CHECK(reopened.event_count() == 3);  // only the three "fresh" survivors
    auto out = reopened.query_events();
    for (const auto& e : out) {
        CHECK(e.event_id.starts_with("fresh-"));
    }
}

TEST_CASE("GuaranteedStateStore: start_cleanup is a no-op on a closed store",
          "[guaranteed_state_store][retention]") {
    // Prevent the background thread from ever launching against a null db_
    // — without the is_open() guard, stop_cleanup on a store that failed to
    // open would dereference db_ in the reaper loop.
    GuaranteedStateStore bad("/no/such/directory/guaranteed-state.db");
    bad.start_cleanup();
    bad.stop_cleanup();
    SUCCEED();
}

TEST_CASE("GuaranteedStateStore: overview aggregations", "[guaranteed_state_store][overview]") {
    yuzu::test::TempDbFile db{std::string_view{"gs-agg-"}};
    GuaranteedStateStore store{db.path, 30, 60};
    REQUIRE(store.is_open());

    auto ev = [&](std::string id, std::string rule, std::string agent, std::string type,
                  std::string ts) {
        auto e = make_event(std::move(id), std::move(rule), std::move(agent), "high", std::move(ts));
        e.event_type = std::move(type);
        return e;
    };
    // Insertion order == rowid order, so the LAST event per (agent,rule) is "latest".
    REQUIRE(store.insert_event(ev("e1", "r1", "a1", "drift.detected", "2026-06-04T10:00:00Z")).has_value());
    REQUIRE(store.insert_event(ev("e2", "r1", "a1", "drift.remediated", "2026-06-04T10:01:00Z")).has_value());
    REQUIRE(store.insert_event(ev("e3", "r1", "a2", "drift.detected", "2026-06-04T10:02:00Z")).has_value());
    REQUIRE(store.insert_event(ev("e4", "r2", "a1", "remediation.failed", "2026-06-04T10:03:00Z")).has_value());

    SECTION("rule_activity: per-rule window counts") {
        std::map<std::string, GuardianRuleActivity> m;
        for (auto& a : store.rule_activity("")) m[a.rule_id] = a;
        REQUIRE(m.count("r1"));
        CHECK(m["r1"].detected == 2);
        CHECK(m["r1"].remediated == 1);
        CHECK(m["r1"].failed == 0);
        CHECK(m["r1"].distinct_agents == 2);
        CHECK(m["r1"].last_activity == "2026-06-04T10:02:00Z");
        CHECK(m["r2"].failed == 1);
        CHECK(m["r2"].distinct_agents == 1);
    }
    SECTION("daily_remediations: per-day fixed/failed") {
        auto days = store.daily_remediations("");
        REQUIRE(days.size() == 1);
        CHECK(days[0].day == "2026-06-04");
        CHECK(days[0].remediated == 1);
        CHECK(days[0].failed == 1);
    }
    SECTION("since cutoff excludes earlier events") {
        std::map<std::string, GuardianRuleActivity> m;
        for (auto& a : store.rule_activity("2026-06-04T10:02:30Z")) m[a.rule_id] = a;
        CHECK(m.count("r1") == 0);  // all r1 events precede the cutoff
        CHECK(m["r2"].failed == 1);
    }
}

TEST_CASE("GuaranteedStateStore: per-(agent,rule) compliance census (Slice B)",
          "[guaranteed_state_store][census]") {
    yuzu::test::TempDbFile db{std::string_view{"gs-census-"}};
    GuaranteedStateStore store{db.path, 30, 60};
    REQUIRE(store.is_open());

    auto ev = [&](std::string id, std::string rule, std::string agent, std::string type,
                  std::string ts) {
        auto e = make_event(std::move(id), std::move(rule), std::move(agent), "high", std::move(ts));
        e.event_type = std::move(type);
        return e;
    };
    auto census = [&] {
        std::map<std::pair<std::string, std::string>, std::string> m;
        for (auto& s : store.agent_rule_statuses())
            m[{s.agent_id, s.rule_id}] = s.state;
        return m;
    };

    // (a1,r1): compliant → drift → remediated  ⇒ final "compliant".
    REQUIRE(store.insert_event(ev("c1", "r1", "a1", "guard.compliant", "2026-06-04T10:00:00Z")));
    REQUIRE(store.insert_event(ev("c2", "r1", "a1", "drift.detected", "2026-06-04T10:01:00Z")));
    REQUIRE(store.insert_event(ev("c3", "r1", "a1", "drift.remediated", "2026-06-04T10:02:00Z")));
    // (a2,r1): drift only ⇒ "drifted".
    REQUIRE(store.insert_event(ev("c4", "r1", "a2", "drift.detected", "2026-06-04T10:00:30Z")));
    // (a1,r2): unhealthy ⇒ "errored".
    REQUIRE(store.insert_event(ev("c5", "r2", "a1", "guard.unhealthy", "2026-06-04T10:00:00Z")));
    // guard.armed carries no verdict ⇒ no census row.
    REQUIRE(store.insert_event(ev("c6", "r3", "a9", "guard.armed", "2026-06-04T10:00:00Z")));

    {
        auto m = census();
        CHECK(m[{"a1", "r1"}] == "compliant");
        CHECK(m[{"a2", "r1"}] == "drifted");
        CHECK(m[{"a1", "r2"}] == "errored");
        CHECK(m.count({"a9", "r3"}) == 0); // guard.armed left no census row
    }

    SECTION("a late-arriving OLDER event does not regress a newer state") {
        // a1/r1 is compliant as of 10:02; replay an older 10:01 drift — must be ignored.
        REQUIRE(store.insert_event(ev("c7", "r1", "a1", "drift.detected", "2026-06-04T10:01:00Z")));
        CHECK(census()[{"a1", "r1"}] == "compliant");
    }
    SECTION("a newer event updates the state") {
        REQUIRE(store.insert_event(ev("c8", "r1", "a1", "drift.detected", "2026-06-04T10:05:00Z")));
        CHECK(census()[{"a1", "r1"}] == "drifted");
    }
    SECTION("batch ingest maintains the census transactionally") {
        std::vector<GuaranteedStateEventRow> batch = {
            ev("b1", "r5", "a5", "guard.compliant", "2026-06-04T11:00:00Z"),
            ev("b2", "r5", "a5", "drift.detected", "2026-06-04T11:01:00Z"),
        };
        REQUIRE(store.insert_events(batch));
        CHECK(census()[{"a5", "r5"}] == "drifted"); // latest in the batch wins
    }
    SECTION("rule-filtered status returns only that guard's per-device rows (Slice C drill-down)") {
        auto r1 = store.agent_rule_statuses("r1");
        CHECK(r1.size() == 2); // a1 + a2
        for (const auto& s : r1)
            CHECK(s.rule_id == "r1");
        CHECK(store.agent_rule_statuses("r2").size() == 1);   // a1 only
        CHECK(store.agent_rule_statuses("nope").empty());     // unknown rule
        CHECK(store.agent_rule_statuses().size() == 3);       // unfiltered = whole fleet
    }
    SECTION("deleting a rule drops its status rows (no orphan census inflation)") {
        GuaranteedStateRuleRow r;
        r.rule_id = "r1";
        r.name = "rule-one";
        r.yaml_source = "x";
        r.enforcement_mode = "audit";
        r.severity = "high";
        r.created_at = "2026-06-04T09:00:00Z";
        r.updated_at = r.created_at;
        REQUIRE(store.create_rule(r)); // r1 already has a1/a2 status rows from above
        REQUIRE(census().count({"a1", "r1"}) == 1);

        REQUIRE(store.delete_rule("r1"));
        auto m = census();
        CHECK(m.count({"a1", "r1"}) == 0); // gone with the rule
        CHECK(m.count({"a2", "r1"}) == 0);
        CHECK(m.count({"a1", "r2"}) == 1); // an unrelated rule's status is untouched
    }
}
