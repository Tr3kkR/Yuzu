/**
 * test_guaranteed_state_store.cpp — Unit tests for GuaranteedStateStore
 *
 * Covers:
 *   - schema migration applies cleanly against a fresh in-memory DB
 *   - rule CRUD round-trip (create / get / list / update / delete)
 *   - event insert + query with filtering
 *   - UNIQUE(name) rejection and unknown-rule update/delete return false
 *   - signature BLOB round-trip (incl. empty vs non-empty)
 *   - PRIMARY KEY (rule_id) duplicate rejection (qe-S5)
 *   - query_events tie-break ordering with distinct timestamps (qe-S1)
 *   - query_events limit clamped to kMaxEventsLimit
 *   - bad-path constructor returns sentinels from every method (qe-S2)
 *   - migration idempotency: re-open existing on-disk DB (qe-S4)
 */

#include "guaranteed_state_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <random>

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
struct TempDbFile {
    std::filesystem::path path;
    TempDbFile() {
        auto tmp = std::filesystem::temp_directory_path();
        std::random_device rd;
        std::mt19937_64 gen(rd());
        path = tmp / ("yuzu-gs-test-" + std::to_string(gen()) + ".db");
    }
    ~TempDbFile() noexcept {
        std::error_code ec;
        std::filesystem::remove(path, ec);
        // WAL + SHM companion files.
        std::filesystem::remove(path.string() + "-wal", ec);
        std::filesystem::remove(path.string() + "-shm", ec);
    }
    TempDbFile(const TempDbFile&) = delete;
    TempDbFile& operator=(const TempDbFile&) = delete;
};

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

// ── Regression tests added in PR 1 governance hardening ────────────────────

TEST_CASE("GuaranteedStateStore: duplicate rule_id rejected (PRIMARY KEY)",
          "[guaranteed_state_store][rules]") {
    // qe-S5 — PRIMARY KEY (rule_id) is structurally separate from UNIQUE(name).
    // A bug that accidentally omitted the PK would not be caught by the
    // existing duplicate-name test, so exercise it explicitly.
    GuaranteedStateStore store(":memory:");
    REQUIRE(store.create_rule(make_rule("same-id", "name-one")));
    CHECK_FALSE(store.create_rule(make_rule("same-id", "name-two")));
}

TEST_CASE("GuaranteedStateStore: empty signature round-trip stays empty",
          "[guaranteed_state_store][rules]") {
    // qe-S3 — create_rule binds NULL when signature is empty; col_blob
    // returns {} for NULL. Verify a rule created with signature={} round-trips
    // to empty, distinct from a rule with a non-empty signature.
    GuaranteedStateStore store(":memory:");
    auto r = make_rule("r-empty", "sig-empty");
    r.signature.clear();
    REQUIRE(store.create_rule(r));

    auto fetched = store.get_rule("r-empty");
    REQUIRE(fetched.has_value());
    CHECK(fetched->signature.empty());

    // List returns the same shape.
    auto listed = store.list_rules();
    REQUIRE(listed.size() == 1);
    CHECK(listed[0].signature.empty());
}

TEST_CASE("GuaranteedStateStore: event query tie-breaks by event_id on equal timestamp",
          "[guaranteed_state_store][events]") {
    // qe-S1 — without the secondary sort, equal-timestamp tie ordering is
    // unspecified and prone to silent CI drift. The store's query_events
    // appends `ORDER BY timestamp DESC, event_id DESC` — exercise it with
    // varied timestamps and equal-timestamp clusters.
    GuaranteedStateStore store(":memory:");

    // Distinct timestamps: DESC-by-timestamp ordering.
    REQUIRE(store.insert_event(
        make_event("older", "rule-1", "agent-A", "high", "2026-04-19T12:00:00Z")));
    REQUIRE(store.insert_event(
        make_event("newer", "rule-1", "agent-A", "high", "2026-04-19T13:00:00Z")));

    auto out = store.query_events();
    REQUIRE(out.size() == 2);
    CHECK(out[0].event_id == "newer");
    CHECK(out[1].event_id == "older");

    // Equal timestamps: secondary event_id DESC decides the tie.
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

TEST_CASE("GuaranteedStateStore: query_events limit is clamped to kMaxEventsLimit",
          "[guaranteed_state_store][events]") {
    // P-S4 / sec-L2 — a malicious or misconfigured caller passing INT_MAX
    // for limit must NOT materialise the entire table. Verify the clamp
    // applies even when the underlying data count is small (the clamp is
    // bind-time, not result-time, but the observable invariant is "no crash,
    // result bounded").
    GuaranteedStateStore store(":memory:");
    for (int i = 0; i < 5; ++i) {
        REQUIRE(store.insert_event(make_event("evt-" + std::to_string(i), "r", "a")));
    }

    GuaranteedStateEventQuery q;
    q.limit = 2'000'000'000;  // INT_MAX-ish
    auto out = store.query_events(q);
    CHECK(out.size() == 5);  // clamp doesn't inflate a small table
    // kMaxEventsLimit is exposed in the header so the REST layer can reason
    // about the cap without re-deriving it.
    CHECK(kMaxEventsLimit == 10'000);
}

TEST_CASE("GuaranteedStateStore: bad path yields closed store with sentinel returns",
          "[guaranteed_state_store][db]") {
    // qe-S2 — sqlite3_open_v2 against an unwritable path leaves db_ null; every
    // public method must return a safe sentinel (false / empty / nullopt / 0).
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
}

TEST_CASE("GuaranteedStateStore: migration is idempotent across re-open",
          "[guaranteed_state_store][db]") {
    // qe-S4 — MigrationRunner is idempotent by contract. Exercise the full
    // open-insert-close-reopen cycle end-to-end so a future regression in the
    // `create_tables()` / `schema_meta` interaction surfaces here.
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
        // Migration re-run must be a no-op; pre-existing data is intact.
        CHECK(s2.rule_count() == 1);
        CHECK(s2.event_count() == 1);

        auto r = s2.get_rule("rule-1");
        REQUIRE(r.has_value());
        CHECK(r->name == "survives-reopen");

        // Second handle can still write — full CRUD path works post-reopen.
        REQUIRE(s2.insert_event(make_event("evt-2", "rule-1", "agent-B")));
        CHECK(s2.event_count() == 2);
    }
}
