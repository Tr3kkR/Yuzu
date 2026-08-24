/**
 * Pure unit tests for the shared per-agent Response-scope filter loop
 * (`server/core/src/response_scope_filter.hpp`, #1712).
 *
 * WHY THIS FILE IS PURE (no ResponseStore, no PostgreSQL, no HTTP): the loop
 * is templated on the row type precisely so its contract can be pinned against
 * a two-field fixture struct. The two production readers that use it
 * (`/fragments/results` in dashboard_routes.cpp, the executions drawer in
 * workflow_routes.cpp) each have their own end-to-end `[pg]`-gated wiring
 * guard proving the predicate is actually wired; those are expensive and
 * belong at that level. The LOOP's own semantics — fail-closed on deny,
 * per-distinct-agent memoization, the distinct-agent drop count that feeds the
 * CC7.2 audit row, and the mid-iteration degrade shape — are decided here at
 * zero I/O cost, which is what CLAUDE.md's test-efficiency discipline asks for
 * ("pure core, thin shell"; server shards are the bottleneck).
 *
 * #1712 named two regression shapes. CH-1 (corrupt/deny-all store -> zero
 * rows) is covered end-to-end at both call sites AND here. CH-2 (a store-read
 * fault arising MID-STEP rather than up front) is covered at two levels: the
 * decision primitive fails closed on a genuinely broken store
 * (test_list_read_confinement.cpp drops a confinement table mid-flight and
 * asserts check_scoped_permission then denies), and the reader-level residue —
 * what this loop does when the predicate starts admitting and then flips to
 * denying partway through the fan-out — is pinned below. The readers
 * themselves hold only a std::function and can never observe a SQLite/PG fault
 * directly, so "flips to deny mid-iteration" IS the mid-step fault as this
 * layer can experience it.
 */

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

#include "response_scope_filter.hpp"

namespace yuzu::server {
namespace {

/// Minimal stand-in for StoredResponse — the filter only ever reads agent_id.
struct Row {
    std::string agent_id;
    std::string payload;
};

std::vector<std::string> agent_ids_of(const std::vector<Row>& rows) {
    std::vector<std::string> out;
    out.reserve(rows.size());
    for (const auto& r : rows)
        out.push_back(r.agent_id);
    return out;
}

} // namespace

TEST_CASE("filter_rows_in_scope: a deny-all predicate (corrupt-rbac store) yields "
          "zero rows, never the fleet",
          "[server][response_scope_filter][1712]") {
    std::vector<Row> rows{{"agent-a", "secret-a"}, {"agent-b", "secret-b"},
                          {"agent-a", "secret-a2"}};

    const auto result = filter_rows_in_scope(
        rows, "confined-operator", [](const std::string&, const std::string&) { return false; });

    CHECK(rows.empty());
    // Two DISTINCT agents dropped, though three rows were withheld — the
    // audit row answers "whose data was withheld", not "how many rows".
    CHECK(result.dropped_agents == 2);
}

TEST_CASE("filter_rows_in_scope: only affirmatively-admitted agents survive",
          "[server][response_scope_filter][1712]") {
    std::vector<Row> rows{{"agent-in", "keep-1"},
                          {"agent-out", "drop-1"},
                          {"agent-in", "keep-2"},
                          {"agent-other", "drop-2"}};

    const auto result = filter_rows_in_scope(
        rows, "confined-operator",
        [](const std::string&, const std::string& agent_id) { return agent_id == "agent-in"; });

    CHECK(agent_ids_of(rows) == std::vector<std::string>{"agent-in", "agent-in"});
    CHECK(rows[0].payload == "keep-1");
    CHECK(rows[1].payload == "keep-2");
    CHECK(result.dropped_agents == 2); // agent-out, agent-other
}

TEST_CASE("filter_rows_in_scope: the username is forwarded to the predicate unchanged",
          "[server][response_scope_filter][1712]") {
    std::vector<Row> rows{{"agent-a", "x"}};
    std::string seen_user;

    filter_rows_in_scope(rows, "alice",
                         [&](const std::string& username, const std::string&) {
                             seen_user = username;
                             return true;
                         });

    CHECK(seen_user == "alice");
    CHECK(rows.size() == 1);
}

TEST_CASE("filter_rows_in_scope: the predicate runs at most once per DISTINCT agent",
          "[server][response_scope_filter][1712]") {
    std::vector<Row> rows;
    for (int i = 0; i < 10; ++i)
        rows.push_back({"agent-a", "row"});
    for (int i = 0; i < 10; ++i)
        rows.push_back({"agent-b", "row"});

    int calls = 0;
    filter_rows_in_scope(rows, "operator",
                         [&](const std::string&, const std::string&) {
                             ++calls;
                             return true;
                         });

    // 20 rows, 2 distinct agents — an unmemoized loop would re-run the RBAC
    // check 20 times.
    CHECK(calls == 2);
    CHECK(rows.size() == 20);
}

TEST_CASE("filter_rows_in_scope #1712 CH-2: a predicate that degrades to deny "
          "mid-iteration drops every agent not already decided",
          "[server][response_scope_filter][1712]") {
    // The mid-step store-read fault as this layer can experience it: the first
    // agent is decided while the store still answers, then the store breaks
    // and `response_agent_in_scope` denies everything thereafter.
    std::vector<Row> rows{{"agent-early", "decided-while-healthy"},
                          {"agent-late-1", "decided-after-degrade"},
                          {"agent-late-2", "decided-after-degrade"}};

    bool store_healthy = true;
    const auto result =
        filter_rows_in_scope(rows, "operator", [&](const std::string&, const std::string&) {
            const bool answer = store_healthy;
            store_healthy = false; // degrade immediately after the first decision
            return answer;
        });

    // Fail-closed: the degrade withholds everything it had not already
    // admitted. It must never widen retroactively.
    CHECK(agent_ids_of(rows) == std::vector<std::string>{"agent-early"});
    CHECK(result.dropped_agents == 2);
}

TEST_CASE("filter_rows_in_scope #1712 CH-2: an agent already ADMITTED before a "
          "mid-iteration degrade is not retroactively widened to others",
          "[server][response_scope_filter][1712]") {
    // Interleaved so the admitted agent recurs AFTER the degrade — its later
    // rows ride the memoized admit (by design, and bounded to that one agent),
    // while a newly-seen agent is denied.
    std::vector<Row> rows{{"agent-a", "1"}, {"agent-b", "2"}, {"agent-a", "3"}};

    int decisions = 0;
    const auto result =
        filter_rows_in_scope(rows, "operator", [&](const std::string&, const std::string&) {
            return ++decisions == 1; // only the very first decision admits
        });

    CHECK(agent_ids_of(rows) == std::vector<std::string>{"agent-a", "agent-a"});
    CHECK(result.dropped_agents == 1); // agent-b only
    CHECK(decisions == 2);             // one per distinct agent, not per row
}

TEST_CASE("filter_rows_in_scope: an empty input is a no-op with no predicate calls",
          "[server][response_scope_filter][1712]") {
    std::vector<Row> rows;
    int calls = 0;

    const auto result = filter_rows_in_scope(rows, "operator",
                                             [&](const std::string&, const std::string&) {
                                                 ++calls;
                                                 return true;
                                             });

    CHECK(rows.empty());
    CHECK(calls == 0);
    CHECK(result.dropped_agents == 0);
}

} // namespace yuzu::server
