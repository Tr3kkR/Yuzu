/**
 * test_legacy_executions_scope_authz.cpp — #3789: legacy `/api/executions*`
 * management-group confinement.
 *
 * Three layers, mirroring test_response_execution_scope_authz.cpp's #1634
 * shape:
 *   1. Pure execution_scope_rules.hpp unit tests — no I/O, no PG.
 *   2. A real-rig (PG) confinement test proving `require_fleet_read`'s
 *      resolved scope actually excludes an out-of-scope agent for Bob.
 *   3. Source tripwires proving every one of the 7 migrated routes in
 *      server.cpp actually calls the fleet gate + the shared rule helpers,
 *      not a hand-copied loop (the terminal-status-only counting bug
 *      recurred twice on the sibling #1634 workstream from exactly that
 *      kind of copy-paste).
 */

#include "authz_model.hpp"
#include "execution_scope_rules.hpp"
#include "test_response_execution_authz_pg_helper.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

httplib::Request bearer_request(const std::string& token) {
    httplib::Request req;
    req.set_header("Authorization", "Bearer " + token);
    return req;
}

#ifndef YUZU_SERVER_SRC_DIR
#error "YUZU_SERVER_SRC_DIR must be injected by tests/meson.build."
#endif

std::string read_server_cpp() {
    std::ifstream input(std::filesystem::path(YUZU_SERVER_SRC_DIR) / "server.cpp");
    REQUIRE(input.is_open());
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::string route_block(const std::string& source, const std::string& marker) {
    const auto begin = source.find(marker);
    REQUIRE(begin != std::string::npos);
    const auto end = source.find("web_server_->", begin + marker.size());
    return source.substr(begin, (end == std::string::npos ? source.size() : end) - begin);
}

AgentExecStatus make_status(const std::string& agent_id, const std::string& status,
                           int64_t completed_at = 0, const std::string& error_detail = "") {
    AgentExecStatus a;
    a.agent_id = agent_id;
    a.status = status;
    a.completed_at = completed_at;
    a.error_detail = error_detail;
    return a;
}

Execution make_exec(const std::string& dispatched_by, int agents_targeted) {
    Execution e;
    e.id = "exec-1";
    e.dispatched_by = dispatched_by;
    e.agents_targeted = agents_targeted;
    return e;
}

} // namespace

// ── execution_visible ──────────────────────────────────────────────────────

TEST_CASE("execution_visible: unconfined caller sees everything", "[execution][scope][3789]") {
    auto exec = make_exec("alice", 1);
    CHECK(execution_visible(exec, {}, std::nullopt, "bob"));
}

TEST_CASE("execution_visible: empty username never matches an empty dispatched_by",
          "[execution][scope][3789]") {
    Execution exec; // dispatched_by defaults to ""
    exec.agents_targeted = 0;
    authz::VisibleSet scope = authz::deny_all();
    CHECK_FALSE(execution_visible(exec, {}, scope, /*username=*/""));
}

TEST_CASE("execution_visible: dispatcher sees their own execution before any "
          "agent has responded (zero status rows)",
          "[execution][scope][3789]") {
    auto exec = make_exec("bob", 3);
    authz::VisibleSet scope = authz::deny_all();
    CHECK(execution_visible(exec, {}, scope, "bob"));
}

TEST_CASE("execution_visible: a non-dispatcher confined caller with zero status "
          "rows cannot see a teammate's execution",
          "[execution][scope][3789]") {
    auto exec = make_exec("alice", 3);
    authz::VisibleSet scope = authz::deny_all();
    CHECK_FALSE(execution_visible(exec, {}, scope, "bob"));
}

TEST_CASE("execution_visible: a visible agent's status row admits a non-dispatcher",
          "[execution][scope][3789]") {
    auto exec = make_exec("alice", 1);
    std::vector<AgentExecStatus> statuses{make_status("bob-agent", "success")};
    authz::VisibleSet scope{std::unordered_set<std::string>{"bob-agent"}};
    CHECK(execution_visible(exec, statuses, scope, "bob"));
}

TEST_CASE("execution_visible: an out-of-scope agent's status row does not admit",
          "[execution][scope][3789]") {
    auto exec = make_exec("alice", 1);
    std::vector<AgentExecStatus> statuses{make_status("alice-agent", "success")};
    authz::VisibleSet scope{std::unordered_set<std::string>{"bob-agent"}};
    CHECK_FALSE(execution_visible(exec, statuses, scope, "bob"));
}

TEST_CASE("execution_visible: full scan, no early exit on the first invisible row",
          "[execution][scope][3789]") {
    auto exec = make_exec("alice", 2);
    std::vector<AgentExecStatus> statuses{make_status("alice-agent", "success"),
                                          make_status("bob-agent", "success")};
    authz::VisibleSet scope{std::unordered_set<std::string>{"bob-agent"}};
    CHECK(execution_visible(exec, statuses, scope, "bob"));
}

// ── confined_projection ────────────────────────────────────────────────────

TEST_CASE("confined_projection: running is never counted as responded",
          "[execution][scope][3789]") {
    std::vector<AgentExecStatus> statuses{make_status("bob-agent", "running")};
    authz::VisibleSet scope{std::unordered_set<std::string>{"bob-agent"}};
    auto counts = confined_projection(statuses, scope);
    CHECK(counts.agents_targeted == 1);
    CHECK(counts.agents_responded == 0);
    CHECK(counts.agents_success == 0);
    CHECK(counts.agents_failure == 0);
}

TEST_CASE("confined_projection: timeout and rejected count as failure, success as success",
          "[execution][scope][3789]") {
    std::vector<AgentExecStatus> statuses{
        make_status("a1", "success"),
        make_status("a2", "timeout"),
        make_status("a3", "rejected"),
        make_status("a4", "failure"),
    };
    authz::VisibleSet scope{std::unordered_set<std::string>{"a1", "a2", "a3", "a4"}};
    auto counts = confined_projection(statuses, scope);
    CHECK(counts.agents_targeted == 4);
    CHECK(counts.agents_responded == 4);
    CHECK(counts.agents_success == 1);
    CHECK(counts.agents_failure == 3);
}

TEST_CASE("confined_projection: out-of-scope rows are excluded from every count",
          "[execution][scope][3789]") {
    std::vector<AgentExecStatus> statuses{make_status("bob-agent", "success"),
                                          make_status("alice-agent", "success")};
    authz::VisibleSet scope{std::unordered_set<std::string>{"bob-agent"}};
    auto counts = confined_projection(statuses, scope);
    CHECK(counts.agents_targeted == 1);
    CHECK(counts.agents_responded == 1);
}

TEST_CASE("confined_projection: last_error_detail is the newest in-scope error",
          "[execution][scope][3789]") {
    std::vector<AgentExecStatus> statuses{
        make_status("bob-agent", "failure", /*completed_at=*/100, "first error"),
        make_status("bob-agent-2", "failure", /*completed_at=*/200, "second error"),
    };
    authz::VisibleSet scope{std::unordered_set<std::string>{"bob-agent", "bob-agent-2"}};
    auto counts = confined_projection(statuses, scope);
    CHECK(counts.last_error_detail == "second error");
}

// ── admit_confined_mutation ─────────────────────────────────────────────────

TEST_CASE("admit_confined_mutation: zero status rows admits only the dispatcher",
          "[execution][scope][3789]") {
    auto exec = make_exec("bob", 2);
    authz::VisibleSet scope = authz::deny_all();
    CHECK(admit_confined_mutation(exec, {}, scope, "bob"));
    CHECK_FALSE(admit_confined_mutation(exec, {}, scope, "alice"));
    CHECK_FALSE(admit_confined_mutation(exec, {}, scope, /*username=*/""));
}

TEST_CASE("admit_confined_mutation: complete cohort, all in scope, admits — even "
          "a non-dispatcher",
          "[execution][scope][3789]") {
    auto exec = make_exec("alice", 2);
    std::vector<AgentExecStatus> statuses{make_status("bob-agent", "success"),
                                          make_status("bob-agent-2", "running")};
    authz::VisibleSet scope{std::unordered_set<std::string>{"bob-agent", "bob-agent-2"}};
    CHECK(admit_confined_mutation(exec, statuses, scope, "bob"));
}

TEST_CASE("admit_confined_mutation: an out-of-scope row denies, even for the "
          "dispatcher — full visibility has no ownership bypass once rows exist",
          "[execution][scope][3789]") {
    auto exec = make_exec("bob", 2);
    std::vector<AgentExecStatus> statuses{make_status("bob-agent", "success"),
                                          make_status("alice-agent", "success")};
    authz::VisibleSet scope{std::unordered_set<std::string>{"bob-agent"}};
    CHECK_FALSE(admit_confined_mutation(exec, statuses, scope, "bob"));
}

TEST_CASE("admit_confined_mutation: an incomplete target ledger denies even when "
          "every EXISTING row is in scope (the false-admission path)",
          "[execution][scope][3789]") {
    // agents_targeted == 2 but only one status row exists yet — the second
    // targeted agent's identity (and scope membership) is unknown.
    auto exec = make_exec("bob", 2);
    std::vector<AgentExecStatus> statuses{make_status("bob-agent", "success")};
    authz::VisibleSet scope{std::unordered_set<std::string>{"bob-agent"}};
    CHECK_FALSE(admit_confined_mutation(exec, statuses, scope, "bob"));
}

TEST_CASE("admit_confined_mutation: a row count exceeding agents_targeted also denies",
          "[execution][scope][3789]") {
    auto exec = make_exec("bob", 1);
    std::vector<AgentExecStatus> statuses{make_status("bob-agent", "success"),
                                          make_status("bob-agent-2", "success")};
    authz::VisibleSet scope{std::unordered_set<std::string>{"bob-agent", "bob-agent-2"}};
    CHECK_FALSE(admit_confined_mutation(exec, statuses, scope, "bob"));
}

TEST_CASE("admit_confined_mutation: a negative agents_targeted denies rather than "
          "admitting via a static_cast<int> row-count mismatch (unhappy-path UP-4)",
          "[execution][scope][3789]") {
    // A corrupt/negative agents_targeted can never equal a non-negative
    // status-row count, so this fails closed on the same `!=` comparison
    // that guards the ordinary incomplete/excess-ledger cases — pinning
    // that as a regression test rather than leaving it implicit.
    auto exec = make_exec("bob", -1);
    std::vector<AgentExecStatus> statuses{make_status("bob-agent", "success")};
    authz::VisibleSet scope{std::unordered_set<std::string>{"bob-agent"}};
    CHECK_FALSE(admit_confined_mutation(exec, statuses, scope, "bob"));
}

// ── Real-rig confinement (PG) ───────────────────────────────────────────────

TEST_CASE("legacy executions: real fleet-read scope excludes Alice's agent for Bob",
          "[pg][execution][scope][3789]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    yuzu::test::ResponseExecutionAuthzPgRig rig{db.dsn()};
    auto req = bearer_request(rig.mint_bob());
    httplib::Response res;
    auto authority = rig.auth_routes->require_fleet_read(req, res, "Execution", "Read");
    REQUIRE(authority.has_value());
    const auto scope = authority->visible_for_query();

    auto exec = make_exec("someone-else", 2);
    std::vector<AgentExecStatus> statuses{make_status("bob-agent", "success"),
                                          make_status("alice-agent", "success")};
    CHECK(execution_visible(exec, statuses, scope, "bob"));
    auto counts = confined_projection(statuses, scope);
    CHECK(counts.agents_targeted == 1); // only bob-agent's row counted
}

TEST_CASE("legacy executions: Bob's global Execute grant admits a complete, "
          "in-scope mutation cohort",
          "[pg][execution][scope][3789]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::response_execution_authz_tpl);
    yuzu::test::ResponseExecutionAuthzPgRig rig{db.dsn()};
    auto req = bearer_request(rig.mint_bob());
    httplib::Response res;
    auto exec_perm = rig.auth_routes->require_permission(req, res, "Execution", "Execute");
    CHECK(exec_perm);

    auto read_authority = rig.auth_routes->require_fleet_read(req, res, "Execution", "Read");
    REQUIRE(read_authority.has_value());
    const auto scope = read_authority->visible_for_query();

    auto exec = make_exec("bob", 1);
    std::vector<AgentExecStatus> statuses{make_status("bob-agent", "success")};
    CHECK(admit_confined_mutation(exec, statuses, scope, "bob"));

    // Alice's execution, targeting only Alice's agent, must still be denied.
    auto alice_exec = make_exec("alice", 1);
    std::vector<AgentExecStatus> alice_statuses{make_status("alice-agent", "success")};
    CHECK_FALSE(admit_confined_mutation(alice_exec, alice_statuses, scope, "bob"));
}

// ── Source tripwires ─────────────────────────────────────────────────────────

TEST_CASE("legacy executions routes: every route retains the fleet gate, not the "
          "bare flat permission gate",
          "[execution][scope][3789][source_tripwire]") {
    const auto source = read_server_cpp();
    const auto list_route = route_block(source, R"(web_server_->Get("/api/executions",)");
    const auto detail = route_block(source, R"(/api/executions/([^/]+))");
    const auto summary = route_block(source, R"(/api/executions/([^/]+)/summary)");
    const auto agents = route_block(source, R"(/api/executions/([^/]+)/agents)");
    const auto rerun = route_block(source, R"(/api/executions/([^/]+)/rerun)");
    const auto cancel = route_block(source, R"(/api/executions/([^/]+)/cancel)");
    const auto children = route_block(source, R"(/api/executions/([^/]+)/children)");

    for (const auto* block :
        {&list_route, &detail, &summary, &agents, &rerun, &cancel, &children}) {
        CHECK(block->find(R"(require_fleet_read(req, res, "Execution", "Read"))") !=
              std::string::npos);
        CHECK(block->find(R"(require_permission(req, res, "Execution", "Read"))") ==
              std::string::npos);
    }
    // Mutations additionally keep the pre-existing Execute permission gate —
    // the fleet gate is structurally Read-only (authz_gates.cpp) and cannot
    // replace it.
    for (const auto* block : {&rerun, &cancel}) {
        CHECK(block->find(R"(require_permission(req, res, "Execution", "Execute"))") !=
              std::string::npos);
    }
}

TEST_CASE("legacy executions detail route: redaction literal and checked reads "
          "are present, unchecked get_execution/get_agent_statuses are not",
          "[execution][scope][3789][source_tripwire]") {
    const auto source = read_server_cpp();
    const auto detail = route_block(source, R"(/api/executions/([^/]+))");
    CHECK(detail.find("(redacted - confined view)") != std::string::npos);
    CHECK(detail.find("get_execution_checked") != std::string::npos);
    CHECK(detail.find("execution_visible") != std::string::npos);
    CHECK(detail.find("confined_projection") != std::string::npos);
    // last_error_detail must NOT be introduced into this legacy payload's
    // JSON output (a source comment nearby explains why, hence checking the
    // field-emission shape specifically rather than the bare substring).
    CHECK(detail.find(R"({"last_error_detail")") == std::string::npos);
}

TEST_CASE("legacy executions agents route: filters to in-scope agents via the "
          "checked status read",
          "[execution][scope][3789][source_tripwire]") {
    const auto source = read_server_cpp();
    const auto agents = route_block(source, R"(/api/executions/([^/]+)/agents)");
    CHECK(agents.find("get_agent_statuses_checked") != std::string::npos);
    CHECK(agents.find("authz::in_scope") != std::string::npos);
    CHECK(agents.find("get_execution_checked") != std::string::npos);
}

TEST_CASE("legacy executions list route: SQL scope pushdown precedes the "
          "checked query, and the limit is capped",
          "[execution][scope][3789][source_tripwire]") {
    const auto source = read_server_cpp();
    const auto list_route = route_block(source, R"(web_server_->Get("/api/executions",)");
    CHECK(list_route.find("query_executions_checked") != std::string::npos);
    CHECK(list_route.find("ExecutionListScope") != std::string::npos);
    CHECK(list_route.find("get_agent_statuses_for_executions_checked") != std::string::npos);
    // Exact statement, not a bare "500" substring — a 5000ms retry_after_ms
    // literal in the same block would false-green a "500" find (#3789
    // quality-engineer S1).
    CHECK(list_route.find("q.limit > 500") != std::string::npos);
}

TEST_CASE("legacy executions summary route: unknown-id collapses to 404 for every "
          "caller, not the old zero-filled 200",
          "[execution][scope][3789][source_tripwire]") {
    const auto source = read_server_cpp();
    const auto summary = route_block(source, R"(/api/executions/([^/]+)/summary)");
    CHECK(summary.find("get_execution_checked") != std::string::npos);
    CHECK(summary.find(R"("not found")") != std::string::npos);
    // The old unconditional get_summary()-then-200 shape must be gone.
    CHECK(summary.find("execution_tracker_->get_summary(") == std::string::npos);
}

TEST_CASE("legacy executions children route: each child is checked against the "
          "same visibility predicate as its parent, not truthfully passed through",
          "[execution][scope][3789][source_tripwire]") {
    const auto source = read_server_cpp();
    const auto children = route_block(source, R"(/api/executions/([^/]+)/children)");
    CHECK(children.find("get_children_checked") != std::string::npos);
    CHECK(children.find("get_agent_statuses_for_executions_checked") != std::string::npos);
    CHECK(children.find("execution_visible(c,") != std::string::npos);
}

TEST_CASE("legacy executions rerun/cancel routes: mutation admission uses the "
          "complete-cohort rule, not a bare visibility check",
          "[execution][scope][3789][source_tripwire]") {
    const auto source = read_server_cpp();
    const auto rerun = route_block(source, R"(/api/executions/([^/]+)/rerun)");
    const auto cancel = route_block(source, R"(/api/executions/([^/]+)/cancel)");
    for (const auto* block : {&rerun, &cancel}) {
        CHECK(block->find("admit_confined_mutation") != std::string::npos);
        CHECK(block->find("get_execution_checked") != std::string::npos);
        // #3789 (adversarial review, Kimi+Codex fix round): statuses must
        // be fetched via the checked accessor UNCONDITIONALLY under
        // gate.scope, not only when exec_opt is present — a regression
        // back to the id-conditional shape reopens the DB-round-trip
        // timing/work oracle between "nonexistent" and "hidden" (quality-
        // engineer S2: this pins the fix, not just admit_confined_mutation's
        // presence).
        CHECK(block->find("get_agent_statuses_checked") != std::string::npos);
    }
    // #3789: mark_cancelled's false-success-on-nonexistent-row bug is fixed
    // by an explicit existence check ahead of the mutation call.
    CHECK(cancel.find("if (!exec_opt)") != std::string::npos);
}
