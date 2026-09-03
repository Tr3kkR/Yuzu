// Deployment engine advance() over the real store: the stage→execute state machine,
// out-of-scope skip (re-authorization), and execute-once across repeated advances.
// PG-gated (drives the real DeploymentRunStore); the parse layer is covered
// separately in test_deployment_parse.cpp.

#include <catch2/catch_test_macros.hpp>

#include "deployment_engine.hpp"
#include "deployment_run_store.hpp"
#include "pg/pg_pool.hpp"
#include "response_store.hpp"

#include "../test_helpers.hpp"

#include <chrono>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::deployment;
using yuzu::server::pg::PgPool;
using yuzu::server::preflight::PreflightTarget;

namespace {

// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): shared key
// with test_deployment_run_store.cpp (identical setup — first build wins).
yuzu::test::PgTestTemplate deprun_tpl{"deprun", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    DeploymentRunStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("deprun template: store failed to migrate");
}};

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

PreflightTarget tgt(const std::string& aid) { return {aid, "host-" + aid, "windows"}; }

std::string step_of(DeploymentRunStore& s, const std::string& id, const std::string& agent) {
    for (const auto& d : s.get_devices(id))
        if (d.agent_id == agent)
            return d.step;
    return "<absent>";
}

// A test harness: real store + programmable poll responses + a dispatch recorder.
struct Harness {
    DeploymentRunStore& store;
    // poll state: execution_id → (agent → response)
    std::unordered_map<std::string, std::unordered_map<std::string, AgentResponse>> poll;
    // recorded dispatches: (action, agent_ids)
    std::vector<std::pair<std::string, std::vector<std::string>>> dispatched;
    // The DispatchCaller each dispatch call actually received — the
    // production-wiring assertion below reads this, not `dispatched`.
    std::vector<yuzu::server::DispatchCaller> dispatch_callers;

    EngineDeps deps() {
        EngineDeps d;
        d.store = &store;
        d.poll_fn = [this](const std::string& eid) {
            auto it = poll.find(eid);
            return it == poll.end() ? std::unordered_map<std::string, AgentResponse>{} : it->second;
        };
        d.dispatch_fn = [this](const std::string&, const std::string& action,
                               const std::vector<std::string>& agents, const std::string&,
                               const std::unordered_map<std::string, std::string>&,
                               const std::string&,
                               const yuzu::server::DispatchCaller& caller)
            -> yuzu::server::ConfinedDispatchOutcome {
            dispatched.push_back({action, agents});
            dispatch_callers.push_back(caller);
            // deny_dispatch mirrors a chokepoint refusal: dispatch_confined
            // returns {command_id, 0} on a denial (the command_id is minted
            // before classification), so a denied and a zero-reach dispatch
            // are indistinguishable to the engine — which is exactly why the
            // engine must settle the claim on ANY zero-sent outcome.
            return {.sent = deny_dispatch ? 0 : static_cast<int>(agents.size()),
                   .command_id = "cmd"};
        };
        return d;
    }

    bool deny_dispatch{false};

    int dispatch_count(const std::string& action, const std::string& agent) const {
        int n = 0;
        for (const auto& [act, agents] : dispatched)
            if (act == action)
                for (const auto& a : agents)
                    if (a == agent)
                        ++n;
        return n;
    }
};

// The caller every test below advances with, unless a test deliberately
// wants a different one (the production-wiring case just below).
yuzu::server::DispatchCaller test_caller() {
    return yuzu::server::DispatchCaller{.principal = "deploy-op", .principal_role = "Administrator"};
}

DeploymentRow make_dep(const std::string& id) {
    DeploymentRow d;
    d.deployment_id = id;
    d.created_by = "alice";
    d.artifact_filename = "pkg.msi";
    d.artifact_sha256 = std::string(64, 'a');
    d.status = "running";
    d.created_at_ms = now_ms();
    return d;
}

} // namespace

TEST_CASE("best_response_per_agent picks terminal > running, then output, then latest",
          "[deployment][engine]") {
    auto mk = [](const std::string& agent, int status, const std::string& out, std::int64_t ts) {
        StoredResponse r;
        r.agent_id = agent;
        r.status = status;
        r.output = out;
        r.received_at_ms = ts;
        return r;
    };
    std::vector<StoredResponse> rows = {
        mk("a", 0, "", 100),               // running, no output
        mk("a", 1, "status|ok", 90),       // terminal + output (earlier) → wins over running
        mk("b", 2, "", 50),                // terminal, no output
        mk("b", 2, "error|x", 60),         // terminal + output (later) → wins
        mk("c", 0, "", 10),                // only a running row → still surfaced
    };
    auto best = best_response_per_agent(rows);
    REQUIRE(best.size() == 3);
    CHECK(best["a"].status == 1);
    CHECK(best["a"].output == "status|ok");
    CHECK(best["b"].output == "error|x");
    CHECK(best["c"].status == 0); // a not-yet-terminal agent is still represented
}

TEST_CASE("deployment engine drives stage→execute, skips out-of-scope, runs once",
          "[pg][deployment][engine]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deprun_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    DeploymentRunStore store{pool};
    REQUIRE(store.is_open());

    const std::string id = "e1";
    // Cohort a1,a2 in scope; a3 OUT of scope (operator lost it after pre-flight).
    REQUIRE(store.create_deployment(make_dep(id), {tgt("a1"), tgt("a2"), tgt("a3")}));

    Harness h{store};
    auto deps = h.deps();
    DeploymentConfig cfg{"https://repo.lan/pkg.msi", "pkg.msi", std::string(64, 'a'), "/qn"};
    const std::unordered_set<std::string> authorized{"a1", "a2"}; // a3 not authorized

    const std::string stage_eid = stage_execution_id(id);
    const std::string exec_eid = exec_execution_id(id);

    // ── Tick 1: stage dispatched to the authorized pending devices; a3 skipped ──
    advance(deps, id, cfg, authorized, test_caller());
    CHECK(step_of(store, id, "a1") == "staging");
    CHECK(step_of(store, id, "a2") == "staging");
    CHECK(step_of(store, id, "a3") == "skipped"); // re-authorization boundary
    CHECK(h.dispatch_count("stage", "a1") == 1);
    CHECK(h.dispatch_count("stage", "a3") == 0); // never dispatched out of scope

    // ── Tick 2: a1 stages OK → executes; a2 stage FAILS ──
    h.poll[stage_eid] = {{"a1", {1, "status|ok\nstaged_path|/p"}},
                         {"a2", {2, "error|hash mismatch"}}};
    advance(deps, id, cfg, authorized, test_caller());
    CHECK(step_of(store, id, "a1") == "executing");
    CHECK(step_of(store, id, "a2") == "failed");
    CHECK(h.dispatch_count("execute_staged", "a1") == 1);
    CHECK(h.dispatch_count("execute_staged", "a2") == 0); // a stage failure never executes

    // ── Tick 3: a1 execute returns exit 0 → succeeded; deployment completes ──
    h.poll[exec_eid] = {{"a1", {1, "status|ok\nexit_code|0"}}};
    advance(deps, id, cfg, authorized, test_caller());
    CHECK(step_of(store, id, "a1") == "succeeded");
    auto dep = store.get_deployment(id);
    REQUIRE(dep);
    CHECK(dep->status == "complete"); // a1 succeeded, a2 failed, a3 skipped → all settled
    CHECK(dep->succeeded == 1);
    CHECK(dep->failed == 1);
    CHECK(dep->skipped == 1);

    // ── Execute-once: extra advances never re-dispatch the installer to a1 ──
    advance(deps, id, cfg, authorized, test_caller());
    advance(deps, id, cfg, authorized, test_caller());
    CHECK(h.dispatch_count("execute_staged", "a1") == 1); // still exactly one
}

// #3133 round-2 review MEDIUM (falsifier): a caller the chokepoint refuses —
// e.g. holding SoftwareDeployment:Execute but not the Write that
// content_dist.stage is classified as — used to leave every claimed device
// stuck in 'staging' forever: the CAS claim ran BEFORE the dispatch outcome
// was known and the {command_id, 0} refusal was discarded. The rows must
// settle to a terminal step instead of wedging in an active one, and the
// engine must not livelock re-claiming and re-denying on every tick.
TEST_CASE("deployment engine settles a claim to failed when the dispatch is refused, "
          "instead of wedging it in staging",
          "[pg][deployment][engine]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deprun_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    DeploymentRunStore store{pool};
    REQUIRE(store.is_open());

    const std::string id = "e-denied";
    REQUIRE(store.create_deployment(make_dep(id), {tgt("a1"), tgt("a2")}));

    Harness h{store};
    h.deny_dispatch = true; // every dispatch answers {command_id, 0} — a refusal
    auto deps = h.deps();
    DeploymentConfig cfg{"https://repo.lan/pkg.msi", "pkg.msi", std::string(64, 'a'), ""};
    const std::unordered_set<std::string> authorized{"a1", "a2"};

    // Tick 1: both devices are claimed, the dispatch is refused, and the rows
    // settle to terminal 'failed' — never left in 'staging'.
    advance(deps, id, cfg, authorized, test_caller());
    CHECK(h.dispatch_count("stage", "a1") == 1);
    CHECK(step_of(store, id, "a1") == "failed");
    CHECK(step_of(store, id, "a2") == "failed");

    // The error names the refusal, so an operator reading the grid sees why
    // nothing ran rather than a bare failure.
    for (const auto& d : store.get_devices(id))
        CHECK(d.error.find("refused or reached no agents") != std::string::npos);

    // Ticks 2-3: terminal rows are never re-claimed or re-dispatched — no
    // deny-livelock, and the deployment itself settles rather than running
    // forever.
    advance(deps, id, cfg, authorized, test_caller());
    advance(deps, id, cfg, authorized, test_caller());
    CHECK(h.dispatch_count("stage", "a1") == 1); // still exactly one
    auto dep = store.get_deployment(id);
    REQUIRE(dep);
    CHECK(dep->failed == 2);
}

TEST_CASE("deployment engine records a non-zero installer exit as failed",
          "[pg][deployment][engine]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deprun_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    DeploymentRunStore store{pool};
    REQUIRE(store.is_open());

    const std::string id = "e2";
    REQUIRE(store.create_deployment(make_dep(id), {tgt("z1")}));
    Harness h{store};
    auto deps = h.deps();
    DeploymentConfig cfg{"https://repo.lan/pkg.msi", "pkg.msi", std::string(64, 'a'), ""};
    const std::unordered_set<std::string> authorized{"z1"};

    advance(deps, id, cfg, authorized, test_caller()); // stage dispatched
    h.poll[stage_execution_id(id)] = {{"z1", {1, "status|ok\nstaged_path|/p"}}};
    advance(deps, id, cfg, authorized, test_caller()); // staged → executing
    h.poll[exec_execution_id(id)] = {{"z1", {2, "status|error\nexit_code|1603"}}};
    advance(deps, id, cfg, authorized, test_caller()); // executing → failed

    auto devs = store.get_devices(id);
    REQUIRE(devs.size() == 1);
    CHECK(devs[0].step == "failed");
    CHECK(devs[0].exit_code == 1603);
    CHECK(store.get_deployment(id)->status == "complete");
}

// ── H1 production-wiring regression ───────────────────────────────────────
//
// Review finding (post-origin/dev-merge adversarial round): `advance()` had
// no caller parameter at all, so `DeploymentRoutes` fed the shared
// BACKGROUND dispatch closure (`command_dispatch_fn`, `DispatchCaller{.system
// = true}`) to every deploy tick. The chokepoint's `caller.system`
// early-return (`agent_registry.hpp`) admits a system caller unconditionally,
// so `content_dist.stage` — declared `SoftwareDeployment:Write` — dispatched
// under system authority regardless of what the triggering OPERATOR actually
// held. A role with `SoftwareDeployment:Execute` but not `Write` should be
// refused by the chokepoint; under the old wiring it never reached the
// chokepoint's authorization check as itself at all.
//
// This proves the half of the fix reachable from this test binary: that
// `advance()` now threads the CALLER it is given, verbatim, to `dispatch_fn`
// — never silently substituting a system caller. `DeploymentRoutes` itself
// is registered on the raw `httplib::Server&` (not yet migrated onto the
// `HttpRouteSink` seam `RestApiV1`/`WorkflowRoutes` use), so it has no route-
// level test harness in this repo. `caller_from_session` there populates
// `principal`/`principal_role`/`exec_visible` from an injected `ExecVisibleFn`
// (a governance-round follow-up fix: it originally omitted `exec_visible`,
// defaulting it to `nullopt`/unfiltered — the exact shape `dispatch_caller.hpp`
// reserves for a genuine `.system = true` background dispatcher, not an
// operator-triggered one — which made the chokepoint's per-target
// `Execution:Execute` intersection a silent no-op for every deployment
// dispatch; `devices_fn(viewer)∩cohort` above is a DIFFERENT authorization
// dimension, `Infrastructure:Read`/flat group-membership, and does not
// substitute for it). It now matches the sibling pattern
// (rest_api_v1.cpp et al.) field-for-field, unverified at the route level for
// the same route-level-harness-gap reason as the rest of this comment. The
// chokepoint's own enforcement of `SoftwareDeployment:Write` — that
// Execute-without-Write is actually refused — is exhaustively covered
// independently in test_dispatch_chokepoint.cpp for every declared
// capability, unchanged by this fix; what THAT coverage could not see,
// because the parameter did not exist, is proven here.
TEST_CASE("H1: advance() threads the caller it is given to dispatch_fn, never a "
          "system substitute",
          "[pg][deployment][engine][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deprun_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    DeploymentRunStore store{pool};
    REQUIRE(store.is_open());

    const std::string id = "h1";
    REQUIRE(store.create_deployment(make_dep(id), {tgt("w1")}));

    Harness h{store};
    auto deps = h.deps();
    DeploymentConfig cfg{"https://repo.lan/pkg.msi", "pkg.msi", std::string(64, 'a'), ""};
    const std::unordered_set<std::string> authorized{"w1"};

    // A non-Administrator caller a real operator session would carry —
    // deliberately NOT the shared test_caller() helper, so this test does
    // not depend on that helper's own choices.
    const yuzu::server::DispatchCaller live_caller{.principal = "carol",
                                                    .principal_role = "PlatformEngineer"};
    advance(deps, id, cfg, authorized, live_caller);

    REQUIRE_FALSE(h.dispatch_callers.empty());
    const auto& reached = h.dispatch_callers.front();
    // The exact regression: this must be `false` and non-empty. Before the
    // fix there was no parameter to assert on at all — `command_dispatch_fn`
    // was hardcoded at the call site with `.system = true` and an empty
    // principal, so a caller-identity assertion here could not even be
    // expressed against production wiring.
    CHECK_FALSE(reached.system);
    CHECK(reached.principal == "carol");
    CHECK(reached.principal_role == "PlatformEngineer");
}

// #1398: content_dist.{stage,execute_staged} are role-gated content, so their
// compiled dispatch-chokepoint gate is ExecuteGate::AdminOrApproval. Without
// this stamp, a non-admin operator's `/auto` Deploy advance would be denied
// ApprovalRequired at the chokepoint despite the pipeline's own governance
// (creator-authority go-cohort, guarded transitions, execute-once CAS,
// per-tick re-authorization) already being the accepted substitute control
// (design doc Decision 5) — proving THAT admission end-to-end is
// test_dispatch_chokepoint.cpp's job (the pure decision, gate x provenance
// matrix); this test proves advance() actually produces the stamp the
// chokepoint needs to admit a non-admin caller in the first place.
TEST_CASE("#1398: advance() stamps GovernedPipeline provenance on every content_dist dispatch, "
          "for a non-admin caller",
          "[pg][deployment][engine][security][1398]") {
    YUZU_REQUIRE_PG_DB_TPL(db, deprun_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    DeploymentRunStore store{pool};
    REQUIRE(store.is_open());

    const std::string id = "gov-pipeline-1398";
    REQUIRE(store.create_deployment(make_dep(id), {tgt("w1")}));

    Harness h{store};
    auto deps = h.deps();
    DeploymentConfig cfg{"https://repo.lan/pkg.msi", "pkg.msi", std::string(64, 'a'), ""};
    const std::unordered_set<std::string> authorized{"w1"};

    // Deliberately non-admin, no ticket, no other provenance — the ONLY
    // thing that should let a role-gated content_dist dispatch through the
    // chokepoint for this caller is the stamp advance() adds.
    const yuzu::server::DispatchCaller non_admin_caller{
        .principal = "dana", .principal_role = "PlatformEngineer", .principal_is_admin = false};
    advance(deps, id, cfg, authorized, non_admin_caller);

    REQUIRE_FALSE(h.dispatch_callers.empty());
    const auto& reached = h.dispatch_callers.front();
    CHECK(reached.principal == "dana");
    CHECK_FALSE(reached.principal_is_admin);
    CHECK(reached.approval_provenance == yuzu::server::ApprovalProvenance::GovernedPipeline);
}
