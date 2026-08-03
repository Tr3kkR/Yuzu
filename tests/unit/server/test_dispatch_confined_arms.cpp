/**
 * test_dispatch_confined_arms.cpp — the PRODUCTION per-arm visible-set
 * intersection (#1788), bound by exact-send-set assertions.
 *
 * WHY THIS FILE EXISTS. The confinement work was previously "proven" by route
 * mocks that recorded the VisibleSet handed to a permissive dispatch stub and
 * asserted nothing about delivery. Those tests stayed GREEN with the
 * intersection deleted from production — a false-green offered as closure
 * evidence for a blocking finding (CDX-R8-02/CDX-FV-01, confirmed
 * independently by both external reviewers: removing `filter_to_scope` from
 * the seam left all six of them passing).
 *
 * These tests bind the real thing. `dispatch_confined_arms` is the ONE
 * implementation both `ServerImpl::dispatch_confined` and the `/api/command`
 * handler call, and here it runs against a recording sink that captures the
 * EXACT set of agents reached. Delete any single `in_scope`/`filter_to_scope`
 * call in it and cases below fail, because they assert who was reached — not
 * that a set was passed along.
 *
 * The matrix is every arm x each of the three VisibleSet states ADR-0033 §1
 * defines: nullopt = unfiltered, present-subset = narrowed, present-EMPTY =
 * deny-all (NOT "no filter"). The present-empty column is the fail-closed
 * contract every unwired-derivation path depends on.
 */

#include "dispatch_confined_arms.hpp"
#include "dispatch_scope_ladder.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

using yuzu::server::ConfinedDispatchOutcome;
using yuzu::server::ConfinedDispatchSink;
using yuzu::server::ConfinedDispatchTargets;
using yuzu::server::dispatch_confined_arms;
using yuzu::server::DispatchArm;
using yuzu::server::DispatchResolvers;
using yuzu::server::resolve_and_dispatch_confined;
using yuzu::server::resolve_scope_targets;
using yuzu::server::ScopeLadderAudit;
using yuzu::server::ScopeLadderResult;
using yuzu::server::authz::VisibleSet;

namespace {

/// Records exactly who was reached. `send_to_all_unfiltered` is deliberately
/// distinguishable from a per-agent walk: the unfiltered fast path is only
/// legitimate when the caller's authority is genuinely unfiltered (nullopt),
/// and a present-empty set reaching it would be the fail-open we are guarding.
struct RecordingSink {
    std::vector<std::string> reached;
    bool unfiltered_broadcast_used = false;
    std::vector<std::string> fleet{"dev-A", "dev-B", "dev-C"};

    ConfinedDispatchSink make() {
        return ConfinedDispatchSink{
            [this](const std::string& id) {
                reached.push_back(id);
                return true;
            },
            [this] {
                unfiltered_broadcast_used = true;
                return static_cast<int>(fleet.size());
            },
            [this] { return fleet; }};
    }

    bool reached_exactly(std::vector<std::string> expected) {
        auto got = reached;
        std::sort(got.begin(), got.end());
        std::sort(expected.begin(), expected.end());
        return got == expected;
    }
};

VisibleSet unfiltered() { return std::nullopt; }
VisibleSet only(std::initializer_list<std::string> ids) {
    return std::unordered_set<std::string>(ids);
}
VisibleSet deny_all() { return std::unordered_set<std::string>{}; }

const std::vector<std::string> kThree{"dev-A", "dev-B", "dev-C"};

} // namespace

// ---------------------------------------------------------------- Ids arm ---

TEST_CASE("Ids arm: unfiltered authority reaches every named agent",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.agent_ids = &kThree;
    const int sent = dispatch_confined_arms(DispatchArm::Ids, t, unfiltered(), false, sink.make());
    CHECK(sent == 3);
    CHECK(sink.reached_exactly({"dev-A", "dev-B", "dev-C"}));
}

TEST_CASE("Ids arm: an out-of-scope id is DROPPED, not reached",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.agent_ids = &kThree;
    const int sent =
        dispatch_confined_arms(DispatchArm::Ids, t, only({"dev-B"}), false, sink.make());
    CHECK(sent == 1);
    CHECK(sink.reached_exactly({"dev-B"}));
    // The security property, stated positively: the hidden agents were never sent to.
    CHECK(std::find(sink.reached.begin(), sink.reached.end(), "dev-A") == sink.reached.end());
    CHECK(std::find(sink.reached.begin(), sink.reached.end(), "dev-C") == sink.reached.end());
}

TEST_CASE("Ids arm: a present-EMPTY visible set reaches NOBODY (fail-closed)",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.agent_ids = &kThree;
    const int sent = dispatch_confined_arms(DispatchArm::Ids, t, deny_all(), false, sink.make());
    CHECK(sent == 0);
    CHECK(sink.reached.empty());
    CHECK_FALSE(sink.unfiltered_broadcast_used);
}

// -------------------------------------------------------------- Group arm ---

TEST_CASE("Group arm: members outside the visible set are dropped",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.group_members = &kThree;
    const int sent = dispatch_confined_arms(DispatchArm::Group, t, only({"dev-A", "dev-C"}), false,
                                            sink.make());
    CHECK(sent == 2);
    CHECK(sink.reached_exactly({"dev-A", "dev-C"}));
}

TEST_CASE("Group arm: a management group is targeting, never an authz exemption",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.group_members = &kThree;
    const int sent = dispatch_confined_arms(DispatchArm::Group, t, deny_all(), false, sink.make());
    CHECK(sent == 0);
    CHECK(sink.reached.empty());
}

TEST_CASE("Group arm: an unavailable management-group store reaches nobody",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t; // group_members left null == store unavailable
    const int sent = dispatch_confined_arms(DispatchArm::Group, t, unfiltered(), false,
                                            sink.make());
    CHECK(sent == 0);
    CHECK(sink.reached.empty());
}

// -------------------------------------------------------------- Scope arm ---

TEST_CASE("Scope arm: the matched set is intersected before dispatch",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.scope_matched = &kThree;
    const int sent =
        dispatch_confined_arms(DispatchArm::Scope, t, only({"dev-C"}), false, sink.make());
    CHECK(sent == 1);
    CHECK(sink.reached_exactly({"dev-C"}));
}

TEST_CASE("Scope arm: aborted resolution (null) reaches nobody — ADR-0036 fail-closed",
          "[server][dispatch][scope][security]") {
    // A parse failure / degraded DB / failed owner check leaves scope_matched
    // null. Reaching nobody is load-bearing: under a NOT combinator an
    // unresolved atom would otherwise invert to match-the-entire-fleet.
    RecordingSink sink;
    ConfinedDispatchTargets t; // scope_matched null
    const int sent = dispatch_confined_arms(DispatchArm::Scope, t, unfiltered(), false,
                                            sink.make());
    CHECK(sent == 0);
    CHECK(sink.reached.empty());
    CHECK_FALSE(sink.unfiltered_broadcast_used);
}

// ---------------------------------------------------------- Broadcast arm ---

TEST_CASE("Broadcast arm: unfiltered authority uses the fast send-to-all path",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    const int sent = dispatch_confined_arms(DispatchArm::Broadcast, {}, unfiltered(), false,
                                            sink.make());
    CHECK(sent == 3);
    CHECK(sink.unfiltered_broadcast_used);
}

TEST_CASE("Broadcast arm: a named __all__ is still narrowed to the visible set",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    const int sent = dispatch_confined_arms(DispatchArm::Broadcast, {}, only({"dev-B"}), false,
                                            sink.make());
    CHECK(sent == 1);
    CHECK(sink.reached_exactly({"dev-B"}));
    // Naming the broadcast must NOT buy the unfiltered path.
    CHECK_FALSE(sink.unfiltered_broadcast_used);
}

TEST_CASE("Broadcast arm: present-EMPTY reaches nobody and never falls back to send-to-all",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    const int sent = dispatch_confined_arms(DispatchArm::Broadcast, {}, deny_all(), false,
                                            sink.make());
    CHECK(sent == 0);
    CHECK(sink.reached.empty());
    CHECK_FALSE(sink.unfiltered_broadcast_used);
}

// --------------------------------------------------------------- None arm ---

TEST_CASE("None arm: the shared closure reaches NOBODY, not everybody (#2500)",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    const int sent = dispatch_confined_arms(DispatchArm::None, {}, unfiltered(),
                                            /*broadcast_on_none=*/false, sink.make());
    CHECK(sent == 0);
    CHECK(sink.reached.empty());
    CHECK_FALSE(sink.unfiltered_broadcast_used);
}

TEST_CASE("None arm: broadcast_on_none honours a deliberate fleet selection, still narrowed",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    const int sent = dispatch_confined_arms(DispatchArm::None, {}, only({"dev-A"}),
                                            /*broadcast_on_none=*/true, sink.make());
    CHECK(sent == 1);
    CHECK(sink.reached_exactly({"dev-A"}));
}

TEST_CASE("None arm: broadcast_on_none with a present-EMPTY set still reaches nobody",
          "[server][dispatch][scope][security]") {
    // The unwired-ExecVisibleFn path: dashboard/MCP substitute a present-empty
    // set rather than nullopt, so failing closed must survive broadcast_on_none.
    RecordingSink sink;
    const int sent = dispatch_confined_arms(DispatchArm::None, {}, deny_all(),
                                            /*broadcast_on_none=*/true, sink.make());
    CHECK(sent == 0);
    CHECK(sink.reached.empty());
    CHECK_FALSE(sink.unfiltered_broadcast_used);
}

// ===================================================================================
// resolve_and_dispatch_confined — the "middle link" (QE-2).
//
// Every test above feeds dispatch_confined_arms a HAND-BUILT DispatchArm and
// ConfinedDispatchTargets — it never exercises the classification
// (classify_dispatch_arm) or the arm-specific target resolution (group store /
// scope ladder) that `ServerImpl::dispatch_confined` and `/api/command` do
// BEFORE calling it. Nothing bound that: replacing the call in
// `ServerImpl::dispatch_confined` with a bare `for (id : agent_ids)
// send_to(id)` left all 12 tests above green (QE-2).
//
// These tests call `resolve_and_dispatch_confined` — the actual shared
// implementation `ServerImpl::dispatch_confined` now delegates to entirely —
// with the SAME (agent_ids, scope_expr) inputs a real caller supplies, so a
// regression collapsing the classification/resolution to a naive loop over
// `agent_ids` fails every case here that is not coincidentally an Ids arm
// under an unfiltered visible set.
// ===================================================================================

namespace {

DispatchResolvers no_group_no_scope_resolvers() { return DispatchResolvers{}; }

} // namespace

TEST_CASE("resolve_and_dispatch_confined: Ids arm is classified and intersected end-to-end",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    const std::vector<std::string> ids{"dev-A", "dev-B", "dev-C"};
    const auto outcome = resolve_and_dispatch_confined(
        ids, /*scope_expr=*/"", only({"dev-B"}), /*broadcast_on_none=*/false,
        no_group_no_scope_resolvers(), sink.make());
    CHECK(outcome.sent == 1);
    CHECK(sink.reached_exactly({"dev-B"}));
    // The security property, stated positively: dev-A/dev-C were never sent to
    // despite being named — a naive unfiltered loop would have reached them.
    CHECK(std::find(sink.reached.begin(), sink.reached.end(), "dev-A") == sink.reached.end());
}

TEST_CASE("resolve_and_dispatch_confined: Group arm resolves via the injected group store, "
          "then intersects",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    DispatchResolvers resolvers;
    std::string requested_group;
    resolvers.group_members_fn = [&](const std::string& group_id) {
        requested_group = group_id;
        return std::vector<std::string>{"dev-A", "dev-B", "dev-C"};
    };
    const auto outcome =
        resolve_and_dispatch_confined({}, "group:eng", only({"dev-A", "dev-C"}),
                                      /*broadcast_on_none=*/false, resolvers, sink.make());
    CHECK(requested_group == "eng"); // the "group:" prefix is stripped before lookup
    CHECK(outcome.sent == 2);
    CHECK(sink.reached_exactly({"dev-A", "dev-C"}));
}

TEST_CASE("resolve_and_dispatch_confined: Broadcast arm (__all__) still narrows to the "
          "visible set",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    const auto outcome =
        resolve_and_dispatch_confined({}, "__all__", only({"dev-B"}), /*broadcast_on_none=*/true,
                                      no_group_no_scope_resolvers(), sink.make());
    CHECK(outcome.sent == 1);
    CHECK(sink.reached_exactly({"dev-B"}));
    CHECK_FALSE(sink.unfiltered_broadcast_used);
}

TEST_CASE("resolve_and_dispatch_confined: None arm reaches nobody when broadcast_on_none is "
          "false (#2500)",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    const auto outcome =
        resolve_and_dispatch_confined({}, "", unfiltered(), /*broadcast_on_none=*/false,
                                      no_group_no_scope_resolvers(), sink.make());
    CHECK(outcome.sent == 0);
    CHECK(sink.reached.empty());
}

TEST_CASE("resolve_and_dispatch_confined: Scope arm dispatches exactly the ladder's matched set",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    DispatchResolvers resolvers;
    std::string requested_expr;
    resolvers.scope_ladder_fn = [&](std::string_view expr) {
        requested_expr = std::string(expr);
        ScopeLadderResult r;
        r.matched = std::vector<std::string>{"dev-A", "dev-B", "dev-C"};
        return r;
    };
    const auto outcome = resolve_and_dispatch_confined(
        {}, "tag:role == \"web\"", only({"dev-C"}), /*broadcast_on_none=*/false, resolvers,
        sink.make());
    CHECK(requested_expr == "tag:role == \"web\"");
    CHECK(outcome.sent == 1);
    CHECK(sink.reached_exactly({"dev-C"}));
}

TEST_CASE("resolve_and_dispatch_confined: Scope arm aborted resolution reaches nobody — "
          "ADR-0036 fail-closed",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    DispatchResolvers resolvers;
    resolvers.scope_ladder_fn = [](std::string_view) {
        return ScopeLadderResult{}; // matched stays nullopt — an aborted ladder
    };
    const auto outcome = resolve_and_dispatch_confined(
        {}, "tag:role == \"web\"", unfiltered(), /*broadcast_on_none=*/false, resolvers,
        sink.make());
    CHECK(outcome.sent == 0);
    CHECK(sink.reached.empty());
    CHECK_FALSE(sink.unfiltered_broadcast_used);
}

TEST_CASE("resolve_and_dispatch_confined: a Scope arm parse error is surfaced, not swallowed",
          "[server][dispatch][scope][security]") {
    RecordingSink sink;
    DispatchResolvers resolvers;
    resolvers.scope_ladder_fn = [](std::string_view) {
        ScopeLadderResult r;
        r.parse_error = "unexpected token";
        return r;
    };
    const auto outcome = resolve_and_dispatch_confined(
        {}, "tag:role == \"web\"", unfiltered(), /*broadcast_on_none=*/false, resolvers,
        sink.make());
    CHECK(outcome.sent == 0);
    REQUIRE(outcome.scope_parse_error.has_value());
    CHECK(*outcome.scope_parse_error == "unexpected token");
    CHECK(sink.reached.empty());
}

// ===================================================================================
// resolve_scope_targets — the ADR-0036 ladder itself (A-3).
//
// `resolve_scope_aliases`/`gate_scope_dispatch`'s OWN correctness on a real
// from_result_set: atom is already pinned against a live ResultSetStore in
// test_scope_walking_authz.cpp; both no-op/Proceed when the expression has NO
// from_result_set: atom, regardless of the store pointer, so a plain
// attribute condition below exercises this ladder's OWN new orchestration
// (which audit hook fires, whether evaluate_scope_fn is even reached) without
// needing a live store. The AbortDbDegraded/AbortOwnerCheck branches (which
// DO require a real from_result_set: atom + a degraded/live store) are
// UNBOUND here for that reason — see the notes in the accompanying patch
// summary.
// ===================================================================================

TEST_CASE("resolve_scope_targets: a matching expression with no from_result_set atom returns "
          "the evaluator's set untouched",
          "[server][dispatch][scope]") {
    bool audit_fired = false;
    ScopeLadderAudit audit;
    audit.evaluation_aborted = [&](const std::string&) { audit_fired = true; };
    audit.resolution_failed = [&](const std::string&) { audit_fired = true; };
    const auto result = resolve_scope_targets(
        "ostype == \"Windows\"", "alice", /*result_set_store=*/nullptr,
        [](const yuzu::scope::Expression&) -> std::optional<std::vector<std::string>> {
            return std::vector<std::string>{"dev-A", "dev-B"};
        },
        audit);
    REQUIRE(result.matched.has_value());
    CHECK(*result.matched == std::vector<std::string>{"dev-A", "dev-B"});
    CHECK_FALSE(result.parse_error.has_value());
    CHECK_FALSE(audit_fired);
}

TEST_CASE("resolve_scope_targets: invalid scope syntax surfaces a parse_error and never "
          "reaches evaluate_scope_fn",
          "[server][dispatch][scope]") {
    bool evaluate_called = false;
    ScopeLadderAudit audit;
    const auto result = resolve_scope_targets(
        "(ostype == \"Windows\"", "alice", nullptr,
        [&](const yuzu::scope::Expression&) -> std::optional<std::vector<std::string>> {
            evaluate_called = true;
            return std::vector<std::string>{};
        },
        audit);
    CHECK_FALSE(result.matched.has_value());
    REQUIRE(result.parse_error.has_value());
    CHECK_FALSE(evaluate_called);
}

TEST_CASE("resolve_scope_targets: a degraded registry evaluation aborts as db_degraded when "
          "a principal is known",
          "[server][dispatch][scope]") {
    std::string aborted_reason;
    ScopeLadderAudit audit;
    audit.evaluation_aborted = [&](const std::string& reason) { aborted_reason = reason; };
    const auto result = resolve_scope_targets(
        "ostype == \"Windows\"", "alice", nullptr,
        [](const yuzu::scope::Expression&) -> std::optional<std::vector<std::string>> {
            return std::nullopt; // registry membership preload failed
        },
        audit);
    CHECK_FALSE(result.matched.has_value());
    CHECK(aborted_reason == "db_degraded");
}

TEST_CASE("resolve_scope_targets: a degraded registry evaluation with no principal aborts as "
          "principal_unresolved",
          "[server][dispatch][scope]") {
    std::string aborted_reason;
    ScopeLadderAudit audit;
    audit.evaluation_aborted = [&](const std::string& reason) { aborted_reason = reason; };
    const auto result = resolve_scope_targets(
        "ostype == \"Windows\"", /*principal=*/"", nullptr,
        [](const yuzu::scope::Expression&) -> std::optional<std::vector<std::string>> {
            return std::nullopt;
        },
        audit);
    CHECK_FALSE(result.matched.has_value());
    CHECK(aborted_reason == "principal_unresolved");
}

// ═══════════════════════════════════════════════════════════════════════════
// K-1 (QE-2 residual): every case above binds `resolve_and_dispatch_confined`
// and `dispatch_confined_arms` by calling them DIRECTLY with a fake sink — but
// none of them exercises `wire_and_dispatch_confined`, the glue that builds
// their inputs from a real `AgentRegistry` + stores (extracted verbatim from
// `ServerImpl::dispatch_confined`). A mutation probe proved that glue was
// UNBOUND: replacing the whole `ServerImpl::dispatch_confined` body with a
// naive unfiltered `send_to` loop left every existing test green, because
// none of them called through it. This test does, against a REAL
// `AgentRegistry` (not a fake — `AgentRegistry` has zero virtuals and cannot
// be faked polymorphically), using the registry's gateway-pending path
// (`set_gateway_node` + `drain_gateway_pending()`) to observe exactly which
// agent_ids a dispatch reached without needing a live gRPC stream.
// ═══════════════════════════════════════════════════════════════════════════

#include "agent_registry.hpp"

namespace {
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
namespace agent_pb = ::yuzu::agent::v1;

agent_pb::AgentInfo make_wiring_test_info(const std::string& id) {
    agent_pb::AgentInfo info;
    info.set_agent_id(id);
    info.set_hostname("host.local");
    return info;
}
} // namespace

TEST_CASE("wire_and_dispatch_confined: the Ids arm intersects exec_visible against a REAL "
          "AgentRegistry (K-1)",
          "[server][dispatch][scope][integration]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    for (const auto& id : {"dev-A", "dev-B", "dev-C"}) {
        registry.register_agent(make_wiring_test_info(id));
        // Gateway-pending path: send_to() queues onto drain_gateway_pending()
        // and returns true with NO live gRPC stream needed — the observable
        // hook this test uses to see exactly who was targeted.
        registry.set_gateway_node(id, "test-gateway");
    }

    yuzu::agent::v1::CommandRequest cmd;
    cmd.set_command_id("wiring-test-cmd");
    cmd.set_plugin("os_info");
    cmd.set_action("version");

    // Confined to dev-A only; agent_ids names all three. If the intersection
    // is deleted (the exact K-1 mutation), all three get queued instead of
    // just dev-A.
    yuzu::server::authz::VisibleSet exec_visible{std::unordered_set<std::string>{"dev-A"}};
    std::vector<std::string> agent_ids{"dev-A", "dev-B", "dev-C"};

    auto noop_audit = [](const std::string&, const std::string&, const std::string&,
                         const std::string&) {};
    const auto [command_id, sent] = yuzu::server::wire_and_dispatch_confined(
        registry, /*mgmt_group_store=*/nullptr, /*result_set_store=*/nullptr,
        /*tag_store=*/nullptr, /*custom_properties_store=*/nullptr,
        /*execution_tracker=*/nullptr, noop_audit, noop_audit,
        /*command_id=*/"wiring-test-cmd", /*execution_id=*/"", /*principal_role=*/"",
        agent_ids, /*scope_expr=*/"", exec_visible, /*broadcast_on_none=*/false, cmd);

    CHECK(sent == 1);
    auto pending = registry.drain_gateway_pending();
    REQUIRE(pending.size() == 1);
    CHECK(pending[0].agent_id == "dev-A");
}
