/**
 * test_dispatch_chokepoint.cpp — PR1.9c: the ONE command-builder chokepoint.
 *
 * WHAT THIS FILE BINDS. `ServerImpl::build_classified_command` (server.cpp) is
 * a private member with no live-Session-free construction path, so it is not
 * directly reachable from a unit test — the same situation
 * `dispatch_confined_arms.hpp`/`dispatch_target_shape.hpp` were extracted to
 * solve for the arm-intersection and targeting-shape rules. This file binds
 * the SAME pure decision `build_classified_command` is built around —
 * `yuzu::server::detail::classify_and_authorize_dispatch` and
 * `yuzu::server::detail::compute_dispatch_tag` (agent_registry.hpp) — directly,
 * with a fake `has_permission` callback, so the classify+authorize rule is
 * proven independent of a live `ServerImpl`/`RbacStore`/database. Every
 * `build_classified_command` call site funnels through this exact function; a
 * from-scratch re-implementation inside a test is the anti-pattern this
 * codebase's own comments warn about repeatedly (#2500, dispatch_confined_arms.hpp).
 *
 * The four "denied, naming the securable" cases below are named after the real
 * call sites they represent (spec: /api/command, forward_legacy_command, a
 * scheduled dispatch, an MCP-shaped `dispatch_confined` caller) because none
 * of those routes/seams is independently reachable from a unit test either
 * (`/api/command` is registered inline on a raw httplib::Server inside
 * `Server::start()`, #2557; MCP/schedule wiring lives in mcp_server.cpp /
 * workflow_routes.hpp, both out of this package's scope per spec boundaries) —
 * what IS common to all four, and what this file actually binds, is the ONE
 * shared decision every one of them routes through.
 *
 * `AgentRegistry::send_to`/`send_to_all`'s narrowed signature (provenance not
 * syntax, PLAN-011), the defensive dispatch_tag check, and the gateway
 * routed-path capability check (PLAN item 5) ARE reachable with a real
 * `AgentRegistry` — those sections bind the real thing.
 */

#include "agent_registry.hpp"
#include "capability_decls/core_dispatch_capabilities.hpp"
#include "command_capability.hpp"
#include "command_capability_parsers.hpp"
#include "dispatch_caller.hpp"
#include "event_bus.hpp"

#include <catch2/catch_test_macros.hpp>

#include <yuzu/metrics.hpp>

#include "agent.pb.h"

#include <array>
#include <map>
#include <span>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::detail;
namespace agent_pb = ::yuzu::agent::v1;

// ═════════════════════════════════════════════════════════════════════════
// PLAN-011 (provenance, not syntax) — the compile-time invariant.
// ═════════════════════════════════════════════════════════════════════════
//
// A syntactically valid dispatch_tag proves nothing: encode_dispatch_tag is a
// public, pure helper any caller could stamp onto a hand-built protobuf. The
// guarantee AgentRegistry::send_to/send_to_all rest on is therefore a TYPE
// invariant — there is no overload that accepts a bare
// yuzu::agent::v1::CommandRequest, so a hand-built one cannot reach the
// registry AT ALL, not even with a forged-but-well-formed tag.
namespace {

template <typename T, typename = void> struct can_send_to_raw_command : std::false_type {};
template <typename T>
struct can_send_to_raw_command<
    T, std::void_t<decltype(std::declval<T&>().send_to(
           std::declval<std::string>(), std::declval<agent_pb::CommandRequest>()))>>
    : std::true_type {};

template <typename T, typename = void> struct can_send_to_all_raw_command : std::false_type {};
template <typename T>
struct can_send_to_all_raw_command<
    T, std::void_t<decltype(std::declval<T&>().send_to_all(
           std::declval<agent_pb::CommandRequest>()))>> : std::true_type {};

// Positive control: the exact same signature shape, but with a
// ClassifiedCommand — proves the traits above are discriminating on the
// TYPE, not merely permanently false for an unrelated reason (a rewritten
// method name, a moved header, ...).
template <typename T, typename = void> struct can_send_to_classified : std::false_type {};
template <typename T>
struct can_send_to_classified<
    T, std::void_t<decltype(std::declval<T&>().send_to(
           std::declval<std::string>(), std::declval<const ClassifiedCommand&>()))>>
    : std::true_type {};

template <typename T, typename = void> struct can_send_to_all_classified : std::false_type {};
template <typename T>
struct can_send_to_all_classified<
    T, std::void_t<decltype(std::declval<T&>().send_to_all(
           std::declval<const ClassifiedCommand&>()))>> : std::true_type {};

} // namespace

static_assert(!can_send_to_raw_command<AgentRegistry>::value,
             "AgentRegistry::send_to must not accept a bare CommandRequest — a hand-built "
             "protobuf, forged tag or not, must not be able to reach the registry (PLAN-011).");
static_assert(!can_send_to_all_raw_command<AgentRegistry>::value,
             "AgentRegistry::send_to_all must not accept a bare CommandRequest (PLAN-011).");
static_assert(can_send_to_classified<AgentRegistry>::value,
             "sanity: AgentRegistry::send_to must still accept a ClassifiedCommand — proves the "
             "negative static_asserts above are discriminating on type, not vacuous.");
static_assert(can_send_to_all_classified<AgentRegistry>::value,
             "sanity: AgentRegistry::send_to_all must still accept a ClassifiedCommand.");

TEST_CASE("ClassifiedCommand: only the test-only door can mint one outside ServerImpl; the "
          "resulting value reaches send_to",
          "[server][dispatch][chokepoint]") {
    // Documents the invariant the static_asserts above prove at compile time:
    // ClassifiedCommandTestAccess is a narrow, explicit, clearly-named door —
    // mirroring EngineLivenessTestAccess (engine_principal_store.hpp) — not a
    // public constructor, setter, or conversion. The declaration is visible
    // to any TU that includes agent_registry.hpp, but production code has no
    // LINKABLE door: ClassifiedCommandTestAccess::make's only definition
    // lives in classified_command_test_access.cpp, a TU deliberately kept
    // off every production source list, so a production caller would
    // compile and then fail to LINK. Only ServerImpl::build_classified_command
    // has a real, linkable path to construct one.
    agent_pb::CommandRequest cmd;
    cmd.set_command_id("door-test");
    cmd.set_plugin("tar");
    cmd.set_action("fleet_snapshot");
    cmd.set_dispatch_tag(
        encode_dispatch_tag(DispatchClass::ReadOnly, Mutability::None, std::string(32, 'a')));
    auto classified = ClassifiedCommandTestAccess::make(cmd);
    CHECK(classified.wire().command_id() == "door-test");

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    agent_pb::AgentInfo info;
    info.set_agent_id("dev-door");
    info.set_hostname("host.local");
    registry.register_agent(info);

    // No live stream and no gateway_node → send_to fails closed (false), not
    // because of anything THIS test is proving — just documenting that a
    // ClassifiedCommand behaves like any other command once past the door.
    CHECK_FALSE(registry.send_to("dev-door", classified));
}

// ═════════════════════════════════════════════════════════════════════════
// classify_and_authorize_dispatch — the pure classify+authorize decision.
// ═════════════════════════════════════════════════════════════════════════

namespace {

// A caller lacking (or being denied) any grant.
[[nodiscard]] bool always_deny(std::string_view, std::string_view, authz::Operation) {
    return false;
}

// A caller holding every grant it could ask for. Used specifically where a
// test needs to prove a denial is NOT merely "RBAC said no" — e.g. the
// system_reserved rule, or the anonymous-operator rule, both of which must
// fire regardless of what RbacStore would have answered.
[[nodiscard]] bool always_allow(std::string_view, std::string_view, authz::Operation) {
    return true;
}

// A small, independent operator-space fixture — four rows, four distinct
// securables, standing in for four different real plugin.action pairs a
// real operator dispatch might target. Deliberately NOT the real catalogue
// (owned by other packages) — this file's job is to bind the shared DECISION,
// not to re-verify the real catalogue's own content (test_command_capability.cpp
// and the plugin_action_catalogue_* fragments' own tests do that).
inline constexpr std::array<CommandCapability, 4> kOperatorFixture{{
    {
        .plugin = "filesystem",
        .action = "read",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "FileRetrieval",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
    },
    {
        .plugin = "chargen",
        .action = "chargen_start",
        .dispatch_class = DispatchClass::Mutating,
        .mutability = Mutability::Reversible,
        .securable = "Execution",
        .operation = authz::Operation::Execute,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
    },
    {
        .plugin = "tar",
        .action = "query",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Infrastructure",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Medium,
        .system_reserved = false,
    },
    {
        .plugin = "vuln_scan",
        .action = "scan",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Security",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = false,
    },
}};

} // namespace

TEST_CASE("classify_and_authorize_dispatch: an unclassified plugin.action is rejected, never a "
          "permissive default",
          "[server][dispatch][chokepoint]") {
    CommandCapabilityRegistry registry{std::span<const CommandCapability>(kOperatorFixture)};
    DispatchCaller caller{.principal = "alice"};

    // has_permission ALWAYS ALLOWS — proves the refusal fires at
    // classification, before authorization is ever consulted.
    auto result = classify_and_authorize_dispatch(registry, caller, "no_such_plugin",
                                                   "no_such_action", always_allow);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().reason == DispatchDenialReason::Unclassified);
    // No securable to name — classification never resolved one.
    CHECK(result.error().securable.empty());
}

TEST_CASE("classify_and_authorize_dispatch: an ambiguous plugin.action is rejected with a "
          "DISTINCT counted error, never first-wins",
          "[server][dispatch][chokepoint]") {
    // A second, independently-authored fragment declaring the SAME
    // plugin.action as kOperatorFixture's filesystem.read row, with
    // deliberately CONFLICTING classification — proves Ambiguous is
    // detected regardless of whether the two rows happen to agree.
    static constexpr std::array<CommandCapability, 1> kDuplicateFragment{{
        {
            .plugin = "filesystem",
            .action = "read",
            .dispatch_class = DispatchClass::Mutating,
            .mutability = Mutability::Reversible,
            .securable = "Infrastructure",
            .operation = authz::Operation::Write,
            .risk_tier = authz::RiskTier::Medium,
            .system_reserved = false,
        },
    }};
    CommandCapabilityRegistry registry{std::span<const CommandCapability>(kOperatorFixture),
                                       std::span<const CommandCapability>(kDuplicateFragment)};
    DispatchCaller caller{.principal = "alice"};

    auto result =
        classify_and_authorize_dispatch(registry, caller, "filesystem", "read", always_allow);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().reason == DispatchDenialReason::Ambiguous);
    CHECK(result.error().securable.empty());

    // A DIFFERENT action from the same registry is unaffected — ambiguity is
    // per plugin.action, not a registry-wide poison (mirrors
    // test_command_capability.cpp's own equivalent assertion on `classify`
    // itself, one layer down).
    auto other = classify_and_authorize_dispatch(registry, caller, "tar", "query", always_allow);
    REQUIRE(other.has_value());
}

TEST_CASE("classify_and_authorize_dispatch: a DispatchCaller with system == false and an empty "
          "principal is rejected — no anonymous operator dispatch",
          "[server][dispatch][chokepoint]") {
    CommandCapabilityRegistry registry{std::span<const CommandCapability>(kOperatorFixture)};
    DispatchCaller anonymous{.principal = "", .system = false};

    // has_permission ALWAYS ALLOWS — proves the empty principal is refused
    // BEFORE ever reaching the permission callback, where a legacy-open
    // RbacStore might otherwise admit an empty username by accident
    // (RbacStore::check_permission has no notion of "no such caller").
    auto result =
        classify_and_authorize_dispatch(registry, anonymous, "filesystem", "read", always_allow);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error().reason == DispatchDenialReason::AnonymousOperator);
}

TEST_CASE("classify_and_authorize_dispatch: a non-authorized operator principal is denied, "
          "naming the securable it was denied on — four call-site shapes",
          "[server][dispatch][chokepoint]") {
    CommandCapabilityRegistry registry{std::span<const CommandCapability>(kOperatorFixture)};

    SECTION("/api/command-shaped: an interactive operator dispatching filesystem.read") {
        DispatchCaller caller{.principal = "alice", .principal_role = "operator"};
        auto result = classify_and_authorize_dispatch(registry, caller, "filesystem", "read",
                                                       always_deny);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().reason == DispatchDenialReason::Forbidden);
        CHECK(result.error().securable == "FileRetrieval");
    }

    SECTION("forward_legacy_command-shaped: an operator dispatching chargen.chargen_start") {
        DispatchCaller caller{.principal = "bob", .principal_role = "operator"};
        auto result = classify_and_authorize_dispatch(registry, caller, "chargen",
                                                       "chargen_start", always_deny);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().reason == DispatchDenialReason::Forbidden);
        CHECK(result.error().securable == "Execution");
    }

    SECTION("schedule-shaped: a scheduled bundle firing under its creating operator's recovered "
            "principal, dispatching tar.query") {
        DispatchCaller caller{.principal = "carol", .principal_role = "operator"};
        auto result =
            classify_and_authorize_dispatch(registry, caller, "tar", "query", always_deny);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().reason == DispatchDenialReason::Forbidden);
        CHECK(result.error().securable == "Infrastructure");
    }

    SECTION("dispatch_confined-under-an-MCP-shaped caller: an MCP session's principal "
            "dispatching vuln_scan.scan") {
        DispatchCaller caller{.principal = "dave", .principal_role = "mcp-operator"};
        auto result =
            classify_and_authorize_dispatch(registry, caller, "vuln_scan", "scan", always_deny);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().reason == DispatchDenialReason::Forbidden);
        CHECK(result.error().securable == "Security");
    }
}

TEST_CASE("classify_and_authorize_dispatch: the three system dispatches succeed under a system "
          "caller, regardless of what RbacStore would answer",
          "[server][dispatch][chokepoint]") {
    CommandCapabilityRegistry registry{
        std::span<const CommandCapability>(capdecls::core_dispatch_capabilities())};
    const DispatchCaller system_caller{.system = true};

    SECTION("tar.fleet_snapshot") {
        // has_permission ALWAYS DENIES — proves success is the STRUCTURAL
        // system-arm rule, not an accidental RBAC pass.
        auto result = classify_and_authorize_dispatch(registry, system_caller, "tar",
                                                       "fleet_snapshot", always_deny);
        REQUIRE(result.has_value());
        CHECK(result->securable == "Response");
        CHECK(result->operation == authz::Operation::Read);
        CHECK(result->dispatch_class == DispatchClass::ReadOnly);
        CHECK(result->system_reserved);
    }
    SECTION("__guard__.push_rules") {
        auto result = classify_and_authorize_dispatch(registry, system_caller, "__guard__",
                                                       "push_rules", always_deny);
        REQUIRE(result.has_value());
        CHECK(result->securable == "GuaranteedState");
        CHECK(result->operation == authz::Operation::Push);
        CHECK(result->system_reserved);
    }
    SECTION("asset_tags.sync") {
        auto result =
            classify_and_authorize_dispatch(registry, system_caller, "asset_tags", "sync",
                                            always_deny);
        REQUIRE(result.has_value());
        CHECK(result->securable == "Tag");
        CHECK(result->operation == authz::Operation::Write);
        CHECK(result->system_reserved);
    }
}

TEST_CASE("classify_and_authorize_dispatch: the three system dispatches are denied to an "
          "operator caller lacking the securable — system_reserved is never caller-attributable",
          "[server][dispatch][chokepoint]") {
    CommandCapabilityRegistry registry{
        std::span<const CommandCapability>(capdecls::core_dispatch_capabilities())};
    const DispatchCaller operator_caller{.principal = "alice", .system = false};

    SECTION("tar.fleet_snapshot") {
        // has_permission ALWAYS ALLOWS — proves the denial is the
        // system_reserved rule, not a missing RBAC grant an operator could
        // otherwise be given.
        auto result = classify_and_authorize_dispatch(registry, operator_caller, "tar",
                                                       "fleet_snapshot", always_allow);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().reason == DispatchDenialReason::Forbidden);
        CHECK(result.error().securable == "Response");
    }
    SECTION("__guard__.push_rules") {
        auto result = classify_and_authorize_dispatch(registry, operator_caller, "__guard__",
                                                       "push_rules", always_allow);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().reason == DispatchDenialReason::Forbidden);
        CHECK(result.error().securable == "GuaranteedState");
    }
    SECTION("asset_tags.sync") {
        auto result = classify_and_authorize_dispatch(registry, operator_caller, "asset_tags",
                                                       "sync", always_allow);
        REQUIRE_FALSE(result.has_value());
        CHECK(result.error().reason == DispatchDenialReason::Forbidden);
        CHECK(result.error().securable == "Tag");
    }
}

// ═════════════════════════════════════════════════════════════════════════
// compute_dispatch_tag — the composition build_classified_command stamps.
// ═════════════════════════════════════════════════════════════════════════

TEST_CASE("compute_dispatch_tag: decodes to the classification supplied, and its plan hash "
          "matches compute_plan_hash over the same inputs",
          "[server][dispatch][chokepoint]") {
    constexpr CommandCapability cap{
        .plugin = "tar",
        .action = "fleet_snapshot",
        .dispatch_class = DispatchClass::ReadOnly,
        .mutability = Mutability::None,
        .securable = "Response",
        .operation = authz::Operation::Read,
        .risk_tier = authz::RiskTier::Low,
        .system_reserved = true,
    };
    const std::map<std::string, std::string> params{{"a", "1"}, {"b", "2"}};

    auto tag = compute_dispatch_tag(cap, "tar", "fleet_snapshot", params, "ids", "exec-1");

    auto decoded = decode_dispatch_tag(tag);
    REQUIRE(decoded.has_value());
    CHECK(decoded->dispatch_class == DispatchClass::ReadOnly);
    CHECK(decoded->mutability == Mutability::None);
    CHECK(decoded->plan_hash ==
          compute_plan_hash("tar", "fleet_snapshot", params, "ids", "exec-1"));

    // Two dispatches differing ONLY in how targets were selected (target_arm)
    // mint distinct plan identities — the property build_classified_command
    // relies on `target_arm` for (spec item 1).
    auto tag_other_arm =
        compute_dispatch_tag(cap, "tar", "fleet_snapshot", params, "scope", "exec-1");
    CHECK(tag_other_arm != tag);

    // Likewise for execution_id.
    auto tag_other_exec =
        compute_dispatch_tag(cap, "tar", "fleet_snapshot", params, "ids", "exec-2");
    CHECK(tag_other_exec != tag);
}

// ═════════════════════════════════════════════════════════════════════════
// AgentRegistry::send_to/send_to_all — the defensive belt-and-braces tag
// check (PLAN item 3) and the gateway routed-path capability check (item 5).
// ═════════════════════════════════════════════════════════════════════════

namespace {

agent_pb::AgentInfo make_agent_info(const std::string& id) {
    agent_pb::AgentInfo info;
    info.set_agent_id(id);
    info.set_hostname("host.local");
    return info;
}

agent_pb::CommandRequest make_well_formed_cmd(const std::string& command_id) {
    agent_pb::CommandRequest cmd;
    cmd.set_command_id(command_id);
    cmd.set_plugin("tar");
    cmd.set_action("fleet_snapshot");
    cmd.set_dispatch_tag(
        encode_dispatch_tag(DispatchClass::ReadOnly, Mutability::None, std::string(32, 'a')));
    return cmd;
}

} // namespace

TEST_CASE("AgentRegistry::send_to: the defensive tag check rejects an empty/malformed "
          "dispatch_tag, counted separately from the gateway-capability denial",
          "[server][dispatch][chokepoint]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(make_agent_info("dev-A"));

    agent_pb::CommandRequest cmd;
    cmd.set_command_id("bad-tag-cmd");
    cmd.set_plugin("tar");
    cmd.set_action("fleet_snapshot");
    // dispatch_tag left unset — decode_dispatch_tag("") fails (empty hash field).
    auto classified = ClassifiedCommandTestAccess::make(cmd);

    CHECK_FALSE(registry.send_to("dev-A", classified));
    CHECK(metrics.counter("yuzu_server_dispatch_tag_invalid_total").value() == 1);
    // NOT the gateway-capability counter — this agent isn't even gateway-routed.
    CHECK(metrics
             .counter("yuzu_server_gateway_capability_denied_total",
                      {{"capability", std::string(kGatewayWireCapabilityDispatchTagV1)}})
             .value() == 0);
}

TEST_CASE("AgentRegistry::send_to_all: the defensive tag check is evaluated once for the whole "
          "broadcast, not per recipient",
          "[server][dispatch][chokepoint]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(make_agent_info("dev-A"));
    registry.register_agent(make_agent_info("dev-B"));

    agent_pb::CommandRequest cmd;
    cmd.set_command_id("bad-tag-broadcast");
    cmd.set_plugin("tar");
    cmd.set_action("fleet_snapshot");
    auto classified = ClassifiedCommandTestAccess::make(cmd);

    CHECK(registry.send_to_all(classified) == 0);
    CHECK(metrics.counter("yuzu_server_dispatch_tag_invalid_total").value() == 1);
}

TEST_CASE("AgentRegistry::send_to: a routed envelope to a gateway session that never advertised "
          "command_dispatch_tag_v1 is denied and counted, not silently downgraded",
          "[server][dispatch][chokepoint]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(make_agent_info("dev-gw"));
    // Node set, capabilities deliberately EMPTY — this gateway has not
    // proven it forwards dispatch_tag untouched.
    registry.set_gateway_route("dev-gw", "gw-node-1", {});

    auto classified = ClassifiedCommandTestAccess::make(make_well_formed_cmd("routed-cmd"));

    CHECK_FALSE(registry.send_to("dev-gw", classified));
    CHECK(registry.drain_gateway_pending().empty());
    CHECK(metrics
             .counter("yuzu_server_gateway_capability_denied_total",
                      {{"capability", std::string(kGatewayWireCapabilityDispatchTagV1)}})
             .value() == 1);
}

TEST_CASE("AgentRegistry::send_to: a routed envelope succeeds once the gateway has advertised "
          "command_dispatch_tag_v1",
          "[server][dispatch][chokepoint]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(make_agent_info("dev-gw"));
    registry.set_gateway_route("dev-gw", "gw-node-1",
                               {std::string(kGatewayWireCapabilityDispatchTagV1)});

    auto classified = ClassifiedCommandTestAccess::make(make_well_formed_cmd("routed-cmd-ok"));

    CHECK(registry.send_to("dev-gw", classified));
    auto pending = registry.drain_gateway_pending();
    REQUIRE(pending.size() == 1);
    CHECK(pending[0].agent_id == "dev-gw");
    CHECK(pending[0].cmd.command_id() == "routed-cmd-ok");
}

TEST_CASE("AgentRegistry::send_to_all: an individual gateway recipient missing the "
          "advertisement is excluded from the count without failing the rest of the broadcast",
          "[server][dispatch][chokepoint]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(make_agent_info("dev-ok"));
    registry.set_gateway_route("dev-ok", "gw-node-1",
                               {std::string(kGatewayWireCapabilityDispatchTagV1)});
    registry.register_agent(make_agent_info("dev-missing"));
    // dev-missing's gateway never advertised the capability.
    registry.set_gateway_route("dev-missing", "gw-node-2", {});

    auto classified = ClassifiedCommandTestAccess::make(make_well_formed_cmd("broadcast-cmd"));

    CHECK(registry.send_to_all(classified) == 1);
    auto pending = registry.drain_gateway_pending();
    REQUIRE(pending.size() == 1);
    CHECK(pending[0].agent_id == "dev-ok");
}

// ═════════════════════════════════════════════════════════════════════════
// PLAN item 5 (CC-03) — AgentRegistry's gateway wire-capability accessors.
// NotifyStreamStatus (gateway_service_impl.cpp) is a thin delegation to
// these — set_gateway_route on CONNECTED (M1 review fix: node + capabilities
// publish together, not two separate calls), clear_stream_if_session
// (extended, agent_registry.cpp) covers DISCONNECTED. Bound directly here
// rather than via a live GatewayUpstreamServiceImpl, which needs a real
// auth::AuthManager/AutoApproveEngine this package does not own and no
// existing test constructs.
// ═════════════════════════════════════════════════════════════════════════

TEST_CASE("AgentRegistry: gateway wire capabilities are recorded and queryable",
          "[server][dispatch][chokepoint][gateway]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(make_agent_info("dev-A"));

    // Node value is irrelevant here — gateway_has_wire_capability never
    // reads it — so a fixed placeholder is used throughout this test.
    registry.set_gateway_route("dev-A", "irrelevant-node", {"command_dispatch_tag_v1", "other_cap"});

    CHECK(registry.gateway_has_wire_capability("dev-A", "command_dispatch_tag_v1"));
    CHECK(registry.gateway_has_wire_capability("dev-A", "other_cap"));
    CHECK_FALSE(registry.gateway_has_wire_capability("dev-A", "unadvertised_cap"));
    // Unknown agent: fail closed.
    CHECK_FALSE(registry.gateway_has_wire_capability("dev-nonexistent", "command_dispatch_tag_v1"));
}

TEST_CASE("AgentRegistry: a reconnect REPLACES advertised wire capabilities, never merges",
          "[server][dispatch][chokepoint][gateway]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(make_agent_info("dev-A"));

    registry.set_gateway_route("dev-A", "irrelevant-node", {"cap_a", "cap_b"});
    REQUIRE(registry.gateway_has_wire_capability("dev-A", "cap_a"));
    REQUIRE(registry.gateway_has_wire_capability("dev-A", "cap_b"));

    // A reconnect behind a DIFFERENT gateway build advertises a narrower set.
    registry.set_gateway_route("dev-A", "irrelevant-node", {"cap_c"});

    CHECK_FALSE(registry.gateway_has_wire_capability("dev-A", "cap_a"));
    CHECK_FALSE(registry.gateway_has_wire_capability("dev-A", "cap_b"));
    CHECK(registry.gateway_has_wire_capability("dev-A", "cap_c"));
}

TEST_CASE("AgentRegistry: clear_stream_if_session clears advertised wire capabilities — the "
          "DISCONNECTED path",
          "[server][dispatch][chokepoint][gateway]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(make_agent_info("dev-A"));
    registry.map_session("sess-1", "dev-A");
    registry.set_gateway_route("dev-A", "irrelevant-node",
                               {std::string(kGatewayWireCapabilityDispatchTagV1)});
    REQUIRE(registry.gateway_has_wire_capability(
        "dev-A", kGatewayWireCapabilityDispatchTagV1));

    // Mirrors GatewayUpstreamServiceImpl::NotifyStreamStatus's DISCONNECTED
    // branch exactly: clear_stream_if_session(agent_id, session_id).
    registry.clear_stream_if_session("dev-A", "sess-1");

    CHECK_FALSE(
        registry.gateway_has_wire_capability("dev-A", kGatewayWireCapabilityDispatchTagV1));
}

TEST_CASE("AgentRegistry: clear_gateway_wire_capabilities drops the advertised set directly",
          "[server][dispatch][chokepoint][gateway]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(make_agent_info("dev-A"));
    registry.set_gateway_route("dev-A", "irrelevant-node", {"cap_a"});
    REQUIRE(registry.gateway_has_wire_capability("dev-A", "cap_a"));

    registry.clear_gateway_wire_capabilities("dev-A");

    CHECK_FALSE(registry.gateway_has_wire_capability("dev-A", "cap_a"));
}
