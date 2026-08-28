#pragma once

/// @file agent_registry.hpp
/// Agent session tracking, scope evaluation, and fleet health aggregation.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <grpcpp/grpcpp.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <yuzu/metrics.hpp>
#include "agent.grpc.pb.h"
#include "command_capability.hpp"
#include "command_capability_parsers.hpp"
#include "dispatch_caller.hpp"
#include "event_bus.hpp"
#include "scope_engine.hpp"

// Forward declarations
namespace yuzu::server {
class TagStore;
class CustomPropertiesStore;
class ResultSetStore;
class DeviceTokenStore;
/// PLAN (p8/PR1.9c): forward-declared so `ClassifiedCommand` below can name
/// it as the only PRODUCTION friend able to construct one — the full
/// definition lives entirely in server.cpp (`ServerImpl` has no separate
/// header; `Server`'s factory is the only public surface).
class ServerImpl;
} // namespace yuzu::server

namespace yuzu::server::detail {

namespace pb = ::yuzu::agent::v1;

/// CC-03 (`proto/yuzu/gateway/v1/gateway.proto`'s `StreamStatusNotification.
/// wire_capabilities` doc comment): the ONE literal a gateway build must
/// advertise on every CONNECTED notification before the server will route a
/// dispatch-tagged `CommandRequest` to an agent behind it — proof the
/// gateway's vendored `agent.proto` carries `CommandRequest.dispatch_tag = 9`
/// and forwards it untouched. Named here (not re-typed at each call site)
/// because `gateway_service_impl.cpp` reads it off the wire and this file's
/// own send path checks for it — a second, independently spelled copy is
/// exactly the kind of drift this file's #1788 doc comments warn about
/// elsewhere.
inline constexpr std::string_view kGatewayWireCapabilityDispatchTagV1{"command_dispatch_tag_v1"};

// ── Dispatch classification + authorization (PR1.9c) ─────────────────────────
//
// The chokepoint invariant this section exists to hold: it must be
// IMPOSSIBLE to put a `CommandRequest` on the wire without BOTH a
// classification decision (does this `plugin.action` pair exist, and what is
// it?) AND an authorization decision (may `caller` issue it?). Provenance,
// not syntax (peer finding PLAN-011): a syntactically valid `dispatch_tag` on
// a hand-built `pb::CommandRequest` proves nothing on its own, because
// `encode_dispatch_tag` is a public, pure helper — so the guarantee below is
// a TYPE invariant (`ClassifiedCommand`'s private constructor), never a
// string check alone.

/// Why `ServerImpl::build_classified_command` refused a dispatch. Every
/// value is counted separately by the caller (ADR-0033 §2: "never a
/// permissive default") — `Unclassified`/`Ambiguous` mirror
/// `ClassificationError` 1:1; `AnonymousOperator`/`Forbidden` are this
/// package's own authorization arm.
enum class DispatchDenialReason : uint8_t {
    Unclassified,      ///< No `CommandCapability` row matches `plugin.action`
                       ///< (also raised for a row whose `execute_gate` parsed
                       ///< as `ExecuteGate::Unspecified` — #1398 defense in
                       ///< depth; see `command_capability.hpp`. That should be
                       ///< IMPOSSIBLE by construction — every fragment's own
                       ///< compile-time sweep makes an omitted `.execute_gate`
                       ///< a build failure — so reaching this arm at runtime
                       ///< means that sweep itself is broken, not that this
                       ///< row is merely unclassified in the ordinary sense).
    Ambiguous,         ///< Two+ fragments independently declared the same row.
    AnonymousOperator, ///< `caller.system == false` with an empty `principal`.
    Forbidden,         ///< Classified, but `caller` may not issue it — either an
                       ///< operator lacking the resolved securable/operation, or
                       ///< ANY operator attempting a `system_reserved` row.
    ApprovalRequired,  ///< #1398: classified and RBAC-authorized, but `cap
                       ///< .execute_gate` requires proof of an approval
                       ///< decision (`DispatchCaller::approval_provenance`)
                       ///< the caller does not carry — `AdminOrApproval`
                       ///< additionally admits an effective-admin caller with
                       ///< no provenance at all; `AlwaysApproval` never does.
                       ///< Deliberately AFTER `Forbidden` in evaluation order:
                       ///< approval is never a substitute for a missing RBAC
                       ///< grant, only for the ADDITIONAL gate on top of one.
    KillSwitched,      ///< Classified and authorized, but the per-action kill
                       ///< switch is OFF for this `plugin.action` (or the config
                       ///< store is degraded, which `action_allowed` reports as
                       ///< disabled — never as enabled). Deliberately DISTINCT
                       ///< from `Forbidden`: this is an operator-thrown
                       ///< emergency stop, not an authorization verdict, and an
                       ///< incident review needs to tell the two apart.
};

/// A refused dispatch. `securable`/`operation` are populated only once
/// classification itself succeeded — `Unclassified`/`Ambiguous` carry no
/// resolved securable, there is nothing to name yet (a caller
/// logging/auditing a denial must branch on `reason` before trusting
/// `securable`). `AnonymousOperator` and `Forbidden` are raised AFTER
/// classification resolved, so both DO name the securable the caller failed
/// to satisfy — that is what makes the audit line actionable.
///
/// `securable` owns its characters rather than viewing `CommandCapability`'s
/// static storage: a denial is the exceptional path, and the consumers
/// concatenate it into operator-facing messages.
struct DispatchDenial {
    DispatchDenialReason reason;
    std::string securable;
    authz::Operation operation{authz::Operation::Read};
};

/// The ONE string form of a `DispatchDenialReason` — snake_case, matching
/// the existing `yuzu_server_dispatch_denied_total{reason=...}` metric label
/// values (unchanged by #1398; this function only deduplicates the mapping,
/// it does not relabel anything already in production dashboards/alerts).
/// Used for BOTH the metric label and the route-local audit detail
/// (`server.cpp`'s `/api/command` handler) — an incident review needs the
/// SAME string in both places to correlate a metric spike with the audit
/// rows that produced it, and a single source avoids the two silently
/// drifting apart the way a hand-duplicated switch invites. No `default:`
/// case (see `authz::to_string` in `authz_model.hpp` for the same pattern)
/// so `-Werror=switch` catches a future `DispatchDenialReason` enumerator
/// added here without a matching label.
[[nodiscard]] constexpr std::string_view to_string(DispatchDenialReason reason) {
    switch (reason) {
        case DispatchDenialReason::Unclassified: return "unclassified";
        case DispatchDenialReason::Ambiguous: return "ambiguous";
        case DispatchDenialReason::AnonymousOperator: return "anonymous_operator";
        case DispatchDenialReason::Forbidden: return "forbidden";
        case DispatchDenialReason::ApprovalRequired: return "approval_required";
        case DispatchDenialReason::KillSwitched: return "kill_switched";
    }
    return "";
}

/// The pure classify+authorize DECISION `ServerImpl::build_classified_command`
/// is built around, extracted so it is directly unit-testable without a live
/// `ServerImpl`/`RbacStore`/database — the same reasoning
/// `dispatch_confined_arms.hpp` and `dispatch_target_shape.hpp` give for their
/// own extractions: a from-scratch copy inside a test is how a shared rule
/// silently drifts from what production actually enforces.
///
/// `has_permission` is injected rather than a live `RbacStore*` so this
/// function's job stays exactly one question — "is `principal` granted
/// `operation` on `securable`, right now" — and every HTTP/session-layer
/// nuance stays OUTSIDE it, owned by whatever binds the callback. Never
/// memoize the callback's answer across calls (ADR-0012 §4) — this function
/// itself never does, and neither may a caller.
///
/// WHAT THE PRODUCTION BINDER ACTUALLY HANDLES TODAY (server.cpp): legacy-open
/// (a loaded-and-disabled RbacStore admits, as every other dispatch-adjacent
/// read here does) and a raw `RbacStore::check_permission`. It does NOT apply
/// JIT elevation: `auth::effective_role` elevates a cookie session to admin for
/// its window, and the elevation-aware surface gate (`require_permission`)
/// admits on that, but this callback receives only a principal STRING and
/// resolves that principal's BASE grants. So a JIT-elevated operator can clear
/// the surface gate and then be denied `Forbidden` here for a securable their
/// base role lacks. That is FAIL-CLOSED — it denies, never over-permits — but
/// it is a real gap in the elevated-dispatch workflow rather than a design
/// choice, and whether elevated authority SHOULD reach dispatch is a security
/// decision that needs its own review. Tracked; do not silently widen this
/// callback to close it.
///
/// System arm (PLAN item 2): `caller.system == true` is trusted BY
/// CONSTRUCTION — `DispatchCaller::system` is set explicitly only at
/// background/system call sites, never derived from external input
/// (`dispatch_caller.hpp`) — so it is routed under an explicit system
/// identity rather than a caller-attributable RBAC decision, which is
/// exactly what `system_reserved` rows are FOR
/// (`capability_decls/core_dispatch_capabilities.hpp`). What a system caller
/// is NOT excused from is classification itself: an unclassified or
/// ambiguous `plugin.action` is refused for a system caller exactly as for an
/// operator one — "route under an identity", never "skip the chokepoint".
[[nodiscard]] inline std::expected<CommandCapability, DispatchDenial>
classify_and_authorize_dispatch(
    const CommandCapabilityRegistry& registry, const DispatchCaller& caller,
    std::string_view plugin, std::string_view action,
    const std::function<bool(std::string_view principal, std::string_view securable,
                             authz::Operation operation)>& has_permission) {
    auto classified = registry.classify(plugin, action);
    if (!classified) {
        return std::unexpected(DispatchDenial{
            classified.error() == ClassificationError::Ambiguous ? DispatchDenialReason::Ambiguous
                                                                  : DispatchDenialReason::Unclassified,
            {}, authz::Operation::Read});
    }
    const CommandCapability cap = *classified;

    // #1398 defense in depth: see DispatchDenialReason::Unclassified's doc
    // comment — every fragment's compile-time sweep should make this
    // unreachable, so reaching it means that sweep is broken, not that this
    // row is ordinarily unclassified. Checked before the system-caller early
    // return: an unclassified/ambiguous plugin.action is refused for a
    // system caller exactly as for an operator one (see this function's own
    // "System arm" doc comment above), and an Unspecified gate is the same
    // shape of classification failure.
    if (cap.execute_gate == ExecuteGate::Unspecified) {
        return std::unexpected(
            DispatchDenial{DispatchDenialReason::Unclassified, {}, authz::Operation::Read});
    }

    if (caller.system)
        return cap;

    // No anonymous operator dispatch (PLAN item 2): an empty principal must
    // never reach `has_permission`, where a legacy-open store would admit it
    // by accident — `RbacStore::check_permission` has no notion of "no such
    // caller", only of "no matching role_permissions row".
    if (caller.principal.empty())
        return std::unexpected(
            DispatchDenial{DispatchDenialReason::AnonymousOperator, std::string(cap.securable),
                           cap.operation});

    // A `system_reserved` row is dispatchable ONLY under a system caller
    // (PLAN item 2) — never caller-attributable, so an operator is refused
    // here regardless of what RBAC says about them; consulting
    // `has_permission` for a row that by definition names no legitimate
    // operator grant would be a category error, not a stricter check.
    if (cap.system_reserved)
        return std::unexpected(
            DispatchDenial{DispatchDenialReason::Forbidden, std::string(cap.securable),
                           cap.operation});

    if (!has_permission(caller.principal, cap.securable, cap.operation))
        return std::unexpected(
            DispatchDenial{DispatchDenialReason::Forbidden, std::string(cap.securable),
                           cap.operation});

    // #1398: the approval-gate dimension, checked LAST — after RBAC, never
    // instead of it. Approval proves an additional decision was made on top
    // of a grant the caller already holds; it can never substitute for a
    // missing one. `AdminOrApproval` additionally admits an effective-admin
    // caller with no approval provenance at all (mirrors the governed
    // `POST /api/instructions/:id/execute` path's own `role-gated` bypass);
    // `AlwaysApproval` admits ONLY a caller carrying real provenance,
    // effective-admin or not.
    const bool has_provenance = caller.approval_provenance != ApprovalProvenance::None;
    // Gate 3 (cpp-expert): a `switch` with no `default:`, not an if-chain —
    // matches `to_string(DispatchDenialReason)`'s own no-`default:` doctrine
    // above, so a future 5th `ExecuteGate` value is a `-Werror=switch` build
    // failure here instead of a silent "no approval required" fallthrough.
    switch (cap.execute_gate) {
        case ExecuteGate::Unspecified:
            // Unreachable in practice — the check earlier in this function
            // already denies `Unspecified` before this point is reached.
            // Enumerated explicitly (not folded into a `default:`, which
            // would defeat the switch-exhaustiveness protection above) so
            // this arm stays defense-in-depth rather than dead code that
            // silently permits if the earlier check is ever removed.
            return std::unexpected(
                DispatchDenial{DispatchDenialReason::ApprovalRequired, std::string(cap.securable),
                               cap.operation});
        case ExecuteGate::None:
            break;
        case ExecuteGate::AdminOrApproval:
            if (!has_provenance && !caller.principal_is_admin) {
                return std::unexpected(DispatchDenial{DispatchDenialReason::ApprovalRequired,
                                                       std::string(cap.securable), cap.operation});
            }
            break;
        case ExecuteGate::AlwaysApproval:
            if (!has_provenance) {
                return std::unexpected(DispatchDenial{DispatchDenialReason::ApprovalRequired,
                                                       std::string(cap.securable), cap.operation});
            }
            break;
    }

    return cap;
}

/// The frozen v1 dispatch-tag wire grammar (`command_capability_parsers.hpp`),
/// composed once so `ServerImpl::build_classified_command` and this file's own
/// tests always stamp/verify a tag the IDENTICAL way — `encode_dispatch_tag` +
/// `compute_plan_hash` are p1-owned pure helpers; this is the one place p8
/// composes them, so a test can call this directly rather than re-deriving the
/// composition from scratch.
[[nodiscard]] inline std::string
compute_dispatch_tag(const CommandCapability& cap, std::string_view plugin, std::string_view action,
                     const std::map<std::string, std::string>& parameters,
                     std::string_view target_arm, std::string_view execution_id) {
    return encode_dispatch_tag(
        cap.dispatch_class, cap.mutability,
        compute_plan_hash(plugin, action, parameters, target_arm, execution_id));
}

class ClassifiedCommand; // Forward decl — completed below; needed as an
                         // incomplete type by the declaration immediately
                         // following.

/// Forward declaration so `ClassifiedCommand` can friend it below — the
/// definition (which needs the completed class) follows the class. Default
/// arguments live here, the one declaration every caller and the friend
/// grant both see; the out-of-class definition repeats none of them (a
/// second default-argument set on the same declaration is ill-formed).
[[nodiscard]] inline std::expected<ClassifiedCommand, DispatchDenial> finalize_classified_command(
    const CommandCapability& cap,
    const std::function<bool(std::string_view plugin, std::string_view action)>& action_allowed,
    std::string_view raw_plugin, std::string_view raw_action, const std::string& command_id,
    const std::unordered_map<std::string, std::string>& parameters = {},
    const std::string& payload = {}, int stagger_seconds = 0, int delay_seconds = 0,
    const std::string& target_arm = {}, const std::string& execution_id = {});

/// PLAN item 3 (PLAN-011, provenance not syntax): the type-level guarantee
/// that a `pb::CommandRequest` reaching `AgentRegistry::send_to`/`send_to_all`
/// passed through `ServerImpl::build_classified_command` — a syntactically
/// valid `dispatch_tag` proves nothing on its own, since `encode_dispatch_tag`
/// is a public, pure helper any caller could stamp onto a hand-built proto.
/// The guarantee is therefore a TYPE invariant: PRIVATE constructor, no public
/// setter, no public conversion that yields a mutable `pb::CommandRequest` —
/// only `ServerImpl` (production), `finalize_classified_command` (production,
/// below), and `ClassifiedCommandTestAccess` (tests, mirroring
/// `EngineLivenessTestAccess` in `engine_principal_store.hpp`) may construct
/// one. A caller that hand-builds a protobuf cannot reach the registry at
/// all: there is no overload of `send_to`/`send_to_all` that accepts one.
class ClassifiedCommand {
public:
    /// Read-only view of the wire command. Deliberately a named accessor
    /// returning `const&`, never a conversion operator — a conversion would
    /// let a `ClassifiedCommand` silently decay to a mutable
    /// `pb::CommandRequest` at a call site that forgot which type it held.
    [[nodiscard]] const pb::CommandRequest& wire() const noexcept { return cmd_; }

private:
    friend class yuzu::server::ServerImpl;
    friend struct ClassifiedCommandTestAccess;
    friend std::expected<ClassifiedCommand, DispatchDenial> finalize_classified_command(
        const CommandCapability&, const std::function<bool(std::string_view, std::string_view)>&,
        std::string_view, std::string_view, const std::string&,
        const std::unordered_map<std::string, std::string>&, const std::string&, int, int,
        const std::string&, const std::string&);

    explicit ClassifiedCommand(pb::CommandRequest cmd) : cmd_(std::move(cmd)) {}

    pb::CommandRequest cmd_;
};

/// The composition step `ServerImpl::build_classified_command` runs AFTER
/// `classify_and_authorize_dispatch` succeeds — extracted for the identical
/// reason that function was: a from-scratch copy inside a test is how a
/// shared rule silently drifts from what production actually enforces, and
/// until this extraction NOTHING unit-tested it directly (M6, wave1
/// remediation). Two behaviours live here, both revert-survivor-sensitive:
///
/// 1. **The per-action kill switch.** `action_allowed` is injected exactly
///    like `classify_and_authorize_dispatch`'s `has_permission` — the
///    production binder wraps `PluginConfigStore::action_allowed`, fail-closed
///    by that store's own contract (a closed store, a lease timeout, or a
///    query failure all report "not allowed"). An empty/unset callback means
///    no kill-switch store is wired at all (legacy-open for THIS gate,
///    mirroring how an absent `plugin_config_store_` behaves in
///    `server.cpp`) — never call this with a callback that unconditionally
///    returns `true` "to be safe"; that reintroduces exactly the ZERO-callers
///    gap this composition exists to close.
/// 2. **BR-009 canonical wire names.** The wire command is built from `cap`'s
///    catalogue-resolved spelling (`cap.plugin`/`cap.action`), never the
///    caller's raw strings — `classify()` is case-insensitive but the agent
///    matches case-SENSITIVELY, so a caller passing `plugin="TAR"` would
///    otherwise be authorized here and rejected on the endpoint. `raw_plugin`/
///    `raw_action` are threaded through ONLY into the dispatch-tag hash
///    (`compute_dispatch_tag`), unchanged from what `build_classified_command`
///    always passed there — the hash and the wire fields are deliberately
///    fed different spellings and this preserves that, rather than "fixing"
///    it as part of an unrelated extraction.
[[nodiscard]] inline std::expected<ClassifiedCommand, DispatchDenial> finalize_classified_command(
    const CommandCapability& cap,
    const std::function<bool(std::string_view plugin, std::string_view action)>& action_allowed,
    std::string_view raw_plugin, std::string_view raw_action, const std::string& command_id,
    const std::unordered_map<std::string, std::string>& parameters,
    const std::string& payload, int stagger_seconds, int delay_seconds,
    const std::string& target_arm, const std::string& execution_id) {
    if (action_allowed && !action_allowed(cap.plugin, cap.action)) {
        return std::unexpected(
            DispatchDenial{DispatchDenialReason::KillSwitched, std::string(cap.securable),
                           cap.operation});
    }

    pb::CommandRequest cmd;
    cmd.set_command_id(command_id);
    cmd.set_plugin(std::string(cap.plugin));
    cmd.set_action(std::string(cap.action));
    for (const auto& [k, v] : parameters)
        (*cmd.mutable_parameters())[k] = v;
    if (!payload.empty())
        cmd.set_payload(payload);
    if (stagger_seconds > 0)
        cmd.set_stagger_seconds(stagger_seconds);
    if (delay_seconds > 0)
        cmd.set_delay_seconds(delay_seconds);

    const std::map<std::string, std::string> ordered_params(parameters.begin(), parameters.end());
    cmd.set_dispatch_tag(
        compute_dispatch_tag(cap, raw_plugin, raw_action, ordered_params, target_arm, execution_id));

    return ClassifiedCommand(std::move(cmd));
}

/// Test-only door to the private constructor above (#2367 pattern — mirrors
/// `EngineLivenessTestAccess`, `engine_principal_store.hpp`, identical
/// rationale). Declared here; the definition is deliberately withheld from
/// every production translation unit and lives ONLY in
/// `tests/unit/server/classified_command_test_access.cpp`, a TU that links
/// into the test binary and is never added to server_core's (or any other
/// production target's) source list. Production code MUST go through
/// `ServerImpl::build_classified_command` — if a production TU ever
/// referenced `ClassifiedCommandTestAccess::make`, it would still COMPILE
/// (the declaration is visible via this header) but FAIL TO LINK, because no
/// production link line carries the definition. That is what upgrades
/// "test-only" from a doc-comment convention to a structural,
/// compile/link-time-enforced control, exactly as #2367 did for
/// `EngineLivenessTestAccess`. This exists only so a unit test can construct
/// a `ClassifiedCommand` fixture without a live
/// `ServerImpl`/`RbacStore`/`CommandCapabilityRegistry`, and so the ONE
/// pre-existing test that threads a real `pb::CommandRequest` through
/// `wire_and_dispatch_confined` into a REAL `AgentRegistry`
/// (`test_dispatch_confined_arms.cpp`'s K-1 case) keeps compiling against
/// `send_to`'s narrowed signature.
struct ClassifiedCommandTestAccess {
    [[nodiscard]] static ClassifiedCommand make(pb::CommandRequest cmd);
};

// -- Plugin metadata ----------------------------------------------------------

struct PluginMeta {
    std::string name;
    std::string version;
    std::string description;
    std::vector<std::string> actions;
};

// -- Agent session (one per connected agent) ----------------------------------
//
// IMMUTABILITY CONTRACT: the identity fields (agent_id..scopable_tags) are
// fully populated BEFORE the session is installed in the registry and are
// never mutated afterwards — re-registration REPLACES the shared_ptr, it
// does not edit in place. Lock-free readers (scope evaluation, the DEX perf
// provider) depend on this — NONE of them reads `gateway_node` or
// `gateway_wire_capabilities` (verified: their only readers are
// send_to/send_to_all, agent_registry.cpp, both under `stream_mu`), which is
// exactly why those two are NOT in this list. Post-publication writes are
// confined to stream/server_context/peer_cert_pem, gateway_node +
// gateway_wire_capabilities (all under stream_mu — the trailing pair
// published together by set_gateway_route, M1 review fix; an earlier
// revision wrote gateway_node under the registry mu_ instead, which both
// raced stream_mu's readers and contradicted this comment) and the atomic
// last_activity_epoch_ms. (Governance G3 cpp-safety — keep it true.)

struct AgentSession {
    std::string agent_id;
    std::string session_id; // Unique per connection — used to prevent stale cleanup races
    std::string hostname;
    std::string os;
    std::string arch;
    std::string agent_version;
    std::vector<std::string> plugin_names;
    std::vector<PluginMeta> plugin_meta;
    std::unordered_map<std::string, std::string> scopable_tags;
    std::string gateway_node; // Non-empty if agent is connected via gateway

    // Stream pointer -- valid only while Subscribe() RPC is active.
    grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream = nullptr;
    grpc::ServerContext* server_context = nullptr; // for timeout cancellation
    // PR3 H-1: the client leaf PEM presented when this Subscribe stream was
    // established, captured so a background sweep can re-evaluate revocation on
    // the long-lived stream (the establishment gate only runs once). Empty when
    // the agent presented no client cert. Guarded by stream_mu alongside stream/
    // server_context.
    std::string peer_cert_pem;
    /// PLAN item 5 (CC-03): the literal wire-capability strings this agent's
    /// gateway advertised on its most recent CONNECTED
    /// `StreamStatusNotification` — empty for a direct (non-gateway) agent
    /// and for a gateway build too old to advertise any. Guarded by
    /// `stream_mu` alongside the other post-publication, connection-lifetime
    /// fields above: a reconnect (a fresh CONNECTED) REPLACES this set, it is
    /// never merged with a prior connection's advertisement (PLAN item 5).
    std::unordered_set<std::string> gateway_wire_capabilities;
    std::mutex stream_mu;

    // Last activity timestamp -- updated on Subscribe reads and Heartbeats.
    // Atomic to avoid acquiring the registry mutex on every stream Read.
    std::atomic<int64_t> last_activity_epoch_ms{
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count()};
};

// -- Agent registry -----------------------------------------------------------

class AgentRegistry {
public:
    explicit AgentRegistry(EventBus& bus, yuzu::MetricsRegistry& metrics);

    /// Register (or re-register) an agent. On re-registration, first revokes any device tokens
    /// bound to this agent_id (W1.5 / #823, corrected by #3401 — see `revoke_by_device`) BEFORE
    /// installing the new session, so a briefly-impersonated agent (mTLS-disabled flow, #779)
    /// cannot keep replaying a token issued to the legitimate agent. First-time registrations
    /// (no prior entry) skip the revoke, preserving the operator workflow of pre-issuing a token
    /// for an agent_id that has not registered yet.
    ///
    /// Fails closed (ADR-0012 §1): if a wired device-token store reports a genuine revoke
    /// failure, the registration is REFUSED — `unexpected(msg)` — and nothing changes (no
    /// session installed, no management-group membership, no topology invalidation). A caller
    /// MUST NOT install a session after a refusal. The revoke runs OFF the registry mutex (see
    /// the .cpp for the two-phase structure, precedent `sweep_revoked`) — only the map
    /// read/write is held under `mu_`, not the blocking Postgres round-trip.
    ///
    /// Also refused, same way, if superseded: because the revoke runs off-lock, a second
    /// `register_agent` call for the same `agent_id` can install its session while this call's
    /// revoke is still in flight. Phase 2 re-checks the map entry against the pointer this call
    /// observed in phase 1 — a mismatch means a newer registration already won, and THIS call
    /// yields rather than overwriting a live session with a stale one (its own revoke already
    /// committed, so nothing is lost by not installing). This restores the ordering the old
    /// single-locked implementation gave for free; it does not add a NEW guarantee beyond that.
    [[nodiscard]] std::expected<void, std::string> register_agent(const pb::AgentInfo& info);

    void set_stream(const std::string& agent_id,
                    grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream,
                    grpc::ServerContext* context = nullptr,
                    const std::string& peer_cert_pem = {});

    void clear_stream(const std::string& agent_id);

    /// PR3 H-1: re-evaluate revocation on every live Subscribe stream and tear
    /// down (TryCancel) any whose presented client leaf is now revoked. The
    /// establishment gate (`Subscribe`) only checks once; a long-lived stream
    /// would otherwise keep dispatching to a revoked/compromised agent until it
    /// voluntarily reconnects (which a hostile agent never does). Driven
    /// periodically from the reaper thread and callable immediately after an
    /// operator revoke (PR4) for prompt teardown. `is_revoked(peer_pem)` returns
    /// true iff that leaf is on the CRL; sessions with no presented cert are
    /// skipped. The predicate is evaluated OFF stream_mu (it reads ca_store);
    /// teardown re-acquires the lock and re-checks the cert is unchanged.
    /// Returns the `agent_id`s whose streams were cancelled (so the caller can
    /// emit a per-teardown audit row — the registry holds no AuditStore). Null
    /// predicate → no-op (empty).
    std::vector<std::string>
    sweep_revoked(const std::function<bool(const std::string& peer_cert_pem)>& is_revoked);

    /// Update last_activity timestamp for an agent (called on heartbeat + subscribe reads).
    void touch_activity(const std::string& agent_id);

    /// Cancel Subscribe streams for agents that haven't heartbeated within the timeout.
    void reap_stale_sessions(std::chrono::seconds timeout);

    void remove_agent(const std::string& agent_id);

    /// Remove an agent only if its current session_id matches (prevents stale
    /// Subscribe cleanup from clobbering a newer reconnection).
    void remove_agent_if_session(const std::string& agent_id, const std::string& session_id);

    /// Clear stream only if the session_id matches the current session.
    void clear_stream_if_session(const std::string& agent_id, const std::string& session_id);

    /// PLAN item 5 (CC-03) / M1 (review finding, post-merge round): record
    /// the gateway node AND the literal wire-capability strings it
    /// advertised for `agent_id` on a CONNECTED `StreamStatusNotification` —
    /// called by `GatewayUpstreamServiceImpl::NotifyStreamStatus`. ONE call,
    /// not two: both fields are published together under `stream_mu`, the
    /// SAME lock `send_to`/`send_to_all` read them under (agent_registry.cpp)
    /// — this used to be two setters in two different lock domains (`node`
    /// under the registry `mu_` only), which was both a C++ data race on
    /// `gateway_node` and let a reader observe `node` present with
    /// capabilities not yet replaced (a false gateway-capability denial).
    /// `capabilities` is ALWAYS a full replace, never a merge: a reconnect
    /// (fresh CONNECTED) behind an upgraded — or downgraded — gateway build
    /// must not keep stacking capabilities the new connection never
    /// advertised. No-op if `agent_id` is not currently registered.
    void set_gateway_route(const std::string& agent_id, const std::string& node,
                           std::vector<std::string> capabilities);

    /// PLAN item 5: drop every advertised wire capability for `agent_id`.
    /// Called on DISCONNECTED. `clear_stream_if_session` also clears this set
    /// (a session whose stream is gone has nothing live to route through),
    /// so a caller that reaches disconnection via that path needs no
    /// separate call.
    void clear_gateway_wire_capabilities(const std::string& agent_id);

    /// PLAN item 5: true iff `agent_id` is currently registered AND its most
    /// recent gateway CONNECTED notification advertised `capability`
    /// literally. False for an unknown agent, a direct (non-gateway) agent,
    /// or a gateway build that never advertised it — every one of those is
    /// "cannot prove this gateway forwards a tagged command", the fail-closed
    /// direction `send_to`/`send_to_all`'s routed-path check depends on.
    [[nodiscard]] bool gateway_has_wire_capability(const std::string& agent_id,
                                                   std::string_view capability) const;

    /// #826: record a peer-IP (e.g. `1.2.3.4`, no port, no scheme) as a
    /// trusted gateway. Populated by `GatewayUpstreamServiceImpl` when a
    /// gateway successfully proxy-registers an agent — the gateway's own
    /// peer becomes "known good" for the TTL window.
    ///
    /// Subscribe's peer-mismatch check (`agent_service_impl.cpp`) consults
    /// this map IN ADDITION to checking that the Subscribe peer IP equals
    /// the Register peer IP. A peer that is NEITHER the original Register
    /// peer NOR a recorded trusted gateway is always rejected, even when
    /// `--gateway-mode` is on (the old code skipped the check entirely
    /// under gateway-mode — the #826 vulnerability).
    ///
    /// **W1.3 R2 / UP-2 / UP-3.** The set used to be `unordered_set` with
    /// no eviction; in a churn-heavy NAT environment the map grew
    /// unboundedly, and an attacker who briefly controlled a routable IP
    /// would keep trust for the lifetime of the process. The map now
    /// records `peer_ip → last_seen` and lookups also require the entry to
    /// be within the TTL window (default 1 h). On every insert we
    /// opportunistically sweep stale entries; if at the entry cap (1024),
    /// we evict the oldest entry first to make room for the new one. Each
    /// successful insert/refresh emits the `yuzu_trusted_gateway_peer_set_size`
    /// gauge so the operator can dashboard the set's health.
    void note_trusted_gateway_peer(std::string_view peer_ip);

    /// Returns true if `peer_ip` was previously recorded via
    /// `note_trusted_gateway_peer` AND the entry is still within the TTL
    /// window. Empty `peer_ip` always returns false — a defence-in-depth
    /// guard so a caller that fails to extract the IP cannot accidentally
    /// satisfy the trusted check.
    bool is_trusted_gateway_peer(std::string_view peer_ip) const;

    /// W1.3 R2: trusted-gateway TTL (eviction window for an entry that
    /// has not been refreshed). Hard-coded for this PR — operator-tunable
    /// flag is tracked as a follow-up.
    static constexpr auto kTrustedGatewayTtl = std::chrono::hours(1);

    /// W1.3 R2: cap on the number of trusted-gateway entries the registry
    /// will hold simultaneously. At cap, the oldest entry is evicted on
    /// insert. 1024 is comfortable headroom for any realistic deployment
    /// (load-balanced gateway clusters have O(tens) of peers); the cap
    /// exists strictly as a memory-DoS guard.
    static constexpr std::size_t kTrustedGatewayCap = 1024;

    /// Test hook: number of entries currently in the trusted-gateway map.
    /// Mirrors `yuzu_trusted_gateway_peer_set_size` for unit tests that
    /// don't want to scrape the Prometheus surface.
    std::size_t trusted_gateway_peer_count() const;

    /// Test hook: subtract `offset` from every entry's last_seen, then
    /// re-publish the gauge. Pushes entries toward (or past) the TTL
    /// boundary without sleeping. Production code MUST NOT call this —
    /// no caller in `server/core/src/**` references it.
    void expire_trusted_gateway_for_test(std::chrono::seconds offset);

    /// W1.5 / #823: install the device-token store so `register_agent`
    /// revokes any device tokens bound to a previous incarnation of the
    /// same agent_id whenever a re-registration is detected. Optional —
    /// if never called, register_agent behaves as before and stale
    /// tokens survive re-registration. Wiring lives behind a setter rather
    /// than the constructor to avoid disturbing the existing AgentRegistry
    /// construction sites, and because production `server.cpp` does not
    /// yet construct a DeviceTokenStore (the call site exists in tests
    /// today; the invariant lands now so it can't be forgotten when the
    /// production wiring catches up).
    ///
    /// Thread contract: holds the registry mutex so a concurrent
    /// `register_agent` cannot observe a partially-installed pointer.
    /// In practice the only caller is the startup wiring path, but the
    /// lock costs nothing and removes a footgun. `register_agent` itself
    /// only reads this pointer under `mu_` — the revoke call it makes
    /// through it runs OFF the lock (#3401; see the .cpp).
    void set_device_token_store(DeviceTokenStore* store);

    /// Test hook: fires once, synchronously, in the calling thread between `register_agent`'s
    /// phase 1 (revoke) and phase 2 (install) — the exact window in which a concurrent
    /// registration for the same `agent_id` can complete and install its own session. Setting
    /// this to a callback that itself calls `register_agent` again deterministically exercises
    /// the supersede-detection path without real threads or timing (mirrors the
    /// `inject_*_fault_for_test` seams in `mcp_stream.hpp`). Cleared after firing — a callback
    /// that re-arms it will recurse. Production code MUST NOT call this — no caller in
    /// `server/core/src/**` references it.
    ///
    /// Single-threaded test use only: the member this sets is read/moved/cleared inside
    /// `register_agent` with no synchronization of its own (guarded neither by `mu_` nor a
    /// dedicated lock — deliberately, since the whole point of this hook is a same-thread,
    /// synchronous interleave rather than a real race). Setting it from one thread while another
    /// thread's `register_agent` call may read or fire it is a data race; every test using this
    /// hook must do so single-threaded (set, call the one `register_agent` that fires it, done).
    void set_register_agent_interleave_hook_for_test(std::function<void()> hook);

    // PLAN item 3 (provenance not syntax): only a `ClassifiedCommand` — mintable
    // ONLY by `ServerImpl::build_classified_command` (or the test-only door) —
    // can reach either of these. A hand-built `pb::CommandRequest` has no
    // overload to bind to; this is a compile-time invariant, not a runtime
    // check (`tests/unit/server/test_dispatch_chokepoint.cpp` pins it).
    //
    // Send a command to a specific agent. Returns false if agent not found,
    // the defensive dispatch_tag check fails, the routed-path gateway-capability
    // check refuses it (PLAN item 5), or the write itself failed. For gateway
    // agents (no local stream), adds to gateway_pending and returns true.
    bool send_to(const std::string& agent_id, const ClassifiedCommand& cmd);

    // Send command to all connected agents. Returns count of agents actually
    // reached — an agent refused by the defensive tag check or the routed-path
    // gateway-capability check (PLAN item 5) is silently excluded from the count,
    // never treated as an error for the other recipients.
    int send_to_all(const ClassifiedCommand& cmd);

    struct GatewayPendingCmd {
        std::string agent_id;
        // Unwrapped to the raw wire type on purpose: by the time a command is
        // queued here, `send_to`/`send_to_all` have already required a
        // `ClassifiedCommand` to reach this point — the provenance guarantee
        // has already done its job, and `forward_gateway_pending` (server.cpp)
        // only re-wraps this into a `SendCommandRequest`, never re-decides
        // classification or authorization.
        pb::CommandRequest cmd;
    };

    std::vector<GatewayPendingCmd> drain_gateway_pending();

    bool has_any() const;

    std::string display_name(const std::string& agent_id) const;

    // Build JSON array of all agents for the web UI (structured).
    nlohmann::json to_json_obj() const;

    // Build JSON array as a serialized string.
    std::string to_json() const;

    // Per-action description map: "plugin.action" -> human-readable description.
    static const std::unordered_map<std::string, std::string>& action_descriptions();

    // Build help catalog: deduplicated plugin metadata across all agents.
    std::string help_json() const;

    // Render help table as HTML fragment (thead + tbody rows).
    std::string help_html(std::string_view filter = "") const;

    // Render autocomplete dropdown items as HTML.
    std::string autocomplete_html(std::string_view query) const;

    // Render command palette instruction results as HTML.
    std::string palette_html(std::string_view query) const;

    // Get list of all agent IDs.
    std::vector<std::string> all_ids() const;

    // Look up the agent_id that was registered for a given Subscribe call.
    std::string find_agent_by_stream(
        grpc::ServerReaderWriter<pb::CommandRequest, pb::CommandResponse>* stream) const;

    std::size_t agent_count() const;

    // Map a session_id to an agent_id (called when Subscribe completes handshake).
    void map_session(const std::string& session_id, const std::string& agent_id);

    // Look up agent session by session_id (for heartbeat validation).
    std::shared_ptr<AgentSession> find_by_session(std::string_view session_id) const;

    // Get a session by agent_id (for scope evaluation).
    std::shared_ptr<AgentSession> get_session(const std::string& agent_id) const;

    // Evaluate a scope expression against all agents, return matching agent IDs.
    // `rs_store` resolves the `from_result_set:<id>` scope kind (capability §30)
    // to per-device membership, scoped to `principal`: a referenced set that
    // `principal` does not own resolves to an empty membership and never matches
    // (no cross-operator targeting — review finding B1). Pass the dispatching
    // operator as `principal` on every command path. Leaving `rs_store` null
    // (with `principal` empty) is safe ONLY for a scope expression that
    // contains NO from_result_set: atom — that is a CALLER OBLIGATION, not an
    // invariant this function can supply: nothing filters the atom out of a
    // parsed expression, so a no-store call site whose expression might carry
    // one (e.g. an operator-authored rule scope) must treat nullopt as
    // "unresolvable here — match nothing" (governance H1, 2026-07-29).
    // Aliases must be pre-resolved
    // to canonical ids by the caller. Stale members (offline / decommissioned
    // agents not in the live registry) drop silently.
    //
    // Returns std::nullopt (ADR-0036 + 2026-07-26 B2 fail-closed contract,
    // widened per governance H1 2026-07-29, and again per ADR-0045) in FIVE
    // cases, all load-bearing:
    //   1. The from_result_set: membership preload hits a Postgres error
    //      mid-scan — NEVER a partial/degraded membership map.
    //   2. The expression references a from_result_set: atom but `principal`
    //      is empty — e.g. a dispatch path that recovers the principal from
    //      an execution row's `dispatched_by` and that lookup missed. A real
    //      store exists but there is no owner to resolve against.
    //   3. The expression references a from_result_set: atom but `rs_store`
    //      is null — the atom cannot be resolved AT ALL at this call site.
    //      (Previously this case silently evaluated the atom false; under a
    //      NOT combinator that inverted to a fleet-wide match — for a
    //      Guardian rule arming an enforcing guard, a fleet-wide arm.)
    //   4. The expression references a props.<key> atom but `props_store`
    //      is null (ADR-0045) — same "cannot resolve at all here" shape as
    //      case 3.
    //   5. The expression references a props.<key> atom and the bulk
    //      get_values_for_keys preload hits a Postgres error (ADR-0045) —
    //      same shape as case 1, for CustomPropertiesStore instead of
    //      ResultSetStore.
    // All five are the same fail-open shape: under a NOT combinator, an atom
    // that resolves "no match" silently INVERTS to "matches every agent" — a
    // fleet-wide dispatch/arm, not a theoretical hardening gap. Every caller
    // that dispatches/enforces/targets on this result MUST treat nullopt as
    // "abort — do not proceed" (dispatch paths) or "match nothing" (push
    // paths, where arming nothing is the safe direction). NARROW: a scope
    // with NEITHER a from_result_set: NOR a props.<key> atom is completely
    // unaffected — value_or({}) is safe there.
    std::optional<std::vector<std::string>>
    evaluate_scope(const yuzu::scope::Expression& expr, const TagStore* tag_store,
                   const CustomPropertiesStore* props_store = nullptr,
                   ResultSetStore* rs_store = nullptr, std::string_view principal = {}) const;

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, std::shared_ptr<AgentSession>> agents_;
    std::unordered_map<std::string, std::string> session_to_agent_;
    EventBus& bus_;
    yuzu::MetricsRegistry& metrics_;
    std::mutex gw_pending_mu_;
    std::vector<GatewayPendingCmd> gw_pending_;

    /// #826 + W1.3 R2: trusted gateway peer-IPs → last_seen timestamp
    /// (steady_clock). Lookups are read-mostly (every Subscribe consults
    /// the map, inserts happen only on ProxyRegister success). Could be a
    /// `shared_mutex`, but the map is small (capped at
    /// `kTrustedGatewayCap`) and contention is negligible — keep a plain
    /// `mutex` for simplicity.
    ///
    /// Map (not set) so insert/refresh-on-existing-key updates the
    /// last_seen timestamp in-place, and stale entries can be swept by
    /// last_seen. Eviction policy: TTL (kTrustedGatewayTtl) at lookup
    /// time; opportunistic sweep on every insert; oldest-first eviction
    /// when at cap.
    mutable std::mutex trusted_gateway_mu_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point>
        trusted_gateway_peer_ips_;

    /// W1.3 R2: shared eviction-and-publish helper called by
    /// `note_trusted_gateway_peer`. Sweeps any entry older than
    /// kTrustedGatewayTtl, then if the map is at kTrustedGatewayCap
    /// removes the single oldest entry. Caller MUST hold
    /// `trusted_gateway_mu_`. Republishes the Prometheus gauge after the
    /// edit lands.
    void sweep_and_publish_trusted_gateway_locked();

    /// W1.5 / #823: optional device-token store used by `register_agent`
    /// to revoke stale tokens on re-registration. Guarded by `mu_` (set
    /// via `set_device_token_store`, read inside `register_agent`).
    ///
    /// Non-owning. `AgentRegistry` never constructs, destroys, or extends the lifetime of the
    /// pointee — the owner (test-scoped `DeviceTokenStore` instances only, today; the server's
    /// long-lived one once a wiring PR lands) MUST outlive this registry, or call
    /// `set_device_token_store(nullptr)` before its own destruction. There is NO production
    /// caller of `set_device_token_store` today (`server.cpp` never invokes it; the pointer stays
    /// `nullptr` in production, matching this store's own dormancy record). Once a wiring PR adds
    /// one, it MUST be one-time startup wiring, before any `register_agent` call can race it — a
    /// re-call mid-lifetime would need the same care `set_stream`/`clear_stream` already take
    /// around a session's raw pointers.
    DeviceTokenStore* device_token_store_{nullptr};

    /// Test-only, see `set_register_agent_interleave_hook_for_test`.
    std::function<void()> register_agent_interleave_hook_for_test_;
};

// -- Scope kind discovery catalog ---------------------------------------------
//
// One row per scope-expression ATTRIBUTE kind the `evaluate_scope` resolver
// (agent_registry.cpp, the `resolver` lambda inside the `agents_` loop) knows
// how to answer. Deliberately colocated with `evaluate_scope` rather than in
// the discovery module (`discover_routes.cpp`) so a reviewer touching the
// resolver sees this list in the same diff hunk / file.
//
// Does NOT cover the two GROUND kinds (`__all__`, `group:<name>`) — those are
// short-circuited by call sites BEFORE a scope expression ever reaches
// yuzu::scope::parse/evaluate (see docs/scope-walking-design.md §"Scope kind"
// and the `scope != "__all__"` guards in server.cpp / dashboard_routes.cpp),
// so they are never seen by this resolver and are listed separately by the
// discovery route.
//
// DRIFT CONTRACT: any NEW `if (key == ...)` / `key.starts_with(...)` branch
// added to the resolver lambda MUST get a matching entry here. The
// `test_discovery_routes.cpp` CROSS-CHECK test exercises `evaluate_scope` for
// every entry below (proving the enumerator is a SUBSET of what the resolver
// honors) and confirms a made-up kind resolves to no match (proving the
// resolver doesn't silently accept everything) — but it cannot detect a
// resolver branch that was added without a matching entry here. Keep both in
// sync by inspection when editing the resolver.
struct ScopeKindInfo {
    std::string kind;        ///< e.g. "tag:<key>"
    std::string syntax;      ///< e.g. "tag:<key> <op> <value>"
    std::string example;     ///< e.g. "tag:department == \"finance\""
    std::string description;
};

/// Every scope-expression ATTRIBUTE kind (post-ground-kind) the resolver
/// answers. Built once (static local) and cached; pure after construction.
const std::vector<ScopeKindInfo>& scope_kind_catalog();

// -- AgentHealthStore ---------------------------------------------------------
// Aggregates per-agent heartbeat status_tags into fleet-wide Prometheus metrics.

struct AgentHealthSnapshot {
    std::string agent_id;
    std::unordered_map<std::string, std::string> status_tags;
    std::chrono::steady_clock::time_point last_seen;
};

class AgentHealthStore {
public:
    void upsert(const std::string& agent_id,
                const google::protobuf::Map<std::string, std::string>& tags);

    void remove(const std::string& agent_id);

    void recompute_metrics(yuzu::MetricsRegistry& metrics, std::chrono::seconds staleness);

    /// Per-agent snapshots carrying ONLY the yuzu.perf_* heartbeat tags
    /// (dex_perf_rules.hpp keys) + agent_id, excluding entries staler than
    /// `staleness` (the same contract recompute_metrics prunes by — pass the
    /// same value so the /dex Performance read model and the Prometheus gauges
    /// see the same population). Deliberately NOT a general-purpose accessor:
    /// the copy runs under the heartbeat-upsert mutex, so it copies the
    /// minimum (G3 performance S1). Do NOT call on a hot path.
    std::vector<AgentHealthSnapshot> perf_snapshot(std::chrono::seconds staleness) const;

    /// Like perf_snapshot, but copies the NETWORK heartbeat facts
    /// (network_perf_rules.hpp kNetTag* keys) PLUS the perf tags the
    /// co-occurrence pressure check reads — the minimum the /network read model
    /// needs. Same staleness contract as recompute_metrics (pass the same value
    /// so the dashboard and the yuzu_fleet_net_* gauges see the same population).
    std::vector<AgentHealthSnapshot> net_snapshot(std::chrono::seconds staleness) const;

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, AgentHealthSnapshot> snapshots_;
};

} // namespace yuzu::server::detail
