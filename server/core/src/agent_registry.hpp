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
    Unclassified,      ///< No `CommandCapability` row matches `plugin.action`.
    Ambiguous,         ///< Two+ fragments independently declared the same row.
    AnonymousOperator, ///< `caller.system == false` with an empty `principal`.
    Forbidden,         ///< Classified, but `caller` may not issue it — either an
                       ///< operator lacking the resolved securable/operation, or
                       ///< ANY operator attempting a `system_reserved` row.
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

/// PLAN item 3 (PLAN-011, provenance not syntax): the type-level guarantee
/// that a `pb::CommandRequest` reaching `AgentRegistry::send_to`/`send_to_all`
/// passed through `ServerImpl::build_classified_command` — a syntactically
/// valid `dispatch_tag` proves nothing on its own, since `encode_dispatch_tag`
/// is a public, pure helper any caller could stamp onto a hand-built proto.
/// The guarantee is therefore a TYPE invariant: PRIVATE constructor, no public
/// setter, no public conversion that yields a mutable `pb::CommandRequest` —
/// only `ServerImpl` (production) and `ClassifiedCommandTestAccess` (tests,
/// mirroring `EngineLivenessTestAccess` in `engine_principal_store.hpp`) may
/// construct one. A caller that hand-builds a protobuf cannot reach the
/// registry at all: there is no overload of `send_to`/`send_to_all` that
/// accepts one.
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

    explicit ClassifiedCommand(pb::CommandRequest cmd) : cmd_(std::move(cmd)) {}

    pb::CommandRequest cmd_;
};

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
// IMMUTABILITY CONTRACT: the identity fields (agent_id..scopable_tags,
// gateway_node) are fully populated BEFORE the session is installed in the
// registry and are never mutated afterwards — re-registration REPLACES the
// shared_ptr, it does not edit in place. Lock-free readers (scope evaluation,
// the DEX perf provider) depend on this. Post-publication writes are confined
// to stream/server_context/peer_cert_pem (under stream_mu) and the atomic
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

    void register_agent(const pb::AgentInfo& info);

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
    /// skipped. The predicate is evaluated OFF stream_mu (it reads ca.db);
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

    void set_gateway_node(const std::string& agent_id, const std::string& node);

    /// PLAN item 5 (CC-03): record the literal wire-capability strings a
    /// gateway advertised for `agent_id` on a CONNECTED
    /// `StreamStatusNotification` — called by `GatewayUpstreamServiceImpl::
    /// NotifyStreamStatus`. ALWAYS a full replace, never a merge: a
    /// reconnect (fresh CONNECTED) behind an upgraded — or downgraded —
    /// gateway build must not keep stacking capabilities the new connection
    /// never advertised. No-op if `agent_id` is not currently registered
    /// (mirrors `set_gateway_node`'s own race tolerance).
    void set_gateway_wire_capabilities(const std::string& agent_id,
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
    /// revokes any device tokens issued under a previous incarnation of
    /// the same agent_id whenever a re-registration is detected. Optional
    /// — if never called, register_agent behaves as before and stale
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
    /// lock costs nothing and removes a footgun.
    void set_device_token_store(DeviceTokenStore* store);

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
    DeviceTokenStore* device_token_store_{nullptr};
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
