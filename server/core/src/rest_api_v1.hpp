#pragma once

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include "api_token_store.hpp"
#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "device_token_store.hpp"
#include "dex_perf_model.hpp"
#include "network_perf_model.hpp"
#include "execution_tracker.hpp"
#include "guaranteed_state_store.hpp"
#include "instruction_store.hpp"
#include "inventory_store.hpp"
#include "license_store.hpp"
#include "management_group_store.hpp"
#include "product_pack_store.hpp"
#include "quarantine_store.hpp"
#include "rbac_store.hpp"
#include "response_store.hpp"
#include "result_set_store.hpp"
#include "schedule_engine.hpp"
#include "software_deployment_store.hpp"
#include "mfa_step_up.hpp"
#include "tag_store.hpp"

// W5.1 — `/api/v1/events` JSON SSE consumes the per-execution event bus.
// Forward-declared to avoid pulling the bus header into every TU that
// already includes rest_api_v1.hpp (test fixtures, server.cpp).
//
// **Lifetime contract:** the bus pointer threaded into `register_routes`
// is BORROWED. The caller MUST keep the bus alive until every SSE
// response has fully unwound. This is non-obvious because httplib runs
// the resource-release closure on a worker thread AFTER the handler
// returns — `bus->unsubscribe(...)` in that closure dereferences the
// borrowed pointer. In production this holds because `ServerImpl::stop()`
// joins the httplib worker pool (`web_server_->stop()` +
// `web_thread_.join()` at `server.cpp:1664-1668`) BEFORE resetting the
// bus (`execution_event_bus_.reset()` at `server.cpp:1712`). Note that
// member-declaration order does NOT enforce this — `web_server_` is
// declared before `execution_event_bus_` (`server.cpp:6206` vs `:6247`),
// so destructor-only ordering would tear down the bus FIRST. The
// explicit shutdown sequence is the load-bearing invariant. Any test
// fixture that drops the bus before draining httplib breaks the
// contract, as would removing the explicit `stop()` call. governance
// round R1 security-LOW-3 / cpp-expert-M-1; R2 cpp-expert noted the
// declaration-order inaccuracy and the doc was corrected to cite the
// explicit shutdown sequence.
namespace yuzu::server {
class ExecutionEventBus;
// Baseline-anchored per-device Guardian status route borrows the BaselineStore.
// Forward-declared (used only as a pointer in register_routes); the .cpp includes
// baseline_store.hpp for the definition.
class BaselineStore;
}

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

/// Versioned REST API v1 — registers all /api/v1/ routes on the httplib::Server.
class RestApiV1 {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    /// Per-device-scoped permission check (mirrors DeviceRoutes::ScopedPermFn): a
    /// global grant passes fleet-wide, otherwise the principal must hold the
    /// permission via a management group the agent is in. Per-device REST reads gate
    /// on this so a management-group-scoped operator is not fail-closed out of
    /// devices they can legitimately see. Empty → caller falls back to the flat
    /// PermFn (the pre-scoping behaviour).
    using ScopedPermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation,
                           const std::string& agent_id)>;
    /// Audit-event callback. Returns true iff the event was persisted
    /// (or the deployment runs audit-off — both look the same to a
    /// caller, see `AuthRoutes::audit_log` doc). Returns false on a
    /// silent persistence failure (audit DB locked / disk full /
    /// corruption). SOC 2 CC6.6 evidence-emitting handlers MUST capture
    /// this return and surface partial-success on the response so
    /// operators don't read a "201 Created" / "200 OK" as compliance
    /// evidence the audit row landed (HIGH-2 on PR #883, UP-H1 on
    /// PR W1.1). Pre-PR #883 this typedef was `void(...)`; existing
    /// call sites that fire-and-forget continue to work — the bool is
    /// just discarded.
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    using ServiceGroupFn = std::function<void(const std::string& service_value)>;
    using TagPushFn = std::function<void(const std::string& agent_id, const std::string& key)>;
    /// Guardian rule push fan-out (contract step 3 / G12): resolve the scope →
    /// in-scope agents, build the GuaranteedStatePush from the store, and deliver via
    /// the agent dispatch path. Returns the number of agents pushed to, or -1 on an
    /// invalid scope expression. Injected from server.cpp where the registry/scope live.
    using GuardianPushFn = std::function<int(const std::string& scope, bool full_sync)>;

    /// Outcome of a session-revocation REST call. `cookie_sessions_revoked`
    /// is the number of in-memory cookie sessions wiped (the operationally
    /// meaningful "active session" count). `api_tokens_revoked` is the
    /// number of API tokens marked revoked for the principal — non-zero
    /// only when the caller asked for full-principal revocation
    /// (`/me`'s "Sign out everywhere"; admin force-logout deliberately
    /// leaves automation tokens intact). `db_persisted` reports whether
    /// the AuthDB DELETE for cookie sessions succeeded; when false, the
    /// caller MUST surface this in the audit row (a "success" audit row
    /// hiding a DB write failure produces fictional CC6.3/CC6.6 evidence).
    struct SessionRevokeResult {
        std::size_t cookie_sessions_revoked{0};
        std::size_t api_tokens_revoked{0};
        bool db_persisted{true};
    };

    /// Carrier for the audit-emission outcome on a session-revocation
    /// response. Populated by the handler from the AuditFn return value
    /// (and an exception try/catch). Distinct from `SessionRevokeResult`
    /// because the audit emission happens AFTER the revoke primitive
    /// completes — operator's "stop NOW" still takes effect even when
    /// the SOC 2 evidence row is lost (HIGH-2 on PR #883).
    struct AuditEmission {
        bool emitted{true};
        // True iff AuditFn threw — distinguishes silent persist failure
        // from an exception path. Both produce `emitted=false` and the
        // `Sec-Audit-Failed: true` response header; the `threw` flag is
        // only surfaced in the spdlog trail.
        bool threw{false};
    };

    /// Revoke every credential bearing a username — cookie sessions
    /// (`AuthManager::invalidate_user_sessions`) and, when
    /// `revoke_api_tokens=true`, the user's API tokens (closes UP-13:
    /// "Sign out everywhere" must mean everywhere, not just browser
    /// cookies). Empty/missing callback = endpoint returns 503.
    using SessionRevokeFn =
        std::function<SessionRevokeResult(const std::string& username, bool revoke_api_tokens)>;

    /// Command dispatch callback — sends a CommandRequest to agents via gRPC
    /// and returns (command_id, agents_reached). Identical signature to
    /// `WorkflowRoutes::CommandDispatchFn`; the server threads the SAME hoisted
    /// `command_dispatch_fn` closure into both so the result-set async
    /// producers (`from-tar-query`, `from-instruction-result`, `re-eval`) drive
    /// the exact dispatch path the workflow + policy engines use. The trailing
    /// `execution_id` is registered command_id→execution_id BEFORE any RPC so
    /// FAST loopback agents can't reply before the mapping lands (UP2-4). Empty
    /// callback leaves the async producer routes returning 503.
    using CommandDispatchFn = std::function<std::pair<std::string, int>(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id)>;

    /// Production overload — constructs an HttplibRouteSink and delegates
    /// to the sink-based overload below.
    ///
    /// `metrics_registry` (optional, may be null) — when non-null the token-
    /// create handlers increment `yuzu_secure_random_failure_total{site=...}`
    /// on CSPRNG entropy-exhaustion failures so SRE on-call has a paging
    /// signal short of grepping audit logs (sre-1 on PR W1.1).
    void register_routes(
        httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
        RbacStore* rbac_store, ManagementGroupStore* mgmt_store, ApiTokenStore* token_store,
        QuarantineStore* quarantine_store, ResponseStore* response_store,
        InstructionStore* instruction_store, ExecutionTracker* execution_tracker,
        ScheduleEngine* schedule_engine, ApprovalManager* approval_manager, TagStore* tag_store,
        AuditStore* audit_store, ServiceGroupFn service_group_fn = {}, TagPushFn tag_push_fn = {},
        InventoryStore* inventory_store = nullptr, ProductPackStore* product_pack_store = nullptr,
        SoftwareDeploymentStore* sw_deploy_store = nullptr,
        DeviceTokenStore* device_token_store = nullptr, LicenseStore* license_store = nullptr,
        GuaranteedStateStore* guaranteed_state_store = nullptr,
        yuzu::MetricsRegistry* metrics_registry = nullptr, SessionRevokeFn session_revoke_fn = {},
        ExecutionEventBus* execution_event_bus = nullptr,
        ResultSetStore* result_set_store = nullptr, CommandDispatchFn command_dispatch_fn = {},
        StepUpFn step_up_fn = {}, GuardianPushFn guardian_push_fn = {},
        DexPerfFn dex_perf_fn = {}, NetPerfFn net_perf_fn = {},
        // Baseline-anchored per-device Guardian status route (appended as a trailing
        // optional dep to keep every existing register_routes call site source-stable).
        BaselineStore* baseline_store = nullptr, ScopedPermFn scoped_perm_fn = {});

    /// Sink-based overload — used by tests to register routes against an
    /// in-process TestRouteSink so dispatch happens without httplib::Server's
    /// TSan-hostile acceptor thread (#438).
    ///
    /// `step_up_fn` (PR2, optional) — when present, the 9 high-risk REST
    /// handlers (token create/revoke, session revoke, Guardian rule
    /// create/update/push, software package create, software deploy
    /// start, file retrieval upload) gate behind it after permissions
    /// pass. Empty functor disables the gate entirely (default — preserves
    /// pre-PR2 behaviour for any caller that hasn't wired it).
    void register_routes(
        class HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
        RbacStore* rbac_store, ManagementGroupStore* mgmt_store, ApiTokenStore* token_store,
        QuarantineStore* quarantine_store, ResponseStore* response_store,
        InstructionStore* instruction_store, ExecutionTracker* execution_tracker,
        ScheduleEngine* schedule_engine, ApprovalManager* approval_manager, TagStore* tag_store,
        AuditStore* audit_store, ServiceGroupFn service_group_fn = {}, TagPushFn tag_push_fn = {},
        InventoryStore* inventory_store = nullptr, ProductPackStore* product_pack_store = nullptr,
        SoftwareDeploymentStore* sw_deploy_store = nullptr,
        DeviceTokenStore* device_token_store = nullptr, LicenseStore* license_store = nullptr,
        GuaranteedStateStore* guaranteed_state_store = nullptr,
        yuzu::MetricsRegistry* metrics_registry = nullptr, SessionRevokeFn session_revoke_fn = {},
        ExecutionEventBus* execution_event_bus = nullptr,
        ResultSetStore* result_set_store = nullptr, CommandDispatchFn command_dispatch_fn = {},
        StepUpFn step_up_fn = {}, GuardianPushFn guardian_push_fn = {},
        DexPerfFn dex_perf_fn = {}, NetPerfFn net_perf_fn = {},
        // Baseline-anchored per-device Guardian status route (appended as a trailing
        // optional dep to keep every existing register_routes call site source-stable).
        BaselineStore* baseline_store = nullptr, ScopedPermFn scoped_perm_fn = {});
};

} // namespace yuzu::server
