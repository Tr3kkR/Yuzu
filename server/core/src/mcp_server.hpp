#pragma once

#include <yuzu/server/auth.hpp>

#include "api_token_store.hpp"
#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "authz_gates.hpp" // #3290 Phase 2: authz::FleetReadGate — query_installed_software's real confinement seam
#include "authz_model.hpp" // #1788: VisibleSet — MCP dispatch confinement (in_scope/filter_to_scope)
#include "ca_store.hpp"
#include "dispatch_caller.hpp" // PLAN-006: DispatchCaller — the principal threaded to dispatch_fn
// ADR-0031 operator surface (PR1.6c) — MCP twins of the operator
// mint/list/revoke upload-grant routes. Reuses UploadGrantListAuthorization/
// UploadGrantListDecision verbatim (not redefined) so the REST list-admit
// gate (GET /api/v1/upload-grants) and this MCP twin cannot drift — same
// reuse discipline as kek_routes.hpp above. Also brings in UploadGrantStore
// fully defined, so no separate include is needed for that.
#include "file_retrieval_routes.hpp"
#include "dex_app_perf_model.hpp"
#include "dex_perf_model.hpp"
#include "network_perf_model.hpp"
#include "execution_tracker.hpp"
#include "guaranteed_state_store.hpp"
#include "instruction_store.hpp"
#include "inventory_store.hpp"
#include "kek_routes.hpp" // KekOps / KekOpResult (#2395 track C): reused, not redefined
// ADR-0031 operator surface (PR1.5c/1.6c, p14): reuses
// UploadGrantListAuthorization/UploadGrantListDecision verbatim (not
// redefined) so the REST list-admit gate (GET /api/v1/upload-grants) and its
// MCP twin (list_upload_grants) cannot drift — same reuse discipline as
// kek_routes.hpp above.
#include "file_retrieval_routes.hpp"
#include "management_group_store.hpp"
#include "mcp_retry.hpp"  // named retry_after_ms floors + poll counter name (#3344)
#include "mcp_session.hpp"
#include "mcp_stream.hpp" // GET SSE channel: StreamRevalidateFn, handle_get_tail (2f PR 2)
#include "policy_store.hpp"
#include "quarantine_store.hpp"
#include "rbac_store.hpp"
#include "response_store.hpp"
#include "schedule_engine.hpp"
#include "scope_engine.hpp"
#include "tag_store.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu {
class MetricsRegistry; // optional bundle-metrics sink (yuzu_bundle_*)
}

namespace yuzu::server {
class SoftwareInventoryStore; // typed daily-sync software store (ADR-0016)
class SoftwareLicensingStore; // ADR-0024 discovery store (query_software_licenses)
// EnginePrincipalStore backs BOTH the PR 4.2 role-assignment MCP twins
// (assign_engine_role/unassign_engine_role/list_engine_roles) AND the PR 4.3
// engine-principal lifecycle tools (ADR-1005 item 2b). Forward-declared
// (pointer-only here); the .cpp includes engine_principal_store.hpp.
class EnginePrincipalStore;
// Periodic Access Reviews (SOC 2 CC6.2) — the campaign store plus the
// optional read-model enrichment dep. Forward-declared (pointer-only in
// build_handler/register_routes); the .cpp includes access_review_store.hpp /
// directory_sync.hpp. AuthDB is already forward-declared via <yuzu/server/auth.hpp>.
class AccessReviewStore;
class DirectorySync;
// ADR-0031 operator surface (PR1.5c, p14) — backs the plugin config/secret/
// kill-switch MCP twins. Forward-declared (pointer-only in the setter
// below); the .cpp includes plugin_config_store.hpp for the definition.
// UploadGrantStore itself is NOT forward-declared here — it arrives fully
// defined via file_retrieval_routes.hpp's own include above.
class PluginConfigStore;
}

namespace yuzu::server::detail {
// A2 discovery: backs the discover_plugins tool (mirrors GET /api/v1/discover/plugins,
// discover_routes.hpp). Forward-declared (pointer-only in build_handler/register_routes);
// the .cpp includes agent_registry.hpp for the definition.
class AgentRegistry;
} // namespace yuzu::server::detail

namespace yuzu::server::mcp {

// Progress bridge core (track 2f PR 3a). Forward-declared (pointer-only here,
// injected via set_stream_bridge); the .cpp includes mcp_stream_bridge.hpp.
class McpStreamBridge;

namespace detail {
/// #2530 G8-F2 — test-only, externally-linked twin of mcp_server.cpp's
/// file-local `kek_failure_tag()` (the MCP audit-detail switch). Mirrors
/// `yuzu::server::detail::kek_route_failure_tag` (kek_routes.hpp) so a
/// table-driven test can assert all three failure vocabularies (REST, MCP,
/// and `kek_rotate_control.hpp`'s `kek_op_outcome_label()`) agree for every
/// `KekOpResult::Failure` value — the switches stay independent by design,
/// this only forwards to the existing production one.
[[nodiscard]] std::string_view kek_mcp_failure_tag(KekOpResult::Failure failure);
} // namespace detail

/// MCP (Model Context Protocol) server — JSON-RPC 2.0 endpoint at /mcp/v1/.
/// Mirrors the RestApiV1 pattern: receives store pointers + auth/perm/audit callbacks.
class McpServer {
public:
    /// C8 fail-closed boot validator (#2383): throws std::runtime_error naming
    /// the offenders when the served kTools[] names, the kToolSecurity
    /// registrations, and the kWriteTools read-only guard set disagree — a
    /// misregistered build refuses to construct (and therefore to boot) instead
    /// of silently skipping the generic tier+approval gate for the missing tool.
    McpServer();

    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;

    /// Per-device tier + management-group scope gate (PR #1796 review H1) — same
    /// shape as DeviceRoutes::ScopedPermFn. Production wires it to
    /// AuthRoutes::require_scoped_permission (the single per-device authz
    /// chokepoint), so the device-targeted write tools (set_tag / delete_tag /
    /// quarantine_device) hold an operator to their management-group scope: a
    /// group-confined operator can act on in-scope devices and is denied on
    /// out-of-scope ones, instead of the global perm_fn's all-or-nothing answer
    /// (#1522 precedent — under the global gate a confined-but-globally-granted
    /// operator could tag/quarantine devices fleet-wide).
    ///
    /// FALLBACK-WHEN-UNWIRED, deliberately: the default `= {}` makes the three
    /// device-targeted handlers fall back to the global perm_fn (the pre-H1
    /// behavior) — NOT fail-open — because build_handler/register_routes carry a
    /// long tail of optional `= {}` deps and C++ forbids a required param after
    /// a defaulted one. The SOLE production caller (server.cpp) always wires it;
    /// the unwired path is a test-only affordance. Do not add a new production
    /// registration without wiring this.
    using ScopedPermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation,
                           const std::string& agent_id)>;
    // Returns false if the audit row could not be persisted. Most MCP call sites
    // discard the result (the generic mcp_audit helper), but destructive tools
    // (e.g. revoke_certificate) observe it to surface an evidence-chain gap in the
    // JSON-RPC result — matching the canonical bool-returning audit contract.
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    using AgentsJsonFn = std::function<nlohmann::json()>;

    /// Push a structured tag change to the agent (mirrors RestApiV1::TagPushFn).
    /// Fired by the `set_tag` write tool (#289 / D4) after a successful tag
    /// write so a category change (role/environment/location/service) reaches
    /// the endpoint exactly as the REST PUT /api/v1/tags path does. Unset (`= {}`)
    /// is a no-op (test harness / RBAC-off).
    using TagPushFn = std::function<void(const std::string& agent_id, const std::string& key)>;

    /// Per-agent response-scope predicate (#1550 HIGH-1 / #1634). Returns true iff
    /// the principal `username` may read responses for `agent_id`. Production wires
    /// it to rbac_store->check_scoped_permission(username,"Response","Read",agent_id,
    /// mgmt_store) — the same chokepoint the per-device REST/dashboard routes use.
    /// NOTE (#1634): this filter is INERT under the current global `Response:Read`
    /// gate — a holder of global Response:Read passes the gate and
    /// check_scoped_permission's global step then admits every agent (no rows
    /// dropped), while a management-group-confined operator is 403'd at the gate
    /// before this runs. So it does NOT yet bound a normal operator to their groups;
    /// its only active effect today is failing CLOSED on a corrupt/load-failed
    /// rbac.db. Effective per-operator scoping needs the admit-then-filter gate for
    /// fan-out reads (the remaining #1634 work; see rest_api_v1.hpp ResponseScopeFn).
    /// The handler resolves the principal ONCE (it already authed the request) and
    /// passes `username` in, so the predicate does NOT re-resolve the session per
    /// call. RBAC-off → returns true (legacy-open, matching require_scoped_permission).
    ///
    /// FAIL-OPEN-WHEN-UNWIRED, deliberately: the default `= {}` means an unset
    /// predicate applies NO filter. This diverges from DeviceRoutes' required
    /// ScopedPermFn (which fails closed) because build_handler/register_routes carry
    /// a long tail of optional `= {}` deps and C++ forbids a required param after a
    /// defaulted one — so the param cannot be made required without reordering the
    /// whole signature. The SOLE production caller (server.cpp) always wires it; the
    /// unwired path is a test-only affordance (legacy-open). Do not add a new
    /// production registration without wiring this.
    ///
    /// The filter is applied AFTER the store's LIMIT, so a fan-out wider than the
    /// row cap that spans out-of-scope agents may truncate the caller's in-scope
    /// view; the result then carries `result_truncated_by_cap:true` so the caller
    /// can detect it. Completeness for >cap collection is the keyset follow-up
    /// (#1634); the cross-operator ISOLATION guarantee (never another operator's
    /// rows) holds regardless. NOTE (ADR-0017): this filter is INERT under the
    /// global Response:Read gate (does not narrow by management group today); the
    /// list-view correction is tracked #1718 PR-B. NOTE: service-scoped tokens are scoped by the token
    /// creator's RBAC, not the service tag (pre-existing, tracked in #1634).
    using ResponseScopeFn =
        std::function<bool(const std::string& username, const std::string& agent_id)>;

    /// Send command callback — dispatches a command and returns (command_id, agents_reached).
    ///
    /// `execution_id` is the pre-created `ExecutionTracker` row id, threaded
    /// through so the dispatch wiring can register the
    /// `command_id → execution_id` mapping with `AgentServiceImpl` BEFORE
    /// any RPC is sent (closes the FAST-agent race documented in
    /// `docs/executions-history-ladder.md` PR 2 / UP2-4 — a sub-millisecond
    /// loopback agent's response would otherwise win against a
    /// post-dispatch mapping-registration call). Empty `execution_id` is a
    /// valid out-of-band dispatch with no tracker row; the wiring skips
    /// registration. **Caller MUST create the execution row before
    /// invoking this and pass the assigned id** — same contract as
    /// `WorkflowRoutes::CommandDispatchFn` (the REST sibling). Added for
    /// issue #1088 so MCP `execute_instruction` can return `execution_id`
    /// in its response and let agentic workers bridge to `/api/v1/events`.
    ///
    /// PLAN-006: the trailing param carries the caller's IDENTITY as well as
    /// its `exec_visible` filter (`yuzu::server::DispatchCaller`, formerly a
    /// bare `VisibleSet`) so the shared `dispatch_confined` seam has a
    /// principal to work with, not only a visibility filter.
    using DispatchFn = std::function<std::pair<std::string, int>(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id,
        // #1788 / PLAN-006: every dispatch arm intersects `caller.exec_visible`
        // against its targets, mirroring /api/command; `caller.principal`
        // identifies who asked.
        const yuzu::server::DispatchCaller& caller)>;

    /// #1788 / PLAN-006: derives the per-request DispatchCaller (identity +
    /// Execution:Execute visible set) the DispatchFn consults. Injected because
    /// the handler has the session but the dispatch lambda (server.cpp) does
    /// not. When this std::function is UNSET, the execute_instruction /
    /// execute_bundle handlers substitute an EMPTY principal alongside a
    /// PRESENT-EMPTY `exec_visible` (deny-all), NOT nullopt — an unwired
    /// derivation fails CLOSED on visibility exactly as before this struct
    /// existed (ADR-0033 §1: a missing applicable filter denies; CDX-R6-02). A
    /// caller that genuinely wants full-fleet dispatch must wire a callback
    /// whose `exec_visible` is std::nullopt; production wires server.cpp's
    /// derive_dispatch_caller (which wraps derive_exec_visible).
    using CallerFn = std::function<yuzu::server::DispatchCaller(const auth::Session&)>;

    /// Owner-FK existence check for engine-principal create/transfer-owner
    /// (design doc `docs/auth-engine-principals-design.md` §3.1:
    /// "owner_username — must reference an existing user", enforced by the
    /// CALLER — `EnginePrincipalStore::create`/`transfer_owner` themselves
    /// only check non-empty, deliberately store-agnostic re: users so the
    /// store never couples to `AuthDB`). Returns true iff `username` names an
    /// existing user. FAIL-CLOSED contract: an unset (`{}`) predicate means
    /// every create/transfer-owner call is denied ("owner existence check
    /// unavailable"), never silently admitted — mirrors
    /// `ApiTokenStore::set_engine_referent_check`'s fail-closed-when-unwired
    /// posture, not the FAIL-OPEN-WHEN-UNWIRED contract used by
    /// ResponseScopeFn above (a defense-in-depth filter over an already-gated
    /// read; this is the sole check standing
    /// between an MCP write and a dangling owner reference).
    using OwnerExistsFn = std::function<bool(const std::string& username)>;

    /// Injects the engine-principal + engine-credential store pointers and
    /// the owner-FK predicate via SETTERS rather than growing the already
    /// 30-parameter build_handler()/register_routes() trailing-parameter
    /// tail further. The handler returned by build_handler() is a non-static
    /// member function's `[=]` lambda, which implicitly captures `this` — so
    /// a setter called AFTER build_handler() still takes live effect on the
    /// very next request, the same live-read property the `read_only_mode`/
    /// `mcp_disabled` pointer captures give today. Safe because the sole
    /// production `McpServer` instance (server.cpp's `mcp_server_`, a
    /// `unique_ptr` member of `ServerImpl`) outlives every handler it
    /// produces. Unset (`nullptr`/`{}`) ⇒ every engine-principal tool answers
    /// "unavailable" rather than crashing or silently no-op'ing — production
    /// wiring is a follow-up task (server.cpp is out of scope for this PR).
    void set_engine_principal_store(EnginePrincipalStore* store) {
        engine_principal_store_ = store;
    }
    /// The SAME `ApiTokenStore` instance server.cpp wires everywhere else —
    /// not an engine-only store. Used here for `create_token`(engine
    /// readonly)/`rotate_engine_credential`/`list_active_for_principal`/
    /// `revoke_for_principal`.
    void set_engine_credential_store(ApiTokenStore* store) { engine_credential_store_ = store; }
    void set_owner_exists_fn(OwnerExistsFn fn) { owner_exists_fn_ = std::move(fn); }

    /// Progress bridge (2f PR 3a). Same setter idiom + lifetime argument as
    /// set_engine_principal_store above (the handler's `[=]` lambda captures
    /// `this`, so the injection is a live read on the next request). Nullable:
    /// unset ⇒ execute_instruction never reserves a bridge record and the
    /// pre-bridge behaviour is byte-identical. server.cpp wires the ServerImpl-
    /// owned bridge; tests inject their own.
    void set_stream_bridge(McpStreamBridge* bridge) { stream_bridge_ = bridge; }

    /// KEK (key-encryption-key) rotation seam (#2395 track C) — same setter
    /// idiom as set_engine_principal_store above (the handler's `[=]` lambda
    /// captures `this`, so the injection is a live read on the next request).
    /// Reuses kek_routes.hpp's `KekOps`/`KekOpResult` verbatim rather than
    /// redefining them, so the REST and MCP surfaces cannot drift. Any of the
    /// three std::functions left unset (default-constructed `KekOps{}`) makes
    /// the corresponding tool answer "unavailable" cleanly — never a null
    /// std::function call. server.cpp wires the SAME KekOps instance it hands
    /// to KekRoutes::register_routes.
    void set_kek_ops(KekOps ops) { kek_ops_ = std::move(ops); }

    /// ADR-0031 operator surface (PR1.5c) — plugin config/secret/kill-switch
    /// store, backing get/set/delete_plugin_config, set/delete_plugin_secret,
    /// get/set_plugin_kill_switch. Same setter idiom as
    /// set_engine_principal_store above (the handler's `[=]` lambda captures
    /// `this`, so the injection is a live read on the next request). Unset
    /// (`nullptr`, the default) ⇒ every one of those tools answers
    /// "unavailable" rather than crashing or silently no-op'ing.
    void set_plugin_config_store(PluginConfigStore* store) { plugin_config_store_ = store; }

    /// ADR-0031 operator surface (PR1.6c) — upload-grant store + the
    /// ADR-0017 list-admit resolver for list_upload_grants, backing
    /// mint/list/revoke_upload_grant. `list_read_fn` is the SAME shape as
    /// `yuzu::server::Deps::ListReadFn` (file_retrieval_routes.hpp) reused
    /// verbatim, not redefined, so the REST GET /api/v1/upload-grants list
    /// gate and this MCP twin cannot drift — server.cpp wires both from the
    /// identical `RbacStore::authorize_list_read` call. Unset store ⇒ every
    /// upload-grant tool answers "unavailable"; unset (default-constructed)
    /// `list_read_fn` fails CLOSED (kDenyAll), matching the REST twin's own
    /// unwired default (file_retrieval_routes.hpp's Deps doc comment) — NOT
    /// the fail-open-when-unwired contract ResponseScopeFn above uses,
    /// because this is the sole admit decision for the route, not
    /// a defense-in-depth filter over an already-gated read.
    using UploadGrantListReadFn =
        std::function<UploadGrantListAuthorization(const std::string& username)>;
    void set_upload_grant_ops(UploadGrantStore* store, UploadGrantListReadFn list_read_fn) {
        upload_grant_store_ = store;
        upload_grant_list_read_fn_ = std::move(list_read_fn);
    }

    /// #3290 Phase 2 — the injected-callback twin of
    /// `AuthRoutes::require_fleet_read`, backing `query_installed_software`'s
    /// real per-agent/service confinement (see `authz::FleetReadGate`'s doc
    /// comment, authz_gates.hpp, and `RestApiV1::FleetReadFn`,
    /// rest_api_v1.hpp, for the shared shape — server.cpp wires the SAME
    /// conversion lambda into both surfaces so REST and MCP cannot drift).
    /// Same setter idiom as `set_upload_grant_ops` above (the handler's
    /// `[=]` lambda captures `this`, so the injection is a live read on the
    /// next request). MUST be this tool's SOLE authorization gate — never
    /// stacked with `perm_fn` for the same `(securable_type, operation)`
    /// (the identical BLOCKING defect `require_fleet_read`'s own doc
    /// comment warns against). Unset (default-constructed) ⇒ the tool fails
    /// CLOSED (503 "unwired"), mirroring `RestApiV1`'s own unwired contract
    /// for the identical seam.
    using FleetReadFn =
        std::function<authz::FleetReadGate(const httplib::Request&, httplib::Response&,
                                           const std::string& securable_type,
                                           const std::string& operation)>;
    void set_fleet_read_fn(FleetReadFn fn) { fleet_read_fn_ = std::move(fn); }

    /// Republish-CRL callback (PR4 B-2): mirrors `CaRoutes::PublishCrlFn` so the
    /// MCP `revoke_certificate` tool republishes the CRL after a revoke exactly as
    /// the REST `/api/v1/ca/revoke` handler does. Returns the new CRL DER, or
    /// nullopt if the CRL could not be (re)built/persisted.
    using PublishCrlFn = std::function<std::optional<std::vector<std::uint8_t>>()>;

    /// Type of the POST /mcp/v1/ handler — same shape as httplib::Server's Post handler
    /// but exposed independently so tests can dispatch in-process without spinning
    /// up an httplib::Server (see #438 for the TSan-vs-httplib-thread-acceptor bug
    /// that motivated this seam).
    using HandlerFn = std::function<void(const httplib::Request&, httplib::Response&)>;

    /// Build the MCP /mcp/v1/ POST handler. The returned function captures all
    /// callbacks and store pointers by value; `read_only_mode` and `mcp_disabled`
    /// are captured by reference so runtime toggles take effect without re-binding.
    /// Caller MUST keep those two booleans alive at least as long as the handler.
    ///
    /// Tests should call this directly and invoke the returned function with
    /// synthesized httplib::Request / httplib::Response — that path avoids the
    /// httplib::Server acceptor thread that crashes under TSan (#438).
    HandlerFn build_handler(AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                            AgentsJsonFn agents_fn, RbacStore* rbac_store,
                            InstructionStore* instruction_store,
                            ExecutionTracker* execution_tracker, ResponseStore* response_store,
                            AuditStore* audit_store, TagStore* tag_store,
                            InventoryStore* inventory_store, PolicyStore* policy_store,
                            ManagementGroupStore* mgmt_store, ApprovalManager* approval_manager,
                            ScheduleEngine* schedule_engine, const bool& read_only_mode,
                            const bool& mcp_disabled, DispatchFn dispatch_fn = nullptr,
                            CaStore* ca_store = nullptr, PublishCrlFn publish_crl_fn = nullptr,
                            GuaranteedStateStore* guaranteed_state_store = nullptr,
                            DexPerfFn dex_perf_fn = {}, NetPerfFn net_perf_fn = {},
                            ResponseScopeFn response_scope_fn = {},
                            SoftwareInventoryStore* software_inventory_store = nullptr,
                            yuzu::MetricsRegistry* metrics = nullptr,
                            AppPerfProviders app_perf_providers = {},
                            QuarantineStore* quarantine_store = nullptr,
                            TagPushFn tag_push_fn = {},
                            // A2 discovery (roadmap Issue 17.1): backs discover_plugins.
                            // Trailing optional dep, like the rest of this parameter tail —
                            // `nullptr` = discover_plugins answers 503 (unwired).
                            yuzu::server::detail::AgentRegistry* agent_registry = nullptr,
                            // H1 (PR #1796): per-device scope gate for the
                            // device-targeted write tools; see ScopedPermFn above.
                            ScopedPermFn scoped_perm_fn = {},
                            // MCP Streamable HTTP transport (ADR-1005 Decision 15, 2f).
                            // sessions == nullptr ⇒ streaming disabled ⇒ pre-2f behaviour
                            // (no minting, no session/Origin checks) — every legacy caller
                            // and test stays byte-identical except the unconditional 202.
                            // `mcp_streaming_disabled` is captured by pointer (live), not the
                            // stale [=]-over-const-bool& alias pattern.
                            McpSessionRegistry* sessions = nullptr,
                            const bool* mcp_streaming_disabled = nullptr,
                            // 3b: SSE-on-POST gate. nullptr or false = plain path - the
                            // wiring-deps fallback every pre-3b caller gets. The shipped
                            // Config default is now true; nullptr here just means this
                            // caller has not wired the flag in, not the production posture.
                            const bool* mcp_streamed_post_enabled = nullptr,
                            std::vector<std::string> allowed_origins = {},
                            // ADR-0024: backs the query_software_licenses discovery read
                            // (the MCP twin of GET /api/v1/sle/agents/{id}).
                            SoftwareLicensingStore* software_licensing_store = nullptr,
                            // PR 4.2 (design §4.1): backs assign_engine_role /
                            // unassign_engine_role / list_engine_roles — the MCP twins
                            // of the REST engine-principal role-assignment surface.
                            // Trailing optional dep; nullptr leaves assign/unassign
                            // answering an internal-error JSON-RPC response (list still
                            // works if rbac_store is wired).
                            EnginePrincipalStore* engine_principal_store = nullptr,
                            // Periodic Access Reviews (SOC 2 CC6.2) — the campaign store
                            // plus the read-model deps build_access_review needs beyond
                            // rbac_store/engine_principal_store above and
                            // engine_credential_store_ (member, ApiTokenStore). Trailing
                            // optional deps; access_review_store == nullptr leaves the
                            // whole access-review tool family answering "unavailable".
                            AccessReviewStore* access_review_store = nullptr,
                            AuthDB* auth_db = nullptr, DirectorySync* directory_sync = nullptr,
                            // #1788 / PLAN-006: derives the per-request DispatchCaller
                            // (identity + Execution:Execute visible set) for the
                            // execute_instruction / execute_bundle dispatch confinement.
                            // Trailing optional, but UNSET fails CLOSED on exec_visible —
                            // the handlers substitute an empty principal alongside a
                            // present-empty (deny-all) VisibleSet, not unfiltered
                            // (CDX-R6-02); a test seam wanting full fleet wires a callback
                            // whose exec_visible is std::nullopt.
                            //
                            // ORDER (merge with 2f PR 3b): this parameter occupies the
                            // slot #2689's positional call sites use — it REPLACES the
                            // former ExecVisibleFn, whose visible set DispatchCaller now
                            // carries — so the streaming trio still appends after it.
                            CallerFn caller_fn = {},
                            // 2f PR 3b (streamed POST): the SAME shared held-open
                            // budget the GET channel leases from - a streamed POST
                            // pins an HTTP worker exactly as a GET SSE stream does,
                            // so it must be admitted by the same arithmetic. All
                            // three are trailing-defaulted for the test seams;
                            // PRODUCTION MUST WIRE ALL THREE when streaming is on,
                            // for the same reasons build_get_handler states: without
                            // the budget there is no admission control on held-open
                            // workers, without re-validation a revoked credential
                            // keeps its stream, and without the principal sink the
                            // close audit cannot name an actor whose credential may
                            // already be gone. Absent any of them the POST simply
                            // never streams - it answers plain JSON, byte-identical
                            // to today, which is the correct degradation.
                            yuzu::server::detail::StreamBudget* stream_budget = nullptr,
                            StreamRevalidateFn revalidate_fn = {},
                            StreamPrincipalAuditFn principal_audit_fn = {});

    /// Build the GET/DELETE handlers for /mcp/v1/ (Streamable HTTP transport).
    /// Separate builders so tests can drive them without the httplib acceptor
    /// thread (#438), mirroring build_handler(). GET is the SSE channel (PR 2:
    /// heartbeats, Last-Event-ID resume, stream caps — the tail lives in
    /// mcp_stream.cpp); DELETE terminates a principal-bound session. Both no-op
    /// to 405 when streaming is disabled and to a kMcpDisabled JSON-RPC error
    /// when MCP is disabled.
    ///
    /// `stream_budget` / `revalidate_fn` are trailing-defaulted for the test
    /// seams; PRODUCTION MUST WIRE BOTH — without the budget there is no
    /// admission control on held-open workers, and without re-validation a
    /// revoked credential keeps its stream (register_routes warns if either is
    /// missing while streaming is on).
    HandlerFn build_get_handler(AuthFn auth_fn, AuditFn audit_fn, const bool* mcp_disabled,
                                const bool* streaming_disabled, McpSessionRegistry* sessions,
                                std::vector<std::string> allowed_origins,
                                yuzu::server::detail::StreamBudget* stream_budget = nullptr,
                                StreamRevalidateFn revalidate_fn = {},
                                yuzu::MetricsRegistry* metrics = nullptr,
                                std::size_t per_principal_cap = kMcpStreamsPerPrincipalDefault,
                                StreamPrincipalAuditFn principal_audit_fn = {});
    HandlerFn build_delete_handler(AuthFn auth_fn, AuditFn audit_fn, const bool* mcp_disabled,
                                   const bool* streaming_disabled, McpSessionRegistry* sessions,
                                   std::vector<std::string> allowed_origins);

    /// Register the /mcp/v1/ POST route on `svr` and emit the startup log line.
    /// Production callers use this; tests prefer build_handler() above.
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         AgentsJsonFn agents_fn, RbacStore* rbac_store,
                         InstructionStore* instruction_store, ExecutionTracker* execution_tracker,
                         ResponseStore* response_store, AuditStore* audit_store,
                         TagStore* tag_store, InventoryStore* inventory_store,
                         PolicyStore* policy_store, ManagementGroupStore* mgmt_store,
                         ApprovalManager* approval_manager, ScheduleEngine* schedule_engine,
                         const bool& read_only_mode, const bool& mcp_disabled,
                         DispatchFn dispatch_fn = nullptr, CaStore* ca_store = nullptr,
                         PublishCrlFn publish_crl_fn = nullptr,
                         GuaranteedStateStore* guaranteed_state_store = nullptr,
                         DexPerfFn dex_perf_fn = {}, NetPerfFn net_perf_fn = {},
                         ResponseScopeFn response_scope_fn = {},
                         SoftwareInventoryStore* software_inventory_store = nullptr,
                         yuzu::MetricsRegistry* metrics = nullptr,
                         AppPerfProviders app_perf_providers = {},
                         QuarantineStore* quarantine_store = nullptr,
                         TagPushFn tag_push_fn = {},
                         yuzu::server::detail::AgentRegistry* agent_registry = nullptr,
                         ScopedPermFn scoped_perm_fn = {},
                         // MCP Streamable HTTP transport (ADR-1005 Decision 15, 2f).
                         // Pointer (not const bool&) so a nullptr default cannot bind a
                         // temporary that would dangle once build_handler captures its address.
                         McpSessionRegistry* sessions = nullptr,
                         const bool* mcp_streaming_disabled = nullptr,
                            // 3b: SSE-on-POST gate. nullptr or false = plain path - the
                            // wiring-deps fallback every pre-3b caller gets. The shipped
                            // Config default is now true; nullptr here just means this
                            // caller has not wired the flag in, not the production posture.
                            const bool* mcp_streamed_post_enabled = nullptr,
                         std::vector<std::string> allowed_origins = {},
                         SoftwareLicensingStore* software_licensing_store = nullptr,
                         // PR 4.2 (design §4.1): engine-principal role-assignment MCP
                         // twins (the 4.2 grant handlers capture this param).
                         EnginePrincipalStore* engine_principal_store = nullptr,
                         // Periodic Access Reviews (SOC 2 CC6.2) — see build_handler's
                         // doc comment above; identical trailing-optional-dep contract.
                         AccessReviewStore* access_review_store = nullptr,
                         AuthDB* auth_db = nullptr, DirectorySync* directory_sync = nullptr,
                         // PR 2 (GET SSE channel): the SHARED held-open-stream budget
                         // (one instance across every SSE surface on the httplib pool,
                         // Decision 15(h)) and the per-tick credential re-validation
                         // seam (Decision 15(c)/(i)).
                         yuzu::server::detail::StreamBudget* stream_budget = nullptr,
                         StreamRevalidateFn revalidate_fn = {},
                         // Operator's --mcp-max-streams-per-principal. Threaded from Config
                         // rather than read as a constant at the attach site: without this
                         // the flag parsed, validated and documented as a live control
                         // while having no effect whatsoever.
                         std::size_t mcp_max_streams_per_principal =
                             kMcpStreamsPerPrincipalDefault,
                         // Explicit-principal audit sink for mcp.stream.close (see
                         // StreamPrincipalAuditFn). Empty falls back to the generic sink.
                         StreamPrincipalAuditFn principal_audit_fn = {},
                         // #1788 / PLAN-006: per-request DispatchCaller deriver,
                         // forwarded to build_handler for MCP dispatch confinement.
                         CallerFn caller_fn = {});

private:
    // ── Engine-principal lifecycle wiring (ADR-1005 item 2b, plan PR 4.3) ──
    // COEXISTENCE (4.2→4.3 rebase): the 4.2 role-assignment handlers use the
    // register_routes `engine_principal_store` PARAM above; the 4.3 lifecycle
    // handlers use these MEMBERS (set via the setters above). server.cpp wires
    // BOTH to the same store. Follow-up: unify onto the member. Nullable;
    // every tool checks before use and answers a clean "unavailable" error.
    EnginePrincipalStore* engine_principal_store_{nullptr};
    ApiTokenStore* engine_credential_store_{nullptr};
    OwnerExistsFn owner_exists_fn_;
    // Progress bridge core (2f PR 3a) - see set_stream_bridge above.
    McpStreamBridge* stream_bridge_{nullptr};
    // KEK rotation seam (#2395 track C) - see set_kek_ops above. Default-
    // constructed (all three std::functions empty) until server.cpp wires it.
    KekOps kek_ops_;
    // ADR-0031 operator surface (PR1.5c/1.6c, p14) - see set_plugin_config_store
    // / set_upload_grant_ops above. Nullable; every backed tool checks before
    // use and answers a clean "unavailable" error, matching
    // engine_principal_store_'s contract above.
    PluginConfigStore* plugin_config_store_{nullptr};
    UploadGrantStore* upload_grant_store_{nullptr};
    UploadGrantListReadFn upload_grant_list_read_fn_;
    // #3290 Phase 2 — see set_fleet_read_fn above.
    FleetReadFn fleet_read_fn_;
};

// The (tool, securable, operation) test-only accessors that formerly lived here
// were relocated to mcp_server_testonly.hpp (issue #2385) — production callers
// have no reason to see them.

// The served tool names whose calls can reach the #2405 pre-approval
// input-schema gate — every tool whose (securable, operation) makes
// requires_approval() true for some tier. Sorted, deterministic. This is the
// closed label set server.cpp pre-seeds for yuzu_mcp_tool_args_invalid_total
// (docs/observability-conventions.md: bounded-label counters are pre-seeded
// to 0 so absent() alerts stay meaningful).
std::vector<std::string> approval_gated_tool_names();

} // namespace yuzu::server::mcp
