#pragma once

#include <yuzu/server/auth.hpp>

#include "api_token_store.hpp"
#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "ca_store.hpp"
#include "dex_perf_model.hpp"
#include "network_perf_model.hpp"
#include "execution_tracker.hpp"
#include "guaranteed_state_store.hpp"
#include "instruction_store.hpp"
#include "inventory_store.hpp"
#include "management_group_store.hpp"
#include "policy_store.hpp"
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

namespace yuzu::server::mcp {

/// MCP (Model Context Protocol) server — JSON-RPC 2.0 endpoint at /mcp/v1/.
/// Mirrors the RestApiV1 pattern: receives store pointers + auth/perm/audit callbacks.
class McpServer {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    // Returns false if the audit row could not be persisted. Most MCP call sites
    // discard the result (the generic mcp_audit helper), but destructive tools
    // (e.g. revoke_certificate) observe it to surface an evidence-chain gap in the
    // JSON-RPC result — matching the canonical bool-returning audit contract.
    using AuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    using AgentsJsonFn = std::function<nlohmann::json()>;

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
    using DispatchFn = std::function<std::pair<std::string, int>(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id)>;

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
                            DexPerfFn dex_perf_fn = {}, NetPerfFn net_perf_fn = {});

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
                         DexPerfFn dex_perf_fn = {}, NetPerfFn net_perf_fn = {});
};

} // namespace yuzu::server::mcp
