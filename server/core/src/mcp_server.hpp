#pragma once

#include <yuzu/server/auth.hpp>

#include "api_token_store.hpp"
#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "execution_tracker.hpp"
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
    using AuditFn = std::function<void(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    using AgentsJsonFn = std::function<nlohmann::json()>;

    /// Send command callback — dispatches a command and returns (command_id, agents_reached).
    using DispatchFn = std::function<std::pair<std::string, int>(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters)>;

    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         AgentsJsonFn agents_fn,
                         RbacStore* rbac_store,
                         InstructionStore* instruction_store,
                         ExecutionTracker* execution_tracker,
                         ResponseStore* response_store,
                         AuditStore* audit_store,
                         TagStore* tag_store,
                         InventoryStore* inventory_store,
                         PolicyStore* policy_store,
                         ManagementGroupStore* mgmt_store,
                         ApprovalManager* approval_manager,
                         ScheduleEngine* schedule_engine,
                         const bool& read_only_mode,
                         const bool& mcp_disabled,
                         DispatchFn dispatch_fn = nullptr);
};

} // namespace yuzu::server::mcp
