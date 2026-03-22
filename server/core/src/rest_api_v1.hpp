#pragma once

#include <yuzu/server/auth.hpp>

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

// Forward declarations — full headers only needed by the .cpp domain files
class ApiTokenStore;
class ApprovalManager;
class AuditStore;
class ExecutionTracker;
class InstructionStore;
class InventoryStore;
class ManagementGroupStore;
class ProductPackStore;
class QuarantineStore;
class RbacStore;
class ResponseStore;
class ScheduleEngine;
class TagStore;

/// Versioned REST API v1 — registers all /api/v1/ routes on the httplib::Server.
class RestApiV1 {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    using AuditFn = std::function<void(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    using ServiceGroupFn = std::function<void(const std::string& service_value)>;
    using TagPushFn =
        std::function<void(const std::string& agent_id, const std::string& key)>;

    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         RbacStore* rbac_store, ManagementGroupStore* mgmt_store,
                         ApiTokenStore* token_store, QuarantineStore* quarantine_store,
                         ResponseStore* response_store, InstructionStore* instruction_store,
                         ExecutionTracker* execution_tracker, ScheduleEngine* schedule_engine,
                         ApprovalManager* approval_manager, TagStore* tag_store,
                         AuditStore* audit_store, ServiceGroupFn service_group_fn = {},
                         TagPushFn tag_push_fn = {},
                         InventoryStore* inventory_store = nullptr,
                         ProductPackStore* product_pack_store = nullptr);
};

} // namespace yuzu::server
