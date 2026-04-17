#pragma once

#include <yuzu/server/auth.hpp>

#include "api_token_store.hpp"
#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "device_token_store.hpp"
#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "inventory_store.hpp"
#include "license_store.hpp"
#include "management_group_store.hpp"
#include "product_pack_store.hpp"
#include "quarantine_store.hpp"
#include "rbac_store.hpp"
#include "response_store.hpp"
#include "schedule_engine.hpp"
#include "software_deployment_store.hpp"
#include "tag_store.hpp"

#include <httplib.h>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

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

    /// Production overload — constructs an HttplibRouteSink and delegates
    /// to the sink-based overload below.
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         RbacStore* rbac_store, ManagementGroupStore* mgmt_store,
                         ApiTokenStore* token_store, QuarantineStore* quarantine_store,
                         ResponseStore* response_store, InstructionStore* instruction_store,
                         ExecutionTracker* execution_tracker, ScheduleEngine* schedule_engine,
                         ApprovalManager* approval_manager, TagStore* tag_store,
                         AuditStore* audit_store, ServiceGroupFn service_group_fn = {},
                         TagPushFn tag_push_fn = {},
                         InventoryStore* inventory_store = nullptr,
                         ProductPackStore* product_pack_store = nullptr,
                         SoftwareDeploymentStore* sw_deploy_store = nullptr,
                         DeviceTokenStore* device_token_store = nullptr,
                         LicenseStore* license_store = nullptr);

    /// Sink-based overload — used by tests to register routes against an
    /// in-process TestRouteSink so dispatch happens without httplib::Server's
    /// TSan-hostile acceptor thread (#438).
    void register_routes(class HttpRouteSink& sink,
                         AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         RbacStore* rbac_store, ManagementGroupStore* mgmt_store,
                         ApiTokenStore* token_store, QuarantineStore* quarantine_store,
                         ResponseStore* response_store, InstructionStore* instruction_store,
                         ExecutionTracker* execution_tracker, ScheduleEngine* schedule_engine,
                         ApprovalManager* approval_manager, TagStore* tag_store,
                         AuditStore* audit_store, ServiceGroupFn service_group_fn = {},
                         TagPushFn tag_push_fn = {},
                         InventoryStore* inventory_store = nullptr,
                         ProductPackStore* product_pack_store = nullptr,
                         SoftwareDeploymentStore* sw_deploy_store = nullptr,
                         DeviceTokenStore* device_token_store = nullptr,
                         LicenseStore* license_store = nullptr);
};

} // namespace yuzu::server
