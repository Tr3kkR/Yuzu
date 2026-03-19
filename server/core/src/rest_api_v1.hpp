#pragma once

#include <yuzu/server/auth.hpp>

#include "api_token_store.hpp"
#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "management_group_store.hpp"
#include "quarantine_store.hpp"
#include "rbac_store.hpp"
#include "response_store.hpp"
#include "schedule_engine.hpp"
#include "tag_store.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

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

    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         RbacStore* rbac_store, ManagementGroupStore* mgmt_store,
                         ApiTokenStore* token_store, QuarantineStore* quarantine_store,
                         ResponseStore* response_store, InstructionStore* instruction_store,
                         ExecutionTracker* execution_tracker, ScheduleEngine* schedule_engine,
                         ApprovalManager* approval_manager, TagStore* tag_store,
                         AuditStore* audit_store, ServiceGroupFn service_group_fn = {},
                         TagPushFn tag_push_fn = {});

private:
    // JSON envelope helpers
    static nlohmann::json ok_response(const nlohmann::json& data);
    static nlohmann::json error_response(const std::string& message, int code = 0);
    static nlohmann::json list_response(const nlohmann::json& data, int64_t total,
                                        int64_t start = 0, int64_t page_size = 50);
};

} // namespace yuzu::server
