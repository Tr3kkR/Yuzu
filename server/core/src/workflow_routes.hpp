#pragma once

#include <yuzu/server/auth.hpp>

#include "approval_manager.hpp"
#include "custom_properties_store.hpp"
#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "policy_store.hpp"
#include "product_pack_store.hpp"
#include "schedule_engine.hpp"
#include "tag_store.hpp"
#include "workflow_engine.hpp"

#include <httplib.h>

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// Workflow, product-pack, execution fragment, and scope-estimate routes.
/// Extracted from ServerImpl::start_web_server() for god-object decomposition.
class WorkflowRoutes {
public:
    using AuthFn =
        std::function<std::optional<auth::Session>(const httplib::Request&, httplib::Response&)>;
    using PermFn =
        std::function<bool(const httplib::Request&, httplib::Response&,
                           const std::string& securable_type, const std::string& operation)>;
    using AuditFn = std::function<void(const httplib::Request&, const std::string& action,
                                       const std::string& result, const std::string& target_type,
                                       const std::string& target_id, const std::string& detail)>;
    using EmitEventFn = std::function<void(const std::string& event_type,
                                           const httplib::Request& req)>;

    /// Callback for scope expression evaluation.
    /// Returns (matched_count, total_agents).
    using ScopeEstimateFn =
        std::function<std::pair<std::size_t, std::size_t>(const std::string& expression)>;

    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         EmitEventFn emit_fn, ScopeEstimateFn scope_fn,
                         WorkflowEngine* workflow_engine,
                         ExecutionTracker* execution_tracker,
                         ScheduleEngine* schedule_engine,
                         ProductPackStore* product_pack_store,
                         InstructionStore* instruction_store,
                         PolicyStore* policy_store);
};

} // namespace yuzu::server
