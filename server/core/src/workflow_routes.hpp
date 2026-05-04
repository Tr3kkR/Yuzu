#pragma once

#include <yuzu/server/auth.hpp>

#include "approval_manager.hpp"
#include "custom_properties_store.hpp"
#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "policy_store.hpp"
#include "product_pack_store.hpp"
#include "response_store.hpp"
#include "schedule_engine.hpp"
#include "tag_store.hpp"
#include "workflow_engine.hpp"

#include <httplib.h>

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
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

    /// Command dispatch callback — sends a command to agents via gRPC.
    /// Returns (command_id, number_of_agents_reached).
    ///
    /// PR 2: optional `execution_id` parameter threads the
    /// command_id→execution_id mapping into the dispatch path so the
    /// mapping is registered with `AgentServiceImpl` BEFORE any RPC is
    /// sent (closes the UP2-4 FAST-agent race where a sub-millisecond
    /// loopback agent could reply before the post-dispatch
    /// register-mapping call). Empty `execution_id` skips registration
    /// (callers that don't track executions, e.g. raw command path).
    using CommandDispatchFn = std::function<std::pair<std::string, int>(
        const std::string& plugin, const std::string& action,
        const std::vector<std::string>& agent_ids, const std::string& scope_expr,
        const std::unordered_map<std::string, std::string>& parameters,
        const std::string& execution_id)>;

    /// PR 2.5 — deps-struct refactor (#670).
    ///
    /// `register_routes` had grown to 16 arguments across two overloads.
    /// PR 3 adds the SSE event-bus pointer — the trigger to land the
    /// struct refactor BEFORE more callbacks accrete. Callers construct
    /// one `Deps` and both overloads take it by value.
    ///
    /// Field ordering follows the original register_routes parameter
    /// order so the diff at call sites is mechanical. Pointer fields
    /// default to nullptr where the previous overload accepted defaults.
    struct Deps {
        AuthFn auth_fn;
        PermFn perm_fn;
        AuditFn audit_fn;
        EmitEventFn emit_fn;
        ScopeEstimateFn scope_fn;
        WorkflowEngine* workflow_engine{nullptr};
        ExecutionTracker* execution_tracker{nullptr};
        ScheduleEngine* schedule_engine{nullptr};
        ProductPackStore* product_pack_store{nullptr};
        InstructionStore* instruction_store{nullptr};
        PolicyStore* policy_store{nullptr};
        CommandDispatchFn command_dispatch_fn;
        ApprovalManager* approval_manager{nullptr};
        ResponseStore* response_store{nullptr};
        /// PR 3 — per-execution SSE event bus for `/sse/executions/{id}`.
        /// When non-null, `ExecutionTracker` publishers (update_agent_status,
        /// refresh_counts, mark_cancelled) emit transitions onto this bus
        /// and the SSE handler subscribes per-connection. nullptr leaves
        /// the SSE route unregistered (test harnesses that don't need it).
        class ExecutionEventBus* execution_event_bus{nullptr};
    };

    /// Production overload — wraps `httplib::Server&` in an HttplibRouteSink
    /// and delegates to the sink-based overload below. New code should keep
    /// using this entrypoint; the sink overload exists for in-process unit
    /// tests that bypass httplib::Server's TSan-hostile acceptor thread (#438).
    void register_routes(httplib::Server& svr, Deps deps);

    /// Sink-based overload — used by tests. See `tests/unit/server/test_route_sink.hpp`.
    void register_routes(class HttpRouteSink& sink, Deps deps);
};

} // namespace yuzu::server
