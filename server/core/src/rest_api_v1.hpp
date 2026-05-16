#pragma once

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include "api_token_store.hpp"
#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "device_token_store.hpp"
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

    /// Production overload — constructs an HttplibRouteSink and delegates
    /// to the sink-based overload below.
    ///
    /// `metrics_registry` (optional, may be null) — when non-null the token-
    /// create handlers increment `yuzu_secure_random_failure_total{site=...}`
    /// on CSPRNG entropy-exhaustion failures so SRE on-call has a paging
    /// signal short of grepping audit logs (sre-1 on PR W1.1).
    void register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn, AuditFn audit_fn,
                         RbacStore* rbac_store, ManagementGroupStore* mgmt_store,
                         ApiTokenStore* token_store, QuarantineStore* quarantine_store,
                         ResponseStore* response_store, InstructionStore* instruction_store,
                         ExecutionTracker* execution_tracker, ScheduleEngine* schedule_engine,
                         ApprovalManager* approval_manager, TagStore* tag_store,
                         AuditStore* audit_store, ServiceGroupFn service_group_fn = {},
                         TagPushFn tag_push_fn = {}, InventoryStore* inventory_store = nullptr,
                         ProductPackStore* product_pack_store = nullptr,
                         SoftwareDeploymentStore* sw_deploy_store = nullptr,
                         DeviceTokenStore* device_token_store = nullptr,
                         LicenseStore* license_store = nullptr,
                         GuaranteedStateStore* guaranteed_state_store = nullptr,
                         yuzu::MetricsRegistry* metrics_registry = nullptr);

    /// Sink-based overload — used by tests to register routes against an
    /// in-process TestRouteSink so dispatch happens without httplib::Server's
    /// TSan-hostile acceptor thread (#438).
    void register_routes(class HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                         AuditFn audit_fn, RbacStore* rbac_store, ManagementGroupStore* mgmt_store,
                         ApiTokenStore* token_store, QuarantineStore* quarantine_store,
                         ResponseStore* response_store, InstructionStore* instruction_store,
                         ExecutionTracker* execution_tracker, ScheduleEngine* schedule_engine,
                         ApprovalManager* approval_manager, TagStore* tag_store,
                         AuditStore* audit_store, ServiceGroupFn service_group_fn = {},
                         TagPushFn tag_push_fn = {}, InventoryStore* inventory_store = nullptr,
                         ProductPackStore* product_pack_store = nullptr,
                         SoftwareDeploymentStore* sw_deploy_store = nullptr,
                         DeviceTokenStore* device_token_store = nullptr,
                         LicenseStore* license_store = nullptr,
                         GuaranteedStateStore* guaranteed_state_store = nullptr,
                         yuzu::MetricsRegistry* metrics_registry = nullptr);
};

} // namespace yuzu::server
