#pragma once

/// @file compliance_routes.hpp
/// Extracted from server.cpp — Compliance dashboard HTMX routes, policy/fragment
/// API routes, and fleet compliance endpoints.  Phase 3a of the god-object
/// decomposition.

#include <yuzu/server/auth.hpp>

#include "http_route_sink.hpp"
#include "policy_store.hpp"

#include <yuzu/metrics.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

class PolicyEvaluator;

/// Compliance routes — /compliance, /fragments/compliance/*, /api/policies/*,
/// /api/policy-fragments/*, /api/compliance/*.
class ComplianceRoutes {
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
                                           const httplib::Request& req,
                                           const nlohmann::json& attrs,
                                           const nlohmann::json& payload_data)>;

    /// Callback to get agents JSON string (avoids incomplete-type dep on AgentRegistry).
    using AgentsJsonFn = std::function<std::string()>;

    /// Register all compliance-related routes on the given server.
    ///
    /// Production overload — wraps `httplib::Server&` in an HttplibRouteSink
    /// and delegates to the sink-based overload below. New code should keep
    /// using this entrypoint; the sink overload exists for in-process unit
    /// tests that bypass httplib::Server's TSan-hostile acceptor thread (#438).
    void register_routes(httplib::Server& svr,
                         AuthFn auth_fn,
                         PermFn perm_fn,
                         AuditFn audit_fn,
                         EmitEventFn emit_event_fn,
                         PolicyStore* policy_store,
                         AgentsJsonFn agents_json_fn,
                         PolicyEvaluator* policy_evaluator = nullptr,
                         /// #2500 - counts a refused remediation target. nullptr = no metric;
                         /// the REFUSAL never depends on this being wired.
                         yuzu::MetricsRegistry* metrics = nullptr);

    /// Sink-based overload — used by tests. See `tests/unit/server/test_route_sink.hpp`.
    void register_routes(HttpRouteSink& sink,
                         AuthFn auth_fn,
                         PermFn perm_fn,
                         AuditFn audit_fn,
                         EmitEventFn emit_event_fn,
                         PolicyStore* policy_store,
                         AgentsJsonFn agents_json_fn,
                         PolicyEvaluator* policy_evaluator = nullptr,
                         yuzu::MetricsRegistry* metrics = nullptr);

private:
    // -- Fragment renderers (called by route handlers) -------------------------

    std::string render_compliance_summary_fragment();
    std::string render_compliance_detail_fragment(const std::string& policy_id);

    // guardian-confinement-2298 PR3 §3e: both compliance fragments below are
    // auth_fn_-only (no perm_fn_ at all) and render per-agent compliance rows
    // fleet-wide plus policy scope expressions — no per-target parameter to
    // scope against. Same shape/ordering/throw-safety contract as
    // GuardianRoutes::deny_service_scoped_ (JSON A4 body even though the
    // caller is an HTMX fragment route — that's the established precedent
    // for this route class, not a fragment-specific shape).
    [[nodiscard]] bool deny_service_scoped_(const httplib::Request& req,
                                            httplib::Response& res) const;

    // -- Static helpers -------------------------------------------------------

    static const char* compliance_level(int pct);

    // -- Dependency pointers (stored by register_routes) -----------------------

    AuthFn auth_fn_;
    PermFn perm_fn_;
    AuditFn audit_fn_;
    EmitEventFn emit_event_fn_;
    PolicyStore* policy_store_{};
    AgentsJsonFn agents_json_fn_;
    yuzu::MetricsRegistry* metrics_{};
    PolicyEvaluator* policy_evaluator_{};
};

} // namespace yuzu::server
