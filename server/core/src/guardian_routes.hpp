#pragma once

/// @file guardian_routes.hpp
/// Guardian dashboard — page route + HTMX fragments for managing "Guaranteed
/// State" enforcement (Guards, Baselines, live status, event timeline).
///
/// Mirrors the ComplianceRoutes shape (server/core/src/compliance_routes.*).
/// Product UI: HTMX, server-rendered, dark-theme only.
///
/// Coordination note (docs/guardian-mvp-contract.md §8): the structured
/// create/update, deploy fan-out, /status aggregations, /events timeline and
/// schema-registry discovery surfaces are being built in parallel on
/// feat/guardian-mvp and do not all exist yet. Until they land, the fragment
/// renderers here emit **contract-shaped MOCK data**; where a real backend
/// already exists (rule CRUD + event query on GuaranteedStateStore) the
/// renderers prefer live data and fall back to mock. Every mock site is
/// marked `TODO(guardian-backend)` with the REST shape it will consume.
///
/// Vocabulary (contract G5): UI text uses the target words (Guard / Baseline /
/// Spark / Assertion); the RBAC securable stays "GuaranteedState" and the REST
/// surface stays /api/v1/guaranteed-state/* until the dedicated rename PR.

#include <yuzu/server/auth.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <optional>
#include <string>

namespace yuzu::server {

class GuaranteedStateStore;

/// Guardian routes — /guardian (page) + /fragments/guardian/* (HTMX fragments).
class GuardianRoutes {
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

    /// Callback to get agents JSON string (avoids an incomplete-type dep on
    /// AgentRegistry — same trick ComplianceRoutes uses).
    using AgentsJsonFn = std::function<std::string()>;

    /// Register all Guardian routes on the given server.
    /// `store` may be null (degrades to fully-mock rendering).
    void register_routes(httplib::Server& svr,
                         AuthFn auth_fn,
                         PermFn perm_fn,
                         AuditFn audit_fn,
                         EmitEventFn emit_event_fn,
                         GuaranteedStateStore* store,
                         AgentsJsonFn agents_json_fn);

private:
    // -- Fragment renderers (called by route handlers) -------------------------
    std::string render_status_fragment(const std::string& view) const;
    std::string render_guards_fragment(const std::string& status_filter) const;
    std::string render_events_fragment(const std::string& type_filter,
                                       const std::string& severity_filter) const;
    std::string render_guard_detail_fragment(const std::string& guard_id) const;
    std::string render_baselines_fragment() const;
    std::string render_baseline_detail_fragment(const std::string& baseline_id) const;
    std::string render_guard_form_fragment() const;
    std::string render_baseline_form_fragment() const;

    // -- Dependency pointers (stored by register_routes) -----------------------
    AuthFn auth_fn_;
    PermFn perm_fn_;
    AuditFn audit_fn_;
    EmitEventFn emit_event_fn_;
    GuaranteedStateStore* store_{};
    AgentsJsonFn agents_json_fn_;
};

} // namespace yuzu::server
