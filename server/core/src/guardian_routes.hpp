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
class BaselineStore;
struct Baseline;

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

    /// Guardian push fan-out: resolve `scope` → in-scope agents, deliver the
    /// store's enabled rules as a `__guard__`/push_rules CommandRequest. Returns
    /// the agent count, or <0 on failure (unparseable scope / not wired). Same
    /// callback the REST `/push` endpoint uses; the dashboard toggle calls it to
    /// auto-deploy a guard change. May be empty (toggle then degrades to
    /// "saved, not deployed").
    using PushFn = std::function<int(const std::string& scope, bool full_sync)>;

    /// Register all Guardian routes on the given server.
    /// `store` may be null (degrades to fully-mock rendering). `baseline_store`
    /// may also be null (Baseline fragments degrade to the mock/empty state).
    void register_routes(httplib::Server& svr,
                         AuthFn auth_fn,
                         PermFn perm_fn,
                         AuditFn audit_fn,
                         EmitEventFn emit_event_fn,
                         GuaranteedStateStore* store,
                         BaselineStore* baseline_store,
                         AgentsJsonFn agents_json_fn,
                         PushFn push_fn);

private:
    // -- Fragment renderers (called by route handlers) -------------------------
    std::string render_status_fragment(const std::string& view) const;
    std::string render_guards_fragment(const std::string& status_filter) const;
    std::string render_events_fragment(const std::string& type_filter,
                                       const std::string& severity_filter) const;
    std::string render_guard_detail_fragment(const std::string& guard_id) const;
    std::string render_baselines_fragment() const;
    std::string render_baseline_detail_fragment(const std::string& baseline_id) const;

    /// True iff a DEPLOYED Baseline's current member set differs from the set
    /// captured at its last deploy (`deployed_snapshot`) — i.e. members were
    /// added/removed but not yet re-deployed, so the change has not reached agents.
    /// False for draft Baselines and for legacy rows with no snapshot.
    bool baseline_members_drifted(const Baseline& b) const;
    std::string render_guard_form_fragment() const;
    std::string render_baseline_form_fragment() const;
    /// The "Edit Baseline" modal form for `baseline_id`, pre-filled with the
    /// Baseline's name + current member-guard names. Empty form if not found.
    std::string render_baseline_edit_form_fragment(const std::string& baseline_id) const;

    /// Apply a STATE-ONLY enable/disable change to one authored Guard and respond
    /// with the re-rendered guards list. No push — the change propagates on the
    /// next Baseline deploy/reconcile. Mode (Watch/Enforce) is immutable, so there
    /// is no mode toggle. Backs `POST /guard/<id>/enabled`.
    void apply_guard_change(const httplib::Request& req, httplib::Response& res,
                            const std::string& rule_id, bool enabled);

    /// Create a structured Guard from the dashboard create-form POST. Builds the
    /// structured spec from form fields, reuses guardian::derive_rule_spec (the
    /// same validation + canonicalisation the REST create uses — single source),
    /// persists via the store, and responds with a success panel + an
    /// out-of-band guards-list refresh. Validation/store errors return 200 + an
    /// inline banner over the re-rendered form (htmx does not swap 4xx bodies).
    /// Backs `POST /fragments/guardian/guards`.
    void create_guard_from_form(const httplib::Request& req, httplib::Response& res);

    /// Create a Baseline (draft) from the create-form POST: name + selected member
    /// guards. Persists via BaselineStore, responds with a success card + an
    /// out-of-band baselines-list refresh. Validation/store errors return 200 + an
    /// inline banner (htmx does not swap 4xx bodies), matching create_guard_from_form.
    /// Backs `POST /fragments/guardian/baselines`.
    void create_baseline_from_form(const httplib::Request& req, httplib::Response& res);

    /// Deploy (or re-deploy) a Baseline: mark it deployed, bump the policy
    /// generation (so the heartbeat reconcile detects staleness), and fleet-wide
    /// full_sync push the union of all deployed Baselines' enabled member Guards
    /// via push_fn_. Management-group targeting is deferred, so deploy is fleet-
    /// wide for now. Responds with the re-rendered detail panel. Backs
    /// `POST /fragments/guardian/baseline/<id>/deploy`.
    void deploy_baseline(const httplib::Request& req, httplib::Response& res,
                         const std::string& baseline_id);

    /// Save edits to an existing Baseline from the edit-form POST: rename + replace
    /// the member-guard set (preserving lifecycle + deploy stamps). Member changes
    /// to a deployed Baseline take effect on the next Re-deploy. Responds with the
    /// re-rendered detail panel + an out-of-band list refresh. Backs
    /// `POST /fragments/guardian/baseline/<id>`.
    void update_baseline_from_form(const httplib::Request& req, httplib::Response& res,
                                   const std::string& baseline_id);

    /// Delete a Baseline. If it was deployed, bump the policy generation and re-push
    /// the (reduced) deployed-Baseline union fleet-wide so its Guards are removed
    /// from agents no other deployed Baseline still delivers them to. Responds with
    /// an empty detail panel + an out-of-band list refresh. Backs
    /// `POST /fragments/guardian/baseline/<id>/delete`.
    void delete_baseline_action(const httplib::Request& req, httplib::Response& res,
                                const std::string& baseline_id);

    // -- Dependency pointers (stored by register_routes) -----------------------
    AuthFn auth_fn_;
    PermFn perm_fn_;
    AuditFn audit_fn_;
    EmitEventFn emit_event_fn_;
    GuaranteedStateStore* store_{};
    BaselineStore* baseline_store_{};
    AgentsJsonFn agents_json_fn_;
    PushFn push_fn_{};
};

} // namespace yuzu::server
