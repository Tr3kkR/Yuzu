#include "authz_gates.hpp"

#include "auth_routes.hpp"
#include "authz_model.hpp"
#include "rest_a4_envelope_http.hpp"

#include <unordered_set>

namespace yuzu::server {

std::expected<authz::ListAuthority, authz::GateFailure>
AuthRoutes::require_fleet_read(const httplib::Request& req, httplib::Response& res,
                               const std::string& securable_type, const std::string& operation) {
    auto session = require_auth(req, res);
    if (!session)
        // require_auth already wrote the 401 response (unaudited — matches
        // require_admin/require_permission's existing convention: audit
        // trail begins at the first post-authentication decision, not at
        // require_auth itself).
        return std::unexpected(authz::GateFailure::Unauthenticated);

    const std::string perm = securable_type + ":" + operation;

    // ── management-group axis: RbacStore::authorize_list_read (ADR-0017),
    // reused as the subordinate primitive — never rewritten. ──────────────
    if (!rbac_store_ || !rbac_store_->is_open()) {
        // Infrastructure unavailable, not a real authorization decision —
        // Degraded/503, aligned with the three sibling
        // "authorization store unavailable" sites in auth_routes.cpp (the
        // engine-principal RBAC-store-unavailable branches; grep the quoted
        // string): same wording, same status code. The 403/Forbidden this
        // used to return was the outlier — a caller doing exponential
        // backoff on 503 would never retry a transient RBAC-store hiccup
        // that surfaced as a permanent-looking 403 (fjarvis/Kimi K2.7, PR
        // #3216 follow-up review). retry_after_ms matches this function's
        // own two Degraded branches below (tag-store unavailable/degraded),
        // not the auth_routes.cpp siblings, which don't set it — this
        // branch is Degraded now, so it carries the same retry signal as
        // every other Degraded branch here. The deliberate DenyAll
        // weakening (implementation plan §2c) now covers only the
        // management-group axis's real-deny-vs-in-query-store-error
        // ambiguity below, not this null-store case.
        audit_log(req, "auth.fleet_read_required", "denied", "", "",
                  "fleet read blocked: RBAC store unavailable");
        res.status = 503;
        res.set_content(detail::a4_denial(res, 503, "authorization store unavailable",
                                          detail::A4ErrorOpts{.retry_after_ms = 5000,
                                                              .permission = perm}),
                        "application/json");
        return std::unexpected(authz::GateFailure::Degraded);
    }

    // Decision (#2298 PR 3, "the flip"): preserve `require_permission`'s
    // service branch hard-403 when RBAC enforcement is not in effect. The
    // service-tag axis below is RBAC-independent — without this check, a
    // disabled-RBAC service-scoped session would get a NARROWED (non-empty,
    // via the tag axis alone) result here, a capability that session never
    // had through `require_permission`. Same predicate
    // (`rbac_enforcement_in_effect`, not raw `is_rbac_enabled()`) as
    // `require_permission`'s service branch, so the two gates can never
    // disagree on a corrupt/degraded store. `rbac_store_` is known non-null
    // and open here (the check above already returned Degraded otherwise).
    if (!session->token_scope_service.empty() && !rbac_enforcement_in_effect(rbac_store_)) {
        audit_log(req, "auth.fleet_read_required", "denied", "", "",
                  "fleet read blocked: service-scoped token requires RBAC to be enabled");
        res.status = 403;
        res.set_content(detail::a4_denial(res, 403,
                                          "service-scoped tokens require RBAC to be enabled",
                                          detail::A4ErrorOpts{.permission = perm}),
                        "application/json");
        return std::unexpected(authz::GateFailure::Forbidden);
    }

    // Spelled via deny_all() rather than relying on the switch below to
    // always overwrite the implicit nullopt(TOP) default — defense-in-depth
    // against a future non-exhaustive edit to ListReadDecision's cases
    // (cpp-safety, governance run 2026-08-17).
    authz::VisibleSet mgmt_scope = authz::deny_all();
    auto mgmt_authz = rbac_store_->authorize_list_read(session->username, securable_type, operation,
                                                       mgmt_group_store_);
    switch (mgmt_authz.decision) {
    case ListReadDecision::DenyAll:
        audit_log(req, "auth.fleet_read_required", "denied", "", "",
                  "fleet read blocked: no management-group grant for " + perm);
        res.status = 403;
        res.set_content(detail::a4_denial(res, 403, "permission denied: " + perm,
                                          detail::A4ErrorOpts{.permission = perm}),
                        "application/json");
        return std::unexpected(authz::GateFailure::Forbidden);
    case ListReadDecision::AdmitAll:
        mgmt_scope = std::nullopt; // TOP — unfiltered
        break;
    case ListReadDecision::AdmitScoped:
        mgmt_scope = std::unordered_set<std::string>(mgmt_authz.visible_agents.begin(),
                                                     mgmt_authz.visible_agents.end());
        break;
    }

    // ── service-scope axis: TOP for a non-service session (so a non-service
    // caller's result is byte-identical to authorize_list_read alone). ────
    authz::VisibleSet service_scope;
    if (!session->token_scope_service.empty()) {
        if (!tag_store_) {
            audit_log(req, "auth.fleet_read_required", "denied", "", "",
                      "fleet read blocked: tag store unavailable");
            res.status = 503;
            res.set_content(detail::a4_denial(res, 503,
                                              "tag store unavailable, cannot verify scope",
                                              detail::A4ErrorOpts{.retry_after_ms = 5000}),
                            "application/json");
            return std::unexpected(authz::GateFailure::Degraded);
        }
        // agents_with_tag is the ADR-0050 typed read
        // (std::expected<…, TagReadError>) — it distinguishes "genuinely no
        // agents tagged" (engaged, possibly empty) from "the tag store
        // degraded" (unexpected), superseding the pre-migration
        // agents_with_tag_checked/B-2b split. The axis must fail closed to
        // GateFailure::Degraded on the latter — never read a degraded store
        // as an empty-but-legitimate service, and never collapse Degraded
        // into Forbidden (the 503-vs-403 distinction this gate exists for).
        auto tagged = tag_store_->agents_with_tag("service", session->token_scope_service);
        if (!tagged) {
            audit_log(req, "auth.fleet_read_required", "denied", "", "",
                      "fleet read blocked: tag store degraded resolving service scope");
            res.status = 503;
            res.set_content(detail::a4_denial(res, 503, "tag store degraded, cannot verify scope",
                                              detail::A4ErrorOpts{.retry_after_ms = 5000}),
                            "application/json");
            return std::unexpected(authz::GateFailure::Degraded);
        }
        service_scope = std::unordered_set<std::string>(tagged->begin(), tagged->end());
    }

    return authz::ListAuthority(authz::meet(mgmt_scope, service_scope));
}

bool AuthRoutes::confine_agent_target(const httplib::Request& req, httplib::Response& res,
                                      const std::string& securable_type,
                                      const std::string& operation, const std::string& agent_id) {
    auto session = require_auth(req, res);
    if (!session)
        return false;

    const std::string perm = securable_type + ":" + operation;

    // #2437/#2500 omitted-vs-empty rule: an empty agent_id is a caller bug
    // (a route that should have required the param but didn't), not "no
    // target to check" — never fall through to an admit for it. This is the
    // exact bug this gate exists to not repeat: require_scoped_permission's
    // service branch skips its only comparison on an empty agent_id and
    // falls through to `return true`.
    if (agent_id.empty()) {
        audit_log(req, "auth.agent_target_required", "denied", "", "",
                  "agent target blocked: empty agent_id");
        res.status = 400;
        res.set_content(detail::a4_denial(res, 400, "agent_id is required",
                                          detail::A4ErrorOpts{.permission = perm}),
                        "application/json");
        return false;
    }

    // Confinement-axis only (see the declaration's doc comment): a
    // non-service session has no service scope to confine against, so this
    // axis is TOP. The RBAC/ITServiceOwner decision is require_scoped_permission's
    // job (NOT require_permission's — that function never consults
    // mgmt_group_store_ and would incorrectly reject a management-group-
    // scoped-only caller; the identical defect class fjarvis's PR #3216
    // review blocked one level up, in auth_routes.hpp), not re-checked here.
    if (session->token_scope_service.empty())
        return true;

    if (!tag_store_) {
        audit_log(req, "auth.agent_target_required", "denied", "Agent", agent_id,
                  "agent target blocked: tag store unavailable");
        res.status = 503;
        res.set_content(detail::a4_denial(res, 503, "tag store unavailable, cannot verify scope",
                                          detail::A4ErrorOpts{.retry_after_ms = 5000}),
                        "application/json");
        return false;
    }
    // ADR-0050 typed read — degrade maps to the 503 branch below, never to
    // the not-in-service Forbidden (same reasoning as require_fleet_read).
    auto tagged = tag_store_->agents_with_tag("service", session->token_scope_service);
    if (!tagged) {
        audit_log(req, "auth.agent_target_required", "denied", "Agent", agent_id,
                  "agent target blocked: tag store degraded resolving service scope");
        res.status = 503;
        res.set_content(detail::a4_denial(res, 503, "tag store degraded, cannot verify scope",
                                          detail::A4ErrorOpts{.retry_after_ms = 5000}),
                        "application/json");
        return false;
    }
    const authz::VisibleSet service_scope{
        std::unordered_set<std::string>(tagged->begin(), tagged->end())};
    if (!authz::in_scope(service_scope, agent_id)) {
        audit_log(req, "auth.agent_target_required", "denied", "Agent", agent_id,
                  "agent is not in service '" + session->token_scope_service + "'");
        res.status = 403;
        res.set_content(
            detail::a4_denial(res, 403,
                              "agent is not in service '" + session->token_scope_service + "'",
                              detail::A4ErrorOpts{.permission = perm}),
            "application/json");
        return false;
    }
    return true;
}

} // namespace yuzu::server
