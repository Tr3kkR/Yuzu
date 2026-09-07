#include "enrollment_directory_routes.hpp"

#include "enrollment_directory_model.hpp"
#include "http_route_sink.hpp"
#include "rest_a4_envelope.hpp"
#include "rest_a4_envelope_http.hpp"
#include "rest_audit.hpp"

#include <yuzu/server/server.hpp> // Config

#include <nlohmann/json.hpp>

namespace yuzu::server {

namespace {

std::string ok_json(const nlohmann::json& data) {
    nlohmann::json body;
    body["data"] = data;
    body["meta"] = {{"api_version", "v1"}};
    return body.dump();
}

std::string list_json(const nlohmann::json& data_array, int64_t total, int64_t start = 0,
                      int64_t page_size = 50) {
    nlohmann::json body;
    body["data"] = data_array;
    body["pagination"] = {{"total", total}, {"start", start}, {"page_size", page_size}};
    body["meta"] = {{"api_version", "v1"}};
    return body.dump();
}

void respond_service_unavailable(httplib::Response& res, const char* what) {
    res.status = 503;
    res.set_content(detail::a4_error(res, std::string(what) + " unavailable"),
                    "application/json");
}

} // namespace

void EnrollmentDirectoryRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn,
                                                PermFn perm_fn, AuditFn audit_fn,
                                                DirectorySync* directory_sync,
                                                auth::AutoApproveEngine* auto_approve,
                                                auth::AuthManager* auth_mgr, Config* cfg) {
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(audit_fn),
                    directory_sync, auto_approve, auth_mgr, cfg);
}

void EnrollmentDirectoryRoutes::register_routes(HttpRouteSink& sink, AuthFn /*auth_fn*/,
                                                PermFn perm_fn, AuditFn audit_fn,
                                                DirectorySync* directory_sync,
                                                auth::AutoApproveEngine* auto_approve,
                                                auth::AuthManager* auth_mgr, Config* cfg) {
    // ── GET /api/v1/directory/users — Directory:Read ────────────────────
    // Genuinely PII (email/UPN/group membership) — REST fails CLOSED on an
    // audit-persist failure (docs/api-twin-recipe.md §4), matching the
    // dex.device.view/guardian.device.view precedent for behavioural-data
    // reads. This closes the real, pre-existing audit gap the #4031 issue
    // flags: the legacy GET /api/directory/users has never audited this
    // read despite exposing PII.
    sink.Get("/api/v1/directory/users", [perm_fn, audit_fn, directory_sync](
                                            const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn(req, res, "Directory", "Read"))
            return;
        if (!directory_sync || !directory_sync->is_open()) {
            respond_service_unavailable(res, "directory sync");
            return;
        }
        if (!detail::emit_behavioral_audit(audit_fn, req, res, "directory.users.view", "success",
                                           "Directory", req.get_param_value("group_id"),
                                           "REST v1 directory users read")) {
            res.status = 503;
            res.set_content(
                detail::a4_error(res, "audit subsystem unavailable; refusing to serve directory "
                                      "user PII without durable evidence"),
                "application/json");
            return;
        }
        auto users = directory_sync->get_synced_users(req.get_param_value("group_id"));
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& u : users)
            arr.push_back(directory_user_row_json(u));
        res.set_content(list_json(arr, static_cast<int64_t>(arr.size())), "application/json");
    });

    // ── GET /api/v1/directory/status — Directory:Read ───────────────────
    // Provider/status/counts + group-role-mapping metadata — no per-person
    // PII, so no audit call (matches list_software_deployments' "metadata,
    // not behavioural PII" precedent in docs/api-twin-recipe.md §8).
    sink.Get("/api/v1/directory/status",
            [perm_fn, directory_sync](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Directory", "Read"))
                    return;
                if (!directory_sync || !directory_sync->is_open()) {
                    respond_service_unavailable(res, "directory sync");
                    return;
                }
                auto status = directory_sync->get_status();
                auto groups = directory_sync->get_synced_groups();
                res.set_content(ok_json(directory_status_json(status, groups)),
                                "application/json");
            });

    // ── GET /api/v1/enrollment/auto-approve-rules — Enrollment:Read ─────
    // #520 decision: REST-only, no MCP twin — see file header. Audited
    // (non-blocking): the rule set is auto-enrollment BYPASS criteria, which
    // carries the same "an attacker learning this is reconnaissance" value
    // #4028 assigns to TLS/plugin-signing config reads — but it is
    // fleet-config, not per-person data, so the posture is plain
    // try_persist_audit (log, never fail-closed), matching
    // docs/api-twin-recipe.md §4's read-vs-behavioural-PII distinction.
    sink.Get("/api/v1/enrollment/auto-approve-rules",
            [perm_fn, audit_fn, auto_approve](const httplib::Request& req,
                                              httplib::Response& res) {
                if (!perm_fn(req, res, "Enrollment", "Read"))
                    return;
                if (!auto_approve) {
                    respond_service_unavailable(res, "auto-approve engine");
                    return;
                }
                (void)detail::try_persist_audit(audit_fn, req, "enrollment.auto_approve.view",
                                                "success", "Enrollment", "",
                                                "REST v1 auto-approve rules read");
                auto rules = auto_approve->list_rules();
                nlohmann::json arr = nlohmann::json::array();
                for (std::size_t i = 0; i < rules.size(); ++i)
                    arr.push_back(auto_approve_rule_row_json(rules[i], i));
                nlohmann::json data;
                data["rules"] = arr;
                data["require_all"] = auto_approve->require_all();
                res.set_content(ok_json(data), "application/json");
            });

    // ── GET /api/v1/enrollment/pending-agents — Enrollment:Read ─────────
    // #520 decision: REST-only, no MCP twin — see file header. Audited
    // (non-blocking): device-identity fingerprint data, "a lighter version
    // of the device_ci GDPR-personal-data-adjacent class" per the #4031
    // issue text — enough to warrant a log entry, not per-person PII in the
    // directory.users.view sense, so not fail-closed.
    sink.Get("/api/v1/enrollment/pending-agents",
            [perm_fn, audit_fn, auth_mgr](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "Enrollment", "Read"))
                    return;
                if (!auth_mgr) {
                    respond_service_unavailable(res, "auth manager");
                    return;
                }
                (void)detail::try_persist_audit(audit_fn, req, "enrollment.pending_agents.view",
                                                "success", "Enrollment", "",
                                                "REST v1 pending-agents read");
                auto agents = auth_mgr->list_pending_agents();
                // Filter out already-approved agents — they don't need admin
                // attention, matching SettingsRoutes::render_pending_fragment()'s
                // identical filter (settings_routes.cpp) so this route genuinely
                // twins that fragment's population, not just its row shape.
                // Gate 4 finding (#4031 hardening round): the unfiltered version
                // silently returned every agent that had EVER enrolled, since
                // nothing ages an approved entry out of pending_agents_ -- on any
                // real fleet that made this route's actual output diverge from
                // its name, OpenAPI summary, docs, and the API-parity ledger's
                // "twinned" status, all of which describe it as the pending/
                // denied queue. TODO: the fragment and this route independently
                // duplicate this filter predicate rather than sharing one -- a
                // follow-up could route both through a single filtered accessor
                // on AuthManager instead.
                nlohmann::json arr = nlohmann::json::array();
                for (const auto& a : agents) {
                    if (a.status != auth::PendingStatus::approved)
                        arr.push_back(pending_agent_row_json(a));
                }
                res.set_content(list_json(arr, static_cast<int64_t>(arr.size())),
                                "application/json");
            });

    // ── GET /api/v1/settings/oidc — OidcConfig:Read ──────────────────────
    // #520 decision: REST-only, no MCP twin — see file header.
    // NAMING TRAP: gates on OidcConfig, never Directory — see
    // enrollment_directory_model.hpp's file header. Audited (non-blocking):
    // IdP/admin-group recon value, same reasoning as auto-approve above; the
    // client secret is never disclosed by oidc_config_json in the first
    // place (masked to a bool), so this route carries no secret-leak risk
    // an audit-failure posture would need to compensate for.
    sink.Get("/api/v1/settings/oidc",
            [perm_fn, audit_fn, cfg](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn(req, res, "OidcConfig", "Read"))
                    return;
                if (!cfg) {
                    respond_service_unavailable(res, "server config");
                    return;
                }
                (void)detail::try_persist_audit(audit_fn, req, "settings.oidc.view", "success",
                                                "OidcConfig", "", "REST v1 OIDC config read");
                res.set_content(ok_json(oidc_config_json(*cfg)), "application/json");
            });
}

} // namespace yuzu::server
