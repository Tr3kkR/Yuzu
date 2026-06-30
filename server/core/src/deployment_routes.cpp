/// @file deployment_routes.cpp
/// `/auto` deploy fragment handlers. See deployment_routes.hpp for the auth/scope
/// contract. The cohort is the SOURCE pre-flight run's go-cohort (bucket go/warn),
/// read owner-scoped + re-intersected with the operator's current visible set; the
/// engine re-authorizes every advance and dispatches the MUTATING execute step at
/// most once per device.

#include "deployment_routes.hpp"

#include "deployment_engine.hpp"
#include "deployment_parse.hpp"
#include "deployment_run_store.hpp"
#include "preflight_parse.hpp"      // bucket_from_token, PreflightTarget
#include "preflight_run_store.hpp"  // PreflightRunStore (source go-cohort)

#include <yuzu/server/auth.hpp> // AuthManager (id bytes)

#include <algorithm>
#include <chrono>
#include <cctype>
#include <string>
#include <unordered_set>
#include <vector>

namespace yuzu::server {

namespace {

// Page-poll cap: the open page stops polling after this many ticks; the deployment
// continues server-side (reopen to refresh). Bounds an open tab, not the run.
constexpr int kPollCap = 600;

std::string param(const httplib::Request& req, const char* key) {
    return req.has_param(key) ? req.get_param_value(key) : std::string{};
}

std::int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string url_encode(const std::string& s) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            out += static_cast<char>(c);
        else {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 0x0F];
        }
    }
    return out;
}

std::string gen_id() {
    return auth::AuthManager::bytes_to_hex(auth::AuthManager::random_bytes(8));
}

deployment::DeploymentConfig config_from_req(const httplib::Request& req) {
    deployment::DeploymentConfig c;
    c.url = param(req, "url");
    c.filename = param(req, "filename");
    c.sha256 = param(req, "sha256");
    c.args = param(req, "args");
    return c;
}

deployment::DeploymentConfig config_from_row(const DeploymentRow& r) {
    deployment::DeploymentConfig c;
    c.url = r.artifact_url;
    c.filename = r.artifact_filename;
    c.sha256 = r.artifact_sha256;
    c.args = r.exec_args;
    return c;
}

} // namespace

std::string DeploymentRoutes::advance_and_render(const std::string& deployment_id,
                                                 const std::string& viewer, int attempt) {
    if (!deploy_store_)
        return render_deploy_note("Deployment store is unavailable on this server.");
    // OWNER-SCOPED read at the seam: a not-yours deployment reads as not-found.
    auto dep = deploy_store_->get_deployment(deployment_id, viewer);
    if (!dep)
        return render_deploy_note("Deployment not found (it may have aged out of retention).");

    // Re-authorization boundary: the engine may dispatch the MUTATING execute step,
    // so it only ever acts on devices the operator CURRENTLY sees. Build the live
    // visible set from devices_fn(viewer); the engine intersects it with the frozen
    // cohort, skips the rest, and dispatches execute once per device.
    std::unordered_set<std::string> authorized;
    if (devices_fn_)
        for (const auto& d : devices_fn_(viewer))
            authorized.insert(d.agent_id);

    const auto cfg = config_from_row(*dep);
    deployment::advance(engine_, deployment_id, cfg, authorized);

    // Re-read fresh state for the render.
    dep = deploy_store_->get_deployment(deployment_id, viewer);
    if (!dep)
        return render_deploy_note("Deployment not found.");
    auto devices = deploy_store_->get_devices(deployment_id);

    std::string repoll;
    if (dep->status == "running" && attempt < kPollCap)
        repoll = "/fragments/auto/deploy/result?dep=" + url_encode(deployment_id) + "&n=" +
                 std::to_string(attempt + 1);
    return render_deploy_results(*dep, devices, repoll);
}

void DeploymentRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                       DevicesFn devices_fn, DispatchFn dispatch_fn, PollFn poll_fn,
                                       AuditFn audit_fn, PreflightRunStore* preflight_store,
                                       DeploymentRunStore* deploy_store) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    devices_fn_ = std::move(devices_fn);
    audit_fn_ = std::move(audit_fn);
    preflight_store_ = preflight_store;
    deploy_store_ = deploy_store;
    engine_.store = deploy_store;
    engine_.poll_fn = std::move(poll_fn);
    engine_.dispatch_fn = std::move(dispatch_fn);

    // ── Deploy config fragment for a pre-flight run ──────────────────────────
    svr.Get("/fragments/auto/deploy", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_ ? auth_fn_(req, res) : std::optional<auth::Session>{};
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        if (!perm_fn_ || !perm_fn_(req, res, "SoftwareDeployment", "Read"))
            return;
        if (!preflight_store_) {
            res.set_content(render_deploy_note("Pre-flight store is unavailable on this server."),
                            "text/html; charset=utf-8");
            return;
        }
        const std::string run_id = param(req, "run");
        // Owner-scoped: a not-yours run reads as not-found (no existence oracle).
        auto run = preflight_store_->get_run(run_id, session->username);
        if (!run) {
            res.set_content(render_deploy_note("Pre-flight run not found."),
                            "text/html; charset=utf-8");
            return;
        }
        res.set_content(render_deploy_config(run->run_id, run->name, run->go, run->warn),
                        "text/html; charset=utf-8");
    });

    // ── Create the deployment from the run's go-cohort + first advance ───────
    svr.Post("/fragments/auto/deploy/run", [this](const httplib::Request& req,
                                                  httplib::Response& res) {
        auto session = auth_fn_ ? auth_fn_(req, res) : std::optional<auth::Session>{};
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        // Mutating fleet action: Execute tier; + Infrastructure:Read for the device
        // resolution + the result render it returns (so the repoll isn't 403-walled).
        if (!perm_fn_ || !perm_fn_(req, res, "Infrastructure", "Read"))
            return;
        if (!perm_fn_(req, res, "SoftwareDeployment", "Execute"))
            return;
        if (!deploy_store_ || !deploy_store_->is_open() || !preflight_store_) {
            res.set_content(render_deploy_note("Deployment store is unavailable on this server."),
                            "text/html; charset=utf-8");
            return;
        }
        const auto cfg = config_from_req(req);
        std::string why;
        if (!deployment::config_valid(cfg, &why)) {
            res.set_content(render_deploy_note("Artifact invalid: " + why),
                            "text/html; charset=utf-8");
            return;
        }
        const std::string run_id = param(req, "run");
        auto run = preflight_store_->get_run(run_id, session->username);
        if (!run) {
            res.set_content(render_deploy_note("Pre-flight run not found."),
                            "text/html; charset=utf-8");
            return;
        }

        // Cohort = the run's go+warn devices ∩ what the operator can CURRENTLY see.
        std::unordered_set<std::string> visible;
        if (devices_fn_)
            for (const auto& d : devices_fn_(session->username))
                visible.insert(d.agent_id);
        std::vector<preflight::PreflightTarget> cohort;
        for (const auto& pd : preflight_store_->get_devices(run_id)) {
            const auto b = preflight::bucket_from_token(pd.bucket);
            if ((b == preflight::Bucket::kPass || b == preflight::Bucket::kWarnOnly) &&
                visible.count(pd.agent_id))
                cohort.push_back({pd.agent_id, pd.hostname, pd.os});
        }
        if (cohort.empty()) {
            if (audit_fn_)
                audit_fn_(req, "deployment.create", "no_devices", "SoftwareDeployment", run_id, "");
            res.set_content(
                render_deploy_note("No deployable (go / warn-only) devices you can currently see in "
                                   "that pre-flight run."),
                "text/html; charset=utf-8");
            return;
        }

        DeploymentRow dep;
        dep.deployment_id = gen_id();
        dep.source_run_id = run_id;
        dep.created_by = session->username;
        dep.name = run->name;
        dep.artifact_url = cfg.url;
        dep.artifact_filename = cfg.filename;
        dep.artifact_sha256 = cfg.sha256;
        dep.exec_args = cfg.args;
        dep.status = "running";
        dep.created_at_ms = now_ms();

        if (!deploy_store_->create_deployment(dep, cohort)) {
            res.set_content(render_deploy_note("Could not persist the deployment."),
                            "text/html; charset=utf-8");
            return;
        }
        if (audit_fn_)
            audit_fn_(req, "deployment.create", "success", "SoftwareDeployment", dep.deployment_id,
                      "run=" + run_id + " file=" + cfg.filename +
                          " devices=" + std::to_string(cohort.size()));

        // First advance (stage dispatch) + render — advance_and_render re-resolves
        // the live authorized set and ticks the engine once.
        res.set_content(advance_and_render(dep.deployment_id, session->username, /*attempt=*/0),
                        "text/html; charset=utf-8");
    });

    // ── Result poll: advance one tick, render (owner-scoped) ─────────────────
    svr.Get("/fragments/auto/deploy/result", [this](const httplib::Request& req,
                                                    httplib::Response& res) {
        auto session = auth_fn_ ? auth_fn_(req, res) : std::optional<auth::Session>{};
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        // The poll BOTH renders (Read) AND advances the mutating engine (Execute) —
        // require both so an Execute-less principal can't drive a deployment, and a
        // Read-less one isn't 403-walled mid-run.
        if (!perm_fn_ || !perm_fn_(req, res, "SoftwareDeployment", "Read"))
            return;
        if (!perm_fn_(req, res, "SoftwareDeployment", "Execute"))
            return;
        const std::string dep_id = param(req, "dep");
        int attempt = 1;
        if (req.has_param("n")) {
            try {
                attempt = std::clamp(std::stoi(req.get_param_value("n")), 1, 100000);
            } catch (...) {
            }
        }
        if (audit_fn_)
            audit_fn_(req, "deployment.advance", "success", "SoftwareDeployment", dep_id, "");
        res.set_content(advance_and_render(dep_id, session->username, attempt),
                        "text/html; charset=utf-8");
    });

    // ── Delete a deployment (owner-scoped, confirm-guarded on the client) ────
    svr.Post("/fragments/auto/deploy/delete", [this](const httplib::Request& req,
                                                     httplib::Response& res) {
        auto session = auth_fn_ ? auth_fn_(req, res) : std::optional<auth::Session>{};
        if (!session) {
            res.status = 401;
            res.set_content("auth required", "text/plain");
            return;
        }
        if (!perm_fn_ || !perm_fn_(req, res, "SoftwareDeployment", "Execute"))
            return;
        const std::string dep_id = param(req, "dep");
        const bool deleted =
            deploy_store_ && deploy_store_->delete_deployment(dep_id, session->username);
        if (audit_fn_)
            audit_fn_(req, "deployment.delete", deleted ? "success" : "noop", "SoftwareDeployment",
                      dep_id, "");
        res.set_content(render_deploy_note(deleted ? "Deployment deleted."
                                                   : "Nothing to delete."),
                        "text/html; charset=utf-8");
    });
}

} // namespace yuzu::server
