/// @file compliance_routes.cpp
/// Compliance dashboard HTMX routes, policy/fragment API routes, and fleet
/// compliance endpoints.  Extracted from server.cpp — Phase 3a of the
/// god-object decomposition.

#include "compliance_routes.hpp"

#include "dispatch_target_shape.hpp" // check_targeting_shape (#2500)

#include "policy_evaluator.hpp"
#include "rest_a4_envelope_http.hpp" // detail::a4_denial (deny_service_scoped_) — mints/reuses
                                     // X-Correlation-Id so header and body always agree
#include "store_errors.hpp"
#include "web_utils.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <string>
#include <vector>

// Compliance page HTML (defined in compliance_ui.cpp).
extern const char* const kComplianceHtml;

namespace yuzu::server {

// ── Static helpers ──────────────────────────────────────────────────────────

const char* ComplianceRoutes::compliance_level(int pct) {
    if (pct >= 90) return "good";
    if (pct >= 70) return "warn";
    return "bad";
}

// ── Fragment renderers ──────────────────────────────────────────────────────

std::string ComplianceRoutes::render_compliance_summary_fragment() {
    // Real policy data from PolicyStore (Phase 5)
    struct PolicyRow {
        std::string id;
        std::string name;
        std::string scope;
        int pct;
        int compliant;
        int total;
        bool enabled;
    };

    std::vector<PolicyRow> policies;
    // ADR-0056: a degraded read must render distinctly from "genuinely no
    // policies" — collapsing them would show a false "0 policies, nothing to
    // see" state when the real answer is "could not ask the store".
    bool degraded = false;

    if (policy_store_ && policy_store_->is_open()) {
        auto all_policies = policy_store_->query_policies();
        if (!all_policies) {
            degraded = true;
        } else {
            for (const auto& p : *all_policies) {
                auto cs = policy_store_->get_compliance_summary(p.id);
                if (!cs) {
                    degraded = true;
                    continue;
                }
                PolicyRow row;
                row.id = p.id;
                row.name = p.name;
                row.scope = p.scope_expression;
                row.total = static_cast<int>(cs->total);
                row.compliant = static_cast<int>(cs->compliant);
                row.pct = (cs->total > 0) ? static_cast<int>(cs->compliant * 100 / cs->total) : 0;
                row.enabled = p.enabled;
                policies.push_back(std::move(row));
            }
        }
    }

    if (degraded) {
        return "<div class=\"detail-panel\"><div class=\"empty-state\">"
               "Policy data temporarily unavailable (store degraded) — try again shortly."
               "</div></div>";
    }

    // Fleet-level compliance from PolicyStore
    FleetCompliance fc;
    if (policy_store_ && policy_store_->is_open()) {
        auto fc_res = policy_store_->get_fleet_compliance();
        if (!fc_res) {
            return "<div class=\"detail-panel\"><div class=\"empty-state\">"
                   "Fleet compliance temporarily unavailable (store degraded) — try again "
                   "shortly.</div></div>";
        }
        fc = *fc_res;
    }
    int fleet_pct = static_cast<int>(fc.compliance_pct);

    std::string html;

    // Hero: fleet compliance percentage + bar
    html += "<div class=\"compliance-hero\">"
            "<div class=\"compliance-pct ";
    html += compliance_level(fleet_pct);
    html += "\">" + std::to_string(fleet_pct) + "%</div>"
            "<div class=\"compliance-bar-wrap\">"
            "<div class=\"compliance-bar\">"
            "<div class=\"compliance-fill ";
    html += compliance_level(fleet_pct);
    html += "\" style=\"width:" + std::to_string(fleet_pct) + "%\"></div>"
            "</div>"
            "<div class=\"compliance-stats\">"
            "<span><strong>" + std::to_string(static_cast<int>(policies.size())) + "</strong> policies active</span>"
            "<span><strong>" + std::to_string(static_cast<int>(fc.total_checks)) + "</strong> device checks</span>"
            "<span>Last evaluated: <strong>just now</strong></span>"
            "</div></div></div>";

    // Policy table
    html += "<table class=\"policy-table\">"
            "<thead><tr>"
            "<th>#</th><th>Policy</th><th>Scope</th>"
            "<th>Compliance</th><th></th><th></th>"
            "</tr></thead><tbody>";

    if (policies.empty()) {
        html += "<tr><td colspan=\"6\" class=\"empty-state\">"
                "No policies defined. Create policies in the Policy Engine to track compliance."
                "</td></tr>";
    } else {
        int row = 0;
        for (const auto& p : policies) {
            ++row;
            html += "<tr>"
                    "<td style=\"color:var(--muted)\">" + std::to_string(row) + "</td>"
                    "<td class=\"policy-name\">" + html_escape(p.name) + "</td>"
                    "<td class=\"policy-scope\">" + html_escape(p.scope) + "</td>"
                    "<td>"
                    "<span class=\"policy-pct " + std::string(compliance_level(p.pct)) + "\">"
                    + std::to_string(p.pct) + "%</span>"
                    "<div class=\"mini-bar\"><div class=\"mini-fill " + std::string(compliance_level(p.pct)) +
                    "\" style=\"width:" + std::to_string(p.pct) + "%\"></div></div>"
                    "</td>"
                    "<td style=\"font-size:0.7rem;color:var(--muted)\">"
                    + std::to_string(p.compliant) + "/" + std::to_string(p.total) +
                    "</td>"
                    "<td>"
                    "<button class=\"btn btn-secondary btn-sm\" "
                    "hx-get=\"/fragments/compliance/" + html_escape(p.id) + "\" "
                    "hx-target=\"#compliance-detail\" "
                    "hx-swap=\"innerHTML\">"
                    "View</button>"
                    "</td></tr>";
        }
    }

    html += "</tbody></table>";
    return html;
}

std::string ComplianceRoutes::render_compliance_detail_fragment(const std::string& policy_id) {
    // Look up the policy from the PolicyStore. Low-stakes (page-title
    // fallback only) — a degraded read just keeps the id as the displayed
    // name, same as "not found" would; not worth a distinct error state here.
    std::string policy_name = policy_id;
    if (policy_store_ && policy_store_->is_open()) {
        auto policy = policy_store_->get_policy(policy_id);
        if (policy && *policy)
            policy_name = (*policy)->name;
    }

    // Get real compliance statuses from the store
    struct AgentRow {
        std::string agent_id;
        std::string hostname;
        std::string os;
        std::string status;
        std::string last_check;
        std::string detail;
    };

    std::vector<AgentRow> agents;
    bool degraded = false;
    if (policy_store_ && policy_store_->is_open()) {
        auto statuses = policy_store_->get_policy_agent_statuses(policy_id);
        if (!statuses) {
            degraded = true;
            statuses = std::vector<PolicyAgentStatus>{};
        }
        for (const auto& s : *statuses) {
            AgentRow row;
            row.agent_id = s.agent_id;
            row.status = s.status;
            row.detail = s.check_result;

            // Look up hostname/os from agent registry
            row.hostname = s.agent_id;
            row.os = "";
            try {
                auto agents_json_str = agents_json_fn_();
                auto arr = nlohmann::json::parse(agents_json_str);
                for (const auto& a : arr) {
                    if (a.value("agent_id", std::string{}) == s.agent_id) {
                        row.hostname = a.value("hostname", s.agent_id);
                        row.os = a.value("os", std::string{});
                        break;
                    }
                }
            } catch (...) {}

            // Format last_check as relative time
            if (s.last_check_at > 0) {
                auto now = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
                auto delta = now - s.last_check_at;
                if (delta < 60) row.last_check = std::to_string(delta) + "s ago";
                else if (delta < 3600) row.last_check = std::to_string(delta / 60) + " min ago";
                else row.last_check = std::to_string(delta / 3600) + "h ago";
            } else {
                row.last_check = "never";
            }

            agents.push_back(std::move(row));
        }
    }

    if (degraded) {
        // ADR-0056: must not read the same as "no compliance data yet" —
        // that phrasing tells an operator to wait, when the real answer is
        // "the store could not be asked".
        return "<div class=\"detail-panel\">"
               "<h3>" + html_escape(policy_name) +
               " <span style=\"font-size:0.7rem;font-weight:400;color:var(--muted)\">"
               "(" + html_escape(policy_id) + ")</span></h3>"
               "<div class=\"empty-state\">Compliance data temporarily unavailable (store "
               "degraded) — try again shortly.</div></div>";
    }
    if (agents.empty()) {
        return "<div class=\"detail-panel\">"
               "<h3>" + html_escape(policy_name) +
               " <span style=\"font-size:0.7rem;font-weight:400;color:var(--muted)\">"
               "(" + html_escape(policy_id) + ")</span></h3>"
               "<div class=\"empty-state\">No compliance data yet. "
               "Agents will report status once the policy triggers fire.</div></div>";
    }

    // Count statuses
    int compliant = 0, non_compliant = 0, unknown = 0, fixing = 0, error_count = 0;
    for (const auto& a : agents) {
        if (a.status == "compliant") ++compliant;
        else if (a.status == "non_compliant") ++non_compliant;
        else if (a.status == "unknown") ++unknown;
        else if (a.status == "fixing") ++fixing;
        else if (a.status == "error") ++error_count;
    }

    std::string html;
    html += "<div class=\"detail-panel\">"
            "<h3>" + html_escape(policy_name) +
            " <span style=\"font-size:0.7rem;font-weight:400;color:var(--muted)\">"
            "(" + html_escape(policy_id) + ")</span></h3>";

    // Status summary badges
    html += "<div style=\"display:flex;gap:1rem;margin-bottom:0.75rem;font-size:0.75rem\">"
            "<span class=\"status-compliant\">" + std::to_string(compliant) + " compliant</span>"
            "<span class=\"status-non-compliant\">" + std::to_string(non_compliant) + " non-compliant</span>"
            "<span class=\"status-pending-eval\">" + std::to_string(unknown) + " unknown</span>"
            "<span class=\"status-remediated\">" + std::to_string(fixing) + " fixing</span>"
            "</div>";

    // Per-agent table
    html += "<table class=\"detail-table\">"
            "<thead><tr>"
            "<th>Agent</th><th>Hostname</th><th>OS</th>"
            "<th>Status</th><th>Last Check</th><th>Detail</th>"
            "</tr></thead><tbody>";

    for (const auto& a : agents) {
        std::string status_class = "status-compliant";
        if (a.status == "non_compliant") status_class = "status-non-compliant";
        else if (a.status == "unknown") status_class = "status-pending-eval";
        else if (a.status == "fixing") status_class = "status-remediated";
        else if (a.status == "error") status_class = "status-non-compliant";

        std::string status_label = a.status;
        if (status_label == "non_compliant") status_label = "Non-Compliant";
        else if (status_label == "compliant") status_label = "Compliant";
        else if (status_label == "unknown") status_label = "Unknown";
        else if (status_label == "fixing") status_label = "Fixing";
        else if (status_label == "error") status_label = "Error";

        html += "<tr>"
                "<td style=\"font-family:var(--mono);font-size:0.7rem;color:var(--yellow)\">"
                + html_escape(a.agent_id) + "</td>"
                "<td>" + html_escape(a.hostname) + "</td>"
                "<td style=\"font-size:0.75rem;color:var(--muted)\">" + html_escape(a.os) + "</td>"
                "<td><span class=\"" + status_class + "\">" + status_label + "</span></td>"
                "<td style=\"font-size:0.7rem;color:var(--muted)\">" + html_escape(a.last_check) + "</td>"
                "<td style=\"font-size:0.75rem\">" + html_escape(a.detail) + "</td>"
                "</tr>";
    }

    html += "</tbody></table></div>";
    return html;
}

// guardian-confinement-2298 PR3 §3e — see the declaration comment in
// compliance_routes.hpp for the ordering/throw-safety rationale (identical
// to GuardianRoutes::deny_service_scoped_).
bool ComplianceRoutes::deny_service_scoped_(const httplib::Request& req,
                                            httplib::Response& res) const {
    auto session = auth_fn_(req, res);
    if (!session)
        return true; // auth_fn_ already wrote 401/redirect; caller returns.
    if (session->token_scope_service.empty())
        return false;
    // Write the 403 FIRST, audit after — a throwing audit_fn_ must not be
    // able to suppress the 403 (mirrors GuardianRoutes::deny_service_scoped_).
    res.status = 403;
    // No `.permission` label: this is a blanket deny with no perm_fn_ gate on
    // either fragment it covers — a service-scoped token HOLDING Policy:Read
    // is still denied here, so naming it as "the missing grant" would be a
    // false self-remediation claim (A4's permission field contract).
    //
    // `a4_denial` (not a hand-built `error_json_a4` + bare correlation id):
    // it mints/reuses the id via `ensure_correlation_id`, which ALSO sets the
    // X-Correlation-Id response header — a hand-built id embeds a
    // correlation_id in the body that the header never carries, breaking the
    // header/body-must-agree contract (found by consistency-auditor, Gate 4).
    res.set_content(
        detail::a4_denial(res, 403,
                          "service-scoped tokens may not read this fleet-wide compliance view"),
        "application/json");
    if (audit_fn_) {
        try {
            audit_fn_(req, "compliance.fragment.access_denied", "denied", "Policy", "",
                      "fleet-wide compliance dashboard fragment denied to a service-scoped "
                      "token (path=" +
                          req.path + ")");
        } catch (const std::exception& e) {
            spdlog::warn("compliance.fragment.access_denied: audit_fn_ threw: {}", e.what());
        } catch (...) {
            spdlog::warn("compliance.fragment.access_denied: audit_fn_ threw (non-std)");
        }
    }
    return true;
}

// ── Route registration ──────────────────────────────────────────────────────

void ComplianceRoutes::register_routes(httplib::Server& svr,
                                       AuthFn auth_fn,
                                       PermFn perm_fn,
                                       AuditFn audit_fn,
                                       EmitEventFn emit_event_fn,
                                       PolicyStore* policy_store,
                                       AgentsJsonFn agents_json_fn,
                                       PolicyEvaluator* policy_evaluator,
                                       yuzu::MetricsRegistry* metrics) {
    // Production shim — wrap the real server in an HttplibRouteSink and
    // delegate to the sink-based overload. Same handlers, same lambdas,
    // same observable behaviour. Test code calls the sink overload directly
    // with a TestRouteSink (#2298 PR 3 §3e).
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(audit_fn),
                    std::move(emit_event_fn), policy_store, std::move(agents_json_fn),
                    policy_evaluator, metrics);
}

void ComplianceRoutes::register_routes(HttpRouteSink& sink,
                                       AuthFn auth_fn,
                                       PermFn perm_fn,
                                       AuditFn audit_fn,
                                       EmitEventFn emit_event_fn,
                                       PolicyStore* policy_store,
                                       AgentsJsonFn agents_json_fn,
                                       PolicyEvaluator* policy_evaluator,
                                       yuzu::MetricsRegistry* metrics) {
    // Store dependency pointers
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    audit_fn_ = std::move(audit_fn);
    metrics_ = metrics;
    emit_event_fn_ = std::move(emit_event_fn);
    policy_store_ = policy_store;
    agents_json_fn_ = std::move(agents_json_fn);
    policy_evaluator_ = policy_evaluator;

    // -- Compliance dashboard page ----------------------------------------
    sink.Get("/compliance",
                     [this](const httplib::Request& req, httplib::Response& res) {
                         auto session = auth_fn_(req, res);
                         if (!session) {
                             res.set_redirect("/login");
                             return;
                         }
                         res.set_content(kComplianceHtml, "text/html; charset=utf-8");
                     });

    // -- Compliance HTMX fragment: fleet summary --------------------------
    sink.Get("/fragments/compliance/summary",
                     [this](const httplib::Request& req, httplib::Response& res) {
                         if (deny_service_scoped_(req, res)) return;
                         auto session = auth_fn_(req, res);
                         if (!session) return;
                         res.set_content(render_compliance_summary_fragment(),
                                         "text/html; charset=utf-8");
                     });

    // -- Compliance HTMX fragment: per-policy agent detail ----------------
    sink.Get(R"(/fragments/compliance/(\w[\w\-]*))",
                     [this](const httplib::Request& req, httplib::Response& res) {
                         if (deny_service_scoped_(req, res)) return;
                         auto session = auth_fn_(req, res);
                         if (!session) return;
                         auto policy_id = req.matches[1].str();
                         res.set_content(render_compliance_detail_fragment(policy_id),
                                         "text/html; charset=utf-8");
                     });

    // -- Policy Engine API (Phase 5) ------------------------------------------

    // GET /api/policy-fragments -- list all fragments
    sink.Get("/api/policy-fragments",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Read"))
                return;
            if (!policy_store_ || !policy_store_->is_open()) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            FragmentQuery q;
            if (req.has_param("name"))
                q.name_filter = req.get_param_value("name");
            try {
                if (req.has_param("limit"))
                    q.limit = std::stoi(req.get_param_value("limit"));
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto frags = policy_store_->query_fragments(q);
            if (!frags) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store degraded"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& f : *frags) {
                arr.push_back({{"id", f.id},
                               {"name", f.name},
                               {"description", f.description},
                               {"check_instruction", f.check_instruction},
                               {"check_compliance", f.check_compliance},
                               {"fix_instruction", f.fix_instruction},
                               {"post_check_instruction", f.post_check_instruction},
                               {"created_at", f.created_at},
                               {"updated_at", f.updated_at}});
            }
            res.set_content(
                nlohmann::json({{"fragments", arr}, {"count", arr.size()}}).dump(),
                "application/json");
        });

    // POST /api/policy-fragments -- create fragment from YAML
    sink.Post("/api/policy-fragments",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Write"))
                return;
            if (!policy_store_ || !policy_store_->is_open()) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            std::string yaml_source;
            // Accept raw YAML body or JSON with yaml_source field
            if (req.get_header_value("Content-Type").find("application/json") != std::string::npos) {
                try {
                    auto j = nlohmann::json::parse(req.body);
                    yaml_source = j.value("yaml_source", "");
                } catch (const std::exception& e) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
                    return;
                }
            } else {
                yaml_source = req.body;
            }

            auto result = policy_store_->create_fragment(yaml_source);
            if (!result) {
                // #396: store-level kConflictPrefix maps to HTTP 409. Strip
                // the internal prefix from the operator-facing JSON body
                // (governance enterprise-N1) and emit a denied audit so
                // name-enumeration leaves a trace (governance compliance-1,
                // up-18). The fragment name is recovered from the error
                // string when audit needs it — the parsed YAML name isn't
                // available here without re-extracting.
                bool is_conflict = is_conflict_error(result.error());
                res.status = is_conflict ? 409 : 400;
                if (is_conflict) {
                    // iter-M1: target_id is the fragment name (parsed from
                    // YAML) so SOC 2 audit reviewers can answer "duplicate
                    // of which fragment?" without re-correlating timestamps.
                    auto attempted_name = PolicyStore::peek_fragment_name(yaml_source);
                    audit_fn_(req, "policy_fragment.create", "denied",
                              "policy_fragment", attempted_name, "duplicate_name");
                }
                auto body_msg = is_conflict
                    ? std::string(strip_conflict_prefix(result.error()))
                    : result.error();
                res.set_content(nlohmann::json({{"error", body_msg}}).dump(), "application/json");
                return;
            }
            audit_fn_(req, "policy_fragment.create", "success", "policy_fragment", *result, "");
            emit_event_fn_("policy_fragment.created", req, {}, {{"fragment_id", *result}});
            res.status = 201;
            res.set_content(nlohmann::json({{"id", *result}, {"status", "created"}}).dump(),
                            "application/json");
        });

    // DELETE /api/policy-fragments/:id
    sink.Delete(R"(/api/policy-fragments/([^/]+))",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Delete"))
                return;
            if (!policy_store_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            bool deleted = policy_store_->delete_fragment(id);
            if (deleted) {
                audit_fn_(req, "policy_fragment.delete", "success", "policy_fragment", id, "");
                emit_event_fn_("policy_fragment.deleted", req, {}, {{"fragment_id", id}});
            }
            res.set_content(nlohmann::json({{"deleted", deleted}}).dump(), "application/json");
        });

    // GET /api/policies -- list all policies
    sink.Get("/api/policies",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Read"))
                return;
            if (!policy_store_ || !policy_store_->is_open()) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            PolicyQuery q;
            if (req.has_param("name"))
                q.name_filter = req.get_param_value("name");
            if (req.has_param("fragment_id"))
                q.fragment_filter = req.get_param_value("fragment_id");
            if (req.has_param("enabled_only"))
                q.enabled_only = true;
            try {
                if (req.has_param("limit"))
                    q.limit = std::stoi(req.get_param_value("limit"));
            } catch (const std::exception&) {
                res.status = 400;
                res.set_content(R"({"error":{"code":400,"message":"invalid numeric query parameter"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto policies = policy_store_->query_policies(q);
            if (!policies) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store degraded"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& p : *policies) {
                nlohmann::json inputs_obj = nlohmann::json::object();
                for (const auto& inp : p.inputs)
                    inputs_obj[inp.key] = inp.value;

                nlohmann::json triggers_arr = nlohmann::json::array();
                for (const auto& t : p.triggers) {
                    triggers_arr.push_back({{"id", t.id},
                                            {"type", t.trigger_type},
                                            {"config", nlohmann::json::parse(t.config_json, nullptr, false)}});
                }

                arr.push_back({{"id", p.id},
                               {"name", p.name},
                               {"description", p.description},
                               {"fragment_id", p.fragment_id},
                               {"scope_expression", p.scope_expression},
                               {"enabled", p.enabled},
                               {"inputs", inputs_obj},
                               {"triggers", triggers_arr},
                               {"management_groups", p.management_groups},
                               {"created_at", p.created_at},
                               {"updated_at", p.updated_at}});
            }
            res.set_content(
                nlohmann::json({{"policies", arr}, {"count", arr.size()}}).dump(),
                "application/json");
        });

    // POST /api/policies -- create policy from YAML
    sink.Post("/api/policies",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Write"))
                return;
            if (!policy_store_ || !policy_store_->is_open()) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            std::string yaml_source;
            if (req.get_header_value("Content-Type").find("application/json") != std::string::npos) {
                try {
                    auto j = nlohmann::json::parse(req.body);
                    yaml_source = j.value("yaml_source", "");
                } catch (const std::exception& e) {
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", e.what()}}).dump(), "application/json");
                    return;
                }
            } else {
                yaml_source = req.body;
            }

            auto result = policy_store_->create_policy(yaml_source);
            if (!result) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                return;
            }
            audit_fn_(req, "policy.create", "success", "policy", *result, "");
            emit_event_fn_("policy.created", req, {}, {{"policy_id", *result}});
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"Policy created","level":"success"}})");
            res.status = 201;
            res.set_content(nlohmann::json({{"id", *result}, {"status", "created"}}).dump(),
                            "application/json");
        });

    // GET /api/policies/:id -- get policy detail
    sink.Get(R"(/api/policies/([^/]+))",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Read"))
                return;
            if (!policy_store_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto policy_res = policy_store_->get_policy(id);
            if (!policy_res) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store degraded"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }
            if (!*policy_res) {
                res.status = 404;
                res.set_content(R"({"error":{"code":404,"message":"policy not found"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }
            const Policy& policy = **policy_res;

            nlohmann::json inputs_obj = nlohmann::json::object();
            for (const auto& inp : policy.inputs)
                inputs_obj[inp.key] = inp.value;

            nlohmann::json triggers_arr = nlohmann::json::array();
            for (const auto& t : policy.triggers) {
                triggers_arr.push_back({{"id", t.id},
                                        {"type", t.trigger_type},
                                        {"config", nlohmann::json::parse(t.config_json, nullptr, false)}});
            }

            // Also fetch compliance summary
            auto cs = policy_store_->get_compliance_summary(id);
            if (!cs) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store degraded"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            // Remediation is only offered where the bound fragment defines a
            // fix_instruction — the "would you like to remediate?" gate. A
            // degraded fragment read is treated the same as "not found" here
            // (false, not offered) — this only gates a UI affordance, not a
            // grant/enforce decision, so fail-soft is acceptable.
            bool remediation_available = false;
            auto frag = policy_store_->get_fragment(policy.fragment_id);
            if (frag && *frag)
                remediation_available = !(*frag)->fix_instruction.empty();

            res.set_content(
                nlohmann::json({{"id", policy.id},
                                {"name", policy.name},
                                {"description", policy.description},
                                {"yaml_source", policy.yaml_source},
                                {"fragment_id", policy.fragment_id},
                                {"scope_expression", policy.scope_expression},
                                {"enabled", policy.enabled},
                                {"remediation_available", remediation_available},
                                {"inputs", inputs_obj},
                                {"triggers", triggers_arr},
                                {"management_groups", policy.management_groups},
                                {"created_at", policy.created_at},
                                {"updated_at", policy.updated_at},
                                {"compliance", {{"compliant", cs->compliant},
                                                 {"non_compliant", cs->non_compliant},
                                                 {"unknown", cs->unknown},
                                                 {"fixing", cs->fixing},
                                                 {"error", cs->error},
                                                 {"total", cs->total}}}})
                    .dump(),
                "application/json");
        });

    // DELETE /api/policies/:id
    sink.Delete(R"(/api/policies/([^/]+))",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Delete"))
                return;
            if (!policy_store_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            bool deleted = policy_store_->delete_policy(id);
            if (deleted) {
                audit_fn_(req, "policy.delete", "success", "policy", id, "");
                emit_event_fn_("policy.deleted", req, {}, {{"policy_id", id}});
                res.set_header("HX-Trigger",
                    R"({"showToast":{"message":"Policy deleted","level":"success"}})");
            }
            res.set_content(nlohmann::json({{"deleted", deleted}}).dump(), "application/json");
        });

    // POST /api/policies/:id/enable
    sink.Post(R"(/api/policies/([^/]+)/enable)",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Write"))
                return;
            if (!policy_store_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto result = policy_store_->enable_policy(id);
            if (!result) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                return;
            }
            audit_fn_(req, "policy.enable", "success", "policy", id, "");
            emit_event_fn_("policy.enabled", req, {}, {{"policy_id", id}});
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"Policy enabled","level":"success"}})");
            res.set_content(R"({"status":"ok"})", "application/json");
        });

    // POST /api/policies/:id/disable
    sink.Post(R"(/api/policies/([^/]+)/disable)",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Write"))
                return;
            if (!policy_store_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto result = policy_store_->disable_policy(id);
            if (!result) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                return;
            }
            audit_fn_(req, "policy.disable", "success", "policy", id, "");
            emit_event_fn_("policy.disabled", req, {}, {{"policy_id", id}});
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"Policy disabled","level":"warning"}})");
            res.set_content(R"({"status":"ok"})", "application/json");
        });

    // POST /api/policies/:id/invalidate -- invalidate cache for one policy
    sink.Post(R"(/api/policies/([^/]+)/invalidate)",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Execute"))
                return;
            if (!policy_store_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto result = policy_store_->invalidate_policy(id);
            if (!result) {
                res.status = 400;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                return;
            }
            audit_fn_(req, "policy.invalidate", "success", "policy", id, "");
            emit_event_fn_("policy.invalidated", req, {}, {{"policy_id", id}, {"agents_reset", std::to_string(*result)}});
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"Policy cache invalidated","level":"success"}})");
            res.set_content(
                nlohmann::json({{"status", "ok"}, {"agents_invalidated", *result}}).dump(),
                "application/json");
        });

    // POST /api/policies/invalidate-all -- invalidate cache for all policies
    sink.Post("/api/policies/invalidate-all",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Execute"))
                return;
            if (!policy_store_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto result = policy_store_->invalidate_all_policies();
            if (!result) {
                res.status = 500;
                res.set_content(nlohmann::json({{"error", result.error()}}).dump(), "application/json");
                return;
            }
            audit_fn_(req, "policy.invalidate_all", "success", "", "", "");
            emit_event_fn_("policy.invalidated_all", req, {}, {{"total_reset", std::to_string(*result)}});
            res.set_header("HX-Trigger",
                R"({"showToast":{"message":"All policy caches invalidated","level":"success"}})");
            res.set_content(
                nlohmann::json({{"status", "ok"}, {"total_invalidated", *result}}).dump(),
                "application/json");
        });

    // POST /api/policies/:id/evaluate -- force an immediate compliance check
    // (the background evaluator picks it up on its next collect cycle).
    sink.Post(R"(/api/policies/([^/]+)/evaluate)",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Execute"))
                return;
            if (!policy_store_ || !policy_store_->is_open() || !policy_evaluator_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy evaluation not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }
            auto id = req.matches[1].str();
            auto policy_check = policy_store_->get_policy(id);
            if (!policy_check) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store degraded"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }
            if (!*policy_check) {
                res.status = 404;
                res.set_content(R"({"error":{"code":404,"message":"policy not found"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }
            auto exec_res = policy_evaluator_->evaluate_now(id);
            if (!exec_res) {
                res.status = 503;
                res.set_content(
                    nlohmann::json({{"error", {{"code", 503}, {"message", "policy evaluation degraded"}}},
                                    {"meta", {{"api_version", "v1"}}}})
                        .dump(),
                    "application/json");
                return;
            }
            auto exec_id = *exec_res;
            if (exec_id.empty()) {
                res.status = 409;
                res.set_content(
                    nlohmann::json({{"error",
                                     {{"code", 409},
                                      {"message",
                                       "policy has no check instruction or matches no agents"}}},
                                    {"meta", {{"api_version", "v1"}}}})
                        .dump(),
                    "application/json");
                return;
            }
            audit_fn_(req, "policy.evaluate", "success", "policy", id, "execution_id=" + exec_id);
            emit_event_fn_("policy.evaluated", req, {},
                           {{"policy_id", id}, {"execution_id", exec_id}});
            res.status = 202;
            res.set_content(
                nlohmann::json({{"status", "dispatched"}, {"execution_id", exec_id}}).dump(),
                "application/json");
        });

    // POST /api/policies/:id/remediate -- manual, gated remediation. Requires
    // the bound fragment to define a fix_instruction. Optional body
    // {"agent_ids":[...]} scopes the fix; absent => all non_compliant agents.
    sink.Post(R"(/api/policies/([^/]+)/remediate)",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Execute"))
                return;
            if (!policy_store_ || !policy_store_->is_open() || !policy_evaluator_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy evaluation not available"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }
            auto id = req.matches[1].str();

            // ── #2500, FIFTH instance ────────────────────────────────────────
            // An empty vector means "every non-compliant agent in this policy"
            // (policy_evaluator.cpp, remediate()). The parse below used to drop
            // non-string entries and accept an empty/non-array/unparseable body
            // silently, so `{"agent_ids":[1,2,3]}` remediated the ENTIRE
            // non-compliant set, answered 202, and audited
            // `policy.remediate|success`. Identical to the /api/command defect
            // this issue is about, on a MUTATING remediation path, and missed by
            // every diff-focused review because the reviews cleared
            // PolicyEvaluator as a DISPATCH caller and never read this route's
            // own parsing.
            //
            // ABSENT body or ABSENT key still means "all non-compliant" - that
            // is the omitted case and it is legitimate. Everything supplied that
            // names nothing is refused.
            std::vector<std::string> agent_ids;
            if (!req.body.empty()) {
                auto j = nlohmann::json::parse(req.body, nullptr, false);
                const auto refuse = [&](std::string_view reason, const std::string& msg) {
                    if (metrics_)
                        metrics_
                            ->counter("yuzu_server_dispatch_target_rejected_total",
                                      {{"route", "policy_remediate"},
                                       {"reason", std::string(reason)}})
                            .increment();
                    if (audit_fn_)
                        audit_fn_(req, "policy.remediate", "denied", "policy", id,
                                  std::string("reason=") + std::string(reason));
                    res.status = 400;
                    res.set_content(nlohmann::json({{"error", {{"code", 400}, {"message", msg}}},
                                                    {"meta", {{"api_version", "v1"}}}})
                                        .dump(),
                                    "application/json");
                };
                if (j.is_discarded() || !j.is_object()) {
                    refuse(yuzu::server::kReasonBodyType,
                           "request body must be a JSON object");
                    return;
                }
                // `scope` is NOT honoured on this route: PolicyEvaluator::remediate
                // takes only (policy_id, agent_ids). Refuse it BEFORE the shared
                // shape check, which would otherwise type-check it, empty-check
                // it, and then let the route discard it — so `{"scope":"tag:x"}`
                // passed validation, left agent_ids empty, and empty here means
                // EVERY non-compliant agent in the policy. A narrowing selector
                // producing a wider MUTATING remediation: this PR's own defect
                // class, arriving through the guard added to prevent it.
                //
                // Worse than the silent drop it replaced, until now: the shared
                // check's `target_conflict` message tells a caller who sends both
                // fields to "supply exactly one", steering them straight into the
                // widening case. Refusing scope outright is the only honest
                // answer on a route that cannot act on it. (Review finding, #2548.)
                if (j.contains("scope")) {
                    refuse(yuzu::server::kReasonScopeUnsupported,
                           "scope is not supported on this route; remediation targets are "
                           "selected by agent_ids, or by omitting it to target every "
                           "non-compliant agent in the policy");
                    return;
                }
                if (auto bv = yuzu::server::check_targeting_shape(j)) {
                    refuse(bv->reason, bv->message);
                    return;
                }
                if (j.contains("agent_ids")) {
                    for (const auto& a : j["agent_ids"])
                        agent_ids.push_back(a.get<std::string>());
                }
            }
            auto result = policy_evaluator_->remediate(id, agent_ids);
            if (!result.ok) {
                int code = 400;
                if (result.error.find("not found") != std::string::npos)
                    code = 404;
                else if (result.error.find("remediation pathway") != std::string::npos ||
                         result.error.find("no non_compliant") != std::string::npos ||
                         result.error.find("no in-scope") != std::string::npos)
                    code = 409;
                audit_fn_(req, "policy.remediate", "denied", "policy", id, result.error);
                res.status = code;
                // Nested A4 error envelope, matching /evaluate and the other
                // policy endpoints (gov consistency SHOULD-1).
                res.set_content(nlohmann::json({{"error", {{"code", code}, {"message", result.error}}},
                                                {"meta", {{"api_version", "v1"}}}})
                                    .dump(),
                                "application/json");
                return;
            }
            audit_fn_(req, "policy.remediate", "success", "policy", id,
                      "execution_id=" + result.execution_id +
                          " agents=" + std::to_string(result.agents));
            emit_event_fn_("policy.remediated", req, {},
                           {{"policy_id", id},
                            {"execution_id", result.execution_id},
                            {"agents", result.agents}});
            res.status = 202;
            res.set_content(nlohmann::json({{"status", "remediating"},
                                            {"execution_id", result.execution_id},
                                            {"agents", result.agents}})
                                .dump(),
                            "application/json");
        });

    // GET /api/compliance -- fleet compliance summary
    sink.Get("/api/compliance",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Read"))
                return;
            if (!policy_store_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto fc = policy_store_->get_fleet_compliance();
            if (!fc) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store degraded"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }
            res.set_content(
                nlohmann::json({{"compliance_pct", fc->compliance_pct},
                                {"total_checks", fc->total_checks},
                                {"compliant", fc->compliant},
                                {"non_compliant", fc->non_compliant},
                                {"unknown", fc->unknown},
                                {"fixing", fc->fixing},
                                {"error", fc->error}})
                    .dump(),
                "application/json");
        });

    // GET /api/compliance/:policy_id -- per-policy compliance detail
    sink.Get(R"(/api/compliance/([^/]+))",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Read"))
                return;
            if (!policy_store_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto policy_id = req.matches[1].str();
            auto summary = policy_store_->get_compliance_summary(policy_id);
            auto statuses = policy_store_->get_policy_agent_statuses(policy_id);
            if (!summary || !statuses) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"policy store degraded"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            nlohmann::json agents_arr = nlohmann::json::array();
            for (const auto& s : *statuses) {
                agents_arr.push_back({{"agent_id", s.agent_id},
                                      {"status", s.status},
                                      {"last_check_at", s.last_check_at},
                                      {"last_fix_at", s.last_fix_at},
                                      {"check_result", s.check_result}});
            }

            res.set_content(
                nlohmann::json({{"policy_id", policy_id},
                                {"summary", {{"compliant", summary->compliant},
                                              {"non_compliant", summary->non_compliant},
                                              {"unknown", summary->unknown},
                                              {"fixing", summary->fixing},
                                              {"error", summary->error},
                                              {"total", summary->total}}},
                                {"agents", agents_arr}})
                    .dump(),
                "application/json");
        });
}

} // namespace yuzu::server
