/// @file compliance_routes.cpp
/// Compliance dashboard HTMX routes, policy/fragment API routes, and fleet
/// compliance endpoints.  Extracted from server.cpp — Phase 3a of the
/// god-object decomposition.

#include "compliance_routes.hpp"

#include "store_errors.hpp"
#include "web_utils.hpp"

#include <nlohmann/json.hpp>

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

    if (policy_store_ && policy_store_->is_open()) {
        auto all_policies = policy_store_->query_policies();
        for (const auto& p : all_policies) {
            auto cs = policy_store_->get_compliance_summary(p.id);
            PolicyRow row;
            row.id = p.id;
            row.name = p.name;
            row.scope = p.scope_expression;
            row.total = static_cast<int>(cs.total);
            row.compliant = static_cast<int>(cs.compliant);
            row.pct = (cs.total > 0) ? static_cast<int>(cs.compliant * 100 / cs.total) : 0;
            row.enabled = p.enabled;
            policies.push_back(std::move(row));
        }
    }

    // Fleet-level compliance from PolicyStore
    auto fc = (policy_store_ && policy_store_->is_open())
                  ? policy_store_->get_fleet_compliance()
                  : FleetCompliance{};
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
    // Look up the policy from the PolicyStore
    std::string policy_name = policy_id;
    if (policy_store_ && policy_store_->is_open()) {
        auto policy = policy_store_->get_policy(policy_id);
        if (policy)
            policy_name = policy->name;
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
    if (policy_store_ && policy_store_->is_open()) {
        auto statuses = policy_store_->get_policy_agent_statuses(policy_id);
        for (const auto& s : statuses) {
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

// ── Route registration ──────────────────────────────────────────────────────

void ComplianceRoutes::register_routes(httplib::Server& svr,
                                       AuthFn auth_fn,
                                       PermFn perm_fn,
                                       AuditFn audit_fn,
                                       EmitEventFn emit_event_fn,
                                       PolicyStore* policy_store,
                                       AgentsJsonFn agents_json_fn) {
    // Store dependency pointers
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    audit_fn_ = std::move(audit_fn);
    emit_event_fn_ = std::move(emit_event_fn);
    policy_store_ = policy_store;
    agents_json_fn_ = std::move(agents_json_fn);

    // -- Compliance dashboard page ----------------------------------------
    svr.Get("/compliance",
                     [this](const httplib::Request& req, httplib::Response& res) {
                         auto session = auth_fn_(req, res);
                         if (!session) {
                             res.set_redirect("/login");
                             return;
                         }
                         res.set_content(kComplianceHtml, "text/html; charset=utf-8");
                     });

    // -- Compliance HTMX fragment: fleet summary --------------------------
    svr.Get("/fragments/compliance/summary",
                     [this](const httplib::Request& req, httplib::Response& res) {
                         auto session = auth_fn_(req, res);
                         if (!session) return;
                         res.set_content(render_compliance_summary_fragment(),
                                         "text/html; charset=utf-8");
                     });

    // -- Compliance HTMX fragment: per-policy agent detail ----------------
    svr.Get(R"(/fragments/compliance/(\w[\w\-]*))",
                     [this](const httplib::Request& req, httplib::Response& res) {
                         auto session = auth_fn_(req, res);
                         if (!session) return;
                         auto policy_id = req.matches[1].str();
                         res.set_content(render_compliance_detail_fragment(policy_id),
                                         "text/html; charset=utf-8");
                     });

    // -- Policy Engine API (Phase 5) ------------------------------------------

    // GET /api/policy-fragments -- list all fragments
    svr.Get("/api/policy-fragments",
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
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& f : frags) {
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
    svr.Post("/api/policy-fragments",
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
    svr.Delete(R"(/api/policy-fragments/([^/]+))",
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
    svr.Get("/api/policies",
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
            nlohmann::json arr = nlohmann::json::array();
            for (const auto& p : policies) {
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
    svr.Post("/api/policies",
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
    svr.Get(R"(/api/policies/([^/]+))",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Read"))
                return;
            if (!policy_store_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto id = req.matches[1].str();
            auto policy = policy_store_->get_policy(id);
            if (!policy) {
                res.status = 404;
                res.set_content(R"({"error":{"code":404,"message":"policy not found"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            nlohmann::json inputs_obj = nlohmann::json::object();
            for (const auto& inp : policy->inputs)
                inputs_obj[inp.key] = inp.value;

            nlohmann::json triggers_arr = nlohmann::json::array();
            for (const auto& t : policy->triggers) {
                triggers_arr.push_back({{"id", t.id},
                                        {"type", t.trigger_type},
                                        {"config", nlohmann::json::parse(t.config_json, nullptr, false)}});
            }

            // Also fetch compliance summary
            auto cs = policy_store_->get_compliance_summary(id);

            res.set_content(
                nlohmann::json({{"id", policy->id},
                                {"name", policy->name},
                                {"description", policy->description},
                                {"yaml_source", policy->yaml_source},
                                {"fragment_id", policy->fragment_id},
                                {"scope_expression", policy->scope_expression},
                                {"enabled", policy->enabled},
                                {"inputs", inputs_obj},
                                {"triggers", triggers_arr},
                                {"management_groups", policy->management_groups},
                                {"created_at", policy->created_at},
                                {"updated_at", policy->updated_at},
                                {"compliance", {{"compliant", cs.compliant},
                                                 {"non_compliant", cs.non_compliant},
                                                 {"unknown", cs.unknown},
                                                 {"fixing", cs.fixing},
                                                 {"error", cs.error},
                                                 {"total", cs.total}}}})
                    .dump(),
                "application/json");
        });

    // DELETE /api/policies/:id
    svr.Delete(R"(/api/policies/([^/]+))",
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
    svr.Post(R"(/api/policies/([^/]+)/enable)",
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
    svr.Post(R"(/api/policies/([^/]+)/disable)",
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
    svr.Post(R"(/api/policies/([^/]+)/invalidate)",
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
    svr.Post("/api/policies/invalidate-all",
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

    // GET /api/compliance -- fleet compliance summary
    svr.Get("/api/compliance",
        [this](const httplib::Request& req, httplib::Response& res) {
            if (!perm_fn_(req, res, "Policy", "Read"))
                return;
            if (!policy_store_) {
                res.status = 503;
                res.set_content(R"({"error":{"code":503,"message":"service unavailable"},"meta":{"api_version":"v1"}})", "application/json");
                return;
            }

            auto fc = policy_store_->get_fleet_compliance();
            res.set_content(
                nlohmann::json({{"compliance_pct", fc.compliance_pct},
                                {"total_checks", fc.total_checks},
                                {"compliant", fc.compliant},
                                {"non_compliant", fc.non_compliant},
                                {"unknown", fc.unknown},
                                {"fixing", fc.fixing},
                                {"error", fc.error}})
                    .dump(),
                "application/json");
        });

    // GET /api/compliance/:policy_id -- per-policy compliance detail
    svr.Get(R"(/api/compliance/([^/]+))",
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

            nlohmann::json agents_arr = nlohmann::json::array();
            for (const auto& s : statuses) {
                agents_arr.push_back({{"agent_id", s.agent_id},
                                      {"status", s.status},
                                      {"last_check_at", s.last_check_at},
                                      {"last_fix_at", s.last_fix_at},
                                      {"check_result", s.check_result}});
            }

            res.set_content(
                nlohmann::json({{"policy_id", policy_id},
                                {"summary", {{"compliant", summary.compliant},
                                              {"non_compliant", summary.non_compliant},
                                              {"unknown", summary.unknown},
                                              {"fixing", summary.fixing},
                                              {"error", summary.error},
                                              {"total", summary.total}}},
                                {"agents", agents_arr}})
                    .dump(),
                "application/json");
        });
}

} // namespace yuzu::server
