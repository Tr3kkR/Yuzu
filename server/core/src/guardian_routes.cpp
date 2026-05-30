/// @file guardian_routes.cpp
/// Guardian dashboard HTMX routes + fragment renderers. See guardian_routes.hpp
/// for the coordination/mock contract.

#include "guardian_routes.hpp"

#include "guaranteed_state_store.hpp"
#include "web_utils.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <string>
#include <vector>

// Guardian page HTML (defined in guardian_ui.cpp).
extern const char* const kGuardianHtml;

namespace yuzu::server {

namespace {

// ── Mock fixtures ───────────────────────────────────────────────────────────
// Contract-shaped sample data so the dashboard is self-demonstrating before the
// backend status/baseline/schema surfaces land (docs/guardian-mvp-contract.md
// §8, §10). Every renderer that uses these is marked TODO(guardian-backend).

struct MockGuard {
    const char* id;
    const char* name;
    const char* os;          // "W" | "L" | "M"
    const char* status;      // compliant|drifted|remediation_failed|errored|exempt|stale
    const char* severity;    // critical|high|medium|low
    int compliant;
    int total;
    bool healthy;            // guard_healthy signal (startup-wiring), distinct from status
};

constexpr std::array<MockGuard, 6> kMockGuards{{
    {"block-smb-445", "block-smb-445", "W", "compliant", "high", 148, 148, true},
    {"edr-agent-running", "edr-agent-running", "W", "compliant", "critical", 148, 148, true},
    {"ssh-no-root-login", "ssh-no-root-login", "L", "drifted", "high", 28, 30, true},
    {"av-scan-7d", "av-scan-7d", "W", "remediation_failed", "high", 144, 148, true},
    {"macos-alf-on", "macos-alf-on", "M", "compliant", "high", 20, 20, true},
    {"reg-watch-legacy", "reg-watch-legacy", "W", "errored", "medium", 0, 148, false},
}};

struct MockEvent {
    const char* time;
    const char* type;        // frozen v1 taxonomy
    const char* guard;
    const char* agent;
    const char* detail;
};

constexpr std::array<MockEvent, 6> kMockEvents{{
    {"10:42:31", "drift.remediated", "block-smb-445", "DESKTOP-A3F", "Port 445 opened &rarr; blocked (2ms)"},
    {"10:41:08", "drift.detected", "av-scan-7d", "LAPTOP-B92", "Last scan 9d ago &rarr; triggered"},
    {"10:39:55", "remediation.failed", "av-scan-7d", "LAPTOP-B92", "Defender service start denied (attempt 3)"},
    {"10:38:12", "guard.armed", "edr-agent-running", "SRV-DC01", "Self-test round-trip OK"},
    {"10:36:40", "guard.unhealthy", "reg-watch-legacy", "DESKTOP-K7M", "KEY_NOTIFY denied &mdash; watch deaf"},
    {"10:35:14", "resilience.escalated", "block-smb-445", "DESKTOP-K7M", "firewall-api &rarr; registry-write"},
}};

struct MockBaseline {
    const char* id;
    const char* name;
    const char* scope;
    const char* lifecycle;   // draft | deployed
    int guards;
    int agents;
};

constexpr std::array<MockBaseline, 3> kMockBaselines{{
    {"cis-win-l1", "CIS Windows L1", "tag:production AND ostype:windows", "deployed", 24, 148},
    {"linux-harden", "Linux Hardening", "ostype:linux", "deployed", 9, 30},
    {"rdp-lockdown", "RDP Lockdown (draft)", "tag:workstations AND NOT tag:jump-hosts", "draft", 3, 0},
}};

// ── Display helpers ─────────────────────────────────────────────────────────

// Worst-of severity ranking for a fleet/rollup badge (contract decision 5):
// remediation_failed/errored (red) > drifted (amber) > compliant (green).
// exempt is out of the denominator; stale is surfaced distinctly elsewhere.
const char* worst_badge_class(int drifted, int remediation_failed, int errored) {
    if (remediation_failed > 0 || errored > 0) return "worst-bad";
    if (drifted > 0) return "worst-warn";
    return "worst-good";
}

const char* worst_badge_label(int drifted, int remediation_failed, int errored) {
    if (remediation_failed > 0 || errored > 0) return "Action required";
    if (drifted > 0) return "Drift present";
    return "All compliant";
}

// Map a status taxonomy value to its badge CSS class + human label.
std::string status_badge(const std::string& status) {
    std::string label = status;
    if (status == "remediation_failed") label = "remediation failed";
    return "<span class=\"gs-badge gs-" + status + "\">" + label + "</span>";
}

std::string stat_card(int n, const char* label, const char* tone) {
    return "<div class=\"stat-card\"><div class=\"stat-num " + std::string(tone) +
           "\">" + std::to_string(n) + "</div><div class=\"stat-label\">" +
           label + "</div></div>";
}

// Normalise an event_type ("drift.detected") to a CSS-safe suffix
// ("drift_detected") for the .et-* chip classes; unknown types render generic.
std::string event_type_class(const std::string& type) {
    std::string s = type;
    for (auto& c : s)
        if (c == '.') c = '_';
    static const std::array<const char*, 6> known{
        {"drift_detected", "drift_remediated", "remediation_failed", "guard_armed",
         "guard_unhealthy", "resilience_escalated"}};
    for (const auto* k : known)
        if (s == k) return "et-" + s;
    return "et-generic";
}

} // namespace

// ── Fragment renderers ───────────────────────────────────────────────────────

std::string GuardianRoutes::render_status_fragment(const std::string& view) const {
    // TODO(guardian-backend): replace mock rollups with
    //   GET /api/v1/guaranteed-state/status  (fleet/guard/agent/mgroup/baseline
    //   + per-state counts + worst-of + staleness). The shape below mirrors
    //   the contract §5 taxonomy so the swap is a data-source change only.
    std::string html;

    if (view.empty() || view == "fleet") {
        const int guards = 42, compliant = 39, drifted = 2, remediation_failed = 0,
                  errored = 1, exempt = 0, stale = 1;
        const int comp_pct = 93;

        html += "<div style=\"display:flex;align-items:center;gap:1rem;flex-wrap:wrap;margin-bottom:0.75rem\">";
        html += "<span class=\"worst-badge " +
                std::string(worst_badge_class(drifted, remediation_failed, errored)) + "\">" +
                worst_badge_label(drifted, remediation_failed, errored) + "</span>";
        html += "<span style=\"font-size:0.72rem;color:var(--muted)\">Platforms: "
                "<strong style=\"color:var(--fg)\">148</strong> W &middot; "
                "<strong style=\"color:var(--fg)\">30</strong> L &middot; "
                "<strong style=\"color:var(--fg)\">20</strong> M</span>";
        html += "</div>";

        html += "<div class=\"stat-cards\">";
        html += stat_card(guards, "Guards", "info");
        html += stat_card(compliant, "Compliant", "good");
        html += stat_card(drifted, "Drifted", "warn");
        html += stat_card(remediation_failed, "Remediation failed", "bad");
        html += stat_card(errored, "Errored", "bad");
        html += stat_card(exempt, "Exempt", "mute");
        html += stat_card(stale, "Stale", "mute");
        html += "<div class=\"stat-card\"><div class=\"stat-num good\">" +
                std::to_string(comp_pct) + "%</div><div class=\"stat-label\">Fleet comp.</div></div>";
        html += "</div>";
        html += "<div class=\"mock-note\">Mock rollup &mdash; wires to "
                "<code>GET /api/v1/guaranteed-state/status</code> when fleet aggregation lands. "
                "<em>Stale</em> is derived from heartbeat freshness and shown distinctly from compliance state.</div>";
        return html;
    }

    struct Row { const char* name; int compliant; int drifted; int rf; int errored; int stale; };
    std::vector<Row> rows;
    std::string col0 = "Guard";
    if (view == "guard") {
        col0 = "Guard";
        rows = {{"block-smb-445", 148, 0, 0, 0, 0},
                {"ssh-no-root-login", 28, 2, 0, 0, 0},
                {"av-scan-7d", 144, 0, 4, 0, 0},
                {"reg-watch-legacy", 0, 0, 0, 148, 0}};
    } else if (view == "agent") {
        col0 = "Agent";
        rows = {{"DESKTOP-A3F", 41, 1, 0, 0, 0},
                {"LAPTOP-B92", 39, 0, 3, 0, 0},
                {"SRV-DC01", 42, 0, 0, 0, 0},
                {"DESKTOP-K7M", 40, 1, 0, 1, 0}};
    } else if (view == "mgroup") {
        col0 = "Management Group";
        rows = {{"Corp / Workstations", 120, 2, 4, 1, 1},
                {"Corp / Servers", 60, 0, 0, 0, 0},
                {"Branch / Linux", 28, 2, 0, 0, 0}};
    } else { // baseline
        col0 = "Baseline";
        rows = {{"CIS Windows L1", 142, 1, 4, 1, 0},
                {"Linux Hardening", 28, 2, 0, 0, 0},
                {"RDP Lockdown (draft)", 0, 0, 0, 0, 0}};
    }

    html += "<table class=\"detail-table\"><thead><tr>"
            "<th>" + col0 + "</th><th>Worst-of</th><th>Compliant</th><th>Drifted</th>"
            "<th>Rem. failed</th><th>Errored</th><th>Stale</th>"
            "</tr></thead><tbody>";
    for (const auto& r : rows) {
        html += "<tr><td style=\"font-weight:600\">" + html_escape(r.name) + "</td>"
                "<td><span class=\"worst-badge " +
                std::string(worst_badge_class(r.drifted, r.rf, r.errored)) +
                "\" style=\"font-size:0.62rem;padding:0.1rem 0.45rem\">" +
                worst_badge_label(r.drifted, r.rf, r.errored) + "</span></td>"
                "<td style=\"color:var(--green)\">" + std::to_string(r.compliant) + "</td>"
                "<td style=\"color:var(--yellow)\">" + std::to_string(r.drifted) + "</td>"
                "<td style=\"color:var(--red)\">" + std::to_string(r.rf) + "</td>"
                "<td style=\"color:var(--red)\">" + std::to_string(r.errored) + "</td>"
                "<td style=\"color:var(--muted)\">" + std::to_string(r.stale) + "</td></tr>";
    }
    html += "</tbody></table>";
    html += "<div class=\"mock-note\">Mock " + html_escape(view) +
            " rollup. Management-group rollup will JOIN ManagementGroupStore membership "
            "(hierarchy-aware); baseline rollup will GROUP BY deployed baseline.</div>";
    return html;
}

std::string GuardianRoutes::render_guards_fragment(const std::string& status_filter) const {
    std::string html = "<div class=\"guard-list\">";

    // Prefer real authored rules when the store has any; otherwise mock so the
    // page demonstrates the full taxonomy. Per-guard live status aggregation is
    // not yet available, so status/counts remain mock either way.
    // TODO(guardian-backend): fold in GET /api/v1/guaranteed-state/status per guard.
    bool used_real = false;
    if (store_ && store_->is_open()) {
        auto rules = store_->list_rules();
        if (!rules.empty()) {
            used_real = true;
            for (const auto& r : rules) {
                const std::string os = r.os_target.empty() ? "ALL"
                                       : (r.os_target == "windows" ? "W"
                                          : r.os_target == "linux"  ? "L"
                                          : r.os_target == "macos"  ? "M" : r.os_target);
                html += "<div class=\"guard-item\" hx-get=\"/fragments/guardian/guard/" +
                        html_escape(r.rule_id) + "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">"
                        "<div class=\"guard-item-top\">"
                        "<span class=\"guard-name\">" + html_escape(r.name) + "</span>"
                        "<span class=\"guard-os\">" + html_escape(os) + "</span>"
                        "<span style=\"margin-left:auto\">" + status_badge("compliant") + "</span>"
                        "</div>"
                        "<div class=\"guard-meta\">"
                        "<span>" + html_escape(r.severity.empty() ? "medium" : r.severity) + "</span>"
                        "<span>mode: " + html_escape(r.enforcement_mode.empty() ? "enforce" : r.enforcement_mode) + "</span>"
                        "<span class=\"health-ok\">&#9679; healthy</span>"
                        "</div></div>";
            }
        }
    }

    if (!used_real) {
        for (const auto& g : kMockGuards) {
            if (!status_filter.empty() && status_filter != g.status) continue;
            const char* health_cls = g.healthy ? "health-ok" : "health-bad";
            const char* health_lbl = g.healthy ? "&#9679; healthy" : "&#9679; unhealthy";
            html += "<div class=\"guard-item\" hx-get=\"/fragments/guardian/guard/" +
                    std::string(g.id) + "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">"
                    "<div class=\"guard-item-top\">"
                    "<span class=\"guard-name\">" + std::string(g.name) + "</span>"
                    "<span class=\"guard-os\">" + std::string(g.os) + "</span>"
                    "<span style=\"margin-left:auto\">" + status_badge(g.status) + "</span>"
                    "</div>"
                    "<div class=\"guard-meta\">"
                    "<span>" + std::string(g.severity) + "</span>"
                    "<span>" + std::to_string(g.compliant) + "/" + std::to_string(g.total) + " agents</span>"
                    "<span class=\"" + health_cls + "\">" + health_lbl + "</span>"
                    "</div></div>";
        }
    }
    html += "</div>";
    if (!used_real)
        html += "<div class=\"mock-note\">Mock guards. Live list reads authored rules from "
                "GuaranteedStateStore; per-guard status wires to "
                "<code>/api/v1/guaranteed-state/status</code>.</div>";
    return html;
}

std::string GuardianRoutes::render_events_fragment(const std::string& type_filter,
                                                   const std::string& severity_filter) const {
    (void)severity_filter;
    std::string html = "<div class=\"event-list\">";

    bool used_real = false;
    if (store_ && store_->is_open()) {
        GuaranteedStateEventQuery q;
        q.limit = 20;
        auto rows = store_->query_events(q);
        if (!rows.empty()) {
            used_real = true;
            for (const auto& e : rows) {
                if (!type_filter.empty() && type_filter != e.event_type) continue;
                html += "<div class=\"event-item\"><div class=\"event-top\">"
                        "<span class=\"event-time\">" + html_escape(e.timestamp) + "</span>"
                        "<span class=\"event-type " + event_type_class(e.event_type) + "\">" +
                        html_escape(e.event_type) + "</span></div>"
                        "<div class=\"event-detail\"><strong>" + html_escape(e.rule_id) +
                        "</strong> on <strong>" + html_escape(e.agent_id) + "</strong></div></div>";
            }
        }
    }

    if (!used_real) {
        for (const auto& e : kMockEvents) {
            if (!type_filter.empty() && type_filter != e.type) continue;
            html += "<div class=\"event-item\"><div class=\"event-top\">"
                    "<span class=\"event-time\">" + std::string(e.time) + "</span>"
                    "<span class=\"event-type " + event_type_class(e.type) + "\">" +
                    std::string(e.type) + "</span></div>"
                    "<div class=\"event-detail\"><strong>" + std::string(e.guard) +
                    "</strong> on <strong>" + std::string(e.agent) + "</strong> &middot; " +
                    std::string(e.detail) + "</div></div>";
        }
    }
    html += "</div>";
    if (!used_real)
        html += "<div class=\"mock-note\">Mock timeline. Live feed reads GuaranteedStateStore events / "
                "<code>GET /api/v1/guaranteed-state/events</code>.</div>";
    return html;
}

std::string GuardianRoutes::render_guard_detail_fragment(const std::string& guard_id) const {
    // Header fields prefer a real rule lookup; the rest is mock.
    std::string name = guard_id, severity = "high", mode = "enforce", os = "windows",
                scope = "tag:production-workstations", yaml;
    if (store_ && store_->is_open()) {
        if (auto r = store_->get_rule(guard_id)) {
            name = r->name;
            severity = r->severity.empty() ? severity : r->severity;
            mode = r->enforcement_mode.empty() ? mode : r->enforcement_mode;
            os = r->os_target.empty() ? "all" : r->os_target;
            scope = r->scope_expr;
            yaml = r->yaml_source;
        }
    }
    if (yaml.empty())
        yaml = "apiVersion: yuzu.io/v1alpha1\nkind: GuaranteedStateRule\nmetadata:\n  name: " +
               name + "\nspec:\n  spark:\n    type: registry-change\n  assertion:\n    "
               "type: registry-value-equals\n  remediation:\n    action: alert-only";

    std::string html;
    html += "<div class=\"detail-panel\"><h3>" + html_escape(name) + " " + status_badge("compliant") + "</h3>";
    html += "<div class=\"kv\">"
            "<div class=\"k\">Severity</div><div>" + html_escape(severity) + "</div>"
            "<div class=\"k\">Mode</div><div>" + html_escape(mode) + "</div>"
            "<div class=\"k\">OS target</div><div>" + html_escape(os) + "</div>"
            "<div class=\"k\">Scope</div><div style=\"font-family:var(--mono);font-size:0.75rem\">" +
            html_escape(scope.empty() ? "(set at Baseline level)" : scope) + "</div>"
            "<div class=\"k\">Composition</div><div>Spark (registry-change) &rarr; "
            "Assertion (registry-value-equals) &rarr; alert</div>"
            "</div>";

    html += "<div style=\"font-size:0.75rem;font-weight:600;margin:0.5rem 0 0.3rem\">Agent compliance</div>";
    html += "<table class=\"detail-table\"><thead><tr><th>Agent</th><th>Status</th>"
            "<th>Last check</th><th>Drifts</th><th>Remediations</th></tr></thead><tbody>"
            "<tr><td>DESKTOP-A3F</td><td>" + status_badge("compliant") + "</td><td>10:42:31</td><td>3</td><td>3</td></tr>"
            "<tr><td>DESKTOP-K7M</td><td>" + status_badge("compliant") + "</td><td>10:35:14</td><td>1</td><td>1</td></tr>"
            "<tr><td>LAPTOP-B92</td><td>" + status_badge("drifted") + "</td><td>10:40:05</td><td>1</td><td>0</td></tr>"
            "</tbody></table>";

    html += "<div style=\"font-size:0.75rem;font-weight:600;margin:0.75rem 0 0.3rem\">YAML source "
            "<span style=\"font-weight:400;color:var(--muted)\">(server-rendered, read-only)</span></div>";
    html += "<pre class=\"yaml\">" + html_escape(yaml) + "</pre>";
    html += "<div class=\"mock-note\">Agent table is mock; wires to "
            "<code>/api/v1/guaranteed-state/status/{agent}</code> per guard.</div>";
    html += "</div>";
    return html;
}

std::string GuardianRoutes::render_baselines_fragment() const {
    // TODO(guardian-backend): baselines store + deploy fan-out do not exist yet
    // (contract §6/§7). Mock list with deploy controls; deploy is Baseline-level.
    std::string html;
    for (const auto& b : kMockBaselines) {
        const bool deployed = std::string(b.lifecycle) == "deployed";
        html += "<div class=\"baseline-card\">"
                "<div class=\"baseline-top\">"
                "<span class=\"baseline-name\" style=\"cursor:pointer\" "
                "hx-get=\"/fragments/guardian/baseline/" + std::string(b.id) +
                "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" + std::string(b.name) + "</span>"
                "<span class=\"lifecycle-" + std::string(b.lifecycle) + "\" style=\"font-size:0.72rem;font-weight:600\">" +
                (deployed ? "&#9679; deployed" : "&#9675; draft") + "</span>"
                "</div>"
                "<div class=\"baseline-scope\">" + std::string(b.scope) + "</div>"
                "<div class=\"guard-meta\">"
                "<span>" + std::to_string(b.guards) + " guards</span>"
                "<span>" + std::to_string(b.agents) + " agents in scope</span>"
                "<span style=\"margin-left:auto\">"
                "<button class=\"btn btn-secondary btn-sm\" "
                "hx-post=\"/fragments/guardian/baseline/" + std::string(b.id) + "/deploy\" "
                "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" +
                (deployed ? "Re-deploy" : "Deploy") + "</button></span>"
                "</div></div>";
    }
    html += "<div class=\"mock-note\">Mock baselines. Create/edit, M:N membership and deploy "
            "(scope &rarr; union-expand &rarr; push) land with the Baseline backend.</div>";
    return html;
}

std::string GuardianRoutes::render_baseline_detail_fragment(const std::string& baseline_id) const {
    const MockBaseline* b = nullptr;
    for (const auto& mb : kMockBaselines)
        if (baseline_id == mb.id) { b = &mb; break; }

    std::string html = "<div class=\"detail-panel\">";
    if (!b) {
        html += "<div class=\"empty-state\">Baseline not found.</div></div>";
        return html;
    }
    const bool deployed = std::string(b->lifecycle) == "deployed";
    html += "<h3>" + std::string(b->name) + " <span class=\"lifecycle-" + std::string(b->lifecycle) +
            "\" style=\"font-size:0.72rem\">" + std::string(b->lifecycle) + "</span></h3>";
    html += "<div class=\"kv\">"
            "<div class=\"k\">Scope</div><div style=\"font-family:var(--mono);font-size:0.75rem\">" +
            std::string(b->scope) + "</div>"
            "<div class=\"k\">Member guards</div><div>" + std::to_string(b->guards) + "</div>"
            "<div class=\"k\">Agents in scope</div><div>" + std::to_string(b->agents) + "</div>"
            "</div>";
    html += "<div class=\"form-actions\">"
            "<button class=\"btn btn-secondary\" hx-post=\"/fragments/guardian/baseline/" +
            std::string(b->id) + "/deploy\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" +
            (deployed ? "Re-deploy" : "Deploy") + "</button></div>";
    html += "<div class=\"mock-note\">Mock baseline detail. Membership editing + deploy fan-out land "
            "with the Baseline backend (contract §6/§7).</div></div>";
    return html;
}

std::string GuardianRoutes::render_guard_form_fragment() const {
    // TODO(guardian-backend): make this schema-driven from
    //   GET /api/v1/guaranteed-state/schemas  (catalog + per-type JSON Schema
    //   with discriminated subschemas). For now a representative static form
    //   for the Slice-A registry types; submission is stubbed.
    std::string html =
        "<div class=\"detail-panel\"><h3>New Guard</h3>"
        "<form class=\"gs-form\" hx-post=\"/fragments/guardian/guards\" "
        "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">"
        "<label>Name</label><input name=\"name\" placeholder=\"block-smb-445\">"
        "<div class=\"form-row\">"
        "<div><label>Severity</label><select name=\"severity\">"
        "<option>critical</option><option selected>high</option><option>medium</option><option>low</option>"
        "</select></div>"
        "<div><label>Enforcement mode</label><select name=\"enforcement_mode\">"
        "<option selected>enforce</option><option>audit</option><option>disabled</option></select></div>"
        "</div>"
        "<label>Spark (trigger)</label><select name=\"spark_type\">"
        "<option value=\"registry-change\">registry-change</option></select>"
        "<label>Assertion</label><select name=\"assertion_type\">"
        "<option value=\"registry-value-equals\">registry-value-equals</option></select>"
        "<div class=\"form-row\">"
        "<div><label>Hive</label><select name=\"hive\"><option>HKLM</option><option>HKCU</option></select></div>"
        "<div><label>Value type</label><select name=\"value_type\">"
        "<option>REG_DWORD</option><option>REG_SZ</option><option>REG_QWORD</option></select></div>"
        "</div>"
        "<label>Key</label><input name=\"key\" placeholder=\"SOFTWARE\\\\YuzuTest\">"
        "<div class=\"form-row\">"
        "<div><label>Value name</label><input name=\"value_name\" placeholder=\"Flag\"></div>"
        "<div><label>Expected</label><input name=\"expected\" placeholder=\"1\"></div>"
        "</div>"
        "<label>Remediation</label><select name=\"remediation_action\">"
        "<option value=\"alert-only\" selected>alert-only</option>"
        "<option value=\"enforce\">enforce (registry-write)</option></select>"
        "<div class=\"form-actions\">"
        "<button type=\"submit\" class=\"btn btn-secondary\">Create Guard</button></div>"
        "</form>"
        "<div class=\"mock-note\">Form is a static scaffold for the Slice-A registry types. It will be "
        "generated from the schema-registry discovery surface "
        "(<code>GET /api/v1/guaranteed-state/schemas</code>, discriminated subschemas) and submit a "
        "structured create when those land. Scope/targeting is set at the Baseline, not per-Guard.</div></div>";
    return html;
}

std::string GuardianRoutes::render_baseline_form_fragment() const {
    std::string html =
        "<div class=\"detail-panel\"><h3>New Baseline</h3>"
        "<form class=\"gs-form\" hx-post=\"/fragments/guardian/baselines\" "
        "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">"
        "<label>Name</label><input name=\"name\" placeholder=\"CIS Windows L1\">"
        "<label>Scope (Scope DSL &mdash; sets device targeting)</label>"
        "<input name=\"scope\" placeholder=\"tag:production AND ostype:windows\">"
        "<label>Member guards</label>"
        "<textarea name=\"guards\" placeholder=\"one guard name per line&#10;block-smb-445&#10;edr-agent-running\"></textarea>"
        "<div class=\"form-actions\">"
        "<button type=\"submit\" class=\"btn btn-secondary\">Create Baseline (draft)</button></div>"
        "</form>"
        "<div class=\"mock-note\">Deploy is a separate, Baseline-level action. Membership is M:N to Guards; "
        "the scope picker will reuse the existing Scope engine. Submission wires to the Baseline backend "
        "when it lands.</div></div>";
    return html;
}

// ── Route registration ───────────────────────────────────────────────────────

void GuardianRoutes::register_routes(httplib::Server& svr,
                                     AuthFn auth_fn,
                                     PermFn perm_fn,
                                     AuditFn audit_fn,
                                     EmitEventFn emit_event_fn,
                                     GuaranteedStateStore* store,
                                     AgentsJsonFn agents_json_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    audit_fn_ = std::move(audit_fn);
    emit_event_fn_ = std::move(emit_event_fn);
    store_ = store;
    agents_json_fn_ = std::move(agents_json_fn);

    // -- Guardian dashboard page ------------------------------------------
    svr.Get("/guardian", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) {
            res.set_redirect("/login");
            return;
        }
        res.set_content(kGuardianHtml, "text/html; charset=utf-8");
    });

    // -- Status rollup (view = fleet|guard|agent|mgroup|baseline) ----------
    svr.Get("/fragments/guardian/status",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!auth_fn_(req, res)) return;
                const std::string view = req.has_param("view") ? req.get_param_value("view") : "fleet";
                res.set_content(render_status_fragment(view), "text/html; charset=utf-8");
            });

    // -- Guards list (optional ?status= filter) ----------------------------
    svr.Get("/fragments/guardian/guards",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!auth_fn_(req, res)) return;
                const std::string sf = req.has_param("status") ? req.get_param_value("status") : "";
                res.set_content(render_guards_fragment(sf), "text/html; charset=utf-8");
            });

    // -- Event timeline (optional ?type= / ?severity= filters) -------------
    svr.Get("/fragments/guardian/events",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!auth_fn_(req, res)) return;
                const std::string tf = req.has_param("type") ? req.get_param_value("type") : "";
                const std::string sf = req.has_param("severity") ? req.get_param_value("severity") : "";
                res.set_content(render_events_fragment(tf, sf), "text/html; charset=utf-8");
            });

    // -- Per-guard detail --------------------------------------------------
    svr.Get(R"(/fragments/guardian/guard/([A-Za-z0-9._\-]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!auth_fn_(req, res)) return;
                res.set_content(render_guard_detail_fragment(req.matches[1].str()),
                                "text/html; charset=utf-8");
            });

    // -- Baselines list ----------------------------------------------------
    svr.Get("/fragments/guardian/baselines",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!auth_fn_(req, res)) return;
                res.set_content(render_baselines_fragment(), "text/html; charset=utf-8");
            });

    // -- Per-baseline detail ----------------------------------------------
    svr.Get(R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!auth_fn_(req, res)) return;
                res.set_content(render_baseline_detail_fragment(req.matches[1].str()),
                                "text/html; charset=utf-8");
            });

    // -- Create forms ------------------------------------------------------
    svr.Get("/fragments/guardian/guard-form",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!auth_fn_(req, res)) return;
                res.set_content(render_guard_form_fragment(), "text/html; charset=utf-8");
            });
    svr.Get("/fragments/guardian/baseline-form",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!auth_fn_(req, res)) return;
                res.set_content(render_baseline_form_fragment(), "text/html; charset=utf-8");
            });

    // -- Mock create (Guard) — structured create lands with the backend ----
    svr.Post("/fragments/guardian/guards",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Write")) return;
                 const std::string name =
                     req.has_param("name") ? req.get_param_value("name") : "(unnamed)";
                 audit_fn_(req, "guaranteed_state.rule.create", "denied", "GuaranteedState", name,
                           "dashboard mock - structured create not yet wired");
                 res.set_content(
                     "<div class=\"detail-panel\"><div class=\"empty-state\">Guard authoring is not "
                     "wired yet &mdash; the structured create endpoint is being built on "
                     "<code>feat/guardian-mvp</code>. Submitted draft: <strong>" +
                         html_escape(name) +
                         "</strong>.</div><div class=\"mock-note\">Will POST a structured Guard "
                         "(spark/assertion/remediation) to the create endpoint.</div></div>",
                     "text/html; charset=utf-8");
             });

    // -- Mock create (Baseline) -------------------------------------------
    svr.Post("/fragments/guardian/baselines",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Write")) return;
                 const std::string name =
                     req.has_param("name") ? req.get_param_value("name") : "(unnamed)";
                 audit_fn_(req, "guaranteed_state.baseline.create", "denied", "GuaranteedState", name,
                           "dashboard mock - baseline backend not yet wired");
                 res.set_content(
                     "<div class=\"detail-panel\"><div class=\"empty-state\">Baseline authoring is not "
                     "wired yet &mdash; the Baseline backend is being built on "
                     "<code>feat/guardian-mvp</code>. Submitted draft: <strong>" +
                         html_escape(name) + "</strong>.</div></div>",
                     "text/html; charset=utf-8");
             });

    // -- Mock deploy (Baseline-level) -------------------------------------
    // NOTE: custom raw-string delimiter R"HX(...)HX" — the JSON payload
    // contains "(mock)", and a default R"(...)" literal would terminate early
    // at the ")" inside it. The HX delimiter avoids that.
    svr.Post(R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+)/deploy)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Push")) return;
                 const std::string id = req.matches[1].str();
                 audit_fn_(req, "guaranteed_state.push", "denied", "GuaranteedState", id,
                           "dashboard mock - deploy fan-out not yet wired");
                 res.set_header("HX-Trigger",
                                R"HX({"showToast":{"message":"Deploy queued (mock)","level":"warning"}})HX");
                 res.set_content(
                     "<div class=\"detail-panel\"><div class=\"empty-state\">Deploy fan-out "
                     "(scope &rarr; union-expand &rarr; push) is being built on "
                     "<code>feat/guardian-mvp</code>; <code>/api/v1/guaranteed-state/push</code> is "
                     "currently a stub. Baseline: <strong>" + html_escape(id) +
                         "</strong>.</div></div>",
                     "text/html; charset=utf-8");
             });
}

} // namespace yuzu::server
