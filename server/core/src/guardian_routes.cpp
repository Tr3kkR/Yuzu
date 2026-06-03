/// @file guardian_routes.cpp
/// Guardian dashboard HTMX routes + fragment renderers. See guardian_routes.hpp
/// for the coordination/mock contract.

#include "guardian_routes.hpp"

#include "guaranteed_state_store.hpp"
#include "guardian_rule_spec.hpp"
#include "secure_random.hpp"
#include "web_utils.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <cctype>
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

// Slugify a Guard name into the rule_id prefix: lowercase, keep [a-z0-9._-],
// collapse other runs to a single '-', trim; falls back to "guard".
std::string slugify(const std::string& name) {
    std::string s;
    bool dash = false;
    for (unsigned char c : name) {
        char lc = static_cast<char>(std::tolower(c));
        const bool ok = (lc >= 'a' && lc <= 'z') || (lc >= '0' && lc <= '9') || lc == '.' ||
                        lc == '_' || lc == '-';
        if (ok) {
            s.push_back(lc);
            dash = false;
        } else if (!dash && !s.empty()) {
            s.push_back('-');
            dash = true;
        }
    }
    if (s.size() > 48) s.resize(48);
    while (!s.empty() && s.back() == '-') s.pop_back();
    return s.empty() ? "guard" : s;
}

// Short unique suffix for a generated rule_id. CSPRNG hex; epoch fallback if the
// PRNG is unavailable (id uniqueness is a UNIQUE-constraint concern, not security).
std::string short_id() {
    if (auto h = random_hex(4); h) return *h;
    return std::to_string(now_epoch_seconds());
}

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

// ── Honest-state helpers (M2 / #1209) ────────────────────────────────────────
// Contract-shaped MOCK fixtures render ONLY when no Guardian backend is present
// (store null / not open) — a pure UI-development fallback. When the store is
// live, an empty result renders an honest empty state, never fabricated guards
// or "148/148 compliant" rollups: on an enforcement console, inventing
// compliance numbers is an observability-integrity hazard. Any mock that does
// render is wrapped in an unmistakable banner so it can never be read as live
// fleet state.
std::string demo_banner(const std::string& what) {
    return "<div style=\"background:rgba(255,176,32,0.12);border:1px solid var(--yellow);"
           "color:var(--yellow);padding:0.45rem 0.7rem;border-radius:0.4rem;margin-bottom:0.6rem;"
           "font-size:0.72rem;font-weight:600\">&#9888; DEMO DATA &mdash; " +
           what + ". Not live fleet state.</div>";
}

std::string empty_state(const std::string& title, const std::string& hint) {
    return "<div style=\"text-align:center;color:var(--muted);padding:1.6rem 1rem;font-size:0.8rem\">"
           "<div style=\"font-weight:600;color:var(--fg);margin-bottom:0.25rem\">" +
           title + "</div>" + hint + "</div>";
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
    const bool live = store_ && store_->is_open();
    std::string html;

    if (view.empty() || view == "fleet") {
        if (live) {
            // Live store: show the REAL guard count. Per-state compliance rollup
            // and fleet % need the status-aggregation backend; until it lands we
            // deliberately OMIT them rather than fabricate "148/148 compliant"
            // (M2 / #1209 — observability integrity on an enforcement console).
            html += "<div class=\"stat-cards\">" +
                    stat_card(static_cast<int>(store_->rule_count()), "Guards", "info") + "</div>";
            html += "<div class=\"mock-note\">Live guard count from GuaranteedStateStore. "
                    "Per-state compliance rollup (compliant / drifted / remediation-failed / "
                    "errored / stale) and fleet&nbsp;% wire to "
                    "<code>GET /api/v1/guaranteed-state/status</code> when fleet aggregation lands.</div>";
            return html;
        }
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
        html += demo_banner("example fleet rollup");
        return html;
    }

    if (live) {
        // Per-dimension rollups (guard / agent / mgroup / baseline) also need the
        // status-aggregation backend; show an honest placeholder, not mock rows.
        return empty_state(html_escape(view) + " rollup pending backend",
                           "Per-" + html_escape(view) +
                               " compliance rollup wires to GET /api/v1/guaranteed-state/status "
                               "when aggregation lands.");
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
    html += demo_banner(html_escape(view) + " rollup example");
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
                const bool on = r.enabled;
                // Empty/unknown renders as audit, NOT enforce: the agent arms
                // enforce only on an exact "enforce" match, so showing ENFORCING
                // for an empty mode would be a false-green (governance C1/B2).
                const std::string mode = (r.enforcement_mode == "enforce") ? "enforce" : "audit";
                const bool enforcing = (mode == "enforce");
                const char* badge_color = on ? (enforcing ? "var(--green)" : "var(--yellow)")
                                             : "var(--muted)";
                const char* badge_text = on ? (enforcing ? "ENFORCING" : "audit-only") : "disabled";
                const std::string rid = html_escape(r.rule_id);
                // Detail nav lives on the top row only, so the control buttons
                // below (siblings, not children) never open the detail panel.
                html += "<div class=\"guard-item\">"
                        "<div class=\"guard-item-top\" style=\"cursor:pointer\" "
                        "hx-get=\"/fragments/guardian/guard/" + rid +
                        "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">"
                        "<span class=\"guard-name\">" + html_escape(r.name) + "</span>"
                        "<span class=\"guard-os\">" + html_escape(os) + "</span>"
                        "<span style=\"margin-left:auto;font-size:0.62rem;font-weight:700;color:" +
                        std::string(badge_color) + "\">" + badge_text + "</span>"
                        "</div>"
                        "<div class=\"guard-meta\">"
                        "<span>" + html_escape(r.severity.empty() ? "medium" : r.severity) + "</span>"
                        "<span>mode: " + html_escape(on ? mode : "disabled") + "</span>"
                        "<span class=\"" + std::string(on ? "health-ok" : "health-bad") +
                        "\">&#9679; " + (on ? "armed" : "off") + "</span>"
                        "</div>"
                        // Live controls: enable/disable + audit↔enforce, auto-deployed.
                        "<div class=\"guard-meta\" style=\"gap:0.4rem;margin-top:0.4rem\">"
                        "<button class=\"btn btn-secondary\" "
                        "style=\"padding:0.15rem 0.5rem;font-size:0.7rem\" "
                        "hx-post=\"/fragments/guardian/guard/" + rid + "/enabled?value=" +
                        (on ? "0" : "1") +
                        "\" hx-target=\"#guardian-guards\" hx-swap=\"innerHTML\">" +
                        (on ? "Disable" : "Enable") + "</button>"
                        "<button class=\"btn btn-secondary\" " +
                        std::string(on ? "" : "disabled ") +
                        "style=\"padding:0.15rem 0.5rem;font-size:0.7rem\" "
                        "hx-post=\"/fragments/guardian/guard/" + rid + "/mode?value=" +
                        (enforcing ? "audit" : "enforce") +
                        "\" hx-target=\"#guardian-guards\" hx-swap=\"innerHTML\">" +
                        (enforcing ? "Switch to Audit" : "Switch to Enforce") + "</button>"
                        "</div>"
                        "</div>";
            }
        }
    }

    const bool live = store_ && store_->is_open();
    if (!used_real && live) {
        // Live store, zero authored rules → honest empty state, not fabricated
        // example guards (M2 / #1209; also the empty-store UX wart, where the mock
        // guards had no enable/mode controls and so made the toggle look missing).
        html += empty_state("No guards defined yet",
                            "Create a guard to start enforcing desired state across the fleet.");
    } else if (!used_real) {
        // No Guardian backend present (pure UI development) → contract-shaped
        // example guards, loudly labelled below so they cannot be read as live.
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
    if (!used_real && !live)
        html += demo_banner("example guards, not authored rules");
    return html;
}

void GuardianRoutes::apply_guard_change(const httplib::Request& req, httplib::Response& res,
                                        const std::string& rule_id, bool set_enabled, bool enabled,
                                        bool set_mode, const std::string& mode) {
    // Error responses return 200 with an inline banner PREPENDED to the
    // re-rendered guard list. The dashboard's htmx config does not swap 4xx/5xx
    // bodies (responseHandling swap:false), so a 4xx/5xx error fragment would
    // silently never render and the operator would get no feedback (governance
    // S1). 200 + banner + list keeps the list visible and shows what failed.
    auto fail = [this, &res](const std::string& msg) {
        res.status = 200;
        res.set_content("<div class=\"gs-error-banner\" style=\"background:#3a1a1a;"
                        "color:var(--red);padding:0.5rem 0.75rem;border-radius:0.4rem;"
                        "margin-bottom:0.5rem;font-size:0.78rem\">&#9888; " +
                            html_escape(msg) + "</div>" + render_guards_fragment(""),
                        "text/html; charset=utf-8");
    };

    if (!store_ || !store_->is_open())
        return fail("Guardian store unavailable.");
    auto rule = store_->get_rule(rule_id);
    if (!rule)
        return fail("No such guard: " + rule_id);

    std::string detail;
    if (set_enabled) {
        rule->enabled = enabled;
        detail = enabled ? "enabled=true" : "enabled=false";
    }
    if (set_mode) {
        if (mode != "enforce" && mode != "audit")
            return fail("Invalid mode (expected enforce or audit).");
        // Enforce-write denylist (H1): the create-time validator never runs on a
        // mode toggle, so re-check the STORED assertion here before promoting an
        // audit guard to a SYSTEM-write. Without this, an operator can create a
        // guard in audit mode on a protected key and flip it to enforce past the
        // gate (contract §6).
        if (mode == "enforce") {
            if (std::string why = guardian::dangerous_enforce_key_in_spec(rule->spec_json);
                !why.empty())
                return fail("Cannot enable enforce mode: this guard targets " + why +
                            ". Keep it in audit mode, or re-author it against a key outside the "
                            "protected persistence/privilege set.");
        }
        rule->enforcement_mode = mode;
        detail = "enforcement_mode=" + mode;
    }
    if (auto r = store_->update_rule(*rule); !r)
        return fail("Update failed: " + r.error());

    // Auto-deploy so the change reaches agents immediately. Scope the push to
    // THIS rule's scope_expr (H1 / #1209, contract G10) instead of the whole
    // fleet — a single toggle must not fan a full_sync out to every agent
    // (toggle storm = self-inflicted DoS, and it violates the network-kindness
    // NFR). full_sync stays true on purpose: the agent has no per-rule removal
    // verb (apply_rules only tears guards down via the full_sync clear), so a
    // disable can only propagate by having the in-scope agents rebuild from the
    // new enabled set — which no longer contains this rule. An empty scope_expr
    // means the rule targets the whole fleet, in which case the push lambda's
    // send_to_all branch is the correct (and only) behaviour.
    int pushed = -2;
    if (push_fn_)
        pushed = push_fn_(/*scope=*/rule->scope_expr, /*full_sync=*/true);
    // Audit the mutation under its OWN verb (not guaranteed_state.push) so "who
    // enabled enforcement / switched mode" is queryable, and so a push-transport
    // failure is not logged as an authz denial of a change that already
    // persisted (governance C2). The deploy outcome rides in the detail.
    const std::string deploy = pushed >= 0 ? ("deployed agents=" + std::to_string(pushed))
                                           : "deploy not wired/failed";
    audit_fn_(req, "guaranteed_state.rule.update", "success", "GuaranteedState", rule_id,
              detail + " (" + deploy + ")");
    res.set_content(render_guards_fragment(""), "text/html; charset=utf-8");
}

void GuardianRoutes::create_guard_from_form(const httplib::Request& req, httplib::Response& res) {
    auto param = [&](const char* k) -> std::string {
        return req.has_param(k) ? req.get_param_value(k) : std::string{};
    };
    // Errors return 200 + an inline banner above a fresh form — htmx's swap:false
    // on 4xx/5xx would otherwise drop the body and the operator would see nothing
    // (same convention as apply_guard_change). Re-entry of values is a known wart
    // (the form re-renders blank); the banner names exactly what to fix.
    auto fail = [this, &res](const std::string& msg) {
        res.status = 200;
        res.set_content("<div class=\"gs-error-banner\" style=\"background:#3a1a1a;"
                        "color:var(--red);padding:0.5rem 0.75rem;border-radius:0.4rem;"
                        "margin-bottom:0.5rem;font-size:0.78rem\">&#9888; " +
                            html_escape(msg) + "</div>" + render_guard_form_fragment(),
                        "text/html; charset=utf-8");
    };

    if (!store_ || !store_->is_open())
        return fail("Guardian store unavailable.");

    const std::string name = param("name");
    const std::string key = param("key");
    const std::string value_type = param("value_type");
    const std::string expected = param("expected");
    const std::string enforcement_mode =
        param("enforcement_mode").empty() ? "enforce" : param("enforcement_mode");
    // Form-level required checks — clearer than a downstream empty-assertion guard.
    if (name.empty() || key.empty() || value_type.empty() || expected.empty())
        return fail("Name, key, value type and expected value are required.");

    nlohmann::json assertion_params;
    assertion_params["hive"] = param("hive").empty() ? "HKLM" : param("hive");
    assertion_params["key"] = key;
    assertion_params["value_name"] = param("value_name"); // "" = key default value
    assertion_params["value_type"] = value_type;
    assertion_params["expected"] = expected;

    // Remediation params = the resilience policy. Only include fields the operator
    // actually set so blanks fall through to defaults rather than being rejected as
    // a non-numeric "" (lenient-in).
    nlohmann::json rem_params;
    rem_params["mode"] = param("resilience_mode").empty() ? "persist" : param("resilience_mode");
    auto add_num = [&](const char* k) {
        const std::string v = param(k);
        if (!v.empty()) rem_params[k] = v;
    };
    add_num("max_attempts");
    add_num("quiet_reset_s");
    add_num("resume_after_s");
    add_num("backoff_initial_ms");
    add_num("backoff_max_ms");
    add_num("event_debounce_ms");

    const std::string action =
        param("remediation_action").empty() ? "alert-only" : param("remediation_action");

    nlohmann::json body;
    body["spark"] = {{"type", "registry-change"}, {"params", nlohmann::json::object()}};
    body["assertion"] = {{"type", "registry-value-equals"}, {"params", std::move(assertion_params)}};
    body["remediation"] = {{"type", action}, {"params", std::move(rem_params)}};

    // Single source: the same derivation + resilience validation the REST create
    // uses, so the dashboard and the API produce identical specs.
    auto spec = guardian::derive_rule_spec(body, name, /*version=*/1, /*enabled=*/true,
                                           enforcement_mode);
    if (spec.error)
        return fail(spec.error->message);

    GuaranteedStateRuleRow row;
    row.rule_id = slugify(name) + "-" + short_id(); // matches [A-Za-z0-9._-]+
    row.name = name;
    row.spec_json = std::move(spec.spec_json);
    row.yaml_source = std::move(spec.yaml_source);
    row.version = 1;
    row.enabled = true;
    row.enforcement_mode = enforcement_mode;
    row.severity = param("severity").empty() ? "medium" : param("severity");
    row.os_target = "windows"; // registry guards are Windows-only today
    row.scope_expr = "";        // unscoped draft — device targeting is set at the Baseline
    const std::string now = format_iso_utc(now_epoch_seconds());
    row.created_at = now;
    row.updated_at = now;
    if (auto session = auth_fn_(req, res)) {
        row.created_by = session->username;
        row.updated_by = session->username;
    }

    if (auto r = store_->create_rule(row); !r)
        return fail("Create failed: " + r.error());

    audit_fn_(req, "guaranteed_state.rule.create", "success", "GuaranteedState", row.rule_id,
              row.name + " (mode=" + row.enforcement_mode + ", action=" + action + ")");

    // Success: a confirmation panel in the detail pane, an out-of-band refresh of
    // the guards list, and a toast (the dashboard's HX-Trigger convention).
    res.set_header("HX-Trigger", R"({"showToast":{"message":"Guard created","level":"success"}})");
    std::string html =
        "<div class=\"detail-panel\"><h3>Guard created</h3>"
        "<div class=\"kv\"><div class=\"k\">Name</div><div>" +
        html_escape(row.name) +
        "</div>"
        "<div class=\"k\">ID</div><div style=\"font-family:var(--mono);font-size:0.75rem\">" +
        html_escape(row.rule_id) +
        "</div>"
        "<div class=\"k\">Mode</div><div>" +
        html_escape(row.enforcement_mode) + " / " + html_escape(action) +
        "</div></div>"
        "<div class=\"mock-note\">Created unscoped (draft). Add it to a Baseline to deploy it to "
        "agents.</div>"
        "<div class=\"form-actions\"><button class=\"btn btn-secondary\" "
        "hx-get=\"/fragments/guardian/guard-form\" hx-target=\"#guardian-detail\" "
        "hx-swap=\"innerHTML\">New Guard</button></div></div>"
        "<div id=\"guardian-guards\" hx-swap-oob=\"innerHTML\">" +
        render_guards_fragment("") + "</div>";
    res.set_content(html, "text/html; charset=utf-8");
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

    const bool live = store_ && store_->is_open();
    if (!used_real && live) {
        // Live store, no drift events recorded yet → honest empty state (M2 / #1209).
        html += empty_state("No drift events yet",
                            "Drift detections and remediations from your guards will appear here.");
    } else if (!used_real) {
        // No Guardian backend present (pure UI development) → example timeline.
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
    if (!used_real && !live)
        html += demo_banner("example drift timeline");
    return html;
}

std::string GuardianRoutes::render_guard_detail_fragment(const std::string& guard_id) const {
    // Header fields prefer a real rule lookup; the rest is mock.
    std::string name = guard_id, severity = "high", mode = "enforce", os = "windows",
                scope = "tag:production-workstations", yaml;
    bool real_rule = false;
    if (store_ && store_->is_open()) {
        if (auto r = store_->get_rule(guard_id)) {
            real_rule = true;
            name = r->name;
            severity = r->severity.empty() ? severity : r->severity;
            mode = (r->enforcement_mode == "enforce") ? "enforce" : "audit"; // empty→audit (C1/B2)
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
    // Header status: for a REAL authored rule the live compliance status is not
    // known here (the agent reports fail-closed and per-agent rollup is unwired),
    // so show an honest "status pending" rather than a fabricated green
    // "compliant" badge (M2 / #1209). Only the no-backend demo path shows the
    // sample badge.
    const std::string header_badge =
        real_rule ? std::string("<span style=\"font-size:0.7rem;color:var(--muted);"
                                "border:1px solid var(--muted);padding:0.1rem 0.4rem;"
                                "border-radius:0.3rem\">status pending</span>")
                  : status_badge("compliant");
    html += "<div class=\"detail-panel\"><h3>" + html_escape(name) + " " + header_badge + "</h3>";
    html += "<div class=\"kv\">"
            "<div class=\"k\">Severity</div><div>" + html_escape(severity) + "</div>"
            "<div class=\"k\">Mode</div><div>" + html_escape(mode) + "</div>"
            "<div class=\"k\">OS target</div><div>" + html_escape(os) + "</div>"
            "<div class=\"k\">Scope</div><div style=\"font-family:var(--mono);font-size:0.75rem\">" +
            html_escape(scope.empty() ? "(set at Baseline level)" : scope) + "</div>"
            "<div class=\"k\">Composition</div><div>Spark (registry-change) &rarr; "
            "Assertion (registry-value-equals) &rarr; alert</div>"
            "</div>";

    html += demo_banner("example per-agent compliance");
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
    html += "</div>";
    return html;
}

std::string GuardianRoutes::render_baselines_fragment() const {
    // TODO(guardian-backend): baselines store + deploy fan-out do not exist yet
    // (contract §6/§7). The entire list is illustrative, so it leads with an
    // unmistakable banner (M2 / #1209) — there is no live data to fall back to.
    std::string html = demo_banner("example baselines — Baseline backend not yet implemented");
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
    html += demo_banner("example baseline — Baseline backend not yet implemented");
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
    html += "</div>";
    return html;
}

std::string GuardianRoutes::render_guard_form_fragment() const {
    // Structured create form for the Slice-A registry types (the only spark /
    // assertion types the agent implements today). Field names map 1:1 to the
    // structured Guard the POST handler builds and feeds to derive_rule_spec, so
    // the dashboard and the REST API produce identical specs + validation. The
    // resilience fieldset emits exactly the keys the agent reads / the /schemas
    // registry publishes. A fuller schema-driven dynamic renderer (one consumer
    // of GET /schemas) is a forward step once more types exist.
    const char* fieldset =
        "border:1px solid var(--border);border-radius:0.4rem;padding:0.6rem 0.75rem;margin:0.5rem 0";
    const char* hint = "color:var(--muted);font-size:0.72rem;margin-bottom:0.4rem";
    std::string html =
        "<div class=\"detail-panel\"><h3>New Guard</h3>"
        "<form class=\"gs-form\" hx-post=\"/fragments/guardian/guards\" "
        "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">"
        "<label>Name</label><input name=\"name\" placeholder=\"block-smb-445\" required>"
        "<div class=\"form-row\">"
        "<div><label>Severity</label><select name=\"severity\">"
        "<option>critical</option><option selected>high</option><option>medium</option><option>low</option>"
        "</select></div>"
        "<div><label>Enforcement mode</label><select name=\"enforcement_mode\">"
        "<option value=\"enforce\" selected>enforce</option><option value=\"audit\">audit</option></select></div>"
        "</div>"
        "<fieldset style=\"";
    html += fieldset;
    html +=
        "\"><legend>Assertion &mdash; registry-value-equals</legend>"
        "<div class=\"form-row\">"
        // Hive / value-type options are exactly the agent-supported set
        // (registry_support::kHives / kValueTypes); a server cross-check test keeps
        // this form, the /schemas enum, and the agent in lock-step (H2). Do not add
        // HKCC / REG_BINARY / REG_MULTI_SZ here — the agent decodes none of them.
        "<div><label>Hive</label><select name=\"hive\">"
        "<option>HKLM</option><option>HKCU</option><option>HKCR</option><option>HKU</option>"
        "</select></div>"
        "<div><label>Value type</label><select name=\"value_type\">"
        "<option>REG_DWORD</option><option>REG_QWORD</option><option>REG_SZ</option>"
        "<option>REG_EXPAND_SZ</option></select></div>"
        "</div>"
        "<label>Key</label><input name=\"key\" placeholder=\"SOFTWARE\\\\YuzuTest\" required>"
        "<div class=\"form-row\">"
        "<div><label>Value name</label><input name=\"value_name\" placeholder=\"Flag (blank = default value)\"></div>"
        "<div><label>Expected</label><input name=\"expected\" placeholder=\"1\" required></div>"
        "</div></fieldset>"
        "<label>Remediation action</label><select name=\"remediation_action\">"
        "<option value=\"alert-only\" selected>alert-only (detect &amp; report)</option>"
        "<option value=\"enforce\">enforce (write the expected value back)</option></select>"
        "<fieldset style=\"";
    html += fieldset;
    html += "\"><legend>Resilience policy</legend><div style=\"";
    html += hint;
    html +=
        "\">Governs re-enforcement when a value keeps drifting (enforce only). Fields not "
        "relevant to the chosen mode are ignored; blanks use the defaults.</div>"
        "<label>Mode</label><select name=\"resilience_mode\">"
        "<option value=\"persist\" selected>persist &mdash; fix on every drift, never give up</option>"
        "<option value=\"backoff\">backoff &mdash; exponential delay, never give up</option>"
        "<option value=\"bounded\">bounded &mdash; give up after N cycles</option></select>"
        "<div class=\"form-row\">"
        "<div><label>Max attempts (bounded)</label>"
        "<input name=\"max_attempts\" type=\"number\" min=\"1\" placeholder=\"5\"></div>"
        "<div><label>Quiet reset (s)</label>"
        "<input name=\"quiet_reset_s\" type=\"number\" min=\"1\" placeholder=\"60\"></div>"
        "</div>"
        "<div class=\"form-row\">"
        "<div><label>Resume after (s, bounded)</label>"
        "<input name=\"resume_after_s\" type=\"number\" min=\"0\" placeholder=\"0 = stay given up\"></div>"
        "<div><label>Event debounce (ms)</label>"
        "<input name=\"event_debounce_ms\" type=\"number\" min=\"0\" placeholder=\"1000\"></div>"
        "</div>"
        "<div class=\"form-row\">"
        "<div><label>Backoff initial (ms)</label>"
        "<input name=\"backoff_initial_ms\" type=\"number\" min=\"1\" placeholder=\"1000\"></div>"
        "<div><label>Backoff max (ms)</label>"
        "<input name=\"backoff_max_ms\" type=\"number\" min=\"1\" placeholder=\"60000\"></div>"
        "</div></fieldset>"
        "<div class=\"form-actions\">"
        "<button type=\"submit\" class=\"btn btn-secondary\">Create Guard</button></div>"
        "</form>"
        "<div class=\"mock-note\">A new Guard is created unscoped (draft); device targeting is set at "
        "the Baseline, not per-Guard. Authoring schemas: "
        "<code>GET /api/v1/guaranteed-state/schemas</code>.</div></div>";
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
                                     AgentsJsonFn agents_json_fn,
                                     PushFn push_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    audit_fn_ = std::move(audit_fn);
    emit_event_fn_ = std::move(emit_event_fn);
    store_ = store;
    agents_json_fn_ = std::move(agents_json_fn);
    push_fn_ = std::move(push_fn);

    // -- Guardian dashboard page ------------------------------------------
    svr.Get("/guardian", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) {
            res.set_redirect("/login");
            return;
        }
        res.set_content(kGuardianHtml, "text/html; charset=utf-8");
    });

    // The data-bearing GET fragments below gate on GuaranteedState:Read (M1 /
    // #1209) — they expose rule names, scope expressions, yaml_source and the
    // drift timeline, which for an enforcement subsystem must require the same
    // securable the REST read API does, not bare authentication. perm_fn_
    // subsumes the auth check (it authenticates, then authorises), matching the
    // Write/Push POST handlers below. The page shell stays auth-only: it is
    // static chrome with no rule data, and a non-Read principal simply sees every
    // fragment return 403.

    // -- Status rollup (view = fleet|guard|agent|mgroup|baseline) ----------
    svr.Get("/fragments/guardian/status",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                const std::string view = req.has_param("view") ? req.get_param_value("view") : "fleet";
                res.set_content(render_status_fragment(view), "text/html; charset=utf-8");
            });

    // -- Guards list (optional ?status= filter) ----------------------------
    svr.Get("/fragments/guardian/guards",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                const std::string sf = req.has_param("status") ? req.get_param_value("status") : "";
                res.set_content(render_guards_fragment(sf), "text/html; charset=utf-8");
            });

    // -- Event timeline (optional ?type= / ?severity= filters) -------------
    svr.Get("/fragments/guardian/events",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                const std::string tf = req.has_param("type") ? req.get_param_value("type") : "";
                const std::string sf = req.has_param("severity") ? req.get_param_value("severity") : "";
                res.set_content(render_events_fragment(tf, sf), "text/html; charset=utf-8");
            });

    // -- Per-guard detail --------------------------------------------------
    svr.Get(R"(/fragments/guardian/guard/([A-Za-z0-9._\-]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                res.set_content(render_guard_detail_fragment(req.matches[1].str()),
                                "text/html; charset=utf-8");
            });

    // -- Baselines list ----------------------------------------------------
    svr.Get("/fragments/guardian/baselines",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                res.set_content(render_baselines_fragment(), "text/html; charset=utf-8");
            });

    // -- Per-baseline detail ----------------------------------------------
    svr.Get(R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                res.set_content(render_baseline_detail_fragment(req.matches[1].str()),
                                "text/html; charset=utf-8");
            });

    // -- Create forms ------------------------------------------------------
    svr.Get("/fragments/guardian/guard-form",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                res.set_content(render_guard_form_fragment(), "text/html; charset=utf-8");
            });
    svr.Get("/fragments/guardian/baseline-form",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                res.set_content(render_baseline_form_fragment(), "text/html; charset=utf-8");
            });

    // -- Structured create (Guard) ----------------------------------------
    // Build a structured Guard from the create-form fields and persist it via
    // the shared derive_rule_spec path (single source with the REST create).
    svr.Post("/fragments/guardian/guards",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Write")) return;
                 create_guard_from_form(req, res);
             });

    // -- Live guard controls: enable/disable + audit↔enforce, auto-deploy --
    // These act on a REAL authored rule and re-push so the change takes effect
    // on the fleet immediately. Both Write (mutates the rule) and Push (deploys
    // to agents) are required — the toggle does both.
    svr.Post(R"(/fragments/guardian/guard/([A-Za-z0-9._\-]+)/enabled)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Write")) return;
                 if (!perm_fn_(req, res, "GuaranteedState", "Push")) return;
                 const std::string id = req.matches[1].str();
                 const bool enable = req.has_param("value") && req.get_param_value("value") == "1";
                 apply_guard_change(req, res, id, /*set_enabled=*/true, enable,
                                    /*set_mode=*/false, "");
             });
    svr.Post(R"(/fragments/guardian/guard/([A-Za-z0-9._\-]+)/mode)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Write")) return;
                 if (!perm_fn_(req, res, "GuaranteedState", "Push")) return;
                 const std::string id = req.matches[1].str();
                 const std::string mode =
                     req.has_param("value") ? req.get_param_value("value") : "audit";
                 apply_guard_change(req, res, id, /*set_enabled=*/false, false,
                                    /*set_mode=*/true, mode);
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
