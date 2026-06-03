/// @file guardian_routes.cpp
/// Guardian dashboard HTMX routes + fragment renderers. See guardian_routes.hpp
/// for the coordination/mock contract.

#include "guardian_routes.hpp"

#include "guaranteed_state_store.hpp"
#include "baseline_store.hpp"
#include "guardian_form_render.hpp"
#include "guardian_rule_spec.hpp"
#include "secure_random.hpp"
#include "store_errors.hpp"
#include "web_utils.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <string>
#include <unordered_map>
#include <utility>
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
            // Precompute, per guard rule_id, the DEPLOYED Baselines that contain it
            // (id + name) — one pass over deployed baselines rather than a query per
            // guard — so each row can render "Deployed: <baseline links>".
            std::unordered_map<std::string, std::vector<std::pair<std::string, std::string>>>
                deployed_by_rule;
            if (baseline_store_ && baseline_store_->is_open())
                for (const auto& b : baseline_store_->list_deployed_baselines())
                    for (const auto& mid : baseline_store_->get_members(b.baseline_id))
                        deployed_by_rule[mid].emplace_back(b.baseline_id, b.name);

            for (const auto& r : rules) {
                const std::string os = r.os_target.empty() ? "ALL"
                                       : (r.os_target == "windows" ? "W"
                                          : r.os_target == "linux"  ? "L"
                                          : r.os_target == "macos"  ? "M" : r.os_target);
                const bool on = r.enabled;
                // Mode is the guard's immutable posture: Observe (watch/audit — empty/
                // unknown renders Observe, never a false-green Enforce; C1/B2) or
                // Enforce. Coloured by posture (CSS .gi-mode.observe/.enforce).
                const bool enforcing = (r.enforcement_mode == "enforce");
                const std::string mode_label = enforcing ? "Enforce" : "Observe";
                const char* mode_cls = enforcing ? "enforce" : "observe";
                const std::string rid = html_escape(r.rule_id);

                // Deployment line: the deployed Baselines that deliver this guard, as
                // links to each baseline's view; otherwise an honest "not deployed".
                std::string deploy_html;
                if (auto dit = deployed_by_rule.find(r.rule_id);
                    dit != deployed_by_rule.end() && !dit->second.empty()) {
                    deploy_html = "<span class=\"gi-dep-on\">&#9679; Deployed:</span> ";
                    bool first = true;
                    for (const auto& [bid, bname] : dit->second) {
                        if (!first) deploy_html += ", ";
                        first = false;
                        deploy_html += "<a class=\"gi-bl\" hx-get=\"/fragments/guardian/baseline/" +
                                       html_escape(bid) +
                                       "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" +
                                       html_escape(bname) + "</a>";
                    }
                } else {
                    deploy_html = "<span class=\"gi-dep-off\">&#9675; not deployed</span>";
                }

                // Left content column carries the detail-nav (clicking it opens the
                // guard); the control button (gi-right) and baseline links (gi-deploy)
                // are outside it, so they keep their own click behaviour.
                html += "<div class=\"guard-item\">"
                        "<div class=\"gi-main\">"
                        "<div class=\"gi-left\" style=\"cursor:pointer\" "
                        "hx-get=\"/fragments/guardian/guard/" + rid +
                        "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">"
                        "<div class=\"gi-row1\">"
                        "<span class=\"guard-name\">" + html_escape(r.name) + "</span>"
                        "<span class=\"gi-mode " + std::string(mode_cls) + "\">" + mode_label +
                        "</span></div>"
                        "<div class=\"gi-meta\">"
                        "<span>" + html_escape(r.severity.empty() ? "medium" : r.severity) + "</span>"
                        "<span class=\"guard-os\">" + html_escape(os) + "</span>"
                        "</div></div>"
                        "<div class=\"gi-right\">"
                        "<span class=\"gi-state " + std::string(on ? "on" : "off") + "\">" +
                        (on ? "ENABLED" : "DISABLED") + "</span>"
                        "<button class=\"btn btn-secondary gi-act\" "
                        "hx-post=\"/fragments/guardian/guard/" + rid + "/enabled?value=" +
                        (on ? "0" : "1") +
                        "\" hx-target=\"#guardian-guards\" hx-swap=\"innerHTML\">" +
                        (on ? "Disable" : "Enable") + "</button>"
                        "</div></div>"
                        "<div class=\"gi-deploy\">" + deploy_html + "</div>"
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
                                        const std::string& rule_id, bool enabled) {
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

    rule->enabled = enabled;
    if (auto r = store_->update_rule(*rule); !r)
        return fail("Update failed: " + r.error());

    // STATE-ONLY (no push). A Guard's enabled flag is global state, not an
    // individual deploy — Guards are not deployable on their own; only Baselines
    // are (docs/guardian-baseline-model.md). The change persists now and takes
    // effect on the next Baseline deploy or heartbeat reconcile, both of which
    // re-push the union of *deployed* Baselines' enabled members. (Mode is set at
    // creation and immutable — a different posture is a different Guard — so there
    // is no mode change here.) Audited under its own rule.update verb so "who
    // enabled / disabled this guard" stays queryable.
    audit_fn_(req, "guaranteed_state.rule.update", "success", "GuaranteedState", rule_id,
              std::string(enabled ? "enabled=true" : "enabled=false") +
                  " (state-only; applies on next deploy/reconcile)");
    res.set_content(render_guards_fragment(""), "text/html; charset=utf-8");
}

void GuardianRoutes::create_guard_from_form(const httplib::Request& req, httplib::Response& res) {
    auto get = [&](const std::string& k) -> std::string {
        return req.has_param(k) ? req.get_param_value(k) : std::string{};
    };
    // Errors return 200 + the form re-rendered with an inline banner at its top —
    // htmx's swap:false on 4xx/5xx would otherwise drop the body and the operator
    // would see nothing (same convention as apply_guard_change). Re-entry of values
    // is a known wart (the form re-renders blank); the banner names what to fix.
    auto fail = [&res](const std::string& msg) {
        res.status = 200;
        const std::string banner = "<div class=\"gs-error-banner\" style=\"background:#3a1a1a;"
                                   "color:var(--red);padding:0.5rem 0.75rem;border-radius:0.4rem;"
                                   "margin-bottom:0.6rem;font-size:0.78rem\">&#9888; " +
                                   html_escape(msg) + "</div>";
        res.set_content(guardian::render_guard_form(banner), "text/html; charset=utf-8");
    };

    if (!store_ || !store_->is_open())
        return fail("Guardian store unavailable.");

    const std::string name = get("name");
    if (name.empty())
        return fail("Name is required.");
    // One "Mode" control (Watch | Enforce) replaces the old enforcement-mode +
    // remediation-action pair. Watch = observe & alert (no write-back); Enforce =
    // auto-remediate. The dashboard speaks "Watch"; the stored enforcement_mode
    // value stays "audit" for back-compat (the agent arms enforce only on an exact
    // "enforce" match, so any non-enforce value behaves as observe).
    const bool enforce_mode = get("mode") == "enforce";
    const std::string enforcement_mode = enforce_mode ? "enforce" : "audit";

    // Trigger type IS the assertion type; the schema-driven decoder reads exactly
    // that type's params (namespaced field names), validates required, and derives
    // the paired spark from the assertion family. Single source with render_guard_form.
    const std::string trigger = get("trigger_type").empty() ? "registry-value-equals" : get("trigger_type");
    auto sa = guardian::assemble_spark_assertion(trigger, get);
    if (sa.error)
        return fail(*sa.error);

    // Remediation params = the resilience policy. Only include fields the operator
    // actually set so blanks fall through to defaults rather than being rejected as
    // a non-numeric "" (lenient-in).
    nlohmann::json rem_params;
    rem_params["mode"] = get("resilience_mode").empty() ? "persist" : get("resilience_mode");
    auto add_num = [&](const char* k) {
        const std::string v = get(k);
        if (!v.empty()) rem_params[k] = v;
    };
    add_num("max_attempts");
    add_num("quiet_reset_s");
    add_num("resume_after_s");
    add_num("backoff_initial_ms");
    add_num("backoff_max_ms");
    add_num("event_debounce_ms");

    const std::string action = enforce_mode ? "enforce" : "alert-only";

    nlohmann::json body;
    body["spark"] = std::move(sa.spark);
    body["assertion"] = std::move(sa.assertion);
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
    row.severity = get("severity").empty() ? "medium" : get("severity");
    // Every realtime spark today (registry-change RegNotifyChangeKeyValue,
    // file-change ReadDirectoryChangesW) is Windows-only; os_target stamps that.
    // Device targeting proper is set at the Baseline, not per-Guard.
    row.os_target = "windows";
    row.scope_expr = ""; // unscoped draft — device targeting is set at the Baseline
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
              row.name + " (trigger=" + trigger + ", mode=" + row.enforcement_mode + ", action=" +
                  action + ")");

    // Success: a confirmation card in the modal, an out-of-band refresh of the
    // guards list, and a toast (the dashboard's HX-Trigger convention).
    res.set_header("HX-Trigger", R"({"showToast":{"message":"Guard created","level":"success"}})");
    std::string html =
        "<div class=\"gs-modal-card\">"
        "<div class=\"gs-modal-header\"><h3>Guard created</h3>"
        "<button type=\"button\" class=\"gs-modal-close\" onclick=\"guardianCloseModal()\" "
        "aria-label=\"Close\">&times;</button></div>"
        "<div class=\"gs-modal-body\"><div class=\"kv\">"
        "<div class=\"k\">Name</div><div>" +
        html_escape(row.name) +
        "</div>"
        "<div class=\"k\">ID</div><div style=\"font-family:var(--mono);font-size:0.75rem\">" +
        html_escape(row.rule_id) +
        "</div>"
        "<div class=\"k\">Trigger</div><div>" +
        html_escape(trigger) +
        "</div>"
        "<div class=\"k\">Mode</div><div>" +
        std::string(enforce_mode ? "Enforce" : "Observe") + "</div></div>"
        "<div class=\"mock-note\">Created unscoped (draft). Add it to a Baseline to deploy it to "
        "agents.</div></div>"
        "<div class=\"gs-modal-footer\">"
        "<button type=\"button\" class=\"btn btn-secondary\" "
        "hx-get=\"/fragments/guardian/guard-form\" hx-target=\"#guardian-modal-content\" "
        "hx-swap=\"innerHTML\">Create another</button>"
        "<button type=\"button\" class=\"btn btn-secondary\" onclick=\"guardianCloseModal()\">"
        "Close</button></div></div>"
        "<div id=\"guardian-guards\" hx-swap-oob=\"innerHTML\">" +
        render_guards_fragment("") + "</div>";
    res.set_content(html, "text/html; charset=utf-8");
}

void GuardianRoutes::create_baseline_from_form(const httplib::Request& req,
                                               httplib::Response& res) {
    // Errors return 200 + the form re-rendered with an inline banner (htmx's
    // swap:false on 4xx would drop the body) — same convention as the guard form.
    auto fail = [this, &res](const std::string& msg) {
        std::vector<std::string> names;
        if (store_ && store_->is_open())
            for (const auto& r : store_->list_rules())
                names.push_back(r.name);
        const std::string banner = "<div class=\"gs-error-banner\" style=\"background:#3a1a1a;"
                                   "color:var(--red);padding:0.5rem 0.75rem;border-radius:0.4rem;"
                                   "margin-bottom:0.6rem;font-size:0.78rem\">&#9888; " +
                                   html_escape(msg) + "</div>";
        res.status = 200;
        // render_baseline_form has no error slot; prepend the banner to its body.
        res.set_content(banner + guardian::render_baseline_form(names),
                        "text/html; charset=utf-8");
    };

    if (!baseline_store_ || !baseline_store_->is_open())
        return fail("Baseline store unavailable.");

    auto get = [&](const std::string& k) -> std::string {
        return req.has_param(k) ? req.get_param_value(k) : std::string{};
    };
    const std::string name = get("name");
    if (name.empty())
        return fail("Name is required.");

    // The create form's member chips carry friendly guard NAMES; the store keys
    // membership on rule_id, so resolve name → rule_id via the Guard store. An
    // unknown name (free-typed, not from the datalist) is reported rather than
    // silently dropped.
    std::vector<std::string> member_ids;
    if (store_ && store_->is_open()) {
        std::unordered_map<std::string, std::string> name_to_id;
        for (const auto& r : store_->list_rules())
            name_to_id.emplace(r.name, r.rule_id);
        std::string unknown;
        const size_t n = req.get_param_value_count("guards");
        for (size_t i = 0; i < n; ++i) {
            const std::string gname = req.get_param_value("guards", i);
            if (gname.empty())
                continue;
            if (auto it = name_to_id.find(gname); it != name_to_id.end())
                member_ids.push_back(it->second);
            else
                unknown += (unknown.empty() ? "" : ", ") + gname;
        }
        if (!unknown.empty())
            return fail("Unknown guard(s): " + unknown + ". Pick from the dropdown.");
    }

    Baseline b;
    b.name = name;
    b.description = get("description");
    if (auto session = auth_fn_(req, res)) {
        b.created_by = session->username;
        b.updated_by = session->username;
    }
    auto created = baseline_store_->create_baseline(b);
    if (!created)
        return fail("Create failed: " + std::string(strip_conflict_prefix(created.error())));
    const std::string id = *created;

    if (!member_ids.empty())
        if (auto r = baseline_store_->set_members(id, member_ids); !r)
            return fail("Baseline created, but adding guards failed: " + r.error());

    audit_fn_(req, "guaranteed_state.baseline.create", "success", "GuaranteedState", id,
              name + " (members=" + std::to_string(member_ids.size()) + ", draft)");

    // Success: confirmation card in the modal + out-of-band refresh of the
    // baselines list + a toast (the dashboard's HX-Trigger convention).
    res.set_header("HX-Trigger", R"({"showToast":{"message":"Baseline created","level":"success"}})");
    std::string html =
        "<div class=\"gs-modal-card\">"
        "<div class=\"gs-modal-header\"><h3>Baseline created</h3>"
        "<button type=\"button\" class=\"gs-modal-close\" onclick=\"guardianCloseModal()\" "
        "aria-label=\"Close\">&times;</button></div>"
        "<div class=\"gs-modal-body\"><div class=\"kv\">"
        "<div class=\"k\">Name</div><div>" + html_escape(name) + "</div>"
        "<div class=\"k\">Member guards</div><div>" + std::to_string(member_ids.size()) + "</div>"
        "<div class=\"k\">Lifecycle</div><div>draft</div></div>"
        "<div class=\"mock-note\">Created as a draft. Assign it to management groups and deploy it "
        "from the baseline's detail panel.</div></div>"
        "<div class=\"gs-modal-footer\">"
        "<button type=\"button\" class=\"btn btn-secondary\" "
        "hx-get=\"/fragments/guardian/baseline-form\" hx-target=\"#guardian-modal-content\" "
        "hx-swap=\"innerHTML\">Create another</button>"
        "<button type=\"button\" class=\"btn btn-secondary\" onclick=\"guardianCloseModal()\">"
        "Close</button></div></div>"
        "<div id=\"guardian-baselines\" hx-swap-oob=\"innerHTML\">" +
        render_baselines_fragment() + "</div>";
    res.set_content(html, "text/html; charset=utf-8");
}

void GuardianRoutes::deploy_baseline(const httplib::Request& req, httplib::Response& res,
                                     const std::string& baseline_id) {
    auto panel = [](const std::string& msg) {
        return "<div class=\"detail-panel\"><div class=\"empty-state\">" + msg + "</div></div>";
    };
    if (!baseline_store_ || !baseline_store_->is_open()) {
        audit_fn_(req, "guaranteed_state.baseline.deploy", "denied", "GuaranteedState", baseline_id,
                  "baseline store unavailable");
        res.set_content(panel("Baseline store unavailable."), "text/html; charset=utf-8");
        return;
    }
    auto b = baseline_store_->get_baseline(baseline_id);
    if (!b) {
        audit_fn_(req, "guaranteed_state.baseline.deploy", "denied", "GuaranteedState", baseline_id,
                  "no such baseline");
        res.set_content(panel("Baseline not found."), "text/html; charset=utf-8");
        return;
    }

    // Mark deployed (lifecycle + deploy stamps). Re-deploy just refreshes them.
    b->lifecycle = kBaselineDeployed;
    b->deployed_at = now_epoch_seconds();
    // Snapshot exactly the member set being deployed (sorted). The detail/list
    // renderers compare live members against this to flag "members changed since
    // last deploy — Re-deploy to apply" (baseline_members_drifted). Re-deploy
    // refreshes it, clearing the flag.
    b->deployed_snapshot = nlohmann::json(baseline_store_->get_members(baseline_id)).dump();
    if (auto session = auth_fn_(req, res)) {
        b->deployed_by = session->username;
        b->updated_by = session->username;
    }
    if (auto r = baseline_store_->update_baseline(*b); !r) {
        audit_fn_(req, "guaranteed_state.baseline.deploy", "failure", "GuaranteedState", baseline_id,
                  "update failed: " + r.error());
        res.set_content(panel("Deploy failed: " + html_escape(r.error())),
                        "text/html; charset=utf-8");
        return;
    }

    // Deploy changes the desired guard set WITHOUT mutating any rule, so bump the
    // policy generation explicitly — otherwise the heartbeat reconcile (which keys
    // off the generation to detect a stale agent) would never fire for a deploy.
    if (store_)
        store_->bump_policy_generation();

    // Converge the fleet to the new deployed-Baseline union. Empty scope = all
    // agents (management-group targeting deferred); full_sync so agents rebuild to
    // exactly the deployed set — a Guard dropped from every deployed Baseline is
    // thereby removed. The push reads the freshly-bumped generation.
    int pushed = -2;
    if (push_fn_)
        pushed = push_fn_(/*scope=*/"", /*full_sync=*/true);

    const std::string deploy = pushed >= 0 ? ("agents=" + std::to_string(pushed))
                                           : "push not wired/failed";
    audit_fn_(req, "guaranteed_state.baseline.deploy", "success", "GuaranteedState", baseline_id,
              b->name + " deployed fleet-wide (" + deploy +
                  ", members=" + std::to_string(baseline_store_->member_count(baseline_id)) + ")");

    res.set_header("HX-Trigger",
                   R"({"showToast":{"message":"Baseline deployed","level":"success"}})");
    // Re-render the detail panel (Deploy → Re-deploy, shows last-deployed) plus an
    // out-of-band refresh of the baselines list so its lifecycle badge updates too.
    std::string html = render_baseline_detail_fragment(baseline_id) +
                       "<div id=\"guardian-baselines\" hx-swap-oob=\"innerHTML\">" +
                       render_baselines_fragment() + "</div>";
    res.set_content(html, "text/html; charset=utf-8");
}

void GuardianRoutes::update_baseline_from_form(const httplib::Request& req, httplib::Response& res,
                                               const std::string& baseline_id) {
    // Re-render the edit form (pre-filled from the store's current state) with an
    // inline banner on error — htmx won't swap a 4xx body.
    auto fail = [this, &res, &baseline_id](const std::string& msg) {
        const std::string banner = "<div class=\"gs-error-banner\" style=\"background:#3a1a1a;"
                                   "color:var(--red);padding:0.5rem 0.75rem;border-radius:0.4rem;"
                                   "margin-bottom:0.6rem;font-size:0.78rem\">&#9888; " +
                                   html_escape(msg) + "</div>";
        res.status = 200;
        res.set_content(banner + render_baseline_edit_form_fragment(baseline_id),
                        "text/html; charset=utf-8");
    };

    if (!baseline_store_ || !baseline_store_->is_open())
        return fail("Baseline store unavailable.");
    auto b = baseline_store_->get_baseline(baseline_id);
    if (!b)
        return fail("Baseline not found.");

    auto get = [&](const std::string& k) -> std::string {
        return req.has_param(k) ? req.get_param_value(k) : std::string{};
    };
    const std::string name = get("name");
    if (name.empty())
        return fail("Name is required.");

    // Resolve posted member-guard NAMES → rule_ids (same as create).
    std::vector<std::string> member_ids;
    if (store_ && store_->is_open()) {
        std::unordered_map<std::string, std::string> name_to_id;
        for (const auto& r : store_->list_rules())
            name_to_id.emplace(r.name, r.rule_id);
        std::string unknown;
        const size_t n = req.get_param_value_count("guards");
        for (size_t i = 0; i < n; ++i) {
            const std::string gname = req.get_param_value("guards", i);
            if (gname.empty())
                continue;
            if (auto it = name_to_id.find(gname); it != name_to_id.end())
                member_ids.push_back(it->second);
            else
                unknown += (unknown.empty() ? "" : ", ") + gname;
        }
        if (!unknown.empty())
            return fail("Unknown guard(s): " + unknown + ". Pick from the dropdown.");
    }

    // Rename only — preserve lifecycle + deploy stamps + description (the form has
    // no description field, so don't let an absent value wipe it).
    b->name = name;
    if (auto session = auth_fn_(req, res))
        b->updated_by = session->username;
    if (auto r = baseline_store_->update_baseline(*b); !r)
        return fail("Save failed: " + std::string(strip_conflict_prefix(r.error())));
    if (auto r = baseline_store_->set_members(baseline_id, member_ids); !r)
        return fail("Saved name, but updating guards failed: " + r.error());

    const bool deployed = b->lifecycle == kBaselineDeployed;
    audit_fn_(req, "guaranteed_state.baseline.update", "success", "GuaranteedState", baseline_id,
              name + " (members=" + std::to_string(member_ids.size()) + ")");

    // Member edits to a DEPLOYED baseline only reach agents on the next Re-deploy
    // (no generation bump here — the deferred Q-A behaviour). Nudge the operator.
    const std::string toast = deployed
                                  ? R"({"showToast":{"message":"Saved — Re-deploy to apply to agents","level":"warning"}})"
                                  : R"({"showToast":{"message":"Baseline saved","level":"success"}})";
    res.set_header("HX-Trigger", toast);
    std::string html = render_baseline_detail_fragment(baseline_id) +
                       "<div id=\"guardian-baselines\" hx-swap-oob=\"innerHTML\">" +
                       render_baselines_fragment() + "</div>";
    res.set_content(html, "text/html; charset=utf-8");
}

void GuardianRoutes::delete_baseline_action(const httplib::Request& req, httplib::Response& res,
                                            const std::string& baseline_id) {
    auto panel = [](const std::string& msg) {
        return "<div class=\"detail-panel\"><div class=\"empty-state\">" + msg + "</div></div>";
    };
    if (!baseline_store_ || !baseline_store_->is_open()) {
        audit_fn_(req, "guaranteed_state.baseline.delete", "denied", "GuaranteedState", baseline_id,
                  "baseline store unavailable");
        res.set_content(panel("Baseline store unavailable."), "text/html; charset=utf-8");
        return;
    }
    auto b = baseline_store_->get_baseline(baseline_id);
    if (!b) {
        audit_fn_(req, "guaranteed_state.baseline.delete", "denied", "GuaranteedState", baseline_id,
                  "no such baseline");
        res.set_content(panel("Baseline not found."), "text/html; charset=utf-8");
        return;
    }
    const bool was_deployed = b->lifecycle == kBaselineDeployed;
    const std::string nm = b->name;
    if (auto r = baseline_store_->delete_baseline(baseline_id); !r) {
        audit_fn_(req, "guaranteed_state.baseline.delete", "failure", "GuaranteedState", baseline_id,
                  "delete failed: " + r.error());
        res.set_content(panel("Delete failed: " + html_escape(r.error())), "text/html; charset=utf-8");
        return;
    }

    // If it was deployed, converge the fleet: bump generation + fleet-wide full_sync
    // so its Guards are torn down where no other deployed Baseline still delivers
    // them (the union recomputes without this Baseline's members).
    int pushed = -2;
    if (was_deployed) {
        if (store_)
            store_->bump_policy_generation();
        if (push_fn_)
            pushed = push_fn_(/*scope=*/"", /*full_sync=*/true);
    }
    const std::string detail =
        nm + (was_deployed ? (" (was deployed; reconciled agents=" + std::to_string(pushed) + ")")
                           : " (draft)");
    audit_fn_(req, "guaranteed_state.baseline.delete", "success", "GuaranteedState", baseline_id,
              detail);

    res.set_header("HX-Trigger",
                   R"({"showToast":{"message":"Baseline deleted","level":"success"}})");
    std::string html = panel("Baseline deleted.") +
                       "<div id=\"guardian-baselines\" hx-swap-oob=\"innerHTML\">" +
                       render_baselines_fragment() + "</div>";
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
    std::string name = guard_id, severity = "high", mode = "Enforce", os = "windows",
                scope = "tag:production-workstations", yaml, spec_json;
    bool real_rule = false;
    bool enabled = true;
    if (store_ && store_->is_open()) {
        if (auto r = store_->get_rule(guard_id)) {
            real_rule = true;
            name = r->name;
            severity = r->severity.empty() ? severity : r->severity;
            // Observe (watch/audit — empty→Observe per C1/B2) or Enforce. Display word
            // only; stored value unchanged.
            mode = (r->enforcement_mode == "enforce") ? "Enforce" : "Observe";
            enabled = r->enabled;
            os = r->os_target.empty() ? "all" : r->os_target;
            scope = r->scope_expr;
            yaml = r->yaml_source;
            spec_json = r->spec_json;
        }
    }

    // Composition line: read the real spark/assertion/remediation from spec_json so
    // a file guard does not render as "registry-change". Falls back to the registry
    // example only on the no-backend demo path (empty/unparseable spec).
    std::string composition = "Spark (registry-change) &rarr; Assertion (registry-value-equals) "
                              "&rarr; alert";
    if (real_rule && !spec_json.empty()) {
        if (auto j = nlohmann::json::parse(spec_json, nullptr, false); !j.is_discarded()) {
            const std::string sp = j.value("spark", nlohmann::json::object()).value("type", "");
            const std::string as = j.value("assertion", nlohmann::json::object()).value("type", "");
            const std::string rem = j.value("remediation", nlohmann::json::object()).value("type", "");
            if (!sp.empty() && !as.empty())
                composition = "Spark (" + html_escape(sp) + ") &rarr; Assertion (" +
                              html_escape(as) + ") &rarr; " + html_escape(rem.empty() ? "alert" : rem);
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
            "<div class=\"k\">Status</div><div style=\"color:" +
            std::string(enabled ? "var(--green)" : "var(--muted)") + ";font-weight:600\">" +
            (enabled ? "enabled" : "disabled") + "</div>"
            "<div class=\"k\">OS target</div><div>" + html_escape(os) + "</div>"
            "<div class=\"k\">Scope</div><div style=\"font-family:var(--mono);font-size:0.75rem\">" +
            html_escape(scope.empty() ? "(set at Baseline level)" : scope) + "</div>"
            "<div class=\"k\">Composition</div><div>" + composition + "</div>"
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

bool GuardianRoutes::baseline_members_drifted(const Baseline& b) const {
    if (b.lifecycle != kBaselineDeployed || b.deployed_snapshot.empty() || !baseline_store_)
        return false;
    auto snap = nlohmann::json::parse(b.deployed_snapshot, nullptr, /*allow_exceptions=*/false);
    if (!snap.is_array())
        return false;
    std::vector<std::string> deployed;
    for (const auto& e : snap)
        if (e.is_string())
            deployed.push_back(e.get<std::string>());
    std::sort(deployed.begin(), deployed.end());
    auto current = baseline_store_->get_members(b.baseline_id);  // ORDER BY rule_id
    std::sort(current.begin(), current.end());                   // defensive
    return current != deployed;
}

std::string GuardianRoutes::render_baselines_fragment() const {
    if (!baseline_store_ || !baseline_store_->is_open())
        return empty_state("Baseline store unavailable",
                           "The Baseline backend is not initialised. Check server /healthz.");

    auto baselines = baseline_store_->list_baselines();
    if (baselines.empty())
        return empty_state("No baselines yet",
                           "A Baseline is a deployable collection of Guards, targeted at "
                           "management groups. Create one to start deploying Guards to your fleet.");

    std::string html;
    for (const auto& b : baselines) {
        const bool deployed = b.lifecycle == kBaselineDeployed;
        const bool drifted = baseline_members_drifted(b);
        const std::size_t members = baseline_store_->member_count(b.baseline_id);
        const auto assign = baseline_store_->get_assignment(b.baseline_id);
        int inc = 0, exc = 0;
        for (const auto& a : assign)
            (a.disposition == kAssignInclude ? inc : exc)++;
        const std::string rid = html_escape(b.baseline_id);
        const std::string target =
            assign.empty() ? std::string("No management groups assigned")
                           : (std::to_string(inc) + " included &middot; " + std::to_string(exc) +
                              " excluded group(s)");
        // A deployed Baseline whose members changed since last deploy gets an amber
        // "changes pending" marker beside the lifecycle badge.
        const std::string pending =
            drifted ? "<span title=\"Member guards changed since last deploy — Re-deploy to apply\" "
                      "style=\"font-size:0.66rem;font-weight:600;color:var(--yellow);"
                      "margin-left:0.4rem\">&#9888; changes pending</span>"
                    : "";
        html += "<div class=\"baseline-card\">"
                "<div class=\"baseline-top\">"
                "<span class=\"baseline-name\" style=\"cursor:pointer\" "
                "hx-get=\"/fragments/guardian/baseline/" + rid +
                "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" + html_escape(b.name) +
                "</span>"
                "<span class=\"lifecycle-" + std::string(deployed ? "deployed" : "draft") +
                "\" style=\"font-size:0.72rem;font-weight:600\">" +
                (deployed ? "&#9679; deployed" : "&#9675; draft") + "</span>" + pending +
                "</div>"
                "<div class=\"baseline-scope\">" + target + "</div>"
                "<div class=\"guard-meta\">"
                "<span>" + std::to_string(members) + " guards</span>"
                "<span style=\"margin-left:auto\">"
                "<button class=\"btn btn-secondary btn-sm\" "
                "hx-post=\"/fragments/guardian/baseline/" + rid + "/deploy\" "
                "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" +
                (deployed ? "Re-deploy" : "Deploy") + "</button></span>"
                "</div></div>";
    }
    return html;
}

std::string GuardianRoutes::render_baseline_detail_fragment(const std::string& baseline_id) const {
    std::string html = "<div class=\"detail-panel\">";
    if (!baseline_store_ || !baseline_store_->is_open()) {
        html += "<div class=\"empty-state\">Baseline store unavailable.</div></div>";
        return html;
    }
    auto b = baseline_store_->get_baseline(baseline_id);
    if (!b) {
        html += "<div class=\"empty-state\">Baseline not found.</div></div>";
        return html;
    }
    const bool deployed = b->lifecycle == kBaselineDeployed;
    const auto members = baseline_store_->get_members(baseline_id);
    const auto assign = baseline_store_->get_assignment(baseline_id);

    html += "<h3>" + html_escape(b->name) + " <span class=\"lifecycle-" +
            std::string(deployed ? "deployed" : "draft") + "\" style=\"font-size:0.72rem\">" +
            (deployed ? "deployed" : "draft") + "</span></h3>";
    if (!b->description.empty())
        html += "<div style=\"color:var(--muted);font-size:0.8rem;margin-bottom:0.5rem\">" +
                html_escape(b->description) + "</div>";

    // Persistent "needs re-deploy" warning: member edits to a deployed Baseline
    // do not reach agents until Re-deploy. Shown until the live member set matches
    // the deployed snapshot again.
    if (baseline_members_drifted(*b))
        html += "<div style=\"background:rgba(255,176,32,0.12);border:1px solid var(--yellow);"
                "color:var(--yellow);padding:0.45rem 0.7rem;border-radius:0.4rem;"
                "margin-bottom:0.6rem;font-size:0.74rem;font-weight:600\">&#9888; Member guards "
                "changed since last deploy &mdash; <strong>Re-deploy</strong> to apply the change "
                "to agents.</div>";

    html += "<div class=\"kv\">"
            "<div class=\"k\">Member guards</div><div>" + std::to_string(members.size()) + "</div>"
            "<div class=\"k\">Assignment</div><div>" +
            (assign.empty() ? std::string("(no management groups yet)")
                            : std::to_string(assign.size()) + " group(s)") +
            "</div>";
    if (deployed && b->deployed_at > 0)
        html += "<div class=\"k\">Last deployed</div><div>" + html_escape(format_iso_utc(b->deployed_at)) +
                (b->deployed_by.empty() ? "" : " by " + html_escape(b->deployed_by)) + "</div>";
    html += "</div>";

    // Member guards — resolve rule_id → human name via the Guard store (small N).
    html += "<div style=\"font-size:0.75rem;font-weight:600;margin:0.6rem 0 0.3rem\">Member guards</div>";
    if (members.empty()) {
        html += empty_state("No guards in this baseline",
                            "Add guards when creating or editing the baseline.");
    } else {
        html += "<ul class=\"bl-member-list\" style=\"margin:0;padding-left:1.1rem;font-size:0.8rem\">";
        for (const auto& rid : members) {
            std::string label = rid;
            if (store_ && store_->is_open())
                if (auto r = store_->get_rule(rid); r && !r->name.empty())
                    label = r->name;
            html += "<li>" + html_escape(label) + "</li>";
        }
        html += "</ul>";
    }

    // Assignment — included/excluded management groups. The picker is deferred
    // until the global management-group feature lands; until then a Baseline has
    // no device targeting and Deploy applies fleet-wide (see the hint below).
    html += "<div style=\"font-size:0.75rem;font-weight:600;margin:0.6rem 0 0.3rem\">"
            "Assignment <span style=\"font-weight:400;color:var(--muted)\">(management groups)</span></div>";
    if (assign.empty()) {
        html += empty_state("Targeting not available yet",
                            "Management-group targeting (included / excluded groups) lands when the "
                            "global management-group feature is ready.");
    } else {
        html += "<ul style=\"margin:0;padding-left:1.1rem;font-size:0.8rem\">";
        for (const auto& a : assign)
            html += "<li>" + html_escape(a.disposition) + ": <code>" + html_escape(a.group_id) +
                    "</code></li>";
        html += "</ul>";
    }

    html += "<div class=\"mock-note\" style=\"margin-top:0.5rem\">Deploy currently applies this "
            "baseline's enabled guards <strong>fleet-wide</strong> (all agents, OS-filtered per "
            "guard). Per-group targeting arrives with management groups.</div>";
    const std::string bid = html_escape(b->baseline_id);
    html += "<div class=\"form-actions\" style=\"margin-top:0.6rem;gap:0.4rem\">"
            // Edit opens the modal with the pre-filled form (rename + add/remove guards).
            "<button class=\"btn btn-secondary\" onclick=\"guardianOpenModal()\" "
            "hx-get=\"/fragments/guardian/baseline/" + bid + "/edit\" "
            "hx-target=\"#guardian-modal-content\" hx-swap=\"innerHTML\">Edit</button>"
            "<button class=\"btn btn-secondary\" hx-post=\"/fragments/guardian/baseline/" + bid +
            "/deploy\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" +
            (deployed ? "Re-deploy" : "Deploy") + "</button>"
            "<button class=\"btn btn-secondary\" style=\"color:var(--red)\" "
            "hx-post=\"/fragments/guardian/baseline/" + bid + "/delete\" "
            "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
            "hx-confirm=\"Delete this baseline? Guards it uniquely delivers will be removed from "
            "agents on the next reconcile.\">Delete</button>"
            "</div>";
    html += "</div>";
    return html;
}

std::string GuardianRoutes::render_guard_form_fragment() const {
    // Schema-driven "New Guard" modal: the operator picks a trigger type and only
    // that trigger's fields are shown, rendered from the compiled-in schema catalog
    // (so a new trigger/assertion type appears here with no UI change). Field names
    // map 1:1 to the structured Guard create_guard_from_form() decodes and feeds to
    // derive_rule_spec — the dashboard and the REST API produce identical specs +
    // validation. See guardian_form_render.{hpp,cpp}.
    return guardian::render_guard_form();
}

std::string GuardianRoutes::render_baseline_form_fragment() const {
    // Seed the Member-guards datalist with existing guard names (live wherever the
    // store has authored rules). The create itself is still a mock — the Baseline
    // backend (store + M:N membership + deploy fan-out) is deferred (contract
    // §6/§7). See guardian_form_render.cpp.
    std::vector<std::string> names;
    if (store_ && store_->is_open())
        for (const auto& r : store_->list_rules())
            names.push_back(r.name);
    return guardian::render_baseline_form(names);
}

std::string GuardianRoutes::render_baseline_edit_form_fragment(const std::string& baseline_id) const {
    std::vector<std::string> names;
    if (store_ && store_->is_open())
        for (const auto& r : store_->list_rules())
            names.push_back(r.name);

    guardian::BaselineFormEdit ec;
    ec.baseline_id = baseline_id;
    if (baseline_store_ && baseline_store_->is_open()) {
        if (auto b = baseline_store_->get_baseline(baseline_id))
            ec.name = b->name;
        // Pre-chip current members by their human name (fall back to rule_id).
        for (const auto& rid : baseline_store_->get_members(baseline_id)) {
            std::string nm = rid;
            if (store_ && store_->is_open())
                if (auto r = store_->get_rule(rid); r && !r->name.empty())
                    nm = r->name;
            ec.selected.push_back(nm);
        }
    }
    return guardian::render_baseline_form(names, ec);
}

// ── Route registration ───────────────────────────────────────────────────────

void GuardianRoutes::register_routes(httplib::Server& svr,
                                     AuthFn auth_fn,
                                     PermFn perm_fn,
                                     AuditFn audit_fn,
                                     EmitEventFn emit_event_fn,
                                     GuaranteedStateStore* store,
                                     BaselineStore* baseline_store,
                                     AgentsJsonFn agents_json_fn,
                                     PushFn push_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    audit_fn_ = std::move(audit_fn);
    emit_event_fn_ = std::move(emit_event_fn);
    store_ = store;
    baseline_store_ = baseline_store;
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
    // Edit-Baseline modal form (pre-filled name + member chips).
    svr.Get(R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+)/edit)",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                res.set_content(render_baseline_edit_form_fragment(req.matches[1].str()),
                                "text/html; charset=utf-8");
            });

    // -- Structured create (Guard) ----------------------------------------
    // Build a structured Guard from the create-form fields and persist it via
    // the shared derive_rule_spec path (single source with the REST create).
    svr.Post("/fragments/guardian/guards",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Write")) return;
                 create_guard_from_form(req, res);
             });

    // -- Live guard control: enable/disable (STATE-ONLY) ------------------
    // Edits a Guard's global enabled flag; does NOT deploy (Guards are not
    // individually deployable — only Baselines are). Write only — no Push — since
    // the change propagates on the next Baseline deploy / heartbeat reconcile
    // (docs/guardian-baseline-model.md). There is deliberately NO mode toggle:
    // Watch/Enforce is fixed at creation (a different posture is a different Guard).
    svr.Post(R"(/fragments/guardian/guard/([A-Za-z0-9._\-]+)/enabled)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Write")) return;
                 const std::string id = req.matches[1].str();
                 const bool enable = req.has_param("value") && req.get_param_value("value") == "1";
                 apply_guard_change(req, res, id, enable);
             });

    // -- Structured create (Baseline) -------------------------------------
    // Persist a draft Baseline (name + member guards) via BaselineStore. Device
    // targeting (management-group assignment) + deploy are set afterwards.
    svr.Post("/fragments/guardian/baselines",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Write")) return;
                 create_baseline_from_form(req, res);
             });

    // -- Deploy / Re-deploy (Baseline-level) ------------------------------
    // Marks the Baseline deployed and converges the fleet to the union of all
    // deployed Baselines' enabled members (fleet-wide for now — management-group
    // targeting is deferred). Requires Push (it changes what agents enforce).
    svr.Post(R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+)/deploy)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Push")) return;
                 deploy_baseline(req, res, req.matches[1].str());
             });

    // -- Edit a Baseline (rename + add/remove member guards) --------------
    // Note: this no-suffix POST is registered AFTER /deploy and /delete; the
    // member regex excludes '/', so it never shadows the suffixed routes.
    svr.Post(R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+)/delete)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Delete")) return;
                 delete_baseline_action(req, res, req.matches[1].str());
             });
    svr.Post(R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+))",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Write")) return;
                 update_baseline_from_form(req, res, req.matches[1].str());
             });
}

} // namespace yuzu::server
