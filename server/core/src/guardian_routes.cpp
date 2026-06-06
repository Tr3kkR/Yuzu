/// @file guardian_routes.cpp
/// Guardian dashboard HTMX routes + fragment renderers. See guardian_routes.hpp
/// for the coordination/mock contract.

#include "guardian_routes.hpp"

#include "guaranteed_state_store.hpp"
#include "baseline_store.hpp"
#include "http_route_sink.hpp"
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
#include <unordered_set>
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

// "value_name" / "expected-hash" → "Value name" / "Expected hash" (generic
// fallback label for an assertion param not given an explicit label below).
std::string humanize_key(const std::string& key) {
    std::string s = key;
    for (auto& c : s)
        if (c == '_' || c == '-') c = ' ';
    if (!s.empty()) s[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(s[0])));
    return s;
}

// Render the assertion's specific values (what the guard checks) as <div class=kv>
// rows: a label + value, with the expected value highlighted in `hi`. Registry +
// file params get friendly labels (Key combines hive\\key, Name = value_name,
// Type = value_type); anything else is humanised. Empty if no params.
std::string render_assertion_values(const nlohmann::json& asrt, const std::string& hi) {
    if (!asrt.is_object())
        return {};
    const auto& p = asrt.value("params", nlohmann::json::object());
    if (!p.is_object() || p.empty())
        return {};
    auto as_str = [](const nlohmann::json& v) {
        return v.is_string() ? v.get<std::string>() : v.dump();
    };
    auto row = [&](const std::string& label, const std::string& val, bool highlight) {
        return "<div class=\"k\">" + html_escape(label) + "</div><div" +
               (highlight ? (" style=\"color:" + hi + ";font-weight:700\"") : std::string{}) + ">" +
               html_escape(val) + "</div>";
    };
    std::string out;
    std::unordered_set<std::string> shown;
    if (p.contains("key")) {  // registry: combine hive\\key into one "Key"
        std::string key = p.contains("hive") ? as_str(p["hive"]) + "\\" : "";
        key += as_str(p["key"]);
        out += row("Key", key, false);
        shown.insert("hive");
        shown.insert("key");
    } else if (p.contains("hive")) {
        out += row("Hive", as_str(p["hive"]), false);
        shown.insert("hive");
    }
    if (p.contains("value_name")) { out += row("Name", as_str(p["value_name"]), false); shown.insert("value_name"); }
    if (p.contains("value_type")) { out += row("Type", as_str(p["value_type"]), false); shown.insert("value_type"); }
    if (p.contains("path")) { out += row("Path", as_str(p["path"]), false); shown.insert("path"); }
    if (p.contains("expected")) { out += row("Expected value", as_str(p["expected"]), true); shown.insert("expected"); }
    if (p.contains("expected_hash")) { out += row("Expected hash", as_str(p["expected_hash"]), true); shown.insert("expected_hash"); }
    for (auto it = p.begin(); it != p.end(); ++it) {
        if (shown.count(it.key())) continue;
        out += row(humanize_key(it.key()), as_str(it.value()), it.key().rfind("expected", 0) == 0);
    }
    return out;
}

// Compliance summary chip for a modal header (Slice C) — colored ●compliant ●drifted
// ●errored ●unknown counts, or "no reports yet" when there is no status data. Shared
// by the Guard and Baseline drill-downs so they read identically.
std::string compliance_chip(int64_t ok, int64_t drift, int64_t err, int64_t unk) {
    std::string c = "<span style=\"font-size:0.66rem;font-weight:600;border:1px solid var(--muted);"
                    "padding:0.12rem 0.45rem;border-radius:0.3rem;display:inline-flex;gap:0.5rem;"
                    "align-items:center\">";
    if (ok + drift + err + unk == 0) {
        c += "<span style=\"color:var(--muted)\">no reports yet</span>";
    } else {
        auto dot = [](const char* col, int64_t n) {
            return "<span style=\"color:" + std::string(col) + "\">&#9679; " + std::to_string(n) +
                   "</span>";
        };
        c += dot("var(--green)", ok) + dot("var(--yellow)", drift) + dot("var(--red)", err) +
             dot("#5b6b80", unk);
    }
    return c + "</span>";
}

// Currently-connected agent_ids, parsed from the registry JSON (registry_.to_json()).
// Used to fold liveness: a status row whose agent is NOT here is "unknown" (offline →
// can't verify). The count of online agents is just the set size.
std::unordered_set<std::string> parse_online_agents(const std::string& agents_json) {
    std::unordered_set<std::string> online;
    auto j = nlohmann::json::parse(agents_json, nullptr, false);
    const nlohmann::json* arr =
        j.is_array() ? &j
        : (j.is_object() && j.contains("agents") && j["agents"].is_array()) ? &j["agents"] : nullptr;
    if (arr)
        for (const auto& a : *arr)
            if (a.contains("agent_id") && a["agent_id"].is_string())
                online.insert(a["agent_id"].get<std::string>());
    return online;
}

// Per-rule current compliance rollup. THE single source for "state now", "needs
// attention", the fleet census, and the drill-downs — all derived from the pruning-
// immune status table (not the prunable event log), with the same liveness fold
// (offline agent → unknown). Keyed by rule_id; absent rule = no device has reported.
struct StateRollup {
    int64_t ok = 0, drift = 0, err = 0, unk = 0;
    int64_t total() const { return ok + drift + err + unk; }
};
std::unordered_map<std::string, StateRollup>
rollup_by_rule(const std::vector<yuzu::server::GuardianAgentRuleStatus>& rows,
               const std::unordered_set<std::string>& online) {
    std::unordered_map<std::string, StateRollup> m;
    for (const auto& s : rows) {
        StateRollup& c = m[s.rule_id];
        const std::string st = online.count(s.agent_id) ? s.state : std::string("unknown");
        if (st == "compliant") ++c.ok;
        else if (st == "drifted") ++c.drift;
        else if (st == "errored") ++c.err;
        else ++c.unk;
    }
    return m;
}

} // namespace

// ── Fragment renderers ───────────────────────────────────────────────────────

std::string GuardianRoutes::render_status_fragment(const std::string& view) const {
    if (!store_ || !store_->is_open())
        return empty_state("Guardian store unavailable", "Check server /healthz.");

    // 7-day window for activity/effectiveness/trend.
    const std::string since = format_iso_utc(now_epoch_seconds() - 7 * 86400);
    const auto activity = store_->rule_activity(since);
    std::unordered_map<std::string, const GuardianRuleActivity*> act;
    for (const auto& a : activity) act[a.rule_id] = &a;

    // Liveness + the SINGLE per-rule compliance rollup, from the pruning-immune status
    // table (offline agent → unknown). Drives "state now", "needs attention", the
    // census, and the drill-downs identically — there is no second, event-log-derived
    // source that could drift out of sync once a quiet guard's events age out.
    const std::unordered_set<std::string> online =
        agents_json_fn_ ? parse_online_agents(agents_json_fn_()) : std::unordered_set<std::string>{};
    const auto by_rule = rollup_by_rule(store_->agent_rule_statuses(), online);

    // Deployed Baselines per rule (coverage + per-Guard "deployed").
    std::unordered_map<std::string, std::vector<std::pair<std::string, std::string>>> deployed_by_rule;
    if (baseline_store_ && baseline_store_->is_open())
        for (const auto& b : baseline_store_->list_deployed_baselines())
            for (const auto& rid : baseline_store_->get_members(b.baseline_id))
                deployed_by_rule[rid].emplace_back(b.baseline_id, b.name);

    auto sech = [](const std::string& t) {
        return "<div style=\"font-size:0.66rem;text-transform:uppercase;letter-spacing:0.06em;"
               "color:var(--muted);font-weight:700;margin:0.9rem 0 0.4rem\">" + t + "</div>";
    };
    auto card = [](const std::string& num, const char* tone, const std::string& label,
                   const std::string& sub) {
        std::string h = "<div class=\"stat-card\"><div class=\"stat-num " + std::string(tone) +
                        "\">" + num + "</div><div class=\"stat-label\">" + label + "</div>";
        if (!sub.empty())
            h += "<div style=\"font-size:0.62rem;color:var(--muted);margin-top:0.15rem\">" + sub + "</div>";
        return h + "</div>";
    };
    // "State now" cell from the rule's current rollup: worst state first, with the
    // count of agents in it; "compliant · N" when some report green; "—" when no
    // device has reported (vs the old event-derived "no drift", which lied once a
    // quiet guard's events were reaped).
    auto state_cell = [](const StateRollup& c) -> std::string {
        if (c.err > 0)
            return "<span style=\"color:var(--red);font-weight:600\">errored &middot; " +
                   std::to_string(c.err) + "</span>";
        if (c.drift > 0)
            return "<span style=\"color:var(--yellow);font-weight:600\">drift on " +
                   std::to_string(c.drift) + "</span>";
        if (c.ok > 0)
            return "<span style=\"color:var(--green)\">compliant &middot; " + std::to_string(c.ok) +
                   "</span>";
        if (c.unk > 0)
            return "<span style=\"color:#5b6b80\">unknown &middot; " + std::to_string(c.unk) + "</span>";
        return std::string("<span style=\"color:var(--muted)\">&mdash;</span>");
    };

    // ── By Guard ──────────────────────────────────────────────────────────
    if (view == "guard") {
        auto rules = store_->list_rules();
        if (rules.empty())
            return empty_state("No Guards yet", "Create a Guard to start enforcing desired state.");
        std::string html =
            "<table class=\"detail-table\"><thead><tr><th>Guard</th><th>Mode</th><th>Deployed</th>"
            "<th>State now</th><th>Detected</th><th>Remediated</th><th>Failed</th><th>Agents</th>"
            "<th>Last activity</th></tr></thead><tbody>";
        for (const auto& r : rules) {
            const bool enforcing = r.enforcement_mode == "enforce";
            const auto* a = act.count(r.rule_id) ? act[r.rule_id] : nullptr;
            const auto sit = by_rule.find(r.rule_id);
            const StateRollup s = sit != by_rule.end() ? sit->second : StateRollup{};
            const bool dep = deployed_by_rule.count(r.rule_id) > 0;
            const std::string rid = html_escape(r.rule_id);
            const std::string na = "<span style=\"color:var(--muted)\">&mdash;</span>";
            html += "<tr style=\"cursor:pointer\" onclick=\"guardianOpenModal()\" "
                    "hx-get=\"/fragments/guardian/guard/" + rid +
                    "\" hx-target=\"#guardian-modal-content\" hx-swap=\"innerHTML\">"
                    "<td style=\"font-weight:600;color:var(--fg)\">" + html_escape(r.name) + "</td>"
                    "<td style=\"color:" + std::string(enforcing ? "var(--yellow)" : "#a5d6ff") +
                    ";font-weight:600\">" + (enforcing ? "Enforce" : "Observe") + "</td>"
                    "<td style=\"color:" + std::string(dep ? "var(--green)" : "var(--muted)") + "\">" +
                    (dep ? std::to_string(deployed_by_rule[r.rule_id].size()) + " Baseline(s)"
                         : "not deployed") + "</td>"
                    "<td>" + state_cell(s) + "</td>"
                    "<td style=\"color:var(--yellow)\">" + std::to_string(a ? a->detected : 0) + "</td>"
                    "<td style=\"color:var(--green)\">" + (enforcing ? std::to_string(a ? a->remediated : 0) : na) + "</td>"
                    "<td style=\"color:var(--red)\">" + (enforcing ? std::to_string(a ? a->failed : 0) : na) + "</td>"
                    "<td>" + std::to_string(a ? a->distinct_agents : 0) + "</td>"
                    "<td style=\"color:var(--muted)\">" +
                    (a && !a->last_activity.empty() ? html_escape(a->last_activity.substr(0, 16)) : "never") +
                    "</td></tr>";
        }
        html += "</tbody></table>";
        return html;
    }

    // ── By Baseline ───────────────────────────────────────────────────────
    if (view == "baseline") {
        if (!baseline_store_ || !baseline_store_->is_open())
            return empty_state("Baseline store unavailable", "Check server /healthz.");
        auto baselines = baseline_store_->list_baselines();
        if (baselines.empty())
            return empty_state("No Baselines yet", "Create a Baseline to deploy Guards.");
        std::string html =
            "<table class=\"detail-table\"><thead><tr><th>Baseline</th><th>Lifecycle</th>"
            "<th>Guards</th><th>State now</th><th>Detected</th><th>Remediated</th><th>Failed</th>"
            "<th>Last deployed</th></tr></thead><tbody>";
        for (const auto& b : baselines) {
            const bool deployed = b.lifecycle == kBaselineDeployed;
            auto members = baseline_store_->get_members(b.baseline_id);
            int64_t det = 0, rem = 0, fail = 0;
            StateRollup bc; // member rollup → baseline "state now"
            for (const auto& rid : members) {
                if (auto it = act.find(rid); it != act.end()) {
                    det += it->second->detected; rem += it->second->remediated; fail += it->second->failed;
                }
                if (auto it = by_rule.find(rid); it != by_rule.end()) {
                    bc.ok += it->second.ok; bc.drift += it->second.drift;
                    bc.err += it->second.err; bc.unk += it->second.unk;
                }
            }
            const std::string state = state_cell(bc);
            const std::string bid = html_escape(b.baseline_id);
            html += "<tr style=\"cursor:pointer\" onclick=\"guardianOpenModal()\" "
                    "hx-get=\"/fragments/guardian/baseline/" + bid +
                    "\" hx-target=\"#guardian-modal-content\" hx-swap=\"innerHTML\">"
                    "<td style=\"font-weight:600;color:var(--fg)\">" + html_escape(b.name) + "</td>"
                    "<td class=\"lifecycle-" + std::string(deployed ? "deployed" : "draft") + "\">" +
                    (deployed ? "&#9679; deployed" : "&#9675; draft") + "</td>"
                    "<td>" + std::to_string(members.size()) + "</td>"
                    "<td>" + state + "</td>"
                    "<td style=\"color:var(--yellow)\">" + std::to_string(det) + "</td>"
                    "<td style=\"color:var(--green)\">" + std::to_string(rem) + "</td>"
                    "<td style=\"color:var(--red)\">" + std::to_string(fail) + "</td>"
                    "<td style=\"color:var(--muted)\">" +
                    (deployed && b.deployed_at > 0 ? html_escape(format_iso_utc(b.deployed_at).substr(0, 16)) : "never") +
                    "</td></tr>";
        }
        html += "</tbody></table>";
        return html;
    }

    // ── Fleet (default) ───────────────────────────────────────────────────
    auto rules = store_->list_rules();
    int deployed_guards = 0;
    for (const auto& r : rules)
        if (deployed_by_rule.count(r.rule_id)) ++deployed_guards;
    const int total_guards = static_cast<int>(rules.size());
    int bl_total = 0, bl_deployed = 0;
    if (baseline_store_ && baseline_store_->is_open())
        for (const auto& b : baseline_store_->list_baselines()) {
            ++bl_total;
            if (b.lifecycle == kBaselineDeployed) ++bl_deployed;
        }
    const int agents = static_cast<int>(online.size()); // connected agents (registry)

    // Census + "needs attention" in ONE pass over the LIVE rules, from the shared
    // by_rule rollup. Orphan status rows for a deleted guard are simply never looked
    // up, so the fleet total stays consistent with the By-Guard table; and because the
    // rollup is the status table (not the prunable event log), a quiet guard does not
    // vanish from "needs attention" once its events age out.
    int64_t cc_ok = 0, cc_drift = 0, cc_err = 0, cc_unk = 0;
    int guards_drifting = 0, drift_instances = 0, guards_errored = 0;
    for (const auto& r : rules) {
        auto it = by_rule.find(r.rule_id);
        if (it == by_rule.end()) continue;
        const StateRollup& c = it->second;
        cc_ok += c.ok; cc_drift += c.drift; cc_err += c.err; cc_unk += c.unk;
        if (c.drift > 0) { ++guards_drifting; drift_instances += static_cast<int>(c.drift); }
        if (c.err > 0) ++guards_errored;
    }
    const int64_t cc_total = cc_ok + cc_drift + cc_err + cc_unk;

    int64_t det = 0, rem = 0, fail = 0;
    for (const auto& a : activity) { det += a.detected; rem += a.remediated; fail += a.failed; }
    const int success_pct = (rem + fail > 0) ? static_cast<int>((rem * 100) / (rem + fail)) : 100;

    std::string html;
    html += "<div style=\"display:flex;align-items:center;gap:1rem;flex-wrap:wrap;margin-bottom:0.5rem\">"
            "<span class=\"worst-badge " +
            std::string(worst_badge_class(guards_drifting, static_cast<int>(fail), guards_errored)) + "\">" +
            worst_badge_label(guards_drifting, static_cast<int>(fail), guards_errored) +
            "</span><span style=\"font-size:0.7rem;color:var(--muted)\">activity window: last 7 days</span></div>";

    html += sech("Coverage");
    html += "<div class=\"stat-cards\">";
    html += card(std::to_string(total_guards), "info", "Guards",
                 std::to_string(deployed_guards) + " deployed &middot; " +
                     std::to_string(total_guards - deployed_guards) + " not");
    html += card(std::to_string(bl_total), "info", "Baselines",
                 std::to_string(bl_deployed) + " deployed &middot; " +
                     std::to_string(bl_total - bl_deployed) + " draft");
    html += card(std::to_string(agents), "mute", "Agents", "known to the server");
    html += "</div>";

    // ── Compliance census ── proportion bar + legend (NOT a donut), from the
    // per-(agent,rule) status feed. "as of last check-in" framing: figures reflect
    // each Guard's last reported state, not a live probe.
    html += sech("Compliance &mdash; as of last check-in");
    if (cc_total == 0) {
        html += "<div style=\"font-size:0.72rem;color:var(--muted);max-width:520px\">No device "
                "check-ins recorded yet &mdash; as deployed agents report each Guard's state (on change, "
                "piggybacked on the heartbeat) the breakdown appears here.</div>";
    } else {
        const int ok_pct = static_cast<int>((cc_ok * 100) / cc_total);
        // flex:N segments fill the bar exactly in proportion — no integer-% rounding gap.
        auto seg = [](int64_t n, const char* col, const std::string& inner) -> std::string {
            if (n <= 0) return std::string{};
            return "<div style=\"flex:" + std::to_string(n) + ";background:" + col +
                   ";display:flex;align-items:center;justify-content:center;overflow:hidden;"
                   "white-space:nowrap;font-size:0.6rem;color:#04101f;font-weight:700\">" + inner +
                   "</div>";
        };
        html += "<div style=\"display:flex;height:20px;border-radius:4px;overflow:hidden;"
                "border:1px solid rgba(255,255,255,0.1);max-width:520px\">";
        html += seg(cc_ok, "var(--green)", std::to_string(ok_pct) + "% compliant");
        html += seg(cc_drift, "var(--yellow)", "");
        html += seg(cc_err, "var(--red)", "");
        html += seg(cc_unk, "#5b6b80", "");
        html += "</div>";
        auto leg = [](const char* col, const char* lbl, int64_t n, const std::string& extra) {
            return "<span><i style=\"display:inline-block;width:.55rem;height:.55rem;border-radius:2px;"
                   "margin-right:.3rem;vertical-align:middle;background:" + std::string(col) + "\"></i>" +
                   lbl + " <b style=\"color:var(--fg)\">" + std::to_string(n) + "</b>" + extra + "</span>";
        };
        html += "<div style=\"display:flex;flex-wrap:wrap;gap:1rem;margin-top:0.45rem;"
                "font-size:0.66rem;color:var(--muted)\">";
        html += leg("var(--green)", "Compliant", cc_ok, "");
        html += leg("var(--yellow)", "Drifted", cc_drift, "");
        html += leg("var(--red)", "Error", cc_err, "");
        html += leg("#5b6b80", "Unknown", cc_unk,
                    " <span style=\"color:var(--muted)\">(agent offline &mdash; last state stale)</span>");
        html += "</div>";
        html += "<div style=\"font-size:0.62rem;color:var(--muted);margin-top:0.3rem\">" +
                std::to_string(cc_total) + " device-guard checks across " + std::to_string(agents) +
                " online agent(s), as of each Guard's last reported change.</div>";
    }

    html += sech("Needs attention");
    html += "<div class=\"stat-cards\">";
    html += card(std::to_string(guards_drifting), guards_drifting ? "warn" : "good", "Guards drifting",
                 "on " + std::to_string(drift_instances) + " agent(s) now");
    html += card(std::to_string(fail), fail ? "bad" : "good", "Enforcement failures", "last 7d");
    html += card(std::to_string(guards_errored), guards_errored ? "bad" : "good", "Unhealthy Guards",
                 "errored / watch-deaf now");
    html += "</div>";

    html += sech("Enforcement effectiveness (7d)");
    html += "<div class=\"stat-cards\">";
    html += card(std::to_string(det), "warn", "Drift detected", "");
    html += card(std::to_string(rem), "good", "Remediated", "");
    html += card(std::to_string(fail), "bad", "Enforcement failed", "");
    html += card(std::to_string(success_pct) + "%", "good", "Enforcement success",
                 std::to_string(rem) + " / " + std::to_string(rem + fail));
    html += "</div>";

    // 7-day remediation trend (bars). Build today-6 .. today buckets.
    std::unordered_map<std::string, GuardianDayCount> dmap;
    for (const auto& d : store_->daily_remediations(since)) dmap[d.day] = d;
    int64_t dmax = 1;
    struct Bucket { std::string label; int64_t rem; int64_t fail; };
    std::vector<Bucket> buckets;
    for (int i = 6; i >= 0; --i) {
        const std::string iso = format_iso_utc(now_epoch_seconds() - i * 86400);
        const std::string day = iso.substr(0, 10);
        const auto it = dmap.find(day);
        const int64_t r = it != dmap.end() ? it->second.remediated : 0;
        const int64_t f = it != dmap.end() ? it->second.failed : 0;
        dmax = std::max<int64_t>(dmax, r + f);
        buckets.push_back({iso.substr(5, 5), r, f});  // MM-DD
    }
    html += sech("Remediations trend (7d)");
    html += "<div style=\"display:flex;align-items:flex-end;gap:0.4rem;height:84px;margin-top:0.3rem\">";
    for (const auto& b : buckets) {
        const int h = static_cast<int>(((b.rem + b.fail) * 72) / dmax);
        const int rh = (b.rem + b.fail) ? static_cast<int>((b.rem * 100) / (b.rem + b.fail)) : 0;
        html += "<div style=\"flex:1;display:flex;flex-direction:column;align-items:center;gap:0.2rem\">"
                "<div style=\"width:60%;height:" + std::to_string(h) + "px;display:flex;"
                "flex-direction:column-reverse;border-radius:2px 2px 0 0;overflow:hidden;min-height:2px\">"
                "<div style=\"height:" + std::to_string(rh) + "%;background:var(--green)\"></div>"
                "<div style=\"height:" + std::to_string(100 - rh) + "%;background:var(--red)\"></div></div>"
                "<small style=\"font-size:0.56rem;color:var(--muted)\">" + b.label + "</small></div>";
    }
    html += "</div>";
    html += "<div style=\"font-size:0.62rem;color:var(--muted);margin-top:0.3rem\">"
            "<span style=\"color:var(--green)\">&#9632;</span> enforced &nbsp; "
            "<span style=\"color:var(--red)\">&#9632;</span> failed</div>";

    // Data-source honesty: compliance is the per-(agent,rule) status feed (agents
    // report a Guard's state only when it CHANGES — nothing in steady state, so it is
    // network-kind); effectiveness + trend are the drift-event log. Offline agents'
    // last-known states count as Unknown until they re-report.
    html += "<div class=\"mock-note\">Compliance reflects each Guard's last reported state (agents send a "
            "state only when it <em>changes</em>, piggybacked on the heartbeat &mdash; no steady-state "
            "chatter). Effectiveness &amp; the 7-day trend come from the drift-event log. Offline agents "
            "show as Unknown until they re-report.</div>";
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
                        deploy_html += "<a class=\"gi-bl\" onclick=\"guardianOpenModal()\" "
                                       "hx-get=\"/fragments/guardian/baseline/" +
                                       html_escape(bid) +
                                       "\" hx-target=\"#guardian-modal-content\" hx-swap=\"innerHTML\">" +
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
                        "onclick=\"guardianOpenModal()\" "
                        "hx-get=\"/fragments/guardian/guard/" + rid +
                        "\" hx-target=\"#guardian-modal-content\" hx-swap=\"innerHTML\">"
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
        html += empty_state("No Guards defined yet",
                            "Create a Guard to start enforcing desired state across the fleet.");
    } else if (!used_real) {
        // No Guardian backend present (pure UI development) → contract-shaped
        // example guards, loudly labelled below so they cannot be read as live.
        for (const auto& g : kMockGuards) {
            if (!status_filter.empty() && status_filter != g.status) continue;
            const char* health_cls = g.healthy ? "health-ok" : "health-bad";
            const char* health_lbl = g.healthy ? "&#9679; healthy" : "&#9679; unhealthy";
            html += "<div class=\"guard-item\" style=\"cursor:pointer\" "
                    "onclick=\"guardianOpenModal()\" hx-get=\"/fragments/guardian/guard/" +
                    std::string(g.id) +
                    "\" hx-target=\"#guardian-modal-content\" hx-swap=\"innerHTML\">"
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
        html += demo_banner("example Guards, not authored rules");
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
        return fail("No such Guard: " + rule_id);

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
            return fail("Unknown Guard(s): " + unknown + ". Pick from the dropdown.");
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
            return fail("Baseline created, but adding Guards failed: " + r.error());

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
        "<div class=\"k\">Member Guards</div><div>" + std::to_string(member_ids.size()) + "</div>"
        "<div class=\"k\">Lifecycle</div><div>draft</div></div>"
        "<div class=\"mock-note\">Created as a draft. Assign it to management groups and deploy it "
        "from the Baseline's detail panel.</div></div>"
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
    // Errors render inside the modal (the action buttons target #guardian-modal-content).
    auto panel = [](const std::string& msg) {
        return "<div class=\"gs-modal-card\"><div class=\"gs-modal-body\"><div class=\"empty-state\">" +
               msg + "</div></div><div class=\"gs-modal-footer\"><button type=\"button\" "
               "class=\"btn btn-secondary\" onclick=\"guardianCloseModal()\">Close</button></div></div>";
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
    // Snapshot exactly the member set being deployed. This is now the AUTHORITATIVE
    // enforced set: BaselineStore::deployed_member_rule_ids() (the push/reconcile
    // gate) reads this snapshot, NOT the live member set — so deploying is the only
    // act (Push-gated) that changes what the fleet enforces. The detail/list
    // renderers diff live members against this to flag "members changed since last
    // deploy — Re-deploy to apply" (baseline_members_drifted); re-deploy refreshes
    // it, clearing the flag and converging the fleet to the new set. Format: a JSON
    // array of rule_id strings (parsed back in baseline_store.cpp).
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
    // Re-render the detail modal (Deploy → Re-deploy, shows last-deployed) in place,
    // plus out-of-band refreshes of both lists (the baseline lifecycle badge and the
    // guards' "Deployed:" links both change on deploy).
    std::string html = render_baseline_detail_fragment(baseline_id) +
                       "<div id=\"guardian-baselines\" hx-swap-oob=\"innerHTML\">" +
                       render_baselines_fragment() + "</div>"
                       "<div id=\"guardian-guards\" hx-swap-oob=\"innerHTML\">" +
                       render_guards_fragment("") + "</div>";
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
            return fail("Unknown Guard(s): " + unknown + ". Pick from the dropdown.");
    }

    // Rename only — preserve lifecycle + deploy stamps + description (the form has
    // no description field, so don't let an absent value wipe it).
    b->name = name;
    if (auto session = auth_fn_(req, res))
        b->updated_by = session->username;
    if (auto r = baseline_store_->update_baseline(*b); !r)
        return fail("Save failed: " + std::string(strip_conflict_prefix(r.error())));
    if (auto r = baseline_store_->set_members(baseline_id, member_ids); !r)
        return fail("Saved name, but updating Guards failed: " + r.error());

    const bool deployed = b->lifecycle == kBaselineDeployed;
    audit_fn_(req, "guaranteed_state.baseline.update", "success", "GuaranteedState", baseline_id,
              name + " (members=" + std::to_string(member_ids.size()) + ")");

    // Member edits to a DEPLOYED baseline only reach agents on the next Re-deploy
    // (no generation bump here — the deferred Q-A behaviour). Nudge the operator.
    const std::string toast = deployed
                                  ? R"({"showToast":{"message":"Saved — Re-deploy to apply to agents","level":"warning"}})"
                                  : R"({"showToast":{"message":"Baseline saved","level":"success"}})";
    res.set_header("HX-Trigger", toast);
    // Re-render the detail modal (replacing the edit form) + refresh both lists OOB
    // (member changes can change which guards show as deployed-under this baseline).
    std::string html = render_baseline_detail_fragment(baseline_id) +
                       "<div id=\"guardian-baselines\" hx-swap-oob=\"innerHTML\">" +
                       render_baselines_fragment() + "</div>"
                       "<div id=\"guardian-guards\" hx-swap-oob=\"innerHTML\">" +
                       render_guards_fragment("") + "</div>";
    res.set_content(html, "text/html; charset=utf-8");
}

void GuardianRoutes::delete_baseline_action(const httplib::Request& req, httplib::Response& res,
                                            const std::string& baseline_id) {
    // Errors render inside the modal (the Delete button targets #guardian-modal-content).
    auto panel = [](const std::string& msg) {
        return "<div class=\"gs-modal-card\"><div class=\"gs-modal-body\"><div class=\"empty-state\">" +
               msg + "</div></div><div class=\"gs-modal-footer\"><button type=\"button\" "
               "class=\"btn btn-secondary\" onclick=\"guardianCloseModal()\">Close</button></div></div>";
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

    // Close the modal (its subject is gone) and refresh both lists out-of-band.
    // No main-target content → htmx clears #guardian-modal-content; guardianModalClose
    // then hides the overlay.
    res.set_header("HX-Trigger",
                   R"({"guardianModalClose":true,"showToast":{"message":"Baseline deleted","level":"success"}})");
    std::string html = "<div id=\"guardian-baselines\" hx-swap-oob=\"innerHTML\">" +
                       render_baselines_fragment() + "</div>"
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
                            "Drift detections and remediations from your Guards will appear here.");
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
    std::string name = guard_id, severity = "high", os = "windows", yaml, spec_json;
    bool real_rule = false, enabled = true, enforcing = false;
    if (store_ && store_->is_open()) {
        if (auto r = store_->get_rule(guard_id)) {
            real_rule = true;
            name = r->name;
            severity = r->severity.empty() ? severity : r->severity;
            // Observe (watch/audit — empty→Observe per C1/B2) or Enforce.
            enforcing = (r->enforcement_mode == "enforce");
            enabled = r->enabled;
            os = r->os_target.empty() ? "all" : r->os_target;
            yaml = r->yaml_source;
            spec_json = r->spec_json;
        }
    }
    const std::string mode = enforcing ? "Enforce" : "Observe";
    const std::string mode_color = enforcing ? "var(--yellow)" : "#a5d6ff";
    const std::string verb = enforcing ? "Enforcing" : "Observing";
    const std::string phrasing =
        enforcing ? "Writes the expected value back on drift, then re-checks (Enforce)."
                  : "Alerts on drift from the expected value &mdash; no write-back (Observe).";

    // Which DEPLOYED Baselines deliver this guard (links into the same modal).
    std::string deployed_html = "<span style=\"color:var(--muted)\">not deployed</span>";
    if (baseline_store_ && baseline_store_->is_open()) {
        std::string links;
        for (const auto& bid : baseline_store_->baselines_containing_rule(guard_id)) {
            auto b = baseline_store_->get_baseline(bid);
            if (!b || b->lifecycle != kBaselineDeployed)
                continue;
            if (!links.empty()) links += ", ";
            links += "<a class=\"gi-bl\" onclick=\"guardianOpenModal()\" "
                     "hx-get=\"/fragments/guardian/baseline/" + html_escape(bid) +
                     "\" hx-target=\"#guardian-modal-content\" hx-swap=\"innerHTML\">" +
                     html_escape(b->name) + "</a>";
        }
        if (!links.empty()) deployed_html = links;
    }

    // Parse spec_json for the composition + the specific values it checks.
    std::string spark_t, assert_t, rem_t, values_html;
    if (!spec_json.empty()) {
        if (auto j = nlohmann::json::parse(spec_json, nullptr, false); j.is_object()) {
            const auto asrt = j.value("assertion", nlohmann::json::object());
            spark_t = j.value("spark", nlohmann::json::object()).value("type", "");
            assert_t = asrt.value("type", "");
            rem_t = j.value("remediation", nlohmann::json::object()).value("type", "");
            values_html = render_assertion_values(asrt, mode_color);
        }
    }

    // ── Per-device status (Slice C drill-down) ── current state per agent for THIS
    // guard, from the Slice B status feed. An offline agent's row shows as "unknown"
    // (we can't verify it now). Hostname + liveness come from the live agent registry;
    // an offline agent has no registry row, so fall back to a short agent_id.
    struct DevRow {
        std::string host;
        std::string state;
        std::string updated;
        bool online{false};
    };
    std::vector<DevRow> devs;
    int64_t d_ok = 0, d_drift = 0, d_err = 0, d_unk = 0;
    {
        std::unordered_map<std::string, std::string> hostname; // connected agents only
        if (agents_json_fn_) {
            auto j = nlohmann::json::parse(agents_json_fn_(), nullptr, false);
            const nlohmann::json* arr =
                j.is_array() ? &j
                : (j.is_object() && j.contains("agents") && j["agents"].is_array()) ? &j["agents"]
                                                                                    : nullptr;
            if (arr)
                for (const auto& a : *arr)
                    if (a.contains("agent_id") && a["agent_id"].is_string())
                        hostname[a["agent_id"].get<std::string>()] = a.value("hostname", std::string{});
        }
        for (const auto& s : store_->agent_rule_statuses(guard_id)) {
            DevRow d;
            d.online = hostname.count(s.agent_id) > 0;
            d.host = (d.online && !hostname[s.agent_id].empty()) ? hostname[s.agent_id]
                                                                 : s.agent_id.substr(0, 12);
            d.updated = s.updated_at;
            d.state = d.online ? s.state : "unknown"; // offline → can't verify
            if (d.state == "compliant") ++d_ok;
            else if (d.state == "drifted") ++d_drift;
            else if (d.state == "errored") ++d_err;
            else ++d_unk;
            devs.push_back(std::move(d));
        }
        auto rank = [](const std::string& st) {
            return st == "compliant" ? 0 : st == "drifted" ? 1 : st == "errored" ? 2 : 3;
        };
        std::sort(devs.begin(), devs.end(), [&](const DevRow& a, const DevRow& b) {
            const int ra = rank(a.state), rb = rank(b.state);
            return ra != rb ? ra < rb : a.host < b.host;
        });
    }
    const int64_t d_total = d_ok + d_drift + d_err + d_unk;

    // Header summary chip — replaces the old static "status pending" badge with the
    // live per-device breakdown (Slice C).
    const std::string sum_chip = compliance_chip(d_ok, d_drift, d_err, d_unk);

    std::string html =
        "<div class=\"gs-modal-card\"><div class=\"gs-modal-header\"><h3>" + html_escape(name) + " " +
        sum_chip + "</h3>"
        "<button type=\"button\" class=\"gs-modal-close\" onclick=\"guardianCloseModal()\" "
        "aria-label=\"Close\">&times;</button></div><div class=\"gs-modal-body\">";

    html += "<div class=\"kv\">"
            "<div class=\"k\">Severity</div><div>" + html_escape(severity) + "</div>"
            "<div class=\"k\">Mode</div><div style=\"color:" + mode_color + ";font-weight:700\">" +
            mode + "</div>"
            "<div class=\"k\">Status</div><div style=\"color:" +
            std::string(enabled ? "var(--green)" : "var(--muted)") + ";font-weight:600\">" +
            (enabled ? "enabled" : "disabled") + "</div>"
            "<div class=\"k\">OS target</div><div>" + html_escape(os) + "</div>"
            "<div class=\"k\">Deployed under</div><div>" + deployed_html + "</div>"
            "</div>";

    if (!values_html.empty()) {
        html += "<div style=\"font-weight:600;font-size:0.8rem;margin:0.5rem 0 0.35rem;color:" +
                mode_color + "\">" + verb + "</div>"
                "<div class=\"kv\">" + values_html + "</div>"
                "<div style=\"font-size:0.7rem;color:var(--muted);margin-bottom:0.4rem\">" +
                phrasing + "</div>";
    }

    // ── Per-device status section + Refresh (Slice C). Refresh re-pulls the latest
    // server-side state into the open modal (hx-get re-render) — no fleet poll, the
    // status table is kept current by the agents' on-change feed.
    html += "<div style=\"display:flex;justify-content:space-between;align-items:center;"
            "font-size:0.66rem;text-transform:uppercase;letter-spacing:0.06em;color:var(--muted);"
            "font-weight:700;margin:0.9rem 0 0.4rem\"><span>Per-device status";
    if (d_total > 0)
        html += " &middot; " + std::to_string(d_total) + " device(s)";
    html += "</span>";
    if (real_rule)
        html += "<button type=\"button\" style=\"font-size:0.66rem;padding:0.2rem 0.55rem;"
                "border-radius:0.35rem;border:1px solid var(--accent);background:none;"
                "color:var(--accent);cursor:pointer\" hx-get=\"/fragments/guardian/guard/" +
                html_escape(guard_id) +
                "\" hx-target=\"#guardian-modal-content\" hx-swap=\"innerHTML\">&#10227; Refresh</button>";
    html += "</div>";
    if (d_total == 0) {
        html += "<div style=\"font-size:0.72rem;color:var(--muted)\">No device has reported this Guard's "
                "state yet &mdash; states appear as deployed agents report (on change).</div>";
    } else {
        auto cell = [](const std::string& st) -> std::string {
            const char* col = st == "compliant" ? "var(--green)"
                            : st == "drifted"   ? "var(--yellow)"
                            : st == "errored"   ? "var(--red)"
                                                : "#5b6b80";
            return "<span style=\"color:" + std::string(col) + ";font-weight:600\">&#9679; " + st +
                   "</span>";
        };
        html += "<table class=\"detail-table\"><thead><tr><th>Device</th><th>State</th>"
                "<th>As of</th></tr></thead><tbody>";
        for (const auto& d : devs) {
            html += "<tr><td style=\"" + std::string(d.online ? "" : "color:var(--muted)") + "\">" +
                    html_escape(d.host) +
                    (d.online ? "" : " <span style=\"font-size:0.66rem\">(offline)</span>") +
                    "</td><td>" + cell(d.state) +
                    "</td><td style=\"color:var(--muted);font-size:0.72rem\">" +
                    (d.online ? html_escape(d.updated.substr(0, 16))
                              : "last reported " + html_escape(d.updated.substr(0, 16))) +
                    "</td></tr>";
        }
        html += "</tbody></table>";
    }

    if (!spark_t.empty() || !yaml.empty()) {
        html += "<details style=\"font-size:0.72rem;color:var(--muted)\">"
                "<summary style=\"cursor:pointer\">Composition / YAML</summary>";
        if (!spark_t.empty() && !assert_t.empty())
            html += "<div style=\"margin:0.3rem 0 0.2rem\">Spark (" + html_escape(spark_t) +
                    ") &rarr; Assertion (" + html_escape(assert_t) + ") &rarr; " +
                    html_escape(rem_t.empty() ? "alert" : rem_t) + "</div>";
        if (!yaml.empty())
            html += "<pre class=\"yaml\">" + html_escape(yaml) + "</pre>";
        html += "</details>";
    }
    if (!real_rule)
        html += "<div class=\"mock-note\">No backend rule found for this id.</div>";

    html += "</div><div class=\"gs-modal-footer\">"
            "<button type=\"button\" class=\"btn btn-secondary\" onclick=\"guardianCloseModal()\">"
            "Close</button></div></div>";
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
        return empty_state("No Baselines yet",
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
            drifted ? "<span title=\"Member Guards changed since last deploy — Re-deploy to apply\" "
                      "style=\"font-size:0.66rem;font-weight:600;color:var(--yellow);"
                      "margin-left:0.4rem\">&#9888; changes pending</span>"
                    : "";
        html += "<div class=\"baseline-card\">"
                "<div class=\"baseline-top\">"
                "<span class=\"baseline-name\" style=\"cursor:pointer\" "
                "onclick=\"guardianOpenModal()\" "
                "hx-get=\"/fragments/guardian/baseline/" + rid +
                "\" hx-target=\"#guardian-modal-content\" hx-swap=\"innerHTML\">" + html_escape(b.name) +
                "</span>"
                "<span class=\"lifecycle-" + std::string(deployed ? "deployed" : "draft") +
                "\" style=\"font-size:0.72rem;font-weight:600\">" +
                (deployed ? "&#9679; deployed" : "&#9675; draft") + "</span>" + pending +
                "</div>"
                "<div class=\"baseline-scope\">" + target + "</div>"
                "<div class=\"guard-meta\">"
                "<span>" + std::to_string(members) + " Guards</span>"
                "<span style=\"margin-left:auto\">"
                "<button class=\"btn btn-secondary btn-sm\" onclick=\"guardianOpenModal()\" "
                "hx-post=\"/fragments/guardian/baseline/" + rid + "/deploy\" "
                "hx-target=\"#guardian-modal-content\" hx-swap=\"innerHTML\">" +
                (deployed ? "Re-deploy" : "Deploy") + "</button></span>"
                "</div></div>";
    }
    return html;
}

std::string GuardianRoutes::render_baseline_detail_fragment(const std::string& baseline_id) const {
    // Small modal-card wrapper so error states still render inside the modal.
    auto card = [](const std::string& title, const std::string& body, const std::string& footer) {
        return "<div class=\"gs-modal-card\"><div class=\"gs-modal-header\"><h3>" + title +
               "</h3><button type=\"button\" class=\"gs-modal-close\" onclick=\"guardianCloseModal()\" "
               "aria-label=\"Close\">&times;</button></div><div class=\"gs-modal-body\">" + body +
               "</div>" + footer + "</div>";
    };
    if (!baseline_store_ || !baseline_store_->is_open())
        return card("Baseline", "<div class=\"empty-state\">Baseline store unavailable.</div>", "");
    auto b = baseline_store_->get_baseline(baseline_id);
    if (!b)
        return card("Baseline", "<div class=\"empty-state\">Baseline not found.</div>", "");

    const bool deployed = b->lifecycle == kBaselineDeployed;
    const auto members = baseline_store_->get_members(baseline_id);
    const auto assign = baseline_store_->get_assignment(baseline_id);
    const std::string bid = html_escape(b->baseline_id);

    // Per-member-guard compliance rollup (Slice C baseline drill-down) — the SAME
    // liveness-folded status-table rollup the overview uses, so the baseline modal and
    // the By-Baseline row can never disagree.
    const std::unordered_set<std::string> online =
        agents_json_fn_ ? parse_online_agents(agents_json_fn_()) : std::unordered_set<std::string>{};
    const auto by_rule = (store_ && store_->is_open())
                             ? rollup_by_rule(store_->agent_rule_statuses(), online)
                             : std::unordered_map<std::string, StateRollup>{};
    StateRollup total; // member sum → header chip
    for (const auto& rid : members)
        if (auto it = by_rule.find(rid); it != by_rule.end()) {
            total.ok += it->second.ok; total.drift += it->second.drift;
            total.err += it->second.err; total.unk += it->second.unk;
        }

    const std::string title =
        html_escape(b->name) + " " +
        compliance_chip(total.ok, total.drift, total.err, total.unk) + " <span class=\"lifecycle-" +
        std::string(deployed ? "deployed" : "draft") + "\" style=\"font-size:0.72rem\">" +
        (deployed ? "deployed" : "draft") + "</span>";

    std::string body;
    if (!b->description.empty())
        body += "<div style=\"color:var(--muted);font-size:0.8rem;margin-bottom:0.5rem\">" +
                html_escape(b->description) + "</div>";
    // Persistent "needs re-deploy" warning: member edits to a deployed Baseline do
    // not reach agents until Re-deploy.
    if (baseline_members_drifted(*b))
        body += "<div style=\"background:rgba(255,176,32,0.12);border:1px solid var(--yellow);"
                "color:var(--yellow);padding:0.45rem 0.7rem;border-radius:0.4rem;"
                "margin-bottom:0.6rem;font-size:0.74rem;font-weight:600\">&#9888; Member Guards "
                "changed since last deploy &mdash; <strong>Re-deploy</strong> to apply the change "
                "to agents.</div>";

    body += "<div class=\"kv\">"
            "<div class=\"k\">Member Guards</div><div>" + std::to_string(members.size()) + "</div>"
            "<div class=\"k\">Assignment</div><div>" +
            (assign.empty() ? std::string("(no management groups yet)")
                            : std::to_string(assign.size()) + " group(s)") + "</div>";
    if (deployed && b->deployed_at > 0)
        body += "<div class=\"k\">Last deployed</div><div>" +
                html_escape(format_iso_utc(b->deployed_at)) +
                (b->deployed_by.empty() ? "" : " by " + html_escape(b->deployed_by)) + "</div>";
    body += "</div>";

    // Member Guards — each row shows its compliance rollup + clicks into the guard
    // drill-down. The header carries a Refresh that re-pulls the latest server state.
    body += "<div style=\"display:flex;justify-content:space-between;align-items:center;"
            "font-size:0.75rem;font-weight:600;margin:0.6rem 0 0.3rem\"><span>Member Guards</span>"
            "<button type=\"button\" style=\"font-size:0.66rem;padding:0.2rem 0.55rem;"
            "border-radius:0.35rem;border:1px solid var(--accent);background:none;color:var(--accent);"
            "cursor:pointer\" hx-get=\"/fragments/guardian/baseline/" + bid +
            "\" hx-target=\"#guardian-modal-content\" hx-swap=\"innerHTML\">&#10227; Refresh</button></div>";
    if (members.empty()) {
        body += empty_state("No Guards in this Baseline",
                            "Add Guards when creating or editing the Baseline.");
    } else {
        // Per-member compliance summary: only the non-zero buckets, colored.
        auto mini = [](const StateRollup& c) -> std::string {
            if (c.total() == 0)
                return " <span style=\"color:var(--muted);font-size:0.7rem\">&middot; no reports</span>";
            std::string parts;
            auto add = [&](const char* col, const char* lbl, int64_t n) {
                if (n <= 0) return;
                if (!parts.empty()) parts += ", ";
                parts += "<span style=\"color:" + std::string(col) + "\">" + std::to_string(n) + " " +
                         lbl + "</span>";
            };
            add("var(--green)", "compliant", c.ok);
            add("var(--yellow)", "drifted", c.drift);
            add("var(--red)", "errored", c.err);
            add("#5b6b80", "unknown", c.unk);
            return " <span style=\"font-size:0.7rem\">&middot; " + parts + "</span>";
        };
        body += "<ul class=\"bl-member-list\" style=\"margin:0;padding-left:1.1rem;font-size:0.8rem\">";
        for (const auto& rid : members) {
            std::string label = rid;
            if (store_ && store_->is_open())
                if (auto r = store_->get_rule(rid); r && !r->name.empty())
                    label = r->name;
            StateRollup c;
            if (auto it = by_rule.find(rid); it != by_rule.end()) c = it->second;
            body += "<li><a class=\"gi-bl\" onclick=\"guardianOpenModal()\" "
                    "hx-get=\"/fragments/guardian/guard/" + html_escape(rid) +
                    "\" hx-target=\"#guardian-modal-content\" hx-swap=\"innerHTML\">" +
                    html_escape(label) + "</a>" + mini(c) + "</li>";
        }
        body += "</ul>";
    }

    // Assignment — deferred until management groups land.
    body += "<div style=\"font-size:0.75rem;font-weight:600;margin:0.6rem 0 0.3rem\">"
            "Assignment <span style=\"font-weight:400;color:var(--muted)\">(management groups)</span></div>";
    if (assign.empty()) {
        body += empty_state("Targeting not available yet",
                            "Management-group targeting (included / excluded groups) lands when the "
                            "global management-group feature is ready.");
    } else {
        body += "<ul style=\"margin:0;padding-left:1.1rem;font-size:0.8rem\">";
        for (const auto& a : assign)
            body += "<li>" + html_escape(a.disposition) + ": <code>" + html_escape(a.group_id) +
                    "</code></li>";
        body += "</ul>";
    }
    body += "<div class=\"mock-note\" style=\"margin-top:0.5rem\">Deploy currently applies this "
            "Baseline's enabled Guards <strong>fleet-wide</strong> (all agents, OS-filtered per "
            "Guard). Per-group targeting arrives with management groups.</div>";

    // Footer actions — all re-render into the modal (#guardian-modal-content).
    const std::string footer =
        "<div class=\"gs-modal-footer\">"
        "<button type=\"button\" class=\"btn btn-secondary\" onclick=\"guardianOpenModal()\" "
        "hx-get=\"/fragments/guardian/baseline/" + bid + "/edit\" "
        "hx-target=\"#guardian-modal-content\" hx-swap=\"innerHTML\">Edit</button>"
        "<button type=\"button\" class=\"btn btn-secondary\" "
        "hx-post=\"/fragments/guardian/baseline/" + bid +
        "/deploy\" hx-target=\"#guardian-modal-content\" hx-swap=\"innerHTML\">" +
        (deployed ? "Re-deploy" : "Deploy") + "</button>"
        "<button type=\"button\" class=\"btn btn-secondary\" style=\"color:var(--red)\" "
        "hx-post=\"/fragments/guardian/baseline/" + bid + "/delete\" "
        "hx-target=\"#guardian-modal-content\" hx-swap=\"innerHTML\" "
        "hx-confirm=\"Delete this baseline? Guards it uniquely delivers will be removed from "
        "agents on the next reconcile.\">Delete</button>"
        "</div>";

    return card(title, body, footer);
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
    // Production adapter: wrap the httplib server in the route-sink seam and
    // delegate to the testable overload below (mirrors RestApiV1 / SettingsRoutes;
    // see http_route_sink.hpp). Lets the handlers be unit-tested in-process via
    // TestRouteSink without httplib's threaded acceptor (the #438 TSan trap).
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), std::move(audit_fn),
                    std::move(emit_event_fn), store, baseline_store, std::move(agents_json_fn),
                    std::move(push_fn));
}

void GuardianRoutes::register_routes(HttpRouteSink& sink,
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
    sink.Get("/guardian", [this](const httplib::Request& req, httplib::Response& res) {
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
    sink.Get("/fragments/guardian/status",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                const std::string view = req.has_param("view") ? req.get_param_value("view") : "fleet";
                res.set_content(render_status_fragment(view), "text/html; charset=utf-8");
            });

    // -- Guards list (optional ?status= filter) ----------------------------
    sink.Get("/fragments/guardian/guards",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                const std::string sf = req.has_param("status") ? req.get_param_value("status") : "";
                res.set_content(render_guards_fragment(sf), "text/html; charset=utf-8");
            });

    // -- Event timeline (optional ?type= / ?severity= filters) -------------
    sink.Get("/fragments/guardian/events",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                const std::string tf = req.has_param("type") ? req.get_param_value("type") : "";
                const std::string sf = req.has_param("severity") ? req.get_param_value("severity") : "";
                res.set_content(render_events_fragment(tf, sf), "text/html; charset=utf-8");
            });

    // -- Per-guard detail --------------------------------------------------
    sink.Get(R"(/fragments/guardian/guard/([A-Za-z0-9._\-]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                res.set_content(render_guard_detail_fragment(req.matches[1].str()),
                                "text/html; charset=utf-8");
            });

    // -- Baselines list ----------------------------------------------------
    sink.Get("/fragments/guardian/baselines",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                res.set_content(render_baselines_fragment(), "text/html; charset=utf-8");
            });

    // -- Per-baseline detail ----------------------------------------------
    sink.Get(R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+))",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                res.set_content(render_baseline_detail_fragment(req.matches[1].str()),
                                "text/html; charset=utf-8");
            });

    // -- Create forms ------------------------------------------------------
    sink.Get("/fragments/guardian/guard-form",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                res.set_content(render_guard_form_fragment(), "text/html; charset=utf-8");
            });
    sink.Get("/fragments/guardian/baseline-form",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                res.set_content(render_baseline_form_fragment(), "text/html; charset=utf-8");
            });
    // Edit-Baseline modal form (pre-filled name + member chips).
    sink.Get(R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+)/edit)",
            [this](const httplib::Request& req, httplib::Response& res) {
                if (!perm_fn_(req, res, "GuaranteedState", "Read")) return;
                res.set_content(render_baseline_edit_form_fragment(req.matches[1].str()),
                                "text/html; charset=utf-8");
            });

    // -- Structured create (Guard) ----------------------------------------
    // Build a structured Guard from the create-form fields and persist it via
    // the shared derive_rule_spec path (single source with the REST create).
    sink.Post("/fragments/guardian/guards",
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
    sink.Post(R"(/fragments/guardian/guard/([A-Za-z0-9._\-]+)/enabled)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Write")) return;
                 const std::string id = req.matches[1].str();
                 const bool enable = req.has_param("value") && req.get_param_value("value") == "1";
                 apply_guard_change(req, res, id, enable);
             });

    // -- Structured create (Baseline) -------------------------------------
    // Persist a draft Baseline (name + member guards) via BaselineStore. Device
    // targeting (management-group assignment) + deploy are set afterwards.
    sink.Post("/fragments/guardian/baselines",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Write")) return;
                 create_baseline_from_form(req, res);
             });

    // -- Deploy / Re-deploy (Baseline-level) ------------------------------
    // Marks the Baseline deployed and converges the fleet to the union of all
    // deployed Baselines' enabled members (fleet-wide for now — management-group
    // targeting is deferred). Requires Push (it changes what agents enforce).
    sink.Post(R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+)/deploy)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Push")) return;
                 deploy_baseline(req, res, req.matches[1].str());
             });

    // -- Edit a Baseline (rename + add/remove member guards) --------------
    // Note: this no-suffix POST is registered AFTER /deploy and /delete; the
    // member regex excludes '/', so it never shadows the suffixed routes.
    sink.Post(R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+)/delete)",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Delete")) return;
                 delete_baseline_action(req, res, req.matches[1].str());
             });
    sink.Post(R"(/fragments/guardian/baseline/([A-Za-z0-9._\-]+))",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Write")) return;
                 update_baseline_from_form(req, res, req.matches[1].str());
             });
}

} // namespace yuzu::server
