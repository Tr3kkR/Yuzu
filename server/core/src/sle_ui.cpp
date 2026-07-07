/// @file sle_ui.cpp
/// /sle Licences-view renderer — a PURE function over the posture-rollup rows
/// (split from sle_routes.cpp, the inventory_ui.cpp pattern). Product UI:
/// HTMX, server-rendered, dark-theme only, htmx core attrs only (CSP blocks
/// hx-on). Honesty rules (ADR-0024 Decision 4 / roadmap G-4):
///   - a `std::nullopt` rollup is a STORE DEGRADE → an "unavailable" banner,
///     NEVER an empty table (an empty compliance table reads as "nothing
///     detected / nothing lapsed");
///   - an empty rollup renders DISTINCT copy for never-evaluated vs
///     evaluated-but-empty (the G-4 meta stamp tells them apart);
///   - the as-of tile flags staleness past 2× the evaluator cadence — a
///     keep-last-good rollup must age visibly, not read as current.
/// D-7: tables + KPI tiles only — charts are deliberately out of SLE v1.
/// R10: copy says "software licence" (British spelling); the footer
/// disambiguates from Yuzu's own product licence and the /inventory catalogue.

#include "sle_routes.hpp"

#include "web_utils.hpp"

#include <string>
#include <vector>

namespace yuzu::server {

namespace {

std::string esc(const std::string& s) { return html_escape(s); }

// Relative-time string for a past epoch (the as-of tile). PURE — the caller
// passes `now` so the renderer never touches the clock.
std::string rel_time(std::int64_t now_secs, std::int64_t then_secs) {
    if (then_secs <= 0)
        return "never";
    std::int64_t d = now_secs - then_secs;
    if (d < 0)
        d = 0;
    if (d < 90)
        return "just now";
    if (d < 5400)
        return std::to_string(d / 60) + "m ago";
    if (d < 172800)
        return std::to_string(d / 3600) + "h ago";
    return std::to_string(d / 86400) + "d ago";
}

// Days-until string for a future epoch (the next-expiry tile/column).
std::string in_days(std::int64_t now_secs, std::int64_t at_secs) {
    if (at_secs <= 0)
        return "&mdash;";
    if (at_secs <= now_secs)
        return "lapsed";
    const std::int64_t days = (at_secs - now_secs + 86399) / 86400;
    return "in " + std::to_string(days) + "d";
}

// Inlined component CSS — the `.sle-*` namespace, cloned from the `.inv-*`
// shapes (self-contained-fragment-CSS precedent; duplicate <style> on a
// re-render is idempotent/harmless).
std::string sle_style() {
    return R"css(<style>
  .sle-wrap{max-width:1180px}
  .sle-h1{font-size:1.35rem;margin:.2rem 0 0;color:var(--white,#fff);font-weight:700}
  .sle-sub{color:var(--muted,#8fa3bd);font-size:.8rem;margin-top:.25rem}
  .sle-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.55rem;margin:.8rem 0}
  .sle-kpi{background:var(--surface,#1a2940);border:1px solid var(--border,#2d4068);border-radius:.5rem;padding:.55rem .8rem}
  .sle-kpi .h{font-size:.6rem;color:var(--muted,#8fa3bd);text-transform:uppercase;letter-spacing:.05em}
  .sle-kpi .big{font-size:1.3rem;font-weight:800;color:var(--white,#fff);margin-top:.1rem}
  .sle-kpi.warn .big{color:var(--yellow,#ffcc00)}.sle-kpi .s2{font-size:.58rem;color:var(--muted,#8fa3bd)}
  .sle-ctrls{display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;margin:.7rem 0}
  .sle-search{background:var(--surface,#1a2940);border:1px solid var(--border,#2d4068);border-radius:.4rem;color:var(--fg,#cfdbe8);padding:.32rem .6rem;font-size:.78rem;min-width:240px}
  .sle-chips{display:flex;border:1px solid var(--border,#2d4068);border-radius:.4rem;overflow:hidden;flex-wrap:wrap}
  .sle-chips .gp-chip{background:var(--surface,#1a2940);color:var(--muted,#8fa3bd);border:0;border-right:1px solid var(--border,#2d4068);padding:.26rem .65rem;font-size:.72rem;cursor:pointer}
  .sle-chips .gp-chip:last-child{border-right:0}.sle-chips .gp-chip.on{background:var(--accent,#00bceb);color:#062534;font-weight:600}
  .sle-banner{font-size:.72rem;color:var(--lightblue,#a5d6ff);background:rgba(165,214,255,.06);border:1px solid rgba(165,214,255,.25);border-radius:.4rem;padding:.45rem .7rem;margin:.55rem 0}
  .sle-degrade{font-size:.78rem;color:#ff8a94;background:rgba(255,87,101,.08);border:1px solid rgba(255,87,101,.4);border-radius:.5rem;padding:.7rem .9rem;margin:.7rem 0}
  .sle-degrade b{color:var(--red,#ff5765)}
  table.sle-tbl{width:100%;border-collapse:collapse;font-size:.8rem}
  table.sle-tbl th{text-align:left;padding:.42rem .6rem;border-bottom:2px solid var(--border,#2d4068);color:var(--muted,#8fa3bd);font-size:.58rem;text-transform:uppercase;letter-spacing:.05em}
  table.sle-tbl td{padding:.44rem .6rem;border-bottom:1px solid var(--border,#2d4068);vertical-align:middle}
  .sle-name{color:var(--white,#fff);font-weight:600}.sle-num{text-align:right;font-variant-numeric:tabular-nums}
  .sle-vend{color:var(--muted,#8fa3bd);font-size:.72rem}
  .sle-grey{color:var(--slate,#6f86a6)}
  .sle-pill{display:inline-block;font-size:.57rem;border:1px solid var(--border,#2d4068);border-radius:.3rem;padding:.04rem .4rem;margin:.05rem .15rem .05rem 0;color:var(--lightblue,#a5d6ff);white-space:nowrap}
  .sle-pill.ok{color:var(--green,#4ed27e);border-color:rgba(78,210,126,.4)}
  .sle-pill.warn{color:var(--yellow,#ffcc00);border-color:rgba(255,204,0,.4)}
  .sle-pill.bad{color:#ff8a94;border-color:rgba(255,87,101,.4)}
  .sle-empty{color:var(--muted,#8fa3bd);font-size:.78rem;padding:.8rem .2rem}
  .sle-note{margin-top:1.2rem;font-size:.7rem;color:var(--muted,#8fa3bd);border-top:1px solid var(--border,#2d4068);padding-top:.6rem}.sle-note b{color:var(--lightblue,#a5d6ff)}
  .sle-mono{font-family:'JetBrains Mono',Consolas,monospace;font-size:.72rem;color:var(--muted,#8fa3bd)}
</style>)css";
}

std::string degrade_banner() {
    return "<div class=\"sle-degrade\"><b>Licence posture unavailable.</b> The posture rollup "
           "could not be read (Postgres pool/query degraded). This is <b>not</b> an empty "
           "estate — reads here are authoritative, so this banner is shown instead of an empty "
           "table. Retry shortly.</div>";
}

// A state chip that re-renders the fragment with the given filter.
std::string chip(const std::string& active_state, bool expiring_active, const char* token,
                 const char* label) {
    const bool on = !expiring_active && active_state == token;
    std::string href = "/fragments/sle/licenses";
    if (token[0] != '\0')
        href += std::string("?state=") + token;
    return std::string("<button class=\"gp-chip") + (on ? " on" : "") + "\" hx-get=\"" + href +
           "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" + label + "</button>";
}

// One per-state count pill (emitted only when the count is non-zero, so a
// row's state column stays scannable).
void pill(std::string& h, std::int64_t n, const char* cls, const char* label) {
    if (n <= 0)
        return;
    h += std::string("<span class=\"sle-pill ") + cls + "\">" + std::to_string(n) + " " + label +
         "</span>";
}

} // namespace

std::string render_sle_licenses_fragment(
    const std::optional<std::vector<LicensePostureRow>>& rollup,
    const SlePostureAggregates& agg, const std::string& state_filter, const std::string& q,
    std::int64_t expiring_days, bool capped, std::int64_t now_secs) {
    std::string h = sle_style();
    h += "<div class=\"sle-wrap\"><h1 class=\"sle-h1\">Software Licensing &amp; Entitlements</h1>"
         "<div class=\"sle-sub\">Software licences <b>detected on endpoints</b> by the daily "
         "licence scan, evaluated against the product registry (ADR-0024). Detection is "
         "agent-observed — this page never edits detected state.</div>";

    // KPI tiles from the UNFILTERED aggregates + the G-4 as-of stamp. The
    // as-of tile warns past 2× the hourly evaluator cadence (a keep-last-good
    // rollup must age visibly, gov UP-3).
    const bool stale = agg.evaluated && (now_secs - agg.as_of) > 7200;
    const std::string as_of_disp = !agg.evaluated
                                       ? std::string("not yet evaluated")
                                       : (stale ? ("stale &mdash; updated " +
                                                   rel_time(now_secs, agg.as_of))
                                                : ("updated " + rel_time(now_secs, agg.as_of)));
    const char* lapsed_cls = agg.lapsed_products > 0 ? "sle-kpi warn" : "sle-kpi";
    const char* expiring_cls = agg.expiring_soon > 0 ? "sle-kpi warn" : "sle-kpi";
    const char* asof_cls = (stale || !agg.evaluated) ? "sle-kpi warn" : "sle-kpi";
    h += "<div class=\"sle-kpis\">"
         "<div class=\"sle-kpi\"><div class=\"h\">Products</div><div class=\"big\">" +
         std::to_string(agg.products) +
         "</div><div class=\"s2\">with detected licences (incl. the unmatched bucket)</div></div>"
         "<div class=\"sle-kpi\"><div class=\"h\">Installs</div><div class=\"big\">" +
         std::to_string(agg.installs) +
         "</div><div class=\"s2\">installed-software devices matched to these products</div></div>"
         "<div class=\"" +
         std::string(lapsed_cls) + "\"><div class=\"h\">Lapsed products</div><div class=\"big\">" +
         std::to_string(agg.lapsed_products) +
         "</div><div class=\"s2\">with expired or unlicensed detections</div></div>"
         "<div class=\"" +
         std::string(expiring_cls) +
         "\"><div class=\"h\">Expiring &le;30d</div><div class=\"big\">" +
         std::to_string(agg.expiring_soon) +
         "</div><div class=\"s2\">licence rows inside the 30-day window</div></div>"
         "<div class=\"sle-kpi\"><div class=\"h\">Next expiry</div>"
         "<div class=\"big\" style=\"font-size:.95rem\">" +
         in_days(now_secs, agg.next_expiry_at) +
         "</div><div class=\"s2\">earliest future licence expiry</div></div>"
         "<div class=\"" +
         std::string(asof_cls) +
         "\"><div class=\"h\">Posture as-of</div>"
         "<div class=\"big\" style=\"font-size:.95rem\">" +
         as_of_disp + "</div><div class=\"s2\">the evaluator recomputes hourly</div></div></div>";

    // Controls: state chips + the expiring quick-filter re-render the fragment
    // server-side (same semantics as the REST /sle/licenses filters); the
    // search box narrows the rendered rows client-side (gpSearch, shell JS).
    const bool expiring_active = expiring_days >= 0 && state_filter.empty();
    h += "<div class=\"sle-ctrls\">"
         "<input class=\"sle-search\" placeholder=\"Filter products\xE2\x80\xA6\" value=\"" +
         esc(q) +
         "\" oninput=\"gpSearch(this)\" data-gpf=\"slelic\">"
         "<div class=\"sle-chips\">" +
         chip(state_filter, expiring_active, "", "All") +
         chip(state_filter, expiring_active, "licensed", "Licensed") +
         chip(state_filter, expiring_active, "subscription_active", "Subscription") +
         chip(state_filter, expiring_active, "trial", "Trial") +
         chip(state_filter, expiring_active, "grace", "Grace") +
         chip(state_filter, expiring_active, "expired", "Expired") +
         chip(state_filter, expiring_active, "unlicensed", "Unlicensed") +
         chip(state_filter, expiring_active, "unknown", "Unknown") +
         chip(state_filter, expiring_active, "lapsed", "Lapsed") +
         std::string("<button class=\"gp-chip") + (expiring_active ? " on" : "") +
         "\" hx-get=\"/fragments/sle/licenses?expiring_within_days=30\" "
         "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">Expiring &le;30d</button>"
         "</div></div>";

    if (!rollup) {
        h += degrade_banner();
        h += "</div>";
        return h;
    }

    const bool filtered_view = !state_filter.empty() || !q.empty() || expiring_days >= 0;
    if (rollup->empty()) {
        if (!agg.evaluated) {
            // Never evaluated (meta stamp 0) — distinct from an evaluated-but-
            // empty estate below (the G-4 distinction the meta stamp exists for).
            h += "<div class=\"sle-empty\">The compliance evaluator has not produced a posture "
                 "rollup yet — detected licences appear here after the first evaluation cycle "
                 "(the evaluator runs hourly, starting shortly after server startup).</div>";
        } else if (filtered_view) {
            h += "<div class=\"sle-empty\">No products match the current filter.</div>";
        } else {
            h += "<div class=\"sle-empty\">The evaluator ran and found no detected software "
                 "licences in the estate. Agents report licence detections on the daily sync; "
                 "a freshly enrolled fleet populates within ~24h.</div>";
        }
        h += "</div>";
        return h;
    }

    if (capped)
        h += "<div class=\"sle-banner\">Showing the most-deployed products (list capped). Narrow "
             "with a state chip or the search box, or use the REST API "
             "(<span class=\"sle-mono\">/api/v1/sle/licenses</span>) for the full set.</div>";

    h += "<table class=\"sle-tbl\"><thead><tr><th>Product</th><th>Vendor</th>"
         "<th class=\"sle-num\">Devices</th><th class=\"sle-num\">Installs</th>"
         "<th>Licence states</th><th>Next expiry</th>"
         "<th class=\"sle-num\">Expiring &le;30d</th></tr></thead><tbody>";
    for (const auto& r : *rollup) {
        const bool unmatched = r.product_key.empty();
        const std::string name = unmatched ? std::string("(unmatched)") : esc(r.title);
        // data-gpname feeds the client-side search across title+vendor+key.
        h += "<tr data-gpf=\"slelic\" data-gpname=\"" +
             esc(r.title + " " + r.vendor + " " + r.product_key) + "\"><td class=\"" +
             (unmatched ? "sle-grey" : "sle-name") + "\">" + name +
             (unmatched ? ""
                        : "<div class=\"sle-mono\">" + esc(r.product_key) + "</div>") +
             "</td><td class=\"sle-vend\">" + esc(r.vendor) + "</td><td class=\"sle-num\">" +
             std::to_string(r.device_count) + "</td><td class=\"sle-num\">" +
             std::to_string(r.install_count) + "</td><td>";
        pill(h, r.licensed_count, "ok", "licensed");
        pill(h, r.subscription_active_count, "ok", "subscription");
        pill(h, r.trial_count, "", "trial");
        pill(h, r.grace_count, "warn", "grace");
        pill(h, r.expired_count, "bad", "expired");
        pill(h, r.unlicensed_count, "bad", "unlicensed");
        pill(h, r.unknown_count, "", "unknown");
        h += "</td><td>" + in_days(now_secs, r.next_expiry_at) + "</td><td class=\"sle-num\">" +
             std::to_string(r.expiring_soon_count) + "</td></tr>";
    }
    h += "</tbody></table>";

    // R10: qualify the two licence senses + the catalogue cross-link.
    h += "<div class=\"sle-note\"><b>Software licences</b> here are third-party licences "
         "detected on endpoints — not your <b>Yuzu licence</b> (Settings &rarr; License) and "
         "not the installed-software catalogue (<a href=\"/inventory\">Inventory</a>, which "
         "lists installations regardless of licensing). The <b>(unmatched)</b> row aggregates "
         "detections the product registry could not yet identify. Per-device drill: "
         "<span class=\"sle-mono\">GET /api/v1/sle/agents/{id}</span>.</div>";
    h += "</div>";
    return h;
}

} // namespace yuzu::server
