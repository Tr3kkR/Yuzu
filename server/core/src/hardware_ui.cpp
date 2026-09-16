/// @file hardware_ui.cpp
/// /hardware dashboard renderers — PURE functions over `hardware_list_model.hpp`
/// types. Split from hardware_routes.cpp (which registers the routes), matching the
/// inventory_routes.cpp / inventory_ui.cpp split. Product UI: HTMX, server-rendered,
/// dark-theme only, htmx core attrs only (CSP blocks hx-on — CLAUDE.md "Product UI
/// and plugin scope"). Honesty: a degraded read renders a banner, never an empty
/// table (ADR-0016 §7).

#include "hardware_routes.hpp"

#include "web_utils.hpp"

#include <charconv>
#include <string>
#include <vector>

namespace yuzu::server {

namespace {

std::string esc(const std::string& s) { return html_escape(s); }

std::string url_encode(const std::string& s) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
            c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 0x0f]);
        }
    }
    return out;
}

std::string os_label(const std::string& os) {
    if (os == "windows" || os == "win") return "Windows";
    if (os == "linux" || os == "lin") return "Linux";
    if (os == "darwin" || os == "macos" || os == "mac") return "macOS";
    return os.empty() ? "?" : esc(os);
}

const char* os_cls(const std::string& os) {
    if (os == "windows" || os == "win") return "win";
    if (os == "linux" || os == "lin") return "lin";
    if (os == "darwin" || os == "macos" || os == "mac") return "mac";
    return "";
}

std::string ci_disp(const std::string& s) {
    if (s.empty() || s == "unknown")
        return "<span class=\"inv-grey\">&mdash;</span>";
    return esc(s);
}

std::string rel_time(std::int64_t now_secs, std::int64_t then_secs) {
    if (then_secs <= 0) return "never";
    std::int64_t d = now_secs - then_secs;
    if (d < 0) d = 0;
    if (d < 90) return "just now";
    if (d < 5400) return std::to_string(d / 60) + "m ago";
    if (d < 172800) return std::to_string(d / 3600) + "h ago";
    return std::to_string(d / 86400) + "d ago";
}

bool is_numeric_dec(const std::string& s) {
    if (s.empty() || s == "unknown") return false;
    unsigned long long v = 0;
    const auto res = std::from_chars(s.data(), s.data() + s.size(), v);
    return res.ec == std::errc{} && res.ptr == s.data() + s.size();
}

std::string ci_cores_threads(const std::string& cores, const std::string& threads) {
    const bool hc = is_numeric_dec(cores);
    const bool ht = is_numeric_dec(threads);
    if (!hc && !ht) return "";
    std::string s;
    if (hc) s += cores + "c";
    if (ht) { if (!s.empty()) s += "/"; s += threads + "t"; }
    return s;
}

std::string ci_ram_gb(const std::string& bytes_dec) {
    if (bytes_dec.empty() || bytes_dec == "unknown") return "";
    unsigned long long v = 0;
    const auto res = std::from_chars(bytes_dec.data(), bytes_dec.data() + bytes_dec.size(), v);
    if (res.ec != std::errc{} || res.ptr != bytes_dec.data() + bytes_dec.size()) return "";
    constexpr unsigned long long kGiB = 1024ULL * 1024 * 1024;
    const unsigned long long tenths_gb = (v * 10) / kGiB;
    return std::to_string(tenths_gb / 10) + "." + std::to_string(tenths_gb % 10) + " GB";
}

std::string ci_cell(const std::string& v) { return ci_disp(v); }

// Full query string for /fragments/hardware/list, echoing every facet so every
// control on the page is self-describing on swap (device_ui.cpp's chip idiom).
// `with_q=false` omits `q=` — used by every control that carries `hx-include="#hw-q"`
// instead, so the LIVE (not-yet-submitted) search box value wins rather than a stale
// URL-embedded copy; httplib keeps only the FIRST of two same-named params, so a
// control must never emit both. `results_only=true` asks the route for just the
// `#hw-results` region (table/chips/breadcrumb/pager), never the KPI strip or h1 —
// that is what makes the search box's own swap not destroy the input mid-keystroke
// (round-2 item 5).
std::string list_url(const HardwareListQuery& q, bool with_q = true, bool results_only = false) {
    std::string u = "/fragments/hardware/list?os=" + url_encode(q.os) +
                    "&status=" + url_encode(q.status) + "&sort=" + url_encode(q.sort) +
                    "&dir=" + (q.desc ? "desc" : "asc") + "&offset=" + std::to_string(q.offset) +
                    "&limit=" + std::to_string(q.limit);
    if (with_q) u += "&q=" + url_encode(q.q);
    if (results_only) u += "&results_only=1";
    return u;
}

std::string hw_style() {
    return R"css(<style>
  .hw-wrap{max-width:1180px}
  .hw-h1{font-size:1.35rem;margin:.2rem 0 0;color:var(--white,#fff);font-weight:700}
  .hw-sub{color:var(--muted,#8fa3bd);font-size:.8rem;margin-top:.25rem}
  .hw-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.55rem;margin:.8rem 0}
  .hw-kpi{background:var(--surface,#1a2940);border:1px solid var(--border,#2d4068);border-radius:.5rem;padding:.55rem .8rem}
  .hw-kpi .h{font-size:.6rem;color:var(--muted,#8fa3bd);text-transform:uppercase;letter-spacing:.05em}
  .hw-kpi .big{font-size:1.3rem;font-weight:800;color:var(--white,#fff);margin-top:.1rem}
  .hw-kpi.warn .big{color:var(--yellow,#ffcc00)}
  .hw-ctrls{display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;margin:.7rem 0}
  .hw-search{background:var(--surface,#1a2940);border:1px solid var(--border,#2d4068);border-radius:.4rem;color:var(--fg,#cfdbe8);padding:.32rem .6rem;font-size:.78rem;min-width:240px}
  .hw-breadcrumb{display:flex;gap:.4rem;flex-wrap:wrap;margin:.4rem 0;font-size:.7rem}
  .hw-crumb{background:var(--surface,#1a2940);border:1px solid var(--border,#2d4068);border-radius:.4rem;padding:.15rem .5rem;color:var(--lightblue,#a5d6ff)}
  .hw-crumb a{color:var(--muted,#8fa3bd);margin-left:.35rem;text-decoration:none}
  table.hw-tbl{width:100%;border-collapse:collapse;font-size:.8rem}
  table.hw-tbl th{text-align:left;padding:.42rem .6rem;border-bottom:2px solid var(--border,#2d4068);color:var(--muted,#8fa3bd);font-size:.58rem;text-transform:uppercase;letter-spacing:.05em}
  table.hw-tbl th.sortable{cursor:pointer;user-select:none}
  table.hw-tbl th.sortable:hover{color:var(--fg,#cfdbe8)}
  table.hw-tbl td{padding:.44rem .6rem;border-bottom:1px solid var(--border,#2d4068);vertical-align:middle}
  table.hw-tbl tr.click{cursor:pointer}table.hw-tbl tr.click:hover td{background:var(--surface,#1a2940)}
  .hw-name{color:var(--white,#fff);font-weight:600;text-decoration:none}
  .hw-mono{font-family:'JetBrains Mono',Consolas,monospace;font-size:.72rem;color:var(--muted,#8fa3bd)}
  .hw-pill{font-size:.57rem;border:1px solid var(--border,#2d4068);border-radius:.3rem;padding:.04rem .4rem;color:var(--lightblue,#a5d6ff)}
  .hw-pill.win{color:#a5d6ff}.hw-pill.lin{color:#ffcc88}.hw-pill.mac{color:#c7b3ff}
  .hw-pill.on{color:var(--green,#4ed27e);border-color:rgba(78,210,126,.4)}
  .hw-pill.off{color:var(--slate,#6f86a6)}
  .hw-page{display:flex;gap:.5rem;align-items:center;margin-top:.6rem;font-size:.72rem;color:var(--muted,#8fa3bd)}
  .hw-degrade{font-size:.78rem;color:#ff8a94;background:rgba(255,87,101,.08);border:1px solid rgba(255,87,101,.4);border-radius:.5rem;padding:.7rem .9rem;margin:.7rem 0}
  .hw-degrade b{color:var(--red,#ff5765)}
  .hw-empty{color:var(--muted,#8fa3bd);font-size:.78rem;padding:.8rem .2rem}
  .hw-grey{color:var(--slate,#6f86a6)}
  .hw-hdr{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap;margin:.4rem 0 .2rem}
  .hw-dot{display:inline-block;width:.5rem;height:.5rem;border-radius:50%;margin-right:.35rem}
  .hw-tag{font-size:.62rem;background:var(--surface,#1a2940);border:1px solid var(--border,#2d4068);border-radius:.3rem;padding:.08rem .4rem;color:var(--muted,#8fa3bd)}
  .hw-lens{display:flex;gap:.3rem;border-bottom:1px solid var(--border,#2d4068);padding-bottom:.5rem;margin:.7rem 0}
  .hw-lens a{font-size:.75rem;color:var(--muted,#8fa3bd);border:1px solid transparent;border-radius:.35rem;padding:.2rem .65rem;cursor:pointer}
  .hw-lens a.on{color:var(--white,#fff);border-color:var(--accent,#00bceb)}
  .ci-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:.3rem .9rem;font-size:.74rem;margin-bottom:.7rem}
  .ci-grid .ci-lab{color:var(--muted,#8fa3bd);font-size:.62rem;text-transform:uppercase;letter-spacing:.03em}
  .ci-sec{margin-top:1rem}
  .ci-sec h4{font-size:.68rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted,#8fa3bd);margin:0 0 .35rem;border-bottom:1px solid var(--border,#2d4068);padding-bottom:.25rem}
  .hw-scroll{overflow-x:auto}
  .hw-macs{display:flex;flex-wrap:wrap;gap:.25rem;margin-top:.2rem}
</style>)css";
}

std::string kpi(const char* label, std::string value, const char* extra_class = "") {
    return std::string("<div class=\"hw-kpi ") + extra_class + "\"><div class=\"h\">" + label +
           "</div><div class=\"big\">" + std::move(value) + "</div></div>";
}

std::string kpis_html(const HardwareKpis& k, bool ci_degraded) {
    std::string h = "<div class=\"hw-kpis\">";
    h += kpi("Total CIs", std::to_string(k.total));
    h += kpi("Online", std::to_string(k.online));
    h += kpi("Offline", std::to_string(k.offline));
    h += kpi("Stale", std::to_string(k.stale), k.stale > 0 ? "warn" : "");
    h += kpi("CI coverage", ci_degraded ? "&mdash;" : (std::to_string(k.with_ci) + " / " + std::to_string(k.total)));
    h += "</div>";
    return h;
}

std::string sortable_th(const char* label, HwSortKey key, const HardwareListQuery& q) {
    const bool active = parse_hw_sort_key(q.sort) == key;
    const bool next_desc = active ? !q.desc : false;
    HardwareListQuery nq = q;
    nq.sort = std::string(hw_sort_token(key));
    nq.desc = next_desc;
    nq.offset = 0; // any sort change resets to page 1
    std::string indicator = active ? (q.desc ? " &#9660;" : " &#9650;") : "";
    return std::string("<th class=\"sortable\" hx-get=\"") + esc(list_url(nq, false, true)) +
           "\" hx-target=\"#hw-results\" hx-swap=\"outerHTML\" hx-include=\"#hw-q\" "
           "hx-sync=\"this:abort\">" + label + indicator + "</th>";
}

std::string chip(const char* label, const std::string& value, const HardwareListQuery& q,
                 bool is_os) {
    HardwareListQuery nq = q;
    if (is_os) nq.os = value; else nq.status = value;
    nq.offset = 0;
    const bool on = (is_os ? q.os : q.status) == value;
    return std::string("<a class=\"gp-chip") + (on ? " on" : "") + "\" hx-get=\"" +
           esc(list_url(nq, false, true)) + "\" hx-target=\"#hw-results\" hx-swap=\"outerHTML\" "
           "hx-include=\"#hw-q\">" + label + "</a>";
}

std::string breadcrumb(const HardwareListQuery& q) {
    // (label, cleared-url, needs-live-q-include). The search crumb clears q itself
    // (with_q=true, blank) so it must NOT also hx-include the (still-populated) box —
    // that would resurrect the just-cleared value. Every other crumb keeps the box's
    // live value via hx-include instead of a URL-embedded (possibly stale) copy.
    std::vector<std::tuple<std::string, std::string, bool>> active;
    if (!q.q.empty()) {
        HardwareListQuery nq = q; nq.q.clear(); nq.offset = 0;
        active.emplace_back("Search: “" + esc(q.q) + "”", list_url(nq, true, true), false);
    }
    if (q.os != "all") {
        HardwareListQuery nq = q; nq.os = "all"; nq.offset = 0;
        active.emplace_back("OS: " + os_label(q.os), list_url(nq, false, true), true);
    }
    if (q.status != "all") {
        HardwareListQuery nq = q; nq.status = "all"; nq.offset = 0;
        active.emplace_back(q.status == "online" ? "Status: Online" : "Status: Offline",
                            list_url(nq, false, true), true);
    }
    if (active.empty()) return "";
    std::string h = "<div class=\"hw-breadcrumb\">";
    for (auto& [label, url, inc] : active)
        h += "<span class=\"hw-crumb\">" + label + "<a hx-get=\"" + esc(url) +
             "\" hx-target=\"#hw-results\" hx-swap=\"outerHTML\"" +
             (inc ? " hx-include=\"#hw-q\"" : "") + ">&times;</a></span>";
    h += "</div>";
    return h;
}

std::string pagination(const HardwareListQuery& q, std::size_t total_matching) {
    const std::size_t start = total_matching == 0 ? 0 : q.offset + 1;
    const std::size_t end = std::min(q.offset + q.limit, total_matching);
    std::string h = "<div class=\"hw-page\"><span>Showing " + std::to_string(start) + "&ndash;" +
                    std::to_string(end) + " of " + std::to_string(total_matching) + "</span>";
    if (q.offset > 0) {
        HardwareListQuery pq = q;
        pq.offset = q.offset >= q.limit ? q.offset - q.limit : 0;
        h += " <button class=\"gp-btn\" hx-get=\"" + esc(list_url(pq, false, true)) +
             "\" hx-target=\"#hw-results\" hx-swap=\"outerHTML\" hx-include=\"#hw-q\" "
             "hx-sync=\"this:abort\">Prev</button>";
    }
    if (q.offset + q.limit < total_matching) {
        HardwareListQuery nq = q; nq.offset = q.offset + q.limit;
        h += " <button class=\"gp-btn\" hx-get=\"" + esc(list_url(nq, false, true)) +
             "\" hx-target=\"#hw-results\" hx-swap=\"outerHTML\" hx-include=\"#hw-q\" "
             "hx-sync=\"this:abort\">Next</button>";
    }
    h += "</div>";
    return h;
}

std::string row_html(const InventoryDeviceRow& d) {
    const std::string name = d.hostname.empty() ? d.agent_id : d.hostname;
    const std::string status_pill = d.online
        ? "<span class=\"hw-pill on\">online</span>"
        : (d.stale ? "<span class=\"hw-pill\">stale</span>" : "<span class=\"hw-pill off\">offline</span>");
    const std::string cpu_ram = [&] {
        const std::string ct = ci_cores_threads(d.ci_cpu_cores, d.ci_cpu_threads);
        const std::string ram = ci_ram_gb(d.ci_ram_bytes);
        std::string parts;
        if (!d.ci_cpu_model.empty() && d.ci_cpu_model != "unknown") parts += esc(d.ci_cpu_model);
        if (!ct.empty()) parts += (parts.empty() ? "" : " &middot; ") + ct;
        return parts.empty() ? std::string("<span class=\"hw-grey\">&mdash;</span>") : parts;
    }();
    const std::string ram_cell = [&] {
        const std::string ram = ci_ram_gb(d.ci_ram_bytes);
        return ram.empty() ? std::string("<span class=\"hw-grey\">&mdash;</span>") : ram;
    }();
    return "<tr class=\"click\" onclick=\"location.href='/hardware/ci?id=" + url_encode(d.agent_id) +
           "'\">"
           "<td><a class=\"hw-name\" href=\"/hardware/ci?id=" + url_encode(d.agent_id) + "\">" +
           esc(name) + "</a></td>"
           "<td><span class=\"hw-pill " + os_cls(d.os) + "\">" + os_label(d.os) + "</span></td>"
           "<td>" + status_pill + "</td>"
           "<td class=\"hw-mono\">" + (d.last_seen.empty() ? "?" : esc(d.last_seen)) + "</td>"
           "<td class=\"hw-mono\">" + ci_cell(d.ci_manufacturer) + "</td>"
           "<td class=\"hw-mono\">" + ci_cell(d.ci_model) + "</td>"
           "<td class=\"hw-mono\">" + ci_cell(d.ci_serial) + "</td>"
           "<td class=\"hw-mono\">" + cpu_ram + "</td>"
           "<td class=\"hw-mono\">" + ram_cell + "</td>"
           "<td class=\"hw-mono\">" + ci_cell(d.ci_os_version) + "</td>"
           "</tr>";
}

std::string device_lens_tab(const char* key, const char* label, const std::string& agent_id,
                            const std::string& active) {
    const std::string on = (active == key) ? " on" : "";
    // lens_only=1: the route answers with ONLY the lens body, so swapping it into
    // #hw-ci-lens never nests a second header + tab bar (round-2 item 6).
    return std::string("<a class=\"") + on + "\" hx-get=\"/fragments/hardware/ci?id=" +
           url_encode(agent_id) + "&lens=" + key + "&lens_only=1\" hx-target=\"#hw-ci-lens\" "
           "hx-swap=\"innerHTML\">" + label + "</a>";
}

std::string sync_button(const std::string& agent_id, const char* source, const char* lens,
                        const HwSyncAffordance& sync, const char* label) {
    using S = HwSyncAffordance::State;
    if (sync.state == S::Ready)
        return std::string("<button type=\"button\" class=\"gp-btn accent\" data-agent=\"") +
               esc(agent_id) + "\" data-lens=\"" + lens + "\" onclick=\"hwSyncNow(this,'" + source +
               "')\">" + label + "</button>";
    const char* note = sync.state == S::Offline      ? "sync needs a connected agent"
                       : sync.state == S::NoExecute  ? "needs the Execute permission"
                                                     : "predates sync-on-demand (0.13.1+)";
    std::string h = std::string("<button type=\"button\" class=\"gp-btn\" disabled>") + label +
                    "</button> <span class=\"hw-mono\">";
    if (sync.state == S::Unsupported && !sync.agent_version.empty())
        h += "agent " + esc(sync.agent_version) + " ";
    h += note;
    h += "</span>";
    return h;
}

std::string render_hardware_results_region(const HardwareListPage& page, bool ci_degraded) {
    const HardwareListQuery& q = page.query;
    std::string h = "<div id=\"hw-results\">";
    h += "<div class=\"gp-filters\">" + chip("All OS", "all", q, true) + chip("Windows", "windows", q, true) +
         chip("Linux", "linux", q, true) + chip("macOS", "macos", q, true) + "</div>";
    h += "<div class=\"gp-filters\">" + chip("All status", "all", q, false) +
         chip("Online", "online", q, false) + chip("Offline", "offline", q, false) + "</div>";

    h += breadcrumb(q);

    if (page.rows.empty()) {
        h += "<div class=\"gp-placeholder\"><b>No devices match.</b> Try clearing a filter.</div>";
    } else {
        h += "<div class=\"hw-scroll\"><table class=\"hw-tbl\"><thead><tr>";
        h += sortable_th("Name", HwSortKey::Name, q);
        h += sortable_th("OS", HwSortKey::Os, q);
        h += sortable_th("Status", HwSortKey::Status, q);
        h += sortable_th("Last seen", HwSortKey::LastSeen, q);
        h += sortable_th("Manufacturer", HwSortKey::Manufacturer, q);
        h += sortable_th("Model", HwSortKey::Model, q);
        h += sortable_th("Serial", HwSortKey::Serial, q);
        h += sortable_th("CPU", HwSortKey::Cpu, q);
        h += sortable_th("RAM", HwSortKey::Ram, q);
        h += sortable_th("OS version", HwSortKey::OsVersion, q);
        h += "</tr></thead><tbody>";
        for (const auto& row : page.rows)
            h += row_html(row);
        h += "</tbody></table></div>";
        h += pagination(q, page.total_matching);
    }
    h += "</div>";
    return h;
}

} // namespace

std::string render_hardware_list_fragment(const HardwareListPage& page, bool ci_degraded,
                                          bool roster_unavailable, bool results_only) {
    if (results_only)
        return render_hardware_results_region(page, ci_degraded);

    std::string h = hw_style();
    h += "<div class=\"hw-wrap\">";
    h += "<h1 class=\"hw-h1\">Hardware</h1>";
    h += "<div class=\"hw-sub\">Configuration items across the fleet &mdash; search, filter, sort.</div>";

    if (roster_unavailable) {
        h += "<div class=\"hw-degrade\"><b>Hardware roster unavailable.</b> The device roster could "
             "not be read. This is <b>not</b> \"no devices\" &mdash; reads here are authoritative, so "
             "this banner is shown instead of an empty table. Retry shortly.</div></div>";
        return h;
    }

    h += kpis_html(page.kpis, ci_degraded);
    if (ci_degraded)
        h += "<div class=\"hw-degrade\"><b>CI columns unavailable.</b> The device-CI store could not "
             "be read &mdash; a blank cell here is not \"no CI\", it is a degraded read.</div>";

    const HardwareListQuery& q = page.query;
    h += "<div class=\"hw-ctrls\">";
    // CSP-safe search (round-2 item 5): htmx's `[key=='Enter']` event filter compiles
    // with `Function()`, which the dashboard CSP (no unsafe-eval) refuses at runtime —
    // htmx silently drops the filter and falls back to a bare `keyup`, firing on every
    // keystroke. `changed`/`delay:` are plain token parsing (no eval), so they degrade
    // safely instead of silently. The input also lives OUTSIDE `#hw-results`, targeted
    // by every other control via `hx-include`, so its own swap can never destroy it.
    h += "<input id=\"hw-q\" type=\"search\" class=\"hw-search\" name=\"q\" value=\"" + esc(q.q) +
         "\" placeholder=\"Search hostname, serial, model, CPU&hellip;\" hx-get=\"" +
         esc(list_url([&] { HardwareListQuery nq = q; nq.offset = 0; return nq; }(), false, true)) +
         "\" hx-target=\"#hw-results\" hx-swap=\"outerHTML\" "
         "hx-trigger=\"keyup changed delay:400ms, search\" hx-sync=\"this:replace\">";
    h += "</div>";

    h += render_hardware_results_region(page, ci_degraded);
    h += "</div>";
    return h;
}

std::string render_hardware_not_found(const std::string& agent_id) {
    return hw_style() + "<div class=\"hw-wrap\"><div class=\"gp-placeholder\"><b>Device not found.</b> "
           "'" + esc(agent_id) + "' has not been seen in the last 30 days, or does not exist.</div></div>";
}

std::string render_hardware_lens_body(const std::string& agent_id, const HardwareCiDetail& detail,
                                      const std::string& lens, std::int64_t now_secs,
                                      const HwCiAffordances& aff) {
    const bool online = detail.identity && detail.identity->online;
    std::string h;
    if (lens == "software") {
        h += render_hardware_software_lens(agent_id, detail.software, detail.software_truncated, online,
                                           aff.sync);
    } else if (lens == "tags") {
        h += render_hardware_tags_lens(agent_id, detail.tags, aff.can_write_tags);
    } else if (lens == "actions") {
        // The route swaps this placeholder for the real actions lens on load —
        // rendering the lens itself needs actions_fn/classify_fn/schema_fn, which
        // the CiDetailFn composition (built for the other three lenses) doesn't
        // carry. Keeping the fetch in its own hx-get also means a slow/offline
        // agent doesn't block the rest of the CI record from rendering.
        h += "<div hx-get=\"/fragments/hardware/ci/actions?id=" + url_encode(agent_id) +
             "\" hx-trigger=\"load\" hx-swap=\"innerHTML\"><span class=\"gp-mute\">Loading "
             "actions&hellip;</span></div>";
    } else {
        if (!detail.ci.has_value()) {
            h += "<div class=\"hw-degrade\"><b>CI record unavailable.</b> The device-CI store could "
                 "not be read (Postgres pool/query degraded). This is <b>not</b> \"no CI record\" "
                 "&mdash; reads here are authoritative. Retry shortly.</div>";
        } else if (!detail.ci->has_value()) {
            h += "<div class=\"hw-empty\">No CI record synced yet for this device (device-CI daily "
                 "sync, ADR-0016 &mdash; a freshly enrolled agent populates within ~24h, or on "
                 "demand).<div style=\"margin-top:.5rem\">" +
                 sync_button(agent_id, "device_ci", "overview", aff.sync, "Sync now") + "</div></div>";
        } else {
            const DeviceCiRecord& r = **detail.ci;
            auto field = [](const char* label, const std::string& val) {
                return std::string("<div><span class=\"ci-lab\">") + label + ": </span>" +
                       ci_disp(val) + "</div>";
            };
            h += "<div class=\"ci-sec\"><h4>General</h4><div class=\"ci-grid\">";
            h += field("Hostname", r.hostname);
            h += field("Domain", r.domain);
            h += field("OU", r.ou);
            h += "<div><span class=\"ci-lab\">First synced: </span>" + esc(rel_time(now_secs, r.first_seen)) + "</div>";
            h += "<div><span class=\"ci-lab\">Last synced: </span>" + esc(rel_time(now_secs, r.last_seen)) + "</div>";
            h += "</div></div>";

            h += "<div class=\"ci-sec\"><h4>Hardware</h4><div class=\"ci-grid\">";
            h += field("Manufacturer", r.manufacturer);
            h += field("Model", r.model);
            h += field("Serial", r.serial);
            h += field("System UUID", r.system_uuid);
            h += field("CPU", r.cpu_model);
            h += field("Cores / threads", ci_cores_threads(r.cpu_cores, r.cpu_threads));
            h += field("Memory", ci_ram_gb(r.ram_bytes));
            h += field("Disks", r.disks_summary);
            h += "</div></div>";

            h += "<div class=\"ci-sec\"><h4>Firmware</h4><div class=\"ci-grid\">";
            h += field("BIOS vendor", r.bios_vendor);
            h += field("BIOS version", r.bios_version);
            h += field("BIOS date", r.bios_date);
            h += "</div></div>";

            h += "<div class=\"ci-sec\"><h4>Network</h4><div class=\"ci-grid\">";
            h += field("Primary MAC", r.primary_mac);
            h += field("NIC count", r.nic_count);
            h += "</div>";
            // A comma-joined string trails off the page at any width (round-3 item
            // 12) — one wrapping chip per address instead of one unbroken line.
            h += "<div><span class=\"ci-lab\">All MACs: </span>";
            if (r.macs_summary.empty() || r.macs_summary == "unknown") {
                h += "<span class=\"inv-grey\">&mdash;</span>";
            } else {
                h += "<div class=\"hw-macs\">";
                std::string cur;
                for (std::size_t i = 0; i <= r.macs_summary.size(); ++i) {
                    if (i == r.macs_summary.size() || r.macs_summary[i] == ',') {
                        while (!cur.empty() && cur.front() == ' ') cur.erase(cur.begin());
                        while (!cur.empty() && cur.back() == ' ') cur.pop_back();
                        if (!cur.empty()) h += "<span class=\"hw-tag\">" + esc(cur) + "</span>";
                        cur.clear();
                    } else {
                        cur.push_back(r.macs_summary[i]);
                    }
                }
                h += "</div>";
            }
            h += "</div></div>";

            h += "<div class=\"ci-sec\"><h4>Operating system</h4><div class=\"ci-grid\">";
            h += field("OS", r.os_name);
            h += field("Version", r.os_version);
            h += field("Build", r.os_build);
            h += field("Architecture", r.arch);
            h += "</div></div>";
        }
    }
    return h;
}

std::string render_hardware_ci_fragment(const std::string& agent_id, const HardwareCiDetail& detail,
                                        const std::string& lens, std::int64_t now_secs,
                                        const HwCiAffordances& aff) {
    if (!detail.identity && !detail.ci.has_value())
        return render_hardware_not_found(agent_id);
    if (!detail.identity && detail.ci.has_value() && !detail.ci->has_value())
        return render_hardware_not_found(agent_id);

    const std::string hostname = detail.identity && !detail.identity->hostname.empty()
                                      ? detail.identity->hostname
                                      : agent_id;
    const std::string os = detail.identity ? detail.identity->os : "";
    const bool online = detail.identity && detail.identity->online;
    const std::string last_seen = detail.identity ? detail.identity->last_seen : "unknown";
    const std::string active_lens = lens.empty() ? "overview" : lens;

    std::string h = hw_style();
    h += "<div class=\"hw-wrap\">";
    h += "<div class=\"hw-hdr\"><a class=\"gp-btn\" href=\"/hardware\">&larr; Hardware</a></div>";
    h += "<div class=\"hw-hdr\">";
    h += "<span class=\"hw-dot\" style=\"background:" + std::string(online ? "#4ed27e" : "#6f86a6") +
         "\"></span>";
    h += "<h1 class=\"hw-h1\" style=\"margin:0\">" + esc(hostname) + "</h1>";
    if (!os.empty())
        h += "<span class=\"hw-pill " + std::string(os_cls(os)) + "\">" + os_label(os) + "</span>";
    h += "<span class=\"hw-mono\">" + esc(agent_id) + "</span>";
    h += "<span class=\"hw-mono\">last seen " + esc(last_seen.empty() ? "?" : last_seen) + "</span>";
    h += "<span style=\"flex:1\"></span>";
    h += sync_button(agent_id, "all", active_lens.c_str(), aff.sync, "Sync now");
    h += "</div>";

    if (detail.tags && !detail.tags->empty()) {
        h += "<div class=\"hw-hdr\">";
        for (const auto& t : *detail.tags)
            h += "<span class=\"hw-tag\">" + esc(t.key) + "=" + esc(t.value) + "</span>";
        h += "</div>";
    }

    h += render_hardware_lens_bar(agent_id, active_lens, /*oob=*/false);
    h += "<div id=\"hw-ci-lens\">";
    h += render_hardware_lens_body(agent_id, detail, active_lens, now_secs, aff);
    h += "</div></div>";
    return h;
}

std::string render_hardware_lens_bar(const std::string& agent_id, const std::string& active, bool oob) {
    std::string h = "<div class=\"hw-lens\" id=\"hw-lens-bar\"" +
                    std::string(oob ? " hx-swap-oob=\"true\"" : "") + ">";
    h += device_lens_tab("overview", "Overview", agent_id, active);
    h += device_lens_tab("software", "Installed software", agent_id, active);
    h += device_lens_tab("tags", "Tags", agent_id, active);
    h += device_lens_tab("actions", "Actions", agent_id, active);
    h += "</div>";
    return h;
}

std::string render_hardware_sync_pending(const std::string& agent_id, const std::string& lens,
                                         std::int64_t await_since, int next_attempt,
                                         const std::string& command_id) {
    return "<div hx-get=\"/fragments/hardware/ci?id=" + url_encode(agent_id) + "&lens=" +
           url_encode(lens) + "&lens_only=1&await_since=" + std::to_string(await_since) +
           "&n=" + std::to_string(next_attempt) + "&command_id=" + url_encode(command_id) +
           "\" hx-trigger=\"load delay:2s\" hx-swap=\"outerHTML\"><span class=\"gp-mute\">Sync "
           "requested &mdash; waiting for the device to report (" + std::to_string(next_attempt - 1) +
           "/30)&hellip;</span></div>";
}

std::string render_hardware_sync_terminal(const std::string& agent_id, const std::string& lens,
                                          const std::string& refusal_output, bool timed_out) {
    std::string h = "<div class=\"hw-degrade\">";
    if (!refusal_output.empty())
        h += "<b>The device refused the sync request:</b> " + esc(refusal_output);
    else if (timed_out)
        h += "<b>Still waiting.</b> The device may be slow, or the report failed &mdash; check the "
             "agent log for <span class=\"hw-mono\">sync:</span> lines.";
    h += " <a class=\"gp-btn\" hx-get=\"/fragments/hardware/ci?id=" + url_encode(agent_id) + "&lens=" +
         url_encode(lens) + "&lens_only=1\" hx-target=\"#hw-ci-lens\" hx-swap=\"innerHTML\">Reload</a>";
    h += "</div>";
    return h;
}

std::string render_hardware_software_lens(const std::string& agent_id,
                                          const std::optional<std::vector<SoftwareEntry>>& software,
                                          bool truncated, bool online, const HwSyncAffordance& sync) {
    if (!software)
        return "<div class=\"hw-degrade\"><b>Installed software unavailable.</b> The software "
               "inventory store could not be read. Retry shortly.</div>";
    if (software->empty()) {
        if (!online)
            return "<div class=\"hw-empty\">No installed-software inventory on record (device is "
                   "offline and has not synced).</div>";
        return "<div class=\"hw-empty\">No installed-software inventory synced yet for this device."
               "<div style=\"margin-top:.5rem\">" +
               sync_button(agent_id, "installed_software", "software", sync, "Sync now") +
               "</div></div>";
    }
    std::string h = "<table class=\"hw-tbl\"><thead><tr><th>Name</th><th>Version</th><th>Publisher</th>"
                    "<th>Install date</th></tr></thead><tbody>";
    for (const auto& e : *software)
        h += "<tr><td class=\"hw-name\">" + esc(e.name) + "</td><td class=\"hw-mono\">" +
             ci_disp(e.version) + "</td><td class=\"hw-mono\">" + ci_disp(e.publisher) +
             "</td><td class=\"hw-mono\">" + ci_disp(e.install_date) + "</td></tr>";
    h += "</tbody></table>";
    if (truncated)
        h += "<div class=\"hw-page\">List truncated &mdash; showing the first " +
             std::to_string(kHwSoftwareCap) + " entries.</div>";
    return h;
}

std::string render_hardware_tags_lens(const std::string& agent_id,
                                      const std::optional<std::vector<DeviceTag>>& tags,
                                      bool can_write) {
    if (!tags)
        return "<div class=\"hw-degrade\"><b>Tags unavailable.</b> The tag store could not be read. "
               "Retry shortly.</div>";
    std::string h;
    if (can_write) {
        // Posts JSON to the EXISTING /api/tags/set (scoped Tag:Write, audited tag.set)
        // via hwTagSet — no new route. Key rules mirror TagStore::validate_key.
        h += "<form class=\"hw-hdr\" data-agent=\"" + esc(agent_id) + "\" onsubmit=\"return false\">"
             "<input class=\"hw-search\" name=\"key\" placeholder=\"key (e.g. owner)\" "
             "pattern=\"[A-Za-z0-9_.:-]{1,64}\" maxlength=\"64\" style=\"min-width:160px\">"
             "<input class=\"hw-search\" name=\"value\" placeholder=\"value\" maxlength=\"448\">"
             "<button type=\"button\" class=\"gp-btn accent\" onclick=\"hwTagSet(this)\">Add tag</button>"
             "</form>";
    }
    if (tags->empty()) {
        h += "<div class=\"hw-empty\">No tags set on this device.</div>";
        return h;
    }
    h += "<table class=\"hw-tbl\"><thead><tr><th>Key</th><th>Value</th><th>Source</th>" +
         std::string(can_write ? "<th></th>" : "") + "</tr></thead><tbody>";
    for (const auto& t : *tags) {
        h += "<tr><td class=\"hw-name\">" + esc(t.key) + "</td><td class=\"hw-mono\">" + esc(t.value) +
             "</td><td class=\"hw-mono\">" + esc(t.source) + "</td>";
        if (can_write)
            h += "<td><a class=\"gp-btn\" data-agent=\"" + esc(agent_id) + "\" data-key=\"" + esc(t.key) +
                 "\" onclick=\"hwTagDelete(this)\">remove</a></td>";
        h += "</tr>";
    }
    h += "</tbody></table>";
    return h;
}

} // namespace yuzu::server
