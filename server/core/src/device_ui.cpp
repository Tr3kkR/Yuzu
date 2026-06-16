/// @file device_ui.cpp
/// Renderers for the shared device surfaces — PURE functions over DeviceRow.
/// Split from device_routes.cpp (which registers the routes) to keep each TU
/// small; the tiny markup helpers are re-declared in this TU's anonymous
/// namespace, same pattern as network_ui.cpp / dex_perf_ui.cpp.
///
/// Product UI: HTMX, server-rendered, dark-theme only, htmx core attrs only
/// (CSP blocks hx-on — plain onclick for navigation, allowed by 'unsafe-inline').
/// Reuses the shared `.gp-*` component CSS from the full-page shell, so no new CSS.
///
/// SLICE 1: the device list + the Device-info (CI-record) lens, over the live
/// registry. Fields not in the thin AgentInfo are NOT fabricated — the Hardware /
/// Network / Owner groups arrive with the inventory slice. The DEX/Guardian lenses
/// render an honest placeholder until their slices land.

#include "device_routes.hpp"

#include "dex_routes.hpp" // dex_signal_label for the DEX lens
#include "web_utils.hpp"

#include <cctype>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

namespace {

std::string esc(const std::string& s) { return html_escape(s); }

std::string url_encode(const std::string& s) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 0x0F];
        }
    }
    return out;
}

std::string os_label(const std::string& os) {
    if (os == "windows") return "Windows";
    if (os == "linux") return "Linux";
    if (os == "darwin" || os == "macos") return "macOS";
    return os.empty() ? std::string("&mdash;") : esc(os);
}

// A small online/offline status dot + word. Inline style (CSP allows style attrs)
// so it doesn't depend on dashboard-only CSS classes.
std::string status_cell(bool online) {
    const char* color = online ? "#4ed27e" : "#6f86a6";
    return "<span style=\"display:inline-block;width:.5rem;height:.5rem;border-radius:50%;"
           "background:" +
           std::string(color) + ";margin-right:.4rem\"></span>" +
           (online ? "<span style=\"color:#4ed27e\">online</span>"
                   : "<span class=\"gp-mute\">offline</span>");
}

// The per-device lens tab bar. Each tab hx-gets its lens fragment into #device-lens
// (the fragment re-renders this bar with its own tab active — the dex_subnav idiom,
// no JS, CSP-safe). `active` ∈ {"info","dex","guardian"}.
std::string device_lens_tabs(const std::string& active, const std::string& agent_id) {
    const std::string id = url_encode(agent_id);
    auto tab = [&](const char* key, const char* label, const std::string& frag) {
        const std::string on = (active == key) ? " on" : "";
        return "<a class=\"gp-chip" + on + "\" hx-get=\"" + frag + "?id=" + id +
               "\" hx-target=\"#device-lens\" hx-swap=\"innerHTML\">" + label + "</a>";
    };
    return "<div class=\"gp-filters\">" + tab("info", "Device info", "/fragments/device/info") +
           tab("dex", "DEX", "/fragments/device/dex") +
           tab("guardian", "Guardian", "/fragments/device/guardian") + "</div>";
}

// A toned DEX-score badge (green/amber/red by band); "—" when n/a (-1).
std::string score_badge(int score) {
    if (score < 0)
        return "<span class=\"gp-mute\">&mdash;</span>";
    const char* color = score >= 90 ? "#4ed27e" : (score >= 75 ? "#ffcc00" : "#ff5765");
    return "<span style=\"display:inline-block;min-width:1.7rem;text-align:center;font-weight:700;"
           "font-size:.68rem;border-radius:.3rem;padding:.05rem .4rem;color:#06121f;background:" +
           std::string(color) + "\">" + std::to_string(score) + "</span>";
}

// Guardian compliance-state badge: compliant=green, drifted=amber, errored=red.
std::string guard_state_badge(const std::string& state) {
    const char* color = state == "compliant" ? "#4ed27e"
                        : state == "errored"  ? "#ff5765"
                                              : "#ffcc00"; // drifted / anything else
    return "<span style=\"font-size:.6rem;font-weight:700;border-radius:.3rem;padding:.05rem .4rem;"
           "color:#06121f;background:" +
           std::string(color) + "\">" + esc(state.empty() ? "unknown" : state) + "</span>";
}

std::string ci_group(const std::string& title, const std::string& rows) {
    return "<div class=\"gp-tile\" style=\"min-width:240px;text-align:left\">"
           "<div class=\"l\" style=\"color:#a5d6ff;margin-bottom:.3rem\">" +
           esc(title) + "</div>" + rows + "</div>";
}
std::string kv(const std::string& k, const std::string& v) {
    return "<div style=\"display:flex;justify-content:space-between;gap:.8rem;font-size:.78rem;"
           "padding:.15rem 0;border-bottom:1px dotted #2d4068\"><span class=\"gp-mute\">" +
           esc(k) + "</span><span style=\"color:#cfdbe8\">" + v + "</span></div>";
}

} // namespace

std::string render_devices_list_fragment(const std::vector<DeviceRow>& rows, const std::string& q,
                                         const std::string& os_token,
                                         const std::string& status_token, std::size_t total_online,
                                         std::size_t total_devices) {
    const std::string qe = url_encode(q);
    // Build a filter-chip URL that keeps the OTHER params and sets one.
    auto url = [&](const std::string& os, const std::string& status) {
        return "/fragments/devices/list?q=" + qe + "&os=" + url_encode(os) + "&status=" +
               url_encode(status);
    };
    auto chip = [&](const std::string& cur, const std::string& val, const char* label,
                    const std::string& href) {
        const std::string on = (cur == val) ? " on" : "";
        return "<a class=\"gp-chip" + on + "\" hx-get=\"" + href +
               "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" + label + "</a>";
    };

    std::string h;
    // Summary tiles (slice 1: counts we can compute for real; at-risk/non-compliant
    // arrive with the DEX-score / Guardian slices).
    h += "<div class=\"gp-tiles\">";
    h += "<div class=\"gp-tile\"><div class=\"n\">" + std::to_string(total_devices) +
         "</div><div class=\"l\">Devices</div></div>";
    h += "<div class=\"gp-tile\"><div class=\"n\" style=\"color:#4ed27e\">" +
         std::to_string(total_online) + "</div><div class=\"l\">Online</div></div>";
    h += "</div>";

    // Controls. Search re-renders on Enter (avoids per-keystroke focus loss); the OS
    // and status chips re-render on click. All carry the current state in the URL.
    h += "<div class=\"gp-filters\" style=\"margin-top:.6rem\">"
         "<input name=\"q\" value=\"" +
         esc(q) +
         "\" placeholder=\"Search hostname, OS, tag\xE2\x80\xA6\" "
         "style=\"background:#0e1a2d;border:1px solid #2d4068;border-radius:.4rem;color:#cfdbe8;"
         "padding:.3rem .6rem;font-size:.78rem;min-width:240px\" "
         "hx-get=\"/fragments/devices/list?os=" +
         url_encode(os_token) + "&status=" + url_encode(status_token) +
         "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
         "hx-trigger=\"keyup[key=='Enter'], search\"></div>";
    h += "<div class=\"gp-filters\">";
    h += "<span class=\"gp-mute\" style=\"font-size:.66rem;align-self:center\">OS</span>";
    h += chip(os_token, "all", "All", url("all", status_token));
    h += chip(os_token, "windows", "Windows", url("windows", status_token));
    h += chip(os_token, "linux", "Linux", url("linux", status_token));
    h += chip(os_token, "macos", "macOS", url("macos", status_token));
    h += "<span class=\"gp-mute\" style=\"font-size:.66rem;align-self:center;margin-left:.6rem\">"
         "Status</span>";
    h += chip(status_token, "all", "All", url(os_token, "all"));
    h += chip(status_token, "online", "Online", url(os_token, "online"));
    h += chip(status_token, "offline", "Offline", url(os_token, "offline"));
    h += "</div>";

    if (rows.empty()) {
        h += "<div class=\"gp-placeholder\"><b>No devices match</b>Broaden the search or filters.</div>";
        return h;
    }

    h += "<table class=\"gp-table\"><thead><tr><th>Device</th><th>Status</th><th>DEX</th><th>OS</th>"
         "<th>Version</th><th>Last seen</th></tr></thead><tbody>";
    for (const auto& d : rows) {
        const std::string label = d.hostname.empty() ? d.agent_id : d.hostname;
        std::string tagline = esc(d.agent_id.substr(0, 12));
        if (!d.segment.empty())
            tagline += " &middot; " + esc(d.segment);
        h += "<tr class=\"gp-rowlink\" style=\"cursor:pointer\" "
             "onclick=\"location.href='/device?id=" +
             url_encode(d.agent_id) + "'\">";
        h += "<td><a href=\"/device?id=" + url_encode(d.agent_id) +
             "\" style=\"font-weight:600;color:#fff\">" + esc(label) +
             "</a><div class=\"gp-mute\" style=\"font-size:.66rem\">" + tagline + "</div></td>";
        h += "<td>" + status_cell(d.online) + "</td>";
        h += "<td>" + score_badge(d.dex_score) + "</td>";
        h += "<td class=\"gp-mute\">" + os_label(d.os) + "/" + esc(d.arch) + "</td>";
        h += "<td class=\"gp-mute\">" + (d.agent_version.empty() ? std::string("&mdash;")
                                                                 : esc(d.agent_version)) +
             "</td>";
        h += "<td class=\"gp-mute\">" + (d.last_seen.empty() ? std::string("&mdash;")
                                                             : esc(d.last_seen)) +
             "</td>";
        h += "</tr>";
    }
    h += "</tbody></table>";
    h += "<div class=\"gp-note\">Showing <b>" + std::to_string(rows.size()) +
         "</b> matching device(s). At fleet scale this is server-paginated &amp; virtualized; "
         "a row opens the device page (Device info &middot; DEX &middot; Guardian).</div>";
    return h;
}

std::string render_device_info_fragment(const DeviceRow& d) {
    std::string tags;
    for (std::size_t i = 0; i < d.tags.size(); ++i)
        tags += (i ? ", " : "") + esc(d.tags[i]);
    if (tags.empty())
        tags = "<span class=\"gp-mute\">none</span>";

    std::string h = device_lens_tabs("info", d.agent_id);
    h += "<div class=\"gp-tiles\" style=\"align-items:stretch\">";
    h += ci_group("Identity", kv("Hostname", esc(d.hostname.empty() ? "&mdash;" : d.hostname)) +
                                  kv("Agent ID", "<span style=\"font-family:var(--mono),Consolas,"
                                                 "monospace;font-size:.7rem\">" +
                                                     esc(d.agent_id) + "</span>") +
                                  kv("OS", os_label(d.os)) +
                                  kv("Architecture", esc(d.arch.empty() ? "&mdash;" : d.arch)));
    h += ci_group("Management",
                  kv("Segment", d.segment.empty() ? std::string("<span class=\"gp-mute\">&mdash;"
                                                                "</span>")
                                                  : esc(d.segment)) +
                      kv("Tags", tags) +
                      kv("Agent version", d.agent_version.empty() ? std::string("&mdash;")
                                                                  : esc(d.agent_version)) +
                      kv("Status", d.online ? "<span style=\"color:#4ed27e\">online</span>"
                                            : "<span class=\"gp-mute\">offline</span>") +
                      kv("Last seen", d.last_seen.empty() ? std::string("&mdash;")
                                                          : esc(d.last_seen)));
    h += "</div>";
    h += "<div class=\"gp-note\">Hardware, network (IP/MAC) and ownership are <b>not in the agent's "
         "registration</b> today &mdash; they arrive with the inventory slice (collector / "
         "custom-properties / CMDB sync), not fabricated here.</div>";
    return h;
}

std::string render_device_lens_placeholder(const std::string& active, const std::string& agent_id,
                                           const std::string& message) {
    return device_lens_tabs(active, agent_id) +
           "<div class=\"gp-placeholder\"><b>Coming in a later slice</b>" + esc(message) + "</div>";
}

std::string render_device_dex_lens(const std::string& agent_id, int score,
                                   const std::vector<std::pair<std::string, std::int64_t>>& signals) {
    std::string h = device_lens_tabs("dex", agent_id);
    h += "<div class=\"gp-tiles\"><div class=\"gp-tile\">";
    if (score < 0)
        h += "<div class=\"n\">&mdash;</div>";
    else
        h += "<div class=\"n " + std::string(score >= 90 ? "good" : "warn") + "\">" +
             std::to_string(score) + "</div>";
    h += "<div class=\"l\">DEX experience</div><div class=\"sx\">last 7 days</div></div></div>";
    if (signals.empty()) {
        h += "<div class=\"gp-placeholder\"><b>No DEX signals</b>Nothing fired on this device in "
             "the window &mdash; experience is clean.</div>";
    } else {
        h += "<div class=\"gp-sech\">Signals (this device, 7d)</div>";
        h += "<table class=\"gp-table\"><thead><tr><th>Signal</th><th>Type</th>"
             "<th class=\"gp-num\">Events</th></tr></thead><tbody>";
        for (const auto& [obs, count] : signals)
            h += "<tr><td>" + dex_signal_label(obs) +
                 "</td><td class=\"gp-mute\" style=\"font-family:Consolas,monospace;font-size:.7rem\">" +
                 esc(obs) + "</td><td class=\"gp-num\">" + std::to_string(count) + "</td></tr>";
        h += "</tbody></table>";
    }
    h += "<div class=\"gp-note\"><button class=\"gp-btn\" hx-get=\"/fragments/dex/device?id=" +
         url_encode(agent_id) +
         "\" hx-target=\"#device-lens\" hx-swap=\"innerHTML\">Load full DEX history</button> "
         "<span class=\"gp-mute\">crash detail, OS split, on-device perf</span></div>";
    return h;
}

std::string render_device_guardian_lens(const std::string& agent_id,
                                        const std::vector<DeviceGuardRow>& guards) {
    std::string h = device_lens_tabs("guardian", agent_id);
    if (guards.empty()) {
        h += "<div class=\"gp-placeholder\"><b>No guards evaluated</b>No Guardian guards have been "
             "evaluated on this device yet.</div>";
        return h;
    }
    int compliant = 0;
    for (const auto& g : guards)
        if (g.state == "compliant")
            ++compliant;
    const int pct = static_cast<int>(100.0 * compliant / static_cast<double>(guards.size()) + 0.5);
    h += "<div class=\"gp-tiles\"><div class=\"gp-tile\"><div class=\"n " +
         std::string(pct >= 100 ? "good" : "warn") + "\">" + std::to_string(pct) +
         "%</div><div class=\"l\">Compliant</div><div class=\"sx\">" + std::to_string(compliant) +
         " of " + std::to_string(guards.size()) + " guards</div></div></div>";
    h += "<div class=\"gp-sech\">Guards on this device</div>";
    h += "<table class=\"gp-table\"><thead><tr><th>Guard</th><th>State</th><th>Last evaluated</th>"
         "</tr></thead><tbody>";
    for (const auto& g : guards)
        h += "<tr><td class=\"name\">" + esc(g.name) + "</td><td>" + guard_state_badge(g.state) +
             "</td><td class=\"gp-mute\">" + esc(g.updated_at) + "</td></tr>";
    h += "</tbody></table>";
    h += "<div class=\"gp-note\">Per-guard state from "
         "<span style=\"font-family:Consolas,monospace\">guardian_agent_rule_status</span>. "
         "Baseline grouping + a live re-evaluate are follow-ups.</div>";
    return h;
}

std::string render_device_page(const DeviceRow& d) {
    const std::string label = d.hostname.empty() ? d.agent_id : d.hostname;
    std::string h = "<a class=\"gp-back\" href=\"/devices\">&larr; Devices</a>";
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>" + esc(label) +
         "</h1></div><div class=\"gp-sub\">" + os_label(d.os) + "/" + esc(d.arch) + " &middot; " +
         status_cell(d.online) + " &middot; DEX experience " + score_badge(d.dex_score) +
         "</div></div>";
    // Cross-cutting live-info action — when the device is online, dispatch a live
    // read-only query to it and render the result. Reuses the existing, proven
    // /fragments/dex/device/perf path (GuaranteedState:Read + Execution:Execute,
    // audited dex.device.perf.query, machine-health $Perf query) — NO new dispatch
    // or surveillance surface; it inherits that gating. Offline → disabled.
    if (d.online) {
        const std::string e = url_encode(d.agent_id);
        h += "<div><button class=\"gp-btn\" hx-get=\"/fragments/dex/device/perf?agent_id=" + e +
             "\" hx-target=\"#device-live\" hx-swap=\"innerHTML\">\xE2\x9A\xA1 Get live info</button>"
             " <span class=\"gp-mute\" style=\"font-size:.66rem\">live read-only query on the "
             "device &middot; Execute-gated &middot; audited</span></div>";
    } else {
        h += "<div><button class=\"gp-btn\" disabled>\xE2\x9A\xA1 Get live info</button>"
             " <span class=\"gp-mute\" style=\"font-size:.66rem\">device offline</span></div>";
    }
    h += "</div>";                       // close gp-head
    h += "<div id=\"device-live\"></div>"; // live-snapshot mount (cross-lens)
    h += "<div id=\"device-lens\">" + render_device_info_fragment(d) + "</div>";
    return h;
}

std::string render_device_not_found(const std::string& agent_id) {
    return "<a class=\"gp-back\" href=\"/devices\">&larr; Devices</a>"
           "<div class=\"gp-placeholder\"><b>Device not found</b>No enrolled device with id " +
           esc(agent_id) + ".</div>";
}

} // namespace yuzu::server
