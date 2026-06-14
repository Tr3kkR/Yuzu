/// @file network_ui.cpp
/// /network dashboard renderers — PURE functions over a NetPerfSnapshot
/// (fleet-now quality cards + the co-occurrence headline + the one devices
/// drill). Split from network_routes.cpp (which registers the routes) to keep
/// each TU small; the tiny markup helpers are deliberately re-declared in this
/// TU's anonymous namespace, same pattern as dex_perf_ui.cpp.
///
/// Product UI: HTMX, server-rendered, dark-theme only, htmx core attrs only
/// (CSP blocks hx-on). Honesty: absent metrics render "—" (never 0); every
/// aggregate carries its reporting population; RTT carries its OWN denominator
/// (Linux reports smoothed RTT; Windows is coarser/absent pending the spike).
/// The page shows EVIDENCE + measured CO-OCCURRENCE — never a blame verdict.

#include "network_routes.hpp"

#include "web_utils.hpp"

#include <cctype>
#include <format>
#include <string>
#include <vector>

namespace yuzu::server {

namespace {

std::string esc(const std::string& s) { return html_escape(s); }

// Percent-encode for a query-string value (RFC 3986 unreserved kept literal).
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

std::string placeholder(const std::string& title, const std::string& sub) {
    return "<div class=\"gp-placeholder\"><b>" + esc(title) + "</b>" + esc(sub) + "</div>";
}

// A drill anchor: hx-get the fragment into the shared page mount (#guardian-detail).
std::string drill(const std::string& path_qs, const std::string& disp) {
    return "<a hx-get=\"" + path_qs + "\" hx-target=\"#guardian-detail\" "
           "hx-swap=\"innerHTML\" style=\"cursor:pointer;\">" + disp + "</a>";
}

std::string fmt_ms(double v) { return std::format("{:.0f} ms", v); }
std::string fmt_pct(double v) { return std::format("{:.1f}%", v); }

// "3.1 MB/s" / "420 KB/s" human form for a bytes/second rate.
std::string fmt_bps(double b) {
    if (b >= 1024.0 * 1024.0)
        return std::format("{:.1f} MB/s", b / (1024.0 * 1024.0));
    if (b >= 1024.0)
        return std::format("{:.0f} KB/s", b / 1024.0);
    return std::format("{:.0f} B/s", b);
}

enum class Unit { kMs, kPct, kBps };
std::string fmt_val(double v, Unit u) {
    switch (u) {
    case Unit::kPct:
        return fmt_pct(v);
    case Unit::kBps:
        return fmt_bps(v);
    case Unit::kMs:
    default:
        return fmt_ms(v);
    }
}

std::string stat_strip(const NetPerfStat& s, Unit u) {
    return "p50 " + fmt_val(s.p50, u) + " &middot; p90 " + fmt_val(s.p90, u) + " &middot; max " +
           fmt_val(s.max, u);
}

/// One clickable fleet-now card. `big` is pre-formatted; `strip` pre-built.
std::string fleet_card(const std::string& big, const char* label, const std::string& strip,
                       const std::string& drill_qs, const char* drill_label) {
    return "<div class=\"gp-tile\"><div class=\"n\">" + big + "</div><div class=\"l\">" +
           std::string(label) + "</div><div class=\"sx\">" + strip + "<br>" +
           drill("/fragments/network/devices?" + drill_qs, std::string("&rarr; ") + drill_label) +
           "</div></div>";
}

std::string cell(const std::optional<double>& v, Unit u) {
    return v ? fmt_val(*v, u) : std::string("<span class=\"gp-mute\">&mdash;</span>");
}

} // namespace

// Shared /network sub-nav (declared in network_routes.hpp).
std::string network_subnav(const std::string& active) {
    auto tab = [&](const char* id, const char* label, const char* frag) {
        const std::string on = (active == id) ? " class=\"on\"" : "";
        return "<a" + on + " hx-get=\"" + frag +
               "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" + label + "</a>";
    };
    return "<div class=\"gp-subnav\">" +
           tab("overview", "Overview", "/fragments/network/overview") +
           tab("devices", "Devices", "/fragments/network/devices") + "</div>";
}

std::string render_network_overview_fragment(const NetPerfSnapshot& snap) {
    const auto now = net_perf_fleet_now(snap);

    std::string h;
    h += "<a class=\"gp-back\" href=\"/\">&larr; Dashboard</a>";
    h += network_subnav("overview");
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>Network quality &mdash; fleet"
         "</h1></div><div class=\"gp-sub\">Per-connection quality measured on each endpoint from "
         "kernel counters (no packet capture, no flow export), rolled up across the fleet. The "
         "headline is <b>where the pain is</b>: because network quality lives in the same on-device "
         "warehouse as CPU/disk and process events, we can show whether a degraded device "
         "<i>co-occurs</i> with a device or app problem &mdash; a network-only tool can&rsquo;t.</div>"
         "</div></div>";

    // ── Fleet now ──
    h += "<div class=\"gp-sech\">Fleet now (last heartbeat cycle)</div>";
    if (now.reporting == 0) {
        h += placeholder("No network telemetry yet",
                         "No device reported a network sample this cycle. Devices appear here within "
                         "a heartbeat of coming online (and of network collection being enabled).");
        return h;
    }
    h += "<div class=\"gp-tiles\">";
    if (now.rtt)
        h += fleet_card(fmt_ms(now.rtt->p50), "Round-trip time (p50)", stat_strip(*now.rtt, Unit::kMs),
                        "metric=rtt", "worst devices by RTT");
    if (now.retrans)
        h += fleet_card(fmt_pct(now.retrans->p50), "TCP retransmission (p50)",
                        stat_strip(*now.retrans, Unit::kPct), "metric=retrans",
                        "worst devices by retransmit");
    if (now.throughput)
        h += fleet_card(fmt_bps(now.throughput->p50), "Throughput (device, p50)",
                        stat_strip(*now.throughput, Unit::kBps), "metric=throughput",
                        "busiest devices");
    h += fleet_card(std::to_string(now.reporting), "Reporting",
                    "of " + std::to_string(now.online) + " online &middot; " +
                        std::to_string(now.rtt_reporting) + " report smoothed RTT",
                    "filter=not_reporting", "devices not reporting");
    h += "</div>";
    h += "<div class=\"gp-note\"><b>Linux</b> reports the full per-connection tier (smoothed RTT, "
         "retransmits, loss) from netlink <span style=\"font-family:var(--mono)\">TCP_INFO</span>; "
         "<b>Windows</b> reports retransmit/loss today &mdash; smoothed RTT is coarser/absent pending "
         "the ESTATS-vs-ETW spike, so the RTT card carries its own (smaller) reporting denominator. "
         "Absent is never averaged in as zero. The same numbers are exported as the "
         "<span style=\"font-family:var(--mono)\">yuzu_fleet_net_*</span> Prometheus gauges.</div>";

    // ── Co-occurrence headline ──
    h += "<div class=\"gp-sech\">Where the pain is &mdash; co-occurrence "
         "<span class=\"gp-mute\">(measured, not blamed)</span></div>";
    if (now.cooc.degraded == 0) {
        h += "<div class=\"gp-note\">No device is currently flagged network-degraded.</div>";
    } else {
        auto band = [&](const char* token, const std::string& label, int64_t n) {
            return "<tr><td>" +
                   drill("/fragments/network/devices?cooc=" + std::string(token), label) +
                   "</td><td style=\"text-align:right\">" + std::to_string(n) + "</td></tr>";
        };
        h += "<div class=\"gp-note\"><b>" + std::to_string(now.cooc.degraded) +
             "</b> devices show degraded network quality. Of those, what <i>else</i> is happening on "
             "the same box right now:</div>";
        h += "<table class=\"gp-table\"><tbody>";
        h += band("device", "&hellip; also under <b>device</b> perf pressure (CPU/mem/disk)",
                  now.cooc.also_device);
        // "no device-perf pressure" is what this band actually measures while the
        // app dimension is unwired — NOT "network stands alone" (that would
        // overstate it, since app instability isn't measured yet).
        h += band("network_only", "&hellip; no device-perf pressure", now.cooc.network_only);
        // App correlation (the DEX crash/hang join) lands with the per-connection
        // collector slice — render it as PENDING, never a confident 0, so the
        // panel can't overstate the network-standalone population.
        h += "<tr><td><span class=\"gp-mute\">&hellip; also showing <b>app</b> instability "
             "(crash/hang)</span></td><td style=\"text-align:right\">"
             "<span class=\"gp-mute\">pending</span></td></tr>";
        h += "</tbody></table>";
        h += "<div class=\"gp-note\"><b>This is counting, not blaming.</b> &ldquo;Also under device "
             "pressure&rdquo; means the two facts co-occur on the same box at the same time &mdash; "
             "not a verdict that the device <i>caused</i> the slowness (memory pressure can look like "
             "a network fault). The causal verdict is a deliberate overlay; v1 ships the evidence. "
             "<b>App-instability co-occurrence is pending</b> &mdash; it arrives with the per-connection "
             "collector; until then a degraded device with no device-perf pressure is shown as exactly "
             "that, not asserted to be network-only.</div>";
    }
    return h;
}

std::string render_network_devices_fragment(const NetPerfSnapshot& snap, NetPerfMetric metric,
                                            bool not_reporting, NetCoocFilter cooc,
                                            const std::optional<std::string>& cohort_filter,
                                            int limit) {
    const auto rows = net_perf_device_list(snap, metric, not_reporting, cooc, cohort_filter, limit);

    std::string title;
    if (not_reporting)
        title = "Devices not reporting network";
    else if (cooc == NetCoocFilter::kAlsoDevice)
        title = "Degraded &mdash; also under device perf pressure";
    else if (cooc == NetCoocFilter::kAlsoApp)
        title = "Degraded &mdash; also showing app instability";
    else if (cooc == NetCoocFilter::kNetworkOnly)
        title = "Degraded &mdash; network signal stands alone";
    else if (cooc == NetCoocFilter::kDegradedAll)
        title = "Network-degraded devices";
    else if (cohort_filter)
        title = (cohort_filter->empty() ? "(untagged)" : esc(*cohort_filter)) +
                std::string(" &mdash; devices");
    else {
        const char* m = metric == NetPerfMetric::kRetrans      ? "retransmit"
                        : metric == NetPerfMetric::kThroughput ? "throughput"
                                                               : "RTT";
        title = std::string("Worst devices by ") + m;
    }

    std::string h;
    h += "<a class=\"gp-back\" hx-get=\"/fragments/network/overview\" hx-target=\"#guardian-detail\" "
         "hx-swap=\"innerHTML\" style=\"cursor:pointer;\">&larr; Network quality</a>";
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>" + title +
         "</h1></div><div class=\"gp-sub\">Values are each device&rsquo;s current heartbeat sample "
         "&mdash; the same data the fleet cards aggregate. The device/app flags are <b>measured "
         "co-occurrence</b>, shown so the correlation is visible at a glance &mdash; never a "
         "verdict.</div></div></div>";

    if (rows.empty())
        return h + placeholder(not_reporting ? "Everyone is reporting" : "No devices",
                               not_reporting
                                   ? "Every online agent contributed a network sample this cycle."
                                   : "No reporting devices match this view.");

    h += "<table class=\"gp-table\"><thead><tr><th>#</th><th>Device</th><th>Cohort</th><th>RTT</th>"
         "<th>Retransmit</th><th>Throughput</th><th>Device pressure</th><th>App</th>"
         "<th>vs fleet</th></tr></thead><tbody>";
    int i = 1;
    for (const auto& r : rows) {
        const std::string flag_dev =
            r.under_pressure ? "<b style=\"color:var(--yellow,#ffcc00)\">device &#9679;</b>"
                             : "<span class=\"gp-mute\">&mdash;</span>";
        const std::string flag_app =
            r.app_unstable ? "<b style=\"color:#c98bff\">app &#9679;</b>"
                           : "<span class=\"gp-mute\">&mdash;</span>";
        h += "<tr><td class=\"gp-mute\">" + std::to_string(i++) + "</td><td>" +
             drill("/fragments/dex/device?id=" + url_encode(r.agent_id), esc(r.agent_id)) +
             "</td><td>" +
             (r.cohort.empty() ? "<span class=\"gp-mute\">(untagged)</span>" : esc(r.cohort)) +
             "</td><td>" + cell(r.rtt_ms, Unit::kMs) + "</td><td>" + cell(r.retrans_pct, Unit::kPct) +
             "</td><td>" + cell(r.throughput_bps, Unit::kBps) + "</td><td>" + flag_dev + "</td><td>" +
             flag_app + "</td><td>" +
             (r.fleet_pctile >= 0 ? std::to_string(r.fleet_pctile) + "th pctile"
                                  : std::string("<span class=\"gp-mute\">&mdash;</span>")) +
             "</td></tr>";
    }
    h += "</tbody></table>";
    return h;
}

} // namespace yuzu::server
