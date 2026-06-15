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
         "</h1></div><div class=\"gp-sub\">Device / <b>local-link</b> health, measured on each "
         "endpoint from kernel counters (no packet capture, no flow export) and rolled up across the "
         "fleet. The retransmit figure is an <b>interval rate</b> (loss in the last few minutes, not a "
         "lifetime average) &mdash; a bad local link drives loss across every connection, so the "
         "device aggregate flags it cleanly. This is a <b>measurement, not a verdict</b>: a "
         "<i>degraded</i> classification (and the device/app co-occurrence it gates) needs a "
         "real-fleet baseline to calibrate, and <i>localization</i> &mdash; is it the network, the "
         "device, or the app? &mdash; needs the per-destination drill; both are later slices.</div>"
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
    h += "<div class=\"gp-note\"><b>Linux</b> reports these from netlink "
         "<span style=\"font-family:var(--mono)\">TCP_INFO</span> + "
         "<span style=\"font-family:var(--mono)\">/proc/net/dev</span>; <b>Windows and macOS emit "
         "nothing yet</b> (their collectors are later slices), so this reflects the Linux fleet. "
         "<b>Retransmission</b> is an interval rate &mdash; &Delta;retransmits / &Delta;segments "
         "smoothed over the last few heartbeats (the lifetime ratio is diluted to noise; the interval "
         "delta cleanly recovers the real rate). <b>RTT is coarse</b> &mdash; a device-aggregate "
         "median blended across loopback/LAN/internet connections (a rough signal, not per-flow "
         "truth; per-destination latency is a later slice). Absent is never averaged in as zero. "
         "Same numbers as the "
         "<span style=\"font-family:var(--mono)\">yuzu_fleet_net_*</span> gauges.</div>";

    // ── Measurement-first: degraded classification + co-occurrence deferred ──
    // The disproven absolute-ratio `degraded` boolean was retired; the interval
    // rate above is empirically sound (separates 0%/4%/12% netem loss), but a
    // hard degraded THRESHOLD needs real-fleet baseline data to calibrate (real
    // internet paths retransmit ~0.5-2% while perfectly healthy — a loopback-
    // calibrated threshold would cry wolf). So v1 ships the measurement; the
    // degraded classification and the device/app co-occurrence it gates are a
    // later slice. The NetCooccurrence model stays wired but unfed.
    h += "<div class=\"gp-sech\">Where the pain is &mdash; co-occurrence "
         "<span class=\"gp-mute\">(later slice)</span></div>";
    h += "<div class=\"gp-note\"><b>Measurement-first.</b> v1 surfaces the interval retransmit rate as "
         "evidence; it does <b>not</b> yet classify a device as <i>network-degraded</i>. A trustworthy "
         "threshold needs a real-fleet baseline (healthy internet links retransmit a little, so the "
         "cutoff can&rsquo;t be guessed), and the device/app co-occurrence headline &mdash; the "
         "<i>where the pain is</i> view &mdash; is gated on that classification. Both land once there "
         "is baseline data to calibrate against. Until then this page is honest evidence, not a "
         "verdict.</div>";
    return h;
}

std::string render_network_devices_fragment(const NetPerfSnapshot& snap, NetPerfMetric metric,
                                            bool not_reporting, NetCoocFilter cooc,
                                            const std::optional<std::string>& cohort_filter,
                                            int limit) {
    const auto rows = net_perf_device_list(snap, metric, not_reporting, cooc, cohort_filter, limit);

    // Reverse of net_perf_metric_from_token — preserve the metric across the
    // cohort picker / cohort-value drill so switching cohort keeps the column.
    const char* metric_token = metric == NetPerfMetric::kRetrans      ? "retrans"
                               : metric == NetPerfMetric::kThroughput ? "throughput"
                                                                      : "rtt";

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

    // ── Cohort key picker ── narrows the list to one operator-chosen tag key's
    // values (mirror dex_perf_ui). available_keys is server-resolved from the
    // TagStore; htmx submits the select's own name=value on change, re-rendering
    // this fragment with ?key=<chosen> (metric preserved). Only the key param is
    // exposed here; the cohort_value filter is reached by drilling a Cohort cell.
    if (!snap.available_keys.empty()) {
        h += "<div class=\"gp-note\">cohort by tag key: <select name=\"key\" "
             "hx-get=\"/fragments/network/devices?metric=" +
             std::string(metric_token) +
             "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" hx-trigger=\"change\" "
             "style=\"background:var(--surface);color:var(--fg);border:1px solid var(--border);"
             "border-radius:.35rem;padding:.15rem .4rem;\">";
        h += "<option value=\"\"" + std::string(snap.cohort_key.empty() ? " selected" : "") +
             ">(none)</option>";
        bool key_listed = false;
        for (const auto& k : snap.available_keys) {
            const bool on = (k == snap.cohort_key);
            key_listed = key_listed || on;
            h += "<option value=\"" + esc(k) + "\"" + (on ? " selected" : "") + ">" + esc(k) +
                 "</option>";
        }
        if (!key_listed && !snap.cohort_key.empty()) // requested key has no tagged devices — honest
            h += "<option value=\"" + esc(snap.cohort_key) + "\" selected>" + esc(snap.cohort_key) +
                 " (no devices tagged)</option>";
        h += "</select></div>";
    }

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
        // Cohort cell: "—" until a key is chosen (the dimension is undefined),
        // then the resolved value as a drill that filters to that cohort_value.
        std::string cohort_cell;
        if (snap.cohort_key.empty()) {
            cohort_cell = "<span class=\"gp-mute\">&mdash;</span>";
        } else {
            const std::string qs = "key=" + url_encode(snap.cohort_key) +
                                   "&amp;cohort_value=" + url_encode(r.cohort) +
                                   "&amp;metric=" + metric_token;
            cohort_cell = drill("/fragments/network/devices?" + qs,
                                r.cohort.empty() ? std::string("(untagged)") : esc(r.cohort));
        }
        h += "<tr><td class=\"gp-mute\">" + std::to_string(i++) + "</td><td>" +
             drill("/fragments/dex/device?id=" + url_encode(r.agent_id), esc(r.agent_id)) +
             "</td><td>" + cohort_cell + "</td><td>" + cell(r.rtt_ms, Unit::kMs) +
             "</td><td>" + cell(r.retrans_pct, Unit::kPct) +
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
