/// @file dex_app_perf_ui.cpp
/// Slice-2 dashboard renderers for DEX app-perf-over-time — the app picker + the
/// per-(app,version) trend table (fleet B2 or named-group B1). PURE functions over
/// the reduced model (`app_perf_version_summaries`), so the HTMX surface, the REST
/// endpoints, and the MCP tools all read the SAME numbers.
///
/// Product UI: HTMX, server-rendered, dark-theme only, htmx core attrs only (CSP
/// blocks hx-on). Sparklines are server-rendered SVG — no client JS. Reuses the
/// shared full-page shell's `.gp-*` component CSS (guardian_page_ui.cpp), same as
/// the sibling DEX renderers. Honesty: absent percentiles render "—" (never 0),
/// an open-top-bucket percentile renders "≥ value" (a floor), a sub-floor named-
/// group point shows its count only. Crashes/hangs per version are DEFERRED in v1
/// (a separate central crash-store join) — the foot notes the gap.

#include "dex_app_perf_ui.hpp"

#include "web_utils.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <format>
#include <string>
#include <vector>

namespace yuzu::server {

// Shared with dex_routes.cpp (declared in dex_routes.hpp).
std::string dex_window_token(int window_days);

namespace {

std::string esc(const std::string& s) { return html_escape(s); }

// Percent-encode for a query-string value (RFC 3986 unreserved kept literal) —
// same helper the sibling DEX renderers carry in their anonymous namespaces.
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

std::string drill(const std::string& path_qs, const std::string& disp) {
    return "<a hx-get=\"" + path_qs +
           "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" style=\"cursor:pointer;\">" +
           disp + "</a>";
}

std::string fmt_pct(double v) { return std::format("{:.1f}%", v); }

// "1.9 GB" / "390 MB" human form for a working-set byte count.
std::string fmt_bytes(double b) {
    if (b >= 1024.0 * 1024.0 * 1024.0)
        return std::format("{:.1f} GB", b / (1024.0 * 1024.0 * 1024.0));
    if (b >= 1024.0 * 1024.0)
        return std::format("{:.0f} MB", b / (1024.0 * 1024.0));
    return std::format("{:.0f} KB", b / 1024.0);
}

// A UTC-midnight epoch-seconds day → "YYYY-MM-DD" (std::chrono, no global gmtime).
std::string ymd(std::int64_t day_epoch_s) {
    using namespace std::chrono;
    const sys_days d = floor<days>(sys_seconds{seconds{day_epoch_s}});
    const year_month_day cal{d};
    return std::format("{:04}-{:02}-{:02}", static_cast<int>(cal.year()),
                       static_cast<unsigned>(cal.month()), static_cast<unsigned>(cal.day()));
}

// p95 cell: "≥X%" when the value is an open-top-bucket floor, "X%" otherwise,
// "—" when withheld (empty population OR a stale histogram scheme).
std::string pctile_cell(const std::optional<HistPctile>& p) {
    if (!p)
        return "&mdash;";
    return (p->lower_bound ? "&ge;&nbsp;" : "") + fmt_pct(p->value);
}

// Server-rendered, CSP-safe sparkline over a daily series. < 2 points → em dash.
std::string spark(const std::vector<double>& vals) {
    if (vals.size() < 2)
        return "<span class=\"gp-mute\">&mdash;</span>";
    constexpr double w = 110, h = 22, p = 2;
    const double mn = *std::min_element(vals.begin(), vals.end());
    const double mx = *std::max_element(vals.begin(), vals.end());
    const double rng = (mx - mn) > 1e-9 ? (mx - mn) : 1.0;
    std::string pts;
    for (std::size_t i = 0; i < vals.size(); ++i) {
        const double x = p + static_cast<double>(i) * (w - 2 * p) /
                                 static_cast<double>(vals.size() - 1);
        const double y = h - p - (vals[i] - mn) / rng * (h - 2 * p);
        pts += std::format("{:.1f},{:.1f} ", x, y);
    }
    return "<svg width=\"110\" height=\"22\"><polyline fill=\"none\" stroke=\"#58a6ff\" "
           "stroke-width=\"1.5\" points=\"" + pts + "\"/></svg>";
}

} // namespace

std::string render_dex_app_perf_picker(const std::vector<AppPerfAppSummary>& apps, bool truncated,
                                       int window_days) {
    const std::string w = dex_window_token(window_days);
    std::string h;
    h += "<a class=\"gp-back\" hx-get=\"/fragments/dex/perf?window=" + w +
         "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
         "style=\"cursor:pointer;\">&larr; Fleet performance</a>";
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>Application performance "
         "over time</h1></div><div class=\"gp-sub\">Per-application CPU &amp; memory across the "
         "fleet, broken out by version, over the retained window. Pick an application to compare "
         "its versions.</div></div></div>";

    if (apps.empty())
        return h + placeholder("No application performance history yet",
                               "Per-application performance roll-ups appear here once devices "
                               "report retained daily summaries. Per-application sampling is "
                               "opt-in (procperf_enabled, off by default) — enable it on the "
                               "devices you want to track.");

    h += "<table class=\"gp-table\"><thead><tr><th>Application</th><th>Versions seen</th>"
         "<th>Last reported</th></tr></thead><tbody>";
    for (const auto& a : apps) {
        h += "<tr><td>" +
             drill("/fragments/dex/perf/app?app=" + url_encode(a.app_name) + "&amp;window=" + w,
                   esc(a.app_name)) +
             "</td><td>" + std::to_string(a.versions) + "</td><td>" + ymd(a.last_day) +
             "</td></tr>";
    }
    h += "</tbody></table>";
    if (truncated)
        h += "<div class=\"gp-note\">List capped &mdash; more applications have history than "
             "shown. Use the REST API (<span style=\"font-family:var(--mono)\">"
             "/api/v1/dex/perf/apps</span>) for the full set.</div>";
    h += "<div class=\"gp-note\">Aggregate roll-up of small daily per-device summaries "
         "(ADR-0004) &mdash; the raw per-process stream never leaves the device. Per-version "
         "crashes/hangs are a planned enrichment (a separate central crash store).</div>";
    return h;
}

std::string render_dex_app_perf_trend(const std::string& app_name,
                                      const std::vector<AppPerfVersionSummary>& versions,
                                      const std::string& scope_group_id,
                                      const std::vector<DexGroupOption>& groups,
                                      std::int64_t group_floor, int window_days) {
    const std::string w = dex_window_token(window_days);
    const bool is_group = !scope_group_id.empty();
    std::string h;
    h += "<a class=\"gp-back\" hx-get=\"/fragments/dex/perf/apps?window=" + w +
         "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
         "style=\"cursor:pointer;\">&larr; All applications</a>";

    // Header. The scope is named in the subtitle so a group rollup is never
    // mistaken for the fleet aggregate.
    std::string scope_name = "the whole fleet";
    if (is_group) {
        scope_name = "a management group";
        for (const auto& g : groups)
            if (g.id == scope_group_id) {
                scope_name = esc(g.name);
                break;
            }
    }
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>" + esc(app_name) +
         " <span class=\"gp-mute\" style=\"font-weight:400;font-size:.85rem\">&mdash; by version, "
         "over time</span></h1></div><div class=\"gp-sub\">CPU &amp; memory per version across <b>" +
         scope_name + "</b>. Each row's trend is the daily mean over the retained history; the "
         "headline is the most recent day.</div></div></div>";

    // -- Scope selector (CSP-safe: htmx hx-get on change sends the select's
    // name=value, appended to the URL query — the proven cohort-picker idiom).
    if (!groups.empty()) {
        const std::string base = "/fragments/dex/perf/app?app=" + url_encode(app_name) +
                                 "&amp;window=" + w;
        h += "<div class=\"gp-note\">Scope: <select name=\"group\" hx-get=\"" + base +
             "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" hx-trigger=\"change\" "
             "style=\"background:var(--surface);color:var(--fg);border:1px solid var(--border);"
             "border-radius:.35rem;padding:.15rem .4rem;\">";
        h += "<option value=\"\"" + std::string(is_group ? "" : " selected") +
             ">Whole fleet</option>";
        for (const auto& g : groups) {
            const bool on = (g.id == scope_group_id);
            h += "<option value=\"" + esc(g.id) + "\"" + (on ? " selected" : "") + ">" +
                 esc(g.name) + "</option>";
        }
        h += "</select></div>";
    }

    if (versions.empty())
        return h + placeholder("No performance history for this application",
                               is_group ? "No member of this group reported retained performance "
                                          "for this application in the window."
                                        : "No device reported retained performance for this "
                                          "application in the window.");

    // The version with the most recent day is tagged "latest" (a factual cue, not
    // a verdict) — compute the max latest_day once.
    std::int64_t newest = 0;
    for (const auto& v : versions)
        newest = (std::max)(newest, v.latest_day);

    h += "<table class=\"gp-table\"><thead><tr><th>Version</th><th>Avg CPU</th><th>p95 CPU</th>"
         "<th>CPU trend</th><th>Avg working set</th><th>Devices</th></tr></thead><tbody>";
    for (const auto& v : versions) {
        const std::string tag =
            (v.latest_day == newest && versions.size() > 1)
                ? " <span style=\"font-size:.62rem;color:#062534;background:var(--accent);"
                  "border-radius:.3rem;padding:.03rem .35rem;font-weight:700\">latest</span>"
                : "";
        const std::string ver = v.version.empty() ? "<span class=\"gp-mute\">(no version)</span>"
                                                  : "<span style=\"font-family:var(--mono)\">" +
                                                        esc(v.version) + "</span>";
        if (v.suppressed) {
            // Sub-floor named-group slice → count only (works-council floor).
            h += "<tr><td>" + ver + tag +
                 "</td><td colspan=\"4\" class=\"gp-mute\">&mdash; n too small (fewer than " +
                 std::to_string(group_floor) + " devices on its latest day &mdash; stats "
                 "withheld)</td><td>" + std::to_string(v.device_count) + "</td></tr>";
            continue;
        }
        h += "<tr><td>" + ver + tag + "</td><td>" + fmt_pct(v.cpu_mean) + "</td><td>" +
             pctile_cell(v.cpu_p95) + "</td><td>" + spark(v.cpu_series) + "</td><td>" +
             fmt_bytes(static_cast<double>(v.ws_mean)) + "</td><td>" +
             std::to_string(v.device_count) + "</td></tr>";
    }
    h += "</tbody></table>";

    std::string foot =
        "Each cell is a roll-up of daily per-device summaries (ADR-0004); the raw per-process "
        "stream never leaves the device. <b>Avg CPU</b> / <b>Avg working set</b> are the latest "
        "day's exact mean across the reporting devices; <b>p95</b> is read from the fixed-bucket "
        "histogram (device p95s can't be averaged), shown as &ldquo;&ge; value&rdquo; when it "
        "lands in the open top bucket. <b>CPU trend</b> is the daily mean over the retained "
        "history. Per-version crashes/hangs are deferred (a separate crash store).";
    if (is_group)
        foot += " This is a <b>named group of specific devices</b>, so any version whose latest "
                "day covers fewer than " +
                std::to_string(group_floor) +
                " devices shows its count only (works-council co-determination). Group scope reads "
                "the per-device store (up to <b>31 days</b>); the whole-fleet view covers the full "
                "<b>180-day</b> aggregate, so a group series is shorter for the same app.";
    h += "<div class=\"gp-note\">" + foot + "</div>";
    return h;
}

namespace {

// The "newest version" cue — a factual tag (most recent day on this device), not a
// verdict. Same idiom as the fleet trend's latest tag.
const char* const kLatestTag =
    " <span style=\"font-size:.62rem;color:#062534;background:var(--accent);border-radius:.3rem;"
    "padding:.03rem .35rem;font-weight:700\">latest</span>";

// One version's metric cells (Avg CPU · Peak CPU · CPU trend · Avg WS · Peak WS ·
// Instances · Days) — shared by the single-version combined row and the multi-
// version sub-row so the two layouts cannot drift.
std::string device_metric_cells(const AppPerfDeviceVersion& v) {
    return "<td>" + fmt_pct(v.cpu_avg) + "</td><td>" + fmt_pct(v.cpu_max) + "</td><td>" +
           spark(v.cpu_series) + "</td><td>" + fmt_bytes(static_cast<double>(v.ws_avg)) +
           "</td><td>" + fmt_bytes(static_cast<double>(v.ws_max)) + "</td><td>" +
           std::to_string(v.instances_max) + "</td><td>" + std::to_string(v.day_count) + "</td>";
}

std::string version_label(const AppPerfDeviceVersion& v) {
    return v.version.empty() ? "<span class=\"gp-mute\">(no version)</span>"
                             : "<span style=\"font-family:var(--mono)\">" + esc(v.version) + "</span>";
}

} // namespace

std::string render_dex_device_app_perf(const std::vector<AppPerfDeviceApp>& apps) {
    if (apps.empty())
        return placeholder("No application performance history for this device",
                           "This device has reported no retained daily application performance "
                           "yet. Per-application sampling is opt-in (procperf_enabled, off by "
                           "default) and a daily summary appears only after the first completed "
                           "UTC day — enable it on this device to populate this view.");

    std::string h = "<table class=\"gp-table\"><thead><tr><th>Application / version</th>"
                    "<th>Avg CPU</th><th>Peak CPU</th><th>CPU trend</th><th>Avg working set</th>"
                    "<th>Peak working set</th><th>Instances</th><th>Days</th></tr></thead><tbody>";
    for (const auto& app : apps) {
        if (app.versions.size() == 1) {
            // Common case: collapse the app + its one version into a single row.
            const auto& v = app.versions.front();
            h += "<tr><td><span style=\"font-weight:600;color:var(--white)\">" + esc(app.app_name) +
                 "</span> " + version_label(v) + "</td>" + device_metric_cells(v) + "</tr>";
            continue;
        }
        // Multi-version: an app header row (the version count) then per-version
        // sub-rows, each carrying its OWN perf — "v125 vs v124 on this box" reads
        // straight off adjacent rows. The newest day is tagged "latest".
        h += "<tr style=\"background:var(--surface)\"><td style=\"font-weight:700;color:var(--white)\">" +
             esc(app.app_name) + " <span class=\"gp-mute\" style=\"font-weight:400;font-size:.7rem\">&middot; " +
             std::to_string(app.versions.size()) +
             " versions</span></td><td colspan=\"7\" class=\"gp-mute\">per-version below</td></tr>";
        for (std::size_t i = 0; i < app.versions.size(); ++i) {
            const auto& v = app.versions[i];
            const std::string tag = (i == 0) ? kLatestTag : ""; // versions are newest-first
            h += "<tr><td style=\"padding-left:1.5rem\">" + version_label(v) + tag + "</td>" +
                 device_metric_cells(v) + "</tr>";
        }
    }
    h += "</tbody></table>";
    h += "<div class=\"gp-note\">Retained <b>daily</b> per-application summaries from the central "
         "store (up to <b>31 days</b>) &mdash; the &ldquo;over time, on this box&rdquo; companion "
         "to the fleet trend. <b>Avg</b> CPU / working set are the sample-weighted window mean; "
         "<b>Peak</b> is the window maximum; <b>CPU trend</b> is the daily mean over the window. "
         "Top resource-significant app-versions only (procperf top-N), names + version only "
         "&mdash; command lines and image paths are never collected. Per-version crashes/hangs are "
         "deferred (a separate central crash-store join on the shared (name, version) identity).</div>";
    return h;
}

} // namespace yuzu::server
