#include "dex_routes.hpp"

#include "guaranteed_state_store.hpp"
#include "http_route_sink.hpp"

#include <cctype>
#include <chrono>
#include <ctime>
#include <format>
#include <string>
#include <vector>

// Shared full-page shell (defined at GLOBAL scope in guardian_page_ui.cpp);
// {{TITLE}}/{{FRAGMENT}} are substituted per request. Reused verbatim so the DEX
// page shares the Guardian chrome + `.gp-*` component CSS (incl. .gp-placeholder
// for "no data"). Declared at global scope to match the definition (the symbol is
// not namespaced).
extern const char* const kGuardianDetailPageHtml;

namespace yuzu::server {

namespace {

// Minimal HTML-escape — every value below originates from agent-reported data
// (subjects, modules, agent_id, platform, reasons), so it MUST be escaped before
// landing in markup (stored-XSS; the Guardian governance flagged an unescaped
// field as a security HIGH). Mirrors the dashboard's escaping idiom.
std::string esc(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        case '\'': out += "&#39;"; break;
        default: out += c;
        }
    }
    return out;
}

std::string num(int64_t n) { return std::to_string(n); }

// The 70 catalogued signal types, GROUPED for display — the server-side mirror
// of the agent catalogue (dex_signal_catalog.cpp; keep in sync when adding a
// signal). The All-signals panel renders EVERY entry, fired or not, so
// operators see what the fleet is monitoring — not just what happened to fire
// in the window. Types present in the DB but absent here (a newer agent's
// signal) are appended under "Other" with the raw-label fallback, so the panel
// never hides data.
struct DexSignalGroup {
    const char* name;
    std::vector<const char*> types;
};

const std::vector<DexSignalGroup>& dex_signal_groups() {
    static const std::vector<DexSignalGroup> kGroups = {
        {"App reliability",
         {"process.crashed", "process.hung", "process.crashed_managed",
          "process.file_access_failure", "app.sxs_error", "app.activation_failed",
          "app.com_failed", "app.error_popup", "app.shutdown_blocked",
          "app.push_notification_error", "app.file_association_reset", "app.staterepo_error"}},
        {"Boot, start-up & shutdown",
         {"os.boot", "boot.degraded_app", "boot.degraded_driver", "boot.degraded_service",
          "boot.degraded_device", "boot.fast_startup_failed", "os.shutdown",
          "shutdown.degraded", "os.restart_initiated", "os.standby", "os.standby_degraded",
          "os.resume_report", "os.uptime_report"}},
        {"Service health",
         {"service.crashed", "service.start_failed", "service.start_timeout", "service.hung",
          "service.logon_failed", "service.recovery_failed", "service.dependency_failed"}},
        {"System stability",
         {"os.bugcheck", "os.power_loss", "os.dirty_shutdown", "os.time_unsynced",
          "os.activation_failed", "os.vss_error", "os.shadow_copies_lost",
          "os.crashdump_disabled", "display.driver_reset", "display.dwm_exited",
          "memory.exhausted"}},
        {"Hardware & storage",
         {"hw.error", "hw.device_start_failed", "hw.user_driver_error", "hw.cpu_throttled",
          "hw.tpm_error", "disk.error", "disk.smart_failure", "disk.port_reset"}},
        {"File system",
         {"fs.corruption", "fs.write_lost", "fs.flush_failed", "fs.database_corrupt",
          "fs.hive_recovered", "fs.autochk_ran"}},
        {"Network",
         {"network.wifi_drop", "network.wifi_connect_failed", "network.dns_timeout",
          "network.dns_register_failed", "network.dhcp_failed", "network.vpn_failed",
          "network.smb_failed", "network.smb_write_lost", "network.ip_conflict",
          "network.name_conflict", "network.port_exhaustion", "session.rdp_disconnected"}},
        {"Identity & logon",
         {"logon.temp_profile", "logon.profile_locked", "logon.slow_subscriber",
          "logon.folder_redirect_failed", "logon.no_dc", "logon.winlogon_terminated",
          "logon.machine_trust_failed", "logon.biometric_error", "logon.hello_error",
          "logon.aad_token_error", "security.kerberos_error", "security.auth_error"}},
        {"Security & protection",
         {"security.rtp_disabled", "security.rtp_error", "security.threat_detected",
          "security.threat_action_failed", "security.av_update_failed",
          "security.tamper_blocked", "security.tls_alert", "security.bitlocker_error",
          "security.cert_enroll_failed"}},
        {"Updates & installs",
         {"update.failed", "update.check_failed", "update.download_failed",
          "update.transfer_failed", "app_install.failed", "app_uninstall.failed",
          "app_install.appx_failed"}},
        {"Policy & management",
         {"gpo.failed", "gpo.cse_failed", "mgmt.mdm_error"}},
        {"Printing",
         {"print.failed", "print.driver_install_failed", "print.plugin_failed"}},
    };
    return kGroups;
}

std::size_t dex_catalogued_type_count() {
    std::size_t n = 0;
    for (const auto& g : dex_signal_groups())
        n += g.types.size();
    return n;
}

// Friendly display label for an obs_type — the ONE place the catalogue taxonomy
// meets the UI. Unknown types fall back to the escaped raw obs_type, so a signal
// added agent-side renders (uglier but correct) with NO server change.
std::string dex_signal_label(const std::string& obs_type) {
    if (obs_type == "process.crashed") return "App crash";
    if (obs_type == "process.hung") return "App hang";
    if (obs_type == "service.crashed") return "Service crash";
    if (obs_type == "service.start_failed") return "Service start failure";
    if (obs_type == "os.bugcheck") return "Blue screen (bugcheck)";
    if (obs_type == "os.power_loss") return "Unexpected reboot";
    if (obs_type == "display.driver_reset") return "Display driver reset";
    if (obs_type == "hw.error") return "Hardware error";
    if (obs_type == "disk.error") return "Disk error";
    if (obs_type == "fs.corruption") return "Filesystem corruption";
    if (obs_type == "memory.exhausted") return "Memory exhaustion";
    if (obs_type == "os.boot") return "Boot";
    if (obs_type == "update.failed") return "Update failure";
    if (obs_type == "app_install.failed") return "App install failure";
    if (obs_type == "logon.temp_profile") return "Profile failure";
    if (obs_type == "gpo.failed") return "Group Policy failure";
    if (obs_type == "network.wifi_drop") return "Wi-Fi disconnect";
    if (obs_type == "network.dns_timeout") return "DNS timeout";
    if (obs_type == "network.ip_conflict") return "IP address conflict";
    if (obs_type == "print.failed") return "Print failure";
    // Wave 2 (2026-06-10)
    if (obs_type == "boot.degraded_app") return "Slow boot: application";
    if (obs_type == "boot.degraded_driver") return "Slow boot: driver";
    if (obs_type == "boot.degraded_service") return "Slow boot: service";
    if (obs_type == "boot.degraded_device") return "Slow boot: device";
    if (obs_type == "os.shutdown") return "Shutdown";
    if (obs_type == "shutdown.degraded") return "Slow shutdown: application";
    if (obs_type == "os.standby") return "Standby/resume";
    if (obs_type == "os.standby_degraded") return "Slow resume";
    if (obs_type == "logon.slow_subscriber") return "Slow logon (subscriber)";
    if (obs_type == "os.uptime_report") return "Uptime report";
    if (obs_type == "os.dirty_shutdown") return "Dirty shutdown";
    if (obs_type == "os.time_unsynced") return "Clock unsynchronized";
    if (obs_type == "os.activation_failed") return "Windows activation failure";
    if (obs_type == "os.vss_error") return "Shadow copy error";
    if (obs_type == "fs.hive_recovered") return "Registry hive recovered";
    if (obs_type == "fs.autochk_ran") return "Disk check at boot";
    if (obs_type == "process.crashed_managed") return "App crash (.NET)";
    if (obs_type == "app.sxs_error") return "App dependency error";
    if (obs_type == "app.activation_failed") return "App activation failure";
    if (obs_type == "app.com_failed") return "COM server failure";
    if (obs_type == "app.error_popup") return "Error dialog shown";
    if (obs_type == "app.shutdown_blocked") return "App blocked shutdown";
    if (obs_type == "service.hung") return "Service hung";
    if (obs_type == "service.start_timeout") return "Service start timeout";
    if (obs_type == "service.logon_failed") return "Service logon failure";
    if (obs_type == "service.recovery_failed") return "Service recovery failure";
    if (obs_type == "disk.smart_failure") return "Disk SMART warning";
    if (obs_type == "disk.port_reset") return "Storage port reset";
    if (obs_type == "fs.write_lost") return "Lost delayed write";
    if (obs_type == "fs.database_corrupt") return "Database corruption";
    if (obs_type == "hw.device_start_failed") return "Device start failure";
    if (obs_type == "hw.cpu_throttled") return "CPU throttled";
    if (obs_type == "network.wifi_connect_failed") return "Wi-Fi connect failure";
    if (obs_type == "network.dhcp_failed") return "DHCP failure";
    if (obs_type == "network.vpn_failed") return "VPN failure";
    if (obs_type == "network.smb_failed") return "File share failure";
    if (obs_type == "network.name_conflict") return "Name conflict";
    if (obs_type == "logon.no_dc") return "No domain controller";
    if (obs_type == "security.kerberos_error") return "Kerberos error";
    if (obs_type == "logon.profile_locked") return "Profile unload blocked";
    if (obs_type == "logon.folder_redirect_failed") return "Folder redirection failure";
    if (obs_type == "security.rtp_disabled") return "Real-time protection off";
    if (obs_type == "security.threat_detected") return "Malware detected";
    if (obs_type == "security.av_update_failed") return "AV update failure";
    if (obs_type == "security.tamper_blocked") return "Tamper attempt blocked";
    if (obs_type == "app_uninstall.failed") return "App uninstall failure";
    if (obs_type == "app_install.appx_failed") return "Store app install failure";
    if (obs_type == "update.transfer_failed") return "Download failure (BITS)";
    if (obs_type == "print.driver_install_failed") return "Printer driver failure";
    if (obs_type == "print.plugin_failed") return "Print spooler plug-in failure";
    // Wave 3 (2026-06-10)
    if (obs_type == "boot.fast_startup_failed") return "Fast startup failure";
    if (obs_type == "os.resume_report") return "Resume from sleep";
    if (obs_type == "os.restart_initiated") return "Restart initiated";
    if (obs_type == "os.shadow_copies_lost") return "Restore points lost";
    if (obs_type == "os.crashdump_disabled") return "Crash dump disabled";
    if (obs_type == "display.dwm_exited") return "Window manager exited";
    if (obs_type == "process.file_access_failure") return "App file-access failure";
    if (obs_type == "app.push_notification_error") return "Notification platform error";
    if (obs_type == "app.file_association_reset") return "File association reset";
    if (obs_type == "app.staterepo_error") return "App repository error";
    if (obs_type == "service.dependency_failed") return "Service dependency failure";
    if (obs_type == "fs.flush_failed") return "Disk flush failure";
    if (obs_type == "hw.user_driver_error") return "Peripheral driver error";
    if (obs_type == "hw.tpm_error") return "TPM error";
    if (obs_type == "network.port_exhaustion") return "TCP port exhaustion";
    if (obs_type == "network.smb_write_lost") return "Share write lost";
    if (obs_type == "network.dns_register_failed") return "DNS registration failure";
    if (obs_type == "session.rdp_disconnected") return "Remote session disconnect";
    if (obs_type == "logon.winlogon_terminated") return "Logon process terminated";
    if (obs_type == "logon.machine_trust_failed") return "Machine trust failure";
    if (obs_type == "logon.biometric_error") return "Biometric sensor error";
    if (obs_type == "logon.hello_error") return "Windows Hello error";
    if (obs_type == "logon.aad_token_error") return "Entra ID token error";
    if (obs_type == "security.auth_error") return "Authentication error";
    if (obs_type == "security.tls_alert") return "TLS failure";
    if (obs_type == "security.threat_action_failed") return "Threat removal failure";
    if (obs_type == "security.rtp_error") return "Protection engine error";
    if (obs_type == "security.bitlocker_error") return "BitLocker error";
    if (obs_type == "security.cert_enroll_failed") return "Certificate enrollment failure";
    if (obs_type == "update.check_failed") return "Update check failure";
    if (obs_type == "update.download_failed") return "Update download failure";
    if (obs_type == "gpo.cse_failed") return "Policy extension failure";
    if (obs_type == "mgmt.mdm_error") return "MDM/Intune error";
    return esc(obs_type); // forward-compatible fallback
}

// Percent-encode for a query-string value (RFC 3986 unreserved set kept literal).
// Used to put an arbitrary subject / agent_id into a drill-down hx-get URL.
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

// An htmx drill-down link: clickable text that swaps the fragment into the shared
// page mount. htmx core attrs only (CSP-safe; no hx-on). `disp` is already
// html-escaped; `qs` is the already-encoded query string.
std::string drill_link(const std::string& path, const std::string& qs, const std::string& disp) {
    return "<a hx-get=\"" + path + "?" + qs + "\" hx-target=\"#guardian-detail\" "
           "hx-swap=\"innerHTML\" style=\"cursor:pointer;\">" + disp + "</a>";
}

// A stat tile. `n`/`sx` callers pass already-escaped content.
std::string mk_tile(const char* cls, const std::string& n, const std::string& label,
                    const std::string& sx) {
    std::string t = "<div class=\"gp-tile\"><div class=\"n " + std::string(cls) + "\">" + n +
                    "</div><div class=\"l\">" + label + "</div>";
    if (!sx.empty())
        t += "<div class=\"sx\">" + sx + "</div>";
    return t + "</div>";
}

// The htmx "back to overview" link shared by both drill-downs.
std::string back_to_overview() {
    return "<a class=\"gp-back\" hx-get=\"/fragments/dex/overview\" hx-target=\"#guardian-detail\" "
           "hx-swap=\"innerHTML\" style=\"cursor:pointer;\">&larr; Reliability overview</a>";
}

// ISO-8601 UTC cutoff for "N days ago"; "" for days<=0 (the "all" window, where a
// per-device-days rate is ill-defined). Mirrors guardian_ingest's ts_to_iso8601.
std::string iso_days_ago(int days) {
    if (days <= 0)
        return {};
    const auto t = std::chrono::system_clock::now() - std::chrono::hours(24 * days);
    std::time_t tt = std::chrono::system_clock::to_time_t(t);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

// Map the window selector value to a day count (0 = "all").
int window_to_days(const std::string& w) {
    if (w == "24h") return 1;
    if (w == "30d") return 30;
    if (w == "all") return 0;
    return 7; // "7d" / default
}

// A dashed "no data" panel — the no-mock-data contract's empty state.
std::string placeholder(const std::string& title, const std::string& sub) {
    return "<div class=\"gp-placeholder\"><b>" + esc(title) + "</b>" + esc(sub) + "</div>";
}

// "12345 ms" / "12.3 s" human form for a boot duration metric.
std::string fmt_ms(double ms) {
    if (ms >= 10000.0)
        return std::format("{:.1f} s", ms / 1000.0);
    return std::format("{:.0f} ms", ms);
}

// The per-row "What happened" cell of the device history: prefer the symbolic
// name (+ reason when it adds information); os.boot rows show the duration.
std::string history_detail(const GuardianObservationRow& r) {
    if (r.obs_type == "os.boot" && r.metric > 0)
        return esc(fmt_ms(r.metric));
    if (!r.symbolic.empty() && !r.reason.empty() && r.symbolic != r.reason)
        return esc(r.symbolic + " " + r.reason);
    if (!r.symbolic.empty())
        return esc(r.symbolic);
    return esc(r.reason);
}

} // namespace

std::string render_dex_overview_fragment(const GuaranteedStateStore* store,
                                         const std::string& since, int window_days,
                                         DexFleet fleet) {
    if (!store)
        return placeholder("Reliability data unavailable",
                           "The signal observation store is not open.");

    // Window selector — htmx core attrs only (CSP-safe; no hx-on). Re-fetches the
    // fragment into the shared page mount. Rendered before the early empty return so
    // the user can switch windows even when the current one has no signals.
    const std::string cur = window_days == 1   ? "24h"
                            : window_days == 30 ? "30d"
                            : window_days == 0  ? "all"
                                                : "7d";
    auto chip = [&](const char* w, const char* label) {
        const std::string on = (cur == w) ? " on" : "";
        return "<a class=\"gp-chip" + on + "\" hx-get=\"/fragments/dex/overview?window=" + w +
               "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" + label + "</a>";
    };
    std::string head;
    head += "<a class=\"gp-back\" href=\"/\">&larr; Dashboard</a>";
    head += "<div class=\"gp-head\"><div>"
            "<div class=\"gp-titleline\"><h1>Digital Employee Experience</h1></div>"
            "<div class=\"gp-sub\">Fleet reliability from device signals (crashes, hangs, "
            "stability, boot, network) &mdash; read-only. Measured facts, not a synthetic "
            "score.</div></div></div>";
    head += "<div class=\"gp-filters\">" + chip("24h", "24h") + chip("7d", "7d") +
            chip("30d", "30d") + chip("all", "All") + "</div>";

    // The whole-catalogue rollup. NOTE: no whole-page empty state any more —
    // the All-signals panel below always lists every catalogued type, fired or
    // not (zero counts are real data: "monitored, nothing happened").
    const auto signals = store->dex_signal_summary(since);

    const auto summary = store->dex_crash_summary(since);
    const auto apps = store->dex_top_apps(since, 20);
    const auto modules = store->dex_top_modules(since, 20);
    const auto devices = store->dex_top_devices(since, 20);
    const auto by_os = store->dex_crashes_by_os(since);
    const auto by_day = store->dex_crashes_by_day(since);
    const auto boot = store->dex_boot_stats(since);

    // A stat tile; cls "unk" + "&mdash;" is the honest no-data state for a rate
    // whose denominator is missing (no fabricated number).
    auto tile = [](const char* cls, const std::string& n, const std::string& label,
                   const std::string& sx) {
        std::string t = "<div class=\"gp-tile\"><div class=\"n " + std::string(cls) + "\">" + n +
                        "</div><div class=\"l\">" + label + "</div>";
        if (!sx.empty())
            t += "<div class=\"sx\">" + sx + "</div>";
        return t + "</div>";
    };

    std::string h = head;
    h += "<div class=\"gp-sech\">Reliability &mdash; measured</div>";
    h += "<div class=\"gp-tiles\">";
    // Crash-free % over reporting Windows agents (the only OS with a collector).
    // Deliberately still a CRASH rate — the headline stays the industry-standard
    // crash-free-devices number; other signals get their own panels below.
    if (fleet.windows_online > 0) {
        int64_t impacted = summary.distinct_devices;
        if (impacted > fleet.windows_online)
            impacted = fleet.windows_online; // clamp (an impacted device may now be offline)
        const double pct = 100.0 * static_cast<double>(fleet.windows_online - impacted) /
                           static_cast<double>(fleet.windows_online);
        h += tile("good", std::format("{:.1f}%", pct), "Crash-free devices",
                  num(fleet.windows_online - impacted) + " of " + num(fleet.windows_online) +
                      " reporting");
    } else {
        h += tile("unk", "&mdash;", "Crash-free devices", "no reporting agents");
    }
    // Crashes / 1k device-days (needs a bounded window to define device-days).
    if (fleet.windows_online > 0 && window_days > 0) {
        const double dd =
            static_cast<double>(fleet.windows_online) * static_cast<double>(window_days);
        const double per1k = dd > 0 ? static_cast<double>(summary.total_crashes) / dd * 1000.0 : 0.0;
        h += tile("", std::format("{:.1f}", per1k), "Crashes / 1k device-days",
                  num(summary.total_crashes) + " crashes &middot; " + std::format("{:.0f}", dd) +
                      " device-days");
    } else {
        h += tile("unk", "&mdash;", "Crashes / 1k device-days",
                  window_days > 0 ? "no reporting agents" : "pick a window");
    }
    h += tile("bad", num(summary.total_crashes), "Crashes", "");
    h += tile("warn", num(summary.distinct_devices), "Devices impacted", "by crashes");
    h += tile("info", num(fleet.windows_online), "Windows agents online",
              num(fleet.total_online) + " total online");
    h += "</div>";
    h += "<div class=\"gp-note\">Rates are over <b>currently-reporting Windows agents</b> (the only "
         "OS with a signal collector today); offline agents are excluded, not counted as crash-free. "
         "macOS/Linux: collector pending.</div>";

    // All signals — every catalogued type, fired or not, GROUPED (App
    // reliability / Boot / Network / …), then any uncatalogued types the DB
    // carries under "Other" (newer-agent forward-compat). Quiet rows render
    // muted with a real zero — monitored, nothing happened. Group header rows
    // also show the group's event total so a hot family stands out collapsed.
    h += "<div class=\"gp-sech\">All signals</div>";
    h += "<div class=\"gp-note\">All " + std::to_string(dex_catalogued_type_count()) +
         " monitored signal types are listed by group; a dash means no events in this "
         "window.</div>";
    h += "<table class=\"gp-table\"><thead><tr><th>Signal</th><th class=\"gp-num\">Events</th>"
         "<th class=\"gp-num\">Devices</th><th>Last seen</th></tr></thead><tbody>";
    auto find_sig = [&](const std::string& t) -> const DexSignalCount* {
        for (const auto& sig : signals)
            if (sig.obs_type == t)
                return &sig;
        return nullptr;
    };
    auto sig_row = [&](const std::string& obs_type, const DexSignalCount* c) {
        if (c) {
            h += "<tr><td>" + dex_signal_label(obs_type) + "</td><td class=\"gp-num\">" +
                 num(c->count) + "</td><td class=\"gp-num\">" + num(c->distinct_devices) +
                 "</td><td class=\"gp-mute\">" + esc(c->last_seen) + "</td></tr>";
        } else {
            h += "<tr class=\"gp-mute\"><td>" + dex_signal_label(obs_type) +
                 "</td><td class=\"gp-num\">0</td><td class=\"gp-num\">&mdash;</td>"
                 "<td class=\"gp-mute\">&mdash;</td></tr>";
        }
    };
    auto group_header = [&](const std::string& name, int64_t total) {
        h += "<tr><td colspan=\"4\" style=\"font-weight:600;padding-top:.7rem;"
             "border-bottom:1px solid var(--border);\">" + esc(name) +
             (total > 0 ? " <span class=\"gp-mute\">&middot; " + num(total) + " events</span>"
                        : "") +
             "</td></tr>";
    };
    for (const auto& group : dex_signal_groups()) {
        int64_t total = 0;
        for (const char* t : group.types)
            if (const auto* c = find_sig(t))
                total += c->count;
        group_header(group.name, total);
        for (const char* t : group.types)
            sig_row(t, find_sig(t));
    }
    // Uncatalogued extras (forward-compat) under "Other".
    {
        std::vector<const DexSignalCount*> extras;
        for (const auto& sig : signals) {
            bool known = false;
            for (const auto& group : dex_signal_groups()) {
                for (const char* t : group.types)
                    if (sig.obs_type == t) {
                        known = true;
                        break;
                    }
                if (known)
                    break;
            }
            if (!known)
                extras.push_back(&sig);
        }
        if (!extras.empty()) {
            int64_t total = 0;
            for (const auto* e : extras)
                total += e->count;
            group_header("Other", total);
            for (const auto* e : extras)
                sig_row(e->obs_type, e);
        }
    }
    h += "</tbody></table>";

    // App reliability — crashes + hangs per app, blast radius, drill-down.
    h += "<div class=\"gp-sech\">App reliability (crashes + hangs)</div>";
    if (apps.empty()) {
        h += placeholder("No data", "No app crashes or hangs recorded.");
    } else {
        h += "<table class=\"gp-table\"><thead><tr><th>Application</th>"
             "<th class=\"gp-num\">Crashes</th><th class=\"gp-num\">Hangs</th>"
             "<th class=\"gp-num\">Devices (blast radius)</th><th>Last seen</th></tr></thead><tbody>";
        for (const auto& a : apps) {
            const std::string label =
                a.subject.empty()
                    ? std::string("&lt;unknown&gt;")
                    : drill_link("/fragments/dex/app", "name=" + url_encode(a.subject),
                                 esc(a.subject));
            h += "<tr><td>" + label + "</td><td class=\"gp-num\">" + num(a.crashes) +
                 "</td><td class=\"gp-num\">" + num(a.hangs) + "</td><td class=\"gp-num\">" +
                 num(a.distinct_devices) + "</td><td class=\"gp-mute\">" + esc(a.last_seen) +
                 "</td></tr>";
        }
        h += "</tbody></table>";
    }

    // Boot performance — every boot reports a duration (os.boot metric).
    h += "<div class=\"gp-sech\">Boot performance</div>";
    if (boot.boots == 0) {
        h += placeholder("No data", "No boot reports in this window (logged a few minutes after "
                                    "each boot).");
    } else {
        h += "<div class=\"gp-tiles\">";
        h += tile("", esc(fmt_ms(boot.avg_ms)), "Average boot", num(boot.boots) + " boots");
        h += tile("warn", esc(fmt_ms(boot.max_ms)), "Slowest boot", "");
        h += tile("info", num(boot.distinct_devices), "Devices reporting boots", "");
        h += "</div>";
        const auto slow = store->dex_slowest_boots(since, 10);
        if (!slow.empty()) {
            h += "<table class=\"gp-table\"><thead><tr><th>Device</th>"
                 "<th class=\"gp-num\">Avg boot</th><th class=\"gp-num\">Slowest</th>"
                 "<th class=\"gp-num\">Boots</th></tr></thead><tbody>";
            for (const auto& b : slow) {
                const std::string label = drill_link("/fragments/dex/device",
                                                     "id=" + url_encode(b.agent_id),
                                                     esc(b.agent_id));
                h += "<tr><td>" + label + "</td><td class=\"gp-num\">" + esc(fmt_ms(b.avg_ms)) +
                     "</td><td class=\"gp-num\">" + esc(fmt_ms(b.max_ms)) +
                     "</td><td class=\"gp-num\">" + num(b.boots) + "</td></tr>";
            }
            h += "</tbody></table>";
        }
    }

    // Crashes per day (trend) — inline bars, no extra shell CSS.
    h += "<div class=\"gp-sech\">Crashes per day</div>";
    if (by_day.empty()) {
        h += placeholder("No data", "No crashes in this window.");
    } else {
        int64_t maxc = 1;
        for (const auto& d : by_day)
            if (d.crashes > maxc)
                maxc = d.crashes;
        h += "<div style=\"display:flex;align-items:flex-end;gap:.4rem;height:90px;\">";
        for (const auto& d : by_day) {
            const int px = static_cast<int>(8 + 74 * d.crashes / maxc);
            h += "<div style=\"flex:1;text-align:center;\">"
                 "<div title=\"" + esc(d.day) + ": " + num(d.crashes) +
                 "\" style=\"height:" + num(px) +
                 "px;background:var(--red);opacity:.8;border-radius:2px 2px 0 0;\"></div>"
                 "<div style=\"font-size:.55rem;color:var(--muted);\">" + esc(d.day.substr(5)) +
                 "</div></div>";
        }
        h += "</div>";
    }

    // By OS — coverage-normalised comparison comes with the rate; raw counts now.
    h += "<div class=\"gp-sech\">Crashes by operating system</div>";
    if (by_os.empty()) {
        h += placeholder("No data", "No crashes carry an OS tag yet.");
    } else {
        h += "<table class=\"gp-table\"><thead><tr><th>OS</th><th class=\"gp-num\">Crashes</th>"
             "<th class=\"gp-num\">Devices</th></tr></thead><tbody>";
        for (const auto& o : by_os) {
            const std::string label = o.platform.empty() ? std::string("&lt;unknown&gt;") : esc(o.platform);
            h += "<tr><td>" + label + "</td><td class=\"gp-num\">" + num(o.crashes) +
                 "</td><td class=\"gp-num\">" + num(o.distinct_devices) + "</td></tr>";
        }
        h += "</tbody></table>";
    }

    // Top faulting modules (crash-scoped).
    h += "<div class=\"gp-sech\">Top faulting modules</div>";
    if (modules.empty()) {
        h += placeholder("No data", "No faulting modules recorded.");
    } else {
        h += "<table class=\"gp-table\"><thead><tr><th>Module</th><th class=\"gp-num\">Crashes</th>"
             "<th class=\"gp-num\">Distinct apps</th></tr></thead><tbody>";
        for (const auto& m : modules) {
            const std::string label = m.component.empty() ? std::string("&lt;unknown&gt;") : esc(m.component);
            h += "<tr><td>" + label + "</td><td class=\"gp-num\">" + num(m.crashes) +
                 "</td><td class=\"gp-num\">" + num(m.distinct_apps) + "</td></tr>";
        }
        h += "</tbody></table>";
    }

    // Most-affected devices (crash-scoped).
    h += "<div class=\"gp-sech\">Most-affected devices</div>";
    if (devices.empty()) {
        h += placeholder("No data", "No affected devices recorded.");
    } else {
        h += "<table class=\"gp-table\"><thead><tr><th>Device</th><th class=\"gp-num\">Crashes</th>"
             "<th>Last seen</th></tr></thead><tbody>";
        for (const auto& d : devices) {
            const std::string label =
                drill_link("/fragments/dex/device", "id=" + url_encode(d.agent_id), esc(d.agent_id));
            h += "<tr><td>" + label + "</td><td class=\"gp-num\">" + num(d.crashes) +
                 "</td><td class=\"gp-mute\">" + esc(d.last_seen) + "</td></tr>";
        }
        h += "</tbody></table>";
    }

    return h;
}

std::string render_dex_app_fragment(const GuaranteedStateStore* store,
                                    const std::string& process_name, const std::string& since) {
    if (!store)
        return back_to_overview() +
               placeholder("Reliability data unavailable", "The signal store is not open.");

    const auto s = store->dex_app_summary(process_name, since);
    std::string h = back_to_overview();
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>" + esc(process_name) +
         "</h1></div><div class=\"gp-sub\">Crash &amp; hang blast radius across the "
         "fleet.</div></div></div>";
    if (s.signals == 0)
        return h + placeholder("No crashes", "No crashes or hangs recorded for this application.");

    const auto modules = store->dex_app_modules(process_name, since, 20);
    const auto exceptions = store->dex_app_exceptions(process_name, since, 20);
    const auto devs = store->dex_app_devices(process_name, since, 20);

    h += "<div class=\"gp-sech\">Impact</div><div class=\"gp-tiles\">";
    h += mk_tile("bad", num(s.crashes), "Crashes", "");
    h += mk_tile("warn", num(s.hangs), "Hangs", "");
    h += mk_tile("warn", num(s.distinct_devices), "Devices affected", "blast radius");
    h += mk_tile("mute", esc(s.first_seen), "First seen", "");
    h += mk_tile("mute", esc(s.last_seen), "Last seen", "");
    h += "</div>";

    h += "<div class=\"gp-sech\">Faulting modules</div>";
    if (modules.empty()) {
        h += placeholder("No data", "");
    } else {
        h += "<table class=\"gp-table\"><thead><tr><th>Module</th>"
             "<th class=\"gp-num\">Crashes</th></tr></thead><tbody>";
        for (const auto& m : modules) {
            const std::string label =
                m.component.empty() ? std::string("&lt;unknown&gt;") : esc(m.component);
            h += "<tr><td>" + label + "</td><td class=\"gp-num\">" + num(m.crashes) + "</td></tr>";
        }
        h += "</tbody></table>";
    }

    h += "<div class=\"gp-sech\">Exceptions</div>";
    if (exceptions.empty()) {
        h += placeholder("No data", "");
    } else {
        h += "<table class=\"gp-table\"><thead><tr><th>Code</th><th>Name</th>"
             "<th class=\"gp-num\">Crashes</th></tr></thead><tbody>";
        for (const auto& e : exceptions) {
            h += "<tr><td>" + esc(e.reason) + "</td><td>" + esc(e.symbolic) +
                 "</td><td class=\"gp-num\">" + num(e.crashes) + "</td></tr>";
        }
        h += "</tbody></table>";
    }

    h += "<div class=\"gp-sech\">Affected devices</div>";
    if (devs.empty()) {
        h += placeholder("No data", "");
    } else {
        h += "<table class=\"gp-table\"><thead><tr><th>Device</th><th class=\"gp-num\">Crashes</th>"
             "<th>Last seen</th></tr></thead><tbody>";
        for (const auto& d : devs) {
            const std::string label =
                drill_link("/fragments/dex/device", "id=" + url_encode(d.agent_id), esc(d.agent_id));
            h += "<tr><td>" + label + "</td><td class=\"gp-num\">" + num(d.crashes) +
                 "</td><td class=\"gp-mute\">" + esc(d.last_seen) + "</td></tr>";
        }
        h += "</tbody></table>";
    }
    return h;
}

std::string render_dex_device_fragment(const GuaranteedStateStore* store,
                                       const std::string& agent_id, const std::string& since) {
    // This is behavioral data (which apps a person runs): the access posture is
    // enforced server-side — permission-gated on GuaranteedState:Read and each
    // open audit-logged (dex.device.view) — without an on-page banner.
    if (!store)
        return back_to_overview() +
               placeholder("Reliability data unavailable", "The signal store is not open.");

    const auto s = store->dex_device_summary(agent_id, since);
    std::string h = back_to_overview();
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>" + esc(agent_id) +
         "</h1></div><div class=\"gp-sub\">Device signal history.</div></div></div>";
    if (s.signals == 0)
        return h + placeholder("No signals", "No reliability signals recorded for this device.");

    const auto history = store->dex_device_history(agent_id, since, 100);
    h += "<div class=\"gp-sech\">Reliability</div><div class=\"gp-tiles\">";
    h += mk_tile("bad", num(s.crashes), "Crashes", "");
    h += mk_tile("warn", num(s.hangs), "Hangs", "");
    h += mk_tile("info", num(s.signals), "All signals", "");
    h += mk_tile("warn", num(s.distinct_apps), "Distinct apps", "crashing or hanging");
    h += mk_tile("mute", esc(s.last_seen), "Last signal", "");
    h += "</div>";

    // Signal history — the friendly multi-signal rendering (closed UP-4: labels,
    // not raw __observation__ events).
    h += "<div class=\"gp-sech\">Signal history</div>";
    h += "<table class=\"gp-table\"><thead><tr><th>When</th><th>Signal</th><th>Subject</th>"
         "<th>What happened</th><th>Component</th></tr></thead><tbody>";
    for (const auto& r : history) {
        h += "<tr><td class=\"gp-mute\">" + esc(r.observed_at) + "</td><td>" +
             dex_signal_label(r.obs_type) + "</td><td>" + esc(r.subject) +
             "</td><td class=\"gp-drift\">" + history_detail(r) + "</td><td>" + esc(r.component) +
             "</td></tr>";
    }
    h += "</tbody></table>";
    return h;
}

void DexRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                GuaranteedStateStore* store, FleetFn fleet_fn, AuditFn audit_fn) {
    // Production adapter: wrap the httplib server in the route-sink seam and
    // delegate to the testable overload (mirrors GuardianRoutes / RestApiV1).
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), store, std::move(fleet_fn),
                    std::move(audit_fn));
}

void DexRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                GuaranteedStateStore* store, FleetFn fleet_fn, AuditFn audit_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    store_ = store;
    fleet_fn_ = std::move(fleet_fn);
    audit_fn_ = std::move(audit_fn);

    // -- Page shell (auth-only static chrome; the fragment it loads gates on Read) --
    sink.Get("/dex", [this](const httplib::Request& req, httplib::Response& res) {
        auto session = auth_fn_(req, res);
        if (!session) {
            res.set_redirect("/login");
            return;
        }
        std::string html(kGuardianDetailPageHtml);
        auto sub = [&](const std::string& tok, const std::string& val) {
            for (auto p = html.find(tok); p != std::string::npos; p = html.find(tok, p + val.size()))
                html.replace(p, tok.size(), val);
        };
        sub("{{TITLE}}", "Yuzu \xE2\x80\x94 DEX");
        sub("{{FRAGMENT}}", "/fragments/dex/overview");
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(std::move(html), "text/html; charset=utf-8");
    });

    // -- Overview fragment (gates on GuaranteedState:Read, like the Guardian reads) --
    sink.Get("/fragments/dex/overview", [this](const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        const std::string w = req.has_param("window") ? req.get_param_value("window") : "7d";
        const int window_days = window_to_days(w);
        const std::string since = iso_days_ago(window_days);
        const DexFleet fleet = fleet_fn_ ? fleet_fn_() : DexFleet{};
        res.set_content(render_dex_overview_fragment(store_, since, window_days, fleet),
                        "text/html; charset=utf-8");
    });

    // -- Per-app drill-down (blast radius). ?name=<process_name> --
    sink.Get("/fragments/dex/app", [this](const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        const std::string name = req.has_param("name") ? req.get_param_value("name") : "";
        res.set_content(render_dex_app_fragment(store_, name, ""), "text/html; charset=utf-8");
    });

    // -- Per-device drill-down (signal history; behavioral PII → audit each open). ?id=<agent_id> --
    sink.Get("/fragments/dex/device", [this](const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        if (audit_fn_)
            audit_fn_(req, "dex.device.view", "success", "agent", id,
                      "DEX per-device signal history");
        res.set_content(render_dex_device_fragment(store_, id, ""), "text/html; charset=utf-8");
    });
}

} // namespace yuzu::server
