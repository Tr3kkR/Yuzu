#include "dex_routes.hpp"

#include "guaranteed_state_store.hpp"
#include "http_route_sink.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <ctime>
#include <format>
#include <string>
#include <string_view>
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

} // namespace — the catalogue accessors below are PUBLIC (declared in
  // dex_routes.hpp) since F1: the Settings → DEX alerts panel renders the
  // routable-type list from the same single source of truth.

// The catalogued signal types (107 today), GROUPED for display — the server-side mirror
// of the agent catalogue (dex_signal_catalog.cpp; keep in sync when adding a
// signal). The All-signals panel renders EVERY entry, fired or not, so
// operators see what the fleet is monitoring — not just what happened to fire
// in the window. Types present in the DB but absent here (a newer agent's
// signal) are appended under "Other" with the raw-label fallback, so the panel
// never hides data.

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
          "hw.tpm_error", "disk.error", "disk.smart_failure", "disk.port_reset", "storage.low"}},
        {"Performance",
         {"perf.cpu_sustained", "perf.memory_pressure", "perf.disk_latency_high"}},
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

// Per-obs_type platform coverage — which OSes collect a signal type today. Windows
// is the whole EvtSubscribe catalogue; Linux (dex_linux_*) and macOS (dex_macos_*)
// collect the subsets below. THIN explicit map (the one bit of new grouping) — keep
// in sync with the agent collectors; a schema↔catalogue cross-check test guards it.
std::vector<std::string> dex_obs_platforms(const std::string& obs_type) {
    static const char* const kLinux[] = {
        // /proc + statvfs polls (dex_linux_proc / dex_linux_storage)
        "perf.cpu_sustained", "perf.memory_pressure", "storage.low", "os.uptime_report",
        // systemd-structured journal (dex_linux_journal)
        "process.crashed", "service.crashed", "memory.exhausted"};
    // NOTE: the expanded Linux kernel/sysfs signals — perf.disk_latency_high,
    // hw.cpu_throttled (dex_linux_sysfs); service.hung, os.time_unsynced
    // (journal); os.bugcheck, os.dirty_shutdown, disk.error, fs.corruption,
    // hw.error, process.hung (dex_linux_kmsg) — land WITH their collectors in the
    // dex-linux-signals batch (#1523). Re-add them here in the same change that
    // brings those collectors onto this branch, and extend the drift-net test in
    // test_dex_routes.cpp. Until then the map must not advertise a Linux signal
    // nothing collects, or a Linux fleet reads "monitored, quiet" as healthy.
    static const char* const kMac[] = {
        "process.crashed", "process.hung",  "os.bugcheck",     "memory.exhausted",
        "os.uptime_report", "disk.smart_failure", "hw.error",  "storage.low",
        "hw.cpu_throttled", "service.crashed",    "network.wifi_drop", "update.failed",
        "print.failed",     "mgmt.mdm_error",     "logon.no_dc",       "fs.corruption"};
    auto in = [&](const char* const* arr, std::size_t n) {
        for (std::size_t i = 0; i < n; ++i)
            if (obs_type == arr[i])
                return true;
        return false;
    };
    std::vector<std::string> out;
    out.emplace_back("windows"); // the catalogue IS the Windows EvtSubscribe set
    if (in(kLinux, std::size(kLinux)))
        out.emplace_back("linux");
    if (in(kMac, std::size(kMac)))
        out.emplace_back("macos");
    return out;
}

// One family's slice of the canonical health composite — the SAME formula as
// dex_compute_health (severity × default-preset × device-impact), for one family.
// Forward-declared here (used by the Catalogue above its definition); defined just
// after dex_compute_health below so it shares the family-weights helpers.
double dex_family_health_deduction(const DexSignalGroup& g,
                                   const std::vector<DexSignalCount>& signals, int64_t N);

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
    if (obs_type == "storage.low") return "Disk nearly full"; // macOS collector (df poll)
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
    // A3 sustained perf breaches (2026-06-12) — Windows state poll (dex_perf_breach)
    if (obs_type == "perf.cpu_sustained") return "Sustained high CPU";
    if (obs_type == "perf.memory_pressure") return "Memory pressure";
    if (obs_type == "perf.disk_latency_high") return "High disk latency";
    return esc(obs_type); // forward-compatible fallback
}

namespace {

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

// F2a: cohort tag-key validation — mirrors TagStore::validate_key (max 64,
// [a-zA-Z0-9_.:-]) so an arbitrary `?key=` can never reach the snapshot
// provider or markup. Validation here (not a TagStore dep) keeps DexRoutes
// decoupled; the alphabets are pinned together by a unit test.
bool valid_tag_key(const std::string& key) {
    if (key.empty() || key.size() > 64)
        return false;
    return key.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "abcdefghijklmnopqrstuvwxyz0123456789_.:-") ==
           std::string::npos;
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

// The htmx "back to overview" link shared by both drill-downs — preserves the
// window so returning from a drill-down lands on the same window the user came
// from (drill-downs are window-scoped; governance C-S1/UP-11).
std::string back_to_overview(const std::string& window) {
    const std::string qs = window.empty() ? std::string{} : "?window=" + window;
    return "<a class=\"gp-back\" hx-get=\"/fragments/dex/overview" + qs +
           "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\" "
           "style=\"cursor:pointer;\">&larr; Reliability overview</a>";
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

// CANONICAL window token for a day count — the inverse of window_to_days. This
// is the XSS chokepoint (governance Gate-8 HIGH): the window value is
// concatenated into hx-get="…" attributes in the drill-down links, so the RAW
// `?window=` query param must NEVER reach markup. Routes canonicalise an
// incoming param through window_to_days→window_token so only one of these four
// fixed literals can ever be rendered, regardless of attacker input.
std::string window_token(int days) {
    return days == 1 ? "24h" : days == 30 ? "30d" : days == 0 ? "all" : "7d";
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

// Public wrappers over the internal window helpers (declared in dex_routes.hpp) so
// the /api/v1/dex REST surface resolves the window token through the exact same
// logic as the dashboard fragments — no second copy of the 24h/7d/30d/all mapping.
int dex_window_to_days(const std::string& window) { return window_to_days(window); }
std::string dex_iso_since(int days) { return iso_days_ago(days); }

// Canonical window token from the (already-validated) window_days — safe to put
// into hx-get attributes (no raw param reaches markup; Gate-8 XSS discipline).
std::string dex_window_token(int window_days) {
    return window_days == 1 ? "24h" : window_days == 30 ? "30d" : window_days == 0 ? "all" : "7d";
}

// Shared DEX sub-nav (Overview · Catalogue · Health score · Trends · Performance ·
// Network). htmx core attrs into the page mount — CSP-safe (no hx-on). The Network
// tab loads the /fragments/network/* renderers (network_ui.cpp), which render this
// same sub-nav with "network" active — so Network sits UNDER DEX rather than as its
// own top-level nav item. The network fragments ignore the threaded ?window= (the
// quality view is a now-view with no window of its own).
std::string dex_subnav(const std::string& active, int window_days) {
    const std::string w = dex_window_token(window_days);
    auto tab = [&](const char* id, const char* label, const char* frag) {
        const std::string on = (active == id) ? " class=\"on\"" : "";
        return "<a" + on + " hx-get=\"" + frag + "?window=" + w +
               "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" + label + "</a>";
    };
    return "<div class=\"gp-subnav\">" + tab("overview", "Overview", "/fragments/dex/overview") +
           tab("catalogue", "Catalogue", "/fragments/dex/catalogue") +
           tab("health", "Health score", "/fragments/dex/health") +
           tab("trends", "Trends", "/fragments/dex/trends") +
           tab("perf", "Performance", "/fragments/dex/perf") +
           tab("network", "Network", "/fragments/network/overview") + "</div>";
}

// Window chips for a given fragment path (reuses the overview pattern).
std::string dex_window_chips(const char* frag, int window_days) {
    const std::string cur = dex_window_token(window_days);
    auto chip = [&](const char* w, const char* label) {
        const std::string on = (cur == w) ? " on" : "";
        return "<a class=\"gp-chip" + on + "\" hx-get=\"" + frag + "?window=" + w +
               "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" + label + "</a>";
    };
    return "<div class=\"gp-filters\">" + chip("24h", "24h") + chip("7d", "7d") +
           chip("30d", "30d") + chip("all", "All") + "</div>";
}

// One family's rollup over the window (events, active count, blast radius, leader).
struct DexFamilyRollup {
    int64_t events = 0;
    int active = 0;
    int total = 0;
    int64_t devices = 0;
    const DexSignalCount* top = nullptr;
    bool benign = false;
};
DexFamilyRollup dex_family_rollup(const DexSignalGroup& g,
                                  const std::vector<DexSignalCount>& signals) {
    DexFamilyRollup r;
    r.total = static_cast<int>(g.types.size());
    r.benign = std::string(g.name) == "Boot, start-up & shutdown";
    for (const char* t : g.types) {
        const DexSignalCount* c = nullptr;
        for (const auto& s : signals)
            if (s.obs_type == t) {
                c = &s;
                break;
            }
        if (!c)
            continue;
        r.events += c->count;
        if (c->count > 0)
            ++r.active;
        if (c->distinct_devices > r.devices)
            r.devices = c->distinct_devices;
        if (!r.top || c->count > r.top->count)
            r.top = c;
    }
    return r;
}

// DEX Catalogue — View 1: the 13 family cards (mockup dex-catalogue.html). Replaces
// the flat All-signals table with a card grid that drills into a family, then a
// signal. Reuses dex_signal_summary + dex_signal_groups; the per-signal drill
// (View 3) needs a generic per-obs_type read-model and lands next.
std::string render_dex_catalogue_fragment(const GuaranteedStateStore* store,
                                          const std::string& since, int window_days,
                                          const DexFleet& fleet, const std::string& os_filter) {
    if (!store)
        return placeholder("Catalogue unavailable", "The signal observation store is not open.");
    const std::string w = dex_window_token(window_days);
    const auto signals = store->dex_signal_summary(since);

    // -- Coverage scope: which platforms are in view ("all" = connected fleet) --
    auto norm = [](std::string o) -> std::string {
        for (auto& c : o) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (o.starts_with("win")) return "windows";
        if (o == "darwin" || o == "macos") return "macos";
        if (o.starts_with("lin")) return "linux";
        return o;
    };
    const std::string osf = (os_filter == "windows" || os_filter == "linux" || os_filter == "macos")
                                ? os_filter
                                : "all";
    std::vector<std::string> scope;
    if (osf == "all") {
        for (const auto& o : fleet.connected_os) {
            auto n = norm(o);
            if (std::find(scope.begin(), scope.end(), n) == scope.end())
                scope.push_back(n);
        }
    } else {
        scope.push_back(osf);
    }
    auto in_scope = [&](const std::string& p) {
        return std::find(scope.begin(), scope.end(), p) != scope.end();
    };
    auto monitored = [&](const std::string& t) {
        for (const auto& p : dex_obs_platforms(t))
            if (in_scope(p))
                return true;
        return false;
    };

    // -- Per-family health score: the ONE canonical composite, projected per family
    // (score = 100 − that family's deduction; same formula as dex_compute_health).
    // Windows-denominated today (the existing fleet composite); a per-OS read is the
    // shared follow-up. --
    std::size_t total_types = dex_catalogued_type_count();
    std::size_t mon_types = 0;
    for (const auto& g : dex_signal_groups())
        for (const char* t : g.types)
            if (monitored(t))
                ++mon_types;

    std::string h;
    h += "<a class=\"gp-back\" href=\"/\">&larr; Dashboard</a>";
    h += dex_subnav("catalogue", window_days);
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>Signal catalogue</h1></div>"
         "<div class=\"gp-sub\"><b>" +
         num(static_cast<int64_t>(mon_types)) + "</b> of " +
         num(static_cast<int64_t>(total_types)) + " signal types <b>actively monitored</b> " +
         (osf == "all" ? "across your connected platforms" : "on " + osf) +
         ". A family lights when a connected platform <b>collects</b> the signal &mdash; not just "
         "when it fired. Quiet checks read as <i>watched</i>, never <i>missing</i>.</div></div></div>";

    // OS filter (Catalogue-style, shared with the device/overview surfaces).
    {
        auto chip = [&](const char* val, const char* label) {
            const std::string on = (osf == val) ? " on" : "";
            return "<a class=\"gp-chip" + on + "\" hx-get=\"/fragments/dex/catalogue?window=" + w +
                   "&os=" + val + "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" +
                   label + "</a>";
        };
        h += "<div class=\"gp-filters\"><span class=\"gp-mute\" style=\"font-size:.66rem;"
             "align-self:center\">OS</span>" +
             chip("all", "All connected") + chip("windows", "Windows") + chip("linux", "Linux") +
             chip("macos", "macOS") + "</div>";
    }
    h += dex_window_chips("/fragments/dex/catalogue", window_days);

    h += "<div class=\"gp-fgrid\">";
    for (const auto& g : dex_signal_groups()) {
        const auto r = dex_family_rollup(g, signals);
        int mon = 0;
        for (const char* t : g.types)
            if (monitored(t))
                ++mon;
        const bool dark = (mon == 0);
        double score = -1.0;
        if (!dark && fleet.windows_online > 0)
            score = std::clamp(
                100.0 - dex_family_health_deduction(g, signals, fleet.windows_online), 0.0, 100.0);
        const char* tone =
            score < 0 ? "" : (score >= 90 ? "ok" : (score >= 75 ? "warn" : "bad"));
        h += "<a class=\"gp-fcard" + std::string(dark ? " quiet" : "") +
             "\" hx-get=\"/fragments/dex/catalogue/group?name=" + url_encode(g.name) +
             "&window=" + w + "&os=" + osf +
             "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">";
        h += "<div class=\"fn\">" + esc(g.name) + "<span class=\"cnt\">" + num(mon) + " of " +
             num(static_cast<int64_t>(g.types.size())) + " monitored</span></div>";
        if (score < 0)
            h += "<div class=\"fev\">&mdash;</div>";
        else
            h += "<div class=\"fev " + std::string(tone) + "\">" +
                 std::to_string(static_cast<int>(score + 0.5)) + "</div>";
        h += "<div class=\"fmeta\">" +
             std::string(dark ? "not collected on your fleet" : "health score") + "</div>";
        if (dark)
            h += "<div class=\"ftop\">no connected platform watches these</div>";
        else if (r.events > 0 && r.top)
            h += "<div class=\"ftop\"><b>" + dex_signal_label(r.top->obs_type) + "</b> &middot; " +
                 num(r.events) + " events</div>";
        else
            h += "<div class=\"ftop\">monitored &middot; nothing fired</div>";
        h += "</a>";
    }
    h += "</div>";
    h += "<div class=\"gp-note\">Score = the family's slice of the fleet health composite "
         "(100 &minus; its deduction). <b>Monitored</b> = a connected platform collects the type; "
         "dimmed = nothing in view watches it (<b>not</b> &ldquo;healthy&rdquo;). Use the OS filter "
         "to read coverage within a platform.</div>";

    // Forward-compat: any obs_type a newer agent emits that isn't catalogued in a
    // family yet surfaces here under "Other" — seen on the wire, just not curated
    // into the 13 families. (Was the overview's "Other" group; it moved here with
    // the rest of the per-type detail when the hub slimmed to summarise-and-link,
    // so nothing the fleet reports is silently dropped.)
    {
        std::vector<const DexSignalCount*> extras;
        for (const auto& sig : signals) {
            bool known = false;
            for (const auto& g : dex_signal_groups()) {
                for (const char* t : g.types)
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
            h += "<div class=\"gp-sech\">Other (uncatalogued)</div>";
            h += "<div class=\"gp-note\">Seen on the wire but not in a curated family yet (a newer "
                 "agent emitted these). Listed so nothing the fleet reports is hidden.</div>";
            h += "<table class=\"gp-table\"><thead><tr><th>Signal</th><th>Type</th>"
                 "<th class=\"gp-num\">Events</th><th class=\"gp-num\">Devices</th><th>Last seen</th>"
                 "</tr></thead><tbody>";
            for (const auto* e : extras) {
                h += "<tr><td>" + dex_signal_label(e->obs_type) +
                     "</td><td class=\"gp-mute\" style=\"font-family:var(--mono)\">" +
                     esc(e->obs_type) + "</td><td class=\"gp-num\">" + num(e->count) +
                     "</td><td class=\"gp-num\">" + num(e->distinct_devices) +
                     "</td><td class=\"gp-mute\">" + esc(e->last_seen) + "</td></tr>";
            }
            h += "</tbody></table>";
        }
    }
    return h;
}

// DEX Catalogue — View 2: one family's signals (the visibility contract — every
// catalogued type, quiet ones muted). `group_name` is allowlisted against
// dex_signal_groups(); unknown names render an escaped placeholder.
std::string render_dex_catalogue_group_fragment(const GuaranteedStateStore* store,
                                                const std::string& since, int window_days,
                                                const std::string& group_name,
                                                const DexFleet& fleet,
                                                const std::string& os_filter) {
    if (!store)
        return placeholder("Catalogue unavailable", "The signal observation store is not open.");
    const DexSignalGroup* grp = nullptr;
    for (const auto& g : dex_signal_groups())
        if (group_name == g.name) {
            grp = &g;
            break;
        }
    if (!grp)
        return placeholder("Unknown family", "No such signal family: " + esc(group_name));

    const std::string w = dex_window_token(window_days);
    const auto signals = store->dex_signal_summary(since);
    const auto r = dex_family_rollup(*grp, signals);
    auto find_sig = [&](const char* t) -> const DexSignalCount* {
        for (const auto& s : signals)
            if (s.obs_type == t)
                return &s;
        return nullptr;
    };

    // -- Coverage scope (mirrors the grid: a type is MONITORED when an in-scope
    // connected platform collects it — not merely when it fired). This is the
    // same fix the grid carries, applied one level down so the tiles are honest. --
    auto norm = [](std::string o) -> std::string {
        for (auto& c : o) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (o.starts_with("win")) return "windows";
        if (o == "darwin" || o == "macos") return "macos";
        if (o.starts_with("lin")) return "linux";
        return o;
    };
    const std::string osf = (os_filter == "windows" || os_filter == "linux" ||
                             os_filter == "macos")
                                ? os_filter
                                : "all";
    std::vector<std::string> scope;
    if (osf == "all") {
        for (const auto& o : fleet.connected_os) {
            auto n = norm(o);
            if (std::find(scope.begin(), scope.end(), n) == scope.end())
                scope.push_back(n);
        }
    } else {
        scope.push_back(osf);
    }
    auto in_scope = [&](const std::string& p) {
        return std::find(scope.begin(), scope.end(), p) != scope.end();
    };
    auto monitored = [&](const char* t) {
        for (const auto& p : dex_obs_platforms(t))
            if (in_scope(p))
                return true;
        return false;
    };
    // In-scope platforms that collect this type — muted detail next to the pill.
    auto coverage_label = [&](const char* t) -> std::string {
        std::vector<std::string> ps;
        for (const auto& p : dex_obs_platforms(t))
            if (in_scope(p))
                ps.push_back(p);
        std::sort(ps.begin(), ps.end());
        std::string out;
        for (const auto& p : ps) {
            if (!out.empty()) out += ", ";
            out += (p == "windows" ? "Windows"
                    : p == "linux" ? "Linux"
                    : p == "macos" ? "macOS"
                                   : p);
        }
        return out;
    };
    int mon = 0;
    for (const char* t : grp->types)
        if (monitored(t))
            ++mon;

    auto tile = [](const char* cls, const std::string& n, const std::string& label,
                   const std::string& sx) {
        std::string t = "<div class=\"gp-tile\"><div class=\"n " + std::string(cls) + "\">" + n +
                        "</div><div class=\"l\">" + label + "</div>";
        if (!sx.empty())
            t += "<div class=\"sx\">" + sx + "</div>";
        return t + "</div>";
    };

    std::string h;
    // Back-link carries the OS lens so the grid restores it (filter persists on drill).
    h += "<a class=\"gp-back\" hx-get=\"/fragments/dex/catalogue?window=" + w + "&os=" + osf +
         "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">&larr; All families</a>";
    h += dex_subnav("catalogue", window_days);
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>" + esc(group_name) +
         "</h1></div><div class=\"gp-sub\"><b>" + num(mon) + "</b> of " +
         num(static_cast<int64_t>(grp->types.size())) + " types <b>monitored</b> " +
         (osf == "all" ? "across your connected platforms" : "on " + osf) + " &middot; " +
         num(r.active) + " active in this window. Monitored types light even when quiet; types no "
         "connected platform collects read as <i>not collected</i> &mdash; never as healthy."
         "</div></div></div>";

    // OS filter chips — same lens as the grid, re-targeting THIS family so the
    // filter both persists AND is changeable in place.
    {
        auto chip = [&](const char* val, const char* label) {
            const std::string on = (osf == val) ? " on" : "";
            return "<a class=\"gp-chip" + on + "\" hx-get=\"/fragments/dex/catalogue/group?name=" +
                   url_encode(group_name) + "&window=" + w + "&os=" + val +
                   "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" + label + "</a>";
        };
        h += "<div class=\"gp-filters\"><span class=\"gp-mute\" style=\"font-size:.66rem;"
             "align-self:center\">OS</span>" +
             chip("all", "All connected") + chip("windows", "Windows") + chip("linux", "Linux") +
             chip("macos", "macOS") + "</div>";
    }

    // Coverage + activity tiles. Health score = this family's slice of the fleet
    // composite (same formula as the grid card), shown when something is monitored.
    h += "<div class=\"gp-tiles\">";
    double score = -1.0;
    if (mon > 0 && fleet.windows_online > 0)
        score = std::clamp(100.0 - dex_family_health_deduction(*grp, signals, fleet.windows_online),
                           0.0, 100.0);
    if (score >= 0)
        h += tile(score >= 90 ? "ok" : (score >= 75 ? "warn" : "bad"),
                  std::to_string(static_cast<int>(score + 0.5)), "Health score",
                  "100 &minus; deduction");
    h += tile("info", num(mon) + " of " + num(static_cast<int64_t>(grp->types.size())), "Monitored",
              osf == "all" ? "on your fleet" : "on " + osf);
    h += tile(r.benign ? "ok" : (r.events > 0 ? "warn" : ""), num(r.events),
              r.benign ? "Reports (window)" : "Events (window)", "");
    h += tile("", num(r.devices), "Devices affected", "");
    h += "</div>";

    h += "<div class=\"gp-sech\">Signals in this family</div>";
    h += "<div class=\"gp-note\">Every catalogued type is listed. <b>Monitored</b> rows are watched "
         "by a connected platform (lit even at zero events); <b>not collected</b> rows have no "
         "platform in view that emits them. Devices is the blast radius (distinct devices).</div>";
    h += "<table class=\"gp-table\"><thead><tr><th>Signal</th><th>Coverage</th>"
         "<th class=\"gp-num\">Events</th><th class=\"gp-num\">Devices</th><th>Last seen</th>"
         "</tr></thead><tbody>";
    auto row = [&](const char* t, const DexSignalCount* c, bool mon_t) {
        // Every row drills into the per-signal-type view (View 3), carrying the OS
        // lens so View3's back-link restores the filtered family.
        const std::string drill = " hx-get=\"/fragments/dex/catalogue/signal?type=" +
                                  url_encode(t) + "&window=" + w + "&os=" + osf +
                                  "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\"";
        const std::string cov =
            mon_t ? "<span class=\"gp-pill dep\">monitored</span> <span class=\"gp-mute\">" +
                        esc(coverage_label(t)) + "</span>"
                  : "<span class=\"gp-pill draft\">not collected" +
                        std::string(osf == "all" ? "" : " on " + osf) + "</span>";
        if (mon_t && c && c->count > 0)
            h += "<tr" + drill + " style=\"cursor:pointer\"><td>" + dex_signal_label(t) +
                 "</td><td>" + cov + "</td><td class=\"gp-num\">" + num(c->count) +
                 "</td><td class=\"gp-num\">" + num(c->distinct_devices) +
                 "</td><td class=\"gp-mute\">" + esc(c->last_seen) + "</td></tr>";
        else if (mon_t)
            h += "<tr class=\"gp-mute\"" + drill + " style=\"cursor:pointer\"><td>" +
                 dex_signal_label(t) + "</td><td>" + cov +
                 "</td><td class=\"gp-num\">0</td><td class=\"gp-num\">&mdash;</td>"
                 "<td>watched</td></tr>";
        else
            h += "<tr class=\"gp-mute\"" + drill + " style=\"cursor:pointer;opacity:.5\"><td>" +
                 dex_signal_label(t) + "</td><td>" + cov +
                 "</td><td class=\"gp-num\">&mdash;</td><td class=\"gp-num\">&mdash;</td>"
                 "<td>&mdash;</td></tr>";
    };
    // Coverage-first reading order: fired (monitored, events>0), then watched
    // (monitored, quiet), then not-collected last.
    for (const char* t : grp->types)
        if (monitored(t)) { const auto* c = find_sig(t); if (c && c->count > 0) row(t, c, true); }
    for (const char* t : grp->types)
        if (monitored(t)) { const auto* c = find_sig(t); if (!c || c->count == 0) row(t, c, true); }
    for (const char* t : grp->types)
        if (!monitored(t)) row(t, find_sig(t), false);
    h += "</tbody></table>";
    return h;
}

// DEX Catalogue — View 3: one signal type's drill-down (subjects, OS split,
// most-affected devices, activity trend). Consumes the generic per-obs_type
// read-model. `obs_type` is bound into SQL (injection-safe) and HTML-escaped in
// markup. The "Collected on" caption is COVERAGE — it comes from dex_obs_platforms
// (the authoritative per-OS map), NOT from observed events: a quiet-but-monitored
// signal must still show its real platforms. The dex_signal_by_os split drives the
// event counts only.
std::string render_dex_catalogue_signal_fragment(const GuaranteedStateStore* store,
                                                 const std::string& since, int window_days,
                                                 const std::string& obs_type,
                                                 const std::string& os_filter,
                                                 const std::set<std::string>* visible) {
    if (!store)
        return placeholder("Catalogue unavailable", "The signal observation store is not open.");
    if (obs_type.empty())
        return placeholder("No signal selected", "Pick a signal type from a family.");
    const std::string w = dex_window_token(window_days);
    const std::string osf = (os_filter == "windows" || os_filter == "linux" ||
                             os_filter == "macos")
                                ? os_filter
                                : "all";

    const char* family = nullptr;
    for (const auto& g : dex_signal_groups()) {
        for (const char* t : g.types)
            if (obs_type == t) {
                family = g.name;
                break;
            }
        if (family)
            break;
    }

    const auto subjects = store->dex_signal_subjects(obs_type, since, 15);
    const auto by_os = store->dex_signal_by_os(obs_type, since);
    const auto devices = store->dex_signal_devices(obs_type, since, 15);
    const auto by_day = store->dex_signal_by_day(obs_type, since);

    int64_t events = 0, devs = 0;
    for (const auto& o : by_os) {
        events += o.crashes; // generic event count
        devs += o.distinct_devices;
    }
    // "Collected on" = which platforms have a collector for this signal type, from
    // the authoritative coverage map (not observed events). This is the signal's
    // full cross-OS coverage; the os filter scopes the event lists, not which
    // platforms can collect the type.
    auto os_disp = [](const std::string& p) -> std::string {
        if (p == "windows") return "Windows";
        if (p == "macos") return "macOS";
        if (p == "linux") return "Linux";
        return p;
    };
    const auto coverage = dex_obs_platforms(obs_type);
    std::string collected_on;
    for (const auto& p : coverage)
        collected_on += (collected_on.empty() ? "" : " + ") + os_disp(p);
    if (collected_on.empty())
        collected_on = "&mdash;";
    const char* coverage_sx = coverage.size() > 1   ? "cross-OS signal"
                              : coverage.size() == 1 ? "single-platform signal"
                                                     : "no collector for this type";
    auto tile = [](const char* cls, const std::string& n, const std::string& label,
                   const std::string& sx) {
        std::string t = "<div class=\"gp-tile\"><div class=\"n " + std::string(cls) + "\">" + n +
                        "</div><div class=\"l\">" + label + "</div>";
        if (!sx.empty())
            t += "<div class=\"sx\">" + sx + "</div>";
        return t + "</div>";
    };

    std::string h;
    if (family)
        h += "<a class=\"gp-back\" hx-get=\"/fragments/dex/catalogue/group?name=" +
             url_encode(family) + "&window=" + w + "&os=" + osf +
             "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">&larr; " + esc(family) +
             "</a>";
    else
        h += "<a class=\"gp-back\" hx-get=\"/fragments/dex/catalogue?window=" + w + "&os=" + osf +
             "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">&larr; Catalogue</a>";
    h += dex_subnav("catalogue", window_days);
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>" + dex_signal_label(obs_type) +
         " <span style=\"font-family:var(--mono);font-size:0.9rem;color:var(--muted)\">" +
         esc(obs_type) + "</span></h1></div><div class=\"gp-sub\">Blast radius and failure shape "
         "for one signal type across the fleet.</div></div></div>";

    h += "<div class=\"gp-tiles\">";
    h += tile(events > 40 ? "bad" : (events > 0 ? "warn" : ""), num(events), "Events (window)", "");
    h += tile("", num(devs), "Devices affected", "");
    h += tile("info", collected_on, "Collected on", coverage_sx);
    h += "</div>";

    if (!by_day.empty()) {
        int64_t mx = 1;
        for (const auto& d : by_day)
            if (d.crashes > mx)
                mx = d.crashes;
        h += "<div class=\"gp-sech\">Activity (window)</div>";
        h += "<div style=\"display:flex;align-items:flex-end;gap:0.35rem;height:64px;margin:0.3rem "
             "0\">";
        for (const auto& d : by_day) {
            int hpx = static_cast<int>(d.crashes * 56 / mx);
            if (hpx < 2)
                hpx = 2;
            h += "<div style=\"flex:1;display:flex;flex-direction:column;align-items:center;"
                 "gap:0.2rem\"><div title=\"" +
                 esc(d.day) + ": " + num(d.crashes) +
                 "\" style=\"width:60%;background:var(--accent);border-radius:2px 2px 0 0;height:" +
                 std::to_string(hpx) + "px\"></div><small style=\"font-size:0.54rem;color:var(--muted)\">" +
                 esc(d.day.size() >= 5 ? d.day.substr(5) : d.day) + "</small></div>";
        }
        h += "</div>";
    }

    h += "<div class=\"gp-sech\">Top subjects</div>";
    if (subjects.empty()) {
        h += placeholder("No data", "No events for this signal in the window.");
    } else {
        h += "<table class=\"gp-table\"><thead><tr><th>Subject</th><th class=\"gp-num\">Events</th>"
             "<th class=\"gp-num\">Devices</th><th>Last seen</th></tr></thead><tbody>";
        for (const auto& s : subjects)
            h += "<tr><td>" + esc(s.subject) + "</td><td class=\"gp-num\">" + num(s.count) +
                 "</td><td class=\"gp-num\">" + num(s.distinct_devices) + "</td><td class=\"gp-mute\">" +
                 esc(s.last_seen) + "</td></tr>";
        h += "</tbody></table>";
    }

    h += "<div class=\"gp-sech\">By operating system</div>";
    h += "<table class=\"gp-table\"><thead><tr><th>OS</th><th class=\"gp-num\">Events</th>"
         "<th class=\"gp-num\">Devices</th></tr></thead><tbody>";
    if (by_os.empty())
        h += "<tr class=\"gp-mute\"><td colspan=\"3\">No events on any OS in this window.</td></tr>";
    for (const auto& o : by_os)
        h += "<tr><td>" + esc(o.platform) + "</td><td class=\"gp-num\">" + num(o.crashes) +
             "</td><td class=\"gp-num\">" + num(o.distinct_devices) + "</td></tr>";
    h += "</tbody></table>";
    h += "<div class=\"gp-note\">An OS with no events for <span style=\"font-family:var(--mono)\">" +
         esc(obs_type) + "</span> may simply <b>not collect</b> it &mdash; read within an OS, never "
         "across; absence is not health.</div>";

    h += "<div class=\"gp-sech\">Most-affected devices</div>";
    h += "<div class=\"gp-note\" style=\"color:var(--accent)\">&#128274; Behavioral data &mdash; "
         "which signals a device emits can reveal what a person runs. Access-gated + audit-logged."
         "</div>";
    if (devices.empty()) {
        h += placeholder("No data", "No devices reported this signal in the window.");
    } else {
        h += "<table class=\"gp-table\"><thead><tr><th>Device</th><th class=\"gp-num\">Events</th>"
             "<th>Last seen</th></tr></thead><tbody>";
        for (const auto& d : devices) {
            if (visible && !visible->count(d.agent_id))
                continue; // out-of-scope device — don't enumerate its id to this operator
            h += "<tr><td>" + esc(d.agent_id) + "</td><td class=\"gp-num\">" + num(d.crashes) +
                 "</td><td class=\"gp-mute\">" + esc(d.last_seen) + "</td></tr>";
        }
        h += "</tbody></table>";
    }
    return h;
}

// The composite-score weighting policy (mockup dex-health-score.html). Names MUST
// match dex_signal_groups(). `severity` = how much a failure of this family hurts
// experience; the four multipliers are the server-chosen weighting PRESETS. This
// is policy (transparent + shown), not data — the DATA is the measured impact rate.
struct DexFamilyWeight {
    const char* name;
    const char* severity; // "high" | "med" | "low"
    double m_default, m_stability, m_productivity, m_security;
};
const std::vector<DexFamilyWeight>& dex_family_weights() {
    static const std::vector<DexFamilyWeight> w = {
        {"App reliability", "high", 1.0, 1.3, 1.1, 0.8},
        {"System stability", "high", 1.0, 1.6, 0.9, 0.9},
        {"Network", "med", 1.0, 0.8, 1.5, 0.9},
        {"Service health", "med", 1.0, 1.2, 1.0, 0.9},
        {"Updates & installs", "med", 1.0, 1.0, 1.1, 1.0},
        {"Security & protection", "high", 1.0, 0.8, 0.7, 2.2},
        {"Identity & logon", "med", 1.0, 0.9, 1.2, 1.6},
        {"Hardware & storage", "med", 1.0, 1.4, 0.8, 0.9},
        {"Performance", "med", 1.0, 1.1, 1.5, 0.7},
        {"Printing", "low", 1.0, 0.6, 1.6, 0.6},
        {"Boot, start-up & shutdown", "low", 1.0, 0.9, 1.5, 0.7},
        {"Policy & management", "low", 1.0, 0.9, 0.9, 1.3},
        {"File system", "low", 1.0, 1.3, 0.7, 0.9},
    };
    return w;
}
double dex_severity_points(const std::string& sev) {
    return sev == "high" ? 12.0 : (sev == "med" ? 6.0 : 2.0);
}
double dex_preset_mult(const DexFamilyWeight& fw, const std::string& preset) {
    if (preset == "stability")
        return fw.m_stability;
    if (preset == "productivity")
        return fw.m_productivity;
    if (preset == "security")
        return fw.m_security;
    return fw.m_default;
}

// The composite-health computation, shared by the Health page and the Overview
// hub's health teaser. score = 100 − Σ deductions; -1 when N<=0 (suppressed, no
// reporting agents → no fabricated 100).
struct DexHealthResult {
    double score = -1.0;
    struct Ded {
        std::string name, sev;
        double deduction = 0.0;
    };
    std::vector<Ded> deds;
};
DexHealthResult dex_compute_health(const std::vector<DexSignalCount>& signals, int64_t N,
                                   const std::string& preset) {
    DexHealthResult r;
    if (N <= 0)
        return r;
    double total = 0.0;
    for (const auto& fw : dex_family_weights()) {
        const DexSignalGroup* g = nullptr;
        for (const auto& grp : dex_signal_groups())
            if (std::string(grp.name) == fw.name) {
                g = &grp;
                break;
            }
        const DexFamilyRollup rr = g ? dex_family_rollup(*g, signals) : DexFamilyRollup{};
        double impact = static_cast<double>(rr.devices) / static_cast<double>(N);
        if (impact > 1.0)
            impact = 1.0;
        const double ded = dex_severity_points(fw.severity) * dex_preset_mult(fw, preset) * impact;
        r.deds.push_back({fw.name, fw.severity, ded});
        total += ded;
    }
    r.score = std::clamp(100.0 - total, 0.0, 100.0);
    return r;
}

// One family's deduction — the per-family term of dex_compute_health above, factored
// out so the Catalogue's per-card score is provably the SAME number (default preset).
double dex_family_health_deduction(const DexSignalGroup& g,
                                   const std::vector<DexSignalCount>& signals, int64_t N) {
    if (N <= 0)
        return 0.0;
    const DexFamilyRollup rr = dex_family_rollup(g, signals);
    double impact = static_cast<double>(rr.devices) / static_cast<double>(N);
    if (impact > 1.0)
        impact = 1.0;
    for (const auto& fw : dex_family_weights())
        if (std::string(fw.name) == g.name)
            return dex_severity_points(fw.severity) * dex_preset_mult(fw, "default") * impact;
    return 0.0;
}

int dex_device_score(const GuaranteedStateStore* store, const std::string& agent_id,
                     const std::string& since) {
    if (!store)
        return -1;
    const auto device_signals = store->dex_device_signal_summary(agent_id, since);
    double total = 0.0;
    for (const auto& fw : dex_family_weights()) {
        const DexSignalGroup* g = nullptr;
        for (const auto& grp : dex_signal_groups())
            if (std::string(grp.name) == fw.name) {
                g = &grp;
                break;
            }
        if (!g)
            continue;
        const DexFamilyRollup rr = dex_family_rollup(*g, device_signals);
        if (rr.benign || rr.events <= 0) // benign reports (boot/uptime) never deduct
            continue;
        // Per-device impact: this device's events in the family, gently scaled
        // (1 event = partial; kCap+ events = full severity). Illustrative cap,
        // pending calibration (like the perf baseline).
        constexpr double kCap = 5.0;
        const double impact = std::min(1.0, static_cast<double>(rr.events) / kCap);
        total += dex_severity_points(fw.severity) * dex_preset_mult(fw, "default") * impact;
    }
    return static_cast<int>(std::clamp(100.0 - total, 0.0, 100.0) + 0.5);
}

// DEX Health score — the derived/SECONDARY composite (mockup dex-health-score.html).
// score = 100 − Σ deductions; deduction(family) = severity points × preset
// multiplier × measured impact rate (devices hit / reporting agents). Every
// deduction traces to a real Catalogue rate — nothing invented. Suppressed (no
// number) when there are no reporting agents (coverage honesty, no fake 100).
std::string render_dex_health_fragment(const GuaranteedStateStore* store, const std::string& since,
                                       int window_days, DexFleet fleet,
                                       const std::string& weighting) {
    if (!store)
        return placeholder("Health score unavailable", "The signal observation store is not open.");
    const std::string w = dex_window_token(window_days);
    const std::string preset =
        (weighting == "stability" || weighting == "productivity" || weighting == "security")
            ? weighting
            : "default";

    const auto signals = store->dex_signal_summary(since);
    const auto summary = store->dex_crash_summary(since);
    const int64_t N = fleet.windows_online; // scored over reporting Windows agents

    std::string h;
    h += "<a class=\"gp-back\" href=\"/\">&larr; Dashboard</a>";
    h += dex_subnav("health", window_days);
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>Experience health</h1></div>"
         "<div class=\"gp-sub\">A single roll-up of the measured signal rates &mdash; it "
         "<b>summarises</b>, it does not replace. Every number it rolls up stays independently "
         "visible on the Catalogue.</div></div></div>";
    h += dex_window_chips("/fragments/dex/health", window_days);
    h += "<div class=\"gp-reversal\">&#9888;&#65039; <b>Derived &amp; secondary.</b> The measured "
         "crash-free rate stays the headline; this composite rolls the measured family rates into "
         "one number (a board slide / fleet-vs-fleet comparison), built transparent &mdash; every "
         "deduction traces to a rate you can open.</div>";

    // Measured headline stays primary.
    h += "<div class=\"gp-sech\">Measured headline (unchanged &mdash; the real number)</div>";
    h += "<div class=\"gp-primary\">";
    if (N > 0) {
        int64_t impacted = summary.distinct_devices > N ? N : summary.distinct_devices;
        const double cf = 100.0 * static_cast<double>(N - impacted) / static_cast<double>(N);
        h += "<div><div class=\"big\">" + std::format("{:.1f}%", cf) +
             "</div><div class=\"lbl\">Crash-free devices</div></div>";
    } else {
        h += "<div><div class=\"big sec\" style=\"color:var(--muted)\">&mdash;</div>"
             "<div class=\"lbl\">Crash-free &middot; no reporting agents</div></div>";
    }
    h += "<div class=\"vdiv\"></div><div><div class=\"big sec\">" + num(summary.total_crashes) +
         "</div><div class=\"lbl\">Crashes (window)</div></div></div>";

    // Composite gauge.
    h += "<div class=\"gp-sech\">Composite index (derived from the measured family rates)</div>";
    if (N == 0) {
        h += placeholder("Index suppressed",
                         "No reporting agents to score &mdash; a composite would be a fabricated "
                         "100, so it is withheld rather than shown. It populates as agents report.");
        return h;
    }

    const auto health = dex_compute_health(signals, N, preset);
    const auto& deds = health.deds;
    const double score = health.score;
    const char* band_cls = score >= 90 ? "excellent" : score >= 75 ? "good" : score >= 60 ? "fair" : "poor";
    const char* band_lbl = score >= 90 ? "Excellent" : score >= 75 ? "Good" : score >= 60 ? "Fair" : "Poor";
    const char* arc = score >= 75 ? "#4ed27e" : score >= 60 ? "#ffcc00" : "#ff5765";

    h += "<div class=\"gp-composite\"><div class=\"gp-gauge\"><svg width=\"140\" height=\"140\" "
         "viewBox=\"0 0 140 140\"><circle cx=\"70\" cy=\"70\" r=\"60\" fill=\"none\" "
         "stroke=\"#2d4068\" stroke-width=\"12\"/><circle cx=\"70\" cy=\"70\" r=\"60\" fill=\"none\" "
         "stroke=\"" + std::string(arc) +
         "\" stroke-width=\"12\" stroke-linecap=\"round\" stroke-dasharray=\"377\" "
         "stroke-dashoffset=\"" + std::format("{:.0f}", 377.0 * (1.0 - score / 100.0)) +
         "\" transform=\"rotate(-90 70 70)\"/></svg><div class=\"val\"><div class=\"num\">" +
         std::format("{:.0f}", score) + "</div><div class=\"band band-" + band_cls + "\">" +
         band_lbl + "</div></div></div>";
    h += "<div style=\"flex:1;min-width:240px\"><span class=\"gp-derived\">derived &middot; "
         "secondary</span><div class=\"gp-sub\" style=\"margin-top:0.3rem\">Scored over <b>" +
         num(N) + "</b> reporting agents. Disarmed + offline are excluded, not scored healthy "
         "&mdash; unknown, not 100.</div>";
    auto pchip = [&](const char* p, const char* label) {
        const std::string on = (preset == p) ? " on" : "";
        return "<a class=\"gp-chip" + on + "\" hx-get=\"/fragments/dex/health?window=" + w +
               "&weighting=" + p + "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" +
               label + "</a>";
    };
    h += "<div class=\"gp-filters\"><span style=\"font-size:0.7rem;color:var(--muted)\">weighting:"
         "</span>" + pchip("default", "Default") + pchip("stability", "Stability") +
         pchip("productivity", "Productivity") + pchip("security", "Security") + "</div>";
    h += "<div class=\"gp-sub\" style=\"font-size:0.62rem\">Presets round-trip to the server (hx-get "
         "<span style=\"font-family:var(--mono)\">?weighting=</span>) &mdash; not a slider. The "
         "number moves because the <i>weights</i> change; the measured rates don't.</div></div></div>";

    // Decomposition (leads).
    auto sorted = deds;
    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b) { return a.deduction > b.deduction; });
    // One color per display family (13) — sized to dex_signal_groups() so two
    // families never share a swatch; index by std::size, not a literal.
    static const char* kColors[] = {"#ff5765", "#ff7a52", "#ffae42", "#ffcc00", "#d6d34e",
                                    "#a9d34e", "#7ed27e", "#4ed27e", "#4ed2a8", "#4ec3d2",
                                    "#4e9fd2", "#6f86a6", "#b48ead"};
    double maxD = 0.0001;
    for (const auto& d : sorted)
        maxD = std::max(maxD, d.deduction);
    h += "<div class=\"gp-sech\">Why this score &mdash; what each family deducts</div>";
    h += "<div class=\"gp-stack\"><span style=\"flex:" + std::format("{:.1f}", score) +
         ";background:#243553;color:var(--fg)\">health " + std::format("{:.0f}", score) + "</span>";
    int ci = 0;
    for (const auto& d : sorted) {
        if (d.deduction < 0.05)
            continue;
        h += "<span style=\"flex:" + std::format("{:.2f}", d.deduction) + ";background:" +
             kColors[static_cast<std::size_t>(ci) % std::size(kColors)] + "\" title=\"" +
             esc(d.name) + ": -" +
             std::format("{:.1f}", d.deduction) + "\"></span>";
        ++ci;
    }
    h += "</div>";
    for (const auto& d : sorted) {
        const bool zero = d.deduction < 0.05;
        h += "<div class=\"gp-ded\"><span class=\"fam\">" + esc(d.name) + "</span><span class=\"wt "
             "wt-" + d.sev + "\">" + d.sev + "</span><span><span class=\"bar\" style=\"display:block;"
             "width:" + std::format("{:.0f}", std::max(2.0, d.deduction / maxD * 100.0)) +
             "%\"></span></span><span class=\"pts\" style=\"color:" +
             (zero ? "var(--muted)" : "var(--red)") + "\">&minus;" + std::format("{:.1f}", d.deduction) +
             "</span></div>";
    }
    h += "<div class=\"gp-note\">Score = <b>100 &minus; weighted deductions</b>, one per family. "
         "Weight = severity class &times; the active preset; deduction = weight &times; the family's "
         "measured impact (devices hit / reporting agents). Nothing is invented &mdash; every "
         "deduction traces to a rate on the Catalogue.</div>";

    // Per-family sub-scores (catalogue order).
    h += "<div class=\"gp-sech\">Per-family health</div><div class=\"gp-subgrid\">";
    for (const auto& d : deds) {
        const double ss = 100.0 - (d.deduction / maxD) * 22.0;
        const char* sc = ss >= 90 ? "excellent" : ss >= 75 ? "good" : ss >= 60 ? "fair" : "poor";
        h += "<div class=\"gp-sscore\"><div class=\"nm\">" + esc(d.name) + "</div><div class=\"vv "
             "band-" + sc + "\">" + std::format("{:.0f}", ss) + "</div><div class=\"ds\">&minus;" +
             std::format("{:.1f}", d.deduction) + " pts &middot; " + d.sev + " weight</div></div>";
    }
    h += "</div>";
    h += "<div class=\"gp-note\">Score trend, weekly movers, and lowest-health devices need a stored "
         "score history &mdash; a follow-on increment (no fabricated history shown here).</div>";
    return h;
}

// obs_type → family index (into dex_signal_groups), or -1.
int dex_family_index(const std::string& obs_type) {
    int fi = 0;
    for (const auto& g : dex_signal_groups()) {
        for (const char* t : g.types)
            if (obs_type == t)
                return fi;
        ++fi;
    }
    return -1;
}
// Inline-SVG sparkline from a daily series.
std::string dex_sparkline(const std::vector<int64_t>& series, const char* color) {
    if (series.empty())
        return {};
    const double wpx = 130, hpx = 28;
    int64_t mx = 1;
    for (auto v : series)
        if (v > mx)
            mx = v;
    std::string pts;
    for (std::size_t i = 0; i < series.size(); ++i) {
        const double x = series.size() > 1 ? static_cast<double>(i) / (series.size() - 1) * wpx : 0;
        const double y = hpx - static_cast<double>(series[i]) / mx * (hpx - 3) - 1;
        if (!pts.empty())
            pts += " ";
        pts += std::format("{:.1f},{:.1f}", x, y);
    }
    return "<svg width=\"130\" height=\"28\" viewBox=\"0 0 130 28\"><polyline points=\"" + pts +
           "\" fill=\"none\" stroke=\"" + color + "\" stroke-width=\"1.5\"/></svg>";
}
const char* dex_heat_color(double t) { // t in 0..1, within-row scaled
    if (t <= 0.0)
        return "#16233a";
    if (t < 0.2)
        return "#243f5e";
    if (t < 0.4)
        return "#2f6f7e";
    if (t < 0.6)
        return "#caa23b";
    if (t < 0.8)
        return "#e07a52";
    return "#ff5765";
}

// DEX Trends — cross-OS comparison + per-family small-multiples + activity heatmap
// (mockup dex-trends.html). The cross-OS scope is DERIVED LIVE from
// dex_os_signal_scope (no stale "macOS 6 of 103"); rows are within-OS only.
std::string render_dex_trends_fragment(const GuaranteedStateStore* store, const std::string& since,
                                       int window_days, DexFleet fleet) {
    if (!store)
        return placeholder("Trends unavailable", "The signal observation store is not open.");
    const auto scope = store->dex_os_signal_scope(since);
    const auto matrix = store->dex_signal_day_matrix(since);
    const auto summary = store->dex_crash_summary(since);
    const int64_t total_types = static_cast<int64_t>(dex_catalogued_type_count());

    auto scope_of = [&](const char* p) -> const DexOsScope* {
        for (const auto& s : scope)
            if (s.platform.find(p) != std::string::npos)
                return &s;
        return nullptr;
    };

    std::string h;
    h += "<a class=\"gp-back\" href=\"/\">&larr; Dashboard</a>";
    h += dex_subnav("trends", window_days);
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>Cross-OS &amp; signal trends"
         "</h1></div><div class=\"gp-sub\">Coverage-honest by design: each OS collects a different "
         "slice of the catalogue, so read <b>within</b> an OS, never across &mdash; fewer signals "
         "means we observe less, not a healthier fleet.</div></div></div>";
    h += dex_window_chips("/fragments/dex/trends", window_days);

    // ── Cross-OS cards (live-derived scope) ──
    h += "<div class=\"gp-sech\">By operating system</div><div class=\"gp-oscards\">";
    auto os_card = [&](const char* key, const char* label, bool primary) {
        const DexOsScope* s = scope_of(key);
        const int64_t types = s ? s->distinct_types : 0;
        const int64_t events = s ? s->total_events : 0;
        const bool live = s != nullptr || (primary && fleet.windows_online > 0);
        std::string c = "<div class=\"gp-oscard" + std::string(live ? "" : " pending") + "\">";
        c += "<div class=\"os\">" + std::string(label) + " <span class=\"state " +
             (!live ? "pending\">collector pending" : (types < total_types ? "limited\">live &middot; limited" : "live\">live")) +
             "</span></div>";
        c += "<div class=\"scope\">Collects <b>" + num(types) + "</b> of " + num(total_types) +
             " signal types in this window</div>";
        c += "<div class=\"gp-tiles\" style=\"margin-top:.6rem\">";
        if (primary && fleet.windows_online > 0) {
            int64_t impacted = summary.distinct_devices > fleet.windows_online ? fleet.windows_online : summary.distinct_devices;
            const double cf = 100.0 * static_cast<double>(fleet.windows_online - impacted) /
                              static_cast<double>(fleet.windows_online);
            c += "<div class=\"gp-tile\"><div class=\"n good\">" + std::format("{:.1f}%", cf) +
                 "</div><div class=\"l\">Crash-free</div></div>";
            c += "<div class=\"gp-tile\"><div class=\"n\">" + num(fleet.windows_online) +
                 "</div><div class=\"l\">Reporting</div></div>";
        }
        c += "<div class=\"gp-tile\"><div class=\"n " + std::string(live ? "" : "mute") + "\">" +
             (live ? num(events) : "&mdash;") + "</div><div class=\"l\">Events (window)</div></div>";
        c += "</div></div>";
        return c;
    };
    h += os_card("win", "Windows", true);
    h += os_card("mac", "macOS", false);
    h += os_card("lin", "Linux", false);
    h += "</div>";
    h += "<div class=\"gp-note\">Each OS row is scoped to the types <b>it</b> collects &mdash; a "
         "lower number on an OS that observes fewer types means narrower observation, <b>not</b> a "
         "healthier fleet. Linux: journald collectors are pending.</div>";

    // ── Aggregate the matrix into family × day ──
    std::vector<std::string> days;
    for (const auto& m : matrix)
        if (days.empty() || days.back() != m.day)
            days.push_back(m.day);
    auto day_index = [&](const std::string& d) {
        for (std::size_t i = 0; i < days.size(); ++i)
            if (days[i] == d)
                return static_cast<int>(i);
        return -1;
    };
    const int nfam = static_cast<int>(dex_signal_groups().size());
    std::vector<std::vector<int64_t>> cell(nfam, std::vector<int64_t>(days.size(), 0));
    for (const auto& m : matrix) {
        const int fi = dex_family_index(m.obs_type);
        const int di = day_index(m.day);
        if (fi >= 0 && di >= 0)
            cell[fi][di] += m.count;
    }

    if (days.empty()) {
        h += "<div class=\"gp-sech\">Signal families over time</div>";
        h += placeholder("No activity yet", "No signals in this window to trend.");
        return h;
    }

    // ── Small-multiples ──
    h += "<div class=\"gp-sech\">Signal families over time</div><div class=\"gp-smgrid\">";
    int fi = 0;
    for (const auto& g : dex_signal_groups()) {
        int64_t total = 0;
        for (auto v : cell[fi])
            total += v;
        h += "<div class=\"gp-sm\"><div class=\"smh\"><span class=\"smn\">" + esc(g.name) +
             "</span><span class=\"smv\">" + num(total) + "</span></div>" +
             dex_sparkline(cell[fi], total > 0 ? "#00bceb" : "#3a4d6b") + "</div>";
        ++fi;
    }
    h += "</div>";

    // ── Heatmap (family × day, last up-to-14 days, row-scaled) ──
    const int show_days = static_cast<int>(days.size()) > 14 ? 14 : static_cast<int>(days.size());
    const int day0 = static_cast<int>(days.size()) - show_days;
    h += "<div class=\"gp-sech\">Activity heatmap (family &times; day)</div>";
    h += "<div class=\"gp-heat\">";
    fi = 0;
    for (const auto& g : dex_signal_groups()) {
        int64_t rowmax = 1;
        for (int d = day0; d < static_cast<int>(days.size()); ++d)
            if (cell[fi][d] > rowmax)
                rowmax = cell[fi][d];
        h += "<div class=\"hrow\"><span class=\"hlbl\">" + esc(g.name) + "</span>";
        for (int d = day0; d < static_cast<int>(days.size()); ++d) {
            const double t = static_cast<double>(cell[fi][d]) / static_cast<double>(rowmax);
            h += "<i style=\"background:" + std::string(dex_heat_color(cell[fi][d] > 0 ? t : 0.0)) +
                 "\" title=\"" + esc(days[d]) + ": " + num(cell[fi][d]) + "\"></i>";
        }
        h += "</div>";
        ++fi;
    }
    h += "</div>";
    h += "<div class=\"gp-note\">Rows are scaled <b>independently</b> (within-family) so a small "
         "family and a busy one both show their shape. Read a row left-to-right for a family's "
         "trend.</div>";
    return h;
}

std::string render_dex_overview_fragment(const GuaranteedStateStore* store,
                                         const std::string& since, int window_days, DexFleet fleet,
                                         const std::set<std::string>* visible) {
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
    head += dex_subnav("overview", window_days);
    head += "<div class=\"gp-head\"><div>"
            "<div class=\"gp-titleline\"><h1>Digital Employee Experience</h1></div>"
            "<div class=\"gp-sub\">Fleet experience from device signals &mdash; the per-device "
            "score distribution, the Device/App/Network breakdown, and the measured reliability "
            "rates below. The score is a <b>derived roll-up of measured facts</b>.</div></div></div>";
    head += "<div class=\"gp-filters\">" + chip("24h", "24h") + chip("7d", "7d") +
            chip("30d", "30d") + chip("all", "All") + "</div>";

    // The whole-catalogue rollup. NOTE: no whole-page empty state any more —
    // the All-signals panel below always lists every catalogued type, fired or
    // not (zero counts are real data: "monitored, nothing happened").
    const auto signals = store->dex_signal_summary(since);

    const auto summary = store->dex_crash_summary(since);
    const auto apps = store->dex_top_apps(since, 8);
    const auto devices = store->dex_top_devices(since, 8);
    const auto by_day = store->dex_crashes_by_day(since);
    // Per-OS signal coverage: every OS that reported anything, with its distinct
    // type count. Drives the By-OS table's LIVE "N of M types" (replaces the
    // mockup's stale "macOS 6 of 103") and the cross-OS explore teaser.
    const auto os_scope = store->dex_os_signal_scope(since);
    const int64_t total_types = static_cast<int64_t>(dex_catalogued_type_count());

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

    // ── Experience (reframed headline) — the per-device DEX score distribution +
    // the family-bucket breakdown (Device/App/Network), ABOVE the measured crash
    // rates (which demote to one section below). Per-device scores are computed
    // here from the connected agent ids (window-respecting); only the Overview
    // pays this cost. ──
    {
        std::vector<int> ds;
        ds.reserve(fleet.connected_agents.size());
        // Per-segment (os) accumulation for the breakdown (small N — linear).
        std::vector<std::string> seg_os;
        std::vector<int> seg_n;
        std::vector<long long> seg_sum;
        auto seg_idx = [&](const std::string& o) -> std::size_t {
            for (std::size_t i = 0; i < seg_os.size(); ++i)
                if (seg_os[i] == o)
                    return i;
            seg_os.push_back(o);
            seg_n.push_back(0);
            seg_sum.push_back(0);
            return seg_os.size() - 1;
        };
        for (const auto& [id, os] : fleet.connected_agents) {
            const int s = dex_device_score(store, id, since);
            if (s < 0)
                continue;
            ds.push_back(s);
            const std::size_t i = seg_idx(os.empty() ? std::string("unknown") : os);
            ++seg_n[i];
            seg_sum[i] += s;
        }
        int great = 0, fair = 0, poor = 0;
        for (int s : ds) {
            if (s >= 90) ++great;
            else if (s >= 75) ++fair;
            else ++poor;
        }
        int overall = -1;
        if (!ds.empty()) {
            std::sort(ds.begin(), ds.end());
            overall = ds[ds.size() / 2]; // median
        }
        auto tone = [](int s) { return s < 0 ? "unk" : (s >= 90 ? "good" : "warn"); };

        // Device/App/Network = the canonical composite, partitioned by family bucket.
        const auto health = dex_compute_health(signals, fleet.windows_online, "default");
        double app_ded = 0, net_ded = 0, dev_ded = 0;
        for (const auto& d : health.deds) {
            if (d.name == "App reliability") app_ded += d.deduction;
            else if (d.name == "Network") net_ded += d.deduction;
            else dev_ded += d.deduction;
        }
        auto bscore = [&](double ded) {
            return health.score < 0 ? -1
                                    : static_cast<int>(std::clamp(100.0 - ded, 0.0, 100.0) + 0.5);
        };
        const int dev = bscore(dev_ded), app = bscore(app_ded), net = bscore(net_ded);

        // Coverage over the connected platforms (reuses the catalogue model).
        auto norm = [](std::string o) -> std::string {
            for (auto& c : o) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (o.starts_with("win")) return "windows";
            if (o == "darwin" || o == "macos") return "macos";
            if (o.starts_with("lin")) return "linux";
            return o;
        };
        std::vector<std::string> cscope;
        for (const auto& o : fleet.connected_os) {
            auto n = norm(o);
            if (std::find(cscope.begin(), cscope.end(), n) == cscope.end())
                cscope.push_back(n);
        }
        std::size_t mon = 0;
        for (const auto& g : dex_signal_groups())
            for (const char* t : g.types)
                for (const auto& p : dex_obs_platforms(t))
                    if (std::find(cscope.begin(), cscope.end(), p) != cscope.end()) {
                        ++mon;
                        break;
                    }

        auto stile = [&](int s, const char* label, const std::string& sx) {
            return tile(tone(s), s < 0 ? "&mdash;" : std::to_string(s), label, sx);
        };
        h += "<div class=\"gp-sech\">Experience</div>";
        h += "<div class=\"gp-tiles\">";
        h += stile(overall, "Overall experience",
                   ds.empty() ? "no devices reporting"
                              : "median of " + num(static_cast<int64_t>(ds.size())) + " devices");
        h += stile(dev, "Device", "stability &middot; perf &middot; hardware");
        h += stile(app, "App", "crashes &amp; hangs");
        h += stile(net, "Network", "connectivity");
        h += tile("info", num(static_cast<int64_t>(mon)) + "/" + num(total_types), "Coverage",
                  cscope.empty()
                      ? "no platforms connected"
                      : "types monitored &middot; " +
                            num(static_cast<int64_t>(cscope.size())) + " platform(s)");
        h += "</div>";
        if (!ds.empty()) {
            auto seg = [](int n, const char* color) {
                return n <= 0 ? std::string()
                              : "<span style=\"flex:" + std::to_string(n) + ";background:" + color +
                                    ";display:flex;align-items:center;justify-content:center;"
                                    "font-size:.62rem;font-weight:700;color:#06121f\">" +
                                    std::to_string(n) + "</span>";
            };
            h += "<div style=\"display:flex;height:24px;border-radius:.4rem;overflow:hidden;"
                 "margin:.2rem 0 .4rem\">" +
                 seg(great, "#4ed27e") + seg(fair, "#ffcc00") + seg(poor, "#ff5765") + "</div>";
            h += "<div class=\"gp-note\" style=\"margin-top:0\">Per-device experience: "
                 "<b style=\"color:#4ed27e\">" + num(great) + " great</b> &middot; "
                 "<b style=\"color:#ffcc00\">" + num(fair) + " fair</b> &middot; "
                 "<b style=\"color:#ff5765\">" + num(poor) + " poor</b>. Score = the device's own "
                 "weighted signal deductions; the Device/App/Network tiles are the same composite, "
                 "partitioned. (Fleet-scale → heartbeat rollup.)</div>";
        }

        // Experience by segment (OS today; mgmt-group / site grouping is a follow-up).
        // Aggregate-first + drill: a segment tile opens the device list filtered to it
        // (Fleet → segment → device — the 400k-safe path; never per-device cells here).
        if (!seg_os.empty()) {
            auto oslbl = [](const std::string& o) -> std::string {
                return o == "windows" ? "Windows"
                       : o == "linux" ? "Linux"
                       : o == "macos" ? "macOS"
                                      : (o.empty() ? std::string("Unknown") : o);
            };
            h += "<div class=\"gp-sech\">Experience by segment <span class=\"gp-mute\" "
                 "style=\"font-weight:400;text-transform:none\">&middot; by OS &middot; click to "
                 "drill</span></div><div class=\"gp-fgrid\">";
            for (std::size_t i = 0; i < seg_os.size(); ++i) {
                const int avg =
                    seg_n[i] > 0
                        ? static_cast<int>(static_cast<double>(seg_sum[i]) / seg_n[i] + 0.5)
                        : -1;
                const char* ft = avg < 0 ? "" : (avg >= 90 ? "ok" : (avg >= 75 ? "warn" : "bad"));
                h += "<a class=\"gp-fcard\" hx-get=\"/fragments/devices/list?os=" +
                     url_encode(seg_os[i]) +
                     "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">";
                h += "<div class=\"fn\">" + oslbl(seg_os[i]) + "<span class=\"cnt\">" +
                     num(seg_n[i]) + " device(s)</span></div>";
                h += "<div class=\"fev " + std::string(ft) + "\">" +
                     (avg < 0 ? std::string("&mdash;") : std::to_string(avg)) + "</div>";
                h += "<div class=\"fmeta\">avg experience &middot; drill &rarr;</div></a>";
            }
            h += "</div>";
        }
    }

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
    h += tile("warn", num(summary.distinct_devices), "Devices impacted",
              fleet.windows_online > 0 ? "of " + num(fleet.windows_online) + " reporting"
                                       : "by crashes");
    // Honest analog of the mockup's "Telemetry coverage" tile: we have no
    // enrolled-fleet denominator, so we surface the reporting count itself
    // (a device we can't hear from is unknown, not a fabricated coverage %).
    h += tile("info", num(fleet.windows_online), "Agents reporting",
              num(fleet.total_online) + " online across all OS");
    h += "</div>";
    h += "<div class=\"gp-note\">Crash rates are over <b>currently-reporting Windows agents</b>; "
         "offline agents are excluded, not counted as crash-free. The Experience score above spans "
         "all connected platforms (Linux/macOS collectors emit a subset of signals).</div>";

    // ── Explore cards — the hub's links into the three deep pages, with live
    // teaser figures (summarise + link; the detail lives on the deep page). ──
    {
        int active = 0;
        for (const auto& s : signals)
            if (s.count > 0)
                ++active;
        const DexSignalGroup* busiest = nullptr;
        int64_t busiest_ev = 0;
        for (const auto& g : dex_signal_groups()) {
            const auto r = dex_family_rollup(g, signals);
            if (r.events > busiest_ev) {
                busiest_ev = r.events;
                busiest = &g;
            }
        }
        const auto health = dex_compute_health(signals, fleet.windows_online, "default");

        auto xcard = [&](const char* frag, const std::string& title, const std::string& big,
                         const char* bigcls, const std::string& desc) {
            return "<a class=\"gp-fcard\" hx-get=\"" + std::string(frag) + "?window=" + cur +
                   "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\"><div class=\"fn\">" +
                   title + "<span class=\"cnt\">open &rarr;</span></div><div class=\"fev " +
                   std::string(bigcls) + "\">" + big + "</div><div class=\"ftop\">" + desc +
                   "</div></a>";
        };

        h += "<div class=\"gp-sech\">Explore</div><div class=\"gp-fgrid\">";
        h += xcard("/fragments/dex/catalogue", "Signal catalogue", num(total_types), "",
                   num(active) + " active &middot; " + num(static_cast<int64_t>(dex_signal_groups().size())) +
                       " families" +
                       (busiest && busiest_ev > 0 ? " &middot; busiest <b>" + esc(busiest->name) + "</b>"
                                                  : ""));
        h += xcard("/fragments/dex/health", "Experience health",
                   health.score < 0 ? std::string("&mdash;") : std::format("{:.0f}", health.score),
                   health.score < 0 ? ""
                   : health.score >= 75 ? "ok"
                   : health.score >= 60 ? "warn"
                                        : "bad",
                   std::string("A derived, <b>secondary</b> roll-up of the measured rates") +
                       (health.score < 0 ? " &mdash; suppressed (no reporting agents)" : ""));
        std::string os_desc;
        for (const auto& s : os_scope) {
            if (!os_desc.empty())
                os_desc += " &middot; ";
            os_desc += esc(s.platform) + " " + num(s.distinct_types) + "/" + num(total_types);
        }
        if (os_desc.empty())
            os_desc = "no signals reported yet";
        h += xcard("/fragments/dex/trends", "Cross-OS &amp; trends",
                   num(static_cast<int64_t>(os_scope.size())), "",
                   "OS reporting &middot; " + os_desc + " types (read within an OS, never across)");
        h += "</div>";
    }

    // Section header with a right-aligned "→ deep page" link. The hub
    // SUMMARISES and links; the All-signals / Boot / modules detail moved to the
    // Catalogue + App-reliability deep pages (this page no longer duplicates
    // them). Inline flex/style is CSP-safe (style attrs allowed) and keeps the
    // 16KB page-shell literal untouched.
    auto sech_link = [&](const std::string& title, const std::string& url,
                         const std::string& cta) {
        return "<div class=\"gp-sech\" style=\"display:flex;align-items:baseline;gap:.6rem\">" +
               title +
               " <a style=\"margin-left:auto;font-weight:600;text-transform:none;letter-spacing:0\""
               " hx-get=\"" + url + "\" hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">" + cta +
               "</a></div>";
    };

    // ── Crashes per day (compact trend) — inline bars, no extra shell CSS. ──
    h += sech_link("Crashes per day", "/fragments/dex/trends?window=" + cur,
                   "all family trends &rarr;");
    if (by_day.empty()) {
        h += placeholder("No data", "No crashes in this window.");
    } else {
        int64_t maxc = 1;
        for (const auto& d : by_day)
            if (d.crashes > maxc)
                maxc = d.crashes;
        h += "<div style=\"display:flex;align-items:flex-end;gap:.4rem;height:84px;\">";
        for (const auto& d : by_day) {
            const int px = static_cast<int>(8 + 68 * d.crashes / maxc);
            h += "<div style=\"flex:1;text-align:center;\">"
                 "<div title=\"" + esc(d.day) + ": " + num(d.crashes) +
                 "\" style=\"height:" + num(px) +
                 "px;background:var(--red);opacity:.8;border-radius:2px 2px 0 0;\"></div>"
                 "<div style=\"font-size:.55rem;color:var(--muted);\">" + esc(d.day.substr(5)) +
                 "</div></div>";
        }
        h += "</div>";
    }

    // ── Top crashing apps │ Most-affected devices — side by side (mockup's
    // 2-col). Inline grid is CSP-safe and avoids the shell CSS. ──
    h += "<div style=\"display:grid;grid-template-columns:1fr 1fr;gap:1.1rem;"
         "align-items:start\">";

    // Left — top crashing apps. Hangs kept: a hung-but-not-crashed app still
    // surfaces honestly rather than vanishing from the hub.
    h += "<div>";
    h += sech_link("Top crashing apps",
                   "/fragments/dex/catalogue/group?name=" + url_encode("App reliability") +
                       "&window=" + cur,
                   "App reliability &rarr;");
    if (apps.empty()) {
        h += placeholder("No data", "No app crashes or hangs recorded.");
    } else {
        h += "<table class=\"gp-table\"><thead><tr><th>Application</th>"
             "<th class=\"gp-num\">Crashes</th><th class=\"gp-num\">Hangs</th>"
             "<th class=\"gp-num\">Devices</th><th>Last seen</th></tr></thead><tbody>";
        for (const auto& a : apps) {
            const std::string label =
                a.subject.empty()
                    ? std::string("&lt;unknown&gt;")
                    : drill_link("/fragments/dex/app",
                                 "name=" + url_encode(a.subject) + "&window=" + cur,
                                 esc(a.subject));
            h += "<tr><td>" + label + "</td><td class=\"gp-num\">" + num(a.crashes) +
                 "</td><td class=\"gp-num\">" + num(a.hangs) + "</td><td class=\"gp-num\">" +
                 num(a.distinct_devices) + "</td><td class=\"gp-mute\">" + esc(a.last_seen) +
                 "</td></tr>";
        }
        h += "</tbody></table>";
        h += "<div class=\"gp-note\">Devices = blast radius (distinct devices), not event "
             "count. Row &rarr; app detail.</div>";
    }
    h += "</div>";

    // Right — most-affected devices (crash-scoped). No behavioral-data banner:
    // the overview list isn't per-device audited (only the device drill-down is,
    // route-side; Dave dropped the banner 2026-06-10), so an "audit-logged on
    // open" claim here would be false. Rows drill into the audited device view.
    h += "<div>";
    h += "<div class=\"gp-sech\">Most-affected devices</div>";
    if (devices.empty()) {
        h += placeholder("No data", "No affected devices recorded.");
    } else {
        h += "<table class=\"gp-table\"><thead><tr><th>Device</th><th class=\"gp-num\">Crashes</th>"
             "<th>Last seen</th></tr></thead><tbody>";
        for (const auto& d : devices) {
            if (visible && !visible->count(d.agent_id))
                continue; // out-of-scope device — don't enumerate its id to this operator
            const std::string label = drill_link("/fragments/dex/device",
                                                 "id=" + url_encode(d.agent_id) + "&window=" + cur,
                                                 esc(d.agent_id));
            h += "<tr><td>" + label + "</td><td class=\"gp-num\">" + num(d.crashes) +
                 "</td><td class=\"gp-mute\">" + esc(d.last_seen) + "</td></tr>";
        }
        h += "</tbody></table>";
    }
    h += "</div></div>"; // /device col + /2-col grid

    // ── By operating system — a coverage teaser into Trends. Rows come from the
    // LIVE per-OS signal scope (every OS that reported anything), so "N of M
    // types" is derived, never the mockup's stale "macOS 6 of 103". Reporting +
    // crash-free are Windows-only (no per-OS denominator elsewhere). Coverage %
    // is omitted: we have no enrolled-fleet denominator, and a device we can't
    // hear from is unknown, not healthy. ──
    auto os_label = [](const std::string& p) -> std::string {
        if (p == "windows")
            return "Windows";
        if (p == "macos")
            return "macOS";
        if (p == "linux")
            return "Linux";
        return p.empty() ? std::string("&lt;unknown&gt;") : esc(p);
    };
    h += sech_link("By operating system", "/fragments/dex/trends?window=" + cur,
                   "full cross-OS &amp; trends &rarr;");
    if (os_scope.empty()) {
        h += placeholder("No data", "No signals carry an OS tag yet.");
    } else {
        h += "<table class=\"gp-table\"><thead><tr><th>OS</th><th class=\"gp-num\">Reporting</th>"
             "<th class=\"gp-num\">Crash-free</th><th>Signal scope</th></tr></thead><tbody>";
        for (const auto& s : os_scope) {
            const bool is_win = (s.platform == "windows");
            std::string reporting = "<span class=\"gp-mute\">&mdash;</span>";
            std::string crashfree = "<span class=\"gp-mute\">&mdash;</span>";
            if (is_win && fleet.windows_online > 0) {
                int64_t impacted = summary.distinct_devices;
                if (impacted > fleet.windows_online)
                    impacted = fleet.windows_online;
                const double pct = 100.0 * static_cast<double>(fleet.windows_online - impacted) /
                                   static_cast<double>(fleet.windows_online);
                reporting = num(fleet.windows_online);
                crashfree = std::format("{:.1f}%", pct);
            }
            h += "<tr><td>" + os_label(s.platform) + "</td><td class=\"gp-num\">" + reporting +
                 "</td><td class=\"gp-num\">" + crashfree + "</td><td class=\"gp-mute\">" +
                 num(s.distinct_types) + " of " + num(total_types) + " types &middot; " +
                 num(s.total_events) + " events</td></tr>";
        }
        h += "</tbody></table>";
        h += "<div class=\"gp-note\">Read <b>within</b> an OS, never across &mdash; a narrower "
             "signal scope (fewer types collected) makes an OS look calmer without being healthier. "
             "Reporting + crash-free are Windows-only today; macOS/Linux collectors are limited / "
             "pending.</div>";
    }

    // ── Hub footer — what this page is. ──
    h += "<div class=\"gp-note\">DEX is a <b>read model over the one Guardian event store</b> "
         "&mdash; it reinterprets the signals agents already report as experience; it owns no "
         "second store. This page is the <b>hub</b>: the measured crash-free rate stays the "
         "headline, and the three cards above open the full catalogue, the health roll-up, and the "
         "cross-OS trends.</div>";

    return h;
}

std::string render_dex_app_fragment(const GuaranteedStateStore* store,
                                    const std::string& process_name, const std::string& window,
                                    const std::set<std::string>* visible) {
    // Window-scoped to match the overview row that linked here (C-S1/UP-11): the
    // token (e.g. "7d") resolves to the same `since` cutoff the overview used.
    const std::string since = iso_days_ago(window_to_days(window));
    if (!store)
        return back_to_overview(window) +
               placeholder("Reliability data unavailable", "The signal store is not open.");

    const auto s = store->dex_app_summary(process_name, since);
    std::string h = back_to_overview(window);
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
            if (visible && !visible->count(d.agent_id))
                continue; // out-of-scope device — don't enumerate its id to this operator
            const std::string label =
                drill_link("/fragments/dex/device",
                           "id=" + url_encode(d.agent_id) + "&window=" + window, esc(d.agent_id));
            h += "<tr><td>" + label + "</td><td class=\"gp-num\">" + num(d.crashes) +
                 "</td><td class=\"gp-mute\">" + esc(d.last_seen) + "</td></tr>";
        }
        h += "</tbody></table>";
    }
    return h;
}

std::string render_dex_device_fragment(const GuaranteedStateStore* store,
                                       const std::string& agent_id, const std::string& window,
                                       const DexPerfSnapshot* perf_snap) {
    // This is behavioral data (which apps a person runs): the access posture is
    // enforced server-side — permission-gated on GuaranteedState:Read and each
    // open audit-logged (dex.device.view) — without an on-page banner.
    // Window-scoped to match the linking overview row (C-S1/UP-11).
    const std::string since = iso_days_ago(window_to_days(window));
    if (!store)
        return back_to_overview(window) +
               placeholder("Reliability data unavailable", "The signal store is not open.");

    // A4: click-to-load device perf panel. Deliberately NOT auto-loaded: the
    // route behind the hx-get dispatches a real tar.sql to the device AND
    // probes Execution:Execute (which audit-logs a denial) — auto-loading
    // would fire a command + possible denied-audit row on every page view by
    // every operator (grill finding 1). A click is an attempted action, so
    // both side effects become honest. Rendered for EVERY device, signals or
    // not: a quiet device still has perf history.
    std::string perf_panel =
        "<div class=\"gp-sech\">Device performance (hourly, on-device warehouse)</div>"
        "<div class=\"gp-note\"><button class=\"gp-btn accent\" "
        "hx-get=\"/fragments/dex/device/perf?agent_id=" +
        url_encode(agent_id) +
        "\" hx-target=\"closest div\" hx-swap=\"innerHTML\">Load performance</button> "
        "<span class=\"gp-mute\">runs a live read-only query on the device</span></div>";

    // PR2: vs-fleet/cohort percentile strips — render-time registry state, no
    // dispatch, no extra permission, so they render directly (no click).
    if (perf_snap) {
        perf_panel += render_dex_device_perf_context(
            dex_perf_device_context(*perf_snap, agent_id), perf_snap->cohort_key, window);
    }

    // PR2: per-app panel behind its OWN click + OWN audit action
    // (dex.device.procperf.query) — usage-class reads stay separately
    // countable from the machine-health load above (works-council access-audit
    // posture; the W0 kill switch gets a one-button seam).
    perf_panel +=
        "<div class=\"gp-sech\">Top applications (this device, last 24 h)</div>"
        "<div class=\"gp-note\"><button class=\"gp-btn accent\" "
        "hx-get=\"/fragments/dex/device/procperf?agent_id=" +
        url_encode(agent_id) + "&amp;window=" + window +
        "\" hx-target=\"closest div\" hx-swap=\"innerHTML\">Load applications</button> "
        "<span class=\"gp-mute\">runs a live read-only query on the device &middot; audited "
        "separately &mdash; per-app is usage-class telemetry</span></div>";

    const auto s = store->dex_device_summary(agent_id, since);
    std::string h = back_to_overview(window);
    h += "<div class=\"gp-head\"><div><div class=\"gp-titleline\"><h1>" + esc(agent_id) +
         "</h1></div><div class=\"gp-sub\">Device signal history.</div></div></div>";
    if (s.signals == 0)
        return h + placeholder("No signals", "No reliability signals recorded for this device.") +
               perf_panel;

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
    h += perf_panel;
    return h;
}

// ── A4: device perf sparklines (federated TAR query) ────────────────────────

namespace {

// The canned per-device warehouse query — last 48 hourly rollups, reversed to
// chronological at parse. `$Perf_Hourly` is the operator-SQL dollar name; the
// agent translates it and runs it through TarDatabase::execute_user_query (the
// read-only authorizer chokepoint, #760/#631), exactly like operator SQL from
// the TAR page. The raw samples never leave the device until this on-demand,
// per-device, permission-gated query (ADR-0004 federated model).
constexpr const char* kDexPerfSql =
    "SELECT hour_ts, cpu_avg, mem_avg, read_lat_us_avg, write_lat_us_avg "
    "FROM $Perf_Hourly ORDER BY hour_ts DESC LIMIT 48";

// PR2: the canned per-app query (A2 `$ProcPerf_Hourly` tier) — last 24 h
// aggregated per application, top 25 by sample-weighted CPU. Runs through the
// same read-only authorizer chokepoint (aggregate functions are permitted;
// #760/#631). The epoch cutoff is computed server-side and embedded as a
// literal — no SQL date functions, no user input. AS aliases pin the schema
// line names the parser locates columns by.
std::string dex_procperf_sql() {
    const auto cutoff = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count() -
                        86400;
    return std::format(
        "SELECT name, SUM(samples) AS samples, MAX(instances_max) AS instances_max, "
        "SUM(cpu_avg*samples)/SUM(samples) AS cpu_avg, MAX(cpu_max) AS cpu_max, "
        "CAST(SUM(ws_avg_bytes*samples)/SUM(samples) AS INTEGER) AS ws_avg, "
        "MAX(ws_max_bytes) AS ws_max, COUNT(*) AS hours "
        "FROM $ProcPerf_Hourly WHERE hour_ts >= {} "
        "GROUP BY name ORDER BY cpu_avg DESC LIMIT 25",
        cutoff);
}

std::vector<std::string> split_pipe(const std::string& line) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (true) {
        const auto bar = line.find('|', pos);
        if (bar == std::string::npos) {
            out.push_back(line.substr(pos));
            return out;
        }
        out.push_back(line.substr(pos, bar - pos));
        pos = bar + 1;
    }
}

// One finite, non-negative double out of an agent-supplied cell; nullopt on
// garbage so the whole row is skipped (a forged cell must not render).
//
// Bounded above by kMaxSaneCell (1e15): every consumer either renders the
// value or casts it to int64_t, and a finite-but-huge double (1e30) makes the
// float→int conversion UNDEFINED BEHAVIOR per [conv.fpint] — remote-agent-
// controlled UB (governance G3 BLOCKING, cpp-safety + cpp-expert consensus).
// 1e15 comfortably covers every legitimate cell (epoch seconds, sample
// counts, working-set bytes up to ~1 PB) and is exactly representable.
//
// Full-token parse: stod("42.5xyz") returns 42.5 and stod is LC_NUMERIC-
// sensitive; requiring pos == size() rejects trailing garbage AND turns a
// comma-decimal-locale mis-parse of "42.5" into a rejection instead of a
// silent value distortion (G3 cpp-expert). libc++ on Apple Clang has no FP
// from_chars, so stod+pos is the portable form.
std::optional<double> cell_double(const std::string& s) {
    constexpr double kMaxSaneCell = 1.0e15;
    if (s.empty() || s.size() > 32)
        return std::nullopt;
    try {
        std::size_t pos = 0;
        const double v = std::stod(s, &pos);
        if (pos == s.size() && std::isfinite(v) && v >= 0.0 && v <= kMaxSaneCell)
            return v;
    } catch (...) {}
    return std::nullopt;
}

// Inline sparkline SVG (server-rendered, CSP-safe, no JS). Y auto-scales to the
// series range; a flat series draws a midline. Emits only formatted numbers —
// markup-safe by construction.
std::string sparkline_svg(const std::vector<double>& in_vals, const char* stroke) {
    if (in_vals.empty())
        return "";
    // A single sample can't draw a line segment (an invisible chart next to
    // real now/min/max text) — duplicate it into a flat 2-point line.
    std::vector<double> vals = in_vals;
    if (vals.size() == 1)
        vals.push_back(vals[0]);
    constexpr double kW = 240.0, kH = 36.0, kPad = 2.0;
    const double lo = *std::min_element(vals.begin(), vals.end());
    const double hi = *std::max_element(vals.begin(), vals.end());
    const bool flat = (hi - lo) < 1e-9;
    const std::size_t n = vals.size();
    std::string pts;
    for (std::size_t i = 0; i < n; ++i) {
        const double x =
            kPad + (kW - 2 * kPad) * static_cast<double>(i) / static_cast<double>(n - 1);
        const double frac = flat ? 0.5 : (vals[i] - lo) / (hi - lo);
        const double y = kH - kPad - (kH - 2 * kPad) * frac;
        pts += std::format("{:.1f},{:.1f} ", x, y);
    }
    return std::format("<svg viewBox=\"0 0 240 36\" width=\"240\" height=\"36\" "
                       "preserveAspectRatio=\"none\" role=\"img\" aria-hidden=\"true\">"
                       "<polyline fill=\"none\" stroke=\"{}\" stroke-width=\"1.5\" "
                       "points=\"{}\"/></svg>",
                       stroke, pts);
}

} // namespace

std::vector<DexPerfPoint> parse_dex_perf_output(const std::string& output) {
    std::vector<DexPerfPoint> out;
    // Column indices into DATA rows, located by name from the __schema__ line
    // (schema cell i names data cell i-1 — the "__schema__" marker is cell 0).
    int col_ts = -1, col_cpu = -1, col_mem = -1, col_rlat = -1, col_wlat = -1;
    bool have_schema = false;
    std::size_t pos = 0;
    int rows = 0;
    while (pos < output.size() && rows < 200) {
        const auto nl = output.find('\n', pos);
        std::string line =
            output.substr(pos, (nl == std::string::npos ? output.size() : nl) - pos);
        pos = (nl == std::string::npos) ? output.size() : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;
        if (!have_schema) {
            if (line.starts_with("error|"))
                return out; // agent-side error payload — nothing to parse
            if (!line.starts_with("__schema__|"))
                continue;
            const auto cols = split_pipe(line);
            for (int i = 1; i < static_cast<int>(cols.size()); ++i) {
                if (cols[i] == "hour_ts") col_ts = i - 1;
                else if (cols[i] == "cpu_avg") col_cpu = i - 1;
                else if (cols[i] == "mem_avg") col_mem = i - 1;
                else if (cols[i] == "read_lat_us_avg") col_rlat = i - 1;
                else if (cols[i] == "write_lat_us_avg") col_wlat = i - 1;
            }
            if (col_ts < 0 || col_cpu < 0 || col_mem < 0 || col_rlat < 0 || col_wlat < 0)
                return out; // wrong shape — refuse rather than guess
            have_schema = true;
            continue;
        }
        const auto cells = split_pipe(line);
        const int need = (std::max)({col_ts, col_cpu, col_mem, col_rlat, col_wlat});
        if (static_cast<int>(cells.size()) <= need)
            continue; // trailer ("total|N") or a torn row
        const auto ts = cell_double(cells[static_cast<std::size_t>(col_ts)]);
        const auto cpu = cell_double(cells[static_cast<std::size_t>(col_cpu)]);
        const auto mem = cell_double(cells[static_cast<std::size_t>(col_mem)]);
        const auto rl = cell_double(cells[static_cast<std::size_t>(col_rlat)]);
        const auto wl = cell_double(cells[static_cast<std::size_t>(col_wlat)]);
        if (!ts || !cpu || !mem || !rl || !wl)
            continue;
        ++rows;
        DexPerfPoint p;
        p.hour_ts = static_cast<std::int64_t>(*ts);
        p.cpu_avg = std::clamp(*cpu, 0.0, 100.0);
        p.mem_avg = std::clamp(*mem, 0.0, 100.0);
        // Worse of read/write avg per-IO service time, µs → ms. Clamped to a
        // sane ceiling (1000 ms/IO is already pathological): the SVG y-axis
        // auto-scales to the series range, so a single forged agent row of
        // 1e9 µs would otherwise crush every real point to an invisible flat
        // line (gov quality-engineer B1).
        p.disk_lat_ms = std::clamp((std::max)(*rl, *wl) / 1000.0, 0.0, 1000.0);
        out.push_back(p);
    }
    std::sort(out.begin(), out.end(),
              [](const DexPerfPoint& a, const DexPerfPoint& b) { return a.hour_ts < b.hour_ts; });
    return out;
}

std::vector<DexProcPerfRow> parse_dex_procperf_output(const std::string& output) {
    std::vector<DexProcPerfRow> out;
    // Same defensive contract as parse_dex_perf_output: columns by NAME from
    // the __schema__ line (schema cell i names data cell i-1), per-field
    // validation, malformed rows skipped, bounded row count.
    int col_name = -1, col_samples = -1, col_inst = -1, col_cpu_avg = -1, col_cpu_max = -1,
        col_ws_avg = -1, col_ws_max = -1, col_hours = -1;
    bool have_schema = false;
    std::size_t pos = 0;
    int rows = 0;
    constexpr double kMaxSaneWsBytes = 1.125899906842624e15; // 1 PiB — beyond absurd
    while (pos < output.size() && rows < 100) {
        const auto nl = output.find('\n', pos);
        std::string line =
            output.substr(pos, (nl == std::string::npos ? output.size() : nl) - pos);
        pos = (nl == std::string::npos) ? output.size() : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            continue;
        if (!have_schema) {
            if (line.starts_with("error|"))
                return out; // agent-side error payload — nothing to parse
            if (!line.starts_with("__schema__|"))
                continue;
            const auto cols = split_pipe(line);
            for (int i = 1; i < static_cast<int>(cols.size()); ++i) {
                if (cols[i] == "name") col_name = i - 1;
                else if (cols[i] == "samples") col_samples = i - 1;
                else if (cols[i] == "instances_max") col_inst = i - 1;
                else if (cols[i] == "cpu_avg") col_cpu_avg = i - 1;
                else if (cols[i] == "cpu_max") col_cpu_max = i - 1;
                else if (cols[i] == "ws_avg") col_ws_avg = i - 1;
                else if (cols[i] == "ws_max") col_ws_max = i - 1;
                else if (cols[i] == "hours") col_hours = i - 1;
            }
            if (col_name < 0 || col_samples < 0 || col_inst < 0 || col_cpu_avg < 0 ||
                col_cpu_max < 0 || col_ws_avg < 0 || col_ws_max < 0 || col_hours < 0)
                return out; // wrong shape — refuse rather than guess
            have_schema = true;
            continue;
        }
        const auto cells = split_pipe(line);
        const int need = (std::max)({col_name, col_samples, col_inst, col_cpu_avg, col_cpu_max,
                                     col_ws_avg, col_ws_max, col_hours});
        if (static_cast<int>(cells.size()) <= need)
            continue; // trailer ("total|N") or a torn row
        const auto& name = cells[static_cast<std::size_t>(col_name)];
        if (name.empty() || name.size() > 256)
            continue; // a forged/torn name cell must not render
        const auto samples = cell_double(cells[static_cast<std::size_t>(col_samples)]);
        const auto inst = cell_double(cells[static_cast<std::size_t>(col_inst)]);
        const auto cpu_avg = cell_double(cells[static_cast<std::size_t>(col_cpu_avg)]);
        const auto cpu_max = cell_double(cells[static_cast<std::size_t>(col_cpu_max)]);
        const auto ws_avg = cell_double(cells[static_cast<std::size_t>(col_ws_avg)]);
        const auto ws_max = cell_double(cells[static_cast<std::size_t>(col_ws_max)]);
        const auto hours = cell_double(cells[static_cast<std::size_t>(col_hours)]);
        if (!samples || !inst || !cpu_avg || !cpu_max || !ws_avg || !ws_max || !hours)
            continue;
        if (*ws_avg > kMaxSaneWsBytes || *ws_max > kMaxSaneWsBytes)
            continue; // forged working-set claim — reject the row
        ++rows;
        DexProcPerfRow r;
        r.name = name;
        r.samples = static_cast<std::int64_t>(*samples);
        r.instances_max = static_cast<std::int64_t>(*inst);
        r.cpu_avg = std::clamp(*cpu_avg, 0.0, 100.0); // a >100% share is a lie
        r.cpu_max = std::clamp(*cpu_max, 0.0, 100.0);
        r.ws_avg_bytes = *ws_avg;
        r.ws_max_bytes = *ws_max;
        r.hours = static_cast<std::int64_t>(*hours);
        out.push_back(std::move(r));
    }
    return out;
}

std::string render_dex_perf_panel(const std::vector<DexPerfPoint>& points) {
    if (points.empty())
        return "<div class=\"gp-note\">No performance history on this device yet &mdash; the "
               "TAR perf sampler may be disabled, or this platform has no collector.</div>";

    struct Row {
        const char* label;
        const char* stroke;
        const char* unit;
        int prec;
        std::vector<double> vals;
    };
    std::vector<Row> series = {
        {"CPU busy", "#58a6ff", "%", 0, {}},
        {"Memory used", "#3fb950", "%", 0, {}},
        {"Disk latency", "#d29922", " ms", 1, {}},
    };
    for (const auto& p : points) {
        series[0].vals.push_back(p.cpu_avg);
        series[1].vals.push_back(p.mem_avg);
        series[2].vals.push_back(p.disk_lat_ms);
    }

    std::string h = "<div>";
    for (const auto& r : series) {
        const double now = r.vals.back();
        const double lo = *std::min_element(r.vals.begin(), r.vals.end());
        const double hi = *std::max_element(r.vals.begin(), r.vals.end());
        h += "<div style=\"display:flex;align-items:center;gap:0.75rem;padding:0.3rem 0\">"
             "<div style=\"min-width:7.5rem\" class=\"gp-mute\">" +
             std::string(r.label) + "</div>" + sparkline_svg(r.vals, r.stroke) +
             std::format("<span class=\"gp-mute\" style=\"font-size:0.8rem\">now {0:.{3}f}{2} "
                         "&middot; min {1:.{3}f}{2} &middot; max {4:.{3}f}{2}</span>",
                         now, lo, r.unit, r.prec, hi) +
             "</div>";
    }
    h += std::format("<div class=\"gp-note\">{} hourly rollups from the device&rsquo;s edge "
                     "warehouse (data stays on-device; fetched live for this view).</div>",
                     points.size());
    h += "</div>";
    return h;
}

void DexRoutes::register_routes(httplib::Server& svr, AuthFn auth_fn, PermFn perm_fn,
                                GuaranteedStateStore* store, FleetFn fleet_fn, AuditFn audit_fn,
                                DispatchFn dispatch_fn, ResponsesFn responses_fn, PerfFn perf_fn,
                                ScopedPermFn scoped_perm_fn, VisibleSetFn visible_set_fn) {
    // Production adapter: wrap the httplib server in the route-sink seam and
    // delegate to the testable overload (mirrors GuardianRoutes / RestApiV1).
    HttplibRouteSink sink(svr);
    register_routes(sink, std::move(auth_fn), std::move(perm_fn), store, std::move(fleet_fn),
                    std::move(audit_fn), std::move(dispatch_fn), std::move(responses_fn),
                    std::move(perf_fn), std::move(scoped_perm_fn), std::move(visible_set_fn));
}

void DexRoutes::register_routes(HttpRouteSink& sink, AuthFn auth_fn, PermFn perm_fn,
                                GuaranteedStateStore* store, FleetFn fleet_fn, AuditFn audit_fn,
                                DispatchFn dispatch_fn, ResponsesFn responses_fn, PerfFn perf_fn,
                                ScopedPermFn scoped_perm_fn, VisibleSetFn visible_set_fn) {
    auth_fn_ = std::move(auth_fn);
    perm_fn_ = std::move(perm_fn);
    scoped_perm_fn_ = std::move(scoped_perm_fn);
    visible_set_fn_ = std::move(visible_set_fn);
    store_ = store;
    fleet_fn_ = std::move(fleet_fn);
    audit_fn_ = std::move(audit_fn);
    dispatch_fn_ = std::move(dispatch_fn);
    responses_fn_ = std::move(responses_fn);
    perf_fn_ = std::move(perf_fn);

    // Resolve the visible-agent set for filtering device-id-rendering lists so an
    // out-of-scope operator can't enumerate other teams' device ids. nullopt = no
    // filter (visible_set_fn unwired, unauthenticated, or the caller sees the whole
    // fleet — global Infrastructure:Read / RBAC off). The renderers take a pointer:
    // nullptr = no filter. Holds the optional in the caller; the pointer must not
    // outlive it.
    auto resolve_visible =
        [this](const httplib::Request& req) -> std::optional<std::set<std::string>> {
        if (!visible_set_fn_)
            return std::nullopt;
        httplib::Response throwaway;
        auto sess = auth_fn_(req, throwaway);
        if (!sess)
            return std::nullopt;
        return visible_set_fn_(sess->username);
    };

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
        // The shared shell marks Guardian as the active nav item; on /dex the
        // DEX link is the active one. Plain string swaps on the static chrome.
        sub("<a href=\"/guardian\" class=\"nav-link active\">Guardian</a>",
            "<a href=\"/guardian\" class=\"nav-link\">Guardian</a>");
        sub("<a href=\"/dex\" class=\"nav-link\">DEX</a>",
            "<a href=\"/dex\" class=\"nav-link active\">DEX</a>");
        res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
        res.set_content(std::move(html), "text/html; charset=utf-8");
    });

    // -- Overview fragment (gates on GuaranteedState:Read, like the Guardian reads) --
    sink.Get("/fragments/dex/overview", [this, resolve_visible](const httplib::Request& req,
                                                                httplib::Response& res) {
        if (!perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        const std::string w = req.has_param("window") ? req.get_param_value("window") : "7d";
        const int window_days = window_to_days(w);
        const std::string since = iso_days_ago(window_days);
        const DexFleet fleet = fleet_fn_ ? fleet_fn_() : DexFleet{};
        const auto vis = resolve_visible(req); // scope the top-devices list to the caller
        res.set_content(render_dex_overview_fragment(store_, since, window_days, fleet,
                                                     vis ? &*vis : nullptr),
                        "text/html; charset=utf-8");
    });

    // -- Catalogue: family-card grid (View 1) + a family's signals (View 2) --
    sink.Get("/fragments/dex/catalogue", [this](const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        const int window_days =
            window_to_days(req.has_param("window") ? req.get_param_value("window") : "7d");
        const std::string since = iso_days_ago(window_days);
        const DexFleet fleet = fleet_fn_ ? fleet_fn_() : DexFleet{};
        const std::string os = req.has_param("os") ? req.get_param_value("os") : "all";
        res.set_content(render_dex_catalogue_fragment(store_, since, window_days, fleet, os),
                        "text/html; charset=utf-8");
    });
    sink.Get("/fragments/dex/catalogue/group",
             [this](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Read"))
                     return;
                 const int window_days =
                     window_to_days(req.has_param("window") ? req.get_param_value("window") : "7d");
                 const std::string since = iso_days_ago(window_days);
                 const std::string name =
                     req.has_param("name") ? req.get_param_value("name") : "";
                 const std::string os = req.has_param("os") ? req.get_param_value("os") : "all";
                 const DexFleet fleet = fleet_fn_ ? fleet_fn_() : DexFleet{};
                 res.set_content(
                     render_dex_catalogue_group_fragment(store_, since, window_days, name, fleet, os),
                     "text/html; charset=utf-8");
             });
    sink.Get("/fragments/dex/catalogue/signal",
             [this, resolve_visible](const httplib::Request& req, httplib::Response& res) {
                 if (!perm_fn_(req, res, "GuaranteedState", "Read"))
                     return;
                 const int window_days =
                     window_to_days(req.has_param("window") ? req.get_param_value("window") : "7d");
                 const std::string since = iso_days_ago(window_days);
                 const std::string type =
                     req.has_param("type") ? req.get_param_value("type") : "";
                 const std::string os = req.has_param("os") ? req.get_param_value("os") : "all";
                 // The per-signal view lists the most-affected DEVICES for this
                 // obs_type — individual-identifying behavioral data. Audit each
                 // open, mirroring /fragments/dex/device, so the "audit-logged on
                 // open" banner the fragment shows is true and the SOC 2
                 // compensating control applies (governance B4).
                 // Capture the audit bool (#1549 review): a dropped evidence row on
                 // this PII drill-down is a works-council/SOC 2 gap. HTML surface →
                 // flag via Sec-Audit-Failed but STILL render (a transient audit
                 // hiccup must not blank the dashboard); the REST sibling fails closed.
                 if (audit_fn_ && !audit_fn_(req, "dex.signal.view", "success", "ObsType", type,
                                             "DEX per-signal most-affected devices"))
                     res.set_header("Sec-Audit-Failed", "true");
                 const auto vis = resolve_visible(req); // scope the most-affected-devices list
                 res.set_content(
                     render_dex_catalogue_signal_fragment(store_, since, window_days, type, os,
                                                          vis ? &*vis : nullptr),
                     "text/html; charset=utf-8");
             });

    // -- Health score: derived/secondary composite (?weighting=<preset>) --
    sink.Get("/fragments/dex/health", [this](const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        const int window_days =
            window_to_days(req.has_param("window") ? req.get_param_value("window") : "7d");
        const std::string since = iso_days_ago(window_days);
        const std::string weighting =
            req.has_param("weighting") ? req.get_param_value("weighting") : "default";
        const DexFleet fleet = fleet_fn_ ? fleet_fn_() : DexFleet{};
        res.set_content(
            render_dex_health_fragment(store_, since, window_days, fleet, weighting),
            "text/html; charset=utf-8");
    });

    // -- Trends: cross-OS comparison + per-family small-multiples + heatmap --
    sink.Get("/fragments/dex/trends", [this](const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        const int window_days =
            window_to_days(req.has_param("window") ? req.get_param_value("window") : "7d");
        const std::string since = iso_days_ago(window_days);
        const DexFleet fleet = fleet_fn_ ? fleet_fn_() : DexFleet{};
        res.set_content(render_dex_trends_fragment(store_, since, window_days, fleet),
                        "text/html; charset=utf-8");
    });

    // -- Per-app drill-down (blast radius). ?name=<process_name> --
    sink.Get("/fragments/dex/app", [this, resolve_visible](const httplib::Request& req,
                                                           httplib::Response& res) {
        if (!perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        const std::string name = req.has_param("name") ? req.get_param_value("name") : "";
        // Canonicalise the window to a fixed token BEFORE it can reach markup —
        // the raw param is reflected into hx-get attributes downstream (Gate-8 XSS).
        const std::string w =
            window_token(window_to_days(req.has_param("window") ? req.get_param_value("window")
                                                                : "7d"));
        const auto vis = resolve_visible(req); // scope the affected-devices list
        res.set_content(render_dex_app_fragment(store_, name, w, vis ? &*vis : nullptr),
                        "text/html; charset=utf-8");
    });

    // -- Per-device drill-down (signal history; behavioral PII → audit each open). ?id=<agent_id> --
    sink.Get("/fragments/dex/device", [this](const httplib::Request& req, httplib::Response& res) {
        const std::string id = req.has_param("id") ? req.get_param_value("id") : "";
        // Per-device scope (tier + management group), not just global Read — an
        // operator can only drill a device inside their scope (mirrors /device; a
        // cross-tenant read of another team's per-device DEX history was the gap).
        if (scoped_perm_fn_ ? !scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)
                            : !perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        // Canonicalise the window before it can reach markup (Gate-8 XSS chokepoint).
        const std::string w =
            window_token(window_to_days(req.has_param("window") ? req.get_param_value("window")
                                                                : "7d"));
        // Capture the audit bool (#1549 review): surface a dropped evidence row on
        // this PII drill-down via Sec-Audit-Failed; HTML surface still renders.
        if (audit_fn_ && !audit_fn_(req, "dex.device.view", "success", "Agent", id,
                                    "DEX per-device signal history"))
            res.set_header("Sec-Audit-Failed", "true");
        // PR2: feed the percentile strips from the perf snapshot (default
        // cohort key — the strips compare against the conventional cohort).
        std::optional<DexPerfSnapshot> snap;
        if (perf_fn_)
            snap = perf_fn_(kDexDefaultCohortKey);
        res.set_content(render_dex_device_fragment(store_, id, w, snap ? &*snap : nullptr),
                        "text/html; charset=utf-8");
    });

    // -- F2a: fleet Performance tab (now-view over registry heartbeat state) ---
    //
    // Render-time aggregation, ZERO new storage. Gates on GuaranteedState:Read
    // like the sibling DEX fragments. NOT audited: the fleet/cohort views are
    // aggregates, and the devices drill lists machine-health telemetry (CPU /
    // commit / disk latency — device state, not behavioral data about what a
    // person runs; the behavioral surfaces — per-device signal history and the
    // per-app procperf view — keep their per-open audit rows).
    sink.Get("/fragments/dex/perf", [this](const httplib::Request& req, httplib::Response& res) {
        if (!perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        const int window_days =
            window_to_days(req.has_param("window") ? req.get_param_value("window") : "7d");
        if (!perf_fn_) {
            res.set_content(placeholder("Fleet performance unavailable",
                                        "This server has no perf snapshot provider wired."),
                            "text/html; charset=utf-8");
            return;
        }
        // Cohort tag key: validated to the TagStore key alphabet so garbage
        // never reaches the provider or markup; invalid/absent falls back to
        // the conventional default ("model" — the asset-tagging recipe's key).
        std::string key =
            req.has_param("key") ? req.get_param_value("key") : kDexDefaultCohortKey;
        if (!valid_tag_key(key))
            key = kDexDefaultCohortKey;
        res.set_content(render_dex_perf_fragment(perf_fn_(key), window_days),
                        "text/html; charset=utf-8");
    });

    sink.Get("/fragments/dex/perf/cohort-diff", [this](const httplib::Request& req,
                                                       httplib::Response& res) {
        if (!perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        const int window_days =
            window_to_days(req.has_param("window") ? req.get_param_value("window") : "7d");
        if (!perf_fn_) {
            res.set_content(placeholder("Fleet performance unavailable",
                                        "This server has no perf snapshot provider wired."),
                            "text/html; charset=utf-8");
            return;
        }
        std::string key = req.has_param("key") ? req.get_param_value("key") : kDexDefaultCohortKey;
        if (!valid_tag_key(key))
            key = kDexDefaultCohortKey;
        // Cohort values come from the picker; "" is the legitimate untagged
        // residual, and the pure model reports found=false for an unknown one.
        const std::string a = req.has_param("a") ? req.get_param_value("a") : "";
        const std::string b = req.has_param("b") ? req.get_param_value("b") : "";
        res.set_content(render_dex_perf_cohort_diff_fragment(perf_fn_(key), a, b, window_days),
                        "text/html; charset=utf-8");
    });

    sink.Get("/fragments/dex/perf/devices", [this, resolve_visible](const httplib::Request& req,
                                                                    httplib::Response& res) {
        if (!perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        const int window_days =
            window_to_days(req.has_param("window") ? req.get_param_value("window") : "7d");
        if (!perf_fn_) {
            res.set_content(placeholder("Fleet performance unavailable",
                                        "This server has no perf snapshot provider wired."),
                            "text/html; charset=utf-8");
            return;
        }
        const DexPerfMetric metric = dex_perf_metric_from_token(
            req.has_param("metric") ? req.get_param_value("metric") : "cpu");
        const bool not_reporting = req.has_param("filter") &&
                                   req.get_param_value("filter") == "not_reporting";
        // Grill fix: the cohort KEY is always resolved (default "model") so
        // the Cohort column shows real values even when the drill came from a
        // metric/Reporting card — without this, every device read "(untagged)",
        // which is a lie. FILTERING is a separate decision: it applies only
        // when cohort_value is present ("" = the untagged residual).
        std::string cohort_key =
            req.has_param("cohort_key") ? req.get_param_value("cohort_key")
                                        : kDexDefaultCohortKey;
        if (!valid_tag_key(cohort_key))
            cohort_key = kDexDefaultCohortKey;
        std::optional<std::string> cohort_filter;
        if (req.has_param("cohort_value"))
            cohort_filter = req.get_param_value("cohort_value");
        int limit = 50;
        if (req.has_param("limit")) {
            try {
                limit = std::clamp(std::stoi(req.get_param_value("limit")), 1, 500);
            } catch (...) {}
        }
        const auto vis = resolve_visible(req); // scope the per-device perf list
        res.set_content(render_dex_perf_devices_fragment(perf_fn_(cohort_key), metric,
                                                         not_reporting, cohort_filter, limit,
                                                         window_days, vis ? &*vis : nullptr),
                        "text/html; charset=utf-8");
    });

    // -- A4: device perf panel — live federated TAR query + result poll --------
    //
    // The panel mechanically EXECUTES a (canned, server-authored) tar.sql on the
    // device, so beyond GuaranteedState:Read it requires the same securable the
    // TAR SQL page does (Execution:Execute). The Execute check is PROBED against
    // a throwaway response so a read-only operator gets an honest in-panel note
    // instead of a swallowed 403 (htmx leaves the target untouched on 4xx).
    auto note = [](httplib::Response& res, const std::string& text) {
        res.set_content("<div class=\"gp-note\">" + text + "</div>", "text/html; charset=utf-8");
    };
    auto can_execute = [this](const httplib::Request& req, const std::string& id) {
        httplib::Response probe; // throwaway: htmx swallows a raw 403, so probe -> note
        return scoped_perm_fn_ ? scoped_perm_fn_(req, probe, "Execution", "Execute", id)
                               : perm_fn_(req, probe, "Execution", "Execute");
    };
    auto pending_div = [](const std::string& command_id, const std::string& agent_id,
                          int attempt) {
        return "<div hx-get=\"/fragments/dex/device/perf/result?command_id=" +
               url_encode(command_id) + "&amp;agent_id=" + url_encode(agent_id) +
               "&amp;n=" + std::to_string(attempt) +
               "\" hx-trigger=\"load delay:700ms\" hx-swap=\"outerHTML\" class=\"gp-note\">"
               "Querying the device&rsquo;s edge warehouse&hellip;</div>";
    };

    sink.Get("/fragments/dex/device/perf", [this, note, can_execute,
                                            pending_div](const httplib::Request& req,
                                                         httplib::Response& res) {
        const std::string id = req.has_param("agent_id") ? req.get_param_value("agent_id") : "";
        // Per-device scoped Read floor + Execute probe (mirrors /device live).
        if (scoped_perm_fn_ ? !scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)
                            : !perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        if (!can_execute(req, id)) {
            note(res, "Live device performance needs the <b>Execute</b> permission &mdash; "
                      "this panel runs a read-only TAR query on the device.");
            return;
        }
        if (!dispatch_fn_ || !responses_fn_) {
            note(res, "Live device query unavailable on this server.");
            return;
        }
        if (id.empty()) {
            res.status = 400;
            return;
        }
        std::unordered_map<std::string, std::string> params{{"sql", kDexPerfSql}};
        const auto [command_id, sent] = dispatch_fn_("tar", "sql", {id}, "", params);
        if (audit_fn_)
            audit_fn_(req, "dex.device.perf.query", sent > 0 ? "success" : "no_agents", "Agent",
                      id, "canned tar.sql $Perf_Hourly -> " + std::to_string(sent) +
                              " agent(s) command_id=" + command_id);
        if (sent == 0) {
            note(res, "Device offline &mdash; the live performance query needs a connected "
                      "agent.");
            return;
        }
        res.set_content(pending_div(command_id, id, 1), "text/html; charset=utf-8");
    });

    sink.Get("/fragments/dex/device/perf/result", [this, note, can_execute, pending_div](
                                                      const httplib::Request& req,
                                                      httplib::Response& res) {
        const std::string command_id =
            req.has_param("command_id") ? req.get_param_value("command_id") : "";
        const std::string id = req.has_param("agent_id") ? req.get_param_value("agent_id") : "";
        // Per-device scoped Read floor + Execute probe (same scope as the dispatch;
        // stops a principal polling another team's command_id through this route).
        if (scoped_perm_fn_ ? !scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)
                            : !perm_fn_(req, res, "GuaranteedState", "Read"))
            return;
        if (!can_execute(req, id)) {
            note(res, "Live device performance needs the <b>Execute</b> permission.");
            return;
        }
        if (!responses_fn_) {
            note(res, "Live device query unavailable on this server.");
            return;
        }
        // Only tar dispatches are pollable here, only for the named agent —
        // narrows what a guessed/stolen command_id can read via this route.
        if (id.empty() || command_id.size() > 64 || !command_id.starts_with("tar-")) {
            res.status = 400;
            return;
        }
        int attempt = 1;
        if (req.has_param("n")) {
            try {
                attempt = std::clamp(std::stoi(req.get_param_value("n")), 1, 30);
            } catch (...) {}
        }
        const DexAgentResponse* with_output = nullptr;
        const DexAgentResponse* failed = nullptr;
        const auto rows = responses_fn_(command_id);
        for (const auto& r : rows) {
            if (r.agent_id != id)
                continue; // another agent's rows are never rendered here
            if (!r.output.empty())
                with_output = &r; // data rides RUNNING rows (response-store contract)
            else if (r.status >= 2)
                failed = &r; // FAILURE / TIMEOUT / REJECTED terminal frame
        }
        if (with_output) {
            // An agent-side error payload ("error|…") parses to empty — surface
            // it distinctly from "no history" (escaped + truncated: agent bytes).
            if (with_output->output.starts_with("error|")) {
                note(res, "The device reported an error: " +
                              esc(with_output->output.substr(6, 200)));
                return;
            }
            res.set_content(render_dex_perf_panel(parse_dex_perf_output(with_output->output)),
                            "text/html; charset=utf-8");
            return;
        }
        if (failed) {
            note(res, "Query failed on the device: " + esc(failed->error_detail.substr(0, 200)));
            return;
        }
        if (attempt >= 20) {
            note(res, "No response from the device (timed out) &mdash; it may have gone "
                      "offline. Reload the page to retry.");
            return;
        }
        res.set_content(pending_div(command_id, id, attempt + 1), "text/html; charset=utf-8");
    });

    // -- PR2: per-app panel — OWN click, OWN audit class ------------------------
    //
    // Same dispatch/poll shape as the perf panel above, but a separate route
    // pair with its own audit action (`dex.device.procperf.query`): per-app is
    // usage-class telemetry (what people run), and the audit trail must keep
    // usage reads separately countable from machine-health reads (grill
    // decision 5; works-council access-audit posture; W0 kill-switch seam).
    auto procperf_pending = [](const std::string& command_id, const std::string& agent_id,
                               int attempt, const std::string& w) {
        return "<div hx-get=\"/fragments/dex/device/procperf/result?command_id=" +
               url_encode(command_id) + "&amp;agent_id=" + url_encode(agent_id) +
               "&amp;n=" + std::to_string(attempt) + "&amp;window=" + w +
               "\" hx-trigger=\"load delay:700ms\" hx-swap=\"outerHTML\" class=\"gp-note\">"
               "Querying the device&rsquo;s edge warehouse&hellip;</div>";
    };

    sink.Get("/fragments/dex/device/procperf",
             [this, note, can_execute, procperf_pending](const httplib::Request& req,
                                                         httplib::Response& res) {
                 const std::string id =
                     req.has_param("agent_id") ? req.get_param_value("agent_id") : "";
                 // Per-device scoped Read floor + Execute probe (mirrors /device live).
                 if (scoped_perm_fn_ ? !scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)
                                     : !perm_fn_(req, res, "GuaranteedState", "Read"))
                     return;
                 if (!can_execute(req, id)) {
                     note(res, "Per-application data needs the <b>Execute</b> permission "
                               "&mdash; this panel runs a read-only TAR query on the device.");
                     return;
                 }
                 if (!dispatch_fn_ || !responses_fn_) {
                     note(res, "Live device query unavailable on this server.");
                     return;
                 }
                 if (id.empty()) {
                     res.status = 400;
                     return;
                 }
                 // Canonicalise before the token can reach markup (Gate-8 XSS).
                 const std::string w = window_token(window_to_days(
                     req.has_param("window") ? req.get_param_value("window") : "7d"));
                 std::unordered_map<std::string, std::string> params{{"sql", dex_procperf_sql()}};
                 const auto [command_id, sent] = dispatch_fn_("tar", "sql", {id}, "", params);
                 if (audit_fn_)
                     audit_fn_(req, "dex.device.procperf.query",
                               sent > 0 ? "success" : "no_agents", "Agent", id,
                               "canned tar.sql $ProcPerf_Hourly (usage-class) -> " +
                                   std::to_string(sent) + " agent(s) command_id=" + command_id);
                 if (sent == 0) {
                     note(res, "Device offline &mdash; the live per-app query needs a connected "
                               "agent.");
                     return;
                 }
                 res.set_content(procperf_pending(command_id, id, 1, w),
                                 "text/html; charset=utf-8");
             });

    sink.Get("/fragments/dex/device/procperf/result",
             [this, note, can_execute, procperf_pending](const httplib::Request& req,
                                                         httplib::Response& res) {
                 const std::string command_id =
                     req.has_param("command_id") ? req.get_param_value("command_id") : "";
                 const std::string id =
                     req.has_param("agent_id") ? req.get_param_value("agent_id") : "";
                 // Per-device scoped Read floor + Execute probe (same scope as the
                 // dispatch; stops polling another team's command_id through this route).
                 if (scoped_perm_fn_ ? !scoped_perm_fn_(req, res, "GuaranteedState", "Read", id)
                                     : !perm_fn_(req, res, "GuaranteedState", "Read"))
                     return;
                 if (!can_execute(req, id)) {
                     note(res, "Per-application data needs the <b>Execute</b> permission.");
                     return;
                 }
                 if (!responses_fn_) {
                     note(res, "Live device query unavailable on this server.");
                     return;
                 }
                 if (id.empty() || command_id.size() > 64 || !command_id.starts_with("tar-")) {
                     res.status = 400;
                     return;
                 }
                 const std::string w = window_token(window_to_days(
                     req.has_param("window") ? req.get_param_value("window") : "7d"));
                 int attempt = 1;
                 if (req.has_param("n")) {
                     try {
                         attempt = std::clamp(std::stoi(req.get_param_value("n")), 1, 30);
                     } catch (...) {}
                 }
                 const DexAgentResponse* with_output = nullptr;
                 const DexAgentResponse* failed = nullptr;
                 const auto rows = responses_fn_(command_id);
                 for (const auto& r : rows) {
                     if (r.agent_id != id)
                         continue; // another agent's rows are never rendered here
                     if (!r.output.empty())
                         with_output = &r; // data rides RUNNING rows
                     else if (r.status >= 2)
                         failed = &r;
                 }
                 if (with_output) {
                     if (with_output->output.starts_with("error|")) {
                         note(res, "The device reported an error: " +
                                       esc(with_output->output.substr(6, 200)));
                         return;
                     }
                     res.set_content(render_dex_procperf_panel(
                                         parse_dex_procperf_output(with_output->output), w),
                                     "text/html; charset=utf-8");
                     return;
                 }
                 if (failed) {
                     note(res, "Query failed on the device: " +
                                   esc(failed->error_detail.substr(0, 200)));
                     return;
                 }
                 if (attempt >= 20) {
                     note(res, "No response from the device (timed out) &mdash; it may have "
                               "gone offline. Reload the page to retry.");
                     return;
                 }
                 res.set_content(procperf_pending(command_id, id, attempt + 1, w),
                                 "text/html; charset=utf-8");
             });
}

} // namespace yuzu::server
