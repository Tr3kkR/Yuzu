#include <yuzu/agent/dex_signal_catalog.hpp>

#include <algorithm>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>

namespace yuzu::agent {

std::string symbolic_exception_name(std::uint32_t code) {
    switch (code) {
    case 0x80000003: return "BREAKPOINT";
    case 0xC0000005: return "ACCESS_VIOLATION";
    case 0xC000001D: return "ILLEGAL_INSTRUCTION";
    case 0xC0000025: return "NONCONTINUABLE_EXCEPTION";
    case 0xC0000026: return "INVALID_DISPOSITION";
    case 0xC000008C: return "ARRAY_BOUNDS_EXCEEDED";
    case 0xC000008E: return "FLOAT_DIVIDE_BY_ZERO";
    case 0xC0000094: return "INTEGER_DIVIDE_BY_ZERO";
    case 0xC0000095: return "INTEGER_OVERFLOW";
    case 0xC0000096: return "PRIVILEGED_INSTRUCTION";
    case 0xC00000FD: return "STACK_OVERFLOW";
    case 0xC0000374: return "HEAP_CORRUPTION";
    case 0xC0000409: return "STACK_BUFFER_OVERRUN";
    case 0xC000041D: return "FATAL_USER_CALLBACK_EXCEPTION";
    case 0xC0000602: return "FAIL_FAST_EXCEPTION"; // __fastfail
    // 0xE0434352 is NOT an NTSTATUS CPU fault — it is the software SEH code the CLR
    // raises when a managed (.NET) exception escapes. Mapping it makes a paired .NET
    // crash (logged as a generic native 1000) legible; the rich managed type/stack
    // lives only in the .NET Runtime 1026 event (a deferred follow-up). See memory
    // project-guardian-process-spark-slices.
    case 0xE0434352: return "CLR_EXCEPTION";
    default: return "";
    }
}

namespace {

// ── Field-access helpers (named with positional fallback) ────────────────────
// Manifest providers emit NAMED <Data Name='X'> elements; classic providers emit
// UNNAMED positional ones. Several SCM/disk/Tcpip events are classic, so every
// extractor that touches them goes through named_or_pos.

std::string named(const EventFields& f, std::string_view name) {
    for (const auto& [k, v] : f)
        if (k == name)
            return v;
    return {};
}

std::string pos(const EventFields& f, std::size_t i) {
    return i < f.size() ? f[i].second : std::string{};
}

std::string named_or_pos(const EventFields& f, std::string_view name, std::size_t i) {
    if (auto v = named(f, name); !v.empty())
        return v;
    return pos(f, i);
}

std::uint32_t parse_hex_u32(const std::string& s) {
    if (s.empty()) return 0;
    try {
        return static_cast<std::uint32_t>(std::stoul(s, nullptr, 16)); // tolerates "0x" prefix
    } catch (...) {
        return 0; // malformed field — leave default rather than throw
    }
}

double parse_metric_ms(const std::string& s) {
    if (s.empty()) return 0.0;
    try {
        const double v = std::stod(s);
        // Reject non-finite / negative garbage — a forged or locale-mangled field
        // must not poison a fleet aggregate (the std::stod ±Inf lesson, R2 B-fix).
        if (!(v >= 0.0) || v > 1.0e12)
            return 0.0;
        return v;
    } catch (...) {
        return 0.0;
    }
}

// Cap free-text reason fields (service-start error strings etc.) so one chatty
// provider can't bloat every wire event + projection row.
std::string clip(std::string s, std::size_t max = 160) {
    if (s.size() > max) {
        s.resize(max);
        s += "…";
    }
    return s;
}

// ── Extractors — one per signal family. PURE: fields in, observation out. ────
// Each fills subject/reason/symbolic/component/metric + the human sentence; the
// caller (extract_signal) stamps obs_type + platform. Field layouts are encoded
// from real captured records where we have them (crash: verified Win11 26100)
// and from the provider manifests elsewhere; every lookup degrades to "" on a
// missing field — an observation with an empty subject still counts.

SignalObservation x_app_crash(const EventFields& f, int) {
    SignalObservation o;
    o.subject = named(f, "AppName");
    o.component = named(f, "ModuleName");
    o.kind = "exception";
    const std::uint32_t code = parse_hex_u32(named(f, "ExceptionCode"));
    o.reason = std::format("0x{:08X}", code);
    o.symbolic = symbolic_exception_name(code);
    o.pid = parse_hex_u32(named(f, "ProcessId")); // e.g. "0x297c"
    // NOTE: AppPath is present in the event but DELIBERATELY not extracted —
    // data-minimisation (file-system paths can leak user folders / doc names).
    // Sentence format kept byte-identical to slice 1 for /events continuity.
    std::string s = std::format("{} pid={} code=0x{:08X}",
                                o.subject.empty() ? "<unknown>" : o.subject, o.pid, code);
    if (!o.symbolic.empty()) s += " " + o.symbolic;
    if (!o.component.empty()) s += " module=" + o.component;
    o.sentence = std::move(s);
    return o;
}

SignalObservation x_app_hang(const EventFields& f, int) {
    SignalObservation o;
    // 1002 is classic-style: positional Data ([0]=program, [1]=version, [2]=pid hex).
    o.subject = named_or_pos(f, "AppName", 0);
    o.pid = parse_hex_u32(named_or_pos(f, "ProcessId", 2));
    o.kind = "hang";
    o.symbolic = "NOT_RESPONDING";
    o.sentence = (o.subject.empty() ? "<unknown>" : o.subject) + " stopped responding" +
                 (o.pid ? " pid=" + std::to_string(o.pid) : "");
    return o;
}

SignalObservation x_service_crashed(const EventFields& f, int id) {
    SignalObservation o;
    o.subject = named_or_pos(f, "param1", 0); // SCM names inserts param1..paramN
    o.reason = std::to_string(id);
    o.symbolic = "SERVICE_CRASHED";
    o.kind = "service";
    o.sentence = "service '" + (o.subject.empty() ? "<unknown>" : o.subject) +
                 "' terminated unexpectedly" +
                 (id == 7034 ? " (no recovery configured)" : "");
    return o;
}

SignalObservation x_service_start_failed(const EventFields& f, int) {
    SignalObservation o;
    o.subject = named_or_pos(f, "param1", 0);
    o.reason = clip(named_or_pos(f, "param2", 1)); // the SCM error text
    // SCM sometimes renders the cause as a raw message-resource reference
    // ("%%1053") instead of expanded text (live-observed on Win11 for the
    // start-timeout path). Surface it as the error number it encodes.
    if (o.reason.starts_with("%%"))
        o.reason = "error " + o.reason.substr(2);
    o.symbolic = "START_FAILED";
    o.kind = "service";
    o.sentence = "service '" + (o.subject.empty() ? "<unknown>" : o.subject) +
                 "' failed to start" + (o.reason.empty() ? "" : ": " + o.reason);
    return o;
}

SignalObservation x_bugcheck(const EventFields& f, int) {
    SignalObservation o;
    o.subject = "system";
    // param1 = "0x0000007e (0x…, 0x…, …)" — keep the bugcheck code (first token).
    const std::string raw = named_or_pos(f, "param1", 0);
    o.reason = raw.substr(0, raw.find(' '));
    o.symbolic = "BUGCHECK";
    o.sentence = "blue screen (bugcheck" + (o.reason.empty() ? "" : " " + o.reason) + ")";
    return o;
}

SignalObservation x_power_loss(const EventFields& f, int) {
    SignalObservation o;
    o.subject = "system";
    const std::string bc = named(f, "BugcheckCode"); // decimal; "0" when pure power loss
    if (!bc.empty() && bc != "0") {
        o.reason = "bugcheck " + bc;
        o.sentence = "rebooted without clean shutdown (bugcheck " + bc + ")";
    } else {
        o.reason = "power loss";
        o.sentence = "rebooted without clean shutdown (power loss or hard hang)";
    }
    o.symbolic = "UNEXPECTED_REBOOT";
    return o;
}

SignalObservation x_display_reset(const EventFields& f, int) {
    SignalObservation o;
    o.subject = named_or_pos(f, "param1", 0); // driver, e.g. "nvlddmkm"
    o.symbolic = "DRIVER_RESET";
    o.sentence = "display driver '" + (o.subject.empty() ? "<unknown>" : o.subject) +
                 "' stopped responding and was recovered (TDR)";
    return o;
}

SignalObservation x_whea(const EventFields&, int id) {
    SignalObservation o;
    o.subject = "hardware";
    o.reason = "whea-" + std::to_string(id);
    o.symbolic = "HARDWARE_ERROR";
    o.sentence = "hardware error reported (WHEA event " + std::to_string(id) + ")";
    return o;
}

SignalObservation x_disk_error(const EventFields& f, int id) {
    SignalObservation o;
    o.subject = named_or_pos(f, "param1", 0); // \Device\Harddisk0\DR0
    o.reason = std::to_string(id);
    switch (id) {
    case 7:   o.symbolic = "BAD_BLOCK"; break;
    case 11:  o.symbolic = "CONTROLLER_ERROR"; break; // live-observed (Win11 26100)
    case 51:  o.symbolic = "PAGING_ERROR"; break;
    case 153: o.symbolic = "IO_RETRIED"; break;
    default:  o.symbolic = "DISK_ERROR"; break;
    }
    o.sentence = "disk error on " + (o.subject.empty() ? "<unknown device>" : o.subject) +
                 " (" + o.symbolic + ")";
    return o;
}

SignalObservation x_fs_corruption(const EventFields& f, int) {
    SignalObservation o;
    o.subject = named_or_pos(f, "DriveName", 0);
    o.symbolic = "FS_CORRUPTION";
    o.sentence = "file system structure corruption detected" +
                 (o.subject.empty() ? std::string{} : " on " + o.subject) + " — chkdsk advised";
    return o;
}

SignalObservation x_memory_exhausted(const EventFields& f, int) {
    SignalObservation o;
    o.subject = "virtual memory";
    o.symbolic = "COMMIT_EXHAUSTED";
    // The 2004 payload names the top commit consumers when the manifest renders
    // them; best-effort — absent on some builds, and the occurrence alone is the
    // signal.
    o.component = named(f, "ProcessName");
    o.sentence = "low virtual memory — commit charge exhausted" +
                 (o.component.empty() ? std::string{} : " (top consumer: " + o.component + ")");
    return o;
}

SignalObservation x_boot(const EventFields& f, int) {
    SignalObservation o;
    o.subject = "boot";
    o.metric = parse_metric_ms(named(f, "BootTime")); // ms, the headline duration
    o.sentence = o.metric > 0
                     ? std::format("boot completed in {:.0f} ms", o.metric)
                     : "boot completed (duration not reported)";
    return o;
}

SignalObservation x_update_failed(const EventFields& f, int) {
    SignalObservation o;
    o.subject = clip(named_or_pos(f, "updateTitle", 1), 120); // KB title — corp patch info, kept
    o.reason = named_or_pos(f, "errorCode", 0);
    o.symbolic = "UPDATE_FAILED";
    o.sentence = "update '" + (o.subject.empty() ? "<unknown>" : o.subject) + "' failed" +
                 (o.reason.empty() ? "" : " (" + o.reason + ")");
    return o;
}

SignalObservation x_msi_failed(const EventFields& f, int) {
    SignalObservation o;
    // 11708 is a classic single-string event: "Product: X -- Installation failed."
    const std::string raw = pos(f, 0);
    if (raw.starts_with("Product: ")) {
        const auto end = raw.find(" -- ");
        o.subject = clip(raw.substr(9, end == std::string::npos ? std::string::npos : end - 9), 120);
    } else {
        o.subject = clip(raw, 120);
    }
    o.symbolic = "INSTALL_FAILED";
    o.sentence = "application install failed: " + (o.subject.empty() ? "<unknown>" : o.subject);
    return o;
}

SignalObservation x_temp_profile(const EventFields&, int id) {
    SignalObservation o;
    // PRIVACY: the event's user context names the affected account — deliberately
    // NOT extracted. The device-scoped occurrence is the DEX signal.
    o.subject = "user profile";
    o.reason = std::to_string(id);
    o.symbolic = id == 1511 ? "TEMP_PROFILE" : "PROFILE_LOAD_FAILED";
    o.sentence = id == 1511 ? "a user was logged on with a temporary profile"
                            : "a user profile failed to load (registry hive)";
    return o;
}

SignalObservation x_gpo_failed(const EventFields& f, int id) {
    SignalObservation o;
    o.subject = "group policy";
    o.reason = named(f, "ErrorCode");
    o.symbolic = "GPO_FAILED";
    o.sentence = "group policy processing failed" +
                 (id == 1129 ? std::string(" (no domain controller connectivity)") : std::string{}) +
                 (o.reason.empty() ? "" : " (error " + o.reason + ")");
    return o;
}

SignalObservation x_wifi_drop(const EventFields& f, int) {
    SignalObservation o;
    // SSID is network infrastructure (not user content) — kept; the disconnect
    // Reason distinguishes intentional from failure disconnects downstream.
    o.subject = named(f, "SSID");
    o.reason = clip(named(f, "Reason"), 120);
    o.symbolic = "WIFI_DISCONNECT";
    o.component = named(f, "InterfaceDescription");
    o.sentence = "Wi-Fi disconnected" +
                 (o.subject.empty() ? std::string{} : " from '" + o.subject + "'") +
                 (o.reason.empty() ? "" : ": " + o.reason);
    return o;
}

SignalObservation x_dns_timeout(const EventFields&, int) {
    SignalObservation o;
    // PRIVACY: the queried name IS browsing behavior — deliberately NOT extracted
    // (the event carries it; we never read the field). Occurrence + count is the
    // DEX signal ("name resolution is failing on this device").
    o.subject = "dns";
    o.reason = "timeout";
    o.symbolic = "DNS_TIMEOUT";
    o.sentence = "DNS name resolution timed out (queried name withheld)";
    return o;
}

SignalObservation x_ip_conflict(const EventFields& f, int) {
    SignalObservation o;
    o.subject = named_or_pos(f, "param1", 0);   // the conflicting IP
    o.component = named_or_pos(f, "param2", 1); // MAC of the other system
    o.symbolic = "IP_CONFLICT";
    o.sentence = "IP address conflict" +
                 (o.subject.empty() ? std::string{} : " for " + o.subject);
    return o;
}

SignalObservation x_print_failed(const EventFields& f, int) {
    SignalObservation o;
    // 372 inserts: %1 doc id, %2 doc name, %3 owner, %4 printer, … PRIVACY: the
    // document name + owner are user content — deliberately NOT extracted; only
    // the printer (infrastructure) is kept.
    o.subject = named_or_pos(f, "Param4", 3);
    o.symbolic = "PRINT_FAILED";
    o.sentence = "a document failed to print" +
                 (o.subject.empty() ? std::string{} : " on '" + o.subject + "'") +
                 " (document name withheld)";
    return o;
}

// ── The catalogue ─────────────────────────────────────────────────────────────
// 20 obs_types. Two are backed by dual provider spellings (BugCheck / Ntfs ship
// under both classic and manifest names depending on build), so the spec count
// is 22. Caps are per-type events/hour — generous for real incident rates,
// tight enough that a storming provider (WHEA corrected-error loops, failing
// disks, Wi-Fi flaps) cannot flood the wire.

const std::vector<SignalSpec>& catalog_impl() {
    static const std::vector<SignalSpec> kCatalog = {
        // App reliability
        {"process.crashed", "Application", "Application Error", {1000}, 0, 120, &x_app_crash},
        {"process.hung", "Application", "Application Hang", {1002}, 0, 120, &x_app_hang},
        // Service reliability
        {"service.crashed", "System", "Service Control Manager", {7031, 7034}, 0, 60,
         &x_service_crashed},
        {"service.start_failed", "System", "Service Control Manager", {7000}, 0, 60,
         &x_service_start_failed},
        // Device stability
        {"os.bugcheck", "System", "Microsoft-Windows-WER-SystemErrorReporting", {1001}, 0, 30,
         &x_bugcheck},
        {"os.bugcheck", "System", "BugCheck", {1001}, 0, 30, &x_bugcheck},
        {"os.power_loss", "System", "Microsoft-Windows-Kernel-Power", {41}, 0, 30, &x_power_loss},
        {"display.driver_reset", "System", "Display", {4101}, 0, 60, &x_display_reset},
        {"hw.error", "System", "Microsoft-Windows-WHEA-Logger", {}, 3, 30, &x_whea},
        // Event 11 (controller error) added after a real Win11 box showed its disk
        // failures land there, not only 7/51/153.
        {"disk.error", "System", "disk", {7, 11, 51, 153}, 0, 30, &x_disk_error},
        {"fs.corruption", "System", "Ntfs", {55}, 0, 30, &x_fs_corruption},
        {"fs.corruption", "System", "Microsoft-Windows-Ntfs", {55}, 0, 30, &x_fs_corruption},
        {"memory.exhausted", "System", "Microsoft-Windows-Resource-Exhaustion-Detector", {2004}, 0,
         12, &x_memory_exhausted},
        // Performance
        {"os.boot", "Microsoft-Windows-Diagnostics-Performance/Operational",
         "Microsoft-Windows-Diagnostics-Performance", {100}, 0, 30, &x_boot},
        // Patch & install health
        {"update.failed", "System", "Microsoft-Windows-WindowsUpdateClient", {20}, 0, 30,
         &x_update_failed},
        {"app_install.failed", "Application", "MsiInstaller", {11708}, 0, 60, &x_msi_failed},
        // Logon & policy experience
        {"logon.temp_profile", "Application", "Microsoft-Windows-User Profiles Service",
         {1511, 1508}, 0, 12, &x_temp_profile},
        {"gpo.failed", "System", "Microsoft-Windows-GroupPolicy", {1125, 1129}, 0, 12,
         &x_gpo_failed},
        // Network experience
        {"network.wifi_drop", "Microsoft-Windows-WLAN-AutoConfig/Operational",
         "Microsoft-Windows-WLAN-AutoConfig", {8003}, 0, 60, &x_wifi_drop},
        {"network.dns_timeout", "System", "Microsoft-Windows-DNS Client Events", {1014}, 0, 30,
         &x_dns_timeout},
        {"network.ip_conflict", "System", "Tcpip", {4199}, 0, 12, &x_ip_conflict},
        // Print experience
        {"print.failed", "Microsoft-Windows-PrintService/Admin", "Microsoft-Windows-PrintService",
         {372}, 0, 60, &x_print_failed},
    };
    return kCatalog;
}

} // namespace

const std::vector<SignalSpec>& dex_signal_catalog() { return catalog_impl(); }

std::vector<std::string> dex_channels() {
    std::vector<std::string> out;
    for (const auto& s : catalog_impl())
        if (std::find(out.begin(), out.end(), s.channel) == out.end())
            out.emplace_back(s.channel);
    return out;
}

std::string dex_channel_query(const std::string& channel) {
    // Structured QueryList, one <Select> per spec: each Select is its own XPath,
    // so no query approaches winevt's 32-expression limit, and the kernel-side
    // filter means the callback only fires for catalogued events.
    std::string q = "<QueryList><Query Id=\"0\" Path=\"" + channel + "\">";
    for (const auto& s : catalog_impl()) {
        if (channel != s.channel)
            continue;
        std::string sel = "*[System[Provider[@Name='" + std::string(s.provider) + "']";
        if (!s.event_ids.empty()) {
            sel += " and (";
            for (std::size_t i = 0; i < s.event_ids.size(); ++i) {
                if (i) sel += " or ";
                sel += "EventID=" + std::to_string(s.event_ids[i]);
            }
            sel += ")";
        }
        if (s.max_level > 0) {
            sel += " and (";
            for (int lv = 1; lv <= s.max_level; ++lv) {
                if (lv > 1) sel += " or ";
                sel += "Level=" + std::to_string(lv);
            }
            sel += ")";
        }
        sel += "]]";
        q += "<Select Path=\"" + channel + "\">" + sel + "</Select>";
    }
    q += "</Query></QueryList>";
    return q;
}

const SignalSpec* find_signal_spec(const std::string& channel, const std::string& provider,
                                   int event_id) {
    for (const auto& s : catalog_impl()) {
        if (channel != s.channel || provider != s.provider)
            continue;
        if (s.event_ids.empty() ||
            std::find(s.event_ids.begin(), s.event_ids.end(), event_id) != s.event_ids.end())
            return &s;
    }
    return nullptr;
}

std::optional<SignalObservation> extract_signal(const std::string& channel,
                                                const std::string& provider, int event_id,
                                                int level, const EventFields& fields) {
    const SignalSpec* spec = find_signal_spec(channel, provider, event_id);
    if (!spec)
        return std::nullopt;
    // Re-check the level filter in pure code (the subscription already filters
    // kernel-side; this keeps the behavior unit-testable + defends a forged event).
    if (spec->max_level > 0 && (level < 1 || level > spec->max_level))
        return std::nullopt;
    SignalObservation o = spec->extract(fields, event_id);
    o.obs_type = spec->obs_type;
    o.platform = "windows"; // sole collector today; Linux/macOS collectors set theirs
    if (o.sentence.empty())
        o.sentence = std::string(spec->obs_type) + (o.subject.empty() ? "" : " " + o.subject);
    return o;
}

} // namespace yuzu::agent
