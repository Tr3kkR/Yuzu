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

// ── Wave-2 helpers ───────────────────────────────────────────────────────────

// First field value that parses as a positive number (classic events like
// EventLog 6013 carry the payload at a positional offset that varies by build —
// the numeric field IS the discriminator).
double first_numeric(const EventFields& f) {
    for (const auto& [k, v] : f) {
        const double d = parse_metric_ms(v);
        if (d > 0.0)
            return d;
    }
    return 0.0;
}

// Strip a Windows path down to its basename. PRIVACY guard: full paths can leak
// usernames (C:\Users\<name>\…) or document locations; the basename keeps the
// diagnostic value (which binary/hive/dll) without the location.
std::string strip_path(const std::string& s) {
    const auto pos = s.find_last_of("\\/");
    return pos == std::string::npos ? s : s.substr(pos + 1);
}

// Render a numeric error field as hex when it looks like an HRESULT/NTSTATUS
// (BITS reports `hr` in DECIMAL — "2147954407" is unreadable; 0x80072EE7 is not).
std::string hex_reason(const std::string& s) {
    if (s.empty()) return s;
    try {
        const unsigned long long v = std::stoull(s);
        if (v > 0xFFFF && v <= 0xFFFFFFFFull)
            return std::format("0x{:08X}", static_cast<std::uint32_t>(v));
    } catch (...) {
    }
    return s;
}

// Value of a "Key: value" line inside a multi-line blob (.NET Runtime 1026 packs
// everything into ONE positional Data element).
std::string line_value(const std::string& blob, std::string_view key) {
    const auto kpos = blob.find(key);
    if (kpos == std::string::npos) return {};
    const auto start = kpos + key.size();
    auto end = blob.find('\n', start);
    if (end == std::string::npos) end = blob.size();
    std::string v = blob.substr(start, end - start);
    while (!v.empty() && (v.back() == '\r' || v.back() == ' ')) v.pop_back();
    while (!v.empty() && v.front() == ' ') v.erase(v.begin());
    return v;
}

// ── Wave-2 extractors ────────────────────────────────────────────────────────
// Real layouts: Diagnostics-Performance 101/103/200/203, EventLog 6008/6013,
// Time-Service 36, .NET 1026, DCOM 10010, Application Popup 26, SCM 7009,
// Kernel-PnP 411, WLAN 8002, Defender 2001, AppX 404, BITS 61 are all pinned
// against records captured from a live Win11 26100 box (2026-06-10); the rest
// are manifest-best-effort with graceful degradation.

// Shared by every Diagnostics-Performance degradation event (101/102/103/109 =
// boot, 203 = shutdown, 301/302 = standby/resume). Real layout: named Name /
// FriendlyName / TotalTime / DegradationTime / Path (Path DROPPED — privacy).
SignalObservation x_dp_degraded(const EventFields& f, int id) {
    SignalObservation o;
    o.subject = named(f, "Name");
    if (o.subject.empty())
        o.subject = named(f, "FriendlyName");
    o.metric = parse_metric_ms(named(f, "DegradationTime"));
    if (o.metric <= 0.0)
        o.metric = parse_metric_ms(named(f, "TotalTime"));
    const char* phase = (id == 203) ? "shutdown" : (id == 301 || id == 302) ? "resume" : "boot";
    o.symbolic = "DEGRADATION";
    o.sentence = "'" + (o.subject.empty() ? "<unknown>" : o.subject) + "' slowed " + phase +
                 (o.metric > 0 ? std::format(" by {:.0f} ms", o.metric) : "");
    return o;
}

SignalObservation x_shutdown_report(const EventFields& f, int) {
    SignalObservation o;
    o.subject = "shutdown";
    o.metric = parse_metric_ms(named(f, "ShutdownTime")); // real: 17733 (ms)
    o.sentence = o.metric > 0 ? std::format("shutdown completed in {:.0f} ms", o.metric)
                              : "shutdown completed (duration not reported)";
    return o;
}

SignalObservation x_standby_report(const EventFields& f, int) {
    SignalObservation o;
    o.subject = "standby";
    o.metric = parse_metric_ms(named(f, "StandbyTime")); // best-effort; 0 = occurrence only
    o.sentence = "standby/resume cycle reported";
    return o;
}

SignalObservation x_winlogon_slow(const EventFields& f, int) {
    SignalObservation o;
    o.subject = named_or_pos(f, "SubscriberName", 0); // e.g. "GPClient" — the classic
    o.symbolic = "SLOW_LOGON_SUBSCRIBER";
    o.sentence = "winlogon notification subscriber '" +
                 (o.subject.empty() ? "<unknown>" : o.subject) + "' is taking a long time";
    return o;
}

SignalObservation x_uptime_report(const EventFields& f, int) {
    SignalObservation o;
    o.subject = "uptime";
    o.metric = first_numeric(f); // real 6013: positional, leading fields empty
    o.sentence = o.metric > 0 ? std::format("system uptime {:.0f} s", o.metric)
                              : "daily uptime report";
    return o;
}

SignalObservation x_dirty_shutdown(const EventFields& f, int) {
    SignalObservation o;
    o.subject = "system";
    o.symbolic = "DIRTY_SHUTDOWN";
    // Real 6008: pos0 = time, pos1 = date (with embedded LTR marks — clip only).
    const std::string t = clip(pos(f, 0), 16), d = clip(pos(f, 1), 16);
    o.sentence = "previous shutdown" + (d.empty() ? std::string{} : " at " + d + " " + t) +
                 " was unexpected";
    return o;
}

SignalObservation x_time_unsynced(const EventFields& f, int id) {
    SignalObservation o;
    o.subject = "time sync";
    o.metric = parse_metric_ms(named(f, "UnsynchronizedTimeSeconds")); // real: 51254
    o.symbolic = "TIME_UNSYNCED";
    o.reason = std::to_string(id);
    o.sentence = o.metric > 0
                     ? std::format("clock unsynchronized for {:.0f} s", o.metric)
                     : "time service cannot reach a time source";
    return o;
}

SignalObservation x_activation_failed(const EventFields& f, int) {
    SignalObservation o;
    o.subject = "windows activation";
    o.reason = hex_reason(named_or_pos(f, "ErrorCode", 0));
    o.symbolic = "ACTIVATION_FAILED";
    o.sentence = "license activation failed" + (o.reason.empty() ? "" : " (" + o.reason + ")");
    return o;
}

SignalObservation x_vss_error(const EventFields& f, int) {
    SignalObservation o;
    o.subject = "volume shadow copy";
    o.reason = clip(pos(f, 0), 80);
    o.symbolic = "VSS_ERROR";
    o.sentence = "volume shadow copy service error";
    return o;
}

SignalObservation x_hive_recovered(const EventFields&, int) {
    SignalObservation o;
    // PRIVACY: the hive path can be C:\Users\<name>\ntuser.dat — not extracted.
    o.subject = "registry hive";
    o.symbolic = "HIVE_RECOVERED";
    o.sentence = "a corrupted registry hive was recovered from its log";
    return o;
}

SignalObservation x_autochk_ran(const EventFields&, int) {
    SignalObservation o;
    o.subject = "autochk";
    o.symbolic = "FS_CHECK_AT_BOOT";
    o.sentence = "file system check ran at boot (volume was marked dirty)";
    return o;
}

SignalObservation x_dotnet_crash(const EventFields& f, int) {
    SignalObservation o;
    // Real 1026: ONE positional blob — extract ONLY the app + exception type
    // (the stack frames can carry paths; they are never shipped).
    const std::string blob = pos(f, 0);
    o.subject = strip_path(line_value(blob, "Application: "));
    std::string exc = line_value(blob, "Exception Info: ");
    if (auto colon = exc.find(':'); colon != std::string::npos)
        exc = exc.substr(0, colon);
    o.reason = clip(std::move(exc), 120); // e.g. "System.ArgumentNullException"
    o.kind = "exception";
    o.symbolic = "CLR_UNHANDLED_EXCEPTION";
    o.sentence = (o.subject.empty() ? "<unknown>" : o.subject) + " .NET unhandled exception" +
                 (o.reason.empty() ? "" : " " + o.reason);
    return o;
}

SignalObservation x_sxs_error(const EventFields& f, int) {
    SignalObservation o;
    o.subject = strip_path(clip(pos(f, 0), 120)); // assembly/app — basename if a path
    o.symbolic = "SXS_ACTIVATION_FAILED";
    o.sentence = "side-by-side activation context generation failed" +
                 (o.subject.empty() ? std::string{} : " for " + o.subject);
    return o;
}

SignalObservation x_app_activation_failed(const EventFields& f, int) {
    SignalObservation o;
    o.subject = clip(named_or_pos(f, "AppId", 0), 120);
    o.reason = hex_reason(named(f, "ErrorCode"));
    o.symbolic = "APP_ACTIVATION_FAILED";
    o.sentence = "app activation failed" +
                 (o.subject.empty() ? std::string{} : ": " + o.subject);
    return o;
}

SignalObservation x_dcom_failed(const EventFields& f, int id) {
    SignalObservation o;
    o.subject = clip(named_or_pos(f, "param1", 0), 80); // CLSID / server (real 10010)
    o.reason = std::to_string(id);
    o.symbolic = "COM_SERVER_FAILED";
    o.sentence = id == 10010 ? "a COM server did not register within the required timeout"
                             : "DCOM could not start a server";
    return o;
}

SignalObservation x_error_popup(const EventFields& f, int) {
    SignalObservation o;
    // Real 26: named Caption + Message — a hard error dialog the USER SAW.
    o.subject = clip(named(f, "Caption"), 80);
    o.symbolic = "ERROR_DIALOG";
    o.sentence = clip(named(f, "Message"), 160);
    if (o.sentence.empty())
        o.sentence = "an error dialog was shown";
    return o;
}

SignalObservation x_shutdown_blocked(const EventFields& f, int) {
    SignalObservation o;
    // PRIVACY: RestartManager carries FullPath — only the display name is taken.
    o.subject = clip(named_or_pos(f, "DisplayName", 0), 80);
    o.symbolic = "SHUTDOWN_BLOCKED";
    o.sentence = "an application could not be shut down" +
                 (o.subject.empty() ? std::string{} : ": " + o.subject);
    return o;
}

SignalObservation x_service_hung(const EventFields& f, int) {
    SignalObservation o;
    o.subject = named_or_pos(f, "param1", 0);
    o.symbolic = "SERVICE_HUNG";
    o.kind = "service";
    o.sentence = "service '" + (o.subject.empty() ? "<unknown>" : o.subject) +
                 "' hung on starting";
    return o;
}

SignalObservation x_service_start_timeout(const EventFields& f, int) {
    SignalObservation o;
    // Real 7009: param1 = timeout ms, param2 = service (REVERSED vs 7000).
    o.subject = named_or_pos(f, "param2", 1);
    const std::string ms = named_or_pos(f, "param1", 0);
    o.reason = ms.empty() ? "timeout" : "timeout " + ms + " ms";
    o.symbolic = "START_TIMEOUT";
    o.kind = "service";
    o.sentence = "service '" + (o.subject.empty() ? "<unknown>" : o.subject) +
                 "' did not connect to the service controller in time";
    return o;
}

SignalObservation x_service_logon_failed(const EventFields& f, int) {
    SignalObservation o;
    // PRIVACY: param2 is the logon ACCOUNT (can be a person) — not extracted.
    o.subject = named_or_pos(f, "param1", 0);
    o.symbolic = "SERVICE_LOGON_FAILED";
    o.kind = "service";
    o.sentence = "service '" + (o.subject.empty() ? "<unknown>" : o.subject) +
                 "' failed to log on (account/password problem)";
    return o;
}

SignalObservation x_service_recovery_failed(const EventFields& f, int) {
    SignalObservation o;
    o.subject = named_or_pos(f, "param2", 1);
    o.component = clip(named_or_pos(f, "param1", 0), 60); // the corrective action
    o.symbolic = "RECOVERY_FAILED";
    o.kind = "service";
    o.sentence = "recovery action failed for service '" +
                 (o.subject.empty() ? "<unknown>" : o.subject) + "'";
    return o;
}

SignalObservation x_disk_smart(const EventFields& f, int) {
    SignalObservation o;
    o.subject = named_or_pos(f, "param1", 0);
    o.symbolic = "SMART_PREDICTIVE_FAILURE";
    o.sentence = "disk " + (o.subject.empty() ? "<unknown>" : o.subject) +
                 " is predicting its own failure (SMART) — back up and replace";
    return o;
}

SignalObservation x_port_reset(const EventFields& f, int) {
    SignalObservation o;
    o.subject = named_or_pos(f, "param1", 0); // \Device\RaidPort0
    o.symbolic = "PORT_RESET";
    o.sentence = "a reset was issued to storage port " +
                 (o.subject.empty() ? "<unknown>" : o.subject) +
                 " (I/O stalled — reset storms indicate a dying disk/cable)";
    return o;
}

SignalObservation x_write_lost(const EventFields& f, int) {
    SignalObservation o;
    o.subject = clip(strip_path(pos(f, 0)), 80);
    o.symbolic = "DELAYED_WRITE_LOST";
    o.sentence = "Windows lost delayed-write data (possible data loss)";
    return o;
}

SignalObservation x_esent_corrupt(const EventFields& f, int id) {
    SignalObservation o;
    // PRIVACY: ESENT params include the database PATH (often under a user
    // profile) — only the owning process name is taken.
    o.subject = clip(strip_path(pos(f, 0)), 80);
    o.reason = std::to_string(id);
    o.symbolic = "DATABASE_CORRUPT";
    o.sentence = "an ESE database is corrupted" +
                 (o.subject.empty() ? std::string{} : " (owner: " + o.subject + ")");
    return o;
}

SignalObservation x_device_start_failed(const EventFields& f, int) {
    SignalObservation o;
    // Real 411: named DeviceInstanceId / DriverName / Status.
    o.subject = clip(named(f, "DeviceInstanceId"), 100);
    o.component = named(f, "DriverName");
    o.reason = named(f, "Status");
    o.symbolic = "DEVICE_START_FAILED";
    o.sentence = "a device failed to start" +
                 (o.subject.empty() ? std::string{} : ": " + o.subject);
    return o;
}

SignalObservation x_cpu_throttled(const EventFields&, int) {
    SignalObservation o;
    o.subject = "cpu";
    o.symbolic = "FIRMWARE_THROTTLED";
    o.sentence = "processor speed is being limited by system firmware (thermal/power cap)";
    return o;
}

SignalObservation x_wifi_connect_failed(const EventFields& f, int) {
    SignalObservation o;
    // Real 8002: named SSID / FailureReason / ReasonCode / InterfaceDescription.
    o.subject = named(f, "SSID");
    o.reason = clip(named(f, "FailureReason"), 120);
    o.component = named(f, "InterfaceDescription");
    o.symbolic = "WIFI_CONNECT_FAILED";
    o.sentence = "Wi-Fi connection failed" +
                 (o.subject.empty() ? std::string{} : " to '" + o.subject + "'") +
                 (o.reason.empty() ? "" : ": " + o.reason);
    return o;
}

SignalObservation x_dhcp_failed(const EventFields& f, int) {
    SignalObservation o;
    o.subject = "dhcp";
    o.reason = hex_reason(clip(named_or_pos(f, "ErrorCode", 0), 40));
    o.symbolic = "DHCP_FAILED";
    o.sentence = "DHCP address acquisition/renewal failed";
    return o;
}

SignalObservation x_vpn_failed(const EventFields& f, int) {
    SignalObservation o;
    // PRIVACY: insert %1 is the dialing USER — deliberately never read; %2 is the
    // connection name, %3 the error code. A drifted layout degrades to empty
    // fields rather than risking the username.
    o.subject = clip(pos(f, 1), 80);
    o.reason = clip(pos(f, 2), 40);
    o.symbolic = "VPN_FAILED";
    o.sentence = "VPN connection failed" +
                 (o.subject.empty() ? std::string{} : " ('" + o.subject + "')") +
                 (o.reason.empty() ? "" : " error " + o.reason);
    return o;
}

SignalObservation x_smb_failed(const EventFields& f, int) {
    SignalObservation o;
    o.subject = clip(named(f, "ServerName"), 80); // corp file server — kept
    o.reason = hex_reason(named(f, "Status"));
    o.symbolic = "SMB_CONNECT_FAILED";
    o.sentence = "network share connection failed" +
                 (o.subject.empty() ? std::string{} : " to " + o.subject);
    return o;
}

SignalObservation x_name_conflict(const EventFields&, int) {
    SignalObservation o;
    o.subject = "netbios name";
    o.symbolic = "NAME_CONFLICT";
    o.sentence = "a duplicate computer name was detected on the network";
    return o;
}

SignalObservation x_no_dc(const EventFields& f, int) {
    SignalObservation o;
    o.subject = clip(pos(f, 0), 60); // the domain — corp infrastructure
    o.reason = clip(pos(f, 1), 120);
    o.symbolic = "NO_DOMAIN_CONTROLLER";
    o.sentence = "no domain controller reachable" +
                 (o.subject.empty() ? std::string{} : " for domain " + o.subject);
    return o;
}

SignalObservation x_kerberos_error(const EventFields& f, int) {
    SignalObservation o;
    o.subject = clip(named_or_pos(f, "Server", 0), 80);
    o.symbolic = "KERBEROS_ERROR";
    o.sentence = "Kerberos authentication error (KRB_AP_ERR_MODIFIED — check SPN/clock)";
    return o;
}

SignalObservation x_rtp_disabled(const EventFields&, int) {
    SignalObservation o;
    o.subject = "real-time protection";
    o.symbolic = "RTP_DISABLED";
    o.sentence = "antivirus real-time protection was disabled";
    return o;
}

SignalObservation x_threat_detected(const EventFields& f, int) {
    SignalObservation o;
    // PRIVACY: the detection carries the file PATH and USER — only the threat
    // family name (malware taxonomy, not user content) is taken.
    o.subject = clip(named(f, "Threat Name"), 80);
    o.symbolic = "THREAT_DETECTED";
    o.sentence = "malware detected" +
                 (o.subject.empty() ? std::string{} : ": " + o.subject);
    return o;
}

SignalObservation x_av_update_failed(const EventFields& f, int) {
    SignalObservation o;
    o.subject = "security intelligence update";
    o.reason = named(f, "Error Code"); // real: Defender names carry SPACES
    o.symbolic = "AV_UPDATE_FAILED";
    o.sentence = "antivirus definition update failed" +
                 (o.reason.empty() ? "" : " (" + o.reason + ")");
    return o;
}

SignalObservation x_tamper_blocked(const EventFields& f, int) {
    SignalObservation o;
    o.subject = "tamper protection";
    o.reason = clip(named_or_pos(f, "Value", 0), 80);
    o.symbolic = "TAMPER_BLOCKED";
    o.sentence = "tamper protection blocked a change to security settings";
    return o;
}

SignalObservation x_appx_failed(const EventFields& f, int) {
    SignalObservation o;
    // Real 404: named PackageFullName / ErrorCode / SummaryError.
    o.subject = clip(named(f, "PackageFullName"), 100);
    o.reason = named(f, "ErrorCode");
    o.symbolic = "APPX_DEPLOY_FAILED";
    o.sentence = "store app deployment failed" +
                 (o.subject.empty() ? std::string{} : ": " + o.subject);
    return o;
}

SignalObservation x_bits_failed(const EventFields& f, int) {
    SignalObservation o;
    // Real 61: named name / url / hr. PRIVACY: the URL is dropped (can encode
    // user-specific endpoints); the job name + hex error carry the diagnosis.
    o.subject = clip(named(f, "name"), 80);
    o.reason = hex_reason(named(f, "hr"));
    o.symbolic = "TRANSFER_FAILED";
    o.sentence = "background transfer failed" +
                 (o.subject.empty() ? std::string{} : " ('" + o.subject + "')") +
                 (o.reason.empty() ? "" : " " + o.reason);
    return o;
}

SignalObservation x_profile_locked(const EventFields&, int) {
    SignalObservation o;
    // PRIVACY: the event names the profile (≈ the person) — not extracted.
    o.subject = "user profile";
    o.symbolic = "PROFILE_LOCKED";
    o.sentence = "a user profile registry hive did not unload (held by another process)";
    return o;
}

SignalObservation x_folder_redirect_failed(const EventFields&, int) {
    SignalObservation o;
    // PRIVACY: params carry redirected folder paths (user content) — dropped.
    o.subject = "folder redirection";
    o.symbolic = "REDIRECT_FAILED";
    o.sentence = "folder redirection failed";
    return o;
}

SignalObservation x_print_driver_failed(const EventFields& f, int) {
    SignalObservation o;
    o.subject = clip(named_or_pos(f, "Param1", 0), 80);
    o.symbolic = "DRIVER_INSTALL_FAILED";
    o.sentence = "printer driver installation failed" +
                 (o.subject.empty() ? std::string{} : ": " + o.subject);
    return o;
}

SignalObservation x_print_plugin_failed(const EventFields& f, int) {
    SignalObservation o;
    o.subject = clip(strip_path(named_or_pos(f, "Param1", 0)), 80);
    o.symbolic = "SPOOLER_PLUGIN_FAILED";
    o.sentence = "the print spooler failed to load a plug-in module";
    return o;
}

// MSI events share the "Product: X -- <verb> failed." string shape; the verb in
// the sentence comes from the event id (11708 install, 11725 uninstall).
SignalObservation x_msi_uninstall_failed(const EventFields& f, int id) {
    SignalObservation o = x_msi_failed(f, id);
    o.symbolic = "UNINSTALL_FAILED";
    o.sentence = "application uninstall failed: " +
                 (o.subject.empty() ? "<unknown>" : o.subject);
    return o;
}

// ── Wave-3 extractors (2026-06-10) ───────────────────────────────────────────
// Real layouts pinned from a live box: Power-Troubleshooter 1 (WakeDuration ms),
// User32 1074 (param7 = USER, dropped), TPM-WMI (real error id 1801 — validates
// the any-id pattern), Biometrics 1014 (BiometricSensor named), AAD 1097
// (decimal Error), MDM 844 (named HRESULT). The rest are manifest-best-effort
// behind the whole-catalogue graceful-degradation test.

SignalObservation x_fast_startup_failed(const EventFields& f, int) {
    SignalObservation o;
    o.subject = "fast startup";
    o.reason = hex_reason(named_or_pos(f, "Status", 0));
    o.symbolic = "FAST_STARTUP_FAILED";
    o.sentence = "fast startup failed — the system fell back to a full boot";
    return o;
}

SignalObservation x_resume_report(const EventFields& f, int) {
    SignalObservation o;
    o.subject = "resume";
    o.metric = parse_metric_ms(named(f, "WakeDuration")); // real: ms
    o.sentence = o.metric > 0 ? std::format("resumed from sleep in {:.0f} ms", o.metric)
                              : "resumed from sleep";
    return o;
}

SignalObservation x_restart_initiated(const EventFields& f, int) {
    SignalObservation o;
    // Real 1074: param1 = "C:\...\app.exe (HOST)", param3 = reason text,
    // param5 = action. PRIVACY: param7 is the initiating USER — never read.
    std::string proc = strip_path(named_or_pos(f, "param1", 0));
    if (auto sp = proc.find(" ("); sp != std::string::npos)
        proc.resize(sp);
    o.subject = clip(std::move(proc), 80);
    const std::string action = named_or_pos(f, "param5", 4);
    const std::string why = named_or_pos(f, "param3", 2);
    o.reason = clip(why, 60);
    o.symbolic = "RESTART_INITIATED";
    o.sentence = (action.empty() ? std::string("restart/shutdown") : action) + " initiated" +
                 (o.subject.empty() ? std::string{} : " by " + o.subject) +
                 (why.empty() ? "" : " (" + clip(why, 60) + ")");
    return o;
}

SignalObservation x_shadow_copies_lost(const EventFields&, int) {
    SignalObservation o;
    o.subject = "shadow copies";
    o.symbolic = "SHADOW_COPIES_LOST";
    o.sentence = "shadow copies were deleted under I/O pressure (restore points lost)";
    return o;
}

SignalObservation x_crashdump_disabled(const EventFields&, int) {
    SignalObservation o;
    o.subject = "crash dump";
    o.symbolic = "CRASHDUMP_DISABLED";
    o.sentence = "crash dump initialization failed — a future BSOD would leave no dump";
    return o;
}

SignalObservation x_dwm_exited(const EventFields& f, int) {
    SignalObservation o;
    o.subject = "desktop window manager";
    o.reason = clip(pos(f, 0), 40);
    o.symbolic = "DWM_EXITED";
    o.sentence = "the Desktop Window Manager exited (visible flicker/black screen)";
    return o;
}

SignalObservation x_file_access_failure(const EventFields& f, int) {
    SignalObservation o;
    // PRIVACY: the inaccessible FILE PATH (often a user document) is dropped;
    // the app name carries the diagnosis.
    o.subject = strip_path(clip(pos(f, 0), 80));
    o.symbolic = "FILE_ACCESS_FAILED";
    o.sentence = "an application could not access a required file (disk or network problem)";
    return o;
}

SignalObservation x_push_notification_error(const EventFields&, int id) {
    SignalObservation o;
    o.subject = "push notifications";
    o.reason = "wpn-" + std::to_string(id);
    o.symbolic = "NOTIFICATION_ERROR";
    o.sentence = "the push-notification platform reported an error";
    return o;
}

SignalObservation x_file_association_reset(const EventFields& f, int) {
    SignalObservation o;
    o.subject = clip(named_or_pos(f, "Extension", 0), 20);
    o.symbolic = "ASSOCIATION_RESET";
    o.sentence = "a file-type association was reset to the Windows default" +
                 (o.subject.empty() ? std::string{} : " (" + o.subject + ")");
    return o;
}

SignalObservation x_staterepo_error(const EventFields&, int id) {
    SignalObservation o;
    o.subject = "app state repository";
    o.reason = "sr-" + std::to_string(id);
    o.symbolic = "STATEREPO_ERROR";
    o.sentence = "the app state repository reported an error (Start/Search health)";
    return o;
}

SignalObservation x_dependency_failed(const EventFields& f, int) {
    SignalObservation o;
    o.subject = named_or_pos(f, "param1", 0);
    o.component = named_or_pos(f, "param2", 1); // the dependency that failed
    o.symbolic = "DEPENDENCY_FAILED";
    o.kind = "service";
    o.sentence = "service '" + (o.subject.empty() ? "<unknown>" : o.subject) +
                 "' did not start because its dependency failed" +
                 (o.component.empty() ? "" : " (" + o.component + ")");
    return o;
}

SignalObservation x_flush_failed(const EventFields&, int) {
    SignalObservation o;
    o.subject = "ntfs";
    o.symbolic = "FLUSH_FAILED";
    o.sentence = "the system failed to flush data to the transaction log — corruption possible";
    return o;
}

SignalObservation x_user_driver_error(const EventFields& f, int) {
    SignalObservation o;
    o.subject = clip(strip_path(pos(f, 0)), 80);
    o.symbolic = "USER_DRIVER_ERROR";
    o.sentence = "a user-mode device driver (webcam/USB class) reported a problem";
    return o;
}

SignalObservation x_tpm_error(const EventFields&, int id) {
    SignalObservation o;
    o.subject = "tpm";
    o.reason = "tpm-" + std::to_string(id); // real: 1801
    o.symbolic = "TPM_ERROR";
    o.sentence = "the TPM reported an error (Hello/BitLocker dependency)";
    return o;
}

SignalObservation x_port_exhaustion(const EventFields&, int id) {
    SignalObservation o;
    o.subject = "tcp ports";
    o.reason = std::to_string(id);
    o.symbolic = "PORT_EXHAUSTION";
    o.sentence = "ephemeral TCP port allocation failed (port exhaustion — connections will "
                 "fail until freed)";
    return o;
}

SignalObservation x_smb_write_lost(const EventFields& f, int) {
    SignalObservation o;
    o.subject = clip(pos(f, 0), 80); // \\server\share — corp infrastructure
    o.symbolic = "DELAYED_WRITE_LOST";
    o.sentence = "Windows lost delayed-write data on a network share";
    return o;
}

SignalObservation x_dns_register_failed(const EventFields&, int id) {
    SignalObservation o;
    o.subject = "dns registration";
    o.reason = std::to_string(id);
    o.symbolic = "DNS_REGISTER_FAILED";
    o.sentence = "this host could not register its own DNS records";
    return o;
}

SignalObservation x_rdp_disconnected(const EventFields& f, int id) {
    SignalObservation o;
    // PRIVACY: LSM events name the USER and the client ADDRESS — neither read.
    o.subject = "rdp session";
    const std::string why = named(f, "Reason");
    o.reason = why.empty() ? std::to_string(id) : clip(why, 60);
    o.symbolic = "RDP_DISCONNECTED";
    o.sentence = "a remote desktop session was disconnected";
    return o;
}

SignalObservation x_winlogon_terminated(const EventFields&, int) {
    SignalObservation o;
    o.subject = "winlogon";
    o.symbolic = "WINLOGON_TERMINATED";
    o.sentence = "the Windows logon process terminated unexpectedly";
    return o;
}

SignalObservation x_machine_trust_failed(const EventFields& f, int) {
    SignalObservation o;
    o.subject = clip(pos(f, 0), 60); // the domain — corp infrastructure
    o.reason = clip(pos(f, 1), 60);
    o.symbolic = "MACHINE_TRUST_FAILED";
    o.sentence = "this computer could not authenticate with its domain (broken trust)";
    return o;
}

SignalObservation x_biometric_error(const EventFields& f, int id) {
    SignalObservation o;
    o.subject = clip(named(f, "BiometricSensor"), 80); // real: sensor model
    if (o.subject.empty())
        o.subject = "biometric sensor";
    o.reason = "bio-" + std::to_string(id);
    o.symbolic = "BIOMETRIC_ERROR";
    o.sentence = "a biometric (fingerprint/face) sensor reported an error";
    return o;
}

SignalObservation x_hello_error(const EventFields&, int id) {
    SignalObservation o;
    o.subject = "windows hello";
    o.reason = "hello-" + std::to_string(id);
    o.symbolic = "HELLO_ERROR";
    o.sentence = "Windows Hello for Business reported an error";
    return o;
}

SignalObservation x_aad_token_error(const EventFields& f, int id) {
    SignalObservation o;
    // PRIVACY: AAD ErrorMessage texts can embed UPNs — only the numeric error is
    // taken (real layout: decimal 'Error' → render as hex).
    o.subject = "entra sso";
    o.reason = hex_reason(named(f, "Error"));
    if (o.reason.empty())
        o.reason = std::to_string(id);
    o.symbolic = "AAD_TOKEN_ERROR";
    o.sentence = "Entra ID (AAD) token acquisition error — SSO/sign-in may be failing";
    return o;
}

SignalObservation x_auth_error(const EventFields&, int id) {
    SignalObservation o;
    o.subject = "authentication";
    o.reason = std::to_string(id);
    o.symbolic = "AUTH_ERROR";
    o.sentence = "the security system reported an authentication error";
    return o;
}

SignalObservation x_tls_alert(const EventFields& f, int id) {
    SignalObservation o;
    o.subject = "tls";
    const std::string alert = named_or_pos(f, "AlertDesc", 0);
    o.reason = alert.empty() ? std::to_string(id) : "alert " + clip(alert, 20);
    o.symbolic = "TLS_ALERT";
    o.sentence = "a fatal TLS alert was generated (secure connections failing)";
    return o;
}

SignalObservation x_threat_action_failed(const EventFields& f, int) {
    SignalObservation o;
    // Same privacy posture as 1116: threat name kept, path + user dropped.
    o.subject = clip(named(f, "Threat Name"), 80);
    o.symbolic = "THREAT_ACTION_FAILED";
    o.sentence = "antivirus could not complete its action against a detected threat";
    return o;
}

SignalObservation x_rtp_error(const EventFields& f, int) {
    SignalObservation o;
    o.subject = "real-time protection";
    o.reason = named(f, "Error Code"); // Defender names carry spaces
    o.symbolic = "RTP_ERROR";
    o.sentence = "real-time protection encountered an error";
    return o;
}

SignalObservation x_bitlocker_error(const EventFields&, int id) {
    SignalObservation o;
    o.subject = "bitlocker";
    o.reason = "bl-" + std::to_string(id);
    o.symbolic = "BITLOCKER_ERROR";
    o.sentence = "BitLocker reported an error";
    return o;
}

SignalObservation x_cert_enroll_failed(const EventFields&, int id) {
    SignalObservation o;
    o.subject = "certificate enrollment";
    o.reason = std::to_string(id);
    o.symbolic = "CERT_ENROLL_FAILED";
    o.sentence = "automatic certificate enrollment failed (expiring VPN/Wi-Fi certs ahead)";
    return o;
}

SignalObservation x_update_check_failed(const EventFields& f, int) {
    SignalObservation o;
    o.subject = "update check";
    o.reason = hex_reason(named_or_pos(f, "errorCode", 0));
    o.symbolic = "UPDATE_CHECK_FAILED";
    o.sentence = "checking for updates failed" + (o.reason.empty() ? "" : " (" + o.reason + ")");
    return o;
}

SignalObservation x_update_download_failed(const EventFields& f, int) {
    SignalObservation o;
    o.subject = clip(named_or_pos(f, "updateTitle", 1), 120);
    o.reason = hex_reason(named_or_pos(f, "errorCode", 0));
    o.symbolic = "UPDATE_DOWNLOAD_FAILED";
    o.sentence = "an update failed to download" +
                 (o.subject.empty() ? std::string{} : ": " + o.subject);
    return o;
}

SignalObservation x_gpo_cse_failed(const EventFields& f, int) {
    SignalObservation o;
    o.subject = clip(named_or_pos(f, "ExtensionName", 0), 60);
    o.reason = hex_reason(named(f, "ErrorCode"));
    o.symbolic = "GPO_CSE_FAILED";
    o.sentence = "Windows failed to apply a Group Policy extension" +
                 (o.subject.empty() ? std::string{} : " (" + o.subject + ")");
    return o;
}

SignalObservation x_mdm_error(const EventFields& f, int id) {
    SignalObservation o;
    o.subject = "mdm agent";
    o.reason = named(f, "HRESULT"); // real layout
    if (o.reason.empty())
        o.reason = "mdm-" + std::to_string(id);
    o.symbolic = "MDM_ERROR";
    o.sentence = "the device-management (MDM/Intune) agent reported an error";
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

        // ── Wave 2 (2026-06-10): +50 signals ─────────────────────────────────
        // Boot, start-up & shutdown
        {"boot.degraded_app", "Microsoft-Windows-Diagnostics-Performance/Operational",
         "Microsoft-Windows-Diagnostics-Performance", {101}, 0, 30, &x_dp_degraded},
        {"boot.degraded_driver", "Microsoft-Windows-Diagnostics-Performance/Operational",
         "Microsoft-Windows-Diagnostics-Performance", {102}, 0, 30, &x_dp_degraded},
        {"boot.degraded_service", "Microsoft-Windows-Diagnostics-Performance/Operational",
         "Microsoft-Windows-Diagnostics-Performance", {103}, 0, 30, &x_dp_degraded},
        {"boot.degraded_device", "Microsoft-Windows-Diagnostics-Performance/Operational",
         "Microsoft-Windows-Diagnostics-Performance", {109}, 0, 30, &x_dp_degraded},
        {"os.shutdown", "Microsoft-Windows-Diagnostics-Performance/Operational",
         "Microsoft-Windows-Diagnostics-Performance", {200}, 0, 30, &x_shutdown_report},
        {"shutdown.degraded", "Microsoft-Windows-Diagnostics-Performance/Operational",
         "Microsoft-Windows-Diagnostics-Performance", {203}, 0, 30, &x_dp_degraded},
        {"os.standby", "Microsoft-Windows-Diagnostics-Performance/Operational",
         "Microsoft-Windows-Diagnostics-Performance", {300}, 0, 30, &x_standby_report},
        {"os.standby_degraded", "Microsoft-Windows-Diagnostics-Performance/Operational",
         "Microsoft-Windows-Diagnostics-Performance", {301, 302}, 0, 30, &x_dp_degraded},
        {"logon.slow_subscriber", "Application", "Microsoft-Windows-Winlogon", {6005, 6006}, 0, 12,
         &x_winlogon_slow},
        {"os.uptime_report", "System", "EventLog", {6013}, 0, 4, &x_uptime_report},
        // System stability
        // NOTE: 6008 usually co-fires with Kernel-Power 41 after the same dirty
        // reboot — composite stability scores must not sum the two types.
        {"os.dirty_shutdown", "System", "EventLog", {6008}, 0, 12, &x_dirty_shutdown},
        {"os.time_unsynced", "System", "Microsoft-Windows-Time-Service", {36, 47}, 0, 12,
         &x_time_unsynced},
        {"os.activation_failed", "Application", "Microsoft-Windows-Security-SPP", {8198}, 0, 12,
         &x_activation_failed},
        {"os.vss_error", "Application", "VSS", {8193}, 0, 12, &x_vss_error},
        {"fs.hive_recovered", "System", "Microsoft-Windows-Kernel-General", {5}, 0, 12,
         &x_hive_recovered},
        {"fs.autochk_ran", "Application", "Microsoft-Windows-Wininit", {1001}, 0, 12,
         &x_autochk_ran},
        // App reliability
        // NOTE: a managed crash usually PAIRS with a process.crashed 1000 — this
        // type adds the exception TYPE the native event lacks; app crash counts
        // use process.crashed alone.
        {"process.crashed_managed", "Application", ".NET Runtime", {1026}, 0, 120,
         &x_dotnet_crash},
        {"app.sxs_error", "Application", "SideBySide", {33, 35, 59}, 0, 30, &x_sxs_error},
        {"app.activation_failed", "Microsoft-Windows-TWinUI/Operational",
         "Microsoft-Windows-Immersive-Shell", {5973}, 0, 30, &x_app_activation_failed},
        // 10016 (activation permission noise) is deliberately EXCLUDED.
        {"app.com_failed", "System", "Microsoft-Windows-DistributedCOM", {10005, 10010}, 0, 12,
         &x_dcom_failed},
        {"app.error_popup", "System", "Application Popup", {26}, 0, 30, &x_error_popup},
        {"app.shutdown_blocked", "Application", "Microsoft-Windows-RestartManager", {10006}, 0, 12,
         &x_shutdown_blocked},
        // Service health
        {"service.hung", "System", "Service Control Manager", {7022}, 0, 30, &x_service_hung},
        {"service.start_timeout", "System", "Service Control Manager", {7009}, 0, 30,
         &x_service_start_timeout},
        {"service.logon_failed", "System", "Service Control Manager", {7038}, 0, 12,
         &x_service_logon_failed},
        {"service.recovery_failed", "System", "Service Control Manager", {7032}, 0, 12,
         &x_service_recovery_failed},
        // Hardware & storage
        {"disk.smart_failure", "System", "disk", {52}, 0, 12, &x_disk_smart},
        {"disk.port_reset", "System", "storahci", {129}, 0, 30, &x_port_reset},
        {"disk.port_reset", "System", "stornvme", {129}, 0, 30, &x_port_reset},
        {"fs.write_lost", "System", "Ntfs", {50}, 0, 12, &x_write_lost},
        {"fs.database_corrupt", "Application", "ESENT", {447, 454, 467}, 0, 12, &x_esent_corrupt},
        {"hw.device_start_failed", "Microsoft-Windows-Kernel-PnP/Configuration",
         "Microsoft-Windows-Kernel-PnP", {411}, 0, 12, &x_device_start_failed},
        {"hw.cpu_throttled", "System", "Microsoft-Windows-Kernel-Processor-Power", {37}, 0, 12,
         &x_cpu_throttled},
        // Network
        {"network.wifi_connect_failed", "Microsoft-Windows-WLAN-AutoConfig/Operational",
         "Microsoft-Windows-WLAN-AutoConfig", {8002}, 0, 60, &x_wifi_connect_failed},
        {"network.dhcp_failed", "Microsoft-Windows-Dhcp-Client/Admin",
         "Microsoft-Windows-Dhcp-Client", {1001, 1002}, 0, 12, &x_dhcp_failed},
        {"network.vpn_failed", "Application", "RasClient", {20227}, 0, 12, &x_vpn_failed},
        {"network.smb_failed", "Microsoft-Windows-SmbClient/Connectivity",
         "Microsoft-Windows-SmbClient", {30803}, 0, 30, &x_smb_failed},
        {"network.name_conflict", "System", "NetBT", {4319}, 0, 12, &x_name_conflict},
        // Identity & logon
        {"logon.no_dc", "System", "NETLOGON", {5719}, 0, 12, &x_no_dc},
        {"security.kerberos_error", "System", "Microsoft-Windows-Security-Kerberos", {4}, 0, 12,
         &x_kerberos_error},
        {"logon.profile_locked", "Application", "Microsoft-Windows-User Profiles Service", {1530},
         0, 12, &x_profile_locked},
        {"logon.folder_redirect_failed", "Application", "Microsoft-Windows-Folder Redirection",
         {502}, 0, 12, &x_folder_redirect_failed},
        // Security & protection
        {"security.rtp_disabled", "Microsoft-Windows-Windows Defender/Operational",
         "Microsoft-Windows-Windows Defender", {5001}, 0, 12, &x_rtp_disabled},
        {"security.threat_detected", "Microsoft-Windows-Windows Defender/Operational",
         "Microsoft-Windows-Windows Defender", {1116}, 0, 30, &x_threat_detected},
        {"security.av_update_failed", "Microsoft-Windows-Windows Defender/Operational",
         "Microsoft-Windows-Windows Defender", {2001}, 0, 12, &x_av_update_failed},
        {"security.tamper_blocked", "Microsoft-Windows-Windows Defender/Operational",
         "Microsoft-Windows-Windows Defender", {5013}, 0, 12, &x_tamper_blocked},
        // Updates & installs
        {"app_uninstall.failed", "Application", "MsiInstaller", {11725}, 0, 30,
         &x_msi_uninstall_failed},
        {"app_install.appx_failed", "Microsoft-Windows-AppXDeploymentServer/Operational",
         "Microsoft-Windows-AppXDeployment-Server", {404}, 0, 30, &x_appx_failed},
        {"update.transfer_failed", "Microsoft-Windows-Bits-Client/Operational",
         "Microsoft-Windows-Bits-Client", {61}, 0, 30, &x_bits_failed},
        // Printing
        {"print.driver_install_failed", "Microsoft-Windows-PrintService/Admin",
         "Microsoft-Windows-PrintService", {215}, 0, 12, &x_print_driver_failed},
        {"print.plugin_failed", "Microsoft-Windows-PrintService/Admin",
         "Microsoft-Windows-PrintService", {808}, 0, 12, &x_print_plugin_failed},

        // ── Wave 3 (2026-06-10): +33 signals ─────────────────────────────────
        // Boot, start-up & shutdown
        {"boot.fast_startup_failed", "System", "Microsoft-Windows-Kernel-Boot", {29}, 0, 12,
         &x_fast_startup_failed},
        {"os.resume_report", "System", "Microsoft-Windows-Power-Troubleshooter", {1}, 0, 30,
         &x_resume_report},
        {"os.restart_initiated", "System", "User32", {1074}, 0, 12, &x_restart_initiated},
        // System stability
        {"os.shadow_copies_lost", "System", "volsnap", {25}, 0, 12, &x_shadow_copies_lost},
        {"os.crashdump_disabled", "System", "volmgr", {46}, 0, 12, &x_crashdump_disabled},
        {"display.dwm_exited", "Application", "Desktop Window Manager", {9009}, 0, 12,
         &x_dwm_exited},
        // App reliability
        {"process.file_access_failure", "Application", "Application Error", {1005}, 0, 30,
         &x_file_access_failure},
        {"app.push_notification_error", "Microsoft-Windows-PushNotifications-Platform/Operational",
         "Microsoft-Windows-PushNotifications-Platform", {}, 2, 12, &x_push_notification_error},
        {"app.file_association_reset", "Microsoft-Windows-Shell-Core/AppDefaults",
         "Microsoft-Windows-Shell-Core", {62}, 0, 12, &x_file_association_reset},
        {"app.staterepo_error", "Microsoft-Windows-StateRepository/Operational",
         "Microsoft-Windows-StateRepository", {}, 2, 12, &x_staterepo_error},
        // Service health
        {"service.dependency_failed", "System", "Service Control Manager", {7001}, 0, 30,
         &x_dependency_failed},
        // File system
        {"fs.flush_failed", "System", "Ntfs", {57}, 0, 12, &x_flush_failed},
        // Hardware & storage
        {"hw.user_driver_error", "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
         "Microsoft-Windows-DriverFrameworks-UserMode", {10110, 10111}, 0, 12,
         &x_user_driver_error},
        {"hw.tpm_error", "System", "Microsoft-Windows-TPM-WMI", {}, 2, 12, &x_tpm_error},
        // Network
        {"network.port_exhaustion", "System", "Tcpip", {4227, 4231}, 0, 12, &x_port_exhaustion},
        {"network.smb_write_lost", "System", "mrxsmb", {50}, 0, 12, &x_smb_write_lost},
        {"network.dns_register_failed", "System", "Microsoft-Windows-DNS-Client", {8015, 8016}, 0,
         12, &x_dns_register_failed},
        {"session.rdp_disconnected",
         "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
         "Microsoft-Windows-TerminalServices-LocalSessionManager", {24, 39, 40}, 0, 30,
         &x_rdp_disconnected},
        // Identity & logon
        {"logon.winlogon_terminated", "Application", "Microsoft-Windows-Winlogon", {4005}, 0, 12,
         &x_winlogon_terminated},
        {"logon.machine_trust_failed", "System", "NETLOGON", {3210}, 0, 12,
         &x_machine_trust_failed},
        {"logon.biometric_error", "Microsoft-Windows-Biometrics/Operational",
         "Microsoft-Windows-Biometrics", {}, 2, 12, &x_biometric_error},
        {"logon.hello_error", "Microsoft-Windows-HelloForBusiness/Operational",
         "Microsoft-Windows-HelloForBusiness", {}, 2, 12, &x_hello_error},
        {"logon.aad_token_error", "Microsoft-Windows-AAD/Operational", "Microsoft-Windows-AAD",
         {1097, 1098}, 0, 12, &x_aad_token_error},
        {"security.auth_error", "System", "LsaSrv", {40960, 40961}, 0, 12, &x_auth_error},
        // Security & protection
        {"security.tls_alert", "System", "Schannel", {36874, 36887}, 0, 12, &x_tls_alert},
        {"security.threat_action_failed", "Microsoft-Windows-Windows Defender/Operational",
         "Microsoft-Windows-Windows Defender", {1119}, 0, 12, &x_threat_action_failed},
        {"security.rtp_error", "Microsoft-Windows-Windows Defender/Operational",
         "Microsoft-Windows-Windows Defender", {3002}, 0, 12, &x_rtp_error},
        {"security.bitlocker_error", "Microsoft-Windows-BitLocker/BitLocker Management",
         "Microsoft-Windows-BitLocker-API", {}, 2, 12, &x_bitlocker_error},
        {"security.cert_enroll_failed", "Application",
         "Microsoft-Windows-CertificateServicesClient-AutoEnrollment", {6, 13}, 0, 12,
         &x_cert_enroll_failed},
        // Updates & installs
        {"update.check_failed", "System", "Microsoft-Windows-WindowsUpdateClient", {16, 25}, 0,
         12, &x_update_check_failed},
        {"update.download_failed", "System", "Microsoft-Windows-WindowsUpdateClient", {31}, 0, 12,
         &x_update_download_failed},
        // Policy & management
        {"gpo.cse_failed", "System", "Microsoft-Windows-GroupPolicy", {1085}, 0, 12,
         &x_gpo_cse_failed},
        {"mgmt.mdm_error",
         "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
         "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider", {}, 2, 12,
         &x_mdm_error},
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
