/**
 * tar_schema_registry.cpp -- Capture source definitions, DDL generation,
 *                            $-name translation, and rollup/retention SQL.
 */

#include "tar_schema_registry.hpp"

#include <algorithm>
#include <format>
#include <sstream>
#include <unordered_set>

namespace yuzu::tar {

namespace {

// ── Source definitions ──────────────────────────────────────────────────────

// Common columns present in all live tables (id, ts, snapshot_id are implicit
// in DDL generation; we list the data columns here).
// "action" is the event type (started/stopped, connected/disconnected, etc.)

const std::vector<CaptureSourceDef>& build_sources() {
    static const std::vector<CaptureSourceDef> sources = {
        // ── Process ─────────────────────────────────────────────────────
        {
            .name = "process",
            .dollar_name = "Process",
            .os_support = {
                {"windows", OsSupportStatus::kSupported,           "etw",
                 "ETW Microsoft-Windows-Kernel-Process (gap-free start/stop, "
                 "names-only, owning user resolved from the SID at start) is the "
                 "primary feeder; CreateToolhelp32Snapshot poll is the fallback "
                 "if the ETW session cannot start. No command line is captured."},
                {"linux",   OsSupportStatus::kSupported,           "procfs",
                 "Reads /proc/<pid>/status and /proc/<pid>/cmdline."},
                {"macos",   OsSupportStatus::kSupportedConstrained, "endpoint_security",
                 "Endpoint Security NOTIFY_EXEC/EXIT stream (gap-free, full image "
                 "path, accurate ppid, owning user from the audit token) where the "
                 "framework + entitlement are present (full Xcode SDK build, "
                 "com.apple.developer.endpoint-security.client, root). Falls back to "
                 "the KERN_PROC_ALL sysctl poll otherwise. Names-only on BOTH paths "
                 "— no command line (works-council posture); the poll blanks the "
                 "proc_pidpath image it would otherwise place in cmdline."},
            },
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    // Raised 5k→100k for the gap-free ETW stream on Windows (the
                    // poll produced far fewer rows). ~100k × ~150 B ≈ ~15 MB
                    // bounded; the hourly/daily/monthly count rollups carry the
                    // long tail. Non-Windows poll simply never fills it.
                    .retention_default = 100000,
                    .columns = {
                        {"ts",          "INTEGER"},
                        {"snapshot_id", "INTEGER"},
                        {"action",      "TEXT"},
                        {"pid",         "INTEGER"},
                        {"ppid",        "INTEGER"},
                        {"name",        "TEXT"},
                        {"cmdline",     "TEXT"},
                        {"user",        "TEXT"},
                    },
                },
                {
                    .suffix = "hourly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 86400, // 24 hours
                    .columns = {
                        {"hour_ts",     "INTEGER"},
                        {"name",        "TEXT"},
                        {"user",        "TEXT"},
                        {"start_count", "INTEGER"},
                        {"stop_count",  "INTEGER"},
                    },
                },
                {
                    .suffix = "daily",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 2678400, // 31 days
                    .columns = {
                        {"day_ts",      "INTEGER"},
                        {"name",        "TEXT"},
                        {"user",        "TEXT"},
                        {"start_count", "INTEGER"},
                        {"stop_count",  "INTEGER"},
                    },
                },
                {
                    .suffix = "monthly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 31536000, // 12 months (~365 days)
                    .columns = {
                        {"month_ts",    "INTEGER"},
                        {"name",        "TEXT"},
                        {"user",        "TEXT"},
                        {"start_count", "INTEGER"},
                        {"stop_count",  "INTEGER"},
                    },
                },
            },
        },

        // ── TCP ─────────────────────────────────────────────────────────
        {
            .name = "tcp",
            .dollar_name = "TCP",
            .os_support = {
                {"windows", OsSupportStatus::kSupported,           "iphlpapi",
                 "GetExtendedTcpTable / GetExtendedUdpTable — polled at the "
                 "fast collector interval. ETW Microsoft-Windows-Kernel-Network "
                 "is planned (capture_method='etw') for sub-second connect/close "
                 "fidelity; not yet wired."},
                {"linux",   OsSupportStatus::kSupported,           "procfs",
                 "Reads /proc/net/{tcp,tcp6,udp,udp6}. Connection lifetime "
                 "below the fast interval may be missed."},
                {"macos",   OsSupportStatus::kSupportedConstrained, "proc_pidfdinfo",
                 "proc_listallpids + proc_pidfdinfo(PROC_PIDFDSOCKETINFO) via "
                 "libproc. Inherent TOCTOU between pid enumeration and per-fd "
                 "query — short-lived sockets that close before the per-fd "
                 "query may produce empty rows. Endpoint Security framework "
                 "(kPlanned) is the modern replacement for sub-second fidelity."},
            },
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    .retention_default = 5000,
                    .columns = {
                        {"ts",           "INTEGER"},
                        {"snapshot_id",  "INTEGER"},
                        {"action",       "TEXT"},
                        {"proto",        "TEXT"},
                        {"local_addr",   "TEXT"},
                        {"local_port",   "INTEGER"},
                        {"remote_addr",  "TEXT"},
                        {"remote_host",  "TEXT"},
                        {"remote_port",  "INTEGER"},
                        {"state",        "TEXT"},
                        {"pid",          "INTEGER"},
                        {"process_name", "TEXT"},
                    },
                },
                {
                    .suffix = "hourly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 86400,
                    .columns = {
                        {"hour_ts",          "INTEGER"},
                        {"remote_addr",      "TEXT"},
                        {"remote_port",      "INTEGER"},
                        {"proto",            "TEXT"},
                        {"process_name",     "TEXT"},
                        {"connect_count",    "INTEGER"},
                        {"disconnect_count", "INTEGER"},
                    },
                },
                {
                    .suffix = "daily",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 2678400,
                    .columns = {
                        {"day_ts",           "INTEGER"},
                        {"remote_addr",      "TEXT"},
                        {"remote_port",      "INTEGER"},
                        {"proto",            "TEXT"},
                        {"process_name",     "TEXT"},
                        {"connect_count",    "INTEGER"},
                        {"disconnect_count", "INTEGER"},
                    },
                },
                {
                    .suffix = "monthly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 31536000,
                    .columns = {
                        {"month_ts",         "INTEGER"},
                        {"remote_addr",      "TEXT"},
                        {"remote_port",      "INTEGER"},
                        {"proto",            "TEXT"},
                        {"process_name",     "TEXT"},
                        {"connect_count",    "INTEGER"},
                        {"disconnect_count", "INTEGER"},
                    },
                },
            },
        },

        // ── Service ─────────────────────────────────────────────────────
        {
            .name = "service",
            .dollar_name = "Service",
            .os_support = {
                {"windows", OsSupportStatus::kSupported,           "scm",
                 "EnumServicesStatusEx / QueryServiceConfig. Captures "
                 "display_name, status, startup_type."},
                {"linux",   OsSupportStatus::kSupportedConstrained, "systemctl",
                 "systemctl list-units. startup_type is reported as 'unknown' "
                 "(would require a second systemctl call per unit). Hosts "
                 "without systemd (Alpine sysvinit, OpenRC) are unsupported."},
                {"macos",   OsSupportStatus::kSupportedConstrained, "launchctl",
                 "launchctl list — no startup_type, status is binary "
                 "running/stopped only."},
            },
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    .retention_default = 5000,
                    .columns = {
                        {"ts",                "INTEGER"},
                        {"snapshot_id",       "INTEGER"},
                        {"action",            "TEXT"},
                        {"name",              "TEXT"},
                        {"display_name",      "TEXT"},
                        {"status",            "TEXT"},
                        {"prev_status",       "TEXT"},
                        {"startup_type",      "TEXT"},
                        {"prev_startup_type", "TEXT"},
                    },
                },
                {
                    .suffix = "hourly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 86400,
                    .columns = {
                        {"hour_ts",        "INTEGER"},
                        {"name",           "TEXT"},
                        {"status_changes", "INTEGER"},
                        {"last_status",    "TEXT"},
                    },
                },
            },
        },

        // ── User ────────────────────────────────────────────────────────
        {
            .name = "user",
            .dollar_name = "User",
            .os_support = {
                {"windows", OsSupportStatus::kSupported,           "wts",
                 "WTSEnumerateSessionsW + WTSQuerySessionInformationW — "
                 "captures interactive, RDP, console. Requires Terminal "
                 "Services (always present on supported Windows; absent on "
                 "Server Core 2008 R2 minimal installs). WTSEnumerateSessionsExW "
                 "is the recommended successor for new code but is not yet wired."},
                {"linux",   OsSupportStatus::kSupportedConstrained, "utmp",
                 "Reads /var/run/utmp via getutent. Containers running with "
                 "no /var/run/utmp produce no events. logon_type is inferred "
                 "from tty name (pts/* -> remote)."},
                {"macos",   OsSupportStatus::kSupportedConstrained, "utmpx",
                 "getutxent. logon_type inferred from tty (ttys* -> remote). "
                 "GUI logins are not always reflected in utmpx."},
            },
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    .retention_default = 5000,
                    .columns = {
                        {"ts",          "INTEGER"},
                        {"snapshot_id", "INTEGER"},
                        {"action",      "TEXT"},
                        {"user",        "TEXT"},
                        {"domain",      "TEXT"},
                        {"logon_type",  "TEXT"},
                        {"session_id",  "TEXT"},
                    },
                },
                {
                    .suffix = "daily",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 2678400,
                    .columns = {
                        {"day_ts",      "INTEGER"},
                        {"user",        "TEXT"},
                        {"domain",      "TEXT"},
                        {"login_count", "INTEGER"},
                        {"logout_count","INTEGER"},
                    },
                },
            },
        },

        // ── Perf (BRD A1 — continuous device performance sampling) ──────
        // One derived row per sample interval (default 30 s): CPU %, memory
        // used/commit %, summed disk throughput + per-IO latency, summed
        // non-loopback network throughput. Raw samples stay on-device
        // (ADR-0004); the hourly tier carries avg/max for trend queries.
        {
            .name = "perf",
            .dollar_name = "Perf",
            .os_support = {
                {"windows", OsSupportStatus::kSupported,  "ntcounters",
                 "Raw kernel counters — GetSystemTimes, GlobalMemoryStatusEx + "
                 "GetPerformanceInfo, IOCTL_DISK_PERFORMANCE, GetIfTable2. "
                 "No PDH, no WMI, no shell-out. Some virtual disks do not "
                 "answer IOCTL_DISK_PERFORMANCE — disk columns read 0 there."},
                {"linux",   OsSupportStatus::kPlanned,    "procfs",
                 "/proc/stat, /proc/meminfo, /proc/diskstats, /proc/net/dev."},
                {"macos",   OsSupportStatus::kPlanned,    "host_statistics",
                 "host_processor_info / host_statistics64 + IOKit counters."},
            },
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 604800, // 7 days of 30 s samples ≈ 20k rows
                    .columns = {
                        {"ts",                "INTEGER"},
                        {"snapshot_id",       "INTEGER"},
                        {"cpu_pct",           "REAL"},
                        {"mem_used_pct",      "REAL"},
                        {"commit_pct",        "REAL"},
                        {"disk_read_bps",     "INTEGER"},
                        {"disk_write_bps",    "INTEGER"},
                        {"disk_read_lat_us",  "INTEGER"},
                        {"disk_write_lat_us", "INTEGER"},
                        {"net_rx_bps",        "INTEGER"},
                        {"net_tx_bps",        "INTEGER"},
                    },
                },
                {
                    .suffix = "hourly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 2678400, // 31 days
                    .columns = {
                        {"hour_ts",            "INTEGER"},
                        {"samples",            "INTEGER"},
                        {"cpu_avg",            "REAL"},
                        {"cpu_max",            "REAL"},
                        {"mem_avg",            "REAL"},
                        {"mem_max",            "REAL"},
                        {"commit_avg",         "REAL"},
                        {"read_bps_avg",       "INTEGER"},
                        {"write_bps_avg",      "INTEGER"},
                        {"read_lat_us_avg",    "INTEGER"},
                        {"write_lat_us_avg",   "INTEGER"},
                        {"read_lat_us_max",    "INTEGER"},
                        {"write_lat_us_max",   "INTEGER"},
                        {"rx_bps_avg",         "INTEGER"},
                        {"tx_bps_avg",         "INTEGER"},
                    },
                },
            },
        },

        // ── BRD A2: top-N per-application resource samples ───────────────
        // Rides the same collect_perf tick as the device sampler; aggregated
        // by IMAGE NAME (app-level — per-PID detail lives on process_live),
        // top-10 by CPU ∪ top-10 by working set per tick (<= 20 rows/30 s).
        // NAMES ONLY — no command lines (privacy default); operator redaction
        // patterns apply to the name; own `procperf_enabled` toggle so per-app
        // visibility can be disabled while device-level sampling stays on
        // (works-council posture).
        {
            .name = "procperf",
            .dollar_name = "ProcPerf",
            // Opt-in (works-council posture): a fresh agent reports it disabled
            // on tar.status, matching the explicit "false" collection gate.
            .default_enabled = false,
            .os_support = {
                {"windows", OsSupportStatus::kSupported,  "ntsysinfo",
                 "One NtQuerySystemInformation(SystemProcessInformation) "
                 "snapshot per tick — image name, CPU times, working set for "
                 "every process; no PDH, no WMI, no per-process handles."},
                {"linux",   OsSupportStatus::kPlanned,    "procfs",
                 "/proc/[pid]/stat utime+stime + VmRSS."},
                {"macos",   OsSupportStatus::kPlanned,    "libproc",
                 "proc_pid_rusage / proc_taskinfo per sysctl PID list."},
            },
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 604800, // 7 days × ≤20 rows/30 s ≈ 400k small rows
                    .columns = {
                        {"ts",          "INTEGER"},
                        {"snapshot_id", "INTEGER"},
                        {"name",        "TEXT"},
                        {"instances",   "INTEGER"},
                        {"cpu_pct",     "REAL"},
                        {"ws_bytes",    "INTEGER"},
                    },
                },
                {
                    .suffix = "hourly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 2678400, // 31 days, per (hour, app)
                    .columns = {
                        {"hour_ts",       "INTEGER"},
                        {"name",          "TEXT"},
                        {"samples",       "INTEGER"},
                        {"instances_max", "INTEGER"},
                        {"cpu_avg",       "REAL"},
                        {"cpu_max",       "REAL"},
                        {"ws_avg_bytes",  "INTEGER"},
                        {"ws_max_bytes",  "INTEGER"},
                    },
                },
            },
        },

        // ── netqual (BRD Workstream E — per-connection TCP quality) ──────
        // One row per (tick, ESTABLISHED connection): smoothed RTT + jitter
        // + a CURRENT-loss gauge (tcpi_lost) + lifetime retrans/segs context,
        // joined to the owning process. Co-sampled with the `tcp` source so it
        // shares the snapshot_id (joins to process/perf on ts). Only a coarse
        // destination CLASS (`remote_bucket`) is stored — never the raw remote
        // address — and collection carries its own opt-in toggle + per-tick
        // top-N cap (collector slice). Row-count retention bounds storage
        // deterministically regardless of connection churn.
        {
            .name = "netqual",
            .dollar_name = "NetQual",
            // Opt-in (usage-class per-connection telemetry): disabled on a fresh
            // agent, matching the explicit "false" collection gate.
            .default_enabled = false,
            .os_support = {
                {"linux",   OsSupportStatus::kSupported, "inetdiag",
                 "netlink SOCK_DIAG / INET_DIAG TCP_INFO dump (the interface "
                 "`ss -ti` uses — no packet capture, no CAP_NET_ADMIN: a "
                 "non-root agent reads system TCP_INFO), joined to the "
                 "connection's owning process by 4-tuple."},
                {"windows", OsSupportStatus::kPlanned,   "estats",
                 "ESTATS (GetPerTcpConnectionEStats) for smoothed RTT, or the "
                 "Microsoft-Windows-TCPIP ETW provider for retransmit/loss — "
                 "the mechanism is a spike (see /network design)."},
                {"macos",   OsSupportStatus::kPlanned,   "nstat",
                 "per-socket tcp_connection_info via the private nstat / "
                 "PRIVATE_TCP_INFO path."},
            },
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    // Per-connection rows are far more numerous than the device
                    // perf tier; the collector's per-tick top-N cap is the real
                    // bound, this row cap is the deterministic storage backstop.
                    .retention_default = 100000,
                    .columns = {
                        {"ts",            "INTEGER"},
                        {"snapshot_id",   "INTEGER"},
                        {"proto",         "TEXT"},
                        {"remote_bucket", "TEXT"},
                        {"process_name",  "TEXT"},
                        {"rtt_us",        "INTEGER"},
                        {"rtt_var_us",    "INTEGER"},
                        {"lost",          "INTEGER"},
                        {"retrans",       "INTEGER"},
                        {"segs_out",      "INTEGER"},
                        {"ca_state",      "INTEGER"},
                    },
                },
            },
        },

        // ── Module / image loads (M1 — docs/tar-module-loads.md) ──────────
        // What loads INTO a process: DLL / dylib / .so + driver / kext / kmod
        // loads, each with a signing verdict — the DLL-search-order-hijack,
        // injection, and BYOVD surface $Process cannot answer. `module_dir` IS
        // captured (the hijack signal is the path, not a command line — a narrow,
        // deliberate divergence from the names-only process posture; no cmdline).
        // M1 registers the schema queryable-empty; collectors are kPlanned until
        // M2 (Windows ETW), M4/M5 (macOS ES), M6 (Linux auditd kmod). The high-
        // volume edge risk-filter that really bounds module_live ships with the
        // first collector; opt-in (module_enabled, default off) like procperf.
        {
            .name = "module",
            .dollar_name = "Module",
            // Opt-in (~100× process volume; ships disabled until an operator
            // turns it on). default_enabled=false is what discharges the M1 §13
            // condition that module_enabled must NOT read as true before a
            // collector exists — it makes tar.status, retention, and the
            // paused_at transition all agree the source starts disabled.
            .default_enabled = false,
            .os_support = {
                {"windows", OsSupportStatus::kSupported, "etw",
                 "Microsoft-Windows-Kernel-Process image-load events (IMAGE "
                 "keyword 0x40, events 5/6) on a dedicated ETW session; driver "
                 "loads surface as kernel image-loads (System pid). Signing is "
                 "verified out-of-band at drain (WinVerifyTrust + CryptQueryObject "
                 "signer, cached); module_dir is scrubbed of user-profile prefixes "
                 "before storage. CodeIntegrity/Operational (3033/3034) blocked-load "
                 "overlay is M3."},
                {"linux", OsSupportStatus::kPlanned, "auditd",
                 "Kernel-module loads via auditd init_module/finit_module (kmod "
                 "only in v1; /proc/modules seed). Shared-object (.so) loads need "
                 "eBPF and are deferred to a separate track. Wired in M6."},
                {"macos", OsSupportStatus::kPlanned, "endpoint_security",
                 "ES NOTIFY_KEXTLOAD/KEXTUNLOAD (first-class) plus user-space "
                 "dylibs via NOTIFY_MMAP (constrained) on the SAME ES client the "
                 "process source uses; code-signing identity (team id / cdhash) "
                 "rides the message, so signing needs no extra call. Wired in "
                 "M4/M5."},
            },
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    // The edge risk-filter (unsigned/kernel/blocked at full
                    // fidelity; signed system modules first-seen-then-count) is
                    // the real bound; this row cap is the deterministic backstop.
                    .retention_default = 100000,
                    .columns = {
                        {"ts",            "INTEGER"},
                        {"snapshot_id",   "INTEGER"},
                        {"action",        "TEXT"},
                        {"pid",           "INTEGER"},
                        {"process_name",  "TEXT"},
                        {"module_name",   "TEXT"},
                        {"module_dir",    "TEXT"},
                        {"signed_state",  "TEXT"},
                        {"signer",        "TEXT"},
                        {"is_kernel",     "INTEGER"},
                    },
                },
                {
                    .suffix = "hourly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 86400, // 24 hours
                    .columns = {
                        {"hour_ts",      "INTEGER"},
                        {"module_name",  "TEXT"},
                        {"signer",       "TEXT"},
                        {"signed_state", "TEXT"},
                        {"is_kernel",    "INTEGER"},
                        {"load_count",   "INTEGER"},
                    },
                },
                {
                    .suffix = "daily",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 2678400, // 31 days
                    .columns = {
                        {"day_ts",       "INTEGER"},
                        {"module_name",  "TEXT"},
                        {"signer",       "TEXT"},
                        {"signed_state", "TEXT"},
                        {"is_kernel",    "INTEGER"},
                        {"load_count",   "INTEGER"},
                    },
                },
                {
                    .suffix = "monthly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 31536000, // 12 months (~365 days)
                    .columns = {
                        {"month_ts",     "INTEGER"},
                        {"module_name",  "TEXT"},
                        {"signer",       "TEXT"},
                        {"signed_state", "TEXT"},
                        {"is_kernel",    "INTEGER"},
                        {"load_count",   "INTEGER"},
                    },
                },
            },
        },

        // ── Software install/uninstall events (Phase 8 Wave 1) ────────────────
        // Diffs the installed-software inventory on the `tar.software` tick
        // (hourly default) and records install/remove/upgrade events over time —
        // the historical "what was installed/removed on this box, when" the
        // point-in-time installed_apps inventory cannot answer. Default-ON
        // (asset-management + vuln-relevance, like `service`/`user`), not the
        // opt-in posture used for the app-usage-class sources.
        //
        // Windows captures BOTH machine-wide (HKLM Uninstall 64-bit + WOW6432Node)
        // AND per-user (HKU\<SID> for loaded hives, mounting NTUSER.DAT for
        // logged-off profiles) — the `scope` column distinguishes them and `user`
        // carries the profile name for per-user rows. Linux (dpkg/rpm) and macOS
        // (pkgutil) are kPlanned (queryable-empty) until a fast-follow wires the
        // installed_apps enumeration into a collector.
        {
            .name = "software",
            .dollar_name = "Software",
            .os_support = {
                {"windows", OsSupportStatus::kSupported, "registry",
                 "Registry Uninstall keys, polled-and-diffed on the tar.software "
                 "tick: HKLM 64-bit + WOW6432Node 32-bit (machine scope) plus each "
                 "user profile's HKU\\<SID>\\...\\Uninstall (per-user scope; "
                 "NTUSER.DAT is mounted for logged-off profiles so the per-user "
                 "inventory is complete regardless of logon state). SystemComponent "
                 "entries are skipped. No command line / no usage data — names, "
                 "versions, publisher only."},
                {"linux",   OsSupportStatus::kPlanned, "dpkg_rpm",
                 "dpkg-query / rpm -qa / pacman -Q diff (reuse of the installed_apps "
                 "enumeration). Wired in a fast-follow."},
                {"macos",   OsSupportStatus::kPlanned, "pkgutil",
                 "system_profiler SPApplicationsDataType + pkgutil diff (reuse of "
                 "the installed_apps enumeration). Wired in a fast-follow."},
            },
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    // Install/uninstall is very low-volume — 5000 rows holds years
                    // of change history on a normal endpoint.
                    .retention_default = 5000,
                    .columns = {
                        {"ts",           "INTEGER"},
                        {"snapshot_id",  "INTEGER"},
                        {"action",       "TEXT"}, // installed, removed, upgraded
                        {"name",         "TEXT"},
                        {"version",      "TEXT"},
                        {"prev_version", "TEXT"}, // populated only for 'upgraded'
                        {"publisher",    "TEXT"},
                        {"scope",        "TEXT"}, // machine, user
                        {"user",         "TEXT"}, // profile name for per-user rows; '' for machine
                        {"install_date", "TEXT"}, // registry InstallDate (YYYYMMDD) where present
                    },
                },
                {
                    .suffix = "daily",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 2678400, // 31 days
                    .columns = {
                        {"day_ts",        "INTEGER"},
                        {"name",          "TEXT"},
                        {"scope",         "TEXT"},
                        {"install_count", "INTEGER"},
                        {"remove_count",  "INTEGER"},
                        {"upgrade_count", "INTEGER"},
                    },
                },
                {
                    .suffix = "monthly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 31536000, // 12 months (~365 days)
                    .columns = {
                        {"month_ts",      "INTEGER"},
                        {"name",          "TEXT"},
                        {"scope",         "TEXT"},
                        {"install_count", "INTEGER"},
                        {"remove_count",  "INTEGER"},
                        {"upgrade_count", "INTEGER"},
                    },
                },
            },
        },

        // ── ARP / address-resolution table (ADR-0015) ─────────────────────
        // Host L2 adjacency: IP<->MAC bindings per interface. Snapshot-diff
        // appeared/removed keyed on the (interface, ip_address, mac_address)
        // binding — a changing entry_type on the same binding is a value update,
        // not churn. Opt-in (default_enabled=false): low-PII infrastructure data
        // but shipped disabled per the standing capture-source posture. Windows
        // only in this slice; Linux/macOS are kPlanned (see docs/tar-implementer.md
        // "Adding a capture source").
        {
            .name = "arp",
            .dollar_name = "ARP",
            .default_enabled = false,
            .os_support = {
                {"windows", OsSupportStatus::kSupported,           "iphlpapi",
                 "GetIpNetTable2(AF_UNSPEC) — the kernel ARP / IPv6 neighbour "
                 "cache. Full interface/ip/mac/entry_type. Polled at the fast "
                 "collector interval."},
                {"linux",   OsSupportStatus::kPlanned,             "procfs",
                 "/proc/net/arp — kernel ARP table (IPv4). Wired in the Linux "
                 "follow-up."},
                {"macos",   OsSupportStatus::kPlanned,             "route_sysctl",
                 "sysctl NET_RT_FLAGS / RTF_LLINFO routing-socket dump. MAC is "
                 "available; entry_type reported 'unknown' (constrained). Wired "
                 "in the macOS follow-up."},
            },
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    .retention_default = 5000,
                    .columns = {
                        {"ts",          "INTEGER"},
                        {"snapshot_id", "INTEGER"},
                        {"action",      "TEXT"},
                        {"interface",   "TEXT"},
                        {"ip_address",  "TEXT"},
                        {"mac_address", "TEXT"},
                        {"entry_type",  "TEXT"},
                    },
                },
                {
                    .suffix = "hourly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 86400, // 24 hours
                    .columns = {
                        {"hour_ts",      "INTEGER"},
                        {"interface",    "TEXT"},
                        {"ip_address",   "TEXT"},
                        {"mac_address",  "TEXT"},
                        {"appear_count", "INTEGER"},
                        {"remove_count", "INTEGER"},
                    },
                },
            },
        },

        // ── DNS resolution cache (ADR-0015) ───────────────────────────────
        // Host DNS resolver-cache STATE (not per-process queries — the cache is
        // system-wide and carries no pid; per-process attribution via the
        // Microsoft-Windows-DNS-Client ETW provider is a deferred follow-up, so
        // never join dns_live to a process by pid). Snapshot-diff appeared/removed
        // keyed on the (name, record_type, data) resolution; ttl_remaining_s is a
        // value field and is NOT part of the diff key (it decrements every tick
        // and must not churn). Opt-in (usage-class PII — reveals visited domains).
        // Windows only here; Linux/macOS kPlanned.
        {
            .name = "dns",
            .dollar_name = "DNS",
            .default_enabled = false,
            .os_support = {
                {"windows", OsSupportStatus::kSupported,           "dnsapi",
                 "DnsGetCacheDataTable — the DNS client resolver cache. Full "
                 "name/record_type/data/TTL. Polled at the fast collector "
                 "interval."},
                {"linux",   OsSupportStatus::kPlanned,             "systemd-resolved",
                 "systemd-resolved cache via the resolve1 D-Bus interface where "
                 "present; falls back to /etc/hosts (source='hosts_file'). Hosts "
                 "without systemd-resolved yield hosts-file entries only "
                 "(constrained). Wired in the Linux follow-up."},
                {"macos",   OsSupportStatus::kPlanned,             "dscacheutil",
                 "dscacheutil -cachedump subprocess. TTL is unavailable "
                 "(ttl_remaining_s reported -1, constrained). Wired in the macOS "
                 "follow-up."},
            },
            .granularities = {
                {
                    .suffix = "live",
                    .retention_type = RetentionType::kRowCount,
                    .retention_default = 5000,
                    .columns = {
                        {"ts",              "INTEGER"},
                        {"snapshot_id",     "INTEGER"},
                        {"action",          "TEXT"},
                        {"name",            "TEXT"},
                        {"record_type",     "TEXT"},
                        {"data",            "TEXT"},
                        {"ttl_remaining_s", "INTEGER"},
                        {"source",          "TEXT"},
                    },
                },
                {
                    .suffix = "hourly",
                    .retention_type = RetentionType::kTimeBased,
                    .retention_default = 86400, // 24 hours
                    .columns = {
                        {"hour_ts",      "INTEGER"},
                        {"name",         "TEXT"},
                        {"record_type",  "TEXT"},
                        {"appear_count", "INTEGER"},
                        {"remove_count", "INTEGER"},
                    },
                },
            },
        },
    };
    return sources;
}

// Build the $-name -> real table name map once.
const std::unordered_map<std::string, std::string>& dollar_name_map() {
    static const auto map = [] {
        std::unordered_map<std::string, std::string> m;
        for (const auto& src : build_sources()) {
            for (const auto& g : src.granularities) {
                // $Process_Live -> process_live
                std::string dollar = std::format("${}_{}",
                    src.dollar_name,
                    std::string(1, static_cast<char>(std::toupper(static_cast<unsigned char>(g.suffix[0])))) +
                    std::string(g.suffix.substr(1)));
                std::string real = std::format("{}_{}", src.name, g.suffix);
                m[dollar] = real;
            }
        }
        return m;
    }();
    return map;
}

// Reverse map: real table name -> (source index, granularity index)
struct TableRef {
    size_t source_idx;
    size_t gran_idx;
};

const std::unordered_map<std::string, TableRef>& table_ref_map() {
    static const auto map = [] {
        std::unordered_map<std::string, TableRef> m;
        const auto& srcs = build_sources();
        for (size_t si = 0; si < srcs.size(); ++si) {
            for (size_t gi = 0; gi < srcs[si].granularities.size(); ++gi) {
                std::string real = std::format("{}_{}", srcs[si].name, srcs[si].granularities[gi].suffix);
                m[real] = {si, gi};
            }
        }
        return m;
    }();
    return map;
}

// Get the timestamp column name for a granularity suffix
std::string_view ts_column_for_suffix(std::string_view suffix) {
    if (suffix == "live")    return "ts";
    if (suffix == "hourly")  return "hour_ts";
    if (suffix == "daily")   return "day_ts";
    if (suffix == "monthly") return "month_ts";
    return "ts";
}

} // namespace

// ── Public API ──────────────────────────────────────────────────────────────

const std::vector<CaptureSourceDef>& capture_sources() {
    return build_sources();
}

bool source_default_enabled(std::string_view source_name) {
    for (const auto& src : build_sources()) {
        if (src.name == source_name)
            return src.default_enabled;
    }
    return true; // unknown source → the always-on default
}

std::vector<std::string> accepted_capture_methods(std::string_view source_name) {
    std::vector<std::string> methods;
    for (const auto& src : build_sources()) {
        if (src.name != source_name)
            continue;
        for (const auto& os : src.os_support) {
            if (os.status == OsSupportStatus::kUnsupported)
                continue;
            std::string m{os.capture_method};
            if (std::find(methods.begin(), methods.end(), m) == methods.end()) {
                methods.push_back(std::move(m));
            }
        }
    }
    std::sort(methods.begin(), methods.end());
    return methods;
}

std::string_view current_platform_os() {
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#elif defined(__linux__)
    return "linux";
#else
    return "";
#endif
}

std::vector<std::string> accepted_capture_methods_for_os(std::string_view source_name,
                                                         std::string_view os) {
    std::vector<std::string> methods;
    for (const auto& src : build_sources()) {
        if (src.name != source_name)
            continue;
        for (const auto& sup : src.os_support) {
            if (sup.os != os)
                continue;
            if (sup.status == OsSupportStatus::kUnsupported)
                continue;
            std::string m{sup.capture_method};
            if (std::find(methods.begin(), methods.end(), m) == methods.end())
                methods.push_back(std::move(m));
        }
    }
    std::sort(methods.begin(), methods.end());
    return methods;
}

std::string effective_network_capture_method([[maybe_unused]] std::string_view configured) {
    // Polling is the only wired network capture mechanism on every OS today.
    // `enumerate_connections()` (the collect_fast network leg) always polls,
    // regardless of the stored `network_capture_method`: the per-OS platform
    // APIs (procfs / iphlpapi / proc_pidfdinfo) ARE the polling implementation,
    // and the kPlanned kernel-event methods (etw / endpoint_security) are
    // accepted for pre-staging but not yet collected. So every configured value
    // maps to an effective mechanism of "polling". When a kernel-event collector
    // lands, branch on `configured` (and the live session state, as the process
    // collector does with `etw_active_`) here -- this is the single source of
    // truth the `status` action reports (issue #1528).
    return "polling";
}

std::string generate_warehouse_ddl() {
    std::ostringstream ddl;
    for (const auto& src : build_sources()) {
        for (const auto& g : src.granularities) {
            std::string table_name = std::format("{}_{}", src.name, g.suffix);

            ddl << "CREATE TABLE IF NOT EXISTS " << table_name << " (\n";
            ddl << "    id INTEGER PRIMARY KEY AUTOINCREMENT";

            for (const auto& col : g.columns) {
                ddl << ",\n    " << col.name << " " << col.sql_type;
                // Numeric columns default to 0, text to '' — all NOT NULL.
                if (col.sql_type == "INTEGER" || col.sql_type == "REAL") {
                    ddl << " NOT NULL DEFAULT 0";
                } else {
                    ddl << " NOT NULL DEFAULT ''";
                }
            }
            ddl << "\n);\n";

            // Index on the timestamp column
            auto ts_col = ts_column_for_suffix(g.suffix);
            ddl << std::format("CREATE INDEX IF NOT EXISTS idx_{0}_{1} ON {0}({1});\n",
                               table_name, ts_col);

            // Extra indexes for live tables
            if (g.suffix == "live" && src.name == "process") {
                ddl << std::format("CREATE INDEX IF NOT EXISTS idx_{0}_name ON {0}(name);\n",
                                   table_name);
            }
            if (g.suffix == "live" && src.name == "tcp") {
                ddl << std::format("CREATE INDEX IF NOT EXISTS idx_{0}_remote ON {0}(remote_addr);\n",
                                   table_name);
            }
            if (g.suffix == "live" && src.name == "software") {
                ddl << std::format("CREATE INDEX IF NOT EXISTS idx_{0}_name ON {0}(name);\n",
                                   table_name);
            }
            if (g.suffix == "live" && src.name == "module") {
                ddl << std::format("CREATE INDEX IF NOT EXISTS idx_{0}_name ON {0}(module_name);\n",
                                   table_name);
                // The canonical "unsigned image loaded in the last 24h" query
                // filters signed_state; index it so that scan stays cheap once a
                // collector populates module_live.
                ddl << std::format(
                    "CREATE INDEX IF NOT EXISTS idx_{0}_signed_state ON {0}(signed_state);\n",
                    table_name);
            }

            ddl << "\n";
        }
    }
    return ddl.str();
}

std::optional<std::string> translate_dollar_name(std::string_view dollar_name) {
    auto& map = dollar_name_map();
    auto it = map.find(std::string(dollar_name));
    if (it != map.end())
        return it->second;
    return std::nullopt;
}

bool is_queryable_table(std::string_view real_table_name) {
    // Built once from the registry: every typed warehouse table (the
    // table_ref_map keys) plus the two base config/state tables. tar_events is
    // deliberately excluded — schema v3 drops it, so allowlisting it would turn
    // its "no such table" error into a weak existence oracle distinct from the
    // generic authorizer denial (#760 UP-8).
    static const std::unordered_set<std::string> allowed = [] {
        std::unordered_set<std::string> s{"tar_state", "tar_config"};
        for (const auto& [real, ref] : table_ref_map())
            s.insert(real);
        return s;
    }();
    return allowed.contains(std::string(real_table_name));
}

std::vector<std::string> all_dollar_names() {
    std::vector<std::string> names;
    for (const auto& [dollar, real] : dollar_name_map()) {
        names.push_back(dollar);
    }
    std::sort(names.begin(), names.end());
    return names;
}

std::vector<std::string> columns_for_table(const std::string& real_table_name) {
    auto& refs = table_ref_map();
    auto it = refs.find(real_table_name);
    if (it == refs.end())
        return {};

    const auto& src = build_sources()[it->second.source_idx];
    const auto& gran = src.granularities[it->second.gran_idx];

    std::vector<std::string> cols;
    cols.reserve(gran.columns.size() + 1);
    cols.emplace_back("id"); // M14: include DDL-generated id column
    for (const auto& c : gran.columns) {
        cols.emplace_back(c.name);
    }
    return cols;
}

std::string rollup_sql(std::string_view source_name, std::string_view target_suffix) {
    // ── Process rollups ─────────────────────────────────────────────────
    if (source_name == "process") {
        if (target_suffix == "hourly") {
            return R"(INSERT INTO process_hourly (hour_ts, name, user, start_count, stop_count)
SELECT (ts / 3600) * 3600, name, user,
       SUM(CASE WHEN action = 'started' THEN 1 ELSE 0 END),
       SUM(CASE WHEN action = 'stopped' THEN 1 ELSE 0 END)
FROM process_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 3600) * 3600, name, user)";
        }
        if (target_suffix == "daily") {
            return R"(INSERT INTO process_daily (day_ts, name, user, start_count, stop_count)
SELECT (hour_ts / 86400) * 86400, name, user,
       SUM(start_count), SUM(stop_count)
FROM process_hourly
WHERE hour_ts >= ? AND hour_ts < ?
GROUP BY (hour_ts / 86400) * 86400, name, user)";
        }
        if (target_suffix == "monthly") {
            // M2: Use strftime for calendar-month boundaries instead of fixed 30-day approximation
            return R"(INSERT INTO process_monthly (month_ts, name, user, start_count, stop_count)
SELECT CAST(strftime('%s', date(day_ts, 'unixepoch', 'start of month')) AS INTEGER), name, user,
       SUM(start_count), SUM(stop_count)
FROM process_daily
WHERE day_ts >= ? AND day_ts < ?
GROUP BY strftime('%Y-%m', day_ts, 'unixepoch'), name, user)";
        }
    }

    // ── TCP rollups ─────────────────────────────────────────────────────
    if (source_name == "tcp") {
        if (target_suffix == "hourly") {
            return R"(INSERT INTO tcp_hourly (hour_ts, remote_addr, remote_port, proto, process_name, connect_count, disconnect_count)
SELECT (ts / 3600) * 3600, remote_addr, remote_port, proto, process_name,
       SUM(CASE WHEN action = 'connected' THEN 1 ELSE 0 END),
       SUM(CASE WHEN action = 'disconnected' THEN 1 ELSE 0 END)
FROM tcp_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 3600) * 3600, remote_addr, remote_port, proto, process_name)";
        }
        if (target_suffix == "daily") {
            return R"(INSERT INTO tcp_daily (day_ts, remote_addr, remote_port, proto, process_name, connect_count, disconnect_count)
SELECT (hour_ts / 86400) * 86400, remote_addr, remote_port, proto, process_name,
       SUM(connect_count), SUM(disconnect_count)
FROM tcp_hourly
WHERE hour_ts >= ? AND hour_ts < ?
GROUP BY (hour_ts / 86400) * 86400, remote_addr, remote_port, proto, process_name)";
        }
        if (target_suffix == "monthly") {
            return R"(INSERT INTO tcp_monthly (month_ts, remote_addr, remote_port, proto, process_name, connect_count, disconnect_count)
SELECT CAST(strftime('%s', date(day_ts, 'unixepoch', 'start of month')) AS INTEGER),
       remote_addr, remote_port, proto, process_name,
       SUM(connect_count), SUM(disconnect_count)
FROM tcp_daily
WHERE day_ts >= ? AND day_ts < ?
GROUP BY strftime('%Y-%m', day_ts, 'unixepoch'), remote_addr, remote_port, proto, process_name)";
        }
    }

    // ── Service rollups ─────────────────────────────────────────────────
    if (source_name == "service") {
        if (target_suffix == "hourly") {
            return R"(INSERT INTO service_hourly (hour_ts, name, status_changes, last_status)
SELECT (ts / 3600) * 3600, name,
       SUM(CASE WHEN action = 'state_changed' THEN 1 ELSE 0 END),
       (SELECT s2.status FROM service_live s2
        WHERE s2.name = service_live.name AND s2.ts >= ? AND s2.ts < ?
        ORDER BY s2.ts DESC LIMIT 1)
FROM service_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 3600) * 3600, name)";
        }
    }

    // ── User rollups ────────────────────────────────────────────────────
    if (source_name == "user") {
        if (target_suffix == "daily") {
            return R"(INSERT INTO user_daily (day_ts, user, domain, login_count, logout_count)
SELECT (ts / 86400) * 86400, user, domain,
       SUM(CASE WHEN action = 'login' THEN 1 ELSE 0 END),
       SUM(CASE WHEN action = 'logout' THEN 1 ELSE 0 END)
FROM user_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 86400) * 86400, user, domain)";
        }
    }

    // ── Perf rollups (BRD A1) ───────────────────────────────────────────
    if (source_name == "perf") {
        if (target_suffix == "hourly") {
            return R"(INSERT INTO perf_hourly (hour_ts, samples, cpu_avg, cpu_max, mem_avg, mem_max, commit_avg,
    read_bps_avg, write_bps_avg, read_lat_us_avg, write_lat_us_avg,
    read_lat_us_max, write_lat_us_max, rx_bps_avg, tx_bps_avg)
SELECT (ts / 3600) * 3600, COUNT(*),
       AVG(cpu_pct), MAX(cpu_pct), AVG(mem_used_pct), MAX(mem_used_pct), AVG(commit_pct),
       CAST(AVG(disk_read_bps) AS INTEGER), CAST(AVG(disk_write_bps) AS INTEGER),
       CAST(AVG(disk_read_lat_us) AS INTEGER), CAST(AVG(disk_write_lat_us) AS INTEGER),
       MAX(disk_read_lat_us), MAX(disk_write_lat_us),
       CAST(AVG(net_rx_bps) AS INTEGER), CAST(AVG(net_tx_bps) AS INTEGER)
FROM perf_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 3600) * 3600)";
        }
    }

    // ── Per-app perf rollups (BRD A2) — per (hour, app name) ─────────────
    if (source_name == "procperf") {
        if (target_suffix == "hourly") {
            return R"(INSERT INTO procperf_hourly (hour_ts, name, samples, instances_max,
    cpu_avg, cpu_max, ws_avg_bytes, ws_max_bytes)
SELECT (ts / 3600) * 3600, name, COUNT(*), MAX(instances),
       AVG(cpu_pct), MAX(cpu_pct),
       CAST(AVG(ws_bytes) AS INTEGER), MAX(ws_bytes)
FROM procperf_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 3600) * 3600, name)";
        }
    }

    // ── Module / image-load rollups (M1) — per (module, signer, sig, kernel) ──
    // load_count counts 'loaded' events only; 'seed'/'blocked'/'unloaded' stay
    // visible at full fidelity in module_live and are not folded into the count.
    if (source_name == "module") {
        if (target_suffix == "hourly") {
            return R"(INSERT INTO module_hourly (hour_ts, module_name, signer, signed_state, is_kernel, load_count)
SELECT (ts / 3600) * 3600, module_name, signer, signed_state, is_kernel,
       SUM(CASE WHEN action = 'loaded' THEN 1 ELSE 0 END)
FROM module_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 3600) * 3600, module_name, signer, signed_state, is_kernel)";
        }
        if (target_suffix == "daily") {
            return R"(INSERT INTO module_daily (day_ts, module_name, signer, signed_state, is_kernel, load_count)
SELECT (hour_ts / 86400) * 86400, module_name, signer, signed_state, is_kernel,
       SUM(load_count)
FROM module_hourly
WHERE hour_ts >= ? AND hour_ts < ?
GROUP BY (hour_ts / 86400) * 86400, module_name, signer, signed_state, is_kernel)";
        }
        if (target_suffix == "monthly") {
            return R"(INSERT INTO module_monthly (month_ts, module_name, signer, signed_state, is_kernel, load_count)
SELECT CAST(strftime('%s', date(day_ts, 'unixepoch', 'start of month')) AS INTEGER),
       module_name, signer, signed_state, is_kernel,
       SUM(load_count)
FROM module_daily
WHERE day_ts >= ? AND day_ts < ?
GROUP BY strftime('%Y-%m', day_ts, 'unixepoch'), module_name, signer, signed_state, is_kernel)";
        }
    }

    // ── Software rollups (Phase 8 Wave 1) — per (name, scope) ─────────────────
    // Counts install/remove/upgrade events. Per-user rows from different
    // profiles fold together under the same (name, scope='user') bucket — the
    // count tier is "how many install events", not "by which user" (that detail
    // stays at full fidelity in software_live).
    if (source_name == "software") {
        if (target_suffix == "daily") {
            return R"(INSERT INTO software_daily (day_ts, name, scope, install_count, remove_count, upgrade_count)
SELECT (ts / 86400) * 86400, name, scope,
       SUM(CASE WHEN action = 'installed' THEN 1 ELSE 0 END),
       SUM(CASE WHEN action = 'removed' THEN 1 ELSE 0 END),
       SUM(CASE WHEN action = 'upgraded' THEN 1 ELSE 0 END)
FROM software_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 86400) * 86400, name, scope)";
        }
        if (target_suffix == "monthly") {
            return R"(INSERT INTO software_monthly (month_ts, name, scope, install_count, remove_count, upgrade_count)
SELECT CAST(strftime('%s', date(day_ts, 'unixepoch', 'start of month')) AS INTEGER),
       name, scope,
       SUM(install_count), SUM(remove_count), SUM(upgrade_count)
FROM software_daily
WHERE day_ts >= ? AND day_ts < ?
GROUP BY strftime('%Y-%m', day_ts, 'unixepoch'), name, scope)";
        }
    }

    // ── ARP rollups (ADR-0015) — per (interface, ip, mac) binding ────────
    if (source_name == "arp") {
        if (target_suffix == "hourly") {
            return R"(INSERT INTO arp_hourly (hour_ts, interface, ip_address, mac_address, appear_count, remove_count)
SELECT (ts / 3600) * 3600, interface, ip_address, mac_address,
       SUM(CASE WHEN action = 'appeared' THEN 1 ELSE 0 END),
       SUM(CASE WHEN action = 'removed' THEN 1 ELSE 0 END)
FROM arp_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 3600) * 3600, interface, ip_address, mac_address)";
        }
    }

    // ── DNS rollups (ADR-0015) — per (name, record_type) ─────────────────
    if (source_name == "dns") {
        if (target_suffix == "hourly") {
            return R"(INSERT INTO dns_hourly (hour_ts, name, record_type, appear_count, remove_count)
SELECT (ts / 3600) * 3600, name, record_type,
       SUM(CASE WHEN action = 'appeared' THEN 1 ELSE 0 END),
       SUM(CASE WHEN action = 'removed' THEN 1 ELSE 0 END)
FROM dns_live
WHERE ts >= ? AND ts < ?
GROUP BY (ts / 3600) * 3600, name, record_type)";
        }
    }

    return {};
}

std::string retention_sql(const std::string& real_table_name, int64_t now_epoch) {
    auto& refs = table_ref_map();
    auto it = refs.find(real_table_name);
    if (it == refs.end())
        return {};

    const auto& src = build_sources()[it->second.source_idx];
    const auto& gran = src.granularities[it->second.gran_idx];

    if (gran.retention_type == RetentionType::kRowCount) {
        // H6: Use OFFSET boundary instead of NOT IN anti-pattern — O(n) vs O(n*k)
        return std::format(
            "DELETE FROM {} WHERE id <= "
            "(SELECT id FROM {} ORDER BY id DESC LIMIT 1 OFFSET {})",
            real_table_name, real_table_name, gran.retention_default);
    } else {
        // Delete rows older than the retention window
        int64_t cutoff = now_epoch - gran.retention_default;
        auto ts_col = ts_column_for_suffix(gran.suffix);
        return std::format(
            "DELETE FROM {} WHERE {} < {}",
            real_table_name, ts_col, cutoff);
    }
}

} // namespace yuzu::tar
