/**
 * tar_schema_registry.cpp -- Capture source definitions, DDL generation,
 *                            $-name translation, and rollup/retention SQL.
 */

#include "tar_schema_registry.hpp"

#include <algorithm>
#include <format>
#include <sstream>

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
                {"windows", OsSupportStatus::kSupported,           "toolhelp32",
                 "CreateToolhelp32Snapshot — full pid/ppid/name/cmdline; "
                 "cmdline retrieval requires PROCESS_QUERY_LIMITED_INFORMATION."},
                {"linux",   OsSupportStatus::kSupported,           "procfs",
                 "Reads /proc/<pid>/status and /proc/<pid>/cmdline."},
                {"macos",   OsSupportStatus::kSupportedConstrained, "sysctl",
                 "KERN_PROC_ALL via sysctl. Cmdline requires SIP-respecting "
                 "KERN_PROCARGS2 — empty for hardened-runtime processes that "
                 "the agent cannot inspect."},
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

std::string generate_warehouse_ddl() {
    std::ostringstream ddl;
    for (const auto& src : build_sources()) {
        for (const auto& g : src.granularities) {
            std::string table_name = std::format("{}_{}", src.name, g.suffix);

            ddl << "CREATE TABLE IF NOT EXISTS " << table_name << " (\n";
            ddl << "    id INTEGER PRIMARY KEY AUTOINCREMENT";

            for (const auto& col : g.columns) {
                ddl << ",\n    " << col.name << " " << col.sql_type;
                // ts columns and counts get NOT NULL
                if (col.sql_type == "INTEGER") {
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
