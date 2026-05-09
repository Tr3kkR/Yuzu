/**
 * tar_fleet_snapshot.cpp -- JSON builder for the tar.fleet_snapshot action.
 *
 * See tar_fleet_snapshot.hpp for the schema. Cmdline redaction reuses
 * redact_cmdline from tar_collectors.hpp; the same default patterns
 * (password/secret/token/api_key/credential) are applied as on the
 * regular collect_fast diff path.
 */

#include "tar_fleet_snapshot.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>

namespace yuzu::tar {

using json = nlohmann::json;

std::string build_fleet_snapshot_json(const std::vector<yuzu::agent::ProcessInfo>& processes,
                                      const std::vector<NetConnection>& connections,
                                      const std::vector<std::string>& local_ips,
                                      const std::string& hostname, int64_t ts,
                                      const std::vector<std::string>& redaction_patterns,
                                      bool process_source_enabled, bool tcp_source_enabled,
                                      int max_rows) {

    if (max_rows <= 0)
        max_rows = kFleetSnapshotMaxRows;

    const bool truncated_procs = processes.size() > static_cast<size_t>(max_rows);
    const bool truncated_conns = connections.size() > static_cast<size_t>(max_rows);

    const size_t proc_count = std::min(processes.size(), static_cast<size_t>(max_rows));
    const size_t conn_count = std::min(connections.size(), static_cast<size_t>(max_rows));

    json proc_arr = json::array();
    proc_arr.get_ref<json::array_t&>().reserve(proc_count);
    for (size_t i = 0; i < proc_count; ++i) {
        const auto& p = processes[i];
        proc_arr.push_back({{"pid", p.pid},
                            {"ppid", p.ppid},
                            {"name", p.name},
                            {"cmdline", redact_cmdline(p.cmdline, redaction_patterns)},
                            {"user", p.user}});
    }

    json conn_arr = json::array();
    conn_arr.get_ref<json::array_t&>().reserve(conn_count);
    for (size_t i = 0; i < conn_count; ++i) {
        const auto& c = connections[i];
        conn_arr.push_back({{"proto", c.proto},
                            {"local_addr", c.local_addr},
                            {"local_port", c.local_port},
                            {"remote_addr", c.remote_addr},
                            {"remote_host", c.remote_host},
                            {"remote_port", c.remote_port},
                            {"state", c.state},
                            {"pid", c.pid},
                            {"process_name", c.process_name}});
    }

    json ips_arr = json::array();
    ips_arr.get_ref<json::array_t&>().reserve(local_ips.size());
    for (const auto& ip : local_ips)
        ips_arr.push_back(ip);

    json doc = {{"schema", "fleet_snapshot.v1"},
                {"schema_minor", 1},
                {"ts", ts},
                {"hostname", hostname},
                {"local_ips", std::move(ips_arr)},
                {"processes", std::move(proc_arr)},
                {"connections", std::move(conn_arr)},
                {"truncated_processes", truncated_procs},
                {"truncated_connections", truncated_conns}};

    if (!process_source_enabled)
        doc["process_source_paused"] = true;
    if (!tcp_source_enabled)
        doc["tcp_source_paused"] = true;

    return doc.dump();
}

} // namespace yuzu::tar
