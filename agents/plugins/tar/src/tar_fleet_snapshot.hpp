#pragma once

/**
 * tar_fleet_snapshot.hpp -- JSON builder for the tar.fleet_snapshot action
 *
 * Pure free function that takes already-collected process and connection
 * inventories plus the host's local IPs and emits a single JSON document
 * conforming to the fleet_snapshot.v1 schema. Factored out of tar_plugin.cpp
 * so it can be unit-tested without instantiating the plugin or stubbing
 * CommandContext.
 *
 * Schema (one JSON object):
 *   {
 *     "schema": "fleet_snapshot.v1",
 *     "schema_minor": 1,
 *     "ts": <int64_t epoch seconds>,
 *     "hostname": <string>,
 *     "local_ips": [<string>, ...],
 *     "processes": [
 *       {"pid":<u32>, "ppid":<u32>, "name":<string>,
 *        "cmdline":<string|"[REDACTED by TAR]">, "user":<string>}, ...
 *     ],
 *     "connections": [
 *       {"proto":<string>, "local_addr":<string>, "local_port":<int>,
 *        "remote_addr":<string>, "remote_host":<string>, "remote_port":<int>,
 *        "state":<string>, "pid":<u32>, "process_name":<string>}, ...
 *     ],
 *     "truncated_processes": <bool>,
 *     "truncated_connections": <bool>,
 *     "process_source_paused": <bool>,    // optional, only when true
 *     "tcp_source_paused":     <bool>     // optional, only when true
 *   }
 *
 * `schema_minor` allows additive evolution (e.g. PR 7 adding rss_kb) without
 * a breaking version bump. Consumers MUST ignore unknown keys.
 */

#include "tar_collectors.hpp"

#include <yuzu/agent/process_enum.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::tar {

/// Hard cap on each list to bound payload size on busy hosts. Empirically a
/// fully-populated snapshot at this cap (4096 procs + 4096 conns) is ~1.3 MB
/// of JSON; realistic hosts emit 50-500 KB. Truncation flags inform the
/// server when the cap is hit so the operator can investigate.
inline constexpr int kFleetSnapshotMaxRows = 4096;

/**
 * Build the fleet_snapshot.v1 JSON document.
 *
 * @param processes        Process inventory (cmdline will be redacted in-place
 *                         per redaction_patterns; original input is not modified).
 * @param connections      Network connection inventory.
 * @param local_ips        Host-bound non-loopback non-link-local IPs.
 * @param hostname         Reporting host's name.
 * @param ts               Epoch seconds at snapshot time.
 * @param redaction_patterns  Glob patterns for cmdline redaction (e.g. "*password*").
 * @param process_source_enabled  When false, emits process_source_paused=true
 *                                so the renderer can show "partial observation".
 * @param tcp_source_enabled      Same for the tcp source.
 * @param max_rows         Truncation cap per list (defaults to kFleetSnapshotMaxRows).
 *
 * @return Single-line JSON string (no trailing newline).
 */
std::string build_fleet_snapshot_json(
    const std::vector<yuzu::agent::ProcessInfo>& processes,
    const std::vector<NetConnection>& connections, const std::vector<std::string>& local_ips,
    const std::string& hostname, int64_t ts,
    const std::vector<std::string>& redaction_patterns = kDefaultRedactionPatterns,
    bool process_source_enabled = true, bool tcp_source_enabled = true,
    int max_rows = kFleetSnapshotMaxRows);

} // namespace yuzu::tar
