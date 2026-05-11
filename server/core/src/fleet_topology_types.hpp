#pragma once

/**
 * fleet_topology_types.hpp -- Data types + JSON serialization for /viz/fleet
 *
 * Three top-level shapes consumed by the renderer:
 *   MachineNode     -- one fleet host (cube in the 3D scene)
 *   ProcessNode     -- one process inside a MachineNode (interior dot)
 *   ConnectionEdge  -- one open socket from src process; scope tells the
 *                       renderer whether to draw an interior line, an
 *                       inter-cube edge, or an "external/Internet" edge
 *
 * The renderer JSON shape is a concession to bandwidth: short keys, scalar
 * values where possible, optional fields omitted when empty. Test suite
 * locks the wire format.
 *
 * RawAgentSnapshot is the *input* shape -- one parsed fleet_snapshot.v1
 * payload from a single agent. The FleetTopologyStore aggregates a vector
 * of these into a TopologySnapshot.
 */

#include "process_category.hpp"

#include <cstdint>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// One process inside a machine cube.
struct ProcessNode {
    uint32_t pid{0};
    uint32_t ppid{0};
    std::string name;
    std::string user;
    ProcessCategory category{ProcessCategory::Other};
    /// CVE severity from the worst CVE matched against this process by
    /// name. Empty when no overlay was requested or no match found.
    /// Values: "critical" / "high" / "medium" / "low".
    std::string worst_severity;
    /// Number of CVE matches at any severity. 0 when overlay disabled.
    int cve_count{0};
};

/// Scope of a connection edge -- determines how the renderer draws it.
enum class EdgeScope {
    Local,         ///< local_addr and remote_addr both loopback (interior line)
    InternalFleet, ///< remote_addr resolves to another fleet machine
    External,      ///< remote_addr is outside the fleet (Internet sentinel)
};

inline std::string_view scope_to_string(EdgeScope s) {
    switch (s) {
    case EdgeScope::Local:
        return "local";
    case EdgeScope::InternalFleet:
        return "internal_fleet";
    case EdgeScope::External:
        return "external";
    }
    return "external";
}

/// One TCP / UDP socket originating from a process on this machine.
/// Inbound (LISTEN-only) sockets do not appear; only ESTABLISHED + outbound
/// CLOSE_WAIT / CLOSING / etc. with non-empty remote endpoints.
struct ConnectionEdge {
    std::string proto; ///< "tcp" / "tcp6" / "udp" / "udp6"
    uint32_t src_pid{0};
    std::string src_addr;
    int src_port{0};
    std::string dst_addr;
    int dst_port{0};
    /// agent_id of the destination machine when remote_addr resolves to a
    /// fleet host; empty for Local and External scopes.
    std::string dst_agent_id;
    /// Resolved destination pid on the SAME machine for `EdgeScope::Local`
    /// connections only. Populated by pairing each loopback connection with
    /// its reciprocal half (same 4-tuple, swapped). Zero (the default) when
    /// the destination is unresolved -- PR 8 drops those before they reach
    /// the renderer, so a `dst_pid == 0` on a Local edge that survives into
    /// a TopologySnapshot is a build-snapshot bug.
    uint32_t dst_pid{0};
    EdgeScope scope{EdgeScope::External};
    std::string state; ///< ESTABLISHED, CLOSE_WAIT, etc.
};

/// One fleet machine -- a cube in the 3D scene.
struct MachineNode {
    std::string agent_id;
    std::string hostname;
    std::string os;
    std::vector<std::string> local_ips;
    std::vector<ProcessNode> processes;
    std::vector<ConnectionEdge> connections;
    /// True when the agent failed to respond within the dispatch deadline
    /// or when the snapshot is older than the cache TTL. Renderer uses
    /// this to dim the cube and show "stale" overlay.
    bool stale{false};
    /// Epoch seconds when the agent emitted this snapshot. 0 when stale=true.
    int64_t ts{0};
    /// Truncation flags propagated from fleet_snapshot.v1.
    bool truncated_processes{false};
    bool truncated_connections{false};
};

/// Aggregate snapshot returned by FleetTopologyStore::get.
struct TopologySnapshot {
    int64_t generated_at{0};  ///< Server epoch seconds at build time
    bool include_vuln{false}; ///< Was the vuln overlay computed?
    std::vector<MachineNode> machines;
};

/// Input shape -- one parsed fleet_snapshot.v1 payload from a single agent.
/// SERVER-INTERNAL ONLY; never serialised to a renderer. The fetcher seam
/// produces a vector of these; FleetTopologyStore turns them into the
/// aggregate above. Carries `cmdline` (which MachineNode deliberately drops
/// post-redaction) so PR 7+ richer classification can use it.
struct RawAgentSnapshot {
    std::string agent_id;
    /// Full hostname (from snapshot).
    std::string hostname;
    /// OS reported by AgentRegistry session (snapshot doesn't carry it).
    std::string os;
    int64_t ts{0};
    std::vector<std::string> local_ips;
    bool truncated_processes{false};
    bool truncated_connections{false};
    /// Raw process rows from fleet_snapshot.v1 -- preserves cmdline so
    /// future PRs can use it for richer classification.
    struct RawProcess {
        uint32_t pid{0};
        uint32_t ppid{0};
        std::string name;
        std::string cmdline;
        std::string user;
    };
    std::vector<RawProcess> processes;
    struct RawConnection {
        std::string proto;
        std::string local_addr;
        int local_port{0};
        std::string remote_addr;
        std::string remote_host;
        int remote_port{0};
        std::string state;
        uint32_t pid{0};
        std::string process_name;
    };
    std::vector<RawConnection> connections;
    /// True when this agent timed out / errored during dispatch. Resulting
    /// MachineNode will have empty processes/connections and stale=true.
    bool stale{false};
};

// ── JSON serialization (shape locked by tests) ────────────────────────────

inline void to_json(nlohmann::json& j, const ProcessNode& p) {
    j = {{"pid", p.pid},
         {"ppid", p.ppid},
         {"name", p.name},
         {"user", p.user},
         {"category", category_to_string(p.category)}};
    if (!p.worst_severity.empty()) {
        j["worst_severity"] = p.worst_severity;
        j["cve_count"] = p.cve_count;
    }
}

inline void to_json(nlohmann::json& j, const ConnectionEdge& e) {
    j = {{"proto", e.proto},
         {"src_pid", e.src_pid},
         {"src_addr", e.src_addr},
         {"src_port", e.src_port},
         {"dst_addr", e.dst_addr},
         {"dst_port", e.dst_port},
         {"scope", scope_to_string(e.scope)},
         {"state", e.state}};
    if (!e.dst_agent_id.empty())
        j["dst_agent_id"] = e.dst_agent_id;
    if (e.dst_pid != 0)
        j["dst_pid"] = e.dst_pid;
}

inline void to_json(nlohmann::json& j, const MachineNode& m) {
    j = {{"agent_id", m.agent_id},
         {"hostname", m.hostname},
         {"os", m.os},
         {"local_ips", m.local_ips},
         {"processes", m.processes},
         {"connections", m.connections},
         {"stale", m.stale},
         {"ts", m.ts}};
    if (m.truncated_processes)
        j["truncated_processes"] = true;
    if (m.truncated_connections)
        j["truncated_connections"] = true;
}

inline void to_json(nlohmann::json& j, const TopologySnapshot& s) {
    // schema_minor allows additive evolution. Renderers MUST ignore unknown
    // keys. Bumped 1 -> 2 in PR 8 to advertise ConnectionEdge.dst_pid on
    // EdgeScope::Local edges.
    j = {{"schema", "fleet_topology.v1"},
         {"schema_minor", 2},
         {"generated_at", s.generated_at},
         {"include_vuln", s.include_vuln},
         {"machines", s.machines}};
}

} // namespace yuzu::server
