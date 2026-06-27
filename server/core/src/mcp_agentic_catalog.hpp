#pragma once

#include <algorithm>
#include <string>
#include <string_view>

namespace yuzu::server::mcp::agentic {

struct IncidentPlaybook {
    const char* name;
    const char* title;
    const char* category;
    const char* first_tool;
    const char* classification;
    const char* requires_connector;
    const char* summary;
    const char* steps_json;
};

inline std::string lower_copy(std::string v) {
    std::transform(v.begin(), v.end(), v.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return v;
}

inline constexpr IncidentPlaybook
    kIncidentPlaybooks
        [] =
            {
                {"openshift_cluster_operator_degraded", "OpenShift cluster operator degraded",
                 "openshift", "classify_operational_question", "requires_external_connector",
                 "OpenShift/Kubernetes API connector for operator, pod, route, event, and node "
                 "internals.",
                 "Use Yuzu for endpoint evidence around affected worker hosts, DNS/proxy, "
                 "certificates, "
                 "container runtime state, and patch drift; do not claim cluster-internal cause "
                 "without a "
                 "cluster connector.",
                 R"(["Classify whether the question asks for cluster internals or host evidence.","Use get_fleet_posture_fast to identify impacted OS/site cohorts.","Use query_inventory/get_agent_inventory for host certs, services, DNS, proxy, runtime packages, and patch state.","Use get_network_fleet/list_network_devices for site or route-quality evidence.","Mark OpenShift operator/pod/event facts as connector gaps unless supplied by the user."])"},
                {"container_build_failure", "Docker buildx or Chisel container build failure",
                 "containers", "classify_operational_question", "answerable_with_live_dispatch",
                 "Registry/build-system connector for build logs and cache metadata.",
                 "Yuzu can inspect build hosts for architecture, QEMU/binfmt packages, "
                 "Docker/buildx versions, "
                 "proxy/DNS/CA state, disk pressure, and endpoint network quality.",
                 R"(["Classify the failure mode: multi-arch, QEMU, cache, registry auth, DNS/proxy, CA, or runtime slice.","Inspect build-host inventory and recent command responses before dispatching anything new.","Check fleet/network posture for DNS, proxy, packet loss, and disk-pressure cohorts.","Use live dispatch only for read-only host probes; ask for approval before remediation."])"},
                {"collaboration_quality_issue", "Teams or Zoom call quality issue", "collaboration",
                 "get_fleet_posture_fast", "answerable_now", "",
                 "Yuzu can summarize endpoint and network evidence: site cohorts, RTT/retransmits, "
                 "VPN/proxy "
                 "hints, Wi-Fi adapters, CPU/memory pressure, and app instability observations.",
                 R"(["Start with get_fleet_posture_fast for top network and DEX findings.","Use get_network_fleet and list_network_devices to identify affected sites/cohorts.","Use list_dex_signals/get_dex_signal_detail for app crashes or device pressure.","Separate endpoint evidence from Teams/Zoom tenant-service telemetry, which needs vendor connectors."])"},
                {"endpoint_security_client_outage",
                 "Endpoint security, VPN, proxy, or ZTNA client outage", "security_client",
                 "get_fleet_posture_fast", "answerable_with_live_dispatch", "",
                 "Yuzu can identify affected hosts through installed-app, service, process, "
                 "event-log, DNS, "
                 "proxy, VPN, and network evidence. Remediation stays approval-gated.",
                 R"(["Summarize fleet posture and affected OS/site cohorts.","Query inventory for client package, version, service, driver, and extension state.","Use DEX/network findings to distinguish bad update blast radius from tunnel/proxy/DNS issues.","Prepare remediation only after scope is narrowed and approval is explicit."])"},
                {"patch_or_reboot_risk",
                 "Patch, pending reboot, disk encryption, or update-wave risk", "endpoint_ops",
                 "get_fleet_posture_fast", "answerable_now", "",
                 "Yuzu can answer from endpoint inventory, policy/compliance drift, recent "
                 "responses, and "
                 "agent liveness. Disk-encryption vendor gaps must be labelled when inventory is "
                 "absent.",
                 R"(["Use get_fleet_posture_fast for online/offline, OS mix, and compliance drift.","Query inventory and responses for pending reboot/update/encryption signals.","Summarize blast radius by OS, site, and management group.","Do not reboot or patch without explicit approval and the correct MCP tier."])"},
                {"database_client_or_host_bottleneck", "Postgres or Oracle client/host bottleneck",
                 "database", "classify_operational_question", "requires_external_connector",
                 "Database connector for waits, locks, sessions, plans, replication, and backup "
                 "internals.",
                 "Yuzu can inspect database hosts or clients for CPU, memory, disk latency, "
                 "network path, "
                 "service state, client versions, certificates, and process evidence.",
                 R"(["Classify database-internal asks as connector-required.","Use Yuzu host evidence to check CPU, memory, disk, network, client package, cert, and service posture.","Use recent responses/executions if prior database-host probes exist.","Keep lock/session/wait conclusions conditional unless database telemetry is supplied."])"},
                {"java_node_service_degradation",
                 "Spring Cloud Gateway, Java, or Node service degradation", "runtime",
                 "classify_operational_question", "answerable_with_live_dispatch", "",
                 "Yuzu can inspect host pressure, service/process state, certificates, DNS/proxy, "
                 "deployed "
                 "versions, event logs, and endpoint network quality; app traces need an APM/log "
                 "connector.",
                 R"(["Classify whether the user asks for host evidence or application traces.","Check posture for CPU, memory, disk, RTT, retransmits, and app crash signals.","Inspect inventory/responses for JVM/Node versions, service status, truststores, certificates, and config rollout markers.","Do not infer route, heap, or event-loop root cause without direct app telemetry."])"},
                {"kvm_libvirt_host_issue", "KVM/libvirt host or VM availability issue",
                 "virtualization", "classify_operational_question", "requires_external_connector",
                 "libvirt/KVM connector or host-level probe for VM, bridge, and storage-pool "
                 "internals.",
                 "Yuzu can inspect the virtualization host's services, packages, "
                 "bridge/DNS/network state, "
                 "disk pressure, and event logs when those facts are inventoried or safely "
                 "dispatched.",
                 R"(["Classify VM-internal state as connector-required unless host probes are available.","Use host inventory for libvirt service/socket, bridge config, storage pressure, and kernel/package state.","Use network and DEX performance tools for noisy-host or degraded-link evidence.","Keep VM-state claims scoped to observed host evidence."])"},
};

// Resolve a scenario name or friendly tag to a playbook. Matching is EXACT on
// the playbook name, on its category, or on a curated tag alias (G-S8, #1653
// review). The previous loose `title.find(key)` / `key.find(category)` substring
// matching returned the WRONG playbook for short/generic queries — "a", "host",
// or "operator" each matched the first playbook whose title happened to contain
// the substring, sending an agentic worker the wrong first tool and connector
// advice. Aliases keep the documented friendly tags (postgres, teams, buildx,
// crowdstrike, …) working without reintroducing substring ambiguity.
inline const IncidentPlaybook* find_playbook(std::string_view name_or_tag) {
    const auto key = lower_copy(std::string(name_or_tag));
    if (key.empty())
        return nullptr;
    struct Alias {
        std::string_view tag;
        std::string_view category;
    };
    static constexpr Alias kAliases[] = {
        {"openshift", "openshift"},        {"kubernetes", "openshift"},
        {"k8s", "openshift"},              {"teams", "collaboration"},
        {"zoom", "collaboration"},         {"collaboration", "collaboration"},
        {"buildx", "containers"},          {"docker", "containers"},
        {"chisel", "containers"},          {"container", "containers"},
        {"crowdstrike", "security_client"},{"zscaler", "security_client"},
        {"anyconnect", "security_client"}, {"vpn", "security_client"},
        {"postgres", "database"},          {"oracle", "database"},
        {"database", "database"},          {"java", "runtime"},
        {"node", "runtime"},               {"spring", "runtime"},
        {"kvm", "virtualization"},         {"libvirt", "virtualization"},
        {"patch", "endpoint_ops"},         {"reboot", "endpoint_ops"},
    };
    std::string_view category_key = key;
    for (const auto& a : kAliases) {
        if (key == a.tag) {
            category_key = a.category;
            break;
        }
    }
    for (const auto& p : kIncidentPlaybooks) {
        if (key == lower_copy(p.name) || category_key == p.category)
            return &p;
    }
    return nullptr;
}

} // namespace yuzu::server::mcp::agentic
