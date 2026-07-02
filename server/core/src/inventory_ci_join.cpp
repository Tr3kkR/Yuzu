/// @file inventory_ci_join.cpp
/// See inventory_ci_join.hpp.

#include "inventory_ci_join.hpp"

namespace yuzu::server {

void attach_device_ci(std::vector<InventoryDeviceRow>& rows,
                      const std::unordered_map<std::string, DeviceCiRecord>& ci_by_agent) {
    for (auto& row : rows) {
        auto it = ci_by_agent.find(row.agent_id);
        if (it == ci_by_agent.end())
            continue; // no CI synced for this agent yet — leave the ci_* fields blank
        const DeviceCiRecord& ci = it->second;
        row.ci_serial = ci.serial;
        row.ci_model = ci.model;
        row.ci_cpu_cores = ci.cpu_cores;
        row.ci_cpu_threads = ci.cpu_threads;
        row.ci_ram_bytes = ci.ram_bytes;
    }
}

} // namespace yuzu::server
