#pragma once

#include "instruction_store.hpp"

#include <string>
#include <vector>

namespace yuzu::server {

struct PluginCapability {
    std::string plugin_name;
    std::string plugin_version;
    std::string plugin_description;
    std::vector<std::string> actions;
};

// Generate InstructionDefinitions from plugin capabilities.
// Each plugin+action pair produces one deterministic definition with
// id "legacy.<plugin_name>.<action>".
std::vector<InstructionDefinition>
generate_legacy_definitions(const std::vector<PluginCapability>& capabilities);

// Sync generated definitions into the store, skipping any whose id
// already exists.  Returns the count of new definitions created.
int sync_legacy_definitions(InstructionStore& store,
                            const std::vector<PluginCapability>& capabilities,
                            const std::string& created_by = "system");

} // namespace yuzu::server
