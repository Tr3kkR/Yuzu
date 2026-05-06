#pragma once
//
// plugin_config_sync.hpp — internal helper exposed for unit testing.
//
// The agent's per-plugin PluginContextImpl maps are snapshot-copied from
// the master plugin_ctx_.config during the load loop, freezing each one
// before the agent has populated agent.plugins.count, agent.modules.count,
// the agent.plugins.N.* roster, or any agent.modules.N.* entries written
// after that plugin's own snapshot point. This helper closes the gap by
// copying every key in the master map into every per-plugin context after
// load completes — so plugins reading via get_config() see the complete
// post-load state instead of "(not set)".
//
// Templated on the per-plugin context map type so the helper has no
// dependency on the (anonymous-namespace) PluginContextImpl definition
// in agent.cpp. Unit tests stub `pctx->config` with a minimal struct
// that exposes just an `unordered_map<string,string> config` field.
//
// Caller contract:
//   - master:  the agent's authoritative config map
//   - plugins: a map whose values dereference (via -> or *) to a struct
//              with a `config` member of type
//              std::unordered_map<std::string, std::string>
//   - Behaviour: after the call, every plugin's config contains every
//     key in master (overwriting any prior value with the same key).
//
// Limitation (tracked separately): the sync is one-shot. Runtime keys
// written to plugin_ctx_.config AFTER this call (e.g. agent.session_id,
// agent.reconnect_count, agent.latency_ms, agent.grpc_channel_state,
// agent.connected_since) do NOT propagate into per-plugin contexts.
// Plugins reading those keys still observe stale snapshot values until
// a future per-write fan-out helper closes the gap.

#include <string>
#include <unordered_map>

namespace yuzu::agent::detail {

template <typename CtxMap>
inline void
sync_master_config_to_plugins(const std::unordered_map<std::string, std::string>& master,
                              CtxMap& plugins) {
    for (auto& kv : plugins) {
        auto& pctx = kv.second;
        for (const auto& [k, v] : master) {
            pctx->config[k] = v;
        }
    }
}

} // namespace yuzu::agent::detail
