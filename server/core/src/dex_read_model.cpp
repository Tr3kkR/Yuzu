#include "dex_read_model.hpp"

#include "dex_routes.hpp" // dex_device_score -- full DexFleet/DexSignalGroup defs live here too

#include <nlohmann/json.hpp>

namespace yuzu::server {

using json = nlohmann::json;

// ── MCP-only gap #1: per-device DEX score ────────────────────────────────────

DexDeviceScoreModel build_dex_device_score_model(GuaranteedStateStore* store,
                                                 const std::string& agent_id,
                                                 const std::string& window,
                                                 const std::string& since) {
    DexDeviceScoreModel m;
    m.agent_id = agent_id;
    m.window = window;
    if (!store)
        return m; // score stays -1, signals stays empty -- "no data" degrade
    m.score = dex_device_score(store, agent_id, since);
    m.signals = store->dex_device_signal_summary(agent_id, since);
    return m;
}

std::string dex_device_score_json(const DexDeviceScoreModel& model, bool audit_persisted) {
    json signals = json::array();
    for (const auto& s : model.signals) {
        signals.push_back({{"obs_type", s.obs_type},
                           {"count", s.count},
                           {"distinct_devices", s.distinct_devices},
                           {"last_seen", s.last_seen}});
    }
    json out{{"agent_id", model.agent_id},
             {"window", model.window},
             {"score", model.score}};
    out["signals"] = std::move(signals);
    if (!audit_persisted)
        out["audit_persisted"] = false;
    return out.dump();
}

// ── MCP-only gap #2: per-device app-perf drill ───────────────────────────────

std::string dex_device_app_perf_json(const std::string& agent_id, const std::string& app_filter,
                                     const std::vector<AppPerfDailyRow>& rows,
                                     bool audit_persisted) {
    json arr = json::array();
    for (const auto& r : rows) {
        if (!app_filter.empty() && r.app_name != app_filter)
            continue;
        arr.push_back({{"app_name", r.app_name},
                       {"version", r.version},
                       {"day", r.day},
                       {"samples", r.samples},
                       {"instances_max", r.instances_max},
                       {"cpu_avg", r.cpu_avg},
                       {"cpu_max", r.cpu_max},
                       {"ws_avg_bytes", r.ws_avg_bytes},
                       {"ws_max_bytes", r.ws_max_bytes}});
    }
    json out{{"agent_id", agent_id}, {"app", app_filter}};
    out["rows"] = std::move(arr);
    if (!audit_persisted)
        out["audit_persisted"] = false;
    return out.dump();
}

} // namespace yuzu::server
