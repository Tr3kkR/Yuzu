#include "preflight_eval.hpp"

#include "response_store.hpp"

#include <nlohmann/json.hpp>

namespace yuzu::server::preflight {

namespace {
// Generous per-check fetch: a run re-dispatches, so one agent may have several
// command_ids under the same execution_id; latest_per_agent collapses them. The
// cap bounds the materialised set (fleet-scale keyset paging is a follow-up).
constexpr int kResponseFetchCap = 10000;

int score_response(const StoredResponse& r) {
    int s = 0;
    if (r.status != 0) // 0 = RUNNING; terminal beats running
        s += 2;
    if (!r.output.empty())
        s += 1;
    return s;
}
} // namespace

std::string check_execution_id(const std::string& run_id, std::string_view check_key) {
    return "preflight-" + run_id + "-" + std::string(check_key);
}

bool check_applicable(std::string_view key, const PreflightConfig& cfg) {
    if (key == "app")
        return !cfg.app_name.empty();
    return true;
}

std::vector<std::pair<std::string, std::string>> applicable_checks(const PreflightConfig& cfg) {
    std::vector<std::pair<std::string, std::string>> out;
    for (const auto& c : kPreflightChecks)
        if (check_applicable(c.key, cfg))
            out.emplace_back(c.key, c.label);
    return out;
}

std::unordered_map<std::string, std::string> dispatch_params(std::string_view key,
                                                             const PreflightConfig& cfg) {
    if (key == "app")
        return {{"name", cfg.app_name}};
    if (key == "disk" && !cfg.volume.empty())
        return {{"path", cfg.volume}};
    return {};
}

std::vector<PreflightCheckResponses>
collect_check_responses(ResponseStore& store, const std::string& run_id,
                        const std::vector<std::pair<std::string, std::string>>& applicable) {
    std::vector<PreflightCheckResponses> out;
    out.reserve(applicable.size());
    ResponseQuery q;
    q.limit = kResponseFetchCap;
    for (const auto& [key, label] : applicable) {
        PreflightCheckResponses cr;
        cr.key = key;
        cr.label = label;
        auto rows = store.query_by_execution(check_execution_id(run_id, key), q);
        // latest_per_agent: terminal beats running, then non-empty output, then
        // the later arrival (mirrors policy_evaluator.cpp).
        std::unordered_map<std::string, const StoredResponse*> best;
        for (const auto& r : rows) {
            auto it = best.find(r.agent_id);
            if (it == best.end()) {
                best.emplace(r.agent_id, &r);
                continue;
            }
            const StoredResponse& cur = *it->second;
            const int sr = score_response(r), sc = score_response(cur);
            if (sr > sc || (sr == sc && r.received_at_ms > cur.received_at_ms))
                it->second = &r;
        }
        for (const auto& [agent, rp] : best)
            cr.by_agent[agent] = {rp->status, rp->output};
        out.push_back(std::move(cr));
    }
    return out;
}

std::string checks_to_json(const std::vector<PreflightDeviceCheck>& checks) {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& c : checks)
        arr.push_back({{"key", c.key},
                       {"label", c.label},
                       {"v", static_cast<int>(c.verdict)},
                       {"val", c.value}});
    // Agent-derived values may carry odd bytes → replace, never throw.
    return arr.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

std::vector<PreflightDeviceCheck> checks_from_json(const std::string& json) {
    std::vector<PreflightDeviceCheck> out;
    auto j = nlohmann::json::parse(json, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_array())
        return out;
    for (const auto& e : j) {
        if (!e.is_object())
            continue;
        PreflightDeviceCheck c;
        c.key = e.value("key", std::string{});
        c.label = e.value("label", std::string{});
        int v = e.value("v", static_cast<int>(Verdict::kUnknown));
        if (v < 0 || v > static_cast<int>(Verdict::kUnknown))
            v = static_cast<int>(Verdict::kUnknown);
        c.verdict = static_cast<Verdict>(v);
        c.value = e.value("val", std::string{});
        out.push_back(std::move(c));
    }
    return out;
}

std::string config_to_json(const PreflightConfig& cfg) {
    nlohmann::json j = {{"app_name", cfg.app_name},
                        {"app_min", cfg.app_min_version},
                        {"app_max", cfg.app_max_version},
                        {"os_min", cfg.os_min_version},
                        {"arch", cfg.req_arch},
                        {"min_gib", cfg.min_free_gib},
                        {"volume", cfg.volume},
                        {"reboot_block", cfg.reboot_block}};
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

PreflightConfig config_from_json(const std::string& json) {
    PreflightConfig c;
    auto j = nlohmann::json::parse(json, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object())
        return c;
    c.app_name = j.value("app_name", std::string{});
    c.app_min_version = j.value("app_min", std::string{});
    c.app_max_version = j.value("app_max", std::string{});
    c.os_min_version = j.value("os_min", std::string{});
    c.req_arch = j.value("arch", std::string{});
    c.min_free_gib = j.value("min_gib", static_cast<std::int64_t>(0));
    c.volume = j.value("volume", std::string{});
    c.reboot_block = j.value("reboot_block", true);
    return c;
}

} // namespace yuzu::server::preflight
