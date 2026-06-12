#include "dex_alert_router.hpp"

#include <yuzu/metrics.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <utility>
#include <vector>

namespace yuzu::server {

std::unordered_set<std::string> parse_routed_types(const std::string& json) {
    std::unordered_set<std::string> out;
    if (json.empty())
        return out;
    const auto parsed = nlohmann::json::parse(json, nullptr, /*allow_exceptions=*/false);
    if (!parsed.is_array())
        return out;
    constexpr std::size_t kMaxTypes = 512;
    constexpr std::size_t kMaxTypeLen = 128;
    for (const auto& el : parsed) {
        if (out.size() >= kMaxTypes)
            break;
        if (!el.is_string())
            continue;
        auto s = el.get<std::string>();
        if (s.empty() || s.size() > kMaxTypeLen)
            continue;
        out.insert(std::move(s));
    }
    return out;
}

std::string routed_types_to_json(const std::unordered_set<std::string>& types) {
    std::vector<std::string> sorted(types.begin(), types.end());
    std::sort(sorted.begin(), sorted.end());
    return nlohmann::json(sorted).dump();
}

DexAlertRouter::DexAlertRouter(DexAlertRouterConfig cfg) : cfg_(cfg) {}

void DexAlertRouter::set_on_alert(std::function<void(const RoutedSignalAlert&)> cb) {
    on_alert_ = std::move(cb);
}

void DexAlertRouter::set_metrics(yuzu::MetricsRegistry* metrics) { metrics_ = metrics; }

void DexAlertRouter::set_routes(std::unordered_set<std::string> types) {
    std::lock_guard lock(mu_);
    routed_ = std::move(types);
    if (metrics_)
        metrics_->gauge("yuzu_server_dex_alert_routed_types")
            .set(static_cast<double>(routed_.size()));
}

std::unordered_set<std::string> DexAlertRouter::routes() const {
    std::lock_guard lock(mu_);
    return routed_;
}

void DexAlertRouter::inc_metric(const char* name) {
    if (metrics_)
        metrics_->counter(name).increment();
}

void DexAlertRouter::make_room_locked(std::int64_t now_unix) {
    if (last_fire_.size() < cfg_.max_entries)
        return;
    // Sweep everything whose cooldown already expired.
    std::erase_if(last_fire_, [&](const auto& kv) {
        return now_unix - kv.second >= cfg_.cooldown_seconds;
    });
    if (last_fire_.size() < cfg_.max_entries)
        return;
    // Still full: evict the single stalest entry — its silence period ends a
    // little early (a duplicate alert), which beats suppressing a FRESH one.
    auto victim = last_fire_.begin();
    for (auto it = last_fire_.begin(); it != last_fire_.end(); ++it)
        if (it->second < victim->second)
            victim = it;
    last_fire_.erase(victim);
    inc_metric("yuzu_server_dex_alert_cooldowns_evicted_total");
}

void DexAlertRouter::observe(const std::string& obs_type, const std::string& subject,
                             const std::string& agent_id, std::int64_t now_unix) {
    bool fire = false;
    {
        std::lock_guard lock(mu_);
        if (routed_.find(obs_type) == routed_.end())
            return; // not routed — the overwhelmingly common path, one hash probe
        const std::string key = obs_type + '\x1f' + agent_id;
        if (auto it = last_fire_.find(key); it != last_fire_.end() &&
                                            now_unix - it->second < cfg_.cooldown_seconds) {
            inc_metric("yuzu_server_dex_alerts_suppressed_total");
            return; // in cooldown
        }
        // Rolling-minute fan-out budget (the blast-radius UP-2 posture).
        if (now_unix - fire_minute_start_ >= 60) {
            fire_minute_start_ = now_unix;
            fire_minute_count_ = 0;
        }
        if (fire_minute_count_ >= cfg_.max_fires_per_minute) {
            inc_metric("yuzu_server_dex_alerts_dropped_total");
            return; // budget exhausted — the cooldown is NOT armed, so the
                    // alert fires on a later sighting once the burst passes
        }
        ++fire_minute_count_;
        make_room_locked(now_unix);
        last_fire_[key] = now_unix;
        fire = true;
    }
    if (fire && on_alert_) {
        inc_metric("yuzu_server_dex_alerts_fired_total");
        RoutedSignalAlert a;
        a.obs_type = obs_type;
        a.subject = subject;
        a.agent_id = agent_id;
        on_alert_(a); // outside the lock — SQLite + webhook dispatch
    }
}

} // namespace yuzu::server
