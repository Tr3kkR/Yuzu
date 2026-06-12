#include "dex_blast_radius.hpp"

#include <algorithm>
#include <utility>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace yuzu::server {

std::string blast_subject_from_detail(const std::string& detail_json) {
    // Same defensive parse + clamp discipline as project_observation_locked
    // (guaranteed_state_store.cpp) — keep the two in sync so the alert names
    // the same subject the projection records.
    nlohmann::json j = nlohmann::json::parse(detail_json, nullptr, /*allow_exceptions=*/false);
    constexpr std::size_t kFieldMax = 256;
    auto field = [&](const char* k) -> std::string {
        if (j.is_object())
            if (auto it = j.find(k); it != j.end() && it->is_string()) {
                std::string v = it->get<std::string>();
                if (v.size() > kFieldMax) {
                    v.resize(kFieldMax);
                    // Don't leave a torn UTF-8 sequence at the cut.
                    while (!v.empty() && (static_cast<unsigned char>(v.back()) & 0xC0) == 0x80)
                        v.pop_back();
                    if (!v.empty() && (static_cast<unsigned char>(v.back()) & 0xC0) == 0xC0)
                        v.pop_back();
                }
                return v;
            }
        return {};
    };
    std::string subject = field("subject");
    if (subject.empty())
        subject = field("process"); // slice-1 crash key fallback (PR #1311 transition)
    return subject;
}

BlastRadiusDetector::BlastRadiusDetector(BlastRadiusConfig cfg) : cfg_(cfg) {}

void BlastRadiusDetector::set_on_incident(std::function<void(const BlastRadiusIncident&)> cb) {
    on_incident_ = std::move(cb);
}

void BlastRadiusDetector::sweep_stale_locked(std::int64_t now_unix) {
    const std::int64_t horizon =
        now_unix - std::max(cfg_.window_seconds, cfg_.cooldown_seconds);
    for (auto it = pairs_.begin(); it != pairs_.end();) {
        if (it->second.last_touch < horizon) {
            total_entries_ -= it->second.agents.size();
            it = pairs_.erase(it);
        } else {
            ++it;
        }
    }
}

void BlastRadiusDetector::observe(const std::string& obs_type, const std::string& subject,
                                  const std::string& agent_id, std::int64_t now_unix) {
    BlastRadiusIncident incident;
    bool fire = false;
    {
        std::lock_guard lk(mu_);
        const std::string key = obs_type + '\x1f' + subject;
        auto it = pairs_.find(key);
        if (it == pairs_.end()) {
            if (pairs_.size() >= cfg_.max_pairs) {
                sweep_stale_locked(now_unix);
                if (pairs_.size() >= cfg_.max_pairs) {
                    // Cap holds even after the sweep — drop the NEW pair, never
                    // an established one (an attacker spraying synthetic
                    // subjects must not evict a real incident mid-window).
                    spdlog::debug("BlastRadius: pair cap ({}) reached — dropping sighting "
                                  "of new pair {}",
                                  cfg_.max_pairs, obs_type);
                    return;
                }
            }
            it = pairs_.emplace(key, Pair{}).first;
        }
        Pair& p = it->second;
        // Prune sightings that fell out of the window, then record this one.
        const std::int64_t window_start = now_unix - cfg_.window_seconds;
        for (auto a = p.agents.begin(); a != p.agents.end();) {
            if (a->second < window_start) {
                a = p.agents.erase(a);
                --total_entries_;
            } else {
                ++a;
            }
        }
        if (auto a = p.agents.find(agent_id); a != p.agents.end()) {
            a->second = now_unix; // refresh — never blocked by the budget
        } else if (total_entries_ < cfg_.max_total_entries) {
            p.agents.emplace(agent_id, now_unix);
            ++total_entries_;
        } else {
            // Entry budget exhausted (memory bound) — the new sighting goes
            // untracked; the budget frees as stale entries prune on touch or
            // sweep. Saturated = under-count, never over-allocate.
            if (!entry_budget_warned_) {
                entry_budget_warned_ = true;
                spdlog::warn("BlastRadius: tracked-sighting budget ({}) exhausted — new "
                             "sightings untracked until stale entries age out",
                             cfg_.max_total_entries);
            }
        }
        p.last_touch = now_unix;

        // last_alert == 0 means "never alerted" — it must not read as an
        // alert at epoch 0 (which would wrongly impose a cooldown near small
        // clock values and is semantically a different state).
        const bool in_cooldown =
            p.last_alert != 0 && now_unix - p.last_alert < cfg_.cooldown_seconds;
        if (static_cast<int>(p.agents.size()) >= cfg_.min_devices && !in_cooldown) {
            p.last_alert = now_unix;
            incident.obs_type = obs_type;
            incident.subject = subject;
            incident.device_count = static_cast<int>(p.agents.size());
            incident.window_seconds = cfg_.window_seconds;
            fire = true;
        }
    }
    // Callback OUTSIDE the lock: it does SQLite + webhook dispatch, and a
    // re-entrant observe() from a callback must not deadlock.
    if (fire && on_incident_) {
        try {
            on_incident_(incident);
        } catch (...) {
            // An alert-sink failure must never poison the ingest thread.
            spdlog::warn("BlastRadius: on_incident sink threw for {} '{}' — alert lost",
                         incident.obs_type, incident.subject);
        }
    }
}

} // namespace yuzu::server
