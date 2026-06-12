#include "dex_blast_radius.hpp"

#include <algorithm>
#include <utility>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <yuzu/metrics.hpp>

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
    // Strip control bytes (gov sec LOW): the subject lands in a server log line
    // (DexAlertRouter/BlastRadius), a notification title/message, and webhook
    // JSON. JSON encoding handles the wire today, but a raw \n forges log lines
    // and is a latent trap for any future HTML notification renderer. Replace
    // anything < 0x20 (and DEL) with '?'.
    for (char& c : subject)
        if (static_cast<unsigned char>(c) < 0x20 || static_cast<unsigned char>(c) == 0x7F)
            c = '?';
    return subject;
}

BlastRadiusDetector::BlastRadiusDetector(BlastRadiusConfig cfg) : cfg_(cfg) {}

void BlastRadiusDetector::set_on_incident(std::function<void(const BlastRadiusIncident&)> cb) {
    on_incident_ = std::move(cb);
}

void BlastRadiusDetector::set_metrics(yuzu::MetricsRegistry* metrics) { metrics_ = metrics; }

void BlastRadiusDetector::update_alert_shape(int min_devices, int window_seconds,
                                             int cooldown_seconds) {
    std::lock_guard lock(mu_);
    cfg_.min_devices = std::clamp(min_devices, 2, 100000);
    cfg_.window_seconds = std::clamp(window_seconds, 60, 86400);
    cfg_.cooldown_seconds = std::clamp(cooldown_seconds, 0, 7 * 86400);
    spdlog::info("BlastRadius: alert shape updated — min_devices={} window={}s cooldown={}s",
                 cfg_.min_devices, cfg_.window_seconds, cfg_.cooldown_seconds);
}

BlastRadiusConfig BlastRadiusDetector::alert_shape() const {
    std::lock_guard lock(mu_);
    return cfg_;
}

void BlastRadiusDetector::inc_metric(const char* name) {
    if (metrics_)
        metrics_->counter(name).increment();
}

bool BlastRadiusDetector::sweep_stale_locked(std::int64_t now_unix) {
    const std::int64_t horizon =
        now_unix - std::max(cfg_.window_seconds, cfg_.cooldown_seconds);
    const std::size_t before = pairs_.size();
    for (auto it = pairs_.begin(); it != pairs_.end();) {
        if (it->second.last_touch < horizon) {
            total_entries_ -= it->second.agents.size();
            it = pairs_.erase(it);
        } else {
            ++it;
        }
    }
    return pairs_.size() < before;
}

void BlastRadiusDetector::evict_lru_locked() {
    // Evict the least-recently-touched pair to admit a new one (gov UP-3). A
    // pair that has already reached the incident threshold is EXEMPT from
    // eviction (gov Gate-8 sec LOW): an established incident is touched on every
    // sighting so its last_touch is recent anyway, but a SLOW-building or
    // recently-fired incident could otherwise be the global-min — exempting any
    // `>= min_devices` pair protects both. Only if the entire map is at-threshold
    // incidents (pathological — a genuine fleet-wide multi-incident) do we fall
    // back to evicting the overall LRU so the cap can never deadlock. O(pairs),
    // only on a full-after-sweep insert.
    const auto min_devices = static_cast<std::size_t>(cfg_.min_devices);
    auto victim = pairs_.end();          // preferred: LRU among non-incidents
    std::int64_t victim_touch = 0;
    auto fallback = pairs_.end();        // overall LRU (only if all are incidents)
    std::int64_t fallback_touch = 0;
    for (auto it = pairs_.begin(); it != pairs_.end(); ++it) {
        if (fallback == pairs_.end() || it->second.last_touch < fallback_touch) {
            fallback = it;
            fallback_touch = it->second.last_touch;
        }
        if (it->second.agents.size() < min_devices &&
            (victim == pairs_.end() || it->second.last_touch < victim_touch)) {
            victim = it;
            victim_touch = it->second.last_touch;
        }
    }
    const auto chosen = (victim != pairs_.end()) ? victim : fallback;
    if (chosen != pairs_.end()) {
        total_entries_ -= chosen->second.agents.size();
        pairs_.erase(chosen);
        inc_metric("yuzu_server_dex_blast_radius_pairs_evicted_total");
    }
}

bool BlastRadiusDetector::fire_budget_ok_locked(std::int64_t now_unix) {
    const std::int64_t minute = now_unix / 60;
    if (minute != fire_minute_start_) {
        fire_minute_start_ = minute;
        fire_minute_count_ = 0;
    }
    if (fire_minute_count_ >= cfg_.max_fires_per_minute)
        return false;
    ++fire_minute_count_;
    return true;
}

void BlastRadiusDetector::observe(const std::string& obs_type, const std::string& subject,
                                  const std::string& agent_id, std::int64_t now_unix) {
    // Build the key BEFORE taking the lock — keep heap allocation out of the
    // critical section (gov perf).
    const std::string key = obs_type + '\x1f' + subject;
    BlastRadiusIncident incident;
    bool fire = false;
    {
        std::lock_guard lk(mu_);
        auto it = pairs_.find(key);
        if (it == pairs_.end()) {
            if (pairs_.size() >= cfg_.max_pairs) {
                sweep_stale_locked(now_unix);
                // Cap still holds after the sweep: evict the least-recently-
                // touched pair rather than dropping this new sighting, so a real
                // new incident is never silently suppressed by a saturated map
                // (gov UP-3). The LRU victim cannot be a live incident.
                if (pairs_.size() >= cfg_.max_pairs)
                    evict_lru_locked();
            }
            it = pairs_.emplace(key, Pair{}).first;
        }
        Pair& p = it->second;
        // Prune sightings that fell out of the window — THROTTLED (gov UP-1):
        // the prune is O(agents-in-pair); at fleet scale a hot incident pair
        // would otherwise run it on every ingest under this global lock. A few
        // seconds of staleness is irrelevant to the threshold. Always prune on
        // a pair's first touch (last_prune == 0).
        if (p.last_prune == 0 || now_unix - p.last_prune >= cfg_.prune_interval_seconds) {
            const std::int64_t window_start = now_unix - cfg_.window_seconds;
            for (auto a = p.agents.begin(); a != p.agents.end();) {
                if (a->second < window_start) {
                    a = p.agents.erase(a);
                    --total_entries_;
                } else {
                    ++a;
                }
            }
            p.last_prune = now_unix;
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
            inc_metric("yuzu_server_dex_blast_radius_entries_dropped_total");
            if (!entry_budget_warned_) {
                entry_budget_warned_ = true;
                spdlog::warn("BlastRadius: tracked-sighting budget ({}) exhausted — new "
                             "sightings untracked until stale entries age out",
                             cfg_.max_total_entries);
            }
        }
        p.last_touch = now_unix;
        if (metrics_)
            metrics_->gauge("yuzu_server_dex_blast_radius_pairs_tracked")
                .set(static_cast<double>(pairs_.size()));

        // last_alert == 0 means "never alerted" — it must not read as an
        // alert at epoch 0 (which would wrongly impose a cooldown near small
        // clock values and is semantically a different state).
        const bool in_cooldown =
            p.last_alert != 0 && now_unix - p.last_alert < cfg_.cooldown_seconds;
        if (static_cast<int>(p.agents.size()) >= cfg_.min_devices && !in_cooldown) {
            // Global fan-out rate cap (gov UP-2). Arm the per-pair cooldown ONLY
            // when an alert actually fires (gov Gate-8 sec MEDIUM): a
            // budget-CLIPPED pair must keep re-attempting on later ingests and
            // fire the moment the per-minute bucket frees — NOT go silent for a
            // full cooldown on an alert that was never sent (which would also let
            // an attacker flood cheap incidents to lock out a real one for a
            // cooldown). The budget check is O(1), so re-attempts are cheap.
            if (fire_budget_ok_locked(now_unix)) {
                p.last_alert = now_unix;
                incident.obs_type = obs_type;
                incident.subject = subject;
                incident.device_count = static_cast<int>(p.agents.size());
                incident.window_seconds = cfg_.window_seconds;
                fire = true;
            } else {
                inc_metric("yuzu_server_dex_blast_radius_fires_dropped_total");
            }
        }
    }
    // Callback OUTSIDE the lock: it does SQLite + webhook dispatch, and a
    // re-entrant observe() from a callback must not deadlock.
    if (fire && on_incident_) {
        inc_metric("yuzu_server_dex_blast_radius_incidents_total");
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
