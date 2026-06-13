#pragma once

/**
 * dex_blast_radius.hpp — fleet-wide incident detection over DEX observations
 * (BRD rows 32/137 — docs/dex-brd-coverage.md slice D3).
 *
 * One device crashing is a fact; N distinct devices reporting the SAME failing
 * subject inside a short window is an incident ("Chrome is crashing on 12
 * devices *right now*"). The detector keeps an in-memory sliding window per
 * (obs_type, subject) pair, counts DISTINCT agents, and fires the wired
 * on_incident callback when a pair crosses the device threshold — with a
 * per-pair cooldown so a standing incident alerts once per cooldown period,
 * not once per observation.
 *
 * Placement: fed from the shared Guardian ingest chokepoint
 * (guardian_ingest.cpp) AFTER the event commits, so both the direct Subscribe
 * path and the gateway path are covered and a rolled-back duplicate never
 * counts. Purely in-memory and derived: state is rebuilt organically from
 * live traffic after a restart (an incident that is still happening keeps
 * reporting; one that ended needs no late alert).
 *
 * Bounds (a compromised enrolled agent must not balloon server memory): the
 * pair map is capped — stale pairs are swept on demand, and at the cap the
 * least-recently-touched pair that has NOT reached the incident threshold is
 * evicted to admit a new one (so spray of fresh subjects evicts stale sprayed
 * pairs; any pair already at `>= min_devices` is exempt, protecting both
 * established and slow-building incidents — only an all-incidents map falls
 * back to evicting the overall LRU). Per-pair agent sets are pruned to
 * the window, throttled so a hot pair under a real fleet incident does not run
 * an O(agents) prune on every ingest (the cost that would otherwise stall ALL
 * Guardian ingest at the worst moment — gov UP-1/perf). A global
 * incident-fire rate cap bounds the notification + webhook fan-out under a
 * correlated multi-subject incident (gov UP-2).
 *
 * Threading: observe() is called concurrently from gRPC ingest threads —
 * internal mutex; the callback is invoked OUTSIDE the lock (it does SQLite +
 * webhook dispatch). set_on_incident() / set_metrics() follow the
 * set-before-traffic contract (wired once at boot, like the other service-impl
 * setters).
 */

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

struct BlastRadiusConfig {
    int min_devices{5};          ///< distinct agents that make an incident
    int window_seconds{900};     ///< sliding window (15 min)
    int cooldown_seconds{3600};  ///< per-pair re-alert suppression (1 h)
    std::size_t max_pairs{4096}; ///< tracked (obs_type, subject) pairs cap
    /// Global cap on tracked (pair, agent) sightings — the MEMORY bound. The
    /// pair cap bounds map keys, not entries: a coordinated hostile fleet
    /// spraying distinct subjects inside its rate caps could otherwise grow
    /// the agent sets toward hundreds of MB. 100k entries ≈ ~5 MB worst.
    /// At the budget, NEW sightings go untracked (existing ones still
    /// refresh), so an established incident keeps counting and a saturated
    /// detector under-counts rather than over-allocates.
    std::size_t max_total_entries{100000};
    /// Minimum seconds between any two per-pair window-prunes (gov UP-1/perf):
    /// the prune is O(agents-in-pair); at fleet scale a hot incident pair would
    /// otherwise run it on every ingest under the global lock, stalling all
    /// Guardian ingest. A few seconds of window staleness is irrelevant to a
    /// 5-device / 900s threshold.
    int prune_interval_seconds{30};
    /// Global cap on incident FIRES per rolling minute (gov UP-2): bounds the
    /// synchronous notification insert + webhook/offload fan-out under a
    /// correlated multi-subject incident (a bad patch crashing many apps).
    /// Excess fires are dropped (counted) — the per-pair cooldown still applies
    /// underneath, so this only clips a genuine multi-subject burst.
    int max_fires_per_minute{20};
};

struct BlastRadiusIncident {
    std::string obs_type;
    std::string subject;     ///< "" when the signal carries no subject
    int device_count{0};     ///< distinct agents inside the window at fire time
    int window_seconds{0};   ///< the window the count was taken over
};

/// Extract the alert-facing subject from an observation's detail_json: the
/// uniform "subject" key with the slice-1 "process" fallback, clamped to the
/// same 256-byte / UTF-8-safe limit as the projection (sec-M1 — an enrolled
/// agent must not place multi-MB strings into notification titles or webhook
/// bodies). Defensive: malformed/empty JSON → "". Pure + unit-testable.
std::string blast_subject_from_detail(const std::string& detail_json);

class BlastRadiusDetector {
public:
    explicit BlastRadiusDetector(BlastRadiusConfig cfg = {});

    /// Wire the incident sink. Set ONCE at boot before traffic flows
    /// (set-before-traffic contract); not synchronised against observe().
    void set_on_incident(std::function<void(const BlastRadiusIncident&)> cb);

    /// Wire Prometheus metrics (set-before-traffic). nullptr = no metrics
    /// (tests). Surfaces incidents fired, fan-out drops, budget/pair drops, and
    /// the live pair count so a silently-saturated detector is observable
    /// (gov SRE OBS-1 / compliance S1).
    void set_metrics(yuzu::MetricsRegistry* metrics);

    /// F1: update the ALERT-SHAPE knobs at runtime (Settings → DEX alerts).
    /// Only the operator-meaningful trio is tunable — the memory/fan-out
    /// bounds (max_pairs, entry budget, prune throttle, fire budget) stay
    /// fixed, they are DoS posture, not policy. Values are clamped to sane
    /// ranges (min_devices >= 2 — single-device alerting is the alert
    /// router's job; window 60s..24h; cooldown 0..7d). Takes the internal
    /// mutex — safe against concurrent observe().
    void update_alert_shape(int min_devices, int window_seconds, int cooldown_seconds);

    /// Snapshot of the current alert-shape trio (settings rendering).
    BlastRadiusConfig alert_shape() const;

    /// Record one observation sighting. Cheap (hash-map ops under one mutex);
    /// fires the incident callback (outside the lock) when this sighting tips
    /// the pair over the threshold and the pair is not in cooldown.
    void observe(const std::string& obs_type, const std::string& subject,
                 const std::string& agent_id, std::int64_t now_unix);

private:
    struct Pair {
        std::unordered_map<std::string, std::int64_t> agents; ///< agent_id → last seen
        std::int64_t last_alert{0};
        std::int64_t last_touch{0};
        std::int64_t last_prune{0}; ///< last window-prune (throttle, gov UP-1)
    };

    // Caller holds mu_. Sweep pairs whose last touch fell out of both the
    // window and the cooldown. Returns true if at least one pair was freed.
    bool sweep_stale_locked(std::int64_t now_unix);

    // Caller holds mu_. Evict the single least-recently-touched pair to admit a
    // new one when the cap holds after a sweep (gov UP-3 — never silently drop
    // a fresh real incident; the LRU victim is the stalest sprayed pair).
    void evict_lru_locked();

    // Caller holds mu_. Rolling-minute incident-fire budget (gov UP-2).
    bool fire_budget_ok_locked(std::int64_t now_unix);

    // Counter bump helpers (no-op when metrics_ unset).
    void inc_metric(const char* name);

    BlastRadiusConfig cfg_; // alert-shape trio mutable via update_alert_shape (under mu_)
    std::function<void(const BlastRadiusIncident&)> on_incident_;
    yuzu::MetricsRegistry* metrics_{nullptr};
    mutable std::mutex mu_;
    std::unordered_map<std::string, Pair> pairs_; ///< key: obs_type + '\x1f' + subject
    std::size_t total_entries_{0};                ///< tracked (pair, agent) sightings
    bool entry_budget_warned_{false};
    std::int64_t fire_minute_start_{0}; ///< current rolling-minute bucket
    int fire_minute_count_{0};          ///< fires in the current bucket
};

} // namespace yuzu::server
