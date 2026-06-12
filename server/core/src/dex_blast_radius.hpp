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
 * pair map is capped — stale pairs are swept on demand and a brand-new pair
 * arriving at the cap is dropped (counted, logged at debug). Per-pair agent
 * sets are pruned to the window on every touch.
 *
 * Threading: observe() is called concurrently from gRPC ingest threads —
 * internal mutex; the callback is invoked OUTSIDE the lock (it does SQLite +
 * webhook dispatch). set_on_incident() follows the set-before-traffic
 * contract (wired once at boot, like the other service-impl setters).
 */

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>

namespace yuzu::server {

struct BlastRadiusConfig {
    int min_devices{5};          ///< distinct agents that make an incident
    int window_seconds{900};     ///< sliding window (15 min)
    int cooldown_seconds{3600};  ///< per-pair re-alert suppression (1 h)
    std::size_t max_pairs{4096}; ///< tracked (obs_type, subject) pairs cap
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
    };

    // Caller holds mu_. Sweep pairs whose last touch fell out of both the
    // window and the cooldown; used when the map hits max_pairs.
    void sweep_stale_locked(std::int64_t now_unix);

    BlastRadiusConfig cfg_;
    std::function<void(const BlastRadiusIncident&)> on_incident_;
    std::mutex mu_;
    std::unordered_map<std::string, Pair> pairs_; ///< key: obs_type + '\x1f' + subject
};

} // namespace yuzu::server
