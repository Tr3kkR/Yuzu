#pragma once

/**
 * dex_alert_router.hpp — operator-configured per-signal alert routing (BRD
 * rows 124/136 — docs/dex-brd-coverage.md slice F1).
 *
 * The blast-radius detector answers "is this failure SPREADING"; this router
 * answers "the operator asked to be told about THIS signal type at all". An
 * operator routes a set of obs_types (Settings → DEX alerts); each routed
 * observation then raises an operator notification and fires the `dex.signal`
 * webhook/offload event — per-device, first sighting, with a per
 * (obs_type, agent) cooldown so a flapping device alerts once per period, not
 * once per observation. DEFAULT: nothing routed — exactly the pre-F1
 * behavior (blast-radius incidents remain the only automatic alerts).
 *
 * Placement: fed from the SAME guardian_ingest chokepoint as the blast-radius
 * detector (both wire paths, after the event commits). Purely in-memory and
 * derived — cooldown state rebuilds organically after a restart (worst case:
 * one duplicate alert per routed (type, agent) pair).
 *
 * Bounds (same hostile-fleet posture as the blast-radius detector): the
 * cooldown map is capped — expired entries are swept on demand and at the cap
 * the stalest entry is evicted; a global fires-per-minute budget bounds the
 * synchronous notification insert + webhook fan-out when a routed type storms
 * fleet-wide (the blast-radius detector is the right tool for that case, and
 * it still fires).
 *
 * Threading: observe() is called concurrently from gRPC ingest threads —
 * internal mutex; the callback runs OUTSIDE the lock (SQLite + webhook
 * dispatch). set_routes() is the one RUNTIME-mutable input (the settings
 * panel applies changes live, no restart) and takes the same mutex.
 * set_on_alert()/set_metrics() follow the set-before-traffic contract.
 */

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server {

struct DexAlertRouterConfig {
    /// Seconds a routed (obs_type, agent) pair stays silenced after firing.
    int cooldown_seconds{3600};
    /// Cooldown-entry cap — the memory bound under a hostile fleet.
    std::size_t max_entries{8192};
    /// Global cap on alert fires per rolling minute (notification + webhook
    /// fan-out bound; mirrors the blast-radius UP-2 posture).
    int max_fires_per_minute{30};
};

struct RoutedSignalAlert {
    std::string obs_type;
    std::string subject;  ///< "" when the signal carries no subject
    std::string agent_id;
};

/// Parse the persisted routing config (a JSON array of obs_type strings,
/// e.g. ["os.bugcheck","perf.cpu_sustained"]) into the routed set.
/// Defensive: malformed JSON / non-string elements → skipped; oversized
/// types (>128 bytes) and arrays (>512 entries) are clamped so a corrupted
/// config row cannot balloon memory. Pure + unit-testable.
std::unordered_set<std::string> parse_routed_types(const std::string& json);

/// Serialize the routed set back to the persisted JSON form (sorted, so the
/// stored value is stable/diffable). Pure + unit-testable.
std::string routed_types_to_json(const std::unordered_set<std::string>& types);

class DexAlertRouter {
public:
    explicit DexAlertRouter(DexAlertRouterConfig cfg = {});

    /// Wire the alert sink. Set ONCE at boot before traffic flows
    /// (set-before-traffic contract); not synchronised against observe().
    void set_on_alert(std::function<void(const RoutedSignalAlert&)> cb);

    /// Wire Prometheus metrics (set-before-traffic). nullptr = no metrics.
    void set_metrics(yuzu::MetricsRegistry* metrics);

    /// Replace the routed-type set. RUNTIME-safe (the settings panel calls
    /// this live); takes the internal mutex. Cooldown state for de-routed
    /// types is left to age out (harmless — never consulted again).
    void set_routes(std::unordered_set<std::string> types);

    /// Snapshot of the routed set (settings rendering).
    std::unordered_set<std::string> routes() const;

    /// Record one observation sighting. Cheap; fires the alert callback
    /// (outside the lock) when the type is routed, the (type, agent) pair is
    /// not in cooldown, and the fire budget allows.
    void observe(const std::string& obs_type, const std::string& subject,
                 const std::string& agent_id, std::int64_t now_unix);

private:
    // Caller holds mu_. Sweep expired cooldown entries; if still at the cap,
    // evict the single stalest entry (a full map must not block a fresh
    // routed alert).
    void make_room_locked(std::int64_t now_unix);

    void inc_metric(const char* name);

    DexAlertRouterConfig cfg_;
    std::function<void(const RoutedSignalAlert&)> on_alert_;
    yuzu::MetricsRegistry* metrics_{nullptr};
    mutable std::mutex mu_;
    std::unordered_set<std::string> routed_;
    std::unordered_map<std::string, std::int64_t> last_fire_; ///< type+'\x1f'+agent → ts
    std::int64_t fire_minute_start_{0};
    int fire_minute_count_{0};
};

} // namespace yuzu::server
