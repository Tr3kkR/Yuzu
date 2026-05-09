#pragma once

/**
 * fleet_topology_store.hpp -- Aggregator + cache for /viz/fleet topology
 *
 * The store turns a vector of per-agent fleet_snapshot.v1 payloads into a
 * single TopologySnapshot, applying:
 *   * Process categorisation (process_category.hpp)
 *   * Cross-machine IP resolution (ip → agent_id map)
 *   * Connection scope classification (Local / InternalFleet / External)
 *   * Optional vulnerability overlay (NvdDatabase::match_inventory)
 *
 * Caching: 60-second TTL keyed by `include_vuln` (LRU-of-2). When a get()
 * call finds the slot cold or expired, exactly one caller refills it; the
 * others wait on the same shared_ptr. Cache and dispatch are decoupled
 * via the `Fetcher` seam -- PR 2 ships this with fake fetchers used by
 * tests; PR 3 will inject the real fetcher that drives the agent dispatch
 * via AgentRegistry::send_to + an agent_service_impl response callback.
 *
 * Thread-safe: a std::shared_mutex guards the slots map; refill runs
 * outside the lock so dispatch latency doesn't block other slot reads.
 */

#include "fleet_topology_types.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu::server {

class NvdDatabase; ///< Forward-declare; vuln overlay only uses match_inventory.

class FleetTopologyStore {
public:
    /// Fetcher seam: produces one RawAgentSnapshot per known fleet agent
    /// within the supplied deadline. Implementations time out individual
    /// agents, set stale=true on no-response rows, and return whatever
    /// they collected. PR 2 uses fakes; PR 3 wires the real dispatch.
    using Fetcher =
        std::function<std::vector<RawAgentSnapshot>(std::chrono::milliseconds deadline)>;

    /// @param fetcher        Required. Called on cache miss / expiry.
    /// @param nvd            Optional. When include_vuln=true and nvd is
    ///                       non-null, processes get worst_severity + cve_count.
    /// @param ttl            Cache TTL; defaults to 60 s.
    /// @param fetch_deadline How long the fetcher gets before partial results
    ///                       are accepted; defaults to 5 s.
    FleetTopologyStore(Fetcher fetcher, NvdDatabase* nvd = nullptr,
                       std::chrono::milliseconds ttl = std::chrono::seconds(60),
                       std::chrono::milliseconds fetch_deadline = std::chrono::milliseconds(5000));

    FleetTopologyStore(const FleetTopologyStore&) = delete;
    FleetTopologyStore& operator=(const FleetTopologyStore&) = delete;

    /// Returns a snapshot. Either a cache hit (fast path) or a refill
    /// (calls the fetcher synchronously, with `fetch_deadline` budget).
    /// `include_vuln=true` performs the NVD join when nvd_ is set; it is
    /// a no-op when nvd_ is null (worst_severity stays empty).
    std::shared_ptr<const TopologySnapshot> get(bool include_vuln);

    /// Forcibly drop the cache; the next get() will refill. Used by tests
    /// and by the operator-facing `?fresh=1` query parameter.
    void invalidate();

    // ── Observability counters ─────────────────────────────────────────────
    uint64_t cache_hits() const noexcept { return cache_hits_.load(std::memory_order_relaxed); }
    uint64_t cache_misses() const noexcept { return cache_misses_.load(std::memory_order_relaxed); }
    /// Number of fetch waiters that piggybacked on an in-flight refill
    /// (single-flight wins). Useful for spotting stampede risk on /viz/fleet.
    uint64_t refill_waiters() const noexcept {
        return refill_waiters_.load(std::memory_order_relaxed);
    }

    /// Build a TopologySnapshot from raw inputs without any caching. Public
    /// so PR 3 can reuse the same logic in any future on-demand path that
    /// bypasses the cache (e.g. a per-machine drill-in endpoint).
    TopologySnapshot build_snapshot(std::vector<RawAgentSnapshot> raw, bool include_vuln) const;

private:
    Fetcher fetcher_;
    NvdDatabase* nvd_{nullptr};
    std::chrono::milliseconds ttl_;
    std::chrono::milliseconds fetch_deadline_;

    struct Slot {
        std::shared_ptr<const TopologySnapshot> snap;
        std::chrono::steady_clock::time_point cached_at{};
        bool refilling{false};
        std::condition_variable cv;
    };

    mutable std::mutex slots_mu_;
    /// Only two slots ever -- false (no vuln) and true (with vuln). A map
    /// keyed by bool is overkill but mirrors the symmetry plainly.
    std::unordered_map<bool, std::unique_ptr<Slot>> slots_;

    std::atomic<uint64_t> cache_hits_{0};
    std::atomic<uint64_t> cache_misses_{0};
    std::atomic<uint64_t> refill_waiters_{0};

    bool fresh_locked(const Slot& s) const;
};

} // namespace yuzu::server
