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
 *
 * Lifetime: one instance per Server, owned by the daemon for its lifetime.
 * Constructor is called once in server.cpp with the real fetcher injected;
 * never per-request.
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

    /// PR 6 / OBS-2: optional observer fired exactly once per refill, with
    /// the wall-clock duration of the fetcher_() call only (not the cache
    /// lock, not the build_snapshot pass). Server wires this to a
    /// Prometheus histogram so operators can distinguish "agent dispatch
    /// is slow" from "the rest of the request is slow" -- the existing
    /// `yuzu_viz_topology_request_seconds` histogram measures the whole
    /// HTTP path. Null-by-default; observer is invoked on success AND on
    /// fetcher exception (so a hung fetcher still produces an upper-bound
    /// observation).
    using FetchDurationObserver = std::function<void(std::chrono::duration<double>)>;

    /// @param fetcher        Required. Called on cache miss / expiry.
    /// @param nvd            Optional. When include_vuln=true and nvd is
    ///                       non-null, processes get worst_severity + cve_count.
    ///                       NOTE: PR 2 ships the join wired but inert: the
    ///                       agent's fleet_snapshot.v1 payload does not yet
    ///                       carry installed versions, so match_inventory --
    ///                       which requires a non-empty version per item --
    ///                       returns no matches today. PR 10 (vulnerability
    ///                       overlay) will either extend the agent payload
    ///                       with versions or add a name-only path to NVD.
    /// @param ttl            Cache TTL; defaults to 60 s.
    /// @param fetch_deadline How long the fetcher gets before partial results
    ///                       are accepted; defaults to 5 s. Waiters on a
    ///                       single-flight refill use ttl_+slack as their
    ///                       cv.wait_for bound so a hung fetcher cannot block
    ///                       caller threads forever (UP-8 / CAP-2).
    /// @param max_snapshot_bytes Soft cap on the serialised snapshot size.
    ///                       Refills exceeding this log a WARN and are NOT
    ///                       cached (next get() retries) so a runaway fleet
    ///                       cannot wedge the cache slot at multi-GB.
    ///                       Defaults to 256 MB. Set 0 to disable.
    FleetTopologyStore(Fetcher fetcher, NvdDatabase* nvd = nullptr,
                       std::chrono::milliseconds ttl = std::chrono::seconds(60),
                       std::chrono::milliseconds fetch_deadline = std::chrono::milliseconds(5000),
                       std::size_t max_snapshot_bytes = 256ull * 1024 * 1024);

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

    /// Set the optional fetcher-duration observer (see
    /// FetchDurationObserver above). Pass an empty function to clear.
    ///
    /// Thread-safe: setter and `get()` synchronise on slots_mu_; `get()`
    /// snapshots the std::function under the lock and invokes it after
    /// dropping the lock. A re-wire applies to refills started after the
    /// setter returns -- in-flight refills run their already-snapshotted
    /// observer to completion. Re-wires are not torn-read-prone.
    /// **Convention** (not enforced): callers wire this once during
    /// server bring-up before the store sees real traffic; mid-traffic
    /// re-wires work but accumulate split-bucket histogram observations
    /// across the boundary, which is rarely useful operationally. (gov
    /// R6 architect SHOULD-1.)
    void set_fetch_duration_observer(FetchDurationObserver observer);

    // ── Observability counters ─────────────────────────────────────────────
    uint64_t cache_hits() const noexcept { return cache_hits_.load(std::memory_order_relaxed); }
    uint64_t cache_misses() const noexcept { return cache_misses_.load(std::memory_order_relaxed); }
    /// Number of fetch waiters that piggybacked on an in-flight refill
    /// (single-flight wins). Useful for spotting stampede risk on /viz/fleet.
    uint64_t refill_waiters() const noexcept {
        return refill_waiters_.load(std::memory_order_relaxed);
    }
    /// Refills whose serialised size exceeded max_snapshot_bytes_ and were
    /// therefore NOT cached. A runaway counter signals a misbehaving agent
    /// (or the fleet outgrew the configured cap).
    uint64_t refill_oversize_drops() const noexcept {
        return refill_oversize_drops_.load(std::memory_order_relaxed);
    }
    /// Single-flight waiters that timed out on cv.wait_for before the refill
    /// completed. Non-zero indicates the fetcher is exceeding its deadline.
    uint64_t refill_wait_timeouts() const noexcept {
        return refill_wait_timeouts_.load(std::memory_order_relaxed);
    }
    /// PR 8 forensic counter (gov R8): EdgeScope::Local edges whose reciprocal
    /// half was missing from the agent snapshot and were therefore dropped
    /// before serialisation. Expected to be non-zero under normal churn (kernel
    /// race during teardown, TIME_WAIT halves, agent's 4096-connection cap
    /// cutting a partner). A spike vs steady-state baseline signals systematic
    /// loss -- e.g. an agent reporting half-open sockets, or a kernel-version
    /// change altering /proc/net/tcp atomicity. Surfaces in metrics as
    /// `yuzu_viz_local_edges_dropped_total`.
    uint64_t local_edges_dropped() const noexcept {
        return local_edges_dropped_.load(std::memory_order_relaxed);
    }

    /// Build a TopologySnapshot from raw inputs without any caching. Public
    /// so PR 3 can reuse the same logic in any future on-demand path that
    /// bypasses the cache (e.g. a per-machine drill-in endpoint).
    TopologySnapshot build_snapshot(std::vector<RawAgentSnapshot> raw, bool include_vuln) const;

    /// Sentinel snapshot returned when the fetcher fails on a cold slot --
    /// has generated_at set but machines empty. Public so PR 3 can render
    /// "no fleet data" identically whether the failure was first-call or
    /// later. (governance round 1, UP-9.)
    TopologySnapshot empty_snapshot(bool include_vuln) const;

private:
    Fetcher fetcher_;
    FetchDurationObserver fetch_observer_;
    NvdDatabase* nvd_{nullptr};
    std::chrono::milliseconds ttl_;
    std::chrono::milliseconds fetch_deadline_;
    std::size_t max_snapshot_bytes_;

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
    std::atomic<uint64_t> refill_oversize_drops_{0};
    std::atomic<uint64_t> refill_wait_timeouts_{0};
    /// `mutable` because `build_snapshot()` is const (pure transformation
    /// over `raw`) but updates this observability counter on each drop pass.
    mutable std::atomic<uint64_t> local_edges_dropped_{0};

    bool fresh_locked(const Slot& s) const;
};

} // namespace yuzu::server
