#pragma once

/// @file stream_budget.hpp
/// Shared admission budget for held-open SSE responses (ADR-1005 Decision 15(h)).
///
/// Every held-open SSE response pins one httplib worker thread for the whole
/// life of the stream (the content provider blocks in `cv.wait_for`). The
/// worker pool is shared by EVERY surface on the web server, so the cap on
/// concurrent streams must be computed ONCE across all of them — not
/// per-route. This budget is that single instance: MCP's `GET /mcp/v1/` takes
/// leases from it today; the streamed-POST channel (track 2f PR 3) and
/// `GET /api/v1/events` (issue #2056) adopt the SAME instance rather than
/// minting a parallel counter, or the shared pool can still be starved by the
/// surfaces that opted out.
///
/// Header-only, sibling of `event_bus.hpp` (whose sink primitives it pairs
/// with) — small enough that a separate TU adds no value, and directly
/// unit-testable.

#include <cstddef>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

namespace yuzu::server::detail {

/// Plain-REST reserve: worker threads held back from streams, so a saturated stream
/// budget does not starve ordinary request/response traffic (Decision 15(h), CH-6).
///
/// HONESTY NOTE: this is a reserve only against the surfaces that actually take
/// leases. httplib has no per-route worker reservation — three other held-open
/// providers share the same pool and are still UNCAPPED (`GET /api/v1/events`,
/// the dashboard execution SSE, and the legacy `/events` stream; issue #2056 moves
/// them onto this budget). Until they adopt it, the reserve bounds the MCP surface,
/// not the pool as a whole.
inline constexpr std::size_t kPlainRestReserveDefault = 8;

/// Workers a single permitted stream can pin at once. A stream is normally one
/// provider on one worker — but a takeover leaves the superseded provider draining
/// (still pinning its worker) while the replacement runs, and `McpStreamState` allows
/// at most ONE pending handover per session. So the budget must reserve two workers
/// for every stream it admits, or a fleet of reconnecting clients would oversubscribe
/// the pool by exactly the number of handovers in flight.
inline constexpr std::size_t kMaxProvidersPerStream = 2;

/// Floor for `--http-worker-threads`. httplib's own default base is `max(8, cores-1)`;
/// going below 8 drives the derived stream budget to zero, which would disable MCP
/// streaming entirely from behind a knob that reads like a tuning parameter.
inline constexpr std::size_t kMinHttpWorkerThreads = 8;

/// Effective global stream cap: the operator's request, clamped to what the worker
/// pool can actually spare once the reserve and the per-stream provider allowance are
/// taken out. Pure — the unit-testable half of CH-6.
inline constexpr std::size_t derive_stream_budget(std::size_t pool_max,
                                                  std::size_t plain_rest_reserve,
                                                  std::size_t requested_global_cap) {
    const std::size_t spare = pool_max > plain_rest_reserve ? pool_max - plain_rest_reserve : 0;
    const std::size_t affordable = spare / kMaxProvidersPerStream;
    return requested_global_cap < affordable ? requested_global_cap : affordable;
}

/// Global + per-principal admission counters for held-open SSE responses.
///
/// REJECT-not-evict (Decision 15(j)): a cap hit denies the NEW stream; a live
/// stream is never torn down to make room for a newcomer, so one noisy
/// principal cannot cut another's stream.
///
/// Thread-safe: httplib dispatches attach/release across worker threads.
class StreamBudget {
public:
    struct Config {
        std::size_t global_cap = 16;
        std::size_t per_principal_cap = 4;
    };

    explicit StreamBudget(Config cfg) : cfg_(cfg) {}

    StreamBudget(const StreamBudget&) = delete;
    StreamBudget& operator=(const StreamBudget&) = delete;

    /// Move-only RAII slot. Releasing is idempotent and never throws, so a
    /// stream's slot is returned exactly once no matter which path
    /// (client disconnect, revocation, shutdown, exception) tears it down.
    class Lease {
    public:
        Lease() = default;

        Lease(Lease&& other) noexcept
            : budget_(other.budget_), principal_(std::move(other.principal_)) {
            other.budget_ = nullptr;
        }

        Lease& operator=(Lease&& other) noexcept {
            if (this != &other) {
                release();
                budget_ = other.budget_;
                principal_ = std::move(other.principal_);
                other.budget_ = nullptr;
            }
            return *this;
        }

        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;

        ~Lease() { release(); }

        explicit operator bool() const { return budget_ != nullptr; }

        /// Return the slot early. Idempotent — a second call is a no-op, so the
        /// destructor after an explicit release does nothing.
        ///
        /// `noexcept` is structural, not decorative: this runs from ~Lease (itself
        /// implicitly noexcept) on a provider-teardown path, so a throwing
        /// `lock_guard` here would terminate anyway. Making it explicit means the
        /// "a slot is always returned" claim cannot be quietly broken by a future
        /// throwing member.
        void release() noexcept {
            if (budget_ != nullptr) {
                budget_->release_slot(principal_);
                budget_ = nullptr;
            }
        }

    private:
        friend class StreamBudget;
        Lease(StreamBudget* budget, std::string principal)
            : budget_(budget), principal_(std::move(principal)) {}

        StreamBudget* budget_ = nullptr;
        std::string principal_;
    };

    struct AcquireResult {
        Lease lease;                          ///< engaged iff admitted
        const char* reject_reason = nullptr;  ///< set iff rejected; a static literal, safe to
                                              ///< use as a bounded metric label value
    };

    /// Reject reasons — a CLOSED set (bounded `yuzu_mcp_stream_rejects_total{reason}`
    /// cardinality; never derive a label from caller-controlled input).
    static constexpr const char* kRejectPerPrincipal = "per_principal_stream_cap";
    static constexpr const char* kRejectGlobal = "global_stream_cap";

    enum class Admission {
        kEnforceCaps,  ///< a NEW stream: subject to both caps
        kTakeover,     ///< replaces a stream this principal already holds
    };

    /// A takeover is admitted without a cap check but STILL TAKES A LEASE. It is not
    /// a new stream — it replaces one the principal already has — and refusing it
    /// would lock a reconnecting client out behind its own not-yet-reaped zombie
    /// stream. It must still be counted, because the superseded provider goes on
    /// pinning its worker until it drains; an uncounted pinned worker is precisely
    /// the hole this budget exists to close. The resulting overshoot is bounded by
    /// `kMaxProvidersPerStream`, which `derive_stream_budget` reserves for.
    AcquireResult try_acquire(const std::string& principal,
                              Admission mode = Admission::kEnforceCaps) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = per_principal_.find(principal);
        const std::size_t held = it == per_principal_.end() ? 0 : it->second;
        if (mode == Admission::kEnforceCaps) {
            if (total_ >= cfg_.global_cap) {
                return {Lease{}, kRejectGlobal};
            }
            if (held >= cfg_.per_principal_cap) {
                return {Lease{}, kRejectPerPrincipal};
            }
        }
        // Insert BEFORE bumping the total: the map insert allocates (a node plus a string
        // copy) and can throw, and a throw after `++total_` would leak a global slot for
        // the life of the process — a cap that silently tightens every time the machine is
        // under memory pressure.
        per_principal_[principal] = held + 1;
        ++total_;
        return {Lease{this, principal}, nullptr};
    }

    std::size_t active() const {
        std::lock_guard<std::mutex> lk(mu_);
        return total_;
    }

    std::size_t active_for(const std::string& principal) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = per_principal_.find(principal);
        return it == per_principal_.end() ? 0 : it->second;
    }

    Config config() const { return cfg_; }

private:
    void release_slot(const std::string& principal) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = per_principal_.find(principal);
        if (it == per_principal_.end()) {
            return;  // defensive: a lease is only minted through try_acquire
        }
        if (--it->second == 0) {
            // Erase at zero so the map is bounded by LIVE principals, not by every
            // principal that ever streamed (Decision 15(d): all in-memory state bounded).
            per_principal_.erase(it);
        }
        if (total_ > 0) {
            --total_;
        }
    }

    mutable std::mutex mu_;
    Config cfg_;
    std::size_t total_ = 0;
    std::unordered_map<std::string, std::size_t> per_principal_;
};

}  // namespace yuzu::server::detail
