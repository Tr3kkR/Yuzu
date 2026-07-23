#pragma once

/// @file principal_quota.hpp
///
/// In-memory, thread-safe per-principal quota primitive (PR 4.4, ADR-1005
/// class engine principals — per-principal quota cap). Mirrors the token-
/// bucket idiom of `rate_limiter.hpp` (per-IP) and the already-shipped
/// per-principal cap in `mcp_session.hpp` (`per_principal_cap`), but folds
/// TWO dimensions — concurrency (in-flight reservation) and rate (token
/// bucket) — behind one `try_acquire()` call so callers get a single
/// admit/reject decision instead of composing two primitives by hand.
///
/// CAVEAT — per-instance only: this cap lives in one process's memory. A
/// multi-instance deployment (N server replicas behind a load balancer)
/// gives each principal N × the configured cap, not a fleet-wide cap.
/// Durable, cross-instance quota (a shared store keyed by principal) is
/// deferred to Phase 8 and tracked there — do not treat this class as a
/// global enforcement point until that lands.
///
/// SSE / streaming note: a streaming response DOES take a concurrency slot
/// (every engine request does — see `apply_engine_quota_gate`), but the
/// naive post-routing release fires as soon as routing hands off to the
/// chunked/SSE body — long before the stream finishes. So a streaming
/// route must instead **adopt** the acquired slot into its content-provider
/// resource-releaser via `detail::adopt_quota_slot_into_stream`
/// (`principal_quota_gate.hpp`), which holds the reservation for the
/// stream's real lifetime and releases it on disconnect/completion. Do NOT
/// route streaming through `try_rate_only()` — that leaves the stream
/// concurrency-unbounded and reintroduces the UP-1 cross-principal
/// worker-pool DoS. `try_rate_only()` has no production caller today and is
/// retained only for the primitive's own tests. The single source of truth
/// for the streaming-route contract is `principal_quota_gate.hpp`
/// (`is_streaming_path` registry + `adopt_quota_slot_into_stream`).

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace yuzu::server {

/// Which side of a request is being debited. Phase 5: operator-side debit
/// under delegation (§5 step 6); dormant in 4.4 — every 4.4 caller passes
/// kEngine. The enum exists now so the wire/metric shape (QuotaDecision::side)
/// doesn't need to change again when Phase 5 lands.
enum class QuotaSide { kEngine, kOperator };

/// Which dimension a rejection came from (kNone when admitted).
enum class QuotaLimit { kNone, kConcurrency, kRate };

struct QuotaDecision {
    bool admitted{true};
    QuotaLimit limit{QuotaLimit::kNone};   // which dimension rejected (kNone if admitted)
    QuotaSide side{QuotaSide::kEngine};
    std::int64_t retry_after_ms{0};        // honest: rate -> bucket refill time; concurrency -> kConcurrencyRetryMs
};

class PrincipalQuota;

/// Move-only RAII reservation. On admit, holds one concurrency slot for the
/// principal that requested it and releases it on destruction (or on an
/// explicit `reset()`). On reject, holds nothing — `decision().admitted` is
/// false and the destructor is a no-op.
class QuotaSlot {
  public:
    QuotaSlot() = default;  // empty (holds nothing)

    QuotaSlot(QuotaSlot&& other) noexcept;
    QuotaSlot& operator=(QuotaSlot&& other) noexcept;

    QuotaSlot(const QuotaSlot&) = delete;
    QuotaSlot& operator=(const QuotaSlot&) = delete;

    /// Implicitly noexcept already (all subobjects have non-throwing dtors); spelled
    /// out so the guarantee is visible where callers reason about it.
    ~QuotaSlot() noexcept;

    bool admitted() const { return decision_.admitted; }
    const QuotaDecision& decision() const { return decision_; }

    /// Release the held concurrency slot early (if any). Idempotent — safe
    /// to call multiple times, and safe on an empty/rejected slot (no-op).
    ///
    /// `noexcept` is STRUCTURAL, not decorative (same rule as
    /// StreamBudget::Lease::release). This runs from ~QuotaSlot, which is itself
    /// noexcept, and ~QuotaSlot runs from an httplib content-provider releaser
    /// invoked by ~Response — so a throw escaping here is std::terminate and NO
    /// caller-side try/catch can intercept it: the terminate happens inside the
    /// destructor, before unwinding reaches any handler. The containment therefore
    /// has to live here, at the source, which is what makes it real.
    void reset() noexcept;

  private:
    friend class PrincipalQuota;

    QuotaSlot(PrincipalQuota* owner, std::string principal_id, QuotaDecision decision)
        : owner_(owner), principal_id_(std::move(principal_id)), decision_(decision) {}

    // Borrowed, non-owning back-pointer to the PrincipalQuota that minted this
    // slot; non-null iff this slot holds a concurrency reservation. Lifetime
    // safety: `PrincipalQuota` is a `ServerImpl` member and `~ServerImpl()` runs
    // `stop()` — whose `web_thread_.join()` waits for httplib's `listen()` to
    // return, which only happens after `ThreadPool::shutdown()` has JOINED every
    // worker thread. A streaming slot adopted into a content-provider releaser
    // therefore always releases (on its worker thread) before `principal_quota_`
    // is destroyed. Never dereference `owner_` outside `release()` (which takes
    // `mu_`); a slot must not outlive its PrincipalQuota by construction.
    PrincipalQuota* owner_{nullptr};
    std::string principal_id_;
    QuotaDecision decision_{};
};

struct PrincipalQuotaConfig {
    int max_concurrency{16};               // per-principal in-flight cap
    double rate_per_second{20.0};          // per-principal token-bucket refill
    double burst{40.0};                    // bucket capacity
    std::int64_t idle_evict_seconds{300};  // purge_stale threshold
};

/// Thread-safe per-principal quota tracker. One mutex guards a
/// `principal_id -> PerPrincipal` map; a `QuotaSlot`'s destructor re-locks
/// and decrements `in_flight` for the principal it was minted against.
class PrincipalQuota {
  public:
    explicit PrincipalQuota(PrincipalQuotaConfig cfg = {});

    /// Named, documented retry hint for a concurrency rejection — there is
    /// no natural "when will a slot free up" estimate the way a token
    /// bucket has a refill time, so this is a fixed short backoff rather
    /// than a magic literal scattered at call sites.
    static constexpr std::int64_t kConcurrencyRetryMs = 250;

    /// Acquire covers BOTH dimensions in one call: debits the token bucket
    /// (rate) AND reserves a concurrency slot. Returns an admitted
    /// QuotaSlot (holding the concurrency reservation) or a rejected
    /// QuotaSlot carrying the QuotaDecision (limit=kRate or kConcurrency).
    ///
    /// Ordering (deliberate, so a reject never leaks state): concurrency is
    /// checked FIRST without mutating anything; only if there is headroom
    /// does the call debit the rate bucket; only if that succeeds does it
    /// reserve the concurrency slot. A rate reject therefore never reserves
    /// concurrency, and a concurrency-at-capacity reject never touches the
    /// rate bucket — every rejected call leaves per-principal state exactly
    /// as it was before the call.
    QuotaSlot try_acquire(const std::string& principal_id, QuotaSide side);

    /// Rate-only debit for streaming/long-poll paths that must NOT hold a
    /// concurrency slot (see the SSE note in the file header). Returns a
    /// QuotaDecision — never reserves or releases a concurrency slot.
    QuotaDecision try_rate_only(const std::string& principal_id, QuotaSide side);

    /// Purge principals idle for longer than `idle_evict_seconds`, as of
    /// `now_epoch_seconds`. A principal with a live in-flight reservation
    /// (in_flight > 0) is never purged, even if idle past the threshold —
    /// purging it would orphan the eventual QuotaSlot::release() into a
    /// freshly re-inserted entry.
    ///
    /// NO PRODUCTION CALLER as of the governance hardening round — parity
    /// with the also-unwired `RateLimiter::purge_stale()`. Deliberate, not
    /// an oversight: the map is bounded by the count of distinct
    /// authenticated engine principals (a small, operator-provisioned set —
    /// nothing an unauthenticated caller can inflate), so unbounded growth
    /// isn't the exposure an IP-keyed limiter would have. Wiring this to a
    /// periodic sweep is a reasonable follow-up once engine-principal counts
    /// are large enough for the map's steady-state memory to matter; when
    /// that lands, do NOT add it to `health_recompute_thread_` casually —
    /// that thread's sweep body is a shared serial budget with the
    /// security-relevant revocation sweep also on it (see the comment at
    /// its call site in server.cpp), so extending it needs SRE sign-off,
    /// not just a trivial call-site addition.
    void purge_stale(std::int64_t now_epoch_seconds);

    /// Number of tracked principals (for monitoring / tests).
    std::size_t principal_count() const;

    /// Test-only introspection: current in-flight count for a principal
    /// (0 if untracked).
    int in_flight(const std::string& principal_id) const;

  private:
    friend class QuotaSlot;

    struct PerPrincipal {
        int in_flight{0};
        double tokens{0.0};
        // UP-4: the token-bucket refill clock is std::chrono::steady_clock
        // (monotonic, immune to NTP steps/wall-clock adjustment) — NOT
        // system_clock. A wall-clock backward step would snap every
        // principal's bucket to `cfg_.burst` (rate-limit bypass window); a
        // forward step would silently stall refill for however long the
        // step was. last_seen (idle-eviction bookkeeping for purge_stale)
        // deliberately stays wall-clock — see purge_stale's doc comment.
        std::chrono::steady_clock::time_point last_refill{};
        double last_seen{0.0};  // epoch seconds (purge_stale's clock, unchanged)
    };

    // Caller holds mu_. Inserts a fresh, full-bucket entry on first sight.
    PerPrincipal& locate_locked(const std::string& principal_id,
                                std::chrono::steady_clock::time_point now);

    // Caller holds mu_. Refills `pp`'s bucket up to `cfg_.burst` for the
    // elapsed time since its last refill, then stamps last_refill := now.
    void refill_locked(PerPrincipal& pp, std::chrono::steady_clock::time_point now) const;

    // Called by QuotaSlot::reset()/~QuotaSlot(). Decrements in_flight for
    // `principal_id` if the principal is still tracked; a no-op if it has
    // since been purged (defensive — purge_stale already guards against
    // purging a live in-flight principal, so this should not happen in
    // practice).
    /// noexcept: called from QuotaSlot::reset(), which runs in destructors on
    /// httplib's response-teardown path. See QuotaSlot::reset's comment.
    void release(const std::string& principal_id) noexcept;

    PrincipalQuotaConfig cfg_;
    mutable std::mutex mu_;
    std::unordered_map<std::string, PerPrincipal> principals_;
};

}  // namespace yuzu::server
