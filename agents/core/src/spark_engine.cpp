/**
 * spark_engine.cpp — see spark_engine.hpp.
 *
 * Wheel design: a single timer thread scans the armed map for the earliest
 * scheduled deadline and condition-waits until it (or an arm/disarm/stop
 * nudge). Arm/disarm rates are low and armed counts are small (hundreds), so
 * the O(n) scan per wake is deliberately simpler and more robust than a heap
 * with lazy invalidation — revisit only if the resource gate says so.
 *
 * Lock discipline: per-type processing (which may do filesystem I/O for disk
 * reads) and ALL delivery run with mu_ released; state commits re-acquire mu_
 * and re-look-up by key, so a spark disarmed mid-flight is simply skipped.
 * Inline handlers therefore run on the wheel thread WITHOUT mu_ held — an
 * inline handler may safely call arm/disarm/stats.
 */

#include "spark_engine.hpp"

#include <yuzu/agent/guard_systemd.hpp> // valid_unit_name — pure, all-platform, shared with the guard

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <exception>
#include <iterator>
#include <optional>
#include <string_view>
#include <utility>
#include <variant>

namespace yuzu::agent {

namespace {

bool params_match_type(const SparkSpec& spec) {
    switch (spec.type) {
    case SparkType::Interval: return std::holds_alternative<IntervalSparkParams>(spec.params);
    case SparkType::Startup:  return std::holds_alternative<StartupSparkParams>(spec.params);
    case SparkType::Disk:     return std::holds_alternative<DiskSparkParams>(spec.params);
    case SparkType::File:     return std::holds_alternative<FileSparkParams>(spec.params);
    case SparkType::Service:  return std::holds_alternative<ServiceSparkParams>(spec.params);
    case SparkType::Registry: return std::holds_alternative<RegistrySparkParams>(spec.params);
    }
    return false;
}

// A message whose COMPLETION cannot allocate (#2270). Everything expensive happens
// in the constructor — which arm_impl runs BEFORE its first shared-state commit,
// where a throw is still harmless — so finish() can be noexcept:
//   * the prefix is assigned FIRST, then the buffer is pre-SIZED (not merely
//     reserved) to prefix + headroom. reserve() would be the wrong tool twice
//     over: a later assign() invalidates the reasoning, and capacity is not a
//     postcondition the standard carries across a move.
//   * finish() copies at most `headroom` bytes over elements that ALREADY EXIST
//     and then shrinks. Shrinking resize() erases in place on every implementation,
//     and its only specified Throws case (n > max_size()) is unreachable here. Note
//     that is a QoI fact, not a normative one: [string.require]/4 lists resize among
//     the reference-invalidating operations, so the standard does not FORBID a
//     reallocation on shrink — libstdc++, libc++ and MSVC STL all set the length in
//     place (cpp-expert, governance round 4).
// The suffix is therefore TRUNCATED rather than grown when it overruns the
// headroom. That is the deliberate trade: a clipped error message beats a
// std::bad_alloc thrown past a committed subscription.
constexpr std::size_t kErrHeadroom = 256;
constexpr std::string_view kWatchThrewPrefix = "watch mechanism threw: ";
constexpr std::string_view kWatchThrewNonStd = "a non-std exception";

class BoundedMsg {
public:
    BoundedMsg() = default;
    explicit BoundedMsg(std::string_view prefix, std::size_t headroom = kErrHeadroom)
        : buf_(prefix.size() + headroom, '\0'), prefix_(prefix.size()) {
        // Sized-then-filled, so this really is ONE allocation. Constructing from the
        // prefix and then resize()ing measured TWO whenever the prefix exceeded the
        // SSO threshold, which both production prefixes do.
        // Same null-data() guard as finish(): an empty string_view has a null data(),
        // and libc++ reaches __builtin_memmove(dst, nullptr, 0) where libstdc++
        // short-circuits. Unreachable today — every ctor site passes a non-empty
        // literal — but the guard belongs on both copies or on neither, and the round
        // that added it to finish() left this one exposed (Gate 8, cs8-2).
        if (!prefix.empty())
            std::copy_n(prefix.data(), prefix.size(), buf_.data());
    }
    /// NON-COPYABLE by construction: a copy would allocate prefix_ + headroom, which
    /// is precisely the cost this class exists to keep out of the post-commit window.
    /// Nothing copies one today (Replay is nothrow-move-constructible so vector growth
    /// moves), but a future throwing-move member of Replay would flip move_if_noexcept
    /// to copy silently. Same tripwire idiom as the static_asserts in the header.
    BoundedMsg(const BoundedMsg&) = delete;
    BoundedMsg& operator=(const BoundedMsg&) = delete;
    BoundedMsg(BoundedMsg&&) noexcept = default;
    BoundedMsg& operator=(BoundedMsg&&) noexcept = default;
    /// Complete the message with as much of `text` as the headroom holds, and
    /// hand it over. Allocates nothing; the returned string is moved out.
    /// [[nodiscard]] because discarding the result silently empties the buffer.
    [[nodiscard]] std::string finish(std::string_view text) noexcept {
        if (buf_.size() >= prefix_) {
            const std::size_t n = std::min(buf_.size() - prefix_, text.size());
            // Guard the zero case: an empty string_view has a null data(), and while
            // libstdc++ short-circuits copy_n on n == 0, libc++ reaches
            // __builtin_memmove(dst, nullptr, 0) which UBSan's nonnull-attribute
            // reports. macOS is the leg nobody has compiled, so take the branch.
            if (n != 0)
                std::copy_n(text.data(), n, buf_.data() + prefix_);
            buf_.resize(prefix_ + n);
        }
        return std::move(buf_);
    }

private:
    std::string buf_;
    std::size_t prefix_{0};
};

// Call a mechanism's watch() and convert an escaping throw into a returned
// std::unexpected. A mechanism MUST report failure by returning std::unexpected,
// but the real ones can throw (spark_file's watch() → fs::current_path() on a
// relative path). BOTH arm paths — the live arm_impl and the pre-start replay in
// start() — route through here so the exception boundary and its message text
// live in exactly one place and cannot drift apart (#2019 review). Each caller
// keeps its OWN failure handling: arm_impl rolls the whole key back; the replay
// faults in place (its subscribers already hold ids).
//
// #2270: error DELIVERY is non-throwing by construction. The caller passes a
// BoundedMsg built before its own commit; completing it here cannot allocate. The
// concat this used to do was the defect: it ran INSIDE the catch handler, so a
// bad_alloc there escaped watch_guarded and both its callers — past arm_impl's
// committed subscription (the ghost key), and out of the void start(). The hook
// call and the completion are contained anyway, so no exception from this block
// can reach a caller by any route.
[[nodiscard]] std::expected<void, std::string>
watch_guarded(ISparkMechanism* mech, const std::string& key, const SparkParams& params,
              BoundedMsg& err, const std::function<void(int)>& fault_hook) {
    try {
        return mech->watch(key, params);
    } catch (const std::exception& e) {
        try {
            if (fault_hook)
                fault_hook(SparkEngine::kArmFaultPhaseWatchErrorBuild);
            return std::unexpected(err.finish(e.what()));
        } catch (...) {
            return std::unexpected(err.finish(std::string_view{}));
        }
    } catch (...) {
        try {
            if (fault_hook)
                fault_hook(SparkEngine::kArmFaultPhaseWatchErrorBuild);
            return std::unexpected(err.finish(kWatchThrewNonStd));
        } catch (...) {
            return std::unexpected(err.finish(std::string_view{}));
        }
    }
}

/// #2815: RAII lease over one pass through a post-mu_ mechanism-call window.
///
/// ARM IT AS THE LAST STATEMENT OF THE mu_ BLOCK THAT RESOLVES THE MECHANISM, and let
/// it live to the end of the enclosing FUNCTION - not merely until unwatch() returns.
/// Both halves are load-bearing:
///   * "last statement under mu_" - arming earlier is harmless, but anything after it
///     inside the lock that could throw would run this destructor while mu_ is still
///     held. The destructor takes no lock, so that is not a deadlock today; keeping the
///     arm last means it never becomes one.
///   * "to the end of the function" - the window does not close when the mechanism call
///     does. disarm()'s own catch touches disarm_unwatch_failures_ AFTER unwatch()
///     throws, and unregister_consumer() runs on into quiesce_consumer(), which reads
///     consumer_join_budget_ms_ and consumer_threads_detached_. Releasing at the
///     mechanism call would leave both of those outside the barrier.
///
/// Everything here is noexcept: this is destroyed on the door caller's thread during
/// ordinary return AND during exception unwind, and an observe-only subsystem must
/// never be the reason the agent terminates.
class TeardownLease {
public:
    explicit TeardownLease(std::atomic<std::uint64_t>& count) noexcept : count_(&count) {}
    ~TeardownLease() { release(); }
    TeardownLease(const TeardownLease&) = delete;
    TeardownLease& operator=(const TeardownLease&) = delete;

    /// Caller holds mu_.
    void arm_locked() noexcept {
        count_->fetch_add(1, std::memory_order_relaxed);
        armed_ = true;
    }

private:
    void release() noexcept {
        if (!armed_)
            return;
        armed_ = false;
        // RELEASE ordering: a waiter that observes zero via an ACQUIRE load has
        // happens-before over every engine access this caller made in the window.
        count_->fetch_sub(1, std::memory_order_acq_rel);
    }
    std::atomic<std::uint64_t>* count_;
    bool armed_{false};
};

/// Wait until no caller is inside a teardown window, or `budget` elapses.
/// Returns true if the lease drained, false on expiry. See the member's doc in
/// spark_engine.hpp for why this polls rather than waiting on a condition_variable.
bool wait_teardown_leases(const std::atomic<std::uint64_t>& count,
                          std::chrono::milliseconds budget) noexcept {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    for (;;) {
        if (count.load(std::memory_order_acquire) == 0)
            return true;
        if (std::chrono::steady_clock::now() >= deadline)
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

/// The UNBOUNDED counterpart, for ~SparkEngine only. A caller that never returns turns
/// what used to be a silent use-after-free into a visible hang, which is the trade this
/// fix deliberately makes. Dormant in the shipped agent: main.cpp's OrphanExitGuard
/// hard_exit()s while any Guardian I/O worker is still live, long before ~Agent - so a
/// wedged worker terminates the process there, not here.
void wait_teardown_leases_forever(const std::atomic<std::uint64_t>& count) noexcept {
    while (count.load(std::memory_order_acquire) != 0)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
}

} // namespace

bool SparkEngine::is_event_driven(SparkType type) noexcept {
    return type == SparkType::File || type == SparkType::Service ||
           type == SparkType::Registry;
}

SparkEngine::SparkEngine() = default;

SparkEngine::~SparkEngine() {
    stop();
    // #2815: THE fix. stop()'s own wait is bounded and may have given up; nothing else
    // in this destructor may run until every caller has left a teardown window, because
    // the very next thing that happens is the destruction of the members those callers
    // still hold (mech_ops_mu_by_type_, mechanisms_, consumers_). Last statement of the
    // body on purpose - member destructors run only once this returns.
    wait_teardown_leases_forever(inflight_teardowns_);
}

// ── Mechanisms ────────────────────────────────────────────────────────────────

std::expected<void, std::string>
SparkEngine::register_mechanism(SparkType type, std::unique_ptr<ISparkMechanism> mechanism) {
    if (!mechanism)
        return std::unexpected("mechanism must not be null");
    if (!is_event_driven(type))
        return std::unexpected(std::string("spark type '") + spark_type_token(type) +
                               "' is timer-driven — the wheel services it, it has no mechanism");
    // lifecycle_mu_ before mu_ (see the header's LOCK ORDER note). This is the ONLY
    // writer of mechanisms_; holding it here is what lets stop() iterate the map
    // without mu_ even while the main thread is still registering during boot and the
    // SCM control thread calls Agent::stop() (Gate-4 UP-1).
    std::lock_guard life(lifecycle_mu_);
    std::lock_guard lk(mu_);
    if (running_ || stopped_)
        return std::unexpected("mechanisms must be registered before start()");
    // Populate the per-type mech-ops lock FIRST, then mechanisms_ — both under
    // the same mu_ so they stay in lockstep (#2011). Order matters for the
    // .at()-can't-throw invariant every call site relies on: if the second
    // try_emplace throws std::bad_alloc, the surviving state must never be
    // "mechanisms_ has the type but mech_ops_mu_by_type_ does not" (which would
    // make a later arm/disarm reach .at(type) → std::out_of_range on a live
    // path). Emplacing the lock first means a throw leaves at most an unused
    // mutex entry for a type with no mechanism — harmless, since arm() of a
    // type with no mechanism is rejected before any .at() (cpp-safety Gate 3).
    mech_ops_mu_by_type_.try_emplace(type);
    auto [it, inserted] = mechanisms_.try_emplace(type, std::move(mechanism));
    if (!inserted)
        return std::unexpected(std::string("a mechanism is already registered for spark type '") +
                               spark_type_token(type) + "'");
    return {};
}

// ── Consumers ─────────────────────────────────────────────────────────────────

std::expected<SparkEngine::ConsumerId, std::string>
SparkEngine::register_consumer(std::string name, QueuedHandler handler, std::size_t queue_cap) {
    if (!handler)
        return std::unexpected("consumer handler must not be null");
    if (name.empty())
        return std::unexpected("consumer name must not be empty");
    if (queue_cap == 0)
        return std::unexpected("consumer queue_cap must be > 0");

    ConsumerId id = 0;
    {
        std::lock_guard lk(mu_);
        if (stopped_)
            return std::unexpected("engine is stopped");
        id = next_id_++;
    }
    auto consumer = std::make_shared<Consumer>();
    consumer->name = std::move(name);
    consumer->handler = std::move(handler);
    consumer->cap = queue_cap;
    // Capture only the two shared_ptrs, NEVER `this`: the thread may be detached
    // at shutdown (UP-1) and outlive the engine, so it must not dereference it.
    consumer->thread = std::thread(&SparkEngine::consumer_loop, consumer, delivery_);
    // Test seam: lets a test deterministically force stop() to run exactly
    // here — the un-synchronized window this function's own re-check below
    // exists to close — instead of relying on a flaky multi-threaded race.
    if (register_race_hook_for_test_)
        register_race_hook_for_test_();
    bool inserted = false;
    // Captures an emplace() throw (e.g. bad_alloc) rather than letting it
    // propagate straight out of the locked block: `consumer` going out of
    // scope with its thread still joinable would call std::terminate before
    // this function's caller ever sees the exception (Sol rung-7.5 review
    // finding 2). Quiesced + rethrown below, OUTSIDE consumers_mu_.
    std::exception_ptr emplace_exception;
    {
        std::lock_guard lk(consumers_mu_);
        // Re-check: stop() can land between the stopped_ check above and this
        // insert. stop() sets stopped_ (under mu_) and later swaps consumers_
        // out (under consumers_mu_) without ever seeing an entry inserted after
        // its swap — nobody signals the thread just started above, and the
        // un-joined joinable std::thread inside its shared_ptr<Consumer>
        // terminates the process at destruction. That breaks this header's own
        // "register safe from any thread" contract (governance Tr3kkR finding,
        // PR #1927 review).
        if (!stopped_) {
            try {
                consumers_.emplace(id, consumer);
                inserted = true;
            } catch (...) {
                emplace_exception = std::current_exception();
            }
        }
    }
    if (emplace_exception) {
        quiesce_consumer(consumer);
        std::rethrow_exception(emplace_exception);
    }
    if (!inserted) {
        // Lost the race: quiesce the just-started thread ourselves, exactly as
        // stop() would have, before reporting failure — OUTSIDE consumers_mu_.
        // quiesce_consumer's bounded join may block up to
        // consumer_join_budget_ms_; every other consumers_mu_ site (arm,
        // unregister_consumer, emit_event's dispatch, stats, and a
        // concurrently running real stop()'s own swap) must never stall
        // behind it — mirrors disarm()'s and stop()'s own "release the lock
        // before anything that may block" discipline (governance cpp-expert /
        // cpp-safety finding, PR #1927 review).
        quiesce_consumer(consumer);
        return std::unexpected("engine is stopped");
    }
    return id;
}

void SparkEngine::unregister_consumer(ConsumerId id) {
    // 1) Take the consumer out of the fan-out map FIRST, before scanning
    // armed_ for its subscriptions. LOAD-BEARING ordering for the M1
    // ghost-subscription fix (#1994): arm()'s consumer-existence pre-check
    // (consumers_mu_) and arm_impl()'s armed_ insert (mu_) are two different
    // critical sections a concurrent unregister_consumer() can land between.
    // arm_impl() closes its half of the race with a re-check AFTER the insert
    // that rolls back on a lost race (see arm_impl below) — but that re-check
    // is only airtight if THIS function's consumers_ erase always
    // happens-before its own armed_ scan. With the erase first: any insert
    // that lands before our armed_ scan is caught by the scan itself; any
    // insert that lands after our armed_ scan must also land after our erase
    // (same-thread program order), so arm_impl's re-check — which always runs
    // after its insert — observes the consumer already gone and rolls back.
    // A ghost would require our scan to miss the sub (scan-before-insert) AND
    // arm_impl's re-check to see the consumer as present (re-check-before-
    // erase) — impossible once erase precedes scan, since that would need
    // erase < scan < insert < re-check < erase (self-contradictory).
    std::shared_ptr<Consumer> consumer;
    {
        std::lock_guard lk(consumers_mu_);
        auto it = consumers_.find(id);
        if (it == consumers_.end())
            return;
        consumer = std::move(it->second);
        consumers_.erase(it);
    }

    // 2) Remove the consumer's subscriptions so no new events are enqueued.
    // Collect (mechanism, key) pairs for any watch that goes fully
    // unsubscribed as a result, so they can be unwatch()'d with mu_ released
    // below — mirrors disarm()'s pattern exactly. Erasing armed_ without this
    // leaves the mechanism's OS watch (IOCP directory registration / registry
    // TP_WAIT / SCM notification) live for a spark the engine no longer
    // considers armed: emit_event() finds no armed_ entry and drops the
    // firings, the handle accumulates until engine stop(), and
    // stats().armed_sparks undercounts what the OS is actually watching
    // (governance Tr3kkR finding, PR #1927 review).
    struct PendingUnwatch {
        ISparkMechanism* mech;
        std::string key;
        SparkType type; // picks this type's mech-ops lock at consumption
    };
    std::vector<PendingUnwatch> to_unwatch;
    // #2815 door 3/4. Armed UNCONDITIONALLY below (not only when to_unwatch is
    // non-empty): this function continues past its mechanism calls into
    // quiesce_consumer(), which reads consumer_join_budget_ms_ and writes
    // consumer_threads_detached_ - engine members, so the window this lease covers is
    // the whole function tail either way.
    TeardownLease lease(inflight_teardowns_);
    {
        std::lock_guard lk(mu_);
        for (auto it = armed_.begin(); it != armed_.end();) {
            auto& subs = it->second.subs;
            std::erase_if(subs, [&](const Subscriber& s) {
                if (s.tier == SparkTier::Queued && s.consumer == id) {
                    sub_keys_.erase(s.id);
                    return true;
                }
                return false;
            });
            if (subs.empty()) {
                // Same running_-gated pattern as disarm(): a pre-start or
                // post-stop unregister has no watch to drop.
                if (running_ && is_event_driven(it->second.spec.type)) {
                    auto mit = mechanisms_.find(it->second.spec.type);
                    if (mit != mechanisms_.end())
                        to_unwatch.push_back({mit->second.get(), it->first, it->second.spec.type});
                }
                it = armed_.erase(it);
            } else {
                ++it;
            }
        }
        // #2815: LAST statement under mu_, and after the collection loop has finished -
        // one lease per door-call, never a token per queued item. The loop can itself
        // throw part-way (std::erase_if, the to_unwatch push_back); arming after it
        // means a partial collection unwinds with nothing to balance.
        lease.arm_locked();
    }
    // Stop watching with mu_ RELEASED (unwatch may block; a racing inline emit
    // takes mu_) — mirrors disarm(). Serialized via this type's
    // mech_ops_mu_by_type_ entry with a staleness re-check immediately before
    // each call (#1994 M2): a concurrent re-arm of an equal spec may have
    // already renewed this key between our erase above and here, in which case
    // this unwatch is stale and must be skipped rather than tearing down the
    // fresh watch.
    for (auto& pu : to_unwatch) {
        // Hook fires BEFORE the mech-ops lock is taken (never while held) — see
        // disarm()'s identical placement rationale.
        if (disarm_race_hook_for_test_)
            disarm_race_hook_for_test_();
        std::lock_guard ops(mech_ops_mu_by_type_.at(pu.type));
        {
            std::lock_guard lk(mu_);
            if (armed_.contains(pu.key))
                continue; // a concurrent re-arm already renewed this key
        }
        pu.mech->unwatch(pu.key);
    }

    // 3) Bounded-join (or detach) its dispatch thread.
    quiesce_consumer(consumer);
}

void SparkEngine::signal_stop(const std::shared_ptr<Consumer>& consumer) {
    {
        std::lock_guard lk(consumer->mu);
        consumer->stopping = true;
    }
    consumer->cv.notify_all();
}

void SparkEngine::await_consumer(const std::shared_ptr<Consumer>& consumer,
                                 std::chrono::steady_clock::time_point deadline) {
    // Bound the join against a shared deadline: a queued handler is explicitly
    // permitted to block (network / plugin I/O), so a hung one must not hang
    // shutdown (UP-1 / #1311). A SHARED deadline (not a fresh per-consumer
    // budget) keeps N hung consumers to ~1×budget total, not N×budget (UP2-3).
    // On expiry DETACH — safe because the thread captured only its own
    // shared_ptr<Consumer> + shared_ptr<DeliveryCounters>, never the engine.
    bool finished = false;
    {
        std::unique_lock lk(consumer->done_mu);
        finished = consumer->done_cv.wait_until(lk, deadline, [&] { return consumer->finished; });
    }
    if (!consumer->thread.joinable())
        return;
    if (finished) {
        consumer->thread.join();
    } else {
        consumer->thread.detach();
        consumer_threads_detached_.fetch_add(1, std::memory_order_relaxed);
        spdlog::warn("SparkEngine: consumer '{}' handler did not finish within budget — detached "
                     "(shutdown not blocked)",
                     consumer->name);
    }
}

void SparkEngine::quiesce_consumer(const std::shared_ptr<Consumer>& consumer) {
    signal_stop(consumer);
    await_consumer(consumer, std::chrono::steady_clock::now() + std::chrono::milliseconds(
                                 consumer_join_budget_ms_.load(std::memory_order_relaxed)));
}

void SparkEngine::consumer_loop(std::shared_ptr<Consumer> consumer,
                                std::shared_ptr<DeliveryCounters> counters) {
    for (;;) {
        SparkEvent ev;
        {
            std::unique_lock lk(consumer->mu);
            consumer->cv.wait(lk, [&] { return consumer->stopping || !consumer->queue.empty(); });
            if (consumer->stopping) {
                // Prompt shutdown: whatever is still queued is dropped + counted
                // rather than delivered late into a tearing-down agent.
                counters->dropped.fetch_add(consumer->queue.size(), std::memory_order_relaxed);
                consumer->queue.clear();
                break;
            }
            ev = std::move(consumer->queue.front());
            consumer->queue.pop_front();
        }
        try {
            consumer->handler(ev);
            counters->delivered.fetch_add(1, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            counters->errors.fetch_add(1, std::memory_order_relaxed);
            spdlog::warn("SparkEngine: consumer '{}' handler threw on spark '{}': {}",
                         consumer->name, ev.key, e.what());
        } catch (...) {
            counters->errors.fetch_add(1, std::memory_order_relaxed);
            spdlog::warn("SparkEngine: consumer '{}' handler threw on spark '{}'", consumer->name,
                         ev.key);
        }
    }
    // Signal clean exit so a bounded quiesce_consumer join succeeds (vs detach).
    {
        std::lock_guard lk(consumer->done_mu);
        consumer->finished = true;
    }
    consumer->done_cv.notify_all();
}

// ── Arming ────────────────────────────────────────────────────────────────────

std::expected<std::uint64_t, std::string>
SparkEngine::validate_and_floor(const SparkSpec& spec) const {
    if (!params_match_type(spec))
        return std::unexpected(std::string("spark params do not match type '") +
                               spark_type_token(spec.type) + "'");
    switch (spec.type) {
    case SparkType::Interval: {
        const auto& p = std::get<IntervalSparkParams>(spec.params);
        const std::uint64_t floor = cadence_floor_ms_.load(std::memory_order_relaxed);
        const std::uint64_t eff = std::max(p.interval_ms, floor);
        if (eff != p.interval_ms)
            spdlog::warn("SparkEngine: interval {}ms below the {}ms floor — clamped",
                         p.interval_ms, floor);
        return eff;
    }
    case SparkType::Startup:
        return 0;
    case SparkType::Disk: {
        const auto& p = std::get<DiskSparkParams>(spec.params);
        if (p.path.empty())
            return std::unexpected("disk spark: path must not be empty");
        if (p.used_pct_threshold == 0 || p.used_pct_threshold > 100)
            return std::unexpected("disk spark: used_pct_threshold must be 1..100");
        const std::uint64_t floor = cadence_floor_ms_.load(std::memory_order_relaxed);
        const std::uint64_t eff = std::max(p.poll_ms, floor);
        if (eff != p.poll_ms)
            spdlog::warn("SparkEngine: disk poll {}ms below the {}ms floor — clamped", p.poll_ms,
                         floor);
        return eff;
    }
    case SparkType::File: {
        const auto& p = std::get<FileSparkParams>(spec.params);
        if (p.path.empty())
            return std::unexpected("file spark: path must not be empty");
        return 0; // event-driven: no wheel cadence
    }
    case SparkType::Registry: {
        const auto& p = std::get<RegistrySparkParams>(spec.params);
        if (p.hive != "HKLM" && p.hive != "HKCU" && p.hive != "HKCR" && p.hive != "HKU")
            return std::unexpected("registry spark: hive must be one of HKLM/HKCU/HKCR/HKU");
        if (p.key.empty())
            return std::unexpected("registry spark: key must not be empty");
        return 0; // event-driven: no wheel cadence
    }
    case SparkType::Service: {
        const auto& p = std::get<ServiceSparkParams>(spec.params);
        if (!valid_unit_name(p.service_name))
            return std::unexpected("service spark: name must be non-empty, <=256 chars, "
                                   "alphanumeric plus . _ - @");
        return 0; // event-driven: no wheel cadence
    }
    }
    return std::unexpected("unknown spark type");
}

std::chrono::steady_clock::time_point
SparkEngine::initial_due(const SparkSpec& spec, std::uint64_t cadence_ms,
                         std::chrono::steady_clock::time_point now) const {
    switch (spec.type) {
    case SparkType::Startup:
        return now; // fire as soon as the wheel runs
    case SparkType::Disk:
        // Early first reading, but timer-driven — never at-arm (macOS lesson).
        return now + std::chrono::milliseconds(std::min(cadence_ms, kFirstDiskPollCapMs));
    default:
        return now + std::chrono::milliseconds(cadence_ms);
    }
}

std::expected<SparkEngine::SubscriptionId, std::string> SparkEngine::arm(ConsumerId consumer,
                                                                         SparkSpec spec) {
    {
        std::lock_guard lk(consumers_mu_);
        if (!consumers_.contains(consumer))
            return std::unexpected("unknown consumer id");
    }
    // The FIRST half of the M1 window (#1994) — pre-check passed, nothing inserted
    // yet. No locks held. See the seam's header doc for why arm_race_hook_for_test_
    // cannot reach the same interleaving.
    if (arm_precheck_race_hook_for_test_)
        arm_precheck_race_hook_for_test_();
    Subscriber sub;
    sub.tier = SparkTier::Queued;
    sub.consumer = consumer;
    return arm_impl(std::move(spec), std::move(sub));
}

std::expected<SparkEngine::SubscriptionId, std::string>
SparkEngine::arm_inline(SparkSpec spec, InlineHandler handler) {
    if (!handler)
        return std::unexpected("inline handler must not be null");
    Subscriber sub;
    sub.tier = SparkTier::Inline;
    sub.inline_fn = std::move(handler);
    return arm_impl(std::move(spec), std::move(sub));
}

std::expected<SparkEngine::SubscriptionId, std::string> SparkEngine::arm_impl(SparkSpec spec,
                                                                              Subscriber sub) {
    const auto cadence = validate_and_floor(spec);
    if (!cadence)
        return std::unexpected(cadence.error());
    const std::string key = spark_key(spec);
    const bool event_driven = is_event_driven(spec.type);
    // Saved before `sub` is moved into armed_.subs below — needed for the
    // post-insert consumer re-check (#1994 M1, Queued tier only).
    const SparkTier tier = sub.tier;
    const ConsumerId consumer_id = sub.consumer;

    // Set to the mechanism + params only when a NEW event-driven watch must be
    // armed live (a fresh key on a running engine). Deferred/deduped arms and
    // all timer-driven arms leave it null.
    // #2270 — arm_impl is STRONG-GUARANTEE against std::bad_alloc. The old order
    // inserted into armed_ and then kept allocating (spec copy, sub_keys_ node,
    // subs growth, the log line), so a throw part-way left a GHOST key: an armed_
    // entry with no subscriber and no watcher. A later equal-spec arm deduped onto
    // it (inserted == false), skipped watch_guarded(), and reported SUCCESS with no
    // OS watcher running — silent, durable detection loss that outlived the memory
    // pressure. Two layers close it:
    //   (1) inside mu_: every allocation happens BEFORE the first shared-state
    //       commit, the one remaining allocating commit is try/caught, and the tail
    //       that publishes the subscription cannot throw (pinned by static_assert).
    //       Note the in-lock rollback also unpublishes nothing: the publish tail runs
    //       AFTER the last allocating step, so there is nothing committed to undo.
    //   (2) past the commit: NO ALLOCATION FAILURE CAN ESCAPE. Every string a
    //       post-commit path can return is built below, before the commit, and only
    //       moved afterwards; watch_guarded() completes its error into a pre-sized
    //       buffer; the consumer-race teardown is a specialization of disarm() that
    //       copies nothing. Read that precisely - it is NOT "the window never
    //       allocates": the log lines in it still format into heap buffers. It is
    //       that every remaining allocating statement sits inside a catch-all, so a
    //       bad_alloc from one costs a log line and nothing else.
    //       COVERAGE, STATED EXACTLY, because the blanket version of this sentence was
    //       false: tests/unit/test_spark_alloc_budget.cpp counts this window with the
    //       logger silenced for the FAILED-WATCH, DEDUP and fresh-SUCCESS shapes. The
    //       pre-start/timer and teardown_arm_race shapes are covered by inspection
    //       only (#2816). An adversarial reviewer disproved the earlier unqualified
    //       "pinned by" wording by inserting an allocation on the success path and
    //       watching the budget binary pass green - do not restore a blanket claim
    //       here without a counted case behind every shape.
    //
    // There is deliberately NO post-commit rollback. An earlier revision had one and
    // it was a net negative: across two review rounds it shipped a wrong branch
    // predicate (it deleted healthy sibling subscriptions and orphaned live OS
    // watches on the deduped, timer and pre-start shapes), then a TOCTOU whose
    // converse re-created the very ghost this fix exists to close - a rollback
    // running with no locks held, after an unwind window, cannot reliably decide
    // what it is allowed to undo. Layer (2) removes the need for one: the round that
    // deleted the rollback claimed the log line was the only thing left that could
    // throw, and that was FALSE - the error concat inside watch_guarded's catch
    // handler reproduced the ghost on demand.
    //
    // RESIDUALS, stated rather than papered over. Layer (2) is about ALLOCATION
    // failure; two other things past the commit can still throw out of this function:
    //   * a std::system_error from acquiring mech_ops_mu_by_type_ or consumers_mu_.
    //     std::mutex::lock throws only on EDEADLK/EINVAL/EAGAIN - a process-is-broken
    //     condition, not the memory pressure #2270 is about - and recovering from it
    //     is what the rollback failed twice to do safely. Out of scope here.
    //   * arm_race_hook_for_test_ below, which exists to inject exactly such a throw.
    //     (The seam inside watch_guarded is contained there and cannot escape.)
    // And one that does NOT escape but is not repaired either: a throwing mechanism
    // unwatch() during the consumer-race teardown leaves an orphaned OS watch.
    // Reclamation is mechanism-dependent, not simply OS-dependent: a File watch
    // (Windows-only mechanism) is never reclaimed short of a process restart; a
    // Service watch (Linux or Windows) is reclaimed the next time stop() runs; a
    // Registry watch (Windows-only mechanism) cannot fail this way at all. Contained
    // and counted as stats().arm_race_unwatch_failures_total, and surfaced as a
    // sparse heartbeat tag; teardown_arm_race carries the per-mechanism bound and the
    // reason repairing it is not attempted.
    ISparkMechanism* mech = nullptr;
    SparkParams watch_params;
    SubscriptionId id = 0;
    // #2815 door 4/4 - the one the original design missed. This is not a TEARDOWN, but
    // it is the same window: `mech` and mech_ops_mu_by_type_.at(spec.type) are resolved
    // under mu_ and then used with mu_ RELEASED, so ~SparkEngine freeing those members
    // mid-watch is the same use-after-free. The lease also covers the M1 consumer
    // re-check and teardown_arm_race() call in this function's tail, which read
    // consumers_mu_/consumers_.
    TeardownLease lease(inflight_teardowns_);

    // ── pre-built returns (#2270 layer 2) ─────────────────────────────────────────
    // Built here, where a throw unwinds a still-untouched engine, and only MOVED
    // after the commit. Building them later - inside a catch handler, or on a return
    // path - is the defect this replaces: it puts an allocation in a window where a
    // bad_alloc strands a live subscription. (next_id_ having advanced is not state a
    // caller can observe; skipping an id is unobservable.)
    //
    // All of it happens BEFORE mu_ is taken. An earlier revision built the three
    // watch-related carriers inside the lock, where the fresh-event-driven shape is
    // known — but that put three allocations under the one mutex that also serialises
    // disarm(), emit_event dispatch and every other arm(), on the ordinary success
    // path, to save work only a failing arm needs (governance round 4, happy-path
    // HP-1 + sre). `event_driven` is known here, so the shape test that matters is
    // available without the lock. Four shapes now build carriers they will not use:
    // a deduped event-driven arm; a PRE-START event-driven arm (which previously built
    // nothing, since the build sat inside `if (running_)`); and an arm rejected inside
    // the lock, either for `stopped_` or for an unsupported type - two shapes. All are bounded, per-call, and off
    // the mutex, which is the cheaper side of the trade (Gate 8 - SRE8-4).
    std::string consumer_race_msg;
    std::string disarmed_mid_arm_msg;
    BoundedMsg watch_threw_msg;
    BoundedMsg watch_fail_msg;
    if (tier == SparkTier::Queued)
        consumer_race_msg = "consumer unregistered during arm";
    if (event_driven) {
        disarmed_mid_arm_msg = "spark '" + key + "' was disarmed before its watch could be armed";
        watch_threw_msg = BoundedMsg(kWatchThrewPrefix);
        watch_fail_msg = BoundedMsg("watch mechanism failed to arm '" + key + "': ");
    }

    {
        std::lock_guard lk(mu_);
        if (stopped_)
            return std::unexpected("engine is stopped");
        if (event_driven && !mechanisms_.contains(spec.type))
            // No watcher for this type on this platform → reject, rather than
            // arm without a watcher (spark.hpp: armed == a watcher is running).
            return std::unexpected(std::string("no watch mechanism for spark type '") +
                                   spark_type_token(spec.type) + "' — unsupported on this platform");
        sub.id = next_id_++;
        id = sub.id;

        // Everything that allocates for a BRAND-NEW key is built on this local, so a
        // throw here cannot touch armed_'s CONTENTS. One deliberate exception, below:
        // the dedup branch grows an existing entry's subs capacity before the commit,
        // which the catch does not undo — capacity only, no observable state change.
        Armed fresh;
        auto* existing = [&]() -> Armed* {
            auto it = armed_.find(key);
            return it == armed_.end() ? nullptr : &it->second;
        }();
        if (existing == nullptr) {
            fresh.spec = spec;
            fresh.cadence_ms = *cadence;
            if (event_driven) {
                // TRAP 1: event-driven sparks NEVER sit on the wheel — the wheel
                // scan + `default: continue` assume it. A live engine arms the
                // watch now (below, mu_ released); a pre-start arm is armed by
                // start()'s replay.
                fresh.scheduled = false;
                if (running_) {
                    mech = mechanisms_.at(spec.type).get();
                    watch_params = spec.params;
                    // The carriers this shape needs were built before the lock.
                }
            } else {
                fresh.scheduled = true;
                fresh.next_due =
                    initial_due(fresh.spec, fresh.cadence_ms, std::chrono::steady_clock::now());
            }
            fresh.subs.push_back(std::move(sub));
        } else {
            // Dedup: a second arm of an equal event-driven spec shares the existing
            // watcher — mech stays null, no second watch() (N subscriptions, 1
            // watcher). Reserve now (strong-guarantee: a throw leaves the vector
            // untouched) so the publishing push_back below cannot throw.
            // LOAD-BEARING AND UNPINNED: deleting this line leaves the whole suite
            // green (measured), because without a reallocation the publish behaves
            // identically - the defect it prevents is only reachable when push_back
            // itself must allocate under memory pressure. The static_assert on
            // Subscriber's move covers the move, not the reallocation. Do not
            // "simplify" it away on the strength of a green run.
            existing->subs.reserve(existing->subs.size() + 1);
        }

        // ── commit ────────────────────────────────────────────────────────────
        // First shared-state mutation. try_emplace is itself strong: it throws
        // before committing anything.
        auto [it, inserted] = armed_.try_emplace(key);
        try {
            if (arm_fault_hook_for_test_)
                arm_fault_hook_for_test_(kArmFaultPhaseBeforeSubKeys);
            // The last allocating step. On a throw the armed_ entry we just made
            // must go, or it becomes the ghost this whole ordering exists to prevent.
            sub_keys_.emplace(id, key);
        } catch (...) {
            if (inserted)
                armed_.erase(it);
            throw;
        }

        // ── publish (nothrow tail) ────────────────────────────────────────────
        // Nothing below allocates: the Armed move-assign and the Subscriber move
        // into already-reserved capacity are both nothrow, pinned by the
        // static_asserts in the header next to the structs they constrain.
        if (inserted) {
            it->second = std::move(fresh);
        } else {
            Armed& armed = it->second;
            if (armed.spec.type == SparkType::Startup && !armed.scheduled && running_) {
                // A late subscriber to an already-fired startup spark still gets its
                // one-shot: re-schedule so the arm itself is the observable "startup".
                armed.scheduled = true;
                armed.next_due = std::chrono::steady_clock::now();
            }
            armed.subs.push_back(std::move(sub));
        }
        if (!event_driven)
            wheel_cv_.notify_all();
        if (inserted) {
            // spdlog formats into a heap buffer, so under the very memory pressure
            // #2270 is about it can throw - and a throw here would strand a committed
            // subscription. Losing a log line is strictly better than unwinding a
            // live arm. (Not the only allocating statement past the commit - see the
            // pre-built returns above for the ones that were removed rather than
            // contained.)
            try {
                spdlog::info("SparkEngine: armed '{}'", key);
            } catch (...) {
            }
        }
        if (mech)
            lease.arm_locked(); // #2815: last statement under mu_
    }

    // Arm the OS watch with mu_ RELEASED — watch() may block on handle setup,
    // and an inline emit from the mechanism re-enters under mu_. `mech` is set
    // only for a NEWLY-INSERTED event-driven key, so a failure here means the
    // watcher for this whole key never came up. Serialized via this type's
    // mech_ops_mu_by_type_ entry with a staleness re-check immediately before
    // the call (#1994 M2): a concurrent disarm/unregister may have torn this
    // brand-new key down already (its sole subscriber — ours — removed, e.g. by
    // unregister_consumer racing our own consumer), in which case watching it
    // now would leave an orphaned OS watch with no armed_ entry.
    if (mech) {
        std::lock_guard ops(mech_ops_mu_by_type_.at(spec.type));
        {
            std::lock_guard lk(mu_);
            if (!armed_.contains(key))
                return std::unexpected(std::move(disarmed_mid_arm_msg));
        }
        // A mechanism must RETURN std::unexpected on failure, not throw — but
        // the real ones can (e.g. spark_file's watch() uses fs::current_path()
        // without an ec overload, which throws on a relative path with a bad
        // CWD). An escaping throw would leave a zombie armed_ entry with no
        // watcher and no id ever returned to the
        // caller — an std::expected-contract violation the caller can neither
        // observe nor disarm (governance UP-7). watch_guarded() turns a throw
        // into a returned failure so it falls into the whole-key teardown.
        auto w = watch_guarded(mech, key, watch_params, watch_threw_msg,
                               arm_fault_hook_for_test_);
        if (!w) {
            {
                std::lock_guard lk(mu_);
                drop_key_locked(key);
            }
            // Bookkeeping is already clean, but the message is still completed from
            // the pre-sized buffer: a mechanism error is caller-controlled in length,
            // so concatenating it here would put an unbounded allocation past the
            // commit and break the property the whole layer rests on.
            return std::unexpected(watch_fail_msg.finish(w.error()));
        }
    }

    if (arm_race_hook_for_test_)
        arm_race_hook_for_test_();

    // M1 (#1994): `consumer_id` existed at arm()'s pre-check, but a concurrent
    // unregister_consumer() may have removed it (and our subscription with it)
    // any time between that pre-check and here. Re-check AFTER the insert (and
    // watch, if any) and undo our subscription on a lost race — see
    // unregister_consumer()'s erase-before-scan ordering for why this
    // re-check is airtight. Inline subs have no registered consumer to check.
    // The teardown is teardown_arm_race(), NOT disarm(). Read the next clause as
    // precisely as arm_impl's "(2) past the commit" clause above: it is NOT that
    // either one's locked section never allocates — the log line in each still
    // formats into a heap buffer (teardown_arm_race's own contained "disarmed"
    // log, disarm()'s twin contained "disarmed" log) — it is that both now
    // CONTAIN that allocation in a catch-all rather than letting it escape. So the
    // reason to route through teardown_arm_race is no longer allocation: disarm()
    // must LOOK UP a key this caller already holds, and its last-subscriber
    // branch is whole-key-capable, while what a lost M1 race owes is the
    // removal of exactly ONE subscription — a sibling that deduped onto this
    // key keeps its own.
    if (tier == SparkTier::Queued) {
        bool consumer_alive = false;
        {
            std::lock_guard lk(consumers_mu_);
            consumer_alive = consumers_.contains(consumer_id);
        }
        if (!consumer_alive) {
            teardown_arm_race(id, key, spec.type, event_driven);
            return std::unexpected(std::move(consumer_race_msg));
        }
    }
    return id;
}

void SparkEngine::drop_key_locked(const std::string& key) {
    // Tear down the ENTIRE key, not just one subscription (governance B1): a
    // concurrent arm() of an equal spec may have deduped ONTO this key (adding
    // its own sub with a valid id it believes is armed). Removing only one
    // subscription would leave that sibling armed with NO watcher — violating
    // "armed == a watcher is running" (spark.hpp). Dropping the whole key makes
    // any sibling id inert (disarm is idempotent), which is correct: a failed
    // arm of the key is a failed arm for everyone sharing it. Caller holds mu_
    // and owns any OS-watch teardown — this touches bookkeeping only.
    auto it = armed_.find(key);
    if (it == armed_.end())
        return;
    for (const auto& s : it->second.subs)
        sub_keys_.erase(s.id);
    armed_.erase(it);
}

void SparkEngine::teardown_arm_race(SubscriptionId id, const std::string& key, SparkType type,
                                    bool event_driven) {
    // disarm()'s body, specialized so no allocation failure can escape it (#2270
    // layer 2). Every difference from disarm() is deliberate; keep the two in lockstep:
    //   * `key`/`type` come from the caller, so no lookup and no copy is needed.
    //   * `event_driven` is likewise the caller's already-computed value (arm_impl's
    //     own `const bool event_driven = is_event_driven(spec.type);`), not
    //     recomputed from the stored Armed::spec.type the way disarm()'s
    //     `is_event_driven(ai->second.spec.type)` is — same "the caller already
    //     holds it" rationale as `key`/`type` above. Identical value today (both
    //     derive from the same spec.type), found and confirmed equivalent-but-
    //     undocumented by an external adversarial review (PR #2843) — kept as its
    //     own bullet rather than folded into the first, since it is a PASSED value,
    //     not merely an unlooked-up one, and a future edit that lets the two diverge
    //     needs this spelled out to catch.
    //   * the log line is contained — as disarm()'s now is too.
    //   * a throwing unwatch() is contained and counted — as disarm()'s now is too,
    //     into its own separately-scoped counter.
    // The last two were differences until disarm() was hardened; they are recorded as
    // parity rather than deleted, so a reader diffing the pair sees why each is there.
    // Everything else is disarm() verbatim in effect (four documented differences,
    // not zero), and must stay that way: ONE subscription is removed, never the key,
    // because losing the M1 race invalidates OUR arm and nobody else's. A sibling
    // that deduped onto this key keeps its subscription AND its watcher — deleting
    // those is precisely the defect that failed review twice.
    ISparkMechanism* mech = nullptr;
    TeardownLease lease(inflight_teardowns_); // #2815 door 2/4
    {
        std::lock_guard lk(mu_);
        auto ki = sub_keys_.find(id);
        if (ki == sub_keys_.end())
            return; // unregister_consumer's scan already removed us — nothing to undo
        // Key off the LOCATED entry, not the caller's string, as disarm() does. The two
        // are identical today — `sub_keys_` has exactly one insert site and ids are
        // monotonic and never reused — but if they ever diverged, keying off the caller
        // would make erase_if match nothing while sub_keys_.erase(ki) below still ran,
        // leaving a live subscription that keeps receiving events and can never be
        // disarmed. Reading ki->second costs nothing (the no-lookup argument for taking
        // `key` from the caller is about disarm() having to FIND it, which this is not).
        //
        // SCOPE OF THIS HARDENING, stated exactly because an earlier revision overclaimed
        // it (Gate 8 — sec8-3, CA8-2): `located` covers the find and the erase_if it
        // guards, and NOTHING further. It is a reference INTO sub_keys_, so it dangles
        // the moment sub_keys_.erase(ki) runs below. The M2 re-check and the unwatch are
        // both AFTER that erase, so they can only use the caller's `key` — sound because
        // the two are provably equal (one insert site, ids never reused). The log below
        // is before the erase and could use either; it uses `key` for consistency, not
        // necessity (Gate 9 — CA9-3/sec9-4 caught the earlier wording lumping all three). Copying it out to
        // use later would reintroduce exactly the allocation this teardown exists to
        // avoid. Do not "finish the job" by binding it wider without reading this.
        const std::string& located = ki->second;
        auto ai = armed_.find(located);
        if (ai != armed_.end()) {
            auto& subs = ai->second.subs;
            std::erase_if(subs, [&](const Subscriber& s) { return s.id == id; });
            if (subs.empty()) {
                try {
                    spdlog::info("SparkEngine: disarmed '{}' (last subscription gone)", key);
                } catch (...) {
                }
                // Only while running_: the watch was armed only while running, and
                // stop() unwinds every mechanism. Resolve the mechanism HERE rather
                // than reusing arm_impl's `mech` — that local is null on a deduped
                // arm, and a deduped arm whose sibling is removed by the same
                // unregister scan can still be the call that empties the key.
                if (running_ && event_driven) {
                    auto mit = mechanisms_.find(type);
                    if (mit != mechanisms_.end())
                        mech = mit->second.get();
                }
                armed_.erase(ai);
            }
        }
        sub_keys_.erase(ki);
        wheel_cv_.notify_all();
        if (mech)
            lease.arm_locked(); // #2815: last statement under mu_
    }
    if (mech) {
        // Hook BEFORE the mech-ops lock, never while held — a test hook that re-arms
        // from here would self-deadlock on that non-recursive mutex (disarm(), same
        // placement and same reason).
        if (disarm_race_hook_for_test_)
            disarm_race_hook_for_test_();
        std::lock_guard ops(mech_ops_mu_by_type_.at(type));
        {
            std::lock_guard lk(mu_);
            if (armed_.contains(key))
                return; // a concurrent equal-spec re-arm already renewed this key (M2)
        }
        // CONTAINED, as disarm() now is too (see its own unwatch, which was brought into
        // lockstep on this point later). unwatch() is not noexcept and
        // the real mechanisms allocate inside it (spark_service queues a Cmd holding a
        // key copy; spark_file grows retiring_), so under the memory pressure this
        // whole layer is about it can throw.
        //
        // WHY CONTAIN. The engine's OWN bookkeeping is consistent by this point, so
        // propagating buys no repair. It is NOT that propagating is harmless: measured
        // during governance round 4, the sibling site that DOES propagate
        // (unregister_consumer's uncontained unwatch) escapes a void function and
        // permanently strands the consumer's dispatch thread — the thread holds its own
        // Consumer alive by shared_ptr, `stopping` is never set, and the entry is
        // already erased so stop() cannot reach it either. That is the concrete
        // argument for containing here rather than a preference.
        //
        // RESIDUAL, deliberately not repaired, and the BOUND IS PLATFORM-SPECIFIC —
        // do not restate it as a flat "until stop()", which is what round 4 found to
        // be false:
        //   * Linux/sd-bus: the OS watch outlives its armed_ entry and IS reclaimed by
        //     stop() (and by unregister_consumer, and re-adopted by a later equal-spec
        //     arm, since watch() is idempotent per key).
        //   * WINDOWS/spark_file: worse. push_retiring() takes the OWNING unique_ptr by
        //     value,
        //     so a throwing push_back destroys it with an IOCP completion still
        //     pending, and stop()'s UAF quarantine walks dirs_/ancestors_/retiring_ —
        //     none of which now hold it. The completion dangles for the REMAINING
        //     PROCESS LIFETIME; only a process restart reclaims it. The underlying
        //     strong-guarantee hole in push_retiring is pre-existing and tracked
        //     separately; what belongs here is an honest bound.
        // A retry loop would be another lock-free repair guessing at state it cannot
        // see, which is exactly what failed twice.
        try {
            mech->unwatch(key);
        } catch (...) {
            arm_race_unwatch_failures_.fetch_add(1, std::memory_order_relaxed);
            try {
                spdlog::error("SparkEngine: unwatch('{}') threw during consumer-race teardown - "
                              "the OS watch is not reclaimed by this call; a File watch "
                              "(Windows) persists until a process restart, while other "
                              "mechanisms are reclaimed at the mechanism's stop()",
                              key);
            } catch (...) {
            }
        }
    }
}

void SparkEngine::disarm(SubscriptionId id) {
    ISparkMechanism* mech = nullptr;
    std::string unwatch_key;
    SparkType unwatch_type{}; // carried forward to pick this type's mech-ops lock
    TeardownLease lease(inflight_teardowns_); // #2815 door 1/4
    {
        std::lock_guard lk(mu_);
        auto ki = sub_keys_.find(id);
        if (ki == sub_keys_.end())
            return;
        // Key off the LOCATED entry BY REFERENCE (#2270). The copy this replaced
        // allocated in a function that must not throw once erase_if below has run.
        // PRECISELY: a throw AT THIS SITE was harmless — nothing is mutated yet and the
        // disarm is cleanly retryable. The residue this hardening is about belongs to the
        // two allocations BELOW erase_if; they are commented where they are, not here.
        // SCOPE, stated exactly because the same wording had to be corrected once
        // in teardown_arm_race: `key` is a reference INTO sub_keys_. It is read
        // only ABOVE the move below; past that point it names a moved-from string
        // and must not be read, and past sub_keys_.erase(ki) it dangles outright.
        const std::string& key = ki->second;
        auto ai = armed_.find(key);
        if (ai != armed_.end()) {
            auto& subs = ai->second.subs;
            std::erase_if(subs, [&](const Subscriber& s) { return s.id == id; });
            if (subs.empty()) {
                // CONTAINED, matching teardown_arm_race. spdlog allocates, and the
                // condition this whole layer exists for is the one that makes it
                // throw; the engine's bookkeeping below must complete regardless.
                try {
                    spdlog::info("SparkEngine: disarmed '{}' (last subscription gone)", key);
                } catch (...) {
                }
                // Only tear the OS watch down when the engine is live: the watch
                // was armed only while running_, and stop() already unwinds every
                // mechanism. A pre-start or post-stop disarm has no watch to drop.
                if (running_ && is_event_driven(ai->second.spec.type)) {
                    auto mit = mechanisms_.find(ai->second.spec.type);
                    if (mit != mechanisms_.end()) {
                        mech = mit->second.get();
                        // MOVE, not copy. It allocates nothing on ANY implementation:
                        // basic_string's move-assign is noexcept for std::allocator, so it
                        // cannot allocate whatever the SSO threshold — the buffer steal is
                        // only the over-SSO mechanism, not the reason. Leaves `key` moved-from —
                        // see the scope note above. armed_ holds its own key
                        // string, so `ai` and the erase below are unaffected.
                        unwatch_key = std::move(ki->second);
                        unwatch_type = ai->second.spec.type;
                    }
                }
                armed_.erase(ai);
            }
        }
        sub_keys_.erase(ki);
        wheel_cv_.notify_all();
        if (mech)
            lease.arm_locked(); // #2815: last statement under mu_
    }
    // Stop watching with mu_ RELEASED (unwatch may block; a racing inline emit
    // takes mu_). Serialized via this type's mech_ops_mu_by_type_ entry with a
    // staleness re-check immediately before the call (#1994 M2): a concurrent
    // re-arm of an equal spec may have already renewed this key between our
    // unlock above and here, in which case this unwatch is stale and must be
    // skipped rather than tearing down the fresh watch.
    if (mech) {
        // Hook fires BEFORE the mech-ops lock is taken (never while held): a test
        // hook that re-arms from here calls back into arm_impl(), which takes
        // this same non-recursive mutex — invoking the hook any later would
        // self-deadlock.
        if (disarm_race_hook_for_test_)
            disarm_race_hook_for_test_();
        std::lock_guard ops(mech_ops_mu_by_type_.at(unwatch_type));
        {
            std::lock_guard lk(mu_);
            if (armed_.contains(unwatch_key))
                return; // a concurrent re-arm already renewed this key
        }
        // CONTAINED AND COUNTED, matching teardown_arm_race's own unwatch catch — the
        // fourth and last lockstep difference between the two. unwatch() is not
        // noexcept and the real mechanisms allocate inside it (spark_service queues a
        // Cmd holding a key copy; spark_file grows retiring_), so under the memory
        // pressure this layer is about it can throw.
        //
        // WHY CONTAIN, and it is not merely symmetry. This is a void function whose caller
        // is Guardian's ordinary withdraw path: a throw escapes GuardianSparkBackend::disarm
        // into GuardianSparkRuntime::detach_rule_locked AFTER index_->remove_rule and
        // rules_.erase have run but BEFORE keys_.erase and the "disarmed" lifecycle entry.
        // That strands a keys_ row which makes a later same-key attach's keys_.emplace
        // silently no-op, and loses the audit entry too. The engine's own bookkeeping is
        // complete by this point, so propagating repairs nothing and costs both.
        //
        // The OS watch is still NOT reclaimed. That residual is unchanged, which is why
        // this is counted rather than swallowed silently.
        try {
            mech->unwatch(unwatch_key);
        } catch (...) {
            disarm_unwatch_failures_.fetch_add(1, std::memory_order_relaxed);
            try {
                spdlog::error("SparkEngine: unwatch('{}') threw during disarm - the OS watch "
                              "is not reclaimed by this call; a File watch (Windows) persists "
                              "until a process restart, while other mechanisms are reclaimed "
                              "at the mechanism's stop()",
                              unwatch_key);
            } catch (...) {
            }
        }
    }
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

void SparkEngine::start() {
    // lifecycle_mu_ before mu_ (header LOCK ORDER). Held for the whole of start() so a
    // concurrent stop() — reachable from the Windows SCM control thread during boot —
    // cannot interleave with mechanism bring-up and leave mechanisms started AFTER
    // their stop() ran, which would destroy them with live threads (Gate-4 UP-1).
    std::lock_guard life(lifecycle_mu_);
    std::size_t armed_count = 0;
    std::vector<ISparkMechanism*> mechs;
    struct Replay {
        ISparkMechanism* mech;
        std::string key;
        SparkParams params;
        SparkType type; // picks this type's mech-ops lock at replay
        /// Built during collection so watch_guarded's error completion allocates
        /// nothing at replay time (#2270), the same buffer arm_impl hands it.
        /// SCOPE LIMIT: this does NOT make start() OOM-safe. running_ is already
        /// latched and the wheel is up by the time this vector is built, so a
        /// bad_alloc in the collection pass itself still escapes the void start(),
        /// exactly as before. #2270 is about arm_impl's post-commit window; the
        /// replay path shares the boundary, not the guarantee.
        BoundedMsg err;
    };
    std::vector<Replay> replays;
    {
        std::lock_guard lk(mu_);
        if (running_ || stopped_) {
            spdlog::warn("SparkEngine::start() called while {} — ignored",
                         stopped_ ? "stopped" : "already running");
            return;
        }
        running_ = true;
        // Re-base deadlines on the start instant: an interval armed long before
        // start must not fire immediately; a startup spark fires now. Event-driven
        // sparks armed before start are collected for a watch() replay below.
        const auto now = std::chrono::steady_clock::now();
        for (auto& [key, armed] : armed_) {
            if (armed.scheduled) {
                armed.next_due = initial_due(armed.spec, armed.cadence_ms, now);
            } else if (is_event_driven(armed.spec.type)) {
                auto mit = mechanisms_.find(armed.spec.type);
                if (mit != mechanisms_.end())
                    replays.push_back({mit->second.get(), key, armed.spec.params, armed.spec.type,
                                       BoundedMsg(kWatchThrewPrefix)});
            }
        }
        for (auto& [type, m] : mechanisms_)
            mechs.push_back(m.get());
        armed_count = armed_.size();
        wheel_thread_ = std::thread([this] { wheel_loop(); });
    }
    // Start mechanisms (wire the emit + fault callbacks), THEN replay pre-start
    // watches — both with mu_ released (handle setup blocks). Mechanisms are
    // started before any watch() reaches them.
    for (auto* m : mechs)
        m->start([this](const std::string& key, SparkData data) { emit_event(key, std::move(data)); },
                 [this](const std::string& key, bool faulted, std::string_view reason) {
                     report_fault(key, faulted, reason);
                 });
    for (auto& r : replays) {
        // Serialized via this type's mech_ops_mu_by_type_ entry with a staleness
        // re-check (#1994 M2): a concurrent disarm() may have torn this key down
        // between start()'s collection pass above (mu_ released since) and here.
        std::lock_guard ops(mech_ops_mu_by_type_.at(r.type));
        {
            std::lock_guard lk(mu_);
            if (!armed_.contains(r.key))
                continue; // disarmed before its pre-start replay could run
        }
        // An escaping throw here would unwind out of the void start() AFTER
        // running_ is latched and the wheel + mechanisms are up, leaving this
        // spark in armed_/sub_keys_ with no watcher — the exact "armed == a
        // watcher is running" violation UP-7 closed on the live arm_impl path.
        // watch_guarded() turns a throw into a returned failure; unlike arm_impl
        // we fault in place (subscribers already hold ids — do NOT roll back).
        auto w = watch_guarded(r.mech, r.key, r.params, r.err, arm_fault_hook_for_test_);
        if (!w) {
            // Pre-start replay failure leaves the spark armed-without-watcher —
            // mark it faulted so the drift is observable (B1) rather than a
            // silent log, mirroring the runtime fault channel. (The post-start
            // arm path rolls back instead; a pre-start replay's subscribers
            // already hold ids, so we keep the entry but flag it deaf.)
            spdlog::error("SparkEngine: mechanism failed to arm pre-start watch '{}': {}", r.key,
                          w.error());
            report_fault(r.key, true, "pre-start replay watch failed");
        }
    }
    spdlog::info("SparkEngine started ({} spark(s) armed)", armed_count);
}

void SparkEngine::stop() noexcept try {
    // ── WHO CALLS THIS, AND WHY THERE IS NO SIGNAL-HANDLER MITIGATION ANY MORE ──────
    //
    // stop() is reachable from exactly three places, and NONE of them is a SparkEngine
    // thread:
    //   - `Agent::stop()`, called from main.cpp's shutdown WATCHER thread (POSIX) or
    //     service_win.cpp's SCM control thread (Windows). Both ordinary threads.
    //   - run()'s ScopeExit, on the run() thread.
    //   - ~SparkEngine, on the thread that owns the engine (main).
    //
    // It used to ALSO be reachable from the POSIX signal handler, which called
    // Agent::stop() inline — and a signal is delivered to an ARBITRARY thread, including
    // the wheel, a mechanism poll thread, or a consumer dispatch thread. That forced a
    // whole mitigation layer: masking SIGINT/SIGTERM on every spark thread, a same-thread
    // re-entry guard (a signal could land on a thread already holding lifecycle_mu_ inside
    // start()), and a lock-free self-join bail-out. Five governance rounds found five
    // separate BLOCKING defects IN THAT MITIGATION LAYER.
    //
    // main.cpp now uses a self-pipe: the handler writes one byte and a dedicated watcher
    // thread performs the teardown. stop() therefore CANNOT run on a spark thread, and all
    // of that machinery is deleted. Do not re-add it — fix the caller instead.
    //
    // What REMAINS necessary, and must not be simplified away: lifecycle_mu_ +
    // teardown_complete_. Agent::stop() on the Windows SCM control thread genuinely races
    // ~SparkEngine on main, which is a real cross-thread hazard independent of signals.
    //
    // lifecycle_mu_ is held for the WHOLE teardown. It makes the teardown_complete_
    // early-out below a COMPLETION barrier rather than a bare flag check: a second stop()
    // (or ~SparkEngine, which calls stop()) blocks HERE until the in-flight teardown has
    // finished, then sees teardown_complete_ and returns having genuinely waited.
    //
    // Without it, the loser returned immediately while the winner was still inside
    // wheel_thread_.join() / m->stop() — so ~SparkEngine could run on to
    // ~std::thread(joinable) → std::terminate, and destroy mechanisms_ out from under
    // the thread still calling m->stop() on them → use-after-free. Reachable for real:
    // Agent::stop() runs on the Windows SCM control thread (service_win.cpp
    // handler_ex) concurrently with the main thread's shutdown. Gate-3 B3.
    //
    // SAME-THREAD RE-ENTRY cannot happen: none of the three callers above can already be
    // inside stop() on its own thread (the nested ScopeExit/destructor calls are
    // SEQUENTIAL — the lock is released between them, and the second finds
    // teardown_complete_ set). The re-entry guard that once sat here existed only for the
    // signal-handler path and is deleted with it.
    std::lock_guard life(lifecycle_mu_);

    // 1) Stop the watcher side first so nothing new is produced.
    //
    // The early-out is on teardown_complete_, NOT on stopped_. They mean different
    // things and conflating them was a regression in this very fix (Gate-8
    // security-guardian): stopped_ latches "accept no new work" BEFORE the risky
    // teardown below (joins, map ops, spdlog — all of which can throw). Early-returning
    // on stopped_ meant a throw mid-teardown made stop() report success having torn down
    // nothing past the throw, AND made every later stop() — including ~SparkEngine's —
    // a no-op. The destructor would then destroy a still-joinable wheel_thread_
    // (std::terminate) and mechanisms_ with live threads (use-after-free): exactly the
    // outcomes noexcept was added to prevent, converted from loud to silent.
    //
    // teardown_complete_ is set ONLY after the teardown actually finishes, so a failed
    // teardown is retried by the next caller (in practice the destructor) instead of
    // being latched away.
    {
        std::lock_guard lk(mu_);
        if (teardown_complete_)
            return;
        stopped_ = true; // no new consumers / arms / registrations from here
        running_ = false;
    }
    wheel_cv_.notify_all();
    // SELF-JOIN is unreachable: stop() never runs on a spark thread (see the caller
    // inventory at the top of this function), so joining the wheel thread from itself —
    // std::system_error(resource_deadlock_would_occur) out of a noexcept fn — cannot
    // occur. joinable() guards the never-started and already-torn-down cases only.
    if (wheel_thread_.joinable())
        wheel_thread_.join();

    // 1b) #2815: wait — BOUNDED — for every caller already inside a post-mu_ mechanism
    // window (disarm / teardown_arm_race / unregister_consumer / arm_impl's watch) to
    // leave it, before step 2 starts tearing those same mechanisms down. The locked
    // block above has already flipped running_ AND stopped_, and all four doors gate
    // their own entry on those under mu_ BEFORE resolving a mechanism, so no NEW caller
    // can arm a lease from here on: this waits on a set that only shrinks.
    //
    // BOUNDED, AND IT PROCEEDS ON EXPIRY. stop() is called from Agent::stop() and from
    // the Windows SCM control thread; it may never become a place a shutdown can hang,
    // which is the same rule that makes the consumer join bounded (UP-1 / #1311). This
    // wait is therefore a determinism/API-contract nicety - "stop() returned" should
    // normally mean "nothing is still inside the engine" - and NOT the safety mechanism.
    // The safety mechanism is ~SparkEngine's UNBOUNDED wait, which is what actually
    // prevents the members from being freed under a parked caller.
    //
    // Budget: consumer_join_budget_ms_, reusing the existing shutdown budget (and its
    // test seam) rather than inventing a second one.
    if (!wait_teardown_leases(inflight_teardowns_,
                              std::chrono::milliseconds(
                                  consumer_join_budget_ms_.load(std::memory_order_relaxed)))) {
        teardown_join_timeouts_.fetch_add(1, std::memory_order_relaxed);
        // Contained: spdlog allocates, and this is inside a noexcept teardown whose
        // remaining steps (mechanism stop, consumer join) must still run.
        try {
            spdlog::warn("SparkEngine::stop(): a mechanism teardown was still in flight after "
                         "the shutdown budget — proceeding; a late unwatch() may now reach an "
                         "already-stopped mechanism (~SparkEngine still waits for it before "
                         "freeing anything)");
        } catch (...) {
        }
    }

    // 2) Stop event-driven mechanisms (producers, like the wheel) BEFORE the
    // consumer threads they feed — a mechanism must quiesce before its downstream
    // consumers. Iterating without mu_ is safe because lifecycle_mu_ (held above)
    // excludes register_mechanism() — the ONLY writer of mechanisms_. The previous
    // justification ("structurally stable post-start — no concurrent registration")
    // was false during the boot window: the main thread registers while the SCM
    // control thread can already be in stop(). Gate-4 UP-1.
    for (auto& [type, m] : mechanisms_)
        m->stop();

    // 3) Stop consumer dispatch threads (bounded join, detach-if-hung — UP-1;
    // leftovers dropped + counted).
    std::map<ConsumerId, std::shared_ptr<Consumer>> consumers;
    {
        std::lock_guard lk(consumers_mu_);
        consumers.swap(consumers_);
    }
    // Two-phase so N hung consumers cost ~1×budget total, not N×budget (UP2-3):
    // signal every consumer to stop first, THEN await them all against ONE
    // shared deadline.
    for (auto& [id, consumer] : consumers)
        signal_stop(consumer);
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(consumer_join_budget_ms_.load(
                              std::memory_order_relaxed));
    for (auto& [id, consumer] : consumers)
        await_consumer(consumer, deadline);
    {
        std::lock_guard lk(mu_);
        teardown_complete_ = true; // ONLY here — a throw above leaves it false, so the
                                   // next stop() (the destructor's) retries the teardown
    }
    spdlog::info("SparkEngine stopped");
} catch (...) {
    // stop() is noexcept and is called from ~SparkEngine. A throwing teardown
    // (std::system_error from a join, bad_alloc from the consumer map, or spdlog
    // itself) must not std::terminate the agent for an observe-only subsystem —
    // that would defeat the very degrade-to-no-spark guard in agent.cpp that this
    // engine's boot failure path depends on (Gate-3 cpp-expert SHOULD-1).
    //
    // LOUD, not silent (Gate-8 security-guardian): a swallowed teardown failure means a
    // mechanism may not have released its OS handles. teardown_complete_ stays FALSE, so
    // the next caller re-runs the teardown rather than latching the failure away. The log
    // is itself wrapped — spdlog can throw, and a throw from this last-resort handler
    // would re-open the terminate hole we are closing.
    //
    // HONEST SCOPE OF THE RETRY (Gate-8 round 2): re-running stop() re-drives the wheel
    // join (joinable()-guarded, so no double-join) and the mechanism stop()s (idempotent).
    // It CANNOT re-drive the consumer phase: consumers_ is swapped into a local BEFORE the
    // signal/await loops, so a throw there loses them and the retry finds nothing to await.
    // At rung 1 that phase is a no-op (no consumer is ever registered), but the retry
    // guarantee must not be over-claimed for rung 2, which is when consumers arrive.
    try {
        spdlog::error("SparkEngine::stop() threw during teardown — OS handles may not have "
                      "been released; the wheel + mechanism teardown will be re-run on "
                      "destruction (the consumer phase, if reached, cannot be re-run)");
    } catch (...) {
    }
}

bool SparkEngine::is_running() const noexcept {
    std::lock_guard lk(mu_);
    return running_;
}

// ── Wheel ─────────────────────────────────────────────────────────────────────

void SparkEngine::wheel_loop() {
    std::unique_lock lk(mu_);
    // Snapshot the disk reader once: the seam contract is set-then-start, and a
    // stable local keeps the processing path data-race-free without mu_.
    const DiskReaderFn disk_reader = disk_reader_;
    while (!stopped_) {
        // Earliest scheduled deadline (O(n) scan — see file header).
        std::optional<std::chrono::steady_clock::time_point> next;
        for (const auto& [key, armed] : armed_) {
            if (armed.scheduled && (!next || armed.next_due < *next))
                next = armed.next_due;
        }
        const auto now = std::chrono::steady_clock::now();
        if (!next) {
            wheel_cv_.wait(lk);
            continue;
        }
        if (*next > now) {
            wheel_cv_.wait_until(lk, *next);
            continue; // re-evaluate: stop / arm / disarm may have changed the world
        }

        // Collect everything due; process + deliver with mu_ RELEASED.
        struct DueItem {
            std::string key;
            SparkSpec spec;
            std::uint64_t cadence_ms{0};
            bool latched{false};
        };
        std::vector<DueItem> due;
        for (auto& [key, armed] : armed_) {
            if (armed.scheduled && armed.next_due <= now)
                due.push_back({key, armed.spec, armed.cadence_ms, armed.disk_latched});
        }
        lk.unlock();
        for (auto& item : due) {
            SparkFireDecision decision;
            switch (item.spec.type) {
            case SparkType::Interval:
                decision = interval_process_due(item.cadence_ms, now);
                break;
            case SparkType::Startup:
                decision = startup_process_due();
                break;
            case SparkType::Disk:
                decision = disk_process_due(std::get<DiskSparkParams>(item.spec.params),
                                            item.cadence_ms, item.latched, disk_reader, now);
                break;
            default:
                continue; // event-driven types never sit on the wheel
            }

            // Commit state; the spark may have been disarmed while we processed.
            std::optional<SparkEvent> event;
            std::vector<Subscriber> subs;
            lk.lock();
            auto it = armed_.find(item.key);
            if (it != armed_.end()) {
                Armed& armed = it->second;
                armed.disk_latched = item.latched;
                if (decision.reschedule)
                    armed.next_due = *decision.reschedule;
                else
                    armed.scheduled = false;
                if (decision.emit) {
                    SparkEvent ev;
                    ev.key = item.key;
                    ev.type = armed.spec.type;
                    ev.seq = ++armed.seq;
                    ev.at = std::chrono::system_clock::now();
                    ev.data = std::move(decision.data);
                    event = std::move(ev);
                    if (armed.spec.type == SparkType::Startup) {
                        // One-shot semantics are PER SUBSCRIBER: deliver only to
                        // those still pending, so a late arm's re-fire can never
                        // hand an earlier subscriber a second "startup".
                        for (auto& s : armed.subs) {
                            if (s.startup_pending) {
                                subs.push_back(s);
                                s.startup_pending = false;
                            }
                        }
                    } else {
                        subs = armed.subs; // fan-out snapshot
                    }
                }
            }
            lk.unlock();
            if (event) {
                events_total_.fetch_add(1, std::memory_order_relaxed);
                deliver(*event, subs);
            }
            // Loop tail: mu_ is RELEASED here. The next iteration must compute its
            // decision (which does filesystem I/O for Disk) lock-free, so we do
            // NOT re-lock per item — re-locking inside the loop double-locks the
            // next iteration's commit lk.lock() (std::system_error, uncaught on
            // the wheel thread → terminate) whenever ≥2 sparks are due in one
            // scan. Re-acquire ONCE below for the outer wheel scan.
        }
        lk.lock(); // re-hold for the next wheel scan (reads armed_ under mu_)
    }
}

// ── Delivery ──────────────────────────────────────────────────────────────────

void SparkEngine::emit_event(const std::string& key, SparkData data) {
    SparkEvent event;
    std::vector<Subscriber> subs;
    {
        std::lock_guard lk(mu_);
        auto it = armed_.find(key);
        if (it == armed_.end())
            return; // disarmed between the mechanism's fire and here — TRAP 2 safe
        Armed& armed = it->second;
        event.key = key;
        event.type = armed.spec.type;
        event.seq = ++armed.seq;
        event.at = std::chrono::system_clock::now();
        event.data = std::move(data);
        subs = armed.subs; // fan-out snapshot (event-driven: all subs, no startup logic)
    }
    // mu_ released before delivery — an inline consumer that re-arms takes mu_.
    events_total_.fetch_add(1, std::memory_order_relaxed);
    deliver(event, subs);
}

void SparkEngine::report_fault(const std::string& key, bool faulted, std::string_view reason) {
    std::lock_guard lk(mu_);
    auto it = armed_.find(key);
    if (it == armed_.end())
        return; // disarmed between the mechanism's report and here
    if (it->second.faulted == faulted)
        return; // no edge — idempotent per state
    it->second.faulted = faulted;
    if (faulted) {
        watch_faults_.fetch_add(1, std::memory_order_relaxed);
        spdlog::warn("SparkEngine: watch '{}' FAULTED — armed but not watching ({})", key, reason);
    } else {
        spdlog::info("SparkEngine: watch '{}' recovered", key);
    }
}

void SparkEngine::deliver(const SparkEvent& ev, const std::vector<Subscriber>& subs) {
    for (const auto& sub : subs) {
        if (sub.tier == SparkTier::Inline) {
            // ADR §3 watchdog: every inline call is timed; the counters feed the
            // Stage-11 resource gate. Handlers must not throw — but the watcher
            // must survive a contract breach, so catch + count anyway.
            const auto t0 = std::chrono::steady_clock::now();
            try {
                sub.inline_fn(ev);
            } catch (const std::exception& e) {
                inline_errors_.fetch_add(1, std::memory_order_relaxed);
                spdlog::error("SparkEngine: INLINE handler threw on spark '{}' (contract breach): {}",
                              ev.key, e.what());
            } catch (...) {
                inline_errors_.fetch_add(1, std::memory_order_relaxed);
                spdlog::error("SparkEngine: INLINE handler threw on spark '{}' (contract breach)",
                              ev.key);
            }
            const auto us = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - t0)
                    .count());
            inline_calls_.fetch_add(1, std::memory_order_relaxed);
            inline_us_total_.fetch_add(us, std::memory_order_relaxed);
            if (us > 100)
                inline_over_100us_.fetch_add(1, std::memory_order_relaxed);
            if (us > 10'000)
                inline_over_10ms_.fetch_add(1, std::memory_order_relaxed);
            std::uint64_t prev = inline_us_max_.load(std::memory_order_relaxed);
            while (us > prev && !inline_us_max_.compare_exchange_weak(prev, us,
                                                                      std::memory_order_relaxed)) {
            }
            continue;
        }
        // Queued: never block the watcher. Full queue → drop the OLDEST (the
        // consumer keeps seeing the most recent state) and count it.
        std::shared_ptr<Consumer> consumer;
        {
            std::lock_guard lk(consumers_mu_);
            auto it = consumers_.find(sub.consumer);
            if (it != consumers_.end())
                consumer = it->second;
        }
        if (!consumer)
            continue; // consumer unregistered between fan-out snapshot and here
        {
            std::lock_guard lk(consumer->mu);
            if (consumer->stopping)
                continue;
            if (consumer->queue.size() >= consumer->cap) {
                consumer->queue.pop_front();
                delivery_->dropped.fetch_add(1, std::memory_order_relaxed);
                spdlog::warn("SparkEngine: consumer '{}' queue full (cap {}) — dropped oldest",
                             consumer->name, consumer->cap);
            }
            consumer->queue.push_back(ev);
        }
        consumer->cv.notify_one();
    }
}

// ── Stats / seams ─────────────────────────────────────────────────────────────

SparkEngineStats SparkEngine::stats() const {
    SparkEngineStats s;
    {
        std::lock_guard lk(mu_);
        s.armed_sparks = armed_.size();
        s.armed_faulted = static_cast<std::uint64_t>(
            std::count_if(armed_.begin(), armed_.end(), [](const auto& kv) {
                return kv.second.faulted;
            }));
        s.subscriptions = sub_keys_.size();
        // Watcher units while running: the wheel + one per registered event-driven
        // mechanism (a mechanism may itself run a small pool — this is a unit
        // count, not an OS-thread count; hence _units, not _threads).
        s.watcher_units = running_ ? (1 + mechanisms_.size()) : 0;
        // Sum every mechanism's own counters (#1979). mechanisms_ is
        // structurally stable post-registration and stats() is atomic-only
        // (never shares a lock with watch/unwatch/stop), so calling it here
        // under mu_ is safe — no blocking, no reentrancy into the engine.
        for (const auto& [type, m] : mechanisms_) {
            const auto ms = m->stats();
            s.mech_retiring += ms.retiring;
            s.mech_retiring_cap += ms.retiring_cap;
            s.mech_watch_rejected_total += ms.watch_rejected_total;
            s.mech_quarantined_total += ms.quarantined_total;
            s.mech_slow_op_total += ms.slow_op_total;
        }
    }
    {
        std::lock_guard lk(consumers_mu_);
        s.consumers = consumers_.size();
    }
    s.watch_faults_total = watch_faults_.load(std::memory_order_relaxed);
    s.arm_race_unwatch_failures_total =
        arm_race_unwatch_failures_.load(std::memory_order_relaxed);
    s.disarm_unwatch_failures_total = disarm_unwatch_failures_.load(std::memory_order_relaxed);
    s.teardown_join_timeouts_total = teardown_join_timeouts_.load(std::memory_order_relaxed);
    s.consumer_threads_detached = consumer_threads_detached_.load(std::memory_order_relaxed);
    s.events_total = events_total_.load(std::memory_order_relaxed);
    s.queued_delivered_total = delivery_->delivered.load(std::memory_order_relaxed);
    s.queued_dropped_total = delivery_->dropped.load(std::memory_order_relaxed);
    s.consumer_errors_total = delivery_->errors.load(std::memory_order_relaxed);
    s.inline_calls_total = inline_calls_.load(std::memory_order_relaxed);
    s.inline_errors_total = inline_errors_.load(std::memory_order_relaxed);
    s.inline_us_total = inline_us_total_.load(std::memory_order_relaxed);
    s.inline_us_max = inline_us_max_.load(std::memory_order_relaxed);
    s.inline_over_100us_total = inline_over_100us_.load(std::memory_order_relaxed);
    s.inline_over_10ms_total = inline_over_10ms_.load(std::memory_order_relaxed);
    return s;
}

std::map<SparkType, SparkMechanismStats> SparkEngine::stats_by_type() const {
    // Same shape as the mech_* sum in stats() (lines above) but the SparkType key
    // is preserved instead of folded away. mu_-only (never shares a lock with
    // watch/unwatch/stop) and m->stats() is atomic-only, so this cannot block or
    // reenter the engine — identical safety to the stats() sum loop.
    std::map<SparkType, SparkMechanismStats> out;
    std::lock_guard lk(mu_);
    for (const auto& [type, m] : mechanisms_)
        out.emplace(type, m->stats());
    return out;
}

void SparkEngine::set_disk_reader_for_test(DiskReaderFn reader) {
    std::lock_guard lk(mu_);
    disk_reader_ = std::move(reader);
}

void SparkEngine::set_cadence_floor_for_test(std::uint64_t floor_ms) {
    cadence_floor_ms_.store(floor_ms, std::memory_order_relaxed);
}

void SparkEngine::set_consumer_join_budget_for_test(std::uint64_t ms) {
    consumer_join_budget_ms_.store(ms, std::memory_order_relaxed);
}

void SparkEngine::set_register_race_hook_for_test(std::function<void()> hook) {
    register_race_hook_for_test_ = std::move(hook);
}

void SparkEngine::set_arm_race_hook_for_test(std::function<void()> hook) {
    arm_race_hook_for_test_ = std::move(hook);
}

void SparkEngine::set_arm_precheck_race_hook_for_test(std::function<void()> hook) {
    arm_precheck_race_hook_for_test_ = std::move(hook);
}

void SparkEngine::set_disarm_race_hook_for_test(std::function<void()> hook) {
    disarm_race_hook_for_test_ = std::move(hook);
}

void SparkEngine::set_arm_fault_hook_for_test(std::function<void(int)> hook) {
    arm_fault_hook_for_test_ = std::move(hook);
}

} // namespace yuzu::agent
