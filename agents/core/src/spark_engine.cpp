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

} // namespace

bool SparkEngine::is_event_driven(SparkType type) noexcept {
    return type == SparkType::File || type == SparkType::Service ||
           type == SparkType::Registry;
}

SparkEngine::SparkEngine() = default;

SparkEngine::~SparkEngine() {
    stop();
}

// ── Mechanisms ────────────────────────────────────────────────────────────────

std::expected<void, std::string>
SparkEngine::register_mechanism(SparkType type, std::unique_ptr<ISparkMechanism> mechanism) {
    if (!mechanism)
        return std::unexpected("mechanism must not be null");
    if (!is_event_driven(type))
        return std::unexpected(std::string("spark type '") + spark_type_token(type) +
                               "' is timer-driven — the wheel services it, it has no mechanism");
    std::lock_guard lk(mu_);
    if (running_ || stopped_)
        return std::unexpected("mechanisms must be registered before start()");
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
            consumers_.emplace(id, consumer);
            inserted = true;
        }
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
    // 1) Remove the consumer's subscriptions so no new events are enqueued.
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
    };
    std::vector<PendingUnwatch> to_unwatch;
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
                        to_unwatch.push_back({mit->second.get(), it->first});
                }
                it = armed_.erase(it);
            } else {
                ++it;
            }
        }
    }
    // Stop watching with mu_ RELEASED (unwatch may block; a racing inline emit
    // takes mu_) — mirrors disarm().
    for (auto& pu : to_unwatch)
        pu.mech->unwatch(pu.key);

    // 2) Take the consumer out of the fan-out map, then bounded-join its thread.
    std::shared_ptr<Consumer> consumer;
    {
        std::lock_guard lk(consumers_mu_);
        auto it = consumers_.find(id);
        if (it == consumers_.end())
            return;
        consumer = std::move(it->second);
        consumers_.erase(it);
    }
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

    // Set to the mechanism + params only when a NEW event-driven watch must be
    // armed live (a fresh key on a running engine). Deferred/deduped arms and
    // all timer-driven arms leave it null.
    ISparkMechanism* mech = nullptr;
    SparkParams watch_params;
    SubscriptionId id = 0;
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
        auto [it, inserted] = armed_.try_emplace(key);
        Armed& armed = it->second;
        if (inserted) {
            armed.spec = spec;
            armed.cadence_ms = *cadence;
            if (event_driven) {
                // TRAP 1: event-driven sparks NEVER sit on the wheel — the wheel
                // scan + `default: continue` assume it. A live engine arms the
                // watch now (below, mu_ released); a pre-start arm is armed by
                // start()'s replay.
                armed.scheduled = false;
                if (running_) {
                    mech = mechanisms_.at(spec.type).get();
                    watch_params = spec.params;
                }
            } else {
                armed.scheduled = true;
                armed.next_due =
                    initial_due(armed.spec, armed.cadence_ms, std::chrono::steady_clock::now());
            }
            spdlog::info("SparkEngine: armed '{}'", key);
        } else if (armed.spec.type == SparkType::Startup && !armed.scheduled && running_) {
            // A late subscriber to an already-fired startup spark still gets its
            // one-shot: re-schedule so the arm itself is the observable "startup".
            armed.scheduled = true;
            armed.next_due = std::chrono::steady_clock::now();
        }
        // Dedup: a second arm of an equal event-driven spec falls through here
        // (inserted == false) and shares the existing watcher — mech stays null,
        // no second watch() (N subscriptions, 1 watcher).
        sub_keys_.emplace(id, key);
        armed.subs.push_back(std::move(sub));
        if (!event_driven)
            wheel_cv_.notify_all();
    }

    // Arm the OS watch with mu_ RELEASED — watch() may block on handle setup,
    // and an inline emit from the mechanism re-enters under mu_. `mech` is set
    // only for a NEWLY-INSERTED event-driven key, so a failure here means the
    // watcher for this whole key never came up.
    if (mech) {
        auto w = mech->watch(key, watch_params);
        if (!w) {
            // Tear down the ENTIRE key, not just our own subscription (governance
            // B1): between our unlock above and here, a concurrent arm() of an
            // equal spec may have deduped ONTO this key (adding its own sub with
            // a valid id it believes is armed). disarm(id) would remove only ours
            // and leave that sibling armed with NO watcher — violating "armed ==
            // a watcher is running". Dropping the whole key makes any sibling id
            // inert (idempotent disarm), which is correct: a failed watch is a
            // failed arm for everyone sharing it.
            std::lock_guard lk(mu_);
            auto it = armed_.find(key);
            if (it != armed_.end()) {
                for (const auto& s : it->second.subs)
                    sub_keys_.erase(s.id);
                armed_.erase(it);
            }
            return std::unexpected(std::string("watch mechanism failed to arm '") + key +
                                   "': " + w.error());
        }
    }
    return id;
}

void SparkEngine::disarm(SubscriptionId id) {
    ISparkMechanism* mech = nullptr;
    std::string unwatch_key;
    {
        std::lock_guard lk(mu_);
        auto ki = sub_keys_.find(id);
        if (ki == sub_keys_.end())
            return;
        const std::string key = ki->second;
        auto ai = armed_.find(key);
        if (ai != armed_.end()) {
            auto& subs = ai->second.subs;
            std::erase_if(subs, [&](const Subscriber& s) { return s.id == id; });
            if (subs.empty()) {
                spdlog::info("SparkEngine: disarmed '{}' (last subscription gone)", key);
                // Only tear the OS watch down when the engine is live: the watch
                // was armed only while running_, and stop() already unwinds every
                // mechanism. A pre-start or post-stop disarm has no watch to drop.
                if (running_ && is_event_driven(ai->second.spec.type)) {
                    auto mit = mechanisms_.find(ai->second.spec.type);
                    if (mit != mechanisms_.end()) {
                        mech = mit->second.get();
                        unwatch_key = key;
                    }
                }
                armed_.erase(ai);
            }
        }
        sub_keys_.erase(ki);
        wheel_cv_.notify_all();
    }
    // Stop watching with mu_ RELEASED (unwatch may block; a racing inline emit
    // takes mu_).
    if (mech)
        mech->unwatch(unwatch_key);
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

void SparkEngine::start() {
    std::size_t armed_count = 0;
    std::vector<ISparkMechanism*> mechs;
    struct Replay {
        ISparkMechanism* mech;
        std::string key;
        SparkParams params;
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
                    replays.push_back({mit->second.get(), key, armed.spec.params});
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
        auto w = r.mech->watch(r.key, r.params);
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

void SparkEngine::stop() {
    // 1) Stop the watcher side first so nothing new is produced.
    {
        std::lock_guard lk(mu_);
        if (stopped_)
            return;
        stopped_ = true;
        running_ = false;
    }
    wheel_cv_.notify_all();
    if (wheel_thread_.joinable())
        wheel_thread_.join();

    // 2) Stop event-driven mechanisms (producers, like the wheel) BEFORE the
    // consumer threads they feed — a mechanism must quiesce before its
    // downstream consumers. mechanisms_ is structurally stable post-start (no
    // concurrent registration), so iterating without mu_ is safe; stop() is
    // idempotent and a no-op if start() never ran.
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
    spdlog::info("SparkEngine stopped");
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
    }
    {
        std::lock_guard lk(consumers_mu_);
        s.consumers = consumers_.size();
    }
    s.watch_faults_total = watch_faults_.load(std::memory_order_relaxed);
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

} // namespace yuzu::agent
