/**
 * test_spark_mechanism.cpp — the event-driven mechanism seam (spark_mechanism.hpp
 * + the SparkEngine File/Registry arm path). A FakeMechanism stands in for the
 * Windows IOCP / TP_WAIT impls so the WHOLE arm / dedup / fan-out / disarm-
 * teardown / lifecycle path is exercised on ANY platform — the point of the
 * seam (the real mechanisms compile Windows-only; the plumbing is tested here).
 *
 * The two Windows mechanism bodies (spark_file.cpp / spark_registry.cpp) are
 * validated by a DGRHP compile pass + their own resilience tests; this file
 * owns the cross-platform contract.
 */

#include "spark_engine.hpp"
#include "spark_mechanism.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace yuzu::agent;
using namespace std::chrono_literals;

namespace {

template <typename Pred> bool eventually(Pred pred, std::chrono::milliseconds deadline = 5000ms) {
    const auto until = std::chrono::steady_clock::now() + deadline;
    while (!pred()) {
        if (std::chrono::steady_clock::now() >= until)
            return pred();
        std::this_thread::sleep_for(5ms);
    }
    return true;
}

struct Collector {
    std::mutex mu;
    std::vector<SparkEvent> events;
    SparkEngine::QueuedHandler handler() {
        return [this](const SparkEvent& ev) {
            std::lock_guard lk(mu);
            events.push_back(ev);
        };
    }
    std::size_t count() {
        std::lock_guard lk(mu);
        return events.size();
    }
    SparkEvent at(std::size_t i) {
        std::lock_guard lk(mu);
        return events.at(i);
    }
};

/// A cross-platform stand-in for the Windows watch mechanisms. Records the
/// engine's watch/unwatch/start/stop calls and lets a test drive a fire.
class FakeMechanism final : public ISparkMechanism {
public:
    void start(SparkEmitFn emit, SparkFaultFn fault) override {
        std::lock_guard lk(mu_);
        emit_ = std::move(emit);
        fault_ = std::move(fault);
        started_ = true;
        ++start_calls_;
    }
    std::expected<void, std::string> watch(const std::string& key, const SparkParams&) override {
        std::lock_guard lk(mu_);
        ++watch_calls_;
        if (throw_watch_nonstd_)
            throw 42; // non-std throw → exercises watch_guarded()'s catch(...) arm
        if (throw_watch_)
            throw std::runtime_error("forced watch throw"); // contract-violating mechanism (UP-7)
        if (fail_watch_)
            return std::unexpected("forced watch failure");
        watched_.insert(key);
        return {};
    }
    void unwatch(const std::string& key) override {
        std::lock_guard lk(mu_);
        ++unwatch_calls_;
        watched_.erase(key);
    }
    void stop() override {
        std::lock_guard lk(mu_);
        started_ = false;
        ++stop_calls_;
    }

    // ── test drivers ──
    void fire(const std::string& key, SparkData data = SparkData{std::monostate{}}) {
        SparkEmitFn e;
        {
            std::lock_guard lk(mu_);
            e = emit_;
        }
        if (e)
            e(key, std::move(data));
    }
    // Drive the fault/health channel as a real mechanism would (lock released).
    void fire_fault(const std::string& key, bool faulted, std::string_view reason) {
        SparkFaultFn f;
        {
            std::lock_guard lk(mu_);
            f = fault_;
        }
        if (f)
            f(key, faulted, reason);
    }
    bool is_watching(const std::string& key) {
        std::lock_guard lk(mu_);
        return watched_.count(key) > 0;
    }
    int watch_calls() {
        std::lock_guard lk(mu_);
        return watch_calls_;
    }
    int unwatch_calls() {
        std::lock_guard lk(mu_);
        return unwatch_calls_;
    }
    int stop_calls() {
        std::lock_guard lk(mu_);
        return stop_calls_;
    }
    bool started() {
        std::lock_guard lk(mu_);
        return started_;
    }
    void set_fail_watch(bool b) {
        std::lock_guard lk(mu_);
        fail_watch_ = b;
    }
    void set_throw_watch(bool b) {
        std::lock_guard lk(mu_);
        throw_watch_ = b;
    }
    void set_throw_watch_nonstd(bool b) {
        std::lock_guard lk(mu_);
        throw_watch_nonstd_ = b;
    }

private:
    std::mutex mu_;
    SparkEmitFn emit_;
    SparkFaultFn fault_;
    std::set<std::string> watched_;
    bool started_{false};
    bool fail_watch_{false};
    bool throw_watch_{false};
    bool throw_watch_nonstd_{false};
    int watch_calls_{0};
    int unwatch_calls_{0};
    int stop_calls_{0};
    int start_calls_{0};
};

/// A mechanism whose stop() blocks until released — for #1934 UP-1/F4, a
/// regression test that stop()'s mechanism-teardown step runs with no engine
/// lock held.
class BlockingStopMechanism final : public ISparkMechanism {
public:
    void start(SparkEmitFn emit, SparkFaultFn) override { emit_ = std::move(emit); }
    std::expected<void, std::string> watch(const std::string&, const SparkParams&) override {
        return {};
    }
    void unwatch(const std::string&) override {}
    void stop() override {
        stopping_now_.store(true, std::memory_order_release);
        std::unique_lock lk(gate_mu_);
        gate_cv_.wait(lk, [&] { return release_; });
    }
    void fire(const std::string& key) {
        if (emit_)
            emit_(key, SparkData{std::monostate{}});
    }
    bool stopping_now() const { return stopping_now_.load(std::memory_order_acquire); }
    void release() {
        {
            std::lock_guard lk(gate_mu_);
            release_ = true;
        }
        gate_cv_.notify_all();
    }

private:
    SparkEmitFn emit_;
    std::atomic<bool> stopping_now_{false};
    std::mutex gate_mu_;
    std::condition_variable gate_cv_;
    bool release_{false};
};

/// A mechanism whose watch() blocks until released — for #2011, proves the
/// per-mechanism-type mech_ops_mu_by_type_ (not the old engine-wide
/// mech_ops_mu_) no longer couples a stalled watch() on ONE mechanism type to
/// arm/disarm on a DIFFERENT type.
class BlockingWatchMechanism final : public ISparkMechanism {
public:
    void start(SparkEmitFn emit, SparkFaultFn) override { emit_ = std::move(emit); }
    std::expected<void, std::string> watch(const std::string&, const SparkParams&) override {
        watching_now_.store(true, std::memory_order_release);
        std::unique_lock lk(gate_mu_);
        gate_cv_.wait(lk, [&] { return release_; });
        return {};
    }
    void unwatch(const std::string&) override {}
    void stop() override {}
    bool watching_now() const { return watching_now_.load(std::memory_order_acquire); }
    void release() {
        {
            std::lock_guard lk(gate_mu_);
            release_ = true;
        }
        gate_cv_.notify_all();
    }

private:
    SparkEmitFn emit_;
    std::atomic<bool> watching_now_{false};
    std::mutex gate_mu_;
    std::condition_variable gate_cv_;
    bool release_{false};
};

SparkSpec file_spec(const std::string& path) {
    return SparkSpec{SparkType::File, FileSparkParams{path}};
}
SparkSpec registry_spec(const std::string& hive, const std::string& key) {
    return SparkSpec{SparkType::Registry, RegistrySparkParams{hive, key}};
}
SparkSpec service_spec(const std::string& name) {
    return SparkSpec{SparkType::Service, ServiceSparkParams{name}};
}
SparkSpec interval_spec(std::uint64_t ms) {
    return SparkSpec{SparkType::Interval, IntervalSparkParams{ms}};
}

/// Register a fake for `type` and return the borrowed pointer (engine owns it).
FakeMechanism* wire_fake(SparkEngine& engine, SparkType type) {
    auto fake = std::make_unique<FakeMechanism>();
    FakeMechanism* raw = fake.get();
    REQUIRE(engine.register_mechanism(type, std::move(fake)).has_value());
    return raw;
}

} // namespace

TEST_CASE("register_mechanism: validates null / type / duplicate / timing", "[spark][mechanism]") {
    SparkEngine engine;
    CHECK_FALSE(engine.register_mechanism(SparkType::File, nullptr).has_value());
    // Timer-driven types have no mechanism — the wheel services them.
    CHECK_FALSE(
        engine.register_mechanism(SparkType::Interval, std::make_unique<FakeMechanism>()).has_value());
    CHECK_FALSE(
        engine.register_mechanism(SparkType::Disk, std::make_unique<FakeMechanism>()).has_value());

    REQUIRE(engine.register_mechanism(SparkType::File, std::make_unique<FakeMechanism>()).has_value());
    // Duplicate registration for the same type is rejected.
    CHECK_FALSE(
        engine.register_mechanism(SparkType::File, std::make_unique<FakeMechanism>()).has_value());

    engine.start();
    // After start() it is too late to register.
    CHECK_FALSE(engine.register_mechanism(SparkType::Registry, std::make_unique<FakeMechanism>())
                    .has_value());
    engine.stop();
}

TEST_CASE("arm(File) with no mechanism is rejected (armed == a watcher runs)", "[spark][mechanism]") {
    SparkEngine engine;
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    auto sub = engine.arm(*c, file_spec("/etc/hosts"));
    CHECK_FALSE(sub.has_value()); // no File mechanism registered → reject, never inert-arm
    CHECK(engine.stats().armed_sparks == 0);
}

TEST_CASE("arm(Service) with no mechanism is rejected (armed == a watcher runs)",
          "[spark][mechanism]") {
    SparkEngine engine;
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    auto sub = engine.arm(*c, service_spec("sshd"));
    CHECK_FALSE(sub.has_value()); // no Service mechanism registered → reject, never inert-arm
    CHECK(engine.stats().armed_sparks == 0);
}

TEST_CASE("arm(File) validation: empty path rejected", "[spark][mechanism]") {
    SparkEngine engine;
    wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    CHECK_FALSE(engine.arm(*c, file_spec("")).has_value());
}

TEST_CASE("arm(Registry) validation: hive must be HKLM/HKCU/HKCR/HKU", "[spark][mechanism]") {
    SparkEngine engine;
    wire_fake(engine, SparkType::Registry);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    CHECK_FALSE(engine.arm(*c, registry_spec("BOGUS", "Software\\Yuzu")).has_value());
    CHECK_FALSE(engine.arm(*c, registry_spec("HKLM", "")).has_value());
    CHECK(engine.arm(*c, registry_spec("HKLM", "Software\\Yuzu")).has_value());
}

TEST_CASE("arm(Service) validation: name charset and length", "[spark][mechanism]") {
    SparkEngine engine;
    wire_fake(engine, SparkType::Service);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    CHECK_FALSE(engine.arm(*c, service_spec("")).has_value());
    CHECK_FALSE(engine.arm(*c, service_spec(std::string(257, 'a'))).has_value());
    CHECK_FALSE(engine.arm(*c, service_spec("foo bar")).has_value());  // space not allowed
    CHECK_FALSE(engine.arm(*c, service_spec("foo;x")).has_value());    // shell metachar not allowed
    CHECK(engine.arm(*c, service_spec("sshd")).has_value());
    CHECK(engine.arm(*c, service_spec("ssh.service")).has_value());
    CHECK(engine.arm(*c, service_spec("getty@tty1.service")).has_value());
}

TEST_CASE("File spark: arm-after-start watches, fire delivers to the consumer",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value());
    CHECK(fake->is_watching(key));       // the mechanism was told to watch, live
    CHECK(fake->watch_calls() == 1);
    CHECK(engine.stats().armed_sparks == 1);

    fake->fire(key);
    REQUIRE(eventually([&] { return got.count() >= 1; }));
    const SparkEvent ev = got.at(0);
    CHECK(ev.key == key);
    CHECK(ev.type == SparkType::File);
    CHECK(std::holds_alternative<std::monostate>(ev.data));

    engine.stop();
    CHECK(fake->stop_calls() == 1); // mechanism stopped (before consumers)
}

TEST_CASE("File spark: arm-before-start is replayed to the mechanism at start()",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());

    const auto spec = file_spec("/var/log/syslog");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value());
    CHECK_FALSE(fake->is_watching(key)); // not watched until the engine starts
    CHECK(fake->watch_calls() == 0);

    engine.start();
    CHECK(eventually([&] { return fake->is_watching(key); })); // start() replays the watch
    CHECK(fake->watch_calls() == 1);

    fake->fire(key);
    CHECK(eventually([&] { return got.count() >= 1; }));
    engine.stop();
}

TEST_CASE("File spark: equal specs dedup to one watch, fan out to all subscribers",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    Collector a, b;
    auto ca = engine.register_consumer("a", a.handler());
    auto cb = engine.register_consumer("b", b.handler());
    REQUIRE(ca.has_value());
    REQUIRE(cb.has_value());
    engine.start();

    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*ca, spec).has_value());
    REQUIRE(engine.arm(*cb, spec).has_value());
    CHECK(fake->watch_calls() == 1); // dedup: N subscriptions, 1 watcher
    CHECK(engine.stats().armed_sparks == 1);
    CHECK(engine.stats().subscriptions == 2);

    fake->fire(key);
    REQUIRE(eventually([&] { return a.count() >= 1 && b.count() >= 1; }));
    CHECK(a.at(0).seq == b.at(0).seq); // one fire, one seq, both observe it
    engine.stop();
}

TEST_CASE("File spark: unwatch fires only when the last subscription is disarmed",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto ca = engine.register_consumer("a", [](const SparkEvent&) {});
    auto cb = engine.register_consumer("b", [](const SparkEvent&) {});
    REQUIRE(ca.has_value());
    REQUIRE(cb.has_value());
    engine.start();

    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    auto sa = engine.arm(*ca, spec);
    auto sb = engine.arm(*cb, spec);
    REQUIRE(sa.has_value());
    REQUIRE(sb.has_value());

    engine.disarm(*sa);
    CHECK(fake->is_watching(key));    // one subscription remains — watch stays
    CHECK(fake->unwatch_calls() == 0);
    engine.disarm(*sb);
    CHECK(eventually([&] { return !fake->is_watching(key); })); // last one gone → unwatch
    CHECK(fake->unwatch_calls() == 1);
    engine.stop();
}

TEST_CASE("File spark: unregister_consumer unwatches a watch its removal empties "
          "(governance Tr3kkR finding, PR #1927)",
          "[spark][mechanism]") {
    // unregister_consumer erases a consumer's LAST subscription to an armed
    // spark the same way disarm() does — it must tear down the OS watch the
    // same way too. Before the fix, this path erased the armed_ entry without
    // ever calling unwatch(): the mechanism's watch stayed live for a spark
    // the engine no longer considered armed.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto ca = engine.register_consumer("a", [](const SparkEvent&) {});
    auto cb = engine.register_consumer("b", [](const SparkEvent&) {});
    REQUIRE(ca.has_value());
    REQUIRE(cb.has_value());
    engine.start();

    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    auto sa = engine.arm(*ca, spec);
    auto sb = engine.arm(*cb, spec);
    REQUIRE(sa.has_value());
    REQUIRE(sb.has_value());
    CHECK(fake->is_watching(key));

    // Consumer b still holds a subscription — unregistering a NEVER touches
    // the watch, mirroring disarm()'s "watch stays while a subscription
    // remains" behavior.
    engine.unregister_consumer(*ca);
    CHECK(fake->is_watching(key));
    CHECK(fake->unwatch_calls() == 0);

    // Unregistering b removes the watch's LAST subscription — the watch must
    // be torn down, exactly as if b had called disarm() on it directly.
    engine.unregister_consumer(*cb);
    CHECK(eventually([&] { return !fake->is_watching(key); }));
    CHECK(fake->unwatch_calls() == 1);
    CHECK(engine.stats().armed_sparks == 0);
    engine.stop();
}

TEST_CASE("File spark: a consumer unregistered mid-arm leaves no ghost subscription "
          "(#1994 M1)",
          "[spark][mechanism]") {
    // Forces the exact interleaving M1 closes: the consumer existed at arm()'s
    // pre-check (consumers_mu_), but is FULLY unregistered — subscription
    // removed, mechanism unwatched, consumers_ entry erased — after the
    // mechanism watch succeeds and before arm_impl's post-insert consumer
    // re-check. Before the fix, this left a Subscriber permanently in armed_
    // for a consumer that no longer exists: uncounted by unregister_consumer
    // (which ran before the sub was inserted) and never delivered to (deliver()
    // silently no-ops an unknown consumer id) — a silent resource leak, not a
    // crash.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto consumer = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(consumer.has_value());
    engine.start();

    engine.set_arm_race_hook_for_test([&] { engine.unregister_consumer(*consumer); });

    const auto spec = file_spec("/etc/hosts");
    auto sub = engine.arm(*consumer, spec);
    CHECK_FALSE(sub.has_value()); // lost the race — must report failure, not a ghost

    CHECK(engine.stats().subscriptions == 0);
    CHECK(engine.stats().armed_sparks == 0); // no orphaned key left behind
    CHECK(fake->watch_calls() == 1);         // the watch DID succeed before the hook fired
    CHECK(fake->unwatch_calls() == 1);       // unregister_consumer tore it back down — no leak
    engine.stop();
}

TEST_CASE("SparkEngine: arm() racing unregister_consumer() under REAL concurrent "
          "scheduling never leaves a ghost subscription (stress, #1994 M1)",
          "[spark][engine][stress]") {
    // The deterministic hook-based test above proves the recheck-then-rollback
    // LOGIC is correct on one thread; this exercises the actual cross-thread
    // memory-ordering half with real concurrent scheduling and no seam.
    for (int trial = 0; trial < 500; ++trial) {
        SparkEngine engine;
        engine.set_cadence_floor_for_test(10);
        engine.start();
        auto consumer = engine.register_consumer("racer", [](const SparkEvent&) {});
        REQUIRE(consumer.has_value());

        std::atomic<bool> go{false};
        std::thread unregisterer([&] {
            while (!go.load(std::memory_order_acquire))
                std::this_thread::yield();
            engine.unregister_consumer(*consumer);
        });
        go.store(true, std::memory_order_release);
        // Result intentionally unchecked: either outcome (won or lost the race
        // against the concurrent unregister) is valid — the invariant under
        // test is "no crash, no ghost", not which side wins.
        (void)engine.arm(*consumer, interval_spec(20));
        unregisterer.join();
        engine.stop();

        // Whichever side won, the consumer is gone and no subscription should
        // remain pointing at it.
        CHECK(engine.stats().consumers == 0);
        CHECK(engine.stats().subscriptions == 0);
    }
    SUCCEED("500 concurrent arm()/unregister_consumer() trials completed without a crash or "
            "a surviving ghost subscription");
}

TEST_CASE("File spark: a late unwatch from a torn-down arm does not clobber a "
          "concurrent equal-spec re-arm (#1994 M2)",
          "[spark][mechanism]") {
    // Forces the exact interleaving M2 closes: disarm() removes the last
    // subscription to a key (releasing mu_, about to call unwatch()) while a
    // NEW arm() of an EQUAL spec races in, sees the key already gone from
    // armed_, and re-establishes a fresh watch. Before the fix, the first
    // disarm's now-stale unwatch() would run after the fresh watch() and tear
    // it down — leaving armed_ showing the key armed with NO live OS watch.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
    auto c2 = engine.register_consumer("c2", [](const SparkEvent&) {});
    REQUIRE(c1.has_value());
    REQUIRE(c2.has_value());
    engine.start();

    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    auto s1 = engine.arm(*c1, spec);
    REQUIRE(s1.has_value());
    CHECK(fake->is_watching(key));

    // disarm()'s hook fires with mu_ already released, just before its
    // staleness-rechecked unwatch() call — re-arm an equal spec here so the
    // fresh watch is already up by the time the stale unwatch would fire.
    engine.set_disarm_race_hook_for_test([&] {
        auto s2 = engine.arm(*c2, spec);
        REQUIRE(s2.has_value());
    });
    engine.disarm(*s1);

    // The fresh watch must survive: still watched, and the stale unwatch must
    // have been SKIPPED (not merely harmless) — the mechanism never saw it.
    CHECK(fake->is_watching(key));
    CHECK(engine.stats().armed_sparks == 1);
    CHECK(fake->watch_calls() == 2);   // original arm + the re-arm
    CHECK(fake->unwatch_calls() == 0); // the stale unwatch was skipped, not just harmless
    engine.stop();
}

TEST_CASE("File spark: disarm() racing an equal-spec arm() under REAL concurrent "
          "scheduling never tears down a fresh watch (stress, #1994 M2)",
          "[spark][mechanism][stress]") {
    // Companion to the deterministic hook test above (which forces the exact
    // interleaving and is the actual proof of the recheck-then-skip logic).
    // This twin runs the two ops on real threads with no seam: it does NOT
    // reliably hit the nanosecond race window (measured ~0.11s for 500 trials
    // on an idle runner — the window is almost never hit), so its value is
    // exercising the cross-thread memory-ordering of mech_ops_mu_by_type_/mu_
    // under TSan, not interleaving coverage. Mirrors the M1 stress twin's
    // framing. (Single-type here, so per-type vs engine-wide is behaviourally
    // identical — only the identifier changed with #2011.)
    for (int trial = 0; trial < 500; ++trial) {
        SparkEngine engine;
        FakeMechanism* fake = wire_fake(engine, SparkType::File);
        auto c1 = engine.register_consumer("c1", [](const SparkEvent&) {});
        auto c2 = engine.register_consumer("c2", [](const SparkEvent&) {});
        REQUIRE(c1.has_value());
        REQUIRE(c2.has_value());
        engine.start();

        const auto spec = file_spec("/etc/hosts");
        const std::string key = spark_key(spec);
        auto s1 = engine.arm(*c1, spec);
        REQUIRE(s1.has_value());

        std::atomic<bool> go{false};
        // Catch2 assertion macros are NOT thread-safe and a failed REQUIRE
        // throws — off the main thread that escapes the std::thread and
        // std::terminate()s the whole binary (security-guardian/cpp-safety
        // Gate 2/3). Capture the result and assert on the main thread after
        // join(), matching the M1 stress twin.
        std::atomic<bool> rearm_ok{false};
        std::thread rearmer([&] {
            while (!go.load(std::memory_order_acquire))
                std::this_thread::yield();
            rearm_ok.store(engine.arm(*c2, spec).has_value(), std::memory_order_release);
        });
        go.store(true, std::memory_order_release);
        engine.disarm(*s1);
        rearmer.join();
        CHECK(rearm_ok.load(std::memory_order_acquire));

        // Invariant under test regardless of interleaving order: if armed_
        // still shows the key armed (c2's subscription survived), the
        // mechanism must actually be watching it — never torn down and never
        // silently orphaned.
        if (engine.stats().armed_sparks > 0)
            CHECK(fake->is_watching(key));
        engine.stop();
    }
    SUCCEED("500 concurrent disarm()/arm() trials completed with no torn-down fresh watch");
}

TEST_CASE("SparkEngine: a blocking watch() on one mechanism type does not delay "
          "unwatch() on a DIFFERENT mechanism type (#2011)",
          "[spark][mechanism]") {
    // Acceptance test for the rung-0 HARD GATE: with the old engine-wide
    // mech_ops_mu_, a stalled File watch() held the ONE lock every unwatch()
    // queued behind, so a Registry disarm could not proceed until File's watch
    // returned. Per-type locks (mech_ops_mu_by_type_) decouple them.
    SparkEngine engine;
    FakeMechanism* reg_fake = wire_fake(engine, SparkType::Registry);
    auto blocking = std::make_unique<BlockingWatchMechanism>();
    BlockingWatchMechanism* bwm = blocking.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(blocking)).has_value());

    auto consumer = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(consumer.has_value());
    engine.start();

    // Arm a Registry spark first — its FakeMechanism watch() returns at once, so
    // it is live and its later disarm has a real unwatch to issue.
    const auto reg_spec = registry_spec("HKLM", "Software\\Foo");
    auto reg_sub = engine.arm(*consumer, reg_spec);
    REQUIRE(reg_sub.has_value());
    CHECK(reg_fake->is_watching(spark_key(reg_spec)));

    // Arm a File spark whose watch() blocks (holding File's per-type lock) — on
    // a background thread, since arm() will not return until watch() does.
    std::thread blocker([&] { (void)engine.arm(*consumer, file_spec("/etc/hosts")); });
    REQUIRE(eventually([&] { return bwm->watching_now(); }));

    // Disarm the Registry subscription on its own thread while File's watch() is
    // still blocked. Under per-type locks this returns immediately; under the
    // old engine-wide lock it would stay blocked behind File's watch() until we
    // release() below — the eventually() would time out and completed==false.
    std::atomic<bool> disarm_done{false};
    std::thread disarmer([&] {
        engine.disarm(*reg_sub);
        disarm_done.store(true, std::memory_order_release);
    });
    const bool completed = eventually([&] { return disarm_done.load(std::memory_order_acquire); },
                                      2000ms);
    CHECK(completed); // the whole point of #2011: File's stall did not block Registry
    CHECK(reg_fake->unwatch_calls() == 1);

    // Cleanup: release the blocked File watch, then join everything. (Even under
    // a regression where `completed` is false, release() unblocks File's watch,
    // which frees the old shared lock so the pending disarm can finish — so the
    // test fails cleanly rather than hanging.)
    bwm->release();
    disarmer.join();
    blocker.join();
    engine.stop();
}

TEST_CASE("File spark: a mechanism watch failure rolls the arm back", "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    fake->set_fail_watch(true);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();

    auto sub = engine.arm(*c, file_spec("/etc/hosts"));
    CHECK_FALSE(sub.has_value());          // watch failed → arm reported failure
    CHECK(engine.stats().armed_sparks == 0); // and the whole key was torn down (B1)
    CHECK(engine.stats().subscriptions == 0);
    engine.stop();
}

TEST_CASE("File spark: a mechanism that THROWS from watch() rolls the arm back cleanly "
          "(#1994 UP-7)",
          "[spark][mechanism]") {
    // The engine's contract is that a mechanism returns std::unexpected on
    // failure, but the real spark_file::watch() can throw (fs::current_path()
    // on a relative path). A throw must NOT unwind past arm_impl's rollback and
    // leave a zombie armed_ entry with no watcher and no id returned — it must
    // be treated exactly like a returned failure: whole-key teardown, arm()
    // returns a clean std::unexpected (never propagates the exception).
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    fake->set_throw_watch(true);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();

    std::expected<SparkEngine::SubscriptionId, std::string> sub;
    REQUIRE_NOTHROW(sub = engine.arm(*c, file_spec("/etc/hosts"))); // throw is caught, not propagated
    CHECK_FALSE(sub.has_value());
    CHECK(sub.error().find("watch mechanism threw:") != std::string::npos); // catch(std::exception&) text
    CHECK(engine.stats().armed_sparks == 0); // no zombie armed entry
    CHECK(engine.stats().subscriptions == 0);

    // The engine is still usable afterward: a subsequent good arm succeeds.
    fake->set_throw_watch(false);
    auto ok = engine.arm(*c, file_spec("/etc/hosts"));
    CHECK(ok.has_value());
    CHECK(engine.stats().armed_sparks == 1);
    engine.stop();
}

TEST_CASE("File spark: a mechanism that throws a NON-std exception from watch() is still contained "
          "(watch_guarded catch(...))",
          "[spark][mechanism]") {
    // watch_guarded() has two catch arms; the std::exception arm is covered by
    // the tests above. A mechanism throwing a non-std type (here `throw 42;`)
    // must hit the catch(...) arm and be contained exactly the same way — never
    // propagate out of arm(). One test on the live path suffices: both arm sites
    // share the single watch_guarded() boundary.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    fake->set_throw_watch_nonstd(true);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();

    std::expected<SparkEngine::SubscriptionId, std::string> sub;
    REQUIRE_NOTHROW(sub = engine.arm(*c, file_spec("/etc/hosts"))); // non-std throw caught, not propagated
    CHECK_FALSE(sub.has_value());
    CHECK(sub.error().find("non-std exception") != std::string::npos); // catch(...) text, wire-locked
    CHECK(engine.stats().armed_sparks == 0); // no zombie armed entry
    CHECK(engine.stats().subscriptions == 0);
    engine.stop();
}

TEST_CASE("File spark: a pre-start replay watch failure marks the spark faulted, not silent",
          "[spark][mechanism]") {
    // A spark armed BEFORE start defers its watch to start()'s replay. If that
    // replay fails, subscribers already hold ids, so (unlike the post-start arm
    // which rolls back) the entry stays — but it must be flagged deaf via the
    // fault channel so "armed but not watching" is observable, never silent (B1).
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value()); // armed before start (watch deferred)
    fake->set_fail_watch(true);                // the start() replay watch will fail

    engine.start();
    CHECK(eventually([&] { return fake->watch_calls() == 1; }));
    CHECK_FALSE(fake->is_watching(key));       // watch never came up
    CHECK(engine.stats().armed_sparks == 1);   // entry retained (ids outstanding)
    CHECK(engine.stats().armed_faulted == 1);  // …but flagged deaf, not silent
    CHECK(engine.stats().watch_faults_total == 1);
    engine.stop();
}

TEST_CASE("File spark: a pre-start replay watch that THROWS faults the spark, never escapes start() "
          "(#1994 UP-7 symmetric)",
          "[spark][mechanism]") {
    // The pre-start replay path is the symmetric twin of arm_impl: a real
    // mechanism can THROW from watch() (spark_file's fs::current_path() on a
    // relative path). start() is void — an escaping throw would unwind AFTER
    // running_ is latched and the wheel + mechanisms are up, leaving the spark
    // armed-without-watcher (the exact UP-7 hazard). The replay must catch the
    // throw and fault in place (subscribers hold ids → no rollback), exactly
    // like a returned failure — start() must never propagate the exception.
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value()); // armed before start (watch deferred)
    fake->set_throw_watch(true);               // the start() replay watch will THROW

    REQUIRE_NOTHROW(engine.start());           // throw is caught, not propagated
    CHECK(eventually([&] { return fake->watch_calls() == 1; }));
    CHECK_FALSE(fake->is_watching(key));       // watch never came up
    CHECK(engine.stats().armed_sparks == 1);   // entry retained (ids outstanding)
    CHECK(engine.stats().armed_faulted == 1);  // …but flagged deaf, not silently armed
    CHECK(engine.stats().watch_faults_total == 1);
    engine.stop();
}

TEST_CASE("File spark: a pre-start replay watch that throws a NON-std exception faults, never escapes "
          "start()",
          "[spark][mechanism]") {
    // Replay-path twin of the catch(...) coverage: the live-path test above proves
    // watch_guarded()'s catch(...) arm on arm(); this proves the SAME boundary on
    // the pre-start replay in start(). A non-std throw (`throw 42;`) must fault in
    // place (subscribers hold ids → no rollback) and never propagate out of the
    // void start().
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value()); // armed before start (watch deferred)
    fake->set_throw_watch_nonstd(true);        // the start() replay watch will throw a non-std type

    REQUIRE_NOTHROW(engine.start());           // non-std throw is caught, not propagated
    CHECK(eventually([&] { return fake->watch_calls() == 1; }));
    CHECK_FALSE(fake->is_watching(key));
    CHECK(engine.stats().armed_sparks == 1);   // entry retained (ids outstanding)
    CHECK(engine.stats().armed_faulted == 1);  // …flagged deaf
    CHECK(engine.stats().watch_faults_total == 1);
    engine.stop();
}

TEST_CASE("Mechanism fault channel: fault flags health on the transition, recovery clears it (B1)",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value());
    CHECK(engine.stats().armed_faulted == 0);

    fake->fire_fault(key, true, "watch died after arm");
    CHECK(engine.stats().armed_faulted == 1);
    CHECK(engine.stats().watch_faults_total == 1);
    // Re-reporting the same faulted state is a no-op edge — the counter is a
    // transition count, not a per-report count.
    fake->fire_fault(key, true, "still dead");
    CHECK(engine.stats().watch_faults_total == 1);

    fake->fire_fault(key, false, "recovered");
    CHECK(engine.stats().armed_faulted == 0);
    CHECK(engine.stats().watch_faults_total == 1); // recovery does not bump the fault counter
    // A fault for an unknown/disarmed key is ignored (no crash, no drift).
    fake->fire_fault("registry|nope", true, "ghost");
    CHECK(engine.stats().armed_faulted == 0);
    engine.stop();
}

TEST_CASE("Service spark: fire carries ServiceSparkData through the queued tier",
          "[spark][mechanism]") {
    // Unlike File/Registry (monostate — consumer re-reads), Service carries the
    // resolved terminal state. Prove it survives the engine's snapshot/fan-out
    // copy (emit_event copies SparkData by value into each subscriber's queue).
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const auto spec = service_spec("sshd");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value());

    fake->fire(key, SparkData{ServiceSparkData{ServiceRunState::Running}});
    REQUIRE(eventually([&] { return got.count() >= 1; }));
    const SparkEvent ev = got.at(0);
    CHECK(ev.key == key);
    CHECK(ev.type == SparkType::Service);
    REQUIRE(std::holds_alternative<ServiceSparkData>(ev.data));
    CHECK(std::get<ServiceSparkData>(ev.data).state == ServiceRunState::Running);

    fake->fire(key, SparkData{ServiceSparkData{ServiceRunState::Paused}});
    REQUIRE(eventually([&] { return got.count() >= 2; }));
    REQUIRE(std::holds_alternative<ServiceSparkData>(got.at(1).data));
    CHECK(std::get<ServiceSparkData>(got.at(1).data).state == ServiceRunState::Paused);
    engine.stop();
}

TEST_CASE("Service spark: arm-before-start is replayed to the mechanism at start()",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());

    const auto spec = service_spec("sshd");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*c, spec).has_value());
    CHECK_FALSE(fake->is_watching(key)); // not watched until the engine starts
    CHECK(fake->watch_calls() == 0);

    engine.start();
    CHECK(eventually([&] { return fake->is_watching(key); })); // start() replays the watch
    CHECK(fake->watch_calls() == 1);

    fake->fire(key, SparkData{ServiceSparkData{ServiceRunState::Running}});
    CHECK(eventually([&] { return got.count() >= 1; }));
    engine.stop();
}

TEST_CASE("Service spark: equal specs dedup to one watch, fan out to all subscribers",
          "[spark][mechanism]") {
    SparkEngine engine;
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    Collector a, b;
    auto ca = engine.register_consumer("a", a.handler());
    auto cb = engine.register_consumer("b", b.handler());
    REQUIRE(ca.has_value());
    REQUIRE(cb.has_value());
    engine.start();

    const auto spec = service_spec("sshd");
    const std::string key = spark_key(spec);
    REQUIRE(engine.arm(*ca, spec).has_value());
    REQUIRE(engine.arm(*cb, spec).has_value());
    CHECK(fake->watch_calls() == 1); // dedup: N subscriptions, 1 watcher
    CHECK(engine.stats().armed_sparks == 1);
    CHECK(engine.stats().subscriptions == 2);

    fake->fire(key, SparkData{ServiceSparkData{ServiceRunState::Stopped}});
    REQUIRE(eventually([&] { return a.count() >= 1 && b.count() >= 1; }));
    CHECK(a.at(0).seq == b.at(0).seq); // one fire, one seq, both observe it
    engine.stop();
}

TEST_CASE("Mechanism emit path does not deadlock an inline re-arm (TRAP 2)", "[spark][mechanism]") {
    // An inline consumer that re-arms from inside its handler must not deadlock:
    // emit_event snapshots + releases mu_ before delivering, and arm takes mu_.
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    FakeMechanism* fake = wire_fake(engine, SparkType::File);
    std::atomic<bool> rearmed{false};
    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);

    auto inline_sub = engine.arm_inline(spec, [&](const SparkEvent&) {
        // Re-enter the engine from inside the (inline) delivery.
        auto c = engine.register_consumer("late", [](const SparkEvent&) {});
        if (c)
            rearmed.store(engine.arm(*c, SparkSpec{SparkType::Interval, IntervalSparkParams{50}})
                              .has_value());
    });
    REQUIRE(inline_sub.has_value());
    engine.start();

    fake->fire(key); // drives the inline handler synchronously on this thread
    CHECK(eventually([&] { return rearmed.load(); }));
    engine.stop();
}

TEST_CASE("Service spark emit path does not deadlock an inline re-arm (TRAP 2 twin)",
          "[spark][mechanism]") {
    SparkEngine engine;
    engine.set_cadence_floor_for_test(10);
    FakeMechanism* fake = wire_fake(engine, SparkType::Service);
    std::atomic<bool> rearmed{false};
    const auto spec = service_spec("sshd");
    const std::string key = spark_key(spec);

    auto inline_sub = engine.arm_inline(spec, [&](const SparkEvent&) {
        auto c = engine.register_consumer("late-svc", [](const SparkEvent&) {});
        if (c)
            rearmed.store(engine.arm(*c, SparkSpec{SparkType::Interval, IntervalSparkParams{50}})
                              .has_value());
    });
    REQUIRE(inline_sub.has_value());
    engine.start();

    fake->fire(key, SparkData{ServiceSparkData{ServiceRunState::Stopped}});
    CHECK(eventually([&] { return rearmed.load(); }));
    engine.stop();
}

TEST_CASE("SparkEngine: a queued handler re-entering the engine while stop() is inside "
          "mechanism teardown does not deadlock (#1934 UP-1/F4)",
          "[spark][mechanism]") {
    // Pins the property this whole mechanism-call seam depends on:
    // SparkEngine::stop() calls a mechanism's stop() with NO engine lock held
    // (mu_ / consumers_mu_ / every mech_ops_mu_by_type_ entry all released — see
    // stop()'s step 2).
    // A QUEUED handler already dispatched before stop() began may therefore
    // safely call back into the engine (arm/disarm) WHILE stop() is stuck
    // inside a slow mechanism teardown: the re-entrant call must fail cleanly
    // (the engine is stopping) rather than deadlock waiting for a lock stop()
    // is (incorrectly, in a regression) still holding.
    SparkEngine engine;
    auto mech = std::make_unique<BlockingStopMechanism>();
    BlockingStopMechanism* bm = mech.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(mech)).has_value());

    struct Sync {
        std::mutex m;
        std::condition_variable cv;
        bool handler_fired{false};
        bool reentry_done{false};
        std::atomic<bool> reentrant_arm_rejected{false};
    };
    auto sync = std::make_shared<Sync>();

    const auto spec = file_spec("/etc/hosts");
    const std::string key = spark_key(spec);
    auto consumer = engine.register_consumer("c", [&engine, bm, sync](const SparkEvent&) {
        {
            std::lock_guard lk(sync->m);
            sync->handler_fired = true;
        }
        sync->cv.notify_all();
        // Wait until stop() is actually inside the mechanism teardown before
        // re-entering — otherwise this races stop()'s own step 1 instead of
        // exercising step 2's no-lock-held property.
        while (!bm->stopping_now())
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        auto sub2 = engine.arm_inline(SparkSpec{SparkType::Interval, IntervalSparkParams{60'000}},
                                       [](const SparkEvent&) {});
        sync->reentrant_arm_rejected.store(!sub2.has_value());
        {
            std::lock_guard lk(sync->m);
            sync->reentry_done = true;
        }
        sync->cv.notify_all();
        bm->release(); // let stop()'s mechanism teardown — and stop() itself — finish
    });
    REQUIRE(consumer.has_value());
    REQUIRE(engine.arm(*consumer, spec).has_value());
    engine.start();

    bm->fire(key);
    {
        std::unique_lock lk(sync->m);
        sync->cv.wait(lk, [&] { return sync->handler_fired; });
    }

    const auto t0 = std::chrono::steady_clock::now();
    engine.stop(); // must return once the handler releases the gate, not hang
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    CHECK(elapsed < 5000ms);
    {
        std::lock_guard lk(sync->m);
        CHECK(sync->reentry_done);
    }
    CHECK(sync->reentrant_arm_rejected.load()); // failed cleanly, never hung
}

TEST_CASE("platform factories honor the mechanism-or-null contract", "[spark][mechanism]") {
#ifdef _WIN32
    CHECK(make_file_mechanism() != nullptr);
    CHECK(make_registry_mechanism() != nullptr);
    CHECK(make_service_mechanism() != nullptr);
#else
    CHECK(make_file_mechanism() == nullptr);     // off Windows → no mechanism → arm() rejects
    CHECK(make_registry_mechanism() == nullptr);
#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)
    CHECK(make_service_mechanism() != nullptr);  // Linux + libsystemd → real sd-bus mechanism
#else
    CHECK(make_service_mechanism() == nullptr);  // macOS, or Linux built without libsystemd
#endif
#endif
}

// ── Linux-only smoke: drive the REAL sd-bus mechanism against absent units and
//    (env-gated) a live unit transition. The cross-platform cases above prove
//    the engine plumbing via the fake; these prove the actual Linux body fires
//    and that its resource contract (1 bus connection + 1 eventfd + 1 thread,
//    for any N) actually holds — thread count alone would hide a per-unit-
//    connection regression (stage0-resource-baseline.md).
//
//    NOTE on bus-collapse/reconnect: killing the system bus in a test would
//    kill the host session, so there is deliberately no live test for that
//    path here. The fault-channel plumbing itself is proven by the
//    cross-platform FakeMechanism-driven cases above (B1); the PER-UNIT
//    resolve/arm/read logic mirrors guard_systemd.cpp's soak-tested pattern
//    closely, but the reopen-then-re-arm-ALL-units fan-out is structurally
//    NEW here (guard_systemd only ever had one unit per connection) and has
//    NO test coverage, live or fake — a governance Gate-3 finding this
//    session (a real bus-unref leak was found and fixed in this exact path;
//    a mock/fake-bus-driven test of the reopen fan-out is a tracked
//    follow-up). The churn case below (arm N, disarm all) proves no fd/slot
//    leak across repeated arm/disarm, which is the only property a unit
//    test here can directly observe without mocking sd-bus.
#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)

#include <unistd.h> // getpid

#include <cstdlib>     // getenv
#include <filesystem>
#include <fstream>
#include <sstream>

namespace {
std::size_t linux_fd_count() {
    std::error_code ec;
    std::size_t n = 0;
    for (const auto& e : std::filesystem::directory_iterator("/proc/self/fd", ec))
        (void)e, ++n;
    return n;
}
std::size_t linux_thread_count() {
    std::ifstream f("/proc/self/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("Threads:", 0) == 0) {
            std::istringstream iss(line.substr(8));
            std::size_t n = 0;
            iss >> n;
            return n;
        }
    }
    return 0;
}
} // namespace

TEST_CASE("Service spark (real mechanism): an absent unit gets an initial Stopped emit",
          "[spark][mechanism][linux]") {
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const std::string name = "yuzu-nosuch-" + std::to_string(::getpid()) + ".service";
    auto sub = engine.arm(*c, service_spec(name));
    if (!sub.has_value()) {
        engine.stop();
        SUCCEED("service mechanism reports inert (no system bus on this host) — skipping");
        return;
    }
    REQUIRE(eventually([&] { return got.count() >= 1; }));
    REQUIRE(std::holds_alternative<ServiceSparkData>(got.at(0).data));
    CHECK(std::get<ServiceSparkData>(got.at(0).data).state == ServiceRunState::Stopped);
    engine.disarm(*sub);
    engine.stop();
}

TEST_CASE("Service spark (real mechanism): two spark keys coalescing onto one unit each "
          "get their own emit",
          "[spark][mechanism][linux]") {
    // "yuzu-coalesce-<pid>" and "yuzu-coalesce-<pid>.service" are DISTINCT
    // engine-level spark keys (different ServiceSparkParams::service_name,
    // no engine-level dedup) but normalize_unit_name folds them onto the
    // SAME underlying UnitWatch inside the mechanism. Governance flagged
    // this exact scenario (a second key arming onto an already-known unit)
    // as untested by every N-watch resource test, since those all use N
    // DISTINCT unit names.
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const std::string base = "yuzu-coalesce-" + std::to_string(::getpid());
    auto first = engine.arm(*c, service_spec(base));
    if (!first.has_value()) {
        engine.stop();
        SUCCEED("service mechanism reports inert (no system bus on this host) — skipping");
        return;
    }
    REQUIRE(eventually([&] { return got.count() >= 1; }));

    // Second key normalizes to the identical unit name ("base" has no '.'
    // so normalize_unit_name appends ".service" — matching this literal).
    auto second = engine.arm(*c, service_spec(base + ".service"));
    REQUIRE(second.has_value());
    REQUIRE(eventually([&] { return got.count() >= 2; })); // the coalescing key gets its OWN emit

    CHECK(got.at(0).key != got.at(1).key); // distinct engine keys...
    REQUIRE(std::holds_alternative<ServiceSparkData>(got.at(1).data));
    CHECK(std::get<ServiceSparkData>(got.at(1).data).state ==
          ServiceRunState::Stopped); // ...same (absent) unit, same resolved state

    engine.disarm(*first);
    engine.disarm(*second);
    engine.stop();
}

TEST_CASE("Service spark (real mechanism): a real active unit resolves to Running",
          "[spark][mechanism][linux]") {
    // systemd-journald.service is present and active on virtually any systemd
    // host, needs no privilege to READ (only start/stop needs polkit auth), so
    // this exercises the Resolved+Active real-bus path without any live-env
    // gate — the twin of the Windows "Winmgmt" always-running smoke case.
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    auto sub = engine.arm(*c, service_spec("systemd-journald.service"));
    if (!sub.has_value()) {
        engine.stop();
        SUCCEED("service mechanism reports inert (no system bus on this host) — skipping");
        return;
    }
    REQUIRE(eventually([&] { return got.count() >= 1; }));
    REQUIRE(std::holds_alternative<ServiceSparkData>(got.at(0).data));
    CHECK(std::get<ServiceSparkData>(got.at(0).data).state == ServiceRunState::Running);
    engine.disarm(*sub);
    engine.stop();
}

TEST_CASE("Service spark (real mechanism): fd/thread collapse holds across N absent watches",
          "[spark][mechanism][linux][resource]") {
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    const std::string pid = std::to_string(::getpid());
    auto first = engine.arm(*c, service_spec("yuzu-fdproof-0-" + pid + ".service"));
    if (!first.has_value()) {
        engine.stop();
        SUCCEED("service mechanism reports inert (no system bus on this host) — skipping");
        return;
    }
    REQUIRE(eventually([&] { return got.count() >= 1; }));
    const auto fd_base = linux_fd_count();
    const auto thread_base = linux_thread_count();

    std::vector<SparkEngine::SubscriptionId> subs;
    for (int i = 1; i < 20; ++i) {
        auto s = engine.arm(*c, service_spec("yuzu-fdproof-" + std::to_string(i) + "-" + pid +
                                             ".service"));
        REQUIRE(s.has_value());
        subs.push_back(*s);
    }
    REQUIRE(eventually([&] { return got.count() >= 20; }));

    // 19 MORE units armed onto the SAME bus connection: the bus fd + eventfd
    // are already open, so this should add ~0 fds. A regression to a
    // per-unit bus connection (today's guard model) would add ~2 fds/unit —
    // this assertion fails hard, immediately, on that regression.
    CHECK(linux_fd_count() <= fd_base + 2);
    // Thread count is FIXED at 1 mechanism thread regardless of watch count —
    // the wheel + this mechanism + the consumer dispatch thread are already
    // running at fd_base's sample, so arming 19 more units must add ~zero.
    // Small tolerance (matches the fd check above) absorbs unrelated
    // transient OS/runtime threads; a per-unit-thread regression (+19) still
    // fails this decisively.
    CHECK(linux_thread_count() <= thread_base + 2);

    for (auto& s : subs)
        engine.disarm(s);
    engine.disarm(*first);
    CHECK(eventually([&] { return linux_fd_count() <= fd_base; })); // no slot/fd leak on churn
    engine.stop();
}

// Live transition — env-gated so normal CI (incl. bus-less containers) skips it;
// runs on a real systemd box. Recipe:
//   sudo systemd-run --unit=yuzu-spark-probe.service /usr/bin/sleep 3600
//   ( sleep 4; sudo systemctl stop yuzu-spark-probe.service ) &
//   YUZU_SPARK_LIVE_UNIT=yuzu-spark-probe.service ./yuzu_agent_tests "[spark][linux][live]"
TEST_CASE("Service spark (real mechanism): live unit transition fires Running then Stopped",
          "[spark][mechanism][linux][live]") {
    const char* unit = std::getenv("YUZU_SPARK_LIVE_UNIT");
    if (!unit || !*unit) {
        SUCCEED("YUZU_SPARK_LIVE_UNIT unset — skipping live systemd integration test");
        return;
    }
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    auto sub = engine.arm(*c, service_spec(unit));
    REQUIRE(sub.has_value());
    REQUIRE(eventually([&] { return got.count() >= 1; }, 10000ms));
    REQUIRE(std::holds_alternative<ServiceSparkData>(got.at(0).data));
    CHECK(std::get<ServiceSparkData>(got.at(0).data).state == ServiceRunState::Running);

    CHECK(eventually(
        [&] {
            for (std::size_t i = 0; i < got.count(); ++i) {
                const auto& ev = got.at(i);
                if (std::holds_alternative<ServiceSparkData>(ev.data) &&
                    std::get<ServiceSparkData>(ev.data).state == ServiceRunState::Stopped)
                    return true;
            }
            return false;
        },
        30000ms));
    engine.stop();
}

#endif // __linux__ && YUZU_HAVE_LIBSYSTEMD

// ── Windows-only smoke: drive the REAL IOCP / TP_WAIT mechanisms against a live
//    file write / registry write. The cross-platform cases above prove the
//    engine plumbing via the fake; these prove the actual Windows bodies fire.
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <condition_variable>
#include <filesystem>
#include <fstream>

TEST_CASE("File spark (real mechanism): a live file write fires the spark",
          "[spark][mechanism][windows]") {
    namespace fs = std::filesystem;
    // PID-salted temp name — stable, never thread-id/clock (Defender flake #473).
    const fs::path target =
        fs::temp_directory_path() /
        ("spark_file_smoke_" + std::to_string(::GetCurrentProcessId()) + ".txt");
    { std::ofstream(target) << "seed"; } // parent dir + file exist before arming

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    const auto spec = file_spec(target.string());
    REQUIRE(engine.arm(*c, spec).has_value());
    engine.start();

    std::this_thread::sleep_for(150ms); // let the IOCP read arm
    { std::ofstream(target, std::ios::app) << "change"; }

    CHECK(eventually([&] { return got.count() >= 1; }, 8000ms));
    if (got.count() >= 1) {
        CHECK(got.at(0).type == SparkType::File);
        CHECK(got.at(0).key == spark_key(spec));
    }
    engine.stop();
    std::error_code ec;
    fs::remove(target, ec);
}

TEST_CASE("Registry spark (real mechanism): a live value write fires the spark",
          "[spark][mechanism][windows]") {
    // PID-unique subkey under HKCU so parallel CI runners can't collide.
    const std::string sub =
        "Software\\Yuzu\\SparkSmoke_" + std::to_string(::GetCurrentProcessId());
    HKEY h = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr,
                              &h, nullptr) == ERROR_SUCCESS);

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Registry, make_registry_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    const auto spec = registry_spec("HKCU", sub);
    REQUIRE(engine.arm(*c, spec).has_value());
    engine.start();

    std::this_thread::sleep_for(150ms); // let the TP_WAIT notify arm
    const DWORD val = 42;
    ::RegSetValueExA(h, "SparkVal", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&val), sizeof(val));

    CHECK(eventually([&] { return got.count() >= 1; }, 8000ms));
    if (got.count() >= 1) {
        CHECK(got.at(0).type == SparkType::Registry);
        CHECK(got.at(0).key == spark_key(spec));
    }
    engine.stop();
    ::RegCloseKey(h);
    ::RegDeleteKeyA(HKEY_CURRENT_USER, sub.c_str());
}

TEST_CASE("File spark (real mechanism): survives parent-dir delete + recreate",
          "[spark][mechanism][windows][resilience]") {
    namespace fs = std::filesystem;
    // Nest one level so the fallback ancestor is our own quiet dir, not the
    // churny temp root: <root>/<parent>/watched.txt — we delete <parent>.
    const fs::path root =
        fs::temp_directory_path() / ("spark_res_" + std::to_string(::GetCurrentProcessId()));
    const fs::path parent = root / "watched";
    const fs::path target = parent / "file.txt";
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(parent);
    { std::ofstream(target) << "seed"; }

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    const auto spec = file_spec(target.string());
    REQUIRE(engine.arm(*c, spec).has_value());
    engine.start();
    std::this_thread::sleep_for(200ms); // let the dir read arm

    // Blow away the watched file's parent dir → the mechanism's dir handle goes
    // bad and it must fall back to watching <root> for the parent's recreation.
    fs::remove(target, ec);
    fs::remove(parent, ec);
    std::this_thread::sleep_for(300ms);

    // Recreate parent + file, then modify → the ancestor watch must re-resolve
    // the parent dir and re-arm, so this post-recreate change still fires.
    fs::create_directories(parent);
    { std::ofstream(target) << "recreated"; }
    std::this_thread::sleep_for(150ms);
    { std::ofstream(target, std::ios::app) << "change-after-recreate"; }

    CHECK(eventually([&] { return got.count() >= 1; }, 10000ms));
    if (got.count() >= 1)
        CHECK(got.at(0).type == SparkType::File);
    engine.stop();
    fs::remove_all(root, ec);
}

TEST_CASE("File spark (real mechanism): disarm-then-rearm the same file does not lose the watch "
          "(PR #1927 review)",
          "[spark][mechanism][windows][resilience]") {
    namespace fs = std::filesystem;
    const fs::path target =
        fs::temp_directory_path() /
        ("spark_file_rearm_" + std::to_string(::GetCurrentProcessId()) + ".txt");
    { std::ofstream(target) << "seed"; }

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    const auto spec = file_spec(target.string());

    auto sub = engine.arm(*c, spec);
    REQUIRE(sub.has_value());
    engine.start();
    std::this_thread::sleep_for(150ms); // let the IOCP read arm — io_pending now true

    // Disarm then IMMEDIATELY re-arm the same file, no sleep between: unwatch()
    // cancels the outstanding read (io_pending was true) and, pre-fix, left the
    // DirWatch keyed in dirs_ with removing=true — a racing watch() reused
    // that about-to-be-freed slot silently (arm() reports success, but there
    // is no live ReadDirectoryChangesW behind it, and the whole entry vanishes
    // for good once the aborted completion drains). Whether the worker thread
    // wins the race to drain that completion before the very next arm() runs
    // is scheduling-dependent — repeat the cycle so one lucky interleaving
    // can't mask a regression (governance Gate-3 quality-engineer finding).
    for (int i = 0; i < 25; ++i) {
        engine.disarm(*sub);
        sub = engine.arm(*c, spec);
        REQUIRE(sub.has_value());
    }

    std::this_thread::sleep_for(150ms); // let the final read arm (if the fix works)
    { std::ofstream(target, std::ios::app) << "change"; }

    CHECK(eventually([&] { return got.count() >= 1; }, 8000ms));
    if (got.count() >= 1)
        CHECK(got.at(0).type == SparkType::File);

    engine.stop();
    std::error_code ec;
    fs::remove(target, ec);
}

TEST_CASE("File spark (real mechanism): arm() on a nonexistent drive root does not hang "
          "(PR #1927 review)",
          "[spark][mechanism][windows][resilience]") {
    // arm_ancestor's ancestor-walk previously never terminated for a root that
    // doesn't exist: parent_path() of a drive root is a FIXED POINT, not
    // empty, so "walk until empty" spun forever holding the mechanism's own
    // mu_ — bricking every other watch on this mechanism and hanging shutdown
    // behind it. Heap-allocate everything the probe thread touches (mirrors
    // the UP-1/UP2-3 detach-safety idiom above): on a regression this leaks a
    // thread parked forever inside watch() instead of UAF-ing a stack-local
    // engine out from under it — the point is proving termination, not
    // surviving a hang gracefully.
    char letter = 0;
    {
        const DWORD mask = ::GetLogicalDrives();
        // Scan Z down to B (skip only A, the traditional floppy letter) — a
        // heavily-provisioned CI runner (VPN/WSL/Docker Desktop/network
        // shares) can plausibly map every letter D-Z, and this is the ONLY
        // regression test for the arm_ancestor hang, so a silent skip here
        // would leave that fix unverified on exactly the runners most likely
        // to need it (governance Gate-3 quality-engineer finding).
        for (char cand = 'Z'; cand >= 'B'; --cand) {
            if (!(mask & (1u << (cand - 'A')))) {
                letter = cand;
                break;
            }
        }
    }
    if (!letter) {
        FAIL("no free drive letter (B-Z) available to probe an absent root — this box has "
             "every letter mapped, so the arm_ancestor hang fix (finding #3) is unverified here");
    }

    struct Probe {
        SparkEngine engine;
        Collector got;
        std::mutex m;
        std::condition_variable cv;
        bool done{false};
        bool armed{false};
    };
    auto probe = std::make_shared<Probe>();
    REQUIRE(probe->engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());
    auto c = probe->engine.register_consumer("c", probe->got.handler());
    REQUIRE(c.has_value());
    const auto consumer = *c;
    const auto spec = file_spec(std::string(1, letter) + ":\\nonexistent\\dir\\file.txt");
    probe->engine.start();

    std::thread([probe, consumer, spec] {
        auto r = probe->engine.arm(consumer, spec);
        std::lock_guard lk(probe->m);
        probe->armed = r.has_value();
        probe->done = true;
        probe->cv.notify_all();
    }).detach();

    std::unique_lock lk(probe->m);
    const bool finished = probe->cv.wait_for(lk, 5000ms, [&] { return probe->done; });
    CHECK(finished); // a regression hangs this forever instead of finishing
    lk.unlock();
    if (finished) {
        // watch()'s best-effort design always reports success — it records the
        // key and falls back to an ancestor watch for a later (re)creation —
        // even when neither arm_dir nor arm_ancestor found anything real to
        // watch, so `armed == true` here is the CORRECT outcome, not a
        // false-positive. `finished` above is the assertion that matters:
        // termination, not a failure return.
        CHECK(probe->armed);
        probe->engine.stop();
    }
    // else: deliberately leak `probe` (and the parked thread inside it).
}

TEST_CASE("File spark (real mechanism): watch() on an existing key with a different "
          "directory clears the stale registration (#1981)",
          "[spark][mechanism][windows][resilience]") {
    // Drives WindowsFileMechanism DIRECTLY, bypassing SparkEngine: its arm()
    // always derives `key` from spark_key(spec), so the same key can never
    // map to two different paths through THAT call path. ISparkMechanism's
    // contract treats `key` as an opaque caller-supplied identifier though
    // (spark_mechanism.hpp) — a future caller may legitimately re-call
    // watch() for an EXISTING key with updated params on a content edit
    // (Stage 6's differential re-apply: "unchanged bindings don't re-arm"
    // implies a changed one updates in place) without an intervening
    // explicit unwatch(). Before the fix, watch() unconditionally overwrote
    // key_index_[key], leaking the OLD DirWatch::keys[old_fname] entry
    // forever — a spurious-fires-forever leak from the abandoned path
    // (governance chaos-injector Gate 5 finding).
    namespace fs = std::filesystem;
    const auto pid = std::to_string(::GetCurrentProcessId());
    const fs::path dirA = fs::temp_directory_path() / ("spark_1981_a_" + pid);
    const fs::path dirB = fs::temp_directory_path() / ("spark_1981_b_" + pid);
    std::error_code ec;
    fs::remove_all(dirA, ec);
    fs::remove_all(dirB, ec);
    fs::create_directories(dirA);
    fs::create_directories(dirB);
    const fs::path fileA = dirA / "target.txt";
    const fs::path fileB = dirB / "target.txt";
    { std::ofstream(fileA) << "seed"; }
    { std::ofstream(fileB) << "seed"; }

    // Exception-safe cleanup (quality-engineer Gate 3): a failed assertion
    // would otherwise skip the trailing remove_all and leak dirA/dirB.
    // Declared before `mech` so it runs after ~mech closes its handles.
    struct DirCleanup {
        const fs::path& a;
        const fs::path& b;
        ~DirCleanup() {
            std::error_code e;
            fs::remove_all(a, e);
            fs::remove_all(b, e);
        }
    } dir_cleanup{dirA, dirB};

    struct Fires {
        std::mutex mu;
        std::vector<std::string> keys;
        void add(std::string k) {
            std::lock_guard lk(mu);
            keys.push_back(std::move(k));
        }
        std::size_t count() {
            std::lock_guard lk(mu);
            return keys.size();
        }
        std::string at(std::size_t i) {
            std::lock_guard lk(mu);
            return keys.at(i);
        }
    };
    auto fires = std::make_shared<Fires>();

    auto mech = make_file_mechanism();
    REQUIRE(mech);
    mech->start([fires](const std::string& key, SparkData) { fires->add(key); },
                [](const std::string&, bool, std::string_view) {});

    const std::string key = "shared-key-1981";
    REQUIRE(mech->watch(key, FileSparkParams{fileA.string()}).has_value());
    std::this_thread::sleep_for(150ms); // let the read arm

    // Re-arm the SAME key against dirB, with NO intervening unwatch().
    REQUIRE(mech->watch(key, FileSparkParams{fileB.string()}).has_value());
    std::this_thread::sleep_for(150ms);

    { std::ofstream(fileA, std::ios::app) << "changeA"; }
    std::this_thread::sleep_for(300ms);
    CHECK(fires->count() == 0); // the OLD registration must be gone — no spurious fire

    { std::ofstream(fileB, std::ios::app) << "changeB"; }
    CHECK(eventually([&] { return fires->count() >= 1; }, 8000ms));
    if (fires->count() >= 1)
        CHECK(fires->at(0) == key);

    mech->unwatch(key);
    std::this_thread::sleep_for(150ms); // let the worker drain the cancelled read
    mech->stop();
    // dirA/dirB removed by DirCleanup on scope exit.
}

TEST_CASE("File spark (real mechanism): retiring_ is capped and observable under "
          "re-arm churn while the worker is wedged (#1979/#1982)",
          "[spark][mechanism][windows][resilience]") {
    // Determinism trick: the mechanism has ONE worker draining its IOCP, and
    // it calls emit_ with mu_ RELEASED (spark_file.cpp run()) — a blocking
    // emit callback therefore wedges the drain loop deterministically while
    // watch()/unwatch() stay fully operable (they only need mu_, not the
    // worker). Flood retiring_ past the cap while the worker can't drain,
    // confirm it's bounded + observable + a fresh watch() is refused, then
    // release the gate and confirm a full drain plus a prompt, leak-free stop().
    namespace fs = std::filesystem;
    const auto pid = std::to_string(::GetCurrentProcessId());
    const fs::path trigger_dir = fs::temp_directory_path() / ("spark_1979_trig_" + pid);
    std::error_code ec;
    fs::remove_all(trigger_dir, ec);
    fs::create_directories(trigger_dir);
    const fs::path trigger_file = trigger_dir / "t.txt";
    { std::ofstream(trigger_file) << "seed"; }

    // Populated by the flood loop below; captured by reference into the cleanup
    // guard declared next.
    std::vector<fs::path> flood_dirs;

    // Exception-safe temp-dir cleanup (quality-engineer Gate 3): a failed
    // REQUIRE/CHECK unwinds past the trailing remove_all calls, otherwise
    // leaking up to kRetiringCap+8 PID-salted dirs. Declared BEFORE `mech` so
    // (reverse-declaration order) it runs AFTER ~mech has stop()'d/joined and
    // closed every directory handle — removing dirs with live handles open
    // would silently fail. Declared AFTER flood_dirs so flood_dirs outlives it.
    struct DirCleanup {
        const fs::path& trig;
        const std::vector<fs::path>& floods;
        ~DirCleanup() {
            std::error_code e;
            for (const auto& d : floods)
                fs::remove_all(d, e);
            fs::remove_all(trig, e);
        }
    } dir_cleanup{trigger_dir, flood_dirs};

    struct Gate {
        std::mutex m;
        std::condition_variable cv;
        bool release{false};
        std::atomic<int> emit_calls{0};
        void wait() {
            emit_calls.fetch_add(1);
            std::unique_lock lk(m);
            cv.wait(lk, [&] { return release; });
        }
        void open() {
            {
                std::lock_guard lk(m);
                release = true;
            }
            cv.notify_all();
        }
    };
    auto gate = std::make_shared<Gate>();

    auto mech = make_file_mechanism();
    REQUIRE(mech);
    // The mechanism's own cap — read live rather than duplicating the 256
    // literal, so a change to WindowsFileMechanism::kRetiringCap can't leave a
    // silently-wrong constant here (quality-engineer Gate 3).
    const std::uint64_t cap = mech->stats().retiring_cap;
    REQUIRE(cap > 0);

    // If any assertion below fails, Catch2 unwinds the stack — this guard's
    // destructor (declared AFTER mech, so it runs BEFORE mech's own
    // destructor per reverse-declaration-order) opens the gate unconditionally
    // first. Without it, a failed assertion here leaves the worker wedged in
    // emit() forever, and ~WindowsFileMechanism's stop()/worker_.join() hangs
    // the WHOLE test binary, not just this test case.
    struct GateOpener {
        std::shared_ptr<Gate> g;
        ~GateOpener() { g->open(); }
    } gate_opener{gate};

    mech->start([gate](const std::string&, SparkData) { gate->wait(); },
                [](const std::string&, bool, std::string_view) {});

    REQUIRE(mech->watch("trigger", FileSparkParams{trigger_file.string()}).has_value());
    std::this_thread::sleep_for(150ms); // let the read arm

    { std::ofstream(trigger_file, std::ios::app) << "change"; } // fires → worker blocks in emit()
    CHECK(eventually([&] { return gate->emit_calls.load() >= 1; }));

    for (std::uint64_t i = 0; i < cap + 8; ++i) {
        fs::path d = fs::temp_directory_path() /
                     ("spark_1979_flood_" + pid + "_" + std::to_string(i));
        fs::create_directories(d);
        flood_dirs.push_back(d);
        const std::string key = "flood" + std::to_string(i);
        // NOT a REQUIRE: this loop deliberately floods PAST the cap, so once
        // retiring_ hits the cap mid-loop, watch() is SUPPOSED to start
        // refusing — that's the mechanism under test, not a failure.
        // unwatch() on a key whose arm was refused (never in key_index_) is a
        // safe no-op, so it's fine to call unconditionally either way.
        (void)mech->watch(key, FileSparkParams{(d / "f.txt").string()});
        mech->unwatch(key); // cancels the just-armed read (if it armed) → retiring_
    }

    // The worker can't drain (wedged in emit()) — retiring_ must be bounded,
    // observable, and refuse further growth rather than growing unbounded.
    CHECK(mech->stats().retiring >= cap);
    auto refused =
        mech->watch("overflow", FileSparkParams{(trigger_dir / "overflow.txt").string()});
    REQUIRE_FALSE(refused.has_value());
    // Assert it's the CAP rejection specifically, not some unrelated failure
    // (e.g. a not-started mechanism) that would also produce an empty expected
    // (quality-engineer Gate 3).
    CHECK(refused.error().find("cap") != std::string::npos);
    CHECK(mech->stats().watch_rejected_total >= 1);

    gate->open(); // let the worker drain everything
    CHECK(eventually([&] { return mech->stats().retiring == 0; }, 10000ms));

    const auto t0 = std::chrono::steady_clock::now();
    mech->stop();
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    CHECK(elapsed < 5000ms);
    CHECK(mech->stats().quarantined_total == 0); // the cap kept this reachable in the first place
    // trigger_dir + flood_dirs removed by DirCleanup on scope exit.
}

TEST_CASE("Registry spark (real mechanism): survives key delete + recreate",
          "[spark][mechanism][windows][resilience]") {
    const std::string sub =
        "Software\\Yuzu\\SparkRes_" + std::to_string(::GetCurrentProcessId());
    HKEY h = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr,
                              &h, nullptr) == ERROR_SUCCESS);
    ::RegCloseKey(h);

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Registry, make_registry_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    const auto spec = registry_spec("HKCU", sub);
    REQUIRE(engine.arm(*c, spec).has_value());
    engine.start();
    std::this_thread::sleep_for(200ms); // let the target notify arm

    // Delete the watched key → the mechanism falls back to the ancestor NAME
    // watch on the parent (Software\Yuzu).
    ::RegDeleteKeyA(HKEY_CURRENT_USER, sub.c_str());
    std::this_thread::sleep_for(300ms);

    // Recreate it + write a value → the ancestor watch must re-resolve to the
    // target key and fire.
    HKEY h2 = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr,
                              &h2, nullptr) == ERROR_SUCCESS);
    const DWORD val = 7;
    ::RegSetValueExA(h2, "V", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&val), sizeof(val));

    CHECK(eventually([&] { return got.count() >= 1; }, 10000ms));
    if (got.count() >= 1)
        CHECK(got.at(0).type == SparkType::Registry);
    engine.stop();
    ::RegCloseKey(h2);
    ::RegDeleteKeyA(HKEY_CURRENT_USER, sub.c_str());
}

// ── Inline-tier dispatch latency (the ADR-0021 §3 µs claim) ──────────────────
//
// SCOPE — read before trusting these numbers. This measures ONLY the
// in-process inline dispatch: from the fire timestamp the engine stamps in
// emit_event (SparkEvent::at) to the inline handler's entry, run synchronously
// on the mechanism's own thread. It is the queue-BYPASS latency the inline tier
// exists to provide. It deliberately does NOT include:
//   - OS notification latency (kernel → us: ReadDirectoryChangesW /
//     RegNotifyChangeKeyValue delivery) — inherently ms-scale, outside the µs
//     claim, not something we control.
//   - the queued tier (bounded queue + a dispatch-thread hop) — that path is
//     ms-ish by design and is what inline avoids.
// Reported as min/median/max over many fires; the assertion is a LOOSE
// scheduler-quantum sanity bound only. The claim is µs-MEDIAN, NOT a hard
// worst-case cap (owner decision 2026-07-06: p99 can reach 100s of µs and a
// ~10ms outlier is possible on a shared pool), so a hard per-sample assert
// would be a false contract and a flake source.

namespace {
struct LatencyStats {
    std::size_t n{0};
    std::int64_t min_us{0}, median_us{0}, p90_us{0}, max_us{0};
};
LatencyStats summarize_us(std::vector<std::int64_t> v) {
    LatencyStats s;
    s.n = v.size();
    if (v.empty())
        return s;
    std::sort(v.begin(), v.end());
    s.min_us = v.front();
    s.max_us = v.back();
    s.median_us = v[v.size() / 2];
    s.p90_us = v[(v.size() * 9) / 10];
    return s;
}
} // namespace

TEST_CASE("Registry spark (real mechanism): inline dispatch is microsecond-scale",
          "[spark][mechanism][windows][latency]") {
    const std::string sub =
        "Software\\Yuzu\\SparkLat_" + std::to_string(::GetCurrentProcessId());
    HKEY h = nullptr;
    REQUIRE(::RegCreateKeyExA(HKEY_CURRENT_USER, sub.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr,
                              &h, nullptr) == ERROR_SUCCESS);

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Registry, make_registry_mechanism()).has_value());

    std::mutex lat_mu;
    std::vector<std::int64_t> dispatch_us; // SparkEvent::at → inline handler entry
    std::atomic<int> fires{0};
    auto inline_sub = engine.arm_inline(registry_spec("HKCU", sub), [&](const SparkEvent& ev) {
        const auto now = std::chrono::system_clock::now(); // MSVC: precise (~100ns) clock
        const auto us = std::chrono::duration_cast<std::chrono::microseconds>(now - ev.at).count();
        {
            std::lock_guard lk(lat_mu);
            dispatch_us.push_back(us);
        }
        fires.fetch_add(1, std::memory_order_relaxed);
    });
    REQUIRE(inline_sub.has_value());
    engine.start();
    std::this_thread::sleep_for(200ms); // let the TP_WAIT notify arm

    // Many spaced writes → many independent fires (re-arm-before-emit means each
    // spaced write is its own notify, not one coalesced event).
    constexpr int kWrites = 40;
    for (int i = 0; i < kWrites; ++i) {
        const DWORD v = static_cast<DWORD>(i);
        ::RegSetValueExA(h, "V", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v));
        std::this_thread::sleep_for(12ms);
    }
    CHECK(eventually([&] { return fires.load() >= 5; }, 8000ms));
    engine.stop();
    ::RegCloseKey(h);
    ::RegDeleteKeyA(HKEY_CURRENT_USER, sub.c_str());

    std::vector<std::int64_t> samples;
    {
        std::lock_guard lk(lat_mu);
        samples = dispatch_us;
    }
    const LatencyStats s = summarize_us(samples);
    const auto st = engine.stats();
    REQUIRE(s.n >= 5);
    WARN("[registry TP_WAIT] inline DISPATCH us over " << s.n << " fires: min=" << s.min_us
         << " median=" << s.median_us << " p90=" << s.p90_us << " max=" << s.max_us
         << " | inline HANDLER-exec us: max=" << st.inline_us_max << " over " << st.inline_calls_total
         << " calls, over_100us=" << st.inline_over_100us_total
         << " over_10ms=" << st.inline_over_10ms_total
         << "  (OS-notify latency NOT included — that is ms-scale, separate)");
    // Loose sanity only (µs-MEDIAN, not a hard cap): median dispatch under one
    // scheduler quantum. Catches a gross regression, tolerates the tail.
    CHECK(s.median_us < 10000);
}

TEST_CASE("File spark (real mechanism): inline dispatch is microsecond-scale",
          "[spark][mechanism][windows][latency]") {
    namespace fs = std::filesystem;
    const fs::path target =
        fs::temp_directory_path() /
        ("spark_lat_" + std::to_string(::GetCurrentProcessId()) + ".txt");
    { std::ofstream(target) << "seed"; }

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::File, make_file_mechanism()).has_value());

    std::mutex lat_mu;
    std::vector<std::int64_t> dispatch_us;
    std::atomic<int> fires{0};
    auto inline_sub = engine.arm_inline(file_spec(target.string()), [&](const SparkEvent& ev) {
        const auto now = std::chrono::system_clock::now();
        const auto us = std::chrono::duration_cast<std::chrono::microseconds>(now - ev.at).count();
        {
            std::lock_guard lk(lat_mu);
            dispatch_us.push_back(us);
        }
        fires.fetch_add(1, std::memory_order_relaxed);
    });
    REQUIRE(inline_sub.has_value());
    engine.start();
    std::this_thread::sleep_for(200ms); // let the IOCP read arm

    constexpr int kWrites = 40;
    for (int i = 0; i < kWrites; ++i) {
        { std::ofstream(target, std::ios::app) << "x"; }
        std::this_thread::sleep_for(12ms);
    }
    CHECK(eventually([&] { return fires.load() >= 5; }, 8000ms));
    engine.stop();
    std::error_code ec;
    fs::remove(target, ec);

    std::vector<std::int64_t> samples;
    {
        std::lock_guard lk(lat_mu);
        samples = dispatch_us;
    }
    const LatencyStats s = summarize_us(samples);
    const auto st = engine.stats();
    REQUIRE(s.n >= 5);
    WARN("[file IOCP] inline DISPATCH us over " << s.n << " fires: min=" << s.min_us
         << " median=" << s.median_us << " p90=" << s.p90_us << " max=" << s.max_us
         << " | inline HANDLER-exec us: max=" << st.inline_us_max << " over " << st.inline_calls_total
         << " calls, over_100us=" << st.inline_over_100us_total
         << " over_10ms=" << st.inline_over_10ms_total
         << "  (OS-notify latency NOT included — that is ms-scale, separate)");
    CHECK(s.median_us < 10000);
}

// ── Windows Service spark: real SCM mechanism. Winmgmt (WMI) is READ-ONLY in
//    every case below (SERVICE_QUERY_STATUS only) — never stopped/started —
//    it is universally present and safe to watch on any Windows host. A live
//    STATE TRANSITION needs a service this box can safely toggle, which
//    varies by host, so that one case is env-gated (YUZU_SPARK_LIVE_SERVICE).

#include <tlhelp32.h>

#include <cstdlib> // getenv

namespace {
DWORD windows_thread_count() {
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    DWORD n = 0;
    const DWORD pid = ::GetCurrentProcessId();
    if (::Thread32First(snap, &te)) {
        do {
            if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD) &&
                te.th32OwnerProcessID == pid)
                ++n;
            te.dwSize = sizeof(te);
        } while (::Thread32Next(snap, &te));
    }
    ::CloseHandle(snap);
    return n;
}
} // namespace

TEST_CASE("Service spark (real mechanism): initial state resolves for a real and an absent service",
          "[spark][mechanism][windows]") {
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    auto real = engine.arm(*c, service_spec("Winmgmt"));
    REQUIRE(real.has_value());
    REQUIRE(eventually([&] { return got.count() >= 1; }));
    REQUIRE(std::holds_alternative<ServiceSparkData>(got.at(0).data));
    CHECK(std::get<ServiceSparkData>(got.at(0).data).state == ServiceRunState::Running);

    const std::string absent_name = "YuzuNoSuchSvc_" + std::to_string(::GetCurrentProcessId());
    auto absent = engine.arm(*c, service_spec(absent_name));
    REQUIRE(absent.has_value());
    REQUIRE(eventually([&] { return got.count() >= 2; }));
    REQUIRE(std::holds_alternative<ServiceSparkData>(got.at(1).data));
    CHECK(std::get<ServiceSparkData>(got.at(1).data).state == ServiceRunState::Stopped);

    engine.disarm(*real);
    engine.disarm(*absent);
    engine.stop();
}

TEST_CASE("Service spark (real mechanism): two spark keys folding onto one service each "
          "get their own emit",
          "[spark][mechanism][windows]") {
    // "Winmgmt" and "WINMGMT" are DISTINCT engine-level spark keys (no
    // engine-level dedup — different ServiceSparkParams::service_name
    // strings) but fold_ci coalesces them onto the SAME underlying SvcWatch
    // (SCM service names are case-insensitive). Winmgmt is read-only here,
    // never stopped/started. Governance flagged this exact scenario as
    // untested by every N-watch resource test, since those all use N
    // distinct names.
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    auto first = engine.arm(*c, service_spec("Winmgmt"));
    REQUIRE(first.has_value());
    REQUIRE(eventually([&] { return got.count() >= 1; }));

    auto second = engine.arm(*c, service_spec("WINMGMT"));
    REQUIRE(second.has_value());
    REQUIRE(eventually([&] { return got.count() >= 2; })); // the coalescing key gets its OWN emit

    CHECK(got.at(0).key != got.at(1).key); // distinct engine keys...
    REQUIRE(std::holds_alternative<ServiceSparkData>(got.at(1).data));
    CHECK(std::get<ServiceSparkData>(got.at(1).data).state ==
          ServiceRunState::Running); // ...same service, same resolved state

    engine.disarm(*first);
    engine.disarm(*second);
    engine.stop();
}

TEST_CASE("Service spark (real mechanism): thread count is fixed at 1 regardless of watch count",
          "[spark][mechanism][windows][resource]") {
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    auto first = engine.arm(*c, service_spec("Winmgmt"));
    REQUIRE(first.has_value());
    REQUIRE(eventually([&] { return got.count() >= 1; }));
    const DWORD threads_base = windows_thread_count();

    // A handful of always-present real services (read-only) + absent ones —
    // handle count grows (one SC_HANDLE per service is unavoidable), thread
    // count must NOT. Arm one at a time (waiting for each initial emit before
    // the next arm) rather than in a burst — avoids a race where the thread
    // count is sampled before every registration has settled.
    const char* more[] = {"EventLog", "Schedule", "LanmanWorkstation", "Dnscache"};
    std::vector<SparkEngine::SubscriptionId> subs;
    std::size_t expect = 1;
    for (const char* name : more) {
        auto s = engine.arm(*c, service_spec(name));
        REQUIRE(s.has_value());
        subs.push_back(*s);
        ++expect;
        REQUIRE(eventually([&] { return got.count() >= expect; }));
    }
    for (int i = 0; i < 15; ++i) {
        const std::string name =
            "YuzuFdProof_" + std::to_string(i) + "_" + std::to_string(::GetCurrentProcessId());
        auto s = engine.arm(*c, service_spec(name));
        REQUIRE(s.has_value());
        subs.push_back(*s);
        ++expect;
        REQUIRE(eventually([&] { return got.count() >= expect; }));
    }
    // Small tolerance absorbs unrelated transient OS threads (observed once
    // in this session — traced via per-arm instrumentation to an unrelated
    // blip, not this mechanism); a per-watch-thread regression (+19) still
    // fails this decisively.
    CHECK(windows_thread_count() <= threads_base + 2); // +19 more watches, ~0 more threads

    for (auto& s : subs)
        engine.disarm(s);
    engine.disarm(*first);
    engine.stop();
}

TEST_CASE("Service spark (real mechanism): rapid arm/unwatch churn does not UAF (R2)",
          "[spark][mechanism][windows][resilience]") {
    // Winmgmt is READ-ONLY here too — never stopped/started, only watched.
    // NotifyServiceStatusChangeW's immediate on-registration callback fires
    // moments after arming, so a tight arm-then-immediately-unwatch loop races
    // that delivery against teardown_watch's SleepEx(0,TRUE) drain — exactly
    // the R2 hazard (a queued APC running after its SvcWatch is freed) that a
    // static create/delete-without-ever-toggling case would never exercise.
    // If teardown_watch's drain were wrong this would UAF/crash under ASan
    // (or corrupt heap state observably) well before kChurn iterations —
    // but the crash-only oracle is only as strong as the sanitizer coverage
    // behind it, and per docs/ci-architecture.md sanitizers are Linux-
    // self-hosted-nightly only: this Windows test never runs under ASan in
    // CI, so a heap-corrupting-but-non-crashing variant of the bug could
    // pass silently here (governance Gate-3 quality-engineer finding). The
    // production fix (spark_service.cpp's retiring_/retire_grace mechanism)
    // no longer frees a SvcWatch synchronously on removal specifically to
    // remove the UAF this test targets, independent of this gap.
    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());
    Collector got;
    auto c = engine.register_consumer("c", got.handler());
    REQUIRE(c.has_value());
    engine.start();

    constexpr int kChurn = 200;
    for (int i = 0; i < kChurn; ++i) {
        auto sub = engine.arm(*c, service_spec("Winmgmt"));
        REQUIRE(sub.has_value());
        engine.disarm(*sub);
    }
    engine.stop();
    SUCCEED("completed " << kChurn << " rapid arm/unwatch cycles without a crash");
}

// Live transition + latency — env-gated: a real service transition needs a
// service THIS host can safely stop/start, which varies by box (unlike the
// Linux systemd-run recipe, Windows has no equivalent "just create a throwaway
// unit" primitive that starts into a real RUNNING state without a genuine
// service binary). Recipe: pick an already-installed, safe-to-toggle service
// (e.g. "Spooler" on a box that doesn't care about print spooling) and run:
//   net stop Spooler   REM ensure a known starting state
//   yuzu_agent_tests.exe "[spark][windows][live]" with YUZU_SPARK_LIVE_SERVICE=Spooler set,
//   and toggle it externally (net start / net stop Spooler) while the test waits.
TEST_CASE("Service spark (real mechanism): live service transition + inline dispatch latency",
          "[spark][mechanism][windows][live][latency]") {
    const char* env = std::getenv("YUZU_SPARK_LIVE_SERVICE");
    if (!env || !*env) {
        SUCCEED("YUZU_SPARK_LIVE_SERVICE unset — skipping live service integration test");
        return;
    }
    const std::string name(env);

    SparkEngine engine;
    REQUIRE(engine.register_mechanism(SparkType::Service, make_service_mechanism()).has_value());

    std::mutex lat_mu;
    std::vector<std::int64_t> dispatch_us;
    std::vector<ServiceRunState> states;
    auto inline_sub = engine.arm_inline(service_spec(name), [&](const SparkEvent& ev) {
        const auto now = std::chrono::system_clock::now();
        const auto us = std::chrono::duration_cast<std::chrono::microseconds>(now - ev.at).count();
        std::lock_guard lk(lat_mu);
        dispatch_us.push_back(us);
        if (std::holds_alternative<ServiceSparkData>(ev.data))
            states.push_back(std::get<ServiceSparkData>(ev.data).state);
    });
    REQUIRE(inline_sub.has_value());
    engine.start();

    // Toggle externally (operator/script) while this waits for at least the
    // initial resolve + a handful of transitions.
    CHECK(eventually(
        [&] {
            std::lock_guard lk(lat_mu);
            return states.size() >= 3;
        },
        60000ms));
    engine.stop();

    std::vector<std::int64_t> samples;
    {
        std::lock_guard lk(lat_mu);
        samples = dispatch_us;
    }
    if (samples.size() >= 2) {
        const LatencyStats s = summarize_us(samples);
        WARN("[service SCM] inline DISPATCH us over " << s.n << " fires: min=" << s.min_us
             << " median=" << s.median_us << " p90=" << s.p90_us << " max=" << s.max_us
             << "  (OS-notify latency NOT included — that is APC-delivery-scale, separate)");
        CHECK(s.median_us < 10000);
    }
}

#endif // _WIN32
