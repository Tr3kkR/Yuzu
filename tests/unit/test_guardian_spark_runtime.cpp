// test_guardian_spark_runtime.cpp - the GuardianSparkRuntime core (ADR-0021 rung
// 3, hardened rung 4.5). Drives the runtime against fake IStateReader /
// ISparkBackend seams (owned via shared_ptr): arm/disarm edges, shared-watcher
// fan-out, evaluate_key verdict -> outbox -> drain, pending-initial, tri-state
// Unknown -> health, generation purge, cap/backpressure leaving an eval pending,
// detach-safety of a late handler EVEN when the reader ref is dropped, and a
// multi-threaded stress case that is the TSan checkpoint.

#include "guardian_spark_runtime.hpp"

#include "guardian_lifecycle_journal.hpp"

#include <yuzu/agent/kv_store.hpp>
#include <yuzu/agent/spark.hpp>

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <future>
#include <functional>
#include <latch>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <unordered_map>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::agent;

namespace {
using clk = std::chrono::steady_clock;

// A reader whose single-key responses tests set directly. Thread-safe for the
// blocking gate tests (one in-flight read; the response fields aren't rewritten
// during it).
struct FakeReader : IStateReader {
    ReadResult<FileSnapshot> file{read_known(FileSnapshot{.exists = true, .size = 4, .hash = "h"})};
    ReadResult<RegistrySnapshot> reg_snap{read_known(RegistrySnapshot{.present = true, .value = "v"})};
    std::unordered_map<std::string, ReadResult<RegistrySnapshot>> reg_values; ///< per value_name override
    ReadResult<ServiceRunState> svc{read_known(ServiceRunState::Running)};
    std::function<void()> on_read; // optional gate
    std::atomic<int> reads{0};
    std::atomic<std::uint64_t> last_hash_cap{0};
    std::atomic<std::size_t> last_reg_plan_size{0};
    ReadResult<FileSnapshot> read_file(const FileSparkParams&, const FileReadPlan& plan) override {
        reads.fetch_add(1);
        last_hash_cap.store(plan.hash_cap);
        if (on_read) on_read();
        return file;
    }
    RegistryRead read_registry(const RegistrySparkParams&, const RegistryReadPlan& plan) override {
        reads.fetch_add(1);
        last_reg_plan_size.store(plan.value_names.size());
        RegistryRead out;
        out.latency_us = 7;
        for (const auto& vn : plan.value_names) {
            const auto it = reg_values.find(vn);
            out.values.emplace(vn, it != reg_values.end() ? it->second : reg_snap);
        }
        return out;
    }
    ReadResult<ServiceRunState> read_service(const ServiceSparkParams&) override {
        reads.fetch_add(1);
        return svc;
    }
    std::atomic<int> stops{0};
    void request_stop() noexcept override { stops.fetch_add(1); }
};

/// An EPOCH/PULSE extension of FakeBackend's hang_next_arm / hang_next_disarm idiom
/// below, for the #3848 blocking-backend checkpoint.
///
/// WHY AN EXTENSION AND NOT A SECOND MECHANISM. hang_next_* is a single-waiter,
/// single-shot park: a test arms it, one call enters, the test releases it. Exactly right
/// for pinning one race, useless for a sustained soak where EVERY backend call must be
/// able to block, repeatedly, on several threads at once, with nobody holding a per-call
/// handle. So this adds the two things that turn that idiom into a soak gate - a
/// repeating admission rule (`park_every`) and a broadcast release (`pulse()`) - and
/// keeps everything else, naming included, the same. Two park styles in one file read as
/// one family; two unrelated mechanisms would not.
///
/// NEVER HANGS THE SUITE. Every wait is a `wait_for` with a generous deadline, and a
/// deadline hit is COUNTED (`watchdog_trips`) rather than silently absorbed - the test
/// asserts that count is zero, so a gate that stopped being released fails loudly
/// instead of wedging the binary the way a bare `wait()` would.
struct BlockingGate {
    // ── configuration: set before any thread starts, never touched after ──
    int park_every{0};              ///< 0 disables the gate entirely, so the existing
                                    ///< hang_next_* tests are completely unaffected
    int long_every{0};              ///< every Nth park is a LONG hold; 0 = none
    std::uint64_t long_hold_pulses{200}; ///< a long hold lasts this many releaser pulses

    mutable std::mutex mu;
    std::condition_variable cv;
    bool open_{false};              ///< latched open at shutdown: every park returns at once
    std::uint64_t epoch{0};         ///< ++ per pulse(); a short park waits for the next one
    int calls{0};
    int parks{0};
    int parked{0};
    int peak_parked{0};
    std::uint64_t total_parked{0};
    std::uint64_t long_holds{0};
    std::uint64_t watchdog_trips{0};
    /// At most ONE long hold per lane in flight. Each churner owns one IoClass lane and
    /// submits one op at a time, so this only stops a second long hold being selected for
    /// a lane whose previous one has not finished unwinding.
    std::array<bool, 3> long_in_flight{};

    /// Called from inside a backend call, on whatever thread the executor ran it on.
    /// `lane` is the IoClass index, or -1 for a call with no lane (the send fn).
    void maybe_park(int lane) {
        std::unique_lock lk(mu);
        if (park_every <= 0)
            return;
        if (++calls % park_every != 0)
            return;
        const bool want_long = long_every > 0 && (++parks % long_every == 0) && lane >= 0 &&
                               !long_in_flight[static_cast<std::size_t>(lane)];
        ++total_parked;
        ++parked;
        peak_parked = std::max(peak_parked, parked);
        bool released = false;
        if (want_long) {
            ++long_holds;
            long_in_flight[static_cast<std::size_t>(lane)] = true;
            // A LONG hold deliberately outlives the caller's backend_op_deadline, so the
            // submitter observes IoFailure::Timeout and the late-success path runs. Its
            // length is counted in RELEASER PULSES, not wall-clock, so it scales with how
            // slowly a sanitizer build is actually running rather than racing a fixed clock.
            const auto target = epoch + long_hold_pulses;
            released = cv.wait_for(lk, std::chrono::seconds{30},
                                   [&] { return open_ || epoch >= target; });
            long_in_flight[static_cast<std::size_t>(lane)] = false;
        } else {
            const auto target = epoch + 1;
            released = cv.wait_for(lk, std::chrono::seconds{30},
                                   [&] { return open_ || epoch >= target; });
        }
        if (!released)
            ++watchdog_trips;
        --parked;
    }

    void pulse() {
        {
            std::lock_guard lk(mu);
            ++epoch;
        }
        cv.notify_all();
    }
    /// Latch every current and future park open. Idempotent; REQUIRED before any join.
    void open() {
        {
            std::lock_guard lk(mu);
            open_ = true;
        }
        cv.notify_all();
    }
};

struct FakeBackend : ISparkBackend {
    std::atomic<std::uint64_t> next{1};
    std::atomic<int> arms{0};
    std::atomic<int> disarms{0};
    std::atomic<bool> fail_arm{false};
    std::atomic<bool> throw_arm{false}; ///< arm() throws (a backend that throws, not just fails)
    // #2233 item 3: park the NEXT arm() call (on whichever thread calls it - the
    // GuardianIoExecutor detached worker in production/these tests) until
    // release_hang() is called. Mirrors FakeServiceMechanism's hang idiom in
    // test_guardian_engine_spark_reconcile.cpp: the gate is a SEPARATE lock from
    // nothing here (FakeBackend has no other lock), so release_hang() never blocks.
    std::atomic<bool> hang_next_arm{false};
    std::mutex gate_mu_;
    std::condition_variable gate_cv_;
    bool entered_hang_{false};
    bool released_{false};
    /// #3848: the soak gates. Disabled (park_every == 0) unless a test configures them,
    /// so every pre-existing case behaves exactly as before.
    BlockingGate arm_park;
    BlockingGate disarm_park;
    // #3848 census: every subscription id this backend HANDED OUT and every id it was
    // asked to release - written from executor worker threads AND (for the abandonment
    // self-disarm) from inside the arm worker's own lambda. Storage (ids_mu_/armed_ids_/
    // disarmed_ids_) and the exact-id accessors live below, after disarm() - #3816's
    // shape, adopted as-is on merge rather than forking a parallel raw-member convention.
    /// The IoClass lane a spec belongs to, as the runtime derives it — the gates key
    /// their per-lane long-hold state on this. -1 for an inline (non-executor) type.
    static int lane_of(SparkType t) {
        switch (t) {
        case SparkType::File: return 0;
        case SparkType::Registry: return 1;
        case SparkType::Service: return 2;
        default: return -1;
        }
    }
    /// The lane of the id we most recently handed out, so disarm() — which receives only
    /// an id — can park on the right lane. Written under ids_mu_ by arm().
    std::unordered_map<std::uint64_t, int> id_lane_;

    std::expected<std::uint64_t, std::string> arm(const SparkSpec& spec) override {
        if (hang_next_arm.exchange(false)) {
            std::unique_lock<std::mutex> lk{gate_mu_};
            entered_hang_ = true;
            gate_cv_.notify_all();
            gate_cv_.wait(lk, [this] { return released_; });
        }
        // #3848: the soak park sits AFTER the single-shot hang (so the two idioms never
        // interleave) and BEFORE the failure injections (so a parked arm still resolves
        // the way an unparked one would).
        const int lane = lane_of(spec.type);
        arm_park.maybe_park(lane);
        if (throw_arm.load()) throw std::runtime_error("arm boom");
        if (fail_arm.load()) return std::unexpected(std::string{"no mechanism"});
        arms.fetch_add(1);
        const std::uint64_t id = next.fetch_add(1);
        {
            std::lock_guard<std::mutex> lk{ids_mu_};
            armed_ids_.push_back(id);
            id_lane_[id] = lane;
        }
        return id;
    }
    void disarm(std::uint64_t sub) override {
        if (hang_next_disarm.exchange(false)) {
            std::unique_lock<std::mutex> lk{disarm_gate_mu_};
            disarm_entered_hang_ = true;
            disarm_gate_cv_.notify_all();
            disarm_gate_cv_.wait(lk, [this] { return disarm_released_; });
        }
        int lane = -1;
        {
            std::lock_guard<std::mutex> lk{ids_mu_};
            disarmed_ids_.push_back(sub);
            if (const auto it = id_lane_.find(sub); it != id_lane_.end())
                lane = it->second;
        }
        // #3848: recorded BEFORE the park, so a disarm the test then has to wait out is
        // still counted; the census reconciles ids, never call ordering.
        disarm_park.maybe_park(lane);
        disarms.fetch_add(1);
    }
    /// #3816: exact-id recording, not just balanced counts - a wrong-handle disarm
    /// (the right COUNT, the wrong SUBSCRIPTION) would pass a count-only check.
    std::vector<std::uint64_t> armed_ids() const {
        std::lock_guard<std::mutex> lk{ids_mu_};
        return armed_ids_;
    }
    std::vector<std::uint64_t> disarmed_ids() const {
        std::lock_guard<std::mutex> lk{ids_mu_};
        return disarmed_ids_;
    }
    mutable std::mutex ids_mu_;
    std::vector<std::uint64_t> armed_ids_;
    std::vector<std::uint64_t> disarmed_ids_;

    /// Blocks until a hung arm() has actually entered its wait (avoids a racy
    /// sleep-based poll for "is the worker parked yet").
    bool wait_entered_hang(std::chrono::seconds timeout) {
        std::unique_lock<std::mutex> lk{gate_mu_};
        return gate_cv_.wait_for(lk, timeout, [this] { return entered_hang_; });
    }
    void release_hang() {
        {
            std::lock_guard<std::mutex> lk{gate_mu_};
            released_ = true;
        }
        gate_cv_.notify_all();
    }
    /// Quality-engineer Gate 3 finding: entered_hang_/released_ latch permanently
    /// true after one release_hang() and were never resettable, a silent-no-op trap
    /// for any test needing a SECOND hang on the same FakeBackend (e.g. a
    /// timeout-then-retry sequence). Call between uses, only once release_hang()'s
    /// waiter has actually woken (the caller's own synchronization - typically
    /// after observing the effect of the first hang, e.g. a timeout return).
    void reset_hang() {
        std::lock_guard<std::mutex> lk{gate_mu_};
        entered_hang_ = false;
        released_ = false;
    }

    /// Adversarial-review C2/c2 regression coverage: park the NEXT disarm() call
    /// (a SEPARATE gate from arm()'s, so a test can hang a rollback's disarm
    /// specifically without also hanging any arm).
    std::atomic<bool> hang_next_disarm{false};
    std::mutex disarm_gate_mu_;
    std::condition_variable disarm_gate_cv_;
    bool disarm_entered_hang_{false};
    bool disarm_released_{false};
    bool wait_entered_disarm_hang(std::chrono::seconds timeout) {
        std::unique_lock<std::mutex> lk{disarm_gate_mu_};
        return disarm_gate_cv_.wait_for(lk, timeout, [this] { return disarm_entered_hang_; });
    }
    void release_disarm_hang() {
        {
            std::lock_guard<std::mutex> lk{disarm_gate_mu_};
            disarm_released_ = true;
        }
        disarm_gate_cv_.notify_all();
    }
    /// See reset_hang()'s doc - same single-shot-latch fix, disarm side.
    void reset_disarm_hang() {
        std::lock_guard<std::mutex> lk{disarm_gate_mu_};
        disarm_entered_hang_ = false;
        disarm_released_ = false;
    }
};

SparkSpec file_spec(const std::string& path) {
    return SparkSpec{SparkType::File, FileSparkParams{path}};
}
RuleAssertion file_exists_rule(const std::string& rule_id, bool present = true) {
    RuleAssertion a;
    a.kind = AssertionKind::FileExists;
    a.rule_id = rule_id;
    a.expect_present = present;
    return a;
}
SparkSpec svc_spec(const std::string& name) {
    return SparkSpec{SparkType::Service, ServiceSparkParams{name}};
}
RuleAssertion svc_running_rule(const std::string& rule_id) {
    RuleAssertion a;
    a.kind = AssertionKind::ServiceRunning;
    a.rule_id = rule_id;
    return a;
}
SparkSpec reg_spec(const std::string& hive, const std::string& key) {
    return SparkSpec{SparkType::Registry, RegistrySparkParams{hive, key}};
}
RuleAssertion registry_rule(const std::string& rule_id, const std::string& value_name,
                            const std::string& expected) {
    RuleAssertion a;
    a.kind = AssertionKind::RegistryEquals;
    a.rule_id = rule_id;
    a.value_name = value_name;
    a.expected_value = expected;
    return a;
}
// Drains the compliance/health verdicts these tests were written against.
// Filters out Lifecycle (rung 7 audit-on-arm: attach_rule/detach_rule now
// enqueue an armed/disarmed entry on every call) - a SEPARATE helper below
// (drain_lifecycle) is for the tests that specifically exercise that.
std::vector<OutboxEntry> drain_all(GuardianSparkRuntime& rt) {
    std::vector<OutboxEntry> got;
    rt.drain([&](const OutboxEntry& e) {
        if (e.domain != OutboxDomain::Lifecycle)
            got.push_back(e);
        return SendResult::Sent;
    });
    return got;
}
std::vector<OutboxEntry> drain_lifecycle(GuardianSparkRuntime& rt) {
    std::vector<OutboxEntry> got;
    rt.drain([&](const OutboxEntry& e) {
        if (e.domain == OutboxDomain::Lifecycle)
            got.push_back(e);
        return SendResult::Sent;
    });
    return got;
}
std::shared_ptr<GuardianSparkRuntime> make_rt(std::shared_ptr<FakeReader> r,
                                              std::shared_ptr<FakeBackend> b,
                                              GuardianSparkRuntime::Config cfg = {}) {
    // Deterministic clock so debounce is controllable. The lambda captures nothing
    // borrowed (the static satisfies the self-contained-clock contract).
    static std::atomic<std::int64_t> tick{0};
    return std::make_shared<GuardianSparkRuntime>(
        std::move(r), std::move(b), cfg,
        [] { return clk::time_point{} + std::chrono::milliseconds(tick.fetch_add(1000)); });
}

// F5 (6b/6c): a PER-TEST clock the test explicitly advances, unlike make_rt's TU-global
// clock above which auto-advances +1s on every call regardless of which test invoked it.
// The M1 refresh/demotion intervals are minutes-scale - driving them off an uncontrolled
// shared auto-tick would make elapsed-time assertions racy against test execution order.
// Holds its counter in a shared_ptr (not a raw capture) so the runtime's clock stays
// self-contained per its own lifetime contract (guardian_spark_runtime.hpp:186-193,
// the constructor doc block).
struct SettableClock {
    std::shared_ptr<std::atomic<std::int64_t>> ms{std::make_shared<std::atomic<std::int64_t>>(0)};
    void advance(std::int64_t delta_ms) { ms->fetch_add(delta_ms); }
    [[nodiscard]] RuntimeClock as_runtime_clock() const {
        auto m = ms;
        return [m] { return clk::time_point{} + std::chrono::milliseconds(m->load()); };
    }
};
std::shared_ptr<GuardianSparkRuntime> make_rt_with_clock(std::shared_ptr<FakeReader> r,
                                                         std::shared_ptr<FakeBackend> b,
                                                         const SettableClock& sc,
                                                         GuardianSparkRuntime::Config cfg = {}) {
    return std::make_shared<GuardianSparkRuntime>(std::move(r), std::move(b), cfg,
                                                  sc.as_runtime_clock());
}

// A replayable lifecycle entry for try_page_batch tests.
OutboxEntry lc_entry(const std::string& rule, const std::string& eid, const std::string& kind = "armed") {
    return OutboxEntry::lifecycle(rule, 1, eid, 1'700'000'000'000'000'000, kind, "file", "n");
}

// A component + runtime + KvStore rig for page_into_window integration (item 7 PR-Ag C5).
struct PageRig {
    yuzu::test::TempDbFile db{"yuzu_test_page-"};
    std::unique_ptr<KvStore> kv;
    std::shared_ptr<GuardianSparkRuntime> rt;
    std::unique_ptr<GuardianLifecycleJournal> journal;
    PageRig() {
        auto r = KvStore::open(db.path);
        REQUIRE(r.has_value());
        kv = std::make_unique<KvStore>(std::move(*r));
        rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>());
        journal = std::make_unique<GuardianLifecycleJournal>(kv.get());
    }
    // Persist one record as its own batch (a distinct persist call → a distinct batch key).
    void persist(const std::string& rule, const std::string& kind = "armed") {
        std::vector<std::shared_ptr<const JournalRecord>> pending{
            std::make_shared<const JournalRecord>(
                JournalRecord{.rule_id = rule, .generation = 1, .event_id = "e-" + rule,
                              .enqueued_ns = 1'700'000'000'000'000'000, .kind = kind,
                              .guard_type = "file", .rule_name = "n"})};
        REQUIRE(journal->persist(pending, nullptr, kJournalPersistUnbounded, kJournalPersistUnbounded) == 1);
    }
};
} // namespace

TEST_CASE("attach arms the watcher on the 0->1 edge; a sibling rule shares it", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));

    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    REQUIRE(b->arms.load() == 1);
    REQUIRE(rt->armed_key_count() == 1);

    REQUIRE(rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true));
    REQUIRE(b->arms.load() == 1); // shared watcher, no second arm
    REQUIRE(rt->rule_count() == 2);
    REQUIRE(rt->armed_key_count() == 1);

    // One event fans out to both rules.
    rt->evaluate_key(key, EvalReason::Event);
    const auto got = drain_all(*rt);
    REQUIRE(got.size() == 2); // both compliant edges
}

TEST_CASE("detach disarms on the ->0 edge; a sibling detach keeps the watcher", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);

    rt->detach_rule("r1"); // sibling remains -> no disarm
    REQUIRE(b->disarms.load() == 0);
    REQUIRE(rt->armed_key_count() == 1);
    REQUIRE(rt->rule_count() == 1);

    rt->detach_rule("r2"); // ->0 -> disarm
    REQUIRE(b->disarms.load() == 1);
    REQUIRE(rt->armed_key_count() == 0);
}

TEST_CASE("evaluate_key re-reads live state each pass (event is a hint)", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_known(FileSnapshot{.exists = true}); // compliant
    rt->evaluate_key(key, EvalReason::Initial);
    auto got = drain_all(*rt);
    REQUIRE(got.size() == 1);
    REQUIRE(got[0].drift.compliant);

    r->file = read_known(FileSnapshot{.exists = false}); // now absent
    rt->evaluate_key(key, EvalReason::Event);            // re-reads -> drift
    got = drain_all(*rt);
    REQUIRE(got.size() == 1);
    REQUIRE_FALSE(got[0].drift.compliant);
    REQUIRE(got[0].drift.detected_value == "<absent>");
}

TEST_CASE("pending-initial holds until a Known verdict, kept on Unknown", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE(rt->pending_initial(key) == std::vector<std::string>{"r1"});

    // Unknown read -> health event, pending-initial RETAINED.
    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(rt->pending_initial(key) == std::vector<std::string>{"r1"});
    auto got = drain_all(*rt);
    REQUIRE(got.size() == 1);
    REQUIRE(got[0].domain == OutboxDomain::Health);
    REQUIRE_FALSE(got[0].healthy);

    // Known read -> compliance verdict, pending-initial cleared.
    r->file = read_known(FileSnapshot{.exists = true});
    rt->evaluate_key(key, EvalReason::Convergence);
    REQUIRE(rt->pending_initial(key).empty());
}

TEST_CASE("a backend arm failure errors the rule, never a silent legacy fallback",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->fail_arm = true;
    auto rt = make_rt(r, b);
    const auto res = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE_FALSE(res.has_value()); // errored
    REQUIRE(rt->armed_key_count() == 0);
    REQUIRE(rt->rule_count() == 0); // not left half-attached
}

TEST_CASE("drain sends Lifecycle (armed) before Compliance (item 4 / Fable M6)",
          "[spark][runtime]") {
    // The "armed" audit entry must reach the server before the rule's first compliance
    // event, or the trail shows detection preceding arm.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); // Lifecycle "armed"
    rt->evaluate_key(key, EvalReason::Initial);                           // Compliance edge
    REQUIRE(rt->outbox_size() == 1);

    // Capture EVERY domain in send order (drain_all/drain_lifecycle filter by domain).
    std::vector<OutboxEntry> got;
    rt->drain([&](const OutboxEntry& e) {
        got.push_back(e);
        return SendResult::Sent;
    });
    REQUIRE(got.size() == 2);
    CHECK(got[0].domain == OutboxDomain::Lifecycle); // armed first
    CHECK(got[0].lifecycle_kind == "armed");
    CHECK(got[1].domain == OutboxDomain::Compliance); // then the edge
}

TEST_CASE("drain does NOT let a stuck lifecycle head block compliance (Gate 4 UP-3)",
          "[spark][runtime]") {
    // Regression for the M6-gate blackout: an earlier version gated compliance on the
    // lifecycle log being empty, so a lifecycle head that could not send blocked ALL
    // compliance/health indefinitely. Both logs must drain every pass (lifecycle first
    // for best-effort ordering, but NO hard gate) so failure isolation holds.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); // Lifecycle "armed"
    rt->evaluate_key(key, EvalReason::Initial);                           // Compliance edge
    REQUIRE(rt->outbox_size() == 1);

    // Retain the lifecycle head (as if its send keeps failing); compliance must STILL drain.
    std::vector<OutboxDomain> got;
    rt->drain([&](const OutboxEntry& e) {
        got.push_back(e.domain);
        return e.domain == OutboxDomain::Lifecycle ? SendResult::Retain : SendResult::Sent;
    });
    CHECK(rt->outbox_size() == 0); // compliance drained despite the stuck lifecycle head
    REQUIRE(got.size() == 2);
    CHECK(got[0] == OutboxDomain::Lifecycle);  // attempted first (best-effort ordering)
    CHECK(got[1] == OutboxDomain::Compliance); // then compliance, NOT blocked
}

TEST_CASE("drain counts a send that throws and retains the head (item 4 hardening)",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); // Lifecycle "armed"
    REQUIRE(rt->send_exception_count() == 0);

    // A throwing send must not escape drain (that would eventually reach the worker's
    // firewall), must be counted (not silent), and must retain the head.
    rt->drain([](const OutboxEntry&) -> SendResult { throw std::runtime_error("send boom"); });
    CHECK(rt->send_exception_count() == 1);

    const auto lc = drain_lifecycle(*rt); // clean drain: the retained head still sends
    REQUIRE(lc.size() == 1);
    CHECK(lc[0].lifecycle_kind == "armed");
}

TEST_CASE("drain releases outbox_mu_ during send - no head-of-line block (item 4)",
          "[spark][runtime]") {
    // Proof the send (a gRPC Write in production) no longer runs UNDER outbox_mu_: the
    // callback itself takes outbox_mu_ via outbox_size(). Under the old lock-across-send
    // drain this self-deadlocks the drain thread; with item 4 it completes.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); // enqueues an "armed"

    // Run the drain on a separate thread with a timeout so a REGRESSION (self-deadlock
    // when the send runs under outbox_mu_) fails FAST here instead of burning the 240s
    // binary-level CI timeout and killing every other test in the run (quality Gate 3).
    // The blocked thread would hold only locks local to this test's rt - safe to abandon.
    std::atomic<bool> callback_ran{false};
    std::atomic<std::size_t> sent{0};
    auto fut = std::async(std::launch::async, [&] {
        sent = rt->drain([&](const OutboxEntry&) {
            (void)rt->outbox_size(); // takes outbox_mu_ - would DEADLOCK if held across send
            callback_ran = true;
            return SendResult::Sent;
        });
    });
    REQUIRE(fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready); // no deadlock
    fut.get();
    CHECK(callback_ran.load());
    CHECK(sent.load() == 1);
}

TEST_CASE("detach purges a rule's buffered (undrained) outbox entries", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt->evaluate_key(key, EvalReason::Initial); // buffers a compliant edge (not drained)
    REQUIRE(rt->outbox_size() == 1);

    rt->detach_rule("r1");
    REQUIRE(rt->outbox_size() == 0); // purged, never sent for a withdrawn rule
}

TEST_CASE("re-attach supersedes the old generation and purges its stale entry", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    const auto gen1 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(rt->outbox_size() == 1);

    // Re-attach (same rule) -> a new generation; the stale gen-1 entry is purged.
    const auto gen2 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE(gen2.value() > gen1.value());
    REQUIRE(rt->outbox_size() == 0);

    rt->evaluate_key(key, EvalReason::Initial);
    const auto got = drain_all(*rt);
    REQUIRE(got.size() == 1);
    REQUIRE(got[0].generation == gen2.value());
}

TEST_CASE("at outbox cap the eval stays pending and is delivered after a drain", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 2; // the floor; three drifting keys exceed it
    auto rt = make_rt(r, b, cfg);
    const auto k3 = spark_key(file_spec("/c"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", /*present=*/false), true); // drifts
    rt->attach_rule("r2", file_spec("/b"), file_exists_rule("r2", /*present=*/false), true); // drifts
    rt->attach_rule("r3", file_spec("/c"), file_exists_rule("r3", /*present=*/false), true); // drifts
    r->file = read_known(FileSnapshot{.exists = true}); // present -> all rules drift (expect absent)

    rt->evaluate_key(spark_key(file_spec("/a")), EvalReason::Initial); // slot 1
    rt->evaluate_key(spark_key(file_spec("/b")), EvalReason::Initial); // slot 2 (full)
    REQUIRE(rt->outbox_size() == 2);
    rt->evaluate_key(k3, EvalReason::Initial); // rejected at cap -> r3 left pending
    REQUIRE(rt->outbox_size() == 2);
    REQUIRE(rt->outbox_backpressure_drops() == 1);
    REQUIRE(rt->pending_initial(k3) == std::vector<std::string>{"r3"}); // still owes a verdict

    drain_all(*rt);                                // frees the slots
    rt->evaluate_key(k3, EvalReason::Convergence); // now r3's drift lands
    const auto got = drain_all(*rt);
    REQUIRE(got.size() == 1);
    REQUIRE(got[0].rule_id == "r3");
    REQUIRE(rt->pending_initial(k3).empty());
}

TEST_CASE("a configured capacity below two is floored so a recovery pair can never be lost",
          "[spark][runtime]") {
    // A recovery emits TWO entries (guard.healthy + verdict). A cap of 1 would reject
    // the pair on every retry forever. The runtime floors the capacity at 2.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // deliberately below the floor
    auto rt = make_rt(r, b, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", /*present=*/true), true);

    r->file = read_unknown<FileSnapshot>("io"); // errored -> health(false)
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(drain_all(*rt).size() == 1);

    r->file = read_known(FileSnapshot{.exists = false}); // recovery to a DRIFT -> health(true)+drift
    rt->evaluate_key(key, EvalReason::Event);
    const auto g = drain_all(*rt);
    REQUIRE(g.size() == 2); // the pair landed - not permanently rejected
    REQUIRE(rt->pending_initial(key).empty());
}

TEST_CASE("Unknown flood guard: repeat errored evals emit one health(false), count the rest (M1)",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", /*present=*/true), true);

    r->file = read_unknown<FileSnapshot>("io");
    // First errored eval -> exactly one guard.unhealthy on the wire; nothing suppressed yet.
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(drain_all(*rt).size() == 1);
    REQUIRE(rt->unhealthy_suppressed() == 0);

    // The convergence priority lane re-visits a rule still owing a verdict every tick. Three
    // more errored re-evals must produce NO new wire entries - each is counted instead, so a
    // rule stuck errored can't flood the fleet's health-event ingest.
    for (int i = 0; i < 3; ++i)
        rt->evaluate_key(key, EvalReason::Event);
    REQUIRE(drain_all(*rt).empty());
    REQUIRE(rt->unhealthy_suppressed() == 3);
    REQUIRE_FALSE(rt->pending_initial(key).empty()); // still Unknown -> still owes a verdict

    // Recovery emits guard.healthy (+ the compliant edge) and re-arms the edge: the NEXT
    // Unknown emits a fresh health(false), and the suppression counter is untouched by it.
    r->file = read_known(FileSnapshot{.exists = true});
    rt->evaluate_key(key, EvalReason::Event);
    const auto recovered = drain_all(*rt);
    // Precisely: recovery MUST emit a guard.healthy (Health domain, healthy=true), not merely
    // "some entry" - a regression that dropped health(true) on recovery would leave the health
    // stream stuck errored forever (qa Gate-3 SHOULD).
    REQUIRE(std::any_of(recovered.begin(), recovered.end(), [](const OutboxEntry& e) {
        return e.domain == OutboxDomain::Health && e.healthy;
    }));
    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Event);
    REQUIRE(drain_all(*rt).size() == 1);
    REQUIRE(rt->unhealthy_suppressed() == 3);
}

TEST_CASE("Unknown edge rejected at outbox cap is retried, never counted as suppressed (M1)",
          "[spark][runtime]") {
    // Metrics-honesty invariant: unhealthy_suppressed_ counts only COMMITTED repeat-Unknowns,
    // never an edge the outbox rejected (that edge is re-attempted, not suppressed). Guards the
    // counter's placement AFTER the accept-check + COMMIT against a future refactor that hoists it.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 2; // the floor
    auto rt = make_rt(r, b, cfg);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", /*present=*/false), true); // drifts
    rt->attach_rule("r2", file_spec("/b"), file_exists_rule("r2", /*present=*/false), true); // drifts
    const auto kc = spark_key(file_spec("/c"));
    rt->attach_rule("rc", file_spec("/c"), file_exists_rule("rc", /*present=*/true), true);

    // Fill the outbox with two drifts (no slot left).
    r->file = read_known(FileSnapshot{.exists = true});
    rt->evaluate_key(spark_key(file_spec("/a")), EvalReason::Initial);
    rt->evaluate_key(spark_key(file_spec("/b")), EvalReason::Initial);
    REQUIRE(rt->outbox_size() == 2);

    // Edge Unknown for rc while the outbox is full: its single health(false) entry is rejected
    // (both-or-neither), so nothing commits, rc stays pending, and NOTHING is counted suppressed -
    // the edge was not delivered and will be retried, so counting it would over-report.
    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(kc, EvalReason::Initial);
    REQUIRE(rt->outbox_size() == 2);
    REQUIRE(rt->pending_initial(kc) == std::vector<std::string>{"rc"});
    REQUIRE(rt->unhealthy_suppressed() == 0);

    // Drain frees a slot; the STILL-first Unknown re-attempts as a fresh edge and lands.
    drain_all(*rt);
    rt->evaluate_key(kc, EvalReason::Convergence);
    REQUIRE(drain_all(*rt).size() == 1);      // the edge health(false) finally delivered, not lost
    REQUIRE(rt->unhealthy_suppressed() == 0); // still an edge, never a suppression
}

TEST_CASE("Unknown flood guard: two rules on one key each count suppression independently (M1)",
          "[spark][runtime]") {
    // The counter increments PER RULE inside the per-key eval loop, not once per key. A refactor
    // that hoisted the increment outside the loop would silently under-count a multi-rule key
    // (qa Gate-3 SHOULD). Two rules share one spark_key; both go Unknown together.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", /*present=*/true), true);
    rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2", /*present=*/true), true);

    r->file = read_unknown<FileSnapshot>("io");
    // First pass: both rules edge -> two health(false) on the wire, nothing suppressed.
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(drain_all(*rt).size() == 2);
    REQUIRE(rt->unhealthy_suppressed() == 0);

    // Second pass: both rules repeat -> no wire entries, +2 suppressed (one per rule, not one
    // per key).
    rt->evaluate_key(key, EvalReason::Event);
    REQUIRE(drain_all(*rt).empty());
    REQUIRE(rt->unhealthy_suppressed() == 2);
}

// --- F5 6b: errored-refresh backstop -----------------------------------------------

TEST_CASE("M1 refresh: a repeat Unknown before errored_refresh_ms elapses stays suppressed (F5 6b)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt_with_clock(r, b, sc); // default errored_refresh_ms = 300'000
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial); // edge
    REQUIRE(drain_all(*rt).size() == 1);

    sc.advance(1'000); // well short of the 300s default
    rt->evaluate_key(key, EvalReason::Event);
    REQUIRE(drain_all(*rt).empty());
    REQUIRE(rt->unhealthy_suppressed() == 1);
    REQUIRE(rt->unhealthy_refreshed() == 0);
}

TEST_CASE("M1 refresh: a repeat Unknown past errored_refresh_ms re-emits with the CURRENT "
          "detail (F5 6b)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt_with_clock(r, b, sc);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_unknown<FileSnapshot>("eacces");
    rt->evaluate_key(key, EvalReason::Initial); // edge, detail="eacces"
    REQUIRE(drain_all(*rt).size() == 1);

    sc.advance(300'000); // exactly errored_refresh_ms - the ">=" boundary
    r->file = read_unknown<FileSnapshot>("enodev"); // the reason CHANGED mid-episode
    rt->evaluate_key(key, EvalReason::Event);
    const auto got = drain_all(*rt);
    REQUIRE(got.size() == 1);
    REQUIRE(got[0].domain == OutboxDomain::Health);
    REQUIRE_FALSE(got[0].healthy);
    // The refresh re-surfaces the CURRENT reason - unlike a merely-suppressed tick, this is
    // the retired staleness trade (build_entries doc): a changed error is not silently held
    // back until recovery.
    REQUIRE(got[0].health_detail == "enodev");
    REQUIRE(rt->unhealthy_refreshed() == 1);
    REQUIRE(rt->unhealthy_suppressed() == 0);
}

TEST_CASE("M1 refresh: errored_refresh_ms=0 disables refresh - stays edge-only (F5 6b)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.errored_refresh_ms = 0;
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial); // edge
    REQUIRE(drain_all(*rt).size() == 1);

    sc.advance(10'000'000); // arbitrarily far past any real cadence
    rt->evaluate_key(key, EvalReason::Event);
    REQUIRE(drain_all(*rt).empty()); // still nothing - refresh is OFF
    REQUIRE(rt->unhealthy_suppressed() == 1);
    REQUIRE(rt->unhealthy_refreshed() == 0);
}

TEST_CASE("M1 refresh: suppressed and refreshed partition every committed repeat-Unknown, "
          "keyed off the LAST emission not the original edge (F5 6b)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt_with_clock(r, b, sc);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial); // edge @ t=0
    REQUIRE(drain_all(*rt).size() == 1);

    sc.advance(100'000); // t=100s: < 300s since the edge
    rt->evaluate_key(key, EvalReason::Event);
    REQUIRE(drain_all(*rt).empty());
    REQUIRE(rt->unhealthy_suppressed() == 1);

    sc.advance(100'000); // t=200s: still < 300s since the edge
    rt->evaluate_key(key, EvalReason::Event);
    REQUIRE(drain_all(*rt).empty());
    REQUIRE(rt->unhealthy_suppressed() == 2);

    sc.advance(150'000); // t=350s: >= 300s since the edge -> refresh
    rt->evaluate_key(key, EvalReason::Event);
    REQUIRE(drain_all(*rt).size() == 1);
    REQUIRE(rt->unhealthy_refreshed() == 1);
    REQUIRE(rt->unhealthy_suppressed() == 2); // unchanged by the refresh

    sc.advance(50'000); // t=400s: only 50s since the REFRESH (not 400s since the edge)
    rt->evaluate_key(key, EvalReason::Event);
    REQUIRE(drain_all(*rt).empty()); // too soon since the LAST emission -> suppressed again
    REQUIRE(rt->unhealthy_suppressed() == 3);
    REQUIRE(rt->unhealthy_refreshed() == 1);
}

TEST_CASE("M1 refresh: two rules sharing one key each refresh independently, per-rule not "
          "per-key (F5 6b)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt_with_clock(r, b, sc);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial); // both edge
    REQUIRE(drain_all(*rt).size() == 2);

    sc.advance(300'000);
    r->file = read_unknown<FileSnapshot>("io2");
    rt->evaluate_key(key, EvalReason::Event);
    const auto got = drain_all(*rt);
    REQUIRE(got.size() == 2); // BOTH refresh, not one per key
    for (const auto& e : got) {
        REQUIRE(e.domain == OutboxDomain::Health);
        REQUIRE(e.health_detail == "io2");
    }
    REQUIRE(rt->unhealthy_refreshed() == 2);
}

TEST_CASE("M1 refresh: rejected at outbox cap is retried, never counted (F5 6b)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 2; // the floor
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto kc = spark_key(file_spec("/c"));
    rt->attach_rule("rc", file_spec("/c"), file_exists_rule("rc"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(kc, EvalReason::Initial); // edge @ t=0
    REQUIRE(drain_all(*rt).size() == 1);

    sc.advance(300'000); // rc's next Unknown is refresh-due

    // Fill the outbox with two unrelated drifts (r->file must read KNOWN for these).
    r->file = read_known(FileSnapshot{.exists = true});
    rt->attach_rule("r1", file_spec("/x"), file_exists_rule("r1", /*present=*/false), true);
    rt->attach_rule("r2", file_spec("/y"), file_exists_rule("r2", /*present=*/false), true);
    rt->evaluate_key(spark_key(file_spec("/x")), EvalReason::Initial);
    rt->evaluate_key(spark_key(file_spec("/y")), EvalReason::Initial);
    REQUIRE(rt->outbox_size() == 2);

    // rc's refresh is due but the outbox is full: rejected, nothing commits, not counted.
    r->file = read_unknown<FileSnapshot>("io2");
    rt->evaluate_key(kc, EvalReason::Convergence);
    REQUIRE(rt->outbox_size() == 2);
    REQUIRE(rt->unhealthy_refreshed() == 0);
    REQUIRE(rt->unhealthy_suppressed() == 0); // not suppressed either - it will retry, not lose

    // Free a slot; the STILL-due refresh re-attempts and lands (last_unhealthy_emit was never
    // advanced by the rejected attempt, so it is STILL past the interval).
    drain_all(*rt);
    rt->evaluate_key(kc, EvalReason::Convergence);
    const auto got = drain_all(*rt);
    REQUIRE(got.size() == 1);
    REQUIRE(got[0].health_detail == "io2");
    REQUIRE(rt->unhealthy_refreshed() == 1);
}

TEST_CASE("M1 refresh: recovery after a refresh still emits guard.healthy and re-arms the "
          "edge (F5 6b)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt_with_clock(r, b, sc);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial); // edge
    REQUIRE(drain_all(*rt).size() == 1);

    sc.advance(300'000);
    rt->evaluate_key(key, EvalReason::Event); // refresh
    REQUIRE(drain_all(*rt).size() == 1);
    REQUIRE(rt->unhealthy_refreshed() == 1);

    r->file = read_known(FileSnapshot{.exists = true}); // recovers
    rt->evaluate_key(key, EvalReason::Event);
    const auto recovered = drain_all(*rt);
    REQUIRE(std::any_of(recovered.begin(), recovered.end(), [](const OutboxEntry& e) {
        return e.domain == OutboxDomain::Health && e.healthy;
    }));

    // A FRESH errored episode re-arms the edge immediately (not gated on errored_refresh_ms -
    // the edge is the primary emission and always fires on the false->true transition).
    r->file = read_unknown<FileSnapshot>("io3");
    rt->evaluate_key(key, EvalReason::Event);
    const auto got = drain_all(*rt);
    REQUIRE(got.size() == 1);
    REQUIRE(got[0].health_detail == "io3");
    REQUIRE(rt->unhealthy_refreshed() == 1); // unchanged - that was an edge, not a refresh
    REQUIRE(rt->unhealthy_suppressed() == 0);
}

// --- F5 6c: priority-lane demotion -------------------------------------------------

TEST_CASE("M1 demotion: K consecutive committed Convergence-reason Unknown sweeps demote a "
          "still-pending rule off the priority lane (F5 6c)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.pending_demote_sweeps = 3;
    cfg.pending_demote_ms = 0; // isolate the sweep-count arm
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    r->file = read_unknown<FileSnapshot>("io");

    for (int i = 0; i < 2; ++i)
        rt->evaluate_key(key, EvalReason::Convergence); // sweeps 1 (edge) + 2
    REQUIRE(rt->pending_demoted_for_test(key).empty());
    REQUIRE(rt->priority_demoted() == 0);
    const auto before = rt->keys_with_pending_initial();
    REQUIRE(std::find(before.begin(), before.end(), key) != before.end());

    rt->evaluate_key(key, EvalReason::Convergence); // sweep 3 -> demote
    REQUIRE(rt->pending_demoted_for_test(key) == std::vector<std::string>{"r1"});
    REQUIRE(rt->priority_demoted() == 1);
    REQUIRE(rt->keys_with_pending_initial().empty()); // off the priority worklist
    REQUIRE_FALSE(rt->pending_initial(key).empty());  // still "never Known" - membership unchanged
}

TEST_CASE("M1 demotion: elapsed time demotes even with sparse sweeps (F5 6c)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.pending_demote_sweeps = 0; // isolate the elapsed-time arm
    cfg.pending_demote_ms = 120'000;
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); // first_seen @ t=0
    r->file = read_unknown<FileSnapshot>("io");

    rt->evaluate_key(key, EvalReason::Convergence); // t=0: not yet
    REQUIRE(rt->priority_demoted() == 0);

    sc.advance(120'000); // t=120s
    rt->evaluate_key(key, EvalReason::Convergence);
    REQUIRE(rt->priority_demoted() == 1);
    REQUIRE(rt->pending_demoted_for_test(key) == std::vector<std::string>{"r1"});
}

TEST_CASE("M1 demotion: Event-reason evals never advance the sweep counter (F5 6c)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.pending_demote_sweeps = 1; // would demote on the very first COUNTED sweep
    cfg.pending_demote_ms = 0;
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    r->file = read_unknown<FileSnapshot>("io");

    for (int i = 0; i < 5; ++i)
        rt->evaluate_key(key, EvalReason::Event); // never Convergence
    REQUIRE(rt->priority_demoted() == 0);
    REQUIRE(rt->pending_demoted_for_test(key).empty());

    rt->evaluate_key(key, EvalReason::Convergence); // the FIRST counted sweep
    REQUIRE(rt->priority_demoted() == 1);
}

TEST_CASE("M1 demotion: a Known verdict before K sweeps clears pending_initial normally, "
          "without demoting (F5 6c)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.pending_demote_sweeps = 5;
    cfg.pending_demote_ms = 0;
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", /*present=*/true), true);
    r->file = read_unknown<FileSnapshot>("io");

    for (int i = 0; i < 2; ++i)
        rt->evaluate_key(key, EvalReason::Convergence); // sweeps 1+2, well below K=5

    r->file = read_known(FileSnapshot{.exists = true}); // recovers to compliant -> Known
    rt->evaluate_key(key, EvalReason::Convergence);
    REQUIRE(rt->pending_initial(key).empty()); // ordinary erase-on-Known
    REQUIRE(rt->priority_demoted() == 0);
}

TEST_CASE("M1 demotion: a demoted key still converges via its type lane and a later Known "
          "eval erases + emits recovery (F5 6c)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.pending_demote_sweeps = 1;
    cfg.pending_demote_ms = 0;
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", /*present=*/true), true);
    r->file = read_unknown<FileSnapshot>("io");

    rt->evaluate_key(key, EvalReason::Convergence); // K=1: demotes on the very first sweep
    REQUIRE(rt->priority_demoted() == 1);
    REQUIRE(rt->keys_with_pending_initial().empty()); // off the priority lane

    // The scheduler's type lane (keys_for_type()) is unfiltered by demotion - drive that
    // same call directly, as guardian_convergence_scheduler.cpp's sweep_lane() would.
    r->file = read_known(FileSnapshot{.exists = true});
    rt->evaluate_key(key, EvalReason::Convergence);
    const auto got = drain_all(*rt);
    REQUIRE(std::any_of(got.begin(), got.end(), [](const OutboxEntry& e) {
        return e.domain == OutboxDomain::Health && e.healthy;
    }));
    REQUIRE(rt->pending_initial(key).empty()); // Known -> erased; demotion is moot now
}

TEST_CASE("M1 demotion: re-attaching a rule resets its demotion state (F5 6c)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.pending_demote_sweeps = 1;
    cfg.pending_demote_ms = 0;
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    r->file = read_unknown<FileSnapshot>("io");

    rt->evaluate_key(key, EvalReason::Convergence);
    REQUIRE(rt->priority_demoted() == 1);
    REQUIRE(rt->keys_with_pending_initial().empty());

    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); // fresh generation
    const auto after = rt->keys_with_pending_initial();
    REQUIRE(std::find(after.begin(), after.end(), key) != after.end()); // back on the priority lane
    REQUIRE(rt->pending_demoted_for_test(key).empty());
}

TEST_CASE("M1 demotion: pending_demote_sweeps=0 and pending_demote_ms=0 each disable their "
          "arm - never demote-on-first-Unknown (F5 6c)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.pending_demote_sweeps = 0;
    cfg.pending_demote_ms = 0;
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    r->file = read_unknown<FileSnapshot>("io");

    for (int i = 0; i < 20; ++i) {
        rt->evaluate_key(key, EvalReason::Convergence);
        sc.advance(1'000'000); // also exercises the elapsed-time arm being off
    }
    REQUIRE(rt->priority_demoted() == 0);
    REQUIRE(rt->pending_demoted_for_test(key).empty());
    const auto still = rt->keys_with_pending_initial();
    REQUIRE(std::find(still.begin(), still.end(), key) != still.end());
}

TEST_CASE("M1 demotion: a mixed demoted/non-demoted pending set on one key keeps the key on "
          "the priority worklist (F5 6c)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.pending_demote_sweeps = 2;
    cfg.pending_demote_ms = 0;
    auto rt = make_rt_with_clock(r, b, sc, cfg);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    r->file = read_unknown<FileSnapshot>("io");

    rt->evaluate_key(key, EvalReason::Convergence); // r1 sweep 1
    rt->evaluate_key(key, EvalReason::Convergence); // r1 sweep 2 -> demote
    REQUIRE(rt->pending_demoted_for_test(key) == std::vector<std::string>{"r1"});
    REQUIRE(rt->keys_with_pending_initial().empty()); // sole pending rule demoted -> key off

    // A fresh sibling on the SAME key (the watcher already exists - shared-watcher branch).
    rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);
    const auto mixed = rt->keys_with_pending_initial();
    REQUIRE(std::find(mixed.begin(), mixed.end(), key) != mixed.end()); // back on the worklist
    REQUIRE(rt->pending_demoted_for_test(key) == std::vector<std::string>{"r1"}); // r2 not demoted
    const auto pend = rt->pending_initial(key);
    REQUIRE(std::find(pend.begin(), pend.end(), "r1") != pend.end()); // still a member
    REQUIRE(std::find(pend.begin(), pend.end(), "r2") != pend.end());

    // Sweeping again advances ONLY r2's counter - r1 is frozen once demoted (guarded by
    // !pit->second.demoted before incrementing).
    rt->evaluate_key(key, EvalReason::Convergence); // r2 sweep 1
    REQUIRE(rt->priority_demoted() == 1);           // still just r1
    rt->evaluate_key(key, EvalReason::Convergence); // r2 sweep 2 -> demote
    REQUIRE(rt->priority_demoted() == 2);
    REQUIRE(rt->keys_with_pending_initial().empty()); // both demoted now -> key fully off
}

// --- F11: flood measurement, production defaults (#2298) --------------------------
//
// These three cases drive the F5 6b/6c mechanisms end-to-end at PRODUCTION DEFAULT
// Config (unlike the 6b/6c tests above, which mostly override pending_demote_sweeps/ms
// to isolate one arm) to establish the wire-flood ceiling the F11 run doc
// (docs/spark-rebuild-baselines/f11-flood-measurement-run.md) reports, replacing the
// stale pre-F5 ~17k/day extrapolation in docs/spark-stage2-guardian-consumer-design.md.
// A test drives cadence by an explicit clock advance per simulated scheduler tick
// (5s priority lane, 60s/600s type lanes) since GuardianConvergenceScheduler itself
// received zero code change from F5 (docs/spark-stage2-guardian-consumer-design.md:283)
// - the real per-lane tick spacing is the scheduler's job, reproduced here by hand.

TEST_CASE("F11 flood: production-default demotion completes in 12 sweeps @ 5s (60s) - "
          "before any refresh could fire (#2298)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt_with_clock(r, b, sc); // production defaults: 12 sweeps, 120s, 300s refresh
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial); // edge - never-Known, priority lane
    REQUIRE(drain_all(*rt).size() == 1);

    int sweeps = 0;
    while (rt->priority_demoted() == 0) {
        sc.advance(5'000); // the 5s priority-lane cadence (guardian_convergence_scheduler.hpp:72)
        rt->evaluate_key(key, EvalReason::Convergence);
        REQUIRE(drain_all(*rt).empty()); // pre-demotion: every sweep suppressed, none refresh
        ++sweeps;
    }
    CHECK(sweeps == 12); // pending_demote_sweeps default (guardian_spark_runtime.hpp:178)
    CHECK(rt->unhealthy_suppressed() == 12);
    CHECK(rt->unhealthy_refreshed() == 0); // demotion (60s) completes well inside the 300s floor
}

TEST_CASE("F11 flood: post-demotion 60s-cadence lane (service/registry) refreshes exactly "
          "every errored_refresh_ms, first landing at t=300s (#2298)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt_with_clock(r, b, sc);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial); // edge @ t=0
    REQUIRE(drain_all(*rt).size() == 1);

    while (rt->priority_demoted() == 0) { // demote at t=60s, as the prior case establishes
        sc.advance(5'000);
        rt->evaluate_key(key, EvalReason::Convergence);
        drain_all(*rt);
    }
    REQUIRE(rt->priority_demoted() == 1);

    // Now on the 60s type-lane cadence. 14 ticks reaches t=60s+14*60s=900s, spanning
    // three 300s refresh boundaries (t=300s, 600s, 900s) - refreshed is keyed off the
    // LAST emission (the edge at t=0 initially), not re-armed by demotion.
    for (int i = 1; i <= 3; ++i) {
        sc.advance(60'000);
        rt->evaluate_key(key, EvalReason::Convergence);
        drain_all(*rt);
    }
    CHECK(rt->unhealthy_refreshed() == 0); // t=240s: still short of the 300s floor
    sc.advance(60'000); // t=300s: exactly the boundary
    rt->evaluate_key(key, EvalReason::Convergence);
    drain_all(*rt);
    CHECK(rt->unhealthy_refreshed() == 1);
    for (int i = 1; i <= 10; ++i) { // t=360s..900s: two more 300s boundaries at 600s, 900s
        sc.advance(60'000);
        rt->evaluate_key(key, EvalReason::Convergence);
        drain_all(*rt);
    }
    CHECK(rt->unhealthy_refreshed() == 3);
    // Steady-state projection (arithmetic on the measured 300s period, not a fresh
    // 24h loop - 300s divides 86400s evenly): 288 refreshes/day + 1 edge = 289 total
    // guard.unhealthy wire messages/rule/agent/day on this lane - see the F11 run doc.
}

TEST_CASE("F11 flood: post-demotion 600s-cadence lane (file) refreshes on EVERY sweep, "
          "since its cadence already exceeds errored_refresh_ms (#2298)",
          "[spark][runtime]") {
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt_with_clock(r, b, sc);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial); // edge @ t=0
    REQUIRE(drain_all(*rt).size() == 1);

    while (rt->priority_demoted() == 0) { // demote at t=60s
        sc.advance(5'000);
        rt->evaluate_key(key, EvalReason::Convergence);
        drain_all(*rt);
    }
    REQUIRE(rt->priority_demoted() == 1);
    REQUIRE(rt->unhealthy_refreshed() == 0);

    // First post-demotion file-lane sweep: t=60s+600s=660s, already >=300s since the
    // t=0 edge - refreshes immediately, no suppression window at all on this lane.
    sc.advance(600'000);
    rt->evaluate_key(key, EvalReason::Convergence);
    CHECK(drain_all(*rt).size() == 1);
    CHECK(rt->unhealthy_refreshed() == 1);
    CHECK(rt->unhealthy_suppressed() == 12); // unchanged since demotion - never suppressed here

    sc.advance(600'000); // t=1260s
    rt->evaluate_key(key, EvalReason::Convergence);
    CHECK(drain_all(*rt).size() == 1);
    CHECK(rt->unhealthy_refreshed() == 2);
    // At EXACT 600s cadence (no scheduler jitter): 144 refreshes/day + 1 edge = 145
    // total wire messages/rule/agent/day on this lane (86400s/600s = 144 sweeps/day,
    // every one refreshes). This is the NOMINAL figure, not the production ceiling -
    // see the next case for the jittered worst-case, and the F11 run doc for both.
}

TEST_CASE("F11 flood: file lane at the scheduler-jitter floor (480s) still refreshes "
          "every sweep - the TRUE production worst-case ceiling is 180/day, not the "
          "144/day no-jitter figure (#2298, adversarial-review finding)",
          "[spark][runtime]") {
    // ConvergenceScheduler::Config defaults file_cadence_ms=600'000, jitter_pct=20
    // (guardian_convergence_scheduler.hpp:69-73); jittered() draws base_ms +
    // uniform(-span, +span) with span = base_ms*jitter_pct/100 = 120'000
    // (guardian_convergence_scheduler.cpp:59-69) - a SYMMETRIC perturbation, not the
    // later-only skew the run doc originally (incorrectly) claimed. The minimum
    // possible single-draw interval is therefore 600'000-120'000=480'000ms: still
    // above the 300s errored_refresh_ms floor, so every such sweep still refreshes,
    // same as the exact-600s case - but at up to 86400/480=180 refreshes/day, not 144.
    // This case proves that boundary empirically rather than asserting the arithmetic.
    SettableClock sc;
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt_with_clock(r, b, sc);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_unknown<FileSnapshot>("io");
    rt->evaluate_key(key, EvalReason::Initial); // edge @ t=0
    REQUIRE(drain_all(*rt).size() == 1);

    while (rt->priority_demoted() == 0) { // demote at t=60s
        sc.advance(5'000);
        rt->evaluate_key(key, EvalReason::Convergence);
        drain_all(*rt);
    }
    REQUIRE(rt->priority_demoted() == 1);
    REQUIRE(rt->unhealthy_refreshed() == 0);

    // Three consecutive sweeps at the jitter-floor 480s interval: every one refreshes
    // (480s > 300s), proving jitter cannot suppress a file-lane refresh - it can only
    // make them MORE frequent than the no-jitter 144/day figure, up to 180/day.
    for (std::uint64_t i = 1; i <= 3; ++i) {
        sc.advance(480'000);
        rt->evaluate_key(key, EvalReason::Convergence);
        CHECK(drain_all(*rt).size() == 1);
        CHECK(rt->unhealthy_refreshed() == i);
    }
    CHECK(rt->unhealthy_suppressed() == 12); // unchanged - still never suppressed on this lane
    // Ceiling: 86'400s / 480s = 180 refreshes/day + 1 edge = 181 total wire
    // messages/rule/agent/day - the honest production worst-case, not 144. See the
    // F11 run doc's corrected Claims section.
}

TEST_CASE("on_event after begin_stop commits nothing", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE(r->stops.load() == 0);
    rt->begin_stop();
    REQUIRE(rt->stopping());
    CHECK(r->stops.load() == 1); // begin_stop() -> reader_->request_stop(), exactly once
    rt->on_event(SparkEvent{.key = key, .type = SparkType::File});
    REQUIRE(rt->outbox_size() == 0); // stopping -> no commit
}

TEST_CASE("a detached in-flight handler is memory-safe even after the reader ref is dropped",
          "[spark][runtime]") {
    // The runtime OWNS the reader, so keeping the runtime alive (via the handler's
    // captured shared_ptr) keeps the reader alive too. We drop BOTH the test's reader
    // ref and the runtime ref while a handler is mid-read; the detached thread must
    // still finish safely. Under the old borrowed-reference design this destroyed the
    // reader out from under the in-flight read (ASan use-after-free).
    auto reader = std::make_shared<FakeReader>();
    auto backend = std::make_shared<FakeBackend>();
    std::latch reading{1};
    std::latch release{1};
    reader->on_read = [&] {
        reading.count_down();
        release.wait();
    };
    auto rt = std::make_shared<GuardianSparkRuntime>(reader, backend);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    auto handler = GuardianSparkRuntime::make_handler(rt);
    std::thread t([handler, key] { handler(SparkEvent{.key = key, .type = SparkType::File}); });

    reading.wait();  // the pass is inside read(); the runtime (owning the reader) is alive via `handler`
    reader.reset();  // drop the test's reader ref: only the runtime co-owns it now
    rt.reset();      // drop the test's runtime ref: only the detached handler owns it
    release.count_down();
    t.join(); // read finished, verdict committed, reader still alive: no UAF
    SUCCEED();
}

TEST_CASE("two registry rules under one key each read their OWN value_name", "[spark][runtime]") {
    // Rules watching different values under one (hive,key) share ONE spark_key/watcher.
    // The read plan requests both value_names; each rule evaluates against ITS value -
    // reading one snapshot and fanning it to both would give a wrong verdict.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    r->reg_values["A"] = read_known(RegistrySnapshot{.present = true, .value = "1"}); // r1 compliant
    r->reg_values["B"] = read_known(RegistrySnapshot{.present = true, .value = "9"}); // r2 drifts vs "2"
    auto rt = make_rt(r, b);
    const auto key = spark_key(reg_spec("HKLM", "Software\\X"));
    rt->attach_rule("r1", reg_spec("HKLM", "Software\\X"), registry_rule("r1", "A", "1"), true);
    rt->attach_rule("r2", reg_spec("HKLM", "Software\\X"), registry_rule("r2", "B", "2"), true);
    REQUIRE(rt->armed_key_count() == 1); // one shared watcher
    REQUIRE(b->arms.load() == 1);

    rt->evaluate_key(key, EvalReason::Initial);
    auto g = drain_all(*rt);
    REQUIRE(g.size() == 2);
    std::sort(g.begin(), g.end(),
              [](const OutboxEntry& a, const OutboxEntry& c) { return a.rule_id < c.rule_id; });
    REQUIRE(g[0].rule_id == "r1");
    REQUIRE(g[0].drift.compliant); // A == "1"
    REQUIRE(g[1].rule_id == "r2");
    REQUIRE_FALSE(g[1].drift.compliant); // B == "9" != "2"
    REQUIRE(g[1].drift.detected_value == "9");
}

TEST_CASE("two rules watching the SAME registry value dedup the read plan", "[spark][runtime]") {
    // The read plan promises DISTINCT value_names; a rung-5 reader relies on that to
    // avoid redundant OS reads. Two rules on the same value must produce one entry.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    r->reg_values["A"] = read_known(RegistrySnapshot{.present = true, .value = "1"});
    auto rt = make_rt(r, b);
    const auto key = spark_key(reg_spec("HKLM", "Software\\X"));
    rt->attach_rule("r1", reg_spec("HKLM", "Software\\X"), registry_rule("r1", "A", "1"), true);
    rt->attach_rule("r2", reg_spec("HKLM", "Software\\X"), registry_rule("r2", "A", "1"), true);
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(r->last_reg_plan_size.load() == 1); // deduped: value A read once, not twice
    REQUIRE(drain_all(*rt).size() == 2);        // both rules still evaluated
}

TEST_CASE("the file read plan uses the largest hash cap among the key's rules", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    RuleAssertion small = file_exists_rule("r1"); // file-exists: no hash
    small.kind = AssertionKind::FileHashEquals;
    small.expected_hash = "h";
    small.max_bytes = 100;
    RuleAssertion big = small;
    big.rule_id = "r2";
    big.max_bytes = 5000;
    rt->attach_rule("r1", file_spec("/a"), small, true);
    rt->attach_rule("r2", file_spec("/a"), big, true);
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(r->last_hash_cap.load() == 5000); // hashed once at the largest admitting cap
}

TEST_CASE("a rule that joins mid-read is NOT committed against the stale snapshot",
          "[spark][runtime]") {
    // F2+F4: the pass snapshots its plan+gens before I/O and commits only those. A
    // sibling rule that attaches while the read is in flight is not in the plan, so it
    // is not evaluated against a snapshot that predates it - it stays dirty and the
    // priority lane will run it next. (The old post-read fan-out evaluated it here.)
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    std::latch reading{1};
    std::latch release{1};
    r->on_read = [&] {
        reading.count_down();
        release.wait();
    };
    std::thread t([&] { rt->evaluate_key(key, EvalReason::Initial); });
    reading.wait(); // r1's read is in flight; the plan was snapshotted with only r1

    rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true); // joins mid-read
    release.count_down();
    t.join();

    // r1 was in the plan -> committed + cleared; r2 joined after -> still pending.
    REQUIRE(rt->pending_initial(key) == std::vector<std::string>{"r2"});
    const auto g = drain_all(*rt);
    REQUIRE(g.size() == 1); // only r1's verdict, not r2's
    REQUIRE(g[0].rule_id == "r1");
}

TEST_CASE("Unknown->Known recovery emits guard.healthy even when the verdict is Silent",
          "[spark][runtime]") {
    // The systemd worst case: emit_compliant_edge=false, so a recovery to steady
    // compliant is a Silent verdict. Without a health-recovery emit the health stream
    // would stay unhealthy forever. Assert guard.healthy IS emitted on recovery.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(svc_spec("nginx"));
    rt->attach_rule("s1", svc_spec("nginx"), svc_running_rule("s1"), /*emit_compliant_edge=*/false);

    r->svc = read_known(ServiceRunState::Running);
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(rt->outbox_size() == 0); // systemd compliant edge is Silent

    r->svc = read_unknown<ServiceRunState>("scm timeout");
    rt->evaluate_key(key, EvalReason::Event);
    auto g = drain_all(*rt);
    REQUIRE(g.size() == 1);
    REQUIRE(g[0].domain == OutboxDomain::Health);
    REQUIRE_FALSE(g[0].healthy);

    r->svc = read_known(ServiceRunState::Running); // recovery to steady compliant
    rt->evaluate_key(key, EvalReason::Convergence);
    g = drain_all(*rt);
    REQUIRE(g.size() == 1);
    REQUIRE(g[0].domain == OutboxDomain::Health);
    REQUIRE(g[0].healthy); // the recovery signal that was previously never sent
}

TEST_CASE("recovery to a drifted state emits BOTH guard.healthy and the drift verdict",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("f1", file_spec("/a"), file_exists_rule("f1", /*present=*/true), true);

    r->file = read_unknown<FileSnapshot>("io"); // errored
    rt->evaluate_key(key, EvalReason::Initial);
    REQUIRE(drain_all(*rt).size() == 1); // health(false)

    r->file = read_known(FileSnapshot{.exists = false}); // recovery, but now drifted
    rt->evaluate_key(key, EvalReason::Event);
    const auto g = drain_all(*rt);
    REQUIRE(g.size() == 2); // health(true) + the drift, landed atomically
    REQUIRE(g[0].domain == OutboxDomain::Health);
    REQUIRE(g[0].healthy);
    REQUIRE(g[1].domain == OutboxDomain::Compliance);
    REQUIRE_FALSE(g[1].drift.compliant);
}

TEST_CASE("event ids fold in the agent id + are distinct per observation", "[spark][runtime]") {
    // Within one runtime, two observations of the same rule get distinct ids (seq);
    // two agents get distinct id prefixes - so the server's event_id PK never drops a
    // legitimate observation as a duplicate.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    rt->set_agent_id_provider([] { return std::string{"agentA"}; });
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    r->file = read_known(FileSnapshot{.exists = true});
    rt->evaluate_key(key, EvalReason::Initial); // compliant edge
    const auto e1 = drain_all(*rt);
    r->file = read_known(FileSnapshot{.exists = false});
    rt->evaluate_key(key, EvalReason::Event); // drift
    const auto e2 = drain_all(*rt);
    REQUIRE(e1.size() == 1);
    REQUIRE(e2.size() == 1);
    REQUIRE(e1[0].event_id != e2[0].event_id);        // distinct observations
    REQUIRE(e1[0].event_id.rfind("agentA-", 0) == 0); // agent-id folded in
    REQUIRE(e1[0].enqueued_ns > 0);                   // wall-clock timestamp, not steady epoch

    // A second agent with a different id yields a different prefix for the same rule.
    auto rt2 = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>());
    rt2->set_agent_id_provider([] { return std::string{"agentB"}; });
    rt2->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt2->evaluate_key(key, EvalReason::Initial);
    const auto eB = drain_all(*rt2);
    REQUIRE(eB.size() == 1);
    REQUIRE(eB[0].event_id.rfind("agentB-", 0) == 0);
    REQUIRE(eB[0].event_id != e1[0].event_id); // cross-agent distinct
}

TEST_CASE("the agent-id provider is invoked before the read, not on the detached path",
          "[spark][runtime]") {
    // F3b: clock + agent-id provider are snapshotted at pass start, so neither is
    // called after the (possibly blocking) read - a provider borrowing agent state
    // would UAF if shutdown destroyed it mid-read. Gate the read and assert the
    // provider has already run by the time the read is in flight.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    std::atomic<int> provider_calls{0};
    rt->set_agent_id_provider([&] {
        provider_calls.fetch_add(1);
        return std::string{"a"};
    });
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    // attach_rule itself calls the provider once too (its Lifecycle "armed"
    // audit entry, rung 7 - synchronous on the caller's thread, never on the
    // detached-post-read path, so this call is fine). Check the DELTA from here
    // rather than an absolute count, so this stays robust to other legitimate
    // synchronous provider calls: the invariant under test is specifically that
    // evaluate_key's read-thread calls it once, before the blocking read.
    const int before_read = provider_calls.load();

    std::latch reading{1};
    std::latch release{1};
    r->on_read = [&] {
        reading.count_down();
        release.wait();
    };
    std::thread t([&] { rt->evaluate_key(key, EvalReason::Initial); });
    reading.wait();
    REQUIRE(provider_calls.load() == before_read + 1); // snapshotted BEFORE the read
    release.count_down();
    t.join();
}

TEST_CASE("a per-boot nonce disambiguates event ids across runtime instances", "[spark][runtime]") {
    // Two runtimes with the SAME agent id (i.e. a restart) still mint different ids
    // for the same rule + observation, because each has its own random boot nonce -
    // so a restart cannot reproduce a prior id and have the server's PK drop it.
    const auto make_id = [] {
        auto r = std::make_shared<FakeReader>();
        auto b = std::make_shared<FakeBackend>();
        auto rt = make_rt(r, b);
        rt->set_agent_id_provider([] { return std::string{"agentA"}; });
        const auto key = spark_key(file_spec("/a"));
        rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        rt->evaluate_key(key, EvalReason::Initial);
        return drain_all(*rt).at(0).event_id;
    };
    REQUIRE(make_id() != make_id());
}

TEST_CASE("concurrent attach/detach/evaluate/drain do not race (TSan checkpoint)",
          "[spark][runtime][tsan]") {
    auto r = std::make_shared<FakeReader>(); // `file` is not rewritten during this test
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const std::vector<std::string> paths{"/a", "/b", "/c", "/d"};
    std::vector<std::string> keys;
    for (const auto& p : paths) keys.push_back(spark_key(file_spec(p)));

    std::atomic<bool> go{false};
    std::vector<std::thread> threads;
    constexpr int kIters = 400;

    // Churners: attach/detach many rules across the shared keys.
    for (int t = 0; t < 3; ++t) {
        threads.emplace_back([&, t] {
            while (!go.load()) {}
            for (int i = 0; i < kIters; ++i) {
                const std::string rid = "r" + std::to_string(t) + "_" + std::to_string(i % 8);
                const auto& p = paths[(t + i) % paths.size()];
                if (i % 3 == 0)
                    rt->detach_rule(rid);
                else
                    (void)rt->attach_rule(rid, file_spec(p), file_exists_rule(rid), true);
            }
        });
    }
    // Evaluators: hammer evaluate_key on every key.
    for (int t = 0; t < 3; ++t) {
        threads.emplace_back([&, t] {
            while (!go.load()) {}
            for (int i = 0; i < kIters; ++i)
                rt->evaluate_key(keys[(t + i) % keys.size()],
                                 i % 2 ? EvalReason::Event : EvalReason::Convergence);
        });
    }
    // Drainer: continuously drains.
    threads.emplace_back([&] {
        while (!go.load()) {}
        for (int i = 0; i < kIters; ++i) drain_all(*rt);
    });

    go.store(true);
    for (auto& th : threads) th.join();
    rt->begin_stop();
    SUCCEED(); // no crash / no TSan report is the assertion
}

TEST_CASE("concurrent attach/detach/evaluate/drain do not race when the backend and the "
          "send callback BLOCK (TSan checkpoint, #3848)",
          "[spark][runtime][liveness][tsan][tsan-heavy]") {
    // WHY THIS EXISTS. The three committed TSan checkpoints - including the one directly
    // above - all run against an INSTANTANEOUS FakeBackend: nothing blocks in arm, in
    // disarm, or in the send callback. Race-freedom is therefore proven only for a
    // backend that never blocks, which is the one backend production does not have
    // (a real arm is an OS watch registration behind a mechanism's own lock). This case
    // re-runs the same churn shape with every one of those three call sites able to park.
    //
    // WHAT A FAILURE MEANS, stated precisely because it changed during design. On this
    // tree the census below is a NO-REGRESSION check, not a leak detector: attach_rule's
    // worker already self-disarms a late arm success via its `still_wanted` re-check
    // (guardian_spark_runtime.cpp), so a leaked subscription is not reachable today
    // whatever this test does. What a surplus WOULD mean is that the self-disarm contract
    // has been broken - which is exactly the regression a rewrite of that worker lambda
    // could introduce. Recorded as a finding, never dismissed as a test bug.
    //
    // NOT RUN BY ANY PR OR PUSH CI LEG. `[tsan-heavy]` is filtered out whenever
    // b_sanitize == none (tests/meson.build), and the nightly TSan job runs against main,
    // not dev. Its evidence is a LOCAL TSan build - docs/spark-flip-gate.md says so.
    using yuzu::test::spin_until;

    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();

    GuardianSparkRuntime::Config cfg;
    // Short enough that a long backend hold reliably overruns it (the late-success path
    // is the point), long enough that an ORDINARY one-pulse park never does. The gap
    // between the two is what keeps the rejection assertion below meaningful: a short
    // park that spuriously timed out would leave its executor ticket held and make the
    // NEXT op on that key an AlreadyRunning rejection, which is indistinguishable from a
    // real dropped disarm.
    cfg.backend_op_deadline = std::chrono::milliseconds{60};
    auto rt = make_rt(r, b, cfg);

    // ── the three gates ──
    // Arms park on every call, and every 8th park is a LONG hold (300 releaser pulses,
    // ~300 ms against a 60 ms deadline) so the submitter genuinely observes
    // IoFailure::Timeout and the late-arm-success path runs for real.
    b->arm_park.park_every = 1;
    b->arm_park.long_every = 8;
    b->arm_park.long_hold_pulses = 300;
    // Disarms park SHORT ONLY. A long-held disarm would still hold its (class, key)
    // executor ticket when attach_rule's prior-generation disarm timed out, and the arm
    // that immediately follows it inside the same attach_rule call would be refused
    // AlreadyRunning - a self-inflicted rejection the census cannot tell from a real one.
    b->disarm_park.park_every = 1;
    b->disarm_park.long_every = 0;
    // The send callback runs with outbox_mu_ RELEASED but drain_mu_ HELD, and
    // evaluate_key never takes drain_mu_, so a parked send stalls only the drainer.
    BlockingGate send_park;
    send_park.park_every = 4;

    // ── per-lane fixtures: one IoClass per churner, disjoint keys and rule ids ──
    constexpr int kLanes = 3;
    constexpr int kKeysPerLane = 3;
    constexpr int kRidsPerLane = 8;
    constexpr int kIters = 400;
    const auto spec_for = [](int lane, int k) -> SparkSpec {
        switch (lane) {
        case 0: return file_spec("/p3848_" + std::to_string(k));
        case 1: return reg_spec("HKLM", "K3848_" + std::to_string(k));
        default: return svc_spec("svc3848_" + std::to_string(k));
        }
    };
    const auto rule_for = [](int lane, const std::string& rid) -> RuleAssertion {
        switch (lane) {
        case 0: return file_exists_rule(rid);
        case 1: return registry_rule(rid, "V", "v");
        default: return svc_running_rule(rid);
        }
    };
    std::vector<std::string> all_keys;
    for (int lane = 0; lane < kLanes; ++lane)
        for (int k = 0; k < kKeysPerLane; ++k)
            all_keys.push_back(spark_key(spec_for(lane, k)));

    // ── shared state ──
    std::atomic<bool> go{false};
    std::atomic<bool> churn_done{false};
    std::atomic<bool> releaser_stop{false};
    std::atomic<std::uint64_t> evals{0};
    std::atomic<std::uint64_t> drains{0};
    std::atomic<std::uint64_t> sends{0};
    std::atomic<std::uint64_t> attach_ok{0};
    std::atomic<std::uint64_t> attach_err{0};
    std::atomic<std::uint64_t> lane_spin_trips{0}; ///< harness bug detector, asserted zero
    // Each churner's EXCLUSIVE view of what it left attached. Written only by its owner,
    // read by the main thread after every churner has joined.
    std::array<std::map<std::string, std::string>, kLanes> live; // rid -> key

    std::vector<std::thread> workers;
    std::thread releaser;

    // ONE idempotent shutdown sequence, used by BOTH the normal path and the RAII guard
    // below - a Catch2 REQUIRE failure mid-test still has to unwind through live, parked
    // threads safely, and two similar-but-drifting sequences is how that stops working.
    std::once_flag stopped_once;
    const auto stop_everything = [&] {
        std::call_once(stopped_once, [&] {
            churn_done.store(true);
            go.store(true); // never leave a worker spinning on a start flag that never sets
            // GATES OPEN BEFORE ANY JOIN. A worker parked in a gate cannot be joined, and
            // the releaser is about to stop pulsing.
            b->arm_park.open();
            b->disarm_park.open();
            send_park.open();
            releaser_stop.store(true);
            if (releaser.joinable())
                releaser.join();
            for (auto& w : workers)
                if (w.joinable())
                    w.join();
            // Executor workers are DETACHED, so joining our own threads says nothing
            // about them. Wait for the last one to exit before anything they touch dies.
            (void)spin_until([&] { return rt->active_backend_op_workers() == 0; },
                             std::chrono::seconds{30});
        });
    };
    struct Cleanup {
        const std::function<void()>& fn;
        ~Cleanup() { fn(); }
    };
    const std::function<void()> cleanup_fn = stop_everything;
    Cleanup cleanup{cleanup_fn}; // declared AFTER workers/releaser/gates -> runs BEFORE them

    // ── releaser: the only thing that ever un-parks a gate during the soak ──
    releaser = std::thread([&] {
        while (!releaser_stop.load()) {
            b->arm_park.pulse();
            b->disarm_park.pulse();
            send_park.pulse();
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
    });

    // ── churners: one IoClass lane each ──
    for (int lane = 0; lane < kLanes; ++lane) {
        workers.emplace_back([&, lane] {
            while (!go.load()) {
            }
            for (int i = 0; i < kIters; ++i) {
                const int j = i % kRidsPerLane;
                const std::string rid =
                    "r" + std::to_string(lane) + "_" + std::to_string(j);
                // A rid MIGRATES across keys over time, so a re-attach hits attach_rule's
                // prior-generation teardown (detach_rule_locked + an off-lock disarm)
                // before its own arm - the path a same-rid re-attach actually takes.
                const int k = ((i / kRidsPerLane) + j) % kKeysPerLane;
                if (i % 3 == 0) {
                    rt->detach_rule(rid);
                    live[static_cast<std::size_t>(lane)].erase(rid);
                } else {
                    const auto spec = spec_for(lane, k);
                    auto res = rt->attach_rule(rid, spec, rule_for(lane, rid), true);
                    if (res) {
                        attach_ok.fetch_add(1);
                        live[static_cast<std::size_t>(lane)][rid] = spark_key(spec);
                    } else {
                        attach_err.fetch_add(1);
                        // attach_rule ALWAYS tears the prior generation down first
                        // (detach_rule_locked runs in its phase 1, before the arm), so a
                        // failed attach leaves this rid NOT attached - never still
                        // attached to whatever it had before.
                        live[static_cast<std::size_t>(lane)].erase(rid);
                    }
                }
                // THE INVARIANT THAT MAKES THE REJECTION ASSERTION REAL: never submit a
                // second op for this lane while the previous one's (class, key) executor
                // ticket is still held. One submitter per lane, so this serializes
                // nothing across churners - it only waits for this churner's own work.
                if (!spin_until(
                        [&] {
                            const auto st = rt->io_executor_stats_for_test();
                            return st.active_by_class[static_cast<std::size_t>(lane)] == 0;
                        },
                        std::chrono::seconds{30}))
                    lane_spin_trips.fetch_add(1);
            }
        });
    }

    // ── evaluators: hammer evaluate_key across every lane's keys ──
    for (int t = 0; t < 3; ++t) {
        workers.emplace_back([&, t] {
            while (!go.load()) {
            }
            for (int i = 0; i < kIters; ++i) {
                rt->evaluate_key(all_keys[static_cast<std::size_t>((t + i) % all_keys.size())],
                                 i % 2 ? EvalReason::Event : EvalReason::Convergence);
                evals.fetch_add(1);
            }
        });
    }

    // ── drainer: loops on churn_done, not a fixed count. A fixed-count drainer finishes
    //    before the first arm has even landed once the backend can block. ──
    workers.emplace_back([&] {
        while (!go.load()) {
        }
        while (!churn_done.load()) {
            rt->drain([&](const OutboxEntry&) {
                send_park.maybe_park(-1);
                sends.fetch_add(1);
                return SendResult::Sent;
            });
            drains.fetch_add(1);
        }
    });

    go.store(true);
    // Join the churners specifically, then stop everything through the SAME function the
    // RAII guard uses.
    for (int lane = 0; lane < kLanes; ++lane)
        workers[static_cast<std::size_t>(lane)].join();
    churn_done.store(true);
    stop_everything();

    // One final drain with the gates already open, so nothing is left buffered.
    rt->drain([&](const OutboxEntry&) {
        sends.fetch_add(1);
        return SendResult::Sent;
    });

    // ── (a) harness health: if any of these fires, nothing below means anything ──
    CHECK(b->arm_park.watchdog_trips == 0);
    CHECK(b->disarm_park.watchdog_trips == 0);
    CHECK(send_park.watchdog_trips == 0);
    CHECK(lane_spin_trips.load() == 0);
    CHECK(rt->active_backend_op_workers() == 0);

    // ── (b) the blocking paths were actually exercised ──
    CHECK(attach_ok.load() > 0);
    CHECK(b->arm_park.long_holds > 0);
    CHECK(rt->backend_op_timeouts() > 0); // HARD: a long hold must reach the deadline
    CHECK(b->disarm_park.total_parked > 0);
    CHECK(send_park.total_parked > 0);
    CHECK(evals.load() > 0);
    CHECK(drains.load() > 0);
    CHECK(sends.load() > 0);
    CHECK(rt->outbox_size() == 0);

    // ── (c) census + rejection check, BEFORE begin_stop() ──
    // Taken before begin_stop() deliberately: once the executor is stopping, a disarm
    // routed through it is dropped as Stopped, which would present here as a surplus.
    const auto io = rt->io_executor_stats_for_test();
    // These two are what make the reconciliation a proof rather than a likelihood. An
    // AlreadyRunning or CapacityExhausted refusal is counted nowhere at the runtime's own
    // surface and submit_disarm_off_lock drops it silently, so a non-zero here means a
    // surplus below could be a declined disarm rather than a leak - the assertion could
    // no longer distinguish them.
    for (std::size_t c = 0; c < io.counters.size(); ++c) {
        CHECK(io.counters[c].rejected_key == 0);
        CHECK(io.counters[c].rejected_capacity == 0);
    }
    std::multiset<std::uint64_t> armed;
    std::multiset<std::uint64_t> disarmed;
    {
        const auto armed_snapshot = b->armed_ids();
        const auto disarmed_snapshot = b->disarmed_ids();
        armed.insert(armed_snapshot.begin(), armed_snapshot.end());
        disarmed.insert(disarmed_snapshot.begin(), disarmed_snapshot.end());
    }
    for (const auto id : disarmed) {
        // A disarm for an id that was never armed (or armed fewer times than it is
        // disarmed) is a DOUBLE-DISARM, a different defect from a leak and one that must
        // stop the reconciliation rather than quietly cancel a real surplus out of it.
        REQUIRE(armed.count(id) >= disarmed.count(id));
    }
    std::multiset<std::uint64_t> still_armed;
    for (const auto id : armed)
        if (disarmed.count(id) == 0)
            still_armed.insert(id);
    // Live subscriptions must equal live armed keys: the runtime holds exactly one
    // subscription per key, however many rules share it.
    CHECK(still_armed.size() == rt->armed_key_count());

    // ── (d) the churners' exclusive view ──
    std::size_t expected_rules = 0;
    std::set<std::string> expected_keys;
    for (const auto& m : live) {
        expected_rules += m.size();
        for (const auto& [rid, key] : m)
            expected_keys.insert(key);
    }
    CHECK(rt->rule_count() == expected_rules);
    CHECK(rt->armed_key_count() == expected_keys.size());

    rt->begin_stop();
}

// ── rung 7.4: detach_all, status_for_rule, Lifecycle audit, live-drain waker ─

TEST_CASE("attach_rule enqueues a Lifecycle 'armed' entry; detach_rule enqueues 'disarmed'",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    auto rule = file_exists_rule("r1");
    rule.rule_name = "Hosts integrity";
    rt->attach_rule("r1", file_spec("/a"), rule, true);

    auto lc = drain_lifecycle(*rt);
    REQUIRE(lc.size() == 1);
    CHECK(lc[0].rule_id == "r1");
    CHECK(lc[0].lifecycle_kind == "armed");
    // The entry carries the guard identity so the wire event is not blank (#2237 item 4).
    CHECK(lc[0].guard_type == "file");
    CHECK(lc[0].rule_name == "Hosts integrity");

    rt->detach_rule("r1");
    lc = drain_lifecycle(*rt);
    REQUIRE(lc.size() == 1);
    CHECK(lc[0].rule_id == "r1");
    CHECK(lc[0].lifecycle_kind == "disarmed");
    CHECK(lc[0].guard_type == "file"); // disarmed carries the identity too (captured pre-erase)
    CHECK(lc[0].rule_name == "Hosts integrity");
}

TEST_CASE("attach_rule: a THROWING backend arm() rolls back with no ghost index entry / no leak",
          "[spark][runtime]") {
    // Fable rung-7.7b M3: the pre-fix code installed attach_rule's rollback only AFTER
    // arm(), so a THROWING arm() left the rule in the index with no subscription. That
    // ghost then corrupted a LATER successful attach of a sibling rule on the same key
    // (a false 0->1 edge -> double-arm / untracked subscription).
    //
    // #2233 item 3: File/Registry/Service now run backend_->arm() on a detached
    // GuardianIoExecutor worker, off registry_mu_ - a throw there can no longer
    // propagate as a C++ exception across the thread boundary (GuardianIoExecutor
    // contains it by design, converting it to IoFailure::WorkerThrew). attach_rule
    // returns an error instead of throwing; the rollback guarantee below (no ghost
    // index entry, a sibling arms cleanly after) is otherwise unchanged.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    b->throw_arm = true;
    auto gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE_FALSE(gen);
    CHECK(gen.error() == "arm worker threw");
    b->throw_arm = false;

    // Rolled back clean: no armed watcher, the throwing arm did not count, nothing to
    // disarm (arm threw before returning a subscription).
    CHECK(rt->armed_key_count() == 0);
    CHECK(b->arms.load() == 0);
    CHECK(b->disarms.load() == 0);

    // The decisive check: a fresh attach of a SIBLING on the SAME key sees a real 0->1
    // edge and arms EXACTLY once. A lingering ghost from r1 would make this take the
    // existing-key branch and never arm (armed_key_count would stay 0, or double-count).
    REQUIRE(rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true));
    CHECK(rt->armed_key_count() == 1);
    CHECK(b->arms.load() == 1);
}

TEST_CASE("attach_rule: a throw AFTER arm() (waker copy) disarms and leaves no phantom audit",
          "[spark][runtime]") {
    // The throwing-arm test above only covers a throw BEFORE arm has any side effect.
    // This exercises the armed_here=true rollback path: arm() genuinely succeeds, then a
    // later step throws. A callable whose COPY throws, installed as the pending-initial
    // waker, makes the std::function copy inside attach_rule (after arm() returned a
    // subscription) throw. (Fable rung-7.7b: the seam the shipped test lacked.)
    struct ThrowOnCopy {
        ThrowOnCopy() = default;
        ThrowOnCopy(const ThrowOnCopy&) { throw std::runtime_error("waker copy boom"); }
        ThrowOnCopy(ThrowOnCopy&&) noexcept = default;
        ThrowOnCopy& operator=(ThrowOnCopy&&) noexcept = default;
        void operator()() const {}
    };
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    rt->set_pending_initial_waker(ThrowOnCopy{}); // moved in (noexcept); the COPY inside attach throws
    CHECK_THROWS_AS(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true),
                    std::runtime_error);
    rt->set_pending_initial_waker({}); // clear so the sibling attach below is clean

    // arm() succeeded, then the waker copy threw: the rollback disarmed the just-armed
    // subscription and removed the rule, and (the waker copy now precedes the lifecycle
    // enqueue) NO "armed" audit entry was written for the rolled-back attach.
    CHECK(rt->armed_key_count() == 0);
    CHECK(b->arms.load() == 1);    // the arm did happen
    CHECK(b->disarms.load() == 1); // ...and the rollback disarmed it (the armed_here path)
    CHECK(drain_lifecycle(*rt).empty()); // no phantom "armed"

    // Key is clean afterward: a fresh attach arms exactly once.
    REQUIRE(rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true));
    CHECK(rt->armed_key_count() == 1);
    CHECK(b->arms.load() == 2);
}

TEST_CASE("attach_rule: a throw AFTER joining an ALREADY-armed key leaves no ghost rule",
          "[spark][runtime]") {
    // #2233 item 3: distinct from the "throw AFTER arm()" test above, which only
    // covers the arm_edge==true (this call is the key's pioneer) rollback path.
    // This exercises the arm_edge==false (an existing shared watcher) path's OWN
    // rollback, which the #2233 item 3 restructure initially dropped (no backend
    // call happens here, so it is easy to assume nothing needs undoing - but
    // rules_/pending_initial were still mutated before the throw).
    struct ThrowOnCopy {
        ThrowOnCopy() = default;
        ThrowOnCopy(const ThrowOnCopy&) { throw std::runtime_error("waker copy boom"); }
        ThrowOnCopy(ThrowOnCopy&&) noexcept = default;
        ThrowOnCopy& operator=(ThrowOnCopy&&) noexcept = default;
        void operator()() const {}
    };
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true)); // pioneer, clean
    CHECK(rt->rule_count() == 1);

    rt->set_pending_initial_waker(ThrowOnCopy{});
    CHECK_THROWS_AS(rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true),
                    std::runtime_error);
    rt->set_pending_initial_waker({});

    // r2 never committed: no ghost rule, no phantom "armed" audit, and the SHARED
    // watcher (which this call never touched - arm_edge was false) is untouched -
    // still exactly one armed key, one arm() call total, no disarm.
    CHECK(rt->rule_count() == 1); // r1 only
    CHECK(rt->armed_key_count() == 1);
    CHECK(b->arms.load() == 1);
    CHECK(b->disarms.load() == 0);
    auto lc = drain_lifecycle(*rt);
    REQUIRE(lc.size() == 1); // r1's own "armed" only - no r2 entry
    CHECK(lc[0].rule_id == "r1");

    // r1 is still healthy: a fresh detach/attach cycle on it works cleanly.
    rt->detach_rule("r1");
    CHECK(rt->armed_key_count() == 0);
}

TEST_CASE("source tripwire: arming_rollback's .fn is assigned before "
          "arming_keys_.emplace(), not after (#3831)",
          "[spark][runtime][liveness][source_tripwire]") {
    // #3831: a bad_alloc during arming_rollback's OWN .fn= assignment (a 3-capture
    // closure exceeding libstdc++'s std::function SBO) is not injectable from this
    // ordinary test binary - it would need allocator fault-injection at a specific
    // call site, which this repo's only such mechanism (test_spark_alloc_budget.cpp)
    // is a SEPARATE executable for precisely because global operator new replacement
    // cannot coexist with normal test infrastructure (see that file's own "WHY THIS IS
    // A SEPARATE EXECUTABLE" doc comment). Absent that, this pins the textual property
    // the fix actually depends on: .fn is assigned before the mutation it protects, so
    // a throw during the assignment has nothing left to roll back. Mutation-verified:
    // swapping the two lines' relative order makes this fail.
    std::ifstream input(std::filesystem::path(YUZU_AGENT_SRC_DIR) / "guardian_spark_runtime.cpp");
    REQUIRE(input.is_open());
    const std::string source((std::istreambuf_iterator<char>(input)),
                             std::istreambuf_iterator<char>());

    const auto fn_assign_pos = source.find("arming_rollback.fn =");
    REQUIRE(fn_assign_pos != std::string::npos);
    // The real call, not a mention in prose - several comments near both markers say
    // "arming_keys_.emplace()" in passing, and a bare "arming_keys_.emplace(" matches
    // those too (verified: it found one of those comments, which sits ABOVE the real
    // .fn= assignment, and the test FAILED on already-correct code). InFlightArm is the
    // call's own second argument type - it does not appear in any comment mentioning
    // arming_keys_.emplace().
    const auto emplace_pos = source.find("arming_keys_.emplace(key, InFlightArm");
    REQUIRE(emplace_pos != std::string::npos);
    CHECK(fn_assign_pos < emplace_pos);

    // Ordering alone isn't the whole property: a future edit could move this guard's
    // declaration back INSIDE the locked block (reintroducing the pre-#3831 lock-order
    // hazard the block-scope comment above it warns against) while keeping .fn= textually
    // before .emplace() - still "passing" the check above. Pin scope too: .fn= must
    // precede the FIRST std::unique_lock<std::mutex> lk{registry_mu_} in this file (the
    // one attach_rule's locked block opens with; a second, unrelated one exists later
    // for the post-io_executor commit and is not what this line finds, since find()
    // returns the first match).
    const auto lock_pos = source.find("std::unique_lock<std::mutex> lk{registry_mu_}");
    REQUIRE(lock_pos != std::string::npos);
    CHECK(fn_assign_pos < lock_pos);
}

// ── PR #3821 review (fjarvis): prior_disarm dropped on an early exit ───────────
// attach_rule captures prior_disarm (the OWED backend disarm for whatever
// generation this call supersedes) BEFORE deciding which of three branches this
// push takes, but the ONLY submission site was the function's normal fall-through
// exit. Any earlier return or throw dropped it silently: a permanent, untracked
// live watcher - a real regression vs. pre-#2233's inline disarm, which no later
// step in this same function could skip. Three tests below, one per exit shape
// the review named.

TEST_CASE("attach_rule: a same-key busy fail-fast still disarms the re-pushed "
          "rule's OWN prior generation",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    // r2 starts on its own key, fully armed.
    REQUIRE(rt->attach_rule("r2", file_spec("/b"), file_exists_rule("r2"), true));
    CHECK(b->arms.load() == 1);

    // r1 parks a hung arm on "/a".
    b->hang_next_arm.store(true);
    std::thread a_thread{[&] { rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    struct Cleanup {
        FakeBackend* backend;
        std::thread* t;
        ~Cleanup() {
            backend->release_hang();
            if (t->joinable())
                t->join();
        }
    } cleanup{b.get(), &a_thread};
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    // r2 is re-pushed pointing at the SAME key r1 is currently arming ("/a") - a
    // legitimate spec change. detach_rule_locked("r2") captures its old "/b"
    // watcher as prior_disarm, THEN the busy check on "/a" fails fast and returns
    // before prior_disarm's normal submission site.
    auto gen_r2 = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);
    REQUIRE_FALSE(gen_r2);
    CHECK(gen_r2.error() == "arm already in progress for this key");

    // r2's OLD "/b" watcher must be disarmed regardless - it is unreachable from
    // any Guardian state after detach_rule_locked erased it.
    CHECK(b->disarms.load() == 1);

    b->release_hang();
    a_thread.join();
    CHECK(b->arms.load() == 2); // r1's arm, once it resolved; r2's re-push never armed
}

TEST_CASE("attach_rule: an inline-type arm() failure still disarms the re-pushed "
          "rule's prior bounded-key generation",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    CHECK(b->arms.load() == 1);
    CHECK(b->disarms.load() == 0);

    // Re-push r1 as an inline type (Startup - never routes through io_class_
    // for_spark_type's bounded set) whose arm() then fails.
    b->fail_arm = true;
    auto gen2 = rt->attach_rule("r1", SparkSpec{SparkType::Startup, StartupSparkParams{}},
                                file_exists_rule("r1"), true);
    REQUIRE_FALSE(gen2);
    b->fail_arm = false;

    // r1's OLD file-backed watcher must be disarmed even though the re-push
    // itself failed - it is no longer referenced anywhere in Guardian's state.
    CHECK(b->disarms.load() == 1);
    CHECK(rt->rule_count() == 0); // the failed re-push left nothing behind either
}

TEST_CASE("attach_rule: a commit throw still disarms the re-pushed rule's prior "
          "bounded-key generation",
          "[spark][runtime]") {
    struct ThrowOnCopy {
        ThrowOnCopy() = default;
        ThrowOnCopy(const ThrowOnCopy&) { throw std::runtime_error("waker copy boom"); }
        ThrowOnCopy(ThrowOnCopy&&) noexcept = default;
        ThrowOnCopy& operator=(ThrowOnCopy&&) noexcept = default;
        void operator()() const {}
    };
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    CHECK(b->arms.load() == 1);
    CHECK(b->disarms.load() == 0);

    // Re-push r1 as another inline type; commit_new_generation_locked's own waker
    // copy throws AFTER the new arm() succeeds, unwinding out of attach_rule.
    rt->set_pending_initial_waker(ThrowOnCopy{});
    CHECK_THROWS_AS(rt->attach_rule("r1", SparkSpec{SparkType::Startup, StartupSparkParams{}},
                                     file_exists_rule("r1"), true),
                    std::runtime_error);
    rt->set_pending_initial_waker({});

    // Both watchers must be disarmed: the NEW one via the inline branch's own
    // pre-existing rollback (armed_here==true), and r1's OLD file-backed one via
    // the #3821 review fix - the two rollbacks nest (LIFO) and neither replaces
    // the other.
    CHECK(b->arms.load() == 2);    // old File arm + new Startup arm
    CHECK(b->disarms.load() == 2); // both rolled back
    CHECK(rt->rule_count() == 0);
}

// ── #2233 item 3: arm/disarm liveness (bounded, off-registry_mu_ backend calls) ──

TEST_CASE("#2233 item 3: a bounded arm that never returns times out, leaves no state, "
          "and is counted",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});

    const auto t0 = clk::now();
    auto gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    const auto elapsed = clk::now() - t0;

    REQUIRE_FALSE(gen);
    CHECK(gen.error() == "arm timed out");
    // Bounded, not the old unbounded wedge: returns close to the configured
    // deadline, not never and not near-instantly (which would mean the deadline
    // was not actually applied).
    CHECK(elapsed >= std::chrono::milliseconds(50));
    CHECK(elapsed < std::chrono::seconds(10));
    CHECK(rt->armed_key_count() == 0);
    CHECK(rt->rule_count() == 0);
    CHECK(rt->backend_op_timeouts() == 1);
    CHECK(drain_lifecycle(*rt).empty()); // no phantom "armed" for a rule that never armed

    // Cleanup: release the still-parked detached worker so it does not outlive the
    // test (io_executor_'s own shared_ptr<State> keeps it memory-safe regardless,
    // but leaving it parked would leak a real OS thread across tests).
    b->wait_entered_hang(std::chrono::seconds(30));
    b->release_hang();
}

TEST_CASE("#2233 item 3: a bounded disarm that never returns is counted too - "
          "backend_op_timeouts() is not arm-only (sre, PR #3821 scoped-governance)",
          "[spark][runtime][liveness]") {
    // The arm-side timeout test above only pins half of backend_op_timeouts()'s
    // documented contract (guardian_spark_runtime.hpp: "attach_rule calls... PLUS
    // submit_disarm_off_lock calls... - one shared counter for both directions").
    // This pins the disarm side via the simplest submit_disarm_off_lock caller,
    // detach_rule().
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    CHECK(rt->backend_op_timeouts() == 0); // arming cleanly does not touch this counter

    b->hang_next_disarm.store(true);
    const auto t0 = clk::now();
    rt->detach_rule("r1"); // blocks up to backend_op_deadline waiting on the hung disarm
    const auto elapsed = clk::now() - t0;

    CHECK(elapsed >= std::chrono::milliseconds(50));
    CHECK(elapsed < std::chrono::seconds(10));
    CHECK(rt->backend_op_timeouts() == 1);

    // Cleanup: release the still-parked detached worker.
    b->wait_entered_disarm_hang(std::chrono::seconds(30));
    b->release_disarm_hang();
}

TEST_CASE("#2233 item 3: a parked arm on one key does not block a DIFFERENT key's attach",
          "[spark][runtime][liveness]") {
    // The actual defect this PR fixes: pre-fix, backend_->arm() ran INSIDE
    // registry_mu_, so a parked arm on key A blocked every other registry_mu_
    // operation - including an attach on an entirely unrelated key B - until it
    // returned. Proving key B's attach completes promptly WHILE key A's arm is
    // still parked is the direct proof registry_mu_ is genuinely released during
    // the bounded wait, not just released sooner.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    std::atomic<bool> a_done{false};
    std::thread a_thread{[&] {
        rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        a_done.store(true, std::memory_order_release);
    }};
    struct Cleanup {
        FakeBackend* backend;
        std::thread* t;
        ~Cleanup() {
            backend->release_hang();
            if (t->joinable())
                t->join();
        }
    } cleanup{b.get(), &a_thread};

    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    CHECK_FALSE(a_done.load(std::memory_order_acquire)); // still parked

    // key B is a DIFFERENT spark_key (different path) - must complete promptly,
    // well under key A's 30s deadline, while A is still parked.
    const auto t0 = clk::now();
    auto gen_b = rt->attach_rule("r2", file_spec("/b"), file_exists_rule("r2"), true);
    const auto elapsed_b = clk::now() - t0;
    REQUIRE(gen_b);
    CHECK(elapsed_b < std::chrono::seconds(5));
    CHECK(rt->armed_key_count() == 1); // only B so far - A is still parked

    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return a_done.load(std::memory_order_acquire); },
                                   std::chrono::seconds(10)));
    CHECK(rt->armed_key_count() == 2);
}

TEST_CASE("#2233 item 3: a same-key attach while another is in flight fails fast, "
          "never double-arms",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    std::thread a_thread{[&] { rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); }};
    struct Cleanup {
        FakeBackend* backend;
        std::thread* t;
        ~Cleanup() {
            backend->release_hang();
            if (t->joinable())
                t->join();
        }
    } cleanup{b.get(), &a_thread};

    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    // r2 targets the SAME key ("/a") while r1's arm is still parked - must fail
    // fast (not wait, not launch a second backend arm() call).
    const auto t0 = clk::now();
    auto gen_r2 = rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true);
    const auto elapsed = clk::now() - t0;
    REQUIRE_FALSE(gen_r2);
    CHECK(gen_r2.error() == "arm already in progress for this key");
    CHECK(elapsed < std::chrono::seconds(1)); // fail-fast, not a wait
    CHECK(rt->backend_op_busy() == 1);
    CHECK(rt->rule_count() == 0); // r2 was never installed
    CHECK(b->arms.load() == 0);   // no second (or first, yet) backend arm() call

    b->release_hang();
    a_thread.join(); // Cleanup's dtor no-ops afterward (t->joinable() is false post-join)
    CHECK(b->arms.load() == 1); // r1's single arm(), once it finally resolved
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->rule_count() == 1); // r1 only - r2 never attached
}

TEST_CASE("#2233 item 3: begin_stop() wakes a parked arm before its deadline elapses",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    // A long deadline - begin_stop() must wake the wait well before this, not by
    // riding it out.
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    std::atomic<int> outcome_ok{-1};
    const auto t0 = clk::now();
    std::thread a_thread{[&] {
        auto gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        outcome_ok.store(gen.has_value() ? 1 : 0, std::memory_order_release);
    }};
    struct Cleanup {
        FakeBackend* backend;
        std::thread* t;
        ~Cleanup() {
            backend->release_hang();
            if (t->joinable())
                t->join();
        }
    } cleanup{b.get(), &a_thread};

    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    rt->begin_stop(); // must wake the parked wait promptly, not after 30s

    a_thread.join(); // Cleanup's dtor no-ops afterward (t->joinable() is false post-join)
    const auto elapsed = clk::now() - t0;
    CHECK(elapsed < std::chrono::seconds(5)); // woken, not ridden out to the 30s deadline
    CHECK(outcome_ok.load(std::memory_order_acquire) == 0); // rejected (stopping)

    b->release_hang(); // the still-parked backend worker itself (io_executor_.stop()
                       // wakes the WAITER, not the underlying OS call - see begin_stop's doc)
}

TEST_CASE("#3816: begin_stop() followed by a late successful arm disarms the exact "
          "subscription id, once",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    std::atomic<int> outcome_ok{-1};
    std::thread a_thread{[&] {
        auto gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        outcome_ok.store(gen.has_value() ? 1 : 0, std::memory_order_release);
    }};
    struct Cleanup {
        FakeBackend* backend;
        std::thread* t;
        ~Cleanup() {
            backend->release_hang();
            if (t->joinable())
                t->join();
        }
    } cleanup{b.get(), &a_thread};

    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    rt->begin_stop(); // wakes the parked caller with Stopped, well before the arm resolves
    a_thread.join();
    CHECK(outcome_ok.load(std::memory_order_acquire) == 0); // rejected (stopping)

    b->release_hang(); // let the parked arm() finally succeed, well after the stop
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(b->arms.load() == 1);
    CHECK(b->disarms.load() == 1);
    CHECK(b->armed_ids() == b->disarmed_ids()); // the exact id, not merely a count
    CHECK(rt->backend_op_late_arms() == 1);
}

// ── Adversarial-review fix round: C1/c1 (late-success subscription leak) and
// C2/c2 (rollback disarm still under registry_mu_), both reviewers independently
// HIGH, plus C5/k3 (untested detach-during-in-flight-arm withdrawal path). ──

TEST_CASE("#3816 (was C1/c1): a timeout followed by a LATE successful arm "
          "is disarmed by GuardianIoExecutor's own on_abandoned, not leaked",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    // cpp-safety Gate 3 finding: without this, a REQUIRE failure below (exactly the
    // regression this test exists to catch) throws past every plain statement,
    // including the release_hang() near the end - leaking the parked detached
    // worker for the rest of the binary's run. release_hang() is idempotent
    // (harmless if it also runs again, non-exceptionally, further down).
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    auto gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE_FALSE(gen);
    CHECK(gen.error() == "arm timed out");
    // The worker is STILL parked at this point (only release_hang() unblocks it) -
    // attach_rule has already returned Timeout to its own caller.
    CHECK(rt->armed_key_count() == 0);
    CHECK(b->arms.load() == 0);
    CHECK(b->disarms.load() == 0);
    CHECK(rt->backend_op_late_arms() == 0);

    b->release_hang(); // let the parked arm() finally return - successfully, LATE
    // #3816: GuardianIoExecutor itself decides this arm arrived after its own
    // caller gave up and routes it to attach_rule's on_abandoned callback, which
    // disarms it - not a self-check racing arming_keys_'s erase any more.
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; },
                                   std::chrono::seconds(10)));
    CHECK(b->arms.load() == 1);
    CHECK(b->disarms.load() == 1);
    // Exact-id check, not just balanced counts (#3816): the id disarmed must be
    // the SAME id this arm() call minted, never merely "some id".
    CHECK(b->armed_ids() == b->disarmed_ids());
    CHECK(rt->backend_op_late_arms() == 1);
    // No trace of a live watcher anywhere in the runtime's own bookkeeping - the
    // subscription was real (arms==1) but is now fully reclaimed (disarms==1),
    // not silently untracked.
    CHECK(rt->armed_key_count() == 0);
    CHECK(rt->rule_count() == 0);
    CHECK(drain_lifecycle(*rt).empty()); // no phantom "armed" for a rule never committed

    // Runtime is still healthy afterward: a fresh attach on the SAME key arms cleanly.
    REQUIRE(rt->attach_rule("r2", file_spec("/a"), file_exists_rule("r2"), true));
    CHECK(rt->armed_key_count() == 1);
    CHECK(b->arms.load() == 2);
}

TEST_CASE("#3816: a timeout followed by a LATE FAILED arm is not counted as a late "
          "success and attempts no disarm",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    auto gen = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE_FALSE(gen);
    CHECK(gen.error() == "arm timed out");

    b->fail_arm.store(true); // the parked call, once released, fails rather than succeeds
    b->release_hang();
    // No RUNTIME-level counter this failure path touches increments
    // (backend_op_late_arms/arms/disarms all stay put), so there is nothing to
    // spin_until on to prove the worker resumed - give it ample bounded time (same
    // idiom test_guardian_io_executor.cpp uses to prove an erroneous action never
    // happened) before asserting the negative. The EXECUTOR's own T-agnostic
    // Counters::abandoned DOES increment for this case (a late failure is still a
    // normal, non-throwing fn() return, routed to on_abandoned same as a late
    // success) - not testable from this file, since GuardianSparkRuntime exposes
    // no executor-stats accessor; see test_guardian_io_executor.cpp's own coverage.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    CHECK(b->arms.load() == 0);      // arm() itself failed - no subscription ever minted
    CHECK(b->disarms.load() == 0);   // nothing to disarm
    CHECK(rt->backend_op_late_arms() == 0); // a late FAILURE is not a late SUCCESS
}

TEST_CASE("#2233 item 3 (security-guardian F2 / cpp-safety HIGH): a same-rule_id "
          "RETRY after a timeout arms cleanly, exercising the generation token",
          "[spark][runtime][liveness]") {
    // Matches production's actual retry shape more precisely than the C1 test above
    // (which retries as a DIFFERENT rule_id, "r2"): apply_rules' policy_generation
    // hold-on-failure means a timed-out rule is retried under the SAME rule_id on
    // the next push. This is the scenario InFlightArm::generation exists for - a
    // stale worker's self-disarm check must not match a LATER episode's marker just
    // because it shares the same rule_id. This test proves the END-TO-END outcome
    // (subscription census stays consistent: every arm() is eventually matched by
    // exactly one disarm() or one live tracked watcher) across a full
    // timeout-then-retry-then-late-resolution cycle; it does not pin the exact
    // microsecond interleaving cpp-safety traced (that window is genuinely narrow -
    // both the stale worker's check and a rejected retry's own cleanup race through
    // only a couple of registry_mu_ acquisitions - forcing it deterministically
    // would need a new production-code test hook, out of proportion here; the fix
    // itself (compare generation, not just rule_id) is correct by construction
    // regardless of how precisely this test can pin the race).
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline =
                                                          std::chrono::milliseconds(50)});
    struct Cleanup {
        FakeBackend* backend;
        ~Cleanup() { backend->release_hang(); }
    } cleanup{b.get()};

    // Episode 1: times out. arming_keys_ is fully cleared by the time this returns
    // (attach_rule's post-wait commit runs on the SUBMITTER's timeout, independent
    // of whether the underlying backend->arm() call has itself returned yet).
    auto gen1 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE_FALSE(gen1);
    CHECK(gen1.error() == "arm timed out");
    CHECK(rt->rule_count() == 0);

    // Episode 2: SAME rule_id, SAME key, retried immediately while episode 1's
    // worker is still parked (single-flight on the executor rejects this - not
    // committed, not leaked, matches UP-3/UP-4's disclosed "busy" shape).
    auto gen2 = rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE_FALSE(gen2);
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);

    // Release the original hang - whichever episode's worker was actually parked
    // resolves now. Regardless of exactly how the two episodes interleaved above,
    // the runtime's own bookkeeping must end up CONSISTENT: no rule ever commits as
    // armed (both episodes ended in error), and the real backend subscription that
    // arm() mints is eventually disarmed - never left live and untracked.
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return b->arms.load() >= 1; }, std::chrono::seconds(10)));
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() >= b->arms.load(); },
                                   std::chrono::seconds(10)));
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    CHECK(drain_lifecycle(*rt).empty()); // neither episode ever produced a phantom "armed"

    // Runtime is still healthy: a genuinely fresh retry (well after both prior
    // episodes settled) arms cleanly.
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    CHECK(rt->armed_key_count() == 1);
    CHECK(rt->rule_count() == 1);
}

TEST_CASE("#2233 item 3 (C2/c2): the post-arm commit rollback's disarm runs "
          "off registry_mu_ - a parked disarm does not block a different key",
          "[spark][runtime][liveness]") {
    // Reproduces C2/c2's exact scenario: arm succeeds, then a later commit step
    // throws (a throwing waker copy, same seam as the existing "throw AFTER arm()"
    // test), triggering the rollback's compensating disarm. Proves that disarm now
    // runs OFF registry_mu_: while it is parked, a DIFFERENT key's attach proceeds.
    struct ThrowOnCopy {
        ThrowOnCopy() = default;
        ThrowOnCopy(const ThrowOnCopy&) { throw std::runtime_error("waker copy boom"); }
        ThrowOnCopy(ThrowOnCopy&&) noexcept = default;
        ThrowOnCopy& operator=(ThrowOnCopy&&) noexcept = default;
        void operator()() const {}
    };
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_disarm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    rt->set_pending_initial_waker(ThrowOnCopy{});
    std::atomic<bool> a_threw{false};
    std::thread a_thread{[&] {
        try {
            rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        } catch (const std::runtime_error&) {
            a_threw.store(true, std::memory_order_release);
        }
    }};
    struct Cleanup {
        FakeBackend* backend;
        std::thread* t;
        ~Cleanup() {
            backend->release_disarm_hang();
            if (t->joinable())
                t->join();
        }
    } cleanup{b.get(), &a_thread};

    // The rollback's disarm is now parked - PROOF it is not holding registry_mu_:
    // a different key's attach completes promptly while it is still hung. r1's own
    // throw has already happened by this point (synchronously, before its rollback
    // even reaches the disarm call) - safe to clear the waker now so r2's own
    // commit does not ALSO throw on the same still-installed ThrowOnCopy.
    REQUIRE(b->wait_entered_disarm_hang(std::chrono::seconds(30)));
    rt->set_pending_initial_waker({});
    const auto t0 = clk::now();
    auto gen_b = rt->attach_rule("r2", file_spec("/b"), file_exists_rule("r2"), true);
    const auto elapsed_b = clk::now() - t0;
    REQUIRE(gen_b);
    CHECK(elapsed_b < std::chrono::seconds(5));

    b->release_disarm_hang();
    REQUIRE(yuzu::test::spin_until([&] { return a_threw.load(std::memory_order_acquire); },
                                   std::chrono::seconds(10)));

    CHECK(b->arms.load() == 2);    // r1's arm (rolled back) + r2's arm
    CHECK(b->disarms.load() == 1); // r1's rollback disarm only
    CHECK(rt->armed_key_count() == 1); // r2 only - r1 never committed
    CHECK(rt->rule_count() == 1);
    CHECK(drain_lifecycle(*rt).size() == 1); // r2's "armed" only, no phantom for r1
}

TEST_CASE("#2233 item 3 (C5/k3): detaching a rule while its own arm is still "
          "parked withdraws it cleanly, with an eventual compensating disarm",
          "[spark][runtime][liveness]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    std::atomic<bool> a_done{false};
    std::thread a_thread{[&] {
        rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        a_done.store(true, std::memory_order_release);
    }};
    struct Cleanup {
        FakeBackend* backend;
        std::thread* t;
        ~Cleanup() {
            backend->release_hang();
            if (t->joinable())
                t->join();
        }
    } cleanup{b.get(), &a_thread};

    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    // Detach the SAME rule whose arm is still parked - the withdrawn branch
    // (detach_rule_locked's Case 0, guardian_spark_runtime.cpp) must handle this
    // without touching keys_/rules_ (neither exists yet) and without waiting.
    const auto t0 = clk::now();
    rt->detach_rule("r1");
    const auto elapsed = clk::now() - t0;
    CHECK(elapsed < std::chrono::seconds(1)); // withdrawal itself does not wait
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    CHECK(drain_lifecycle(*rt).empty()); // never armed - no "armed" or "disarmed" entry

    b->release_hang(); // let the parked (now-withdrawn) arm finally resolve
    REQUIRE(yuzu::test::spin_until([&] { return b->arms.load() == 1; }, std::chrono::seconds(10)));
    // Withdrawn-path completion (attach_rule's stopping_||withdrawn branch) disarms
    // whatever the late arm produced - same self-cleanup shape as C1/c1 above.
    REQUIRE(yuzu::test::spin_until([&] { return b->disarms.load() == 1; }, std::chrono::seconds(10)));
    REQUIRE(yuzu::test::spin_until([&] { return a_done.load(std::memory_order_acquire); },
                                   std::chrono::seconds(10)));
    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    CHECK(drain_lifecycle(*rt).empty());

    // Runtime is still healthy: a fresh attach on the same key/rule arms cleanly.
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    CHECK(rt->armed_key_count() == 1);
    CHECK(b->arms.load() == 2);
}

TEST_CASE("Lifecycle audit entries are NOT coalesced or purged like compliance/health",
          "[spark][runtime]") {
    // The bug Sol's review caught: GuardianOutbox coalesces by (domain,rule_id)
    // - latest wins - and detach_rule's drop_rule(rule_id) purges every domain
    // for that rule, including (before this fix) Lifecycle. Attach-then-
    // immediately-disable must not lose the "armed" audit evidence.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt->detach_rule("r1"); // same-tick disable, before anything ever drained

    auto lc = drain_lifecycle(*rt);
    REQUIRE(lc.size() == 2); // BOTH survive: armed, then disarmed
    CHECK(lc[0].lifecycle_kind == "armed");
    CHECK(lc[1].lifecycle_kind == "disarmed");
}

TEST_CASE("a same-id re-attach enqueues disarmed-then-armed, both surviving",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1", false), true); // replace

    auto lc = drain_lifecycle(*rt);
    REQUIRE(lc.size() == 3); // armed, disarmed (internal replace), armed (new generation)
    CHECK(lc[0].lifecycle_kind == "armed");
    CHECK(lc[1].lifecycle_kind == "disarmed");
    CHECK(lc[2].lifecycle_kind == "armed");
}

TEST_CASE("detach_all withdraws every attached rule and disarms every backend subscription",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt->attach_rule("r2", svc_spec("sshd"), svc_running_rule("r2"), true);
    REQUIRE(rt->rule_count() == 2);
    REQUIRE(rt->armed_key_count() == 2);
    REQUIRE(b->arms.load() == 2);

    rt->detach_all();

    CHECK(rt->rule_count() == 0);
    CHECK(rt->armed_key_count() == 0);
    CHECK(b->disarms.load() == 2);
    const auto lc = drain_lifecycle(*rt);
    CHECK(lc.size() == 4); // armed x2, disarmed x2
}

TEST_CASE("detach_all also clears pending-initial bookkeeping (no stale scheduler reference)",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE(rt->keys_with_pending_initial().size() == 1);

    rt->detach_all();

    CHECK(rt->keys_with_pending_initial().empty());
    // A convergence sweep over a now-nonexistent key must be a safe no-op, not
    // a dangling reference into freed PerKey state.
    rt->evaluate_key(spark_key(file_spec("/a")), EvalReason::Convergence);
    SUCCEED("sweeping a detached key after detach_all did not crash");
}

TEST_CASE("status_for_rule reflects the last committed verdict; nullopt for an unattached rule",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    CHECK_FALSE(rt->status_for_rule("ghost").has_value());

    r->file = read_known(FileSnapshot{.exists = true});
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt->evaluate_key(spark_key(file_spec("/a")), EvalReason::Initial);

    const auto st = rt->status_for_rule("r1");
    REQUIRE(st.has_value());
    CHECK_FALSE(st->in_unknown);
    REQUIRE(st->last_compliant.has_value());
    CHECK(*st->last_compliant); // file exists, expect_present=true -> compliant

    r->file = read_unknown<FileSnapshot>("transient");
    rt->evaluate_key(spark_key(file_spec("/a")), EvalReason::Convergence);
    const auto st2 = rt->status_for_rule("r1");
    REQUIRE(st2.has_value());
    CHECK(st2->in_unknown);
}

TEST_CASE("the outbox-enqueue waker fires on a compliance commit and on attach/detach lifecycle "
          "entries",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    std::atomic<int> wakes{0};
    rt->set_outbox_enqueue_waker([&] { wakes.fetch_add(1); });

    r->file = read_known(FileSnapshot{.exists = true});
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    CHECK(wakes.load() >= 1); // the "armed" lifecycle enqueue

    const int before_eval = wakes.load();
    rt->evaluate_key(spark_key(file_spec("/a")), EvalReason::Initial);
    CHECK(wakes.load() > before_eval); // the compliant-edge commit

    const int before_detach = wakes.load();
    rt->detach_rule("r1");
    CHECK(wakes.load() > before_detach); // the "disarmed" lifecycle enqueue
}

TEST_CASE("a copied outbox-enqueue waker outliving its installer is a harmless no-op",
          "[spark][runtime]") {
    // Mirrors the already-shipped pending_initial_waker_ lifetime test: a
    // waker capturing only shared, still-alive state must be safe to invoke
    // after whatever installed it is gone.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    auto flag = std::make_shared<std::atomic<bool>>(false);
    rt->set_outbox_enqueue_waker([flag] { flag->store(true); });
    auto copied = rt->outbox_enqueue_waker_for_test();
    rt->set_outbox_enqueue_waker({}); // clear the installed one
    REQUIRE(copied);
    copied(); // the copy still runs fine
    CHECK(flag->load());
}

TEST_CASE("lifecycle_backpressure_drops counts a full audit log without blocking the arm",
          "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // clamped up to the one-max-batch floor
    auto rt = make_rt(r, b, cfg);

    // Fill the lifecycle log to capacity, then churn one rule's arm/disarm on top. Paged in
    // directly because the window is floored at a whole maximum-size batch, so filling it via
    // rule churn alone would take hundreds of attaches to say the same thing.
    const std::size_t cap = rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i < cap; ++i)
        fill.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rt->try_page_batch(std::move(fill)).added == cap);
    REQUIRE(rt->lifecycle_headroom() == 0);
    for (int i = 0; i < 5; ++i)
        rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    CHECK(rt->lifecycle_backpressure_drops() > 0);
    // #2233 item 7: 5 attaches each drop at capacity (5 rejected "armed" entries), but
    // the log-once branch (enqueue_lifecycle_locked's own == 1 gate) must fire exactly
    // ONCE - proving the log-once logic actually gates repeats, not just that it
    // doesn't crash under repetition. Direct proof via the _for_test observable
    // (LogCapture cannot see this: guardian_spark_runtime.cpp is compiled into
    // libyuzu_agent_core.so, and its own doc comment documents the logger-swap not
    // reliably crossing that shared-library boundary).
    CHECK(rt->lifecycle_backpressure_log_fires_for_test() == 1);
    // The arm itself still succeeded throughout - the audit trail never blocks
    // the real detection-capability change.
    CHECK(rt->rule_count() == 1);
    CHECK(b->arms.load() >= 1);
}

// ── Durable-journal staging (item 7 PR-Ag C2) ────────────────────────────────

TEST_CASE("attach_rule stages a durable record; its event_id matches the wire event",
          "[spark][runtime][journal]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    auto staged = rt->snapshot_pending().records;
    REQUIRE(staged.size() == 1);
    CHECK(staged[0]->rule_id == "r1");
    CHECK(staged[0]->kind == "armed");
    CHECK(staged[0]->enqueued_ns > 0);
    CHECK_FALSE(staged[0]->event_id.empty());

    // Mint-once: the durable record and the live wire event carry ONE id (rev-4.1 #4)
    // - a replay must reproduce it byte-for-byte or the server sees a false Conflict.
    auto lc = drain_lifecycle(*rt);
    REQUIRE(lc.size() == 1);
    CHECK(lc[0].event_id == staged[0]->event_id);
    CHECK(lc[0].lifecycle_kind == staged[0]->kind);
    CHECK(lc[0].guard_type == staged[0]->guard_type);
    // The drain pops the send window, NOT the staging vector.
    CHECK(rt->pending_journal_depth() == 1);
}

TEST_CASE("detach_rule stages a disarmed record after the armed one", "[spark][runtime][journal]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true)); // stages "armed"
    rt->detach_rule("r1");                                                         // ->0 edge, stages "disarmed"

    auto staged = rt->snapshot_pending().records;
    REQUIRE(staged.size() == 2);
    CHECK(staged[0]->kind == "armed");
    CHECK(staged[1]->kind == "disarmed");
    CHECK(staged[1]->rule_id == "r1");
}

TEST_CASE("a refused arm stages no durable record (no phantom)", "[spark][runtime][journal]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->fail_arm.store(true);
    auto rt = make_rt(r, b);
    CHECK_FALSE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true).has_value());
    CHECK(rt->snapshot_pending().records.empty()); // arm refused before enqueue → nothing staged
}

TEST_CASE("a throwing arm stages no durable record (no phantom)", "[spark][runtime][journal]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->throw_arm.store(true);
    auto rt = make_rt(r, b);
    // #2233 item 3: File runs off registry_mu_ via GuardianIoExecutor, which contains
    // a worker throw and returns it as an error rather than propagating it - see the
    // "a THROWING backend arm() rolls back..." test above for the full rationale.
    CHECK_FALSE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true).has_value());
    CHECK(rt->snapshot_pending().records.empty()); // rollback undid the arm; nothing staged
}

TEST_CASE("snapshot_pending is FIFO; erase_persisted_prefix drops the oldest N",
          "[spark][runtime][journal]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    REQUIRE(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    REQUIRE(rt->attach_rule("r2", file_spec("/b"), file_exists_rule("r2"), true));
    REQUIRE(rt->attach_rule("r3", file_spec("/c"), file_exists_rule("r3"), true));
    REQUIRE(rt->pending_journal_depth() == 3);

    auto staged = rt->snapshot_pending().records;
    REQUIRE(staged.size() == 3);
    CHECK(staged[0]->rule_id == "r1");
    CHECK(staged[2]->rule_id == "r3");

    rt->erase_persisted_prefix(2, rt->snapshot_pending().drops_at_snapshot); // drop the two oldest (r1, r2)
    REQUIRE(rt->pending_journal_depth() == 1);
    CHECK(rt->snapshot_pending().records[0]->rule_id == "r3");

    rt->erase_persisted_prefix(99, rt->snapshot_pending().drops_at_snapshot); // clamps to size
    CHECK(rt->pending_journal_depth() == 0);
}

// ── Replay: try_page_batch + page_into_window (item 7 PR-Ag C5) ───────────────

TEST_CASE("try_page_batch pages new entries into the send window", "[spark][runtime][journal]") {
    auto rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>());
    CHECK(rt->try_page_batch({lc_entry("r1", "e1"), lc_entry("r2", "e2")}).added == 2);
    auto lc = drain_lifecycle(*rt);
    REQUIRE(lc.size() == 2);
    CHECK(lc[0].event_id == "e1");
    CHECK(lc[1].event_id == "e2");
}

TEST_CASE("try_page_batch skips entries already in the window (membership scan)",
          "[spark][runtime][journal]") {
    auto rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>());
    CHECK(rt->try_page_batch({lc_entry("r1", "e1")}).added == 1);
    // e1 already present; only e2 is net-new.
    CHECK(rt->try_page_batch({lc_entry("r1", "e1"), lc_entry("r2", "e2")}).added == 1);
}

TEST_CASE("try_page_batch defers a batch that does not fit the headroom", "[spark][runtime][journal]") {
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // clamped up to the one-max-batch floor
    auto rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);
    const std::size_t cap = rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill; // fill to exactly ONE free slot
    for (std::size_t i = 0; i + 1 < cap; ++i)
        fill.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rt->try_page_batch(std::move(fill)).added == cap - 1);
    // headroom is 1; a 2-entry batch is deferred WHOLE (never split).
    {   // A 0 return now carries WHY: blocked for headroom, not "already a member". That
        // distinction is what lets the journal tell a waiting backlog from an idle steady
        // state (#2345 Gate 3).
        const auto blocked = rt->try_page_batch({lc_entry("r2", "e2"), lc_entry("r3", "e3")});
        CHECK(blocked.added == 0);
        CHECK(blocked.blocked_for_headroom);
        CHECK(blocked.required == 2);
    }
    CHECK(rt->try_page_batch({lc_entry("r2", "e2")}).added == 1); // a 1-entry batch fits
}

TEST_CASE("page_into_window replays a persisted batch with provenance", "[spark][runtime][journal]") {
    PageRig rig;
    rig.persist("r1");
    auto stats = rig.journal->page_into_window(*rig.rt, /*now_ms=*/1'700'000'100'000);
    CHECK(stats.records_paged == 1);

    auto lc = drain_lifecycle(*rig.rt);
    REQUIRE(lc.size() == 1);
    CHECK(lc[0].event_id == "e-r1");
    CHECK(lc[0].journal_last_in_batch);         // provenance attached for the sent-label
    CHECK_FALSE(lc[0].journal_batch_key.empty());
}

TEST_CASE("page_into_window does not re-page a windowed entry (skips entries already windowed)",
          "[spark][runtime][journal]") {
    PageRig rig;
    rig.persist("r1");
    const std::int64_t now = 1'700'000'100'000;
    CHECK(rig.journal->page_into_window(*rig.rt, now).records_paged == 1);
    // The window still holds e-r1 (not drained): a second pass re-considers it but membership
    // skips it - 0 net-new.
    CHECK(rig.journal->page_into_window(*rig.rt, now + 60'000).records_paged == 0);
}

TEST_CASE("page_into_window reaches the never-sent tail on a stable connection (fair rotation)",
          "[spark][runtime][journal]") {
    PageRig rig;
    const int N = 12; // > burst; the head keeps re-arriving as it is sent + popped
    for (int i = 0; i < N; ++i)
        rig.persist("r" + std::to_string(i));

    // Model a healthy connected agent: page, then drain (send + pop), each tick; the bucket
    // refills as the clock advances. Oldest-first (the old code) would re-send the head forever
    // and starve the tail; fair rotation must reach EVERY batch. (Design §10 mandated test.)
    std::set<std::string> ever_sent;
    std::int64_t t = 1'700'000'000'000;
    for (int tick = 0; tick < 80 && ever_sent.size() < static_cast<std::size_t>(N); ++tick) {
        rig.journal->page_into_window(*rig.rt, t);
        rig.rt->drain([&](const OutboxEntry& e) {
            if (e.domain == OutboxDomain::Lifecycle)
                ever_sent.insert(e.event_id);
            return SendResult::Sent;
        });
        t += 30'000; // 30 s / tick
    }
    CHECK(ever_sent.size() == static_cast<std::size_t>(N)); // no tail starvation
}

TEST_CASE("page_into_window bounds net-new work per pass (rate limit)", "[spark][runtime][journal]") {
    PageRig rig;
    for (int i = 0; i < 20; ++i)
        rig.persist("r" + std::to_string(i));
    // One pass with a fresh bucket pages at most burst + the single-batch overshoot; the rest
    // are DELAYED (still journaled), never dropped.
    const auto s = rig.journal->page_into_window(*rig.rt, 1'700'000'000'000);
    CHECK(s.batches_paged >= 1);
    CHECK(s.batches_paged <= 6); // burst (5) + 1 overshoot
    CHECK(drain_lifecycle(*rig.rt).size() == s.batches_paged);
}

// ── #2364 headroom-blocked EPISODE state ──────────────────────────────────────
// The regime test: the episode clock must SURVIVE a pass that places small batches
// while the big one stays blocked - that is the exact starvation channel #2364
// documents, and the design this replaced (clear-on-placement) zeroed the clock on
// every such pass, measuring nothing (Sol + Kimi opine, 2026-07-23).

TEST_CASE("#2364 episode: survives small-batch placement while the big batch is blocked",
          "[spark][runtime][journal]") {
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // clamped up to the one-max-batch floor (256)
    PageRig rig;
    rig.rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);

    // Fill the window to headroom 3.
    const std::size_t cap = rig.rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i + 3 < cap; ++i)
        fill.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == cap - 3);

    // ONE 4-record batch (blocked: needs 4 > 3) + one 1-record batch (fits).
    std::vector<std::shared_ptr<const JournalRecord>> big;
    for (int i = 0; i < 4; ++i)
        big.push_back(std::make_shared<const JournalRecord>(
            JournalRecord{.rule_id = "big", .generation = 1, .event_id = "e-big-" + std::to_string(i),
                          .enqueued_ns = 1'700'000'000'000'000'000, .kind = "armed",
                          .guard_type = "file", .rule_name = "n"}));
    REQUIRE(rig.journal->persist(big, nullptr, kJournalPersistUnbounded, kJournalPersistUnbounded) == 4);
    rig.persist("small");

    CHECK(rig.journal->headroom_blocked_since_for_test() == -1); // no episode yet

    const std::int64_t t0 = 1'700'000'000'000;
    const auto s1 = rig.journal->page_into_window(*rig.rt, t0);
    CHECK(s1.headroom_blocked);
    CHECK(s1.records_paged == 1); // the small batch placed IN THE SAME PASS
    const auto since1 = rig.journal->headroom_blocked_since_for_test();
    CHECK(since1 >= 0); // episode started

    // Second blocked pass: set-if-unset must HOLD the original stamp, not re-stamp -
    // re-stamping is the sawtooth that pins the age at ~0 under sustained starvation.
    const auto s2 = rig.journal->page_into_window(*rig.rt, t0 + 60'000);
    CHECK(s2.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == since1);

    // The age accessor takes the caller's steady now: exact age, and saturating (a now
    // at-or-before the stamp reads 0, never an unsigned wrap).
    CHECK(rig.journal->headroom_blocked_age_ms(since1 + 5'000) == 5'000);
    CHECK(rig.journal->headroom_blocked_age_ms(since1) == 0);
    CHECK(rig.journal->headroom_blocked_age_ms(since1 - 1) == 0);

    // Recovery: drain the window, then a pass that classifies EVERY candidate with no
    // block observed (a full clean sweep) clears the episode.
    drain_lifecycle(*rig.rt);
    const auto s3 = rig.journal->page_into_window(*rig.rt, t0 + 120'000);
    CHECK_FALSE(s3.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == -1);
    CHECK(rig.journal->headroom_blocked_age_ms(t0) == 0); // no episode -> age 0
}

TEST_CASE("#2364 episode: a clean SLICE of a >128-candidate journal must not clear it",
          "[spark][runtime][journal]") {
    // A pass scans at most kJournalPageMaxBatchesPerPass (128) candidates, so with more
    // candidates than that a clean pass proves nothing about the unscanned tail -
    // clearing on it would sawtooth the gauge in the big-journal regime (both external
    // reviewers, independently). Clearing waits for accumulated block-free coverage of
    // the full candidate set.
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // floor 256
    PageRig rig;
    rig.rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);

    // 130 journal batches whose records are ALREADY in the window (need==0 candidates:
    // cleanly classified, never a blockage, and - crucially - no token spend), plus one
    // OLDEST 1-record batch that cannot fit (headroom 0) and starts the episode.
    auto write_batch = [&](const std::string& nonce, std::uint64_t seq, std::int64_t ts_ms,
                           const std::string& eid) {
        // Mint the key through the production helper: the timestamp is IN the key, and the
        // maintenance passes order and expire by it, so a hand-written key would be corruption.
        const std::string key = journal_batch_key(ts_ms, nonce, seq);
        REQUIRE(rig.kv->set(
            kJournalNamespace, key,
            R"({"v":4,"ts_ms":)" + std::to_string(ts_ms) +
                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":")" + eid +
                R"(","enqueued_ns":1700000000000000000,"kind":"armed","guard_type":"file","rule_name":"n"}]})"));
        return key;
    };
    const std::int64_t base_ts = 1'700'000'000'000;
    const std::string blocked_key = write_batch("aaa", 0, base_ts - 1'000, "e-blk"); // oldest
    std::vector<OutboxEntry> windowed;
    for (int i = 0; i < 130; ++i) {
        const auto id = std::to_string(i);
        write_batch("bbb", static_cast<std::uint64_t>(i), base_ts + i, "e-r" + id);
        windowed.push_back(lc_entry("r" + id, "e-r" + id));
    }
    // Fill the window COMPLETELY: the 130 candidate ids + filler to capacity.
    const std::size_t cap = rig.rt->lifecycle_headroom();
    for (std::size_t i = 130; i < cap; ++i)
        windowed.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(windowed)).added == cap);

    // Pass 1: headroom 0, the oldest candidate needs a slot -> blocked, episode starts.
    const auto s1 = rig.journal->page_into_window(*rig.rt, base_ts + 50'000);
    CHECK(s1.headroom_blocked);
    const auto since = rig.journal->headroom_blocked_since_for_test();
    REQUIRE(since >= 0);

    // The blocked batch gets a durable sent-label (as if delivered), so ordinary passes
    // now SKIP it - every remaining candidate classifies cleanly (already windowed).
    REQUIRE(rig.kv->set(kJournalNamespace, journal_sent_key_from_batch_key(blocked_key), ""));

    // Pass 2: 131 candidates, slice cap 128 -> a CLEAN pass that covered only a slice.
    // The old clear-on-clean-pass rule would clear here; the episode must survive.
    const auto s2 = rig.journal->page_into_window(*rig.rt, base_ts + 110'000);
    CHECK_FALSE(s2.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == since);

    // Pass 3: accumulated block-free coverage (128 + 128) now spans all 131 candidates
    // -> the episode clears.
    const auto s3 = rig.journal->page_into_window(*rig.rt, base_ts + 170'000);
    CHECK_FALSE(s3.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == -1);
}

TEST_CASE("#2364 episode: shrink-churn cannot clear it early (distinct coverage, not a count)",
          "[spark][runtime][journal]") {
    // THE Fable-review regression (2026-07-23). A coverage COUNT compared against the
    // current candidate-set size clears early when prune eviction removes
    // already-counted candidates between passes: the count survives, the bar drops, and
    // the episode clears before the rotation ever re-reaches the still-blocked batch -
    // re-opening the sawtooth in exactly the #2364 shrink-churn regime. Distinct-key
    // coverage must keep the episode alive until every SURVIVING candidate has itself
    // been observed block-free.
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // floor 256
    PageRig rig;
    rig.rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);

    auto write_batch = [&](const std::string& nonce, std::uint64_t seq, std::int64_t ts_ms,
                           const std::string& eid) {
        const std::string key = journal_batch_key(ts_ms, nonce, seq);
        REQUIRE(rig.kv->set(
            kJournalNamespace, key,
            R"({"v":4,"ts_ms":)" + std::to_string(ts_ms) +
                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":")" + eid +
                R"(","enqueued_ns":1700000000000000000,"kind":"armed","guard_type":"file","rule_name":"n"}]})"));
        return key;
    };
    const std::int64_t base_ts = 1'700'000'000'000;
    // Oldest: the blocked batch (1 net-new record, and the window will be full).
    write_batch("aaa", 0, base_ts - 1'000, "e-blk");
    // 260 newer batches, all sent-labelled: they classify cleanly (skip-sent) without
    // needing window room, and 260 > 2x the 128-per-pass slice so full coverage takes
    // more than two passes.
    std::vector<std::string> clean_keys;
    for (int i = 0; i < 260; ++i) {
        const auto id = std::to_string(i);
        const std::string key =
            write_batch("bbb", static_cast<std::uint64_t>(i), base_ts + i, "e-r" + id);
        REQUIRE(rig.kv->set(kJournalNamespace, journal_sent_key_from_batch_key(key), ""));
        clean_keys.push_back(key);
    }
    // Window completely full -> the blk batch can never place.
    const std::size_t cap = rig.rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i < cap; ++i)
        fill.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == cap);

    // Pass 1: the oldest candidate blocks at headroom 0 -> episode starts.
    const auto s1 = rig.journal->page_into_window(*rig.rt, base_ts + 50'000);
    REQUIRE(s1.headroom_blocked);
    const auto since = rig.journal->headroom_blocked_since_for_test();
    REQUIRE(since >= 0);

    // Pass 2: a clean 128-candidate slice (cursor sits after blk), coverage 128 of 261.
    const auto s2 = rig.journal->page_into_window(*rig.rt, base_ts + 110'000);
    CHECK_FALSE(s2.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == since);

    // Prune-eviction stand-in: delete the 128 candidates pass 2 just classified. A
    // count-based rule now holds 128 counted classifications against a 133-candidate
    // set - pass 3's clean slice would push it to 256 >= 133 and clear spuriously.
    for (int i = 0; i < 128; ++i)
        REQUIRE(rig.kv->del(kJournalNamespace, clean_keys[static_cast<std::size_t>(i)]));

    // Pass 3: another clean slice (128 of the 132 remaining cleans; blk still not
    // reached). The still-blocked batch has NOT been observed block-free, so the
    // episode MUST survive - this is the assertion the count rule fails.
    const auto s3 = rig.journal->page_into_window(*rig.rt, base_ts + 170'000);
    CHECK_FALSE(s3.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == since);

    // Pass 4: the rotation finishes the cleans and wraps back to blk - still blocked,
    // and set-if-unset holds the ORIGINAL stamp (the episode was continuous).
    const auto s4 = rig.journal->page_into_window(*rig.rt, base_ts + 230'000);
    CHECK(s4.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == since);
}

TEST_CASE("#2364 episode: a stop-truncated pass with FULL coverage still does not clear",
          "[spark][runtime][journal]") {
    // Drives the in-loop stopping_ break (the only writer of stop_truncated) via the
    // test-only per-candidate hook - no external sequence can land a stop between
    // candidates deterministically. DISCRIMINATING setup (governance Gate 3 QE): the
    // truncated pass completes the coverage of EVERY candidate before the stop lands,
    // so if the stop_truncated guard were deleted the footer's covered-check would
    // evaluate TRUE and clear - this test flips on exactly that mutation, unlike a
    // partial-coverage truncation where the missing keys also block the clear.
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // floor 256
    PageRig rig;
    rig.rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);

    auto write_batch = [&](const std::string& nonce, std::uint64_t seq, std::int64_t ts_ms,
                           const std::string& eid) {
        const std::string key = journal_batch_key(ts_ms, nonce, seq);
        REQUIRE(rig.kv->set(
            kJournalNamespace, key,
            R"({"v":4,"ts_ms":)" + std::to_string(ts_ms) +
                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":")" + eid +
                R"(","enqueued_ns":1700000000000000000,"kind":"armed","guard_type":"file","rule_name":"n"}]})"));
        return key;
    };
    // Same 131-candidate scaffold as the clean-slice test: blk oldest, 130 batches
    // whose records are pre-windowed (need==0 -> clean, token-free classifications).
    const std::int64_t base_ts = 1'700'000'000'000;
    const std::string blocked_key = write_batch("aaa", 0, base_ts - 1'000, "e-blk");
    std::vector<OutboxEntry> windowed;
    for (int i = 0; i < 130; ++i) {
        const auto id = std::to_string(i);
        write_batch("bbb", static_cast<std::uint64_t>(i), base_ts + i, "e-r" + id);
        windowed.push_back(lc_entry("r" + id, "e-r" + id));
    }
    const std::size_t cap = rig.rt->lifecycle_headroom();
    for (std::size_t i = 130; i < cap; ++i)
        windowed.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(windowed)).added == cap);

    // Pass 1: blocked at blk -> episode starts. Then label blk as delivered so every
    // candidate classifies cleanly from here on.
    REQUIRE(rig.journal->page_into_window(*rig.rt, base_ts + 50'000).headroom_blocked);
    const auto since = rig.journal->headroom_blocked_since_for_test();
    REQUIRE(since >= 0);
    REQUIRE(rig.kv->set(kJournalNamespace, journal_sent_key_from_batch_key(blocked_key), ""));

    // Pass 2: ordinary clean 128-slice (covers bbb0..bbb127). Survives - partial.
    (void)rig.journal->page_into_window(*rig.rt, base_ts + 110'000);
    REQUIRE(rig.journal->headroom_blocked_since_for_test() == since);

    // Pass 3: the rotation continues at bbb128, bbb129, then blk - after those THREE
    // classifications coverage of all 131 candidates is complete. Stop on the 4th
    // examined candidate: the pass is truncated AFTER coverage completed, so ONLY the
    // stop_truncated guard stands between this pass and a (wrong) clear.
    int classify_calls = 0;
    rig.journal->set_post_classify_hook_for_test([&] {
        if (++classify_calls == 4)
            rig.journal->request_stop();
    });
    const auto s3 = rig.journal->page_into_window(*rig.rt, base_ts + 170'000);
    CHECK_FALSE(s3.headroom_blocked);
    CHECK(classify_calls == 4); // truncated mid-loop, after the coverage-completing 3rd
    CHECK(rig.journal->headroom_blocked_since_for_test() == since); // NOT cleared
    // #2452 Gate 7: a stop-truncated pass placed nothing and did not verify a clean idle backlog,
    // so it is not "verified idle". This pins the `stop_truncated` tail term - the one governance
    // Gate 8 found unpinned: with records_paged==0 and every other term false, deleting
    // `!stop_truncated` from the tail conjunction would flip this to true.
    CHECK(s3.records_paged == 0);
    CHECK_FALSE(s3.progress_or_verified_idle);
}

TEST_CASE("#2364 episode: restart after clear - a fresh episode stamps and clears cleanly",
          "[spark][runtime][journal]") {
    // Guards the epoch-reset path (governance Gate 3 QE): after block -> clear, a
    // SECOND blocking episode must get its own fresh stamp and must itself be
    // clearable - i.e. the clear really reset the coverage set, and no stale coverage
    // from epoch 1 lets epoch 2 clear early (or blocks it from clearing at all).
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1;
    PageRig rig;
    rig.rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);

    const std::size_t cap = rig.rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i + 3 < cap; ++i)
        fill.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == cap - 3);

    // Episode 1: a 4-record batch blocks against headroom 3.
    std::vector<std::shared_ptr<const JournalRecord>> big;
    for (int i = 0; i < 4; ++i)
        big.push_back(std::make_shared<const JournalRecord>(
            JournalRecord{.rule_id = "big", .generation = 1, .event_id = "e-big-" + std::to_string(i),
                          .enqueued_ns = 1'700'000'000'000'000'000, .kind = "armed",
                          .guard_type = "file", .rule_name = "n"}));
    REQUIRE(rig.journal->persist(big, nullptr, kJournalPersistUnbounded, kJournalPersistUnbounded) == 4);
    const std::int64_t t0 = 1'700'000'000'000;
    REQUIRE(rig.journal->page_into_window(*rig.rt, t0).headroom_blocked);
    REQUIRE(rig.journal->headroom_blocked_since_for_test() >= 0);

    // Clear episode 1: drain frees the window; the next pass places big (full clean
    // coverage of the single candidate).
    drain_lifecycle(*rig.rt);
    (void)rig.journal->page_into_window(*rig.rt, t0 + 60'000);
    REQUIRE(rig.journal->headroom_blocked_since_for_test() == -1);

    // Episode 2: a fresh 2-record batch against a re-filled window (headroom 1).
    const std::size_t headroom_now = rig.rt->lifecycle_headroom();
    std::vector<OutboxEntry> refill;
    for (std::size_t i = 0; i + 1 < headroom_now; ++i)
        refill.push_back(lc_entry("fill2", "g" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(refill)).added == headroom_now - 1);
    std::vector<std::shared_ptr<const JournalRecord>> big2;
    for (int i = 0; i < 2; ++i)
        big2.push_back(std::make_shared<const JournalRecord>(
            JournalRecord{.rule_id = "big2", .generation = 1, .event_id = "e-b2-" + std::to_string(i),
                          .enqueued_ns = 1'700'000'000'000'000'000, .kind = "armed",
                          .guard_type = "file", .rule_name = "n"}));
    REQUIRE(rig.journal->persist(big2, nullptr, kJournalPersistUnbounded, kJournalPersistUnbounded) == 2);
    const auto s3 = rig.journal->page_into_window(*rig.rt, t0 + 120'000);
    CHECK(s3.headroom_blocked);
    const auto since2 = rig.journal->headroom_blocked_since_for_test();
    CHECK(since2 >= 0); // fresh episode stamped after a genuine -1

    // And episode 2 clears on recovery exactly like episode 1 did.
    drain_lifecycle(*rig.rt);
    (void)rig.journal->page_into_window(*rig.rt, t0 + 180'000);
    CHECK(rig.journal->headroom_blocked_since_for_test() == -1);
}

TEST_CASE("#2364 episode: early returns leave the state untouched",
          "[spark][runtime][journal]") {
    // Every return before the end-of-pass update - stop, no token, scan failure - must
    // neither start nor clear an episode: an examination that never ran refutes nothing.
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1;
    PageRig rig;
    rig.rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);

    const std::size_t cap = rig.rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i < cap; ++i)
        fill.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == cap);
    rig.persist("blk"); // 1 net-new record, headroom 0 -> blocks when a pass runs

    const std::int64_t t0 = 1'700'000'000'000;
    // A failed journal scan returns before the update: no episode may start.
    rig.journal->inject_page_read_failures_for_test(1);
    (void)rig.journal->page_into_window(*rig.rt, t0);
    CHECK(rig.journal->headroom_blocked_since_for_test() == -1);

    // A real pass starts it.
    (void)rig.journal->page_into_window(*rig.rt, t0 + 30'000);
    const auto since = rig.journal->headroom_blocked_since_for_test();
    REQUIRE(since >= 0);

    // After request_stop() the pass returns at the entry gate: state untouched.
    rig.journal->request_stop();
    (void)rig.journal->page_into_window(*rig.rt, t0 + 60'000);
    CHECK(rig.journal->headroom_blocked_since_for_test() == since);
}

TEST_CASE("page_into_window prunes an expired batch before replaying (boot barrier)",
          "[spark][runtime][journal]") {
    PageRig rig;
    // Both batches written directly with CONTROLLED ts_ms (persist would stamp real-now).
    auto write_batch = [&](const std::string& nonce, std::uint64_t seq, std::int64_t ts_ms,
                           const std::string& eid) {
        const std::string key = journal_batch_key(ts_ms, nonce, seq);
        REQUIRE(rig.kv->set(
            kJournalNamespace, key,
            R"({"v":4,"ts_ms":)" + std::to_string(ts_ms) +
                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":")" + eid +
                R"(","enqueued_ns":1700000000000000000,"kind":"armed","guard_type":"file","rule_name":"n"}]})"));
        return key;
    };
    write_batch("old", 0, 1000, "e-old");             // ancient → older than 7 days
    write_batch("new", 0, 1'700'000'000'000, "e-new"); // recent

    // The barrier prunes before paging: the ts_ms=1000 batch ages out and is never replayed.
    auto stats = rig.journal->page_into_window(*rig.rt, 1'700'000'050'000LL);
    CHECK(stats.records_paged == 1);
    CHECK(rig.journal->batches_pruned() == 1); // the expired batch pruned by the barrier
    auto lc = drain_lifecycle(*rig.rt);
    REQUIRE(lc.size() == 1);
    CHECK(lc[0].event_id == "e-new");
}

TEST_CASE("page_into_window pages NOTHING when the boot prune's scan fails (#2303 C4)",
          "[spark][runtime][journal]") {
    PageRig rig;
    auto write_batch = [&](const std::string& nonce, std::uint64_t seq, std::int64_t ts_ms,
                           const std::string& eid) {
        const std::string key = journal_batch_key(ts_ms, nonce, seq);
        REQUIRE(rig.kv->set(
            kJournalNamespace, key,
            R"({"v":4,"ts_ms":)" + std::to_string(ts_ms) +
                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":")" + eid +
                R"(","enqueued_ns":1700000000000000000,"kind":"armed","guard_type":"file","rule_name":"n"}]})"));
        return key;
    };
    // Both recent (neither ages out), so ONLY the count cap can evict - and only a prune whose
    // scan succeeds can apply it.
    write_batch("aaa", 0, 1'700'000'000'000, "e-older");
    write_batch("bbb", 0, 1'700'000'001'000, "e-newer");
    rig.journal->set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/1,
                                               /*max_bytes=*/std::size_t(-1), 100);

    // The boot barrier's scan fails. Latching only on read_ok (M5) already kept the barrier
    // un-latched, but the pass used to FALL THROUGH and replay anyway - handing the runtime
    // exactly the over-cap candidates a good prune would have evicted, on the one pass the
    // barrier exists to protect.
    rig.journal->inject_read_failures_for_test(1);
    const auto blocked = rig.journal->page_into_window(*rig.rt, 1'700'000'050'000LL);
    CHECK(blocked.records_paged == 0);
    CHECK(blocked.batches_paged == 0);
    CHECK(drain_lifecycle(*rig.rt).empty());
    CHECK(rig.journal->prune_failures() == 1); // counted, not silent

    // Self-correcting: the failure latched nothing. The next pass prunes cleanly, applies the
    // count cap, and replays only the survivor.
    const auto ok = rig.journal->page_into_window(*rig.rt, 1'700'000'110'000LL);
    CHECK(rig.journal->batches_pruned() == 1);
    CHECK(ok.records_paged == 1);
    auto lc2 = drain_lifecycle(*rig.rt);
    REQUIRE(lc2.size() == 1);
    CHECK(lc2[0].event_id == "e-newer"); // the oldest was evicted by the cap, never replayed
}

TEST_CASE("page_into_window stops enqueuing once request_stop is signalled (stop-race gate)",
          "[spark][runtime][journal]") {
    PageRig rig;
    for (int i = 0; i < 4; ++i)
        rig.persist("r" + std::to_string(i));
    rig.journal->request_stop();
    // A page pass after stop began must not mutate the window.
    CHECK(rig.journal->page_into_window(*rig.rt, 1'700'000'100'000).records_paged == 0);
    CHECK(drain_lifecycle(*rig.rt).empty());
}

TEST_CASE("a paged batch's last entry, when sent, gets a sent-label (send-wrap logic)",
          "[spark][runtime][journal]") {
    PageRig rig;
    rig.persist("r1");
    REQUIRE(rig.journal->page_into_window(*rig.rt, 1'700'000'100'000).records_paged == 1);

    // Drain with the same wrap wire_spark_engine installs: on a Sent last-in-batch paged
    // entry, write the sent-label.
    rig.rt->drain([&](const OutboxEntry& e) {
        if (e.domain == OutboxDomain::Lifecycle && e.journal_last_in_batch &&
            !e.journal_batch_key.empty())
            rig.journal->mark_batch_sent(e.journal_batch_key);
        return SendResult::Sent;
    });
    CHECK(rig.journal->sent_labels_written() == 1);
    auto sent = rig.kv->list_entries(kJournalNamespace, kSentKeyPrefix);
    REQUIRE(sent.has_value());
    CHECK(sent->size() == 1);
}

TEST_CASE("concurrent pagers + a drainer do not race (TSan checkpoint)",
          "[spark][runtime][journal][tsan][tsan-heavy]") {
    PageRig rig;
    for (int i = 0; i < 20; ++i)
        rig.persist("r" + std::to_string(i));

    std::atomic<bool> stop{false};
    std::vector<std::thread> pagers;
    for (int p = 0; p < 3; ++p)
        pagers.emplace_back([&, p] {
            std::int64_t t = 1'700'000'000'000 + p * 1000;
            while (!stop.load(std::memory_order_relaxed)) {
                rig.journal->page_into_window(*rig.rt, t);
                t += 10'000; // advance the clock so the bucket keeps refilling
            }
        });
    std::thread drainer([&] {
        while (!stop.load(std::memory_order_relaxed))
            rig.rt->drain([](const OutboxEntry&) { return SendResult::Sent; });
    });
    // A RETENTION thread, not only pagers (#2345 Gate 8 cpp-safety). prune_locked_ and
    // page_into_window hand three non-atomic members between them - last_prune_now_ms_,
    // last_age_cutoff_, pruned_cutoff_valid_ - and with pagers alone that handoff is never
    // exercised concurrently, so a TSan pass over this test said nothing about it. The clock
    // walks forward fast enough here to drive the age-cutoff logic, not just the lock.
    std::thread pruner([&] {
        std::int64_t t = 1'700'000'000'000;
        while (!stop.load(std::memory_order_relaxed)) {
            rig.journal->prune(t);
            t += 60'000;
        }
    });

    // Interleave from the main thread too, then signal stop (also exercises the stop-race gate).
    for (int i = 0; i < 200; ++i)
        rig.journal->page_into_window(*rig.rt, 1'700'000'500'000 + i * 1000);

    rig.journal->request_stop();
    stop.store(true, std::memory_order_relaxed);
    for (auto& t : pagers)
        t.join();
    drainer.join();
    pruner.join();
    SUCCEED("no data race / crash across concurrent pagers + retention + drain");
}

TEST_CASE("page_into_window quarantines a corrupt batch instead of replaying it (M6)",
          "[spark][runtime][journal]") {
    PageRig rig;
    auto write = [&](const std::string& nonce, std::int64_t ts, const std::string& eid,
                     std::int64_t ns, const std::string& kind) {
        REQUIRE(rig.kv->set(kJournalNamespace, journal_batch_key(ts, nonce, 0),
                            R"({"v":4,"ts_ms":)" + std::to_string(ts) +
                                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":")" + eid +
                                R"(","enqueued_ns":)" + std::to_string(ns) + R"(,"kind":")" + kind +
                                R"(","guard_type":"file","rule_name":"n"}]})"));
    };
    // enqueued_ns=0 floors to epoch second 0, so the server would stamp receipt-now -> a false
    // Conflict every replay. A kind outside {armed,disarmed} is likewise corrupt/tampered.
    // The KEYS here are well-formed: this is VALUE corruption, which since #2299 is discovered
    // by the replay pass when it reads a candidate it is about to place, not by prune.
    write("bad", 1'700'000'000'000, "e-bad", 0, "armed");
    write("badkind", 1'700'000'000'000, "e-bk", 1'700'000'000'000'000'000, "banana");
    write("good", 1'700'000'000'000, "e-good", 1'700'000'000'000'000'000, "armed");

    auto stats = rig.journal->page_into_window(*rig.rt, 1'700'000'050'000);
    CHECK(stats.records_paged == 1);        // only the good batch replayed
    CHECK(rig.journal->quarantined() >= 2); // both corrupt batches moved aside
    CHECK(rig.kv->list_entries(kJournalNamespace, kQuarantineKeyPrefix)->size() >= 2);

    auto sent = drain_lifecycle(*rig.rt);
    REQUIRE(sent.size() == 1);
    CHECK(sent[0].event_id == "e-good"); // the poison batches never reach the wire
}

TEST_CASE("page_into_window reads NO candidate values when every candidate is skipped (#2299)",
          "[spark][runtime][journal]") {
    // THE O(work) assertion. Selection - expiry, ordering, the sent-label skip, rotation - is
    // now a function of the KEY, so a pass that places nothing must read nothing. Before
    // #2299 perf-P-1 the same pass materialized and parsed every row in the namespace before
    // the 128-candidate cap was applied at all (~670 ms and +162 MiB at the byte ceiling).
    PageRig rig;
    const std::int64_t base_ts = 1'700'000'000'000;
    for (int i = 0; i < 40; ++i) {
        const std::string key =
            journal_batch_key(base_ts + i, "aaa", static_cast<std::uint64_t>(i));
        REQUIRE(rig.kv->set(
            kJournalNamespace, key,
            R"({"v":4,"ts_ms":)" + std::to_string(base_ts + i) +
                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":"e)" + std::to_string(i) +
                R"(","enqueued_ns":1700000000000000000,"kind":"armed","guard_type":"file","rule_name":"n"}]})"));
        // Durable sent-label: an ordinary pass skips a delivered batch.
        REQUIRE(rig.kv->set(kJournalNamespace, journal_sent_key_from_batch_key(key), ""));
    }

    const auto stats = rig.journal->page_into_window(*rig.rt, base_ts + 50'000);
    CHECK(stats.skipped_already_sent == 40);
    CHECK(stats.records_paged == 0);
    CHECK(rig.journal->candidate_value_fetches_for_test() == 0); // not one value read

    // A FORCED pass re-offers the labelled batches, so now the values ARE read - at most one
    // read per candidate considered, and only for candidates considered.
    //
    // Stated honestly, because the bound looks stronger than it is: with the loop as written
    // no candidate is visited twice in a pass anyway (the headroom==0 inner scan is followed
    // by `break`), so this assertion does NOT discriminate the memoization in ensure_batch -
    // that memo is defence-in-depth for a future loop shape that does revisit, not something
    // this test can catch regressing. The `== 0` assertion above is the real pin, and it is
    // the one that fails the moment selection stops being key-only.
    const auto before = rig.journal->candidate_value_fetches_for_test();
    const auto forced = rig.journal->page_into_window(*rig.rt, base_ts + 60'000, true);
    const auto fetched = rig.journal->candidate_value_fetches_for_test() - before;
    CHECK(forced.records_paged >= 1);
    CHECK(forced.batches_paged >= 1); // it really did read and place, not skip cheaply
    CHECK(fetched >= 1);
    CHECK(fetched <= 40); // never more than one read per candidate
}

TEST_CASE("#2364 episode: a failed candidate VALUE read never counts as block-free coverage",
          "[spark][runtime][journal]") {
    // A candidate whose value cannot be READ has an UNKNOWN headroom disposition. Recording it
    // as clean would let a chronically unreadable row complete the coverage set and clear a
    // live episode while the batch that is actually blocking went unread - the same shape as
    // the three clear rules already rejected in review (clear-on-place, clear-on-clean-PASS,
    // count-vs-set-size), reached through the point read #2299 introduced.
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // floor 256
    PageRig rig;
    rig.rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);

    auto write_batch = [&](const std::string& nonce, std::uint64_t seq, std::int64_t ts_ms,
                           const std::string& eid) {
        const std::string key = journal_batch_key(ts_ms, nonce, seq);
        REQUIRE(rig.kv->set(
            kJournalNamespace, key,
            R"({"v":4,"ts_ms":)" + std::to_string(ts_ms) +
                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":")" + eid +
                R"(","enqueued_ns":1700000000000000000,"kind":"armed","guard_type":"file","rule_name":"n"}]})"));
        return key;
    };
    const std::int64_t base_ts = 1'700'000'000'000;
    const std::string blocked_key = write_batch("aaa", 0, base_ts - 1'000, "e-blk");
    const std::string other_key = write_batch("bbb", 0, base_ts, "e-oth");

    // Fill the window so the oldest candidate cannot place.
    const std::size_t cap = rig.rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i < cap; ++i)
        fill.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == cap);

    // Pass 1: blocked -> the episode starts.
    REQUIRE(rig.journal->page_into_window(*rig.rt, base_ts + 50'000).headroom_blocked);
    const auto since = rig.journal->headroom_blocked_since_for_test();
    REQUIRE(since >= 0);

    // Label the blocking batch delivered, so from here it is skipped and classified clean.
    // The OTHER candidate is the only one left to prove block-free - and its value read fails.
    REQUIRE(rig.kv->set(kJournalNamespace, journal_sent_key_from_batch_key(blocked_key), ""));
    REQUIRE(rig.kv->set(kJournalNamespace, journal_sent_key_from_batch_key(other_key), ""));
    // Drain the window so nothing is blocked any more: only the unknown disposition remains.
    (void)drain_lifecycle(*rig.rt);

    // Exactly the two candidates this pass considers, so the NEXT pass reads cleanly.
    rig.journal->inject_value_read_failures_for_test(2);
    const auto s2 = rig.journal->page_into_window(*rig.rt, base_ts + 110'000, /*replay_sent=*/true);
    CHECK_FALSE(s2.headroom_blocked);
    // The episode MUST survive: coverage was never proven for the unreadable candidate.
    CHECK(rig.journal->headroom_blocked_since_for_test() == since);
    CHECK(rig.journal->page_read_failures() >= 1); // counted, not silent

    // With the reads working again, the same candidates classify cleanly and the episode ends.
    const auto s3 = rig.journal->page_into_window(*rig.rt, base_ts + 170'000, /*replay_sent=*/true);
    CHECK_FALSE(s3.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == -1);
}

TEST_CASE("persist back-fills provenance onto the live window entry (M3)",
          "[spark][runtime][journal]") {
    PageRig rig;
    // A live entry enters BOTH the send window and staging; persist it, then back-fill.
    REQUIRE(rig.rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
    auto pending = rig.rt->snapshot_pending().records;
    REQUIRE(pending.size() == 1);

    std::vector<PersistedBatch> batches;
    CHECK(rig.journal->persist(pending, &batches, kJournalPersistUnbounded, kJournalPersistUnbounded) == 1);
    REQUIRE(batches.size() == 1);
    for (const auto& b : batches)
        rig.rt->backfill_batch_provenance(b.key, b.event_ids, b.event_ids.back());

    // The live entry now carries the batch key + last-in-batch, so its LIVE send writes a
    // sent-label (before this fix a live-sent entry had no key and later false-alerted).
    rig.rt->drain([&](const OutboxEntry& e) {
        if (e.domain == OutboxDomain::Lifecycle && e.journal_last_in_batch &&
            !e.journal_batch_key.empty())
            rig.journal->mark_batch_sent(e.journal_batch_key);
        return SendResult::Sent;
    });
    CHECK(rig.journal->sent_labels_written() == 1);
    auto sent_m3 = rig.kv->list_entries(kJournalNamespace, kSentKeyPrefix);
    REQUIRE(sent_m3.has_value());
    CHECK(sent_m3->size() == 1);
}

TEST_CASE("a hostile rule_name is rejected from the journal but never crashes the arm (QE-2)",
          "[spark][runtime][journal]") {
    auto rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>());

    // Feed embedded-NUL / invalid-UTF-8 / oversized rule_names through the REAL wired staging
    // path (attach_rule -> enqueue_lifecycle_locked -> build_journal_record -> validate_record),
    // not validate_record in isolation. This is the governance blind-spot #1593 lesson: a
    // "rejected, not thrown" claim for the wired path needs a reproduction. Each must be kept out
    // of the durable journal (journal_field_rejected++) while the arm itself still succeeds.
    const auto arm_with_name = [&](const std::string& rid, const std::string& name) {
        auto rule = file_exists_rule(rid);
        rule.rule_name = name;
        return rt->attach_rule(rid, file_spec("/" + rid), rule, true);
    };

    std::string nul = "bad";
    nul.push_back('\0');
    nul += "name";
    REQUIRE(arm_with_name("r1", nul).has_value());                           // embedded NUL
    REQUIRE(arm_with_name("r2", std::string("bad\xff\xfetail")).has_value()); // invalid UTF-8
    REQUIRE(arm_with_name("r3", std::string(5000, 'x')).has_value());        // > kMaxJournalFieldBytes

    CHECK(rt->journal_field_rejected() == 3); // all three kept OUT of the durable journal
    CHECK(rt->journal_clock_rejected() == 0);
    CHECK(rt->pending_journal_depth() == 0);  // nothing staged (the live audit entry still sent)
}

TEST_CASE("concurrent persist + page + prune + drain do not race (TSan checkpoint, QE-1)",
          "[spark][runtime][journal][tsan][tsan-heavy]") {
    PageRig rig;
    // A small retention cap keeps the pruner trimming the journal so page-passes stay O(small):
    // TSan finds a race from the INTERLEAVING, not from volume, so a short bounded run suffices.
    rig.journal->set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/16,
                                               /*max_bytes=*/static_cast<std::size_t>(-1),
                                               /*max_quarantine=*/100);
    for (int i = 0; i < 16; ++i)
        rig.persist("seed" + std::to_string(i));

    std::atomic<bool> stop{false};
    std::vector<std::thread> workers;
    // Pagers: page_into_window (paging_mutex_ -> KvStore.mu_).
    for (int p = 0; p < 2; ++p)
        workers.emplace_back([&, p] {
            std::int64_t t = 1'700'000'000'000 + p * 1000;
            while (!stop.load(std::memory_order_relaxed)) {
                rig.journal->page_into_window(*rig.rt, t);
                t += 10'000;
            }
        });
    // Pruner: prune() (paging_mutex_ -> KvStore.mu_) - the FR5 prune-vs-paging serialization this
    // test exists to exercise under TSan (previously only single-threaded).
    workers.emplace_back([&] {
        std::int64_t t = 1'700'000'000'000;
        while (!stop.load(std::memory_order_relaxed)) {
            rig.journal->prune(t);
            t += 5'000;
        }
    });
    // Persister: persist() (KvStore.mu_, no paging_mutex_) - a single writer, as in production
    // (always under the engine mtx_); it races page/prune only on the shared KvStore + atomics.
    // Bounded to keep the run short; the pruner recycles the batch budget as it writes.
    workers.emplace_back([&] {
        for (int n = 0; n < 40 && !stop.load(std::memory_order_relaxed); ++n) {
            std::vector<std::shared_ptr<const JournalRecord>> pending{
                std::make_shared<const JournalRecord>(JournalRecord{
                    .rule_id = "w" + std::to_string(n), .generation = 1,
                    .event_id = "we-" + std::to_string(n), .enqueued_ns = 1'700'000'000'000'000'000,
                    .kind = "armed", .guard_type = "file", .rule_name = "n"})};
            (void)rig.journal->persist(pending, nullptr, kJournalPersistUnbounded, kJournalPersistUnbounded);
        }
    });
    // Drainer.
    workers.emplace_back([&] {
        while (!stop.load(std::memory_order_relaxed))
            rig.rt->drain([](const OutboxEntry&) { return SendResult::Sent; });
    });

    for (int i = 0; i < 60; ++i)
        rig.journal->page_into_window(*rig.rt, 1'700'000'500'000 + i * 1000);

    stop.store(true, std::memory_order_relaxed);
    for (auto& w : workers)
        w.join();

    // request_stop() comes AFTER the settle prune below, not before it. Calling it first made
    // that prune return at its shutdown gate without doing anything, so the rebase the
    // assertions depend on never happened and they were checking gauges that had merely
    // survived the concurrent run - passing or flaking on the documented transient
    // double-count interleaving rather than on the property this test is named for
    // (#2345 round 7, Sol). The workers are already joined, so nothing races this.
    //
    // Beyond race-freedom (TSan): the running-counter gauges (#2303) must stay ACCOUNTING-correct
    // under the real concurrent persist/prune interleaving, not just data-race-free. A final
    // settle prune rebases to on-disk truth; the
    // gauges must then exactly equal what namespace_size sees on disk - proving no lost update
    // and no drift accumulated across the concurrent run.
    rig.journal->prune(1'700'000'900'000);
    rig.journal->request_stop();
    auto sz = rig.kv->namespace_size(kJournalNamespace, kBatchKeyPrefix);
    REQUIRE(sz.has_value());
    CHECK(rig.journal->journal_batch_count() == sz->count);
    CHECK(rig.journal->journal_bytes() == sz->bytes);
    CHECK(rig.journal->gauge_underflow() == 0); // never fell into the fail-open underflow window
}

TEST_CASE("erase_persisted_prefix identifies the prefix it wrote, not an index",
          "[spark][runtime][journal][chaos]") {
    // snapshot_pending() releases outbox_mu_, persist() does its KvStore I/O unlocked, and the
    // erase re-takes the lock. If staging overflows in that window it drops from the FRONT, so
    // position 0 is no longer the record it was - and erasing by index deletes records that
    // were never written. Silent, uncounted destruction of audit evidence, worst exactly when
    // staging is full, i.e. when persist is already failing. RED before the fix: r4 and r5,
    // which were never persisted, are erased and lost.
    auto rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>());
    for (int i = 0; i < 6; ++i)
        REQUIRE(rt->attach_rule("r" + std::to_string(i), file_spec("/p" + std::to_string(i)),
                                file_exists_rule("r" + std::to_string(i)), true));
    REQUIRE(rt->pending_journal_depth() == 6);

    const auto snap = rt->snapshot_pending();
    const auto drops = snap.drops_at_snapshot;
    REQUIRE(snap.records.size() == 6);

    // ...persist commits the first 4. Meanwhile two overflow drops take r0 and r1 off the front.
    rt->drop_oldest_pending_for_test(2);
    REQUIRE(rt->pending_journal_depth() == 4); // r2..r5

    rt->erase_persisted_prefix(4, drops);
    // r0 and r1 are already gone and r2, r3 were the rest of the persisted prefix, so exactly
    // r4 and r5 - never written - must SURVIVE to be retried.
    REQUIRE(rt->pending_journal_depth() == 2);
    const auto left = rt->snapshot_pending().records;
    CHECK(left[0]->rule_id == "r4");
    CHECK(left[1]->rule_id == "r5");
}

TEST_CASE("erase_persisted_prefix erases nothing when drops already exceeded the prefix",
          "[spark][runtime][journal][chaos]") {
    // The far end of the same seam, and the dangerous one. If MORE records were dropped from
    // the front than persist durably wrote, the whole persisted prefix is already gone and
    // there is nothing left to erase. Without the early return, `n -= dropped_since` wraps a
    // size_t to an enormous value, std::min clamps it to the buffer size, and the erase takes
    // the ENTIRE remaining staging buffer - every record staged but never written. That is
    // silent audit-record destruction, and it is worst exactly when it is most likely: staging
    // only overflows when persist is already failing.
    // RED before the fix: pending_journal_depth() == 0 - everything still waiting is destroyed.
    auto rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>());
    for (int i = 0; i < 6; ++i)
        REQUIRE(rt->attach_rule("r" + std::to_string(i), file_spec("/p" + std::to_string(i)),
                                file_exists_rule("r" + std::to_string(i)), true));

    const auto snap = rt->snapshot_pending();
    const auto drops = snap.drops_at_snapshot;
    REQUIRE(snap.records.size() == 6);

    // persist committed 3 (r0..r2). Meanwhile FIVE overflow drops took r0..r4 off the front -
    // strictly more than the prefix that was written.
    rt->drop_oldest_pending_for_test(5);
    REQUIRE(rt->pending_journal_depth() == 1); // only r5 is left, and it was never persisted

    rt->erase_persisted_prefix(3, drops);
    REQUIRE(rt->pending_journal_depth() == 1); // untouched: nothing of the prefix remained
    const auto left = rt->snapshot_pending().records;
    REQUIRE(left.size() == 1);
    CHECK(left[0]->rule_id == "r5"); // the never-persisted record survives to be retried
}

TEST_CASE("#2298: the smallest-blocked scan stops issuing KvStore reads once stop is requested",
          "[spark][runtime][journal]") {
    // The min-blocked-headroom inner scan used to be pure in-memory arithmetic over
    // already-parsed batches. Once the value read became lazy it issues a KvStore point read
    // per remaining candidate - and can issue a quarantine rename - so at the 128-candidate
    // cap it is up to ~127 round trips, each able to block on the 5 s busy timeout, on the
    // very thread GuardianEngine::stop() joins while holding mtx_. That is the bounded-
    // shutdown invariant every other KvStore loop in this file already respects.
    //
    // RED without the gate: the scan reads every remaining candidate after the stop.
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // floor 256
    PageRig rig;
    rig.rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);

    const std::int64_t base_ts = 1'700'000'000'000;
    for (int i = 0; i < 10; ++i) {
        const std::string key =
            journal_batch_key(base_ts + i, "aaa", static_cast<std::uint64_t>(i));
        REQUIRE(rig.kv->set(
            kJournalNamespace, key,
            R"({"v":4,"ts_ms":)" + std::to_string(base_ts + i) +
                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":"e)" + std::to_string(i) +
                R"(","enqueued_ns":1700000000000000000,"kind":"armed","guard_type":"file","rule_name":"n"}]})"));
    }
    // Fill the window completely so the FIRST candidate blocks at headroom 0 and the inner
    // smallest-blocked scan is entered.
    const std::size_t cap = rig.rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i < cap; ++i)
        fill.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == cap);

    // Land the stop while the pass is between candidates: the outer loop has already passed
    // its own gate for candidate 0, so candidate 0 is processed and the inner scan IS
    // entered - which is exactly the window this gate has to cover.
    rig.journal->set_post_classify_hook_for_test([&] { rig.journal->request_stop(); });

    const auto before = rig.journal->candidate_value_fetches_for_test();
    const auto stats = rig.journal->page_into_window(*rig.rt, base_ts + 50'000);
    const auto fetched = rig.journal->candidate_value_fetches_for_test() - before;

    CHECK(stats.headroom_blocked);   // it did reach the blocked branch...
    CHECK(fetched == 1);             // ...and read ONLY the candidate it was already holding
    // The reported requirement stays conservative (seeded from the blocked candidate's own
    // need), so an early break costs a later re-arm, never a wrong-sized one.
    CHECK(stats.min_blocked_headroom >= 1);
}

TEST_CASE("#2364 episode: a STALE clean-key cannot complete coverage on a failed-read pass",
          "[spark][runtime][journal]") {
    // The DISCRIMINATING form of the read-failure guard (governance Gate 3 QE showed the
    // first attempt was not one). The per-candidate rule - a failed-read candidate is never
    // note_clean'd - is not enough on its own, because the coverage set is CROSS-PASS: a key
    // banked by an earlier pass is still in it. So the shape that matters is a pass where
    // every CURRENT candidate is already covered from before, and the only thing this pass
    // learned is that it could not read one of them. Without the footer's pass-level
    // `!value_read_failed` term that pass clears a live episode on stale evidence.
    //
    // Verified by mutation: deleting `!value_read_failed` from the footer turns this red.
    GuardianSparkRuntime::Config cfg;
    cfg.outbox_capacity = 1; // floor 256
    PageRig rig;
    rig.rt = make_rt(std::make_shared<FakeReader>(), std::make_shared<FakeBackend>(), cfg);

    auto write_batch = [&](const std::string& nonce, std::uint64_t seq, std::int64_t ts_ms,
                           const std::string& eid) {
        const std::string key = journal_batch_key(ts_ms, nonce, seq);
        REQUIRE(rig.kv->set(
            kJournalNamespace, key,
            R"({"v":4,"ts_ms":)" + std::to_string(ts_ms) +
                R"(,"entries":[{"rule_id":"r","generation":1,"event_id":")" + eid +
                R"(","enqueued_ns":1700000000000000000,"kind":"armed","guard_type":"file","rule_name":"n"}]})"));
        return key;
    };
    const std::int64_t base_ts = 1'700'000'000'000;
    const std::string kept = write_batch("aaa", 0, base_ts - 1'000, "e-kept");
    const std::string doomed = write_batch("bbb", 0, base_ts, "e-doomed");

    // Start an episode: fill the window so the oldest candidate cannot place.
    const std::size_t cap = rig.rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i < cap; ++i)
        fill.push_back(lc_entry("fill", "f" + std::to_string(i)));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == cap);
    REQUIRE(rig.journal->page_into_window(*rig.rt, base_ts + 50'000).headroom_blocked);
    const auto since = rig.journal->headroom_blocked_since_for_test();
    REQUIRE(since >= 0);
    (void)drain_lifecycle(*rig.rt); // room again, so nothing blocks from here

    // PASS A - bank a clean key for `kept` while leaving `doomed` uncovered, so the episode
    // survives with a non-empty coverage set. `kept` is sent-labelled, so it is skipped (and
    // banked) without any value read; `doomed` is not, so it IS read - and that read fails.
    REQUIRE(rig.kv->set(kJournalNamespace, journal_sent_key_from_batch_key(kept), ""));
    rig.journal->inject_value_read_failures_for_test(1);
    const auto a = rig.journal->page_into_window(*rig.rt, base_ts + 110'000);
    CHECK_FALSE(a.headroom_blocked);
    CHECK(a.skipped_already_sent == 1);
    REQUIRE(rig.journal->headroom_blocked_since_for_test() == since); // still live

    // Retention removes `doomed`. The coverage set now holds a key for every remaining
    // candidate - but it was banked two passes ago, not by the pass that is about to run.
    REQUIRE(rig.kv->del(kJournalNamespace, doomed));

    // PASS B - forced, so the sent-label is ignored and `kept` is actually READ. That read
    // fails. The pass therefore learned nothing about whether `kept` waits on headroom, and
    // must not clear the episode on the strength of pass A's stale entry.
    rig.journal->inject_value_read_failures_for_test(1);
    const auto b = rig.journal->page_into_window(*rig.rt, base_ts + 170'000, /*replay_sent=*/true);
    CHECK_FALSE(b.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == since); // NOT cleared
    CHECK(rig.journal->page_read_failures() >= 2);

    // With the read working again the same pass shape does clear it, so the guard is
    // withholding the clear rather than breaking it.
    const auto c = rig.journal->page_into_window(*rig.rt, base_ts + 230'000, /*replay_sent=*/true);
    CHECK_FALSE(c.headroom_blocked);
    CHECK(rig.journal->headroom_blocked_since_for_test() == -1);
}
