// test_guardian_outbox_drain_worker.cpp - the live-drain worker (ADR-0021 rung
// 7, F6). Drives it against a real GuardianSparkRuntime (fake reader/backend,
// matching the runtime's own test style) with a short periodic bound so the
// backstop-poll path is exercisable in test time too.

#include "guardian_outbox_drain_worker.hpp"

#include "guardian_lifecycle_journal.hpp"

#include <yuzu/agent/kv_store.hpp>
#include <yuzu/agent/spark.hpp>

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::agent;
using namespace std::chrono_literals;

namespace {

struct FakeReader : IStateReader {
    ReadResult<FileSnapshot> file{read_known(FileSnapshot{.exists = true})};
    ReadResult<FileSnapshot> read_file(const FileSparkParams&, const FileReadPlan&) override {
        return file;
    }
    RegistryRead read_registry(const RegistrySparkParams&, const RegistryReadPlan&) override {
        return {};
    }
    ReadResult<ServiceRunState> read_service(const ServiceSparkParams&) override {
        return read_known(ServiceRunState::Running);
    }
    void request_stop() noexcept override {}
};

struct FakeBackend : ISparkBackend {
    std::atomic<std::uint64_t> next{1};
    std::expected<std::uint64_t, std::string> arm(const SparkSpec&) override {
        return next.fetch_add(1);
    }
    void disarm(std::uint64_t) override {}
};

RuleAssertion file_exists_rule(const std::string& rule_id) {
    RuleAssertion a;
    a.kind = AssertionKind::FileExists;
    a.rule_id = rule_id;
    a.expect_present = true;
    return a;
}

SparkSpec file_spec(const std::string& path) {
    return SparkSpec{SparkType::File, FileSparkParams{path}};
}

// A collecting, always-Sent fake send_fn - the worker's own mechanics are
// under test here, not any real wire serialization (that's rung 7.7's job).
struct CollectingSink {
    std::mutex mu;
    std::vector<OutboxEntry> sent;
    SendResult operator()(const OutboxEntry& e) {
        std::lock_guard<std::mutex> lk{mu};
        sent.push_back(e);
        return SendResult::Sent;
    }
    std::size_t count() {
        std::lock_guard<std::mutex> lk{mu};
        return sent.size();
    }
};

bool spin_until(std::function<bool()> pred, std::chrono::milliseconds timeout = 5s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred())
            return true;
        std::this_thread::sleep_for(1ms);
    }
    return pred();
}

// A real KvStore + durable journal alongside the runtime, for the C0 (#2298)
// maintenance-on-the-worker cases: prune + page now run HERE, not on the
// heartbeat / reconnect threads.
struct JournalRig {
    yuzu::test::TempDbFile db{"yuzu_test_drainmaint-"};
    std::unique_ptr<KvStore> kv;
    std::shared_ptr<GuardianSparkRuntime> rt;
    std::unique_ptr<GuardianLifecycleJournal> journal;
    JournalRig() {
        auto r = KvStore::open(db.path);
        REQUIRE(r.has_value());
        kv = std::make_unique<KvStore>(std::move(*r));
        rt = std::make_shared<GuardianSparkRuntime>(std::make_shared<FakeReader>(),
                                                    std::make_shared<FakeBackend>());
        journal = std::make_unique<GuardianLifecycleJournal>(kv.get());
    }
    /// Persist one record as its own durable batch (one persist call = one batch key),
    /// WITHOUT going through the runtime - so the only way it can reach the send window
    /// is the worker's paging pass.
    void persist(const std::string& rule) {
        std::vector<std::shared_ptr<const JournalRecord>> pending{
            std::make_shared<const JournalRecord>(
                JournalRecord{.rule_id = rule, .generation = 1, .event_id = "e-" + rule,
                              .enqueued_ns = 1'700'000'000'000'000'000, .kind = "armed",
                              .guard_type = "file", .rule_name = "n"})};
        REQUIRE(journal->persist(pending) == 1);
    }
};

} // namespace

TEST_CASE("drain_once sends everything currently pending", "[spark][guardian][drain]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rt, std::ref(sink));
    worker.drain_once();

    CHECK(sink.count() == 1); // the "armed" lifecycle entry from attach_rule
}

TEST_CASE("worker survives + counts a throwing send (item 4 hardening)",
          "[spark][guardian][drain]") {
    // A send that throws (e.g. a bad_alloc serializing an entry) must NOT terminate the
    // bare worker thread - which would abort the whole agent (#2037 class). drain_log_
    // unlocked catches the send throw (counting send_exception_count, retaining the head);
    // the entry drains once the send stops throwing. (The worker's own drain_exception_
    // count is a further backstop for a throw in the drain MACHINERY - front_copy/
    // pop_front_if bad_alloc - which needs an allocation-fault seam to exercise; covered by
    // review, not this test.)
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);

    std::atomic<int> throws_left{2};
    std::atomic<bool> drained{false};
    auto sink = [&](const OutboxEntry&) -> SendResult {
        if (throws_left.fetch_sub(1) > 0)
            throw std::runtime_error("send boom");
        drained = true;
        return SendResult::Sent;
    };
    GuardianOutboxDrainWorker worker(*rt, sink, /*periodic_bound_ms=*/20); // fast retry
    worker.start();
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); // enqueues "armed"

    // Reaching here at all proves the worker thread did not terminate on the throws.
    REQUIRE(spin_until([&] { return drained.load(); }, 3s));
    CHECK(rt->send_exception_count() >= 1); // the send throws were counted, not silent
    worker.stop();
}

TEST_CASE("start()/stop() wake promptly on a fresh enqueue, not waiting for the periodic bound",
          "[spark][guardian][drain]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);

    CollectingSink sink;
    // A long periodic bound - if the wake-on-enqueue path is broken, this test
    // times out waiting for the (nonexistent, since we assert well before the
    // bound) backstop poll rather than failing fast.
    GuardianOutboxDrainWorker worker(*rt, std::ref(sink), /*periodic_bound_ms=*/60'000);
    worker.start();

    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE(spin_until([&] { return sink.count() >= 1; }, 2s));

    worker.stop();
}

TEST_CASE("the periodic bound drains even without an explicit enqueue-wake",
          "[spark][guardian][drain]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    // Attach BEFORE start() - no waker installed yet, so the "armed" entry sits
    // unwoken until the worker's own periodic backstop poll picks it up.
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rt, std::ref(sink), /*periodic_bound_ms=*/20);
    worker.start();

    REQUIRE(spin_until([&] { return sink.count() >= 1; }, 2s));
    worker.stop();
}

TEST_CASE("stop() is idempotent and joins cleanly with nothing pending",
          "[spark][guardian][drain]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rt, std::ref(sink));
    worker.start();
    worker.stop();
    worker.stop(); // idempotent
    SUCCEED("double-stop did not hang or crash");
}

TEST_CASE("destroying the worker while running stops and joins it (dtor calls stop())",
          "[spark][guardian][drain]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    CollectingSink sink;
    {
        GuardianOutboxDrainWorker worker(*rt, std::ref(sink));
        worker.start();
        rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        // worker destructs here without an explicit stop() call
    }
    SUCCEED("destructor-driven stop joined cleanly");
}

TEST_CASE("a copied waker outliving the worker is a harmless no-op (Signal stays alive)",
          "[spark][guardian][drain]") {
    // Mirrors ConvergenceScheduler's own copied-waker-outlives-scheduler test.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    CollectingSink sink;
    std::function<void()> copied_waker;
    {
        GuardianOutboxDrainWorker worker(*rt, std::ref(sink));
        worker.start();
        copied_waker = rt->outbox_enqueue_waker_for_test();
        worker.stop();
    } // worker destroyed
    REQUIRE(copied_waker);
    copied_waker(); // must not crash / touch a destroyed mutex
    SUCCEED("post-destruction waker invocation was safe");
}

// ---------------------------------------------------------------------------
// C0 (#2298 gate 1): journal maintenance (retention prune + replay paging)
// relocated onto this worker, off the heartbeat and reconnect threads.
// ---------------------------------------------------------------------------

TEST_CASE("maintenance_once is a no-op without a journal (the pre-C0 construction)",
          "[spark][guardian][drain][maint]") {
    auto rt = std::make_shared<GuardianSparkRuntime>(std::make_shared<FakeReader>(),
                                                     std::make_shared<FakeBackend>());
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rt, std::ref(sink)); // journal defaults to null
    CHECK_FALSE(worker.maintenance_once());
    CHECK(worker.journal_maint_exception_count() == 0);
}

TEST_CASE("maintenance_once pages a durable batch into the window and reports it",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    rig.persist("r1");

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink),
                                     GuardianOutboxDrainWorker::kDefaultPeriodicBoundMs,
                                     rig.journal.get());
    // Nothing is in the window until maintenance pages it: the record was persisted
    // straight to the journal, never through the runtime.
    worker.drain_once();
    CHECK(sink.count() == 0);

    CHECK(worker.maintenance_once()); // true == paged net-new, caller should drain again
    worker.drain_once();
    REQUIRE(sink.count() == 1);
    CHECK(sink.sent[0].event_id == "e-r1");
    CHECK(rig.journal->pages() >= 1);
}

TEST_CASE("a running worker pages AND ships a durable batch in one wake (no second-wake wait)",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    rig.persist("r1");

    CollectingSink sink;
    // A long periodic bound: if the paged entry needed a SECOND wake to ship, this test
    // would time out. try_page_batch does not fire the enqueue waker, so shipping within
    // one wake is exactly the post-page re-drain C0 adds.
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/60'000,
                                     rig.journal.get());
    worker.start();
    worker.notify(); // the reconnect kick
    CHECK(spin_until([&] { return sink.count() == 1; }));
    worker.stop();
}

TEST_CASE("notify() wakes the worker promptly - the reconnect kick replaces inline paging",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/60'000,
                                     rig.journal.get());
    worker.start();
    worker.notify();
    CHECK(spin_until([&] { return rig.journal->pages() >= 1; })); // the kick, not the bound
    const auto before = rig.journal->pages();
    worker.notify();
    CHECK(spin_until([&] { return rig.journal->pages() > before; })); // NOT a 60 s wait
    worker.stop();
}

TEST_CASE("notify() after stop() is a no-op and never resurrects the worker",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/20,
                                     rig.journal.get());
    worker.start();
    worker.stop();
    const auto after_stop = rig.journal->pages();
    worker.notify();
    std::this_thread::sleep_for(60ms); // > 2 periodic bounds had the thread still been alive
    CHECK(rig.journal->pages() == after_stop);
}

TEST_CASE("the prune cadence is TIME-based, not per-wake (an enqueue storm cannot spin prune)",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    CollectingSink sink;
    // A one-hour prune interval: no maintenance pass in this test may prune, however many
    // times it runs. This is the regression guard for the old "every 4th tick" rule, which
    // on a wake-driven worker would have pruned once every 4 enqueues.
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink),
                                     GuardianOutboxDrainWorker::kDefaultPeriodicBoundMs,
                                     rig.journal.get(), /*prune_interval_ms=*/3'600'000);
    for (int i = 0; i < 20; ++i)
        worker.maintenance_once();
    // page_into_window's boot barrier prunes exactly once (before the first replay candidate);
    // the cadence must not have added any of its own on top.
    CHECK(rig.journal->batches_pruned() == 0);
    CHECK(rig.journal->prune_failures() == 0);
    CHECK(rig.journal->pages() >= 1);
}

TEST_CASE("a zero prune interval prunes every maintenance pass (retention still runs here)",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    rig.journal->set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/2,
                                               /*max_bytes=*/static_cast<std::size_t>(-1),
                                               /*max_quarantine=*/100);
    for (int i = 0; i < 6; ++i)
        rig.persist("r" + std::to_string(i));

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink),
                                     GuardianOutboxDrainWorker::kDefaultPeriodicBoundMs,
                                     rig.journal.get(), /*prune_interval_ms=*/0);
    worker.maintenance_once();
    CHECK(rig.journal->batches_pruned() >= 4); // trimmed to the 2-batch cap on the worker
}

TEST_CASE("request_stop() makes a maintenance pass a no-op (bounds the drain-worker join)",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    rig.persist("r1");
    rig.journal->request_stop();

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink),
                                     GuardianOutboxDrainWorker::kDefaultPeriodicBoundMs,
                                     rig.journal.get(), /*prune_interval_ms=*/0);
    CHECK_FALSE(worker.maintenance_once());
    CHECK(rig.journal->pages() == 0);        // page_into_window bailed before its scan
    CHECK(rig.journal->batches_pruned() == 0); // prune bailed before its scan
    worker.drain_once();
    CHECK(sink.count() == 0); // and nothing reached the window after the stop signal
}

TEST_CASE("stop() while maintenance is running joins cleanly and stops mutating the window",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    for (int i = 0; i < 40; ++i)
        rig.persist("r" + std::to_string(i));

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/1,
                                     rig.journal.get(), /*prune_interval_ms=*/0);
    worker.start();
    // Let it get into a maintenance pass, then tear down in the PRODUCTION order:
    // GuardianEngine::stop() signals the journal FIRST, then joins the worker.
    CHECK(spin_until([&] { return rig.journal->pages() >= 1; }));
    rig.journal->request_stop();
    worker.stop();
    const auto pages_at_join = rig.journal->pages();
    std::this_thread::sleep_for(20ms);
    CHECK(rig.journal->pages() == pages_at_join); // no maintenance survived the join
    CHECK(worker.journal_maint_exception_count() == 0);
}

TEST_CASE("a throwing send does not suppress journal maintenance (independent firewalls)",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    rig.persist("r1");
    // The send throws on every entry (counted + head-retained by the runtime's own drain
    // firewall). Journal maintenance must still run every pass: before C0 these two lived on
    // different threads, and folding them onto one must not let either starve the other.
    auto throwing = [](const OutboxEntry&) -> SendResult { throw std::runtime_error("boom"); };
    GuardianOutboxDrainWorker worker(*rig.rt, throwing, /*periodic_bound_ms=*/5,
                                     rig.journal.get());
    worker.start();
    CHECK(spin_until([&] { return rig.journal->records_paged() >= 1; }));
    CHECK(spin_until([&] { return rig.rt->send_exception_count() >= 1; }));
    worker.stop();
    CHECK(worker.journal_maint_exception_count() == 0); // maintenance itself never threw
}

TEST_CASE("a running worker's maintenance races a persister + reconnect kicks (TSan checkpoint)",
          "[spark][guardian][drain][maint][tsan]") {
    // The exact post-C0 concurrency shape: prune + page on the WORKER thread, persist on a
    // separate thread (the heartbeat's surviving phase-1 retry), and reconnect kicks arriving
    // from a third. Before C0 prune/page and persist were serialised on one heartbeat thread,
    // so this interleaving is the one the relocation introduces.
    JournalRig rig;
    rig.journal->set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/16,
                                               /*max_bytes=*/static_cast<std::size_t>(-1),
                                               /*max_quarantine=*/100);
    for (int i = 0; i < 16; ++i)
        rig.persist("seed" + std::to_string(i));

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/1,
                                     rig.journal.get(), /*prune_interval_ms=*/0);
    worker.start();

    std::atomic<bool> stop{false};
    std::thread persister([&] {
        for (int i = 0; !stop.load(std::memory_order_relaxed) && i < 200; ++i)
            rig.persist("live" + std::to_string(i));
    });
    std::thread kicker([&] {
        while (!stop.load(std::memory_order_relaxed))
            worker.notify();
    });

    std::this_thread::sleep_for(200ms);
    stop.store(true, std::memory_order_relaxed);
    persister.join();
    kicker.join();

    // Production teardown order: the journal is signalled FIRST, then the worker is joined.
    rig.journal->request_stop();
    worker.stop();
    SUCCEED("no data race / crash across worker maintenance + persist + reconnect kicks");
}
