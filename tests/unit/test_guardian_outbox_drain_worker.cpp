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
    std::shared_ptr<GuardianLifecycleJournal> journal;
    JournalRig() {
        auto r = KvStore::open(db.path);
        REQUIRE(r.has_value());
        kv = std::make_unique<KvStore>(std::move(*r));
        rt = std::make_shared<GuardianSparkRuntime>(std::make_shared<FakeReader>(),
                                                    std::make_shared<FakeBackend>());
        journal = std::make_shared<GuardianLifecycleJournal>(kv.get());
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

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rt, std::ref(sink), /*periodic_bound_ms=*/20);
    worker.start();
    // Let the boot cycle (which runs WITHOUT waiting) complete first. Attaching before
    // start() - as this test used to - no longer exercises the backstop at all, because that
    // first cycle drains the entry before any timeout elapses (#2298 Sol review).
    CHECK(spin_until([&] { return worker.drain_exception_count() == 0; }, 1s));
    std::this_thread::sleep_for(60ms); // >= 2 periodic bounds: the boot cycle is long done

    // try_page_batch is the one enqueue path that deliberately does NOT fire the waker, so
    // an entry placed this way can ONLY be shipped by the periodic backstop poll.
    std::vector<OutboxEntry> batch;
    batch.push_back(OutboxEntry::lifecycle("r1", 1, "e-backstop", 1'700'000'000'000'000'000,
                                           "armed", "file", "n"));
    REQUIRE(rt->try_page_batch(std::move(batch)) == 1);
    CHECK(sink.count() == 0); // nothing woke the worker

    REQUIRE(spin_until([&] { return sink.count() >= 1; }, 2s)); // the backstop did
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
    CHECK_FALSE(worker.maintenance_once({.prune = true, .page = true}).records_paged > 0);
    CHECK(worker.journal_maint_exception_count() == 0);
}

TEST_CASE("maintenance_once pages a durable batch into the window and reports it",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    rig.persist("r1");

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink),
                                     GuardianOutboxDrainWorker::kDefaultPeriodicBoundMs,
                                     {.journal = rig.journal});
    // Nothing is in the window until maintenance pages it: the record was persisted
    // straight to the journal, never through the runtime.
    worker.drain_once();
    CHECK(sink.count() == 0);

    CHECK(worker.maintenance_once({.prune = true, .page = true}).records_paged > 0);
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
                                     {.journal = rig.journal});
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
                                     {.journal = rig.journal});
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
                                     {.journal = rig.journal});
    worker.start();
    worker.stop();
    const auto after_stop = rig.journal->pages();
    worker.notify();
    std::this_thread::sleep_for(60ms); // > 2 periodic bounds had the thread still been alive
    CHECK(rig.journal->pages() == after_stop);
}

TEST_CASE("the maintenance cadence is TIME-based, not per-wake (an enqueue storm cannot spin it)",
          "[spark][guardian][drain][maint]") {
    // The regression guard for #2298 governance f-1/A1/sec-M1. The earlier version of this
    // test drove maintenance_once() directly against an EMPTY journal and asserted
    // batches_pruned()==0, which is trivially true whether prune ran once or twenty times -
    // it proved nothing (Gate 3 quality-engineer). This one counts ACTUAL journal scans via
    // the pre-scan hook, against a RUNNING worker being hammered with wakes, which is the
    // shape that regresses if anyone reties the cadence to wake count.
    JournalRig rig;
    rig.persist("r1"); // a real journal, so a scan has something to do

    std::atomic<int> prune_scans{0};
    rig.journal->set_pre_scan_hook_for_test([&] { prune_scans.fetch_add(1); });

    CollectingSink sink;
    // Hour-long cadences: NOTHING in this test may legitimately prune or page after the
    // forced boot page, however many times the worker wakes.
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/1,
                                     {.journal = rig.journal,
                                      .page_interval = 1h,
                                      .prune_interval = 1h});
    worker.start();
    // Hammer the waker the way a Guardian drift storm would.
    for (int i = 0; i < 200; ++i)
        worker.notify();
    std::this_thread::sleep_for(150ms); // many wakes at a 1 ms periodic bound
    worker.stop();

    // notify() forces a page each time, and a page's boot barrier prunes ONCE (latching
    // boot_pruned_). What must NOT happen is a scan per wake.
    CHECK(prune_scans.load() <= 2);
    CHECK(rig.journal->pages() <= 205); // forced pages only; no cadence pages on top
}

TEST_CASE("an enqueue-driven wake does not page (only the cadence and the kick do)",
          "[spark][guardian][drain][maint]") {
    // sec-M1 stated precisely: paging is a full journal scan, and the token bucket only
    // throttles NET-NEW paging, so the scan itself must be cadence-bound. A wake caused by
    // an ordinary outbox enqueue must therefore ship the entry WITHOUT rescanning.
    JournalRig rig;
    rig.persist("r1");

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/60'000,
                                     {.journal = rig.journal,
                                      .page_interval = 1h,
                                      .prune_interval = 1h});
    worker.start();
    CHECK(spin_until([&] { return rig.journal->pages() >= 1; })); // the seeded boot page
    const auto pages_after_boot = rig.journal->pages();

    // Now drive 50 enqueue wakes through the REAL waker (attach_rule enqueues a lifecycle
    // entry, which fires the runtime's outbox waker).
    for (int i = 0; i < 50; ++i)
        rig.rt->attach_rule("r" + std::to_string(i), file_spec("/p" + std::to_string(i)),
                            file_exists_rule("r" + std::to_string(i)), true);
    CHECK(spin_until([&] { return sink.count() >= 50; })); // they shipped...
    CHECK(rig.journal->pages() == pages_after_boot);       // ...with no extra journal scan
    worker.stop();
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
                                     {.journal = rig.journal, .prune_interval = 0ms});
    worker.maintenance_once({.prune = true, .page = true});
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
                                     {.journal = rig.journal, .prune_interval = 0ms});
    CHECK_FALSE(worker.maintenance_once({.prune = true, .page = true}).records_paged > 0);
    CHECK(rig.journal->pages() == 0);        // page_into_window bailed before its scan
    CHECK(rig.journal->batches_pruned() == 0); // prune bailed before its scan
    worker.drain_once();
    CHECK(sink.count() == 0); // and nothing reached the window after the stop signal
}

TEST_CASE("a stop landing INSIDE a scan is honoured mid-pass, not just at the entry gate",
          "[spark][guardian][drain][maint]") {
    // The earlier version called request_stop() BEFORE stop(), so every subsequent pass
    // short-circuited at prune's entry guard and the mid-loop gates added by 551e91ac were
    // never executed (Gate 3 quality-engineer). Here the pre-scan hook fires request_stop()
    // from INSIDE a scan already in flight, which is the interleaving those gates exist for.
    JournalRig rig;
    rig.journal->set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/2,
                                               /*max_bytes=*/static_cast<std::size_t>(-1),
                                               /*max_quarantine=*/100);
    for (int i = 0; i < 40; ++i)
        rig.persist("r" + std::to_string(i));

    std::atomic<bool> stopped_mid_scan{false};
    rig.journal->set_pre_scan_hook_for_test([&] {
        rig.journal->request_stop(); // the scan is already past its entry gate
        stopped_mid_scan.store(true);
    });

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink),
                                     GuardianOutboxDrainWorker::kDefaultPeriodicBoundMs,
                                     {.journal = rig.journal, .prune_interval = 0ms});
    worker.maintenance_once({.prune = true, .page = true});

    CHECK(stopped_mid_scan.load());
    // The mid-scan gates must have aborted the pass: nothing was evicted despite 40 batches
    // against a 2-batch cap, and the label-GC / quarantine-bounding scans never ran.
    CHECK(rig.journal->batches_pruned() == 0);
    CHECK(rig.journal->prune_failures() == 0); // an abort is not a failure
}

TEST_CASE("stop() during a running worker's maintenance joins cleanly",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    for (int i = 0; i < 40; ++i)
        rig.persist("r" + std::to_string(i));

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/1,
                                     {.journal = rig.journal, .prune_interval = 0ms});
    worker.start();
    CHECK(spin_until([&] { return rig.journal->pages() >= 1; }));
    // Production teardown order: the journal is signalled FIRST, then the worker joined.
    rig.journal->request_stop();
    worker.stop();
    const auto pages_at_join = rig.journal->pages();
    std::this_thread::sleep_for(20ms);
    CHECK(rig.journal->pages() == pages_at_join); // no maintenance survived the join
    CHECK(worker.journal_maint_exception_count() == 0);
}

TEST_CASE("a throwing maintenance pass is firewalled, counted, and does not stop the loop",
          "[spark][guardian][drain][maint]") {
    // journal_maint_exception_count() was asserted ==0 everywhere but never driven nonzero
    // (Gate 3 quality-engineer). The pre-scan hook throws straight out of prune_locked_
    // uncaught, so no new seam is needed to prove the firewall.
    JournalRig rig;
    rig.persist("r1");
    std::atomic<int> throws{0};
    rig.journal->set_pre_scan_hook_for_test([&] {
        if (throws.fetch_add(1) < 3)
            throw std::runtime_error("scan boom");
    });

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/5,
                                     {.journal = rig.journal,
                                      .page_interval = 0ms,
                                      .prune_interval = 0ms});
    worker.start();
    CHECK(spin_until([&] { return worker.journal_maint_exception_count() >= 1; }));
    // The loop survived and kept going: once the hook stops throwing, work resumes.
    CHECK(spin_until([&] { return rig.journal->pages() >= 1; }));
    worker.stop();
    CHECK(worker.drain_exception_count() == 0); // the drain firewall was NOT tripped
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
                                     {.journal = rig.journal});
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

    // The send is the PRODUCTION wrapper shape, not a bare sink: mark_batch_sent issues a
    // KvStore WRITE from the worker thread, which must race prune's del_keys on the same
    // store. A CollectingSink would never exercise that (Gate 3 cpp-safety).
    CollectingSink sink;
    auto journaled_send = [&](const OutboxEntry& e) -> SendResult {
        const SendResult r = sink(e);
        if (r == SendResult::Sent && e.journal_last_in_batch && !e.journal_batch_key.empty())
            rig.journal->mark_batch_sent(e.journal_batch_key);
        return r;
    };
    GuardianOutboxDrainWorker worker(*rig.rt, journaled_send, /*periodic_bound_ms=*/1,
                                     {.journal = rig.journal, .prune_interval = 0ms});
    worker.start();

    std::atomic<bool> stop{false};
    // Drives the REAL phase-1 persist path (snapshot_pending -> persist ->
    // erase_persisted_prefix -> backfill_batch_provenance over outbox_mu_/pending_journal_),
    // which is precisely the state C0 newly splits across two threads. Persisting straight
    // into the journal, as this test previously did, bypasses all of it.
    std::thread persister([&] {
        for (int i = 0; !stop.load(std::memory_order_relaxed) && i < 200; ++i) {
            const auto rid = "live" + std::to_string(i);
            rig.rt->attach_rule(rid, file_spec("/" + rid), file_exists_rule(rid), true);
            auto pending = rig.rt->snapshot_pending();
            if (pending.empty())
                continue;
            std::vector<PersistedBatch> batches;
            const std::size_t written = rig.journal->persist(pending, &batches);
            if (written > 0) {
                rig.rt->erase_persisted_prefix(written);
                for (const auto& b : batches)
                    if (!b.event_ids.empty())
                        rig.rt->backfill_batch_provenance(b.key, b.event_ids, b.event_ids.back());
            }
        }
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

TEST_CASE("the drain-worker role marker is set on that thread and nowhere else",
          "[spark][guardian][drain][maint]") {
    // This is what GuardianEngine::WorkerHostileMutex consults to abort rather than deadlock
    // if the worker ever takes mtx_ (#2298 A2, reworked after Sol found the earlier
    // pointer-based mechanism was itself a data race and a potential UAF). A true death test
    // needs a subprocess harness this suite does not have, so what is proven here is the
    // PREDICATE the abort keys off: true on the worker thread, false everywhere else.
    JournalRig rig;
    CHECK_FALSE(on_guardian_drain_worker_thread()); // the test thread is not the worker

    std::atomic<bool> marker_inside{false};
    std::atomic<bool> observed{false};
    auto observing_send = [&](const OutboxEntry&) -> SendResult {
        // The INJECTED send is exactly the exposure the marker exists for: an arbitrary
        // std::function supplied by agent.cpp, running here on the worker thread.
        marker_inside.store(on_guardian_drain_worker_thread());
        observed.store(true);
        return SendResult::Sent;
    };
    GuardianOutboxDrainWorker worker(*rig.rt, observing_send, /*periodic_bound_ms=*/5,
                                     {.journal = rig.journal});
    worker.start();
    rig.rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    CHECK(spin_until([&] { return observed.load(); }));
    CHECK(marker_inside.load());
    worker.stop();
    CHECK_FALSE(on_guardian_drain_worker_thread()); // still false here after the join
}

TEST_CASE("a bounded drain truncates, reports it, and later passes finish the backlog",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    for (int i = 0; i < 12; ++i)
        rig.rt->attach_rule("r" + std::to_string(i), file_spec("/p" + std::to_string(i)),
                            file_exists_rule("r" + std::to_string(i)), true);

    CollectingSink sink;
    GuardianSparkRuntime::DrainLimits limits;
    limits.max_entries = 4;
    const auto first = rig.rt->drain_bounded(std::ref(sink), limits);
    CHECK(first.sent == 4);
    CHECK(first.truncated); // entries remain: the caller must re-drain, not sleep
    const auto second = rig.rt->drain_bounded(std::ref(sink), limits);
    CHECK(second.sent == 4);
    rig.rt->drain(std::ref(sink)); // unbounded finish
    CHECK(sink.count() == 12);     // nothing lost, nothing duplicated
}

TEST_CASE("a bounded drain reserves a share so lifecycle cannot starve compliance",
          "[spark][guardian][drain][maint]") {
    // Regression guard for the detection blackout a naive shared budget reintroduced: with
    // lifecycle drained first out of ONE budget, a busy lifecycle log meant compliance/health
    // never ran at all - the exact failure Gate 4 UP-3 removed (#2298 Sol review).
    JournalRig rig;
    for (int i = 0; i < 20; ++i)
        rig.rt->attach_rule("r" + std::to_string(i), file_spec("/p" + std::to_string(i)),
                            file_exists_rule("r" + std::to_string(i)), true);
    rig.rt->evaluate_key(spark_key(file_spec("/p0")), EvalReason::Convergence);

    CollectingSink sink;
    GuardianSparkRuntime::DrainLimits limits;
    limits.max_entries = 8; // lifecycle alone would consume all 8 without a reserve
    rig.rt->drain_bounded(std::ref(sink), limits);

    bool saw_non_lifecycle = false;
    {
        std::lock_guard<std::mutex> lk{sink.mu};
        for (const auto& e : sink.sent)
            if (e.domain != OutboxDomain::Lifecycle)
                saw_non_lifecycle = true;
    }
    CHECK(saw_non_lifecycle);
}

TEST_CASE("a drain starts no further sends once stop is requested",
          "[spark][guardian][drain][maint]") {
    // A count bound let a whole 512-send pass BEGIN after stop() was already blocked in
    // join(); should_stop is now checked before every send (#2298 Sol review).
    JournalRig rig;
    for (int i = 0; i < 20; ++i)
        rig.rt->attach_rule("r" + std::to_string(i), file_spec("/p" + std::to_string(i)),
                            file_exists_rule("r" + std::to_string(i)), true);

    std::atomic<int> sends{0};
    std::atomic<bool> stopping{false};
    auto counting_send = [&](const OutboxEntry&) -> SendResult {
        if (sends.fetch_add(1) >= 2)
            stopping.store(true); // shutdown lands mid-pass
        return SendResult::Sent;
    };
    GuardianSparkRuntime::DrainLimits limits;
    limits.max_entries = 100;
    limits.should_stop = [&] { return stopping.load(); };
    const auto out = rig.rt->drain_bounded(counting_send, limits);
    CHECK(out.truncated);
    CHECK(sends.load() <= 4); // stopped promptly; did not run the whole allowance
}

TEST_CASE("a prune failure does not swallow a forced reconnect page",
          "[spark][guardian][drain][maint]") {
    // prune and page shared one try/catch and both cadence stamps were taken BEFORE the pass,
    // so a prune throw consumed the force flag and lost the reconnect kick for a whole
    // cadence interval (#2298 Sol review).
    JournalRig rig;
    rig.persist("r1");
    std::atomic<int> scans{0};
    rig.journal->set_pre_scan_hook_for_test([&] {
        if (scans.fetch_add(1) < 2)
            throw std::runtime_error("prune boom");
    });

    CollectingSink sink;
    // Page cadence an hour out, so ONLY a forced page can ever run in this test.
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/5,
                                     {.journal = rig.journal,
                                      .page_interval = 1h,
                                      .prune_interval = 0ms});
    worker.start();
    CHECK(spin_until([&] { return worker.journal_maint_exception_count() >= 1; }));
    // The prune throws ate the first cycles, but the force was re-armed rather than lost,
    // so the durable record still reaches the wire.
    CHECK(spin_until([&] { return sink.count() >= 1; }));
    worker.stop();
}
