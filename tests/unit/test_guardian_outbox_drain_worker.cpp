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
                                     {.journal = rig.journal.get()});
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
                                     {.journal = rig.journal.get()});
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
                                     {.journal = rig.journal.get()});
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
                                     {.journal = rig.journal.get()});
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
                                     {.journal = rig.journal.get(),
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
                                     {.journal = rig.journal.get(),
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
                                     {.journal = rig.journal.get(), .prune_interval = 0ms});
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
                                     {.journal = rig.journal.get(), .prune_interval = 0ms});
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
                                     {.journal = rig.journal.get(), .prune_interval = 0ms});
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
                                     {.journal = rig.journal.get(), .prune_interval = 0ms});
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
                                     {.journal = rig.journal.get(),
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
                                     {.journal = rig.journal.get()});
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
                                     {.journal = rig.journal.get(), .prune_interval = 0ms});
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

TEST_CASE("worker_thread_id identifies the worker thread while running, and clears after stop",
          "[spark][guardian][drain][maint]") {
    // This is the mechanism GuardianEngine::WorkerHostileMutex asserts against: it compares
    // the locking thread to this id to catch the one thing that deadlocks the agent - the
    // worker taking mtx_, which stop() holds while joining that very worker (#2298 A2). The
    // assert itself aborts, so what is testable here is that the id it reads is correct.
    JournalRig rig;
    std::atomic<std::thread::id> seen_inside{};
    auto observing_send = [&](const OutboxEntry&) -> SendResult {
        seen_inside.store(std::this_thread::get_id());
        return SendResult::Sent;
    };
    GuardianOutboxDrainWorker worker(*rig.rt, observing_send, /*periodic_bound_ms=*/5,
                                     {.journal = rig.journal.get()});
    CHECK(worker.worker_thread_id() == std::thread::id{}); // not started
    worker.start();
    rig.rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    CHECK(spin_until([&] { return seen_inside.load() != std::thread::id{}; }));
    // The send runs on the worker thread, so the engine would be asserting against exactly
    // this id if that send ever reached for mtx_.
    CHECK(seen_inside.load() == worker.worker_thread_id());
    CHECK(worker.worker_thread_id() != std::this_thread::get_id());
    worker.stop();
    CHECK(worker.worker_thread_id() == std::thread::id{}); // cleared on exit
}
