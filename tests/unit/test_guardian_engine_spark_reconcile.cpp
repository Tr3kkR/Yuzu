// test_guardian_engine_spark_reconcile.cpp - GuardianEngine's rung-7 reconcile
// op: the mutual-exclusion invariant between the spark and legacy IGuard
// detection paths. Tested against a REAL SparkEngine with a fake mechanism
// (Sol's rev-1 review resolution: this is the right vehicle, not a separate
// fake-backend injection seam - it exercises wire_spark_engine's real
// register_consumer/arm/disarm calls, not a shortcut around them).

#include <yuzu/agent/guardian_engine.hpp>
#include <yuzu/agent/kv_store.hpp>

#include "guaranteed_state.pb.h"
#include "guardian_journal_format.hpp" // kJournalNamespace, parse_journal_batch (item 7 PR-Ag)
#include "guardian_journal_heartbeat.hpp" // emit_guardian_journal_heartbeat_tags (aggregate inertness)
#include "guardian_lifecycle_journal.hpp" // GuardianLifecycleJournal (for the _for_test fault seam)
#include "guardian_outbox.hpp" // OutboxEntry, SendResult - full definitions for the test's send_fn
#include "spark_engine.hpp"
#include "spark_mechanism.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <atomic>
#include <condition_variable>
#include <thread>
#include <vector>

#ifndef _WIN32
#  include <sys/wait.h>
#  include <unistd.h>
#endif

#ifndef _WIN32
#include <unistd.h>
#endif

namespace fs = std::filesystem;
namespace gpb = ::yuzu::guardian::v1;
using yuzu::agent::GuardianEngine;
using yuzu::agent::ISparkMechanism;
using yuzu::agent::KvStore;
using yuzu::agent::OutboxEntry;
using yuzu::agent::SendResult;
using yuzu::agent::SparkData;
using yuzu::agent::SparkEmitFn;
using yuzu::agent::SparkEngine;
using yuzu::agent::SparkFaultFn;
using yuzu::agent::SparkParams;
using yuzu::agent::SparkType;

namespace {

std::string uid_suffix() {
#ifdef _WIN32
    if (const char* u = std::getenv("USERNAME")) return std::string("_") + u;
    return "_unknown";
#else
    return "_" + std::to_string(static_cast<unsigned long>(::geteuid()));
#endif
}
fs::path unique_kv_path() {
    const auto dir = fs::temp_directory_path() / ("yuzu_test_guardian_reconcile" + uid_suffix());
    return dir / (yuzu::test::unique_temp_path("reconcile_").filename().string() + ".db");
}

/// A minimal cross-platform stand-in for the real service mechanism (mirrors
/// test_spark_mechanism.cpp's FakeMechanism, trimmed to what these tests
/// need): records watch()/unwatch() calls and can be told to fail its NEXT
/// watch() (for the arm-failure test).
class FakeServiceMechanism final : public ISparkMechanism {
public:
    void start(SparkEmitFn, SparkFaultFn) override {}
    std::expected<void, std::string> watch(const std::string& key, const SparkParams&) override {
        std::lock_guard<std::mutex> lk{mu_};
        if (fail_next_watch_) {
            fail_next_watch_ = false;
            return std::unexpected("forced watch failure");
        }
        watched_.insert(key);
        return {};
    }
    void unwatch(const std::string& key) override {
        std::lock_guard<std::mutex> lk{mu_};
        watched_.erase(key);
    }
    void stop() override {}
    void set_fail_next_watch() {
        std::lock_guard<std::mutex> lk{mu_};
        fail_next_watch_ = true;
    }
    bool is_watching(const std::string& key) {
        std::lock_guard<std::mutex> lk{mu_};
        return watched_.count(key) > 0;
    }
    std::size_t watching_count() {
        std::lock_guard<std::mutex> lk{mu_};
        return watched_.size();
    }

private:
    std::mutex mu_;
    std::set<std::string> watched_;
    bool fail_next_watch_{false};
};

// Service: the ONE type with a mechanism registered in this fixture -> Arm.
gpb::GuaranteedStateRule make_service_rule(const std::string& id, bool enabled = true) {
    gpb::GuaranteedStateRule r;
    r.set_rule_id(id);
    r.set_name(id);
    r.set_enabled(enabled);
    r.set_enforcement_mode("audit");
    r.mutable_spark()->set_type("service-status-change");
    auto* a = r.mutable_assertion();
    a->set_type("service-running");
    (*a->mutable_params())["service_name"] = "Spooler";
    return r;
}

// File: NO mechanism registered in this fixture -> a routine Unsupported gap.
gpb::GuaranteedStateRule make_file_rule(const std::string& id, bool enabled = true) {
    gpb::GuaranteedStateRule r;
    r.set_rule_id(id);
    r.set_name(id);
    r.set_enabled(enabled);
    r.set_enforcement_mode("audit");
    r.mutable_spark()->set_type("file-change");
    auto* a = r.mutable_assertion();
    a->set_type("file-exists");
    (*a->mutable_params())["path"] = "/tmp/yuzu-reconcile-test-target";
    return r;
}

// Invalid: an unrecognized spark type -> an authoring fault, never armed anywhere.
gpb::GuaranteedStateRule make_invalid_rule(const std::string& id) {
    gpb::GuaranteedStateRule r;
    r.set_rule_id(id);
    r.set_name(id);
    r.set_enabled(true);
    r.set_enforcement_mode("audit");
    r.mutable_spark()->set_type("banana");
    r.mutable_assertion()->set_type("whatever");
    return r;
}

struct SparkReconcileFixture {
    yuzu::test::TempDbFile db_{unique_kv_path()};
    std::unique_ptr<KvStore> kv;
    SparkEngine spark_engine;
    FakeServiceMechanism* mechanism{nullptr}; // borrowed; owned by spark_engine
    std::unique_ptr<GuardianEngine> engine;
    std::mutex sent_mu;
    std::vector<OutboxEntry> sent;

    /// `periodic_bound_ms > 0` pins the drain worker's backstop before it is constructed,
    /// so a test can attribute a page to the reconnect kick rather than the backstop.
    explicit SparkReconcileFixture(std::uint64_t periodic_bound_ms = 0) {
        auto opened = KvStore::open(db_.path);
        REQUIRE(opened.has_value());
        kv = std::make_unique<KvStore>(std::move(*opened));

        auto mech = std::make_unique<FakeServiceMechanism>();
        mechanism = mech.get();
        REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
        spark_engine.start();

        engine = std::make_unique<GuardianEngine>(kv.get(), "agent-test", /*prefer_spark=*/true);
        REQUIRE(engine->start_local().has_value());
        if (periodic_bound_ms > 0)
            engine->set_drain_worker_timing_for_test(periodic_bound_ms);
        engine->wire_spark_engine(&spark_engine, /*spark_disabled_by_config=*/false,
                                  [this](const OutboxEntry& e) {
                                      std::lock_guard<std::mutex> lk{sent_mu};
                                      sent.push_back(e);
                                      return SendResult::Sent;
                                  });
        REQUIRE(engine->spark_availability() == GuardianEngine::SparkAvailability::Available);
    }

    // GuardianEngine (and therefore spark_runtime_/scheduler/drain-worker) is
    // stopped/joined FIRST (via engine.reset(), whose dtor calls stop()) -
    // mirrors the production shutdown order (rung 7.7): Guardian's spark
    // teardown must complete before the SparkEngine it borrowed from is torn
    // down, since GuardianSparkEngineBackend holds a borrowed SparkEngine*.
    ~SparkReconcileFixture() {
        engine.reset();
        spark_engine.stop();
    }

    void apply(const gpb::GuaranteedStateRule& rule, bool full_sync = true) {
        gpb::GuaranteedStatePush p;
        p.set_full_sync(full_sync);
        *p.add_rules() = rule;
        // Serialize-then-dispatch, NOT engine->apply_rules(p) directly: every
        // rule here carries an assertion params Map (service_name/hive/key/
        // path), and on Windows MSVC debug, populating that Map in the TEST
        // EXE and then reading it DLL-side hits the #501 cross-image abseil
        // hash-seed split - .find() silently misses ~50% of the time,
        // producing an empty string exactly as if the field were never set
        // (confirmed on DGRHP: every service-type test here failed spark
        // validation with "spec derivation failed", i.e. guardian_assertion_
        // param("service_name") read back empty). guardian_dispatch_push_
        // bytes_for_test deserializes the bytes INSIDE the DLL, so the Map is
        // populated using the DLL's own seed - see guardian_engine.hpp's
        // doc comment on the helper for the full mechanism. Linux is blind to
        // this class of bug (single shared object, no split seed), which is
        // why this went uncaught until the first real Windows compile.
        auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*engine, p.SerializeAsString());
        REQUIRE(dr.exit_code == 0);
    }
};

} // namespace

TEST_CASE("a supported type arms via spark, never in legacy guards_",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_service_rule("r1"));

    CHECK(f.engine->spark_armed_rule_count() == 1);
    CHECK(f.engine->armed_guard_count() == 0);
    CHECK(f.mechanism->watching_count() == 1);
}

TEST_CASE("an unsupported type falls through to legacy, never attempted on spark",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1"));

    // File has no mechanism registered in this fixture - a ROUTINE gap, not a
    // failure: legacy arms it (on non-Windows the legacy FileGuard also
    // no-ops, so this just needs to prove spark never claims it).
    CHECK(f.engine->spark_armed_rule_count() == 0);
    CHECK(f.mechanism->watching_count() == 0);
}

TEST_CASE("an invalid rule (unrecognized spark type) arms nowhere",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_invalid_rule("r1"));

    CHECK(f.engine->rule_count() == 1);       // still persisted
    CHECK(f.engine->spark_armed_rule_count() == 0);
    CHECK(f.engine->armed_guard_count() == 0);
}

TEST_CASE("a spark arm failure is errored, NEVER a silent legacy fallback",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.mechanism->set_fail_next_watch();
    f.apply(make_service_rule("r1"));

    CHECK(f.engine->spark_armed_rule_count() == 0);
    CHECK(f.engine->armed_guard_count() == 0); // NOT armed via legacy either
    CHECK(f.engine->rule_count() == 1);        // still persisted (errored, not deleted)
}

TEST_CASE("disable withdraws from spark; re-enable re-arms via spark",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_service_rule("r1"));
    REQUIRE(f.engine->spark_armed_rule_count() == 1);

    f.apply(make_service_rule("r1", /*enabled=*/false), /*full_sync=*/false);
    CHECK(f.engine->spark_armed_rule_count() == 0);
    CHECK(f.mechanism->watching_count() == 0);

    f.apply(make_service_rule("r1", /*enabled=*/true), /*full_sync=*/false);
    CHECK(f.engine->spark_armed_rule_count() == 1);
    CHECK(f.mechanism->watching_count() == 1);
}

TEST_CASE("a same-id replace while spark-armed swaps generations, never double-arms",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_service_rule("r1"));
    REQUIRE(f.engine->spark_armed_rule_count() == 1);

    f.apply(make_service_rule("r1"), /*full_sync=*/false); // re-push, unchanged content
    CHECK(f.engine->spark_armed_rule_count() == 1); // still 1, not 2
}

TEST_CASE("a same-id replace from spark-armed to legacy-armed withdraws spark first",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_service_rule("r1")); // spark-armed (service mechanism registered)
    REQUIRE(f.engine->spark_armed_rule_count() == 1);
    REQUIRE(f.engine->armed_guard_count() == 0);

    // Same rule_id, now a type with no mechanism registered - must land ONLY
    // in legacy, with the prior spark attachment fully withdrawn, never both.
    f.apply(make_file_rule("r1"), /*full_sync=*/false);
    CHECK(f.engine->spark_armed_rule_count() == 0);
    CHECK(f.mechanism->watching_count() == 0);
}

TEST_CASE("a same-id replace from legacy-armed to spark-armed withdraws legacy first",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1")); // legacy-armed (no mechanism for file-change)
    REQUIRE(f.engine->spark_armed_rule_count() == 0);

    // Same rule_id, now a spark-supported type - must land ONLY in spark, with
    // withdraw_legacy_guard_locked having retired the prior legacy guard.
    f.apply(make_service_rule("r1"), /*full_sync=*/false);
    CHECK(f.engine->spark_armed_rule_count() == 1);
    CHECK(f.engine->armed_guard_count() == 0);
    CHECK(f.mechanism->watching_count() == 1);
}

TEST_CASE("full_sync withdraws a spark-armed rule the new push omits",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_service_rule("r1"));
    REQUIRE(f.engine->spark_armed_rule_count() == 1);

    // A full_sync naming only a DIFFERENT rule must withdraw r1's spark
    // attachment too, not just leave it dangling (Sol's rev-2 review).
    f.apply(make_service_rule("r2"), /*full_sync=*/true);
    CHECK(f.engine->rule_count() == 1);              // only r2 persisted; r1 is gone
    CHECK(f.engine->spark_armed_rule_count() == 1);  // still exactly 1 (r2), not 2
}

TEST_CASE("mutual exclusion holds across a full transition matrix (never both, "
          "exactly one for an armed rule)",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    auto invariant_holds = [&] {
        // Never both: no rule_id can be simultaneously spark- and legacy-armed.
        // (armed_guard_count()/spark_armed_rule_count() are aggregate counts -
        // per-rule cross-checking isn't exposed, but with exactly one rule_id
        // active at a time in this test the aggregate sum bounds it directly.)
        return (f.engine->armed_guard_count() + f.engine->spark_armed_rule_count()) <= 1;
    };

    f.apply(make_service_rule("r1"));                                   // -> spark
    CHECK(invariant_holds());
    CHECK(f.engine->spark_armed_rule_count() == 1);

    f.apply(make_service_rule("r1", false), /*full_sync=*/false);       // -> disabled
    CHECK(invariant_holds());

    f.apply(make_invalid_rule("r1"), /*full_sync=*/false);              // -> invalid
    CHECK(invariant_holds());
    CHECK(f.engine->armed_guard_count() == 0);
    CHECK(f.engine->spark_armed_rule_count() == 0);

    f.mechanism->set_fail_next_watch();
    f.apply(make_service_rule("r1"), /*full_sync=*/false);              // -> arm-failure
    CHECK(invariant_holds());
    CHECK(f.engine->armed_guard_count() == 0);
    CHECK(f.engine->spark_armed_rule_count() == 0);

    f.apply(make_service_rule("r1"), /*full_sync=*/false);              // -> re-armed OK
    CHECK(invariant_holds());
    CHECK(f.engine->spark_armed_rule_count() == 1);
}

TEST_CASE("wire_spark_engine reports Available; --spark-disable reports SparkDisabled; "
          "a failed boot reports SparkFailed",
          "[spark][guardian][reconcile]") {
    {
        SparkReconcileFixture f; // Available - proven by the fixture's own REQUIRE
        CHECK(f.engine->spark_availability() == GuardianEngine::SparkAvailability::Available);
    }
    {
        auto opened = KvStore::open(unique_kv_path());
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
        engine.wire_spark_engine(nullptr, /*spark_disabled_by_config=*/true,
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        CHECK(engine.spark_availability() == GuardianEngine::SparkAvailability::SparkDisabled);
    }
    {
        auto opened = KvStore::open(unique_kv_path());
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
        engine.wire_spark_engine(nullptr, /*spark_disabled_by_config=*/false, // boot failed
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        CHECK(engine.spark_availability() == GuardianEngine::SparkAvailability::SparkFailed);
    }
}

TEST_CASE("prefer_spark=false (the rung 7 production default) never attempts spark, "
          "even when Available",
          "[spark][guardian][reconcile]") {
    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    auto mech = std::make_unique<FakeServiceMechanism>();
    auto* mechanism = mech.get();
    REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
    spark_engine.start();

    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/false}; // the production default
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, false, [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = make_service_rule("r1");
    // Serialize-then-dispatch, not apply_rules(p) directly - see the fixture's
    // apply() helper above for the #501 cross-image Map rationale. This
    // test's own assertions happen to pass either way (spark stays untouched
    // whether prefer_spark_ correctly gates it or the #501 bug invalidly
    // rejects the rule before that gate is even reached), but a wrong-reason
    // pass defeats the point of the test - fixed for correctness even though
    // it wasn't in DGRHP's failure list.
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    CHECK(engine.spark_armed_rule_count() == 0); // spark never even consulted
    CHECK(mechanism->watching_count() == 0);
    // Legacy DID attempt to arm (whether it succeeds depends on the platform's
    // real ServiceGuard/SystemdServiceGuard - not this test's concern; only
    // that spark was never touched).

    engine.stop();
    spark_engine.stop();
}

// ── Durable-journal persist boundary + inertness (item 7 PR-Ag C2) ───────────

TEST_CASE("prefer_spark=true: an armed rule's record is persisted to the durable journal",
          "[spark][guardian][reconcile][journal]") {
    SparkReconcileFixture f;
    f.apply(make_service_rule("r1")); // arms via spark → stages "armed" → apply_rules flush persists

    // The journal namespace is distinct from the rule namespace and survives full_sync.
    auto rows = f.kv->list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix);
    REQUIRE(rows.has_value());
    REQUIRE_FALSE(rows->empty()); // a batch was durably written by the flush guard

    bool found_armed_r1 = false;
    for (const auto& row : *rows) {
        auto b = yuzu::agent::parse_journal_batch(row.value);
        REQUIRE(b.has_value());
        for (const auto& e : b->entries)
            if (e.rule_id == "r1" && e.kind == "armed")
                found_armed_r1 = true;
    }
    CHECK(found_armed_r1);
}

TEST_CASE("prefer_spark=false: no lifecycle record is journaled (inert)",
          "[spark][guardian][reconcile][journal]") {
    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    auto mech = std::make_unique<FakeServiceMechanism>();
    REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
    spark_engine.start();

    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/false}; // production default
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = make_service_rule("r1");
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    // Inert: persist_lifecycle_journal_locked is prefer_spark_-gated AND no spark staging
    // happened (the rule armed on the legacy backend). The maintenance tick is inert too.
    engine.journal_maintenance_tick();
    auto rows = kv.list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix);
    REQUIRE(rows.has_value());
    CHECK(rows->empty());

    engine.stop();
    spark_engine.stop();
}

TEST_CASE("prefer_spark=true: the maintenance tick retries a persist a write failure left pending",
          "[spark][guardian][reconcile][journal]") {
    SparkReconcileFixture f;
    f.engine->lifecycle_journal_for_test()->inject_write_failures_for_test(1);
    f.apply(make_service_rule("r1")); // the apply_rules flush persist FAILS → record stays pending

    auto before = f.kv->list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix);
    REQUIRE(before.has_value());
    CHECK(before->empty()); // nothing durable yet - the write failed

    f.engine->journal_maintenance_tick(); // NO new push/reconnect - the tick alone retries

    auto after = f.kv->list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix);
    REQUIRE(after.has_value());
    bool found = false;
    for (const auto& row : *after) {
        auto b = yuzu::agent::parse_journal_batch(row.value);
        REQUIRE(b.has_value());
        for (const auto& e : b->entries)
            if (e.rule_id == "r1" && e.kind == "armed")
                found = true;
    }
    CHECK(found); // BLOCKER-4: the failed write self-healed via the heartbeat tick
}

TEST_CASE("prefer_spark=true: stop() final-flushes records a write failure left pending",
          "[spark][guardian][reconcile][journal]") {
    SparkReconcileFixture f;
    f.engine->lifecycle_journal_for_test()->inject_write_failures_for_test(1);
    f.apply(make_service_rule("r1")); // persist fails → pending
    CHECK(f.kv->list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix)->empty());

    f.engine->stop(); // the final flush persists the leftover pending record

    auto rows = f.kv->list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix);
    REQUIRE(rows.has_value());
    CHECK_FALSE(rows->empty()); // durable after stop's final flush
}

TEST_CASE("prefer_spark=true: page_journal kicks the drain worker into a paging pass",
          "[spark][guardian][reconcile][journal]") {
    // C0 (#2298 gate 1): page_journal no longer pages INLINE on the caller's (reconnect)
    // thread - it wakes the drain worker, which runs the pass. Same observable replay, minus
    // a full KvStore scan on the thread that has just re-established the stream.
    //
    // The worker's backstop is pinned to an hour BEFORE it is constructed, and the page
    // cadence defaults to 30 s, so within this test's window the ONLY thing that can cause a
    // paging pass is the kick. Without that pin the production 5 s backstop is already
    // ticking through fixture setup and could fire inside the assertion window, letting this
    // pass for the wrong reason (Gate 3 quality-engineer BLOCKING-1).
    SparkReconcileFixture f{/*periodic_bound_ms=*/3'600'000};
    auto* journal = f.engine->lifecycle_journal_for_test();

    // The worker forces one page on its first cycle (boot replay); wait that out first so the
    // assertion below is attributable solely to the kick.
    const auto deadline0 = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (journal->pages() == 0 && std::chrono::steady_clock::now() < deadline0)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    REQUIRE(journal->pages() >= 1);

    const auto before = journal->pages();
    f.engine->page_journal();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (journal->pages() == before && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    CHECK(journal->pages() > before); // only the kick could have caused this
}

TEST_CASE("prefer_spark=false: page_journal + tick are inert (no pass, journal untouched)",
          "[spark][guardian][reconcile][journal]") {
    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    // Seed the journal namespace with a batch that must be left untouched.
    REQUIRE(kv.set(yuzu::agent::kJournalNamespace, "lc:seed:000000000000",
                   R"({"v":4,"ts_ms":1700000000000,"entries":[{"rule_id":"r","generation":1,)"
                   R"("event_id":"e","enqueued_ns":1700000000000000000,"kind":"armed",)"
                   R"("guard_type":"file","rule_name":"n"}]})"));

    SparkEngine spark_engine;
    auto mech = std::make_unique<FakeServiceMechanism>();
    REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
    spark_engine.start();
    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/false};
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Sent; });

    engine.page_journal();
    engine.journal_maintenance_tick();
    CHECK(engine.lifecycle_journal_for_test()->pages() == 0);            // no paging pass ran
    CHECK(kv.exists(yuzu::agent::kJournalNamespace, "lc:seed:000000000000")); // seed untouched

    engine.stop();
    spark_engine.stop();
}

TEST_CASE("prefer_spark=false: journal telemetry is all-zero (aggregate inertness)",
          "[spark][guardian][reconcile][journal]") {
    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    auto mech = std::make_unique<FakeServiceMechanism>();
    REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
    spark_engine.start();
    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/false};
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Sent; });

    // Apply a rule + drive BOTH maintenance paths - none of it touches the journal.
    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = make_service_rule("r1");
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);
    engine.journal_maintenance_tick();
    engine.page_journal();

    // Every journal counter is zero, so the sparse emitter ships NO tags (design §7/§8).
    std::map<std::string, std::string> tags;
    yuzu::agent::emit_guardian_journal_heartbeat_tags(tags, engine.journal_stats());
    CHECK(tags.empty());

    engine.stop();
    spark_engine.stop();
}

// ---------------------------------------------------------------------------
// Death test: the drain worker taking GuardianEngine::mtx_ must ABORT, not hang.
// ---------------------------------------------------------------------------
#ifndef _WIN32

TEST_CASE("a worker-thread mtx_ acquisition aborts the process (death test)",
          "[spark][guardian][reconcile][journal][death]") {
    // The invariant under test is the one that hangs a fleet: GuardianEngine::stop() holds
    // mtx_ across its whole body AND joins the drain worker inside it, so an mtx_ acquisition
    // on that worker deadlocks agent shutdown. WorkerHostileMutex is supposed to turn that
    // into a loud crash. Until now that abort was wired and its predicate was tested, but the
    // abort itself never executed - so this proves the actual failure mode, in a subprocess,
    // because a passing run necessarily kills the process it happens in.
    //
    // The hostile call is placed in the INJECTED SEND, deliberately: that is the real
    // exposure (an arbitrary std::function supplied from agent.cpp), not the journal pointer
    // the first hardening round guarded.
    if constexpr (!yuzu::agent::worker_mutex_guard_enabled()) {
        SUCCEED("WorkerHostileMutex is compiled out in this build; nothing to prove");
        return;
    }

    // fork() WITHOUT exec. Safe here because Catch2 runs test cases sequentially and this one
    // starts no threads before forking, so no other thread can hold a libc lock at fork time.
    // The child is short-lived and aborts; it never returns to the harness.
    const pid_t pid = ::fork();
    REQUIRE(pid >= 0);

    if (pid == 0) {
        // ---- child ----
        // Hand SIGABRT back to the default handler first. Catch2 installs its own fatal-signal
        // handler, which would intercept the abort, print a spurious "FAILED ... SIGABRT" from
        // the child into the parent's output, and make a PASSING run look like a failure.
        // With SIG_DFL the child dies silently and the parent observes the signal, which is
        // the whole assertion.
        ::signal(SIGABRT, SIG_DFL);

        auto opened = KvStore::open(unique_kv_path());
        if (!opened)
            ::_exit(90); // distinct codes so the parent can tell setup failure from no-abort
        KvStore kv{std::move(*opened)};

        SparkEngine spark_engine;
        auto mech = std::make_unique<FakeServiceMechanism>();
        if (!spark_engine.register_mechanism(SparkType::Service, std::move(mech)))
            ::_exit(91);
        spark_engine.start();

        GuardianEngine engine{&kv, "agent-death", /*prefer_spark=*/true};
        if (!engine.start_local())
            ::_exit(92);

        // The send runs ON the worker thread and reaches for mtx_ via journal_stats().
        engine.wire_spark_engine(&spark_engine, /*spark_disabled_by_config=*/false,
                                 [&engine](const OutboxEntry&) {
                                     (void)engine.journal_stats(); // takes mtx_ -> must abort
                                     return SendResult::Sent;
                                 });
        if (engine.spark_availability() != GuardianEngine::SparkAvailability::Available)
            ::_exit(93);

        // Arm a rule so an "armed" lifecycle entry enters the outbox and the worker drains it
        // through the hostile send.
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        *p.add_rules() = make_service_rule("r1");
        (void)yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString());

        // If the guard works we never get here - the worker aborts the whole process. Give it
        // a bounded window, then report "no abort" with a distinct code.
        std::this_thread::sleep_for(std::chrono::seconds(5));
        ::_exit(94);
    }

    // ---- parent ----
    // Poll rather than blocking in waitpid: if the guard has regressed, the child DEADLOCKS
    // (that being the bug) and a blocking wait would hang the whole suite instead of failing.
    int status = 0;
    bool reaped = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while (std::chrono::steady_clock::now() < deadline) {
        const pid_t r = ::waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            reaped = true;
            break;
        }
        REQUIRE(r == 0); // -1 would be a wait error, not a still-running child
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (!reaped) {
        ::kill(pid, SIGKILL);
        ::waitpid(pid, &status, 0);
        FAIL("child never exited: the worker took mtx_ and DEADLOCKED instead of aborting - "
             "exactly the fleet-wide shutdown hang WorkerHostileMutex exists to prevent");
    }

    INFO("child exit code (if it exited normally): " << (WIFEXITED(status) ? WEXITSTATUS(status)
                                                                          : -1));
    REQUIRE(WIFSIGNALED(status));            // died by signal, not a clean exit
    CHECK(WTERMSIG(status) == SIGABRT);      // and specifically via std::abort()
}

#endif // !_WIN32

TEST_CASE("PRODUCTION boot order: wire_spark_engine before start_local",
          "[spark][guardian][reconcile][journal][boot]") {
    // Every other test here (and SparkReconcileFixture itself) calls start_local() BEFORE
    // wire_spark_engine(). Production does the reverse - agent.cpp:969-1001 wires first and
    // documents it as a header contract - so the order that actually ships was untested
    // (#2298 Sol review).
    //
    // It matters because of C0: wire_spark_engine() start()s the drain worker, whose first
    // cycle runs IMMEDIATELY and does journal maintenance against the KvStore. start_local()
    // then loads cached rules and re-arms them from the SAME single-mutex KvStore. If that
    // contention delayed or broke the pre-network re-arm, it would mean enforcement gaps at
    // boot on every endpoint after the prefer_spark flip.
    const auto kv_path = unique_kv_path();
    yuzu::test::TempDbFile db{kv_path};

    // Phase 1: an engine that persists cached rules AND a durable journal, then goes away.
    {
        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        SparkEngine spark_engine;
        REQUIRE(spark_engine.register_mechanism(SparkType::Service,
                                                std::make_unique<FakeServiceMechanism>())
                    .has_value());
        spark_engine.start();
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
        REQUIRE(engine.start_local().has_value());
        engine.wire_spark_engine(&spark_engine, false,
                                 [](const OutboxEntry&) { return SendResult::Retain; });
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        for (int i = 0; i < 5; ++i)
            *p.add_rules() = make_service_rule("r" + std::to_string(i));
        REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString())
                    .exit_code == 0);
        engine.journal_maintenance_tick(); // force the pending records durable
        engine.stop();
        spark_engine.stop();
    }

    // Phase 2: a fresh boot in PRODUCTION order over that same store.
    auto opened = KvStore::open(kv_path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    REQUIRE(spark_engine.register_mechanism(SparkType::Service,
                                            std::make_unique<FakeServiceMechanism>())
                .has_value());
    spark_engine.start();

    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
    // WIRE FIRST - the worker starts here and immediately begins journal maintenance.
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

    // ...and only THEN the pre-network re-arm, racing that maintenance on one KvStore.
    const auto start = std::chrono::steady_clock::now();
    REQUIRE(engine.start_local().has_value());
    const auto elapsed = std::chrono::steady_clock::now() - start;

    // The re-arm must not have been starved by the boot maintenance scan. The KvStore busy
    // timeout is 5 s, so anything approaching it means the two are serialising badly.
    CHECK(elapsed < std::chrono::seconds(2));
    CHECK(engine.rule_count() == 5); // every cached rule came back

    // And the journal side still did its work rather than being crowded out.
    auto* journal = engine.lifecycle_journal_for_test();
    REQUIRE(journal != nullptr);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (journal->pages() == 0 && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    CHECK(journal->pages() >= 1);

    engine.stop();
    spark_engine.stop();
}

TEST_CASE("prefer_spark=true: pending records are durable BEFORE stop() joins the drain worker",
          "[spark][guardian][reconcile][journal][chaos]") {
    // stop() joins the drain worker, and that join is a blocking wait on a send that may be
    // blackholed. A persist placed only AFTER the join never runs if a supervisor's stop
    // timeout or an operator kill lands in that window, and the staged records are destroyed -
    // real loss of an audit record, not the at-least-once redelivery the design guarantees.
    //
    // The observable has to be taken WHILE the join is still blocked; asserting after stop()
    // returns cannot tell the two orderings apart, because the post-join flush persists the
    // same record either way. RED with the pre-join persist removed: the journal is still
    // empty on disk at the moment the join is stuck.
    yuzu::test::TempDbFile db{unique_kv_path()};
    auto opened = KvStore::open(db.path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};

    SparkEngine spark_engine;
    REQUIRE(spark_engine.register_mechanism(SparkType::Service,
                                            std::make_unique<FakeServiceMechanism>())
                .has_value());
    spark_engine.start();

    std::mutex send_mu;
    std::condition_variable send_cv;
    bool in_send = false;   ///< the worker is parked inside a send
    bool release = false;   ///< test lets it finish
    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, /*spark_disabled_by_config=*/false,
                             [&](const OutboxEntry&) {
                                 std::unique_lock<std::mutex> lk{send_mu};
                                 in_send = true;
                                 send_cv.notify_all();
                                 send_cv.wait(lk, [&] { return release; });
                                 return SendResult::Sent;
                             });

    // RAII safety net (mirrors OrphanExitGuard in agents/core/src/hard_exit.hpp):
    // the send callback above parks the drain worker on `release`. If a REQUIRE
    // below fires while the worker is en route to (or already parked in) that
    // callback, Catch2 unwinds this scope; without releasing the worker first,
    // ~GuardianEngine's stop()-join blocks on a `release` that never flips and
    // the still-live worker races the destruction of these stack-local sync
    // primitives - the #1648 non-Catch2 process exit (42) that defeats
    // flake-retry classification and hard-blocks the whole agent suite. Declared
    // AFTER `engine` so reverse-declaration-order destruction runs this FIRST:
    // the worker is released (then joined by ~GuardianEngine) while send_mu/
    // send_cv/release are still alive, so any assertion failure exits as an
    // ordinary, classifiable Catch2 failure instead of a crash.
    struct ReleaseParkedWorker {
        std::mutex& mu;
        std::condition_variable& cv;
        bool& release_flag;
        ~ReleaseParkedWorker() {
            {
                std::lock_guard<std::mutex> lk{mu};
                release_flag = true;
            }
            cv.notify_all();
        }
    } release_parked_worker{send_mu, send_cv, release};

    // One injected write failure leaves the armed rule's record PENDING rather than durable,
    // so what reaches disk later is attributable to a stop()-path persist and nothing else.
    engine.lifecycle_journal_for_test()->inject_write_failures_for_test(1);
    gpb::GuaranteedStatePush push;
    push.set_full_sync(true);
    *push.add_rules() = make_service_rule("r1");
    engine.apply_rules(push);
    REQUIRE(kv.list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix)->empty());

    {   // Park the worker inside a send, so the join below cannot complete.
        // Generous deadline: on a saturated Windows CI runner the drain worker can
        // be starved well past its ~5 s periodic backstop before it reaches the
        // send callback (box-contention flake, not a logic bug - see the WeeTam
        // agent-suite timeouts). The deadline is NOT shrunk by pinning the
        // backstop cadence: a short backstop would let the worker persist the
        // pending record on its own timer BEFORE the stop()-path persist, which
        // would defeat this test's whole attribution. If the worker still misses
        // this window, ReleaseParkedWorker above makes the failure exit cleanly.
        std::unique_lock<std::mutex> lk{send_mu};
        REQUIRE(send_cv.wait_for(lk, std::chrono::seconds(30), [&] { return in_send; }));
    }

    std::atomic<bool> stop_returned{false};
    std::thread stopper{[&] {
        engine.stop();
        stop_returned.store(true, std::memory_order_release);
    }};

    // The assertion: the record reaches disk while stop() is still stuck in the join.
    bool durable_during_join = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline) {
        auto rows = kv.list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix);
        if (rows.has_value() && !rows->empty()) {
            // Confirm the join really is still outstanding, so this cannot pass by observing
            // the POST-join flush of a stop() that had already returned.
            durable_during_join = !stop_returned.load(std::memory_order_acquire);
            break;
        }
        if (stop_returned.load(std::memory_order_acquire))
            break; // stop() finished with nothing on disk: the pre-join persist did not happen
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(durable_during_join);

    {
        std::lock_guard<std::mutex> lk{send_mu};
        release = true;
    }
    send_cv.notify_all();
    stopper.join();
    spark_engine.stop();
}
