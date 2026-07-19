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

#include <cstdlib>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

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

    SparkReconcileFixture() {
        auto opened = KvStore::open(db_.path);
        REQUIRE(opened.has_value());
        kv = std::make_unique<KvStore>(std::move(*opened));

        auto mech = std::make_unique<FakeServiceMechanism>();
        mechanism = mech.get();
        REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
        spark_engine.start();

        engine = std::make_unique<GuardianEngine>(kv.get(), "agent-test", /*prefer_spark=*/true);
        REQUIRE(engine->start_local().has_value());
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
    CHECK(before->empty()); // nothing durable yet — the write failed

    f.engine->journal_maintenance_tick(); // NO new push/reconnect — the tick alone retries

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

TEST_CASE("prefer_spark=true: page_journal runs a paging pass", "[spark][guardian][reconcile][journal]") {
    SparkReconcileFixture f;
    CHECK(f.engine->lifecycle_journal_for_test()->pages() == 0);
    f.engine->page_journal();
    CHECK(f.engine->lifecycle_journal_for_test()->pages() == 1); // it paged (not gated out)
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

    // Apply a rule + drive BOTH maintenance paths — none of it touches the journal.
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
