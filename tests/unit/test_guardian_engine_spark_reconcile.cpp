// test_guardian_engine_spark_reconcile.cpp - GuardianEngine's rung-7 reconcile
// op: the mutual-exclusion invariant between the spark and legacy IGuard
// detection paths. Tested against a REAL SparkEngine with a fake mechanism
// (Sol's rev-1 review resolution: this is the right vehicle, not a separate
// fake-backend injection seam - it exercises wire_spark_engine's real
// register_consumer/arm/disarm calls, not a shortcut around them).

#include <yuzu/agent/guardian_engine.hpp>
#include <yuzu/agent/kv_store.hpp>

#include "guaranteed_state.pb.h"
#include "guardian_backend.hpp" // guardian_backend_from_state/label (#2298 F13)
#include "guardian_convergence_scheduler.hpp" // ConvergenceScheduler (started_for_test, #2238)
#include "guardian_journal_format.hpp" // kJournalNamespace, parse_journal_batch (item 7 PR-Ag)
#include "guardian_journal_heartbeat.hpp" // emit_guardian_journal_heartbeat_tags (aggregate inertness)
#include "guardian_lifecycle_journal.hpp" // GuardianLifecycleJournal (for the _for_test fault seam)
#include "guardian_outbox.hpp" // OutboxEntry, SendResult - full definitions for the test's send_fn
#include "guardian_outbox_drain_worker.hpp" // GuardianOutboxDrainWorker (started_for_test, #2238)
#include "spark_engine.hpp"
#include "spark_mechanism.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
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
using yuzu::agent::make_file_mechanism;
using yuzu::agent::make_registry_mechanism;
using yuzu::agent::make_service_mechanism;
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
    std::set<std::string> watched_snapshot() {
        std::lock_guard<std::mutex> lk{mu_};
        return watched_;
    }

private:
    std::mutex mu_;
    std::set<std::string> watched_;
    bool fail_next_watch_{false};
};

// Service: the ONE type with a mechanism registered in this fixture -> Arm.
// `service` defaults to "Spooler" so every existing call site is unaffected;
// tests that need to distinguish which of several rules armed pass a distinct
// name (#2238 item 1 - three rules sharing one service name would all derive
// the same spark key and be indistinguishable in the mechanism's watch set).
gpb::GuaranteedStateRule make_service_rule(const std::string& id, bool enabled = true,
                                           const std::string& service = "Spooler") {
    gpb::GuaranteedStateRule r;
    r.set_rule_id(id);
    r.set_name(id);
    r.set_enabled(enabled);
    r.set_enforcement_mode("audit");
    r.mutable_spark()->set_type("service-status-change");
    auto* a = r.mutable_assertion();
    a->set_type("service-running");
    (*a->mutable_params())["service_name"] = service;
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

// Registry: also NO mechanism registered in this fixture -> also a routine
// Unsupported gap (F7). Field shape mirrors test_guardian_engine.cpp's
// make_registry_rule() so validation/spec derivation succeeds identically.
gpb::GuaranteedStateRule make_registry_rule(const std::string& id, bool enabled = true) {
    gpb::GuaranteedStateRule r;
    r.set_rule_id(id);
    r.set_name(id);
    r.set_enabled(enabled);
    r.set_enforcement_mode("audit");
    r.mutable_spark()->set_type("registry-change");
    auto* a = r.mutable_assertion();
    a->set_type("registry-value-equals");
    (*a->mutable_params())["hive"] = "HKCU";
    (*a->mutable_params())["key"] = "SOFTWARE\\YuzuTest\\GuardStatusTest";
    (*a->mutable_params())["value_name"] = "Flag";
    (*a->mutable_params())["value_type"] = "REG_DWORD";
    (*a->mutable_params())["expected"] = "1";
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

TEST_CASE("an unsupported type arms neither backend - a distinct terminal state, "
          "never a legacy fallback",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1"));

    // File has no mechanism registered in this fixture - a ROUTINE gap, terminal
    // per F7/#2298 rung 2: enforced by NEITHER backend (previously this test only
    // proved spark never claimed it and never checked armed_guard_count(), so it
    // passed identically under the old legacy-fallback behavior too).
    CHECK(f.engine->spark_armed_rule_count() == 0);
    CHECK(f.engine->armed_guard_count() == 0);
    CHECK(f.mechanism->watching_count() == 0);
    const auto counts = f.engine->unsupported_counts_by_type();
    REQUIRE(counts.count(SparkType::File) == 1);
    CHECK(counts.at(SparkType::File) == 1);
}

TEST_CASE("repeating the same unsupported rule keeps the count at one",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1"));
    REQUIRE(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);

    f.apply(make_file_rule("r1"), /*full_sync=*/false); // re-push, unchanged content
    CHECK(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1); // still 1, not 2
}

TEST_CASE("two unsupported rules of the same type aggregate to two",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1"));
    f.apply(make_file_rule("r2"), /*full_sync=*/false);
    CHECK(f.engine->unsupported_counts_by_type().at(SparkType::File) == 2);
}

TEST_CASE("an unsupported rule's type change moves the count between buckets, "
          "never double-counts",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1"));
    REQUIRE(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);

    // Same rule_id, spark type edited to a different (also-unsupported) type.
    // Registry has no mechanism registered in this fixture either.
    f.apply(make_registry_rule("r1"), /*full_sync=*/false);
    const auto counts = f.engine->unsupported_counts_by_type();
    CHECK(counts.count(SparkType::File) == 0);
    REQUIRE(counts.count(SparkType::Registry) == 1);
    CHECK(counts.at(SparkType::Registry) == 1);
}

TEST_CASE("unsupported -> Arm (mechanism becomes available) clears the count",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1"));
    REQUIRE(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);

    // Same rule_id, now a type WITH a mechanism registered in this fixture.
    f.apply(make_service_rule("r1"), /*full_sync=*/false);
    CHECK(f.engine->unsupported_counts_by_type().count(SparkType::File) == 0);
    CHECK(f.engine->spark_armed_rule_count() == 1);
}

TEST_CASE("unsupported -> disabled clears the count", "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1"));
    REQUIRE(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);

    f.apply(make_file_rule("r1", /*enabled=*/false), /*full_sync=*/false);
    CHECK(f.engine->unsupported_counts_by_type().count(SparkType::File) == 0);
}

TEST_CASE("unsupported -> invalid (unrecognized spark type) clears the count",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1"));
    REQUIRE(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);

    f.apply(make_invalid_rule("r1"), /*full_sync=*/false);
    CHECK(f.engine->unsupported_counts_by_type().count(SparkType::File) == 0);
}

TEST_CASE("full_sync omitting a previously-unsupported rule clears its count",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1"));
    REQUIRE(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);

    // A full_sync naming only a DIFFERENT rule must forget r1's unsupported
    // bookkeeping too, exactly like it withdraws a spark-armed rule the new
    // push omits (see the sibling full_sync test below).
    f.apply(make_service_rule("r2"), /*full_sync=*/true);
    CHECK(f.engine->unsupported_counts_by_type().count(SparkType::File) == 0);
}

TEST_CASE("full_sync retaining a still-unsupported rule stays idempotent",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1")); // full_sync #1
    REQUIRE(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);

    // A second full_sync retaining r1 unchanged: the count must stay exactly 1,
    // not double-count or drop it. NOTE what this does NOT verify: a blanket
    // unsupported_rules_.clear() before the per-rule loop (instead of the
    // precise post-loop sweep apply_rules actually uses) would make r1 look
    // "newly" unsupported and spuriously re-log on every full_sync, but it
    // converges to the SAME final count this asserts - the two designs are
    // indistinguishable by count alone. The log-edge-detection design (erase-
    // then-reinsert per outcome, sweep-not-blanket-clear on full_sync) is
    // verified by code inspection, not a runtime assertion here - this
    // codebase has no log-capture test seam to assert on spdlog output.
    f.apply(make_file_rule("r1"), /*full_sync=*/true);
    CHECK(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);
}

// Governance finding (quality-engineer, F7 #2298): the interaction between the new
// Unsupported branch and the pre-existing policy_generation hold-on-failure logic
// (apply_rules only advances policy_generation_ when reconcile_failures == 0) was
// previously asserted only in a code comment, never at runtime. An Unsupported
// classification returns false WITHOUT throwing, so it must never increment
// reconcile_failures and must never block generation advancement - holding the
// generation on an all-Unsupported push (e.g. every rule on macOS) would make that
// agent re-push forever.
TEST_CASE("an all-unsupported push still advances policy_generation, never holds it",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    REQUIRE(f.engine->policy_generation() == 0);

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    p.set_policy_generation(5);
    *p.add_rules() = make_file_rule("r1"); // unsupported: no mechanism in this fixture
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    CHECK(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);
    CHECK(f.engine->policy_generation() == 5); // advanced, not held
}

TEST_CASE("a production-order restart reconstructs unsupported_rules_ from cached KV",
          "[spark][guardian][reconcile][boot]") {
    // Mirrors "PRODUCTION boot order: wire_spark_engine before start_local" below -
    // unsupported_rules_ has no persisted representation of its own (it is derived
    // purely from re-running classify() against each cached rule during the
    // start_local() re-arm walk), so a restart must rebuild it correctly, in the
    // real wire-then-start_local order, not just the fixture's simplified order.
    const auto kv_path = unique_kv_path();
    yuzu::test::TempDbFile db{kv_path};

    // Phase 1: persist a rule that is unsupported in THIS process, then go away.
    {
        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        SparkEngine spark_engine; // no mechanism registered - file-change is unsupported
        spark_engine.start();
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
        REQUIRE(engine.start_local().has_value());
        engine.wire_spark_engine(&spark_engine, false,
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        *p.add_rules() = make_file_rule("r1");
        REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString())
                    .exit_code == 0);
        REQUIRE(engine.unsupported_counts_by_type().at(SparkType::File) == 1);
        engine.stop();
        spark_engine.stop();
    }

    // Phase 2: a fresh boot in PRODUCTION order (wire_spark_engine before start_local)
    // over that same store - no push this time, unsupported_rules_ must come back
    // purely from the start_local() re-arm walk over the cached rule.
    auto opened = KvStore::open(kv_path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    spark_engine.start();
    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);
    REQUIRE(engine.start_local().has_value());

    CHECK(engine.rule_count() == 1);
    CHECK(engine.spark_armed_rule_count() == 0);
    CHECK(engine.armed_guard_count() == 0);
    const auto counts = engine.unsupported_counts_by_type();
    REQUIRE(counts.count(SparkType::File) == 1);
    CHECK(counts.at(SparkType::File) == 1);

    engine.stop();
    spark_engine.stop();
}

TEST_CASE("start_local degrades per-rule when a re-arm throws: the other cached rules "
          "still arm",
          "[spark][guardian][reconcile][boot]") {
    // #2238 item 1 (fixes BLOCKING-2a): guardian_engine.cpp's start_local() catches a
    // std::system_error thrown while re-arming a single cached rule (modelling a legacy
    // guard's std::thread ctor throwing under thread/handle exhaustion) and continues to
    // the next rule instead of letting the throw escape and terminate the agent. Nothing
    // in production can force that throw deterministically (see the handover's survey of
    // guard_systemd.cpp / guard_file.cpp / guard_registry.cpp), so this drives it via
    // set_rearm_fault_hook_for_test, aimed at exactly one rule by id, and proves: (a)
    // start_local() still returns success, (b) the OTHER cached rules still arm, and (c)
    // an error is logged naming the failed rule.
    const auto kv_path = unique_kv_path();
    yuzu::test::TempDbFile db{kv_path};

    // Phase 1: seed three rules with distinct service names, all armable via spark.
    {
        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        SparkEngine spark_engine;
        auto mech = std::make_unique<FakeServiceMechanism>();
        REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
        spark_engine.start();
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
        REQUIRE(engine.start_local().has_value());
        engine.wire_spark_engine(&spark_engine, false,
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        *p.add_rules() = make_service_rule("r1", true, "SvcA");
        *p.add_rules() = make_service_rule("r2", true, "SvcB");
        *p.add_rules() = make_service_rule("r3", true, "SvcC");
        REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString())
                    .exit_code == 0);
        REQUIRE(engine.spark_armed_rule_count() == 3);
        engine.stop();
        spark_engine.stop();
    }

    // Phase 2: production order (wire_spark_engine before start_local), so spark is
    // Available during the re-arm walk and the un-poisoned rules can actually arm on
    // Linux (legacy guard start() stubs return false here - only the spark backend can
    // demonstrate "other rules still arm").
    auto opened = KvStore::open(kv_path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    auto mech = std::make_unique<FakeServiceMechanism>();
    FakeServiceMechanism* mechanism = mech.get();
    REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
    spark_engine.start();
    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

    engine.set_rearm_fault_hook_for_test([](const std::string& rule_id) {
        if (rule_id == "r2")
            throw std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again),
                                    "injected thread exhaustion");
    });

    REQUIRE(engine.start_local().has_value()); // degrade contract: success despite one poisoned rule

    // Assert BEFORE stop() - stop() unwinds spark watch state.
    CHECK(engine.rule_count() == 3);           // cache intact, including the poisoned rule
    CHECK(engine.spark_armed_rule_count() == 2); // r1 + r3 only
    const auto watched = mechanism->watched_snapshot();
    const bool has_a =
        std::any_of(watched.begin(), watched.end(), [](const std::string& k) { return k.find("SvcA") != std::string::npos; });
    const bool has_b =
        std::any_of(watched.begin(), watched.end(), [](const std::string& k) { return k.find("SvcB") != std::string::npos; });
    const bool has_c =
        std::any_of(watched.begin(), watched.end(), [](const std::string& k) { return k.find("SvcC") != std::string::npos; });
    CHECK(has_a);
    CHECK_FALSE(has_b); // the poisoned rule never armed
    CHECK(has_c);
    CHECK(mechanism->watching_count() == 2);

    // Read directly off the engine, not via spdlog: a captured-logger swap in the test
    // binary was found (macOS CI) to be invisible to spdlog:: calls made inside guardian_engine.cpp,
    // which is compiled into the separate libyuzu_agent_core shared library - the same class
    // of cross-image state-duplication problem as the #501 abseil hash-seed split. Plain
    // object-member state has no such hazard, hence last_rearm_degrade_message_for_test().
    // "re-armed=2" is deliberately not re-checked here - spark_armed_rule_count()==2 above
    // already proves the same fact more directly.
    const std::string degrade_msg = engine.last_rearm_degrade_message_for_test();
    CHECK(degrade_msg.find("r2") != std::string::npos);
    CHECK(degrade_msg.find("failed to re-arm") != std::string::npos);
    CHECK(degrade_msg.find("NOT enforcing") != std::string::npos);
    CHECK(degrade_msg.find("injected thread exhaustion") != std::string::npos);

    engine.set_rearm_fault_hook_for_test(nullptr);
    engine.stop();
    spark_engine.stop();
}

TEST_CASE("prefer_spark=false never populates unsupported_rules_, even for a type "
          "with no mechanism",
          "[spark][guardian][reconcile]") {
    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine; // no mechanism registered - file-change would be
                              // unsupported IF spark were consulted at all
    spark_engine.start();

    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/false}; // the production default
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = make_file_rule("r1");
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    // try_spark is false unconditionally when prefer_spark_ is false - classify()
    // is never even called, so this can never be "Unsupported" (a per-rule spark
    // classification outcome), it goes straight to the legacy-selected path.
    CHECK(engine.unsupported_counts_by_type().empty());

    engine.stop();
    spark_engine.stop();
}

#if defined(__APPLE__)
TEST_CASE("macOS: every mechanism is unsupported under spark preference - the real "
          "platform posture, not a fixture artifact",
          "[spark][guardian][reconcile][darwin]") {
    // Built WITHOUT SparkReconcileFixture (which always injects a FakeServiceMechanism
    // regardless of platform) - the whole point here is to prove the REAL platform
    // factories, exactly as agent.cpp's production try_register does at boot, all
    // three of which return nullptr on macOS (design doc §R2 consequence 3 / #2298).
    yuzu::test::TempDbFile db{unique_kv_path()};
    auto opened = KvStore::open(db.path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};

    SparkEngine spark_engine;
    const auto try_register = [&](SparkType type, std::unique_ptr<ISparkMechanism> mech) {
        if (mech)
            REQUIRE(spark_engine.register_mechanism(type, std::move(mech)).has_value());
    };
    try_register(SparkType::File, make_file_mechanism());
    try_register(SparkType::Registry, make_registry_mechanism());
    try_register(SparkType::Service, make_service_mechanism());
    spark_engine.start(); // all three factories return nullptr on macOS, so nothing
                          // actually got registered above - that IS the thing under test

    GuardianEngine engine{&kv, "agent-test-macos", /*prefer_spark=*/true};
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, /*spark_disabled_by_config=*/false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = make_file_rule("f1");
    *p.add_rules() = make_service_rule("s1");
    *p.add_rules() = make_registry_rule("r1");
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    CHECK(engine.spark_armed_rule_count() == 0);
    CHECK(engine.armed_guard_count() == 0);
    const auto counts = engine.unsupported_counts_by_type();
    CHECK(counts.at(SparkType::File) == 1);
    CHECK(counts.at(SparkType::Registry) == 1);
    CHECK(counts.at(SparkType::Service) == 1);
    // No explicit stop() calls: engine/spark_engine are plain stack locals declared
    // spark_engine-then-engine, so scope-exit destroys engine first, spark_engine
    // second - the exact order SparkReconcileFixture's own dtor comment documents as
    // required (Guardian's spark teardown must finish before the SparkEngine it
    // borrowed from is torn down), for free via normal RAII reverse-order destruction.
}
#endif // defined(__APPLE__)

TEST_CASE("SparkDisabled never populates unsupported_rules_ either",
          "[spark][guardian][reconcile]") {
    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    spark_engine.start();

    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
    REQUIRE(engine.start_local().has_value());
    engine.wire_spark_engine(&spark_engine, /*spark_disabled_by_config=*/true,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::SparkDisabled);

    gpb::GuaranteedStatePush p;
    p.set_full_sync(true);
    *p.add_rules() = make_file_rule("r1");
    auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString());
    REQUIRE(dr.exit_code == 0);

    // try_spark requires spark_availability_ == Available; SparkDisabled is not
    // Available regardless of prefer_spark_, so classify() is never reached here
    // either - the same code path as prefer_spark=false above.
    CHECK(engine.unsupported_counts_by_type().empty());

    engine.stop();
    spark_engine.stop();
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

TEST_CASE("a same-id replace from spark-armed to unsupported withdraws spark, "
          "lands in neither backend",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_service_rule("r1")); // spark-armed (service mechanism registered)
    REQUIRE(f.engine->spark_armed_rule_count() == 1);
    REQUIRE(f.engine->armed_guard_count() == 0);

    // Same rule_id, now a type with no mechanism registered - F7/#2298 rung 2:
    // a distinct terminal state, enforced by NEITHER backend, with the prior
    // spark attachment fully withdrawn. (Previously this test's name/premise
    // said "must land ONLY in legacy" and its assertions passed vacuously -
    // neither checked armed_guard_count(), so "neither" and "legacy" were
    // indistinguishable to it.)
    f.apply(make_file_rule("r1"), /*full_sync=*/false);
    CHECK(f.engine->spark_armed_rule_count() == 0);
    CHECK(f.engine->armed_guard_count() == 0); // proves "neither", not "legacy"
    CHECK(f.mechanism->watching_count() == 0);
    CHECK(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);
}

TEST_CASE("a same-id replace from unsupported to spark-armed arms cleanly, no "
          "stale state",
          "[spark][guardian][reconcile]") {
    SparkReconcileFixture f;
    f.apply(make_file_rule("r1")); // unsupported (no mechanism for file-change);
                                   // this fixture is permanently prefer_spark_=true
                                   // + Available, so a file rule here can only ever
                                   // land Unsupported post-F7, never legacy-armed -
                                   // the scenario this test used to exercise no
                                   // longer occurs on this fixture.
    REQUIRE(f.engine->spark_armed_rule_count() == 0);
    REQUIRE(f.engine->armed_guard_count() == 0);
    REQUIRE(f.engine->unsupported_counts_by_type().at(SparkType::File) == 1);

    // Same rule_id, now a spark-supported type - must land ONLY in spark, with
    // the prior unsupported bookkeeping cleared too.
    f.apply(make_service_rule("r1"), /*full_sync=*/false);
    CHECK(f.engine->spark_armed_rule_count() == 1);
    CHECK(f.engine->armed_guard_count() == 0);
    CHECK(f.mechanism->watching_count() == 1);
    CHECK(f.engine->unsupported_counts_by_type().count(SparkType::File) == 0);
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
    auto unsupported_count = [&] {
        std::uint64_t n = 0;
        for (const auto& [type, c] : f.engine->unsupported_counts_by_type()) n += c;
        return n;
    };
    auto invariant_holds = [&] {
        // Never more than one of {legacy-armed, spark-armed, unsupported} (F7 adds
        // the third state to the pre-existing mutual-exclusion invariant). Aggregate
        // counts - per-rule cross-checking isn't exposed, but with exactly one
        // rule_id active at a time in this test the aggregate sum bounds it directly.
        return (f.engine->armed_guard_count() + f.engine->spark_armed_rule_count() +
                unsupported_count()) <= 1;
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

    f.apply(make_file_rule("r1"), /*full_sync=*/false);                 // -> unsupported (F7)
    CHECK(invariant_holds());
    CHECK(f.engine->armed_guard_count() == 0);
    CHECK(f.engine->spark_armed_rule_count() == 0);
    CHECK(unsupported_count() == 1);

    f.apply(make_service_rule("r1"), /*full_sync=*/false);              // -> re-armed OK
    CHECK(invariant_holds());
    CHECK(f.engine->spark_armed_rule_count() == 1);
    CHECK(unsupported_count() == 0);
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

// ── Journal AGE gauges: dormancy is an ABSENCE (item 6 + #2364) ───────────────

TEST_CASE("journal_age_stats: present on a live prefer_spark worker, nullopt when dormant",
          "[spark][guardian][reconcile][journal]") {
    // prefer_spark=true + wired: the drain worker STARTED, its stamps are seeded, so the
    // age stats are PRESENT - including all-zero ages on a fresh worker (0 is a real
    // reading here; the emit layer ships the staleness pair including 0).
    {
        SparkReconcileFixture f;
        const auto ages = f.engine->journal_age_stats();
        REQUIRE(ages.has_value());
        // Fresh worker: ages in seconds must be tiny (the stamps were just seeded), and
        // no headroom episode exists.
        CHECK(ages->page_stale_seconds < 60);
        CHECK(ages->prune_stale_seconds < 60);
        CHECK(ages->headroom_blocked_seconds == 0);
        // COMPOSED with the real emitter (governance Gate 3 QE - the same
        // engine->emitter composition the counter family's aggregate-inertness test
        // pins): a live fresh worker ships EXACTLY the two staleness tags, including
        // their zero values, and no blocked tag.
        std::map<std::string, std::string> tags;
        yuzu::agent::emit_guardian_journal_age_tags(tags, ages);
        REQUIRE(tags.size() == 2);
        CHECK(tags.count("yuzu.guardian_journal_page_stale_seconds") == 1);
        CHECK(tags.count("yuzu.guardian_journal_prune_stale_seconds") == 1);
        CHECK(tags.count("yuzu.guardian_journal_headroom_blocked_seconds") == 0);
    }
    // prefer_spark=false + wired: the worker is CONSTRUCTED but never started (the flag
    // gates start()), and the ages must be ABSENT - not zero. This is the dormancy
    // posture that keeps a pre-flip fleet from paging on a "stale" inert journal: a
    // fabricated 0 would be wrong the other way (it claims a live fresh worker).
    {
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
        REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);
        const auto ages = engine.journal_age_stats();
        CHECK_FALSE(ages.has_value());
        // Composed: nullopt through the real emitter ships NOTHING - the dormancy
        // contract at the exact seam agent.cpp uses.
        std::map<std::string, std::string> tags;
        yuzu::agent::emit_guardian_journal_age_tags(tags, ages);
        CHECK(tags.empty());
        engine.stop();
        spark_engine.stop();
    }
}

TEST_CASE("wire_spark_engine constructs the spark workers unconditionally but starts them "
          "ONLY under prefer_spark",
          "[spark][guardian][reconcile]") {
    // #2238 item 2 (fixes BLOCKING-2b): the convergence scheduler + drain worker are
    // CONSTRUCTED in wire_spark_engine() regardless of prefer_spark_, but only START()ed
    // under the flag (guardian_engine.cpp's `if (prefer_spark_) { ...->start(); ...
    // ->start(); }`). Reverting that gate to always-start fails no other existing test
    // (journal_age_stats() short-circuits on !prefer_spark_ before it would ever see a
    // started-but-dormant worker). This drives both classes' started_for_test() directly.
    {
        // prefer_spark=false + wired: both constructed, neither started.
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
        REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

        REQUIRE(engine.drain_worker_for_test() != nullptr);
        REQUIRE(engine.convergence_scheduler_for_test() != nullptr);
        CHECK_FALSE(engine.drain_worker_for_test()->started_for_test());
        CHECK_FALSE(engine.convergence_scheduler_for_test()->started_for_test());

        engine.stop();
        spark_engine.stop();
    }
    {
        // prefer_spark=true (SparkReconcileFixture): both constructed AND started.
        SparkReconcileFixture f;
        REQUIRE(f.engine->drain_worker_for_test() != nullptr);
        REQUIRE(f.engine->convergence_scheduler_for_test() != nullptr);
        CHECK(f.engine->drain_worker_for_test()->started_for_test());
        CHECK(f.engine->convergence_scheduler_for_test()->started_for_test());
    }
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

TEST_CASE("prefer_spark=true: journaled event_ids embed the real agent_id (#2237)",
          "[spark][guardian][reconcile][journal]") {
    SparkReconcileFixture f; // constructed with agent_id "agent-test"
    f.apply(make_service_rule("r1"));

    auto rows = f.kv->list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix);
    REQUIRE(rows.has_value());
    REQUIRE_FALSE(rows->empty());

    bool found = false;
    for (const auto& row : *rows) {
        auto b = yuzu::agent::parse_journal_batch(row.value);
        REQUIRE(b.has_value());
        for (const auto& e : b->entries) {
            if (e.rule_id == "r1" && e.kind == "armed") {
                // make_event_id: "<agent_id>-<nonce>-<rule_id>-<wall_ms>-<seq>" - an
                // unwired provider (the pre-#2237 state) mints an empty-prefixed id
                // instead ("-<nonce>-r1-...").
                CHECK(e.event_id.starts_with("agent-test-"));
                found = true;
            }
        }
    }
    CHECK(found);
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
    const auto seed_key = yuzu::agent::journal_batch_key(1'700'000'000'000LL, "seed", 0);
    REQUIRE(kv.set(yuzu::agent::kJournalNamespace, seed_key,
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
    CHECK(kv.exists(yuzu::agent::kJournalNamespace, seed_key)); // seed untouched
    // A WELL-FORMED key on purpose: seeded with the retired pre-ts format this would
    // prove only "a row that prune would quarantine anyway is untouched", which is true
    // of a dormant journal for the wrong reason (governance Gate 3 architect/QE).

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

TEST_CASE("journal_stats() surfaces evicted_unclassified from the engine's real journal",
          "[spark][guardian][reconcile][journal]") {
    // The one plumbing seam the fleet-tags sizeof static_assert cannot cover: the
    // GuardianEngine::journal_stats() assignment that copies the journal's counter into the
    // struct. Every other test reads the journal accessor or builds GuardianJournalStats
    // directly, so a dropped assignment there leaves them all green while the sparse emitter
    // ships field 0 -> the fleet gauge is permanently ABSENT, reading as "nothing to report".
    // This drives the engine's OWN journal to one unclassified eviction and asserts it arrives
    // through journal_stats(). Deleting the assignment turns this red (item 3, consult gap 1).
    auto opened = KvStore::open(unique_kv_path());
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};
    SparkEngine spark_engine;
    REQUIRE(spark_engine.register_mechanism(SparkType::Service,
                                            std::make_unique<FakeServiceMechanism>())
                .has_value());
    spark_engine.start();
    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/false};
    REQUIRE(engine.start_local().has_value());
    // Wiring the spark path is what constructs the lifecycle journal (prefer_spark=false only
    // gates the drain worker's start, not the journal), so journal_stats() has a real source.
    engine.wire_spark_engine(&spark_engine, /*spark_disabled_by_config=*/false,
                             [](const OutboxEntry&) { return SendResult::Sent; });

    auto* journal = engine.lifecycle_journal_for_test();
    REQUIRE(journal != nullptr);
    journal->set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/0,
                                           /*max_bytes=*/std::numeric_limits<std::size_t>::max(),
                                           /*max_quarantine=*/100); // count cap 0 -> evict all
    const std::vector<std::shared_ptr<const yuzu::agent::JournalRecord>> pending{
        std::make_shared<const yuzu::agent::JournalRecord>(yuzu::agent::JournalRecord{
            .rule_id = "r1", .generation = 1, .event_id = "e1", .enqueued_ns = 1,
            .kind = "armed", .guard_type = "file", .rule_name = "n"})};
    REQUIRE(journal->persist(pending, nullptr, yuzu::agent::kJournalPersistUnbounded,
                             yuzu::agent::kJournalPersistUnbounded) == 1);
    // A correlated scan+read failure makes the single evicted batch land in unclassified. This
    // seam drives only the READ-FAILURE cause of unclassified; the shutdown-mid-pass and
    // throw-mid-classification causes are pinned at the component level in
    // test_guardian_lifecycle_journal.cpp. That is sufficient here because the plumbing line
    // under test (journal_stats()'s assignment) is cause-agnostic - it copies one atomic.
    journal->inject_prune_sent_scan_failures_for_test(1);
    journal->inject_prune_sent_read_failures_for_test(5);
    REQUIRE(journal->prune(0).evicted == 1);
    REQUIRE(journal->evicted_unclassified() == 1);

    CHECK(engine.journal_stats().evicted_unclassified == 1); // the assignment under test

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
        // Distinct service names: the "Spooler" default collapses all five rules
        // onto ONE spark key, and phase 2 needs to prove five DISTINCT re-watches
        // survived the restart, not merely that some watch reappeared (#2298 F13).
        for (int i = 0; i < 5; ++i)
            *p.add_rules() = make_service_rule("r" + std::to_string(i), true,
                                               "Svc" + std::to_string(i));
        REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString())
                    .exit_code == 0);
        REQUIRE(engine.spark_armed_rule_count() == 5); // armed via spark BEFORE the restart
        engine.journal_maintenance_tick(); // force the pending records durable
        engine.stop();
        spark_engine.stop();
    }

    // Phase 2: a fresh boot in PRODUCTION order over that same store.
    auto opened = KvStore::open(kv_path);
    REQUIRE(opened.has_value());
    KvStore kv{std::move(*opened)};

    // The durable journal must SURVIVE the restart (#2298 F13 goal 2). Read it from
    // raw KV BEFORE constructing anything else: the phase-2 drain worker's first
    // maintenance cycle pages/prunes immediately on wire, so reading after any
    // engine exists would race that cycle instead of proving pre-restart durability.
    {
        auto surviving =
            kv.list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix);
        REQUIRE(surviving.has_value());
        REQUIRE_FALSE(surviving->empty());
        bool survived_armed_r0 = false;
        for (const auto& row : *surviving) {
            auto b = yuzu::agent::parse_journal_batch(row.value);
            REQUIRE(b.has_value());
            for (const auto& e : b->entries)
                if (e.rule_id == "r0" && e.kind == "armed") survived_armed_r0 = true;
        }
        CHECK(survived_armed_r0);
    }

    SparkEngine spark_engine;
    auto mech2 = std::make_unique<FakeServiceMechanism>();
    auto* mechanism2 = mech2.get(); // borrowed; owned by spark_engine
    REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech2)).has_value());
    spark_engine.start();

    GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
    // WIRE FIRST - the worker starts here and immediately begins journal maintenance.
    engine.wire_spark_engine(&spark_engine, false,
                             [](const OutboxEntry&) { return SendResult::Sent; });
    REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);

    // Spark machinery is running in the exact production window (post-wire,
    // pre-start_local) - the direct observable that re-arm below runs against a
    // LIVE spark backend, not one still spinning up.
    REQUIRE(engine.drain_worker_for_test() != nullptr);
    REQUIRE(engine.convergence_scheduler_for_test() != nullptr);
    CHECK(engine.drain_worker_for_test()->started_for_test());
    CHECK(engine.convergence_scheduler_for_test()->started_for_test());

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

    // The core F13 gap: rule_count() only proves the rules were RE-DISCOVERED. Prove
    // they RE-ARMED VIA SPARK - mutual exclusion held, and each of the five distinct
    // services is actually re-watched by the (new, phase-2) mechanism.
    CHECK(engine.spark_armed_rule_count() == 5);
    CHECK(engine.armed_guard_count() == 0);
    CHECK(engine.unsupported_counts_by_type().empty());
    const auto watched = mechanism2->watched_snapshot();
    CHECK(mechanism2->watching_count() == 5);
    for (int i = 0; i < 5; ++i) {
        const std::string svc = "Svc" + std::to_string(i);
        CHECK(std::any_of(watched.begin(), watched.end(),
                          [&](const std::string& key) { return key.find(svc) != std::string::npos; }));
    }
    CHECK(std::string_view{yuzu::agent::guardian_backend_label(yuzu::agent::guardian_backend_from_state(
              /*prefer_spark=*/true, engine.spark_availability()))} == "spark");

    engine.stop();
    spark_engine.stop();
}

TEST_CASE("a production-order restart into each degraded spark posture: cached rules "
          "survive but spark NEVER half-arms",
          "[spark][guardian][reconcile][boot]") {
    // #2298 F13. The Available posture across a restart is covered above ("PRODUCTION
    // boot order") and by "start_local degrades per-rule when a re-arm throws" (partial
    // re-arm). This covers the other three SparkAvailability postures - SparkDisabled,
    // SparkFailed, and BOTH shapes of Unwired - proving each is not just reported
    // correctly on a single boot (see "wire_spark_engine reports Available; ..." above)
    // but survives a restart with the mutual-exclusion invariant intact: a degraded
    // posture NEVER silently falls back to legacy, and it never half-arms on spark
    // either.
    //
    // Every leg re-checks spark_availability() AFTER start_local() too, not just after
    // wire - stop()/start_local() never write spark_availability_, so pinning it twice
    // is what "correct ACROSS a restart" means literally, not just "correct at wire time".
    const auto seed_armed_rules = [](const fs::path& kv_path) {
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
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Available);
        gpb::GuaranteedStatePush p;
        p.set_full_sync(true);
        *p.add_rules() = make_service_rule("r1", true, "SvcA");
        *p.add_rules() = make_service_rule("r2", true, "SvcB");
        *p.add_rules() = make_service_rule("r3", true, "SvcC");
        REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, p.SerializeAsString())
                    .exit_code == 0);
        REQUIRE(engine.spark_armed_rule_count() == 3); // armed via spark BEFORE the restart
        engine.stop();
        spark_engine.stop();
    };

    { // SparkDisabled: --spark-disable at boot. Legacy is the CORRECT path here, not a
      // fallback (guardian_engine.hpp's SparkDisabled doc), so armed_guard_count() is
      // deliberately NOT asserted - Linux's legacy guard start() stubs return false
      // (this file's other SparkDisabled-adjacent tests hit the same trap), so the only
      // portable assertion is that spark itself was never touched.
        const auto kv_path = unique_kv_path();
        yuzu::test::TempDbFile db{kv_path};
        seed_armed_rules(kv_path);

        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
        engine.wire_spark_engine(nullptr, /*spark_disabled_by_config=*/true,
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::SparkDisabled);
        REQUIRE(engine.start_local().has_value());

        CHECK(engine.spark_availability() == GuardianEngine::SparkAvailability::SparkDisabled);
        CHECK(engine.rule_count() == 3); // cache intact
        CHECK(engine.spark_armed_rule_count() == 0);
        CHECK(engine.unsupported_counts_by_type().empty()); // legacy-selected, not Unsupported
        CHECK(engine.drain_worker_for_test() == nullptr);
        CHECK(engine.convergence_scheduler_for_test() == nullptr);
        CHECK(engine.lifecycle_journal_for_test() == nullptr); // wire returns before construction
        CHECK_FALSE(engine.journal_age_stats().has_value());
        CHECK(std::string_view{yuzu::agent::guardian_backend_label(
                  yuzu::agent::guardian_backend_from_state(true, engine.spark_availability()))} ==
              "legacy");
        engine.stop();
    }

    { // SparkFailed (null-engine path): the boot machinery itself failed to construct.
      // Errored, NEVER a silent fallback to legacy - the reconcile mutual-exclusion
      // guard withdraws from BOTH backends.
        const auto kv_path = unique_kv_path();
        yuzu::test::TempDbFile db{kv_path};
        seed_armed_rules(kv_path);

        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
        engine.wire_spark_engine(nullptr, /*spark_disabled_by_config=*/false, // boot failed
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::SparkFailed);
        REQUIRE(engine.start_local().has_value());

        CHECK(engine.spark_availability() == GuardianEngine::SparkAvailability::SparkFailed);
        CHECK(engine.rule_count() == 3); // cache intact
        CHECK(engine.spark_armed_rule_count() == 0);
        CHECK(engine.armed_guard_count() == 0); // withdrawn from BOTH backends, never legacy fallback
        CHECK(engine.unsupported_counts_by_type().empty());
        CHECK(engine.drain_worker_for_test() == nullptr);
        CHECK(engine.convergence_scheduler_for_test() == nullptr);
        CHECK(engine.lifecycle_journal_for_test() == nullptr); // null-engine branch returns first
        CHECK_FALSE(engine.journal_age_stats().has_value());
        CHECK(std::string_view{yuzu::agent::guardian_backend_label(
                  yuzu::agent::guardian_backend_from_state(true, engine.spark_availability()))} ==
              "spark_failed");
        // The durable journal records from phase 1 (seed_armed_rules never called
        // wire_spark_engine, so no journal existed - nothing to check here) are moot for
        // this leg; the durability-survives-restart assertion lives in the extended
        // "PRODUCTION boot order" test above.
        engine.stop();
    }

    { // Unwired shape (a): never wired at all - the reconcile walk RUNS (rule_count()
      // loads from cache) but the mutual-exclusion guard withdraws every rule from both
      // backends, because SparkFailed/Unwired are NEVER a fallback path.
        const auto kv_path = unique_kv_path();
        yuzu::test::TempDbFile db{kv_path};
        seed_armed_rules(kv_path);

        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};
        REQUIRE(engine.spark_availability() == GuardianEngine::SparkAvailability::Unwired);
        REQUIRE(engine.start_local().has_value());

        CHECK(engine.spark_availability() == GuardianEngine::SparkAvailability::Unwired);
        CHECK(engine.rule_count() == 3); // the walk ran and loaded the cache
        CHECK(engine.spark_armed_rule_count() == 0);
        CHECK(engine.armed_guard_count() == 0);
        CHECK(engine.unsupported_counts_by_type().empty());
        CHECK(engine.drain_worker_for_test() == nullptr);
        CHECK(engine.convergence_scheduler_for_test() == nullptr);
        CHECK(engine.lifecycle_journal_for_test() == nullptr);
        CHECK_FALSE(engine.journal_age_stats().has_value());
        CHECK(std::string_view{yuzu::agent::guardian_backend_label(
                  yuzu::agent::guardian_backend_from_state(true, engine.spark_availability()))} ==
              "unwired");
        engine.stop();
    }

    { // Unwired shape (b): the SIGTERM-beats-boot race - stop() lands before
      // wire_spark_engine(), which is sticky and no-ops. A real concurrent stop() would
      // simply block on the same mutex until start_local()'s walk finished, so a
      // sequential stop() before wire reproduces the race's only observable effect
      // faithfully (see stopped_'s two guard sites in guardian_engine.cpp).
        const auto kv_path = unique_kv_path();
        yuzu::test::TempDbFile db{kv_path};
        seed_armed_rules(kv_path);

        auto opened = KvStore::open(kv_path);
        REQUIRE(opened.has_value());
        KvStore kv{std::move(*opened)};
        SparkEngine spark_engine; // a healthy engine, offered but never touched
        auto mech = std::make_unique<FakeServiceMechanism>();
        auto* mechanism = mech.get();
        REQUIRE(spark_engine.register_mechanism(SparkType::Service, std::move(mech)).has_value());
        spark_engine.start();
        GuardianEngine engine{&kv, "agent-test", /*prefer_spark=*/true};

        engine.stop(); // SIGTERM beat boot; sets the sticky stopped_ flag
        engine.wire_spark_engine(&spark_engine, /*spark_disabled_by_config=*/false,
                                 [](const OutboxEntry&) { return SendResult::Sent; });
        CHECK(engine.spark_availability() == GuardianEngine::SparkAvailability::Unwired); // no-oped

        REQUIRE(engine.start_local().has_value()); // sticky-stop early return: SUCCESS, not an error

        CHECK(engine.spark_availability() == GuardianEngine::SparkAvailability::Unwired);
        CHECK(engine.rule_count() == 0); // the walk never ran - refresh_count_locked() never fired
        CHECK(engine.spark_armed_rule_count() == 0);
        CHECK(engine.armed_guard_count() == 0);
        CHECK(engine.unsupported_counts_by_type().empty());
        CHECK(engine.drain_worker_for_test() == nullptr);
        CHECK(engine.convergence_scheduler_for_test() == nullptr);
        CHECK(engine.lifecycle_journal_for_test() == nullptr);
        CHECK_FALSE(engine.journal_age_stats().has_value());
        CHECK(mechanism->watching_count() == 0); // offered, but the sticky stop kept it untouched
        CHECK(std::string_view{yuzu::agent::guardian_backend_label(
                  yuzu::agent::guardian_backend_from_state(true, engine.spark_availability()))} ==
              "unwired");
        spark_engine.stop();
    }
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

    // A fatal assertion at the wait boundary can unwind while the worker is racing into
    // the parked callback. Declared after engine so this releases the worker before
    // ~GuardianEngine joins it, while send_mu/send_cv/release are still alive.
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
    // Serialize-then-dispatch because the rule carries a protobuf Map; see the fixture's
    // apply() helper above for the Windows EXE/DLL abseil hash-seed boundary.
    REQUIRE(yuzu::agent::guardian_dispatch_push_bytes_for_test(engine, push.SerializeAsString())
                .exit_code == 0);
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

TEST_CASE("start-drain-then-stop: the this-capturing send races stop()'s join (TSan "
          "checkpoint)",
          "[spark][guardian][reconcile][drain][tsan]") {
    // #2238 item 3: no test started the drain worker with a REAL this-capturing send and
    // raced a stop()/teardown against an in-flight send. The literal production callback
    // (AgentImpl::send_guardian_outbox_entry, agent.cpp) is unlinkable from unit tests -
    // AgentImpl is file-local to agent.cpp with zero test references - so this drives the
    // fixture-level this-capturing send instead: SparkReconcileFixture's send lambda
    // captures `this` and writes through a mutex-guarded vector, the same shape as
    // production's stream_write_mu_-guarded write (agent.cpp's send_guardian_outbox_entry).
    // Licensed by the drain contract (guardian_outbox_drain_worker.hpp): send MAY capture
    // `this` because stop() always synchronously joins the worker before the callback's
    // captures can dangle.
    //
    // Asserts liveness only - no timing upper bound, no exact send count (standing flake
    // doctrine; see the drain-worker file's jitter-race test). This exists so nightly TSan
    // actually DRIVES the start-drain-then-stop race, "safe by inspection" being the same
    // posture the drain-worker file's own [tsan] checkpoints take for worker-vs-reader and
    // worker-vs-persister races.
    SparkReconcileFixture f{/*periodic_bound_ms=*/1};

    // Two independent dispatch threads contend against the live drain worker + 4
    // convergence-scheduler lanes. The pusher thread must NOT use Catch2 assertion
    // macros (REQUIRE/CHECK) - those are main-thread-only - so it records raw exit codes
    // for the main thread to assert after joining it.
    std::mutex pusher_mu;
    std::vector<int> pusher_exit_codes;
    std::thread pusher{[&] {
        for (int i = 0; i < 6; ++i) {
            gpb::GuaranteedStatePush p;
            p.set_full_sync(false);
            *p.add_rules() = make_service_rule("p" + std::to_string(i), true,
                                               "SvcP" + std::to_string(i));
            auto dr = yuzu::agent::guardian_dispatch_push_bytes_for_test(*f.engine,
                                                                         p.SerializeAsString());
            std::lock_guard<std::mutex> lk{pusher_mu};
            pusher_exit_codes.push_back(dr.exit_code);
        }
    }};
    // A fatal assertion in the main-thread loop below (f.apply()'s REQUIRE) can unwind
    // while pusher is still running. Join on scope exit so an unwind cannot destroy a
    // joinable std::thread (std::terminate) and mask the real assertion failure behind
    // a raw abort - same shape as ReleaseParkedWorker earlier in this file.
    struct JoinOnExit {
        std::thread& t;
        ~JoinOnExit() {
            if (t.joinable())
                t.join();
        }
    } join_pusher_on_exit{pusher};
    for (int i = 0; i < 6; ++i)
        f.apply(make_service_rule("m" + std::to_string(i), true, "SvcM" + std::to_string(i)),
                /*full_sync=*/false);

    // Test-side lifetime only: the pusher thread dereferences f.engine, so it must finish
    // before anything tears that down - not a production ordering constraint. Redundant
    // with JoinOnExit's destructor on the non-throwing path (join() on an already-joined
    // thread throws std::system_error, but joinable() is false by then, so the guard's
    // join is skipped).
    pusher.join();
    {
        std::lock_guard<std::mutex> lk{pusher_mu};
        for (int code : pusher_exit_codes)
            CHECK(code == 0);
    }

    REQUIRE(yuzu::test::spin_until([&] {
        std::lock_guard<std::mutex> lk{f.sent_mu};
        return !f.sent.empty();
    }));

    // Immediately tear down while sends may be in flight: ~GuardianEngine's stop() holds
    // mtx_ across scheduler stop + the drain worker's join, racing whatever send is
    // mid-callback right now. This is the race under test.
    f.engine.reset();

    std::lock_guard<std::mutex> lk{f.sent_mu};
    CHECK(!f.sent.empty());
    for (const auto& e : f.sent)
        CHECK(!e.event_id.empty());
}
