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
#include <atomic>
#include <chrono>
#include <future>
#include <latch>
#include <memory>
#include <set>
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

struct FakeBackend : ISparkBackend {
    std::atomic<std::uint64_t> next{1};
    std::atomic<int> arms{0};
    std::atomic<int> disarms{0};
    std::atomic<bool> fail_arm{false};
    std::atomic<bool> throw_arm{false}; ///< arm() throws (a backend that throws, not just fails)
    std::expected<std::uint64_t, std::string> arm(const SparkSpec&) override {
        if (throw_arm.load()) throw std::runtime_error("arm boom");
        if (fail_arm.load()) return std::unexpected(std::string{"no mechanism"});
        arms.fetch_add(1);
        return next.fetch_add(1);
    }
    void disarm(std::uint64_t) override { disarms.fetch_add(1); }
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
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);

    b->throw_arm = true;
    CHECK_THROWS_AS(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true),
                    std::runtime_error);
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
    CHECK_THROWS(rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true));
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
