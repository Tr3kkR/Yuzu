// test_guardian_spark_runtime.cpp - the GuardianSparkRuntime core (ADR-0021 rung
// 3, hardened rung 4.5). Drives the runtime against fake IStateReader /
// ISparkBackend seams (owned via shared_ptr): arm/disarm edges, shared-watcher
// fan-out, evaluate_key verdict -> outbox -> drain, pending-initial, tri-state
// Unknown -> health, generation purge, cap/backpressure leaving an eval pending,
// detach-safety of a late handler EVEN when the reader ref is dropped, and a
// multi-threaded stress case that is the TSan checkpoint.

#include "guardian_spark_runtime.hpp"

#include <yuzu/agent/spark.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <latch>
#include <memory>
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
};

struct FakeBackend : ISparkBackend {
    std::atomic<std::uint64_t> next{1};
    std::atomic<int> arms{0};
    std::atomic<int> disarms{0};
    std::atomic<bool> fail_arm{false};
    std::expected<std::uint64_t, std::string> arm(const SparkSpec&) override {
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
std::vector<OutboxEntry> drain_all(GuardianSparkRuntime& rt) {
    std::vector<OutboxEntry> got;
    rt.drain([&](const OutboxEntry& e) {
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

TEST_CASE("on_event after begin_stop commits nothing", "[spark][runtime]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b);
    const auto key = spark_key(file_spec("/a"));
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rt->begin_stop();
    REQUIRE(rt->stopping());
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

    std::latch reading{1};
    std::latch release{1};
    r->on_read = [&] {
        reading.count_down();
        release.wait();
    };
    std::thread t([&] { rt->evaluate_key(key, EvalReason::Initial); });
    reading.wait();
    REQUIRE(provider_calls.load() == 1); // snapshotted BEFORE the read
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
