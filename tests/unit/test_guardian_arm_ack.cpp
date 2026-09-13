// test_guardian_arm_ack.cpp - rung 9c PR-2 Unit 5 (ack bookkeeping preparation,
// docs/spark-stage2-guardian-consumer-design.md §R5.3). GuardianArmAckLedger and
// guardian_push_content_id() are exercised directly here, against a real
// GuardianSparkRuntime + a minimal fake backend (genuine ArmReceipts via
// attach_rule(NonWaiting, ...), not faked statuses) - PREPARATION ONLY: nothing
// here wires the ledger into GuardianEngine::apply_rules() (that is Unit 6).

#include "guardian_arm_ack.hpp"

#include "guaranteed_state.pb.h"

#include <yuzu/agent/spark.hpp>

#include "test_helpers.hpp" // yuzu::test::spin_until

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

using namespace yuzu::agent;
namespace gpb = ::yuzu::guardian::v1;

namespace {

struct FakeReader : IStateReader {
    ReadResult<FileSnapshot> read_file(const FileSparkParams&, const FileReadPlan&) override {
        return read_known(FileSnapshot{.exists = true});
    }
    RegistryRead read_registry(const RegistrySparkParams&, const RegistryReadPlan& plan) override {
        RegistryRead out;
        for (const auto& vn : plan.value_names)
            out.values.emplace(vn, read_known(RegistrySnapshot{.present = true, .value = "v"}));
        return out;
    }
    ReadResult<ServiceRunState> read_service(const ServiceSparkParams&) override {
        return read_known(ServiceRunState::Running);
    }
    void request_stop() noexcept override {}
};

// Minimal fake, sized for this file only (test_guardian_convergence_scheduler.cpp's own
// precedent: each consumer of GuardianSparkRuntime writes its own lean fake rather than
// sharing test_guardian_spark_runtime.cpp's full-featured one). A single hang gate is
// enough - Unit 5's ledger tests need "accepted, still pending" and "later resolves",
// not the soak/lane machinery the runtime's own test suite exercises.
struct FakeBackend : ISparkBackend {
    std::atomic<std::uint64_t> next{1};
    std::atomic<bool> fail_arm{false};
    std::atomic<bool> hang_next_arm{false};
    /// Unlike hang_next_arm (single-shot, consumed by the first caller), this parks
    /// EVERY arm() call - needed for the bounded-drain test below, which needs several
    /// independent keys simultaneously Pending, not just one.
    std::atomic<bool> hang_every_arm{false};
    std::atomic<int> parked{0};
    std::mutex gate_mu_;
    std::condition_variable gate_cv_;
    bool entered_hang_{false};
    bool released_{false};

    std::expected<std::uint64_t, std::string> arm(const SparkSpec&) override {
        if (hang_next_arm.exchange(false) || hang_every_arm.load()) {
            std::unique_lock<std::mutex> lk{gate_mu_};
            entered_hang_ = true;
            ++parked;
            gate_cv_.notify_all();
            gate_cv_.wait(lk, [this] { return released_; });
        }
        if (fail_arm.load())
            return std::unexpected(std::string{"no mechanism"});
        return next.fetch_add(1);
    }
    void disarm(std::uint64_t) override {}

    bool wait_entered_hang(std::chrono::seconds timeout) {
        std::unique_lock<std::mutex> lk{gate_mu_};
        return gate_cv_.wait_for(lk, timeout, [this] { return entered_hang_; });
    }
    bool wait_parked(int n, std::chrono::seconds timeout) {
        std::unique_lock<std::mutex> lk{gate_mu_};
        return gate_cv_.wait_for(lk, timeout, [this, n] { return parked.load() >= n; });
    }
    void release_hang() {
        {
            std::lock_guard<std::mutex> lk{gate_mu_};
            released_ = true;
        }
        gate_cv_.notify_all();
    }
};

SparkSpec file_spec(const std::string& path) {
    return SparkSpec{SparkType::File, FileSparkParams{path}};
}
RuleAssertion file_exists_rule(const std::string& rule_id) {
    RuleAssertion a;
    a.kind = AssertionKind::FileExists;
    a.rule_id = rule_id;
    a.expect_present = true;
    return a;
}

std::shared_ptr<GuardianSparkRuntime> make_rt(std::shared_ptr<FakeReader> r,
                                              std::shared_ptr<FakeBackend> b,
                                              GuardianSparkRuntime::Config cfg = {}) {
    return std::make_shared<GuardianSparkRuntime>(std::move(r), std::move(b), cfg);
}

/// Accept rule_id via attach_rule(NonWaiting, ...) and REQUIRE it came back Accepted
/// (a parked FakeBackend arm never resolves synchronously). Returns the receipt.
GuardianSparkRuntime::ArmReceipt accept(GuardianSparkRuntime& rt, const std::string& rule_id,
                                        const std::string& path = "/a") {
    auto res = rt.attach_rule(GuardianSparkRuntime::NonWaiting{}, rule_id, file_spec(path),
                              file_exists_rule(rule_id), true);
    REQUIRE(res.has_value());
    REQUIRE(res->kind == GuardianSparkRuntime::ArmOutcomeKind::Accepted);
    return res->receipt;
}

/// A minimal single-rule push, for guardian_push_content_id() and decide_retry() tests.
gpb::GuaranteedStatePush one_rule_push(const std::string& rule_id, const std::string& param_value,
                                       bool full_sync = false) {
    gpb::GuaranteedStatePush push;
    push.set_full_sync(full_sync);
    auto* rule = push.add_rules();
    rule->set_rule_id(rule_id);
    rule->set_enabled(true);
    rule->set_enforcement_mode("enforce");
    rule->set_version(1);
    rule->mutable_spark()->set_type("file-change");
    rule->mutable_spark()->mutable_params()->insert({"path", param_value});
    rule->mutable_assertion()->set_type("file-exists");
    return push;
}

} // namespace

TEST_CASE("guardian_push_content_id(): identical content hashes identically "
          "regardless of param insertion order",
          "[spark][ack]") {
    gpb::GuaranteedStatePush a;
    a.set_full_sync(false);
    auto* ra = a.add_rules();
    ra->set_rule_id("r1");
    ra->set_enabled(true);
    ra->set_enforcement_mode("enforce");
    ra->set_version(1);
    ra->mutable_spark()->set_type("file-change");
    ra->mutable_spark()->mutable_params()->insert({"path", "/a"});
    ra->mutable_spark()->mutable_params()->insert({"recursive", "true"});

    gpb::GuaranteedStatePush b;
    b.set_full_sync(false);
    auto* rb = b.add_rules();
    rb->set_rule_id("r1");
    rb->set_enabled(true);
    rb->set_enforcement_mode("enforce");
    rb->set_version(1);
    rb->mutable_spark()->set_type("file-change");
    rb->mutable_spark()->mutable_params()->insert({"recursive", "true"}); // reversed insertion order
    rb->mutable_spark()->mutable_params()->insert({"path", "/a"});

    CHECK(guardian_push_content_id(a) == guardian_push_content_id(b));
}

TEST_CASE("guardian_push_content_id(): a changed param value changes the id; "
          "full_sync alone also changes it",
          "[spark][ack]") {
    const auto base = one_rule_push("r1", "/a");
    const auto changed_param = one_rule_push("r1", "/b");
    const auto changed_full_sync = one_rule_push("r1", "/a", /*full_sync=*/true);

    const auto id_base = guardian_push_content_id(base);
    CHECK(id_base == guardian_push_content_id(one_rule_push("r1", "/a"))); // stable, reproducible
    CHECK(id_base != guardian_push_content_id(changed_param));
    CHECK(id_base != guardian_push_content_id(changed_full_sync));
}

TEST_CASE("GuardianArmAckLedger: a superseded application's stale receipt cannot "
          "satisfy the NEW application, even once it commits",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_every_arm.store(true); // r1 (gen 1) and r2 (gen 2) both need to park independently
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    GuardianArmAckLedger ledger;
    ledger.begin_application(/*generation=*/1, "content-a", /*full_sync=*/false, /*applied=*/1);
    auto r1 = accept(*rt, "r1", "/a");
    ledger.add_pending("r1", r1);
    CHECK_FALSE(ledger.can_advance()); // r1 still pending

    // A higher-generation application supersedes it before r1 ever resolves - r1's own
    // claim is NOT re-added to generation 2; generation 2 gets its own, different rule.
    ledger.begin_application(/*generation=*/2, "content-b", /*full_sync=*/false, /*applied=*/1);
    auto r2 = accept(*rt, "r2", "/b");
    ledger.add_pending("r2", r2);
    CHECK_FALSE(ledger.can_advance()); // r2 still pending - not vacuously true
    REQUIRE(b->wait_parked(2, std::chrono::seconds(30)));

    // Release both - r1 (generation 1's own claim, no longer watched by any ledger) and
    // r2 (generation 2's own claim) resolve independently.
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(r1) && rt->is_terminal(r2); },
                                   std::chrono::seconds(10)));

    // Draining generation 2's ledger must resolve EXACTLY r2 - r1's commit was never
    // added to this application's pending map, so it is neither seen nor counted here.
    CHECK(ledger.drain_locked(*rt, /*max_per_tick=*/10) == 1);
    CHECK(ledger.can_advance());
    CHECK(ledger.applied_count() == 1); // generation 2's own stashed count, unaffected by r1
}

TEST_CASE("GuardianArmAckLedger: can_advance() is false with zero pending, zero "
          "armed, and one resolved failure - never vacuously true",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    // Hang first so attach_core's own completion-before-return race always resolves
    // to Accepted (the worker cannot possibly finish before it's released), THEN flip
    // fail_arm before releasing - a genuinely asynchronous Failed resolution.
    b->hang_next_arm.store(true);
    auto receipt = accept(*rt, "r1");
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));
    b->fail_arm.store(true);
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(receipt); }, std::chrono::seconds(10)));
    REQUIRE(rt->receipt_status(receipt) == GuardianSparkRuntime::ReceiptStatus::Failed);

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, "content", false, 0);
    ledger.add_pending("r1", receipt);
    ledger.drain_locked(*rt, 10);
    CHECK(ledger.can_advance() == false);
}

TEST_CASE("GuardianArmAckLedger: a latched teardown failure holds the generation "
          "even once every receipt commits",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, "content", false, 0);
    ledger.latch_failure(); // e.g. this generation's full_sync kv sweep failed
    auto receipt = accept(*rt, "r1");
    ledger.add_pending("r1", receipt);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(receipt); }, std::chrono::seconds(10)));
    REQUIRE(rt->receipt_status(receipt) == GuardianSparkRuntime::ReceiptStatus::Committed);

    ledger.drain_locked(*rt, 10);
    CHECK_FALSE(ledger.can_advance()); // r1 committed cleanly, but the latch still holds it
}

TEST_CASE("GuardianArmAckLedger::decide_retry(): identical (generation, content, "
          "full_sync) while every receipt is still pending is Suppressed",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    // Governance finding UP-2/SHOULD-2 (Gate 4): decide_retry() now requires BOTH
    // sides of a content_id comparison to look like a real SHA-256 digest (64 hex
    // chars) before trusting the comparison at all - a human-readable placeholder
    // like the old "content-x" would now unconditionally Reapply regardless of what
    // this test is trying to pin, since it isn't a valid hash. Use real-shaped hex
    // stand-ins so the SUPPRESS/REAPPLY assertions below still exercise the
    // content-comparison branch they were written to test, not the sentinel guard.
    const std::string content_x(64, 'a');
    const std::string content_y(64, 'b');

    GuardianArmAckLedger ledger;
    ledger.begin_application(5, content_x, false, 3);
    ledger.add_pending("r1", accept(*rt, "r1"));
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    ledger.drain_locked(*rt, 10); // r1 still parked - stays Pending
    CHECK(ledger.decide_retry(5, content_x, false, *rt) == GuardianArmAckLedger::RetryDecision::Suppress);
    CHECK(ledger.applied_count() == 3);

    // A different generation is never a retry - always Reapply.
    CHECK(ledger.decide_retry(6, content_x, false, *rt) == GuardianArmAckLedger::RetryDecision::Reapply);
    // Changed content under the SAME generation number is Reapply too.
    CHECK(ledger.decide_retry(5, content_y, false, *rt) == GuardianArmAckLedger::RetryDecision::Reapply);
    // Changed full_sync flag alone is Reapply.
    CHECK(ledger.decide_retry(5, content_x, true, *rt) == GuardianArmAckLedger::RetryDecision::Reapply);
    // A non-hash sentinel content_id (the boot placeholder, or a hash-throw
    // fallback) is NEVER trusted to mean "same content", even if it happens to
    // match byte-for-byte - it degrades to Reapply instead.
    CHECK(ledger.decide_retry(5, "", false, *rt) == GuardianArmAckLedger::RetryDecision::Reapply);

    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->rule_count() == 1; }, std::chrono::seconds(10)));
}

TEST_CASE("GuardianArmAckLedger::decide_retry(): once a pending receipt resolves "
          "to a failure, the same (generation, content) is Reapply, not Suppress",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    const std::string content_x(64, 'a'); // see the sibling Suppress test above for why

    GuardianArmAckLedger ledger;
    ledger.begin_application(5, content_x, false, 1);
    auto receipt = accept(*rt, "r1");
    ledger.add_pending("r1", receipt);
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    b->fail_arm.store(true);
    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(receipt); }, std::chrono::seconds(10)));

    ledger.drain_locked(*rt, 10);
    CHECK(ledger.decide_retry(5, content_x, false, *rt) == GuardianArmAckLedger::RetryDecision::Reapply);
}

TEST_CASE("GuardianArmAckLedger::drain_locked(): bounded per call - 3 pending "
          "receipts resolve over two ticks, at most 2 per call",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_every_arm.store(true); // every one of the 3 keys below parks independently
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, "content", false, 3);
    // 3 DISTINCT keys (paths) - same-key siblings would queue behind one shared
    // arm instead of each dispatching (and parking) their own, per R5.2.
    auto r1 = accept(*rt, "r1", "/a");
    auto r2 = accept(*rt, "r2", "/b");
    auto r3 = accept(*rt, "r3", "/c");
    ledger.add_pending("r1", r1);
    ledger.add_pending("r2", r2);
    ledger.add_pending("r3", r3);
    REQUIRE(b->wait_parked(3, std::chrono::seconds(30)));

    b->release_hang();
    REQUIRE(yuzu::test::spin_until([&] { return rt->is_terminal(r1) && rt->is_terminal(r2) &&
                                                rt->is_terminal(r3); },
                                   std::chrono::seconds(10)));

    const auto first = ledger.drain_locked(*rt, /*max_per_tick=*/2);
    CHECK(first == 2);
    CHECK_FALSE(ledger.can_advance()); // one still un-drained

    const auto second = ledger.drain_locked(*rt, /*max_per_tick=*/2);
    CHECK(second == 1);
    CHECK(ledger.can_advance());
}

TEST_CASE("GuardianArmAckLedger::retire(): drops the current application without "
          "resolving it further, and can_advance() reports false afterward",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    b->hang_next_arm.store(true);
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    GuardianArmAckLedger ledger;
    ledger.begin_application(1, "content", false, 1);
    ledger.add_pending("r1", accept(*rt, "r1"));
    REQUIRE(b->wait_entered_hang(std::chrono::seconds(30)));

    ledger.retire();
    CHECK_FALSE(ledger.can_advance()); // no current application at all
    CHECK(ledger.decide_retry(1, "content", false, *rt) == GuardianArmAckLedger::RetryDecision::Reapply);

    b->release_hang(); // the runtime's own claim still resolves on its own schedule (§R5.5)
    REQUIRE(yuzu::test::spin_until([&] { return rt->rule_count() == 1; }, std::chrono::seconds(10)));
}

// ---------------------------------------------------------------------------
// Governance hardening round (Gates 2-6, rung 9c PR-2): sec-1/arch-1 and cae-1
// regression tests. sec-1/arch-1 was the production-live wedge (confirmed
// reachable today via spark_runtime_, independent of prefer_spark_ - see
// sre's and enterprise-readiness's Gate 6 findings): decide_retry() used to
// vacuously Suppress whenever `pending` was empty, which is the case on
// EVERY push at prefer_spark_=false (Accepted is unreachable there) - so a
// failed generation-advance persist was never retried by any repeat push.
// cae-1 was guardian_push_content_id()'s canonicalization not being
// block-boundary-injective (cpp-expert, hand-verified collision).
// ---------------------------------------------------------------------------

TEST_CASE("GuardianArmAckLedger::decide_retry(): an EMPTY pending map is always "
          "Reapply, never a vacuous Suppress",
          "[spark][ack]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = make_rt(r, b, GuardianSparkRuntime::Config{.backend_op_deadline = std::chrono::seconds(30)});

    const std::string content(64, 'c');

    GuardianArmAckLedger ledger;
    // Nothing was ever Accepted this application (the ordinary case at
    // prefer_spark_=false) - pending stays empty for its whole lifetime.
    ledger.begin_application(5, content, false, 3);
    CHECK(ledger.can_advance()); // trivially true - nothing to hold the generation

    // TARGET (sec-1/arch-1): before the fix, an identical (generation, content,
    // full_sync) retry against an application with nothing pending fell through
    // to a vacuous Suppress - exactly the shape of a server retry arriving after
    // a transient persist_generation_locked() failure, which this decision
    // alone is what silently and permanently wedged the reported generation.
    // Reapply here is what lets the caller's own tail gate retry that persist.
    CHECK(ledger.decide_retry(5, content, false, *rt) == GuardianArmAckLedger::RetryDecision::Reapply);
}

TEST_CASE("guardian_push_content_id(): different (spark, assertion) block splits "
          "of the SAME flat field sequence must NOT hash identically",
          "[spark][ack]") {
    // TARGET (cae-1, cpp-expert's hand-constructed collision, independently
    // re-derived by the orchestrator and confirmed with a standalone Python
    // trace before this fix landed): concatenating canonicalize_spec_block()'s
    // own already-field-injective output directly (no length prefix on the
    // BLOCK as a whole) let two rules with different spark/assertion splits of
    // an identical flat field sequence canonicalize - and therefore hash - to
    // the same content_id. Rule X: spark={type:"T", params:{k1:v1,k2:v2}},
    // assertion={type:"A", params:{}}. Rule Y: spark={type:"T",
    // params:{k1:v1}}, assertion={type:"k2", params:{v2:"A"}}. Both produced
    // the flat field sequence [T,k1,v1,k2,v2,A] before the fix.
    gpb::GuaranteedStatePush x;
    x.set_full_sync(false);
    auto* rx = x.add_rules();
    rx->set_rule_id("r1");
    rx->set_enabled(true);
    rx->set_enforcement_mode("enforce");
    rx->set_version(1);
    rx->mutable_spark()->set_type("T");
    rx->mutable_spark()->mutable_params()->insert({"k1", "v1"});
    rx->mutable_spark()->mutable_params()->insert({"k2", "v2"});
    rx->mutable_assertion()->set_type("A");

    gpb::GuaranteedStatePush y;
    y.set_full_sync(false);
    auto* ry = y.add_rules();
    ry->set_rule_id("r1");
    ry->set_enabled(true);
    ry->set_enforcement_mode("enforce");
    ry->set_version(1);
    ry->mutable_spark()->set_type("T");
    ry->mutable_spark()->mutable_params()->insert({"k1", "v1"});
    ry->mutable_assertion()->set_type("k2");
    ry->mutable_assertion()->mutable_params()->insert({"v2", "A"});

    CHECK(guardian_push_content_id(x) != guardian_push_content_id(y));
}
