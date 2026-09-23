/**
 * test_guardian_engine_legacy_sink.cpp — commit-1 red evidence for #4783: the
 * legacy Guardian sink call (GuardianEngine::emit_guard_event -> EventSink ->
 * AgentImpl's synchronous Write() on the Subscribe stream) runs on the SAME
 * thread that detected the drift, so a stalled (not dead) gRPC stream blocks
 * that thread indefinitely. Today (origin/dev, no #4783 fix applied) that
 * means: a legacy guard worker parked mid-report cannot notice a subsequent
 * real endpoint transition until the stream unblocks; GuardianEngine::stop()
 * and a rule-dropping apply_rules() both join guard threads under mtx_, so
 * either can hang the whole engine (and, in production, the agent's shutdown
 * or rule-management path) on one wedged sender.
 *
 * THESE TESTS ARE DELIBERATELY FAILING (or would hang without a watchdog)
 * AGAINST THE CURRENT #4783 HAZARD. They are expected to go green when the
 * #4783 fix (a separate follow-up commit — a detached, bounded legacy-sink
 * executor) lands. Do not "fix" them by loosening assertions — that erases
 * the regression-proof they exist to be. See:
 *   ~/.claude/plans/4783-legacy-guard-sink-blocking-PLAN-v2.md, S4 (T2,
 *   commit-1 subset) and S5 (commit 1).
 *
 * Every case is tagged [!mayfail] (a failing CHECK/REQUIRE here does not fail
 * the suite) and every operation that could hang under the pre-fix hazard
 * runs on a helper thread behind `run_bounded()` below, which always
 * releases the blocking sink's latch and joins the helper before returning —
 * so a red result here is a clean, reported CHECK failure, never a wedged
 * test binary. `run_bounded()` aborts the WHOLE process (spdlog::critical +
 * std::abort()) only if the helper fails to recover even after the latch is
 * released, i.e. a genuinely different hazard than the one these tests exist
 * to document.
 *
 * Local fixture: LegacySinkFixture below is a minimal, INDEPENDENT analogue
 * of test_guardian_engine.cpp's GuardianFixture — that fixture lives inside
 * an anonymous namespace in a different translation unit and cannot be
 * reused from here (see this file's own PLAN section, and the plan doc's
 * T2 header note). Nothing in agents/core (guardian_engine.{hpp,cpp},
 * agent.cpp, any guard_*.{hpp,cpp}) is touched by this commit.
 *
 * CH-1(a)/(b) and CH-2 arm a REAL FileGuard, which is Windows-only for the
 * MVP (FileGuard::start() is a no-op returning false off Windows —
 * guard_file.cpp) — those three cases are #ifdef _WIN32 and simply do not
 * exist in a non-Windows build. CH-1 L1 is cross-platform: it drives the
 * synchronous emit_guard_event() path directly via
 * guardian_emit_drift_for_test(), with no real guard thread involved, and is
 * the only case exercised on this (Linux) build.
 */

#include <yuzu/agent/guardian_engine.hpp>
#include <yuzu/agent/kv_store.hpp>

#include "guaranteed_state.pb.h"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace fs = std::filesystem;
namespace gpb = ::yuzu::guardian::v1;
using yuzu::agent::GuardianEngine;
using yuzu::agent::KvStore;

namespace {

std::string uid_suffix() {
#ifdef _WIN32
    if (const char* u = std::getenv("USERNAME")) return std::string("_") + u;
    return "_unknown";
#else
    return "_" + std::to_string(static_cast<unsigned long>(::geteuid()));
#endif
}

// Same salted-path convention as test_guardian_engine.cpp's unique_kv_path()
// (own copy — different TU, different anonymous namespace, deliberately not
// shared; see this file's header comment). A distinct base directory name
// ("..._legacy_sink") keeps the two files' fixtures from ever colliding on
// disk even though both run in the same suite.
fs::path unique_kv_path() {
    const auto dir = fs::temp_directory_path() / ("yuzu_test_guardian_legacy_sink" + uid_suffix());
    return dir / (yuzu::test::unique_temp_path("legacy_sink_").filename().string() + ".db");
}

/// Minimal local analogue of test_guardian_engine.cpp's GuardianFixture:
/// KvStore + GuardianEngine + start_local(), plus the two rule/push builders
/// this file's cases need. NOT a reuse of that fixture (it is private to its
/// own TU) — see this file's header comment.
struct LegacySinkFixture {
    // FIRST member, same rationale as GuardianFixture's own db_: the
    // destructor fires even if downstream construction throws, so a partial
    // REQUIRE failure below does not leak the .db/-wal/-shm trio.
    yuzu::test::TempDbFile db_{unique_kv_path()};
    std::unique_ptr<KvStore> kv;
    std::unique_ptr<GuardianEngine> engine;

    LegacySinkFixture() {
        auto opened = KvStore::open(db_.path);
        REQUIRE(opened.has_value());
        kv = std::make_unique<KvStore>(std::move(*opened));
        // prefer_spark defaults false: the legacy IGuard path is what #4783 is
        // about, and it is the sole live path in production (routed-concerns.md
        // Spark row) — no need to pass true here.
        engine = std::make_unique<GuardianEngine>(kv.get(), "agent-legacy-sink-test");
        REQUIRE(engine->start_local().has_value());
    }

    static gpb::GuaranteedStateRule make_rule(const std::string& id) {
        gpb::GuaranteedStateRule r;
        r.set_rule_id(id);
        r.set_name(id);
        r.set_yaml_source("name: " + id + "\n");
        r.set_version(1);
        r.set_enabled(true);
        r.set_enforcement_mode("enforce");
        return r;
    }

    /// A file-exists rule (file-change spark + file-exists assertion, B1):
    /// drift when presence != expect_present. `expected` is left at its
    /// default ("present" — the params map key is simply omitted), so drift
    /// means "the file is missing". FileGuard::start() is a no-op off
    /// Windows for the MVP (guard_file.cpp) — only the #ifdef _WIN32 cases in
    /// this file actually arm one; mirrors GuardianFixture::make_file_hash_rule's
    /// own doc note in test_guardian_engine.cpp.
    static gpb::GuaranteedStateRule make_file_exists_rule(const std::string& id,
                                                          const std::string& path) {
        gpb::GuaranteedStateRule r = make_rule(id);
        r.mutable_spark()->set_type("file-change");
        auto* a = r.mutable_assertion();
        a->set_type("file-exists");
        (*a->mutable_params())["path"] = path;
        return r;
    }

    /// Builds the push and dispatches it via
    /// guardian_dispatch_push_bytes_for_test — never a direct apply_rules(push)
    /// call — so the rule's params Map above is both POPULATED and READ inside
    /// the agent-core DLL/so (the #501 cross-image abseil hash-seed split;
    /// GuardianFixture in test_guardian_engine.cpp documents the identical
    /// requirement for any rule carrying assertion params).
    yuzu::agent::GuardianDispatchResult make_push(std::vector<gpb::GuaranteedStateRule> rules,
                                                  bool full_sync) {
        gpb::GuaranteedStatePush push;
        push.set_full_sync(full_sync);
        for (auto& r : rules)
            *push.add_rules() = std::move(r);
        return yuzu::agent::guardian_dispatch_push_bytes_for_test(*engine, push.SerializeAsString());
    }
};

/// Non-blocking recording EventSink used for the arm barrier (every
/// #ifdef _WIN32 case below): waits for a specific rule's arm-time
/// `guard.compliant` edge to arrive, BY IDENTITY, before the test swaps in a
/// BlockingSink — FileGuard::start() spawns its watch thread asynchronously
/// (guard_file.cpp) and the first eval is not synchronous with apply_rules()
/// returning, so without this wait the arm-time edge and the blocking sink
/// installed right after it can race.
class CountingSink {
public:
    yuzu::agent::GuardianEngine::EventSink sink() {
        return [this](const gpb::GuaranteedStateEvent& ev) {
            std::lock_guard lk(mu_);
            events_.emplace_back(ev.rule_id(), ev.event_type());
        };
    }

    bool wait_for(const std::string& rule_id, const std::string& event_type,
                  std::chrono::milliseconds bound) {
        return yuzu::test::spin_until(
            [this, rule_id, event_type] {
                std::lock_guard lk(mu_);
                return std::any_of(events_.begin(), events_.end(), [&](const auto& e) {
                    return e.first == rule_id && e.second == event_type;
                });
            },
            bound);
    }

private:
    mutable std::mutex mu_;
    std::vector<std::pair<std::string, std::string>> events_;
};

/// The blocking EventSink at the center of every case below — this is the
/// #4783 hazard, reproduced directly: the FIRST call parks the calling
/// thread (a real guard worker in the #ifdef _WIN32 cases; the raw
/// guardian_emit_drift_for_test() caller in CH-1 L1) until release() runs on
/// a DIFFERENT thread, standing in for a stalled (not dead) gRPC stream's
/// synchronous Write(). Every call — including ones that arrive after
/// release() — records (rule_id, event_type) in arrival order under the same
/// mutex, so order() is ground truth for the ordering assertions. entered()
/// lets a caller wait until a call is GENUINELY parked before doing a racy
/// follow-up (deleting/recreating the watched file) instead of guessing with
/// a fixed sleep.
class BlockingSink {
public:
    yuzu::agent::GuardianEngine::EventSink sink() {
        return [this](const gpb::GuaranteedStateEvent& ev) { on_event(ev); };
    }

    /// One-shot latch: unblocks every call parked in on_event() now and
    /// forever after. Safe (and a no-op) to call more than once — every
    /// cleanup path below (run_bounded's ScopeExit) calls it unconditionally.
    void release() {
        std::lock_guard lk(mu_);
        released_ = true;
        cv_.notify_all();
    }

    std::size_t entered() const {
        std::lock_guard lk(mu_);
        return entered_;
    }

    std::size_t delivered() const {
        std::lock_guard lk(mu_);
        return order_.size();
    }

    std::vector<std::pair<std::string, std::string>> order() const {
        std::lock_guard lk(mu_);
        return order_;
    }

private:
    void on_event(const gpb::GuaranteedStateEvent& ev) {
        std::unique_lock lk(mu_);
        ++entered_;
        cv_.notify_all();
        cv_.wait(lk, [this] { return released_; }); // the hazard: parks here
        order_.emplace_back(ev.rule_id(), ev.event_type());
    }

    mutable std::mutex mu_;
    std::condition_variable cv_;
    bool released_{false};
    std::size_t entered_{0};
    std::vector<std::pair<std::string, std::string>> order_;
};

/// Runs `op` on a helper thread and returns whether it completed within
/// `bound` — the actual RED assertion every case below makes (`CHECK` on the
/// return value). Whatever the outcome, by the time this function returns
/// the helper has ALREADY been joined: its cleanup unconditionally releases
/// `sink`'s latch (idempotent) and waits — generously, 30s — for the op to
/// finish before joining it (hygiene rule 2/3 from the #4783 plan, folded in
/// here so every call site gets it for free instead of hand-rolling a
/// ScopeExit per test). A genuine post-release hang — something OTHER than
/// the known #4783 sink-block this file exists to reproduce — aborts the
/// whole binary with a diagnostic rather than wedging the rest of the suite
/// (a crash with a clear message beats a silent meson kill).
///
/// Never itself polls any GuardianEngine accessor: the caller does that only
/// after this function has returned, i.e. only once the operation is known
/// to have completed and mtx_ is known to be free (hygiene rule 4).
template <typename F>
bool run_bounded(F&& op, std::chrono::milliseconds bound, BlockingSink& sink, const char* what) {
    std::atomic<bool> done{false};
    std::thread th([&op, &done] {
        op();
        done.store(true, std::memory_order_release);
    });
    yuzu::test::ScopeExit cleanup([&] {
        sink.release();
        if (!done.load(std::memory_order_acquire) &&
            !yuzu::test::spin_until([&done] { return done.load(std::memory_order_acquire); },
                                    std::chrono::seconds{30})) {
            spdlog::critical(
                "legacy_sink watchdog: '{}' never completed even after releasing the "
                "blocking sink latch - aborting rather than hanging the whole test "
                "binary (#4783 pre-fix hazard, commit-1 evidence)",
                what);
            std::abort();
        }
        th.join();
    });
    return yuzu::test::spin_until([&done] { return done.load(std::memory_order_acquire); }, bound);
}

} // namespace

// ── CH-1 L1 (cross-platform): a blocking sink stalls the emitting thread ────

TEST_CASE("CH-1 L1: a blocking legacy sink stalls the emitting thread until released, "
          "delivered in FIFO order once it is (#4783 pre-fix; commit-1 red evidence)",
          "[guardian][engine][legacy_sink][chaos][!mayfail]") {
    BlockingSink sink;
    LegacySinkFixture f; // declared AFTER sink: f destructs (stop()) FIRST on
                         // unwind, guaranteeing no further sink call can reach
                         // an already-destroyed `sink` (there is no guard
                         // thread here, but this mirrors the safe order the
                         // #ifdef _WIN32 cases below need for real ones).

    f.engine->set_event_sink(sink.sink());

    auto emit_abc = [&f] {
        auto drift_for = [](const std::string& rule_id) {
            yuzu::agent::GuardDrift d;
            d.guard_type = "file";
            d.rule_id = rule_id;
            d.rule_name = rule_id;
            return d;
        };
        // emit_guard_event() is fully synchronous in commit 1 (no detached
        // executor exists yet) — each call runs the sink to completion on
        // THIS thread before the next line executes.
        yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-A"));
        yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-B"));
        yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-C"));
    };

    // THE red assertion: the very first emit (A) blocks the calling thread
    // inside sink.sink() until released, so the helper cannot possibly reach
    // B or C — let alone return — within 1s. This MUST fail against
    // unmodified code; run_bounded's own cleanup then releases the latch and
    // drains the helper regardless, so the ordering assertions below still
    // get to run and prove eventual (not lost) delivery.
    const bool finished_within_1s =
        run_bounded(emit_abc, std::chrono::seconds{1}, sink, "CH-1 L1: emit drift for A,B,C");
    CHECK(finished_within_1s);

    const auto delivered = sink.order();
    REQUIRE(delivered.size() == 3);
    CHECK(delivered[0].first == "rule-A");
    CHECK(delivered[0].second == "drift.detected");
    CHECK(delivered[1].first == "rule-B");
    CHECK(delivered[1].second == "drift.detected");
    CHECK(delivered[2].first == "rule-C");
    CHECK(delivered[2].second == "drift.detected");
}

#ifdef _WIN32

// ── CH-1(a) Windows: detection resumes once the block releases ──────────────

TEST_CASE("CH-1(a) Windows: file-guard detection resumes once a blocked legacy sink is "
          "released (#4783 pre-fix; commit-1 evidence)",
          "[guardian][engine][legacy_sink][chaos][!mayfail]") {
    yuzu::test::TempDir dir{"yuzu_test_legacy_sink_ch1a_"};
    fs::create_directories(dir.path);
    const auto target = dir.path / "guarded.txt";
    {
        std::ofstream out(target, std::ios::binary | std::ios::trunc);
        REQUIRE(out.good());
        out << "v1";
    }

    CountingSink arm_sink;
    BlockingSink blocking;
    // f declared LAST among the locals the guard thread's sink callback can
    // reach: destructs FIRST (stop() joins the guard thread) before
    // arm_sink/blocking/dir go away — see CH-1 L1's comment on this ordering.
    LegacySinkFixture f;

    // Arm barrier (plan hygiene rule 8): the file already exists, so
    // FileGuard's initial eval is compliant. Wait for that arm-time
    // guard.compliant edge BY IDENTITY before swapping in the blocking sink.
    f.engine->set_event_sink(arm_sink.sink());
    auto dr = f.make_push({LegacySinkFixture::make_file_exists_rule("r-a", target.string())},
                          /*full_sync=*/true);
    REQUIRE(dr.exit_code == 0);
    REQUIRE(arm_sink.wait_for("r-a", "guard.compliant", std::chrono::seconds{30}));

    f.engine->set_event_sink(blocking.sink());

    // Delete the file: presence (absent) now differs from the rule's default
    // expect_present==true -> a drift report -> the guard's OWN worker
    // thread parks inside the blocking sink, exactly like the production
    // hazard (a stalled Write() on the Subscribe stream).
    fs::remove(target);
    REQUIRE(
        yuzu::test::spin_until([&] { return blocking.entered() >= 1; }, std::chrono::seconds{30}));

    // Recreate WHILE the sender is still wedged - the scenario #4783 is
    // about: a legacy guard thread blocked in a stalled sink cannot notice
    // (let alone report) a subsequent real endpoint transition until release.
    {
        std::ofstream out(target, std::ios::binary | std::ios::trunc);
        REQUIRE(out.good());
        out << "v2";
    }

    blocking.release();

    // Not directly observable in commit 1 whether the recreate was queued
    // while the sender was blocked or only picked up on FileGuard's next
    // wake after release — commit 3 adds a direct pending-count accessor for
    // that distinction. What IS provable here: detection resumes post-release
    // and the compliant edge for the recreate eventually arrives. 2
    // deliveries total under `blocking` (the delete's drift, then the
    // recreate's compliant edge) — the ARM-TIME compliant edge above was
    // captured by `arm_sink`, installed before `blocking`, so it is not one
    // of these two.
    CHECK(yuzu::test::spin_until([&] { return blocking.delivered() >= 2; },
                                 std::chrono::seconds{30}));

    const auto events = blocking.order();
    INFO("blocking sink delivered " << events.size() << " event(s)");
    if (events.size() >= 2) {
        CHECK(events[0].first == "r-a");
        CHECK(events[0].second == "drift.detected");
        CHECK(events[1].first == "r-a");
        CHECK(events[1].second == "guard.compliant");
    }

    f.engine->stop(); // tidy, deterministic teardown before the fixture destructs
}

// ── CH-1(b) Windows: stop() must not hang forever while blocked ─────────────

TEST_CASE("CH-1(b) Windows: GuardianEngine::stop() must not hang forever while a legacy "
          "guard thread is wedged in the blocking sink (#4783 pre-fix; commit-1 red evidence)",
          "[guardian][engine][legacy_sink][chaos][!mayfail]") {
    yuzu::test::TempDir dir{"yuzu_test_legacy_sink_ch1b_"};
    fs::create_directories(dir.path);
    const auto target = dir.path / "guarded.txt";
    {
        std::ofstream out(target, std::ios::binary | std::ios::trunc);
        REQUIRE(out.good());
        out << "v1";
    }

    CountingSink arm_sink;
    BlockingSink blocking;
    LegacySinkFixture f; // declared last — see CH-1(a)'s comment on this order.

    f.engine->set_event_sink(arm_sink.sink());
    auto dr = f.make_push({LegacySinkFixture::make_file_exists_rule("r-a", target.string())},
                          /*full_sync=*/true);
    REQUIRE(dr.exit_code == 0);
    REQUIRE(arm_sink.wait_for("r-a", "guard.compliant", std::chrono::seconds{30}));

    f.engine->set_event_sink(blocking.sink());
    fs::remove(target); // drift: guard thread parks in the blocking sink
    REQUIRE(
        yuzu::test::spin_until([&] { return blocking.entered() >= 1; }, std::chrono::seconds{30}));

    // GuardianEngine::stop() holds mtx_ across stop_all_guards_locked(),
    // which joins the (wedged) legacy guard thread — the exact deadlock
    // #4783 is about, on the shutdown path this time rather than a
    // rule-management path (CH-2, below).
    const bool finished = run_bounded([&] { f.engine->stop(); }, std::chrono::seconds{5}, blocking,
                                      "CH-1(b): stop() while blocked");
    CHECK(finished); // MUST currently fail (red pre-fix)

    // run_bounded already released the latch and joined the stop() helper —
    // the engine is fully stopped either way; nothing further to assert or
    // drain, and the fixture's own destructor (a second stop()) is idempotent.
}

// ── CH-2 Windows: a rule-dropping full_sync must not hang on a wedged peer ──

TEST_CASE("CH-2 Windows: a full_sync push dropping a rule whose guard thread is wedged "
          "in the blocking sink must not hang apply_rules (#4783 pre-fix; commit-1 red "
          "evidence)",
          "[guardian][engine][legacy_sink][chaos][!mayfail]") {
    yuzu::test::TempDir dir{"yuzu_test_legacy_sink_ch2_"};
    fs::create_directories(dir.path);
    const auto path_a = dir.path / "guarded-a.txt";
    const auto path_b = dir.path / "guarded-b.txt";
    for (const auto& p : {path_a, path_b}) {
        std::ofstream out(p, std::ios::binary | std::ios::trunc);
        REQUIRE(out.good());
        out << "v1";
    }

    CountingSink arm_sink;
    BlockingSink blocking;
    LegacySinkFixture f; // declared last — see CH-1(a)'s comment on this order.

    // Arm A and B together; both files pre-exist, so both arm-time evals are
    // compliant edges.
    f.engine->set_event_sink(arm_sink.sink());
    auto dr = f.make_push({LegacySinkFixture::make_file_exists_rule("r-a", path_a.string()),
                           LegacySinkFixture::make_file_exists_rule("r-b", path_b.string())},
                          /*full_sync=*/true);
    REQUIRE(dr.exit_code == 0);
    REQUIRE(arm_sink.wait_for("r-a", "guard.compliant", std::chrono::seconds{30}));
    REQUIRE(arm_sink.wait_for("r-b", "guard.compliant", std::chrono::seconds{30}));
    REQUIRE(f.engine->armed_guard_count() == 2); // safe here: nothing is blocked yet

    f.engine->set_event_sink(blocking.sink());

    fs::remove(path_a); // drift on A only -> A's guard thread parks in the blocking sink
    REQUIRE(
        yuzu::test::spin_until([&] { return blocking.entered() >= 1; }, std::chrono::seconds{30}));

    const auto arm_failures_before = f.engine->arm_failure_count();

    // apply_rules(full_sync=true, {B only}) unconditionally tears down EVERY
    // currently-armed guard (stop_all_guards_locked(), guardian_engine.cpp)
    // before re-arming from the new push — including A, whose worker thread
    // is wedged in the blocking sink above. Pre-fix, that join hangs
    // apply_rules INSIDE mtx_, on this helper thread, forever.
    yuzu::agent::GuardianDispatchResult push_result;
    const bool finished =
        run_bounded([&] { push_result = f.make_push(
                              {LegacySinkFixture::make_file_exists_rule("r-b", path_b.string())},
                              /*full_sync=*/true); },
                    std::chrono::seconds{5}, blocking,
                    "CH-2: full_sync push dropping A while wedged");
    CHECK(finished); // MUST currently fail (red pre-fix)

    // Safe only now that run_bounded has returned: the latch has already
    // been released and the helper already joined (hygiene rule 4 — never
    // poll an mtx_-guarded accessor while a watchdogged op could still hold
    // mtx_).
    CHECK(push_result.exit_code == 0);
    CHECK(f.engine->armed_guard_count() == 1); // only B survives the full_sync
    CHECK(f.engine->arm_failure_count() == arm_failures_before); // B's re-arm is a routine success

    f.engine->stop(); // tidy, deterministic teardown before the fixture destructs
}

#endif // _WIN32
