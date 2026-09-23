/**
 * test_guardian_engine_legacy_sink.cpp — #4783 fix proof: the legacy Guardian
 * sink call (GuardianEngine::emit_guard_event -> EventSink -> AgentImpl's gRPC
 * Write() on the Subscribe stream) no longer runs on the guard's own detection
 * thread. Before this fix, a stalled (not dead) gRPC stream blocked that
 * thread indefinitely: a legacy guard worker parked mid-report could not
 * notice a subsequent real endpoint transition until the stream unblocked,
 * and GuardianEngine::stop() / a rule-dropping apply_rules() both joined
 * guard threads under mtx_, so either could hang the whole engine (and, in
 * production, the agent's shutdown or rule-management path) on one wedged
 * sender.
 *
 * Commit 3 of the delivery plan routes emit_guard_event() through
 * GuardianLegacySinkExecutor (guardian_legacy_sink_executor.hpp, added in
 * commit 2): the guard's own thread only ENQUEUES and returns immediately — a
 * blocking (or merely slow) network send now runs on the executor's own
 * DETACHED worker, never on the thread that detected the drift. These cases
 * were committed RED (commit 1, tagged [!mayfail]) against the pre-fix engine
 * and are GREEN against the fix landed here — see:
 *   ~/.claude/plans/4783-legacy-guard-sink-blocking-PLAN-v2.md, S4 (T2) and S5
 *   (commits 1 and 3).
 *
 * Every operation that could hang under the (now-fixed) hazard still runs on
 * a helper thread behind `run_bounded()` below, which always releases the
 * blocking sink's latch and joins the helper before returning — so a
 * regression here is a clean, reported CHECK failure, never a wedged test
 * binary. `run_bounded()` aborts the WHOLE process (spdlog::critical +
 * std::abort()) only if the helper fails to recover even after the latch is
 * released, i.e. a genuinely different hazard than the one this file exists
 * to guard against. Every case ALSO physically retires the legacy-sink
 * executor's detached worker before its locals destruct
 * (`require_legacy_sink_retired()` below, via a `ScopeExit` so it runs on
 * every exit path including a failed REQUIRE/CHECK): `BlockingSink`/
 * `CountingSink` capture `this` by raw pointer, and delivery is now
 * asynchronous, so nothing may still reference either after this test
 * function's locals start unwinding.
 *
 * Local fixture: LegacySinkFixture below is a minimal, INDEPENDENT analogue
 * of test_guardian_engine.cpp's GuardianFixture — that fixture lives inside
 * an anonymous namespace in a different translation unit and cannot be
 * reused from here (see this file's own PLAN section, and the plan doc's
 * T2 header note). guard_*.{hpp,cpp} are untouched by this commit — only
 * guardian_engine.{hpp,cpp} and agent.cpp (see the plan's commit-3 scope).
 *
 * CH-1(a)/(b) and CH-2 arm a REAL FileGuard, which is Windows-only for the
 * MVP (FileGuard::start() is a no-op returning false off Windows —
 * guard_file.cpp) — those cases (plus the Windows-only shutdown-path
 * regression added in commit 3) are #ifdef _WIN32 and simply do not exist in
 * a non-Windows build. CH-1 L1 and the two cross-platform commit-3 additions
 * (FIFO preservation, stop()-discards-backlog) drive the synchronous half of
 * emit_guard_event() directly via guardian_emit_drift_for_test(), with no
 * real guard thread involved, and are the only cases exercised on this
 * (Linux) build.
 */

#include <yuzu/agent/guardian_engine.hpp>
#include <yuzu/agent/kv_store.hpp>

#include "guaranteed_state.pb.h"
#include "guardian_legacy_sink_executor.hpp" // LegacySendOutcome, legacy_sink_executor_for_test()'s type

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
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
            return yuzu::agent::LegacySendOutcome::Sent;
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
/// #4783 hazard's stand-in: the FIRST call parks the calling thread (the
/// legacy-sink executor's own detached worker, #4783 — never a real guard
/// thread any more) until release() runs on a DIFFERENT thread, standing in
/// for a stalled (not dead) gRPC stream's synchronous Write(). Every call —
/// including ones that arrive after release() — records
/// (rule_id, event_type, event_id) in arrival order under the same mutex, so
/// order()/event_ids() are ground truth for the ordering assertions.
/// entered() lets a caller wait until a call is GENUINELY parked before doing
/// a racy follow-up (deleting/recreating the watched file, or offering a
/// second event) instead of guessing with a fixed sleep.
class BlockingSink {
public:
    yuzu::agent::GuardianEngine::EventSink sink() {
        return [this](const gpb::GuaranteedStateEvent& ev) { return on_event(ev); };
    }

    /// One-shot latch: unblocks every call parked in on_event() now and
    /// forever after. Safe (and a no-op) to call more than once — every
    /// cleanup path below (require_legacy_sink_retired / run_bounded's own
    /// ScopeExit) calls it unconditionally.
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

    /// event_id per delivery, in the SAME arrival order as order() above
    /// (#4783 commit 3 — the FIFO-identity proof the A,A,A case below needs on
    /// top of type ordering).
    std::vector<std::string> event_ids() const {
        std::lock_guard lk(mu_);
        return event_ids_;
    }

private:
    yuzu::agent::LegacySendOutcome on_event(const gpb::GuaranteedStateEvent& ev) {
        std::unique_lock lk(mu_);
        ++entered_;
        cv_.notify_all();
        cv_.wait(lk, [this] { return released_; }); // the hazard stand-in: parks here
        order_.emplace_back(ev.rule_id(), ev.event_type());
        event_ids_.push_back(ev.event_id());
        return yuzu::agent::LegacySendOutcome::Sent;
    }

    mutable std::mutex mu_;
    std::condition_variable cv_;
    bool released_{false};
    std::size_t entered_{0};
    std::vector<std::pair<std::string, std::string>> order_;
    std::vector<std::string> event_ids_;
};

/// Cleanup used by every case below (plan hygiene rules 2/3/6): idempotently
/// release the blocking sink's latch, then REQUIRE the legacy-sink executor's
/// worker(s) to physically retire within 30s before returning.
/// `CountingSink`/`BlockingSink` capture `this` by raw pointer and delivery is
/// now asynchronous (the executor's own detached worker, #4783), so nothing
/// captured by either may still be reachable by a worker once this function's
/// CALLER's locals start destructing — aborts the WHOLE process
/// (spdlog::critical + std::abort()), the same posture run_bounded() takes
/// for a different failure mode, rather than let unwind proceed into a
/// captured-`this` use-after-free. Declare the ScopeExit that calls this
/// AFTER every local it must outlive (fixture, sinks, TempDir, ...) so its
/// destructor — which runs FIRST on unwind — retires the worker before any
/// of them tears down.
void require_legacy_sink_retired(GuardianEngine& engine, BlockingSink& sink, const char* what) {
    sink.release();
    if (!engine.retire_legacy_sink_workers_for_test(std::chrono::seconds{30})) {
        spdlog::critical(
            "legacy_sink cleanup: '{}' - executor worker(s) did not retire even after "
            "releasing the blocking sink latch (30s) - aborting rather than letting scope "
            "unwind into a captured-this use-after-free",
            what);
        std::abort();
    }
}

/// Runs `op` on a helper thread and returns whether it completed within
/// `bound`. Whatever the outcome, by the time this function returns the
/// helper has ALREADY been joined: its cleanup unconditionally releases
/// `sink`'s latch (idempotent) and waits — generously, 30s — for the op to
/// finish before joining it (hygiene rule 2/3 from the #4783 plan, folded in
/// here so every call site gets it for free instead of hand-rolling a
/// ScopeExit per test). NOTE: releasing the latch here unblocks the
/// EXECUTOR's detached worker, not `op` itself in every case (e.g. `op` may
/// be `stop()`, which does not wait on that worker at all) — this function
/// only proves `op` completed within `bound`; it does NOT prove delivery
/// completed, since delivery runs on a separate, un-joined thread. Callers
/// that need to observe delivery must flush/retire afterward (see
/// flush_legacy_sink_for_test / retire_legacy_sink_workers_for_test below).
/// A genuine post-release hang — something OTHER than a network-shaped
/// stall this file exists to reproduce — aborts the whole binary with a
/// diagnostic rather than wedging the rest of the suite (a crash with a
/// clear message beats a silent meson kill).
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
                "binary (#4783)",
                what);
            std::abort();
        }
        th.join();
    });
    return yuzu::test::spin_until([&done] { return done.load(std::memory_order_acquire); }, bound);
}

} // namespace

// ── CH-1 L1 (cross-platform): the detached send stalls, never the emitter ───

TEST_CASE("CH-1 L1: a blocking legacy sink stalls the DETACHED SEND, never the emitting "
          "thread — delivered in FIFO order once released (#4783 fix proof)",
          "[guardian][engine][legacy_sink][chaos]") {
    BlockingSink sink;
    LegacySinkFixture f; // declared after sink — destruction order between these two no
                         // longer matters on its own now that delivery is asynchronous
                         // (the detached worker can outlive both); the ScopeExit below
                         // physically retires the worker before either destructs.
    yuzu::test::ScopeExit cleanup(
        [&] { require_legacy_sink_retired(*f.engine, sink, "CH-1 L1 cleanup"); });

    f.engine->set_event_sink(sink.sink());

    auto emit_abc = [&f] {
        auto drift_for = [](const std::string& rule_id) {
            yuzu::agent::GuardDrift d;
            d.guard_type = "file";
            d.rule_id = rule_id;
            d.rule_name = rule_id;
            return d;
        };
        // #4783: emit_guard_event() only ENQUEUES on the detached executor — each
        // of these three calls returns immediately regardless of whether a prior
        // event's SEND is still blocked in the sink.
        yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-A"));
        yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-B"));
        yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-C"));
    };

    // THE fix proof: all three enqueue instantly (offer() never blocks), so the
    // helper returns within 1s even though the FIRST send is still parked inside
    // sink.sink() at that moment (only released by run_bounded's own cleanup).
    const bool finished_within_1s =
        run_bounded(emit_abc, std::chrono::seconds{1}, sink, "CH-1 L1: emit drift for A,B,C");
    CHECK(finished_within_1s);

    // run_bounded's cleanup already released the latch and joined the "op" helper
    // thread (the one that called offer() three times) — but delivery itself runs
    // on the executor's OWN detached worker, which nobody has waited on yet. Flush
    // before reading order(), or this read races that worker.
    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{5}));

    const auto delivered = sink.order();
    REQUIRE(delivered.size() == 3);
    CHECK(delivered[0].first == "rule-A");
    CHECK(delivered[0].second == "drift.detected");
    CHECK(delivered[1].first == "rule-B");
    CHECK(delivered[1].second == "drift.detected");
    CHECK(delivered[2].first == "rule-C");
    CHECK(delivered[2].second == "drift.detected");

    // Aggregate-count assertion (#4783 commit 3): after the op, the legacy-sink
    // executor's contribution to active_io_workers() must also have retired.
    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));
    CHECK(f.engine->active_io_workers() == 0);
}

// ── #4783 commit 3: FIFO preservation at the engine level (mirrors T1) ──────

TEST_CASE("Three offers for the SAME rule while a send is blocked are delivered in FIFO "
          "order, none dropped or merged (#4783 commit 3, engine-level FIFO-preservation "
          "regression, mirrors GuardianLegacySinkExecutor's own unit-level A,A,A test)",
          "[guardian][engine][legacy_sink][chaos]") {
    BlockingSink sink;
    LegacySinkFixture f;
    yuzu::test::ScopeExit cleanup(
        [&] { require_legacy_sink_retired(*f.engine, sink, "A,A,A cleanup"); });

    f.engine->set_event_sink(sink.sink());

    // Drift, then compliant, then drift again — same rule_id, distinct
    // event_types (mirrors T1's own "A-drift, A-compliant, A-drift" case) so "no
    // coalescing" bites on TYPE, not merely on the event_id sequence checked below.
    yuzu::agent::GuardDrift drift;
    drift.guard_type = "file";
    drift.rule_id = "rule-A";
    drift.rule_name = "rule-A";
    yuzu::agent::GuardDrift compliant = drift;
    compliant.compliant = true;

    // offer() never blocks (#4783) — this first emit's SEND is what parks inside
    // `sink`, not this call.
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift);
    // Handshake (plan hygiene rule 9): wait until the worker is GENUINELY parked
    // inside the sink before offering the next two, so this deterministically
    // exercises "queued behind an in-flight send", not a race.
    REQUIRE(yuzu::test::spin_until([&] { return sink.entered() >= 1; }, std::chrono::seconds{30}));

    // Two more offers for the SAME rule_id while the first is still in flight —
    // pure FIFO queueing, never coalesced/replaced/reordered
    // (guardian_legacy_sink_executor.hpp's queue policy). Deterministic, no spin
    // needed: both calls run on this thread while the only worker is parked.
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, compliant);
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift);
    REQUIRE(f.engine->legacy_sink_executor_for_test().pending_count_for_test() == 2);

    sink.release();

    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{5}));
    const auto delivered = sink.order();
    REQUIRE(delivered.size() == 3);
    CHECK(delivered[0].first == "rule-A");
    CHECK(delivered[0].second == "drift.detected");
    CHECK(delivered[1].first == "rule-A");
    CHECK(delivered[1].second == "guard.compliant");
    CHECK(delivered[2].first == "rule-A");
    CHECK(delivered[2].second == "drift.detected");

    // Identity-bearing on top of type ordering: each event_id's trailing
    // per-engine seq (assigned synchronously in emit_guard_event(), BEFORE the
    // async hand-off) must strictly increase in emission order — proof the
    // executor delivered them in the order they were OFFERED, not merely "three
    // of the right types".
    const auto ids = sink.event_ids();
    REQUIRE(ids.size() == 3);
    auto seq_of = [](const std::string& id) -> std::uint64_t {
        const auto pos = id.rfind('-');
        REQUIRE(pos != std::string::npos);
        return std::stoull(id.substr(pos + 1));
    };
    CHECK(seq_of(ids[0]) < seq_of(ids[1]));
    CHECK(seq_of(ids[1]) < seq_of(ids[2]));

    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));
    CHECK(f.engine->active_io_workers() == 0);
}

// ── #4783 commit 3: stop() discards the backlog, not an in-flight send ──────

TEST_CASE("stop() discards the backlog it never sent, but does not touch a send already "
          "in flight (#4783 commit 3, D3 — discarded_at_stop counts exactly what was "
          "discarded)",
          "[guardian][engine][legacy_sink][chaos]") {
    BlockingSink sink;
    LegacySinkFixture f;
    yuzu::test::ScopeExit cleanup(
        [&] { require_legacy_sink_retired(*f.engine, sink, "stop()-discards-backlog cleanup"); });

    f.engine->set_event_sink(sink.sink());

    auto drift_for = [](const std::string& rule_id) {
        yuzu::agent::GuardDrift d;
        d.guard_type = "file";
        d.rule_id = rule_id;
        d.rule_name = rule_id;
        return d;
    };

    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-A")); // A: goes in-flight
    REQUIRE(yuzu::test::spin_until([&] { return sink.entered() >= 1; }, std::chrono::seconds{30}));
    yuzu::agent::guardian_emit_drift_for_test(*f.engine, drift_for("rule-B")); // B: queued behind A
    REQUIRE(f.engine->legacy_sink_executor_for_test().pending_count_for_test() == 1);

    const bool finished = run_bounded([&] { f.engine->stop(); }, std::chrono::seconds{5}, sink,
                                      "stop()-discards-backlog: stop() while A in flight, B queued");
    CHECK(finished);

    // run_bounded's cleanup already released the latch — wait for A's now-unblocked
    // send (and the worker's own physical retirement) rather than racing it.
    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));

    CHECK(sink.delivered() == 1); // only A — B was discarded by stop(), never sent
    const auto delivered = sink.order();
    REQUIRE(delivered.size() == 1);
    CHECK(delivered[0].first == "rule-A");
    CHECK(f.engine->legacy_sink_executor_for_test().stats().discarded_at_stop == 1);
    CHECK(f.engine->active_io_workers() == 0);
}

#ifdef _WIN32

// ── CH-1(a) Windows: detection resumes once the block releases ──────────────

TEST_CASE("CH-1(a) Windows: file-guard detection continues (the guard thread never "
          "blocks) while a legacy-sink send is wedged, and the pending recreate-edge is "
          "queued, not lost (#4783 fix proof)",
          "[guardian][engine][legacy_sink][chaos]") {
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
    LegacySinkFixture f;
    yuzu::test::ScopeExit cleanup(
        [&] { require_legacy_sink_retired(*f.engine, blocking, "CH-1(a) cleanup"); });

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
    // expect_present==true -> a drift report. #4783: the guard's own worker
    // thread merely OFFERS this to the detached executor and returns; it is the
    // EXECUTOR's worker that parks inside the blocking sink, standing in for a
    // stalled Write() on the Subscribe stream — the guard thread itself stays
    // free to keep detecting.
    fs::remove(target);
    REQUIRE(
        yuzu::test::spin_until([&] { return blocking.entered() >= 1; }, std::chrono::seconds{30}));

    // Recreate WHILE the sender is still wedged - the scenario #4783 is about: a
    // legacy guard thread must notice (and REPORT) a subsequent real endpoint
    // transition even while the PRIOR report's send is still stuck.
    {
        std::ofstream out(target, std::ios::binary | std::ios::trunc);
        REQUIRE(out.good());
        out << "v2";
    }

    // #4783 commit 3: directly observable now — the recreate's compliant edge is
    // QUEUED (not merely "eventually noticed") while the sender is still wedged.
    // FileGuard's own watch loop is asynchronous/poll-driven, so this is a
    // bounded wait, not an immediate assertion.
    REQUIRE(yuzu::test::spin_until(
        [&] { return f.engine->legacy_sink_executor_for_test().pending_count_for_test() >= 1; },
        std::chrono::seconds{30}));

    blocking.release();

    // Flush (idle), then assert the exact count — deterministic rather than a
    // polling spin on delivered().
    REQUIRE(f.engine->flush_legacy_sink_for_test(std::chrono::seconds{30}));
    // 2 deliveries total under `blocking` (the delete's drift, then the
    // recreate's compliant edge) — the ARM-TIME compliant edge above was
    // captured by `arm_sink`, installed before `blocking`, so it is not one of
    // these two.
    CHECK(blocking.delivered() == 2);

    const auto events = blocking.order();
    INFO("blocking sink delivered " << events.size() << " event(s)");
    if (events.size() >= 2) {
        CHECK(events[0].first == "r-a");
        CHECK(events[0].second == "drift.detected");
        CHECK(events[1].first == "r-a");
        CHECK(events[1].second == "guard.compliant");
    }

    // Aggregate-count assertion (#4783 commit 3).
    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));
    CHECK(f.engine->active_io_workers() == 0);

    f.engine->stop(); // tidy, deterministic teardown before the fixture destructs
}

// ── CH-1(b) Windows: stop() must complete promptly while blocked ────────────

TEST_CASE("CH-1(b) Windows: GuardianEngine::stop() completes promptly while a "
          "legacy-sink send is wedged in the blocking sink (#4783 fix proof)",
          "[guardian][engine][legacy_sink][chaos]") {
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
    yuzu::test::ScopeExit cleanup(
        [&] { require_legacy_sink_retired(*f.engine, blocking, "CH-1(b) cleanup"); });

    f.engine->set_event_sink(arm_sink.sink());
    auto dr = f.make_push({LegacySinkFixture::make_file_exists_rule("r-a", target.string())},
                          /*full_sync=*/true);
    REQUIRE(dr.exit_code == 0);
    REQUIRE(arm_sink.wait_for("r-a", "guard.compliant", std::chrono::seconds{30}));

    f.engine->set_event_sink(blocking.sink());
    fs::remove(target); // drift: the executor's worker (not the guard thread, #4783) parks
    REQUIRE(
        yuzu::test::spin_until([&] { return blocking.entered() >= 1; }, std::chrono::seconds{30}));

    // GuardianEngine::stop() joins the (now-prompt) legacy guard thread and then
    // only stops the executor from ADMITTING new sends — it does not wait for
    // this already-in-flight one. #4783's actual fix: before it, stop() held
    // mtx_ across stop_all_guards_locked(), which joined the (wedged) legacy
    // guard thread — the exact deadlock this test exists to prove is gone, on
    // the shutdown path this time (CH-2, below, is the rule-management-path
    // counterpart).
    const bool finished = run_bounded([&] { f.engine->stop(); }, std::chrono::seconds{5}, blocking,
                                      "CH-1(b): stop() while blocked");
    CHECK(finished);

    // run_bounded already released the latch and joined the stop() helper — the
    // engine is fully stopped either way; wait for the executor's worker to
    // physically retire and confirm the aggregate count reflects it (#4783
    // commit 3).
    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));
    CHECK(f.engine->active_io_workers() == 0);
}

// ── #4783 commit 3: shutdown-path aggregate-count regression ────────────────

TEST_CASE("CH-1(b) engine regression: the legacy-sink executor's physical worker count "
          "reads 1 while GuardianEngine::stop() is blocked on a wedged send and reaches "
          "0 only after it releases (#4783 commit 3, aggregate active_io_workers() proof)",
          "[guardian][engine][legacy_sink][chaos]") {
    yuzu::test::TempDir dir{"yuzu_test_legacy_sink_ch1b_regr_"};
    fs::create_directories(dir.path);
    const auto target = dir.path / "guarded.txt";
    {
        std::ofstream out(target, std::ios::binary | std::ios::trunc);
        REQUIRE(out.good());
        out << "v1";
    }

    CountingSink arm_sink;
    BlockingSink blocking;
    LegacySinkFixture f;
    yuzu::test::ScopeExit cleanup(
        [&] { require_legacy_sink_retired(*f.engine, blocking, "CH-1(b) engine regression cleanup"); });

    f.engine->set_event_sink(arm_sink.sink());
    auto dr = f.make_push({LegacySinkFixture::make_file_exists_rule("r-a", target.string())},
                          /*full_sync=*/true);
    REQUIRE(dr.exit_code == 0);
    REQUIRE(arm_sink.wait_for("r-a", "guard.compliant", std::chrono::seconds{30}));

    f.engine->set_event_sink(blocking.sink());
    fs::remove(target); // drift -> the executor's worker (not the guard thread) blocks
    REQUIRE(
        yuzu::test::spin_until([&] { return blocking.entered() >= 1; }, std::chrono::seconds{30}));

    // mtx_ is free here — no watchdogged op is running yet, so this is a safe
    // direct poll (hygiene rule 4), asserted BEFORE the watchdogged stop() below
    // rather than racing its own release. This is the aggregate counterpart to
    // T1's own single-executor active_worker_count() assertion.
    CHECK(f.engine->legacy_sink_executor_for_test().active_worker_count() == 1);
    CHECK(f.engine->active_io_workers() == 1);

    // stop() itself must complete promptly (#4783's actual fix): it joins the
    // guard thread (which never entered Write()) and then only stops the
    // executor from ADMITTING new sends — it does not wait for this
    // already-in-flight one.
    const bool finished = run_bounded([&] { f.engine->stop(); }, std::chrono::seconds{5},
                                      blocking, "CH-1(b) engine regression: stop() while blocked");
    CHECK(finished);

    // run_bounded's own cleanup already released the latch and joined the
    // stop() helper — re-asserting "still 1" here would race the worker
    // actually finishing, so wait for physical retirement instead and check it
    // lands at 0.
    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));
    CHECK(f.engine->legacy_sink_executor_for_test().active_worker_count() == 0);
    CHECK(f.engine->active_io_workers() == 0);
}

// ── CH-2 Windows: a rule-dropping full_sync must not hang on a wedged peer ──

TEST_CASE("CH-2 Windows: a full_sync push dropping a rule whose legacy-sink send is "
          "wedged does not hang apply_rules (#4783 fix proof)",
          "[guardian][engine][legacy_sink][chaos]") {
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
    yuzu::test::ScopeExit cleanup(
        [&] { require_legacy_sink_retired(*f.engine, blocking, "CH-2 cleanup"); });

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

    fs::remove(path_a); // drift on A only -> its offer()'d send parks in the blocking sink
    REQUIRE(
        yuzu::test::spin_until([&] { return blocking.entered() >= 1; }, std::chrono::seconds{30}));

    const auto arm_failures_before = f.engine->arm_failure_count();

    // apply_rules(full_sync=true, {B only}) unconditionally tears down EVERY
    // currently-armed guard (stop_all_guards_locked(), guardian_engine.cpp)
    // before re-arming from the new push — including A. #4783: A's guard
    // thread itself never entered Write(), so this join is prompt regardless
    // of A's send still being wedged on the executor's own worker.
    yuzu::agent::GuardianDispatchResult push_result;
    const bool finished =
        run_bounded([&] { push_result = f.make_push(
                              {LegacySinkFixture::make_file_exists_rule("r-b", path_b.string())},
                              /*full_sync=*/true); },
                    std::chrono::seconds{5}, blocking,
                    "CH-2: full_sync push dropping A while wedged");
    CHECK(finished);

    // Safe only now that run_bounded has returned: the latch has already
    // been released and the helper already joined (hygiene rule 4 — never
    // poll an mtx_-guarded accessor while a watchdogged op could still hold
    // mtx_).
    CHECK(push_result.exit_code == 0);
    CHECK(f.engine->armed_guard_count() == 1); // only B survives the full_sync
    CHECK(f.engine->arm_failure_count() == arm_failures_before); // B's re-arm is a routine success

    // Aggregate-count assertion (#4783 commit 3): wait for both A's now-released
    // send and B's arm-time compliant edge (queued behind it) to fully drain.
    REQUIRE(f.engine->retire_legacy_sink_workers_for_test(std::chrono::seconds{5}));
    CHECK(f.engine->active_io_workers() == 0);

    f.engine->stop(); // tidy, deterministic teardown before the fixture destructs
}

#endif // _WIN32
