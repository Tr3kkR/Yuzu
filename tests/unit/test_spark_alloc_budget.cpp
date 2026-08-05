/**
 * test_spark_alloc_budget.cpp — #2270: the post-commit window allocates NOTHING.
 *
 * WHY THIS IS A SEPARATE EXECUTABLE. It replaces the global operator new/delete
 * to count allocations. That is process-wide and cannot be scoped to one test,
 * so it does not belong in the 1500-case agent binary, and it must be ABSENT
 * (not merely inert) from sanitizer builds, which own the allocator themselves.
 * meson builds this target only for `b_sanitize=none` on Linux.
 *
 * WHAT IT BUYS OVER THE FAULT SEAMS. test_spark_mechanism.cpp pins the OUTCOME
 * (no ghost when something throws in the window). It cannot pin the PREMISE —
 * that nothing in the window allocates in the first place — because a green run
 * proves nothing about a statement that only fails under memory pressure. That
 * gap is exactly how #2270 survived three review rounds: the round-3 fix deleted
 * the post-commit rollback on the stated grounds that only the log line could
 * still allocate there, and that claim was false and untested. These cases turn
 * the allocation census into an assertion that runs in CI.
 *
 * PORTABILITY, STATED PLAINLY. Executable-side replacement of operator new
 * interposes for libyuzu_agent_core.so on this ELF/libstdc++ build — MEASURED,
 * after an earlier review round asserted it could not. That is not a portable
 * contract: ELF preemption depends on visibility, direct binding and LTO;
 * Mach-O and the Windows CRT resolve allocation differently; and the exact
 * counts depend on this standard library's SSO threshold. So this is LINUX
 * MUTATION EVIDENCE, not the cross-platform pin — that stays with the fault
 * seams and the state assertions in test_spark_mechanism.cpp.
 */

#include "spark_engine.hpp"
#include "spark_mechanism.hpp"

#include <spdlog/spdlog.h>

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <mutex>
#include <new>
#include <set>
#include <string>

// ── the counter ──────────────────────────────────────────────────────────────
//
// thread_local and constant-initialised: no static-init ordering, no recursion,
// and the wheel/mechanism threads allocating concurrently cannot perturb a
// measurement taken on the arming thread (which is what every case here does).
namespace {
thread_local std::uint64_t g_allocs = 0;
thread_local bool g_counting = false;

/// Count allocations on THIS thread for the lifetime of the guard.
class AllocCount {
public:
    AllocCount() {
        g_allocs = 0;
        g_counting = true;
    }
    ~AllocCount() { g_counting = false; }
    AllocCount(const AllocCount&) = delete;
    AllocCount& operator=(const AllocCount&) = delete;
    [[nodiscard]] std::uint64_t count() const { return g_allocs; }
    void stop() { g_counting = false; }
};

void* tally_and_alloc(std::size_t n, std::size_t align) {
    if (g_counting)
        ++g_allocs;
    // A zero-size request must still yield a distinct pointer.
    void* p = (align > alignof(std::max_align_t))
                  ? std::aligned_alloc(align, ((n == 0 ? 1 : n) + align - 1) / align * align)
                  : std::malloc(n == 0 ? 1 : n);
    return p;
}

/// malloc-or-new_handler loop, per [new.delete.single].
void* alloc_or_throw(std::size_t n, std::size_t align) {
    for (;;) {
        if (void* p = tally_and_alloc(n, align))
            return p;
        std::new_handler h = std::get_new_handler();
        if (h == nullptr)
            throw std::bad_alloc{};
        h();
    }
}
} // namespace

// Every replaceable form, so no allocation escapes the count and every
// deallocation is matched to std::free (aligned_alloc/malloc both free()).
void* operator new(std::size_t n) { return alloc_or_throw(n, alignof(std::max_align_t)); }
void* operator new[](std::size_t n) { return alloc_or_throw(n, alignof(std::max_align_t)); }
void* operator new(std::size_t n, std::align_val_t a) {
    return alloc_or_throw(n, static_cast<std::size_t>(a));
}
void* operator new[](std::size_t n, std::align_val_t a) {
    return alloc_or_throw(n, static_cast<std::size_t>(a));
}
void* operator new(std::size_t n, const std::nothrow_t&) noexcept {
    return tally_and_alloc(n, alignof(std::max_align_t));
}
void* operator new[](std::size_t n, const std::nothrow_t&) noexcept {
    return tally_and_alloc(n, alignof(std::max_align_t));
}
void* operator new(std::size_t n, std::align_val_t a, const std::nothrow_t&) noexcept {
    return tally_and_alloc(n, static_cast<std::size_t>(a));
}
void* operator new[](std::size_t n, std::align_val_t a, const std::nothrow_t&) noexcept {
    return tally_and_alloc(n, static_cast<std::size_t>(a));
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
void operator delete(void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete(void* p, std::align_val_t, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* p, std::align_val_t, const std::nothrow_t&) noexcept { std::free(p); }

// ── fixtures ─────────────────────────────────────────────────────────────────

using namespace yuzu::agent;

namespace {

/// Deliberately long: a key must exceed this standard library's SSO threshold,
/// or the very copies these cases measure would be free and the pin inert.
const std::string kPath = "/var/lib/yuzu/spark-alloc-budget/a-deliberately-long-watch-path";
const std::string kKey = "file|10:" + kPath;

SparkSpec long_file_spec() { return SparkSpec{SparkType::File, FileSparkParams{kPath}}; }

/// Minimal mechanism. Its failure text is short ON PURPOSE — SSO, so returning
/// it allocates nothing and the counts below are the ENGINE's, not the fake's.
class CountingMechanism final : public ISparkMechanism {
public:
    void start(SparkEmitFn emit, SparkFaultFn) override { emit_ = std::move(emit); }
    std::expected<void, std::string> watch(const std::string& key, const SparkParams&) override {
        std::lock_guard lk(mu_);
        ++watch_calls_;
        if (fail_)
            return std::unexpected("nope"); // SSO: no allocation
        watched_.insert(key);
        return {};
    }
    void unwatch(const std::string& key) override {
        std::lock_guard lk(mu_);
        ++unwatch_calls_;
        watched_.erase(key);
    }
    void stop() override {}
    void set_fail(bool b) {
        std::lock_guard lk(mu_);
        fail_ = b;
    }
    int watch_calls() {
        std::lock_guard lk(mu_);
        return watch_calls_;
    }

private:
    std::mutex mu_;
    SparkEmitFn emit_;
    std::set<std::string> watched_;
    bool fail_{false};
    int watch_calls_{0};
    int unwatch_calls_{0};
};

CountingMechanism* wire(SparkEngine& engine) {
    auto m = std::make_unique<CountingMechanism>();
    CountingMechanism* raw = m.get();
    REQUIRE(engine.register_mechanism(SparkType::File, std::move(m)).has_value());
    return raw;
}

/// spdlog formats into heap buffers, and every logging statement in the measured
/// window is deliberately contained rather than removed (losing a log line beats
/// unwinding a live arm). Silence the logger for the measurement so the counts
/// describe the engine's own bookkeeping and do not drift with spdlog's internals.
class QuietLog {
public:
    QuietLog() : prev_(spdlog::get_level()) { spdlog::set_level(spdlog::level::off); }
    ~QuietLog() { spdlog::set_level(prev_); }
    QuietLog(const QuietLog&) = delete;
    QuietLog& operator=(const QuietLog&) = delete;

private:
    spdlog::level::level_enum prev_;
};

/// Grow sub_keys_'s bucket array past anything the measured arm needs, so a
/// rehash cannot land inside a measurement and read as an engine allocation.
void warm_buckets(SparkEngine& engine, SparkEngine::ConsumerId c) {
    std::vector<SparkEngine::SubscriptionId> ids;
    for (int i = 0; i < 128; ++i) {
        auto s = engine.arm(c, SparkSpec{SparkType::Interval,
                                         IntervalSparkParams{static_cast<std::uint64_t>(1000 + i)}});
        REQUIRE(s.has_value());
        ids.push_back(*s);
    }
    for (auto id : ids)
        engine.disarm(id);
}

} // namespace

TEST_CASE("the interposer actually reaches the engine's allocations", "[spark][alloc]") {
    // Guards against the whole file silently becoming a no-op: if a future
    // toolchain change stops the executable-side replacement from preempting
    // libyuzu_agent_core.so, every budget below would pass at zero and prove
    // nothing. An arm of a FRESH key must allocate (map nodes, at minimum).
    SparkEngine engine;
    wire(engine);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    QuietLog quiet;

    std::uint64_t n = 0;
    {
        AllocCount counting;
        (void)engine.arm(*c, long_file_spec());
        n = counting.count();
    }
    CHECK(n > 0);
    engine.stop();
}

TEST_CASE("arm_impl: the failed-watch path allocates nothing after the commit (#2270)",
          "[spark][alloc]") {
    // The window round 3 got wrong. Counting starts inside the mechanism's
    // watch() — i.e. after the commit, after the publish, after the "armed" log —
    // and ends when arm() returns, so it covers exactly: the mechanism's return,
    // drop_key_locked, the error completion, and the return itself.
    //
    // MUTATION EVIDENCE: restoring the pre-fix concat
    //   std::string("watch mechanism failed to arm '") + key + "': " + w.error()
    // makes this 3, not 0.
    SparkEngine engine;
    CountingMechanism* mech = wire(engine);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    warm_buckets(engine, *c);
    QuietLog quiet;

    mech->set_fail(true);
    bool armed_counter = false;
    engine.set_arm_fault_hook_for_test([&](int phase) {
        if (phase == SparkEngine::kArmFaultPhaseBeforeSubKeys) {
            g_allocs = 0;
            g_counting = true;
            armed_counter = true;
        }
    });
    auto sub = engine.arm(*c, long_file_spec());
    g_counting = false;
    const std::uint64_t post_commit = g_allocs;
    engine.set_arm_fault_hook_for_test(nullptr);

    REQUIRE_FALSE(sub.has_value());
    REQUIRE(armed_counter);
    REQUIRE(mech->watch_calls() == 1);
    CHECK_FALSE(sub.error().empty()); // the error still arrives, from the bounded buffer
    // Budget: the sub_keys_ emplace and NOTHING after it. That emplace costs TWO,
    // not one — the map node, plus a heap buffer for the key, which is longer than
    // this standard library's SSO threshold (measured directly: the same emplace
    // with a short key costs 1, which is also why kPath is deliberately long — a
    // short key would hide a regression inside the SSO buffer).
    // Everything the failure path does after it — the mechanism's return,
    // drop_key_locked, completing the error message, returning it — adds nothing.
    CHECK(post_commit == 2);
    CHECK(engine.stats().armed_sparks == 0);
    engine.stop();
}

TEST_CASE("arm_impl: the deduped commit publishes without allocating (#2270 reserve pin)",
          "[spark][alloc]") {
    // The load-bearing, previously UNPINNED reserve() at the dedup branch. Counting
    // is armed from the phase-1 fault hook, which fires immediately before the last
    // in-lock allocating step, so the budget is the sub_keys_ emplace and nothing
    // else: TWO allocations, the map node plus the heap buffer for the over-SSO key
    // (measured; the same emplace with a short key costs 1). The publishing
    // push_back must contribute nothing — it writes into capacity reserve() took
    // BEFORE the commit.
    //
    // MUTATION EVIDENCE: deleting `existing->subs.reserve(existing->subs.size() + 1)`
    // makes this 3 — the push_back reallocates the vector AFTER the commit, which is
    // precisely the throw site the reserve exists to move out of the window. Deleting
    // it leaves every other test in the repo green (measured); this is the only case
    // that fails.
    SparkEngine engine;
    wire(engine);
    auto c = engine.register_consumer("c", [](const SparkEvent&) {});
    REQUIRE(c.has_value());
    engine.start();
    warm_buckets(engine, *c);
    QuietLog quiet;

    auto first = engine.arm(*c, long_file_spec());
    REQUIRE(first.has_value());

    std::uint64_t post_commit = 0;
    bool armed_counter = false;
    engine.set_arm_fault_hook_for_test([&](int phase) {
        if (phase == SparkEngine::kArmFaultPhaseBeforeSubKeys) {
            g_allocs = 0;
            g_counting = true;
            armed_counter = true;
        }
    });
    auto second = engine.arm(*c, long_file_spec()); // dedups onto the existing key
    g_counting = false;
    post_commit = g_allocs;
    engine.set_arm_fault_hook_for_test(nullptr);

    REQUIRE(second.has_value());
    REQUIRE(armed_counter);
    CHECK(post_commit == 2); // the sub_keys_ emplace (node + key buffer), and nothing else
    engine.stop();
}
