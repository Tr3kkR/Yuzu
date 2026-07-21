/**
 * test_principal_quota.cpp — PR 4.4 (ADR-1005 class engine principals,
 * per-principal quota cap) primitive coverage for `PrincipalQuota`
 * (server/core/src/principal_quota.hpp): concurrency admission/rejection,
 * rate-bucket admission/rejection, per-principal isolation (the #1973
 * property per-IP limiting lacked — one principal exhausting its cap must
 * never touch another principal's quota), and `purge_stale`'s
 * never-purge-a-live-in-flight-principal invariant.
 *
 * Pure in-memory primitive — no PostgreSQL required.
 */

#include "principal_quota.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <latch>
#include <string>
#include <thread>
#include <vector>

using yuzu::server::PrincipalQuota;
using yuzu::server::PrincipalQuotaConfig;
using yuzu::server::QuotaLimit;
using yuzu::server::QuotaSide;
using yuzu::server::QuotaSlot;

namespace {

std::int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

// ── Concurrency ───────────────────────────────────────────────────────────

TEST_CASE("PrincipalQuota concurrency: admits up to max_concurrency, (N+1)th rejects",
          "[quota][primitive]") {
    PrincipalQuota q(
        PrincipalQuotaConfig{.max_concurrency = 3, .rate_per_second = 1000.0, .burst = 1000.0});
    std::vector<QuotaSlot> slots;
    for (int i = 0; i < 3; ++i) {
        auto slot = q.try_acquire("p1", QuotaSide::kEngine);
        REQUIRE(slot.admitted());
        slots.push_back(std::move(slot));
    }
    CHECK(q.in_flight("p1") == 3);

    auto overflow = q.try_acquire("p1", QuotaSide::kEngine);
    CHECK_FALSE(overflow.admitted());
    CHECK(overflow.decision().limit == QuotaLimit::kConcurrency);
    CHECK(overflow.decision().retry_after_ms > 0);
    // Reject leaves state byte-identical — still exactly 3 in flight.
    CHECK(q.in_flight("p1") == 3);
}

TEST_CASE("PrincipalQuota concurrency: destroying/reset()-ing an admitted slot frees exactly one",
          "[quota][primitive]") {
    PrincipalQuota q(
        PrincipalQuotaConfig{.max_concurrency = 2, .rate_per_second = 1000.0, .burst = 1000.0});
    auto a = q.try_acquire("p1", QuotaSide::kEngine);
    auto b = q.try_acquire("p1", QuotaSide::kEngine);
    REQUIRE(a.admitted());
    REQUIRE(b.admitted());
    CHECK(q.in_flight("p1") == 2);

    auto rejected = q.try_acquire("p1", QuotaSide::kEngine);
    CHECK_FALSE(rejected.admitted());

    a.reset(); // explicit release — idempotent, safe to call again
    a.reset();
    CHECK(q.in_flight("p1") == 1);

    auto c = q.try_acquire("p1", QuotaSide::kEngine);
    CHECK(c.admitted());
    CHECK(q.in_flight("p1") == 2);

    {
        auto d = std::move(b); // dtor at end of this scope releases the slot
        CHECK(q.in_flight("p1") == 2);
    }
    CHECK(q.in_flight("p1") == 1);

    c.reset();
    CHECK(q.in_flight("p1") == 0);
}

TEST_CASE("PrincipalQuota concurrency teeth: N+K threads racing try_acquire admit exactly N",
          "[quota][primitive]") {
    // The Catch2 assertion macros are NOT multithread-safe (repo convention,
    // see test_mcp_session.cpp), so worker threads only accumulate into
    // atomics; every CHECK runs on the main thread after the peak has been
    // observed and after join(). std::latch (no thread-id/steady_clock
    // salting) synchronizes threads to maximize overlap without sleeps.
    constexpr int kMaxConcurrency = 4;
    constexpr int kExtra = 3;
    constexpr int kThreads = kMaxConcurrency + kExtra;

    PrincipalQuota q(PrincipalQuotaConfig{
        .max_concurrency = kMaxConcurrency, .rate_per_second = 1000.0, .burst = 1000.0});

    std::latch start_latch(kThreads);   // all threads line up before racing try_acquire
    std::latch settled_latch(kThreads); // main waits until every thread has an outcome
    std::latch release_latch(1);        // main releases admitted threads after inspecting the peak

    std::atomic<int> admitted{0};
    std::atomic<int> rejected{0};
    std::atomic<int> bad_reject{0}; // a reject that isn't limit==kConcurrency + retry_after_ms>0

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&] {
            start_latch.arrive_and_wait();
            auto slot = q.try_acquire("racer", QuotaSide::kEngine);
            if (slot.admitted()) {
                ++admitted;
                settled_latch.count_down();
                release_latch.wait(); // hold the slot open so the peak is observable
                // slot destructs here, releasing on thread exit.
            } else {
                if (slot.decision().limit != QuotaLimit::kConcurrency ||
                    slot.decision().retry_after_ms <= 0) {
                    ++bad_reject;
                }
                ++rejected;
                settled_latch.count_down();
            }
        });
    }

    settled_latch.wait(); // every thread has an outcome now

    CHECK(admitted.load() == kMaxConcurrency);
    CHECK(rejected.load() == kExtra);
    CHECK(bad_reject.load() == 0);
    CHECK(q.in_flight("racer") == kMaxConcurrency); // exactly N admitted+live at peak

    release_latch.count_down(); // let the admitted threads release and exit
    for (auto& t : threads) t.join();

    CHECK(q.in_flight("racer") == 0); // every admitted slot released cleanly
}

// ── Rate ──────────────────────────────────────────────────────────────────

TEST_CASE("PrincipalQuota rate: burst exhausts, rejects with kRate and a refill-consistent retry",
          "[quota][primitive]") {
    // High concurrency ceiling so only the rate dimension can reject; each
    // admitted slot is released immediately so concurrency never
    // contributes to the rejection.
    PrincipalQuota q(
        PrincipalQuotaConfig{.max_concurrency = 1000, .rate_per_second = 1000.0, .burst = 3.0});
    for (int i = 0; i < 3; ++i) {
        auto slot = q.try_acquire("p1", QuotaSide::kEngine);
        REQUIRE(slot.admitted());
    }

    auto overflow = q.try_acquire("p1", QuotaSide::kEngine);
    CHECK_FALSE(overflow.admitted());
    CHECK(overflow.decision().limit == QuotaLimit::kRate);
    // At rate_per_second=1000 the theoretical refill time for one token is
    // ~1ms; bound loosely (generous CI-jitter slack) rather than pinning an
    // exact value — the honest contract is "positive and small", not a
    // specific millisecond count.
    CHECK(overflow.decision().retry_after_ms > 0);
    CHECK(overflow.decision().retry_after_ms < 200);
}

TEST_CASE("PrincipalQuota rate: tokens replenish after elapsed time", "[quota][primitive]") {
    PrincipalQuota q(
        PrincipalQuotaConfig{.max_concurrency = 1000, .rate_per_second = 1000.0, .burst = 2.0});
    // Drain the burst via try_rate_only (streaming-style — no concurrency
    // slot involved, isolating the rate dimension).
    CHECK(q.try_rate_only("p1", QuotaSide::kEngine).admitted);
    CHECK(q.try_rate_only("p1", QuotaSide::kEngine).admitted);
    auto exhausted = q.try_rate_only("p1", QuotaSide::kEngine);
    CHECK_FALSE(exhausted.admitted);
    CHECK(exhausted.limit == QuotaLimit::kRate);

    // At 1000 tokens/sec a 30ms sleep refills far more than the single
    // token needed — the primitive reads wall-clock internally (no
    // injectable clock), so this is a real wait with generous margin over
    // the ~1ms theoretical refill time, not a tight timing assertion.
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    auto replenished = q.try_rate_only("p1", QuotaSide::kEngine);
    CHECK(replenished.admitted);
}

// ── Isolation (the #1973 property) ───────────────────────────────────────

TEST_CASE("PrincipalQuota isolation: principal A exhausting its cap never rejects principal B "
          "(#1973)",
          "[quota][primitive]") {
    SECTION("concurrency isolation") {
        PrincipalQuota q(PrincipalQuotaConfig{
            .max_concurrency = 1, .rate_per_second = 1000.0, .burst = 1000.0});
        auto a1 = q.try_acquire("A", QuotaSide::kEngine);
        REQUIRE(a1.admitted());
        auto a2 = q.try_acquire("A", QuotaSide::kEngine);
        CHECK_FALSE(a2.admitted());
        CHECK(a2.decision().limit == QuotaLimit::kConcurrency);

        // B is a completely independent principal — must admit despite A
        // being fully saturated.
        auto b1 = q.try_acquire("B", QuotaSide::kEngine);
        CHECK(b1.admitted());
        CHECK(q.in_flight("A") == 1);
        CHECK(q.in_flight("B") == 1);
        CHECK(q.principal_count() == 2);
    }

    SECTION("rate isolation") {
        PrincipalQuota q(
            PrincipalQuotaConfig{.max_concurrency = 1000, .rate_per_second = 1.0, .burst = 1.0});
        auto a1 = q.try_rate_only("A", QuotaSide::kEngine);
        REQUIRE(a1.admitted);
        auto a2 = q.try_rate_only("A", QuotaSide::kEngine);
        CHECK_FALSE(a2.admitted);
        CHECK(a2.limit == QuotaLimit::kRate);

        // B's bucket starts full and untouched by A's exhaustion.
        auto b1 = q.try_rate_only("B", QuotaSide::kEngine);
        CHECK(b1.admitted);
    }
}

// ── purge_stale / principal_count ────────────────────────────────────────

TEST_CASE("PrincipalQuota purge_stale: evicts idle principals, never one with in_flight>0",
          "[quota][primitive]") {
    PrincipalQuota q(PrincipalQuotaConfig{.max_concurrency = 5,
                                          .rate_per_second = 1000.0,
                                          .burst = 1000.0,
                                          .idle_evict_seconds = 300});

    auto held = q.try_acquire("held", QuotaSide::kEngine);
    REQUIRE(held.admitted());

    auto idle_slot = q.try_acquire("idle", QuotaSide::kEngine);
    REQUIRE(idle_slot.admitted());
    idle_slot.reset(); // in_flight back to 0, but the principal stays tracked

    CHECK(q.principal_count() == 2);

    // Far beyond idle_evict_seconds for both principals' real last_seen.
    const std::int64_t far_future = now_epoch_seconds() + 10'000;
    q.purge_stale(far_future);

    // "held" survives (in_flight>0); "idle" (in_flight==0, idle past
    // threshold) does not.
    CHECK(q.principal_count() == 1);
    CHECK(q.in_flight("held") == 1);
    CHECK(q.in_flight("idle") == 0); // untracked now — reads back as 0

    // The surviving principal's slot release must still decrement
    // correctly after living through a purge pass that spared it.
    held.reset();
    CHECK(q.in_flight("held") == 0);

    // Now idle too — a second purge pass evicts it.
    q.purge_stale(far_future + 1);
    CHECK(q.principal_count() == 0);
}

TEST_CASE("PrincipalQuota principal_count tracks distinct principals seen", "[quota][primitive]") {
    PrincipalQuota q;
    CHECK(q.principal_count() == 0);
    (void)q.try_rate_only("A", QuotaSide::kEngine);
    CHECK(q.principal_count() == 1);
    (void)q.try_rate_only("B", QuotaSide::kEngine);
    CHECK(q.principal_count() == 2);
    (void)q.try_rate_only("A", QuotaSide::kEngine); // repeat — not a new principal
    CHECK(q.principal_count() == 2);
}
