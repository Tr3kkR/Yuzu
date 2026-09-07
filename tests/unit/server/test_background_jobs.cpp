// test_background_jobs.cpp — WS-10 slice 10.1: the background-job classification
// table (server/core/src/background_jobs.hpp) is the checked-in, CI-auditable
// guarantee that every background pass is classified for replica-safety. This
// test binds the table's internal consistency and completeness; the per-site
// YUZU_ASSERT_BACKGROUND_JOB consteval gate binds that no live pass escapes it.

#include "background_jobs.hpp"

#include <catch2/catch_test_macros.hpp>

#include <set>
#include <string_view>

using yuzu::server::BackgroundJobClass;
using yuzu::server::kBackgroundJobs;

namespace {
const yuzu::server::BackgroundJobDecl* find(std::string_view pass) {
    for (const auto& j : kBackgroundJobs)
        if (j.pass == pass)
            return &j;
    return nullptr;
}
} // namespace

TEST_CASE("background-job table is internally consistent", "[server][background-jobs]") {
    std::set<std::string_view> seen;
    for (const auto& j : kBackgroundJobs) {
        // Every field populated.
        CHECK_FALSE(j.pass.empty());
        CHECK_FALSE(j.owning_thread.empty());
        CHECK_FALSE(j.mechanism.empty());
        // Valid class.
        const bool valid_class = j.cls == BackgroundJobClass::ReplicaSafe ||
                                 j.cls == BackgroundJobClass::FencedLeaderOnly ||
                                 j.cls == BackgroundJobClass::DisabledUntilFixed;
        CHECK(valid_class);
        // Pass symbol is unique — the key the site-assert and the audit join on.
        INFO("duplicate pass symbol: " << j.pass);
        CHECK(seen.insert(j.pass).second);
    }
}

TEST_CASE("background-job table classifies every audited pass correctly",
          "[server][background-jobs]") {
    // Count tripwire — forces a conscious table update when a pass is added or
    // removed (a silent count change is exactly what WS-10 exists to prevent).
    // Update this number ONLY alongside a real classification change.
    CHECK(kBackgroundJobs.size() == 32);

    // The load-bearing per-pass calls — a regression here is the WS-10 hazard.
    SECTION("MUST-run-per-replica passes are ReplicaSafe, never leader-gated") {
        // ADR-2002 §5: leader-gating the event-outbox poll starves non-leader SSE.
        auto* poll = find("execution_tracker.poll_event_outbox_once");
        REQUIRE(poll != nullptr);
        CHECK(poll->cls == BackgroundJobClass::ReplicaSafe);
    }
    SECTION("the four #2508 clock-guard targets are ReplicaSafe (single-writer via guard)") {
        for (std::string_view p : {"app_perf_fleet_store.prune",
                                   "preflight_run_store.prune_older_than",
                                   "deployment_run_store.prune_older_than",
                                   "execution_tracker.reconcile_stale_concurrency_claims"}) {
            auto* j = find(p);
            INFO("missing/misclassified: " << p);
            REQUIRE(j != nullptr);
            CHECK(j->cls == BackgroundJobClass::ReplicaSafe);
        }
    }
    SECTION("side-effecting singletons are FencedLeaderOnly") {
        for (std::string_view p : {"schedule_runner.tick", "policy_evaluator.tick",
                                   "quarantine_reconciler.tick", "ca.publish_crl"}) {
            auto* j = find(p);
            INFO("missing/misclassified: " << p);
            REQUIRE(j != nullptr);
            CHECK(j->cls == BackgroundJobClass::FencedLeaderOnly);
        }
    }
    SECTION("nvd_sync is DisabledUntilFixed (engine-tier migration pending)") {
        auto* j = find("nvd_sync.do_sync");
        REQUIRE(j != nullptr);
        CHECK(j->cls == BackgroundJobClass::DisabledUntilFixed);
    }
}

TEST_CASE("background_job_index resolves membership at compile time",
          "[server][background-jobs]") {
    static_assert(yuzu::server::background_job_index("schedule_runner.tick") >= 0);
    static_assert(yuzu::server::background_job_index("no.such.pass") == -1);
    CHECK(yuzu::server::background_job_index("ca.publish_crl") >= 0);
    CHECK(yuzu::server::background_job_index("nope") == -1);
}
