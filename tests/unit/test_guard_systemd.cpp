/**
 * test_guard_systemd.cpp — pure state-mapping logic for the Linux systemd service
 * guard (SystemdServiceGuard).
 *
 * The state-mapping helpers are compiled on EVERY platform (only the sd-bus engine
 * is Linux-gated), so these cases run and assert identically on Windows, macOS and
 * Linux CI — mirroring how the Windows EvtSubscribe engine's pure extractors are
 * tested off Windows. The landmine this pins down: systemd's richer ActiveState
 * vocabulary must collapse onto the two published tokens {running, stopped} WITHOUT
 * adding a schema enum, and transitional states must never raise a drift.
 */

#include <yuzu/agent/guard_systemd.hpp>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <string>
#include <type_traits>
#include <vector>

using namespace yuzu::agent;
using Desired = ServiceGuard::Desired;

namespace {
// A fixed steady_clock instant at `ms` milliseconds past the epoch — lets the
// decision-machine tests drive the debounce window deterministically (the absolute
// origin is irrelevant; only deltas matter to systemd_decide_emit).
std::chrono::steady_clock::time_point at(long long ms) {
    return std::chrono::steady_clock::time_point{std::chrono::milliseconds(ms)};
}
} // namespace

// Ownership contract (cpp-safety): the guard owns an eventfd + an sd_bus* + a
// std::thread; copy or move would double-close / double-join. Non-copyable AND
// non-movable, exactly like the other guards.
static_assert(!std::is_copy_constructible_v<SystemdServiceGuard>);
static_assert(!std::is_copy_assignable_v<SystemdServiceGuard>);
static_assert(!std::is_move_constructible_v<SystemdServiceGuard>);
static_assert(!std::is_move_assignable_v<SystemdServiceGuard>);

TEST_CASE("parse_active_state maps every systemd ActiveState", "[guardian][guard][systemd][state]") {
    CHECK(parse_active_state("active") == SystemdState::Active);
    CHECK(parse_active_state("reloading") == SystemdState::Reloading);
    CHECK(parse_active_state("inactive") == SystemdState::Inactive);
    CHECK(parse_active_state("failed") == SystemdState::Failed);
    CHECK(parse_active_state("activating") == SystemdState::Activating);
    CHECK(parse_active_state("deactivating") == SystemdState::Deactivating);
    CHECK(parse_active_state("maintenance") == SystemdState::Maintenance);
    // Unknown / garbage / empty never throws and never masquerades as a real state.
    CHECK(parse_active_state("") == SystemdState::Unknown);
    CHECK(parse_active_state("bogus") == SystemdState::Unknown);
    CHECK(parse_active_state("ACTIVE") == SystemdState::Unknown); // case-sensitive: D-Bus is lower
}

TEST_CASE("transitional states are held (never compared)", "[guardian][guard][systemd][state]") {
    // Mid-transition or not-understood → held: the guard waits for a terminal state.
    CHECK(systemd_state_is_transitional(SystemdState::Reloading));
    CHECK(systemd_state_is_transitional(SystemdState::Activating));
    CHECK(systemd_state_is_transitional(SystemdState::Deactivating));
    CHECK(systemd_state_is_transitional(SystemdState::Maintenance));
    CHECK(systemd_state_is_transitional(SystemdState::Unknown));
    // Terminal states are acted on.
    CHECK_FALSE(systemd_state_is_transitional(SystemdState::Active));
    CHECK_FALSE(systemd_state_is_transitional(SystemdState::Inactive));
    CHECK_FALSE(systemd_state_is_transitional(SystemdState::Failed));
    CHECK_FALSE(systemd_state_is_transitional(SystemdState::Absent));
}

TEST_CASE("service-running is satisfied only by active", "[guardian][guard][systemd][compliance]") {
    CHECK(systemd_is_compliant(Desired::Running, SystemdState::Active));
    CHECK_FALSE(systemd_is_compliant(Desired::Running, SystemdState::Inactive));
    CHECK_FALSE(systemd_is_compliant(Desired::Running, SystemdState::Failed));
    CHECK_FALSE(systemd_is_compliant(Desired::Running, SystemdState::Absent));
}

TEST_CASE("service-stopped is satisfied by inactive, failed, or absent",
          "[guardian][guard][systemd][compliance]") {
    CHECK(systemd_is_compliant(Desired::Stopped, SystemdState::Inactive));
    CHECK(systemd_is_compliant(Desired::Stopped, SystemdState::Failed)); // dead ⇒ not running
    CHECK(systemd_is_compliant(Desired::Stopped, SystemdState::Absent)); // gone ⇒ not running
    CHECK_FALSE(systemd_is_compliant(Desired::Stopped, SystemdState::Active));
}

TEST_CASE("detected_value token stays in the cross-platform vocabulary",
          "[guardian][guard][systemd][token]") {
    // running/stopped/absent reuse the Windows guard's words so the dashboard renders
    // uniformly; systemd-native words are kept for the states Windows has no name for.
    CHECK(systemd_state_token(SystemdState::Active) == "running");
    CHECK(systemd_state_token(SystemdState::Inactive) == "stopped");
    CHECK(systemd_state_token(SystemdState::Absent) == "absent");
    CHECK(systemd_state_token(SystemdState::Failed) == "failed");
    CHECK(systemd_state_token(SystemdState::Activating) == "activating");
    // The remaining tokens are the dashboard contract for these states too — pin them
    // so a future rename can't silently change what an operator sees.
    CHECK(systemd_state_token(SystemdState::Reloading) == "reloading");
    CHECK(systemd_state_token(SystemdState::Deactivating) == "deactivating");
    CHECK(systemd_state_token(SystemdState::Maintenance) == "maintenance");
    CHECK(systemd_state_token(SystemdState::Unknown) == "unknown");
}

TEST_CASE("normalize_unit_name applies the systemctl .service default",
          "[guardian][guard][systemd][unit]") {
    CHECK(normalize_unit_name("ssh") == "ssh.service");      // bare name ⇒ .service
    CHECK(normalize_unit_name("ssh.service") == "ssh.service"); // already suffixed
    CHECK(normalize_unit_name("foo.socket") == "foo.socket");   // other suffix preserved
    CHECK(normalize_unit_name("getty@tty1.service") == "getty@tty1.service");
}

TEST_CASE("valid_unit_name mirrors the server authoring charset", "[guardian][guard][systemd][unit]") {
    CHECK(valid_unit_name("ssh"));
    CHECK(valid_unit_name("ssh.service"));
    CHECK(valid_unit_name("getty@tty1.service"));
    CHECK(valid_unit_name("my-app_1.timer"));
    CHECK(valid_unit_name(std::string(256, 'a')));    // exactly at the 256 cap — accepted
    CHECK_FALSE(valid_unit_name(""));                 // empty
    CHECK_FALSE(valid_unit_name("ssh service"));      // space
    CHECK_FALSE(valid_unit_name("evil;rm -rf"));      // shell metachars
    CHECK_FALSE(valid_unit_name(std::string(257, 'a'))); // over the 256 cap
}

TEST_CASE("make_service_guard returns a non-null guard carrying the rule id",
          "[guardian][guard][systemd][factory]") {
    ServiceGuard::Config cfg;
    cfg.rule_id = "rule-abc";
    cfg.rule_name = "watch ssh";
    cfg.service_name = "ssh.service";
    cfg.desired = Desired::Stopped;
    auto g = make_service_guard(cfg, [](const GuardDrift&) {});
    REQUIRE(g != nullptr);
    CHECK(g->rule_id() == "rule-abc");
    // Note: start() is deliberately NOT called here — it spawns a watch thread and
    // (on Linux) touches the live system bus, which is integration territory, not a
    // unit test. Off Linux start() is a no-op returning false by construction.
}

// ── systemd_decide_emit — the transition state machine (pure, runs everywhere) ──
// This is the logic that previously lived only inside run()'s emit lambda, reachable
// only against a live bus. Extracted so the dedup + collapse-debounce + the UP-5
// commit rule are table-testable off Linux.

TEST_CASE("systemd_decide_emit: terminal-change machine", "[guardian][guard][systemd][emit]") {
    EmitState st;
    constexpr std::uint64_t deb = 1000;
    CHECK(systemd_decide_emit(Desired::Running, SystemdState::Activating, st, deb, at(0)).action ==
          EmitAction::Hold); // transitional → held, no commit
    CHECK(systemd_decide_emit(Desired::Running, SystemdState::Active, st, deb, at(10)).action ==
          EmitAction::CompliantSilent); // compliant edge committed, silent
    CHECK(systemd_decide_emit(Desired::Running, SystemdState::Active, st, deb, at(20)).action ==
          EmitAction::NoChange); // same terminal — silent
    CHECK(systemd_decide_emit(Desired::Running, SystemdState::Deactivating, st, deb, at(30)).action ==
          EmitAction::Hold);
    const auto d = systemd_decide_emit(Desired::Running, SystemdState::Inactive, st, deb, at(40));
    CHECK(d.action == EmitAction::Emit); // drift edge
    CHECK(d.collapsed_count == 0);
}

TEST_CASE("systemd_decide_emit: a debounce-suppressed drift is never lost (UP-5)",
          "[guardian][guard][systemd][emit]") {
    EmitState st;
    constexpr std::uint64_t deb = 1000;
    // First drift emits and opens the debounce window.
    CHECK(systemd_decide_emit(Desired::Running, SystemdState::Inactive, st, deb, at(0)).action ==
          EmitAction::Emit);
    // A DIFFERENT drift state inside the window is folded — and crucially NOT committed
    // to last_terminal, so the same state recurring inside the window stays foldable.
    CHECK(systemd_decide_emit(Desired::Running, SystemdState::Failed, st, deb, at(100)).action ==
          EmitAction::Suppressed);
    CHECK(systemd_decide_emit(Desired::Running, SystemdState::Failed, st, deb, at(200)).action ==
          EmitAction::Suppressed);
    // Past the window the Failed drift re-surfaces with its collapsed count. The bug was:
    // last_terminal advanced on suppress → this read as NoChange and Failed was lost.
    const auto d = systemd_decide_emit(Desired::Running, SystemdState::Failed, st, deb, at(1500));
    CHECK(d.action == EmitAction::Emit);
    CHECK(d.collapsed_count == 2);
}

TEST_CASE("systemd_decide_emit: re-drift after recovery still reports",
          "[guardian][guard][systemd][emit]") {
    EmitState st;
    constexpr std::uint64_t deb = 100;
    CHECK(systemd_decide_emit(Desired::Running, SystemdState::Failed, st, deb, at(0)).action ==
          EmitAction::Emit);
    // Recovery commits the compliant state...
    CHECK(systemd_decide_emit(Desired::Running, SystemdState::Active, st, deb, at(2000)).action ==
          EmitAction::CompliantSilent);
    // ...so a later relapse into the SAME failed state is a genuine change and re-emits.
    // (A naive "commit last_terminal only on emit" fix would lose this — the compliant
    // branch must commit too.)
    CHECK(systemd_decide_emit(Desired::Running, SystemdState::Failed, st, deb, at(4000)).action ==
          EmitAction::Emit);
}

TEST_CASE("systemd_decide_emit: service-stopped compliance direction",
          "[guardian][guard][systemd][emit]") {
    EmitState st;
    constexpr std::uint64_t deb = 1000;
    CHECK(systemd_decide_emit(Desired::Stopped, SystemdState::Inactive, st, deb, at(0)).action ==
          EmitAction::CompliantSilent); // stopped is compliant for want-stopped
    CHECK(systemd_decide_emit(Desired::Stopped, SystemdState::Active, st, deb, at(10)).action ==
          EmitAction::Emit);            // running is the drift
    CHECK(systemd_decide_emit(Desired::Stopped, SystemdState::Failed, st, deb, at(2000)).action ==
          EmitAction::CompliantSilent); // failed ⇒ not running ⇒ compliant
}

#if defined(__linux__)
// LIVE integration test — exercises the one path the pure cases cannot: the
// event-driven sd-bus PropertiesChanged transition on a REAL unit. Gated on
// YUZU_SYSTEMD_LIVE_UNIT so normal CI (incl. bus-less containers) skips it; runs on
// a real systemd box. Recipe:
//   sudo systemd-run --unit=yuzu-probe.service /usr/bin/sleep 3600   # active unit
//   ( sleep 4; sudo systemctl stop yuzu-probe.service ) &           # transition it
//   YUZU_SYSTEMD_LIVE_UNIT=yuzu-probe.service ./yuzu_agent_tests "[systemd][live]"
// Arms desired=running: the active unit is compliant (silent) until it stops, when
// the guard must emit a "stopped" drift via the PropertiesChanged path.
TEST_CASE("live: SystemdServiceGuard detects a real unit transition",
          "[guardian][guard][systemd][live]") {
    const char* unit = std::getenv("YUZU_SYSTEMD_LIVE_UNIT");
    if (!unit || !*unit) {
        SUCCEED("YUZU_SYSTEMD_LIVE_UNIT unset — skipping live systemd integration test");
        return;
    }
    struct Collector {
        std::mutex m;
        std::condition_variable cv;
        std::vector<GuardDrift> drifts;
        void push(const GuardDrift& d) {
            std::lock_guard lk(m);
            drifts.push_back(d);
            cv.notify_all();
        }
        bool wait_for(const std::string& val, std::chrono::milliseconds to) {
            std::unique_lock lk(m);
            return cv.wait_for(lk, to, [&] {
                for (const auto& d : drifts)
                    if (d.detected_value == val)
                        return true;
                return false;
            });
        }
    } col;

    ServiceGuard::Config cfg;
    cfg.rule_id = "live-1";
    cfg.rule_name = "live transition probe";
    cfg.service_name = unit;
    cfg.desired = Desired::Running; // active = compliant; a stop must drift
    cfg.enforce = false;
    cfg.event_debounce_ms = 0; // observe every transition (no collapse) in the test
    auto g = make_service_guard(cfg, [&](const GuardDrift& d) { col.push(d); });
    REQUIRE(g->start());
    // The unit is active at arm (compliant → silent). The external stop fires the
    // PropertiesChanged path; we should see a "stopped" drift within the window.
    const bool drifted = col.wait_for("stopped", std::chrono::seconds(30));
    g->stop();
    CHECK(drifted);
}
#endif
