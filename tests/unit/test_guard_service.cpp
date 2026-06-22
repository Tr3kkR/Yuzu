/**
 * test_guard_service.cpp — pure compliance + compliant-edge logic for the Windows
 * ServiceGuard.
 *
 * The Windows SCM watch itself (NotifyServiceStatusChangeW) has no unit harness — it
 * is integration-tested against a real service (e.g. Spooler) in Windows UAT. The
 * DECISION logic, however, is pure and lifted into guard_service.hpp, so it compiles
 * and asserts identically on every platform here, mirroring test_guard_systemd.cpp.
 *
 * These cases pin the Slice-B fix: a compliant service must emit guard.compliant
 * ONCE on the edge INTO compliant (so it reads "compliant", not "pending", in the
 * per-(agent,rule) census), while steady compliant stays silent and any drift is
 * always reported. Before the fix the compliant path was a silent short-circuit —
 * which is exactly what this test now prevents from regressing.
 */

#include <yuzu/agent/guard_service.hpp>

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <type_traits>

using namespace yuzu::agent;
using Desired = ServiceGuard::Desired;

// Ownership contract (cpp-safety): the guard owns a HANDLE (stop event) + a
// std::thread, and holds a std::atomic; copy or move would double-close / double-join.
// Non-copyable AND non-movable, exactly like the other guards.
static_assert(!std::is_copy_constructible_v<ServiceGuard>);
static_assert(!std::is_copy_assignable_v<ServiceGuard>);
static_assert(!std::is_move_constructible_v<ServiceGuard>);
static_assert(!std::is_move_assignable_v<ServiceGuard>);

TEST_CASE("service_state_token maps every state", "[guardian][guard][service][state]") {
    CHECK(service_state_token(ServiceState::Running) == "running");
    CHECK(service_state_token(ServiceState::Stopped) == "stopped");
    CHECK(service_state_token(ServiceState::Paused) == "paused");
    CHECK(service_state_token(ServiceState::Absent) == "absent");
}

TEST_CASE("service_is_compliant: running- vs stopped-desired (absent is compliant when stopped)",
          "[guardian][guard][service][compliant]") {
    // service-running: only Running satisfies it.
    CHECK(service_is_compliant(Desired::Running, ServiceState::Running));
    CHECK_FALSE(service_is_compliant(Desired::Running, ServiceState::Stopped));
    CHECK_FALSE(service_is_compliant(Desired::Running, ServiceState::Paused));
    CHECK_FALSE(service_is_compliant(Desired::Running, ServiceState::Absent));
    // service-stopped: Stopped AND Absent are compliant — an absent service is,
    // definitionally, not running, so it does not drift a "must be stopped" rule.
    CHECK(service_is_compliant(Desired::Stopped, ServiceState::Stopped));
    CHECK(service_is_compliant(Desired::Stopped, ServiceState::Absent));
    CHECK_FALSE(service_is_compliant(Desired::Stopped, ServiceState::Running));
    CHECK_FALSE(service_is_compliant(Desired::Stopped, ServiceState::Paused));
}

TEST_CASE("service_classify_edge: compliant fires ONCE on the edge, then steady is silent",
          "[guardian][guard][service][edge]") {
    std::optional<bool> last; // nullopt = never compared (fresh arm)
    // The initial on-registration compare against a compliant service is the EDGE —
    // this is the fix (it was silent before, leaving the guard "pending" forever).
    CHECK(service_classify_edge(Desired::Running, ServiceState::Running, last) ==
          ServiceEmit::CompliantEdge);
    REQUIRE(last.has_value());
    CHECK(*last == true);
    // Steady compliant → silent (network-kindness / NFR).
    CHECK(service_classify_edge(Desired::Running, ServiceState::Running, last) ==
          ServiceEmit::CompliantSteady);
    CHECK(*last == true);
}

TEST_CASE("service_classify_edge: drift is reported, recovery re-emits a compliant edge",
          "[guardian][guard][service][edge]") {
    std::optional<bool> last;
    CHECK(service_classify_edge(Desired::Running, ServiceState::Running, last) ==
          ServiceEmit::CompliantEdge);
    // Service stops → drift (the guard's primary job — must still fire post-refactor).
    CHECK(service_classify_edge(Desired::Running, ServiceState::Stopped, last) == ServiceEmit::Drift);
    CHECK(*last == false);
    // Each non-compliant observation is a drift (debounce/dedup is the caller's job).
    CHECK(service_classify_edge(Desired::Running, ServiceState::Paused, last) == ServiceEmit::Drift);
    CHECK(*last == false);
    // Recovery → a compliant EDGE again (NOT steady), so the return-to-compliant is
    // reported and the census flips back to compliant.
    CHECK(service_classify_edge(Desired::Running, ServiceState::Running, last) ==
          ServiceEmit::CompliantEdge);
    CHECK(*last == true);
}

TEST_CASE("service_classify_edge: service-stopped rule — absent is a compliant edge, running drifts",
          "[guardian][guard][service][edge]") {
    std::optional<bool> last;
    CHECK(service_classify_edge(Desired::Stopped, ServiceState::Absent, last) ==
          ServiceEmit::CompliantEdge);
    CHECK(*last == true);
    CHECK(service_classify_edge(Desired::Stopped, ServiceState::Running, last) == ServiceEmit::Drift);
    CHECK(*last == false);
}
