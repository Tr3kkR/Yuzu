#pragma once

/**
 * guard_service.hpp — Windows Service Control Manager (SCM) Spark for Yuzu
 * Guardian (delivery-plan PR5).
 *
 * Watches one Windows service's run state in REAL TIME via
 * NotifyServiceStatusChangeW (kernel-notified, ~0ms — the SCM analogue of
 * RegistryGuard's RegNotifyChangeKeyValue, NOT the Trigger Engine's status poll).
 * On a *terminal* run-state transition it compares the live state to the rule's
 * desired state (`service-running` / `service-stopped`) and reports a GuardDrift
 * to its sink — the GuardianEngine turns that into a GuaranteedStateEvent.
 *
 * Enforce mode drives the service back to its desired state via advapi32
 * service-control (StartServiceW / ControlService) — never `sc.exe` / `net start`
 * (design doc §17: "NOT sc.exe or net start"). Like RegistryGuard, enforcement is
 * gated by the per-rule resilience strategy (C3); detection + drift reporting
 * happen regardless of whether the fix is attempted.
 *
 * `service-disabled` (start-TYPE config, for which SCM fires no notification) is
 * intentionally NOT in this slice: it is registry-expressible TODAY via the
 * existing RegistryGuard on HKLM\SYSTEM\CurrentControlSet\Services\<name>\Start
 * (= 4), so CIS "service disabled" controls are already authorable as content.
 * Adding it here without an agent that arms it is exactly the H2/G9 drift the
 * server↔agent enum cross-check exists to prevent (see service_support::kStates).
 *
 * Deliberately proto-free and windows.h-free (the stop handle is a void*). On
 * non-Windows the class is a no-op (start() returns false) so the engine and tests
 * build everywhere; the watch is Windows-only for the MVP.
 */

#include <yuzu/plugin.h>                       // YUZU_EXPORT
#include <yuzu/agent/guard.hpp>                // IGuard, GuardDrift, GuardSink
#include <yuzu/agent/resilience_strategy.hpp> // ResilienceConfig (C3 retry policy)

#include <atomic>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

namespace yuzu::agent {

/// The desired run-state assertion tokens the ServiceGuard actually decodes. THIS
/// is the agent-side source of truth: the C3b server JSON-Schema enums and the
/// dashboard form MUST publish exactly these tokens, and `derive_rule_spec` MUST
/// reject anything outside them — otherwise a guard authored against an unhandled
/// state never arms (silent G11 errored). A server↔agent cross-check unit test
/// binds the published enum to this array so the two can never drift (H2 / G9),
/// exactly as `registry_support::kHives` does for the registry guard. Header-only
/// constexpr so the server test binary can read it without linking the
/// (Windows-only) guard implementation. `service-disabled` is deliberately absent
/// until the agent arms it.
namespace service_support {
inline constexpr std::string_view kStates[] = {"running", "stopped"};
} // namespace service_support

/// Service drift report alias — the common GuardDrift, kept as a name for the
/// service guard's call sites and tests. A service guard sets `guard_type`
/// "service".
using ServiceDrift = GuardDrift;

/// One Windows-service run-state watch. start() opens the SCM + service handle and
/// starts the watch thread; that thread registers NotifyServiceStatusChangeW
/// (whose immediate on-registration callback IS the initial compare — no
/// query-then-arm gap) and services notifications from an alertable wait until
/// stop().
class YUZU_EXPORT ServiceGuard : public IGuard {
public:
    /// Desired run state, encoded by the assertion TYPE (`service-running` →
    /// Running, `service-stopped` → Stopped). The string forms in
    /// service_support::kStates are the wire/author tokens.
    enum class Desired { Running, Stopped };

    struct Config {
        std::string rule_id;
        std::string rule_name;
        std::string service_name; ///< SCM service (key) name, e.g. "Spooler"
        Desired desired{Desired::Running};
        /// true = on drift, drive the service to `desired` via service-control
        /// (StartServiceW / ControlService); false = observe/audit only.
        bool enforce{false};
        /// C3: per-rule enforcement retry policy (Persist/Backoff/Bounded). Default
        /// Persist (immediate, never give up). Consulted in enforce mode only.
        ResilienceConfig resilience{};
        /// C3: event/sink debounce window (ms) — collapses rapid flaps into a count.
        /// 0 = emit every drift. Default 1000 (the RegistryGuard convention).
        std::uint64_t event_debounce_ms{1000};
    };
    using Sink = GuardSink;

    ServiceGuard(Config cfg, Sink sink);
    ~ServiceGuard() override;
    ServiceGuard(const ServiceGuard&) = delete;
    ServiceGuard& operator=(const ServiceGuard&) = delete;

    /// Open the SCM + service, arm the status-change notification, and start the
    /// watch thread. Returns false if the guard could not be started (empty/invalid
    /// service name, or non-Windows build). A service that does not yet exist is NOT
    /// a start failure — the watch arms and reports drift (and, in enforce mode for
    /// `service-running`, reports remediation.failed since a missing service cannot
    /// be started).
    bool start() override;
    void stop() override;

    const std::string& rule_id() const override { return cfg_.rule_id; }

private:
    void run();

    Config cfg_;
    Sink sink_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
    void* stop_event_{nullptr}; ///< HANDLE (void* keeps windows.h out of this header)
};

} // namespace yuzu::agent
