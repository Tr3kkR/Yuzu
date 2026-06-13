#pragma once

/**
 * guard_systemd.hpp — systemd (Linux) Spark for Yuzu Guardian, the Linux twin of
 * the Windows ServiceGuard (guard_service.hpp).
 *
 * Watches ONE systemd unit's run state in real time over the system D-Bus
 * (sd-bus): it Subscribes to the systemd Manager, resolves the unit object path,
 * reads `ActiveState`, and arms a PropertiesChanged match on the unit. On a
 * terminal state change it compares the live state to the rule's desired state
 * (`service-running` / `service-stopped`) and reports a GuardDrift to its sink —
 * the GuardianEngine turns that into a GuaranteedStateEvent (platform=linux),
 * exactly as the Windows ServiceGuard does. This is the sd-bus analogue of
 * NotifyServiceStatusChangeW; latency is event-driven (~ms), not a poll.
 *
 * v1 SCOPE — OBSERVE ONLY. This guard detects and reports drift; it does NOT
 * enforce (no MaskUnit / StopUnit). Enforcement (the scoped polkit grant +
 * mask-persistence + the Linux critical-unit denylist) is a separate,
 * governance-gated change. An enforce-mode rule on Linux therefore observes only,
 * with a warning — drift is still detected and reported, just not remediated.
 *
 * STATE MAPPING (the landmine — settled deliberately). systemd's ActiveState
 * (active / reloading / inactive / failed / activating / deactivating /
 * maintenance) is RICHER than the two tokens the wire schema publishes
 * (service_support::kStates = {running, stopped}). v1 maps ONTO those two tokens
 * and adds NO new schema enum (which would force a server-schema + H2/G9 change):
 *   - service-running  → compliant iff ActiveState == active
 *   - service-stopped  → compliant iff ActiveState ∈ {inactive, failed, <absent>}
 *   - activating / deactivating / reloading / maintenance → TRANSITIONAL: held,
 *     never compared or emitted (mirrors the Windows guard holding on *_PENDING).
 * `masked` is an enforce DETAIL (v2), not a desired-state token.
 *
 * Proto-free and sd-bus-free by design (mirrors guard_service.hpp): the system bus
 * handle is held as an opaque `void*`, so <systemd/sd-bus.h> never leaks into a
 * translation unit that includes this header. On non-Linux the class is a no-op
 * (start() returns false) so the engine and tests build everywhere; the watch is
 * Linux-only. The state-mapping helpers below are PURE and compiled on every
 * platform (testable off-Linux against captured ActiveState strings), exactly as
 * dex_observer.hpp's extract_named_data is.
 */

#include <yuzu/plugin.h>             // YUZU_EXPORT
#include <yuzu/agent/guard.hpp>      // IGuard, GuardDrift, GuardSink
#include <yuzu/agent/guard_service.hpp> // ServiceGuard::Config / Desired (reused)

#include <atomic>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

namespace yuzu::agent {

/// systemd unit ActiveState, normalised. `Absent` is synthetic (the unit is not
/// loaded / NoSuchUnit — not a D-Bus value); `Unknown` is any string we do not
/// recognise (treated as transitional / held, never drifted, so a state we do not
/// understand can never raise a false positive).
enum class SystemdState {
    Active,       ///< "active"
    Reloading,    ///< "reloading"     (transitional)
    Inactive,     ///< "inactive"
    Failed,       ///< "failed"
    Activating,   ///< "activating"    (transitional)
    Deactivating, ///< "deactivating"  (transitional)
    Maintenance,  ///< "maintenance"   (transitional; rare)
    Absent,       ///< unit not loaded / NoSuchUnit (synthetic)
    Unknown,      ///< unrecognised ActiveState (held, never drifted)
};

/// Parse a systemd `ActiveState` property string to SystemdState. Pure — never
/// throws; an unrecognised value maps to Unknown. (Absent is never produced here;
/// the engine sets it when the unit fails to load.)
YUZU_EXPORT SystemdState parse_active_state(std::string_view active_state);

/// True for the systemd states that are MID-TRANSITION (or not understood): the
/// guard holds on these — no compare, no drift — and waits for a terminal state,
/// mirroring the Windows guard holding on *_PENDING.
YUZU_EXPORT bool systemd_state_is_transitional(SystemdState s);

/// Compliance against the rule's desired run state, for a TERMINAL state only
/// (callers gate on !systemd_state_is_transitional first). `service-running` is
/// satisfied only by Active; `service-stopped` by Inactive, Failed, or Absent (a
/// failed or absent unit is, definitionally, not running).
YUZU_EXPORT bool systemd_is_compliant(ServiceGuard::Desired want, SystemdState got);

/// The diagnostic token for GuardDrift.detected_value. Re-uses the Windows guard's
/// running/stopped/absent vocabulary where it maps, and keeps the systemd-native
/// word otherwise (failed / activating / …) — detected_value is a free-form
/// diagnostic string, NOT a schema enum, so this never touches the wire schema.
YUZU_EXPORT std::string_view systemd_state_token(SystemdState s);

/// systemctl ergonomics: a unit reference with no type suffix defaults to
/// `.service` (so an author may write "ssh" for "ssh.service"). A name that
/// already carries a '.' (ssh.service, foo.socket, bar.timer) is returned
/// unchanged. Pure.
YUZU_EXPORT std::string normalize_unit_name(std::string_view unit);

/// Defence-in-depth charset check, mirroring ServiceGuard::valid_service_name and
/// the server-side authoring validator: non-empty, <=256 chars, alphanumeric plus
/// `. _ - @`. Keeps the agent honest if a malformed name slips past the server.
YUZU_EXPORT bool valid_unit_name(std::string_view unit);

/// One live systemd unit run-state watch. start() opens the system bus and starts
/// the watch thread; the thread Subscribes, resolves the unit path, reads
/// ActiveState (the initial compare), arms a PropertiesChanged match, and services
/// it from a poll loop until stop(). Reuses ServiceGuard::Config (the service_name
/// field carries the systemd unit name; the enforce/resilience fields are ignored
/// in the v1 observe-only build). No-op off Linux (start() returns false).
class YUZU_EXPORT SystemdServiceGuard : public IGuard {
public:
    using Config = ServiceGuard::Config;
    using Desired = ServiceGuard::Desired;
    using Sink = GuardSink;

    SystemdServiceGuard(Config cfg, Sink sink);
    ~SystemdServiceGuard() override;
    SystemdServiceGuard(const SystemdServiceGuard&) = delete;
    SystemdServiceGuard& operator=(const SystemdServiceGuard&) = delete;

    /// Open the system bus and start the watch thread. Returns false if the unit
    /// name is invalid, the system bus is unavailable (non-systemd host →
    /// detect-only / unarmed for v1), or off Linux. A unit that does not yet exist
    /// is NOT a start failure — the watch arms and reports drift, polling for the
    /// unit's return (mirrors the Windows absent path).
    bool start() override;
    void stop() override;

    const std::string& rule_id() const override { return cfg_.rule_id; }

private:
    void run();

    Config cfg_;
    Sink sink_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
    int wake_fd_{-1};       ///< eventfd: stop() writes it to break the poll loop
    void* bus_{nullptr};    ///< sd_bus* (void* keeps sd-bus.h out of this header)
};

/// Platform factory for the `service-status-change` Spark: a SystemdServiceGuard on
/// Linux, the Windows/other ServiceGuard otherwise. Returns a unique_ptr<IGuard> so
/// the GuardianEngine dispatch stays platform-clean (mirrors make_dex_observer()).
/// Never null.
YUZU_EXPORT std::unique_ptr<IGuard> make_service_guard(ServiceGuard::Config cfg, GuardSink sink);

} // namespace yuzu::agent
