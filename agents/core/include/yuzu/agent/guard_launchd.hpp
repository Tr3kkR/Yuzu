#pragma once

/**
 * guard_launchd.hpp — launchd (macOS) Spark for Yuzu Guardian, the darwin twin of
 * the Windows ServiceGuard (guard_service.hpp) and the Linux SystemdServiceGuard
 * (guard_systemd.hpp).
 *
 * Watches launchd jobs' run state in the SYSTEM domain. launchd exposes no public
 * state-change notification API (design §19.2.3 / §21.1), so detection is a
 * `launchctl print system/<label>` poll overlaid with a kqueue EVFILT_PROC /
 * NOTE_EXIT watch on the job's live PID: a stop is detected in ~0ms via the kernel
 * event (which triggers an immediate re-poll to reclassify — KeepAlive may already
 * be respawning the job), while start/reload detection is bounded by the poll
 * cadence. On a terminal state change it compares the live state to the rule's
 * desired state (`service-running` / `service-stopped`) and reports a GuardDrift
 * to its sink — the GuardianEngine turns that into a GuaranteedStateEvent
 * (platform=macos), exactly as the Windows and Linux guards do.
 *
 * v1 SCOPE — OBSERVE ONLY (mirrors the Linux guard). macOS has no stable public
 * API for starting/stopping arbitrary launchd services (design §20: SMJobSubmit is
 * deprecated; SMAppService manages only the calling app's own services), so
 * enforcement is a separate governance-gated change (`command` escape hatch +
 * a dangerous_enforce_service_stop denylist extension). An enforce-mode rule on
 * macOS therefore observes only, with a warning — drift is still detected and
 * reported, just not remediated.
 *
 * STATE MAPPING (settled deliberately, the guard_systemd.hpp discipline).
 * `launchctl print`'s `state` vocabulary is mapped onto the two published tokens
 * (service_support::kStates = {running, stopped}) with NO new schema enum:
 *   - service-running  → compliant iff state == running
 *   - service-stopped  → compliant iff state ∈ {not running, waiting, <absent>}
 *     (a loaded-but-idle on-demand job is, definitionally, not running)
 *   - any unrecognised state → Unknown: HELD, never compared or emitted, so a
 *     state we do not understand can never raise a false positive.
 * A label launchd does not know ("Could not find service", exit 113) is Absent; a
 * transient failure (popen failure, unparseable output) is Unknown/held — never a
 * fabricated Absent, mirroring systemd_error_name_is_absence's fail-safe split.
 *
 * The LaunchdWatchCore surface (start(emit, fault) / watch / unwatch / stop) is
 * deliberately congruent with ISparkMechanism (spark_mechanism.hpp): when Spark
 * Stage 2 rehomes Guardian detection onto mechanisms, this core becomes the darwin
 * service mechanism's engine with a thin adapter — do not let the two surfaces
 * drift apart. Congruence covers the watch/emit LIFECYCLE only: the fault channel
 * here is one-way terminal (no `faulted=false` recovered edge like SparkFaultFn's
 * — cf. spark_service.cpp's reconnect path), so the Stage-2 adapter must supply
 * the health-edge semantics. (The spark factories themselves are untouched:
 * make_service_mechanism() keeps returning nullptr on macOS until that rehome.)
 *
 * Threading contract (core):
 *  - `emit` runs on the core's single watch thread: keep it non-blocking and NEVER
 *    call watch/unwatch/stop from inside it — stop() joins that thread and would
 *    deadlock. Calling the GuardSink from it is fine (every guard does).
 *  - watch/unwatch/stop are safe from any thread OTHER than the emit thread,
 *    with ONE stopper: concurrent stop() calls are unsupported (the join is not
 *    serialized — the engine's single-threaded guard lifecycle is the contract).
 *    An emit for a key may still be delivered while unwatch() runs (the watch
 *    thread verifies the key under the lock before copying the callback, but
 *    delivery is outside it); stop() joins, so no emit runs after stop() returns.
 *  - The poll subprocess is an unbounded local `launchctl print` (macOS ships no
 *    /usr/bin/timeout; the existing launchctl call sites share this posture) — a
 *    hung launchd would stall this guard's thread only, and effectively means the
 *    host is already dead.
 *
 * Proto-free; <sys/event.h> never leaks into this header (pimpl). On non-macOS
 * builds the core compiles as a stub (watch() reports unsupported) and the guard's
 * start() returns false, so the engine and tests build everywhere — the dex_macos
 * convention. The state-mapping helpers below are PURE and compiled on every
 * platform (testable off-macOS against captured `launchctl print` output), exactly
 * as guard_systemd.hpp's parse_active_state is.
 */

#include <yuzu/plugin.h>                // YUZU_EXPORT
#include <yuzu/agent/guard.hpp>         // IGuard, GuardDrift, GuardSink
#include <yuzu/agent/guard_service.hpp> // ServiceGuard::Config / Desired (reused)
#include <yuzu/agent/guard_systemd.hpp> // EmitAction / EmitDecision (reused)

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::agent {

/// launchd job run state, normalised. `Absent` is synthetic (launchd does not know
/// the label — "Could not find service"); `Unknown` is any `state` value we do not
/// recognise AND any transient query failure (treated as held, never drifted, so a
/// state we do not understand — or a blip — can never raise a false positive).
enum class LaunchdState {
    Running,    ///< "running"
    NotRunning, ///< "not running" (loaded, not executing)
    Waiting,    ///< "waiting" (loaded, waiting on demand/KeepAlive — not executing)
    Absent,     ///< label unknown to launchd (synthetic)
    Unknown,    ///< unrecognised state / transient query failure (held, never drifted)
};

/// The top-level fields of one `launchctl print system/<label>` job block that the
/// guard reasons about. `pid` is present only while the job is running.
struct LaunchdJobInfo {
    LaunchdState state{LaunchdState::Unknown};
    std::optional<std::int64_t> pid;
    std::string path;    ///< on-disk plist path (may be empty)
    std::string program; ///< executable path (may be empty)
};

/// Parse `launchctl print system/<label>` STDOUT to a LaunchdJobInfo. Pure — never
/// throws on malformed input; missing/unrecognised fields leave defaults (state
/// Unknown). Only TOP-LEVEL `key = value` lines are read: nested blocks
/// (arguments/environment/endpoints/coalitions) are skipped by brace-depth
/// tracking — load-bearing, because nested blocks contain their own `state =
/// active` lines that must not override the job's `state = not running`.
/// `launchctl print` output is explicitly NOT a stable API (Apple's own help
/// text) — hence the defensive posture: unknown keys ignored, unknown states
/// held. The recognised state vocabulary + the absence marker/exit-113 pairing
/// are single-version observations (macOS 26.5.2); the parse degrades toward
/// "held", never a false positive, on an unrecognised future format.
YUZU_EXPORT LaunchdJobInfo parse_launchctl_print(std::string_view text);

/// Classify one COMPLETED `launchctl print` invocation (exit code + combined
/// stdout/stderr). Absent requires BOTH the definitive "Could not find service"
/// marker AND a real failing exit (exit_code > 0; launchctl reports genuine
/// absence with exit 113) — a successful print containing the marker in
/// job-controlled fields parses normally. Every other failure (popen failure or
/// signal-killed child encoded as exit_code < 0 — even with the marker in
/// partial output — a failing exit without the marker, empty output) is
/// transient → Unknown/held, never a fabricated Absent (otherwise a fork blip
/// would raise a false "stopped" drift — the systemd_error_name_is_absence
/// discipline). A failing exit WITH parseable output also holds: never trust a
/// full job block from a failing launchctl. Pure.
YUZU_EXPORT LaunchdJobInfo classify_launchctl_print(int exit_code, std::string_view output);

/// True for the states the guard HOLDS on — no compare, no drift — waiting for a
/// state it understands. For launchd that is only Unknown: `launchctl print` shows
/// no mid-transition vocabulary (running / not running / waiting are all terminal).
YUZU_EXPORT bool launchd_state_is_transitional(LaunchdState s);

/// Compliance against the rule's desired run state, for a TERMINAL state only.
/// `service-running` is satisfied only by Running; `service-stopped` by
/// NotRunning, Waiting, or Absent (an idle or missing job is not running).
YUZU_EXPORT bool launchd_is_compliant(ServiceGuard::Desired want, LaunchdState got);

/// The diagnostic token for GuardDrift.detected_value. Reuses the cross-platform
/// running/stopped/absent vocabulary where it maps and keeps the launchd-native
/// word otherwise (waiting) — detected_value is a free-form diagnostic string, NOT
/// a schema enum, so this never touches the wire schema.
YUZU_EXPORT std::string_view launchd_state_token(LaunchdState s);

/// Defence-in-depth charset check, mirroring valid_unit_name and the server-side
/// authoring validator: non-empty, <=256 chars, alphanumeric plus `. _ - @`. The
/// label is interpolated into the launchctl command line, so this is also the
/// injection gate — the core re-checks it even though the guard checks first.
YUZU_EXPORT bool valid_launchd_label(std::string_view label);

/// Mutable per-watch dedup + debounce state threaded through launchd_decide_emit —
/// the launchd twin of EmitState (guard_systemd.hpp), same commit rules.
struct LaunchdEmitState {
    LaunchdState last_terminal{LaunchdState::Unknown};
    std::optional<std::chrono::steady_clock::time_point> last_emit;
    std::uint64_t suppressed{0};
};

/// PURE transition evaluator (compiled + tested on every platform). Identical
/// commit rules to systemd_decide_emit — commit `last_terminal` on the compliant
/// edge AND on an actual emit, never on a hold or a debounce-suppressed drift
/// (else a job flapping back into the SAME drift state reads as NoChange and the
/// suppressed drift is silently lost). Reuses EmitAction/EmitDecision.
YUZU_EXPORT EmitDecision launchd_decide_emit(ServiceGuard::Desired want, LaunchdState got,
                                             LaunchdEmitState& state, std::uint64_t debounce_ms,
                                             std::chrono::steady_clock::time_point now);

/// One delivered job-state observation: the classified result of a poll (periodic,
/// initial, or NOTE_EXIT-triggered). Delivered on every poll — consumers dedup via
/// launchd_decide_emit, so a steady state costs nothing on the wire.
struct LaunchdWatchEvent {
    std::string key; ///< the watch this observation belongs to
    LaunchdJobInfo info;
};

using LaunchdWatchEmitFn = std::function<void(const LaunchdWatchEvent&)>;
/// Fault channel (key, description) — kept for ISparkMechanism congruence. Fired
/// only when the watch thread stops TERMINALLY (kevent wait failure, an escaping
/// exception): fault means "this watch is dead", not "degraded". A per-PID
/// EVFILT_PROC registration loss merely degrades that watch to poll-only and is
/// logged, never faulted.
using LaunchdWatchFaultFn = std::function<void(const std::string&, const std::string&)>;

/// One multiplexed launchd job-state watch primitive: N labels serviced by ONE
/// watch thread owning one kqueue (EVFILT_USER stop wake + EVFILT_PROC NOTE_EXIT
/// per live job PID) and one `launchctl print` poll schedule. Consumers register
/// labels by key and receive LaunchdWatchEvents. This is the launchd analogue of
/// the spark service mechanism's "one connection servicing N registrations" shape.
/// The core is ONE-SHOT: start() once, stop() once — after stop() it cannot be
/// restarted; construct a fresh core instead (the engine constructs a fresh guard,
/// and therefore a fresh core, per arm).
class YUZU_EXPORT LaunchdWatchCore {
public:
    LaunchdWatchCore();
    ~LaunchdWatchCore(); ///< calls stop()

    LaunchdWatchCore(const LaunchdWatchCore&) = delete;
    LaunchdWatchCore& operator=(const LaunchdWatchCore&) = delete;

    /// Create the kqueue + watch thread and retain the callbacks. Call exactly
    /// once, before any watch(). If the kernel facilities cannot be armed (kqueue
    /// or the stop-wake registration fails — without which clean shutdown could
    /// not be guaranteed), the core marks itself unusable and every watch() fails.
    void start(LaunchdWatchEmitFn emit, LaunchdWatchFaultFn fault);

    /// Begin watching one launchd label under `key`. The label does not need to
    /// exist yet (an unknown label reports Absent and keeps polling for its
    /// return). Distinct watches need distinct keys — a duplicate key is an
    /// error. Returns an error string on an invalid label, a failed core, or a
    /// non-macOS build.
    [[nodiscard]] std::expected<void, std::string> watch(const std::string& key,
                                                         const std::string& label);

    /// Stop watching `key`. Unknown key → no-op. See the threading contract above
    /// for the in-flight-emit caveat.
    void unwatch(const std::string& key);

    /// Tear down the watch thread and kqueue. Idempotent. Joins the thread — no
    /// emit runs after this returns.
    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// One live launchd job run-state watch (macOS). start() validates the label,
/// arms a LaunchdWatchCore watch, and reports drift through the GuardSink. Reuses
/// ServiceGuard::Config (the service_name field carries the launchd label; the
/// enforce/resilience fields are ignored in the v1 observe-only build). No-op off
/// macOS (start() returns false).
class YUZU_EXPORT LaunchdServiceGuard : public IGuard {
public:
    using Config = ServiceGuard::Config;
    using Desired = ServiceGuard::Desired;
    using Sink = GuardSink;

    LaunchdServiceGuard(Config cfg, Sink sink);
    ~LaunchdServiceGuard() override;
    LaunchdServiceGuard(const LaunchdServiceGuard&) = delete;
    LaunchdServiceGuard& operator=(const LaunchdServiceGuard&) = delete;

    /// Arm the watch. Returns false if the label is invalid, the kernel watch
    /// facilities could not be armed, or off macOS. A label that does not exist
    /// yet is NOT a start failure — the watch arms and reports drift, polling for
    /// the job's arrival (mirrors the Windows/Linux absent path).
    bool start() override;
    void stop() override;

    const std::string& rule_id() const override { return cfg_.rule_id; }

private:
    void on_observation(const LaunchdJobInfo& info); ///< runs on the core thread

    Config cfg_;
    Sink sink_;
    // emit_state_ is declared BEFORE core_ so it is destroyed AFTER it: ~core_
    // joins the watch thread, so no in-flight emit can touch emit_state_ once it
    // begins destruction. (~LaunchdServiceGuard's explicit stop() enforces this
    // too; the ordering encodes the invariant if that body is ever refactored.)
    LaunchdEmitState emit_state_; ///< touched only on the core thread (start→join)
    LaunchdWatchCore core_;
};

} // namespace yuzu::agent
