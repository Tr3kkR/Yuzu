#pragma once

/**
 * spark_mechanism.hpp — the injectable watch-mechanism seam for event-driven
 * spark types (ADR-0021 Stage 1 PR 1b).
 *
 * Interval / Startup / Disk are timer-driven and serviced by the SparkEngine's
 * wheel (spark_engine.cpp). File / Registry / Service are EVENT-driven: they do
 * not sit on the wheel — a kernel notification, not a deadline, is the trigger.
 * Each such type is serviced by one `ISparkMechanism` that multiplexes EVERY
 * armed spark of its type onto O(mechanism) OS resources — one IOCP + thread
 * for file changes, one TP_WAIT pool for registry changes, one sd-bus
 * connection + thread (Linux) or one alertable-wait thread + one SCM
 * connection (Windows) for service changes — never O(rules).
 *
 * The seam is what keeps this PR testable off Windows: the real IOCP / TP_WAIT
 * impls are Windows-only (spark_file.cpp / spark_registry.cpp), but a test
 * fake wired via SparkEngine::register_mechanism() exercises the whole
 * arm / dedup / fan-out / disarm-teardown path on any platform (the
 * DiskReaderFn seam precedent, generalised to a stateful, thread-owning
 * mechanism — the tar ProcStreamCollector shape). Service (spark_service.cpp,
 * Stage-1 PR 1c) is the first mechanism real on TWO platforms at once (Linux
 * sd-bus + Windows SCM) rather than Windows-only.
 *
 * Platform contract (why arm() rejects rather than succeeds-inert off Windows):
 * `make_file_mechanism()` / `make_registry_mechanism()` return a real
 * mechanism on Windows and `nullptr` elsewhere; `make_service_mechanism()`
 * returns a real mechanism on Windows AND on Linux built with libsystemd
 * (`-DYUZU_HAVE_LIBSYSTEMD`, gated by the `systemd_guard` meson feature option
 * — the same option that gates guard_systemd.cpp), `nullptr` on macOS or a
 * Linux build without libsystemd. A SparkEngine with no mechanism for a type
 * REJECTS arm() of that type — preserving the spark.hpp invariant "Armed means
 * the engine is running a watcher for the spec" (a succeed-but-inert arm would
 * be armed with no watcher). This mirrors the guard_file / guard_registry /
 * guard_systemd precedent (no-op off-platform → never reads as armed). The
 * "Linux agent receives a cross-platform Baseline containing a file guard" UX
 * is Guardian's concern (Stage 2), not the detection primitive's.
 */

#include <yuzu/agent/spark.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::agent {

/// The engine's fire callback, handed to a mechanism at start(). The mechanism
/// calls it — from its OWN thread — when the watched condition for `key` fires.
/// `data` is std::monostate for file/registry (the event itself is the fact;
/// the consumer re-reads whatever state it asserts over). The engine's
/// implementation (SparkEngine::emit_event) looks the key up under its lock,
/// snapshots subscribers, releases the lock, then delivers — so a mechanism may
/// call emit() freely without risking the engine's lock (an inline consumer
/// that re-arms takes that lock).
///
/// MAY THROW - guard it on any thread where an escaping exception is fatal
/// (an OS callback, a detached worker): the engine's implementation copies the
/// key and the subscriber snapshot under its lock (spark_engine.cpp emit_event)
/// and the queued tier's deque push allocates (deliver()), none of it caught, so
/// std::bad_alloc can escape; only the Inline handler's own throw is contained
/// by deliver(). Returns void: there is no delivery acknowledgement, "submitted
/// without throwing" is all a mechanism can know (#2012/#3840 PR-B1).
using SparkEmitFn = std::function<void(const std::string& key, SparkData data)>;

/// The engine's fault/health callback (ADR-0021 Stage 1, governance B1). A
/// mechanism calls it — from its OWN thread — when a watch it had SUCCESSFULLY
/// armed can no longer be maintained (`faulted=true`: the watched key/dir was
/// deleted and re-arm failed, a registry re-arm returned an error, a future
/// sd-bus/SCM connection collapsed), and again when that watch recovers
/// (`faulted=false`). `reason` is a short human string for the log. This closes
/// the gap where "armed == a watcher is running" (spark.hpp) could silently
/// drift AFTER a successful arm: the engine folds the fault into per-key health
/// (SparkEngineStats::armed_faulted + watch_faults_total) so a deaf watch is
/// observable, never silent. Called with the engine lock released (like emit).
/// Idempotent per state — repeating the same faulted value is a no-op edge.
using SparkFaultFn =
    std::function<void(const std::string& key, bool faulted, std::string_view reason)>;

/// Point-in-time mechanism-internal counters (#1979), folded into
/// SparkEngineStats' mech_* fields by SparkEngine::stats() and surfaced the
/// same way (agent heartbeat status_tags — no /metrics endpoint). Every field
/// defaults to 0, so a mechanism with nothing to report (the cross-platform
/// test fake, spark_registry, spark_service today) needs no code — only
/// spark_file.cpp's teardown-quarantine machinery has anything to say yet.
///
/// CONSISTENCY CONTRACT: the fields are backed by independent atomics read
/// without a shared lock, so a returned SparkMechanismStats is a point-in-time
/// SKEW, not a coherent snapshot — never derive an invariant across two fields.
/// Note in particular that `retiring` CAN exceed `retiring_cap`: the cap gates
/// only new watch() calls, while teardown (unwatch / superseded-ancestor) is
/// deliberately never gated, so in-flight teardowns can overshoot the cap
/// (spark_file's watch() documents this) — it is NOT a `retiring <= retiring_cap`
/// invariant. Treat each field as its own independent gauge.
struct SparkMechanismStats {
    /// Watches cancelled (unwatch() or a superseded ancestor) but not yet
    /// drained by the mechanism's own worker — the #1979 retiring_ gauge.
    std::uint64_t retiring{0};
    /// The mechanism's fixed cap on `retiring` past which new watch() calls
    /// are refused (#1979); 0 means "no cap / not applicable". Exposed so an
    /// operator (and the test) can read how close `retiring` is to the limit
    /// rather than hardcoding the constant.
    std::uint64_t retiring_cap{0};
    /// New watches refused because retiring_ was at its cap (#1979) — a
    /// failed arm() call at the SparkEngine layer, never silent.
    std::uint64_t watch_rejected_total{0};
    /// Watches leaked to process lifetime because a cancelled I/O's
    /// completion never arrived within the shutdown budget (#1982) — should
    /// stay 0 in practice; the retiring_ cap bounds it structurally.
    std::uint64_t quarantined_total{0};
    /// Mechanism-internal operations that took longer than the mechanism's
    /// own "slow" threshold while holding its lock (#1980) — an early warning
    /// for a stalled watcher, not a hard fault.
    std::uint64_t slow_op_total{0};
    /// TRUE when the mechanism started but could NOT bind its OS facility, so every
    /// watch() will be refused: no systemd system bus (a container — Dockerfile.agent
    /// ships libsystemd0, but a container has no bus), OpenSCManager denied, or the
    /// IOCP/threadpool could not be created. The mechanism stays REGISTERED (so arm()
    /// gets an honest rejection rather than "unknown type"), which is exactly why this
    /// bit is needed: without it, `registered` and `functional` are indistinguishable
    /// on the wire, and an inert mechanism reports byte-identically to a healthy idle
    /// one — "looks healthy, can detect nothing".
    ///
    /// Known at start(), NOT at arm() — which is why it lands at rung 1 rather than
    /// waiting on #2084's armed-but-deaf liveness (governance Gate-3 cross-platform +
    /// Gate-6 sre, reached independently).
    bool inert{false};
};

/// One watch mechanism for one event-driven SparkType. Lifecycle mirrors the
/// engine: register (pre-start) → start(emit, fault) → watch/unwatch as sparks
/// arm/disarm while running → stop(). The engine calls start / watch / unwatch
/// / stop with its own `mu_` released - but NOT lock-free: every watch() and
/// unwatch() runs under `SparkEngine::mech_ops_mu_by_type_[type]`, the per-TYPE
/// serialiser (#1994 M2 / #2011), so a mechanism method that blocks on an OS
/// call stalls every other arm/disarm of the SAME type for exactly that long
/// (#2012/#3840). Two contract points follow (corrected in PR-B1; the previous
/// wording here claimed watch() "may block on OS handle setup without stalling
/// every other arm/disarm", which was true only across TYPES):
///   1. A mechanism is responsible for BOUNDING its own watch()/unwatch(): run
///      the blocking OS call on a worker it owns, wait at most a short budget
///      on the control path, and commit or hand the result off later. Registry
///      does this since PR-B1 (spark_registry.cpp, "Ownership / dispatch
///      protocol"); File and Service still block for the OS-call duration
///      (PR-B2/PR-B3).
///   2. A mechanism must NEVER call emit()/fault() synchronously from inside
///      watch()/unwatch() - not even on an immediate-success path. The engine's
///      per-type lock is on that call stack, and an Inline consumer reacting by
///      re-arming the same type would self-deadlock the non-recursive lock.
///      Deliver from a mechanism-owned thread, with the mechanism's own lock
///      released.
class ISparkMechanism {
public:
    virtual ~ISparkMechanism() = default;

    ISparkMechanism() = default;
    ISparkMechanism(const ISparkMechanism&) = delete;
    ISparkMechanism& operator=(const ISparkMechanism&) = delete;

    /// Begin the mechanism thread(s). `emit` and `fault` are retained for the
    /// mechanism's lifetime. Called exactly once by SparkEngine::start(), BEFORE
    /// the engine replays any watch() for a spark armed before start.
    virtual void start(SparkEmitFn emit, SparkFaultFn fault) = 0;

    /// Begin watching one armed spark. `params` is the variant alternative
    /// matching this mechanism's type (the engine guarantees the match).
    /// Called only while the mechanism is started. Distinct armed specs carry
    /// distinct keys; a mechanism MAY coalesce them onto shared OS resources
    /// (e.g. one ReadDirectoryChangesW per parent directory) and route a raw
    /// notification back to the matching key(s). Returns an error string on
    /// unrecoverable setup failure (the engine rolls the arm back).
    [[nodiscard]] virtual std::expected<void, std::string>
    watch(const std::string& key, const SparkParams& params) = 0;

    /// Stop watching one spark (its last subscription went). Idempotent; an
    /// unknown key is ignored. May be invoked concurrently with another
    /// unwatch(), with watch(), and with stop() — implementations must
    /// tolerate an unwatch() that arrives after stop() as an idempotent no-op
    /// (#1994 L3).
    virtual void unwatch(const std::string& key) = 0;

    /// Join the mechanism thread(s). Idempotent. Called by SparkEngine::stop()
    /// BEFORE consumer dispatch threads — a mechanism is a producer, like the
    /// wheel, so it must quiesce before its downstream consumers.
    virtual void stop() = 0;

    /// Point-in-time counters (#1979). Callable from any thread without
    /// engine-lock coordination — an implementation with counters to report
    /// backs them with atomics, never a lock shared with watch/unwatch/stop.
    /// Defaulted so existing/fake mechanisms need no change.
    ///
    /// MUST STAY LOCK-FREE — this is now LOAD-BEARING, not merely a preference
    /// (governance Gate-2 security). `SparkEngine::stats_by_type()` calls this while
    /// holding the engine's `mu_`, and a mechanism worker can hold its own lock while
    /// calling `emit_event()`, which takes `mu_`. A mechanism that acquires a lock in
    /// stats() therefore closes an ABBA cycle and can deadlock the agent. All three
    /// shipped mechanisms read only `std::atomic`s here. Keep it that way.
    [[nodiscard]] virtual SparkMechanismStats stats() const { return {}; }
};

/// Platform factory: a real IOCP + ReadDirectoryChangesW file-change mechanism
/// on Windows, `nullptr` on every other platform.
[[nodiscard]] YUZU_EXPORT std::unique_ptr<ISparkMechanism> make_file_mechanism();

/// Platform factory: a real TP_WAIT + RegNotifyChangeKeyValue registry-change
/// mechanism on Windows, `nullptr` on every other platform. This zero-argument
/// form constructs the mechanism with NO shared F3 counter (its detached probe
/// and drain workers are then counted only lane-locally) - it exists for tests
/// and for the platform-capability cross-check; production wiring uses the
/// counter-taking overload below.
[[nodiscard]] YUZU_EXPORT std::unique_ptr<ISparkMechanism> make_registry_mechanism();

/// Production factory (#2012/#3840 PR-B1): the same mechanism, with every
/// SparkDetachedLane it owns constructed over `f3_counter` - the agent-lifetime
/// orphan-exit counter (AgentImpl::spark_detached_workers_) that
/// guardian_active_io_workers() sums, so a probe or drain worker still parked at
/// shutdown is visible to the F3 hard-exit decision (spark_detached_call.hpp,
/// "F3 / §24"). Same platform contract as the zero-argument form: real on
/// Windows, `nullptr` elsewhere (the argument is ignored off Windows). A null
/// counter is accepted and behaves like the zero-argument form.
[[nodiscard]] YUZU_EXPORT std::unique_ptr<ISparkMechanism>
make_registry_mechanism(std::shared_ptr<std::atomic<std::size_t>> f3_counter);

/// Platform factory: a real multiplexed service/unit run-state mechanism — one
/// sd-bus connection servicing N `PropertiesChanged` matches on Linux built
/// with libsystemd, one alertable-wait thread + one SCM connection servicing N
/// `NotifyServiceStatusChangeW` registrations on Windows — and `nullptr` on
/// macOS or a Linux build without libsystemd (`systemd_guard` meson option),
/// where arm(Service) is then rejected per the platform contract above.
[[nodiscard]] YUZU_EXPORT std::unique_ptr<ISparkMechanism> make_service_mechanism();

/// Test seam (#2839): make the NEXT retire of a cancelled DirWatch run `hook` immediately
/// before the file mechanism grows `retiring_` to take ownership of it — the one statement
/// in that transfer that can allocate, and so the one place a std::bad_alloc could once
/// destroy a DirWatch with a live kernel read still pointing at its buffer and OVERLAPPED.
///
/// A FREE FUNCTION AT THE TU BOUNDARY, not a member, because WindowsFileMechanism lives in
/// spark_file.cpp's anonymous namespace: there is no per-mechanism header to hang a
/// `*_for_test` method on, and adding one would export an implementation detail from a
/// file whose whole point is that it stays private to its translation unit. Same "fault
/// phase" contract as SparkEngine::set_arm_fault_hook_for_test — the hook exists so a test
/// can AIM an allocation failure at one statement, which a real std::bad_alloc cannot be.
///
/// Returns true if the hook was installed — i.e. `mech` really is the Windows file
/// mechanism. FALSE on every non-Windows platform (where make_file_mechanism() returns
/// nullptr and there is nothing to hook) and for any other mechanism type, so a caller
/// that forgets to check gets a visible false rather than a silent no-op. Pass a null
/// `hook` to clear. Single-shot: the hook is consumed by the retire it fires on. Same
/// set-then-use contract as the engine's seams — no concurrent-access support.
[[nodiscard]] YUZU_EXPORT bool
set_file_retire_fault_hook_for_test(ISparkMechanism& mech, std::function<void()> hook);

/// Test controls for the Windows Registry mechanism (#2012/#3840 PR-B1). Same
/// TU-boundary free-function shape as set_file_retire_fault_hook_for_test above,
/// for the same reason (the class lives in spark_registry.cpp's anonymous
/// namespace). Zero / empty means "leave unchanged"; a null `probe_hook` clears
/// any installed hook. Set-then-use: no concurrent-access support.
struct RegistryMechanismTestControls {
    /// Runs on the detached probe worker, BEFORE its OS calls, with the subkey
    /// being probed. Parking here models a hung hive; throwing models a probe
    /// that failed inside the worker (surfaces as a WorkerThrew backend failure).
    std::function<void(std::string_view subkey)> probe_hook;
    std::size_t probe_lane_cap{0};
    std::size_t drain_lane_cap{0};
    std::size_t retiring_cap{0};
    std::chrono::milliseconds caller_wait_budget{0};
    std::chrono::milliseconds health_grace{0};
    std::chrono::milliseconds backend_retry_base{0};
    std::chrono::milliseconds admission_backoff_seed{0};
    std::chrono::milliseconds sweep_cadence{0};
};

/// Mechanism-internal counters the public SparkMechanismStats does not carry
/// (admission refusals, backend failures, discards, drains, synthetic fires).
/// Point-in-time skew like SparkMechanismStats - never derive an invariant
/// across two fields. Exposure on the heartbeat is a separate decision; this is
/// the test-visible surface only.
struct RegistryMechanismDebugCounters {
    std::uint64_t probe_launched{0};
    std::uint64_t probe_admission_rejected{0};
    std::uint64_t probe_launch_failed{0};
    std::uint64_t probe_backend_failed{0};
    std::uint64_t probe_discarded{0};
    std::uint64_t drains_launched{0};
    std::uint64_t drains_completed{0};
    std::uint64_t drains_admission_rejected{0};
    std::uint64_t drains_untracked{0}; ///< launched drains stop() cannot wait for (tracking alloc failed)
    std::uint64_t synthetic_fires{0};
    std::uint64_t health_edges{0};
    std::uint64_t emit_failed{0};    ///< emit() threw on submit (fire callback or sweeper)
    std::uint64_t resync_retries{0}; ///< restored resync debt re-staged by the sweeper
    std::size_t probe_workers_active{0};
    std::size_t drain_workers_active{0};
    std::size_t live_watches{0};
    std::size_t retiring{0};
    std::size_t drain_backlog{0};
};

/// Returns true if `mech` is the Windows Registry mechanism and the controls
/// were applied; false on every non-Windows platform and for any other
/// mechanism type (a caller that forgets to check gets a visible false).
[[nodiscard]] YUZU_EXPORT bool
set_registry_test_controls_for_test(ISparkMechanism& mech, RegistryMechanismTestControls controls);

/// nullopt on every non-Windows platform and for any other mechanism type.
[[nodiscard]] YUZU_EXPORT std::optional<RegistryMechanismDebugCounters>
registry_debug_counters_for_test(const ISparkMechanism& mech);

} // namespace yuzu::agent
