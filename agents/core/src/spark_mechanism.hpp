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

#include <expected>
#include <functional>
#include <memory>
#include <string>

namespace yuzu::agent {

/// The engine's fire callback, handed to a mechanism at start(). The mechanism
/// calls it — from its OWN thread — when the watched condition for `key` fires.
/// `data` is std::monostate for file/registry (the event itself is the fact;
/// the consumer re-reads whatever state it asserts over). The engine's
/// implementation (SparkEngine::emit_event) looks the key up under its lock,
/// snapshots subscribers, releases the lock, then delivers — so a mechanism may
/// call emit() freely without risking the engine's lock (an inline consumer
/// that re-arms takes that lock).
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
};

/// One watch mechanism for one event-driven SparkType. Lifecycle mirrors the
/// engine: register (pre-start) → start(emit, fault) → watch/unwatch as sparks
/// arm/disarm while running → stop(). The engine calls start / watch / unwatch
/// / stop with NO engine lock held — a mechanism method may block on OS handle
/// setup without stalling every other arm/disarm/emit.
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
    [[nodiscard]] virtual SparkMechanismStats stats() const { return {}; }
};

/// Platform factory: a real IOCP + ReadDirectoryChangesW file-change mechanism
/// on Windows, `nullptr` on every other platform.
[[nodiscard]] YUZU_EXPORT std::unique_ptr<ISparkMechanism> make_file_mechanism();

/// Platform factory: a real TP_WAIT + RegNotifyChangeKeyValue registry-change
/// mechanism on Windows, `nullptr` on every other platform.
[[nodiscard]] YUZU_EXPORT std::unique_ptr<ISparkMechanism> make_registry_mechanism();

/// Platform factory: a real multiplexed service/unit run-state mechanism — one
/// sd-bus connection servicing N `PropertiesChanged` matches on Linux built
/// with libsystemd, one alertable-wait thread + one SCM connection servicing N
/// `NotifyServiceStatusChangeW` registrations on Windows — and `nullptr` on
/// macOS or a Linux build without libsystemd (`systemd_guard` meson option),
/// where arm(Service) is then rejected per the platform contract above.
[[nodiscard]] YUZU_EXPORT std::unique_ptr<ISparkMechanism> make_service_mechanism();

} // namespace yuzu::agent
