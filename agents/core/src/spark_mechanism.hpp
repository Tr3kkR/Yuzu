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
    /// Work the mechanism had to abandon at stop() instead of completing:
    /// File - watches leaked to process lifetime because a cancelled I/O's
    /// completion never arrived within the shutdown budget (#1982); Registry -
    /// establishment probes still parked on a detached worker when stop()
    /// returned (leaked-and-counted, the worker self-disposes and is F3-counted).
    /// Should stay 0 in practice; the retiring_ cap bounds File's structurally.
    std::uint64_t quarantined_total{0};
    /// Watch-establishment work that exceeded the mechanism's own threshold
    /// (#1980): File - an arm-path OS operation over its slow threshold while
    /// holding its lock; Registry - an accepted establishment or re-arm
    /// obligation still unestablished past its health grace (counted by the
    /// sweeper, the OS call itself runs off-lock). An early warning for a
    /// stalled or refused watcher, not a hard fault.
    std::uint64_t slow_op_total{0};
    /// TRUE when the mechanism started but could NOT bind its OS facility, so every
    /// watch() will be refused: no systemd system bus (a container — Dockerfile.agent
    /// ships libsystemd0, but a container has no bus), OpenSCManager denied, or the
    /// IOCP/threadpool could not be created; Registry also raises it while its
    /// sweeper (the sole producer of late commits and health edges) has failed
    /// several consecutive passes, and clears it on the next successful pass
    /// (#2012 PR-B1). The mechanism stays REGISTERED (so arm()
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
///      protocol"); File does this since PR-B2 (spark_file.cpp, watch()'s own
///      caller-wait-budget + off-lock discovery probe). Service's
///      watch()/unwatch() are already O(1) queue pushes but its SCM
///      open/notify still run head-of-line on its worker (PR-B3, not yet
///      landed).
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
/// on Windows, `nullptr` on every other platform. This zero-argument form
/// constructs the mechanism with NO shared F3 counter (its detached discovery
/// probes are then counted only lane-locally) - it exists for tests and the
/// platform-capability cross-check; production wiring uses the counter-taking
/// overload below (#2012/#3840 PR-B2, mirrors make_registry_mechanism's split).
[[nodiscard]] YUZU_EXPORT std::unique_ptr<ISparkMechanism> make_file_mechanism();

/// Production factory (#2012/#3840 PR-B2): the same mechanism, with its
/// discovery-probe SparkDetachedLane constructed over `f3_counter` - the
/// agent-lifetime orphan-exit counter (AgentImpl::spark_detached_workers_)
/// that guardian_active_io_workers() sums, so a probe still parked at
/// shutdown is visible to the F3 hard-exit decision (spark_detached_call.hpp,
/// "F3 / §24"). Same platform contract as the zero-argument form: real on
/// Windows, `nullptr` elsewhere (the argument is ignored off Windows). A null
/// counter is accepted and behaves like the zero-argument form.
[[nodiscard]] YUZU_EXPORT std::unique_ptr<ISparkMechanism>
make_file_mechanism(std::shared_ptr<std::atomic<std::size_t>> f3_counter);

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

/// Test controls for the Windows File mechanism (#2012/#3840 PR-B2 - the
/// off-lock discovery/open restructure, mirroring RegistryMechanismTestControls
/// below for the same reason: WindowsFileMechanism lives in spark_file.cpp's
/// anonymous namespace, so this is a TU-boundary free-function seam, not a
/// method. Zero / empty means "leave unchanged"; a null `probe_hook` clears any
/// installed hook. Set-then-use: no concurrent-access support. A later call does
/// NOT reset a field left at zero/empty in that call's own struct - a multi-phase
/// test that lowers a cap (or any other scalar here) in one call must raise it
/// again explicitly in a later call, or it stays lowered for the rest of the
/// test (see the #2012 PR-B2 "admission refusal is never counted as a backend
/// failure" test in test_spark_mechanism.cpp for a flake this caused).
struct FileMechanismTestControls {
    /// Runs on the detached discovery-probe worker, BEFORE its OS calls, with
    /// the directory path being probed (the ORIGINAL target path passed to
    /// reserve_probe_locked() - not each ancestor candidate the walk visits).
    /// Parking here models a hung/unresponsive filesystem path; throwing models
    /// a probe that failed inside the worker (surfaces as a WorkerThrew backend
    /// failure). Null clears it.
    std::function<void(std::wstring_view dir)> probe_hook;
    /// Runs on run()'s own worker thread inside run_off_lock(), off-lock, on
    /// any pass that staged at least one probe launch - right after that
    /// launch loop, before dispatch. Throwing here models an allocation
    /// failure landing after a probe in the SAME pass has already launched
    /// successfully but before publish_pass_locked() can commit it (the same
    /// interleaving PR #4225's review found for spark_registry.cpp). Fires
    /// only when a launch was actually staged, so a test can arm it once, up
    /// front, with no timing race against run()'s own cadence. Null clears it.
    std::function<void()> emit_bookkeeping_hook;
    /// Runs on run()'s own worker thread, under mu_, at the very top of
    /// route_noop_rearm() (an ancestor watch's fire -> reissue path) - BEFORE
    /// the real ReadDirectoryChangesW reissue - with the ancestor's own `dir`
    /// (the resolved path a DEPENDENT shelters under, i.e. DirWatch::dir on
    /// the ancestors_ entry, not a dependent's own target path). Returning
    /// true forces this reissue to be treated as FAILED without making the
    /// real OS call: io_pending is cleared and the handle dropped exactly as
    /// a genuine synchronous ReadDirectoryChangesW failure would leave them,
    /// so the caller's existing `if (!route_noop_rearm(w))
    /// invalidate_ancestor_locked(w);` branch runs for real - this is
    /// the only way to deterministically exercise the #829 fix (a failed
    /// reissue must invalidate the ancestor and every dependent, not leave
    /// nothing to trigger recovery) without racing a real filesystem delete
    /// against the kernel's own completion timing. Returning false (or a
    /// null hook) lets the real reissue proceed normally. Null clears it.
    std::function<bool(std::wstring_view ancestor_dir)> ancestor_rearm_fail_hook;
    /// Runs on run()'s own worker thread, under mu_, right after a REAL
    /// completion is dequeued and its owning DirWatch identified - BEFORE
    /// `ok` is used for anything (process_completion_locked's own dispatch,
    /// work.consumed_ok) - with the watch's own `dir` (real target or
    /// ancestor). Returning true overrides `ok` to FALSE for this pass,
    /// regardless of what GetQueuedCompletionStatus actually reported:
    /// `bytes`/`ov` are untouched, so a real notification's data is still
    /// whatever the kernel delivered, but process_completion_locked's `!ok`
    /// branch runs exactly as it would for a genuine backend failure. This
    /// is the deterministic way to reach that branch - forcing a REAL
    /// ReadDirectoryChangesW failure (deleting the watched directory,
    /// closing its handle) is neither reliable across filesystems nor
    /// reproducible without racing the kernel's own completion timing; this
    /// hook needs a real completion to already be in flight (a file
    /// write/rename under the watched dir, or an ancestor's own read), it
    /// only overrides how that arrival is INTERPRETED. Returning false (or a
    /// null hook) leaves `ok` as the kernel reported it. Null clears it.
    /// MUST NOT THROW (unlike every other hook in this struct): this call
    /// site sits before run()'s per-pass try block, on the worker thread
    /// with no catch-all — an escaping exception here terminates the
    /// process rather than modeling a contained pass failure.
    std::function<bool(std::wstring_view dir)> notify_fail_hook;
    /// Runs on run()'s own worker thread, under mu_, as the FIRST statement
    /// of invalidate_ancestor_locked() (#2012/#3840 PR-B2 review round-3
    /// closure pass) - before `dependents.reserve()`, the one allocating
    /// statement in that function - with the ancestor's own `dir`. Throwing
    /// here models that reserve() failing, exercising process_completion_
    /// locked()'s two local catches around invalidate_ancestor_locked()
    /// (the `!ok` ancestor branch and the failed-rearm branch), each of
    /// which falls back to stamping `dead_pending_invalidate` directly
    /// rather than propagating - and, combined with multiple dependents
    /// sharing the ancestor, exercises attach_ancestor_locked()'s own
    /// dead_pending_invalidate check (a later probe resolving to the same
    /// ancestor key must invalidate-then-recreate, never bare-erase while
    /// other dependents still reference the entry). Null clears it.
    std::function<void(std::wstring_view ancestor_dir)> ancestor_invalidate_fail_hook;
    /// Runs on run()'s own worker thread, under mu_, immediately BEFORE the
    /// real-directory reissue's ReadDirectoryChangesW call in
    /// process_completion_locked()'s ordinary-notification branch (AFTER
    /// stage_fire_locked() has already staged this pass's real notice) -
    /// with the watch's own target `dir`. Returning true forces this
    /// reissue to be treated as FAILED without making the real OS call
    /// (io_pending cleared, handle dropped), the real-directory mirror of
    /// ancestor_rearm_fail_hook above. This is the deterministic way to
    /// land a probe-launch (the reissue-fail recovery path) in the SAME
    /// pass as an already-staged ordinary notice, without racing a second
    /// watch's independent retry schedule against this one's real
    /// completion timing. Returning false (or a null hook) lets the real
    /// reissue proceed normally. Null clears it.
    std::function<bool(std::wstring_view dir)> real_rearm_fail_hook;
    /// Runs on run()'s own worker thread, under mu_, as the FIRST statement
    /// of process_completion_locked() - before the `removing` check, before
    /// any notice is staged, before the read is reissued - with the watch's
    /// own `dir` (real target or ancestor, whichever DirWatch owns the
    /// completion just dequeued). Throwing here models an allocation failure
    /// landing immediately after IOCP hands back a completion, before this
    /// pass has done anything with it - the "consumed completion" recovery
    /// surface (this file's header comment, rule 6 / the PR-B2 plan's trap
    /// table entry for run()): the completion is already gone from the IOCP
    /// queue and will never be redelivered, so whatever this hook interrupts
    /// must be recoverable WITHOUT another packet ever arriving. Null clears
    /// it.
    std::function<void(std::wstring_view dir)> completion_hook;
    /// Runs at the very top of reserve_probe_locked() (#2012/#3840 PR-B2
    /// review finding 5), after the "already Pending" early-return but
    /// BEFORE `job.dir = w.dir` (the one allocating statement in that
    /// function), with the watch's own `dir`. Throwing here models that
    /// allocation failing, exercising the fix that fully constructs `job`
    /// before stamping any Pending/generation state on `w`. Null clears it.
    std::function<void(std::wstring_view dir)> reserve_probe_fail_hook;
    /// Runs in resolve_probe_locked(), immediately before its own
    /// spdlog::warn (#2012/#3840 PR-B2 review finding 6) - AFTER the state
    /// transition (fail_backend_locked/defer_backend_retry_locked already
    /// ran) but before the log line, with the watch's own `dir`. Only
    /// reached on the r.has_value() && !r->ok branch (a resolved-but-failed
    /// probe, not a WorkerThrew/boxing failure) - throwing here models the
    /// log call's own allocation (fs::path(...).string(), the format
    /// buffer) failing. Null clears it.
    std::function<void(std::wstring_view dir)> resolve_log_fail_hook;
    /// Runs in create_ancestor_from_probe_locked(), immediately before
    /// `ancestors_.try_emplace(akey)` (#2012/#3840 PR-B2 review finding 1) -
    /// AFTER the new ancestor's local bookkeeping strings are copied but
    /// BEFORE any OS call (IOCP associate / ReadDirectoryChangesW) is
    /// issued, with the resolved ancestor directory. Throwing here models
    /// the map insertion itself failing (a rehash bad_alloc); the fix's
    /// insert-then-arm ordering means that can no longer destroy a
    /// kernel-referenced DirWatch, since no read has been issued yet at this
    /// point. Null clears it.
    std::function<void(std::wstring_view resolved_dir)> ancestor_insert_fail_hook;
    /// Runs in watch()'s brand-new-DirWatch registration path (#2012/#3840
    /// PR-B2 review finding 4), as the first statement of the transactional
    /// try block (before `slot = std::make_unique<DirWatch>()`), with the
    /// directory being registered. Throwing here models an allocation
    /// failing anywhere in that block; the fix rolls the just-inserted
    /// `dirs_[dirkey]` entry back so a later watch() for the same directory
    /// retries cleanly instead of riding along with a permanently-deaf slot
    /// (fresh == false, no probe ever reserved). Null clears it.
    std::function<void(std::wstring_view dir)> watch_register_fail_hook;
    /// Runs at the top of attach_dir_locked() (#2012/#3840 PR-B2 review
    /// finding 7), under mu_, with the watch's own `dir`. Returning true
    /// forces the commit to be treated as a FAILED backend establishment
    /// WITHOUT making the real CreateIoCompletionPort/ReadDirectoryChangesW
    /// calls - models a field condition (e.g. an SMB share or filter driver
    /// refusing the association) resolving inside watch()'s own caller-wait
    /// window, exercising the fix that routes a fast-resolve commit failure
    /// through defer_backend_retry_locked (no health stamping into a
    /// discards sink that is never dispatched) instead of the unconditional
    /// fail_backend_locked. Returning false (or a null hook) lets the real
    /// calls proceed normally. Null clears it.
    std::function<bool(std::wstring_view dir)> attach_fail_hook;
    /// Runs at the very top of commit_probe_locked(), under mu_, with the
    /// watch's own `dir`, immediately AFTER w.probe/w.call are reset to
    /// Idle/empty but BEFORE attach_dir_locked()/attach_ancestor_locked()
    /// runs (#2012/#3840 PR-B2 review, round-3 table opine). Throwing here
    /// models an allocation failing inside attach_*_locked's own early,
    /// pre-OS-call work (e.g. attach_ancestor_locked's
    /// fold_ci(res.resolved_dir)) — the exact window commit_probe_locked's
    /// own catch closes: without it, the watch would be left looking fully
    /// Idle-at-rest with the just-consumed discovery result silently
    /// dropped and no owner for establishment. Null clears it.
    std::function<void(std::wstring_view dir)> commit_attach_fail_hook;
    std::size_t probe_lane_cap{0};
    std::size_t retiring_cap{0};
    std::chrono::milliseconds caller_wait_budget{0};
    std::chrono::milliseconds health_grace{0};
    std::chrono::milliseconds sweep_cadence{0};
    std::chrono::milliseconds backend_retry_base{0};
    std::chrono::milliseconds admission_backoff_seed{0};
    std::chrono::milliseconds traversal_budget{0};
};

/// Mechanism-internal counters the public SparkMechanismStats does not carry.
/// Point-in-time skew like SparkMechanismStats - never derive an invariant
/// across two fields. Test-visible surface only (mirrors
/// RegistryMechanismDebugCounters).
struct FileMechanismDebugCounters {
    std::uint64_t probe_launched{0};
    std::uint64_t probe_admission_rejected{0};
    std::uint64_t probe_launch_failed{0};
    std::uint64_t probe_backend_failed{0};
    std::uint64_t probe_discarded{0};
    std::uint64_t synthetic_fires{0};
    std::uint64_t health_edges{0};
    std::uint64_t emit_failed{0};    ///< emit() threw on submit
    std::uint64_t fault_failed{0};   ///< fault() threw on submit
    std::uint64_t resync_retries{0}; ///< restored resync debt re-staged on a later pass
    std::size_t probe_workers_active{0};
    std::size_t live_dirs{0};
    std::size_t live_ancestors{0};
    std::size_t retiring{0};
};

/// Returns true if `mech` is the Windows File mechanism and the controls were
/// applied; false on every non-Windows platform and for any other mechanism
/// type (a caller that forgets to check gets a visible false).
[[nodiscard]] YUZU_EXPORT bool
set_file_test_controls_for_test(ISparkMechanism& mech, FileMechanismTestControls controls);

/// nullopt on every non-Windows platform and for any other mechanism type.
[[nodiscard]] YUZU_EXPORT std::optional<FileMechanismDebugCounters>
file_debug_counters_for_test(const ISparkMechanism& mech);

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
    /// Runs on the sweeper thread at the top of every pass, under the
    /// mechanism's lock, AFTER the pass has reserved its containers and BEFORE
    /// it mutates any watch. Throwing here models a pass that failed on
    /// allocation (the pass is unwound, counted and retried on a backoff;
    /// persistent failure reports the mechanism inert). Null clears it.
    std::function<void()> sweep_hook;
    /// Runs on the sweeper thread inside run_off_lock(), off-lock, on any pass
    /// that staged at least one probe launch - right after that launch loop,
    /// before drain/dispatch processing. Throwing here models an allocation
    /// failure landing after a probe in the SAME pass has already launched
    /// successfully but before publish_locked() can commit it - the exact
    /// interleaving PR #4225's review found could otherwise strand that
    /// probe's watch permanently. Fires only when a launch was actually
    /// staged, so a test can arm it once, up front, with no timing race
    /// against the sweeper's own cadence. Null clears it.
    std::function<void()> emit_bookkeeping_hook;
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
    std::uint64_t fault_failed{0};      ///< fault() threw on submit (sweeper path)
    std::uint64_t sweep_pass_failed{0}; ///< sweeper passes that threw and were retried
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
