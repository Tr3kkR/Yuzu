#pragma once

/// @file log_handoff.hpp
/// #4666 PR-1: the bounded async log hand-off primitive (delivery-plan v2 section 1,
/// design B). Retires the "every spdlog:: call can block the calling thread on sink I/O"
/// hazard that made #4606's Guardian instrumentation lines a flip precondition
/// (docs/spark-flip-gate.md section 7) -- see
/// .claude/plans/spark-4666-retire-synchronous-log-writes-DELIVERY-PLAN.md for the full
/// design record (adjudication table, decisions taken, risk register).
///
/// PR-1 SCOPE ONLY: this file builds the primitive -- StallObservableSink, LogHandoff,
/// drain_log_bounded() -- as a correct, fully unit-tested, standalone unit. Nothing here
/// is called from the shipped binary yet: PR-2 wires main.cpp's/service_win.cpp's real
/// install()/teardown() call sites and the guardian_engine.cpp/guardian_spark_runtime.hpp
/// drain_log_bounded() call sites. Do not infer that any of this is live in production
/// from this file's existence alone.
///
/// THE GUARANTEE (plan 1.1), stated exactly: a producer's spdlog:: call formats on the
/// calling thread, constructs the log_msg (stamping `time` and `thread_id` there), and
/// enqueues under spdlog's internal queue_mutex_ (held by enqueuers and by the pool's
/// single worker only while it pops, never during a sink write). It does NOT wait for
/// sink I/O or for queue capacity (overrun_oldest never blocks the producer on a full
/// queue -- it evicts the oldest queued message instead). It can still take
/// formatter/allocation time on the calling thread, and can throw into the logger's
/// error handler (non-I/O, see below). "Non-blocking" in this file means exactly that,
/// not "instantaneous" and not "never throws".
///
/// STRUCTURE: one spdlog::details::thread_pool (capacity kLogQueueCapacity, exactly one
/// worker thread), constructed directly via std::make_shared -- NEVER
/// spdlog::init_thread_pool(), so no spdlog registry owns it (LogHandoff is the sole
/// owner) -- feeding one spdlog::async_logger (name "", overrun_oldest) whose sinks are
/// each wrapped in a StallObservableSink. install() makes that logger the process
/// default logger IN THIS IMAGE ONLY (see "MULTI-IMAGE" below).
///
/// FIXED RESOURCE COST (plan 1.2, corrected in the final review -- NOT "only when
/// queued"): spdlog's circular_q pre-allocates all `kLogQueueCapacity + 1` slots at
/// thread_pool CONSTRUCTION time. sizeof(spdlog::details::async_msg) is 408 bytes on
/// x64 (measured against the vendored spdlog 1.17.0). kLogQueueCapacity=8192 therefore
/// costs 8193 * 408 bytes = 3,342,744 bytes = 3.34 MB (~=3.19 MiB) of RSS, ALWAYS, from
/// the moment a LogHandoff is constructed -- not a ceiling that only costs memory once
/// messages pile up. See docs/resource-ledgers/4666-log-handoff.md for the full
/// resource-ledger accounting. Payload bytes beyond the fixed per-slot allocation (a
/// queued message's formatted text) are additional and unbounded by this primitive --
/// they are bounded only by kLogQueueCapacity * (typical line length), measured on the
/// rig in a later PR, never asserted here.
///
/// NON-I/O ERROR HANDLER (plan 1.2): installed on the logger (not the spdlog-global
/// handler, which does NOT reach a logger installed later via set_default_logger --
/// confirmed by the plan's own experiment). Reached from BOTH the producer thread (a
/// formatter/allocation exception, or "pool gone") and the pool's single worker thread
/// (a sink's log()/flush() throwing) -- concurrently, in general, so the 256-byte
/// last-message buffer is guarded by a plain std::mutex, NOT a lock-free/single-writer
/// scheme (that was a specification bug in an earlier draft, caught by the final
/// review -- verify against ErrorState below, not against a stale comment elsewhere).
///
/// TEARDOWN CONTRACT (plan 1.4, PR-1-scoped): teardown() is idempotent (a second call,
/// or the destructor firing after an explicit call, is a no-op) and is a STANDALONE,
/// SELF-CONTAINED call -- it constructs its own ShutdownDeadlineGuard
/// (shutdown_deadline_guard.hpp) around the (possibly blocking) drain-and-destroy work,
/// so a caller (PR-2's main.cpp/service_win.cpp) does not need to build a SEPARATE
/// watchdog around the call to teardown() -- it only needs to CALL teardown() at the
/// right point in its own shutdown sequence. This differs from a strict reading of "the
/// caller wires the watchdog" one might infer from a distant summary of this plan
/// section: PR-1's own unit tests (U5) require observing the deadline action fire
/// WHILE INSIDE a call to teardown() on a wedged sink, which is only possible if
/// teardown() owns the watchdog itself -- matching the SAME pattern already established
/// by AgentImpl::stop() (agent.cpp), which likewise constructs its own
/// ShutdownDeadlineGuard as its first statement rather than relying on an external
/// wrapper. What PR-2 DOES still own: (a) calling teardown() at the right point in
/// main.cpp's/service_win.cpp's shutdown sequence (not built here -- nothing calls
/// teardown() from the shipped binary yet); (b) the macOS second-registry half (see
/// "MULTI-IMAGE" below), because teardown() by itself can only reach the registry of
/// the image it runs in.
///
/// teardown() steps (T0-T3; T4 from the plan -- "guard.cancel()" -- is implicit RAII
/// here, the guard's destructor cancels it when the enclosing scope ends normally):
///   T0: mark torn_down_ (idempotency gate) and deregister this instance from the
///       global drain-lookup slot (see drain_log_bounded() below) BEFORE doing any
///       teardown work, so a concurrent drain_log_bounded() call either already holds
///       its own live (weak-locked) reference, or observes "nothing installed" from
///       this point on -- never a half-torn-down handle.
///   T1: logger_->flush() (a queued request; no delivery is claimed), then
///       pool_.reset(): ~thread_pool posts a terminate message under the `block` policy
///       and JOINS its one worker. A healthy sink drains in order and the join returns
///       promptly; a wedged sink means this call simply does not return until the
///       watchdog above fires hard_exit() on the whole process, or (in the
///       teardown_with_action_for_test() path) the injected test action fires instead
///       of the process actually exiting -- the caller must not treat that as
///       "teardown() returned" (see the test's own comment).
///   T2: EVERY image's registry drops its reference to the logger by overwriting the
///       "" default-logger slot with a NULL-sink logger (never
///       spdlog::shutdown()/drop_all(), which null default_logger_ itself and would
///       segfault a straggler spdlog::info() call). This step runs UNCONDITIONALLY,
///       even if install() was never called on this instance -- a test that never
///       installed this LogHandoff as the default logger will still observe the
///       process-wide default become the null sink after calling teardown() (this is
///       deliberate: see U4/U10 in test_log_handoff.cpp, which pins exactly this
///       behavior). PR-1 only ever runs in the ONE registry image it is compiled into
///       (the agent-core library); the MULTI-IMAGE note below is what PR-2 must add.
///   T3: this object's own last reference to the async logger's sinks (logger_.reset(),
///       wrapped_sinks_.clear()) -- runs under the same watchdog as T1, since final
///       sink destruction (e.g. a rotating file sink's fclose()) is exactly the
///       uncovered I/O path the plan's adjudication table calls out (3.4).
///
/// MULTI-IMAGE (plan 1.9): confirmed by symbol inspection (final review) that Linux has
/// ONE spdlog registry shared by the exe, libyuzu_agent_core.so, and every plugin .so
/// (RTLD_LAZY | RTLD_LOCAL with no RTLD_DEEPBIND resolves the global/core scope for
/// every plugin) -- so install()/teardown() as implemented here are already complete
/// for Linux. Windows is one registry too (spdlog.dll, dynamic). macOS is LIKELY two
/// registries (exe image + this library's image) -- unproved, characterised by PR-2's
/// own fixture -- in which case install() must ALSO be called in the exe image (this
/// function returns the shared_ptr<logger> specifically so main.cpp can do that), and
/// teardown() needs an exe-image half too (PR-2's job -- this class only tears down the
/// registry of the image IT runs in).
///
/// CONSTRUCTION FAILURE (plan 1.7, Decision 7): two DISTINCT, DISTINGUISHABLE failure
/// surfaces, matched precisely to the plan's carve-out --
///   (1) pool/thread/async-logger construction failure (thread creation refused,
///       bad_alloc): create()/create_with_sinks() returns std::unexpected -- nothing is
///       installed, no global state is touched. The CALLER (main.cpp, PR-2) maps this
///       to EXIT_FAILURE with no synchronous-logging fallback -- a host that cannot
///       create one thread cannot run the agent's own ThreadPool either, and a silently
///       synchronous logger is the exact forbidden mode this primitive exists to
///       retire.
///   (2) a `--log-file` OPEN failure (missing/unwritable directory) is NOT treated as a
///       LogHandoff construction failure: create() catches it internally and falls back
///       to a console-only sink set (still async/non-blocking), exactly like today's
///       main.cpp #1822 behavior, and returns SUCCESS with used_log_file_fallback()==
///       true and log_file_fallback_reason() set to the caught exception's message --
///       so a Windows service or systemd unit that starts fine today with a bad
///       --log-file path keeps starting after this change; PR-2's main.cpp is expected
///       to print the same kind of diagnostic line it prints today, driven by these two
///       accessors, rather than refuse to start.
///
/// drain_log_bounded() (plan 1.8): a pre-abort breadcrumb helper, free function so
/// guardian_engine.cpp/guardian_spark_runtime.hpp's abort paths (PR-2) can call it
/// without depending on LogHandoff's internals. NULL-SAFE: returns false immediately if
/// no LogHandoff is currently registered (create()/create_with_sinks() was never called
/// or failed, or teardown() has already deregistered it). Looks up the
/// currently-installed instance's pool/logger/sinks via WEAK references held in a small
/// internal snapshot object, so a CONCURRENT teardown() can never leave this function
/// dereferencing a freed pool.
///
/// DRAIN-READER LEASE (fixes a real, reproduced defect -- an earlier draft of this
/// primitive claimed a residual race here was harmless; it was not, see below):
/// drain_log_bounded() holds a `DrainLease` (log_handoff.cpp) for its ENTIRE
/// pool-touching span, which increments LogHandoff's own `drain_gate_->active_readers`
/// for that span and decrements it again strictly AFTER every local strong
/// `shared_ptr<thread_pool>` this function ever creates has already been dropped
/// (guaranteed by C++ reverse-declaration-order destruction -- the lease is declared
/// BEFORE any local pool/sink shared_ptr, so it destructs AFTER them). teardown()'s T0
/// closes admission of new leases (LogHandoff::close_drain_admission()) BEFORE doing
/// any teardown work, then -- still INSIDE its own already-armed ShutdownDeadlineGuard
/// scope, not after it -- calls LogHandoff::wait_for_drain_quiescence(), which blocks
/// until active_readers reaches zero. Only once that returns does teardown_body() run
/// its own pool_.reset(). This guarantees teardown_body()'s pool_.reset() is ALWAYS the
/// call that observes the last reference (if any drain_log_bounded() call was ever
/// concurrently in flight, it has, by construction, already dropped its own copy before
/// active_readers can reach zero) -- so the actual blocking ~thread_pool() join can
/// ONLY ever happen on teardown()'s own thread, inside its own watchdog's scope, never
/// on a drain_log_bounded() caller's thread. A drain_log_bounded() call itself is
/// therefore bounded by its own `wait` parameter as documented, with no exception: it
/// never becomes responsible for the pool's blocking destructor.
///
/// THE DEFECT THIS REPLACES (kept here as a historical note, not a live property):
/// a prior revision let drain_log_bounded() hold a bare strong pool_ reference with no
/// lease/admission-close protocol. If teardown() ran concurrently, its own
/// pool_.reset() became a non-destructive ref-decrement (the drainer still held a live
/// copy), so teardown_body() returned quickly and the ShutdownDeadlineGuard local to
/// teardown() was destroyed and cancelled on that NORMAL scope exit -- before the real
/// blocking work (the pool's actual destruction) had happened. The drainer's own later
/// release of its reference could then be the one that dropped the last owner, running
/// ~thread_pool()'s blocking join on the drain thread with NO watchdog covering it at
/// all -- silently violating the "process-wide safety property" this file claimed.
/// Reproduced independently by two reviewers with standalone repros before this fix
/// landed; see the routed Spark row's clause (4) and
/// docs/resource-ledgers/4666-log-handoff.md for the corrected proof this fix provides.

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <spdlog/async_logger.h>
#include <spdlog/details/thread_pool.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/sink.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::agent {

/// Message-count bound (plan 1.2/Decision 3), NOT a byte bound -- see the FIXED
/// RESOURCE COST note above for the 3.34 MB (~=3.19 MiB) fixed RSS this implies.
inline constexpr std::size_t kLogQueueCapacity = 8192;

/// Default grace for LogHandoff::teardown()'s internal watchdog (Decision 8). Distinct
/// from kShutdownDeadlineGrace/kOrphanDrainGrace -- this bounds ONLY the log-teardown
/// step, not the whole shutdown sequence.
inline constexpr std::chrono::milliseconds kLogTeardownGrace{2000};

/// Distinct from hard_exit's other production codes (1 second-signal, 3 F3 orphan-exit,
/// 4 shutdown deadline -- see hard_exit.hpp/shutdown_deadline_guard.hpp) so exit-code
/// monitoring can tell a log-teardown-specific hang apart from the others.
inline constexpr int kLogTeardownExitCode = 5;

/// A spdlog sink wrapping exactly ONE inner sink, observing in-flight writes without
/// changing behavior: log()/flush() are forwarded to the inner sink unchanged (same
/// exceptions propagate, same return values -- there are none, spdlog sinks are
/// void-returning), wrapped in an RAII guard that tracks "a write is currently
/// in-flight on this sink" and "when did the CURRENTLY in-flight write start" via plain
/// atomics. set_pattern()/set_formatter() are forwarded too (a v1-to-v2 drop of this
/// forwarding was a final-review-caught defect -- without it, e.g. `--log-format json`
/// would silently revert to the default text pattern; see test U-json).
///
/// Every log()/flush() call on a GIVEN LogHandoff's sinks runs on the SAME thread (the
/// owning thread_pool's one worker) -- there is never more than one write in flight per
/// sink -- so in_flight_ only ever reads 0 or 1 in practice, but is tracked as a count
/// (not a bool) for the same reason RAII guards generally are: correctness under
/// exceptions/early-return does not depend on that invariant holding.
///
/// spdlog::sinks::sink::set_level()/level()/should_log() are NOT virtual (see sink.h)
/// and are therefore inherited unchanged from the base class, operating on THIS
/// wrapper's own level_ member -- a caller that somehow held a raw pointer to the INNER
/// sink and called set_level() on it directly would have no effect on filtering, since
/// spdlog's async_logger::backend_sink_it_() calls should_log() on the sinks it was
/// constructed with (the wrappers), never on whatever an inner sink wraps. No code in
/// this repo does that today (main.cpp filters via logger_->set_level(), which is
/// checked on the PRODUCER side before a message is even queued) -- noted here so a
/// future caller does not rediscover this the hard way.
class YUZU_EXPORT StallObservableSink final : public spdlog::sinks::sink {
public:
    explicit StallObservableSink(std::shared_ptr<spdlog::sinks::sink> inner);

    void log(const spdlog::details::log_msg& msg) override;
    void flush() override;
    void set_pattern(const std::string& pattern) override;
    void set_formatter(std::unique_ptr<spdlog::formatter> sink_formatter) override;

    /// True while a log()/flush() call into the inner sink is currently running.
    [[nodiscard]] bool in_write() const noexcept;

    /// steady_clock time the CURRENTLY in-flight write started. Only meaningful while
    /// in_write() reads true (a caller observing in_write()==false afterward simply
    /// means the write already finished between the two reads -- benign, see
    /// LogHandoff::stalled_for()'s own comment).
    [[nodiscard]] std::chrono::steady_clock::time_point write_started_at() const noexcept;

private:
    struct WriteGuard {
        explicit WriteGuard(StallObservableSink& self) noexcept;
        ~WriteGuard();
        WriteGuard(const WriteGuard&) = delete;
        WriteGuard& operator=(const WriteGuard&) = delete;
        StallObservableSink& self_;
    };

    std::shared_ptr<spdlog::sinks::sink> inner_;
    std::atomic<int> in_flight_{0};
    std::atomic<std::int64_t> started_at_ticks_{0}; // steady_clock::duration::rep
};

/// Opaque control block backing drain_log_bounded()'s reader lease (log_handoff.cpp);
/// forward-declared only -- see the file banner's DRAIN-READER LEASE paragraph. No
/// caller outside log_handoff.cpp ever names this type.
class DrainGate;

/// Owns the private single-thread pool, the async logger, and the wrapper sinks (plan
/// 1.2/1.4). Non-copyable, non-movable -- there is exactly one owner, matching
/// ShutdownDeadlineGuard's own precedent for a shutdown-path primitive with a single,
/// stack/member-local owner. See the file banner above for the full contract.
///
/// THREAD-SAFETY CONTRACT (should-fix from the #4666 PR-1 adversarial review):
/// teardown()/teardown_with_action_for_test() are documented callable "from any
/// thread" and ARE internally synchronized against a CONCURRENT drain_log_bounded()
/// call (the DRAIN-READER LEASE above) and against each other/the destructor (the
/// torn_down_ exchange). They are NOT synchronized against a concurrent call to the
/// plain accessors below (overrun_total()/queue_depth()/in_write()/stalled_for()/
/// log_errors_total()/last_log_error_for_test()) or against install()/logger() --
/// those read pool_/logger_/wrapped_sinks_/error_state_ directly, with no lock, while
/// teardown_body() resets them. This is UNREACHABLE in PR-1 (nothing calls these
/// accessors from a second thread yet) but is a REAL CONSTRAINT for PR-3's planned
/// heartbeat poller, which by construction runs on a different thread than whatever
/// calls teardown(). Matching ShutdownDeadlineGuard's own precedent ("safe to call
/// from the constructing thread only", shutdown_deadline_guard.hpp), the rule for a
/// caller introducing a second thread here is: EITHER serialize every accessor/
/// install()/logger() call against teardown() with the caller's own lock, OR (if a
/// wait-free poller is required) snapshot pool_/logger_/wrapped_sinks_ the same
/// weak-ptr way drain_log_bounded() already does, before PR-3 wires a poller against
/// this class. Do not assume the accessors are already safe for that use just because
/// nothing today calls them concurrently.
class YUZU_EXPORT LogHandoff {
public:
    /// Production-shaped construction options -- the "sinks per mode" decision table
    /// from plan section 1.6, expressed as data so PR-2's main.cpp only needs to
    /// translate its already-parsed CLI flags into this struct and call create().
    struct Options {
        /// Windows-service mode: no console is attached under the SCM (plan 1.6), so a
        /// log file is the only sink even when one is configured; when log_file is
        /// std::nullopt in this mode, the OWNER (main.cpp, PR-2) is expected to have
        /// already picked a default path before calling create() -- exactly as
        /// main.cpp:645-649 does today -- this struct does not invent one itself.
        bool service_mode{false};

        /// std::nullopt: console-only (spdlog's own stdout_color_sink_mt -- this is
        /// the shipped Linux path, deploy/systemd/yuzu-agent.service has no
        /// --log-file). Set: rotating file sink, plus a stderr sink too when
        /// !service_mode (plan 1.6). See the CONSTRUCTION FAILURE note above for what
        /// happens when the file cannot be opened.
        std::optional<std::filesystem::path> log_file;

        /// Matches main.cpp's own --log-max-size/--log-max-files CLI defaults (50 MB /
        /// 5 files) so a caller that does not override these gets the same rotation
        /// behavior as today.
        std::size_t log_max_size{50u * 1024 * 1024};
        std::size_t log_max_files{5};
    };

    LogHandoff(const LogHandoff&) = delete;
    LogHandoff& operator=(const LogHandoff&) = delete;
    LogHandoff(LogHandoff&&) = delete;
    LogHandoff& operator=(LogHandoff&&) = delete;

    /// Fail-closed like OrphanExitGuard (hard_exit.hpp): if teardown() was never
    /// called explicitly, this runs it now rather than let the pool/logger destruct
    /// unguarded (see the file banner's TEARDOWN CONTRACT).
    ~LogHandoff();

    /// Production factory: builds the sink list per Options (plan 1.6) and delegates to
    /// create_with_sinks(). See the file banner's CONSTRUCTION FAILURE note for the two
    /// distinguishable failure surfaces this implements.
    static std::expected<std::unique_ptr<LogHandoff>, std::string> create(const Options& options);

    /// Lower-level factory over an ALREADY-CHOSEN, non-empty sink list -- used
    /// internally by create() and directly by tests that want to inject a test double
    /// sink without going through the Options/mode-selection logic. `queue_capacity`
    /// defaults to the production bound (kLogQueueCapacity) -- production callers never
    /// override it; a test overrides it to get deterministic overflow behavior (U3)
    /// without waiting to fill 8192 real slots.
    static std::expected<std::unique_ptr<LogHandoff>, std::string>
    create_with_sinks(std::vector<spdlog::sink_ptr> sinks,
                      std::size_t queue_capacity = kLogQueueCapacity);

    /// True iff Options::log_file was set but the file could not be opened, so
    /// construction fell back to a console-only sink set (the 1.7 carve-out). Always
    /// false for an object built via create_with_sinks() directly.
    [[nodiscard]] bool used_log_file_fallback() const noexcept { return log_file_fallback_; }

    /// The caught exception's message when used_log_file_fallback() is true; empty
    /// otherwise.
    [[nodiscard]] const std::string& log_file_fallback_reason() const noexcept {
        return log_file_fallback_reason_;
    }

    /// Sets this instance's logger as spdlog's default logger IN THIS IMAGE. Returns
    /// the logger so the caller can also install it into a second image's registry
    /// (the macOS case -- see the file banner's MULTI-IMAGE note). Calling this more
    /// than once just re-sets the same logger; harmless.
    std::shared_ptr<spdlog::logger> install();

    /// The owned logger, independent of whether install() was called -- for a caller
    /// that wants to call set_formatter()/set_pattern()/set_level() before or instead
    /// of installing as the process default.
    [[nodiscard]] std::shared_ptr<spdlog::logger> logger() const noexcept { return logger_; }

    // ---- Observability accessors (plan 1.2/1.3) --------------------------------

    /// Cumulative count of messages evicted by the overrun_oldest overflow policy
    /// (spdlog's own counter; never reset by this class).
    [[nodiscard]] std::size_t overrun_total() const;

    /// Current queue depth (spdlog's own thread_pool::queue_size()).
    [[nodiscard]] std::size_t queue_depth() const;

    /// True while any wrapped sink is currently inside a log()/flush() call.
    [[nodiscard]] bool in_write() const noexcept;

    /// Seconds the longest-currently-running wrapped-sink write has been in flight; 0
    /// if none is in flight. Best-effort, see StallObservableSink::write_started_at()'s
    /// own comment for the benign race this can reflect.
    [[nodiscard]] std::chrono::seconds stalled_for() const noexcept;

    /// Cumulative count of times the logger's non-I/O error handler fired (a sink
    /// throw, or a producer-side formatter/allocation exception, or "pool gone").
    [[nodiscard]] std::uint64_t log_errors_total() const;

    /// The most recent error message the handler observed, truncated to 256 bytes.
    /// Test/diagnostic accessor -- not surfaced on the heartbeat (PR-3's job, if ever).
    [[nodiscard]] std::string last_log_error_for_test() const;

    /// T0-T3 (see the file banner's TEARDOWN CONTRACT). Exactly once -- a second call,
    /// from any thread, is a no-op. NOEXCEPT and fail-closed: if anything inside throws
    /// unexpectedly, this calls hard_exit(kLogTeardownExitCode) itself rather than let
    /// an exception escape a call the destructor depends on being noexcept.
    void teardown(std::chrono::milliseconds grace = kLogTeardownGrace) noexcept;

    /// Test-only twin of teardown(): same T0-T3 steps and the same internal watchdog,
    /// but the deadline ACTION is caller-supplied instead of the real
    /// hard_exit(kLogTeardownExitCode) -- so a test can observe "did the deadline fire"
    /// without terminating the test binary. Deliberately NOT noexcept/fail-closed like
    /// teardown() -- an unexpected exception here fails the calling Catch2 TEST_CASE,
    /// which is the correct outcome for a test-only entry point, rather than
    /// hard_exit()ing the whole test binary and losing every other test's result.
    /// Production callers never call this.
    void teardown_with_action_for_test(std::chrono::milliseconds grace,
                                       std::function<void()> action);

    /// Test-only fault injection for create()/create_with_sinks()'s pool/logger
    /// construction step (U7) -- mirrors the OS actually refusing to create the pool's
    /// one worker thread, without depending on real resource exhaustion. Consumed
    /// (reset to false) by the very next create_with_sinks() call, so it never leaks
    /// into a later, unrelated test. Production callers never set this.
    static void set_construction_fault_for_test(bool fail) noexcept;

private:
    struct ErrorState {
        mutable std::mutex mu;
        std::uint64_t count{0};
        std::string last_message;
    };

    LogHandoff() = default;

    void teardown_body();

    /// T0 half of the drain-reader-lease fix: stops admitting NEW drain_log_bounded()
    /// leases. Called BEFORE the ShutdownDeadlineGuard is constructed (fast, never
    /// blocks). Null-safe (a no-op if drain_gate_ was never set, e.g. a construction
    /// failure before it was assigned).
    void close_drain_admission();

    /// The blocking half: waits until every already-admitted drain_log_bounded() lease
    /// has released (drain_gate_->active_readers == 0). MUST be called INSIDE the
    /// ShutdownDeadlineGuard's scope (see teardown()/teardown_with_action_for_test())
    /// so a lease that never releases is still bounded by the watchdog, never an
    /// unwatched wait. Null-safe, same as close_drain_admission().
    void wait_for_drain_quiescence();

    static void register_global_drain_handle(LogHandoff* self);
    static void clear_global_drain_handle(const LogHandoff* self);

    std::shared_ptr<spdlog::details::thread_pool> pool_;
    std::shared_ptr<spdlog::async_logger> logger_;
    std::vector<std::shared_ptr<StallObservableSink>> wrapped_sinks_;
    std::shared_ptr<ErrorState> error_state_;
    std::shared_ptr<DrainGate> drain_gate_; // see close_drain_admission()/wait_for_drain_quiescence()
    std::atomic<bool> torn_down_{false};
    bool log_file_fallback_{false};
    std::string log_file_fallback_reason_;

    static inline std::atomic<bool> construction_fault_for_test_{false};
};

/// Pre-abort breadcrumb helper (plan 1.8). See the file banner's own paragraph for the
/// full null-safety and concurrent-teardown contract. Never blocks longer than `wait`
/// in the ordinary (non-racing-a-concurrent-teardown) case.
YUZU_EXPORT bool drain_log_bounded(std::chrono::milliseconds wait);

} // namespace yuzu::agent
