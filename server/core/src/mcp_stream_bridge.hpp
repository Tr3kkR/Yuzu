#pragma once

// MCP progress bridge CORE (ADR-1005 Decision 15, track 2f PR 3a).
//
// The consumer-side projection of ExecutionEventBus events onto a session's MCP
// stream surfaces: per-request correlation records, the bus subscription, the
// arming mailbox, one projector thread, and ring/final publication. The G1
// core/presentation split is structural - this header knows NOTHING of httplib,
// revalidation, or wire writes (those live in McpPostPump, PR 3b). In-memory,
// non-durable, no new store.
//
// GET-only mode is LIVE (rung 3a.7 wires reserve/subscribe/arm(kGetOnly) into
// execute_instruction in mcp_server.cpp + construction in server.cpp). The
// STREAMED-POST surface is still dead: on_post_closed / request_cancel /
// ArmMode::kStreaming and therefore the whole kRingOnly lifecycle (parked
// finals, the pressure hatch) have no production caller until the 3b pump lands
// - deliberately, the same zero-producer staging as publish_final (3a.4).
//
// ── Record lifecycle ────────────────────────────────────────────────────────
//
//   kArming ──arm(kStreaming)──────────▶ kStreaming ──on_post_closed()─▶ kRingOnly
//      │  └──arm(kGetOnly | cancel-degrade)─▶ kArmedGetOnly                  │
//      │                                        │ (terminal projected)       │
//      └──abandon()──▶ kAborted                 ▼                            ▼
//                                             kDone ◀────── sweep() ─────────┘
//
//   kArming        reserved, pre-dispatch; mailbox latches events, nothing projects.
//   kStreaming     POST pump owns projection (3b). In 3a nothing arms this in
//                  production; a test-driven kStreaming record latches until parked.
//   kArmedGetOnly  plain JSON already answered the POST. Progress goes LIVE on the
//                  GET stream (single stream - no broadcast); NO final frame, NO pin.
//   kRingOnly      parked: progress + the pinned final go to the ring only (resume
//                  replay; the MCP spec's MUST NOT broadcast). Subscription retained
//                  for the pinned terminal. Does NOT extend session life - nothing
//                  here touches last_seen; resume window = idle_ttl from the last
//                  CLIENT activity.
//   kAborted       pre-dispatch failure class (abandon); erased immediately.
//   kDone          terminal state; sweep unsubscribes/unpins/erases.
//
// Cancel (C1 arbitration): request_cancel() only records PENDING intent - arm()
// and abandon() are the sole terminal arbitrators, both under the record mutex.
// arm() consuming the flag degrades streamed intent to kArmedGetOnly (subscription
// retained, no pin, plain-JSON ack) and audits AFTER winning; abandon() discards
// the pending flag silently (the request died pre-dispatch - its error path is
// the truth). Cancel is never a phase winner on its own.
//
// Terminal durability (Decision 15(f)): a parked record's real final rides
// publish_final (pinned, resume-replayable). publish_final()==0 → retry once with
// the prebuilt fallback → still 0 → poison_terminal() + counter (the mcp_stream
// caller obligation). The sticky per-record `terminal_accepted` bit is the
// write-once discriminator: once a real terminal is secured, every later bus
// event for that record is dropped - the final is always last (D2).
//
// Pressure escape hatch (cap `ring_only_pressure_cap`, E1 two-stage): sweep picks
// the OLDEST parked record, sets pressure_requested (the projector claims no new
// progress batch for it), and - only once no progress projection is in flight -
// QUIESCES the subscription, revalidates under the record mutex, and claims kDone
// ONLY for a terminal-unaccepted, projection-free record; that victim gets a
// pinned kMcpTerminalUnavailable synthesis carrying the execution_id. A latched
// or in-flight real terminal always defers the teardown; a REAL pinned final is
// never destroyed and its pin survives the record (ack/session-death rules
// release it). Never evicts a newer record.
//
// Poison blast radius: poison_terminal() is session-wide - every future attach on
// that session 410s. Reached only on a double publish-failure (allocation death);
// counted, and the durable execution_id fetch remains the recovery path.
//
// ── LOCK HIERARCHY (acquire strictly left→right; releasing before acquiring a
//    lower tier is always allowed) ────────────────────────────────────────────
//
//   bridge_mu_ → ExecutionEventBus Channel::mu → BridgeRecord::mu
//              → McpStreamState::mu_ → SseSinkState::mu
//
//   WakeCore::mu             - wake-only LEAF. Taken (briefly, to flip
//       work_pending_/stop and notify) from under Channel::mu + record mu
//       (listener wake) and from under record mu (arm()'s handoff wake).
//       NOTHING is ever acquired while holding it.
//   McpSessionRegistry::mu_  - isolated leaf (stream_for/exists acquire nothing
//       beneath; the bridge never calls the registry while holding bridge_mu_).
//
//   Listeners (running under Channel::mu) touch record mu + WakeCore::mu ONLY -
//   never bridge_mu_, never a stream/sink lock, never the bus, never the metrics
//   registry (C5: drops/failures are record-local relaxed atomics flushed by the
//   projector). bridge_mu_ holders MAY call the bus (subscribe under bridge_mu_
//   serializes installation against teardown, A3; shutdown's unsubscribe walk) -
//   legal precisely because listeners never take bridge_mu_.
//
//   C5 (#2409) pressure visitor: the sweep calls unsubscribe_and_visit_terminal
//   WITHOUT holding bridge_mu_ (it re-validates map identity, releases bridge_mu_,
//   then calls the bus). The visit takes Channel::mu → record mu (a valid suffix);
//   its callback runs under Channel::mu and, like a listener, touches record mu +
//   WakeCore::mu ONLY - never bridge_mu_, never the bus (either would invert the
//   order). The streamed-charge decrement it would owe is deferred to the
//   post-visit teardown_claimed (under bridge_mu_), preserving exactly-once.

#include "execution_event_bus.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::mcp {

class McpStreamState;
class McpSessionRegistry;

/// Arming-mailbox capacity (progress frames; the terminal has its own reserved
/// slot and is never dropped). Matches the sink-queue scale, not the ring's.
inline constexpr std::size_t kBridgeMailboxCap = 16;

class McpStreamBridge {
public:
    struct Config {
        /// Decision 15(d): global cap over ALL records, enforced at reserve().
        /// A dispatched record is NEVER evicted to make room (reject-not-evict).
        std::size_t global_record_cap = 256;
        /// Parked (kRingOnly) records tolerated before the pressure escape hatch
        /// force-expires the oldest (see the class comment).
        std::size_t ring_only_pressure_cap = 64;
        /// A kArming record is normally sub-millisecond (reserve→subscribe→arm
        /// all happen in ONE synchronous execute_instruction handler call). A
        /// record still kArming after this long is orphaned - its handler died
        /// between reserve and arm (the double-`bad_alloc` corner: arm's fallback
        /// build throws, then abandon()'s make_key ALSO throws under OOM), which
        /// sweep would otherwise never reclaim because it deliberately skips
        /// kArming (governance cpp-safety SHOULD). The threshold is generous -
        /// dispatch is a fire-and-forget fan-out (it does not wait for agents),
        /// so the reserve→arm window is milliseconds; 5 min is many orders of
        /// margin, so a live handler is never reaped.
        std::chrono::seconds arming_reap_after{300};
    };

    /// Injectable steady clock for the kArming reaper (deterministic tests).
    /// Defaults to steady_clock::now(); only the DIFFERENCE between calls matters.
    using ClockFn = std::function<std::chrono::steady_clock::time_point()>;

    /// httplib-free audit sink (G1): (action, execution_id, detail). Wired by
    /// 3a.7; empty = no audit. Every invocation is exception-contained (C5) -
    /// a throwing sink can never abort a sweep or corrupt accounting.
    using AuditFn = std::function<void(const std::string& action, const std::string& execution_id,
                                       const std::string& detail)>;

    /// Phases - see the lifecycle diagram above.
    enum class Phase : int { kArming, kStreaming, kArmedGetOnly, kRingOnly, kDone, kAborted };

    enum class ArmMode { kGetOnly, kStreaming };

    enum class ArmOutcome {
        kArmed,            ///< armed in the requested mode
        kDegradedGetOnly,  ///< streamed intent + pending cancel consumed → GET-only lifecycle (H6)
        kAborted,          ///< abandon already won (record in kAborted)
        kNotFound,         ///< no such record (abandon won and erased, or never reserved)
        kAlreadyArmed,     ///< arm called twice - caller bug, first arm stands
    };

    enum class CancelOutcome {
        kAcceptedPending,  ///< recorded; arm()/abandon() will arbitrate (C1 - no audit yet)
        kNoOp,             ///< not kArming (nothing to cancel in 3a), duplicate, or unknown
    };

    /// C5 (#2409): the terminal frame a claimed pressure-teardown publishes.
    /// kNone = real final already pinned (or nothing to publish); kFallbackFinal =
    /// success-shaped "fetch by execution_id" for a terminal-known-payload-lost
    /// record; kSynthesizeUnavailable = the -32014 error, reachable ONLY for a
    /// record that genuinely never saw a terminal.
    enum class TeardownFinal { kNone, kSynthesizeUnavailable, kFallbackFinal };

    struct ReserveResult {
        bool ok = false;
        /// Static literal iff !ok - doubles as the reject_total{reason} label:
        /// "disabled" | "shutdown" | "unknown_session" | "duplicate_request_id" |
        /// "global_cap" | "pin_slots".
        const char* reject_reason = nullptr;
    };

    /// `bus` nullable ⇒ bridge disabled: reserve() rejects "disabled", nothing
    /// subscribes, callers fall back to today's plain path byte-identically.
    /// Two overloads instead of a `Config cfg = {}` default: GCC rejects
    /// consuming Config's default member initializers before the enclosing
    /// class is complete (the McpSessionRegistry precedent) - the delegation in
    /// the .cpp resolves Config{} where the class is complete.
    McpStreamBridge(ExecutionEventBus* bus, McpSessionRegistry* sessions,
                    yuzu::MetricsRegistry* metrics = nullptr, AuditFn audit = {});
    McpStreamBridge(ExecutionEventBus* bus, McpSessionRegistry* sessions,
                    yuzu::MetricsRegistry* metrics, AuditFn audit, Config cfg);
    /// Calls the idempotent shutdown() - correct teardown even if stop() never ran.
    /// MUST run while the bus is still alive (server.cpp resets the bridge BEFORE
    /// the bus, mirroring [BUS-BEFORE-TRACKER]).
    ~McpStreamBridge();
    McpStreamBridge(const McpStreamBridge&) = delete;
    McpStreamBridge& operator=(const McpStreamBridge&) = delete;
    McpStreamBridge(McpStreamBridge&&) = delete;
    McpStreamBridge& operator=(McpStreamBridge&&) = delete;

    /// S1: keyed kArming record insert - dup-key/cap/pin-slot admission BEFORE
    /// create_execution, so every rejection is truthfully "no execution row".
    /// Streamed admission counts LIVE PINS plus streamed records that have not
    /// pinned yet (`pinned_count() + streamed_unpinned_[session]`) - orphan pins
    /// left by pressure/pin-ack teardown stay counted until the ring releases
    /// them (A5/C3; transient over-count rejects fail-closed).
    ReserveResult reserve(const std::string& session_id, const std::string& principal,
                          const nlohmann::json& jsonrpc_id,
                          std::optional<nlohmann::json> progress_token, bool streamed_intent);

    /// S3: bus subscribe_and_replay(execution_id, 0) onto the reserved record.
    /// Runs UNDER bridge_mu_ (A3): installation and the sub-token store are
    /// serialized against every teardown, so no listener can exist without a
    /// token a teardown can see. A bus throw propagates - the caller abandons
    /// (installation failure has zero side effects per the 3a.3 contract).
    bool subscribe(const std::string& session_id, const nlohmann::json& jsonrpc_id,
                   const std::string& execution_id);

    /// S5/S6: atomic flip-and-drain (H2). Prebuilds the fallback final BEFORE the
    /// flip; CAS + handoff wake under ONE record-mutex hold - a listener append
    /// lands either pre-flip (drained by the handoff wake) or post-flip (drained
    /// by the listener's own unconditional wake); nothing strands.
    /// `result_base` = the serialized JSON-RPC *result object* exactly as today's
    /// plain path builds it (B5); the parked real final re-emits it with
    /// status/agents_success/agents_failure added as TOP-LEVEL result keys.
    /// Empty ⇒ the bus-payload-only shape (tests; 3b always passes the real base).
    ArmOutcome arm(const std::string& session_id, const nlohmann::json& jsonrpc_id, ArmMode mode,
                   std::string result_base = {});

    /// Record cancel INTENT (C1). Never audits, never transitions - arm() or
    /// abandon() consume it. kNoOp for anything not kArming (a parked/GET-only
    /// record has no POST stream to detach in 3a; 3b routes kStreaming cancel
    /// through the pump).
    CancelOutcome request_cancel(const std::string& session_id, const nlohmann::json& jsonrpc_id);

    /// Pre-dispatch failure unwind: kArming → kAborted, unsubscribe (waits out
    /// in-flight listeners), discard mailbox, release charge, erase. The caller
    /// owns lease release / mark_cancelled / the byte-identical error path (G1).
    bool abandon(const std::string& session_id, const nlohmann::json& jsonrpc_id);

    /// 3b pump-releaser seam, landed now because it is the only path into
    /// kRingOnly: kStreaming → kRingOnly, assign parked order, wake the
    /// projector (A1 - a latched terminal must not wait for the next bus event).
    bool on_post_closed(const std::string& session_id, const nlohmann::json& jsonrpc_id);

    /// Reap + enforce (server tick wiring is 3a.7; public for tests):
    ///   0. kDone records → unsubscribe/unpin-bookkeeping/erase.
    ///   1. pin-ack: a kRingOnly record whose pinned final left the ring
    ///      (GET resume consumed it - the H4 const poll, no callback edge) → kDone.
    ///   2. session death: kArmedGetOnly/kRingOnly whose session no longer
    ///      exists (the non-touching registry query) → kDone. kArming is
    ///      excluded - request-scoped, its own POST arbitrates.
    ///   3. pressure: see the class comment (E1 two-stage, multi-victim).
    /// NOTE (3a.7): the tick MUST also call McpSessionRegistry::gc() - exists()
    /// never destroys an expired session's stream, so pins held by a dead
    /// session are only released when registry GC actually runs.
    void sweep();

    /// Idempotent. Gates every public mutator (C6), stops + joins the projector
    /// (never holding bridge_mu_ across the join), then unsubscribes everything,
    /// settles charge accounting, and clears the maps.
    void shutdown();

    // ── Observability / test accessors ─────────────────────────────────────
    std::size_t record_count() const;
    std::size_t ring_only_count() const;
    std::optional<Phase> phase_for(const std::string& session_id,
                                   const nlohmann::json& jsonrpc_id) const;
    /// One-shot: the NEXT listener invocation throws std::bad_alloc inside its
    /// boundary (counted, contained). Mirrors inject_publish_fault_for_test.
    void inject_listener_fault_for_test();
    /// Test seam: force the next audit/metrics flush attempts to observe a
    /// throwing observability layer (C5 fault seam).
    void inject_observability_fault_for_test(int times = 1);
    /// One-shot: the NEXT arm() throws std::bad_alloc pre-flip, modelling an
    /// allocation failure in the result_base copy / fallback build. Proves the
    /// execute_instruction handler's guard degrades to the plain path and leaks
    /// no kArming record.
    void inject_arm_fault_for_test();
    /// One-shot: the NEXT reserve() (after admission) / subscribe() throws
    /// std::bad_alloc, modelling an allocation failure. Proves the handler's
    /// reserve/subscribe guards degrade to the plain path (governance quality).
    void inject_reserve_fault_for_test();
    void inject_subscribe_fault_for_test();
    /// One-shot: the NEXT pressure-visitor terminal-payload copy (kTerminalBuffered
    /// latch) throws std::bad_alloc, modelling a copy OOM. Proves the visit defers +
    /// keeps the listener + leaves terminal_accepted false (#2409 safety-S1).
    void inject_visit_copy_fault_for_test();
    /// Override the reaper clock for deterministic age tests (default:
    /// steady_clock::now). Only the difference between calls matters.
    void set_clock_for_test(ClockFn clock);

private:
    /// One latched bus event. Nothrow-movable - load-bearing for the projector's
    /// extraction (C4) and the listener's construct-then-move commit (D2).
    struct MailboxEntry {
        std::uint64_t bus_id = 0;
        std::string data;
    };
    static_assert(std::is_nothrow_move_assignable_v<MailboxEntry> &&
                      std::is_nothrow_move_constructible_v<MailboxEntry>,
                  "projector extraction and listener commit rely on nothrow moves");

    /// Listener-reachable state, shared_ptr-owned so a leaked listener can never
    /// touch a destroyed bridge (C7 - the listener captures {record, wake core}
    /// and NOTHING else; helpers are free functions).
    struct WakeCore {
        std::mutex mu;
        std::condition_variable cv;
        bool work_pending = false;  ///< guarded by mu - the lost-wakeup killer
        bool stop = false;          ///< guarded by mu
        std::atomic<bool> listener_fault{false};
        /// C5/D3: deltas whose registry flush failed transiently, retried by later
        /// projector passes; records also drain their locals here at teardown.
        std::atomic<std::uint64_t> pending_listener_failures{0};
        std::atomic<std::uint64_t> pending_mailbox_drops{0};
    };

    struct BridgeRecord {
        // Immutable after reserve()/subscribe()/arm() hand-off points (each field
        // is written before the record becomes reachable by the code that reads
        // it; see the .cpp field-by-field notes). Safe to read lock-free AFTER
        // observing a post-write phase via the record mutex.
        std::string session_id;
        std::string principal;
        nlohmann::json jsonrpc_id;
        std::string key;               ///< session_id + '\n' + jsonrpc_id.dump()
        bool streamed_intent = false;
        std::uint64_t seq = 0;         ///< reservation order
        std::chrono::steady_clock::time_point created;  ///< set at reserve; the kArming reaper's age base
        std::shared_ptr<McpStreamState> stream;  ///< taken at reserve via stream_for
        std::optional<nlohmann::json> progress_token;
        std::string execution_id;      ///< set at subscribe(), before any listener exists
        std::string fallback_final;    ///< prebuilt at arm(), before the flip
        std::string result_base;       ///< serialized result object (B5); set at arm()

        // Subscription bookkeeping - guarded by bridge_mu_ (A3: installed and
        // torn down only under it or by the kDone claimant).
        std::size_t sub_id = 0;
        bool subscribed = false;

        // Atomic for cheap phase reads; every kArming-EXIT transition and every
        // →kDone claim happens under `mu` (C1/B2 arbitration).
        std::atomic<Phase> phase{Phase::kArming};

        // ── Guarded by mu ──────────────────────────────────────────────────
        mutable std::mutex mu;
        std::array<MailboxEntry, kBridgeMailboxCap> mailbox{};
        std::size_t mb_head = 0;
        std::size_t mb_count = 0;
        std::optional<MailboxEntry> terminal_slot;  ///< reserved; never dropped
        /// STICKY write-once discriminator (D2): set only after the first
        /// terminal payload is fully secured in terminal_slot; NEVER cleared -
        /// not by extraction, restore, settle, or poison. The listener drops
        /// every event once set. Never inferred from terminal_slot.has_value().
        bool terminal_accepted = false;
        bool cancel_pending = false;       ///< C1 - intent only; arm/abandon arbitrate
        /// B2/C2: claimed around EVERY batch that may publish (progress or
        /// terminal). Sweep never claims kDone while set; stays asserted until
        /// any deferred charge decrement under bridge_mu_ completes (D4).
        bool projection_in_flight = false;
        bool pressure_requested = false;   ///< E1 - projector claims no new progress batch
        /// H1 (MCP MUST: notifications/progress `progress` strictly increases):
        /// the highest `progress` value already committed to the wire for this
        /// record, and whether any has been sent. Touched ONLY by the single
        /// projector thread inside project_record (never the listener/sweep), so
        /// no synchronization is needed.
        std::uint64_t last_progress_sent = 0;
        bool progress_sent_any = false;
        bool terminal_projected = false;   ///< settled (published, GET-only-consumed, or poisoned)
        bool final_published = false;      ///< a REAL final committed to the ring
        /// A5/C3: the per-session streamed-admission charge. Released exactly
        /// once (pin proof, cancel-degrade, pinless settle incl. poison, or
        /// teardown of a still-charged record); cleared under mu, decremented
        /// under bridge_mu_ AFTER releasing mu.
        bool streamed_charge_held = false;
        /// Exactly-once teardown claim: concurrent sweep() calls may both gather
        /// evidence on the same record; the first to set this under mu owns the
        /// teardown, the loser skips (no double synthesis/audit).
        bool torn_down = false;
        std::uint64_t pinned_event_id = 0;
        std::uint64_t parked_seq = 0;      ///< assigned on entry to kRingOnly
        std::optional<std::string> final_frame;  ///< 3b pump seam: written LAST on the wire

        // C5: record-local, listener-writable observability. Flushed by the
        // projector / teardown through the noexcept obs guard - the listener
        // itself never touches a metrics mutex.
        std::atomic<std::uint64_t> mailbox_drop_delta{0};
        std::atomic<std::uint64_t> listener_failure_delta{0};
    };

    static std::string make_key(const std::string& session_id, const nlohmann::json& jsonrpc_id);
    /// Free-standing listener factory (C7/D5): captures record + wake core only.
    static ExecutionEventBus::Listener make_listener(std::shared_ptr<BridgeRecord> rec,
                                                     std::shared_ptr<WakeCore> core);
    static void wake(WakeCore& core) noexcept;

    std::shared_ptr<BridgeRecord> find_locked(const std::string& key) const;  // holds bridge_mu_

    void run_projector();
    void project_record(const std::shared_ptr<BridgeRecord>& rec);
    /// Build the parked real final from the bus terminal payload + result_base (B5).
    static std::string build_real_final(const BridgeRecord& rec, const std::string& terminal_data);
    /// The publish_final → retry-fallback → poison ladder (A6). Returns the
    /// committed id (0 ⇒ poisoned). `frame` is only viewed (passed as a
    /// string_view to publish_final); the retry uses the record's fallback_final.
    std::uint64_t publish_terminal_ladder(const std::shared_ptr<BridgeRecord>& rec,
                                          std::string frame);

    /// Claimed-kDone teardown: unsubscribe, publish the decided terminal frame
    /// (kSynthesizeUnavailable = -32014 for a never-terminal victim; kFallbackFinal
    /// = success-shaped for a terminal-known-payload-lost victim; kNone = nothing),
    /// charge settle, obs transfer, erase.
    void teardown_claimed(const std::shared_ptr<BridgeRecord>& rec, TeardownFinal decision,
                          const char* audit_action);
    /// Release the streamed charge exactly once (clears under record mu - caller
    /// must NOT hold it - then decrements under bridge_mu_).
    void release_charge(const std::shared_ptr<BridgeRecord>& rec);
    void decrement_streamed_locked(const std::string& session_id);  // holds bridge_mu_

    // ── noexcept observability (C5) ────────────────────────────────────────
    template <typename F> bool obs_guard(F&& f) noexcept;
    void count_reject(const char* reason) noexcept;
    void publish_records_gauge(std::size_t n) noexcept;  ///< never called under bridge_mu_
    void flush_record_obs(BridgeRecord& rec) noexcept;
    void flush_core_obs() noexcept;
    void audit_contained(const char* action, const std::string& execution_id,
                         const std::string& detail) noexcept;

    ExecutionEventBus* bus_ = nullptr;
    McpSessionRegistry* sessions_ = nullptr;
    yuzu::MetricsRegistry* metrics_ = nullptr;
    AuditFn audit_;
    Config cfg_;

    mutable std::mutex bridge_mu_;
    bool shutdown_started_ = false;  ///< guarded by bridge_mu_ (C6 lifecycle gate)
    std::unordered_map<std::string, std::shared_ptr<BridgeRecord>> records_;
    /// Streamed records that have NOT yet pinned a final (the admission charge
    /// ledger, A5). Zero-valued entries are erased (no historical-session growth).
    std::unordered_map<std::string, std::size_t> streamed_unpinned_;
    std::uint64_t next_seq_ = 1;         ///< guarded by bridge_mu_
    std::uint64_t next_parked_seq_ = 1;  ///< guarded by bridge_mu_

    std::shared_ptr<WakeCore> core_ = std::make_shared<WakeCore>();
    std::thread projector_;
    std::atomic<bool> shutdown_called_{false};
    std::atomic<int> obs_fault_remaining_{0};  ///< C5 fault seam
    std::atomic<bool> arm_fault_{false};       ///< one-shot arm() throw seam
    std::atomic<bool> reserve_fault_{false};   ///< one-shot reserve() throw seam
    std::atomic<bool> subscribe_fault_{false}; ///< one-shot subscribe() throw seam
    std::atomic<bool> visit_copy_fault_{false};///< one-shot pressure-visit copy throw seam
    ClockFn clock_;                            ///< reaper clock (default steady_clock::now)

    std::chrono::steady_clock::time_point now() const {
        return clock_ ? clock_() : std::chrono::steady_clock::now();
    }
};

}  // namespace yuzu::server::mcp
