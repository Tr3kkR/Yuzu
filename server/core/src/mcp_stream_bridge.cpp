#include "mcp_stream_bridge.hpp"

#include "mcp_jsonrpc.hpp"
#include "mcp_session.hpp"
#include "mcp_stream.hpp"
#include "rest_a4_envelope.hpp"

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <new>
#include <system_error>
#include <utility>
#include <vector>

namespace yuzu::server::mcp {

namespace {
constexpr const char* kMetricRecordsActive = "yuzu_mcp_bridge_records_active";
constexpr const char* kMetricRejects = "yuzu_mcp_bridge_reject_total";
constexpr const char* kMetricListenerFailures = "yuzu_mcp_bridge_listener_failures_total";
constexpr const char* kMetricMailboxDrops = "yuzu_mcp_bridge_mailbox_drops_total";
constexpr const char* kMetricProjectorCycles = "yuzu_mcp_bridge_projector_cycles_total";
constexpr const char* kMetricProjectionDegraded = "yuzu_mcp_bridge_projection_degraded_total";
constexpr const char* kMetricStreamingBackstop = "yuzu_mcp_bridge_streaming_backstop_total";
// #2487: a teardown_claimed step that could not complete on the bare maintenance
// thread. `stage` is a CLOSED literal set (unsubscribe | release_charge | erase),
// pre-seeded in server.cpp. Any nonzero value means a record, its streamed charge,
// or its bus subscription outlived its teardown and now waits for shutdown() -
// alert on > 0.
constexpr const char* kMetricTeardownIncomplete = "yuzu_mcp_bridge_teardown_incomplete_total";
// #2529: a streamed admission charge that could not be released at its natural
// release point (arm()'s cancel-degrade) and is therefore RETAINED on the record
// until its teardown reclaims it. Distinct from kMetricTeardownIncomplete, which
// is teardown_claimed's own steps on the maintenance thread; this one fires on a
// request thread. Both-or-neither holds either way - the record and the ledger
// still agree - so a nonzero value is a deferred release, never a stranded slot.
constexpr const char* kMetricChargeReleaseDeferred =
    "yuzu_mcp_bridge_charge_release_deferred_total";
// Sessions currently holding every streamed-POST pin slot. The diagnostic that
// distinguishes "busy, will clear" from "leaked, never will" - without it the only
// signal for a wedged session was a bare reject counter, and both the 429
// remediation and the docs tell the caller to wait for calls that may already have
// finished. Governance 2026-07-27 (enterprise-readiness).
constexpr const char* kMetricSessionsAtPinCap = "yuzu_mcp_bridge_sessions_at_pin_cap";
// Produced ONLY by the bridge's publish_final -> fallback -> poison ladder
// (below); named in the yuzu_mcp_stream_* family because it describes stream-
// terminal delivery, not because mcp_stream.cpp increments it (poison_terminal()
// increments nothing; publish_guarded uses the generic publish-failure counter).
constexpr const char* kMetricTerminalPublishFailures =
    "yuzu_mcp_stream_terminal_publish_failures_total";

/// Parse the two monotone counters out of an execution-progress payload.
/// Throws on malformed JSON - the caller catches per batch (C4).
struct ProgressCounts {
    std::uint64_t responded = 0;
    std::uint64_t targeted = 0;
};
ProgressCounts parse_progress(const std::string& data) {
    const auto j = nlohmann::json::parse(data);
    ProgressCounts c;
    c.responded = j.value("agents_responded", std::uint64_t{0});
    c.targeted = j.value("agents_targeted", std::uint64_t{0});
    return c;
}
}  // namespace

// ── Construction / shutdown ────────────────────────────────────────────────

McpStreamBridge::McpStreamBridge(ExecutionEventBus* bus, McpSessionRegistry* sessions,
                                 yuzu::MetricsRegistry* metrics, AuditFn audit)
    : McpStreamBridge(bus, sessions, metrics, std::move(audit), Config{}) {}

McpStreamBridge::McpStreamBridge(ExecutionEventBus* bus, McpSessionRegistry* sessions,
                                 yuzu::MetricsRegistry* metrics, AuditFn audit, Config cfg)
    : bus_(bus), sessions_(sessions), metrics_(metrics), audit_(std::move(audit)), cfg_(cfg) {
    projector_ = std::thread([this] { run_projector(); });
}

McpStreamBridge::~McpStreamBridge() { shutdown(); }

void McpStreamBridge::shutdown() {
    if (shutdown_called_.exchange(true)) {
        return;  // idempotent - dtor after an explicit stop() is a no-op
    }
    {
        // Gate every public mutator first (C6): anything arriving after this
        // observes the flag while resolving its record under bridge_mu_ and
        // returns shutdown/not-found without waking the (soon dead) projector.
        std::lock_guard<std::mutex> lk(bridge_mu_);
        shutdown_started_ = true;
    }
    {
        // Stop the projector BEFORE touching records, and never while holding
        // bridge_mu_ - the projector snapshots under it (C6 join ordering).
        std::lock_guard<std::mutex> lk(core_->mu);
        core_->stop = true;
    }
    core_->cv.notify_all();
    if (projector_.joinable()) {
        projector_.join();
    }
    // The critical shutdown guarantees are already met above (mutators gated,
    // projector joined) BEFORE any allocation. The teardown below allocates a
    // reaped vector; a bad_alloc there must not propagate through the noexcept
    // ServerImpl::stop() or the destructor (→ std::terminate) and must not leave
    // the idempotence flag consumed with the work half-done in a way a retry
    // could resume - so the whole best-effort cleanup is contained. On OOM at
    // shutdown some subscriptions may linger, but the process is already tearing
    // down and no projector remains to touch them.
    try {
        std::vector<std::shared_ptr<BridgeRecord>> reaped;
        {
            std::lock_guard<std::mutex> lk(bridge_mu_);
            reaped.reserve(records_.size());
            for (auto& [key, rec] : records_) {
                if (rec->subscribed && bus_ != nullptr) {
                    // bridge_mu_ → Channel::mu is a declared edge; unsubscribe waits
                    // out in-flight listeners (they take record mu + WakeCore::mu
                    // only, never bridge_mu_ - no cycle).
                    bus_->unsubscribe(rec->execution_id, rec->sub_id);
                }
                rec->subscribed = false;
                reaped.push_back(rec);
            }
            records_.clear();
            streamed_unpinned_.clear();
        }
        for (const auto& rec : reaped) {
            {
                // Settle charge bookkeeping for consistency (the ledger map is
                // already gone; the flag must not read as "held" to a late observer).
                std::lock_guard<std::mutex> lk(rec->mu);
                rec->streamed_charge_held = false;
            }
            flush_record_obs(*rec);
        }
        flush_core_obs();
        publish_records_gauge(0);
    } catch (...) {  // NOLINT(bugprone-empty-catch) - see the note above
    }
}

// ── Key / lookup ───────────────────────────────────────────────────────────

std::string McpStreamBridge::make_key(const std::string& session_id,
                                      const nlohmann::json& jsonrpc_id) {
    // Session ids are 32 lowercase hex chars (mint), so '\n' cannot collide;
    // dump() keeps string "1" (\"1\") distinct from integer 1 (1).
    return session_id + '\n' + jsonrpc_id.dump();
}

std::shared_ptr<McpStreamBridge::BridgeRecord>
McpStreamBridge::find_locked(const std::string& key) const {
    auto it = records_.find(key);
    return it == records_.end() ? nullptr : it->second;
}

// ── Wake path ──────────────────────────────────────────────────────────────

void McpStreamBridge::wake(WakeCore& core) noexcept {
    try {
        {
            // The flag flips under the SAME mutex the projector's wait predicate
            // reads - a notify can never slot between predicate-check and sleep
            // (the lost-wakeup killer). WakeCore::mu is a strict leaf.
            std::lock_guard<std::mutex> lk(core.mu);
            core.work_pending = true;
        }
        core.cv.notify_one();
    } catch (...) {  // NOLINT(bugprone-empty-catch) - a wake must never escape a listener
    }
}

// ── Listener (free factory, C7/D5: captures record + wake core ONLY) ──────

ExecutionEventBus::Listener McpStreamBridge::make_listener(std::shared_ptr<BridgeRecord> rec,
                                                           std::shared_ptr<WakeCore> core) {
    return [rec = std::move(rec), core = std::move(core)](const ExecutionEvent& ev) noexcept {
        // Hard constraint 7: strictly copy-only + notify, catch-and-count.
        // Runs under Channel::mu; touches record mu + WakeCore::mu only.
        try {
            if (core->listener_fault.exchange(false, std::memory_order_acq_rel)) {
                throw std::bad_alloc{};  // inject_listener_fault_for_test
            }
            const bool is_terminal = ev.event_type == "execution-completed";
            const bool is_progress = ev.event_type == "execution-progress";
            if (!is_terminal && !is_progress) {
                return;  // agent-transition et al: not projected (documented)
            }
            {
                std::lock_guard<std::mutex> lk(rec->mu);
                if (rec->terminal_accepted) {
                    // D2: the final is last. A committed publisher really can emit
                    // post-terminal progress (refresh_counts after mark_cancelled)
                    // and duplicate terminals - all dropped once a terminal is
                    // secured.
                    return;
                }
                if (is_terminal) {
                    // Construct fully OUTSIDE the slot, then commit with a
                    // noexcept move: a payload-copy throw leaves the slot
                    // untouched and terminal_accepted unset.
                    MailboxEntry tmp{ev.id, ev.data};
                    rec->terminal_slot = std::move(tmp);
                    rec->terminal_accepted = true;  // sticky from here on
                } else {
                    if (rec->mb_count == kBridgeMailboxCap) {
                        // Drop-oldest-progress; counted record-locally (C5 - the
                        // listener never touches a metrics mutex).
                        rec->mb_head = (rec->mb_head + 1) % kBridgeMailboxCap;
                        --rec->mb_count;
                        rec->mailbox_drop_delta.fetch_add(1, std::memory_order_relaxed);
                    }
                    MailboxEntry tmp{ev.id, ev.data};
                    rec->mailbox[(rec->mb_head + rec->mb_count) % kBridgeMailboxCap] =
                        std::move(tmp);
                    ++rec->mb_count;
                }
            }
            wake(*core);
        } catch (...) {
            // Counted record-locally; the projector flushes it to the registry.
            rec->listener_failure_delta.fetch_add(1, std::memory_order_relaxed);
        }
    };
}

// ── reserve / subscribe / arm / cancel / abandon / park ────────────────────

McpStreamBridge::ReserveResult McpStreamBridge::reserve(const std::string& session_id,
                                                        const std::string& principal,
                                                        const nlohmann::json& jsonrpc_id,
                                                        std::optional<nlohmann::json> progress_token,
                                                        bool streamed_intent) {
    if (bus_ == nullptr) {
        count_reject("disabled");
        return {false, "disabled"};
    }
    {
        // D4: check shutdown BEFORE the registry call (and re-check after) so
        // the isolated-registry-lock rule holds without racing the gate.
        bool shutting_down = false;
        {
            std::lock_guard<std::mutex> lk(bridge_mu_);
            shutting_down = shutdown_started_;
        }
        if (shutting_down) {
            count_reject("shutdown");  // L2: count here too, like the post-registry branch
            return {false, "shutdown"};
        }
    }
    // Registry leaf - never called under bridge_mu_. stream_for touches
    // last_seen, which is correct here: reserve runs on a client request that
    // already slid the TTL at session-validate. Nothing on the PARKED path
    // touches it again (retention honesty).
    auto stream = sessions_ != nullptr ? sessions_->stream_for(session_id, principal) : nullptr;
    if (!stream) {
        count_reject("unknown_session");
        return {false, "unknown_session"};
    }
    if (reserve_fault_.exchange(false, std::memory_order_acq_rel)) {
        throw std::bad_alloc{};  // test seam: model an allocation failure post-admission
    }
    // Allocate outside bridge_mu_ (the mint precedent - construction is cheap
    // to discard on a reject and must not serialize against the map).
    auto rec = std::make_shared<BridgeRecord>();
    rec->session_id = session_id;
    rec->principal = principal;
    rec->jsonrpc_id = jsonrpc_id;
    rec->key = make_key(session_id, jsonrpc_id);
    rec->streamed_intent = streamed_intent;
    rec->created = now();
    rec->stream = std::move(stream);
    rec->progress_token = std::move(progress_token);

    const char* reject = nullptr;
    std::size_t active = 0;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            reject = "shutdown";
        } else if (records_.contains(rec->key)) {
            reject = "duplicate_request_id";
        } else if (records_.size() >= cfg_.global_record_cap) {
            reject = "global_cap";
        } else if (streamed_intent) {
            // A5: live pins + streamed records that have not pinned yet. Orphan
            // pins (pressure/pin-ack teardown) stay counted via pinned_count()
            // until the ring releases them; a transient over-count between a pin
            // commit and its ledger decrement rejects fail-closed.
            auto it = streamed_unpinned_.find(session_id);
            const std::size_t unpinned = it == streamed_unpinned_.end() ? 0 : it->second;
            if (rec->stream->pinned_count() + unpinned >= kMaxStreamedPostsPerSession) {
                reject = "pin_slots";
            }
        }
        if (reject == nullptr) {
            rec->seq = next_seq_++;
            // C6a: the ledger bump and the map insert must commit TOGETHER. Both
            // allocate - `operator[]` inserts a node, `emplace` allocates a node
            // and copies the key - so either can throw with the other already
            // applied. A ledger bump that survives a failed insert is a PHANTOM
            // charge: no record exists that will ever release it, so this
            // session's `pinned_count() + unpinned` stays permanently inflated
            // and every later streamed reserve on it rejects pin_slots for the
            // life of the process. Reordering to "emplace first" does NOT fix
            // this - it only swaps which mutation is left orphaned.
            struct LedgerRollback {
                McpStreamBridge* self;
                const std::string& session;
                BridgeRecord& rec;
                bool armed = false;
                bool committed = false;
                ~LedgerRollback() noexcept {
                    if (armed && !committed) {
                        // Runs while bridge_mu_ is still held (declared after the
                        // lock_guard, so it destructs first). find/decrement/erase
                        // allocates nothing, so it cannot throw out of here.
                        self->decrement_streamed_locked(session);
                        rec.streamed_charge_held = false;
                    }
                }
            } rollback{this, session_id, *rec};

            if (streamed_intent) {
                ++streamed_unpinned_[session_id];
                rollback.armed = true;
                rec->streamed_charge_held = true;
            }
            if (reserve_commit_fault_.exchange(false, std::memory_order_acq_rel)) {
                // Test seam: an allocation failure in the window BETWEEN the
                // ledger bump and the insert. The post-admission seam above fires
                // before the record is even constructed, so it cannot model this.
                throw std::bad_alloc{};
            }
            records_.emplace(rec->key, rec);
            rollback.committed = true;
            active = records_.size();
        }
    }
    if (reject != nullptr) {
        count_reject(reject);
        return {false, reject};
    }
    publish_records_gauge(active);
    return {true, nullptr};
}

bool McpStreamBridge::subscribe(const std::string& session_id, const nlohmann::json& jsonrpc_id,
                                const std::string& execution_id) {
    if (bus_ == nullptr) {
        return false;
    }
    // A3: the WHOLE install runs under bridge_mu_ - installation and the
    // sub-token store are serialized against shutdown/teardown, so a listener
    // can never exist without a token a teardown can see. bridge_mu_ →
    // Channel::mu is the declared edge; the replay runs the listener inline
    // (record mu + WakeCore::mu - no cycle).
    std::lock_guard<std::mutex> lk(bridge_mu_);
    if (shutdown_started_) {
        return false;
    }
    auto rec = find_locked(make_key(session_id, jsonrpc_id));
    if (!rec) {
        return false;
    }
    if (subscribe_fault_.exchange(false, std::memory_order_acq_rel)) {
        throw std::bad_alloc{};  // test seam: model a subscribe allocation failure
    }
    // Prebuilt HERE, before the record-mu hold, for the same reason arm() does it
    // (H2): the throwing work happens while nothing has changed, and the commit
    // below is a noexcept move. Load-bearing for park_after_dispatch_failure - a
    // record parked before arm() ran has no other source for a fallback final, and
    // every fallback publisher (the projector ladder and teardown's kFallbackFinal
    // arm) reads this field. Without it such a record would publish an EMPTY frame.
    std::string fallback = build_fallback_final(jsonrpc_id, execution_id);
    {
        // EXACTLY-ONCE, STATE-CHECKED (#2487 review). The "written before any
        // listener exists, immutable afterwards" contract is what lets
        // teardown_claimed BORROW execution_id instead of copying it, and what
        // stops a second listener being installed on a record a sweep has already
        // claimed. It used to be a comment; now it is a gate.
        //
        // The window that made it load-bearing: a sweep claimant sets torn_down
        // and releases both locks before teardown_claimed runs, and the record is
        // erased from records_ only at the very END of teardown. A subscribe()
        // arriving in between still resolves the record, would reassign the string
        // out from under teardown's borrowed reference (a reallocating assignment
        // = a genuine data race on the read), and would install a fresh listener
        // that the imminent erase then strands forever - recreating precisely the
        // orphan-listener leak this change exists to prevent. Reachable via the
        // kArming reaper, which cannot distinguish a dead handler from a very slow
        // one.
        std::lock_guard<std::mutex> rlk(rec->mu);
        // `torn_down` is REDUNDANT today and kept deliberately: every claim path
        // moves the phase out of kArming in the same critical section that sets
        // torn_down, so the phase check below always catches a claimed record first.
        // Verified by mutation - deleting this clause alone leaves the suite green,
        // whereas deleting either of the other two reddens it. It is retained as
        // defence in depth so that a future claim path which forgets to move the
        // phase still cannot admit a subscribe; it is NOT independently covered.
        if (rec->subscribed || rec->torn_down ||
            rec->phase.load(std::memory_order_acquire) != Phase::kArming) {
            return false;
        }
        rec->execution_id = execution_id;
        rec->fallback_final = std::move(fallback);
    }
    // ORDERING INVARIANT (governance performance/UP-5): the caller MUST invoke
    // subscribe() BEFORE dispatch / the first refresh_counts, so the bus channel
    // has no buffered events yet and this inline replay-under-bridge_mu_ is O(0).
    // If a future refactor moved subscribe() after progress began, this would
    // hold bridge_mu_ across an O(buffer, up to kBufferCap=1000) replay, stalling
    // every reserve/arm/abandon/sweep behind it.
    const auto sub_id = bus_->subscribe_and_replay(execution_id, 0, make_listener(rec, core_));
    rec->sub_id = sub_id;
    rec->subscribed = true;
    return true;
}

McpStreamBridge::ArmOutcome McpStreamBridge::arm(const std::string& session_id,
                                                 const nlohmann::json& jsonrpc_id, ArmMode mode,
                                                 std::string result_base) {
    std::shared_ptr<BridgeRecord> rec;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return ArmOutcome::kNotFound;
        }
        rec = find_locked(make_key(session_id, jsonrpc_id));
    }
    if (!rec) {
        return ArmOutcome::kNotFound;  // abandon won and erased - equally valid
    }
    if (arm_fault_.exchange(false, std::memory_order_acq_rel)) {
        throw std::bad_alloc{};  // test seam: model a pre-flip allocation failure
    }
    // Prebuild the minimal fallback final BEFORE the flip (H2): all throwing
    // work happens while nothing has changed. subscribe() already stored an
    // identical string (so a park before arm has one); this rebuild keeps arm
    // self-sufficient, and both go through build_fallback_final so the bytes have
    // exactly one derivation.
    std::string exec_id;
    {
        std::lock_guard<std::mutex> rlk(rec->mu);
        exec_id = rec->execution_id;
    }
    std::string fallback = build_fallback_final(jsonrpc_id, exec_id);

    bool consumed_cancel = false;
    bool degraded = false;
    ArmOutcome outcome = ArmOutcome::kArmed;  // defensively initialised; assigned below
    {
        // The ONE record-mutex hold (H2): noexcept moves, arbitration, flip,
        // handoff wake. A concurrent listener append lands pre-flip (drained by
        // this wake) or post-flip (drained by its own unconditional wake).
        std::lock_guard<std::mutex> rlk(rec->mu);
        // C6 re-check under the flip hold: shutdown() sets shutdown_called_
        // (atomic) at its very start, BEFORE it stops+joins the projector and
        // clears the map. A caller that passed the top-of-arm shutdown gate but
        // released bridge_mu_ before reaching here could otherwise flip a
        // detached record and wake a joined projector. Bailing keeps the C6
        // gating contract true independent of the (masking) server wiring order.
        if (shutdown_called_.load(std::memory_order_acquire)) {
            return ArmOutcome::kNotFound;
        }
        const Phase cur = rec->phase.load(std::memory_order_acquire);
        if (cur == Phase::kAborted) {
            return ArmOutcome::kAborted;
        }
        if (cur != Phase::kArming) {
            return ArmOutcome::kAlreadyArmed;
        }
        rec->fallback_final = std::move(fallback);
        rec->result_base = std::move(result_base);
        consumed_cancel = rec->cancel_pending;
        rec->cancel_pending = false;
        degraded = consumed_cancel && mode == ArmMode::kStreaming;
        const Phase target =
            (mode == ArmMode::kStreaming && !degraded) ? Phase::kStreaming : Phase::kArmedGetOnly;
        rec->phase.store(target, std::memory_order_release);
        outcome = degraded ? ArmOutcome::kDegradedGetOnly : ArmOutcome::kArmed;
        wake(*core_);  // the handoff - same hold
    }
    if (degraded) {
        // #2529: the degraded record follows the GET-only lifecycle and can never
        // pin, so its admission charge is owed back. This USED TO clear
        // streamed_charge_held inside the flip hold above and take bridge_mu_ here
        // afterwards - the split that broke release_charge and project_record, with
        // the same consequence: a throw at the second acquisition left the record
        // reading "not held" while streamed_unpinned_[session] still counted it, so
        // that entry never reached 0, never got erased, and the session accumulated
        // forever. Routing through release_charge - which takes BOTH locks in
        // hierarchy order and re-reads the flag under them - makes it both-or-
        // neither, and keeps ONE implementation of the release rather than a third
        // copy. Exactly-once survives the move: the flag is the interlock, so a
        // concurrent teardown racing this simply wins and this call no-ops.
        //
        // CONTAINED, and the outcome is still returned. A failure here leaves a
        // CONSISTENT record (charge held, ledger counts it) that its own teardown
        // repairs, whereas throwing would lose a flip that already succeeded and
        // hand the caller an error response for a request whose plain result is
        // perfectly good. This is also what makes the H2 property above literally
        // true: after the flip, arm() cannot throw. Same posture as teardown step 3,
        // which contains and counts a release_charge failure rather than abandoning
        // the teardown.
        try {
            release_charge(rec);
        } catch (...) {
            count_charge_release_deferred();
        }
    }
    if (consumed_cancel) {
        // C1: audit only AFTER winning the arbitration, outside every lock.
        audit_contained("mcp.bridge.cancel", exec_id,
                        outcome == ArmOutcome::kDegradedGetOnly
                            ? "consumed_by_arm: streamed intent degraded to get-only"
                            : "consumed_by_arm: get-only request, nothing to detach",
                        {}, AuditResult::kSuccess);
    }
    return outcome;
}

McpStreamBridge::CancelOutcome McpStreamBridge::request_cancel(const std::string& session_id,
                                                               const nlohmann::json& jsonrpc_id,
                                                               std::string_view principal) {
    std::shared_ptr<BridgeRecord> rec;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return CancelOutcome::kNoOp;
        }
        rec = find_locked(make_key(session_id, jsonrpc_id));
    }
    if (!rec) {
        return CancelOutcome::kNoOp;  // no oracle: unknown == not cancellable
    }
    std::string exec_id;
    {
        std::lock_guard<std::mutex> rlk(rec->mu);
        const Phase ph = rec->phase.load(std::memory_order_acquire);
        if (ph == Phase::kStreaming) {
            // 3b: the record HAS a live streamed response, so there is nothing for
            // a later arbiter to decide - the cancel applies NOW. Closing the sink
            // is the whole action: the pump wakes, sees `closed`, and finishes with
            // kCancelled, which writes the close frame carrying execution_id and
            // partial:true; its releaser then parks the record.
            //
            // The EXECUTION is deliberately untouched - not unsubscribed, not
            // abandoned, never marked cancelled. MCP cancellation withdraws the
            // client's interest in a RESPONSE; the dispatched command keeps running
            // on real agents and its result stays fetchable by execution_id.
            // Cancelling the work here would let a client believe it had stopped a
            // fleet-wide change it had not.
            if (!rec->post_sink) {
                return CancelOutcome::kNoOp;  // never bound, or already parked
            }
            // COPIED BEFORE THE MUTATION, deliberately: this is the only allocation
            // on the path, and doing it after the close would let a bad_alloc
            // propagate out of a cancel that had ALREADY ended the response - the
            // caller catches, reports kNoOp, and a cancel that genuinely took effect
            // goes unaudited and uncounted. Same discipline as arm(), which
            // prebuilds its fallback before the flip.
            exec_id = rec->execution_id;
            // The close TRANSITION is the interlock, not the phase. `post_sink` is
            // not cleared until on_post_closed_keyed, which runs later from the
            // pump's releaser, so two cancels arriving before that BOTH see
            // kStreaming with a live sink - a retried notification is ordinary
            // client behaviour, not a race anyone has to engineer. Only the caller
            // that actually flipped `closed` may claim the detach; a duplicate is
            // kNoOp, which is also the honest answer once there is no live response
            // left to detach. A close that could not be delivered returns false
            // too, so the audit below can never assert something that did not
            // happen.
            if (!close_post_sink(rec->post_sink)) {
                return CancelOutcome::kNoOp;
            }
        } else if (ph == Phase::kArming && !rec->cancel_pending) {
            // Pre-arm: intent ONLY - no audit, no transition (C1). A later
            // pre-dispatch failure (abandon) invalidates the cancel/degrade
            // outcome, so the win is arm()'s and the audit belongs there.
            rec->cancel_pending = true;
            return CancelOutcome::kAcceptedPending;
        } else {
            return CancelOutcome::kNoOp;
        }
    }
    // Outside every lock (C1 discipline). Unlike the kArming path there is no later
    // arbiter to audit this one, so it is audited HERE, exactly once - CH-12
    // requires a cancellation to be auditable, and this is the only site that knows
    // it took effect.
    audit_contained("mcp.bridge.cancel", exec_id,
                    "detached the streamed response; the execution continues", {},
                    AuditResult::kSuccess, principal);
    return CancelOutcome::kDetached;
}

bool McpStreamBridge::close_post_sink(
    const std::shared_ptr<sse_bus::SseSinkState>& sink) noexcept {
    if (!sink) {
        return false;
    }
    try {
        // `closed` is stored UNDER the sink mutex rather than as a bare atomic
        // write, for the same reason poke_post_sink takes it: the pump evaluates
        // its wait predicate under this mutex, so a store outside it can land
        // between that evaluation and the wait and leave the pump asleep on a
        // stream the client has already given up on - a lost wakeup that costs a
        // full tick and keeps an HTTP worker pinned meanwhile.
        //
        // Callers hold the record mutex, which the declared hierarchy places ABOVE
        // this one (BridgeRecord::mu -> McpStreamState::mu_ -> SseSinkState::mu),
        // so this nesting is the sanctioned direction.
        bool was_open = false;
        {
            std::lock_guard<std::mutex> lk(sink->mu);
            // exchange, not store: the RETURN VALUE is what makes the caller's
            // action exactly-once. Under the mutex so it cannot interleave with
            // the pump's predicate evaluation.
            was_open = !sink->closed.exchange(true, std::memory_order_acq_rel);
        }
        sink->cv.notify_all();
        return was_open;
    } catch (...) { // NOLINT(bugprone-empty-catch)
        // A cancel we could not deliver is not worth propagating out of a noexcept
        // seam on a request thread: the response still ends at its cap, and the
        // execution was never at risk either way. Reported as "not closed by me"
        // so the caller cannot audit a detach that did not occur.
    }
    return false;
}

bool McpStreamBridge::abandon(const std::string& session_id, const nlohmann::json& jsonrpc_id) {
    std::shared_ptr<BridgeRecord> rec;
    std::size_t active = 0;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return false;  // shutdown owns global teardown
        }
        const auto key = make_key(session_id, jsonrpc_id);
        rec = find_locked(key);
        if (!rec) {
            return false;
        }
        {
            std::lock_guard<std::mutex> rlk(rec->mu);
            if (rec->phase.load(std::memory_order_acquire) != Phase::kArming) {
                return false;  // arm won - the caller lost the arbitration (C1)
            }
            rec->phase.store(Phase::kAborted, std::memory_order_release);
            rec->cancel_pending = false;  // discarded, never audited (C1)
            rec->mb_head = 0;
            rec->mb_count = 0;
            rec->terminal_slot.reset();
            if (rec->streamed_charge_held) {
                rec->streamed_charge_held = false;
                decrement_streamed_locked(session_id);  // already under bridge_mu_
            }
        }
        if (rec->subscribed && bus_ != nullptr) {
            // Waits out in-flight listeners; after this returns no thread can
            // append (they take record mu + WakeCore::mu only - no cycle).
            bus_->unsubscribe(rec->execution_id, rec->sub_id);
        }
        rec->subscribed = false;
        records_.erase(key);
        active = records_.size();
    }
    flush_record_obs(*rec);
    publish_records_gauge(active);
    return true;
}

bool McpStreamBridge::park_after_dispatch_failure(const std::string& session_id,
                                                  const nlohmann::json& jsonrpc_id,
                                                  std::string_view principal) {
    std::shared_ptr<BridgeRecord> rec;
    std::uint64_t parked_seq = 0;
    std::string exec_id;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return false;  // shutdown owns global teardown
        }
        rec = find_locked(make_key(session_id, jsonrpc_id));
        if (!rec) {
            return false;  // abandon or a sweep claim won - equally valid
        }
        parked_seq = next_parked_seq_++;
    }
    {
        std::lock_guard<std::mutex> rlk(rec->mu);
        // C6 re-check under the transition hold (same rationale as arm() and
        // on_post_closed): a shutdown that raced past the top gate must not have
        // this transition wake a joined projector on a detached record.
        if (shutdown_called_.load(std::memory_order_acquire)) {
            return false;
        }
        Phase expected = Phase::kArming;
        if (!rec->phase.compare_exchange_strong(expected, Phase::kRingOnly,
                                                std::memory_order_acq_rel)) {
            return false;  // arm() or abandon() already arbitrated this record
        }
        // Discarded without audit, exactly as abandon does (C1): the cancel was
        // intent against a stream that now will never exist. The streamed charge
        // is deliberately RETAINED - a parked record can still pin its final, and
        // the pin-ack / teardown paths release it exactly once.
        rec->cancel_pending = false;
        rec->parked_seq = parked_seq;
        exec_id = rec->execution_id;
    }
    // The mailbox and any latched terminal survived the transition, so hand the
    // record to the projector now rather than waiting for the next bus event.
    wake(*core_);
    audit_contained("mcp.bridge.dispatch_failure", exec_id,
                    "parked after a post-dispatch failure: the execution continues and its "
                    "result stays fetchable by execution_id",
                    {}, AuditResult::kSuccess, principal);
    return true;
}

std::optional<std::string> McpStreamBridge::record_key(const std::string& session_id,
                                                       const nlohmann::json& jsonrpc_id) {
    auto key = make_key(session_id, jsonrpc_id);  // allocates HERE, which is the point
    std::lock_guard<std::mutex> lk(bridge_mu_);
    if (shutdown_started_ || !find_locked(key)) {
        return std::nullopt;
    }
    return key;
}

bool McpStreamBridge::on_post_closed(const std::string& session_id,
                                     const nlohmann::json& jsonrpc_id) {
    // ONE implementation; this overload just pays the key allocation. Keeping a
    // second copy of the transition here is how the two would drift.
    return on_post_closed_keyed(make_key(session_id, jsonrpc_id));
}

bool McpStreamBridge::on_post_closed_keyed(const std::string& key) {
    std::shared_ptr<BridgeRecord> rec;
    std::uint64_t parked_seq = 0;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return false;
        }
        rec = find_locked(key);
        if (!rec) {
            return false;
        }
        parked_seq = next_parked_seq_++;
    }
    {
        std::lock_guard<std::mutex> rlk(rec->mu);
        // C6 re-check under the transition hold (same rationale as arm()): a
        // shutdown that raced past the top gate must not have this transition
        // wake a joined projector on a detached record.
        if (shutdown_called_.load(std::memory_order_acquire)) {
            return false;
        }
        // A delivered final means the client already holds its answer, so there
        // is nothing left to resume: settle kDone and let sweep reap it. Without
        // a final, park for GET resume. Both are the same CAS out of kStreaming,
        // so a record can only ever take one of them.
        const Phase target = rec->final_written ? Phase::kDone : Phase::kRingOnly;
        Phase expected = Phase::kStreaming;
        if (!rec->phase.compare_exchange_strong(expected, target, std::memory_order_acq_rel)) {
            return false;
        }
        rec->parked_seq = parked_seq;
        // The wire is gone; holding its sink would pin a dead connection's state
        // for as long as the record parks.
        rec->post_sink.reset();
    }
    // A1: a terminal latched while the pump was dying must not wait for the next
    // bus event or sweep - hand the record to the projector now.
    wake(*core_);
    return true;
}

bool McpStreamBridge::on_final_written(const std::string& key) {
    std::shared_ptr<BridgeRecord> rec;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return false;
        }
        rec = find_locked(key);
        if (!rec) {
            return false;
        }
    }
    std::lock_guard<std::mutex> rlk(rec->mu);
    if (rec->phase.load(std::memory_order_acquire) != Phase::kStreaming) {
        return false;  // only a live streamed wire can have written a final
    }
    rec->final_written = true;
    // UNPIN RULE (a), the streamed-POST half: "the final was written on the POST
    // wire" (mcp_stream.hpp). This is the rung that makes that event exist, and
    // until now nothing called unpin() at all - so a COMPLETED streamed call left
    // its pin behind forever, admission counted it against
    // kMaxStreamedPostsPerSession, and four successful calls locked a session out
    // permanently while the 429 told the client to wait for calls that had already
    // finished. Rule (b) (a GET resume acking past the id) only ever covered the
    // resume case; a client that received its final on the POST wire never resumes.
    //
    // Safe precisely here: the pump calls this ONLY after write_all succeeded, so a
    // dead peer returns kClientGone without reaching it and correctly keeps the pin
    // for a resuming client. Lock order holds - BridgeRecord::mu is above
    // McpStreamState::mu_.
    if (rec->pinned_event_id != 0 && rec->stream) {
        rec->stream->unpin(rec->pinned_event_id);
    }
    return true;
}

std::optional<std::string> McpStreamBridge::bind_post_sink(
    const std::string& session_id, const nlohmann::json& jsonrpc_id,
    std::shared_ptr<sse_bus::SseSinkState> sink) {
    if (!sink) {
        return std::nullopt;
    }
    auto key = make_key(session_id, jsonrpc_id);  // allocates HERE, before any state changes
    std::shared_ptr<BridgeRecord> rec;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return std::nullopt;
        }
        rec = find_locked(key);
        if (!rec) {
            return std::nullopt;
        }
    }
    {
        std::lock_guard<std::mutex> rlk(rec->mu);
        if (rec->phase.load(std::memory_order_acquire) != Phase::kStreaming) {
            return std::nullopt;  // only a live streamed record has a POST wire
        }
        rec->post_sink = std::move(sink);
        // BIND-TIME HANDSHAKE: evaluate the pending-work predicate inside the SAME
        // hold that stores the sink. Work can latch between arm() and this call -
        // a terminal, most consequentially - and the projector only forwards wakes
        // to a sink it can already see, so anything latched before the bind would
        // otherwise cost the pump a full tick.
        if (has_pending_work_locked(*rec)) {
            poke_post_sink(rec->post_sink);
        }
    }
    return key;
}

McpStreamBridge::PostBatch McpStreamBridge::take_post_batch(const std::string& key,
                                                            bool cap_expired) {
    PostBatch out;
    std::shared_ptr<BridgeRecord> rec;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return out;  // shutdown owns teardown; the pump sees an empty tick
        }
        rec = find_locked(key);
        if (!rec) {
            return out;
        }
    }
    // ONE projection implementation - see the header note. project_record accepts
    // kStreaming only when handed a batch, and fills it with the frames it just
    // committed to the ring.
    project_record(rec, &out, cap_expired);
    flush_record_obs(*rec);
    // PARK-VS-CLAIM FENCE. A close can flip kStreaming -> kRingOnly while this
    // pump holds the projection claim. That transition wakes the projector once,
    // but the projector finds the claim set and returns; by the time the claim
    // clears (project_record's guard, just above) nothing wakes it again, and a
    // parked record holding a latched terminal stalls until the next sweep tick.
    // Re-waking here closes that window. A spurious wake costs one projector pass
    // over a record with no work; a missed one costs a stalled result.
    if (rec->phase.load(std::memory_order_acquire) != Phase::kStreaming) {
        wake(*core_);
    }
    return out;
}

bool McpStreamBridge::has_pending_work_locked(const BridgeRecord& rec) {
    // The SAME predicate project_record uses to decide there is a batch worth
    // claiming. Factored so the bind handshake and the projector's wake-forwarding
    // cannot disagree with the consumer about what "pending" means.
    const bool progress = rec.mb_count > 0 && !rec.pressure_requested;
    const bool terminal = rec.terminal_accepted &&
                          !rec.terminal_projected.load(std::memory_order_acquire) &&
                          rec.terminal_slot.has_value();
    return progress || terminal;
}

void McpStreamBridge::poke_post_sink(
    const std::shared_ptr<sse_bus::SseSinkState>& sink) noexcept {
    if (!sink) {
        return;
    }
    try {
        // Taking the sink mutex before notifying is what makes this a HANDOFF
        // rather than a lost wakeup. The pump evaluates its predicate under this
        // mutex, so a bare notify could land in the window between that
        // evaluation and the wait, and the pump would then sleep through work
        // that was already there. Nothing is mutated under it - the predicate
        // reads bridge state - so the acquisition IS the synchronisation. Same
        // discipline as close_sink storing `closed` under this mutex.
        //
        // NOT INDEPENDENTLY COVERED, and deliberately so: removing this
        // acquisition leaves the suite green, because the poke reaches here only
        // after the bus listener, the projector wake and a thread switch, by
        // which time any waiting pump is already inside wait_for. Forcing the
        // window would need a test hook inside this function, which would prove
        // the hook rather than the discipline. Verified by mutation and recorded
        // as uncovered rather than given a test that passes for the wrong reason.
        //
        // Callers hold the record mutex, which the declared hierarchy places
        // ABOVE this one (BridgeRecord::mu -> McpStreamState::mu_ ->
        // SseSinkState::mu), so this nesting is the sanctioned direction; the
        // pump holds the sink mutex only to evaluate a predicate, never across
        // a write.
        {
            std::lock_guard<std::mutex> slk(sink->mu);
            // SET something the pump's predicate READS. Taking the mutex alone is
            // not a wake: the pump waits on a predicated wait_for, so a bare notify
            // makes it re-evaluate, find nothing, and sleep out the rest of the
            // tick. Without this flag the whole wake path - this function and
            // bind_post_sink's handshake - is inert, and progress arrives on a
            // fixed grid rather than as it happens.
            sink->poked.store(true, std::memory_order_release);
        }
        sink->cv.notify_one();
    } catch (...) {  // NOLINT(bugprone-empty-catch) - the pump's tick timeout is the backstop
    }
}

// ── Projector ──────────────────────────────────────────────────────────────

void McpStreamBridge::run_projector() {
    for (;;) {
        {
            std::unique_lock<std::mutex> lk(core_->mu);
            core_->cv.wait(lk, [&] { return core_->stop || core_->work_pending; });
            if (core_->stop) {
                return;  // listeners are unsubscribed by shutdown; residual
                         // progress frames of a dying process are not a delivery
                         // obligation (terminals are durable-fetchable)
            }
            core_->work_pending = false;
        }
        // BARE-THREAD BOUNDARY: run_projector is a std::thread entry with no
        // caller try/catch, so ANY escaped exception is std::terminate (#2037
        // class). The record snapshot ALLOCATES (snap.reserve / push_back) - a
        // bad_alloc there would escape past the per-record guard below, which is
        // why the whole cycle body is contained. A transient allocation failure
        // drops this cycle; the next wake retries, and a latched terminal stays
        // durably fetchable in the meantime (Decision 15(f)).
        try {
            std::vector<std::shared_ptr<BridgeRecord>> snap;
            {
                std::lock_guard<std::mutex> lk(bridge_mu_);
                snap.reserve(records_.size());
                for (const auto& [key, rec] : records_) {
                    snap.push_back(rec);
                }
            }
            for (const auto& rec : snap) {
                try {
                    project_record(rec);
                } catch (...) {
                    // project_record's claim guard restored any unsettled terminal;
                    // this is a true should-not-happen backstop (all interior throw
                    // sites are individually caught).
                    spdlog::warn("MCP bridge projector: projection pass failed (contained)");
                }
                flush_record_obs(*rec);
            }
            flush_core_obs();
            // Event-driven liveness signal (governance sre): a flat rate here
            // while records_active > 0 means the projector is wedged.
            if (metrics_ != nullptr) {
                obs_guard([&] { metrics_->counter(kMetricProjectorCycles).increment(); });
            }
        } catch (...) {  // NOLINT(bugprone-empty-catch) - see the boundary note above
        }
    }
}

void McpStreamBridge::project_record(const std::shared_ptr<BridgeRecord>& rec, PostBatch* out,
                                     bool cap_expired) {
    Phase ph;
    std::array<MailboxEntry, kBridgeMailboxCap> batch{};
    std::size_t batch_n = 0;
    std::optional<MailboxEntry> term;
    {
        std::lock_guard<std::mutex> rlk(rec->mu);
        ph = rec->phase.load(std::memory_order_acquire);
        // kStreaming is PUMP-owned: only take_post_batch (which passes `out`) may
        // project it. The projector still visits such records, but its whole job
        // there is to FORWARD THE WAKE - a streamed record's frames are ring-only
        // (deliver_live=false), so the publish path never notifies the POST sink
        // and the pump would otherwise sleep out its tick on work already latched.
        if (ph == Phase::kStreaming && out == nullptr) {
            if (has_pending_work_locked(*rec)) {
                poke_post_sink(rec->post_sink);
            }
            return;
        }
        if (ph != Phase::kArmedGetOnly && ph != Phase::kRingOnly && ph != Phase::kStreaming) {
            return;  // kArming latches; kDone/kAborted dead
        }
        if (rec->projection_in_flight.load(std::memory_order_acquire)) {
            if (out != nullptr) {
                out->deferred = true;  // the pump retries next tick; nothing is owed
            }
            return;  // the claim fences sweep and the other projector (B2)
        }
        // E1: while a pressure sweep is waiting on this record, no NEW progress
        // batch may start - only an already-latched terminal settles.
        const bool want_progress = rec->mb_count > 0 && !rec->pressure_requested;
        const bool want_terminal = rec->terminal_accepted &&
                                   !rec->terminal_projected.load(std::memory_order_acquire) &&
                                   rec->terminal_slot.has_value();
        if (!want_progress && !want_terminal) {
            // CAP ARBITRATION, decided INSIDE the record lock alongside the
            // terminal check rather than by the pump beforehand: a terminal that
            // latched in the same instant wins, and ordinary progress is never
            // ring-committed merely to probe for one.
            if (out != nullptr && cap_expired) {
                out->cap_settled = true;
            }
            return;
        }
        // The claim - everything below is noexcept. Relaxed: this critical
        // section IS the mutual exclusion, and every consumer reads under the
        // same `mu`; the acquire/release pair matters only for ~ClaimGuard's
        // lock-free clear (#2528 protocol, stated on the field).
        rec->projection_in_flight.store(true, std::memory_order_relaxed);
        if (want_progress) {
            for (std::size_t i = 0; i < rec->mb_count; ++i) {
                batch[i] = std::move(rec->mailbox[(rec->mb_head + i) % kBridgeMailboxCap]);
            }
            batch_n = rec->mb_count;
            rec->mb_head = 0;
            rec->mb_count = 0;
        }
        if (want_terminal) {
            term = std::move(rec->terminal_slot);
            rec->terminal_slot.reset();  // explicit - never trust moved-from state (C4)
        }
    }

    // Settle-or-restore guard (B4/C4): whatever exits this scope, an unsettled
    // terminal payload goes BACK into the slot (terminal_accepted is sticky and
    // never cleared, so no listener can have refilled it) and the claim clears.
    //
    // ORDERING (load-bearing, governance cpp-expert): `guard` is declared HERE,
    // OUTSIDE the per-branch `lock_guard(rec->mu)` scopes below. Destructors run
    // in reverse order, so on any branch exit the inner lock_guard releases
    // rec->mu FIRST, then ~ClaimGuard re-locks it - never a same-thread double
    // lock. Do not move this declaration inside a locked scope.
    struct ClaimGuard {
        const std::shared_ptr<BridgeRecord>& rec;
        std::optional<MailboxEntry>& term;
        std::atomic<int>& lock_fault;
        bool terminal_settled = false;
        ~ClaimGuard() noexcept {
            // Contained: this destructor is implicitly noexcept and its FIRST act is a
            // mutex acquisition - the one throw site this file's own fault model treats
            // as real (it injects resource_deadlock_would_occur elsewhere). Unguarded,
            // a lock failure here is std::terminate on the projector thread, and
            // guaranteed so if the destructor runs during unwinding.
            try {
                if (lock_fault.load(std::memory_order_relaxed) > 0 &&
                    lock_fault.fetch_sub(1, std::memory_order_acq_rel) > 0) {
                    // inject_claim_lock_fault_for_test - the modelled mutex failure
                    throw std::system_error(
                        std::make_error_code(std::errc::resource_deadlock_would_occur));
                }
                std::lock_guard<std::mutex> rlk(rec->mu);
                if (term.has_value() && !terminal_settled) {
                    rec->terminal_slot = std::move(term);
                } else if (terminal_settled) {
                // The terminal was committed to the wire but the bookkeeping below
                // may not have run - it is the one thing between the commit and the
                // flag that can throw (two mutex acquisitions). Without this, such a
                // record has terminal_accepted set and terminal_projected clear, and
                // the pressure visitor's "latched but unprojected -> defer" arm then
                // defers it FOREVER; because a defer exits the pressure loop, one
                // wedged victim stalls ring-only pressure relief bridge-wide. Setting
                // it here is safe precisely because terminal_settled means the frame
                // is already published - it cannot cause a republish.
                    rec->terminal_projected.store(true, std::memory_order_release);
                }
                rec->projection_in_flight.store(false, std::memory_order_release);
                return;
            } catch (...) {  // NOLINT(bugprone-empty-catch) - degraded settle below
            }

            // DEGRADED SETTLE (#2528). `mu` is unavailable, so none of the above
            // ran. The claim must be released anyway - leaving it set wedges the
            // record out of all four consumers, and because a defer exits the
            // pressure loop, one wedged victim stalls ring-only pressure relief
            // bridge-wide. This is the ONE statement of what the skipped
            // bookkeeping means; the field comments point here rather than
            // restate it.
            //
            //  (a) progress-only batch (no terminal extracted): nothing was owed.
            //      Releasing the claim is a COMPLETE recovery.
            //  (b) terminal_settled: the frame is already committed to the ring;
            //      the only lost write is terminal_projected. Storing it here is
            //      honest - settled means published, so it cannot cause a
            //      republish - and it lets the pressure visitor claim with kNone
            //      instead of deferring on "latched but unprojected" forever.
            //  (c) extracted but NOT settled (the restore-and-retry path): the
            //      payload cannot go back into terminal_slot, and no listener will
            //      refill it, so the retry is gone. Mark it lost. The consumer
            //      contract - success-shaped fallback final, never kNone, never
            //      -32014 - is stated on terminal_payload_lost and honoured in the
            //      pressure visitor.
            //
            // Ordering is load-bearing: the bookkeeping stores are released BEFORE
            // the claim, so no consumer can observe a released claim over stale
            // bookkeeping. A consumer that races and reads the pre-store values
            // merely defers one sweep tick and re-reads - bounded, not wedged.
            if (terminal_settled) {
                rec->terminal_projected.store(true, std::memory_order_release);
            } else if (term.has_value()) {
                rec->terminal_payload_lost.store(true, std::memory_order_release);
            }
            rec->projection_degraded_delta.fetch_add(1, std::memory_order_relaxed);
            rec->projection_in_flight.store(false, std::memory_order_release);
        }
    } guard{rec, term, claim_lock_fault_};

    // Phase observed under the mutex ⇒ arm() completed ⇒ the immutable-after-arm
    // fields (progress_token, execution_id, fallback_final, result_base, stream,
    // jsonrpc_id) are safe to read lock-free from here.
    const bool get_only = ph == Phase::kArmedGetOnly;

    // Progress first - the final must be last on the wire.
    if (batch_n > 0 && rec->progress_token.has_value()) {
        for (std::size_t i = 0; i < batch_n; ++i) {
            std::uint64_t responded = 0;
            std::uint64_t targeted = 0;
            try {
                const auto counts = parse_progress(batch[i].data);
                // UP-4: skip a frame with no meaningful denominator. An
                // execution-progress event published BEFORE set_agents_targeted
                // (an agent responding during dispatch) carries agents_targeted=0;
                // latched during kArming, it would otherwise drain into a
                // `total:0` progress notification, which a strict MCP client can
                // reject. `total` is monotone-meaningful only once targeted>0.
                if (counts.targeted == 0) {
                    continue;
                }
                targeted = counts.targeted;
                // Defensive clamp: responded must never exceed targeted on the
                // wire (a transient count skew between the two COUNT(*) subqueries
                // must not surface as progress>total).
                responded = std::min(counts.responded, counts.targeted);
            } catch (...) {
                // C4: drop this batch's remainder, keep going to terminal
                // settlement. A malformed/unbuildable progress delta is
                // fire-and-forget by contract.
                spdlog::warn("MCP bridge: progress frame build failed; dropping batch remainder");
                break;
            }
            // H1 (governance adversarial review): both supported MCP revisions say
            // notifications/progress `progress` MUST INCREASE with each frame.
            // The bus publishes a fresh refresh_counts snapshot on EVERY agent
            // response (and the S4.5 fix makes duplicate snapshots more likely),
            // and snapshot-and-release publishing outside the tracker mutex can
            // even momentarily decrease the count - so forwarding every snapshot
            // verbatim would emit equal/decreasing progress. Suppress any
            // candidate not strictly greater than the last value already
            // committed to the wire for this record (the first frame is always
            // allowed, so an initial 0/N is fine as the starting point). Same
            // "a strict client can reject" rationale as the UP-4 total:0 skip.
            if (rec->progress_sent_any && responded <= rec->last_progress_sent) {
                continue;
            }
            std::string frame;
            try {
                const std::string msg = std::to_string(responded) + "/" +
                                        std::to_string(targeted) + " agents responded";
                frame = progress_notification(*rec->progress_token, responded, targeted,
                                              msg, rec->execution_id);
            } catch (...) {
                spdlog::warn("MCP bridge: progress frame build failed; dropping batch remainder");
                break;
            }
            const std::uint64_t id = get_only
                                         ? rec->stream->publish("message", frame)  // live GET + ring
                                         : rec->stream->publish_ring_only("message", frame);  // replay
            // Advance the watermark ONLY after the frame actually committed
            // (id != 0); a pre-commit publish failure leaves the value un-sent so
            // a later equal-value snapshot can still carry it.
            if (id != 0) {
                rec->last_progress_sent = responded;
                rec->progress_sent_any = true;
                if (out != nullptr) {
                    // Only COMMITTED frames reach the live POST wire. A frame the
                    // ring rejected pre-commit has no replayable counterpart, so
                    // sending it live would leave a resuming client with a gap it
                    // can never fill - and the watermark above deliberately did
                    // not advance for it either.
                    try {
                        out->progress.push_back(std::move(frame));
                    } catch (...) {  // NOLINT(bugprone-empty-catch)
                        // The ring copy is durable; losing the live copy costs
                        // this client a frame it can still fetch by resume.
                    }
                }
            }
        }
    }

    if (!term.has_value()) {
        return;  // guard clears the claim
    }

    if (get_only) {
        // GET-only mode: NO final frame, NO pin - the plain JSON response
        // already answered this request. Settle and finish the lifecycle.
        guard.terminal_settled = true;
        std::lock_guard<std::mutex> rlk(rec->mu);
        rec->terminal_projected.store(true, std::memory_order_release);
        Phase expected = Phase::kArmedGetOnly;
        rec->phase.compare_exchange_strong(expected, Phase::kDone, std::memory_order_acq_rel);
        return;  // sweep reaps kDone
    }

    // kRingOnly: real final via the pinned ladder.
    std::string frame;
    bool built = false;
    try {
        if (projection_build_fault_.load(std::memory_order_acquire) > 0 &&
            projection_build_fault_.fetch_sub(1, std::memory_order_acq_rel) > 0) {
            throw std::bad_alloc{};  // inject_projection_build_fault_for_test
        }
        frame = build_real_final(*rec, term->data);
        built = true;
    } catch (...) {
        try {
            if (projection_fallback_fault_.load(std::memory_order_acquire) > 0 &&
                projection_fallback_fault_.fetch_sub(1, std::memory_order_acq_rel) > 0) {
                throw std::bad_alloc{};  // inject_projection_fallback_fault_for_test
            }
            frame = rec->fallback_final;  // prebuilt at subscribe/arm; copy can only OOM
            built = true;
        } catch (...) {  // NOLINT(bugprone-empty-catch)
        }
    }
    if (!built) {
        // Allocation death even for the prebuilt fallback. Restore (guard) and
        // let the NEXT wake retry - deliberately no self-wake here, so a
        // persistent OOM cannot hot-loop the projector (B4/A6c: sweep cadence
        // and any later bus/arm activity bound the retry latency instead).
        return;
    }
    if (out != nullptr) {
        // Copied BEFORE the ladder consumes it, and before anything is published:
        // if this allocation fails, the guard restores the terminal, the claim
        // clears and the pump retries - nothing has been committed or delivered
        // twice. Doing it after the publish would risk a ring commit the pump
        // never learns about.
        out->final_frame = frame;
    }
    const auto fid = publish_terminal_ladder(rec, std::move(frame)).id;
    // Settle IMMEDIATELY after the commit/poison decision (C4): no later
    // bookkeeping failure may restore + republish.
    guard.terminal_settled = true;
    {
        // Locks in hierarchy order and held ACROSS the flag clear and the ledger
        // decrement. This used to clear the flag under rec->mu, release, and only
        // then take bridge_mu_ - the same split that broke release_charge, with the
        // same consequence: a throw at the second acquisition leaves the record
        // reading "not held" while streamed_unpinned_[session] still counts it, so
        // that entry never reaches 0, never gets erased, and the session accumulates
        // forever. run_projector's per-record catch swallows it, so nothing retries.
        // Fixing release_charge alone would have fixed the instance and left the sink.
        // This WAS the second of three; arm()'s cancel-degrade path was the third and
        // is now routed through release_charge itself (#2529), so every clear of
        // streamed_charge_held in this file now happens under BOTH locks or under
        // bridge_mu_ with the ledger mutated in the same hold. Verified by sweep:
        // shutdown clears the whole ledger map wholesale, reserve's LedgerRollback
        // unwinds both while bridge_mu_ is still held, and abandon holds both. Keep it
        // that way - a new split here is not a local style choice, it is a permanent
        // per-session leak.
        std::lock_guard<std::mutex> lk(bridge_mu_);
        std::lock_guard<std::mutex> rlk(rec->mu);
        rec->terminal_projected.store(true, std::memory_order_release);
        if (fid != 0) {
            rec->final_published = true;
            rec->pinned_event_id = fid;
        }
        if (rec->streamed_charge_held) {
            // C3: settled - either the final is pinned (admission now counts it
            // via pinned_count()) or it settled pinless/poisoned (no pin will
            // ever come). Exactly-once: cleared and decremented together.
            rec->streamed_charge_held = false;
            decrement_streamed_locked(rec->session_id);
        }
    }
    // D4: the guard clears projection_in_flight only now, AFTER the deferred
    // charge decrement - sweep can never observe a half-settled record.
}

std::string McpStreamBridge::build_fallback_final(const nlohmann::json& jsonrpc_id,
                                                  const std::string& execution_id) {
    return success_response(
        jsonrpc_id, std::string(R"({"execution_id":)") + detail::json_quoted(execution_id) +
                        R"(,"status":"unknown","detail":)" +
                        detail::json_quoted("terminal counts unavailable - fetch by execution_id "
                                            "(get_execution_status / query_responses)") +
                        "}");
}

std::string McpStreamBridge::build_real_final(const BridgeRecord& rec,
                                              const std::string& terminal_data) {
    // B5: result_base is the serialized JSON-RPC *result object* exactly as
    // today's plain path built it; the additive fields are TOP-LEVEL result
    // keys, never folded into content[0].text.
    //
    // This is the one place the bridge uses nlohmann for OUTPUT (parse-merge-
    // reserialize), against the MCP surface's usual JObj/JArr-build convention
    // (governance security-LOW): a genuine three-way merge of an opaque
    // caller-shaped result object + two additive keys needs a real JSON DOM, and
    // dump() escapes correctly, so there is no injection risk. Reached ONLY on
    // the kRingOnly path, which is 3b-dead in production today.
    nlohmann::json base = rec.result_base.empty() ? nlohmann::json::object()
                                                  : nlohmann::json::parse(rec.result_base);
    if (!base.is_object()) {
        base = nlohmann::json::object();
    }
    const auto t = nlohmann::json::parse(terminal_data);
    base["status"] = t.value("status", "unknown");
    if (t.contains("agents_success")) {
        base["agents_success"] = t["agents_success"];
    }
    if (t.contains("agents_failure")) {
        base["agents_failure"] = t["agents_failure"];
    }
    if (!base.contains("execution_id")) {
        base["execution_id"] = rec.execution_id;  // the durable fetch handle, always present
    }
    return success_response(rec.jsonrpc_id, base.dump());
}

McpStreamBridge::LadderResult
McpStreamBridge::publish_terminal_ladder(const std::shared_ptr<BridgeRecord>& rec,
                                         std::string&& frame) {
    auto fid = rec->stream->publish_final("message", frame);
    if (fid != 0) {
        return {fid, TerminalRung::kPrimary};
    }
    if (metrics_ != nullptr) {
        obs_guard([&] { metrics_->counter(kMetricTerminalPublishFailures).increment(); });
    }
    // Retry once with the prebuilt per-record fallback (immutable member - the
    // string_view stays alive across the call).
    fid = rec->stream->publish_final("message", rec->fallback_final);
    if (fid != 0) {
        return {fid, TerminalRung::kFallback};
    }
    if (metrics_ != nullptr) {
        obs_guard([&] { metrics_->counter(kMetricTerminalPublishFailures).increment(); });
    }
    // Double failure: sticky session poison - every future attach 410s and the
    // durable execution_id fetch is the recovery path (Decision 15(f) wiring of
    // the mcp_stream caller obligation).
    rec->stream->poison_terminal();
    return {0, TerminalRung::kPoisoned};
}

// ── Sweep ──────────────────────────────────────────────────────────────────

void McpStreamBridge::sweep() {
    // Refresh the busy-vs-wedged reading once per maintenance tick, before the
    // passes below can change it.
    publish_pin_cap_gauge();
    std::vector<std::shared_ptr<BridgeRecord>> snap;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return;
        }
        snap.reserve(records_.size());
        for (const auto& [key, rec] : records_) {
            snap.push_back(rec);
        }
    }

    // Passes 0-2: kDone reap, pin-ack, session death. Classification evidence
    // is gathered without bridge_mu_, but the CLAIM re-validates everything
    // under bridge_mu_ → record mu (B2/D4 - classification IS the claim).
    for (const auto& rec : snap) {
        const Phase ph = rec->phase.load(std::memory_order_acquire);
        bool claim = false;
        const char* action = nullptr;
        if (ph == Phase::kDone) {
            claim = true;
            action = "mcp.bridge.done_reap";
        } else if (ph == Phase::kArming) {
            // A record still kArming long past its synchronous handler's return
            // is orphaned: the double-bad_alloc corner (arm's fallback build
            // threw, then abandon's make_key ALSO threw under OOM) leaves it
            // stranded, and sweep otherwise never reclaims kArming. Reap it to
            // stop a monotonic global-slot leak (governance cpp-safety SHOULD).
            // `created` is write-once (immutable after reserve, before the record
            // is shared), so a lock-free read is safe; a concurrent arm() that
            // moves the phase off kArming makes the claim re-check below fail and
            // defer to the live handler.
            if (now() - rec->created > cfg_.arming_reap_after) {
                claim = true;
                action = "mcp.bridge.arming_reaped";
            }
        } else if (ph == Phase::kStreaming) {
            // BACKSTOP for the streamed-POST leak. Every pass below claims only
            // kDone / kArming / kArmedGetOnly / kRingOnly, so a record stranded
            // in kStreaming - its releaser swallowed the close, or the process
            // lost the connection without running one - is invisible to ALL of
            // them, INCLUDING session death, and leaks for the life of the
            // process. The primary defence is that the releaser's close path
            // allocates nothing (on_post_closed_keyed); this is the second one.
            //
            // It PARKS, never reaps. A reap would unsubscribe, unpin and erase,
            // destroying resume state and possibly a real latched terminal that
            // the client can still legitimately collect. It also deliberately
            // does NOT set `claim` and go through the block below: that block
            // sets torn_down, which means "permanently excluded from reclaim",
            // so a merely-parked record would never be swept again. A transition
            // is not a teardown.
            //
            // Routed through the SAME transition the releaser uses rather than a
            // second copy of it - including its final_written branch, so a record
            // whose final reached the wire still settles kDone rather than
            // parking for a resume nobody needs.
            const bool session_alive =
                sessions_ != nullptr && sessions_->exists(rec->session_id, rec->principal);
            // `created` and `key` are write-once (immutable after reserve, before
            // the record is shared), so both are safe to read lock-free here.
            const bool stale = now() - rec->created > cfg_.streaming_park_after;
            if ((!session_alive || stale) && on_post_closed_keyed(rec->key) && metrics_ != nullptr) {
                obs_guard([&] { metrics_->counter(kMetricStreamingBackstop).increment(); });
            }
        } else if (ph == Phase::kArmedGetOnly || ph == Phase::kRingOnly) {
            // Registry leaf, no locks held. Non-touching: a parked record must
            // never extend session life.
            const bool session_alive =
                sessions_ != nullptr && sessions_->exists(rec->session_id, rec->principal);
            if (!session_alive) {
                claim = true;
                action = "mcp.bridge.session_dead";
            } else if (ph == Phase::kRingOnly) {
                std::lock_guard<std::mutex> rlk(rec->mu);
                // H4: const pin poll - the ring's unpin (resume-cursor ack) is
                // the consumption proof; no stream→bridge callback edge.
                if (rec->final_published && rec->pinned_event_id != 0 &&
                    !rec->projection_in_flight.load(std::memory_order_acquire) &&
                    !rec->stream->is_pinned(rec->pinned_event_id)) {
                    claim = true;
                    action = "mcp.bridge.pin_acked";
                }
            }
        }
        if (!claim) {
            continue;
        }
        bool claimed = false;
        {
            std::lock_guard<std::mutex> lk(bridge_mu_);
            if (shutdown_started_) {
                return;
            }
            auto it = records_.find(rec->key);
            if (it == records_.end() || it->second != rec) {
                continue;  // map identity: somebody else already tore it down
            }
            std::lock_guard<std::mutex> rlk(rec->mu);
            const Phase cur = rec->phase.load(std::memory_order_acquire);
            if (rec->projection_in_flight.load(std::memory_order_acquire) || rec->torn_down) {
                continue;  // B2: never claim mid-projection; teardown is exactly-once
            }
            if (cur != ph && cur != Phase::kDone) {
                // Moved on since the evidence was gathered (a kDone settle in
                // between is still reapable; a kArming record a concurrent arm()
                // just flipped falls here and is skipped - the live handler owns
                // it); anything else waits for the next sweep with fresh evidence.
                continue;
            }
            // A reaped kArming record ends in kAborted (pre-dispatch failure
            // class); every other claim ends in kDone. teardown_claimed does not
            // inspect the phase value - only the torn_down/erase bookkeeping.
            rec->phase.store(ph == Phase::kArming ? Phase::kAborted : Phase::kDone,
                             std::memory_order_release);
            rec->torn_down = true;
            claimed = true;
        }
        if (claimed) {
            teardown_claimed(rec, TeardownFinal::kNone, action);
        }
    }

    // Pass 3: ring-only pressure (E1 two-stage, multi-victim, oldest-first).
    for (;;) {
        std::shared_ptr<BridgeRecord> oldest;
        std::size_t ring_only = 0;
        {
            std::lock_guard<std::mutex> lk(bridge_mu_);
            if (shutdown_started_) {
                return;
            }
            for (const auto& [key, rec] : records_) {
                if (rec->phase.load(std::memory_order_acquire) != Phase::kRingOnly) {
                    continue;
                }
                ++ring_only;
                std::lock_guard<std::mutex> rlk(rec->mu);
                if (!oldest || rec->parked_seq < oldest->parked_seq) {
                    oldest = rec;
                }
            }
        }
        if (ring_only <= cfg_.ring_only_pressure_cap || !oldest) {
            return;
        }
        // Stage 1: mark the victim so the projector starts no NEW progress batch
        // (project_record gates on pressure_requested). ALL disposition logic
        // lives in the atomic visit below - one source of truth (CORE-2).
        {
            std::lock_guard<std::mutex> rlk(oldest->mu);
            oldest->pressure_requested = true;
        }
        // Re-validate map identity before the visit (the victim was selected in a
        // prior bridge_mu_ section; a concurrent teardown may have moved it).
        {
            std::lock_guard<std::mutex> lk(bridge_mu_);
            if (shutdown_started_) {
                return;
            }
            auto it = records_.find(oldest->key);
            if (it == records_.end() || it->second != oldest) {
                continue;  // torn down concurrently - recount
            }
        }
        // Stage 2: the atomic visit that closes #2409 (was the KNOWN GAP here).
        // Under a SINGLE hold of the bus channel mutex, `f` computes the
        // disposition from record state (the bus verdict arbitrates ONLY a record
        // with no secured terminal) and claims kDone via a torn_down CAS under
        // record mu; the bus erases the listener ONLY on that committed claim.
        // bridge_mu_ is NOT held across the visit (it takes Channel::mu → record
        // mu, a valid suffix of the declared hierarchy; `f` must not take
        // bridge_mu_ or call a bus method). Every DEFER keeps the listener, so a
        // deferred terminal channel can never be GC'd out from under the record.
        bool claimed_by_me = false;
        TeardownFinal decision = TeardownFinal::kNone;
        ExecutionEventBus::VisitStatus status = ExecutionEventBus::VisitStatus::kAbsentChannel;
        if (bus_ != nullptr) {
            // NOT noexcept ON PURPOSE: the ONE uncontained throw here is the
            // record-lock acquisition below (before any mutation). Letting it
            // propagate lets unsubscribe_and_visit_terminal's try/catch convert it
            // to kInternalError (fail-closed), which a noexcept lambda would instead
            // turn into std::terminate before that catch can see it. Everything
            // after the lock is noexcept stores + an internally-contained payload
            // copy, so a propagated throw means "record untouched" == "f did not
            // run" - the kInternalError invariant holds.
            auto f = [&](ExecutionEventBus::TerminalVisit verdict,
                         const ExecutionEvent* ev) -> bool {
                std::lock_guard<std::mutex> rlk(oldest->mu);
                const Phase ph = oldest->phase.load(std::memory_order_acquire);
                if (oldest->torn_down || ph != Phase::kRingOnly) {
                    return false;  // stale: a competing claimant already owns it
                }
                // Record-side state dominates the bus verdict (CORE-2).
                if (oldest->terminal_accepted &&
                    oldest->terminal_projected.load(std::memory_order_acquire)) {
                    // Settled real final already pinned: claim, publish nothing.
                    oldest->phase.store(Phase::kDone, std::memory_order_release);
                    oldest->torn_down = true;
                    claimed_by_me = true;
                    decision = TeardownFinal::kNone;
                    return true;
                }
                if (oldest->terminal_accepted &&
                    !oldest->terminal_projected.load(std::memory_order_acquire)) {
                    if (oldest->terminal_payload_lost.load(std::memory_order_acquire)) {
                        // #2528 degraded settle: a real terminal existed, but its
                        // payload was extracted and then lost when ~ClaimGuard could
                        // not retake mu. terminal_slot is empty and sticky
                        // terminal_accepted stops any listener refill, so NO projector
                        // retry exists and deferring here would defer forever. Same
                        // disposition as kTerminalKnownLost: the success-shaped
                        // fallback, never -32014 (a terminal did happen) and never
                        // kNone (which would answer the client nothing).
                        oldest->phase.store(Phase::kDone, std::memory_order_release);
                        oldest->torn_down = true;
                        claimed_by_me = true;
                        decision = TeardownFinal::kFallbackFinal;
                        return true;
                    }
                    return false;  // latched, not pinned: defer; projector settles
                }
                if (oldest->projection_in_flight.load(std::memory_order_acquire)) {
                    return false;  // a progress projection is mid-flight: defer
                }
                // No secured terminal: the bus verdict arbitrates. Secure any
                // terminal record-side BEFORE the (claim-driven) erase.
                switch (verdict) {
                    case ExecutionEventBus::TerminalVisit::kTerminalBuffered:
                        // `ev` is the FIRST terminal-flagged event, which in the
                        // refresh_counts split is a terminal-flagged execution-progress
                        // (NOT execution-completed). build_real_final consumes it
                        // correctly ONLY because refresh_counts stamps status +
                        // agents_success/failure onto that terminal progress payload
                        // (execution_tracker.cpp ~:477-482) - a load-bearing coupling
                        // (#2409 cons-S5/UP-3): if that stamping is ever removed, the
                        // final would silently degrade to status:"unknown".
                        if (ev != nullptr) {
                            try {
                                if (visit_copy_fault_.load(std::memory_order_relaxed) > 0 &&
                                    visit_copy_fault_.fetch_sub(1, std::memory_order_acq_rel) > 0) {
                                    throw std::bad_alloc{};  // inject_visit_copy_fault_for_test
                                }
                                // Construct fully OUTSIDE the slot, then commit with
                                // a noexcept move - a copy OOM leaves the slot and
                                // terminal_accepted untouched (mirror the listener).
                                MailboxEntry tmp{ev->id, ev->data};
                                oldest->terminal_slot = std::move(tmp);
                                oldest->terminal_accepted = true;
                            } catch (...) {  // NOLINT(bugprone-empty-catch) - deliberate
                                // Copy OOM: nothing secured. Defer, keep the
                                // listener (a retry latches next sweep).
                            }
                        }
                        return false;  // defer; the projector publishes the real final
                    case ExecutionEventBus::TerminalVisit::kTerminalKnownLost:
                        // Terminal existed but its payload aged out of the bus buffer:
                        // claim + publish the success-shaped fallback, never -32014.
                        oldest->phase.store(Phase::kDone, std::memory_order_release);
                        oldest->torn_down = true;
                        claimed_by_me = true;
                        decision = TeardownFinal::kFallbackFinal;
                        return true;
                    case ExecutionEventBus::TerminalVisit::kNeverTerminal:
                    default:
                        oldest->phase.store(Phase::kDone, std::memory_order_release);
                        oldest->torn_down = true;
                        claimed_by_me = true;
                        decision = TeardownFinal::kSynthesizeUnavailable;
                        return true;
                }
            };
            status = bus_->unsubscribe_and_visit_terminal(oldest->execution_id,
                                                          oldest->sub_id, f);
        }
        if (claimed_by_me) {
            // f won the claim under Channel::mu (FA-1: the captured flag, NOT
            // record-state inference - a concurrent sweep's winner leaves the record
            // kDone-in-map until its teardown erases it). Re-acquire the shutdown
            // gate the pre-visit block released: the claim commits WITHOUT bridge_mu_
            // (inside f, under Channel::mu), so shutdown() can have started meanwhile.
            // If it has, DO NOT publish/audit against a torn-down record - shutdown()'s
            // own walk covers every record (all phases), releasing the charge and
            // unsubscribing, so the claimed record is still cleaned up.
            {
                std::lock_guard<std::mutex> lk(bridge_mu_);
                if (shutdown_started_) {
                    return;
                }
                auto it = records_.find(oldest->key);
                if (it == records_.end() || it->second != oldest) {
                    continue;  // shutdown/another sweep already removed it
                }
            }
            teardown_claimed(oldest, decision, "mcp.bridge.forced_expire");
            continue;  // recount
        }
        if (status == ExecutionEventBus::VisitStatus::kAbsentChannel ||
            status == ExecutionEventBus::VisitStatus::kInternalError) {
            // f did NOT run (no channel / a lock threw). CF-2: claim from record
            // state ONLY when unambiguous (settled real final, or a secured
            // terminal-known-lost with no projection in flight); else defer +
            // retry. NEVER infer kNeverTerminal from a missing channel (#2409).
            // Near-unreachable under erase-only-on-claim (a deferred record keeps
            // its listener, so its channel never GCs), but kept for robustness.
            bool guard_claim = false;
            TeardownFinal guard_decision = TeardownFinal::kNone;
            {
                std::lock_guard<std::mutex> lk(bridge_mu_);
                if (shutdown_started_) {
                    return;
                }
                auto it = records_.find(oldest->key);
                if (it == records_.end() || it->second != oldest) {
                    continue;
                }
                std::lock_guard<std::mutex> rlk(oldest->mu);
                // Defensive only (near-unreachable: a non-claimed kRingOnly record
                // keeps its listener, so its channel is never GC'd -> f runs, no
                // kAbsentChannel). Claim ONLY an unambiguous settled real final; a
                // record that never secured a terminal defers (NEVER synthesize
                // -32014 from an absent channel - that would re-open #2409).
                // NOTE (#2528): a terminal_payload_lost record is NOT claimed here.
                // Its honest disposition is kFallbackFinal, and this block is
                // deliberately kNone-only - every publishing disposition must stay
                // reachable solely from the visitor above, where the bus has already
                // removed the listener. Such a record defers on this near-unreachable
                // path and is reclaimed by shutdown(); widening the guard block would
                // trade a bounded defer for a publish over a live listener.
                if (!oldest->torn_down &&
                    oldest->phase.load(std::memory_order_acquire) == Phase::kRingOnly &&
                    oldest->terminal_accepted &&
                    oldest->terminal_projected.load(std::memory_order_acquire)) {
                    guard_claim = true;
                    guard_decision = TeardownFinal::kNone;
                    oldest->phase.store(Phase::kDone, std::memory_order_release);
                    oldest->torn_down = true;
                }
            }
            if (guard_claim) {
                teardown_claimed(oldest, guard_decision, "mcp.bridge.forced_expire");
                continue;
            }
        }
        // Deferred (not claimed, or a bus-less build): wake the projector to settle
        // any secured terminal, then return. Defer-class exits the loop so we never
        // re-visit the same oldest victim in a tight cycle within one sweep (FA-4).
        wake(*core_);
        return;
    }
}

void McpStreamBridge::teardown_claimed(std::shared_ptr<BridgeRecord> rec, TeardownFinal decision,
                                       const char* audit_action) noexcept {
    // Claimant owns the record: the phase (kDone / kAborted) AND `torn_down` were
    // both stored under record mu before we got here. `torn_down` PERMANENTLY
    // excludes this record from every later sweep claim, so THERE IS NO RETRIER -
    // whatever this function leaves unfinished stays unfinished until shutdown()
    // walks records_. Declared noexcept so that property is machine-checked rather
    // than asserted by comment.
    //
    // `rec` is taken BY VALUE, not by const&. The borrow below is a reference INTO
    // the record, and the erase step drops one strong reference to it - so the
    // keep-alive must be structural here, not an unenforced obligation on all three
    // call sites to hold their own copy.
    //
    // #2487 SCOPE, STATED HONESTLY: this narrows the crash surface, it does not
    // close it. The two allocations that made this function abort the process (an
    // execution-id copy and a const char* -> std::string audit temporary) are GONE -
    // that is the actual fix. The per-step containment below is defence in depth
    // against a fault that is currently near-unreachable: unsubscribe, the charge
    // decrement and the map erase are find/erase and node operations that allocate
    // nothing, so only a std::mutex::lock failure can reach these branches. It earns
    // its place because the day anyone adds an allocating call (say
    // gc_terminal_channels(), which publish() already does) to
    // ExecutionEventBus::unsubscribe, that branch becomes live under exactly the
    // memory pressure it was written for. The maintenance thread as a whole is NOT
    // exception-safe: sibling blocks on that thread remain unguarded.
    //
    // Ownership here is THREE things, not two: the records_ entry, the streamed
    // charge, and the BUS SUBSCRIPTION. Erasing the map entry while the subscription
    // survives is the worst available outcome - make_listener captures a shared_ptr
    // to this record, so erasing destroys nothing; the listener stays installed and
    // keeps waking a record nothing can find, shutdown() can no longer reach it (it
    // walks records_), and channel GC refuses to reap the channel because it
    // requires listeners.empty().
    //
    // `execution_id` is immutable after subscribe(), which ENFORCES that with a
    // state gate, so bind it - never copy.
    const std::string& exec_id = rec->execution_id;

    // Contained step runner. Declaring the wrapper noexcept is safe (and NOT the
    // "noexcept defeats an outer catch" trap) because the catch that contains the
    // work lives INSIDE it.
    const auto contained = [](auto&& f) noexcept -> bool {
        try {
            f();
            return true;
        } catch (...) {
            return false;
        }
    };
    // Last-resort evidence. The metric and the audit row both route through guards
    // that swallow, and under the OOM this function exists for BOTH can fail - which
    // would leave a stranded record with no evidence of any kind. This log line is
    // the floor; it is itself contained because formatting allocates.
    const auto log_incomplete = [&](const char* stage) noexcept {
        (void)contained([&] {
            // "reason=" matches the metric label so an operator can correlate the log
            // line with yuzu_mcp_bridge_teardown_incomplete_total{reason} directly.
            // It said "stage=" while the label was renamed, which meant grepping the
            // journal for the label value found nothing.
            spdlog::error("MCP bridge teardown incomplete [reason={} execution_id={}]: "
                          "resource retained until shutdown",
                          stage, exec_id);
        });
    };

    // ── Step 1: PUBLISH the decided disposition ────────────────────────────────
    // BEFORE the unsubscribe, deliberately. A later step failing must never lose a
    // terminal the pressure visitor already decided on: the previous order returned
    // early on an unsubscribe failure and silently dropped the frame, leaving the
    // client with no terminal, no poison and no retrier. Safe to reorder because the
    // only dispositions that publish anything are reached from the pressure pass,
    // where unsubscribe_and_visit_terminal has ALREADY removed the listener - so for
    // every publishing case there is no live listener to race, and for kNone there
    // is nothing to publish.
    TerminalRung rung = TerminalRung::kNotAttempted;
    bool ladder_reached = false;
    switch (decision) {
        case TeardownFinal::kSynthesizeUnavailable:
            // Pressure victim that genuinely NEVER saw a terminal (verified at claim
            // under Channel::mu): pin a machine-readable terminal-unavailable so a
            // later resume still finds truth in the ring.
            try {
                if (terminal_build_fault_.load(std::memory_order_acquire) > 0 &&
                    terminal_build_fault_.fetch_sub(1, std::memory_order_acq_rel) > 0) {
                    throw std::bad_alloc{};  // inject_terminal_build_fault_for_test
                }
                std::string data =
                    std::string(R"({"execution_id":)") + detail::json_quoted(exec_id) +
                    R"(,"correlation_id":)" +
                    detail::json_quoted(yuzu::server::detail::make_correlation_id()) +
                    R"(,"retry_after_ms":null,"remediation":)" +
                    detail::json_quoted("result no longer buffered - fetch it by "
                                        "execution_id (get_execution_status / "
                                        "query_responses)") +
                    "}";
                std::string frame =
                    error_response(rec->jsonrpc_id, kMcpTerminalUnavailable,
                                   "streamed result forced-expired under memory pressure", data);
                ladder_reached = true;
                rung = publish_terminal_ladder(rec, std::move(frame)).rung;
            } catch (...) {
                // Distinguish "never reached the ladder" (frame build threw) from
                // "the ladder itself threw": the audit must not claim a frame could
                // not be BUILT when it was built and the publish threw.
                rung = ladder_reached ? TerminalRung::kPublishThrew : TerminalRung::kNotAttempted;
                if (metrics_ != nullptr) {
                    obs_guard([&] { metrics_->counter(kMetricTerminalPublishFailures).increment(); });
                }
            }
            break;
        case TeardownFinal::kFallbackFinal:
            // Terminal existed but its payload aged out of the bus buffer: publish
            // the prebuilt SUCCESS-shaped final, NEVER -32014.
            try {
                if (terminal_build_fault_.load(std::memory_order_acquire) > 0 &&
                    terminal_build_fault_.fetch_sub(1, std::memory_order_acq_rel) > 0) {
                    throw std::bad_alloc{};  // models the fallback_final copy failing
                }
                // Copy FIRST, then flag. The ladder takes an rvalue reference
                // precisely so this copy cannot hide at the call boundary: done
                // there it would allocate AFTER ladder_reached was set, making a
                // copy OOM audit as "publishing threw" when the ladder was never
                // entered. No test can distinguish those two orderings (the fault
                // seam cannot sit at the copy point in both), so the signature
                // enforces it instead.
                std::string frame = rec->fallback_final;
                ladder_reached = true;
                rung = publish_terminal_ladder(rec, std::move(frame)).rung;
            } catch (...) {
                rung = ladder_reached ? TerminalRung::kPublishThrew : TerminalRung::kNotAttempted;
                if (metrics_ != nullptr) {
                    obs_guard([&] { metrics_->counter(kMetricTerminalPublishFailures).increment(); });
                }
            }
            break;
        case TeardownFinal::kNone:
            break;  // real final already pinned, or nothing to publish
    }

    // Derived ONCE and passed to every audit site below, bail or not. See
    // disposition_phrase(); nothing here re-derives the terminal's fate.
    const char* const disposition = disposition_phrase(decision, rung);
    const bool terminal_delivered = decision == TeardownFinal::kNone ||
                                    rung == TerminalRung::kPrimary ||
                                    rung == TerminalRung::kFallback;

    // ── Step 2: unsubscribe ────────────────────────────────────────────────────
    if (!contained([&] {
            if (take_step_fault(TeardownStage::kUnsubscribe)) {
                // system_error, not bad_alloc: a mutex failure is the only thing these
                // steps actually admit, and the seam should model the real fault.
                throw std::system_error(
                    std::make_error_code(std::errc::resource_deadlock_would_occur),
                    "injected teardown unsubscribe failure");
            }
            std::lock_guard<std::mutex> lk(bridge_mu_);
            if (rec->subscribed && bus_ != nullptr) {
                bus_->unsubscribe(exec_id, rec->sub_id);
            }
            rec->subscribed = false;
        })) {
        // Bail with the record still in records_, still charged: internally
        // consistent, reclaimed by shutdown(), and never an orphan listener.
        // torn_down is deliberately NOT cleared - re-entering the exactly-once
        // teardown protocol is a design change, deferred rather than smuggled into a
        // containment fix. Tracked as #2513 (retriable teardown), which also records
        // the real blast radius: a retained subscription pins the bus channel and its
        // replay buffer for the process lifetime.
        count_teardown_incomplete(TeardownStage::kUnsubscribe);
        log_incomplete(stage_name(TeardownStage::kUnsubscribe));
        // The detail must not assert a delivery that did not happen. There are three
        // teardown_claimed call sites; the pin-ack / session-death / arming-reap one
        // passes kNone literally and publishes nothing, and the two pressure sites
        // pass a decision that still delivers nothing on kPoisoned / kPublishThrew /
        // kNotAttempted - so "the terminal was published" is only true when the ladder
        // actually committed. The disposition below is derived, not assumed.
        audit_contained(audit_action, exec_id,
                        "teardown incomplete: bus unsubscribe failed; the record, its streamed "
                        "charge and its bus subscription are all retained for shutdown",
                        disposition, AuditResult::kFailure);
        return;
    }

    // ── Step 3: release the streamed charge ────────────────────────────────────
    const bool charge_released = contained([&] {
        if (take_step_fault(TeardownStage::kReleaseCharge)) {
            throw std::system_error(std::make_error_code(std::errc::resource_deadlock_would_occur),
                                    "injected teardown release_charge failure");
        }
        release_charge(rec);
    });
    if (!charge_released) {
        count_teardown_incomplete(TeardownStage::kReleaseCharge);
        log_incomplete(stage_name(TeardownStage::kReleaseCharge));
    }
    flush_record_obs(*rec);  // already noexcept

    // ── Step 4: erase the map entry ────────────────────────────────────────────
    std::size_t active = 0;
    if (!contained([&] {
            if (take_step_fault(TeardownStage::kErase)) {
                throw std::system_error(
                    std::make_error_code(std::errc::resource_deadlock_would_occur),
                    "injected teardown erase failure");
            }
            std::lock_guard<std::mutex> lk(bridge_mu_);
            auto it = records_.find(rec->key);
            if (it != records_.end() && it->second == rec) {
                records_.erase(it);
            }
            active = records_.size();
        })) {
        // The gauge would be a lie, but the row must NOT be skipped: an erase
        // failure previously produced no audit evidence at all, which is the same
        // "no row" gap this work closes for the sibling step.
        count_teardown_incomplete(TeardownStage::kErase);
        log_incomplete(stage_name(TeardownStage::kErase));
        // Must consult charge_released: the two stages fail independently on the same
        // fault class, so a compound failure previously produced a row asserting a
        // settled charge while the metric said otherwise - understating the blast
        // radius to whoever reads the row during an incident.
        // Takes the disposition like every other bail site. This one used to branch on
        // charge_released ALONE and say nothing about the terminal, so a teardown that
        // poisoned the session and then failed to erase left the poisoning entirely
        // unevidenced - the same defect as the other two sites, found only after both
        // of those had been fixed individually.
        audit_contained(audit_action, exec_id,
                        charge_released
                            ? "teardown incomplete: record erase failed; the subscription and "
                              "the streamed charge were settled, the record is retained for "
                              "shutdown"
                            : "teardown incomplete: record erase failed AND the streamed charge "
                              "was not released; the record and one per-session admission slot "
                              "are both retained for shutdown",
                        disposition, AuditResult::kFailure);
        return;
    }
    publish_records_gauge(active);

    // ── Step 5: audit the real outcome ─────────────────────────────────────────
    // The terminal's fate comes from disposition_phrase, the SAME source the bail
    // sites use - this block used to hand-roll its own per-rung wording, which is
    // how two of its literals were left asserting "the stream was NOT poisoned"
    // after that claim had been corrected one function over. One source, no drift.
    //
    // kNone contributes no disposition at all, so a clean pin-ack / session-death
    // reap still emits a byte-identical empty-detail row.
    const char* stage_detail = "";
    if (!charge_released) {
        // The stage half: a leaked admission slot outlives the request and is the
        // operator-actionable part. It no longer REPLACES the disposition - both are
        // passed and joined, so a teardown that leaked a slot AND poisoned reports
        // both halves.
        stage_detail = "teardown incomplete: streamed charge not released; the record was "
                       "erased but one per-session admission slot is held until shutdown";
    }
    // The disposition is dropped ONLY on a wholly clean kNone reap, so that the most
    // common row stays byte-identical to before this work. Any FAILURE row keeps it -
    // dropping it there would be the same silence this round exists to remove, and a
    // kNone teardown that leaked a slot still needs to say it published nothing.
    const bool clean_kNone = decision == TeardownFinal::kNone && charge_released;
    audit_contained(audit_action, exec_id, stage_detail,
                    clean_kNone ? std::string_view{} : std::string_view{disposition},
                    charge_released && terminal_delivered ? AuditResult::kSuccess
                                                          : AuditResult::kFailure);
}

void McpStreamBridge::release_charge(const std::shared_ptr<BridgeRecord>& rec) {
    if (charge_lock_fault_.load(std::memory_order_relaxed) > 0 &&
        charge_lock_fault_.fetch_sub(1, std::memory_order_acq_rel) > 0) {
        // inject_charge_lock_fault_for_test - the modelled mutex failure, thrown
        // BEFORE either lock so it models the acquisition itself failing. It sits
        // here, in the shared primitive, rather than at a call site: this is the
        // one place that owns the both-or-neither property both callers depend on.
        throw std::system_error(std::make_error_code(std::errc::resource_deadlock_would_occur),
                                "injected release_charge lock failure");
    }
    // BOTH halves under BOTH locks, in hierarchy order. The split version cleared
    // the flag under rec->mu and only THEN took bridge_mu_ - and that acquisition is
    // the sole throw site, so a failure left the record reading "not held" while
    // streamed_unpinned_[session] still counted it. That entry could then never
    // reach 0, so decrement_streamed_locked's erase never ran and the
    // no-historical-session-accumulation invariant was permanently broken for that
    // session - a far larger blast radius than the one admission slot it looks like.
    // Locking first means a throw happens before any mutation: both commit, or
    // neither does.
    std::lock_guard<std::mutex> lk(bridge_mu_);
    std::lock_guard<std::mutex> rlk(rec->mu);
    if (rec->streamed_charge_held) {
        rec->streamed_charge_held = false;
        decrement_streamed_locked(rec->session_id);
    }
}

void McpStreamBridge::decrement_streamed_locked(const std::string& session_id) {
    auto it = streamed_unpinned_.find(session_id);
    if (it == streamed_unpinned_.end()) {
        return;  // defensive - exactly-once release should make this unreachable
    }
    if (it->second > 0) {
        --it->second;
    }
    if (it->second == 0) {
        streamed_unpinned_.erase(it);  // C3: no historical-session accumulation
    }
}

// ── Observability (C5: contained, never under bridge_mu_/listener) ────────

template <typename F> bool McpStreamBridge::obs_guard(F&& f) noexcept {
    if (obs_fault_remaining_.load(std::memory_order_relaxed) > 0 &&
        obs_fault_remaining_.fetch_sub(1, std::memory_order_relaxed) > 0) {
        return false;  // injected observability failure (C5 fault seam)
    }
    try {
        f();
        return true;
    } catch (...) {
        return false;
    }
}

void McpStreamBridge::count_reject(const char* reason) noexcept {
    if (metrics_ != nullptr) {
        obs_guard([&] { metrics_->counter(kMetricRejects, {{"reason", reason}}).increment(); });
    }
}

void McpStreamBridge::count_charge_release_deferred() noexcept {
    if (metrics_ != nullptr) {
        obs_guard([&] { metrics_->counter(kMetricChargeReleaseDeferred).increment(); });
    }
}

void McpStreamBridge::count_teardown_incomplete(TeardownStage stage) noexcept {
    if (metrics_ != nullptr) {
        obs_guard([&] {
            metrics_->counter(kMetricTeardownIncomplete, {{"reason", stage_name(stage)}})
                .increment();
        });
    }
}

bool McpStreamBridge::take_step_fault(TeardownStage stage) noexcept {
    const auto idx = static_cast<std::size_t>(stage);
    if (idx >= kTeardownStageCount) {
        return false;
    }
    auto& slot = teardown_step_fault_[idx];
    return slot.load(std::memory_order_relaxed) > 0 &&
           slot.fetch_sub(1, std::memory_order_acq_rel) > 0;
}

void McpStreamBridge::publish_records_gauge(std::size_t n) noexcept {
    if (metrics_ != nullptr) {
        obs_guard([&] { metrics_->gauge(kMetricRecordsActive).set(static_cast<double>(n)); });
    }
}

void McpStreamBridge::publish_pin_cap_gauge() noexcept {
    // Counts sessions with NO streamed admission left. A session that legitimately
    // has four calls in flight is indistinguishable, from a bare reject counter,
    // from one wedged forever - and when it is wedged the 429 remediation ("wait
    // for one to finish") is a lie. This is the number support needs.
    //
    // Called from the sweep rather than the admission path: it is a periodic health
    // reading, not a hot-path counter, and computing it needs bridge_mu_.
    if (metrics_ == nullptr) {
        return;
    }
    std::size_t at_cap = 0;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        for (const auto& [session, unpinned] : streamed_unpinned_) {
            (void)session;
            if (unpinned >= kMaxStreamedPostsPerSession) {
                ++at_cap;
            }
        }
    }
    obs_guard([&] { metrics_->gauge(kMetricSessionsAtPinCap).set(static_cast<double>(at_cap)); });
}

void McpStreamBridge::flush_record_obs(BridgeRecord& rec) noexcept {
    // D3: exchange-then-restore. A transiently failing registry never loses the
    // accumulated delta - it is put back (or parked on the shared core) for a
    // later flush; only final process shutdown may drop it.
    const auto drops = rec.mailbox_drop_delta.exchange(0, std::memory_order_relaxed);
    if (drops != 0) {
        if (metrics_ == nullptr ||
            !obs_guard([&] {
                metrics_->counter(kMetricMailboxDrops).increment(static_cast<double>(drops));
            })) {
            core_->pending_mailbox_drops.fetch_add(drops, std::memory_order_relaxed);
        }
    }
    const auto fails = rec.listener_failure_delta.exchange(0, std::memory_order_relaxed);
    if (fails != 0) {
        if (metrics_ == nullptr ||
            !obs_guard([&] {
                metrics_->counter(kMetricListenerFailures).increment(static_cast<double>(fails));
            })) {
            core_->pending_listener_failures.fetch_add(fails, std::memory_order_relaxed);
        }
    }
    const auto degraded = rec.projection_degraded_delta.exchange(0, std::memory_order_relaxed);
    if (degraded != 0) {
        if (metrics_ == nullptr ||
            !obs_guard([&] {
                metrics_->counter(kMetricProjectionDegraded)
                    .increment(static_cast<double>(degraded));
            })) {
            core_->pending_projection_degraded.fetch_add(degraded, std::memory_order_relaxed);
        }
    }
}

void McpStreamBridge::flush_core_obs() noexcept {
    if (metrics_ == nullptr) {
        return;  // keep pending - a registry may never appear, but losing the
                 // count is worse than holding an int
    }
    const auto drops = core_->pending_mailbox_drops.exchange(0, std::memory_order_relaxed);
    if (drops != 0 &&
        !obs_guard([&] {
            metrics_->counter(kMetricMailboxDrops).increment(static_cast<double>(drops));
        })) {
        core_->pending_mailbox_drops.fetch_add(drops, std::memory_order_relaxed);
    }
    const auto fails = core_->pending_listener_failures.exchange(0, std::memory_order_relaxed);
    if (fails != 0 &&
        !obs_guard([&] {
            metrics_->counter(kMetricListenerFailures).increment(static_cast<double>(fails));
        })) {
        core_->pending_listener_failures.fetch_add(fails, std::memory_order_relaxed);
    }
    const auto degraded = core_->pending_projection_degraded.exchange(0, std::memory_order_relaxed);
    if (degraded != 0 &&
        !obs_guard([&] {
            metrics_->counter(kMetricProjectionDegraded).increment(static_cast<double>(degraded));
        })) {
        core_->pending_projection_degraded.fetch_add(degraded, std::memory_order_relaxed);
    }
}

const char* McpStreamBridge::disposition_phrase(TeardownFinal decision,
                                               TerminalRung rung) noexcept {
    // ONE source for every teardown bail site. The recurring defect on this function
    // was a bail site that described the mechanical failure and stayed silent about
    // the terminal - most consequentially about a POISONED session, which is
    // session-wide (every later attach 410s). Three separate rounds fixed one site
    // and left another; deriving it once removes the opportunity.
    if (decision == TeardownFinal::kNone) {
        return "this teardown published nothing (any earlier final is unaffected)";
    }
    switch (rung) {
        case TerminalRung::kPrimary:
            return decision == TeardownFinal::kSynthesizeUnavailable
                       ? "the terminal-unavailable frame was published"
                       : "the fallback final was published";
        case TerminalRung::kFallback:
            return "the intended terminal failed and the prebuilt fallback final was "
                   "published instead";
        case TerminalRung::kPoisoned:
            return "the terminal publish POISONED the session - every later attach 410s and "
                   "the client must re-initialize; recover the result by execution_id";
        case TerminalRung::kPublishThrew:
            // Deliberately does NOT claim the stream escaped poisoning. publish_final
            // is noexcept, so the only way the ladder throws is poison_terminal() (#2531),
            // which sets its sticky flag under mu_ and THEN calls close_sink outside
            // it - so a throw here means the session very likely IS poisoned, with the
            // flag already set. The previous wording asserted the opposite. This arm
            // is reachable but has no fault seam (nothing can make close_sink throw
            // from a test), so it is stated conservatively rather than pinned.
            return "the terminal was built but publishing threw; nothing was confirmed "
                   "published and the session's poison state is indeterminate (a throw at this "
                   "point almost certainly means it WAS poisoned - see #2531; the wording stays "
                   "conservative only because nothing can pin it) - recover by execution_id";
        case TerminalRung::kNotAttempted:
            break;
    }
    return "the terminal frame could not be built; nothing was published and THIS teardown did "
           "not poison the session - recover the result by execution_id";
}

void McpStreamBridge::audit_contained(const char* action, const std::string& execution_id,
                                      std::string_view stage, std::string_view disposition,
                                      AuditResult result, std::string_view actor) noexcept {
    if (audit_) {
        // Every owned string the AuditFn signature needs - action from a const char*,
        // and the joined detail from the two views - is constructed HERE, inside the
        // guard, so the join cannot allocate on an uncontained path (#2487).
        obs_guard([&] {
            std::string detail(stage);
            if (!detail.empty() && !disposition.empty()) {
                detail += "; ";
            }
            detail.append(disposition);
            audit_(action, execution_id, std::move(detail), result, std::string(actor));
        });
    }
}

// ── Accessors / test seams ─────────────────────────────────────────────────

std::size_t McpStreamBridge::record_count() const {
    std::lock_guard<std::mutex> lk(bridge_mu_);
    return records_.size();
}

std::optional<bool> McpStreamBridge::post_sink_closed_for_test(
    const std::string& session_id, const nlohmann::json& jsonrpc_id) const {
    std::shared_ptr<BridgeRecord> rec;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        auto it = records_.find(make_key(session_id, jsonrpc_id));
        if (it == records_.end()) {
            return std::nullopt;
        }
        rec = it->second;
    }
    std::lock_guard<std::mutex> rlk(rec->mu);
    if (!rec->post_sink) {
        return std::nullopt;
    }
    return rec->post_sink->closed.load(std::memory_order_acquire);
}

std::size_t McpStreamBridge::ring_only_count() const {
    std::lock_guard<std::mutex> lk(bridge_mu_);
    std::size_t n = 0;
    for (const auto& [key, rec] : records_) {
        if (rec->phase.load(std::memory_order_acquire) == Phase::kRingOnly) {
            ++n;
        }
    }
    return n;
}

std::optional<McpStreamBridge::Phase>
McpStreamBridge::phase_for(const std::string& session_id, const nlohmann::json& jsonrpc_id) const {
    std::lock_guard<std::mutex> lk(bridge_mu_);
    auto rec = find_locked(make_key(session_id, jsonrpc_id));
    if (!rec) {
        return std::nullopt;
    }
    return rec->phase.load(std::memory_order_acquire);
}

void McpStreamBridge::inject_listener_fault_for_test() {
    core_->listener_fault.store(true, std::memory_order_release);
}

void McpStreamBridge::inject_observability_fault_for_test(int times) {
    obs_fault_remaining_.store(times, std::memory_order_relaxed);
}

void McpStreamBridge::inject_arm_fault_for_test() {
    arm_fault_.store(true, std::memory_order_release);
}

void McpStreamBridge::inject_reserve_fault_for_test() {
    reserve_fault_.store(true, std::memory_order_release);
}

void McpStreamBridge::inject_subscribe_fault_for_test() {
    subscribe_fault_.store(true, std::memory_order_release);
}

void McpStreamBridge::inject_visit_copy_fault_for_test(int times) {
    visit_copy_fault_.store(times, std::memory_order_release);
}

void McpStreamBridge::inject_reserve_commit_fault_for_test() {
    reserve_commit_fault_.store(true, std::memory_order_release);
}

void McpStreamBridge::inject_claim_lock_fault_for_test(int times) {
    claim_lock_fault_.store(times, std::memory_order_release);
}

void McpStreamBridge::inject_projection_build_fault_for_test(int times) {
    projection_build_fault_.store(times, std::memory_order_release);
}

void McpStreamBridge::inject_projection_fallback_fault_for_test(int times) {
    projection_fallback_fault_.store(times, std::memory_order_release);
}

void McpStreamBridge::inject_teardown_step_fault_for_test(TeardownStage stage, int times) {
    const auto idx = static_cast<std::size_t>(stage);
    if (idx >= kTeardownStageCount) {
        return;  // public method: an out-of-range cast must not become an OOB write
    }
    teardown_step_fault_[idx].store(times, std::memory_order_release);
}

void McpStreamBridge::inject_terminal_build_fault_for_test(int times) {
    terminal_build_fault_.store(times, std::memory_order_release);
}

void McpStreamBridge::inject_charge_lock_fault_for_test(int times) {
    charge_lock_fault_.store(times, std::memory_order_release);
}

void McpStreamBridge::set_clock_for_test(ClockFn clock) { clock_ = std::move(clock); }

}  // namespace yuzu::server::mcp
