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
// #2487: a teardown_claimed step that could not complete on the bare maintenance
// thread. `stage` is a CLOSED literal set (unsubscribe | release_charge | erase),
// pre-seeded in server.cpp. Any nonzero value means a record, its streamed charge,
// or its bus subscription outlived its teardown and now waits for shutdown() -
// alert on > 0.
constexpr const char* kMetricTeardownIncomplete = "yuzu_mcp_bridge_teardown_incomplete_total";
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
            if (streamed_intent) {
                rec->streamed_charge_held = true;
                ++streamed_unpinned_[session_id];
            }
            records_.emplace(rec->key, rec);
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
        if (rec->subscribed || rec->torn_down ||
            rec->phase.load(std::memory_order_acquire) != Phase::kArming) {
            return false;
        }
        rec->execution_id = execution_id;
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
    // work happens while nothing has changed.
    std::string exec_id;
    {
        std::lock_guard<std::mutex> rlk(rec->mu);
        exec_id = rec->execution_id;
    }
    std::string fallback = success_response(
        jsonrpc_id, std::string(R"({"execution_id":)") + detail::json_quoted(exec_id) +
                        R"(,"status":"unknown","detail":)" +
                        detail::json_quoted("terminal counts unavailable - fetch by execution_id "
                                            "(get_execution_status / query_responses)") +
                        "}");

    bool consumed_cancel = false;
    bool release_streamed_charge = false;
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
        const bool degrade = consumed_cancel && mode == ArmMode::kStreaming;
        const Phase target =
            (mode == ArmMode::kStreaming && !degrade) ? Phase::kStreaming : Phase::kArmedGetOnly;
        rec->phase.store(target, std::memory_order_release);
        if (degrade && rec->streamed_charge_held) {
            // C1: the degraded record follows the GET-only lifecycle and can
            // never pin - its admission charge is released here, exactly once.
            rec->streamed_charge_held = false;
            release_streamed_charge = true;
        }
        outcome = degrade ? ArmOutcome::kDegradedGetOnly : ArmOutcome::kArmed;
        wake(*core_);  // the handoff - same hold
    }
    if (release_streamed_charge) {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        decrement_streamed_locked(session_id);
    }
    if (consumed_cancel) {
        // C1: audit only AFTER winning the arbitration, outside every lock.
        audit_contained("mcp.bridge.cancel", exec_id,
                        outcome == ArmOutcome::kDegradedGetOnly
                            ? "consumed_by_arm: streamed intent degraded to get-only"
                            : "consumed_by_arm: get-only request, nothing to detach");
    }
    return outcome;
}

McpStreamBridge::CancelOutcome McpStreamBridge::request_cancel(const std::string& session_id,
                                                               const nlohmann::json& jsonrpc_id) {
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
    std::lock_guard<std::mutex> rlk(rec->mu);
    if (rec->phase.load(std::memory_order_acquire) != Phase::kArming || rec->cancel_pending) {
        return CancelOutcome::kNoOp;
    }
    // Intent ONLY - no audit, no transition (C1): a later pre-dispatch failure
    // (abandon) invalidates the cancel/degrade outcome, so the win is arm()'s.
    rec->cancel_pending = true;
    return CancelOutcome::kAcceptedPending;
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

bool McpStreamBridge::on_post_closed(const std::string& session_id,
                                     const nlohmann::json& jsonrpc_id) {
    std::shared_ptr<BridgeRecord> rec;
    std::uint64_t parked_seq = 0;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
            return false;
        }
        rec = find_locked(make_key(session_id, jsonrpc_id));
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
        Phase expected = Phase::kStreaming;
        if (!rec->phase.compare_exchange_strong(expected, Phase::kRingOnly,
                                                std::memory_order_acq_rel)) {
            return false;
        }
        rec->parked_seq = parked_seq;
    }
    // A1: a terminal latched while the (3b) pump was dying must not wait for
    // the next bus event or sweep - hand the record to the projector now.
    wake(*core_);
    return true;
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

void McpStreamBridge::project_record(const std::shared_ptr<BridgeRecord>& rec) {
    Phase ph;
    std::array<MailboxEntry, kBridgeMailboxCap> batch{};
    std::size_t batch_n = 0;
    std::optional<MailboxEntry> term;
    {
        std::lock_guard<std::mutex> rlk(rec->mu);
        ph = rec->phase.load(std::memory_order_acquire);
        if (ph != Phase::kArmedGetOnly && ph != Phase::kRingOnly) {
            return;  // kArming latches; kStreaming is pump-owned (3b); kDone/kAborted dead
        }
        if (rec->projection_in_flight) {
            return;  // single projector today, but the claim also fences sweep (B2)
        }
        // E1: while a pressure sweep is waiting on this record, no NEW progress
        // batch may start - only an already-latched terminal settles.
        const bool want_progress = rec->mb_count > 0 && !rec->pressure_requested;
        const bool want_terminal =
            rec->terminal_accepted && !rec->terminal_projected && rec->terminal_slot.has_value();
        if (!want_progress && !want_terminal) {
            return;
        }
        rec->projection_in_flight = true;  // the claim - everything below is noexcept
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
        bool terminal_settled = false;
        ~ClaimGuard() {
            std::lock_guard<std::mutex> rlk(rec->mu);
            if (term.has_value() && !terminal_settled) {
                rec->terminal_slot = std::move(term);
            }
            rec->projection_in_flight = false;
        }
    } guard{rec, term};

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
        rec->terminal_projected = true;
        Phase expected = Phase::kArmedGetOnly;
        rec->phase.compare_exchange_strong(expected, Phase::kDone, std::memory_order_acq_rel);
        return;  // sweep reaps kDone
    }

    // kRingOnly: real final via the pinned ladder.
    std::string frame;
    bool built = false;
    try {
        frame = build_real_final(*rec, term->data);
        built = true;
    } catch (...) {
        try {
            frame = rec->fallback_final;  // prebuilt at arm; copy can only OOM
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
    const auto fid = publish_terminal_ladder(rec, std::move(frame)).id;
    // Settle IMMEDIATELY after the commit/poison decision (C4): no later
    // bookkeeping failure may restore + republish.
    guard.terminal_settled = true;
    bool release = false;
    {
        std::lock_guard<std::mutex> rlk(rec->mu);
        rec->terminal_projected = true;
        if (fid != 0) {
            rec->final_published = true;
            rec->pinned_event_id = fid;
        }
        if (rec->streamed_charge_held) {
            // C3: settled - either the final is pinned (admission now counts it
            // via pinned_count()) or it settled pinless/poisoned (no pin will
            // ever come). Exactly-once: cleared here, decremented below.
            rec->streamed_charge_held = false;
            release = true;
        }
    }
    if (release) {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        decrement_streamed_locked(rec->session_id);
    }
    // D4: the guard clears projection_in_flight only now, AFTER the deferred
    // charge decrement - sweep can never observe a half-settled record.
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
                                         std::string frame) {
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
                    !rec->projection_in_flight &&
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
            if (rec->projection_in_flight || rec->torn_down) {
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
                if (oldest->terminal_accepted && oldest->terminal_projected) {
                    // Settled real final already pinned: claim, publish nothing.
                    oldest->phase.store(Phase::kDone, std::memory_order_release);
                    oldest->torn_down = true;
                    claimed_by_me = true;
                    decision = TeardownFinal::kNone;
                    return true;
                }
                if (oldest->terminal_accepted && !oldest->terminal_projected) {
                    return false;  // latched, not pinned: defer; projector settles
                }
                if (oldest->projection_in_flight) {
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
                if (!oldest->torn_down &&
                    oldest->phase.load(std::memory_order_acquire) == Phase::kRingOnly &&
                    oldest->terminal_accepted && oldest->terminal_projected) {
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

void McpStreamBridge::teardown_claimed(const std::shared_ptr<BridgeRecord>& rec,
                                       TeardownFinal decision, const char* audit_action) {
    // Claimant owns the record: the phase (kDone / kAborted) AND `torn_down` were
    // both stored under record mu before we got here. `torn_down` PERMANENTLY
    // excludes this record from every later sweep claim (the guard at the top of
    // pass 0-2), so THERE IS NO RETRIER - whatever this function leaves unfinished
    // stays unfinished until shutdown() walks records_.
    //
    // #2487: this runs on the bare maintenance thread (the server.cpp health loop),
    // where an escaped exception is std::terminate. Ownership here is THREE things,
    // not two: the records_ entry, the streamed charge, and the BUS SUBSCRIPTION.
    // Erasing the map entry while the subscription survives is the worst available
    // outcome - make_listener captures a shared_ptr to this record, so erasing
    // destroys nothing; the listener stays installed and keeps waking a record
    // nothing can find, shutdown() can no longer reach it (it walks records_), and
    // channel GC refuses to reap the channel because it requires listeners.empty().
    // Hence: unsubscribe FIRST, and on failure leave the record wholly intact for
    // shutdown() rather than erase around a live listener.
    //
    // `execution_id` is immutable after subscribe() (see the BridgeRecord field
    // notes) and `rec` keeps it alive for this whole call, so BIND it - never copy.
    // The copy this replaced was an uncontained allocation on this thread (#2487);
    // the lock-free read is the documented "safe after observing a post-write phase
    // via the record mutex" case, and matches the unsubscribe sites in shutdown(),
    // abandon() and the pressure pass, which already read it unlocked.
    const std::string& exec_id = rec->execution_id;

    // Contained step runner: nothing below may propagate. Declaring the wrapper
    // noexcept is safe (and NOT the "noexcept defeats an outer catch" trap) because
    // the catch that contains the work lives INSIDE it.
    const auto contained = [](auto&& f) noexcept -> bool {
        try {
            f();
            return true;
        } catch (...) {
            return false;
        }
    };

    const bool unsubscribed = contained([&] {
        if (teardown_unsub_fault_.load(std::memory_order_acquire) > 0 &&
            teardown_unsub_fault_.fetch_sub(1, std::memory_order_acq_rel) > 0) {
            // system_error, not bad_alloc: a mutex failure is the only thing this
            // step actually admits, and the seam should model the real fault.
            throw std::system_error(std::make_error_code(std::errc::resource_deadlock_would_occur),
                                    "injected teardown unsubscribe failure");
        }
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (rec->subscribed && bus_ != nullptr) {
            bus_->unsubscribe(exec_id, rec->sub_id);
        }
        rec->subscribed = false;
    });
    if (!unsubscribed) {
        // Only a mutex failure reaches here - unsubscribe allocates nothing given a
        // const& key. Bail with the record still in records_, still subscribed and
        // still charged: internally consistent, reclaimed by shutdown(), and never
        // an orphan listener. Deliberately does NOT clear torn_down to re-open the
        // claim - re-entering the exactly-once teardown protocol is a design change,
        // filed separately rather than smuggled into a containment fix.
        count_teardown_incomplete("unsubscribe");
        audit_contained(audit_action, exec_id,
                        "teardown incomplete: bus unsubscribe failed, record retained "
                        "for shutdown",
                        "failure");
        return;
    }
    // #2506 F4: initialised BEFORE the switch, because frame construction can throw
    // before the ladder is ever reached. The default is kNotAttempted, NOT
    // kPoisoned: the catch below increments a counter and does not call
    // poison_terminal(), so defaulting to kPoisoned would make the audit assert a
    // session poisoning that never happened - the same class of false-outcome claim
    // this finding is about (#2487 review).
    TerminalRung rung = TerminalRung::kNotAttempted;
    switch (decision) {
        case TeardownFinal::kSynthesizeUnavailable:
            // Pressure victim that genuinely NEVER saw a terminal (verified at
            // claim under Channel::mu): pin a machine-readable terminal-unavailable
            // so a later resume still finds truth in the ring. A4 grammar:
            // error.data carries the durable handle.
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
                rung = publish_terminal_ladder(rec, std::move(frame)).rung;  // 0 twice ⇒ poison
            } catch (...) {
                // Build-side OOM: nothing published. The record is gone either way;
                // the durable execution fetch remains, and the failure is counted.
                if (metrics_ != nullptr) {
                    obs_guard([&] { metrics_->counter(kMetricTerminalPublishFailures).increment(); });
                }
            }
            break;
        case TeardownFinal::kFallbackFinal:
            // Terminal existed but its payload aged out of the bus buffer
            // (kTerminalKnownLost): publish the prebuilt success-shaped final
            // ("fetch by execution_id"), NEVER -32014. Contain the by-value copy of
            // fallback_final (may OOM).
            try {
                if (terminal_build_fault_.load(std::memory_order_acquire) > 0 &&
                    terminal_build_fault_.fetch_sub(1, std::memory_order_acq_rel) > 0) {
                    throw std::bad_alloc{};  // models the by-value fallback_final copy failing
                }
                rung = publish_terminal_ladder(rec, rec->fallback_final).rung;  // 0 twice ⇒ poison
            } catch (...) {
                if (metrics_ != nullptr) {
                    obs_guard([&] { metrics_->counter(kMetricTerminalPublishFailures).increment(); });
                }
            }
            break;
        case TeardownFinal::kNone:
            break;  // real final already pinned, or nothing to publish
    }
    // Past the unsubscribe the subscription is gone, so the remaining two owned
    // things MUST both be settled - and independently: a failure to release the
    // charge must not also strand the map entry, and vice versa (#2487). Each step
    // is contained on its own; a failure is counted, never propagated.
    if (!contained([&] { release_charge(rec); })) {
        count_teardown_incomplete("release_charge");
    }
    flush_record_obs(*rec);  // already noexcept
    std::size_t active = 0;
    if (!contained([&] {
            std::lock_guard<std::mutex> lk(bridge_mu_);
            auto it = records_.find(rec->key);
            if (it != records_.end() && it->second == rec) {
                records_.erase(it);
            }
            active = records_.size();
        })) {
        count_teardown_incomplete("erase");
        return;  // gauge would be a lie and the audit would claim a teardown that
                 // did not complete; the record is still reachable by shutdown().
    }
    publish_records_gauge(active);
    // kNone detail stays empty: teardown_claimed(kNone) is shared with pass-2
    // (session-death / pin-ack reaps) whose records need not hold a real final, so a
    // "real final pinned" string would be inaccurate there (sec-INFO1 declined).
    //
    // #2506 F4: the detail names WHAT ACTUALLY REACHED THE RING, not what this
    // branch intended to publish. The ladder can fall through to the record's
    // prebuilt fallback, or poison the session and publish nothing at all; an audit
    // row asserting "synthesized" or "published" in those cases is evidence of a
    // delivery that never happened. The committed id alone cannot distinguish them -
    // a nonzero id from the retry is indistinguishable from one from the primary
    // frame - which is why the ladder reports its rung.
    const char* audit_detail = "";
    bool delivered = true;
    if (decision == TeardownFinal::kSynthesizeUnavailable) {
        switch (rung) {
            case TerminalRung::kPrimary:
                audit_detail = "terminal-unavailable synthesized (pressure)";
                break;
            case TerminalRung::kFallback:
                audit_detail = "terminal-unavailable synthesis failed; fallback final "
                               "published instead (pressure)";
                break;
            case TerminalRung::kPoisoned:
                audit_detail = "terminal-unavailable synthesis failed; session poisoned, "
                               "nothing published (pressure)";
                delivered = false;
                break;
            case TerminalRung::kNotAttempted:
                audit_detail = "terminal-unavailable frame could not be built; nothing "
                               "published and the stream was NOT poisoned - recover by "
                               "execution_id (pressure)";
                delivered = false;
                break;
        }
    } else if (decision == TeardownFinal::kFallbackFinal) {
        switch (rung) {
            case TerminalRung::kPrimary:
            case TerminalRung::kFallback:
                audit_detail = "fallback final published (terminal payload lost)";
                break;
            case TerminalRung::kPoisoned:
                audit_detail = "fallback final failed; session poisoned, nothing published "
                               "(terminal payload lost)";
                delivered = false;
                break;
            case TerminalRung::kNotAttempted:
                audit_detail = "fallback final could not be copied; nothing published and "
                               "the stream was NOT poisoned - recover by execution_id "
                               "(terminal payload lost)";
                delivered = false;
                break;
        }
    }
    audit_contained(audit_action, exec_id, audit_detail, delivered ? "success" : "failure");
}

void McpStreamBridge::release_charge(const std::shared_ptr<BridgeRecord>& rec) {
    bool release = false;
    {
        std::lock_guard<std::mutex> rlk(rec->mu);
        if (rec->streamed_charge_held) {
            rec->streamed_charge_held = false;
            release = true;
        }
    }
    if (release) {
        std::lock_guard<std::mutex> lk(bridge_mu_);
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

void McpStreamBridge::count_teardown_incomplete(const char* stage) noexcept {
    if (metrics_ != nullptr) {
        obs_guard(
            [&] { metrics_->counter(kMetricTeardownIncomplete, {{"stage", stage}}).increment(); });
    }
}

void McpStreamBridge::publish_records_gauge(std::size_t n) noexcept {
    if (metrics_ != nullptr) {
        obs_guard([&] { metrics_->gauge(kMetricRecordsActive).set(static_cast<double>(n)); });
    }
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
}

void McpStreamBridge::audit_contained(const char* action, const std::string& execution_id,
                                      std::string_view detail, const char* result) noexcept {
    if (audit_) {
        // Both owned strings the AuditFn signature needs (action from a const char*,
        // detail from the view) are constructed HERE, inside the guard - #2487.
        obs_guard([&] { audit_(action, execution_id, std::string(detail), result); });
    }
}

// ── Accessors / test seams ─────────────────────────────────────────────────

std::size_t McpStreamBridge::record_count() const {
    std::lock_guard<std::mutex> lk(bridge_mu_);
    return records_.size();
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

void McpStreamBridge::inject_teardown_unsubscribe_fault_for_test(int times) {
    teardown_unsub_fault_.store(times, std::memory_order_release);
}

void McpStreamBridge::inject_terminal_build_fault_for_test(int times) {
    terminal_build_fault_.store(times, std::memory_order_release);
}

void McpStreamBridge::set_clock_for_test(ClockFn clock) { clock_ = std::move(clock); }

}  // namespace yuzu::server::mcp
