#include "mcp_stream_bridge.hpp"

#include "mcp_jsonrpc.hpp"
#include "mcp_session.hpp"
#include "mcp_stream.hpp"
#include "rest_a4_envelope.hpp"

#include <yuzu/metrics.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <new>
#include <utility>
#include <vector>

namespace yuzu::server::mcp {

namespace {
constexpr const char* kMetricRecordsActive = "yuzu_mcp_bridge_records_active";
constexpr const char* kMetricRejects = "yuzu_mcp_bridge_reject_total";
constexpr const char* kMetricListenerFailures = "yuzu_mcp_bridge_listener_failures_total";
constexpr const char* kMetricMailboxDrops = "yuzu_mcp_bridge_mailbox_drops_total";
// Shared with mcp_stream's poison path by NAME (one operator-facing series for
// "a terminal could not be delivered", whichever layer detected it).
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
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (shutdown_started_) {
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
    // Allocate outside bridge_mu_ (the mint precedent - construction is cheap
    // to discard on a reject and must not serialize against the map).
    auto rec = std::make_shared<BridgeRecord>();
    rec->session_id = session_id;
    rec->principal = principal;
    rec->jsonrpc_id = jsonrpc_id;
    rec->key = make_key(session_id, jsonrpc_id);
    rec->streamed_intent = streamed_intent;
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
    {
        // Written before any listener exists; immutable afterwards.
        std::lock_guard<std::mutex> rlk(rec->mu);
        rec->execution_id = execution_id;
    }
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
    ArmOutcome outcome;
    {
        // The ONE record-mutex hold (H2): noexcept moves, arbitration, flip,
        // handoff wake. A concurrent listener append lands pre-flip (drained by
        // this wake) or post-flip (drained by its own unconditional wake).
        std::lock_guard<std::mutex> rlk(rec->mu);
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
            std::string frame;
            try {
                const auto counts = parse_progress(batch[i].data);
                const std::string msg = std::to_string(counts.responded) + "/" +
                                        std::to_string(counts.targeted) + " agents responded";
                frame = progress_notification(*rec->progress_token, counts.responded,
                                              counts.targeted, msg, rec->execution_id);
            } catch (...) {
                // C4: drop this batch's remainder, keep going to terminal
                // settlement. A malformed/unbuildable progress delta is
                // fire-and-forget by contract.
                spdlog::warn("MCP bridge: progress frame build failed; dropping batch remainder");
                break;
            }
            if (get_only) {
                rec->stream->publish("message", frame);  // live GET + ring (single stream)
            } else {
                rec->stream->publish_ring_only("message", frame);  // resume replay only
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
    const auto fid = publish_terminal_ladder(rec, std::move(frame));
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

std::uint64_t McpStreamBridge::publish_terminal_ladder(const std::shared_ptr<BridgeRecord>& rec,
                                                       std::string frame) {
    auto fid = rec->stream->publish_final("message", frame);
    if (fid != 0) {
        return fid;
    }
    if (metrics_ != nullptr) {
        obs_guard([&] { metrics_->counter(kMetricTerminalPublishFailures).increment(); });
    }
    // Retry once with the prebuilt per-record fallback (immutable member - the
    // string_view stays alive across the call).
    fid = rec->stream->publish_final("message", rec->fallback_final);
    if (fid != 0) {
        return fid;
    }
    if (metrics_ != nullptr) {
        obs_guard([&] { metrics_->counter(kMetricTerminalPublishFailures).increment(); });
    }
    // Double failure: sticky session poison - every future attach 410s and the
    // durable execution_id fetch is the recovery path (Decision 15(f) wiring of
    // the mcp_stream caller obligation).
    rec->stream->poison_terminal();
    return 0;
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
                // between is still reapable); anything else waits for the next
                // sweep with fresh evidence.
                continue;
            }
            rec->phase.store(Phase::kDone, std::memory_order_release);
            rec->torn_down = true;
            claimed = true;
        }
        if (claimed) {
            teardown_claimed(rec, /*synthesize_unavailable=*/false, action);
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
        // Stage 1: freeze new progress work on the victim; decide deferral.
        bool synthesize = false;
        {
            std::lock_guard<std::mutex> rlk(oldest->mu);
            oldest->pressure_requested = true;
            if (oldest->projection_in_flight && !oldest->terminal_accepted) {
                // E1: a progress-only projection is mid-flight. Defer WITHOUT
                // unsubscribing - the live subscription retains a terminal that
                // arrives before the next sweep. Never evict a newer record.
                return;
            }
            if (oldest->terminal_accepted && !oldest->terminal_projected) {
                // A real terminal is secured but not yet on the ring. Let the
                // projector settle it; the NEXT sweep can then claim this same
                // (still oldest) record. Never synthesize over a real result,
                // never evict a newer record instead.
                wake(*core_);
                return;
            }
            // SETTLED (terminal_projected - the real final is pinned in the ring,
            // or the stream is poisoned) or terminal-less: claimable. Spec E3:
            // a torn-down real-final victim keeps its pin (truth stays in the
            // ring); synthesis is only for a victim that never saw a terminal.
            synthesize = !oldest->terminal_accepted;
        }
        // Stage 2: quiesce - after unsubscribe returns, no listener can be
        // in flight for this record and none will ever run again.
        {
            std::lock_guard<std::mutex> lk(bridge_mu_);
            if (shutdown_started_) {
                return;
            }
            auto it = records_.find(oldest->key);
            if (it == records_.end() || it->second != oldest) {
                continue;  // torn down concurrently - recount
            }
            if (oldest->subscribed && bus_ != nullptr) {
                bus_->unsubscribe(oldest->execution_id, oldest->sub_id);
            }
            oldest->subscribed = false;
        }
        // Revalidate + claim (the unsubscribed interval could still have
        // delivered a terminal before unsubscribe returned).
        bool claimed = false;
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
            if ((oldest->terminal_accepted && !oldest->terminal_projected) ||
                oldest->projection_in_flight) {
                // A real terminal slipped in before unsubscribe returned (or a
                // projection started): defer while unsubscribed - safe, the
                // payload is locally secured and the projector will publish it;
                // the next sweep claims the then-settled record.
                wake(*core_);
                return;
            }
            synthesize = !oldest->terminal_accepted;  // re-derive on fresh state
            if (oldest->phase.load(std::memory_order_acquire) != Phase::kRingOnly ||
                oldest->torn_down) {
                continue;
            }
            oldest->phase.store(Phase::kDone, std::memory_order_release);
            oldest->torn_down = true;
            claimed = true;
        }
        if (claimed) {
            teardown_claimed(oldest, synthesize, "mcp.bridge.forced_expire");
        }
        // Loop: recount and keep reaping until the population is at the cap.
    }
}

void McpStreamBridge::teardown_claimed(const std::shared_ptr<BridgeRecord>& rec,
                                       bool synthesize_unavailable, const char* audit_action) {
    // Claimant owns the record (phase == kDone, stored under record mu).
    std::string exec_id;
    {
        std::lock_guard<std::mutex> rlk(rec->mu);
        exec_id = rec->execution_id;
    }
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        if (rec->subscribed && bus_ != nullptr) {
            bus_->unsubscribe(exec_id, rec->sub_id);
        }
        rec->subscribed = false;
    }
    if (synthesize_unavailable) {
        // Pressure victim with NO secured terminal (revalidated at claim): pin a
        // machine-readable terminal-unavailable so a later resume still finds
        // truth in the ring. A4 grammar: error.data carries the durable handle.
        try {
            std::string data = std::string(R"({"execution_id":)") + detail::json_quoted(exec_id) +
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
            publish_terminal_ladder(rec, std::move(frame));  // 0 twice ⇒ poison (A6a)
        } catch (...) {
            // Build-side OOM: nothing published. The record is gone either way;
            // the durable execution fetch remains, and the failure is counted.
            if (metrics_ != nullptr) {
                obs_guard([&] { metrics_->counter(kMetricTerminalPublishFailures).increment(); });
            }
        }
    }
    release_charge(rec);
    flush_record_obs(*rec);
    std::size_t active = 0;
    {
        std::lock_guard<std::mutex> lk(bridge_mu_);
        auto it = records_.find(rec->key);
        if (it != records_.end() && it->second == rec) {
            records_.erase(it);
        }
        active = records_.size();
    }
    publish_records_gauge(active);
    audit_contained(audit_action, exec_id, synthesize_unavailable
                                               ? "terminal-unavailable synthesized (pressure)"
                                               : "");
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
                                      const std::string& detail) noexcept {
    if (audit_) {
        obs_guard([&] { audit_(action, execution_id, detail); });
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

}  // namespace yuzu::server::mcp
