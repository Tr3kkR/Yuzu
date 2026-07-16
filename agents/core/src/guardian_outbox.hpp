#pragma once

/**
 * guardian_outbox.hpp - the Guardian spark consumer's in-memory, lifetime-safe
 * emit buffer (ADR-0021 Stage 2 rung 2). PURE and caller-serialized: no I/O, no
 * threads, no clock, no proto. The runtime drives it under its registry mutex and
 * injects a send function at drain time, so every branch is unit-tested standalone.
 *
 * Why it exists (the pre-network / A3 gap it closes): GuardianEngine arms and does
 * its initial eval BEFORE the server sink is published (start_local runs before
 * Subscribe-open). Emitting straight to the sink there DROPS the event, yet
 * decide_emit has already committed last_compliant - so the compliant edge is lost
 * forever and steady-compliant stays silent, and the server never learns
 * compliance. The consumer instead enqueues here and drains when the sink is live.
 * This is an in-memory buffer plus a boot re-eval, NOT durable event delivery: a
 * process restart re-arms and re-evaluates from scratch rather than replaying.
 *
 * Contract the runtime MUST honour (enforced structurally here where possible):
 *   - enqueue BEFORE commit. Run the eval against a COPY of RuleEvalState, enqueue
 *     the outcome, and commit the copy back ONLY if enqueue() returned true. If it
 *     returned false (at cap), discard the copy so the eval stays pending and
 *     convergence retries - never advance decider state for an event we could not
 *     buffer. (decide_emit mutates state mid-eval, hence copy-eval-enqueue-commit.)
 *   - peek / send / remove-on-success. drain() sends in FIFO order and removes an
 *     entry only when the send reports success; a false return OR a throw retains
 *     the entry and STOPS the drain (the stream is down - do not burn N syscalls).
 *   - SEPARATE coalescing domains. compliance / health each coalesce to the latest
 *     per rule independently; a health event never overwrites a pending compliance
 *     event for the same rule. Lifecycle is NOT a domain this class accepts - see
 *     GuardianLifecycleLog below and enqueue()'s rejection of it.
 *   - generation-tagged, purged on rule update/disable. A stale entry from a
 *     superseded generation is dropped, never sent.
 *   - event_id + timestamp fixed at ENQUEUE (the caller sets them; this stays free
 *     of clock/randomness). Coalescing replaces with the latest observation's id+ts.
 *   - full-cap => reject (caller leaves the eval pending) + bump the backpressure
 *     counter. NEVER silently evict a buffered entry to make room.
 *
 * The drain trigger (sink publication + every reconnect, not sync_with_server) and
 * the boot re-arm/re-eval are the runtime's wiring, not this structure's concern.
 */

#include <yuzu/agent/guard.hpp> // GuardDrift

#include <cstddef>
#include <cstdint>
#include <list>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace yuzu::agent {

/// Independent coalescing channels. Two entries coalesce (latest wins) only when
/// BOTH domain and rule_id match, so a rule can have one pending entry per domain.
/// Lifecycle is the odd one out: GuardianOutbox::enqueue()/enqueue_all() REJECT
/// it (see there for why - coalescing is the wrong semantics for an audit trail).
/// It exists on this shared enum/struct only because GuardianLifecycleLog reuses
/// OutboxEntry as its payload type; production code only ever routes it there.
enum class OutboxDomain {
    Compliance, ///< guard.compliant / guard.drift (payload: GuardDrift)
    Health,     ///< guard.unhealthy / guard.healthy (payload: healthy + detail)
    Lifecycle,  ///< guard.armed / guard.disarmed / guard.errored (payload: kind) - GuardianLifecycleLog only
};

/// One buffered emit. Which payload fields are meaningful is fixed by `domain`.
struct OutboxEntry {
    OutboxDomain domain{OutboxDomain::Compliance};
    std::string rule_id;
    std::uint64_t generation{0}; ///< the rule generation this was produced under; dropped once superseded
    std::string event_id;        ///< fixed at enqueue (wire idempotency)
    std::int64_t enqueued_ns{0}; ///< timestamp fixed at enqueue

    GuardDrift drift{};          ///< Compliance payload

    bool healthy{true};          ///< Health payload: true = recovered, false = unhealthy
    std::string health_detail;   ///< Health payload: read-error detail (unhealthy)

    std::string lifecycle_kind;  ///< Lifecycle payload: "armed" | "disarmed" | "errored"

    static OutboxEntry compliance(std::string rule_id, std::uint64_t generation,
                                  std::string event_id, std::int64_t enqueued_ns, GuardDrift drift) {
        OutboxEntry e;
        e.domain = OutboxDomain::Compliance;
        e.rule_id = std::move(rule_id);
        e.generation = generation;
        e.event_id = std::move(event_id);
        e.enqueued_ns = enqueued_ns;
        e.drift = std::move(drift);
        return e;
    }
    static OutboxEntry health(std::string rule_id, std::uint64_t generation, std::string event_id,
                              std::int64_t enqueued_ns, bool healthy, std::string detail) {
        OutboxEntry e;
        e.domain = OutboxDomain::Health;
        e.rule_id = std::move(rule_id);
        e.generation = generation;
        e.event_id = std::move(event_id);
        e.enqueued_ns = enqueued_ns;
        e.healthy = healthy;
        e.health_detail = std::move(detail);
        return e;
    }
    static OutboxEntry lifecycle(std::string rule_id, std::uint64_t generation, std::string event_id,
                                 std::int64_t enqueued_ns, std::string kind) {
        OutboxEntry e;
        e.domain = OutboxDomain::Lifecycle;
        e.rule_id = std::move(rule_id);
        e.generation = generation;
        e.event_id = std::move(event_id);
        e.enqueued_ns = enqueued_ns;
        e.lifecycle_kind = std::move(kind);
        return e;
    }
};

/// What a send attempt reported. Retain and Failed are equivalent to the drain
/// (both stop it and keep the entry); they read differently at the call site.
enum class SendResult {
    Sent,   ///< delivered; remove the entry
    Retain, ///< stream down / Write()==false; keep the entry and stop draining
};

/// FIFO, per-(domain,rule_id)-coalesced, capacity-bounded emit buffer.
/// Non-thread-safe by design: the runtime serialises access under its registry
/// mutex. A std::list preserves enqueue order with O(1) coalesce-in-place (the
/// index maps a key to the node, whose iterator stays valid across other edits)
/// and O(1) pop of a drained head.
class GuardianOutbox {
public:
    explicit GuardianOutbox(std::size_t capacity) : capacity_(capacity) {}

    /// Buffer `e`, coalescing to the latest for its (domain, rule_id). Returns
    /// false iff a NEW key would exceed capacity - the caller then leaves the eval
    /// pending (does NOT commit its decider copy) and this bumps the backpressure
    /// counter. Coalescing an existing key never grows the buffer, so it always
    /// succeeds and replaces the payload/id/timestamp/generation in place.
    ///
    /// Also returns false (no counter bump - this is a caller bug, not a capacity
    /// condition) for a Lifecycle-domain entry: this class's coalescing semantics
    /// would silently lose armed/disarmed/errored audit evidence, which is exactly
    /// what GuardianLifecycleLog exists to prevent. Route Lifecycle entries to
    /// GuardianLifecycleLog::enqueue() instead.
    bool enqueue(OutboxEntry e) {
        if (e.domain == OutboxDomain::Lifecycle)
            return false;
        const Key k{e.domain, e.rule_id};
        const auto it = index_.find(k);
        if (it != index_.end()) {
            *it->second = std::move(e); // coalesce: latest observation wins, keep position
            return true;
        }
        if (pending_.size() >= capacity_) {
            ++backpressure_drops_;
            return false; // never evict a buffered entry
        }
        pending_.push_back(std::move(e));
        index_.emplace(k, std::prev(pending_.end()));
        return true;
    }

    /// Atomically buffer a SET of entries: both-or-neither. Returns false iff the
    /// NEW keys among them would exceed capacity, in which case NONE are buffered
    /// (and the backpressure counter bumps once) so the caller leaves the whole eval
    /// pending. Used for the health-recovery pair (guard.healthy + the verdict) which
    /// must land together or not at all - a partial commit would advance decider state
    /// for an event the server never receives. Coalescing entries never count as growth.
    bool enqueue_all(std::vector<OutboxEntry> entries) {
        for (const auto& e : entries) {
            if (e.domain == OutboxDomain::Lifecycle) // see enqueue()'s rejection note
                return false;
        }
        std::size_t new_keys = 0;
        std::unordered_set<Key, KeyHash> adding;
        for (const auto& e : entries) {
            const Key k{e.domain, e.rule_id};
            if (index_.find(k) == index_.end() && adding.insert(k).second)
                ++new_keys;
        }
        if (pending_.size() + new_keys > capacity_) {
            ++backpressure_drops_;
            return false;
        }
        for (auto& e : entries)
            enqueue(std::move(e)); // each fits now (a coalesce, or within the reserved room)
        return true;
    }

    /// Send buffered entries in FIFO order. `send` is invoked as
    /// `SendResult send(const OutboxEntry&)`; a Sent entry is removed, a Retain (or
    /// a thrown exception) is kept and stops the drain. Returns the number sent.
    template <typename SendFn>
    std::size_t drain(SendFn&& send) {
        std::size_t sent = 0;
        while (!pending_.empty()) {
            const OutboxEntry& front = pending_.front();
            SendResult r = SendResult::Retain;
            try {
                r = send(front);
            } catch (...) {
                break; // treat a throw as a down stream: retain the head, stop
            }
            if (r != SendResult::Sent)
                break;
            index_.erase(Key{front.domain, front.rule_id});
            pending_.pop_front();
            ++sent;
        }
        return sent;
    }

    /// Drop every pending entry for a rule (used on disable / withdraw).
    void drop_rule(const std::string& rule_id) {
        for (auto it = pending_.begin(); it != pending_.end();) {
            if (it->rule_id == rule_id) {
                index_.erase(Key{it->domain, it->rule_id});
                it = pending_.erase(it);
            } else {
                ++it;
            }
        }
    }

    /// Drop pending entries for a rule that predate `active_generation` (a
    /// superseded generation must never send). Entries at or above it are kept.
    void purge_stale(const std::string& rule_id, std::uint64_t active_generation) {
        for (auto it = pending_.begin(); it != pending_.end();) {
            if (it->rule_id == rule_id && it->generation < active_generation) {
                index_.erase(Key{it->domain, it->rule_id});
                it = pending_.erase(it);
            } else {
                ++it;
            }
        }
    }

    [[nodiscard]] std::size_t size() const { return pending_.size(); }
    [[nodiscard]] bool empty() const { return pending_.empty(); }
    [[nodiscard]] std::size_t capacity() const { return capacity_; }
    /// Count of rejected enqueues (never-evicted backpressure), for telemetry.
    [[nodiscard]] std::uint64_t backpressure_drops() const { return backpressure_drops_; }

private:
    struct Key {
        OutboxDomain domain;
        std::string rule_id;
        bool operator==(const Key& o) const { return domain == o.domain && rule_id == o.rule_id; }
    };
    struct KeyHash {
        std::size_t operator()(const Key& k) const {
            return std::hash<std::string>{}(k.rule_id) ^
                   (static_cast<std::size_t>(k.domain) * 0x9e3779b97f4a7c15ull);
        }
    };

    std::size_t capacity_;
    std::list<OutboxEntry> pending_;
    std::unordered_map<Key, std::list<OutboxEntry>::iterator, KeyHash> index_;
    std::uint64_t backpressure_drops_{0};
};

/// APPEND-ONLY audit log for Lifecycle (guard.armed / guard.disarmed / guard.errored)
/// entries (ADR-0021 Stage 2 rung 7, audit-on-arm). Deliberately NOT the same
/// structure as GuardianOutbox: that class coalesces per (domain, rule_id) -
/// latest wins - and its drop_rule()/purge_stale() erase every domain for a
/// rule, INCLUDING Lifecycle. Both are correct and desired for a live
/// compliance/health verdict (only the latest matters, and a withdrawn rule's
/// stale verdict must not send) but WRONG for an audit trail: a rule armed then
/// quickly disabled must not have its "armed" evidence silently coalesced away
/// or purged by the disable's own withdrawal - the trail is the point. This
/// class enqueues FIFO, sends FIFO, coalesces nothing, and is never purged by
/// rule_id or generation - an entry leaves only when successfully sent.
/// Capacity-bounded like its sibling (reject-new + count on full; never evict).
class GuardianLifecycleLog {
public:
    explicit GuardianLifecycleLog(std::size_t capacity) : capacity_(capacity) {}

    /// Buffer `e`. Returns false iff at capacity - the caller's arm/disarm still
    /// succeeds (the audit trail is not allowed to block or unwind a real
    /// detection-capability change); the caller should count/log this loudly
    /// rather than swallow it (see the header note on outbox-full-on-arm).
    bool enqueue(OutboxEntry e) {
        if (pending_.size() >= capacity_) {
            ++backpressure_drops_;
            return false;
        }
        pending_.push_back(std::move(e));
        return true;
    }

    /// Send in FIFO order; a Sent entry is removed, a Retain (or a throw) stops
    /// the drain and keeps the head - identical send contract to GuardianOutbox.
    template <typename SendFn>
    std::size_t drain(SendFn&& send) {
        std::size_t sent = 0;
        while (!pending_.empty()) {
            const OutboxEntry& front = pending_.front();
            SendResult r = SendResult::Retain;
            try {
                r = send(front);
            } catch (...) {
                break;
            }
            if (r != SendResult::Sent)
                break;
            pending_.pop_front();
            ++sent;
        }
        return sent;
    }

    [[nodiscard]] std::size_t size() const { return pending_.size(); }
    [[nodiscard]] bool empty() const { return pending_.empty(); }
    [[nodiscard]] std::uint64_t backpressure_drops() const { return backpressure_drops_; }

private:
    std::size_t capacity_;
    std::list<OutboxEntry> pending_;
    std::uint64_t backpressure_drops_{0};
};

} // namespace yuzu::agent
