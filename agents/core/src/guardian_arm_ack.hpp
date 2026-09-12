#pragma once

/**
 * guardian_arm_ack.hpp - rung 9c PR-2 Unit 5 (ack bookkeeping preparation).
 * See docs/spark-stage2-guardian-consumer-design.md §R5.3.
 *
 * GuardianArmAckLedger tracks ONE outstanding "application" - the set of rules
 * a single apply_rules() push accepted for spark arming
 * (GuardianEngine::ReconcileOutcome::Accepted) whose arms have not yet
 * resolved - so a heartbeat-bounded drain (§R5.3) can tell whether a
 * generation may advance, and a same-generation full_sync retry can be told
 * apart from a genuinely new or changed push (§R5.3's own duplicate-retry
 * language: "A same-generation re-push ... is a no-op while every outstanding
 * episode for that generation is still genuinely pending ... and only
 * triggers a full re-apply once something has actually failed, expired, or
 * the push's content has changed underneath it").
 *
 * PREPARATION ONLY (Unit 5): built and independently tested here, not yet
 * wired into apply_rules()/reconcile_rule_locked() - GuardianSparkRuntime::
 * attach_rule() still uses its blocking overload in production, so
 * ReconcileOutcome::Accepted is never actually produced yet (see that enum's
 * own doc comment in guardian_engine.hpp). Unit 6 connects this to the live
 * path: apply_rules() begins/feeds an application, the heartbeat drains it,
 * and its generation-hold gate reads can_advance() instead of assuming
 * pending_arms == 0.
 *
 * Deliberately conservative and pre-K-bound (rung 9c PR-2's own scope only):
 * a receipt that resolves to anything other than Committed holds its
 * application's generation FOREVER, exactly like today's synchronous
 * behavior - no quarantine, no K-bound retry-then-waive. §R5.2's ClaimEnd
 * already preserves the finer split a later rung 9c PR needs to implement
 * that (queue-wait expiry vs. dispatched timeout vs. genuine refusal); this
 * ledger does not need it and does not re-derive it here.
 *
 * One current application, never a history (Astra opine review: "New
 * application: stale receipts cannot acknowledge it"). begin_application()
 * unconditionally replaces whatever was there. A receipt from a superseded
 * application resolving later touches nothing - it is simply no longer in
 * any ledger's pending set. This is safe by construction, not by explicit
 * cancellation: an ArmReceipt is an OBSERVATION handle (its own doc comment)
 * and its KeyClaim is owned entirely by the runtime's own claims_ registry
 * either way - dropping the ledger's copy neither withdraws the rule nor
 * abandons the operation.
 */

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include <yuzu/plugin.h>

#include "guardian_spark_runtime.hpp" // GuardianSparkRuntime::ArmReceipt (nested type - needs the complete class)

namespace yuzu::guardian::v1 {
class GuaranteedStatePush;
} // namespace yuzu::guardian::v1

namespace yuzu::agent {

/// Per-heartbeat-tick bound for GuardianArmAckLedger::drain_locked() (rung 9c PR-2
/// Unit 6), matching guardian_journal_format.hpp's kJournalPersistMaxRecordsPerTick
/// in spirit (bound the one heartbeat-thread caller, never the one-shot callers -
/// there are none for this ledger yet, but the same principle applies if one is
/// ever added). Generous relative to a realistic push size since each entry costs
/// one brief, allocation-free registry_mu_ check, not KV I/O.
inline constexpr std::size_t kAckDrainMaxPerTick = 1024;

/// Content identity for a push: a rule_id, its enabled flag, enforcement_mode,
/// version, and its spark/assertion/remediation GuardianSpecBlocks (type +
/// params, each params map canonicalized by sorted key - proto's own
/// map<string,string> wire serialization is NOT deterministic, so hashing
/// SerializeAsString() directly would make two byte-identical pushes hash
/// differently depending on hash-map iteration order alone), plus the push's
/// own full_sync flag. Deliberately does NOT read yaml_source: that field is
/// the verbatim, human-authoritative form the agent "never parses" (see the
/// proto's own comment) - the agent's arming behavior is driven entirely by
/// the structured blocks, so a yaml_source-only edit that leaves every
/// structured block unchanged must not be treated as a content change here.
/// Two pushes with identical content (by this definition) hash identically
/// regardless of process, restart, or map iteration order.
YUZU_EXPORT std::string guardian_push_content_id(const yuzu::guardian::v1::GuaranteedStatePush& push);

class YUZU_EXPORT GuardianArmAckLedger {
public:
    GuardianArmAckLedger();
    ~GuardianArmAckLedger();

    GuardianArmAckLedger(const GuardianArmAckLedger&) = delete;
    GuardianArmAckLedger& operator=(const GuardianArmAckLedger&) = delete;

    /// Starts tracking a new application, discarding whatever the previous one
    /// still had pending (see the file header: no history, no carry-over).
    /// `content_id` is a caller-computed identity over the push's actual rule
    /// contents plus its full_sync flag (a generation number alone is not
    /// content identity - two different pushes can share one; see the design
    /// doc's own "unordered-map-dependent protobuf byte string alone is
    /// insufficient" warning about naive serialization of a rule's
    /// map<string,string> spark params). `applied` is the count the caller's
    /// own apply_rules() already computed for this push - stashed so a
    /// Suppress decision (decide_retry(), below) can hand it straight back
    /// without recomputing anything.
    void begin_application(std::uint64_t generation, std::string content_id, bool full_sync,
                           std::size_t applied);

    /// Add one rule's accepted-but-unresolved arm to the current application.
    /// Caller's responsibility: only ever called for a rule_id
    /// reconcile_rule_locked mapped to ReconcileOutcome::Accepted, for the
    /// application currently open (i.e. after begin_application() for this
    /// push - never across a push boundary, and never with no current
    /// application). A no-op (logged, not asserted - this is bookkeeping, not
    /// a safety property) if called with no current application.
    void add_pending(std::string rule_id, GuardianSparkRuntime::ArmReceipt receipt);

    /// Mark the current application as having hit one of apply_rules()'s
    /// existing generation-hold failures (the kv sweep failure, a del_keys
    /// undercount, a full_sync teardown throw, a put_rule_locked failure) -
    /// these are orthogonal to any single rule's own arm outcome, so they
    /// cannot be expressed as a receipt. A no-op if there is no current
    /// application.
    void latch_failure();

    /// Expected to be called with the caller's own engine lock held, matching
    /// journal_maintenance_tick()'s own posture - this call does not take any
    /// lock of its own beyond what `runtime`'s public API already takes
    /// internally (registry_mu_, briefly, allocation-free). Sweeps
    /// runtime.expire_overdue_claims() first (rung 9c PR-2 Unit 2's own
    /// deferred "later by Unit 5's tick"), then resolves up to `max_per_tick`
    /// of the current application's still-pending receipts via
    /// runtime.receipt_status(). A no-op (returns 0) if there is no current
    /// application. Returns the number of receipts resolved THIS call (tests
    /// / diagnostics only - bounded draining is otherwise silent).
    ///
    /// The bound is on how many receipts RESOLVE this call, not how many are
    /// examined - every still-pending receipt is checked every call (one
    /// brief, allocation-free receipt_status() each; unlike the lifecycle
    /// journal's own bounded drain, there is no KV I/O here to bound, and
    /// std::map has no resume cursor to page through anyway), so a large
    /// pending set costs a scan, never a stall. This is also why
    /// decide_retry() re-checks `runtime` directly rather than trusting
    /// resolved_failed alone: a receipt beyond this call's max_per_tick cap
    /// can still be sitting in `pending`, already resolved, uncounted.
    std::size_t drain_locked(GuardianSparkRuntime& runtime, std::size_t max_per_tick);

    /// True iff there IS a current application, it has nothing left pending,
    /// nothing resolved to a failure, and nothing latched - i.e. its
    /// generation may advance. False, not vacuously true, when there is no
    /// current application at all (nothing to advance FOR is not the same
    /// question as "may advance").
    ///
    /// A current application with an EMPTY pending map because add_pending()
    /// was simply never called (every rule this push resolved synchronously -
    /// Armed or Inert, nothing Accepted) trivially returns true here, matching
    /// today's pending_arms == 0 behavior exactly - this is the common case,
    /// not a gap. The design doc's own "Zero-accepted push ... does NOT
    /// advance vacuously" warning is about a DIFFERENT thing: a rule refused
    /// AT ADMISSION (ReconcileOutcome::Failed), which is counted by
    /// apply_rules()'s own pre-existing reconcile_failures gate and never
    /// reaches this ledger as a receipt at all. What THIS ledger must never
    /// do vacuously is call an application done when a receipt it WAS given
    /// resolved to anything other than Committed - that is resolved_failed,
    /// checked above, independent of whether pending is empty.
    bool can_advance() const;

    /// The `applied` count stashed at begin_application() time (or updated by
    /// set_applied(), below). Valid only when there is a current application;
    /// 0 otherwise.
    std::size_t applied_count() const;

    /// TEST-ONLY: the current application's still-pending receipt count (0 if there
    /// is no current application). Lets a test settle on "every accepted arm from
    /// the last push has resolved" without a production accessor of its own -
    /// GuardianEngine::ack_pending_count_for_test() forwards to this. No production
    /// caller.
    std::size_t pending_count_for_test() const;

    /// rung 9c PR-2 Unit 6: apply_rules() calls begin_application() BEFORE its
    /// per-rule loop (so reconcile_rule_locked's add_pending() calls during
    /// that loop land in the right application) but does not know the real
    /// applied count until the loop finishes - this updates it afterward, so
    /// a later same-generation Suppress decision hands back the true count
    /// rather than begin_application()'s placeholder. A no-op if there is no
    /// current application.
    void set_applied(std::size_t applied);

    /// The generation the current application is FOR (0 if there is none) -
    /// what journal_maintenance_tick() compares against policy_generation_
    /// before advancing it once can_advance() is true.
    std::uint64_t pending_generation() const;

    enum class RetryDecision { Suppress, Reapply };

    /// Whether an incoming push matching (generation, content_id, full_sync)
    /// against the CURRENT application is a genuine same-generation retry
    /// that can be skipped (Suppress), or must be treated as new work
    /// (Reapply) - a different generation, changed content under the same
    /// generation number, or an application that has already seen a failure
    /// (latched or a resolved receipt). Reapply when there is no current
    /// application at all - nothing to suppress against. Never mutates
    /// state (a query only - `runtime` is read via receipt_status(), which
    /// takes its own brief registry_mu_ internally); call this AFTER
    /// drain_locked() so a receipt that resolved this tick is reflected.
    ///
    /// `runtime` is consulted directly, not just `resolved_failed`, because
    /// drain_locked() is BOUNDED: a receipt past one tick's max_per_tick cap
    /// can sit in `pending` long after it actually resolved (to Failed or
    /// anything else), and Suppress must mean "every pending receipt is
    /// still genuinely Pending" - not merely "drain_locked hasn't gotten to
    /// it yet". This scan is what makes that true without drain_locked
    /// itself needing an unbounded pass first.
    RetryDecision decide_retry(std::uint64_t generation, const std::string& content_id,
                               bool full_sync, const GuardianSparkRuntime& runtime) const;

    /// Stop-time: drop the current application without resolving it further.
    /// Its receipts' claims remain the runtime's own problem exactly as
    /// §R5.5 already describes (in-flight workers finish on their own
    /// schedule after stop() returns; a late-arriving success is disarmed
    /// rather than left live) - dropping the ledger's observation handles
    /// changes none of that. Idempotent.
    void retire();

private:
    struct Application {
        std::uint64_t generation{0};
        std::string content_id;
        bool full_sync{false};
        std::size_t applied{0};
        bool latched_failure{false};
        std::size_t resolved_armed{0};
        std::size_t resolved_failed{0};
        std::map<std::string, GuardianSparkRuntime::ArmReceipt> pending;
    };
    std::unique_ptr<Application> current_;
};

} // namespace yuzu::agent
