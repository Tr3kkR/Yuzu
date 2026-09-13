#include "guardian_arm_ack.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <vector>

#include <spdlog/spdlog.h>

#include "guaranteed_state.pb.h"
#include "sync_canonical.hpp" // sha256_hex

namespace yuzu::agent {

namespace {

namespace gpb = ::yuzu::guardian::v1;

/// Length-prefixed field append ("<byte-length>:<bytes>"), NOT a bare separator
/// byte - a field's own content can legitimately contain any byte a param value
/// might (spark params are free-form strings), so a fixed separator alone is
/// injective only if no field can ever contain it. sync_canonical.hpp's own
/// clamp_field strips exactly this class of framing byte from ITS fields before
/// they cross the wire for the same reason this file has to canonicalize
/// without assuming its own inputs are pre-scrubbed. Length-prefixing makes the
/// encoding injective regardless of what a value contains.
void append_field(std::string& out, std::string_view s) {
    out += std::to_string(s.size());
    out.push_back(':');
    out += s;
}

std::string canonicalize_spec_block(const gpb::GuardianSpecBlock& block) {
    std::string out;
    append_field(out, block.type());
    // proto's map<string,string> iterates in an UNSPECIFIED (hash-map) order -
    // copying into std::map sorts it by key so two byte-identical blocks
    // always canonicalize identically, regardless of process or restart.
    const std::map<std::string, std::string> sorted(block.params().begin(), block.params().end());
    for (const auto& [k, v] : sorted) {
        append_field(out, k);
        append_field(out, v);
    }
    return out;
}

/// True iff `s` has the exact shape of a real `guardian_push_content_id()` output
/// (lowercase-or-uppercase hex, 64 chars - a SHA-256 digest). Governance finding
/// sec-1/arch-1 gate-review (rung 9c PR-2 hardening): decide_retry() must never
/// trust a content_id comparison where EITHER side is a sentinel rather than a
/// real hash - the empty string GuardianEngine::start_local()'s boot placeholder
/// uses, and the empty string guardian_push_content_id()'s own throw fallback
/// uses below, both fail this check trivially (wrong length), so two DIFFERENT
/// pushes that both hit the throw fallback (or one that collides with the boot
/// placeholder) can never be misread as "the same content" merely because their
/// sentinels are byte-identical to each other.
bool is_sha256_hex(std::string_view s) {
    if (s.size() != 64)
        return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
}

/// Governance finding SHOULD-1 (Gate 4, consistency-auditor): drain_locked()'s own
/// async-failure warn previously logged no reason at all, unlike the sync-refusal
/// warn in reconcile_rule_locked() which always names one. Exhaustive switch, no
/// `default`, mirroring GuardianSparkRuntime::receipt_status()'s own convention -
/// a future ReceiptStatus addition (e.g. a K-bound Quarantined) fails to COMPILE
/// here rather than silently landing in a catch-all bucket.
const char* receipt_status_name(GuardianSparkRuntime::ReceiptStatus status) {
    using S = GuardianSparkRuntime::ReceiptStatus;
    switch (status) {
    case S::Pending:
        return "Pending";
    case S::Committed:
        return "Committed";
    case S::Failed:
        return "Failed";
    case S::Expired:
        return "Expired";
    case S::Withdrawn:
        return "Withdrawn";
    case S::Stopped:
        return "Stopped";
    }
    return "Unknown"; // unreachable if the switch above is kept exhaustive
}

} // namespace

std::string guardian_push_content_id(const gpb::GuaranteedStatePush& push) {
    std::vector<const gpb::GuaranteedStateRule*> sorted_rules;
    sorted_rules.reserve(static_cast<std::size_t>(push.rules_size()));
    for (const auto& r : push.rules())
        sorted_rules.push_back(&r);
    std::sort(sorted_rules.begin(), sorted_rules.end(),
             [](const gpb::GuaranteedStateRule* a, const gpb::GuaranteedStateRule* b) {
                 return a->rule_id() < b->rule_id();
             });

    std::string canon = push.full_sync() ? "F1" : "F0";
    for (const auto* r : sorted_rules) {
        append_field(canon, r->rule_id());
        append_field(canon, r->enabled() ? "1" : "0");
        append_field(canon, r->enforcement_mode());
        append_field(canon, std::to_string(r->version()));
        // Governance finding cae-1 (Gate 3, cpp-expert, verified with a hand-constructed
        // collision): concatenating each block's own already-field-injective output
        // directly is NOT block-boundary-injective - nothing marks where one block's
        // fields end and the next begins, so two rules with different (spark,
        // assertion) splits of the same flat field sequence canonicalize identically.
        // append_field() on the whole block output restores injectivity the same way
        // it already does for individual fields, by length-prefixing the boundary.
        append_field(canon, canonicalize_spec_block(r->spark()));
        append_field(canon, canonicalize_spec_block(r->assertion()));
        append_field(canon, canonicalize_spec_block(r->remediation()));
    }
    return sha256_hex(canon);
}

GuardianArmAckLedger::GuardianArmAckLedger() = default;
GuardianArmAckLedger::~GuardianArmAckLedger() = default;

void GuardianArmAckLedger::begin_application(std::uint64_t generation, std::string content_id,
                                             bool full_sync, std::size_t applied) {
    // Unconditionally replaces whatever was open - Astra opine review: "New
    // application: stale receipts cannot acknowledge it." The old Application's
    // pending map (if any) is simply destroyed here; its receipts' claims stay
    // owned by the runtime's own claims_ registry regardless (ArmReceipt is an
    // observation handle - see the header).
    current_ = std::make_unique<Application>();
    current_->generation = generation;
    current_->content_id = std::move(content_id);
    current_->full_sync = full_sync;
    current_->applied = applied;
}

void GuardianArmAckLedger::add_pending(std::string rule_id,
                                       GuardianSparkRuntime::ArmReceipt receipt) {
    if (!current_) {
        try {
            spdlog::error("Guardian: add_pending('{}') with no open application - dropped",
                         rule_id);
        } catch (...) {
        }
        return;
    }
    current_->pending.insert_or_assign(std::move(rule_id), std::move(receipt));
}

void GuardianArmAckLedger::latch_failure() {
    if (current_)
        current_->latched_failure = true;
}

std::size_t GuardianArmAckLedger::drain_locked(GuardianSparkRuntime& runtime,
                                               std::size_t max_per_tick,
                                               std::size_t* failed_out) {
    // Runtime-wide sweep, not scoped to this application's own pending set -
    // rung 9c PR-2 Unit 2's expire_overdue_claims() abandons any Arm claim
    // whose real deadline has passed regardless of which (if any) ledger is
    // watching it. Always run, even with no current application: a stray
    // overdue claim from a superseded application still needs to resolve.
    runtime.expire_overdue_claims();

    if (!current_)
        return 0;

    std::size_t resolved = 0;
    for (auto it = current_->pending.begin();
        it != current_->pending.end() && resolved < max_per_tick;) {
        const auto status = runtime.receipt_status(it->second);
        // Exhaustive switch, no `default` - SHOULD-1's own fix (see the
        // receipt_status_name() helper above): a future ReceiptStatus value fails
        // to compile here rather than silently landing in a catch-all "failed"
        // bucket the way the old if/else-if/else chain would have.
        using S = GuardianSparkRuntime::ReceiptStatus;
        switch (status) {
        case S::Pending:
            ++it;
            continue;
        case S::Committed:
            ++current_->resolved_armed;
            break;
        case S::Failed:
        case S::Expired:
        case S::Withdrawn:
        case S::Stopped:
            ++current_->resolved_failed;
            if (failed_out)
                ++*failed_out; // UP-3: feeds GuardianEngine::arm_failures_ (see caller)
            // rung 9c PR-2 Unit 6: the only place this can be logged - reconcile_rule_locked's
            // own "spark arm failed" warn fires only for a SYNCHRONOUS refusal now; an
            // Accepted rule that later resolves to anything but Committed would otherwise be
            // silent on a Guaranteed State product. Heartbeat thread: contained, like every
            // other log call on this path. Names `status` per governance finding SHOULD-1
            // (Gate 4, consistency-auditor) - the sync-refusal warn in
            // reconcile_rule_locked() already names its own failure reason, and this one
            // silently didn't.
            try {
                spdlog::warn("Guardian: spark arm failed for rule '{}' (accepted, resolved "
                             "asynchronously, status={})",
                             it->first, receipt_status_name(status));
            } catch (...) {
            }
            break;
        }
        it = current_->pending.erase(it);
        ++resolved;
    }
    return resolved;
}

bool GuardianArmAckLedger::can_advance() const {
    if (!current_)
        return false; // nothing to advance FOR - not the same question as "may advance"
    return current_->pending.empty() && current_->resolved_failed == 0 &&
          !current_->latched_failure;
}

std::size_t GuardianArmAckLedger::applied_count() const {
    return current_ ? current_->applied : 0;
}

std::size_t GuardianArmAckLedger::pending_count_for_test() const {
    return current_ ? current_->pending.size() : 0;
}

void GuardianArmAckLedger::set_applied(std::size_t applied) {
    if (current_)
        current_->applied = applied;
}

std::uint64_t GuardianArmAckLedger::pending_generation() const {
    return current_ ? current_->generation : 0;
}

GuardianArmAckLedger::RetryDecision GuardianArmAckLedger::decide_retry(
    std::uint64_t generation, const std::string& content_id, bool full_sync,
    const GuardianSparkRuntime& runtime) const {
    if (!current_)
        return RetryDecision::Reapply; // nothing open to suppress against
    // Governance finding sec-1/arch-1 (Gates 2-4, 5x independently confirmed - the
    // production-live wedge): the WHOLE reason this dedup exists is to protect a
    // claim that is genuinely still in flight from a spurious re-teardown+re-arm on
    // an identical retry (see this file's header). With nothing pending there is
    // NOTHING to protect - either no rule was ever Accepted this application (the
    // ordinary case at prefer_spark_=false, where Accepted never occurs at all) or
    // everything already resolved - so Suppressing here served no purpose except to
    // ALSO swallow the one thing apply_rules()'s own tail gate still needed to do on
    // a repeat push: retry a policy-generation persist that failed last time. Before
    // this fix, an empty `pending` map fell all the way through to a vacuous
    // Suppress, and the retry that would have re-attempted the failed persist never
    // ran - silently and permanently wedging the reported generation below the
    // server's value until restart. Reapply here restores exact pre-PR behavior for
    // this case (a full re-run, matching what a retry always did before this
    // ledger existed) and costs nothing extra when the prior application already
    // succeeded, since the resulting re-run finds every rule already correctly
    // armed and nothing left to change.
    if (current_->pending.empty())
        return RetryDecision::Reapply;
    if (current_->generation != generation)
        return RetryDecision::Reapply; // a different generation is not a retry at all
    // Governance finding UP-2/SHOULD-2 (Gate 4, converged independently from two
    // reviewers): a content_id that is not an actual SHA-256 digest is a SENTINEL,
    // never a real content identity - GuardianEngine::start_local()'s boot
    // placeholder and guardian_push_content_id()'s own throw fallback both use the
    // empty string today. Two DIFFERENT pushes that both hit the throw fallback (or
    // a real post-boot push landing at the same generation the boot placeholder
    // opened) must never be read as "identical content" merely because their
    // sentinels happen to be byte-identical to each other - that comparison was
    // never meaningful in the first place.
    if (!is_sha256_hex(current_->content_id) || !is_sha256_hex(content_id))
        return RetryDecision::Reapply;
    if (current_->content_id != content_id || current_->full_sync != full_sync)
        return RetryDecision::Reapply; // same generation number, changed content underneath it
    if (current_->latched_failure || current_->resolved_failed > 0)
        return RetryDecision::Reapply; // something already failed - a real re-apply is owed
    // drain_locked() is BOUNDED - a receipt past one tick's cap can still sit in
    // `pending` long after it actually resolved. Suppress means every pending
    // receipt is STILL genuinely Pending, not merely "not yet drained" - so consult
    // the runtime directly rather than trust resolved_failed alone (which only
    // counts what drain_locked has actually retired so far).
    for (const auto& entry : current_->pending) {
        const auto status = runtime.receipt_status(entry.second);
        if (status != GuardianSparkRuntime::ReceiptStatus::Pending &&
            status != GuardianSparkRuntime::ReceiptStatus::Committed)
            return RetryDecision::Reapply;
    }
    return RetryDecision::Suppress; // identical content, nothing failed yet, rest still pending
}

void GuardianArmAckLedger::retire() {
    current_.reset(); // §R5.5: in-flight workers finish on their own schedule; this just
                      // stops watching them, exactly as begin_application() already does
                      // for a superseded application.
}

} // namespace yuzu::agent
