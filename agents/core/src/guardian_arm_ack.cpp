#include "guardian_arm_ack.hpp"

#include <algorithm>
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
        canon += canonicalize_spec_block(r->spark());
        canon += canonicalize_spec_block(r->assertion());
        canon += canonicalize_spec_block(r->remediation());
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
                                               std::size_t max_per_tick) {
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
        if (status == GuardianSparkRuntime::ReceiptStatus::Pending) {
            ++it;
            continue;
        }
        if (status == GuardianSparkRuntime::ReceiptStatus::Committed)
            ++current_->resolved_armed;
        else
            ++current_->resolved_failed;
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

GuardianArmAckLedger::RetryDecision GuardianArmAckLedger::decide_retry(
    std::uint64_t generation, const std::string& content_id, bool full_sync,
    const GuardianSparkRuntime& runtime) const {
    if (!current_)
        return RetryDecision::Reapply; // nothing open to suppress against
    if (current_->generation != generation)
        return RetryDecision::Reapply; // a different generation is not a retry at all
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
