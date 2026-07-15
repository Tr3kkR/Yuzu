#pragma once

/**
 * spark_key_rule_index.hpp - the consumer-side spark_key -> {rule_id} index
 * (ADR-0021 Stage 2 rung 2, slice 2a).
 *
 * The SparkEngine dedups arming by spark_key: N subscriptions with an equal
 * (type, params) spec share ONE watcher, and a SparkEvent carries only its
 * `key`, never a rule_id or SubscriptionId (spark.hpp). So a Guardian-style
 * consumer that must map each event back to the rules it should evaluate owns
 * this reverse mapping itself; the rule-agnostic engine cannot.
 *
 * Two roles in one small value type:
 *   1. Fan-out register-of-record. rules_for(key) answers "which rules must I
 *      evaluate for this event" when a single shared watcher fires ONE event
 *      for MANY rules (governance UP-11 / happy-path Issue 2).
 *   2. Shared-watcher refcount. add() reports the 0->1 edge (arm the watcher)
 *      and remove_rule() reports the ->0 edge (disarm it), so withdrawing rule
 *      A never blinds rule B that shares the same key.
 *
 * Proto-free and lock-free by design: plain state owned by one consumer and
 * mutated only under that consumer's own serialisation. Each rule maps to
 * exactly one key at a time (its current spec); a redeploy that changes the
 * spec is a remove-then-add, which add() handles internally.
 *
 * Slice 2a builds and unit-tests this INERT: nothing arms yet, so at agent
 * runtime it is never populated and stays empty. Slice 2b populates it at arm
 * time and drives SparkEngine::arm()/disarm() off the 0->1 / ->0 edges.
 */

#include <cstddef>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::agent {

class SparkKeyRuleIndex {
public:
    /// Associate `rule_id` with `spark_key`. If the rule is already mapped to a
    /// DIFFERENT key (a redeploy that changed the spec), it is first removed
    /// from that key. An identical (key, rule) pair is an idempotent no-op.
    /// @return true iff `spark_key` went from zero rules to one - the 0->1 edge
    ///         a caller turns into a single SparkEngine::arm(). Note: a redeploy
    ///         that vacated the rule's OLD key does not surface that key's ->0
    ///         edge here; the caller drives disarm off remove_rule() instead, so
    ///         the redeploy sequence is remove_rule(old) then add(new).
    bool add(std::string_view spark_key, std::string_view rule_id);

    /// Remove `rule_id` from whatever key it is under (withdraw or the first
    /// half of a redeploy). Idempotent - a no-op for an unknown rule.
    /// @return the key `rule_id` was under IFF that key now has zero rules - the
    ///         ->0 edge a caller turns into a single SparkEngine::disarm().
    ///         nullopt when the rule was unknown OR the key still has siblings.
    std::optional<std::string> remove_rule(std::string_view rule_id);

    /// Rules currently mapped to `spark_key`, in deterministic (sorted) order;
    /// empty for an unknown key. This is the fan-out set an event resolves to.
    [[nodiscard]] std::vector<std::string> rules_for(std::string_view spark_key) const;

    /// Number of rules sharing `spark_key` (0 for unknown) - the watcher refcount.
    [[nodiscard]] std::size_t refcount(std::string_view spark_key) const;

    /// The key `rule_id` is currently mapped to, or nullopt if unknown.
    [[nodiscard]] std::optional<std::string> key_for_rule(std::string_view rule_id) const;

    [[nodiscard]] bool empty() const noexcept { return by_rule_.empty(); }
    [[nodiscard]] std::size_t key_count() const noexcept { return by_key_.size(); }
    [[nodiscard]] std::size_t rule_count() const noexcept { return by_rule_.size(); }

private:
    // key -> set of rule_ids sharing it (sorted, deduped). A key entry never
    // lives empty: remove_rule() erases it on the ->0 edge, so key_count()
    // equals the live shared-watcher count.
    std::map<std::string, std::set<std::string>, std::less<>> by_key_;
    // rule_id -> its single current key. The reverse index that lets
    // remove_rule() work from a rule_id alone and lets add() detect a key move.
    std::map<std::string, std::string, std::less<>> by_rule_;
};

inline bool SparkKeyRuleIndex::add(std::string_view spark_key, std::string_view rule_id) {
    if (auto rit = by_rule_.find(rule_id); rit != by_rule_.end()) {
        if (rit->second == spark_key) return false; // identical (key, rule): no-op
        remove_rule(rule_id);                        // moved to a new key: drop the old
    }
    std::string key{spark_key};
    auto& rules = by_key_[key];
    const bool first = rules.empty();
    rules.emplace(rule_id);
    by_rule_.insert_or_assign(std::string{rule_id}, std::move(key));
    return first;
}

inline std::optional<std::string> SparkKeyRuleIndex::remove_rule(std::string_view rule_id) {
    auto rit = by_rule_.find(rule_id);
    if (rit == by_rule_.end()) return std::nullopt;
    const std::string key = rit->second; // copy before erase: needed for the return + lookup
    by_rule_.erase(rit);
    if (auto kit = by_key_.find(key); kit != by_key_.end()) {
        kit->second.erase(std::string{rule_id});
        if (kit->second.empty()) {
            by_key_.erase(kit);
            return key; // ->0 edge: caller disarms the shared watcher
        }
    }
    return std::nullopt; // siblings remain: the watcher stays armed
}

inline std::vector<std::string> SparkKeyRuleIndex::rules_for(std::string_view spark_key) const {
    std::vector<std::string> out;
    if (auto it = by_key_.find(spark_key); it != by_key_.end())
        out.assign(it->second.begin(), it->second.end());
    return out;
}

inline std::size_t SparkKeyRuleIndex::refcount(std::string_view spark_key) const {
    auto it = by_key_.find(spark_key);
    return it == by_key_.end() ? 0U : it->second.size();
}

inline std::optional<std::string> SparkKeyRuleIndex::key_for_rule(std::string_view rule_id) const {
    auto it = by_rule_.find(rule_id);
    if (it == by_rule_.end()) return std::nullopt;
    return it->second;
}

} // namespace yuzu::agent
