#pragma once

/**
 * guardian_spark_consumer.hpp - the Guardian consumer of SparkEvents
 * (ADR-0021 Stage 2 rung 2). Design: docs/spark-stage2-guardian-consumer-design.md.
 *
 * Rung 2 makes Guardian a SparkEngine client: instead of constructing one
 * legacy IGuard per rule, it registers a single queued consumer and arms one
 * spark per enabled rule, then evaluates each rule's assertion in the consumer
 * handler off the resulting SparkEvents. This class is that consumer.
 *
 * SLICE 2a (this file) is the INERT skeleton. It carries the two pieces that
 * are pure and testable WITHOUT arming anything:
 *   - the spark_key -> rule index (SparkKeyRuleIndex), the register-of-record
 *     that resolves a shared-watcher event back to the rules it fans out to;
 *   - the platform-rejection classifier, a pure decision over the host's spark
 *     capability that separates a routine cross-platform miss (Unsupported)
 *     from an authoring fault (Unrecognized).
 * It performs NO assertion evaluation and NO enforcement - that meaning layer
 * migrates verbatim from the legacy IGuard classes in slice 2b. It is NOT
 * wired into agent boot at 2a (the engine arms nothing), so at runtime this
 * class is never constructed and the index stays empty; it exists to be built,
 * reviewed, and unit-tested standalone so 2b's cutover is a wiring change, not
 * a new-logic change.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <yuzu/agent/spark.hpp> // SparkType, SparkEvent

#include "spark_key_rule_index.hpp"

#include <cstddef>
#include <functional>
#include <set>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::agent {

/// Where a Guardian rule lands when the consumer considers arming it on THIS
/// host. The Unsupported/Unrecognized split is the whole point of the
/// platform-rejection design (ADR-0021): a cross-platform Baseline reaching a
/// host that structurally lacks the mechanism (Registry or File off Windows,
/// Service off Linux/macOS) is ROUTINE and terminal-states to `unsupported`,
/// NOT an authoring fault. Only an unknown spark type is `errored`/page-worthy.
enum class RulePlacement {
    Arm,          ///< known event-driven type WITH a mechanism on this host: 2b arms it
    Unsupported,  ///< known type, NO mechanism registered here: routine, terminal-state unsupported
    Unrecognized, ///< spark type token not understood: an authoring error (errored)
};

class YUZU_EXPORT GuardianSparkConsumer {
public:
    /// Sink invoked once per rule an event resolves to. A slice-2a test installs
    /// an observing sink; slice 2b installs GuardianEngine's real
    /// assertion-evaluate + GuaranteedStateEvent-emit path. The handler runs on
    /// the SparkEngine consumer dispatch thread (never a watcher thread), so it
    /// must not block indefinitely (SparkEngine::register_consumer contract).
    using RuleHitFn = std::function<void(std::string_view rule_id, const SparkEvent& ev)>;

    GuardianSparkConsumer() = default;
    GuardianSparkConsumer(const GuardianSparkConsumer&) = delete;
    GuardianSparkConsumer& operator=(const GuardianSparkConsumer&) = delete;

    /// Classify a rule's spark type against the mechanisms available on this
    /// host. PURE and side-effect-free. `supported` is the set of event-driven
    /// types the SparkEngine has a registered mechanism for; slice 2b sources it
    /// from SparkEngine::stats_by_type() keys ("the key set doubles as the
    /// agent's spark capability", spark_engine.hpp). CRITICAL: the discriminator
    /// is capability membership, NEVER the text of an arm() rejection message
    /// (ADR-0021 platform-rejection) - a string match would silently misfile a
    /// rejection the day the message wording changes.
    [[nodiscard]] static RulePlacement classify(std::string_view spark_type_token,
                                                const std::set<SparkType>& supported) noexcept;

    /// The spark_key -> rule index (register-of-record). Populated at arm time
    /// in slice 2b; exposed here so that path and the tests can drive it.
    [[nodiscard]] SparkKeyRuleIndex& index() noexcept { return index_; }
    [[nodiscard]] const SparkKeyRuleIndex& index() const noexcept { return index_; }

    /// Install the per-rule sink (test seam at 2a; real evaluation at 2b).
    void set_rule_hit(RuleHitFn fn) { on_rule_hit_ = std::move(fn); }

    /// Resolve `ev` to its rule set via the index and dispatch each rule to the
    /// sink. This is the SparkEngine::QueuedHandler body once armed. At slice 2a
    /// the sink is evaluation-free (test-only); the assertion / drift / debounce
    /// / remediate logic migrates here from the legacy guards in slice 2b.
    /// @return the number of rules `ev` resolved to (0 for an unmapped key).
    std::size_t on_event(const SparkEvent& ev);

private:
    SparkKeyRuleIndex index_;
    RuleHitFn on_rule_hit_;
};

} // namespace yuzu::agent
