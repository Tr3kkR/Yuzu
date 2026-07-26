#pragma once

/// @file audit_retention_rules.hpp
/// The decision rule of the audit retention clock guard (#2360), as a pure
/// function.
///
/// Split out of `AuditStore` deliberately, following the convention the other
/// server stores use for exactly this problem (`preflight_parse.hpp`,
/// `deployment_parse.hpp`, `network_perf_rules.hpp`, `compliance_eval.hpp`): a
/// pure decision function lives in its own header so it can be pinned by a
/// table test with no database, no clock and no fixture, WITHOUT widening the
/// store's public class surface. No sibling store exposes a public static, and
/// `AuditStore` should not be the first.
///
/// Why it is worth isolating: the retention guard's precedence went unpinned
/// long enough for two separate mutations to survive, because reaching it meant
/// standing up a seeded multi-pass integration test. As a free function it is
/// four bools in, one enum out.

namespace yuzu::server::audit_retention {

/// What the guard can conclude about one retention pass, in precedence order.
enum class Anomaly {
    None,     ///< Nothing to report; the pass may delete (paced by the cap).
    Wipe,     ///< This pass would expire every datable row.
    Step,     ///< The gap since the previous pass exceeds the absolute threshold.
    BadState, ///< The persisted clock reading cannot be used at all.
};

/// Classify one pass. PURE: no state, no side effects, so each condition can be
/// reasoned about and tested alone.
///
/// Precedence is BadState > Step > Wipe. A reading that cannot be trusted makes
/// the other two unreliable, and an elapsed-time step explains a wipe better
/// than the wipe explains itself. Note BadState and Step are in fact mutually
/// exclusive by construction -- `prev_unusable` implies the caller has
/// disengaged the previous reading, which `big_step` requires -- so that edge is
/// unreachable rather than merely ordered.
///
/// `!has_expired` short-circuits to None: with nothing to delete there is
/// nothing to hold back, and the only thing still worth reporting is an unusable
/// reading, which is why `prev_unusable` is tested first.
[[nodiscard]] constexpr Anomaly classify(bool has_expired, bool would_wipe, bool big_step,
                                         bool prev_unusable) noexcept {
    if (prev_unusable)
        return Anomaly::BadState;
    if (!has_expired)
        return Anomaly::None;
    if (big_step)
        return Anomaly::Step;
    return would_wipe ? Anomaly::Wipe : Anomaly::None;
}

} // namespace yuzu::server::audit_retention
