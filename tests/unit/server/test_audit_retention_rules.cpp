/**
 * test_audit_retention_rules.cpp -- The retention guard's decision rule (#2360)
 *
 * `classify` is four bools in, one enum out, so its behaviour can be stated
 * EXHAUSTIVELY: all 16 inputs, each with the reason it maps where it does. That
 * is the point of extracting it. The integration tests in test_audit_store.cpp
 * cover the guard end-to-end through a seeded database; this file covers the
 * rule alone, which is where two mutations previously survived -- reaching the
 * precedence order meant standing up a multi-pass fixture, so nobody did.
 *
 * A table this complete is a mutation detector by construction: any change to
 * an operator, a return value, or the order of the four tests reddens at least
 * one row.
 */

#include "audit_retention_rules.hpp"

#include <catch2/catch_test_macros.hpp>

using yuzu::server::audit_retention::Anomaly;
using yuzu::server::audit_retention::classify;

TEST_CASE("audit classify: the whole truth table", "[audit_store][audit_rules]") {
    struct Row {
        bool has_expired;
        bool would_wipe;
        bool big_step;
        bool prev_unusable;
        Anomaly want;
        const char* why;
    };

    // All 2^4 = 16 inputs. `prev_unusable` first (it makes the others
    // unreliable), then `!has_expired` (nothing at risk), then step over wipe
    // (the step EXPLAINS the wipe).
    static constexpr Row kRows[] = {
        // prev_unusable dominates, whatever else is true.
        {false, false, false, true, Anomaly::BadState, "unusable reading, nothing expired"},
        {false, false, true, true, Anomaly::BadState, "unusable reading beats step"},
        {false, true, false, true, Anomaly::BadState, "unusable reading beats wipe"},
        {false, true, true, true, Anomaly::BadState, "unusable reading beats both"},
        {true, false, false, true, Anomaly::BadState, "unusable reading with rows expired"},
        {true, false, true, true, Anomaly::BadState, "unusable + step"},
        {true, true, false, true, Anomaly::BadState, "unusable + wipe"},
        {true, true, true, true, Anomaly::BadState, "unusable + step + wipe"},

        // Nothing expired: nothing is at risk, so nothing is reported. Note
        // would_wipe/big_step are still passed and still ignored -- a rule that
        // reported a step on an empty table would warn every pass on a quiet
        // server whose clock legitimately moved.
        {false, false, false, false, Anomaly::None, "quiet pass"},
        {false, false, true, false, Anomaly::None, "step but nothing to delete"},
        {false, true, false, false, Anomaly::None, "would-wipe cannot arise with nothing expired"},
        {false, true, true, false, Anomaly::None, "neither matters with nothing expired"},

        // Rows expired: step outranks wipe.
        {true, false, false, false, Anomaly::None, "ordinary expiry -- the common case"},
        {true, false, true, false, Anomaly::Step, "step with a survivor still reports"},
        {true, true, false, false, Anomaly::Wipe, "wipe with no step"},
        {true, true, true, false, Anomaly::Step, "step EXPLAINS the wipe, so it wins"},
    };

    static_assert(sizeof(kRows) / sizeof(kRows[0]) == 16, "the table must stay exhaustive");

    for (const Row& r : kRows) {
        INFO(r.why << " (has_expired=" << r.has_expired << " would_wipe=" << r.would_wipe
                   << " big_step=" << r.big_step << " prev_unusable=" << r.prev_unusable << ")");
        CHECK(classify(r.has_expired, r.would_wipe, r.big_step, r.prev_unusable) == r.want);
    }
}

TEST_CASE("audit classify: usable at compile time", "[audit_store][audit_rules]") {
    // `constexpr` is part of the contract, not decoration: it is what lets the
    // table above be `static constexpr` and what proves the function reads no
    // state. A future edit that reaches for a clock or a member breaks this.
    static_assert(classify(true, true, true, false) == Anomaly::Step);
    static_assert(classify(true, true, false, false) == Anomaly::Wipe);
    static_assert(classify(false, true, true, false) == Anomaly::None);
    static_assert(classify(false, false, false, true) == Anomaly::BadState);
    SUCCEED("compile-time evaluation asserted above");
}
