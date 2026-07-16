/**
 * test_interaction_parsers.cpp — pure interaction parse helpers
 * (interaction_parsers.hpp, macOS parity 1.3).
 *
 * The popen shell-out is the impure shell; the decision-shaped decoding of the
 * try/on-error `osascript display dialog` sentinel output is header-pure and
 * pinned here on every host (the licensing_parsers.hpp pattern). The honest-
 * status invariant is the point: anything that is not an offered button or the
 * -128 user-cancel decodes to not_reachable, never a fabricated response.
 */

#include "interaction_parsers.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace yuzu::interaction;

TEST_CASE("dialog: real button presses decode to their response", "[interaction]") {
    CHECK(parse_dialog_result("##BTN##OK") == DialogOutcome::ok);
    CHECK(parse_dialog_result("##BTN##Cancel") == DialogOutcome::cancel);
    CHECK(parse_dialog_result("##BTN##Yes") == DialogOutcome::yes);
    CHECK(parse_dialog_result("##BTN##No") == DialogOutcome::no);
    CHECK(parse_dialog_result("##BTN##OK\n") == DialogOutcome::ok); // trailing newline tolerated
}

TEST_CASE("dialog: -128 is user-cancel, every other error is not_reachable", "[interaction]") {
    CHECK(parse_dialog_result("##ERR##-128") == DialogOutcome::cancel);   // user canceled / escape
    CHECK(parse_dialog_result("##ERR##-1743") == DialogOutcome::not_reachable); // not authorised (TCC)
    CHECK(parse_dialog_result("##ERR##-600") == DialogOutcome::not_reachable);  // app not running
    CHECK(parse_dialog_result("##ERR##-1719") == DialogOutcome::not_reachable); // no window server
    CHECK(parse_dialog_result("##ERR##0") == DialogOutcome::not_reachable);     // any non-cancel number
}

TEST_CASE("dialog: unreachable session / missing binary / garbage is never a false button",
          "[interaction]") {
    CHECK(parse_dialog_result("") == DialogOutcome::not_reachable);
    // The daemon has no GUI session: osascript writes error prose (via 2>&1),
    // none of which starts with a sentinel.
    CHECK(parse_dialog_result(
              "execution error: Not authorized to send Apple events (-1743).") ==
          DialogOutcome::not_reachable);
    CHECK(parse_dialog_result("sh: osascript: command not found") ==
          DialogOutcome::not_reachable);
    // A sentinel prefix but a label we never offered — cannot map honestly.
    CHECK(parse_dialog_result("##BTN##Maybe") == DialogOutcome::not_reachable);
    // The pre-fix bug: bare "button returned:OK" prose no longer sneaks through
    // as ok — without a sentinel prefix it is not_reachable, and the real path
    // now emits ##BTN##OK anyway.
    CHECK(parse_dialog_result("button returned:OK") == DialogOutcome::not_reachable);
}
