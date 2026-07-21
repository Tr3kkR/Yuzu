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

TEST_CASE("build_dialog_command: exact AppleScript shape, pinned against a typo regression",
          "[interaction]") {
    const auto cmd = build_dialog_command("Alert", "Something happened",
                                          "buttons {\"OK\"} default button \"OK\"");
    // Title/message land in the one interpolated display-dialog line; every
    // other fragment (try/on-error/end-try + both sentinel returns) is a
    // fixed literal a future edit could typo without any compiler diagnostic
    // — this pins the exact source text parse_dialog_result's contract
    // depends on.
    CHECK(cmd ==
          "osascript -e 'try' "
          "-e 'display dialog \"Something happened\" with title \"Alert\" "
          "buttons {\"OK\"} default button \"OK\"' "
          "-e 'return \"##BTN##\" & (button returned of result)' "
          "-e 'on error errMsg number errNum' "
          "-e 'return \"##ERR##\" & errNum' "
          "-e 'end try' 2>&1");
}

TEST_CASE("build_dialog_command: btn_spec is threaded through verbatim per button config",
          "[interaction]") {
    CHECK(build_dialog_command("T", "M", "buttons {\"OK\"} default button \"OK\"")
              .contains("buttons {\"OK\"} default button \"OK\"'"));
    CHECK(build_dialog_command("T", "M", "buttons {\"Cancel\", \"OK\"} default button \"OK\"")
              .contains("buttons {\"Cancel\", \"OK\"} default button \"OK\"'"));
    CHECK(build_dialog_command("T", "M", "buttons {\"No\", \"Yes\"} default button \"Yes\"")
              .contains("buttons {\"No\", \"Yes\"} default button \"Yes\"'"));
    // The sentinel/control-flow skeleton is identical regardless of button
    // config — only the one display-dialog line varies.
    for (auto* spec : {"buttons {\"OK\"} default button \"OK\"",
                       "buttons {\"Cancel\", \"OK\"} default button \"OK\"",
                       "buttons {\"No\", \"Yes\"} default button \"Yes\""}) {
        const auto cmd = build_dialog_command("T", "M", spec);
        CHECK(cmd.starts_with("osascript -e 'try' "));
        CHECK(cmd.ends_with("-e 'end try' 2>&1"));
        CHECK(cmd.contains("-e 'return \"##BTN##\" & (button returned of result)' "));
        CHECK(cmd.contains("-e 'on error errMsg number errNum' "));
        CHECK(cmd.contains("-e 'return \"##ERR##\" & errNum' "));
    }
}
