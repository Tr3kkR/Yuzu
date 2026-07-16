#pragma once

/**
 * interaction_parsers.hpp — pure parse helpers for the interaction plugin's
 * macOS message_box leg: decoding the sentinel-wrapped `osascript` output of a
 * try/on-error `display dialog` into a structured dialog outcome.
 *
 * Header-only and OS-free so the parsing is unit-tested on every host
 * (test_interaction_parsers.cpp — the licensing_parsers.hpp pattern); the
 * popen shell-out in interaction_plugin.cpp is the impure shell, and the
 * operator-supplied title/message it interpolates are already run through
 * sanitize() there, so nothing attacker-controlled reaches this parser.
 *
 * Honest-status invariant: an `osascript` that could not display the dialog
 * (no Aqua/GUI session on the root LaunchDaemon, a TCC denial, a missing
 * binary, or any unrecognised output) decodes to `not_reachable` — NEVER a
 * false button. The one error attributable to the user, AppleScript's -128
 * "user canceled", decodes to `cancel`; every other error is not_reachable.
 */

#include <string_view>

namespace yuzu::interaction {

/// Outcome of a macOS message_box dispatch, decoded from the osascript
/// sentinel output. `not_reachable` is the fail-closed default.
enum class DialogOutcome { ok, cancel, yes, no, not_reachable };

/// The osascript command wraps `display dialog` in try/on-error and returns
/// either `##BTN##<button>` (a real button press) or `##ERR##<errNum>` (an
/// AppleScript error). Error -128 is "user canceled"; anything else means the
/// dialog never reached a display server. Unrecognised output (empty, shell
/// error prose, a missing osascript binary) is treated as not_reachable — the
/// honest-status invariant, never a false `ok`.
[[nodiscard]] inline DialogOutcome parse_dialog_result(std::string_view out) {
    // Trim surrounding whitespace/newlines the shell may have left behind.
    while (!out.empty() && (out.front() == ' ' || out.front() == '\t' ||
                            out.front() == '\n' || out.front() == '\r'))
        out.remove_prefix(1);
    while (!out.empty() && (out.back() == ' ' || out.back() == '\t' ||
                            out.back() == '\n' || out.back() == '\r'))
        out.remove_suffix(1);

    constexpr std::string_view kBtn = "##BTN##";
    constexpr std::string_view kErr = "##ERR##";

    if (out.rfind(kBtn, 0) == 0) {
        const std::string_view button = out.substr(kBtn.size());
        // `display dialog` echoes the literal button label we specified.
        if (button == "OK") return DialogOutcome::ok;
        if (button == "Cancel") return DialogOutcome::cancel;
        if (button == "Yes") return DialogOutcome::yes;
        if (button == "No") return DialogOutcome::no;
        // A label we never offered — cannot map honestly to a response.
        return DialogOutcome::not_reachable;
    }

    if (out.rfind(kErr, 0) == 0) {
        const std::string_view err_num = out.substr(kErr.size());
        // -128 is AppleScript's "user canceled"; everything else (no window
        // server, not authorised, app not running, …) is a delivery failure.
        return err_num == "-128" ? DialogOutcome::cancel : DialogOutcome::not_reachable;
    }

    return DialogOutcome::not_reachable;
}

} // namespace yuzu::interaction
