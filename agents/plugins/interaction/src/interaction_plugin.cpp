/**
 * interaction_plugin.cpp — Desktop user interaction plugin for Yuzu
 *
 * Actions:
 *   "notify"      — Show a desktop notification/toast.
 *   "message_box" — Show a modal message dialog, return button clicked.
 *   "input"       — Show a text input dialog, return entered text.
 *   "survey"      — Show a multi-question survey form, collect responses.
 *   "set_dnd"     — Enable/disable Do Not Disturb mode (suppress notifications).
 *
 * Output is pipe-delimited, one field per line via write_output():
 *   key|value
 *
 * Platform support:
 *   Windows — ShellNotifyIconW, MessageBoxW, PowerShell InputBox / Forms
 *   Linux   — notify-send, zenity
 *   macOS   — osascript (display notification, display dialog)
 *
 * Input validation: title/message/prompt fields are sanitized to prevent
 * command injection in popen calls. Only alphanumeric, spaces, and safe
 * punctuation are allowed.
 */

#include <yuzu/plugin.hpp>

#include "interaction_parsers.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#include <win_str.hpp>  // shared yuzu::win wide<->UTF-8 helpers (#1681)
#else
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess (arch-L1)
#endif

namespace {

// ── Input sanitization ────────────────────────────────────────────────────────

/**
 * Returns true if the character is safe for inclusion in shell commands.
 * Blocks backticks, $, |, ;, &, <, >, (, ), {, }, [, ], \, newlines,
 * single quotes, double quotes, and other shell metacharacters.
 *
 * M13: Single and double quotes are blocked on macOS/Linux because
 * osascript and zenity commands embed user text inside shell quotes.
 * Allowing quotes would enable shell injection via quote-breaking.
 * On Windows, native APIs (MessageBoxW, ShellNotifyIconW) are used
 * so quotes are safe — but we block them uniformly for defense-in-depth.
 */
bool is_safe_char(char c) {
    if (c >= 'a' && c <= 'z') return true;
    if (c >= 'A' && c <= 'Z') return true;
    if (c >= '0' && c <= '9') return true;
    // Safe punctuation: space, period, comma, hyphen, underscore, colon,
    // question mark, exclamation, slash, at, hash, percent, plus, equals.
    // Note: single quote and double quote are intentionally excluded (M13)
    // to prevent shell injection on macOS/Linux popen calls.
    switch (c) {
    case ' ':  case '.':  case ',':  case '-':  case '_':
    case ':':  case '?':  case '!':  case '/':  case '@':
    case '#':  case '%':  case '+':  case '=':  case '\t':
        return true;
    default:
        return false;
    }
}

/**
 * Sanitize a string for safe inclusion in shell commands.
 * Replaces any unsafe character with an underscore.
 * Returns empty string if input is empty.
 */
std::string sanitize(std::string_view input) {
    std::string result{input};
    for (auto& c : result) {
        if (!is_safe_char(c)) {
            c = '_';
        }
    }
    return result;
}

/**
 * Validate that a required parameter is non-empty. Writes an error
 * to ctx and returns false if validation fails.
 */
bool require_param(yuzu::CommandContext& ctx, std::string_view value,
                   std::string_view param_name) {
    if (value.empty()) {
        ctx.write_output(std::format("status|error|missing required parameter: {}",
                                     param_name));
        return false;
    }
    return true;
}

#if !defined(_WIN32)
// A generous per-call wall-clock bound for the interaction shell-outs. osascript
// dialogs are interactive and can legitimately block on a user, so this is
// deliberately long — it only fires on a genuinely wedged invocation.
constexpr std::chrono::seconds kInteractionCmdDeadline{120};

/**
 * Run a command and capture its output. Routed through the bounded,
 * fork-lock-covered, CLOEXEC-pipe runner (arch-L1) instead of a raw popen, whose
 * pipe is never CLOEXEC and whose fork is unserialized against the agent's other
 * launchers. `/bin/sh -c` preserves the exact shell semantics popen used.
 */
std::string run_command(const std::string& cmd) {
    auto res = yuzu::agent::run_bounded_subprocess(
        {"/bin/sh", "-c", cmd},
        yuzu::agent::SubprocessOptions{.deadline = kInteractionCmdDeadline});
    std::string output = res.output;
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r')) {
        output.pop_back();
    }
    return output;
}

/**
 * Run a command and return its exit code. Runner-backed (arch-L1). Returns the
 * -1 signal-death sentinel on a deadline/cancel kill, matching the old
 * pclose(!WIFEXITED) path.
 */
int run_command_status(const std::string& cmd) {
    auto res = yuzu::agent::run_bounded_subprocess(
        {"/bin/sh", "-c", cmd},
        yuzu::agent::SubprocessOptions{.deadline = kInteractionCmdDeadline});
    return res.exit_code;
}

/**
 * Result of run_command_capture(): the captured output plus the process
 * exit code, from a single run_bounded_subprocess round trip.
 */
struct CommandResult {
    std::string output;
    int exit_code = -1;
};

/**
 * Run a command via popen, capturing both its output and its exit status
 * in one invocation (unlike calling run_command() + run_command_status()
 * separately, which would run an interactive command — e.g. an osascript
 * dialog — twice).
 *
 * Used on macOS to tell "osascript ran and produced this text" apart from
 * "osascript failed" (non-zero exit, e.g. no reachable GUI session for the
 * daemon to display a dialog on) so failure is never mistaken for a
 * successful-but-unrecognized response.
 */
CommandResult run_command_capture(const std::string& cmd) {
    // One runner invocation yields both output and exit code (arch-L1) — the
    // same single-round-trip contract the popen version had, now bounded,
    // fork-lock-covered, and with CLOEXEC pipes. exit_code is WEXITSTATUS on a
    // natural exit, -1 on a deadline/cancel signal-kill.
    auto res = yuzu::agent::run_bounded_subprocess(
        {"/bin/sh", "-c", cmd},
        yuzu::agent::SubprocessOptions{.deadline = kInteractionCmdDeadline});
    CommandResult result;
    result.output = res.output;
    result.exit_code = res.exit_code;
    while (!result.output.empty() &&
           (result.output.back() == '\n' || result.output.back() == '\r')) {
        result.output.pop_back();
    }
    return result;
}
#endif // !_WIN32

// ── Platform: notify ──────────────────────────────────────────────────────────

#ifdef _WIN32

int platform_notify(yuzu::CommandContext& ctx, const std::string& title,
                    const std::string& message, const std::string& type) {
    // Convert strings to wide
    // wide conversion via the shared win_str.hpp helper (#1681). NOTE: to_wide uses an
    // explicit length, so an embedded NUL in title/message is no longer truncated at
    // conversion -- safe here only because wtitle/wmessage are consumed via c_str() by
    // NUL-terminated Win32 APIs (MessageBoxW / Shell_NotifyIconW). A future length-aware
    // consumer of operator-supplied text would need to strip/reject embedded NULs first.
    using yuzu::win::to_wide;

    std::wstring wtitle = to_wide(title);
    std::wstring wmessage = to_wide(message);

    // Create a hidden window for the notification
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = nullptr; // No window — use task tray
    nid.uID = 1;
    nid.uFlags = NIF_INFO | NIF_ICON | NIF_TIP;
    nid.dwInfoFlags = NIIF_NONE;

    // Map type to icon
    if (type == "warning") {
        nid.dwInfoFlags = NIIF_WARNING;
    } else if (type == "error") {
        nid.dwInfoFlags = NIIF_ERROR;
    } else {
        nid.dwInfoFlags = NIIF_INFO;
    }

    wcsncpy_s(nid.szInfoTitle, wtitle.c_str(), _TRUNCATE);
    wcsncpy_s(nid.szInfo, wmessage.c_str(), _TRUNCATE);
    wcsncpy_s(nid.szTip, L"Yuzu Agent", _TRUNCATE);

    // Load default application icon
    nid.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(32516)); // IDI_INFORMATION

    Shell_NotifyIconW(NIM_ADD, &nid);
    Shell_NotifyIconW(NIM_MODIFY, &nid);

    // Brief sleep so the notification is visible, then clean up
    Sleep(100);
    Shell_NotifyIconW(NIM_DELETE, &nid);

    ctx.write_output("status|ok");
    return 0;
}

#elif defined(__APPLE__)

int platform_notify(yuzu::CommandContext& ctx, const std::string& title,
                    const std::string& message, const std::string& /*type*/) {
    std::string safe_title = sanitize(title);
    std::string safe_msg = sanitize(message);

    std::string cmd = std::format(
        "osascript -e 'display notification \"{}\" with title \"{}\"' 2>&1",
        safe_msg, safe_title);

    int rc = run_command_status(cmd);
    if (rc == 0) {
        ctx.write_output("status|ok");
        return 0;
    }
    // Non-zero exit from osascript on a daemon most often means there is
    // no reachable GUI session to post the notification to. Report that
    // honestly rather than a bare "failed" (which reads like a bug in
    // this plugin rather than an environment limitation) — but still
    // return non-zero so the agent core records this command as a
    // terminal FAILURE rather than SUCCESS, since nothing was ever shown
    // to the user.
    ctx.write_output("status|unavailable|no reachable GUI session");
    return 1;
}

#elif defined(__linux__)

int platform_notify(yuzu::CommandContext& ctx, const std::string& title,
                    const std::string& message, const std::string& type) {
    std::string safe_title = sanitize(title);
    std::string safe_msg = sanitize(message);

    // Map type to urgency
    std::string urgency = "normal";
    if (type == "error") urgency = "critical";
    else if (type == "warning") urgency = "normal";
    else urgency = "low";

    std::string cmd = std::format(
        "notify-send -u {} '{}' '{}' 2>&1",
        urgency, safe_title, safe_msg);

    int rc = run_command_status(cmd);
    if (rc == 0) {
        ctx.write_output("status|ok");
    } else {
        ctx.write_output("status|error|notify-send not available or failed");
    }
    return 0;
}

#else

int platform_notify(yuzu::CommandContext& ctx, const std::string& /*title*/,
                    const std::string& /*message*/, const std::string& /*type*/) {
    ctx.write_output("status|error|platform not supported");
    return 1;
}

#endif

// ── Platform: message_box ─────────────────────────────────────────────────────

#ifdef _WIN32

int platform_message_box(yuzu::CommandContext& ctx, const std::string& title,
                         const std::string& message, const std::string& buttons) {
    // wide conversion via the shared win_str.hpp helper (#1681). NOTE: to_wide uses an
    // explicit length, so an embedded NUL in title/message is no longer truncated at
    // conversion -- safe here only because wtitle/wmessage are consumed via c_str() by
    // NUL-terminated Win32 APIs (MessageBoxW / Shell_NotifyIconW). A future length-aware
    // consumer of operator-supplied text would need to strip/reject embedded NULs first.
    using yuzu::win::to_wide;

    UINT mb_type = MB_TOPMOST | MB_SETFOREGROUND;
    if (buttons == "okcancel") {
        mb_type |= MB_OKCANCEL;
    } else if (buttons == "yesno") {
        mb_type |= MB_YESNO;
    } else {
        mb_type |= MB_OK;
    }

    std::wstring wtitle = to_wide(title);
    std::wstring wmessage = to_wide(message);

    int result = MessageBoxW(nullptr, wmessage.c_str(), wtitle.c_str(), mb_type);

    switch (result) {
    case IDOK:     ctx.write_output("response|ok");     break;
    case IDCANCEL: ctx.write_output("response|cancel"); break;
    case IDYES:    ctx.write_output("response|yes");    break;
    case IDNO:     ctx.write_output("response|no");     break;
    default:       ctx.write_output("response|ok");     break;
    }
    return 0;
}

#elif defined(__APPLE__)

int platform_message_box(yuzu::CommandContext& ctx, const std::string& title,
                         const std::string& message, const std::string& buttons) {
    std::string safe_title = sanitize(title);
    std::string safe_msg = sanitize(message);

    std::string btn_spec;
    if (buttons == "yesno") {
        btn_spec = "buttons {\"No\", \"Yes\"} default button \"Yes\"";
    } else if (buttons == "okcancel") {
        btn_spec = "buttons {\"Cancel\", \"OK\"} default button \"OK\"";
    } else {
        btn_spec = "buttons {\"OK\"} default button \"OK\"";
    }

    // Wrap the dialog in try/on-error and return a sentinel so an unreachable
    // display server (this agent is a root LaunchDaemon with no Aqua/GUI
    // session — see docs/agent-privilege-model.md) is reported honestly as
    // not_reachable instead of a false button. The bare substring match this
    // replaced fell through to "response|ok" for ANY unrecognised output,
    // claiming the user clicked OK on a dialog that was never shown. The
    // try/on-error idiom mirrors platform_input; capturing the error NUMBER
    // keeps a genuine user-cancel (-128) distinct from an undeliverable
    // session.
    //
    // Documented shell exception (docs/cpp-conventions.md, shell/process
    // boundaries): this osascript invocation is built via the plugin's
    // existing popen-based run_command helper rather than argv-style
    // execution because AppleScript has no non-shell invocation form and
    // Yuzu has no cross-platform subprocess helper today. safe_msg/
    // safe_title are already sanitize()d (unsafe chars replaced with '_',
    // so no shell/AppleScript metacharacter reaches the string); btn_spec
    // and every sentinel/-e fragment are fixed compile-time literals — no
    // operator-supplied text controls the command's shape.
    std::string cmd = yuzu::interaction::build_dialog_command(safe_title, safe_msg, btn_spec);

    switch (yuzu::interaction::parse_dialog_result(run_command(cmd))) {
    case yuzu::interaction::DialogOutcome::ok:
        ctx.write_output("response|ok");
        break;
    case yuzu::interaction::DialogOutcome::cancel:
        ctx.write_output("response|cancel");
        break;
    case yuzu::interaction::DialogOutcome::yes:
        ctx.write_output("response|yes");
        break;
    case yuzu::interaction::DialogOutcome::no:
        ctx.write_output("response|no");
        break;
    case yuzu::interaction::DialogOutcome::not_reachable:
        // No GUI session / TCC denial / osascript failure — honest status,
        // never a fabricated button. Rides the new `status` result column AND
        // returns terminal FAILURE so a generic success/failure consumer (the
        // executions drawer, retry/automation logic) does not read a dialog
        // that was never shown as SUCCESS. This matches the sibling actions
        // notify/input/survey, which already return 1 for the identical
        // undeliverable-session condition.
        ctx.write_output("status|not_reachable");
        return 1;
    }
    return 0;
}

#elif defined(__linux__)

int platform_message_box(yuzu::CommandContext& ctx, const std::string& title,
                         const std::string& message, const std::string& buttons) {
    std::string safe_title = sanitize(title);
    std::string safe_msg = sanitize(message);

    if (buttons == "yesno") {
        std::string cmd = std::format(
            "zenity --question --title='{}' --text='{}' 2>/dev/null",
            safe_title, safe_msg);
        int rc = run_command_status(cmd);
        ctx.write_output(rc == 0 ? "response|yes" : "response|no");
    } else if (buttons == "okcancel") {
        std::string cmd = std::format(
            "zenity --question --title='{}' --text='{}' "
            "--ok-label='OK' --cancel-label='Cancel' 2>/dev/null",
            safe_title, safe_msg);
        int rc = run_command_status(cmd);
        ctx.write_output(rc == 0 ? "response|ok" : "response|cancel");
    } else {
        std::string cmd = std::format(
            "zenity --info --title='{}' --text='{}' 2>/dev/null",
            safe_title, safe_msg);
        run_command_status(cmd);
        ctx.write_output("response|ok");
    }
    return 0;
}

#else

int platform_message_box(yuzu::CommandContext& ctx, const std::string& /*title*/,
                         const std::string& /*message*/, const std::string& /*buttons*/) {
    ctx.write_output("status|error|platform not supported");
    return 1;
}

#endif

// ── Platform: input ───────────────────────────────────────────────────────────

#ifdef _WIN32

int platform_input(yuzu::CommandContext& ctx, const std::string& title,
                   const std::string& prompt, const std::string& default_value) {
    // Use PowerShell to show an InputBox dialog via VB interaction
    std::string safe_title = sanitize(title);
    std::string safe_prompt = sanitize(prompt);
    std::string safe_default = sanitize(default_value);

    // PowerShell script using .NET VisualBasic.Interaction (available on all Windows)
    std::string ps_script = std::format(
        "Add-Type -AssemblyName Microsoft.VisualBasic; "
        "$result = [Microsoft.VisualBasic.Interaction]::InputBox('{}', '{}', '{}'); "
        "if ($result -eq $null -or $result -eq '') {{ Write-Output '##CANCELLED##' }} "
        "else {{ Write-Output $result }}",
        safe_prompt, safe_title, safe_default);

    std::string cmd = "powershell.exe -NoProfile -NonInteractive -Command \"" + ps_script + "\"";

    std::string output;
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) {
        ctx.write_output("status|error|failed to launch PowerShell");
        return 1;
    }

    std::array<char, 256> buf{};
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe) != nullptr) {
        output += buf.data();
    }
    _pclose(pipe);

    // Trim trailing whitespace
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r' ||
                                output.back() == ' ')) {
        output.pop_back();
    }

    if (output == "##CANCELLED##" || output.empty()) {
        ctx.write_output("cancelled|true");
    } else {
        ctx.write_output(std::format("response|{}", output));
    }
    return 0;
}

#elif defined(__APPLE__)

int platform_input(yuzu::CommandContext& ctx, const std::string& title,
                   const std::string& prompt, const std::string& default_value) {
    std::string safe_title = sanitize(title);
    std::string safe_prompt = sanitize(prompt);
    std::string safe_default = sanitize(default_value);

    // "on error number err_num" + re-raising every code other than -128
    // (the AppleScript "User canceled" error) ensures only a genuine Cancel
    // click is converted to the "##CANCELLED##" sentinel at exit 0; any
    // other failure (e.g. no reachable GUI session) propagates as a
    // non-zero osascript exit so it is never misreported as cancellation.
    std::string cmd = std::format(
        "osascript -e 'try' -e 'set result to text returned of "
        "(display dialog \"{}\" with title \"{}\" default answer \"{}\")' "
        "-e 'return result' -e 'on error number err_num' "
        "-e 'if err_num is -128 then return \"##CANCELLED##\"' "
        "-e 'error number err_num' -e 'end try' 2>&1",
        safe_prompt, safe_title, safe_default);

    auto result = run_command_capture(cmd);

    // The exit-code/output decision is the pure classify_input_capture (qe-L2,
    // unit-tested): a non-zero exit is a delivery failure reported as an honest
    // status|unavailable (never the error text wrapped as a response), the
    // ##CANCELLED## sentinel is a user cancel, everything else is real input.
    auto decision = yuzu::interaction::classify_input_capture(result.exit_code, result.output);
    ctx.write_output(decision.output_line);
    return decision.rc;
}

#elif defined(__linux__)

int platform_input(yuzu::CommandContext& ctx, const std::string& title,
                   const std::string& prompt, const std::string& default_value) {
    std::string safe_title = sanitize(title);
    std::string safe_prompt = sanitize(prompt);
    std::string safe_default = sanitize(default_value);

    // Capture output and exit code in a single invocation using a
    // shell wrapper that appends the exit status on a separate line.
    std::string cmd = std::format(
        "sh -c 'OUT=$(zenity --entry --title='\"'\"'{}'\"'\"' "
        "--text='\"'\"'{}'\"'\"' --entry-text='\"'\"'{}'\"'\"' 2>/dev/null); "
        "RC=$?; echo \"$OUT\"; echo \"__RC=$RC\"'",
        safe_title, safe_prompt, safe_default);

    std::string output = run_command(cmd);

    // Parse the exit code from the last line
    int rc = 1;
    std::string user_text;
    auto rc_pos = output.rfind("__RC=");
    if (rc_pos != std::string::npos) {
        auto rc_str = output.substr(rc_pos + 5);
        std::from_chars(rc_str.data(), rc_str.data() + rc_str.size(), rc);
        user_text = output.substr(0, rc_pos);
        // Trim trailing newline from user text
        while (!user_text.empty() &&
               (user_text.back() == '\n' || user_text.back() == '\r')) {
            user_text.pop_back();
        }
    }

    if (rc != 0) {
        ctx.write_output("cancelled|true");
    } else {
        ctx.write_output(std::format("response|{}", user_text));
    }
    return 0;
}

#else

int platform_input(yuzu::CommandContext& ctx, const std::string& /*title*/,
                   const std::string& /*prompt*/, const std::string& /*default_value*/) {
    ctx.write_output("status|error|platform not supported");
    return 1;
}

#endif

// ── Survey question types ─────────────────────────────────────────────────────

struct SurveyQuestion {
    std::string prompt;
    std::string type;  // "text", "yesno", "choice"
    std::vector<std::string> choices;
};

/**
 * Parse the questions JSON parameter.
 * Expected format: [{prompt:"...", type:"text|yesno|choice", choices:[...]}]
 *
 * Uses minimal manual parsing to avoid adding nlohmann_json as a plugin
 * dependency. The questions JSON is validated server-side before dispatch.
 */
std::vector<SurveyQuestion> parse_questions_json(std::string_view json) {
    std::vector<SurveyQuestion> result;
    // Minimal JSON array-of-objects parser
    // Find each {...} block inside the outer [...]
    size_t pos = json.find('[');
    if (pos == std::string_view::npos) return result;

    while (pos < json.size()) {
        auto obj_start = json.find('{', pos);
        if (obj_start == std::string_view::npos) break;
        auto obj_end = json.find('}', obj_start);
        if (obj_end == std::string_view::npos) break;

        auto obj = json.substr(obj_start, obj_end - obj_start + 1);
        SurveyQuestion q;

        // Extract "prompt":"..."
        auto extract_str = [&](std::string_view key) -> std::string {
            auto kpos = obj.find(key);
            if (kpos == std::string_view::npos) return {};
            auto colon = obj.find(':', kpos + key.size());
            if (colon == std::string_view::npos) return {};
            auto qstart = obj.find('"', colon + 1);
            if (qstart == std::string_view::npos) return {};
            auto qend = obj.find('"', qstart + 1);
            if (qend == std::string_view::npos) return {};
            return std::string{obj.substr(qstart + 1, qend - qstart - 1)};
        };

        q.prompt = extract_str("\"prompt\"");
        q.type = extract_str("\"type\"");
        if (q.type.empty()) q.type = "text";

        // Extract choices array if present
        if (q.type == "choice") {
            auto carr = obj.find("\"choices\"");
            if (carr != std::string_view::npos) {
                auto arr_start = obj.find('[', carr);
                auto arr_end = obj.find(']', arr_start);
                if (arr_start != std::string_view::npos && arr_end != std::string_view::npos) {
                    auto arr = obj.substr(arr_start, arr_end - arr_start + 1);
                    size_t cpos = 0;
                    while (cpos < arr.size()) {
                        auto cs = arr.find('"', cpos);
                        if (cs == std::string_view::npos) break;
                        auto ce = arr.find('"', cs + 1);
                        if (ce == std::string_view::npos) break;
                        q.choices.emplace_back(arr.substr(cs + 1, ce - cs - 1));
                        cpos = ce + 1;
                    }
                }
            }
        }

        if (!q.prompt.empty())
            result.push_back(std::move(q));

        pos = obj_end + 1;
    }
    return result;
}

// ── Platform: survey ──────────────────────────────────────────────────────────

#ifdef _WIN32

int platform_survey(yuzu::CommandContext& ctx, const std::string& title,
                    const std::vector<SurveyQuestion>& questions) {
    // Build a PowerShell script that creates a Windows.Forms dialog
    std::string ps;
    ps += "Add-Type -AssemblyName System.Windows.Forms; ";
    ps += "$form = New-Object System.Windows.Forms.Form; ";
    ps += std::format("$form.Text = '{}'; ", sanitize(title));
    ps += "$form.Width = 450; $form.StartPosition = 'CenterScreen'; ";
    ps += "$form.AutoSize = $true; $form.AutoSizeMode = 'GrowOnly'; ";
    ps += "$form.FormBorderStyle = 'FixedDialog'; $form.MaximizeBox = $false; ";
    ps += "$y = 10; $controls = @(); ";

    for (size_t i = 0; i < questions.size(); ++i) {
        const auto& q = questions[i];
        std::string safe_prompt = sanitize(q.prompt);
        std::string idx = std::to_string(i);

        // Label
        ps += std::format(
            "$lbl{} = New-Object System.Windows.Forms.Label; "
            "$lbl{}.Text = '{}'; $lbl{}.Location = New-Object System.Drawing.Point(10,$y); "
            "$lbl{}.AutoSize = $true; $form.Controls.Add($lbl{}); $y += 22; ",
            idx, idx, safe_prompt, idx, idx, idx);

        if (q.type == "yesno") {
            ps += std::format(
                "$cb{} = New-Object System.Windows.Forms.CheckBox; "
                "$cb{}.Text = 'Yes'; $cb{}.Location = New-Object System.Drawing.Point(10,$y); "
                "$form.Controls.Add($cb{}); $controls += $cb{}; $y += 30; ",
                idx, idx, idx, idx, idx);
        } else if (q.type == "choice" && !q.choices.empty()) {
            ps += std::format(
                "$cmb{} = New-Object System.Windows.Forms.ComboBox; "
                "$cmb{}.DropDownStyle = 'DropDownList'; "
                "$cmb{}.Location = New-Object System.Drawing.Point(10,$y); "
                "$cmb{}.Width = 400; ",
                idx, idx, idx, idx);
            for (const auto& ch : q.choices) {
                ps += std::format("$cmb{}.Items.Add('{}') | Out-Null; ", idx, sanitize(ch));
            }
            ps += std::format(
                "if($cmb{}.Items.Count -gt 0){{ $cmb{}.SelectedIndex = 0 }}; "
                "$form.Controls.Add($cmb{}); $controls += $cmb{}; $y += 30; ",
                idx, idx, idx, idx);
        } else {
            // text
            ps += std::format(
                "$txt{} = New-Object System.Windows.Forms.TextBox; "
                "$txt{}.Location = New-Object System.Drawing.Point(10,$y); "
                "$txt{}.Width = 400; "
                "$form.Controls.Add($txt{}); $controls += $txt{}; $y += 30; ",
                idx, idx, idx, idx, idx);
        }
    }

    // OK/Cancel buttons
    ps += "$y += 10; ";
    ps += "$ok = New-Object System.Windows.Forms.Button; $ok.Text = 'OK'; ";
    ps += "$ok.Location = New-Object System.Drawing.Point(250,$y); ";
    ps += "$ok.DialogResult = [System.Windows.Forms.DialogResult]::OK; ";
    ps += "$form.Controls.Add($ok); $form.AcceptButton = $ok; ";
    ps += "$cancel = New-Object System.Windows.Forms.Button; $cancel.Text = 'Cancel'; ";
    ps += "$cancel.Location = New-Object System.Drawing.Point(340,$y); ";
    ps += "$cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; ";
    ps += "$form.Controls.Add($cancel); $form.CancelButton = $cancel; ";
    ps += "$form.TopMost = $true; ";
    ps += "$result = $form.ShowDialog(); ";
    ps += "if($result -eq [System.Windows.Forms.DialogResult]::Cancel){ ";
    ps += "  Write-Output '##CANCELLED##'; exit; } ";

    // Collect results
    ps += "foreach($c in $controls){ ";
    ps += "  if($c -is [System.Windows.Forms.CheckBox]){ ";
    ps += "    if($c.Checked){ Write-Output 'yes' } else { Write-Output 'no' } ";
    ps += "  } elseif($c -is [System.Windows.Forms.ComboBox]){ ";
    ps += "    Write-Output $c.SelectedItem ";
    ps += "  } else { Write-Output $c.Text } ";
    ps += "} ";

    std::string cmd = "powershell.exe -NoProfile -NonInteractive -Command \"" + ps + "\"";

    std::string output;
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) {
        ctx.write_output("status|error|failed to launch PowerShell");
        return 1;
    }

    std::array<char, 256> buf{};
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe) != nullptr) {
        output += buf.data();
    }
    _pclose(pipe);

    // Trim trailing whitespace
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r' ||
                                output.back() == ' ')) {
        output.pop_back();
    }

    if (output == "##CANCELLED##") {
        ctx.write_output("cancelled|true");
        return 0;
    }

    // Parse line-by-line responses
    ctx.write_output("cancelled|false");
    std::istringstream iss(output);
    std::string line;
    size_t qi = 0;
    while (std::getline(iss, line) && qi < questions.size()) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        ctx.write_output(std::format("answer_{}|{}", qi, line));
        ++qi;
    }
    ctx.write_output(std::format("question_count|{}", questions.size()));
    return 0;
}

#elif defined(__APPLE__)

int platform_survey(yuzu::CommandContext& ctx, const std::string& title,
                    const std::vector<SurveyQuestion>& questions) {
    // macOS: sequential osascript dialogs for each question. "cancelled|false"
    // is emitted only after every question below has succeeded (see the tail
    // of this function) — emitting it up front here would contradict a later
    // "status|unavailable" or "cancelled|true" for the very same survey.
    for (size_t i = 0; i < questions.size(); ++i) {
        const auto& q = questions[i];
        std::string safe_prompt = sanitize(q.prompt);
        std::string safe_title = sanitize(title);

        if (q.type == "yesno") {
            std::string cmd = std::format(
                "osascript -e 'try' -e 'set r to button returned of "
                "(display dialog \"{}\" with title \"{}\" buttons {{\"No\", \"Yes\"}} "
                "default button \"Yes\")' -e 'return r' "
                "-e 'on error number err_num' "
                "-e 'if err_num is -128 then return \"##CANCELLED##\"' "
                "-e 'error number err_num' -e 'end try' 2>&1",
                safe_prompt, safe_title);
            auto result = run_command_capture(cmd);
            if (result.exit_code != 0) {
                // osascript failed outright (not the AppleScript-level "on
                // error", which exits 0) — no reachable GUI session. Stop
                // the survey rather than fabricate an answer. Non-zero
                // return so the agent core records this command as a
                // terminal FAILURE rather than SUCCESS.
                ctx.write_output("status|unavailable|no reachable GUI session");
                return 1;
            }
            if (result.output == "##CANCELLED##") {
                ctx.write_output("cancelled|true");
                return 0;
            }
            // The AppleScript's button set is exactly {"No", "Yes"}, so a
            // successful invocation should return exactly one of those two
            // labels. Match exactly rather than by substring — anything
            // else is unrecognized output, not a "no" answer, so it is
            // reported honestly (non-zero) instead of fabricated.
            if (result.output == "Yes") {
                ctx.write_output(std::format("answer_{}|yes", i));
            } else if (result.output == "No") {
                ctx.write_output(std::format("answer_{}|no", i));
            } else {
                ctx.write_output("status|unavailable|unrecognized osascript response");
                return 1;
            }

        } else if (q.type == "choice" && !q.choices.empty()) {
            // Build AppleScript choose from list
            std::string items;
            std::vector<std::string> safe_choices;
            safe_choices.reserve(q.choices.size());
            for (size_t ci = 0; ci < q.choices.size(); ++ci) {
                if (ci > 0) items += ", ";
                safe_choices.push_back(sanitize(q.choices[ci]));
                items += "\"" + safe_choices.back() + "\"";
            }
            std::string cmd =
                "osascript -e 'try' -e 'set r to choose from list {" + items +
                "} with title \"" + safe_title + "\" with prompt \"" + safe_prompt +
                "\"' -e 'if r is false then' -e 'return \"##CANCELLED##\"' "
                "-e 'else' -e 'return item 1 of r' -e 'end if' "
                "-e 'on error number err_num' "
                "-e 'if err_num is -128 then return \"##CANCELLED##\"' "
                "-e 'error number err_num' -e 'end try' 2>&1";
            auto result = run_command_capture(cmd);
            if (result.exit_code != 0) {
                // Non-zero return so the agent core records this command
                // as a terminal FAILURE rather than SUCCESS.
                ctx.write_output("status|unavailable|no reachable GUI session");
                return 1;
            }
            if (result.output == "##CANCELLED##") {
                ctx.write_output("cancelled|true");
                return 0;
            }
            // "choose from list" can only return an item from the list we
            // supplied. Confirm the output matches one of the sanitized
            // choices we offered rather than trusting it blindly — output
            // that matches none of them is unrecognized, not a genuine
            // selection, so it is reported honestly (non-zero) instead of
            // fabricated.
            bool recognized = std::find(safe_choices.begin(), safe_choices.end(),
                                        result.output) != safe_choices.end();
            if (!recognized) {
                ctx.write_output("status|unavailable|unrecognized osascript response");
                return 1;
            }
            ctx.write_output(std::format("answer_{}|{}", i, result.output));

        } else {
            // text input
            std::string cmd = std::format(
                "osascript -e 'try' -e 'set r to text returned of "
                "(display dialog \"{}\" with title \"{}\" default answer \"\")' "
                "-e 'return r' -e 'on error number err_num' "
                "-e 'if err_num is -128 then return \"##CANCELLED##\"' "
                "-e 'error number err_num' -e 'end try' 2>&1",
                safe_prompt, safe_title);
            auto result = run_command_capture(cmd);
            if (result.exit_code != 0) {
                // Non-zero return so the agent core records this command
                // as a terminal FAILURE rather than SUCCESS.
                ctx.write_output("status|unavailable|no reachable GUI session");
                return 1;
            }
            if (result.output == "##CANCELLED##") {
                ctx.write_output("cancelled|true");
                return 0;
            }
            ctx.write_output(std::format("answer_{}|{}", i, result.output));
        }
    }
    // All questions completed without failure or cancellation — only now is
    // it accurate to report the survey as not cancelled.
    ctx.write_output("cancelled|false");
    ctx.write_output(std::format("question_count|{}", questions.size()));
    return 0;
}

#elif defined(__linux__)

int platform_survey(yuzu::CommandContext& ctx, const std::string& title,
                    const std::vector<SurveyQuestion>& questions) {
    // Linux: sequential zenity dialogs for each question
    ctx.write_output("cancelled|false");

    for (size_t i = 0; i < questions.size(); ++i) {
        const auto& q = questions[i];
        std::string safe_prompt = sanitize(q.prompt);
        std::string safe_title = sanitize(title);

        if (q.type == "yesno") {
            std::string cmd = std::format(
                "zenity --question --title='{}' --text='{}' 2>/dev/null",
                safe_title, safe_prompt);
            int rc = run_command_status(cmd);
            if (rc == 5) { // zenity returns 5 for timeout/ESC, 1 for No
                ctx.write_output("cancelled|true");
                return 0;
            }
            ctx.write_output(std::format("answer_{}|{}", i, rc == 0 ? "yes" : "no"));

        } else if (q.type == "choice" && !q.choices.empty()) {
            std::string items;
            for (const auto& ch : q.choices) {
                items += " '" + sanitize(ch) + "'";
            }
            std::string cmd = std::format(
                "sh -c 'OUT=$(zenity --list --title='\"'\"'{}'\"'\"' "
                "--text='\"'\"'{}'\"'\"' --column=Option{} 2>/dev/null); "
                "RC=$?; echo \"$OUT\"; echo \"__RC=$RC\"'",
                safe_title, safe_prompt, items);
            std::string output = run_command(cmd);

            int rc = 1;
            std::string chosen;
            auto rc_pos = output.rfind("__RC=");
            if (rc_pos != std::string::npos) {
                auto rc_str = output.substr(rc_pos + 5);
                std::from_chars(rc_str.data(), rc_str.data() + rc_str.size(), rc);
                chosen = output.substr(0, rc_pos);
                while (!chosen.empty() && (chosen.back() == '\n' || chosen.back() == '\r'))
                    chosen.pop_back();
            }
            if (rc != 0) {
                ctx.write_output("cancelled|true");
                return 0;
            }
            ctx.write_output(std::format("answer_{}|{}", i, chosen));

        } else {
            // text entry
            std::string cmd = std::format(
                "sh -c 'OUT=$(zenity --entry --title='\"'\"'{}'\"'\"' "
                "--text='\"'\"'{}'\"'\"' 2>/dev/null); "
                "RC=$?; echo \"$OUT\"; echo \"__RC=$RC\"'",
                safe_title, safe_prompt);
            std::string output = run_command(cmd);

            int rc = 1;
            std::string user_text;
            auto rc_pos = output.rfind("__RC=");
            if (rc_pos != std::string::npos) {
                auto rc_str = output.substr(rc_pos + 5);
                std::from_chars(rc_str.data(), rc_str.data() + rc_str.size(), rc);
                user_text = output.substr(0, rc_pos);
                while (!user_text.empty() &&
                       (user_text.back() == '\n' || user_text.back() == '\r'))
                    user_text.pop_back();
            }
            if (rc != 0) {
                ctx.write_output("cancelled|true");
                return 0;
            }
            ctx.write_output(std::format("answer_{}|{}", i, user_text));
        }
    }
    ctx.write_output(std::format("question_count|{}", questions.size()));
    return 0;
}

#else

int platform_survey(yuzu::CommandContext& ctx, const std::string& /*title*/,
                    const std::vector<SurveyQuestion>& /*questions*/) {
    ctx.write_output("status|error|platform not supported");
    return 1;
}

#endif

} // namespace

class InteractionPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "interaction"; }
    std::string_view version() const noexcept override { return "0.3.0"; }
    std::string_view description() const noexcept override {
        return "Desktop user interaction — notifications, message boxes, input dialogs, surveys, DND";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {
            "notify", "message_box", "input", "survey", "set_dnd", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        plugin_ctx_ = ctx.raw();
        // Restore DND state from KV store
        yuzu::PluginContext wrap{plugin_ctx_};
        auto dnd_val = wrap.storage_get("dnd_enabled");
        if (dnd_val == "true") {
            dnd_enabled_ = true;
            auto exp_str = wrap.storage_get("dnd_expires_at");
            if (!exp_str.empty()) {
                int64_t exp = 0;
                std::from_chars(exp_str.data(), exp_str.data() + exp_str.size(), exp);
                dnd_expires_at_ = exp;
            }
        }
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params params) override {
        if (action == "notify")
            return do_notify(ctx, params);
        if (action == "message_box")
            return do_message_box(ctx, params);
        if (action == "input")
            return do_input(ctx, params);
        if (action == "survey")
            return do_survey(ctx, params);
        if (action == "set_dnd")
            return do_set_dnd(ctx, params);

        ctx.write_output(std::format("status|error|unknown action: {}", action));
        return 1;
    }

private:
    int do_notify(yuzu::CommandContext& ctx, yuzu::Params params) {
        // Check DND — suppress notifications when active
        if (is_dnd_active()) {
            ctx.write_output("status|suppressed|do not disturb is active");
            return 0;
        }

        auto title = params.get("title");
        auto message = params.get("message");
        auto type = params.get("type", "info");

        if (!require_param(ctx, title, "title")) return 1;
        if (!require_param(ctx, message, "message")) return 1;

        // Validate type
        if (type != "info" && type != "warning" && type != "error") {
            ctx.write_output("status|error|invalid type: must be info, warning, or error");
            return 1;
        }

        return platform_notify(ctx, sanitize(title), sanitize(message),
                               std::string{type});
    }

    int do_message_box(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto title = params.get("title");
        auto message = params.get("message");
        auto buttons = params.get("buttons", "ok");

        if (!require_param(ctx, title, "title")) return 1;
        if (!require_param(ctx, message, "message")) return 1;

        // Validate buttons
        if (buttons != "ok" && buttons != "okcancel" && buttons != "yesno") {
            ctx.write_output("status|error|invalid buttons: must be ok, okcancel, or yesno");
            return 1;
        }

        return platform_message_box(ctx, sanitize(title), sanitize(message),
                                    std::string{buttons});
    }

    int do_input(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto title = params.get("title");
        auto prompt = params.get("prompt");
        auto default_value = params.get("default_value", "");

        if (!require_param(ctx, title, "title")) return 1;
        if (!require_param(ctx, prompt, "prompt")) return 1;

        return platform_input(ctx, sanitize(title), sanitize(prompt),
                              sanitize(default_value));
    }

    int do_survey(yuzu::CommandContext& ctx, yuzu::Params params) {
        // Check DND
        if (is_dnd_active()) {
            ctx.write_output("status|suppressed|do not disturb is active");
            return 0;
        }

        auto title = params.get("title");
        auto questions_json = params.get("questions");

        if (!require_param(ctx, title, "title")) return 1;
        if (!require_param(ctx, questions_json, "questions")) return 1;

        auto questions = parse_questions_json(questions_json);
        if (questions.empty()) {
            ctx.write_output("status|error|no valid questions parsed from JSON");
            return 1;
        }

        return platform_survey(ctx, sanitize(title), questions);
    }

    int do_set_dnd(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto enabled_str = params.get("enabled", "true");
        auto duration_str = params.get("duration_minutes", "0");

        bool enabled = (enabled_str == "true" || enabled_str == "1" || enabled_str == "yes");
        int duration_minutes = 0;
        if (!duration_str.empty()) {
            std::from_chars(duration_str.data(),
                            duration_str.data() + duration_str.size(),
                            duration_minutes);
        }

        dnd_enabled_ = enabled;

        if (enabled && duration_minutes > 0) {
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
            dnd_expires_at_ = now + (static_cast<int64_t>(duration_minutes) * 60);
        } else {
            dnd_expires_at_ = 0;
        }

        // Persist to KV store
        if (plugin_ctx_) {
            yuzu::PluginContext wrap{plugin_ctx_};
            wrap.storage_set("dnd_enabled", enabled ? "true" : "false");
            wrap.storage_set("dnd_expires_at", std::to_string(dnd_expires_at_));
        }

        ctx.write_output(std::format("dnd_enabled|{}", enabled ? "true" : "false"));
        if (enabled && duration_minutes > 0) {
            ctx.write_output(std::format("dnd_duration_minutes|{}", duration_minutes));
            ctx.write_output(std::format("dnd_expires_at|{}", dnd_expires_at_));
        }
        ctx.write_output("status|ok");
        return 0;
    }

    // ── DND state ────────────────────────────────────────────────────────────

    bool is_dnd_active() const {
        if (!dnd_enabled_) return false;
        if (dnd_expires_at_ > 0) {
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
            if (now >= dnd_expires_at_) {
                // DND has expired — clear it
                // const_cast because we need to update state in a const method;
                // this is safe as the agent serializes execute() calls per command.
                const_cast<InteractionPlugin*>(this)->dnd_enabled_ = false;
                const_cast<InteractionPlugin*>(this)->dnd_expires_at_ = 0;
                if (plugin_ctx_) {
                    yuzu::PluginContext wrap{const_cast<InteractionPlugin*>(this)->plugin_ctx_};
                    wrap.storage_set("dnd_enabled", "false");
                    wrap.storage_set("dnd_expires_at", "0");
                }
                return false;
            }
        }
        return true;
    }

    YuzuPluginContext* plugin_ctx_{nullptr};
    bool dnd_enabled_{false};
    int64_t dnd_expires_at_{0};  // epoch seconds, 0 = indefinite
};

YUZU_PLUGIN_EXPORT(InteractionPlugin)
