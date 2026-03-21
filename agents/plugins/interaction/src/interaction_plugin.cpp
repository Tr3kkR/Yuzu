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
/**
 * Run a command via popen and capture the first line of output.
 * Returns the output string (may be empty).
 */
std::string run_command(const std::string& cmd) {
    std::string output;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return output;

    std::array<char, 256> buf{};
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe) != nullptr) {
        output += buf.data();
    }
    pclose(pipe);

    // Trim trailing newline
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r')) {
        output.pop_back();
    }
    return output;
}

/**
 * Run a command via popen and return the exit code.
 */
int run_command_status(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return -1;

    // Drain output
    std::array<char, 256> buf{};
    while (fgets(buf.data(), static_cast<int>(buf.size()), pipe) != nullptr) {
        // discard
    }
    int status = pclose(pipe);
#if defined(__linux__) || defined(__APPLE__)
    // pclose returns the wait status; extract exit code
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return -1;
#else
    return status;
#endif
}
#endif // !_WIN32

// ── Platform: notify ──────────────────────────────────────────────────────────

#ifdef _WIN32

int platform_notify(yuzu::CommandContext& ctx, const std::string& title,
                    const std::string& message, const std::string& type) {
    // Convert strings to wide
    auto to_wide = [](const std::string& s) -> std::wstring {
        if (s.empty()) return {};
        int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        if (len <= 0) return {};
        std::wstring ws(len - 1, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, ws.data(), len);
        return ws;
    };

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
    } else {
        ctx.write_output("status|error|osascript failed");
    }
    return 0;
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
    auto to_wide = [](const std::string& s) -> std::wstring {
        if (s.empty()) return {};
        int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        if (len <= 0) return {};
        std::wstring ws(len - 1, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, ws.data(), len);
        return ws;
    };

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

    std::string cmd = std::format(
        "osascript -e 'display dialog \"{}\" with title \"{}\" {}' 2>&1",
        safe_msg, safe_title, btn_spec);

    std::string output = run_command(cmd);

    // osascript returns "button returned:OK" or "button returned:Yes" etc.
    if (output.find("Cancel") != std::string::npos) {
        ctx.write_output("response|cancel");
    } else if (output.find("No") != std::string::npos) {
        ctx.write_output("response|no");
    } else if (output.find("Yes") != std::string::npos) {
        ctx.write_output("response|yes");
    } else {
        ctx.write_output("response|ok");
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

    std::string cmd = std::format(
        "osascript -e 'try' -e 'set result to text returned of "
        "(display dialog \"{}\" with title \"{}\" default answer \"{}\")' "
        "-e 'return result' -e 'on error' -e 'return \"##CANCELLED##\"' -e 'end try' 2>&1",
        safe_prompt, safe_title, safe_default);

    std::string output = run_command(cmd);

    if (output == "##CANCELLED##") {
        ctx.write_output("cancelled|true");
    } else {
        ctx.write_output(std::format("response|{}", output));
    }
    return 0;
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
    // macOS: sequential osascript dialogs for each question
    ctx.write_output("cancelled|false");

    for (size_t i = 0; i < questions.size(); ++i) {
        const auto& q = questions[i];
        std::string safe_prompt = sanitize(q.prompt);
        std::string safe_title = sanitize(title);

        if (q.type == "yesno") {
            std::string cmd = std::format(
                "osascript -e 'try' -e 'set r to button returned of "
                "(display dialog \"{}\" with title \"{}\" buttons {{\"No\", \"Yes\"}} "
                "default button \"Yes\")' -e 'return r' "
                "-e 'on error' -e 'return \"##CANCELLED##\"' -e 'end try' 2>&1",
                safe_prompt, safe_title);
            std::string out = run_command(cmd);
            if (out == "##CANCELLED##") {
                ctx.write_output("cancelled|true");
                return 0;
            }
            ctx.write_output(std::format("answer_{}|{}", i,
                out.find("Yes") != std::string::npos ? "yes" : "no"));

        } else if (q.type == "choice" && !q.choices.empty()) {
            // Build AppleScript choose from list
            std::string items;
            for (size_t ci = 0; ci < q.choices.size(); ++ci) {
                if (ci > 0) items += ", ";
                items += "\"" + sanitize(q.choices[ci]) + "\"";
            }
            std::string cmd =
                "osascript -e 'try' -e 'set r to choose from list {" + items +
                "} with title \"" + safe_title + "\" with prompt \"" + safe_prompt +
                "\"' -e 'if r is false then' -e 'return \"##CANCELLED##\"' "
                "-e 'else' -e 'return item 1 of r' -e 'end if' "
                "-e 'on error' -e 'return \"##CANCELLED##\"' -e 'end try' 2>&1";
            std::string out = run_command(cmd);
            if (out == "##CANCELLED##") {
                ctx.write_output("cancelled|true");
                return 0;
            }
            ctx.write_output(std::format("answer_{}|{}", i, out));

        } else {
            // text input
            std::string cmd = std::format(
                "osascript -e 'try' -e 'set r to text returned of "
                "(display dialog \"{}\" with title \"{}\" default answer \"\")' "
                "-e 'return r' -e 'on error' -e 'return \"##CANCELLED##\"' -e 'end try' 2>&1",
                safe_prompt, safe_title);
            std::string out = run_command(cmd);
            if (out == "##CANCELLED##") {
                ctx.write_output("cancelled|true");
                return 0;
            }
            ctx.write_output(std::format("answer_{}|{}", i, out));
        }
    }
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
    std::string_view version() const noexcept override { return "0.2.0"; }
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

        ctx.write_output(std::format("unknown action: {}", action));
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
