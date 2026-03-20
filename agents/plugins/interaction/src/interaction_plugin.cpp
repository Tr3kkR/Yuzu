/**
 * interaction_plugin.cpp — Desktop user interaction plugin for Yuzu
 *
 * Actions:
 *   "notify"      — Show a desktop notification/toast.
 *   "message_box" — Show a modal message dialog, return button clicked.
 *   "input"       — Show a text input dialog, return entered text.
 *
 * Output is pipe-delimited, one field per line via write_output():
 *   key|value
 *
 * Platform support:
 *   Windows — ShellNotifyIconW, MessageBoxW, PowerShell InputBox
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
#include <cstdio>
#include <format>
#include <string>
#include <string_view>

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
 * Blocks backticks, $, |, ;, &, <, >, (, ), {, }, [, ], \, newlines, and
 * other shell metacharacters.
 */
bool is_safe_char(char c) {
    if (c >= 'a' && c <= 'z') return true;
    if (c >= 'A' && c <= 'Z') return true;
    if (c >= '0' && c <= '9') return true;
    // Safe punctuation: space, period, comma, hyphen, underscore, colon,
    // question mark, exclamation, slash, at, hash, percent, plus, equals,
    // single quote, double quote (for display text)
    switch (c) {
    case ' ':  case '.':  case ',':  case '-':  case '_':
    case ':':  case '?':  case '!':  case '/':  case '@':
    case '#':  case '%':  case '+':  case '=':  case '\'':
    case '"':  case '\t':
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

} // namespace

class InteractionPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "interaction"; }
    std::string_view version() const noexcept override { return "0.1.0"; }
    std::string_view description() const noexcept override {
        return "Desktop user interaction — notifications, message boxes, input dialogs";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"notify", "message_box", "input", nullptr};
        return acts;
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override {
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

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }

private:
    int do_notify(yuzu::CommandContext& ctx, yuzu::Params params) {
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
};

YUZU_PLUGIN_EXPORT(InteractionPlugin)
