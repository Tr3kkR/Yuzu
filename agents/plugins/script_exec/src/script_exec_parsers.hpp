#pragma once

/**
 * script_exec_parsers.hpp — pure decision layer for script_exec's migration
 * off its private CreateProcessA / fork+execvpe / execvp spawn paths onto
 * yuzu::agent::run_bounded_subprocess (ADR-3002, PLAN-04 option b).
 *
 * Header-only and OS-call-free — same split as firewall_parsers.hpp and
 * content_dist_exec_parsers.hpp: no fork(), no CreateProcess(), no
 * filesystem/env I/O of its own, so the argv[0] resolution rules (both the
 * POSIX and Windows regimes) and the per-mode argv assembly are all
 * golden-asserted in test_script_exec_parsers.cpp without ever spawning a
 * process. script_exec_plugin.cpp's do_exec/do_bash/do_powershell are the
 * thin runner-calling shell around this header — they read the parent
 * process's real PATH/env and pass it in here as plain data; nothing here
 * ever reads the OS environment or touches the filesystem itself.
 *
 * The one caller-supplied "is this candidate executable" check
 * (IsExecutableFn) is the injected OS boundary, mirroring
 * subprocess_launch_spec.hpp's Spawner seam: production code plugs in a
 * real access()/GetFileAttributesA probe at the call site; tests plug in a
 * scripted fake set.
 */

#include <cctype>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::script_exec {

/// Which of script_exec's three actions assemble_argv is building argv for.
enum class ExecMode { exec, bash, powershell };

/// Pluggable "would the runner be able to exec this candidate" probe —
/// production passes a real filesystem check; tests pass a fake set so
/// resolve_executable is exercised with no OS calls at all.
using IsExecutableFn = std::function<bool(const std::string&)>;

/// The absolute System32 PowerShell path assemble_argv's powershell mode
/// uses — the same well-known 5.1 location interaction_plugin.cpp's
/// kPowerShellPath already probes (ADR-3002 "tool path probing" precedent).
inline constexpr const char* kPowerShellPath =
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

namespace detail {

inline bool is_path_like(std::string_view cmd, bool windows_rules) {
    if (cmd.find('/') != std::string_view::npos)
        return true;
    if (windows_rules) {
        if (cmd.find('\\') != std::string_view::npos)
            return true;
        // A drive prefix ("C:foo" / "C:\\foo") is path-like even with no
        // separator anywhere else in the string.
        if (cmd.size() >= 2 && cmd[1] == ':')
            return true;
    }
    return false;
}

/// POSIX ('/...') or Windows ('C:\...', 'C:/...', '\\server\share')
/// absolute-path check — mirrors subprocess_launch_spec.hpp's
/// detail::is_absolute_path so a resolved cmd satisfies the SAME
/// "argv[0] must be absolute" contract the runner enforces at spawn time,
/// gated behind `windows_rules` so the POSIX regime never accepts a
/// backslash/drive form.
inline bool is_absolute_like(std::string_view cmd, bool windows_rules) {
    if (cmd.empty())
        return false;
    if (cmd.front() == '/')
        return true;
    if (!windows_rules)
        return false;
    if (cmd.size() >= 3 && std::isalpha(static_cast<unsigned char>(cmd[0])) != 0 &&
        cmd[1] == ':' && (cmd[2] == '\\' || cmd[2] == '/'))
        return true;
    if (cmd.size() >= 2 && cmd[0] == '\\' && cmd[1] == '\\')
        return true;
    return false;
}

/// Join a path-like RELATIVE cmd ("./tool", ".\\tool.exe") onto the
/// injected cwd string — plain string concatenation, never an OS call
/// (std::filesystem::absolute/canonical would both touch the filesystem).
inline std::string join_cwd(std::string_view cwd, std::string_view rel, bool windows_rules) {
    std::string out{cwd};
    const char sep = windows_rules ? '\\' : '/';
    if (!out.empty() && out.back() != '/' && out.back() != '\\')
        out += sep;
    out += rel;
    return out;
}

} // namespace detail

/// Split a PATH-style environment value ("a:b:c" POSIX, "a;b;c" Windows) on
/// its OS separator into ordered entries. Pure string splitting — the
/// plugin reads the real PATH via getenv() at the call site (the impure
/// shell) and hands the raw value in here; this never touches the
/// environment itself. Deliberately NOT the runner's fixed four-directory
/// default: the caller's PATH is whatever the parent process actually has,
/// which is exactly what resolve_executable below must probe now that the
/// child receives that same value via SubprocessOptions::extra_env.
///
/// An INTERIOR empty segment (leading/trailing/doubled separator, e.g.
/// "a::b") is preserved rather than dropped — POSIX PATH convention treats
/// an empty component as "search the current directory," and
/// resolve_executable resolves it against the injected cwd rather than
/// silently skipping it. A wholly empty `path_value` still yields zero
/// entries: the caller cannot distinguish an unset PATH from PATH="" at the
/// getenv() layer (both collapse to an empty string_view), and treating
/// that ambiguous case as "no search path" is the conservative reading.
[[nodiscard]] inline std::vector<std::string> split_path_entries(std::string_view path_value,
                                                                  bool windows_rules) {
    std::vector<std::string> entries;
    if (path_value.empty())
        return entries;
    const char sep = windows_rules ? ';' : ':';
    std::size_t start = 0;
    while (start <= path_value.size()) {
        auto pos = path_value.find(sep, start);
        if (pos == std::string_view::npos)
            pos = path_value.size();
        entries.emplace_back(path_value.substr(start, pos - start));
        start = pos + 1;
    }
    return entries;
}

/// Resolve `cmd` (script_exec's "command" param, or an exec-mode argv[0]) to
/// an absolute path the runner can exec — pure and OS-call-free so both the
/// POSIX and Windows regimes are testable on any host via `windows_rules`.
///
/// BR-009 (whole-branch review): the RESOLUTION ALGORITHM below matches
/// execvp()/CreateProcessA()'s pre-migration rules exactly, but the `cwd`
/// value the CALLER passes in does NOT — script_exec_plugin.cpp passes a
/// fixed safe sentinel (kRunnerDefaultCwd: "/" on POSIX, Windows'
/// System32 on Windows), never the agent daemon's actual real working
/// directory the deleted paths implicitly used. This is a deliberate,
/// documented compatibility break (ADR-3002 A6), not an exact behavioural
/// preservation — see kRunnerDefaultCwd's own comment at the call site.
///
///  - a PATH-LIKE cmd (contains '/', or under windows_rules contains '\\'
///    or has a drive-letter prefix) that is already ABSOLUTE passes through
///    unchanged;
///  - a PATH-LIKE cmd that is RELATIVE (./tool, .\tool.exe) resolves
///    against `cwd` (a plain string parameter, never read from the OS here)
///    to an absolute path — the same JOIN RULE execvp()/CreateProcessA()
///    applied to a "./tool"-style argv[0] under the process's real cwd, now
///    made explicit since the runner's argv[0] contract requires an
///    already-absolute path, but joined against the caller-supplied `cwd`
///    above, not necessarily the daemon's own; a Windows DRIVE-RELATIVE
///    cmd ("C:foo", no backslash/slash after the colon) is the one
///    exception — it resolves against `cwd` only when `cwd` names the SAME
///    drive (the "C:" prefix is stripped before joining, since Windows
///    treats "C:foo" as "foo relative to drive C's cwd," never as a literal
///    filename containing a colon), and is refused (nullopt) for a
///    differing drive rather than producing an invalid path;
///  - a BARE name (no separator anywhere) is searched in `path_entries`, in
///    order, via `is_executable_fn`; an empty or relative PATH entry
///    (POSIX's "current directory" convention, or a relative directory) is
///    itself resolved against `cwd` first, so every probed/returned
///    candidate stays absolute; under windows_rules each entry is probed
///    twice, first the bare name then name + ".exe" — PATHEXT is
///    deliberately reduced to just .exe here, since the runner
///    runtime-rejects a .bat/.cmd/.com argv[0] outright (CVE-2024-24576;
///    subprocess_launch_spec.hpp) — probing those extensions would only
///    ever hand the runner a spawn it refuses.
///
/// Returns std::nullopt when nothing resolves — the caller emits the
/// existing status|error / exit_code|-1 shape without ever calling the
/// runner.
[[nodiscard]] inline std::optional<std::string>
resolve_executable(std::string_view cmd, std::string_view cwd,
                    const std::vector<std::string>& path_entries,
                    const IsExecutableFn& is_executable_fn, bool windows_rules) {
    if (cmd.empty())
        return std::nullopt;

    if (detail::is_path_like(cmd, windows_rules)) {
        if (detail::is_absolute_like(cmd, windows_rules))
            return std::string{cmd};
        if (windows_rules && cmd.size() >= 2 && cmd[1] == ':') {
            // Drive-relative form ("C:foo", NOT "C:\foo"/"C:/foo" -- those
            // took the is_absolute_like branch above). Windows resolves
            // this against the NAMED drive's own current directory, never
            // as a literal filename containing a colon -- join_cwd's plain
            // concatenation below would otherwise produce exactly that
            // invalid embedded-":" path. Only the injected cwd's own drive
            // is resolvable here (no other drive's cwd is available), so a
            // differing drive letter is refused fail-closed rather than
            // guessed at.
            if (cwd.size() >= 2 && cwd[1] == ':' &&
                std::tolower(static_cast<unsigned char>(cwd[0])) ==
                    std::tolower(static_cast<unsigned char>(cmd[0]))) {
                return detail::join_cwd(cwd, cmd.substr(2), windows_rules);
            }
            return std::nullopt;
        }
        return detail::join_cwd(cwd, cmd, windows_rules);
    }

    const std::string name{cmd};
    const char sep = windows_rules ? '\\' : '/';
    for (const auto& entry : path_entries) {
        // A PATH entry itself can be empty (POSIX "current directory"
        // convention) or relative -- both must still resolve to an
        // ABSOLUTE search directory before being probed/returned, since the
        // runner's argv[0] contract (mirrored here) rejects a relative
        // argv[0] outright; an entry already absolute is used as-is.
        std::string dir;
        if (entry.empty())
            dir = std::string{cwd};
        else if (detail::is_absolute_like(entry, windows_rules))
            dir = entry;
        else
            dir = detail::join_cwd(cwd, entry, windows_rules);

        std::string candidate = dir;
        if (!candidate.empty() && candidate.back() != sep)
            candidate += sep;
        candidate += name;
        if (is_executable_fn(candidate))
            return candidate;
        if (windows_rules) {
            std::string with_exe = candidate + ".exe";
            if (is_executable_fn(with_exe))
                return with_exe;
        }
    }
    return std::nullopt;
}

/// Split `args` on whitespace, honoring '"'/'\'' quoted spans (the quote
/// characters are stripped, no escape processing beyond that) — the exact
/// rule script_exec's "args" param has always followed (unchanged from the
/// plugin-local helper this replaces). Pure and allocation-only.
[[nodiscard]] inline std::vector<std::string> split_args(std::string_view s) {
    std::vector<std::string> result;
    std::string current;
    bool in_quote = false;
    char quote_char = 0;

    for (char ch : s) {
        if (in_quote) {
            if (ch == quote_char) {
                in_quote = false;
            } else {
                current += ch;
            }
        } else if (ch == '"' || ch == '\'') {
            in_quote = true;
            quote_char = ch;
        } else if (ch == ' ' || ch == '\t') {
            if (!current.empty()) {
                result.push_back(std::move(current));
                current.clear();
            }
        } else {
            current += ch;
        }
    }
    if (!current.empty())
        result.push_back(std::move(current));
    return result;
}

/// Assemble the final argv run_bounded_subprocess receives, for each of
/// script_exec's three modes:
///
///  - exec: {resolved_cmd, ...split_args(args)} — `resolved_cmd` is already
///    an absolute path (see resolve_executable above); `args` is the raw,
///    unsplit "args" param; `script` is ignored.
///  - bash: {"/bin/bash", "-c", script} — `script` as ONE argv element
///    (ADR-3002 Decision 5, rung 3: bash, not this outer spawn, interprets
///    it); `resolved_cmd`/`args` are ignored.
///  - powershell: {kPowerShellPath, "-NoProfile", "-NonInteractive",
///    "-EncodedCommand", script} — `script` here is ALREADY the Base64
///    UTF-16LE payload (encoding needs CryptBinaryToStringA, an OS call, so
///    it happens in the plugin shell before this pure function is ever
///    called); `resolved_cmd`/`args` are ignored.
[[nodiscard]] inline std::vector<std::string> assemble_argv(ExecMode mode,
                                                             const std::string& resolved_cmd,
                                                             std::string_view args,
                                                             const std::string& script) {
    switch (mode) {
    case ExecMode::exec: {
        std::vector<std::string> argv{resolved_cmd};
        for (auto& a : split_args(args))
            argv.push_back(std::move(a));
        return argv;
    }
    case ExecMode::bash:
        return {"/bin/bash", "-c", script};
    case ExecMode::powershell:
        return {kPowerShellPath, "-NoProfile", "-NonInteractive", "-EncodedCommand", script};
    }
    return {};
}

} // namespace yuzu::script_exec
