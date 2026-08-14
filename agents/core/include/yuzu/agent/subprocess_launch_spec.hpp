#pragma once

/**
 * subprocess_launch_spec.hpp -- pure, allocation-only "what would we launch"
 * core for the agent-core subprocess runner (ADR-3002 best-practice
 * addendum, item B1).
 *
 * Mirrors the repo's `*_parsers.hpp` pattern (see e.g.
 * agents/plugins/firewall/src/firewall_parsers.hpp): every function here is a
 * pure free function over plain data -- no fork(), no CreateProcess(), no
 * filesystem/env I/O of its own -- so the argv/env validation, the Colascione
 * Windows command-line quoting, the allow-list environment shape, and the
 * rlimit/exec-verification options can all be golden-asserted on the
 * returned LaunchSpec in a unit test, without ever spawning a process
 * (CLAUDE.md test discipline: the real fork/exec bounded-real-child tests in
 * test_subprocess_runner.cpp remain the integration layer this does not
 * replace).
 *
 * subprocess_runner.cpp's run_bounded_subprocess() calls build_launch_spec()
 * to get its validated argv, its allow-list envp, and (on Windows) its
 * pre-quoted command line -- the actual fork()/execve()/CreateProcessW() call
 * and the deadline/reap/kill loop stay exactly the shipped implementation;
 * only the "what to launch" decision moves through this pure core.
 *
 * Header-only (every function is `inline`) and NOT declared YUZU_EXPORT: it
 * is included directly by subprocess_runner.cpp and by
 * test_subprocess_runner.cpp (test-only), both in-tree translation units --
 * it never needs a stable cross-DSO ABI the way subprocess_runner.hpp does,
 * and being header-only means adding it costs no new meson.build target.
 */

#include <algorithm>
#include <cctype>
#include <cstddef> // std::size_t/std::ptrdiff_t (cpp-expert A2: transitive-only via
                   // other headers today; included explicitly since this header
                   // uses both directly)
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::agent {

/** Why build_launch_spec rejected an argv/opts pair outright (no OS call was
 *  ever attempted for one of these). */
enum class LaunchSpecError {
    none,
    empty_argv,
    relative_argv0,
    embedded_nul,
    banned_windows_extension, // .bat/.cmd/.com as argv[0] (CVE-2024-24576; ADR-3002:537-606)
};

/** One assembled environment variable, KEY and VALUE kept separate so a test
 *  can assert on either without re-parsing a "KEY=VALUE" blob. */
struct EnvVar {
    std::string key;
    std::string value;

    friend bool operator==(const EnvVar&, const EnvVar&) = default;
};

/** Everything the OS shell needs to launch a child, precomputed and
 *  validated by build_launch_spec() -- no I/O touched constructing it. */
struct LaunchSpec {
    LaunchSpecError error = LaunchSpecError::none;

    std::vector<std::string> argv; // validated; argv[0] absolute, no embedded NUL
    std::vector<EnvVar> env;        // A5: clear-and-allow-list, built here from nothing
    std::string working_dir;        // A6: resolved cwd (non-empty once error == none)
    std::uint32_t umask_value = 0077; // A6 (POSIX only; ignored by the Windows shell)
    bool merge_stderr = false;

    // A2/Windows: the fully Colascione-quoted single command-line string.
    // Precomputed unconditionally (pure string logic, no Win32 dependency) so
    // its shape is testable on every platform, even though only the Windows
    // shell ever consumes it.
    std::string windows_command_line;

    // A1/Windows: which handles the shell must mark inheritable and name in
    // PROC_THREAD_ATTRIBUTE_HANDLE_LIST -- expressed as roles rather than
    // live HANDLEs (which don't exist yet at spec-build time), so a test can
    // assert the list's *shape* without ever calling into Win32.
    struct WindowsHandlePolicy {
        bool inherit_stdout_write = true;
        // True iff merge_stderr routes stderr onto the SAME pipe as stdout --
        // kept as its own bool (rather than always mirroring
        // inherit_stdout_write) so a test can assert the named handle list
        // never grows past exactly what merge_stderr requires.
        bool inherit_stderr_write = false;
    } windows_handles;

    // B3: optional per-invocation rlimit caps, all unset (off) unless the
    // caller opted in via LaunchOptions.
    struct Rlimits {
        std::optional<std::uint64_t> cpu_seconds;
        std::optional<std::uint64_t> address_space_bytes;
        std::optional<std::uint64_t> fsize_bytes;
        std::optional<std::uint64_t> nofile_count;
    } rlimits;

    // B6: TOCTOU-safe exec verification, disabled unless the caller opted in.
    // Runner primitive only -- no in-tree caller enables this in this PR.
    struct ExecVerification {
        bool enabled = false;
        bool require_root_owned = true;
        std::optional<std::uint64_t> expected_size;
    } exec_verify;
};

/** Inputs to build_launch_spec -- a deliberately narrow mirror of
 *  SubprocessOptions' launch-SHAPING fields, not its runtime-polling fields
 *  (deadline/max_lines/on_line/... stay entirely the OS shell's concern).
 *  Its own type rather than reusing SubprocessOptions so this header has
 *  zero dependency on subprocess_runner.hpp -- no include cycle, no
 *  YUZU_EXPORT need. */
struct LaunchOptions {
    std::optional<std::string> working_dir;
    bool merge_stderr = false;
    std::optional<std::string> tz; // passed through from the parent's TZ, if set
    LaunchSpec::Rlimits rlimits;
    LaunchSpec::ExecVerification exec_verify;
};

/** The bare outcome a Spawner reports for a LaunchSpec. Deliberately minimal
 *  (does not carry captured output/timing) -- it exists to prove the
 *  injection seam (see Spawner below) is independently testable, not to
 *  replace SubprocessResult. */
struct SpawnOutcome {
    bool tool_ran = false;
    int exit_code = -1;
    bool spawn_error = false;
};

/**
 * Injectable seam between a validated LaunchSpec and the real OS call
 * (fork()+execve() on POSIX, CreateProcessW() on Windows). Production code
 * has no concrete Spawner today -- run_bounded_subprocess's shipped
 * fork/exec/deadline/reap loop is kept exactly as-is per this package's
 * "without redoing its core" boundary, so nothing in subprocess_runner.cpp's
 * hot path is instantiated through this interface. It exists so a unit test
 * can substitute a scripted fake and exercise "does build_launch_spec's
 * output make sense to hand to a spawner" without ever creating a process;
 * see test_subprocess_runner.cpp's B1 test block for the fake in use.
 */
class Spawner {
public:
    virtual ~Spawner() = default;
    virtual SpawnOutcome spawn(const LaunchSpec& spec) = 0;
};

namespace detail {

inline bool contains_nul(const std::string& s) {
    return s.find('\0') != std::string::npos;
}

/** POSIX ('/...') or Windows ('C:\...', 'C:/...', '\\server\share') absolute
 *  path check. Shared by both platform shells so argv[0]'s "must be
 *  absolute" contract is defined exactly once. */
inline bool is_absolute_path(const std::string& p) {
    if (p.empty())
        return false;
    if (p.front() == '/')
        return true;
    if (p.size() >= 3 && std::isalpha(static_cast<unsigned char>(p[0])) != 0 && p[1] == ':' &&
        (p[2] == '\\' || p[2] == '/'))
        return true;
    if (p.size() >= 2 && p[0] == '\\' && p[1] == '\\')
        return true;
    return false;
}

inline bool ends_with_ci(const std::string& s, std::string_view suffix) {
    if (s.size() < suffix.size())
        return false;
    return std::equal(s.end() - static_cast<std::ptrdiff_t>(suffix.size()), s.end(), suffix.begin(),
                       [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) == b; });
}

/** Windows ADR-3002 ban: .bat/.cmd/.com can never be exec'd safely as
 *  argv[0] by quoting alone (CVE-2024-24576 for .bat/.cmd; .com banned
 *  alongside as defense-in-depth). Checked on every platform (cheap, and
 *  keeps the spec's validation platform-independent) even though only the
 *  Windows shell can ever actually be handed one of these. */
inline bool is_banned_windows_extension(const std::string& path) {
    return ends_with_ci(path, ".bat") || ends_with_ci(path, ".cmd") || ends_with_ci(path, ".com");
}

} // namespace detail

/// A5 clear-and-allow-list env, built from nothing for the target OS
/// (`windows == true` selects the Windows allow-list). Pure and host-agnostic
/// so both branches are unit-testable on any host -- build_launch_spec() calls
/// it with the compile target.
///
/// CDX-P2-008: Windows children must NOT receive the POSIX `PATH`
/// (`/usr/bin:...`) or `LC_ALL=C` -- those are meaningless there and a migrated
/// tool that consults PATH/locale/temp would observe nonsense. The Windows list
/// is the minimal deterministic system set: `SystemRoot`/`windir` (required by
/// many Win32 APIs), the canonical system search `PATH`, and a machine-wide
/// `TEMP`/`TMP`. Values are the canonical defaults (a `C:` system volume); a
/// future real Windows caller that must honour a relocated system root threads
/// the actual paths through `opts` rather than reading the parent environment
/// (which A5's clear-slate forbids). Locale is left to the system default -- no
/// LC_ALL analogue is imposed.
inline std::vector<EnvVar> default_launch_env(bool windows,
                                              const std::optional<std::string>& tz) {
    std::vector<EnvVar> env;
    if (windows) {
        env.push_back({"SystemRoot", "C:\\Windows"});
        env.push_back({"windir", "C:\\Windows"});
        env.push_back({"PATH", "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem"});
        env.push_back({"TEMP", "C:\\Windows\\Temp"});
        env.push_back({"TMP", "C:\\Windows\\Temp"});
    } else {
        // LD_*/DYLD_*/IFS/BASH_ENV/GCONV_PATH are stripped by construction
        // (never added, so there is nothing to strip from).
        env.push_back({"PATH", "/usr/bin:/bin:/usr/sbin:/sbin"});
        env.push_back({"LC_ALL", "C"});
    }
    if (tz && !tz->empty())
        env.push_back({"TZ", *tz});
    return env;
}

/**
 * Colascione backslash-before-quote argv-element quoting: the algorithm the
 * Microsoft CRT's own command-line parser (and every parser that follows its
 * rules) expects. Operates byte-wise over the UTF-8 form directly -- '"' and
 * '\\' are single-byte ASCII in UTF-8 and never appear as a continuation
 * byte of a multi-byte sequence, so no decoding is needed to quote correctly.
 * Exposed standalone (not just inlined into build_launch_spec) so a unit
 * test can drive the edge vectors -- empty arg, embedded quote, trailing
 * backslash run, spaces, Unicode -- directly.
 */
inline std::string quote_windows_arg(const std::string& arg) {
    const bool needs_quotes = arg.empty() || arg.find_first_of(" \t\n\v\"") != std::string::npos;
    if (!needs_quotes)
        return arg;

    std::string out = "\"";
    std::size_t i = 0;
    while (true) {
        std::size_t backslashes = 0;
        while (i < arg.size() && arg[i] == '\\') {
            ++backslashes;
            ++i;
        }
        if (i == arg.size()) {
            // Backslashes immediately before the closing quote must be
            // doubled so the CRT parser doesn't read the last one as
            // escaping our terminator.
            out.append(backslashes * 2, '\\');
            break;
        }
        if (arg[i] == '"') {
            out.append(backslashes * 2 + 1, '\\');
            out += '"';
            ++i;
        } else {
            out.append(backslashes, '\\');
            out += arg[i];
            ++i;
        }
    }
    out += '"';
    return out;
}

/**
 * Pure validation + assembly: rejects exactly what run_bounded_subprocess's
 * runtime checks reject (empty argv, a non-absolute argv[0], an embedded NUL
 * in any element, a banned .bat/.cmd/.com extension) and, for a valid argv,
 * builds the full allow-list environment, the Colascione-quoted Windows
 * command line, and the handle-list/rlimit/exec-verify shape the OS shell
 * uses verbatim. No syscall; the only allocation is ordinary
 * std::string/std::vector growth -- safe to call, and to unit-test, without
 * ever spawning a process.
 */
inline LaunchSpec build_launch_spec(const std::vector<std::string>& argv, const LaunchOptions& opts) {
    LaunchSpec spec;
    if (argv.empty()) {
        spec.error = LaunchSpecError::empty_argv;
        return spec;
    }
    if (!detail::is_absolute_path(argv.front())) {
        spec.error = LaunchSpecError::relative_argv0;
        return spec;
    }
    for (const auto& a : argv) {
        if (detail::contains_nul(a)) {
            spec.error = LaunchSpecError::embedded_nul;
            return spec;
        }
    }
    if (detail::is_banned_windows_extension(argv.front())) {
        spec.error = LaunchSpecError::banned_windows_extension;
        return spec;
    }

    spec.argv = argv;
    spec.merge_stderr = opts.merge_stderr;
    spec.working_dir = opts.working_dir.value_or(std::string("/"));
    spec.umask_value = 0077;
    spec.rlimits = opts.rlimits;
    spec.exec_verify = opts.exec_verify;

    // A5: clear-and-allow-list env, built here from nothing for the compile
    // target (CDX-P2-008: Windows must not inherit the POSIX shape). The
    // per-OS list lives in the pure, host-testable default_launch_env().
#ifdef _WIN32
    constexpr bool kWindowsEnv = true;
#else
    constexpr bool kWindowsEnv = false;
#endif
    spec.env = default_launch_env(kWindowsEnv, opts.tz);

    for (std::size_t i = 0; i < spec.argv.size(); ++i) {
        if (i)
            spec.windows_command_line += ' ';
        spec.windows_command_line += quote_windows_arg(spec.argv[i]);
    }
    spec.windows_handles.inherit_stdout_write = true;
    spec.windows_handles.inherit_stderr_write = opts.merge_stderr;

    return spec;
}

} // namespace yuzu::agent
