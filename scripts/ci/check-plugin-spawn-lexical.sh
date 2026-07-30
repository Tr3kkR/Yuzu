#!/usr/bin/env bash
# check-plugin-spawn-lexical.sh -- Decision-10a per-PR lexical spawn gate
# (docs/adr/3002-acquisition-ladder.md:459-488).
#
# A zero-cost, no-build text scan (the check-compose-versions.sh pattern)
# that fails a PR introducing a raw process-spawn token in agents/plugins/*
# or agents/core -- outside the registered allowlist below -- rather than
# going through the shared, sanctioned runner
# (yuzu::agent::run_bounded_subprocess, agents/core/src/subprocess_runner.cpp).
# This is tier (a) of the ADR's two-tier enforcement; CodeQL (tier b,
# scheduled, call-identity-aware) is the deep net this cannot be -- see the
# ADR for why neither tier alone is sufficient.
#
# Token semantics are pinned exactly as the ADR specifies:
#   * word-boundary matching, so a raw token never matches as a substring of
#     a longer identifier (`subsystem(` must never trip on `system`);
#   * the exec family is enumerated BY NAME, never a glob -- a bare `exec*`
#     would match every plugin's own `execute(` method. `execve`, `fexecve`,
#     and `execveat` are ALSO enumerated here, beyond the ADR's original
#     literal list -- this PR's own runner work (A5's explicit envp, B6's
#     TOCTOU-safe exec) introduces real calls to them, and leaving them out
#     would let a plugin call raw execve() and never trip the gate;
#   * `system`/`fork`/`posix_spawn`/`popen`/`_popen` as bounded whole words;
#   * the Windows family spelled out (`CreateProcess*`, `ShellExecute*`,
#     `_spawn*`/`_wspawn*`);
#   * a token only counts as a hit when it looks like a CALL (`token(`),
#     narrowing (not eliminating -- see the comment/string stripper below)
#     prose false positives.
#
# Two allowlist tiers, both by FILE (see the ADR's "exceptions by call
# identity, never by file" -- the per-call-identity mechanism is the sink
# manifest, docs/agent-spawn-sink-manifest.md, population tracked separately
# in #2380 and out of this PR's scope; a coarser file-level allowlist is the
# honest state this lexical-only gate can enforce today without that
# manifest):
#   1. RUNNER_ALLOWLIST -- the ONE canonical, permanent, ADR-sanctioned
#      allowlist entry: the runner's own implementation. A second file
#      forking/exec'ing/CreateProcess'ing directly is exactly the "scattered
#      copies" this ADR exists to prevent -- route through the runner
#      instead of adding a second entry here.
#   2. GRANDFATHERED -- pre-existing, NOT-YET-MIGRATED call sites (migration
#      sequencing is a separate roadmap concern, not this ADR's or this
#      script's job -- see fork_lock.hpp's own residual ledger). Frozen as of
#      this PR so a full-tree run is green against the CURRENT codebase
#      instead of failing on ~40 known, already-accepted sites the migration
#      hasn't reached yet; a NEW site in a file not already on this list
#      still fails the gate. Removing an entry as a site migrates onto the
#      runner is expected and welcome.
#
# Usage:
#   scripts/ci/check-plugin-spawn-lexical.sh              # scan the real tree
#   scripts/ci/check-plugin-spawn-lexical.sh --selftest    # fixture self-test
#
# Exit status: 0 = clean (or selftest passed), 1 = a raw spawn token was
# found outside the allowlist (or selftest failed), 2 = usage error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SELFTEST=0
case "${1:-}" in
  "") ;;
  --selftest) SELFTEST=1 ;;
  *)
    echo "usage: $0 [--selftest]" >&2
    exit 2
    ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
  echo "check-plugin-spawn-lexical: python3 is required (already a hard build dependency, see" >&2
  echo "CLAUDE.md's PyYAML note) but was not found on PATH." >&2
  exit 2
fi

python3 - "$REPO_ROOT" "$SELFTEST" <<'PYEOF'
import os
import re
import shutil
import sys
import tempfile

repo_root = sys.argv[1]
selftest_flag = sys.argv[2] == "1"

# ---- pinned token family (ADR-3002:459-488) ----------------------------
EXEC_FAMILY = [
    "execl", "execlp", "execle", "execv", "execvp", "execvpe",
    "execve", "fexecve", "execveat",
]
BOUNDED_WORDS = ["system", "fork", "posix_spawn", "popen", "_popen"]
WINDOWS_FAMILY = [
    "CreateProcess", "CreateProcessA", "CreateProcessW", "CreateProcessAsUser",
    "ShellExecute", "ShellExecuteA", "ShellExecuteW",
    "_spawnl", "_spawnle", "_spawnlp", "_spawnlpe",
    "_spawnv", "_spawnve", "_spawnvp", "_spawnvpe",
    "_wspawnl", "_wspawnle", "_wspawnlp", "_wspawnlpe",
    "_wspawnv", "_wspawnve", "_wspawnvp", "_wspawnvpe",
]
ALL_TOKENS = EXEC_FAMILY + BOUNDED_WORDS + WINDOWS_FAMILY
# Longest-first so e.g. `execvpe` is tried before `execv` in the alternation
# (Python's `re` alternation picks the first alternative that matches at a
# position, not the longest, so ordering matters here).
ALL_TOKENS.sort(key=len, reverse=True)
TOKEN_RE = re.compile(r"\b(" + "|".join(re.escape(t) for t in ALL_TOKENS) + r")\s*\(")


def strip_comments_and_strings(text):
    """Best-effort C/C++ `//`/`/* */` comment and string/char-literal
    stripper (replaces stripped regions with spaces, preserving newlines, so
    reported line numbers stay accurate) -- a prose mention like
    "// call fork() here" or a string literal containing one of these words
    must not trip the gate. Not a real preprocessor/lexer: it does not
    understand raw string literals (R"(...)") or trigraphs, neither of which
    this codebase uses for anything spawn-related.
    """
    out = []
    i, n = 0, len(text)
    in_line_comment = in_block_comment = in_string = in_char = False
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if c == "\n":
                in_line_comment = False
                out.append(c)
            else:
                out.append(" ")
            i += 1
            continue
        if in_block_comment:
            if c == "*" and nxt == "/":
                out.append("  ")
                i += 2
                in_block_comment = False
                continue
            out.append(c if c == "\n" else " ")
            i += 1
            continue
        if in_string:
            if c == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
                continue
            if c == '"':
                in_string = False
                out.append(" ")
                i += 1
                continue
            out.append(c if c == "\n" else " ")
            i += 1
            continue
        if in_char:
            if c == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
                continue
            if c == "'":
                in_char = False
                out.append(" ")
                i += 1
                continue
            out.append(c if c == "\n" else " ")
            i += 1
            continue
        if c == "/" and nxt == "/":
            in_line_comment = True
            out.append("  ")
            i += 2
            continue
        if c == "/" and nxt == "*":
            in_block_comment = True
            out.append("  ")
            i += 2
            continue
        if c == '"':
            in_string = True
            out.append(" ")
            i += 1
            continue
        if c == "'":
            in_char = True
            out.append(" ")
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


# ---- allowlist tier 1: the canonical registered allowlist entry --------
RUNNER_ALLOWLIST = {
    "agents/core/src/subprocess_runner.cpp",
}

# ---- allowlist tier 2: pre-existing, not-yet-migrated sites -------------
# Grounded in the actual tree as of this PR (verified by running this
# script's --selftest-adjacent full scan against a bare allowlist and
# reading every hit -- not copied from a doc comment that could have
# drifted). A meson.build hit (Meson's own `host_machine.system()`) is not a
# C/C++ source file and is excluded by SCAN_EXT below, not by this list.
GRANDFATHERED = {
    "agents/plugins/antivirus/src/antivirus_plugin.cpp",
    "agents/plugins/bitlocker/src/bitlocker_plugin.cpp",
    "agents/plugins/certificates/src/certificates_plugin.cpp",
    "agents/plugins/content_dist/src/content_dist_plugin.cpp",
    "agents/plugins/device_identity/src/device_identity_plugin.cpp",
    "agents/plugins/discovery/src/discovery_plugin.cpp",
    "agents/plugins/event_logs/src/event_logs_plugin.cpp",
    "agents/plugins/firewall/src/firewall_plugin.cpp",
    "agents/plugins/hardware/src/hardware_plugin.cpp",
    "agents/plugins/installed_apps/src/installed_apps_plugin.cpp",
    "agents/plugins/interaction/src/interaction_plugin.cpp",
    "agents/plugins/ioc/src/ioc_plugin.cpp",
    "agents/plugins/license_scan/src/licensing_linux.cpp",
    "agents/plugins/msi_packages/src/msi_packages_plugin.cpp",
    "agents/plugins/network_actions/src/network_actions_plugin.cpp",
    "agents/plugins/network_config/src/network_config_plugin.cpp",
    "agents/plugins/network_diag/src/network_diag_plugin.cpp",
    "agents/plugins/os_info/src/os_info_plugin.cpp",
    "agents/plugins/processes/src/processes_plugin.cpp",
    "agents/plugins/quarantine/src/quarantine_plugin.cpp",
    "agents/plugins/sccm/src/sccm_plugin.cpp",
    "agents/plugins/script_exec/src/script_exec_plugin.cpp",
    "agents/plugins/services/src/services_plugin.cpp",
    "agents/plugins/software_actions/src/software_actions_plugin.cpp",
    "agents/plugins/tar/src/tar_mapdrive_collector.cpp",
    "agents/plugins/tar/src/tar_service_collector.cpp",
    "agents/plugins/users/src/users_plugin.cpp",
    "agents/plugins/vuln_scan/src/config_checks.hpp",
    "agents/plugins/vuln_scan/src/vuln_scan_plugin.cpp",
    "agents/plugins/windows_updates/src/windows_updates_plugin.cpp",
    "agents/plugins/wol/src/wol_plugin.cpp",
    "agents/core/src/dex_linux_collector.cpp",
    "agents/core/src/dex_linux_journal.hpp",
    "agents/core/src/dex_macos_collector.cpp",
    "agents/core/src/trigger_engine.cpp",
}

ALLOWLIST = RUNNER_ALLOWLIST | GRANDFATHERED

SCAN_DIRS = ["agents/plugins", "agents/core/src", "agents/core/include"]
SCAN_EXT = (".c", ".cc", ".cpp", ".h", ".hpp")


def iter_scanned_files(root):
    for scan_dir in SCAN_DIRS:
        base = os.path.join(root, scan_dir)
        if not os.path.isdir(base):
            continue
        for dirpath, _dirnames, filenames in os.walk(base):
            for fn in filenames:
                if fn.endswith(SCAN_EXT):
                    full = os.path.join(dirpath, fn)
                    rel = os.path.relpath(full, root).replace(os.sep, "/")
                    yield rel, full


def scan(root, allowlist):
    findings = []
    for rel, full in iter_scanned_files(root):
        if rel in allowlist:
            continue
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        stripped = strip_comments_and_strings(text)
        for lineno, line in enumerate(stripped.splitlines(), start=1):
            m = TOKEN_RE.search(line)
            if m:
                findings.append((rel, lineno, m.group(1)))
    return findings


def run_full_scan(root):
    findings = scan(root, ALLOWLIST)
    if findings:
        for rel, lineno, tok in findings:
            print(
                f"::error file={rel},line={lineno}::raw spawn token `{tok}(` outside the "
                f"registered allowlist (Decision-10a, ADR-3002:459-488) -- route through "
                f"yuzu::agent::run_bounded_subprocess (agents/core/src/subprocess_runner.cpp), "
                f"or if this is a genuinely pre-existing site awaiting migration, add it to "
                f"GRANDFATHERED in scripts/ci/check-plugin-spawn-lexical.sh with a tracking issue."
            )
        print(f"\n{len(findings)} raw spawn token(s) found outside the allowlist.", file=sys.stderr)
        return 1
    print("check-plugin-spawn-lexical: clean (no raw spawn tokens outside the registered allowlist).")
    return 0


def run_selftest():
    tmp = tempfile.mkdtemp(prefix="yuzu_test_spawn_gate_")
    try:
        # Clean fixture: a plugin that routes through the runner; a comment
        # mentioning every banned token in prose must not trip the gate.
        clean_dir = os.path.join(tmp, "clean", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(clean_dir)
        with open(os.path.join(clean_dir, "fixture_plugin.cpp"), "w") as f:
            f.write(
                "#include <yuzu/agent/subprocess_runner.hpp>\n"
                "// This comment mentions fork() and popen() and system() and execve() in\n"
                "// prose only -- must NOT trip the gate once comments are stripped.\n"
                "void run() {\n"
                "    auto r = yuzu::agent::run_bounded_subprocess({\"/bin/echo\"}, {});\n"
                "    (void)r;\n"
                "}\n"
            )
        clean_findings = scan(os.path.join(tmp, "clean"), set())
        if clean_findings:
            print(f"SELFTEST FAILED: clean fixture unexpectedly flagged: {clean_findings}")
            return 1

        # Seeded fixture: a raw popen() call outside any allowlist must fail.
        seeded_dir = os.path.join(tmp, "seeded", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(seeded_dir)
        with open(os.path.join(seeded_dir, "fixture_plugin.cpp"), "w") as f:
            f.write(
                "#include <cstdio>\n"
                "void run() {\n"
                "    FILE* p = popen(\"echo hi\", \"r\");\n"
                "    (void)p;\n"
                "}\n"
            )
        seeded_findings = scan(os.path.join(tmp, "seeded"), set())
        if not seeded_findings:
            print("SELFTEST FAILED: seeded raw-spawn fixture was NOT flagged")
            return 1
        if not any(tok == "popen" for _rel, _lineno, tok in seeded_findings):
            print(f"SELFTEST FAILED: seeded fixture flagged for the wrong token: {seeded_findings}")
            return 1

        # Allowlisted fixture: a raw call inside a file ON the allowlist
        # (standing in for the runner's own implementation) must NOT be
        # flagged -- the sanctioned spawner never trips its own gate.
        allow_dir = os.path.join(tmp, "allow", "agents", "core", "src")
        os.makedirs(allow_dir)
        with open(os.path.join(allow_dir, "subprocess_runner.cpp"), "w") as f:
            f.write("void run() { system(\"echo hi\"); }\n")
        allow_findings = scan(os.path.join(tmp, "allow"), ALLOWLIST)
        if allow_findings:
            print(f"SELFTEST FAILED: the runner's own allowlisted file was flagged: {allow_findings}")
            return 1

        # False-positive guard: `execute(` (a real plugin method name) must
        # never match the exec family (the ADR's own "a bare exec* glob
        # would match every plugin's execute(" concern).
        exe_dir = os.path.join(tmp, "execute_guard", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(exe_dir)
        with open(os.path.join(exe_dir, "fixture_plugin.cpp"), "w") as f:
            f.write("int execute(int argc, char** argv) { return 0; }\n")
        exe_findings = scan(os.path.join(tmp, "execute_guard"), set())
        if exe_findings:
            print(f"SELFTEST FAILED: execute( false-positived: {exe_findings}")
            return 1

        # `subsystem(` false-positive guard (the ADR's own example for the
        # bounded word `system`).
        sub_dir = os.path.join(tmp, "subsystem_guard", "agents", "plugins", "fixture_plugin", "src")
        os.makedirs(sub_dir)
        with open(os.path.join(sub_dir, "fixture_plugin.cpp"), "w") as f:
            f.write("void subsystem(int x) { (void)x; }\n")
        sub_findings = scan(os.path.join(tmp, "subsystem_guard"), set())
        if sub_findings:
            print(f"SELFTEST FAILED: subsystem( false-positived: {sub_findings}")
            return 1

        print("check-plugin-spawn-lexical --selftest: all fixtures behaved as expected.")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if selftest_flag:
    sys.exit(run_selftest())
else:
    sys.exit(run_full_scan(repo_root))
PYEOF
