#!/usr/bin/env python3
"""selfcheck-issue-guard.py -- prove the issue-guard hook FIRES, via the real wiring.

Run this locally, on Windows especially:

    py -3 scripts/hooks/selfcheck-issue-guard.py

Why it exists (ADR-3001 A1, R3). tests/test_issue_guard.py proves the hook's
*logic* by spawning it with this interpreter. It cannot prove the *wiring*: on
Windows `python3` resolves to the Microsoft Store App-Execution-Alias stub,
which runs, prints "Python was not found", exits nonzero and emits NO stdout --
so a `python3`-wired hook fails OPEN and is silently dead. CI is Linux-only and
never sees that trap. This check closes the gap: it reads the ACTUAL command
string from .claude/settings.json, runs it through Git Bash exactly as Claude
Code does (POSIX `sh`/Git Bash on Windows, with $CLAUDE_PROJECT_DIR in the
environment), pipes a synthetic PreToolUse payload, and asserts the hook both
denies a bad `gh issue create` and stays silent on an allowed call.

If the resolver ever regresses to a dead interpreter, the deny JSON does not
appear and this check FAILS -- which is the whole point. It passes on Linux/
macOS too (harmless), so it is safe to run anywhere; it is deliberately NOT
wired into meson/CI because the trap it guards only exists off-CI.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SETTINGS = ROOT / ".claude" / "settings.json"
HOOK_BASENAME = "issue-standard-guard.py"


def find_wired_command() -> str:
    """Return the exact PreToolUse command string that wires the issue guard."""
    cfg = json.loads(SETTINGS.read_text(encoding="utf-8"))
    for entry in cfg.get("hooks", {}).get("PreToolUse", []):
        for hook in entry.get("hooks", []):
            cmd = hook.get("command", "")
            if HOOK_BASENAME in cmd:
                return cmd
    raise SystemExit(
        f"FAIL: no PreToolUse hook in {SETTINGS} references {HOOK_BASENAME} -- "
        "the guard is not wired."
    )


def run_via_bash(command: str, payload: dict, extra_env: dict | None = None) -> tuple[int, str, str]:
    """Run `command` through Git Bash with CLAUDE_PROJECT_DIR set, feeding payload."""
    bash = shutil.which("bash")
    if not bash:
        raise SystemExit(
            "FAIL: `bash` (Git Bash) not found on PATH. Claude Code runs hooks "
            "through Git Bash on Windows; this self-check needs it too."
        )
    env = dict(os.environ)
    env["CLAUDE_PROJECT_DIR"] = str(ROOT)
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        [bash, "-c", command],
        input=json.dumps(payload).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    return (
        proc.returncode,
        proc.stdout.decode("utf-8", "replace").strip(),
        proc.stderr.decode("utf-8", "replace").strip(),
    )


def decision_of(stdout: str) -> str:
    if not stdout:
        return "allow"
    try:
        return json.loads(stdout)["hookSpecificOutput"]["permissionDecision"]
    except Exception:
        return f"<unparseable: {stdout!r}>"


def main() -> int:
    command = find_wired_command()
    print(f"wired command: {command}")

    failures = []

    # 1. A bad create MUST deny. If the interpreter is the dead stub, the hook
    #    emits nothing and this fails -- exactly the R3 regression we guard.
    bad = {
        "tool_name": "Bash",
        "tool_input": {"command": 'gh issue create --title T --label P1,needs-triage'},
    }
    rc, out, err = run_via_bash(command, bad)
    dec = decision_of(out)
    print(f"  bad create      -> exit={rc} decision={dec}")
    if rc != 0:
        failures.append(f"hook exited {rc} (must be 0); stderr={err!r}")
    if dec != "deny":
        failures.append(
            "a bad `gh issue create` did NOT deny through the real wiring -- "
            "the interpreter likely did not resolve to a real Python (the R3 "
            f"stub trap). decision={dec!r} stderr={err!r}"
        )

    # 2. A non-create call MUST stay silent (allow).
    ok = {"tool_name": "Bash", "tool_input": {"command": "gh pr view 1"}}
    rc, out, err = run_via_bash(command, ok)
    dec = decision_of(out)
    print(f"  non-create call -> exit={rc} decision={dec}")
    if rc != 0:
        failures.append(f"hook exited {rc} on allowed call; stderr={err!r}")
    if dec != "allow":
        failures.append(f"a non-create call did not allow: decision={dec!r} out={out!r}")

    # 3. The PowerShell matcher must fire too (second matcher in settings.json):
    #    a backtick-newline continuation must not hide the create.
    ps = {"tool_name": "PowerShell",
          "tool_input": {"command": "gh issue `\ncreate --title T --label P1,needs-triage"}}
    rc, out, err = run_via_bash(command, ps)
    dec = decision_of(out)
    print(f"  powershell bad  -> exit={rc} decision={dec}")
    if dec != "deny":
        failures.append(f"a bad PowerShell create did not deny: decision={dec!r} stderr={err!r}")

    # 4. The ADR-mandated operator escape hatch must short-circuit to allow.
    rc, out, err = run_via_bash(command, bad, extra_env={"YUZU_ISSUE_STANDARD_ACK": "1"})
    dec = decision_of(out)
    print(f"  ACK=1 bypass    -> exit={rc} decision={dec}")
    if dec != "allow":
        failures.append(f"YUZU_ISSUE_STANDARD_ACK=1 did not bypass: decision={dec!r}")

    if failures:
        print("\nSELF-CHECK FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nself-check OK: the issue-guard hook fires through the real settings.json wiring.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
