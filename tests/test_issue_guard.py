#!/usr/bin/env python3
"""Behavioural tests for scripts/hooks/issue-standard-guard.py.

The first tests scripts/hooks/ has ever had. A convention hook that silently
stops enforcing -- because the interpreter wiring broke, a refactor regressed
the decision logic, or a fail-open path swallowed a real violation -- is
indistinguishable from a conformant session: the failure is invisible in normal
use and CI runs on Linux where the Windows interpreter trap never bites. So the
logic is pinned here, on every platform, by feeding the hook synthetic
PreToolUse payloads on stdin (exactly as Claude Code does) and asserting the
decision it emits.

The two meta-invariants at the end are the point: a known-bad create MUST deny
and a known-good create MUST allow. If someone neuters the hook to always-allow,
the deny cases fail; to always-deny, the allow cases fail.

Run directly (`python3 tests/test_issue_guard.py`) or via meson (suite: docs).
The hook is spawned with THIS interpreter (sys.executable), so the test proves
the hook's *logic*; the *wiring* (that settings.json resolves a real Python on
Windows) is proved separately by scripts/hooks/selfcheck-issue-guard.py.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "scripts" / "hooks" / "issue-standard-guard.py"

# A body that satisfies all four mandatory sections (real newlines).
GOOD_BODY = (
    "## Context\nwhy this matters\n"
    "## Evidence\nfoo.cpp:42 is wrong\n"
    "## Acceptance criteria\nit stops being wrong\n"
    "## Origin\ngovernance run; probes ran, nothing found"
)


def make_transcript(tmpdir: Path, commands: list[str], name: str) -> str:
    """Write a JSONL transcript whose entries are Bash tool_use blocks."""
    path = tmpdir / f"{name}.jsonl"
    lines = []
    for cmd in commands:
        lines.append(json.dumps({
            "type": "assistant",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "tool_use", "name": "Bash", "input": {"command": cmd}}
                ],
            },
        }))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def run_hook(
    command: str | None,
    transcript_path: str | None = None,
    tool_name: str = "Bash",
    raw_stdin: bytes | None = None,
    env_extra: dict | None = None,
) -> tuple[str, str]:
    """Invoke the hook and return (decision, reason). No stdout => 'allow'."""
    if raw_stdin is not None:
        payload = raw_stdin
    else:
        tool_input = {} if command is None else {"command": command}
        obj: dict = {"tool_name": tool_name, "tool_input": tool_input}
        if transcript_path is not None:
            obj["transcript_path"] = transcript_path
        payload = json.dumps(obj).encode("utf-8")

    run_env = {**os.environ, **env_extra} if env_extra else None
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=run_env,
    )
    # A hook must ALWAYS exit 0 -- the decision is in the JSON, not the code.
    if proc.returncode != 0:
        raise AssertionError(
            f"hook exited {proc.returncode} (must always be 0); "
            f"stderr={proc.stderr.decode('utf-8', 'replace')}"
        )
    out = proc.stdout.decode("utf-8", "replace").strip()
    if not out:
        return ("allow", "")
    obj = json.loads(out)
    hso = obj["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse", hso
    return (hso["permissionDecision"], hso.get("permissionDecisionReason", ""))


# Each case: (name, command, expected_decision, [substrings the reason must have])
# All label-bearing commands include a full valid body so the body check never
# fires unless a case is specifically about the body.
def build_cases(with_probe: str, no_probe: str):
    valid = f'gh issue create --title "T" --body "{GOOD_BODY}" --label bug,P1,needs-triage'
    return [
        # --- allow: fully conformant ---
        ("valid non-roadmap create", valid, with_probe, "allow", []),
        (
            "valid roadmap create (no priority, no state)",
            f'gh issue create --title "T" --body "{GOOD_BODY}" --label enhancement,roadmap',
            with_probe, "allow", [],
        ),
        (
            "labels as repeated flags",
            f'gh issue create --title T --body "{GOOD_BODY}" -l bug -l P0 -l ready-for-agent',
            with_probe, "allow", [],
        ),
        (
            "facet label alongside the mandatory axes is fine",
            f'gh issue create --title T --body "{GOOD_BODY}" --label bug,P2,ready-for-agent,performance',
            with_probe, "allow", [],
        ),
        (
            "body via --body-file is not inspected (allow)",
            "gh issue create --title T --body-file body.md --label bug,P1,needs-triage",
            with_probe, "allow", [],
        ),
        (
            "body via $VAR is unresolvable (allow, no body ask)",
            'gh issue create --title T --body "$BODY" --label bug,P1,needs-triage',
            with_probe, "allow", [],
        ),
        (
            "--web defers to the browser form (allow)",
            "gh issue create --web --label whatever",
            with_probe, "allow", [],
        ),
        (
            "not a gh issue create at all (allow, no output)",
            "gh pr list --repo Tr3kkR/Yuzu",
            with_probe, "allow", [],
        ),
        (
            "gh issue create only inside a quoted string is not a real create",
            'echo "gh issue create --label bug"',
            with_probe, "allow", [],
        ),

        # --- deny: label-contract violations ---
        (
            "no type label",
            f'gh issue create --title T --body "{GOOD_BODY}" --label P1,needs-triage',
            with_probe, "deny", ["no TYPE label"],
        ),
        (
            "two type labels",
            f'gh issue create --title T --body "{GOOD_BODY}" --label bug,task,P1,needs-triage',
            with_probe, "deny", ["multiple TYPE labels"],
        ),
        (
            "no priority on the gh path",
            f'gh issue create --title T --body "{GOOD_BODY}" --label bug,needs-triage',
            with_probe, "deny", ["no PRIORITY"],
        ),
        (
            "no triage state",
            f'gh issue create --title T --body "{GOOD_BODY}" --label bug,P1',
            with_probe, "deny", ["no TRIAGE STATE"],
        ),
        (
            "two priorities",
            f'gh issue create --title T --body "{GOOD_BODY}" --label bug,P0,P1,needs-triage',
            with_probe, "deny", ["multiple PRIORITY"],
        ),
        (
            "roadmap must not carry a priority",
            f'gh issue create --title T --body "{GOOD_BODY}" --label enhancement,roadmap,P1',
            with_probe, "deny", ["roadmap` carries no priority"],
        ),
        (
            "roadmap must not carry a triage state",
            f'gh issue create --title T --body "{GOOD_BODY}" --label enhancement,roadmap,needs-triage',
            with_probe, "deny", ["roadmap` carries no triage state"],
        ),
        (
            "no labels at all",
            'gh issue create --title T --body "some text"',
            with_probe, "deny", ["no TYPE label"],
        ),
        (
            "automation-owned label at filing (do-not-close)",
            f'gh issue create --title T --body "{GOOD_BODY}" --label bug,P0,needs-triage,do-not-close',
            with_probe, "deny", ["automation-owned"],
        ),

        # --- ask: human-judgement cases ---
        (
            "security label -> ask",
            f'gh issue create --title T --body "{GOOD_BODY}" --label bug,P1,needs-triage,security',
            with_probe, "ask", ["security", "advisories"],
        ),
        (
            "missing dedupe probe -> ask",
            valid, no_probe, "ask", ["duplicate-search probe"],
        ),
        (
            "resolvable body missing sections -> ask",
            'gh issue create --title T --body "just a one liner" --label bug,P1,needs-triage',
            with_probe, "ask", ["missing required section"],
        ),

        # --- precedence: a label deny outranks a body/security ask ---
        (
            "deny outranks ask when both apply",
            'gh issue create --title T --body "one liner" --label P1,needs-triage,security',
            with_probe, "deny", ["no TYPE label"],
        ),

        # --- red-team regressions (confirmed defects, now fixed) ---
        (
            "R1: extra whitespace between tokens does not bypass the gate",
            f'gh   issue   create --title T --body "{GOOD_BODY}" --label do-not-close',
            with_probe, "deny", ["automation-owned"],
        ),
        (
            "R2: newline-joined typeless first create is still caught",
            f'gh issue create --title T --label P1,needs-triage\n'
            f'gh issue create --title T2 --body "{GOOD_BODY}" --label bug,P1,needs-triage',
            with_probe, "deny", ["no TYPE label"],
        ),
        (
            "R2b: newline-joined typeless SECOND create is caught",
            f'gh issue create --title T1 --body "{GOOD_BODY}" --label bug,P1,needs-triage\n'
            f'gh issue create --title T2 --label P1,needs-triage',
            with_probe, "deny", ["no TYPE label"],
        ),
        (
            "R8: a quoted operator in the title does not truncate the flag list",
            f'gh issue create --title "&" --body "{GOOD_BODY}" --label bug,P1,needs-triage',
            with_probe, "allow", [],
        ),
        (
            "R9: a quoted semicolon does not hide a later automation-owned label",
            f'gh issue create --title ";" --body "{GOOD_BODY}" --label bug,P1,needs-triage --label do-not-close',
            with_probe, "deny", ["automation-owned"],
        ),
        (
            "R10: a pipe glued to the label value does not over-block a valid create",
            f'gh issue create --title T --body "{GOOD_BODY}" --label bug,P1,needs-triage|grep foo',
            with_probe, "allow", [],
        ),
        (
            "R3: mis-cased SECURITY label still asks",
            f'gh issue create --title T --body "{GOOD_BODY}" --label bug,P1,needs-triage,SECURITY',
            with_probe, "ask", ["security"],
        ),
        (
            "R3b: mis-cased DO-NOT-CLOSE still denies",
            f'gh issue create --title T --body "{GOOD_BODY}" --label bug,P1,needs-triage,DO-NOT-CLOSE',
            with_probe, "deny", ["automation-owned"],
        ),
        (
            "R3c: all-caps valid labels are accepted (GitHub is case-insensitive)",
            f'gh issue create --title T --body "{GOOD_BODY}" --label BUG,P1,NEEDS-TRIAGE',
            with_probe, "allow", [],
        ),
        (
            "path-prefixed gh is still matched",
            f'/usr/bin/gh issue create --title T --body "{GOOD_BODY}" --label P1,needs-triage',
            with_probe, "deny", ["no TYPE label"],
        ),
        (
            "redirection after the flags does not break parsing",
            f'gh issue create --title T --body "{GOOD_BODY}" --label bug,P1,needs-triage > out.txt',
            with_probe, "allow", [],
        ),
        (
            "R7: heredoc body prose is not parsed as flags",
            'gh issue create --title T --label bug,P1,needs-triage --body-file - <<EOF\n'
            'Context: this mentions --label do-not-close in prose\nEOF',
            with_probe, "allow", [],
        ),

        # --- red-team pass 2 regressions (rewrite defects, now fixed) ---
        (
            "RT2-1: `<<` in a quoted body does not corrupt parsing (bypass fixed)",
            'gh issue create --title T --label bug,P1,needs-triage,do-not-close '
            '--body "## Evidence\nsee foo.cpp:42 cout << data << endl\nmore text"',
            with_probe, "deny", ["automation-owned"],
        ),
        (
            "RT2-1b: Erlang `<<Bin>>` in a quoted body is not a heredoc",
            'gh issue create --title T --label bug,P1,needs-triage,do-not-close '
            '--body "uses <<Payload>> binaries"',
            with_probe, "deny", ["automation-owned"],
        ),
        (
            "RT2-2: `<<` in a quoted body does not strip a section (over-block fixed)",
            'gh issue create --title T --label bug,P1,needs-triage --body '
            '"## Context\nc\n## Evidence\nqueue << STOP marker\n'
            '## Acceptance criteria\nac\nSTOP\n## Origin\nprobes ran"',
            with_probe, "allow", [],
        ),
        (
            "RT2-3: a `<<<` here-string does not swallow the create",
            'gh issue create --title T --label bug,P1,needs-triage,do-not-close <<< "input"',
            with_probe, "deny", ["automation-owned"],
        ),
        (
            "RT2-4: a line continuation inside the create phrase is caught",
            'gh issue \\\ncreate --title T --label bug,P1,needs-triage,do-not-close',
            with_probe, "deny", ["automation-owned"],
        ),
        (
            "RT2-7: gh.exe is matched (Windows)",
            f'gh.exe issue create --title T --body "{GOOD_BODY}" --label P1,needs-triage',
            with_probe, "deny", ["no TYPE label"],
        ),

        # --- adversarial-review (Codex) regressions ---
        (
            "C1: labels after a shell `#` comment are not counted (smuggle fixed)",
            'gh issue create --title T --label P1 # --label bug,needs-triage',
            with_probe, "deny", ["no TYPE label"],
        ),
        (
            "C1b: a prose trailing comment does not break a valid create",
            f'gh issue create --title T --body "{GOOD_BODY}" '
            '--label bug,P1,needs-triage # filing the parser bug',
            with_probe, "allow", [],
        ),
        (
            "C4: `echo gh issue create ...` is not a filing (over-block fixed)",
            'echo gh issue create --title T --label P1,needs-triage',
            with_probe, "allow", [],
        ),
        (
            "C4b: `command gh issue create` (wrapper) is still enforced",
            'command gh issue create --title T --label P1,needs-triage',
            with_probe, "deny", ["no TYPE label"],
        ),
        (
            "C4c: `sudo gh issue create` (wrapper) is still enforced",
            'sudo gh issue create --title T --label P1,needs-triage',
            with_probe, "deny", ["no TYPE label"],
        ),
        (
            "C4d: `VAR=1 gh issue create` (assignment prefix) is still enforced",
            'GH_HOST=github.com gh issue create --title T --label P1,needs-triage',
            with_probe, "deny", ["no TYPE label"],
        ),

        # --- governance (unhappy-path HIGH): command-substitution / grouping smuggle ---
        (
            "G-HIGH: URL=$(gh issue create ...) capture idiom is enforced",
            'URL=$(gh issue create --title T --label bug,P1,needs-triage,do-not-close)',
            with_probe, "deny", ["automation-owned"],
        ),
        (
            "G-HIGH: bare $(gh issue create ...) capture is enforced",
            'N=$(gh issue create --title T --label P1,needs-triage)',
            with_probe, "deny", ["no TYPE label"],
        ),
        (
            "G-HIGH: backtick capture is enforced",
            'URL=`gh issue create --title T --label P1,needs-triage`',
            with_probe, "deny", ["no TYPE label"],
        ),
        (
            "G-HIGH: ( subshell ) is enforced",
            '( gh issue create --title T --label P1,needs-triage )',
            with_probe, "deny", ["no TYPE label"],
        ),
        (
            "G-HIGH: `if ! gh issue create` is enforced",
            'if ! gh issue create --title T --label P1,needs-triage; then echo x; fi',
            with_probe, "deny", ["no TYPE label"],
        ),
        (
            "G-HIGH: `{ ...; }` grouping is enforced",
            '{ gh issue create --title T --label P1,needs-triage; }',
            with_probe, "deny", ["no TYPE label"],
        ),
        (
            "G-HIGH: leading redirection prefix is enforced",
            '> out.txt gh issue create --title T --label P1,needs-triage',
            with_probe, "deny", ["no TYPE label"],
        ),
        (
            "G-HIGH: /usr/bin/env wrapper (basename) is enforced",
            '/usr/bin/env gh issue create --title T --label P1,needs-triage',
            with_probe, "deny", ["no TYPE label"],
        ),
        (
            "G-HIGH: `timeout 5 gh` (arg-wrapper) is enforced",
            'timeout 5 gh issue create --title T --label P1,needs-triage',
            with_probe, "deny", ["no TYPE label"],
        ),
        (
            "G-HIGH-neg: a VALID create captured in $() is allowed",
            f'URL=$(gh issue create --title T --body "{GOOD_BODY}" --label bug,P1,needs-triage)',
            with_probe, "allow", [],
        ),

        # --- governance (quality-engineer M2): equals / glued parse forms ---
        (
            "M2: `--label=` equals form parses",
            f'gh issue create --title T --body "{GOOD_BODY}" --label=bug,P1,needs-triage',
            with_probe, "allow", [],
        ),
        (
            "M2: glued `-lX` short cluster parses",
            f'gh issue create --title T --body "{GOOD_BODY}" -lbug -lP1 -lneeds-triage',
            with_probe, "allow", [],
        ),
        (
            "M2: typeless glued `-lX` is denied (no silent pass)",
            f'gh issue create --title T --body "{GOOD_BODY}" -lP1 -lneeds-triage',
            with_probe, "deny", ["no TYPE label"],
        ),
        (
            "M2: `--body=` equals form is inspected (missing sections -> ask)",
            'gh issue create --title T --label bug,P1,needs-triage --body=just-a-one-liner',
            with_probe, "ask", ["missing required section"],
        ),
    ]


def main() -> int:
    failures: list[str] = []

    if not HOOK.is_file():
        print(f"hook not found: {HOOK}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        with_probe = make_transcript(tmp, [
            "gh issue list --repo Tr3kkR/Yuzu --state open --search foo.cpp",
            "cat foo.cpp",
        ], "with_probe")
        no_probe = make_transcript(tmp, ["cat foo.cpp", "ls -la"], "no_probe")

        for name, cmd, transcript, want, subs in build_cases(with_probe, no_probe):
            try:
                decision, reason = run_hook(cmd, transcript_path=transcript)
            except AssertionError as exc:
                failures.append(f"[{name}] {exc}")
                continue
            if decision != want:
                failures.append(
                    f"[{name}] decision={decision!r} want={want!r} reason={reason!r}"
                )
                continue
            for sub in subs:
                if sub not in reason:
                    failures.append(f"[{name}] reason missing {sub!r}: {reason!r}")

        # --- fail-open on malformed input (must never wedge a session) ---
        for label, raw in [
            ("empty stdin", b""),
            ("non-JSON stdin", b"not json at all"),
            ("unbalanced quotes in command",
             json.dumps({"tool_name": "Bash",
                         "tool_input": {"command": 'gh issue create --title "oops'}}).encode()),
            ("missing transcript_path is not fatal",
             json.dumps({"tool_name": "Bash",
                         "tool_input": {"command": "gh pr view 1"}}).encode()),
        ]:
            try:
                decision, _ = run_hook(None, raw_stdin=raw)
                if decision != "allow":
                    failures.append(f"[fail-open: {label}] decision={decision!r} want allow")
            except AssertionError as exc:
                failures.append(f"[fail-open: {label}] {exc}")

        # --- dedupe probe detection is tokenised, not substring (R5/R6) ---
        valid_create = f'gh issue create --title T --body "{GOOD_BODY}" --label bug,P1,needs-triage'
        echo_fake = make_transcript(tmp, ['echo "gh search issues foo"', "ls"], "echo_fake")
        s_in_value = make_transcript(
            tmp, ["gh issue list --repo Tr3kkR/Yuzu-Server --state open"], "s_in_value")
        real_short = make_transcript(tmp, ["gh issue list -S foo.cpp"], "real_short")
        global_flag = make_transcript(
            tmp, ["gh --repo Tr3kkR/Yuzu issue list --search foo"], "global_flag")
        glued_s = make_transcript(tmp, ["gh issue list -Sfoo"], "glued_s")
        gh_exe = make_transcript(tmp, ["gh.exe issue list --search bar"], "gh_exe")
        for label, transcript, want in [
            ("R5: echo of probe text is not a real probe", echo_fake, "ask"),
            ("R6: -S inside a value is not a probe", s_in_value, "ask"),
            ("real -S short-flag probe is recognised", real_short, "allow"),
            ("RT2-5: global flag before subcommand still a probe", global_flag, "allow"),
            ("RT2-6: glued -Sfoo short-flag is a probe", glued_s, "allow"),
            ("RT2-7b: gh.exe probe is recognised", gh_exe, "allow"),
        ]:
            try:
                decision, _ = run_hook(valid_create, transcript_path=transcript)
                if decision != want:
                    failures.append(f"[{label}] decision={decision!r} want={want!r}")
            except AssertionError as exc:
                failures.append(f"[{label}] {exc}")

        # --- R4: an oversized command fails open (no O(n^2) shlex stall) ---
        huge = "gh issue create --title T --label do-not-close --body " + ("A" * 40000)
        try:
            decision, _ = run_hook(huge, transcript_path=with_probe)
            if decision != "allow":
                failures.append(f"[R4: oversized command fails open] decision={decision!r} want allow")
        except AssertionError as exc:
            failures.append(f"[R4: oversized command fails open] {exc}")

        # --- C2: PowerShell backtick-newline continuation is normalised ---
        for label, cmd, want in [
            ("C2: PS backtick-cont between issue and create",
             "gh issue `\ncreate --title T --label P1,needs-triage", "deny"),
            ("C2b: PS backtick-cont between flags",
             "gh issue create --title T `\n--label P1,needs-triage", "deny"),
        ]:
            try:
                decision, _ = run_hook(cmd, transcript_path=with_probe, tool_name="PowerShell")
                if decision != want:
                    failures.append(f"[{label}] decision={decision!r} want={want!r}")
            except AssertionError as exc:
                failures.append(f"[{label}] {exc}")

        # --- C3: the ADR-mandated YUZU_ISSUE_STANDARD_ACK=1 operator bypass ---
        bad = "gh issue create --title T --label P1,needs-triage"  # no type -> would deny
        try:
            decision, _ = run_hook(bad, transcript_path=with_probe,
                                   env_extra={"YUZU_ISSUE_STANDARD_ACK": "1"})
            if decision != "allow":
                failures.append(f"[C3: ACK=1 bypass] decision={decision!r} want allow")
            decision, _ = run_hook(bad, transcript_path=with_probe,
                                   env_extra={"YUZU_ISSUE_STANDARD_ACK": "0"})
            if decision != "deny":
                failures.append(f"[C3: ACK=0 does not bypass] decision={decision!r} want deny")
        except AssertionError as exc:
            failures.append(f"[C3: ACK bypass] {exc}")

        # --- non-shell tool is ignored ---
        try:
            decision, _ = run_hook("gh issue create --label bug", transcript_path=no_probe,
                                   tool_name="Edit")
            if decision != "allow":
                failures.append(f"[non-shell tool ignored] decision={decision!r} want allow")
        except AssertionError as exc:
            failures.append(f"[non-shell tool ignored] {exc}")

        # --- META: the hook is provably live (not a silent no-op) ---
        deny_dec, _ = run_hook(
            'gh issue create --title T --label P1,needs-triage', transcript_path=with_probe)
        if deny_dec != "deny":
            failures.append(
                "META: a known-bad create did not deny -- the guard is disabled/no-op")
        allow_dec, _ = run_hook(
            f'gh issue create --title T --body "{GOOD_BODY}" --label bug,P1,needs-triage',
            transcript_path=with_probe)
        if allow_dec != "allow":
            failures.append(
                "META: a known-good create did not allow -- the guard over-blocks")

    if failures:
        print(f"issue-guard hook checks FAILED ({len(failures)}):")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("issue-guard hook checks OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
