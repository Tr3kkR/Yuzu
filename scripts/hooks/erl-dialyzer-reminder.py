#!/usr/bin/env python3
"""
erl-dialyzer-reminder.py -- Stop hook: nudge to run dialyzer after Erlang edits.

CLAUDE.md mandate: "Always run rebar3 dialyzer after any Erlang change.
Compilation succeeding is not enough." This hook fires exactly when that rule is
at risk -- at the end of a turn where THIS session edited a .erl file but has not
run dialyzer since the last such edit -- and emits a one-shot block so the agent
runs dialyzer before concluding.

Wired via .claude/settings.json -> hooks.Stop. Reads the Stop-hook JSON on stdin
(transcript_path + stop_hook_active), scans the transcript for tool calls.

Design:
  - Conditional: triggers only on a real .erl edit in this session (transcript
    scan), never a blanket "every stop" reminder.
  - Self-clearing: a `rebar3 dialyzer` Bash call AFTER the last .erl edit
    satisfies the rule -> stay silent.
  - One-shot: if stop_hook_active is already true, allow the stop. Never loops,
    never nags more than once per continuation chain.
  - Fail-open: ANY error -> allow the stop (exit 0, no decision). A reminder hook
    must never wedge a session.
  - UTF-8 explicit on every read (stdin + transcript). Never inherit cp1252.
    (see memory reference_hookify_ascii_only for why that bites on Windows)
"""
import json
import os
import sys

EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")
SHELL_TOOLS = ("Bash", "PowerShell")


def _iter_tool_uses(transcript_path):
    """Yield (line_index, tool_name, tool_input) for every tool_use in the transcript."""
    with open(transcript_path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            msg = rec.get("message", rec)
            content = msg.get("content") if isinstance(msg, dict) else None
            if not isinstance(content, list):
                continue
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    yield i, block.get("name", ""), block.get("input", {}) or {}


def main():
    # Read stdin as UTF-8 bytes -> json (never trust locale/cp1252).
    try:
        raw = sys.stdin.buffer.read()
        data = json.loads(raw.decode("utf-8", errors="replace")) if raw else {}
    except Exception:
        return  # fail-open

    # One-shot guard: we already blocked this stop cycle -> let it stop now.
    if data.get("stop_hook_active"):
        return

    transcript_path = data.get("transcript_path")
    if not transcript_path:
        return
    transcript_path = os.path.expanduser(transcript_path)
    if not os.path.isfile(transcript_path):
        return

    last_erl_edit = -1
    last_dialyzer = -1
    edited = []
    try:
        for idx, name, tin in _iter_tool_uses(transcript_path):
            if name in EDIT_TOOLS:
                fp = str(tin.get("file_path") or tin.get("notebook_path") or "")
                if fp.endswith(".erl"):
                    last_erl_edit = idx
                    if fp not in edited:
                        edited.append(fp)
            elif name in SHELL_TOOLS:
                if "dialyzer" in str(tin.get("command") or ""):
                    last_dialyzer = idx
    except Exception:
        return  # fail-open

    if last_erl_edit < 0:
        return                       # no Erlang edited this session
    if last_dialyzer > last_erl_edit:
        return                       # dialyzer already run since the last .erl edit

    shown = [os.path.basename(f) for f in edited[:5]]
    more = "" if len(edited) <= 5 else f" (+{len(edited) - 5} more)"
    files_str = ", ".join(shown) + more

    reason = (
        f"You edited Erlang source this session ({files_str}) but have not run "
        "dialyzer since. CLAUDE.md requires dialyzer to be clean before commit -- "
        "compilation succeeding is NOT enough; dialyzer catches type violations, "
        "dead code, and missing deps the compiler silently accepts.\n\n"
        "Run it before finishing (or use the /gateway-dialyzer skill):\n"
        "    source scripts/ensure-erlang.sh\n"
        "    cd gateway && rebar3 dialyzer\n\n"
        "If there is a specific reason to skip (e.g. no semantic .erl change), say "
        "so and stop again -- this reminder fires only once per stop."
    )
    print(json.dumps({"decision": "block", "reason": reason}))


if __name__ == "__main__":
    try:
        main()
    finally:
        sys.exit(0)  # ALWAYS exit 0 -- a reminder must never trap the session
