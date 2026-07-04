#!/usr/bin/env python3
"""
changelog-fragment-guard.py -- PreToolUse hook: deny direct CHANGELOG.md edits.

This repo records unreleased changes as one-file-per-change fragments under
changelog.d/ (see changelog.d/README.md). Direct edits to CHANGELOG.md's
[Unreleased] section made every second PR conflict — two PRs inserting bullets
at the same line can never auto-merge — and the conflict-resolution push voided
the PR's approvals (dev ruleset: require_last_push_approval). The fix is
structural: PRs create uniquely-named fragment files that cannot conflict, and
CHANGELOG.md is only rewritten at release time by
`python3 scripts/assemble-changelog.py promote X.Y.Z` (a Bash call, so this
hook never blocks the release promote).

Wired via .claude/settings.json -> hooks.PreToolUse (matcher Edit|Write|
MultiEdit|NotebookEdit). Reads the PreToolUse JSON on stdin; when the target
file is CHANGELOG.md it denies the tool call with a reason that tells the
agent exactly what to do instead. The docs-lint `Changelog fragments` CI job
is the server-side backstop for sessions without hooks.

Design (matches erl-dialyzer-reminder.py conventions):
  - Fail-open: ANY error -> allow the call (no output, exit 0). A convention
    hook must never wedge a session.
  - UTF-8 explicit on stdin (never inherit cp1252 on Windows; see memory
    reference_hookify_ascii_only).
  - ALWAYS exit 0; the decision is carried in the JSON, not the exit code.
"""
import json
import os
import sys

EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")

REASON = """\
Direct edits to CHANGELOG.md are disabled in this repo: every PR that touched
the [Unreleased] section conflicted with whichever PR merged first, and the
rebase push voided the PR's approvals.

Do this instead -- add ONE new file (fragments can never conflict):

    changelog.d/<PR-or-issue-number>-<short-slug>.<section>.md
    <section> = added | changed | deprecated | removed | fixed | security

The file body is the finished changelog bullet(s), starting with "- ", written
exactly as they should appear under "### Added" (etc.) in CHANGELOG.md.
Example: changelog.d/1832-inventory-devices-tab.added.md

If this branch ALREADY has direct CHANGELOG.md edits (e.g. a PR opened before
this convention), this recipe converts them to fragments and restores the file:

    git fetch origin dev
    git checkout origin/dev -- scripts/assemble-changelog.py changelog.d/README.md
    python3 scripts/assemble-changelog.py --extract origin/dev --id <PR#>

Full convention: changelog.d/README.md. CHANGELOG.md is rewritten only at
release time via `python3 scripts/assemble-changelog.py promote X.Y.Z` (run it
with Bash -- this guard only covers the file-edit tools). Fixing a typo in an
already-released section is rare and operator-owned: ask the user, who can
approve a Bash-based edit or make it themselves."""


def main():
    # Read stdin as UTF-8 bytes -> json (never trust locale/cp1252).
    try:
        raw = sys.stdin.buffer.read()
        data = json.loads(raw.decode("utf-8", errors="replace")) if raw else {}
    except Exception:
        return  # fail-open

    if data.get("tool_name") not in EDIT_TOOLS:
        return
    tool_input = data.get("tool_input") or {}
    file_path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
    if os.path.basename(file_path) != "CHANGELOG.md":
        return

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": REASON,
        }
    }))


if __name__ == "__main__":
    try:
        main()
    finally:
        sys.exit(0)  # ALWAYS exit 0 -- decision is in the JSON, never the exit code
