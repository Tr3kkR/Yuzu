#!/usr/bin/env bash
#
# SessionStart hook: inject docs/claim-discipline.md into every Claude Code session
# in this repo. (Codex sessions don't run Claude Code SessionStart hooks — they get
# Gate 0 review-time coverage only, via .codex/skills/governance/SKILL.md's pointer
# to this doc, not this ambient injection.)
#
# This script carries no copy of the rules text — docs/claim-discipline.md is their
# single home (see that file's rule 1). Changing the rules means editing that file;
# this script only reads it. Keeping a second copy here is the exact edit-time drift
# rule 1 exists to prevent, applied to the mechanism that ships rule 1.
#
# Fails OPEN: a missing `jq`, a missing doc, or any other error means no context is
# injected and the session starts normally. This hook must never block a session.
# That silence is permanent and per-contributor if `jq` itself is missing — 3
# independent Gate 6/4 reviewers flagged this on the PR that added this script
# (nothing signals "skipped" vs "ran and found nothing"; unverified whether Claude
# Code surfaces SessionStart hook stderr/exit codes anywhere a contributor would
# see). Mitigating, not fixing: `jq` is already a silent hard dependency of this
# repo's OWN governance ledger mechanics (`.claude/skills/governance/SKILL.md`
# Gate 8's `jq -e` checks) — a contributor missing it has a bigger, pre-existing gap
# than losing this hook's injection. Not solved here; noted so a future fix knows
# the actual blast radius before building one.
set -uo pipefail

command -v jq >/dev/null 2>&1 || exit 0

cd "${CLAUDE_PROJECT_DIR:-$PWD}" 2>/dev/null || exit 0

DOC="docs/claim-discipline.md"
[ -f "$DOC" ] || exit 0

RULES="$(cat "$DOC")" || exit 0
[ -n "$RULES" ] || exit 0

jq -n --arg ctx "$RULES" \
  '{hookSpecificOutput: {hookEventName: "SessionStart", additionalContext: $ctx}}' \
  || exit 0
