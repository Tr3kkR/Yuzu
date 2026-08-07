#!/usr/bin/env bash
#
# SessionStart hook: inject docs/claim-discipline.md into every session in this repo.
#
# This script carries no copy of the rules text — docs/claim-discipline.md is their
# single home (see that file's rule 1). Changing the rules means editing that file;
# this script only reads it. Keeping a second copy here is the exact edit-time drift
# rule 1 exists to prevent, applied to the mechanism that ships rule 1.
#
# Fails OPEN: a missing `jq`, a missing doc, or any other error means no context is
# injected and the session starts normally. This hook must never block a session.
set -uo pipefail

command -v jq >/dev/null 2>&1 || exit 0

cd "${CLAUDE_PROJECT_DIR:-$PWD}" 2>/dev/null || exit 0

DOC="docs/claim-discipline.md"
[ -f "$DOC" ] || exit 0

RULES="$(cat "$DOC")" || exit 0
[ -n "$RULES" ] || exit 0

jq -n --arg ctx "$RULES" \
  '{hookSpecificOutput: {hookEventName: "SessionStart", additionalContext: $ctx}}'
