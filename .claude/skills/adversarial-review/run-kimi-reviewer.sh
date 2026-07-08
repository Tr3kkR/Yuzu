#!/usr/bin/env bash
# run-kimi-reviewer.sh — drive the Kimi Code side of an adversarial two-phase review.
#
# Mirror of run-codex-reviewer.sh for the `kimi` CLI (Kimi Code, `kimi -p`).
# Renders the SAME review-prompt.md body (identical question/severity bar), appends
# an execution-environment note, then runs `kimi -p` non-interactively. Kimi writes
# its own review to $REVIEW_DIR/kimi.phaseN.md (its Read/Write tools are auto-approved
# headless); we also capture stdout to a summary file.
#
# NOTE (corrected 2026-07-03, kimi-code 0.17.0): `kimi -p` REFUSES to combine with
# `--yolo`/`--auto` ("Cannot combine"), but empirically its shell tool still executes
# benign commands (compiles, targeted test runs) in prompt mode without either flag —
# there is no interactive approval prompt to hang on headless. Default mode below stays
# STATIC-READ for backward-compat/safety; pass --dynamic when the caller has already
# prepared a working build dir (see docs/adr and the worktree+vcpkg-symlink build recipe)
# and wants Kimi to actually compile/run tests.
#
# Usage:
#   run-kimi-reviewer.sh --phase 1 --review-dir DIR --target "PR #X, head abc, diff A..B" \
#       [--repo .] [--anchors "- CLAUDE.md\n- docs/foo.md §3"] \
#       [--self kimi] [--peer codex] [--model NAME] [--dynamic]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROMPT_TEMPLATE="$SCRIPT_DIR/review-prompt.md"

PHASE=""
REVIEW_DIR=""
TARGET=""
REPO="$(pwd)"
ANCHORS="(none specified — fall back to CLAUDE.md routing table + the docs it points changed files at)"
SELF="kimi"
PEER="codex"
MODEL=""
DYNAMIC="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase)       PHASE="$2"; shift 2 ;;
    --review-dir)  REVIEW_DIR="$2"; shift 2 ;;
    --target)      TARGET="$2"; shift 2 ;;
    --repo)        REPO="$2"; shift 2 ;;
    --anchors)     ANCHORS="$2"; shift 2 ;;
    --self)        SELF="$2"; shift 2 ;;
    --peer)        PEER="$2"; shift 2 ;;
    --model)       MODEL="$2"; shift 2 ;;
    --dynamic)     DYNAMIC="true"; shift 1 ;;
    --prompt-template) PROMPT_TEMPLATE="$2"; shift 2 ;;
    -h|--help)     grep '^#' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -n "$PHASE" && -n "$REVIEW_DIR" && -n "$TARGET" ]] || {
  echo "error: --phase, --review-dir, and --target are required" >&2; exit 2; }
[[ "$PHASE" == "1" || "$PHASE" == "2" ]] || { echo "error: --phase must be 1 or 2" >&2; exit 2; }
[[ -f "$PROMPT_TEMPLATE" ]] || { echo "error: prompt template not found: $PROMPT_TEMPLATE" >&2; exit 2; }

mkdir -p "$REVIEW_DIR"
REPO="$(cd "$REPO" && pwd)"
REVIEW_DIR="$(cd "$REVIEW_DIR" && pwd)"

render() {
  local body
  body="$(cat "$PROMPT_TEMPLATE")"
  body="${body//\{\{SELF\}\}/$SELF}"
  body="${body//\{\{PEER\}\}/$PEER}"
  body="${body//\{\{TARGET\}\}/$TARGET}"
  body="${body//\{\{REPO\}\}/$REPO}"
  body="${body//\{\{REVIEW_DIR\}\}/$REVIEW_DIR}"
  body="${body//\{\{PHASE\}\}/$PHASE}"
  body="${body//\{\{ANCHORS\}\}/$ANCHORS}"
  printf '%s\n' "$body"
}

# Execution-environment addendum (this reviewer only) — keeps the review BODY identical
# but tells Kimi whether shell execution is available this run.
if [[ "$DYNAMIC" == "true" ]]; then
read -r -d '' ADDENDUM <<'EOF' || true

---
## EXECUTION ENVIRONMENT (this reviewer instance only — does not change the review question)
You are running headless with a REAL, UNSANDBOXED shell tool on the orchestrator's host — commands
you run execute directly, with no OS-level jail and no approval prompt. Stay strictly within the
review task: read and verify the repo at REPO, write your phase file, nothing else.
Use the shell to make your review EMPIRICAL rather than static:
- `git grep` / read the ACTUAL source and docs in the working root to verify the change's factual
  claims — cited line numbers, cross-references, "shipped"/"merged" assertions, and any claim about
  code state — instead of trusting the diff's prose. `git log` / `git branch --contains` settle
  merge-state claims.
- The full diff is materialized at `REVIEW_DIR/DIFF.patch` if you prefer it over `git diff`.
- IF a configured `build-<os>/` build dir is present (check first — it may not be), you may compile the
  changed TUs and run targeted test tags (e.g. `./tests-build-server-<triplet>/yuzu_server_tests
  "[tag]"`, preferred over the full `meson test` suite). If none is present — e.g. a docs-only change
  with nothing to compile — do NOT attempt `meson setup`/compile; verify by reading/grepping instead.
Tag any finding you verified by running a command (a grep that proved a claim, a test you ran)
PROVENANCE `test-run` (or `compiled` if you built it); reserve `static-read` for diff-reading only.
State exactly what you ran and its result in the RAN section.
Everything else in the protocol above (severity bar, schema, phases, writing your phase file to the
path given) applies unchanged.
EOF
else
read -r -d '' ADDENDUM <<'EOF' || true

---
## EXECUTION ENVIRONMENT (this reviewer instance only — does not change the review question)
You are running headless in READ-ONLY EXECUTION mode. Your file **Read and Write tools work**
(use them to read the diff/source/anchors and to write your phase file), but **shell/command
execution is UNAVAILABLE** — any attempt to run a shell command, compile, run tests, or invoke
git WILL be denied and waste the run. Therefore:
- Do NOT attempt to compile or run tests or run any shell command. Inspect code by READING files
  in the working tree.
- Tag every finding PROVENANCE as `static-read`.
- In the RAN section, state plainly: "empiricism unavailable this run (read-only mode) — review is
  static-read only."
Everything else in the protocol above (severity bar, schema, phases, writing your phase file to the
path given) applies unchanged.
EOF
fi

PROMPT="$(render)$ADDENDUM"
SUMMARY_FILE="$REVIEW_DIR/$SELF.phase$PHASE.summary.md"

echo ">> Kimi reviewer: SELF=$SELF PEER=$PEER PHASE=$PHASE (dynamic=$DYNAMIC)" >&2
echo ">> repo=$REPO  review_dir=$REVIEW_DIR" >&2
echo ">> expecting Kimi to write: $REVIEW_DIR/$SELF.phase$PHASE.md" >&2

KIMI_ARGS=(-p "$PROMPT")
[[ -n "$MODEL" ]] && KIMI_ARGS+=(-m "$MODEL")

# kimi runs in the cwd; cd into the repo so relative paths resolve.
( cd "$REPO" && kimi "${KIMI_ARGS[@]}" ) 2>&1 | tee "$SUMMARY_FILE" >&2 || true

PHASE_FILE="$REVIEW_DIR/$SELF.phase$PHASE.md"
if [[ -s "$PHASE_FILE" ]]; then
  echo ">> OK: $PHASE_FILE ($(wc -l < "$PHASE_FILE") lines)" >&2
else
  echo ">> WARNING: $PHASE_FILE missing or empty — Kimi may not have written it." >&2
  echo ">> Check its stdout summary at: $SUMMARY_FILE" >&2
  exit 1
fi
