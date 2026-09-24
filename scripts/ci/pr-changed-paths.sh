#!/usr/bin/env bash
# pr-changed-paths.sh — the paths a pull request changes, read from the commit CI builds.
#
# On a pull_request run every job checks out GitHub's test merge commit M (first parent the base
# tip, second the PR head). What the PR changes, as built, is diff(M^1, M): bound to the commit the
# jobs test, no file-count cap, no API call, and `--no-renames` lists both sides of a rename. ci.yml
# feeds it to the docs-only gate and to scripts/ci/affected-suites.sh.
#
# Output: one path per line, as git prints it with core.quotePath=false (a path git still C-quotes
# starts with `"`, and both classifiers fail closed on it). Exits non-zero, printing nothing, unless
# HEAD is that merge commit: HEAD equals $GITHUB_SHA (when set), has exactly two parents, and the
# second is PR_HEAD_SHA. The checkout must include the parents (`fetch-depth: 2`).
#
# Usage: pr-changed-paths.sh PR_HEAD_SHA > paths
# Tests: tests/shell/test_suite_selection_wiring.sh (a real merge commit in a scratch repository).
set -euo pipefail

head_sha="${1:-}"
if [[ ! "$head_sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "pr-changed-paths: usage: pr-changed-paths.sh PR_HEAD_SHA (40 hex digits)" >&2
  exit 2
fi
merge="$(git rev-parse --verify HEAD)"
if [[ -n "${GITHUB_SHA:-}" && "$merge" != "$GITHUB_SHA" ]]; then
  echo "pr-changed-paths: HEAD $merge is not this run's commit $GITHUB_SHA" >&2
  exit 1
fi
read -r -a commit <<< "$(git rev-list --parents -n 1 "$merge")"
if (( ${#commit[@]} != 3 )); then
  echo "pr-changed-paths: HEAD $merge is not a two-parent merge commit (or its parents were not fetched)" >&2
  exit 1
fi
if [[ "${commit[2]}" != "$head_sha" ]]; then
  echo "pr-changed-paths: the merge commit's second parent ${commit[2]} is not the PR head $head_sha" >&2
  exit 1
fi
# Buffered, so a failing diff prints nothing; an empty diff prints nothing either (no blank line,
# which a line reader would take for one path), and both consumers treat an empty list as run-all.
paths="$(git --no-pager -c core.quotePath=false diff --no-ext-diff --no-renames --name-only \
           "${commit[1]}" "$merge" --)"
if [[ -n "$paths" ]]; then printf '%s\n' "$paths"; fi
