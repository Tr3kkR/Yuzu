#!/usr/bin/env bash
# detect-code-change.sh — fail-closed changed-path classifier for ci.yml.
#
# Prints exactly "true" or "false" to stdout; diagnostics go to stderr.
#
# Interfaces:
#
#   detect-code-change.sh [--class code] [TOTAL] < changed-paths
#
#     The existing docs-only gate (issue #1978). Reads one path per line from
#     stdin. TOTAL is GitHub's authoritative pull_request.changed_files count.
#
#   detect-code-change.sh --class ci-infrastructure --git-diff BASE [HEAD]
#
#     The workflow canary gate. Establishes the diff itself, then reports true
#     iff it includes .github/workflows/, .github/actions/, or scripts/ci/.
#     A diff error reports true: an uncertain change set must run the canary.
#
# The default class remains `code` for backward compatibility.
#
# For the default `code` class, the optional positional TOTAL is GitHub's
# authoritative pull_request.changed_files count. It guards the "List pull
# requests files" REST endpoint's 3000-file cap: if the piped list is shorter
# than this count the list was truncated, and we FAIL CLOSED to "true" (build)
# rather than trust a partial view that might hide a code file past the cap.
#
# The docs-only ignore set mirrors the pull_request `paths-ignore` ci.yml used
# to carry, with GitHub's root-anchored filter semantics — a bare `*.md`,
# `LICENSE`, or `.gitignore` pattern matches ONLY the repository root, never a
# nested path:
#   - docs/**                        (any depth under docs/)
#   - root-level *.md                (README.md, but NOT sdk/README.md)
#   - LICENSE, .gitignore            (root only)
#   - .github/runner-inventory.json
#   - .github/workflows/runner-inventory-sentinel.yml
# Anything else -> code_changed=true. Fail-closed throughout: any uncertainty
# (empty list, truncated list) builds rather than silently skipping the matrix.
#
# KEEP IN SYNC: this ignore set must match the `push:` trigger's paths-ignore
# in .github/workflows/ci.yml — editing one without the other diverges PR-time
# and post-merge build behaviour.
#
# Run tests:  bash tests/shell/test_detect_code_change.sh
set -euo pipefail

path_class="code"
expected_total=""

usage() {
  cat >&2 <<'EOF'
usage:
  detect-code-change.sh [--class code] [TOTAL] < changed-paths
  detect-code-change.sh --class ci-infrastructure --git-diff BASE [HEAD]
EOF
  exit 2
}

if [[ "${1:-}" == "--class" ]]; then
  (( $# >= 2 )) || usage
  path_class="$2"
  shift 2
fi

emit() { printf '%s\n' "$1"; exit 0; }

files=()
diff_established=false
case "$path_class" in
  code)
    (( $# <= 1 )) || usage
    expected_total="${1:-}"
    mapfile -t files || true
    ;;
  ci-infrastructure)
    [[ "${1:-}" == "--git-diff" ]] || usage
    (( $# >= 2 && $# <= 3 )) || usage
    diff_base="$2"
    diff_head="${3:-HEAD}"
    # Keep diff acquisition inside this module. In particular, do not pipe
    # `git diff` into a matcher: without explicit pipefail handling, git's
    # error becomes the matcher's ordinary "no paths matched" result (the old
    # canary false-green). Disable external diff drivers so repo/user config
    # cannot replace this evidence source.
    # Disable rename folding too. A rename out of an owned path must expose
    # both its source and destination; the default rename display can report
    # only the non-CI destination and incorrectly classify the change as safe.
    if ! diff_output=$(git --no-pager -c core.quotePath=false diff \
          --no-ext-diff --no-renames --name-only "$diff_base" "$diff_head" --); then
      echo "detect-code-change: unable to establish git diff '$diff_base'..'$diff_head' -> matched (fail-closed)" >&2
      emit true
    fi
    diff_established=true
    if [[ -n "$diff_output" ]]; then
      mapfile -t files <<< "$diff_output"
    fi
    ;;
  *)
    echo "detect-code-change: unknown path class '$path_class'" >&2
    usage
    ;;
esac

count=${#files[@]}

# An empty stdin is missing evidence. An empty, successfully established git
# diff is a proven no-change result and is handled by the selected class below.
if (( count == 0 )); then
  if [[ "$diff_established" != true ]]; then
    echo "detect-code-change: empty file list -> matched (fail-closed)" >&2
    emit true
  fi
  emit false
fi

# Fail-closed: the files API is capped at 3000 entries. If the caller passed
# the authoritative changed-file count and it does not match what we received,
# the list is truncated (or otherwise inconsistent) and a code file may sit
# beyond the cap — build rather than trust the partial list.
if [[ -n "$expected_total" ]]; then
  if [[ ! "$expected_total" =~ ^[0-9]+$ ]]; then
    echo "detect-code-change: invalid authoritative total '$expected_total' -> matched (fail-closed)" >&2
    emit true
  fi
  if (( count != expected_total )); then
    echo "detect-code-change: received $count of $expected_total files (truncated/mismatch) -> matched (fail-closed)" >&2
    emit true
  fi
fi

for f in "${files[@]}"; do
  [[ -z "$f" ]] && continue
  # Git C-quotes paths containing control characters. A line-oriented parser
  # cannot prove their original prefix, so select the expensive path rather
  # than treating the quoted representation as a non-match.
  if [[ "$diff_established" == true && "$f" == \"* ]]; then
    echo "detect-code-change: quoted git path cannot be classified -> matched (fail-closed)" >&2
    emit true
  fi
  if [[ "$path_class" == "ci-infrastructure" ]]; then
    case "$f" in
      .github/workflows/*|.github/actions/*|scripts/ci/*)
        echo "detect-code-change: CI infrastructure path matched: $f" >&2
        emit true
        ;;
    esac
  else
    case "$f" in
      docs/*) ;;                                        # docs/** (any depth)
      LICENSE|.gitignore) ;;                             # root-only exact match
      .github/runner-inventory.json) ;;
      .github/workflows/runner-inventory-sentinel.yml) ;;
      *.md)
        # GitHub's `*.md` filter is root-only; a nested .md is NOT ignored.
        if [[ "$f" == */* ]]; then
          echo "detect-code-change: nested markdown is code-side per old paths-ignore -> building: $f" >&2
          emit true
        fi
        ;;
      *)
        echo "detect-code-change: non-docs path -> building: $f" >&2
        emit true
        ;;
    esac
  fi
done

emit false
